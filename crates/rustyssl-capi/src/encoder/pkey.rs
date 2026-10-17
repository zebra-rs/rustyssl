//! Encoding keys (`OSSL_ENCODER_CTX_new_for_pkey(3)`; `encoder_pkey.c`): a context whose
//! instances are the encoders of the key's type (by any of its key manager's names) that do
//! the selection — other providers' first, if they can import the key, then the key manager's
//! own provider's, which the chain then tries first — and whose construct gives the key's own
//! data to its provider's encoders and an imported copy to another's.
//!
//! As in OpenSSL, a legacy key (one without a key manager) gets no encoders, and the context
//! is given the key's `save_parameters`.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_OSSL_ENCODER, ERR_R_OSSL_ENCODER_LIB, ERR_R_PASSED_INVALID_ARGUMENT,
    ERR_R_PASSED_NULL_PARAMETER, EVP_PKEY, OSSL_ENCODER, OSSL_ENCODER_CTX, OSSL_ENCODER_INSTANCE,
    OSSL_ENCODER_PARAM_SAVE_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PARAM,
};

use super::ctx::{
    OSSL_ENCODER_CTX_add_encoder, OSSL_ENCODER_CTX_add_extra, OSSL_ENCODER_CTX_free,
    OSSL_ENCODER_CTX_new, OSSL_ENCODER_CTX_set_output_structure, OSSL_ENCODER_CTX_set_output_type,
    OSSL_ENCODER_CTX_set_params, OSSL_ENCODER_CTX_set_selection, ctx, instance,
};
use super::{OSSL_ENCODER_do_all_provided, encoder};
use crate::err;
use crate::evp::fetch;
use crate::evp::keymgmt;
use crate::evp::pkey::{KeyData, pkey};
use crate::ffi::{ffi_callback, ffi_export};
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_int};

/// `construct_data_st`: in C memory, as freeing the context frees it with `OPENSSL_free`.
#[derive(Clone, Copy)]
struct ConstructData {
    /// The key, whose data (with the key manager) lives while the context is used.
    pk: *const EVP_PKEY,
    selection: c_int,
    encoder_inst: *mut OSSL_ENCODER_INSTANCE,
    obj: *const c_void,
    constructed_obj: *mut c_void,
}

/// The key's key manager and data (its provided form).
///
/// # Safety
/// `pk` is a live key.
unsafe fn provided(pk: *const EVP_PKEY) -> (Option<keymgmt::Ref>, *mut c_void) {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { pkey(pk) }) else {
        return (None, ptr::null_mut());
    };
    let (km, kd) = k.provided();
    (
        km,
        kd.as_ref()
            .map_or(ptr::null_mut(), |d: &std::sync::Arc<KeyData>| d.ptr()),
    )
}

ffi_callback! {
    /// `encoder_import_cb`: the instance's encoder imports the exported parameters.
    ///
    /// # Safety
    /// `arg` is a live `ConstructData` whose instance is set.
    pub(crate) unsafe extern "C" fn import_cb(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let Some(data) = (unsafe { arg.cast::<ConstructData>().as_mut() }) else { return 0 };
        // SAFETY: the instance set before exporting.
        let Some(inst) = (unsafe { instance(data.encoder_inst) }) else { return 0 };
        data.constructed_obj = match inst.encoder().funcs.import_object {
            // SAFETY: the encoder's function with its context, the selection, and the array.
            Some(import) => unsafe { import(inst.ctx.0, data.selection, params) },
            None => ptr::null_mut(),
        };
        c_int::from(!data.constructed_obj.is_null())
    }
}

ffi_callback! {
    /// `encoder_construct_pkey`: the key's data for its own provider's encoders, else a copy
    /// the instance's encoder imports from the key's export (the public key too for a private
    /// key); once per encoding.
    ///
    /// # Safety
    /// `encoder_inst` is a live instance; `arg` is a live `ConstructData`.
    pub(crate) unsafe extern "C" fn construct_pkey(encoder_inst: *mut OSSL_ENCODER_INSTANCE, arg: *mut c_void) -> *const c_void
    where failure = ptr::null(), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let Some(data) = (unsafe { arg.cast::<ConstructData>().as_mut() }) else { return ptr::null() };
        if data.obj.is_null() {
            // SAFETY: as above.
            let Some(inst) = (unsafe { instance(encoder_inst) }) else { return ptr::null() };
            // SAFETY: the context's key.
            let (km, kd) = unsafe { provided(data.pk) };
            let Some(km) = km else { return ptr::null() };
            if km.get().prov.0 != inst.encoder().prov.0 {
                let mut selection = data.selection;
                if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
                    selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
                }
                data.encoder_inst = encoder_inst;
                // SAFETY: the key manager's data; the callback takes the construct data.
                if unsafe { km.get().export(kd, selection, Some(import_cb), arg) } == 0 {
                    return ptr::null();
                }
                data.obj = data.constructed_obj;
            } else {
                data.obj = kd;
            }
        }
        data.obj
    }
}

ffi_callback! {
    /// `encoder_destruct_pkey`: frees an imported copy.
    ///
    /// # Safety
    /// `arg` is a live `ConstructData`.
    pub(crate) unsafe extern "C" fn destruct_pkey(arg: *mut c_void)
    where failure = (), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let Some(data) = (unsafe { arg.cast::<ConstructData>().as_mut() }) else { return };
        let matched = data.obj == data.constructed_obj.cast_const();
        // SAFETY: the instance that imported, or NULL.
        if let Some(inst) = unsafe { instance(data.encoder_inst) }
            && let Some(free) = inst.encoder().funcs.free_object
        {
            // SAFETY: the encoder's object, or NULL.
            unsafe { free(data.constructed_obj) };
        }
        data.constructed_obj = ptr::null_mut();
        if matched {
            data.obj = ptr::null();
        }
    }
}

/// `collected_encoder_st`.
struct Collect {
    names: Vec<Vec<u8>>,
    id_names: Vec<u32>,
    keymgmt_prov: *const rustyssl_abi::OSSL_PROVIDER,
    ctx: *mut OSSL_ENCODER_CTX,
    find_same_provider: bool,
}

ffi_callback! {
    /// `collect_encoder`: an instance of the encoder added when it's of the key's type (by
    /// number, for the key manager's provider; by name, for another, which must be able to
    /// import), does the selection, and is from the provider this pass looks at.
    ///
    /// # Safety
    /// `encoder_h` is a live encoder; `arg` is a `Collect`.
    pub(crate) unsafe extern "C" fn collect_encoder(encoder_h: *mut OSSL_ENCODER, arg: *mut c_void)
    where failure = (), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let Some(data) = (unsafe { arg.cast::<Collect>().as_ref() }) else { return };
        // SAFETY: as above.
        let Some(e) = (unsafe { encoder(encoder_h) }) else { return };
        let prov = e.prov.0.cast_const();
        if (data.keymgmt_prov == prov) != data.find_same_provider {
            return;
        }
        // SAFETY: the context being set up.
        let selection = unsafe { ctx(data.ctx) }.map_or(0, |c| c.lock().selection);
        for (name, &id) in data.names.iter().zip(&data.id_names) {
            let matched = if data.find_same_provider { id == e.name_id } else { e.is_a(name) };
            if !matched {
                continue;
            }
            if let Some(does) = e.funcs.does_selection
                // SAFETY: the encoder's function with its provider's context.
                && unsafe { does(e.provider_ctx(), selection) } == 0
            {
                continue;
            }
            if data.keymgmt_prov != prov && e.funcs.import_object.is_none() {
                continue;
            }
            // SAFETY: the context; the encoder.
            if unsafe { OSSL_ENCODER_CTX_add_encoder(data.ctx, encoder_h) } != 0 {
                break;
            }
        }
    }
}

/// `ossl_encoder_ctx_setup_for_pkey`: the instances for a provided key, and the construct when
/// there are some. False on failure.
///
/// # Safety
/// `c` is a live context; `pk` is a live key.
unsafe fn setup_for_pkey(c: *mut OSSL_ENCODER_CTX, pk: *const EVP_PKEY, selection: c_int) -> bool {
    // SAFETY: the caller's guarantee.
    let (km, _) = unsafe { provided(pk) };
    let Some(km) = km else { return true };
    let prov = km.get().prov.0;
    // SAFETY: the key manager's live provider.
    let libctx = unsafe { crate::provider::libctx_of(prov) };
    let names = km.get().names();
    // SAFETY: the provider's library context.
    let id_names = names
        .iter()
        .map(|n| unsafe { fetch::number_in_libctx(libctx, n) })
        .collect();
    let mut collect = Collect {
        names,
        id_names,
        keymgmt_prov: prov.cast_const(),
        ctx: c,
        find_same_provider: false,
    };
    for same in [false, true] {
        collect.find_same_provider = same;
        // SAFETY: the library context; the callback takes the collection, which outlives it.
        unsafe {
            OSSL_ENCODER_do_all_provided(libctx, Some(collect_encoder), (&raw mut collect).cast())
        };
    }
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { ctx(c) }) else {
        return false;
    };
    if cx.lock().insts.is_empty() {
        return true;
    }
    let data: *mut ConstructData = crate::mem::alloc(size_of::<ConstructData>()).cast();
    if data.is_null() {
        return false;
    }
    // SAFETY: room for the data, from the C allocator (the context frees it so).
    unsafe {
        data.write(ConstructData {
            pk,
            selection,
            encoder_inst: ptr::null_mut(),
            obj: ptr::null(),
            constructed_obj: ptr::null_mut(),
        });
    }
    let mut st = cx.lock();
    st.construct = Some(construct_pkey);
    st.construct_data = data.cast();
    st.cleanup = Some(destruct_pkey);
    true
}

ffi_export! {
    /// A context that encodes the key's selected parts to `output_type` (and `output_struct`,
    /// if given) with the encoders of its key type. NULL with an error.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key that outlives the context; the strings are NULL or strings,
    /// the type and structure kept by the context.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_new_for_pkey(pkey_: *const EVP_PKEY, selection: c_int, output_type: *const c_char, output_struct: *const c_char, propquery: *const c_char) -> *mut OSSL_ENCODER_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_ENCODER
    {
        const F: &str = "OSSL_ENCODER_CTX_new_for_pkey";
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { pkey(pkey_) }) else {
            err::raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        };
        if !k.lock().is_assigned() {
            err::raise_with_text(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_INVALID_ARGUMENT, F, "The passed EVP_PKEY must be assigned a key");
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let c = unsafe { OSSL_ENCODER_CTX_new() };
        if c.is_null() {
            err::raise(ERR_LIB_OSSL_ENCODER, ERR_R_OSSL_ENCODER_LIB, F);
            return ptr::null_mut();
        }
        // SAFETY: the context; the caller's strings and key.
        let ok = unsafe { OSSL_ENCODER_CTX_set_output_type(c, output_type) } != 0
            // SAFETY: as above.
            && (output_struct.is_null() || unsafe { OSSL_ENCODER_CTX_set_output_structure(c, output_struct) } != 0)
            // SAFETY: as above.
            && unsafe { OSSL_ENCODER_CTX_set_selection(c, selection) } != 0
            // SAFETY: as above.
            && unsafe { setup_for_pkey(c, pkey_, selection) }
            // SAFETY: as above.
            && unsafe { OSSL_ENCODER_CTX_add_extra(c, ptr::null_mut(), propquery) } != 0;
        if !ok {
            // SAFETY: made above.
            unsafe { OSSL_ENCODER_CTX_free(c) };
            return ptr::null_mut();
        }
        let mut save = k.save_parameters();
        let params = [
            // SAFETY: a static name; a local that outlives the call.
            unsafe { OSSL_PARAM_construct_int(OSSL_ENCODER_PARAM_SAVE_PARAMETERS.as_ptr(), &raw mut save) },
            // SAFETY: no preconditions.
            unsafe { OSSL_PARAM_construct_end() },
        ];
        // SAFETY: the context; the array.
        unsafe { OSSL_ENCODER_CTX_set_params(c, params.as_ptr()) };
        c
    }
}
