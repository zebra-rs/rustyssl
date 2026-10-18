//! Decoding keys (`OSSL_DECODER_CTX_new_for_pkey(3)`; `decoder_pkey.c`): a decoder context
//! whose chain ends in the key decoders of the providers' key types (all of them, or a type
//! and the SM2 that an EC key may turn out to be), and whose construct makes an `EVP_PKEY` of
//! what they decode — loaded by the decoder's own provider's key manager, or exported to
//! another provider's.
//!
//! As in OpenSSL, the context returned is a copy of a template set up for the arguments: its
//! instances have new decoder contexts, without the parameters (the properties, the input
//! structure) the template's were given. OpenSSL keeps the templates in a cache; rustyssl sets
//! one up for each call, which gives the same contexts.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ERR_LIB_OSSL_DECODER, ERR_R_OSSL_DECODER_LIB, EVP_KEYMGMT, EVP_PKEY, OSSL_DECODER,
    OSSL_DECODER_CTX, OSSL_DECODER_INSTANCE, OSSL_DECODER_PARAM_PROPERTIES,
    OSSL_KEYMGMT_SELECT_ALL, OSSL_LIB_CTX, OSSL_OBJECT_PARAM_DATA_STRUCTURE,
    OSSL_OBJECT_PARAM_DATA_TYPE, OSSL_OBJECT_PARAM_REFERENCE, OSSL_PARAM, OSSL_PARAM_OCTET_STRING,
};
use rustyssl_crypto::property::List;

use super::ctx::{
    OSSL_DECODER_CTX_add_extra, OSSL_DECODER_CTX_free, OSSL_DECODER_CTX_new,
    OSSL_DECODER_CTX_set_input_structure, OSSL_DECODER_CTX_set_input_type,
    OSSL_DECODER_CTX_set_params, OSSL_DECODER_CTX_set_selection, add_decoder_inst, ctx, instance,
    instance_dup, instance_new,
};
use super::{OSSL_DECODER_do_all_provided, decoder};
use crate::err;
use crate::evp::fetch;
use crate::evp::keymgmt::{self, EVP_KEYMGMT_do_all_provided, EVP_KEYMGMT_fetch};
use crate::ffi::{ffi_callback, ffi_export};
use crate::handle::Handle;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_utf8_string,
    OSSL_PARAM_locate_const,
};

/// The construct's data (`decoder_pkey_data_st`).
struct PkeyData {
    libctx: *mut OSSL_LIB_CTX,
    propq: Option<CString>,
    selection: c_int,
    keymgmts: Vec<keymgmt::Ref>,
    object_type: Option<CString>,
    /// Where the key goes (the application's pointer; NULL in a template).
    object: *mut *mut EVP_PKEY,
    /// The context the data belongs to (NULL in a template).
    ctx: *mut OSSL_DECODER_CTX,
}

impl PkeyData {
    /// The properties, as C takes them.
    fn propq(&self) -> *const c_char {
        self.propq.as_deref().map_or(ptr::null(), CStr::as_ptr)
    }
}

/// A C string argument, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

/// The object type the parameters give (`OSSL_OBJECT_PARAM_DATA_TYPE`), `Ok(None)` without
/// one; `Err` if it isn't a string.
///
/// # Safety
/// `params` is an array.
unsafe fn data_type(params: *const OSSL_PARAM) -> Result<Option<CString>, ()> {
    // SAFETY: the caller's array; a static name.
    let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE.as_ptr()) };
    if p.is_null() {
        return Ok(None);
    }
    let mut s: *mut c_char = ptr::null_mut();
    // SAFETY: the parameter; a local for a new string.
    if unsafe { OSSL_PARAM_get_utf8_string(p, &raw mut s, 0) } == 0 {
        return Err(());
    }
    // SAFETY: the new string.
    let owned = unsafe { CStr::from_ptr(s) }.to_owned();
    // SAFETY: made by the getter with the C allocator.
    unsafe { crate::mem::release(s.cast()) };
    Ok(Some(owned))
}

ffi_callback! {
    /// `decoder_construct_pkey`: a key of the decoded object's type from its reference, through
    /// a key manager of the decoder's provider that can load it (one of the context's, else
    /// fetched), or another provider's that imports what the decoder exports; true if the
    /// application's key pointer got one.
    ///
    /// # Safety
    /// `decoder_inst` is a live instance; `params` is an array; `construct_data` is the
    /// context's `PkeyData`.
    pub(crate) unsafe extern "C" fn construct_pkey(decoder_inst: *mut OSSL_DECODER_INSTANCE, params: *const OSSL_PARAM, construct_data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        let Some(data) = (unsafe { construct_data.cast::<PkeyData>().as_mut() }) else { return 0 };
        // SAFETY: as above.
        let Some(inst) = (unsafe { instance(decoder_inst) }) else { return 0 };
        let d = inst.decoder();
        // SAFETY: as above.
        match unsafe { data_type(params) } {
            Ok(Some(t)) => data.object_type = Some(t),
            Ok(None) => {}
            Err(()) => return 0,
        }
        // SAFETY: as above; a static name.
        let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE.as_ptr()) };
        // SAFETY: a parameter of the array, or NULL.
        let Some(p) = (unsafe { p.as_ref() }) else { return 0 };
        if p.data_type != OSSL_PARAM_OCTET_STRING.cast_unsigned() {
            return 0;
        }
        let (object_ref, object_ref_sz) = (p.data.cast_const(), p.data_size);
        let object_type = data.object_type.as_deref();
        let found = data.keymgmts.iter().find(|km| {
            let m = km.get();
            m.prov.0 == d.prov.0
                && m.has_load()
                && object_type.is_some_and(|t| m.is_a(t.to_bytes()))
        });
        let km = match found {
            Some(km) => Some(km.clone()),
            None => {
                let name = object_type.map_or(ptr::null(), CStr::as_ptr);
                // SAFETY: the context's library context and properties.
                let m = unsafe { EVP_KEYMGMT_fetch(data.libctx, name, data.propq()) };
                // SAFETY: a new reference, or NULL.
                unsafe { keymgmt::Ref::adopt(m) }
            }
        };
        let Some(km) = km else {
            // SAFETY: the application's pointer.
            return c_int::from(!unsafe { data.object.read() }.is_null());
        };
        let m = km.get();
        let keydata = if m.prov.0 == d.prov.0 {
            // SAFETY: the decoder's reference to its object.
            unsafe { m.load(object_ref, object_ref_sz) }
        } else {
            let selection = if data.selection == 0 { OSSL_KEYMGMT_SELECT_ALL } else { data.selection };
            let mut import = crate::evp::pkey::TryImport {
                keymgmt: km.clone(),
                keydata: ptr::null_mut(),
                selection,
                allocated: false,
            };
            if let Some(export_object) = d.funcs.export_object {
                // SAFETY: the decoder's function with its context and reference; the callback
                // takes the import data, which outlives the call.
                unsafe { export_object(inst.ctx.0, object_ref, object_ref_sz, Some(crate::evp::pkey::try_import), (&raw mut import).cast()) };
            }
            import.keydata
        };
        if keydata.is_null() && !data.ctx.is_null() {
            // SAFETY: the context the data belongs to.
            if let Some(c) = unsafe { ctx(data.ctx) } {
                c.lock().harderr = true;
            }
        }
        let pkey = if keydata.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: the key manager's new data.
            unsafe { make_pkey(&km, keydata) }
        };
        // SAFETY: the application's pointer.
        unsafe { data.object.write(pkey) };
        c_int::from(!pkey.is_null())
    }
}

/// `evp_keymgmt_util_make_pkey`: a new key holding the key manager's data (freed on failure).
///
/// # Safety
/// `keydata` is key data of `km`, which the key takes.
pub(crate) unsafe fn make_pkey(km: &keymgmt::Ref, keydata: *mut c_void) -> *mut EVP_PKEY {
    let Some(kd) = crate::evp::pkey::KeyData::adopt(km.clone(), keydata) else {
        return ptr::null_mut();
    };
    // SAFETY: no preconditions.
    let pk = unsafe { crate::evp::pkey::EVP_PKEY_new() };
    // SAFETY: the new key, or NULL.
    let Some(k) = (unsafe { crate::evp::pkey::pkey(pk) }) else {
        return ptr::null_mut();
    };
    if !crate::evp::pkey::assign(k, kd) {
        // SAFETY: made above.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pk) };
        return ptr::null_mut();
    }
    pk
}

ffi_callback! {
    /// `decoder_clean_pkey_construct_arg`.
    ///
    /// # Safety
    /// `construct_data` is NULL or a `PkeyData` this module made, not used afterwards.
    pub(crate) unsafe extern "C" fn clean_pkey(construct_data: *mut c_void)
    where failure = (), library = ERR_LIB_OSSL_DECODER
    {
        if !construct_data.is_null() {
            // SAFETY: the caller's guarantee.
            drop(unsafe { Box::from_raw(construct_data.cast::<PkeyData>()) });
        }
    }
}

/// `collect_data_st`.
struct Collect {
    libctx: *mut OSSL_LIB_CTX,
    ctx: *mut OSSL_DECODER_CTX,
    keytype: Option<CString>,
    keytype_id: u32,
    sm2_id: u32,
    total: c_int,
    error_occurred: bool,
    keytype_resolved: bool,
    pq: Option<List>,
    keymgmts: Vec<keymgmt::Ref>,
}

/// `check_keymgmt`: whether the key manager is of the key type asked for (or SM2, for the
/// EC key type's OID or name), all for none.
fn check_keymgmt(m: &keymgmt::Keymgmt, data: &mut Collect) -> bool {
    let Some(keytype) = &data.keytype else {
        return true;
    };
    if !data.keytype_resolved {
        // SAFETY: the context's library context.
        data.keytype_id = unsafe { fetch::number_in_libctx(data.libctx, keytype.to_bytes()) };
        if data.keytype_id != 0
            && matches!(keytype.to_bytes(), b"id-ecPublicKey" | b"1.2.840.10045.2.1")
        {
            // SAFETY: as above.
            data.sm2_id = unsafe { fetch::number_in_libctx(data.libctx, b"SM2") };
        }
        data.keytype_resolved = true;
    }
    data.keytype_id != 0 && (m.name_id == data.keytype_id || m.name_id == data.sm2_id)
}

ffi_callback! {
    /// `collect_keymgmt`: the key manager kept if it's of the key type asked for.
    ///
    /// # Safety
    /// `keymgmt` is a live key manager; `arg` is a `Collect`.
    pub(crate) unsafe extern "C" fn collect_keymgmt(keymgmt_h: *mut EVP_KEYMGMT, arg: *mut c_void)
    where failure = (), library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        let Some(data) = (unsafe { arg.cast::<Collect>().as_mut() }) else { return };
        // SAFETY: as above.
        let Some(r) = (unsafe { keymgmt::Ref::new(keymgmt_h) }) else { return };
        if check_keymgmt(r.get(), data) {
            data.keymgmts.push(r);
        }
    }
}

/// The ASCII case-insensitive comparison OpenSSL's `OPENSSL_strcasecmp` makes.
fn eq_case(a: &CStr, b: &[u8]) -> bool {
    a.to_bytes().eq_ignore_ascii_case(b)
}

/// `collect_decoder_keymgmt`: an instance of the decoder added when it's of the key
/// manager's type, reads the context's input type (or DER under PEM), and matches the
/// properties asked for; true if added.
///
/// # Safety
/// `decoder_h` is a live decoder; `provctx` is its provider's context.
unsafe fn collect_decoder_keymgmt(
    m: &keymgmt::Keymgmt,
    decoder_h: *mut OSSL_DECODER,
    provctx: *mut c_void,
    data: &mut Collect,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { decoder(decoder_h) }) else {
        return false;
    };
    if m.name_id != d.name_id {
        return false;
    }
    let dctx = match d.funcs.newctx {
        // SAFETY: the decoder's function with its provider's context.
        Some(newctx) => unsafe { newctx(provctx) },
        None => ptr::null_mut(),
    };
    if dctx.is_null() {
        data.error_occurred = true;
        return false;
    }
    // SAFETY: the decoder and its new context, which the instance takes.
    let di = unsafe { instance_new(decoder_h, dctx) };
    // SAFETY: just made, or NULL.
    let Some(inst) = (unsafe { instance(di) }) else {
        data.error_occurred = true;
        return false;
    };
    // SAFETY: the context being set up.
    let Some(c) = (unsafe { ctx(data.ctx) }) else {
        return false;
    };
    let start = c.lock().start_input_type;
    // SAFETY: the application's string, or NULL.
    if let Some(start) = unsafe { text(start) } {
        let it = inst.input_type();
        if !eq_case(it, start.to_bytes()) && (!eq_case(it, b"DER") || !eq_case(start, b"PEM")) {
            // SAFETY: made above, not added.
            unsafe { OSSL_DECODER_INSTANCE::free(di) };
            return false;
        }
    }
    if let Some(pq) = &data.pq {
        let score = fetch::match_count(pq, &d.props);
        if score < 0 {
            // SAFETY: as above.
            unsafe { OSSL_DECODER_INSTANCE::free(di) };
            return false;
        }
        inst.score
            .store(score, core::sync::atomic::Ordering::Relaxed);
    }
    add_decoder_inst(c, di);
    data.total += 1;
    true
}

ffi_callback! {
    /// `collect_decoder`: an instance of the decoder for the first collected key manager of its
    /// type, if it does the context's selection.
    ///
    /// # Safety
    /// `decoder` is a live decoder; `arg` is a `Collect`.
    pub(crate) unsafe extern "C" fn collect_decoder(decoder_h: *mut OSSL_DECODER, arg: *mut c_void)
    where failure = (), library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        let Some(data) = (unsafe { arg.cast::<Collect>().as_mut() }) else { return };
        if data.error_occurred {
            return;
        }
        // SAFETY: as above.
        let Some(d) = (unsafe { decoder(decoder_h) }) else { return };
        let provctx = d.provider_ctx();
        // SAFETY: the context being set up.
        let selection = unsafe { ctx(data.ctx) }.map_or(0, |c| c.lock().selection);
        if let Some(does) = d.funcs.does_selection
            // SAFETY: the decoder's function with its provider's context.
            && unsafe { does(provctx, selection) } == 0
        {
            return;
        }
        let keymgmts = core::mem::take(&mut data.keymgmts);
        for km in &keymgmts {
            // SAFETY: the caller's decoder and its provider's context.
            if unsafe { collect_decoder_keymgmt(km.get(), decoder_h, provctx, data) } || data.error_occurred {
                break;
            }
        }
        data.keymgmts = keymgmts;
    }
}

/// `ossl_decoder_ctx_setup_for_pkey`: the template's instances (the key decoders of the
/// collected key managers' types) and, when it has some, its construct. False on failure.
///
/// # Safety
/// `c` is a live context; `libctx` is NULL or a live library context.
unsafe fn setup_for_pkey(
    c: *mut OSSL_DECODER_CTX,
    keytype: Option<&CStr>,
    libctx: *mut OSSL_LIB_CTX,
    propquery: Option<&CStr>,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { ctx(c) }) else {
        return false;
    };
    let mut collect = Collect {
        libctx,
        ctx: c,
        keytype: keytype.map(CStr::to_owned),
        keytype_id: 0,
        sm2_id: 0,
        total: 0,
        error_occurred: false,
        keytype_resolved: false,
        // SAFETY: as above.
        pq: unsafe { fetch::query_with_global(libctx, propquery.map(CStr::to_bytes)) },
        keymgmts: Vec::new(),
    };
    // SAFETY: as above; the callback takes the collection, which outlives the call.
    unsafe {
        EVP_KEYMGMT_do_all_provided(libctx, Some(collect_keymgmt), (&raw mut collect).cast())
    };
    if collect.error_occurred {
        return false;
    }
    // SAFETY: as above.
    unsafe {
        OSSL_DECODER_do_all_provided(libctx, Some(collect_decoder), (&raw mut collect).cast())
    };
    if collect.error_occurred {
        return false;
    }
    let mut st = cx.lock();
    if !st.insts.is_empty() {
        let data = Box::new(PkeyData {
            libctx,
            propq: propquery.map(CStr::to_owned),
            selection: st.selection,
            keymgmts: core::mem::take(&mut collect.keymgmts),
            object_type: None,
            object: ptr::null_mut(),
            ctx: ptr::null_mut(),
        });
        st.construct = Some(construct_pkey);
        st.construct_data = Box::into_raw(data).cast();
        st.cleanup = Some(clean_pkey);
    }
    true
}

/// `ossl_decoder_ctx_for_pkey_dup`: a new context with the template's selection, copies of
/// its instances, and its construct with a copy of its data that fills `pkey`; the input type
/// and structure given. NULL with an error.
///
/// # Safety
/// `src` is a live template; `pkey` is a key pointer the context may fill; the strings are
/// NULL or strings, kept by the new context.
unsafe fn for_pkey_dup(
    src: *mut OSSL_DECODER_CTX,
    pkey: *mut *mut EVP_PKEY,
    input_type: *const c_char,
    input_structure: *const c_char,
) -> *mut OSSL_DECODER_CTX {
    const F: &str = "ossl_decoder_ctx_for_pkey_dup";
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { ctx(src) }) else {
        return ptr::null_mut();
    };
    // SAFETY: no preconditions.
    let dest = unsafe { OSSL_DECODER_CTX_new() };
    // SAFETY: just made, or NULL.
    let Some(dc) = (unsafe { ctx(dest) }) else {
        err::raise(ERR_LIB_OSSL_DECODER, ERR_R_OSSL_DECODER_LIB, F);
        return ptr::null_mut();
    };
    let fail = |reason: c_int| {
        err::raise(ERR_LIB_OSSL_DECODER, reason, F);
        // SAFETY: made above.
        unsafe { OSSL_DECODER_CTX_free(dest) };
        ptr::null_mut()
    };
    // SAFETY: the new context; the caller's strings.
    if unsafe { OSSL_DECODER_CTX_set_input_type(dest, input_type) } == 0
        // SAFETY: as above.
        || unsafe { OSSL_DECODER_CTX_set_input_structure(dest, input_structure) } == 0
    {
        return fail(ERR_R_OSSL_DECODER_LIB);
    }
    let (selection, insts, construct, cleanup, data_src) = {
        let st = s.lock();
        (
            st.selection,
            st.insts.clone(),
            st.construct,
            st.cleanup,
            st.construct_data,
        )
    };
    let mut copies = Vec::with_capacity(insts.len());
    for &i in &insts {
        // SAFETY: an instance of the template.
        let c = unsafe { instance_dup(i) };
        if c.is_null() {
            for &made in &copies {
                // SAFETY: made above, not added.
                unsafe { OSSL_DECODER_INSTANCE::free(made) };
            }
            return fail(ERR_R_OSSL_DECODER_LIB);
        }
        copies.push(c);
    }
    {
        let mut st = dc.lock();
        st.selection = selection;
        st.insts = copies;
        st.construct = construct;
    }
    // SAFETY: the template's data, a `PkeyData` when its construct is this module's.
    if let Some(src_data) = unsafe { data_src.cast::<PkeyData>().as_ref() } {
        let data = Box::new(PkeyData {
            libctx: src_data.libctx,
            propq: src_data.propq.clone(),
            selection: src_data.selection,
            keymgmts: src_data.keymgmts.clone(),
            object_type: None,
            object: pkey,
            ctx: dest,
        });
        dc.lock().construct_data = Box::into_raw(data).cast();
    }
    dc.lock().cleanup = cleanup;
    dest
}

ffi_export! {
    /// A decoder context that decodes a key of `keytype` (any, for NULL) into `*pkey`, from
    /// `input_type` with `input_structure` (each any, for NULL) and the selection, with the
    /// library context's decoders matching `propquery`. NULL with an error.
    ///
    /// # Safety
    /// `pkey` is a key pointer the context fills while it lives; the strings are NULL or
    /// strings, `input_type` and `input_structure` kept by the context; `libctx` is NULL or a
    /// live library context.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_new_for_pkey(pkey: *mut *mut EVP_PKEY, input_type: *const c_char, input_structure: *const c_char, keytype: *const c_char, selection: c_int, libctx: *mut OSSL_LIB_CTX, propquery: *const c_char) -> *mut OSSL_DECODER_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_DECODER
    {
        const F: &str = "OSSL_DECODER_CTX_new_for_pkey";
        // SAFETY: no preconditions.
        let template = unsafe { OSSL_DECODER_CTX_new() };
        if template.is_null() {
            err::raise(ERR_LIB_OSSL_DECODER, ERR_R_OSSL_DECODER_LIB, F);
            return ptr::null_mut();
        }
        let mut decoder_params = Vec::with_capacity(3);
        if !input_structure.is_null() {
            // SAFETY: a static name; the caller's string, read during the call.
            decoder_params.push(unsafe { OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE.as_ptr(), input_structure.cast_mut(), 0) });
        }
        if !propquery.is_null() {
            // SAFETY: as above.
            decoder_params.push(unsafe { OSSL_PARAM_construct_utf8_string(OSSL_DECODER_PARAM_PROPERTIES.as_ptr(), propquery.cast_mut(), 0) });
        }
        // SAFETY: no preconditions.
        decoder_params.push(unsafe { OSSL_PARAM_construct_end() });
        // SAFETY: the caller's string.
        let keytype = unsafe { text(keytype) };
        // SAFETY: as above.
        let propq = unsafe { text(propquery) };
        // SAFETY: the template; the caller's strings and library context.
        let ok = unsafe { OSSL_DECODER_CTX_set_input_type(template, input_type) } != 0
            // SAFETY: as above.
            && unsafe { OSSL_DECODER_CTX_set_input_structure(template, input_structure) } != 0
            // SAFETY: as above.
            && unsafe { OSSL_DECODER_CTX_set_selection(template, selection) } != 0
            // SAFETY: as above.
            && unsafe { setup_for_pkey(template, keytype, libctx, propq) }
            // SAFETY: as above.
            && unsafe { OSSL_DECODER_CTX_add_extra(template, libctx, propquery) } != 0
            // SAFETY: as above; the parameters over the caller's strings.
            && (propquery.is_null() || unsafe { OSSL_DECODER_CTX_set_params(template, decoder_params.as_ptr()) } != 0);
        if !ok {
            err::raise(ERR_LIB_OSSL_DECODER, ERR_R_OSSL_DECODER_LIB, F);
            // SAFETY: made above.
            unsafe { OSSL_DECODER_CTX_free(template) };
            return ptr::null_mut();
        }
        // SAFETY: the template; the caller's guarantee.
        let ctx = unsafe { for_pkey_dup(template, pkey, input_type, input_structure) };
        // SAFETY: made above, freed once.
        unsafe { OSSL_DECODER_CTX_free(template) };
        ctx
    }
}
