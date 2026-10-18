//! Decoding (`OSSL_DECODER_CTX(3)`, `OSSL_DECODER_from_bio(3)`; `decoder_lib.c`): a context's
//! decoder instances (each a decoder with its own context and its input type and structure,
//! from its properties), added one by one or by `add_extra`'s chains; its selection, input
//! type and structure, construct and cleanup, and passphrase; and the walk of the chain that
//! decodes.
//!
//! The walk follows `decoder_process` step for step. From the last instance back, each decoder
//! that may take the data (the start input type at the top, then the previous decoder's name,
//! the data type and structure it passed on, and once the input structure asked for) runs on
//! the input from where the level started, within an error mark; one that passes data on (an
//! `OSSL_OBJECT_PARAM_DATA` octet string, with its type and structure) gets the next level,
//! where the construct callback gets the first say. The walk stops at the first decoder that
//! fails, constructs, or passes data on; a decoder that does none of these leaves no errors.
//!
//! Decoders read through a core BIO, which here is the BIO itself with a reference; no lock is
//! held while a decoder, the construct callback, or a passphrase callback runs.

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use libc::FILE;

use rustyssl_abi::{
    BIO, BIO_C_FILE_SEEK, BIO_C_FILE_TELL, BIO_C_SET_FILE_PTR, BIO_CTRL_INFO, BIO_NOCLOSE,
    ERR_LIB_OSSL_DECODER, ERR_R_BIO_LIB, ERR_R_INTERNAL_ERROR, ERR_R_INVALID_PROPERTY_DEFINITION,
    ERR_R_PASSED_NULL_PARAMETER, ERR_R_UNSUPPORTED, OSSL_CALLBACK, OSSL_CORE_BIO, OSSL_DECODER,
    OSSL_DECODER_CLEANUP, OSSL_DECODER_CONSTRUCT, OSSL_DECODER_CTX, OSSL_DECODER_INSTANCE,
    OSSL_DECODER_R_DECODER_NOT_FOUND, OSSL_LIB_CTX, OSSL_OBJECT_PARAM_DATA,
    OSSL_OBJECT_PARAM_DATA_STRUCTURE, OSSL_OBJECT_PARAM_DATA_TYPE, OSSL_OBJECT_PARAM_INPUT_TYPE,
    OSSL_PARAM, OSSL_PARAM_OCTET_STRING, OSSL_PASSPHRASE_CALLBACK, UI_METHOD, pem_password_cb,
};

use super::{Decoder, decoder};
use crate::bio::{BIO_ctrl, BIO_free, BIO_new, BIO_pop, BIO_push, BIO_up_ref};
use crate::err::{
    self, ERR_clear_last_mark, ERR_peek_error, ERR_peek_last_error, ERR_pop_to_mark, ERR_set_mark,
};
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_utf8_string_ptr,
    OSSL_PARAM_locate_const,
};
use crate::passphrase::{PwData, passphrase_callback_dec};
use crate::provider::Ptr;

/// The most `add_extra` looks for decoders after those of the chain's ends (`depth <= 10`).
const MAX_EXTRA_DEPTH: usize = 10;

/// A decoder instance (`OSSL_DECODER_INSTANCE`): a decoder, its context, and its input type and
/// structure.
pub(crate) struct Instance {
    /// The decoder, with a reference.
    pub(crate) decoder: Ptr<OSSL_DECODER>,
    /// The decoder's context.
    pub(crate) ctx: Ptr<c_void>,
    input_type: CString,
    input_structure: Option<CString>,
    /// The input type's number, once looked up (0 before).
    input_type_id: AtomicU32,
    /// For `add_extra`'s stable sort under a property query.
    order: AtomicI32,
    pub(crate) score: AtomicI32,
    flag_input_structure_was_set: bool,
}

handle_type!(OSSL_DECODER_INSTANCE => Instance);

impl Drop for Instance {
    fn drop(&mut self) {
        // SAFETY: the instance's decoder, live while it holds the reference.
        if let Some(d) = unsafe { decoder(self.decoder.0) }
            && let Some(free) = d.funcs.freectx
        {
            // SAFETY: the decoder's function with its own context.
            unsafe { free(self.ctx.0) };
        }
        // SAFETY: the reference the instance holds.
        unsafe { OSSL_DECODER::free(self.decoder.0) };
    }
}

impl Instance {
    /// The instance's decoder.
    pub(crate) fn decoder(&self) -> &Decoder {
        // SAFETY: the instance holds a reference to its live decoder.
        match unsafe { decoder(self.decoder.0) } {
            Some(d) => d,
            None => crate::ffi::die("an instance's decoder is live"),
        }
    }

    /// `OSSL_DECODER_INSTANCE_get_input_type`.
    pub(crate) fn input_type(&self) -> &CStr {
        &self.input_type
    }

    /// `OSSL_DECODER_INSTANCE_get_input_structure`.
    pub(crate) fn input_structure(&self) -> Option<&CStr> {
        self.input_structure.as_deref()
    }
}

/// The instance behind a handle, or `None` for NULL.
///
/// # Safety
/// `inst` is NULL or a live instance.
pub(crate) unsafe fn instance<'a>(inst: *const OSSL_DECODER_INSTANCE) -> Option<&'a Instance> {
    // SAFETY: the caller's guarantee.
    unsafe { OSSL_DECODER_INSTANCE::get(inst) }
}

/// `ossl_decoder_fast_is_a`: whether `name` (its number cached in `cache`) is the decoder's.
fn fast_is_a(d: &Decoder, name: &CStr, cache: &AtomicU32) -> bool {
    let mut id = cache.load(Ordering::Relaxed);
    if id == 0 {
        id = d.number_of(name.to_bytes());
        cache.store(id, Ordering::Relaxed);
    }
    id > 0 && id == d.name_id
}

/// `ossl_decoder_instance_new`: an instance of the decoder with its context (which it takes,
/// freeing it on failure), its input type and structure from the decoder's properties; NULL
/// with an error.
///
/// # Safety
/// `decoder` is a live decoder; `decoderctx` is its context.
pub(crate) unsafe fn instance_new(
    decoder_h: *mut OSSL_DECODER,
    decoderctx: *mut c_void,
) -> *mut OSSL_DECODER_INSTANCE {
    const F: &str = "ossl_decoder_instance_new";
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { decoder(decoder_h) }) else {
        err::raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER, F);
        return ptr::null_mut();
    };
    let free_ctx = || {
        if let Some(f) = d.funcs.freectx {
            // SAFETY: the decoder's function with the context the caller gave.
            unsafe { f(decoderctx) };
        }
    };
    let libctx = d.libctx();
    // SAFETY: the decoder's provider's context.
    let Some(input) = (unsafe { crate::evp::fetch::string_property(libctx, &d.props, b"input") })
    else {
        // SAFETY: the provider's string, or NULL.
        let props = unsafe { text(d.properties()) }
            .map_or_else(String::new, |p| p.to_string_lossy().into_owned());
        err::raise_with_text(
            ERR_LIB_OSSL_DECODER,
            ERR_R_INVALID_PROPERTY_DEFINITION,
            F,
            &format!(
                "the mandatory 'input' property is missing for decoder {} (properties: {props})",
                d.name().to_string_lossy()
            ),
        );
        free_ctx();
        return ptr::null_mut();
    };
    // SAFETY: as above.
    let structure = unsafe { crate::evp::fetch::string_property(libctx, &d.props, b"structure") };
    let (Ok(input_type), Ok(input_structure)) =
        (CString::new(input), structure.map(CString::new).transpose())
    else {
        free_ctx();
        return ptr::null_mut();
    };
    // SAFETY: the caller's live decoder; the instance holds the reference.
    if !unsafe { OSSL_DECODER::up_ref(decoder_h) } {
        err::raise(ERR_LIB_OSSL_DECODER, ERR_R_INTERNAL_ERROR, F);
        free_ctx();
        return ptr::null_mut();
    }
    OSSL_DECODER_INSTANCE::new_handle(Instance {
        decoder: Ptr(decoder_h),
        ctx: Ptr(decoderctx),
        input_type,
        input_structure,
        input_type_id: AtomicU32::new(0),
        order: AtomicI32::new(0),
        score: AtomicI32::new(0),
        flag_input_structure_was_set: false,
    })
}

/// A new context for the decoder, given `input_structure` (as `OSSL_OBJECT_PARAM_DATA_STRUCTURE`)
/// when it takes parameters; NULL if either fails.
///
/// # Safety
/// `d` is a live decoder; `input_structure` is NULL or a string.
unsafe fn new_decoder_ctx(d: &Decoder, input_structure: *const c_char) -> *mut c_void {
    let Some(newctx) = d.funcs.newctx else {
        return ptr::null_mut();
    };
    // SAFETY: the decoder's function with its provider's context.
    let dctx = unsafe { newctx(d.provider_ctx()) };
    if dctx.is_null() || input_structure.is_null() {
        return dctx;
    }
    if let Some(set) = d.funcs.set_ctx_params {
        // SAFETY: a parameter over the caller's string, read during the call.
        let params = [
            unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_OBJECT_PARAM_DATA_STRUCTURE.as_ptr(),
                    input_structure.cast_mut(),
                    0,
                )
            },
            // SAFETY: no preconditions.
            unsafe { OSSL_PARAM_construct_end() },
        ];
        // SAFETY: the decoder's function with its new context and the array.
        if unsafe { set(dctx, params.as_ptr()) } == 0 {
            if let Some(free) = d.funcs.freectx {
                // SAFETY: as above.
                unsafe { free(dctx) };
            }
            return ptr::null_mut();
        }
    }
    dctx
}

/// `ossl_decoder_instance_dup`: a copy of the instance with its own reference to the decoder
/// and a new decoder context (made afresh, with none of the original's parameters), or NULL.
///
/// # Safety
/// `src` is a live instance.
pub(crate) unsafe fn instance_dup(src: *const OSSL_DECODER_INSTANCE) -> *mut OSSL_DECODER_INSTANCE {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { instance(src) }) else {
        return ptr::null_mut();
    };
    let d = s.decoder();
    // SAFETY: the instance's live decoder; the copy holds the reference.
    if !unsafe { OSSL_DECODER::up_ref(s.decoder.0) } {
        err::raise(
            ERR_LIB_OSSL_DECODER,
            ERR_R_INTERNAL_ERROR,
            "ossl_decoder_instance_dup",
        );
        return ptr::null_mut();
    }
    let dctx = match d.funcs.newctx {
        // SAFETY: the decoder's function with its provider's context.
        Some(newctx) => unsafe { newctx(d.provider_ctx()) },
        None => ptr::null_mut(),
    };
    if dctx.is_null() {
        err::raise(
            ERR_LIB_OSSL_DECODER,
            ERR_R_INTERNAL_ERROR,
            "ossl_decoder_instance_dup",
        );
        // SAFETY: the reference taken above.
        unsafe { OSSL_DECODER::free(s.decoder.0) };
        return ptr::null_mut();
    }
    OSSL_DECODER_INSTANCE::new_handle(Instance {
        decoder: s.decoder,
        ctx: Ptr(dctx),
        input_type: s.input_type.clone(),
        input_structure: s.input_structure.clone(),
        input_type_id: AtomicU32::new(s.input_type_id.load(Ordering::Relaxed)),
        order: AtomicI32::new(s.order.load(Ordering::Relaxed)),
        score: AtomicI32::new(s.score.load(Ordering::Relaxed)),
        flag_input_structure_was_set: s.flag_input_structure_was_set,
    })
}

/// `ossl_decoder_instance_new_forprov`: an instance of the decoder with a new context given the
/// input structure, or NULL.
///
/// # Safety
/// `decoder` is a live decoder; `input_structure` is NULL or a string.
pub(crate) unsafe fn instance_new_forprov(
    decoder_h: *mut OSSL_DECODER,
    input_structure: *const c_char,
) -> *mut OSSL_DECODER_INSTANCE {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { decoder(decoder_h) }) else {
        err::raise(
            ERR_LIB_OSSL_DECODER,
            ERR_R_PASSED_NULL_PARAMETER,
            "ossl_decoder_instance_new_forprov",
        );
        return ptr::null_mut();
    };
    // SAFETY: as above.
    let dctx = unsafe { new_decoder_ctx(d, input_structure) };
    if dctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the decoder and its new context.
    unsafe { instance_new(decoder_h, dctx) }
}

/// A context's state (the fields of `ossl_decoder_ctx_st` but the passphrase).
pub(crate) struct State {
    /// The application's string (not copied, as OpenSSL keeps the pointer), or NULL; during a
    /// walk, a level's input type for the levels under it.
    pub(crate) start_input_type: *const c_char,
    /// The application's string, or NULL.
    pub(crate) input_structure: *const c_char,
    pub(crate) selection: c_int,
    pub(crate) insts: Vec<*mut OSSL_DECODER_INSTANCE>,
    pub(crate) construct: OSSL_DECODER_CONSTRUCT,
    pub(crate) cleanup: OSSL_DECODER_CLEANUP,
    pub(crate) construct_data: *mut c_void,
    /// Set by the key construct when a key manager couldn't take a decoded key; OSSL_STORE
    /// reads it.
    pub(crate) harderr: bool,
}

/// A decoder context (`OSSL_DECODER_CTX`).
pub(crate) struct Ctx {
    state: Mutex<State>,
    /// The passphrase source, at a fixed address the passphrase callback gets.
    pw: UnsafeCell<PwData>,
}

// SAFETY: OpenSSL's contexts are for one thread at a time; the state is behind a lock, and the
// passphrase data is only changed by the context's own functions, never during a decode.
unsafe impl Sync for Ctx {}
// SAFETY: as above.
unsafe impl Send for Ctx {}

handle_type!(OSSL_DECODER_CTX => Ctx);

impl Ctx {
    /// The state, locked (never across a callback).
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The passphrase data's address, for the passphrase callback.
    fn pw(&self) -> *mut PwData {
        self.pw.get()
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        let st = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        if let Some(cleanup) = st.cleanup {
            // SAFETY: the application's cleanup with its data, as OpenSSL calls it.
            unsafe { cleanup(st.construct_data) };
        }
        for &i in &st.insts {
            // SAFETY: the context's own instances, freed once.
            unsafe { OSSL_DECODER_INSTANCE::free(i) };
        }
    }
}

/// The context behind a handle, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn ctx<'a>(ctx: *const OSSL_DECODER_CTX) -> Option<&'a Ctx> {
    // SAFETY: the caller's guarantee.
    unsafe { OSSL_DECODER_CTX::get(ctx) }
}

/// A C string argument, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

/// Raises `ERR_R_PASSED_NULL_PARAMETER` from `func` for a NULL context.
#[track_caller]
fn null_ctx(func: &str) {
    err::raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER, func);
}

/// `ossl_decoder_ctx_add_decoder_inst`: the instance added to the context's chain (which then
/// owns it). False, with the instance freed, never: pushing can't fail here.
pub(crate) fn add_decoder_inst(c: &Ctx, inst: *mut OSSL_DECODER_INSTANCE) {
    c.lock().insts.push(inst);
}

/// The core BIO a decoder reads (`ossl_core_bio_new_from_bio`): the BIO, with a reference.
///
/// # Safety
/// `bio` is a live BIO.
pub(crate) unsafe fn core_bio_new_from_bio(bio: *mut BIO) -> *mut OSSL_CORE_BIO {
    // SAFETY: the caller's guarantee.
    if unsafe { BIO_up_ref(bio) } == 0 {
        return ptr::null_mut();
    }
    bio.cast()
}

/// `ossl_bio_new_from_core_bio`, for the default provider's decoders: a BIO reading the core
/// BIO, with a reference the caller frees.
///
/// # Safety
/// `cbio` is a live core BIO.
pub(crate) unsafe fn bio_new_from_core_bio(cbio: *mut OSSL_CORE_BIO) -> *mut BIO {
    let bio: *mut BIO = cbio.cast();
    // SAFETY: the caller's guarantee; a core BIO is a BIO here.
    if unsafe { BIO_up_ref(bio) } == 0 {
        return ptr::null_mut();
    }
    bio
}

/// `BIO_tell`.
///
/// # Safety
/// `bio` is a live BIO.
unsafe fn tell(bio: *mut BIO) -> c_long {
    // SAFETY: the caller's guarantee.
    unsafe { BIO_ctrl(bio, BIO_C_FILE_TELL, 0, ptr::null_mut()) }
}

/// `decoder_process_data_st`.
struct Process {
    ctx: *mut OSSL_DECODER_CTX,
    bio: *mut BIO,
    current_decoder_inst_index: usize,
    recursion: usize,
    flag_next_level_called: bool,
    flag_construct_called: bool,
    flag_input_structure_checked: bool,
}

/// A UTF-8 string parameter's pointer (`OSSL_PARAM_get_utf8_string_ptr`), `Err` if it isn't one.
///
/// # Safety
/// `params` is an array.
unsafe fn utf8_param(params: *const OSSL_PARAM, key: &CStr) -> Result<*const c_char, ()> {
    // SAFETY: the caller's array; a static name.
    let p = unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
    if p.is_null() {
        return Ok(ptr::null());
    }
    let mut s: *const c_char = ptr::null();
    // SAFETY: a parameter of the array; a local.
    if unsafe { OSSL_PARAM_get_utf8_string_ptr(p, &raw mut s) } == 0 {
        return Err(());
    }
    Ok(s)
}

/// Whether two C strings are equal ignoring ASCII case (`OPENSSL_strcasecmp(a, b) == 0`).
///
/// # Safety
/// `a` and `b` are strings.
unsafe fn eq_case(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: the caller's guarantee.
    let x = unsafe { CStr::from_ptr(a) };
    // SAFETY: as above.
    let y = unsafe { CStr::from_ptr(b) };
    x.to_bytes().eq_ignore_ascii_case(y.to_bytes())
}

/// `decoder_process`: a level of the walk, as an `OSSL_CALLBACK` the decoders call with what they
/// pass on (`params`), or the top level (NULL `params`).
///
/// # Safety
/// `arg` is a live `Process`; `params` is NULL or an array.
unsafe extern "C" fn decoder_process(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(data) = (unsafe { arg.cast::<Process>().as_mut() }) else {
        return 0;
    };
    let ctx_h = data.ctx;
    // SAFETY: the walk's live context.
    let Some(c) = (unsafe { ctx(ctx_h) }) else {
        return 0;
    };
    data.flag_next_level_called = true;
    let mut new_data = Process {
        ctx: ctx_h,
        bio: ptr::null_mut(),
        current_decoder_inst_index: 0,
        recursion: data.recursion.saturating_add(1),
        flag_next_level_called: false,
        flag_construct_called: false,
        flag_input_structure_checked: false,
    };
    let start_input_type = c.lock().start_input_type;
    let mut ok = 0;
    let mut decoder_h: *mut OSSL_DECODER = ptr::null_mut();
    let mut data_type: *const c_char = ptr::null();
    let mut data_structure: *const c_char = ptr::null();
    let mut bio = data.bio;
    'end: {
        if params.is_null() {
            data.current_decoder_inst_index = c.lock().insts.len();
        } else {
            let inst_h = c
                .lock()
                .insts
                .get(data.current_decoder_inst_index)
                .copied()
                .unwrap_or(ptr::null_mut());
            // SAFETY: an instance of the context.
            let Some(inst) = (unsafe { instance(inst_h) }) else {
                break 'end;
            };
            decoder_h = inst.decoder.0;
            data.flag_construct_called = false;
            let (construct, construct_data) = {
                let st = c.lock();
                (st.construct, st.construct_data)
            };
            if let Some(f) = construct {
                // SAFETY: the application's constructor with the instance, the decoder's
                // parameters, and its data; no lock is held.
                let rv = unsafe { f(inst_h, params, construct_data) };
                ok = c_int::from(rv > 0);
                if ok != 0 {
                    data.flag_construct_called = true;
                    break 'end;
                }
            }
            // SAFETY: the decoder's array; a static name.
            let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA.as_ptr()) };
            // SAFETY: a parameter of the array, or NULL.
            let Some(pd) = (unsafe { p.as_ref() })
                .filter(|p| p.data_type == OSSL_PARAM_OCTET_STRING.cast_unsigned())
            else {
                break 'end;
            };
            // OpenSSL passes the size as an int, cut short past INT_MAX; this fails instead.
            let Ok(n) = c_int::try_from(pd.data_size) else {
                break 'end;
            };
            // SAFETY: the parameter's octets, which outlive the level.
            new_data.bio = unsafe { crate::bio::mem::BIO_new_mem_buf(pd.data, n) };
            if new_data.bio.is_null() {
                break 'end;
            }
            bio = new_data.bio;
            // SAFETY: the decoder's array.
            let Ok(t) = (unsafe { utf8_param(params, OSSL_OBJECT_PARAM_DATA_TYPE) }) else {
                break 'end;
            };
            data_type = t;
            // SAFETY: as above.
            let Ok(s) = (unsafe { utf8_param(params, OSSL_OBJECT_PARAM_DATA_STRUCTURE) }) else {
                break 'end;
            };
            data_structure = s;
            // SAFETY: the decoder's array; a static name.
            let pi =
                unsafe { OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_INPUT_TYPE.as_ptr()) };
            if !pi.is_null() {
                let mut it: *const c_char = ptr::null();
                // SAFETY: a parameter of the array; a local.
                if unsafe { OSSL_PARAM_get_utf8_string_ptr(pi, &raw mut it) } == 0 {
                    break 'end;
                }
                let mut st = c.lock();
                st.start_input_type = it;
                let is = st.input_structure;
                drop(st);
                // SAFETY: the application's string and the decoder's, when not NULL.
                let checked = !is.is_null()
                    && (unsafe { eq_case(is, c"SubjectPublicKeyInfo".as_ptr()) }
                        || (!data_structure.is_null()
                            && unsafe { eq_case(data_structure, c"PrivateKeyInfo".as_ptr()) })
                        || unsafe { eq_case(is, c"PrivateKeyInfo".as_ptr()) });
                if checked {
                    data.flag_input_structure_checked = true;
                }
            }
            // SAFETY: the decoder's strings, when not NULL.
            if !data_type.is_null()
                && !data_structure.is_null()
                // SAFETY: the decoder's string.
                && unsafe { eq_case(data_structure, c"type-specific".as_ptr()) }
            {
                data_structure = ptr::null();
            }
        }
        if data.current_decoder_inst_index == 0 {
            break 'end;
        }
        // SAFETY: the level's live BIO.
        let loc = unsafe { tell(bio) };
        if loc < 0 {
            err::raise(ERR_LIB_OSSL_DECODER, ERR_R_BIO_LIB, "decoder_process");
            break 'end;
        }
        // SAFETY: as above.
        let cbio = unsafe { core_bio_new_from_bio(bio) };
        if cbio.is_null() {
            err::raise(ERR_LIB_OSSL_DECODER, ERR_R_BIO_LIB, "decoder_process");
            break 'end;
        }
        // SAFETY: the decoder of the level above, when there is one.
        let prev = unsafe { decoder(decoder_h) };
        let mut i = data.current_decoder_inst_index;
        while i > 0 {
            i -= 1;
            let (new_inst_h, start, input_structure, selection) = {
                let st = c.lock();
                (
                    st.insts.get(i).copied().unwrap_or(ptr::null_mut()),
                    st.start_input_type,
                    st.input_structure,
                    st.selection,
                )
            };
            // SAFETY: an instance of the context.
            let Some(new_inst) = (unsafe { instance(new_inst_h) }) else {
                continue;
            };
            let new_decoder = new_inst.decoder();
            let new_input_type = new_inst.input_type();
            let new_input_structure = new_inst.input_structure();
            // SAFETY: the application's string, when not NULL.
            if prev.is_none()
                && !start.is_null()
                // SAFETY: the application's string.
                && !unsafe { eq_case(start, new_input_type.as_ptr()) }
            {
                continue;
            }
            if let Some(p) = prev
                && !fast_is_a(p, new_input_type, &new_inst.input_type_id)
            {
                continue;
            }
            // SAFETY: the decoder's string, when not NULL.
            if !data_type.is_null()
                // SAFETY: the decoder's string.
                && !new_decoder.is_a(unsafe { CStr::from_ptr(data_type) }.to_bytes())
            {
                continue;
            }
            if !data_structure.is_null() {
                // SAFETY: as above.
                let matches = new_input_structure
                    .is_some_and(|s| unsafe { eq_case(data_structure, s.as_ptr()) });
                if !matches {
                    continue;
                }
            }
            if !data.flag_input_structure_checked
                && !input_structure.is_null()
                && let Some(s) = new_input_structure
            {
                data.flag_input_structure_checked = true;
                // SAFETY: the application's string.
                if !unsafe { eq_case(s.as_ptr(), input_structure) } {
                    continue;
                }
            }
            // SAFETY: the level's BIO.
            unsafe { BIO_ctrl(bio, BIO_C_FILE_SEEK, loc, ptr::null_mut()) };
            // SAFETY: as above.
            if unsafe { tell(bio) } != loc {
                break;
            }
            // SAFETY: no preconditions.
            unsafe { ERR_set_mark() };
            new_data.current_decoder_inst_index = i;
            new_data.flag_input_structure_checked = data.flag_input_structure_checked;
            let Some(decode) = new_decoder.funcs.decode else {
                continue;
            };
            let cb: OSSL_CALLBACK = Some(decoder_process);
            let pw_cb: OSSL_PASSPHRASE_CALLBACK = Some(passphrase_callback_dec);
            // SAFETY: the decoder's function with its context, the core BIO, the walk's next
            // level, and the context's passphrase data; no lock is held.
            ok = unsafe {
                decode(
                    new_inst.ctx.0,
                    cbio,
                    selection,
                    cb,
                    (&raw mut new_data).cast(),
                    pw_cb,
                    c.pw().cast(),
                )
            };
            data.flag_construct_called = new_data.flag_construct_called;
            if ok == 0 || data.flag_construct_called {
                // SAFETY: the mark set above.
                unsafe { ERR_clear_last_mark() };
                break;
            }
            // SAFETY: as above.
            unsafe { ERR_pop_to_mark() };
            if new_data.flag_next_level_called {
                break;
            }
        }
        // SAFETY: the reference taken above.
        unsafe { BIO_free(cbio.cast()) };
    }
    if !new_data.bio.is_null() {
        // SAFETY: the level's own BIO.
        unsafe { BIO_free(new_data.bio) };
    }
    c.lock().start_input_type = start_input_type;
    ok
}

/// `OSSL_DECODER_from_bio`.
///
/// # Safety
/// `ctx_h` is NULL or a live context; `input` is NULL or a live BIO.
unsafe fn from_bio(ctx_h: *mut OSSL_DECODER_CTX, input: *mut BIO) -> c_int {
    const F: &str = "OSSL_DECODER_from_bio";
    if input.is_null() {
        null_ctx(F);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { OSSL_DECODER_CTX::hold(ctx_h) }) else {
        err::raise_with_text(
            ERR_LIB_OSSL_DECODER,
            OSSL_DECODER_R_DECODER_NOT_FOUND,
            F,
            "No decoders were found. For standard decoders you need at least one of the default or base providers available. Did you forget to load them?",
        );
        return 0;
    };
    if c.lock().insts.is_empty() {
        err::raise_with_text(
            ERR_LIB_OSSL_DECODER,
            OSSL_DECODER_R_DECODER_NOT_FOUND,
            F,
            "No decoders were found. For standard decoders you need at least one of the default or base providers available. Did you forget to load them?",
        );
        return 0;
    }
    // SAFETY: no preconditions.
    let lasterr = unsafe { ERR_peek_last_error() };
    let mut bio = input;
    let mut new_bio = ptr::null_mut();
    // SAFETY: the caller's live BIO.
    if unsafe { tell(bio) } < 0 {
        // SAFETY: no preconditions.
        let method = unsafe { crate::bio::buffer::BIO_f_readbuffer() };
        // SAFETY: a static method.
        new_bio = unsafe { BIO_new(method) };
        if new_bio.is_null() {
            return 0;
        }
        // SAFETY: the new filter over the caller's BIO.
        bio = unsafe { BIO_push(new_bio, bio) };
    }
    let mut data = Process {
        ctx: ctx_h,
        bio,
        current_decoder_inst_index: 0,
        recursion: 0,
        flag_next_level_called: false,
        flag_construct_called: false,
        flag_input_structure_checked: false,
    };
    // SAFETY: the context's passphrase data, changed only by its own functions.
    unsafe { (*c.pw()).enable_caching() };
    // SAFETY: the walk's data, live through the call.
    let mut ok = unsafe { decoder_process(ptr::null(), (&raw mut data).cast()) };
    if !data.flag_construct_called {
        let (start, structure) = {
            let st = c.lock();
            (st.start_input_type, st.input_structure)
        };
        // SAFETY: the application's strings, or NULL.
        let start = unsafe { text(start) };
        // SAFETY: as above.
        let structure = unsafe { text(structure) };
        let spaces = if start.is_some() && structure.is_some() {
            " "
        } else {
            ""
        };
        let comma = if start.is_some() && structure.is_some() {
            ", "
        } else {
            ""
        };
        let type_label = if start.is_some() { "Input type: " } else { "" };
        let structure_label = if structure.is_some() {
            "Input structure: "
        } else {
            ""
        };
        let show =
            |s: Option<&CStr>| s.map_or_else(String::new, |s| s.to_string_lossy().into_owned());
        // SAFETY: no preconditions.
        if unsafe { ERR_peek_last_error() } == lasterr || unsafe { ERR_peek_error() } == 0 {
            err::raise_with_text(
                ERR_LIB_OSSL_DECODER,
                ERR_R_UNSUPPORTED,
                F,
                &format!(
                    "No supported data to decode. {spaces}{type_label}{}{comma}{structure_label}{}",
                    show(start),
                    show(structure)
                ),
            );
        }
        ok = 0;
    }
    // SAFETY: as above.
    unsafe { (*c.pw()).clear_cache() };
    if !new_bio.is_null() {
        // SAFETY: the filter pushed above, taken off and freed.
        unsafe { BIO_pop(new_bio) };
        // SAFETY: as above.
        unsafe { BIO_free(new_bio) };
    }
    ok
}

ffi_export! {
    /// A new, empty decoder context.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_new() -> *mut OSSL_DECODER_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_DECODER
    {
        OSSL_DECODER_CTX::new_handle(Ctx {
            state: Mutex::new(State {
                start_input_type: ptr::null(),
                input_structure: ptr::null(),
                selection: 0,
                insts: Vec::new(),
                construct: None,
                cleanup: None,
                construct_data: ptr::null_mut(),
                harderr: false,
            }),
            pw: UnsafeCell::new(PwData::default()),
        })
    }
}

ffi_export! {
    /// Frees a context: its cleanup runs with its construct data, then its instances and
    /// passphrase go. NULL does nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context the caller gives up.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_free(ctx: *mut OSSL_DECODER_CTX)
    where failure = (), library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { OSSL_DECODER_CTX::free(ctx) };
    }
}

ffi_export! {
    /// Gives `params` to each instance's decoder that takes context parameters. 1 if all took
    /// them (or there are no instances), else 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `params` is NULL or an array.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_set_params(ctx_: *mut OSSL_DECODER_CTX, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(ctx_) }) else {
            null_ctx("OSSL_DECODER_CTX_set_params");
            return 0;
        };
        let insts = c.lock().insts.clone();
        let mut ok = 1;
        for i in insts {
            // SAFETY: an instance of the context.
            let Some(inst) = (unsafe { instance(i) }) else { continue };
            let Some(set) = inst.decoder().funcs.set_ctx_params else { continue };
            if inst.ctx.0.is_null() {
                continue;
            }
            // SAFETY: the decoder's function with its context and the caller's array.
            if unsafe { set(inst.ctx.0, params) } == 0 {
                ok = 0;
            }
        }
        ok
    }
}

/// Sets one field of a context's state; 0 (with an error) for NULL.
///
/// # Safety
/// `ctx_` is NULL or a live context.
unsafe fn set_field(ctx_: *mut OSSL_DECODER_CTX, func: &str, f: impl FnOnce(&mut State)) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(ctx_) }) else {
        null_ctx(func);
        return 0;
    };
    f(&mut c.lock());
    1
}

ffi_export! {
    /// Sets what is to be decoded (`OSSL_KEYMGMT_SELECT_*`). 1, or 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_set_selection(ctx_: *mut OSSL_DECODER_CTX, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_field(ctx_, "OSSL_DECODER_CTX_set_selection", |s| s.selection = selection) }
    }
}

ffi_export! {
    /// Sets the input's type (the string is kept, not copied). 1, or 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `input_type` is NULL or a string that outlives its use.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_set_input_type(ctx_: *mut OSSL_DECODER_CTX, input_type: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_field(ctx_, "OSSL_DECODER_CTX_set_input_type", |s| s.start_input_type = input_type) }
    }
}

ffi_export! {
    /// Sets the input's structure (the string is kept, not copied). 1, or 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `input_structure` is NULL or a string that outlives its
    /// use.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_set_input_structure(ctx_: *mut OSSL_DECODER_CTX, input_structure: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_field(ctx_, "OSSL_DECODER_CTX_set_input_structure", |s| s.input_structure = input_structure) }
    }
}

ffi_export! {
    /// Sets the constructor of what's decoded. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_set_construct(ctx_: *mut OSSL_DECODER_CTX, construct: OSSL_DECODER_CONSTRUCT) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_field(ctx_, "OSSL_DECODER_CTX_set_construct", |s| s.construct = construct) }
    }
}

ffi_export! {
    /// Sets the constructor's data. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_set_construct_data(ctx_: *mut OSSL_DECODER_CTX, construct_data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_field(ctx_, "OSSL_DECODER_CTX_set_construct_data", |s| s.construct_data = construct_data) }
    }
}

ffi_export! {
    /// Sets the cleanup the context's freeing runs with the construct data. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_set_cleanup(ctx_: *mut OSSL_DECODER_CTX, cleanup: OSSL_DECODER_CLEANUP) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_field(ctx_, "OSSL_DECODER_CTX_set_cleanup", |s| s.cleanup = cleanup) }
    }
}

ffi_export! {
    /// The constructor, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_get_construct(ctx_: *mut OSSL_DECODER_CTX) -> OSSL_DECODER_CONSTRUCT
    where failure = None, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx(ctx_) }.and_then(|c| c.lock().construct)
    }
}

ffi_export! {
    /// The constructor's data, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_get_construct_data(ctx_: *mut OSSL_DECODER_CTX) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx(ctx_) }.map_or(ptr::null_mut(), |c| c.lock().construct_data)
    }
}

ffi_export! {
    /// The cleanup, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_get_cleanup(ctx_: *mut OSSL_DECODER_CTX) -> OSSL_DECODER_CLEANUP
    where failure = None, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx(ctx_) }.and_then(|c| c.lock().cleanup)
    }
}

ffi_export! {
    /// The number of the context's decoder instances (0 for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_get_num_decoders(ctx_: *mut OSSL_DECODER_CTX) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx(ctx_) }.map_or(0, |c| c_int::try_from(c.lock().insts.len()).unwrap_or(c_int::MAX))
    }
}

ffi_export! {
    /// Adds an instance of the decoder (with a new context) to the context. 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `decoder` is NULL or a live decoder.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_add_decoder(ctx_: *mut OSSL_DECODER_CTX, decoder_: *mut OSSL_DECODER) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        let (Some(c), Some(d)) = (unsafe { ctx(ctx_) }, unsafe { decoder(decoder_) }) else {
            null_ctx("OSSL_DECODER_CTX_add_decoder");
            return 0;
        };
        let Some(newctx) = d.funcs.newctx else { return 0 };
        // SAFETY: the decoder's function with its provider's context.
        let dctx = unsafe { newctx(d.provider_ctx()) };
        if dctx.is_null() {
            return 0;
        }
        // SAFETY: the caller's decoder; its new context, which the instance takes.
        let inst = unsafe { instance_new(decoder_, dctx) };
        if inst.is_null() {
            return 0;
        }
        add_decoder_inst(c, inst);
        1
    }
}

/// `collect_extra_decoder`'s data.
struct Extra<'a> {
    c: &'a Ctx,
    output_type: CString,
    output_type_id: AtomicU32,
    /// `IS_SAME` (false) or `IS_DIFFERENT` (true).
    different: bool,
    w_prev_start: usize,
    w_new_end: usize,
}

/// `collect_extra_decoder`: an instance of `d` added if its name is the output type, it isn't
/// already in the window, it takes the context's input structure, and its input type is (or,
/// for the second pass, isn't) its own name.
///
/// # Safety
/// `decoder_h` is a live decoder.
unsafe fn collect_extra(decoder_h: *mut OSSL_DECODER, x: &mut Extra<'_>) {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { decoder(decoder_h) }) else {
        return;
    };
    if !fast_is_a(d, &x.output_type, &x.output_type_id) {
        return;
    }
    let (in_window, input_structure) = {
        let st = x.c.lock();
        let window = st
            .insts
            .get(x.w_prev_start..x.w_new_end)
            .unwrap_or_default();
        let dup = window.iter().any(|&i| {
            // SAFETY: an instance of the context.
            unsafe { instance(i) }.is_some_and(|inst| inst.decoder().algodef.0 == d.algodef.0)
        });
        (dup, st.input_structure)
    };
    if in_window {
        return;
    }
    // SAFETY: the decoder; the application's string, or NULL.
    let dctx = unsafe { new_decoder_ctx(d, input_structure) };
    if dctx.is_null() {
        return;
    }
    // SAFETY: the decoder; its new context, which the instance takes.
    let di = unsafe { instance_new(decoder_h, dctx) };
    // SAFETY: just made, or NULL.
    let Some(inst) = (unsafe { instance(di) }) else {
        return;
    };
    let same = fast_is_a(d, inst.input_type(), &inst.input_type_id);
    if same == x.different {
        // SAFETY: made above, not added.
        unsafe { OSSL_DECODER_INSTANCE::free(di) };
        return;
    }
    add_decoder_inst(x.c, di);
    x.w_new_end += 1;
}

ffi_export! {
    /// Adds the decoders that can feed the context's instances (those whose name is an
    /// instance's input type, of the library context's providers), level by level, at most ten
    /// levels deep. 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `libctx` is NULL or a live library context; `propq` is
    /// NULL or a string.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_add_extra(ctx_: *mut OSSL_DECODER_CTX, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(ctx_) }) else {
            null_ctx("OSSL_DECODER_CTX_add_extra");
            return 0;
        };
        if c.lock().insts.is_empty() {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let decoders = unsafe { super::all(libctx) };
        // SAFETY: as above.
        if !propq.is_null() || unsafe { crate::evp::fetch::has_global_properties(libctx) } {
            let mut st = c.lock();
            for (n, &i) in st.insts.iter().enumerate() {
                // SAFETY: an instance of the context.
                if let Some(inst) = unsafe { instance(i) } {
                    inst.order.store(c_int::try_from(n).unwrap_or(c_int::MAX), Ordering::Relaxed);
                }
            }
            st.insts.sort_by_key(|&i| {
                // SAFETY: as above.
                unsafe { instance(i) }.map_or((0, 0), |inst| (inst.score.load(Ordering::Relaxed), inst.order.load(Ordering::Relaxed)))
            });
        }
        let mut w_prev_start = 0;
        let mut w_prev_end = c.lock().insts.len();
        let mut depth = 0;
        loop {
            let w_new_start = w_prev_end;
            let mut x = Extra {
                c,
                output_type: CString::default(),
                output_type_id: AtomicU32::new(0),
                different: false,
                w_prev_start,
                w_new_end: w_new_start,
            };
            for different in [false, true] {
                x.different = different;
                for i in w_prev_start..w_prev_end {
                    let inst_h = c.lock().insts.get(i).copied().unwrap_or(ptr::null_mut());
                    // SAFETY: an instance of the context.
                    let Some(inst) = (unsafe { instance(inst_h) }) else { continue };
                    x.output_type = inst.input_type().to_owned();
                    x.output_type_id = AtomicU32::new(0);
                    for m in &decoders {
                        // SAFETY: a decoder held by the list.
                        unsafe { collect_extra(m.as_ptr().cast(), &mut x) };
                    }
                }
            }
            let count = x.w_new_end - w_new_start;
            w_prev_start = w_new_start;
            w_prev_end = x.w_new_end;
            depth += 1;
            if count == 0 || depth > MAX_EXTRA_DEPTH {
                break;
            }
        }
        1
    }
}

ffi_export! {
    /// Decodes from the BIO with the context's decoders. 1 if something was constructed, else 0
    /// (with OpenSSL's "No supported data to decode" error when the decoders left none).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `in_` is NULL or a live BIO.
    pub unsafe extern "C" fn OSSL_DECODER_from_bio(ctx_: *mut OSSL_DECODER_CTX, in_: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { from_bio(ctx_, in_) }
    }
}

ffi_export! {
    /// As `OSSL_DECODER_from_bio`, from a file (not closed).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `fp` is a live file.
    pub unsafe extern "C" fn OSSL_DECODER_from_fp(ctx_: *mut OSSL_DECODER_CTX, fp: *mut FILE) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: no preconditions.
        let method = unsafe { crate::bio::file::BIO_s_file() };
        // SAFETY: a static method.
        let b = unsafe { BIO_new(method) };
        if b.is_null() {
            err::raise(ERR_LIB_OSSL_DECODER, ERR_R_BIO_LIB, "bio_from_file");
            return 0;
        }
        // SAFETY: the new file BIO; the caller's file, not closed.
        unsafe { BIO_ctrl(b, BIO_C_SET_FILE_PTR, c_long::from(BIO_NOCLOSE), fp.cast()) };
        // SAFETY: the caller's guarantee; the BIO.
        let ret = unsafe { from_bio(ctx_, b) };
        // SAFETY: made above.
        unsafe { BIO_free(b) };
        ret
    }
}

ffi_export! {
    /// As `OSSL_DECODER_from_bio`, from `*pdata_len` octets at `*pdata`; on success both move
    /// past what was decoded.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `pdata` and `pdata_len` are NULL or writable, `*pdata`
    /// holding `*pdata_len` octets.
    pub unsafe extern "C" fn OSSL_DECODER_from_data(ctx_: *mut OSSL_DECODER_CTX, pdata: *mut *const c_uchar, pdata_len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        if pdata.is_null() || unsafe { pdata.read() }.is_null() || pdata_len.is_null() {
            null_ctx("OSSL_DECODER_from_data");
            return 0;
        }
        // SAFETY: as above.
        let data = unsafe { pdata.read() };
        // SAFETY: as above.
        let len = unsafe { pdata_len.read() };
        // OpenSSL passes the length as an int, cut short past INT_MAX; this fails instead.
        let Ok(n) = c_int::try_from(len) else { return 0 };
        // SAFETY: the caller's octets, read during the call.
        let membio = unsafe { crate::bio::mem::BIO_new_mem_buf(data.cast(), n) };
        let mut ret = 0;
        // SAFETY: the caller's guarantee; the BIO, or NULL.
        if unsafe { from_bio(ctx_, membio) } != 0 {
            let mut rest: *mut c_char = ptr::null_mut();
            // SAFETY: the memory BIO; a local.
            let left = unsafe { BIO_ctrl(membio, BIO_CTRL_INFO, 0, (&raw mut rest).cast()) };
            // SAFETY: the caller's guarantee.
            unsafe { pdata.write(rest.cast_const().cast()) };
            // SAFETY: as above.
            unsafe { pdata_len.write(usize::try_from(left).unwrap_or(0)) };
            ret = 1;
        }
        // SAFETY: made above, or NULL.
        unsafe { BIO_free(membio) };
        ret
    }
}

/// Changes the context's passphrase data with `f`; 0 (with an error) for NULL.
///
/// # Safety
/// `ctx_` is NULL or a live context, not decoding.
unsafe fn with_pw(ctx_: *mut OSSL_DECODER_CTX, f: impl FnOnce(&mut PwData) -> bool) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(ctx_) }) else {
        return 0;
    };
    // SAFETY: the context's own data, changed only here and never during a decode.
    c_int::from(f(unsafe { &mut *c.pw() }))
}

ffi_export! {
    /// Sets a copy of the passphrase. 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `kstr` is NULL or holds `klen` octets.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_set_passphrase(ctx_: *mut OSSL_DECODER_CTX, kstr: *const c_uchar, klen: usize) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { crate::ffi::bytes(kstr, klen) }).filter(|_| !kstr.is_null()) else {
            err::raise(rustyssl_abi::ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, "ossl_pw_set_passphrase");
            return 0;
        };
        // SAFETY: the caller's guarantee.
        unsafe { with_pw(ctx_, |pw| {
            pw.set_passphrase(k);
            true
        }) }
    }
}

ffi_export! {
    /// Sets the UI method that asks for the passphrase. 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `ui_method` is NULL or a live method that outlives its use.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_set_passphrase_ui(ctx_: *mut OSSL_DECODER_CTX, ui_method: *const UI_METHOD, ui_data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { with_pw(ctx_, |pw| pw.set_ui_method(ui_method, ui_data)) }
    }
}

ffi_export! {
    /// Sets the PEM password callback that gives the passphrase. 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `cb` takes `cbarg`.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_set_pem_password_cb(ctx_: *mut OSSL_DECODER_CTX, cb: pem_password_cb, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { with_pw(ctx_, |pw| pw.set_pem_password_cb(cb, cbarg)) }
    }
}

ffi_export! {
    /// Sets the passphrase callback. 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `cb` takes `cbarg`.
    pub unsafe extern "C" fn OSSL_DECODER_CTX_set_passphrase_cb(ctx_: *mut OSSL_DECODER_CTX, cb: OSSL_PASSPHRASE_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { with_pw(ctx_, |pw| pw.set_ossl_passphrase_cb(cb, cbarg)) }
    }
}

ffi_export! {
    /// Has the instance's decoder export the object `reference` names (`export_object`).
    ///
    /// # Safety
    /// The arguments are NULL or what the decoder's `export_object` takes.
    pub unsafe extern "C" fn OSSL_DECODER_export(decoder_inst: *mut OSSL_DECODER_INSTANCE, reference: *mut c_void, reference_sz: usize, export_cb: OSSL_CALLBACK, export_cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        let inst = unsafe { instance(decoder_inst) };
        let (Some(inst), false, Some(_), false) = (inst, reference.is_null(), export_cb, export_cbarg.is_null()) else {
            null_ctx("OSSL_DECODER_export");
            return 0;
        };
        let Some(export) = inst.decoder().funcs.export_object else { return 0 };
        // SAFETY: the decoder's function with its context and the caller's arguments.
        unsafe { export(inst.ctx.0, reference, reference_sz, export_cb, export_cbarg) }
    }
}

ffi_export! {
    /// The instance's decoder, or NULL.
    ///
    /// # Safety
    /// `decoder_inst` is NULL or a live instance.
    pub unsafe extern "C" fn OSSL_DECODER_INSTANCE_get_decoder(decoder_inst: *mut OSSL_DECODER_INSTANCE) -> *mut OSSL_DECODER
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { instance(decoder_inst) }.map_or(ptr::null_mut(), |i| i.decoder.0)
    }
}

ffi_export! {
    /// The instance's decoder context, or NULL.
    ///
    /// # Safety
    /// `decoder_inst` is NULL or a live instance.
    pub unsafe extern "C" fn OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst: *mut OSSL_DECODER_INSTANCE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { instance(decoder_inst) }.map_or(ptr::null_mut(), |i| i.ctx.0)
    }
}

ffi_export! {
    /// The instance's input type, or NULL.
    ///
    /// # Safety
    /// `decoder_inst` is NULL or a live instance.
    pub unsafe extern "C" fn OSSL_DECODER_INSTANCE_get_input_type(decoder_inst: *mut OSSL_DECODER_INSTANCE) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { instance(decoder_inst) }.map_or(ptr::null(), |i| i.input_type.as_ptr())
    }
}

ffi_export! {
    /// The instance's input structure (NULL for none), whether it was set into `*was_set`.
    ///
    /// # Safety
    /// `decoder_inst` is NULL or a live instance; `was_set` is writable.
    pub unsafe extern "C" fn OSSL_DECODER_INSTANCE_get_input_structure(decoder_inst: *mut OSSL_DECODER_INSTANCE, was_set: *mut c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_DECODER
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { instance(decoder_inst) }) else { return ptr::null() };
        if !was_set.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { was_set.write(c_int::from(i.flag_input_structure_was_set)) };
        }
        i.input_structure.as_ref().map_or(ptr::null(), |s| s.as_ptr())
    }
}

/// The first instance of a context, for tests.
#[cfg(test)]
pub(crate) fn ctx_first_instance(c: *mut OSSL_DECODER_CTX) -> *mut OSSL_DECODER_INSTANCE {
    // SAFETY: a live context in the test.
    unsafe { ctx(c) }
        .and_then(|c| c.lock().insts.first().copied())
        .unwrap_or(ptr::null_mut())
}
