//! Encoder contexts (`OSSL_ENCODER_CTX(3)`, `OSSL_ENCODER_to_bio(3)`; `encoder_lib.c`,
//! `encoder_meth.c`, `encoder_pkey.c`'s passphrase setters): the instances of the encoders
//! added, the output type, structure, and selection asked for, the construct that gives the
//! object to encode, and the passphrase source; and `encoder_process`'s chain, from the last
//! instance added backwards.
//!
//! As in OpenSSL, the chain's top encoder must give the output type, and each encoder below it
//! gives the input type of the one above it (its output type one of that encoder's names); the
//! output structure, once asked for, must be met by some encoder on the way. The bottom encoder
//! encodes the object the construct gives; each one above encodes the octets of the one below.
//! Freeing a context frees its construct data with `OPENSSL_free`, whatever it is.

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use libc::FILE;
use rustyssl_abi::{
    BIO, BIO_C_GET_BUF_MEM_PTR, BIO_C_SET_FILE_PTR, BIO_NOCLOSE, BUF_MEM, ERR_LIB_OSSL_DECODER,
    ERR_LIB_OSSL_ENCODER, ERR_R_BUF_LIB, ERR_R_INIT_FAIL, ERR_R_INTERNAL_ERROR,
    ERR_R_INVALID_PROPERTY_DEFINITION, ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_PASSED_NULL_PARAMETER,
    OSSL_ENCODER, OSSL_ENCODER_CLEANUP, OSSL_ENCODER_CONSTRUCT, OSSL_ENCODER_CTX,
    OSSL_ENCODER_INSTANCE, OSSL_ENCODER_PARAM_CIPHER, OSSL_ENCODER_PARAM_PROPERTIES,
    OSSL_ENCODER_R_ENCODER_NOT_FOUND, OSSL_OBJECT_PARAM_DATA, OSSL_OBJECT_PARAM_DATA_STRUCTURE,
    OSSL_OBJECT_PARAM_DATA_TYPE, OSSL_PARAM, OSSL_PASSPHRASE_CALLBACK, UI_METHOD, pem_password_cb,
};

use super::{Encoder, encoder};
use crate::bio::{BIO_ctrl, BIO_free, BIO_new};
use crate::decoder::ctx::core_bio_new_from_bio;
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
};
use crate::passphrase::{PwData, passphrase_callback_enc};
use crate::provider::Ptr;

/// An encoder instance (`OSSL_ENCODER_INSTANCE`): an encoder, its context, and its output type
/// and structure.
pub(crate) struct Instance {
    /// The encoder, with a reference.
    pub(crate) encoder: Ptr<OSSL_ENCODER>,
    /// The encoder's context.
    pub(crate) ctx: Ptr<c_void>,
    output_type: CString,
    output_structure: Option<CString>,
}

handle_type!(OSSL_ENCODER_INSTANCE => Instance);

impl Drop for Instance {
    fn drop(&mut self) {
        // SAFETY: the instance's encoder, live while it holds the reference.
        if let Some(e) = unsafe { encoder(self.encoder.0) }
            && let Some(free) = e.funcs.freectx
        {
            // SAFETY: the encoder's function with its own context.
            unsafe { free(self.ctx.0) };
        }
        // SAFETY: the reference the instance holds.
        unsafe { OSSL_ENCODER::free(self.encoder.0) };
    }
}

impl Instance {
    /// The instance's encoder.
    pub(crate) fn encoder(&self) -> &Encoder {
        // SAFETY: the instance holds a reference to its live encoder.
        match unsafe { encoder(self.encoder.0) } {
            Some(e) => e,
            None => crate::ffi::die("an instance's encoder is live"),
        }
    }
}

/// The instance behind a handle, or `None` for NULL.
///
/// # Safety
/// `inst` is NULL or a live instance.
pub(crate) unsafe fn instance<'a>(inst: *const OSSL_ENCODER_INSTANCE) -> Option<&'a Instance> {
    // SAFETY: the caller's guarantee.
    unsafe { OSSL_ENCODER_INSTANCE::get(inst) }
}

/// A context's state (the fields of `ossl_encoder_ctx_st` but the passphrase).
pub(crate) struct State {
    /// The application's strings (not copied, as OpenSSL keeps the pointers), or NULL.
    output_type: *const c_char,
    output_structure: *const c_char,
    pub(crate) selection: c_int,
    pub(crate) insts: Vec<*mut OSSL_ENCODER_INSTANCE>,
    pub(crate) construct: OSSL_ENCODER_CONSTRUCT,
    pub(crate) construct_data: *mut c_void,
    pub(crate) cleanup: OSSL_ENCODER_CLEANUP,
}

/// An encoder context (`OSSL_ENCODER_CTX`).
pub(crate) struct Ctx {
    state: Mutex<State>,
    /// The passphrase source, at a fixed address the passphrase callback gets.
    pw: UnsafeCell<PwData>,
}

// SAFETY: OpenSSL's contexts are for one thread at a time; the state is behind a lock, and the
// passphrase data is only changed by the context's own functions, never during an encode.
unsafe impl Sync for Ctx {}
// SAFETY: as above.
unsafe impl Send for Ctx {}

handle_type!(OSSL_ENCODER_CTX => Ctx);

impl Ctx {
    /// The state, locked (never across a callback).
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn pw(&self) -> *mut PwData {
        self.pw.get()
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        let st = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        for &i in &st.insts {
            // SAFETY: the context's own instances, freed once.
            unsafe { OSSL_ENCODER_INSTANCE::free(i) };
        }
        // SAFETY: OpenSSL frees the construct data with `OPENSSL_free` (C memory, or NULL).
        unsafe { crate::mem::release(st.construct_data) };
        self.pw.get_mut().clear();
    }
}

/// The context behind a handle, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn ctx<'a>(ctx: *const OSSL_ENCODER_CTX) -> Option<&'a Ctx> {
    // SAFETY: the caller's guarantee.
    unsafe { OSSL_ENCODER_CTX::get(ctx) }
}

/// A C string argument, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

/// Raises `ERR_R_PASSED_NULL_PARAMETER` from `func`.
#[track_caller]
fn null_arg(func: &str) {
    err::raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER, func);
}

ffi_export! {
    /// A new, empty context.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_new() -> *mut OSSL_ENCODER_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_ENCODER
    {
        OSSL_ENCODER_CTX::new_handle(Ctx {
            state: Mutex::new(State {
                output_type: ptr::null(),
                output_structure: ptr::null(),
                selection: 0,
                insts: Vec::new(),
                construct: None,
                construct_data: ptr::null_mut(),
                cleanup: None,
            }),
            pw: UnsafeCell::new(PwData::default()),
        })
    }
}

ffi_export! {
    /// Frees the context, its instances, and its construct data (`OPENSSL_free`). NULL does
    /// nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context the caller gives up.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_free(ctx_: *mut OSSL_ENCODER_CTX)
    where failure = (), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { OSSL_ENCODER_CTX::free(ctx_) };
    }
}

ffi_export! {
    /// Gives the parameters to each instance's encoder context that takes them. 1, or 0 if any
    /// refuses them.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `params` is NULL or an array.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_params(ctx_: *mut OSSL_ENCODER_CTX, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(ctx_) }) else {
            null_arg("OSSL_ENCODER_CTX_set_params");
            return 0;
        };
        let insts = c.lock().insts.clone();
        let mut ok = 1;
        for i in insts {
            // SAFETY: an instance of the context.
            let Some(inst) = (unsafe { instance(i) }) else { continue };
            let Some(set) = inst.encoder().funcs.set_ctx_params else { continue };
            if inst.ctx.0.is_null() {
                continue;
            }
            // SAFETY: the encoder's function with its context and the caller's array.
            if unsafe { set(inst.ctx.0, params) } == 0 {
                ok = 0;
            }
        }
        ok
    }
}

/// A field of the context set; 0 (with an error) for a NULL context.
///
/// # Safety
/// `ctx_` is NULL or a live context.
unsafe fn set_field(ctx_: *mut OSSL_ENCODER_CTX, func: &str, f: impl FnOnce(&mut State)) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(ctx_) }) else {
        null_arg(func);
        return 0;
    };
    f(&mut c.lock());
    1
}

ffi_export! {
    /// Sets the selection (which must not be 0). 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_selection(ctx_: *mut OSSL_ENCODER_CTX, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        if unsafe { ctx(ctx_) }.is_none() {
            null_arg("OSSL_ENCODER_CTX_set_selection");
            return 0;
        }
        if selection == 0 {
            err::raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_INVALID_ARGUMENT, "OSSL_ENCODER_CTX_set_selection");
            return 0;
        }
        // SAFETY: as above.
        unsafe { set_field(ctx_, "OSSL_ENCODER_CTX_set_selection", |s| s.selection = selection) }
    }
}

ffi_export! {
    /// Sets the output type (kept, not copied). 1, or 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `output_type` is NULL or a string that outlives its use.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_output_type(ctx_: *mut OSSL_ENCODER_CTX, output_type: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        if output_type.is_null() {
            null_arg("OSSL_ENCODER_CTX_set_output_type");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { set_field(ctx_, "OSSL_ENCODER_CTX_set_output_type", |s| s.output_type = output_type) }
    }
}

ffi_export! {
    /// Sets the output structure (kept, not copied). 1, or 0 for NULL.
    ///
    /// # Safety
    /// As for `OSSL_ENCODER_CTX_set_output_type`.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_output_structure(ctx_: *mut OSSL_ENCODER_CTX, output_structure: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        if output_structure.is_null() {
            null_arg("OSSL_ENCODER_CTX_set_output_structure");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { set_field(ctx_, "OSSL_ENCODER_CTX_set_output_structure", |s| s.output_structure = output_structure) }
    }
}

/// `ossl_encoder_instance_new`: an instance of the encoder with its context (freed by the
/// caller on failure), its output type and structure from the encoder's properties; NULL with
/// an error.
///
/// # Safety
/// `encoder_h` is a live encoder.
unsafe fn instance_new(
    encoder_h: *mut OSSL_ENCODER,
    encoderctx: *mut c_void,
) -> *mut OSSL_ENCODER_INSTANCE {
    const F: &str = "ossl_encoder_instance_new";
    // SAFETY: the caller's guarantee.
    let Some(e) = (unsafe { encoder(encoder_h) }) else {
        null_arg(F);
        return ptr::null_mut();
    };
    let libctx = e.libctx();
    // SAFETY: the encoder's provider's context.
    let output = unsafe { crate::evp::fetch::string_property(libctx, &e.props, b"output") };
    let Some(output) = output.and_then(|o| CString::new(o).ok()) else {
        // SAFETY: the provider's string, or NULL.
        let props = unsafe { text(e.properties()) }
            .map_or_else(String::new, |p| p.to_string_lossy().into_owned());
        err::raise_with_text(
            ERR_LIB_OSSL_DECODER,
            ERR_R_INVALID_PROPERTY_DEFINITION,
            F,
            &format!(
                "the mandatory 'output' property is missing for encoder {} (properties: {props})",
                e.name().to_string_lossy()
            ),
        );
        return ptr::null_mut();
    };
    // SAFETY: as above.
    let structure = unsafe { crate::evp::fetch::string_property(libctx, &e.props, b"structure") };
    let Ok(output_structure) = structure.map(CString::new).transpose() else {
        return ptr::null_mut();
    };
    // SAFETY: the caller's live encoder; the instance holds the reference.
    if !unsafe { OSSL_ENCODER::up_ref(encoder_h) } {
        err::raise(ERR_LIB_OSSL_ENCODER, ERR_R_INTERNAL_ERROR, F);
        return ptr::null_mut();
    }
    OSSL_ENCODER_INSTANCE::new_handle(Instance {
        encoder: Ptr(encoder_h),
        ctx: Ptr(encoderctx),
        output_type: output,
        output_structure,
    })
}

ffi_export! {
    /// Adds an instance of the encoder (with a new context) to the context. 1, or 0.
    ///
    /// # Safety
    /// `ctx` and `encoder` are NULL or live.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_add_encoder(ctx_: *mut OSSL_ENCODER_CTX, encoder_h: *mut OSSL_ENCODER) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let (Some(c), Some(e)) = (unsafe { ctx(ctx_) }, unsafe { encoder(encoder_h) }) else {
            null_arg("OSSL_ENCODER_CTX_add_encoder");
            return 0;
        };
        let ectx = match e.funcs.newctx {
            // SAFETY: the encoder's function with its provider's context.
            Some(newctx) => unsafe { newctx(e.provider_ctx()) },
            None => ptr::null_mut(),
        };
        if ectx.is_null() {
            return 0;
        }
        // SAFETY: the encoder and its new context.
        let inst = unsafe { instance_new(encoder_h, ectx) };
        if inst.is_null() {
            if let Some(free) = e.funcs.freectx {
                // SAFETY: the context made above.
                unsafe { free(ectx) };
            }
            return 0;
        }
        c.lock().insts.push(inst);
        1
    }
}

ffi_export! {
    /// Adds the encoders that could feed the context's ones: none (as in OpenSSL). 1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_add_extra(_ctx: *mut OSSL_ENCODER_CTX, _libctx: *mut rustyssl_abi::OSSL_LIB_CTX, _propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        1
    }
}

ffi_export! {
    /// How many instances the context has (0 for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_get_num_encoders(ctx_: *mut OSSL_ENCODER_CTX) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx(ctx_) }.map_or(0, |c| c_int::try_from(c.lock().insts.len()).unwrap_or(c_int::MAX))
    }
}

ffi_export! {
    /// Sets the construct. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_construct(ctx_: *mut OSSL_ENCODER_CTX, construct: OSSL_ENCODER_CONSTRUCT) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_field(ctx_, "OSSL_ENCODER_CTX_set_construct", |s| s.construct = construct) }
    }
}

ffi_export! {
    /// Sets the construct's data (which freeing the context frees with `OPENSSL_free`). 1, or
    /// 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `construct_data` is NULL or C memory.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_construct_data(ctx_: *mut OSSL_ENCODER_CTX, construct_data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_field(ctx_, "OSSL_ENCODER_CTX_set_construct_data", |s| s.construct_data = construct_data) }
    }
}

ffi_export! {
    /// Sets the cleanup. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_cleanup(ctx_: *mut OSSL_ENCODER_CTX, cleanup: OSSL_ENCODER_CLEANUP) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_field(ctx_, "OSSL_ENCODER_CTX_set_cleanup", |s| s.cleanup = cleanup) }
    }
}

ffi_export! {
    /// The instance's encoder, or NULL.
    ///
    /// # Safety
    /// `encoder_inst` is NULL or a live instance.
    pub unsafe extern "C" fn OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst: *mut OSSL_ENCODER_INSTANCE) -> *mut OSSL_ENCODER
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { instance(encoder_inst) }.map_or(ptr::null_mut(), |i| i.encoder.0)
    }
}

ffi_export! {
    /// The instance's encoder context, or NULL.
    ///
    /// # Safety
    /// `encoder_inst` is NULL or a live instance.
    pub unsafe extern "C" fn OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst: *mut OSSL_ENCODER_INSTANCE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { instance(encoder_inst) }.map_or(ptr::null_mut(), |i| i.ctx.0)
    }
}

ffi_export! {
    /// The instance's output type, or NULL.
    ///
    /// # Safety
    /// `encoder_inst` is NULL or a live instance.
    pub unsafe extern "C" fn OSSL_ENCODER_INSTANCE_get_output_type(encoder_inst: *mut OSSL_ENCODER_INSTANCE) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { instance(encoder_inst) }.map_or(ptr::null(), |i| i.output_type.as_ptr())
    }
}

ffi_export! {
    /// The instance's output structure, or NULL.
    ///
    /// # Safety
    /// `encoder_inst` is NULL or a live instance.
    pub unsafe extern "C" fn OSSL_ENCODER_INSTANCE_get_output_structure(encoder_inst: *mut OSSL_ENCODER_INSTANCE) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { instance(encoder_inst) }
            .and_then(|i| i.output_structure.as_deref())
            .map_or(ptr::null(), CStr::as_ptr)
    }
}

/// `encoder_process_data_st`.
struct Process {
    ctx: *mut OSSL_ENCODER_CTX,
    bio: *mut BIO,
    current_encoder_inst_index: usize,
    level: c_int,
    next_encoder_inst: *mut OSSL_ENCODER_INSTANCE,
    count_output_structure: c_int,
    prev_encoder_inst: *mut OSSL_ENCODER_INSTANCE,
    running_output: Option<Vec<u8>>,
    data_type: *const c_char,
}

/// The ASCII case-insensitive comparison of two C strings (`OPENSSL_strcasecmp`, equal or not).
///
/// # Safety
/// Both are strings.
unsafe fn eq_case(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: the caller's guarantee.
    let a = unsafe { CStr::from_ptr(a) };
    // SAFETY: as above.
    let b = unsafe { CStr::from_ptr(b) };
    a.to_bytes().eq_ignore_ascii_case(b.to_bytes())
}

/// A memory BIO's octets, taken out of it (`BIO_get_mem_ptr`, then the buffer emptied).
///
/// # Safety
/// `b` is a live memory BIO.
unsafe fn take_mem(b: *mut BIO) -> Vec<u8> {
    let mut buf: *mut BUF_MEM = ptr::null_mut();
    // SAFETY: the caller's BIO; a local for its buffer.
    unsafe { BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, (&raw mut buf).cast()) };
    // SAFETY: the BIO's buffer, or NULL.
    unsafe { buf.as_ref() }
        .and_then(|m| {
            // SAFETY: the buffer's octets.
            unsafe { crate::ffi::bytes(m.data.cast::<u8>(), m.length) }
        })
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

/// `encoder_process`: the chain from the instances below `current_encoder_inst_index`, as
/// OpenSSL walks it: 1 for output written, 0 for a failure, -1 for no encoder fitting.
///
/// # Safety
/// `data.ctx` is a live context; `data.bio` is a live BIO.
unsafe fn process(data: &mut Process) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(data.ctx) }) else {
        return 0;
    };
    let top = data.next_encoder_inst.is_null();
    let (output_type, output_structure, insts, selection, construct, construct_data, cleanup) = {
        let st = c.lock();
        (
            st.output_type,
            st.output_structure,
            st.insts.clone(),
            st.selection,
            st.construct,
            st.construct_data,
            st.cleanup,
        )
    };
    if top {
        data.count_output_structure = if output_structure.is_null() { -1 } else { 0 };
    }
    let mut ok: c_int = -1;
    let mut current: *mut OSSL_ENCODER_INSTANCE = ptr::null_mut();
    let mut found = false;
    let mut i = data.current_encoder_inst_index;
    while i > 0 {
        i -= 1;
        let inst_h = insts.get(i).copied().unwrap_or(ptr::null_mut());
        // SAFETY: an instance of the context.
        let Some(inst) = (unsafe { instance(inst_h) }) else {
            continue;
        };
        current = inst_h;
        let cur_type = inst.output_type.as_ptr();
        let cur_structure = inst
            .output_structure
            .as_deref()
            .map_or(ptr::null(), CStr::as_ptr);
        if top {
            // SAFETY: both strings.
            if !output_type.is_null() && !unsafe { eq_case(cur_type, output_type) } {
                continue;
            }
        } else {
            // SAFETY: the instance above, live while the context is.
            let next = unsafe { instance(data.next_encoder_inst) };
            if !next.is_some_and(|n| n.encoder().is_a(inst.output_type.to_bytes())) {
                continue;
            }
        }
        if !output_structure.is_null() && !cur_structure.is_null() {
            // SAFETY: both strings.
            if !unsafe { eq_case(output_structure, cur_structure) } {
                continue;
            }
            data.count_output_structure += 1;
        }
        let mut new_data = Process {
            ctx: data.ctx,
            bio: ptr::null_mut(),
            current_encoder_inst_index: i,
            level: data.level + 1,
            next_encoder_inst: inst_h,
            count_output_structure: data.count_output_structure,
            prev_encoder_inst: ptr::null_mut(),
            running_output: None,
            data_type: ptr::null(),
        };
        // SAFETY: as above.
        ok = unsafe { process(&mut new_data) };
        data.prev_encoder_inst = new_data.prev_encoder_inst;
        // As OpenSSL's, the level below's data type isn't brought up.
        data.running_output = new_data.running_output.take();
        if ok != 0 {
            found = true;
            break;
        }
    }
    if !found {
        // No instance fitted, or each failed: OpenSSL's `i < 0`.
        ok = -1;
    }
    let mut original: *const c_void = ptr::null();
    let mut allocated_out: *mut BIO = ptr::null_mut();
    if found {
        // SAFETY: the instance the loop stopped at.
        let Some(inst) = (unsafe { instance(current) }) else {
            return 0;
        };
        let e = inst.encoder();
        let mut abstract_params: Vec<OSSL_PARAM> = Vec::new();
        let mut current_abstract: *const OSSL_PARAM = ptr::null();
        let mut input = data.running_output.take();
        match ok {
            0 => {}
            -1 => {
                if data.count_output_structure == 0 {
                    return 0;
                }
                original = match construct {
                    // SAFETY: the application's construct with the instance and its data.
                    Some(f) => unsafe { f(current, construct_data) },
                    None => ptr::null(),
                };
                data.data_type = e.name().as_ptr();
                ok = c_int::from(!original.is_null());
            }
            _ => {
                let Some(out) = input.as_mut() else {
                    err::raise(
                        ERR_LIB_OSSL_ENCODER,
                        ERR_R_INTERNAL_ERROR,
                        "encoder_process",
                    );
                    return 0;
                };
                // SAFETY: the instance below, live while the context is.
                let prev_structure = unsafe { instance(data.prev_encoder_inst) }
                    .and_then(|p| p.output_structure.as_deref())
                    .map_or(ptr::null(), CStr::as_ptr);
                // SAFETY: static names; strings and octets that outlive the call.
                abstract_params.push(unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_OBJECT_PARAM_DATA_TYPE.as_ptr(),
                        data.data_type.cast_mut(),
                        0,
                    )
                });
                if !prev_structure.is_null() {
                    // SAFETY: as above.
                    abstract_params.push(unsafe {
                        OSSL_PARAM_construct_utf8_string(
                            OSSL_OBJECT_PARAM_DATA_STRUCTURE.as_ptr(),
                            prev_structure.cast_mut(),
                            0,
                        )
                    });
                }
                // SAFETY: as above.
                abstract_params.push(unsafe {
                    OSSL_PARAM_construct_octet_string(
                        OSSL_OBJECT_PARAM_DATA.as_ptr(),
                        out.as_mut_ptr().cast(),
                        out.len(),
                    )
                });
                // SAFETY: no preconditions.
                abstract_params.push(unsafe { OSSL_PARAM_construct_end() });
                current_abstract = abstract_params.as_ptr();
            }
        }
        if ok != 0 {
            let current_out = if top {
                data.bio
            } else {
                // SAFETY: no preconditions.
                let method = unsafe { crate::bio::mem::BIO_s_mem() };
                // SAFETY: a static method.
                allocated_out = unsafe { BIO_new(method) };
                allocated_out
            };
            let cbio = if current_out.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: the output BIO.
                unsafe { core_bio_new_from_bio(current_out) }
            };
            if cbio.is_null() {
                ok = 0;
            } else {
                ok = match e.funcs.encode {
                    // SAFETY: the encoder's function with its context, the output, the object or
                    // the octets below, the selection, and the context's passphrase data.
                    Some(encode) => unsafe {
                        encode(
                            inst.ctx.0,
                            cbio,
                            original,
                            current_abstract,
                            selection,
                            Some(passphrase_callback_enc),
                            c.pw().cast(),
                        )
                    },
                    None => 0,
                };
                // SAFETY: the core BIO's reference.
                unsafe { BIO_free(cbio.cast()) };
            }
            data.prev_encoder_inst = current;
        }
        drop(input);
        drop(abstract_params);
    }
    data.running_output = None;
    if !allocated_out.is_null() {
        // SAFETY: the memory BIO made above.
        data.running_output = Some(unsafe { take_mem(allocated_out) });
        // SAFETY: as above, freed once.
        unsafe { BIO_free(allocated_out) };
    }
    if !original.is_null()
        && let Some(f) = cleanup
    {
        // SAFETY: the application's cleanup with its data.
        unsafe { f(construct_data) };
    }
    ok
}

/// `OSSL_ENCODER_to_bio`'s checks and walk.
///
/// # Safety
/// `ctx_` is NULL or a live context; `out` is a live BIO.
unsafe fn to_bio(ctx_: *mut OSSL_ENCODER_CTX, out: *mut BIO) -> c_int {
    const F: &str = "OSSL_ENCODER_to_bio";
    // SAFETY: the caller's guarantee.
    let n = unsafe { ctx(ctx_) }.map_or(0, |c| c.lock().insts.len());
    if n == 0 {
        err::raise_with_text(
            ERR_LIB_OSSL_ENCODER,
            OSSL_ENCODER_R_ENCODER_NOT_FOUND,
            F,
            "No encoders were found. For standard encoders you need at least one of the default or base providers available. Did you forget to load them?",
        );
        return 0;
    }
    // SAFETY: as above.
    let ready = unsafe { ctx(ctx_) }.is_some_and(|c| {
        let st = c.lock();
        st.cleanup.is_some() && st.construct.is_some()
    });
    if !ready {
        err::raise(ERR_LIB_OSSL_ENCODER, ERR_R_INIT_FAIL, F);
        return 0;
    }
    let mut data = Process {
        ctx: ctx_,
        bio: out,
        current_encoder_inst_index: n,
        level: 0,
        next_encoder_inst: ptr::null_mut(),
        count_output_structure: 0,
        prev_encoder_inst: ptr::null_mut(),
        running_output: None,
        data_type: ptr::null(),
    };
    // SAFETY: as above.
    c_int::from(unsafe { process(&mut data) } > 0)
}

ffi_export! {
    /// Encodes the context's object into the BIO. 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `out` is a live BIO.
    pub unsafe extern "C" fn OSSL_ENCODER_to_bio(ctx_: *mut OSSL_ENCODER_CTX, out: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { to_bio(ctx_, out) }
    }
}

ffi_export! {
    /// `OSSL_ENCODER_to_bio` into a `FILE`, left open.
    ///
    /// # Safety
    /// As for `OSSL_ENCODER_to_bio`, with `fp` an open `FILE`.
    pub unsafe extern "C" fn OSSL_ENCODER_to_fp(ctx_: *mut OSSL_ENCODER_CTX, fp: *mut FILE) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: no preconditions.
        let method = unsafe { crate::bio::file::BIO_s_file() };
        // SAFETY: a static method.
        let b = unsafe { BIO_new(method) };
        if b.is_null() {
            err::raise(ERR_LIB_OSSL_ENCODER, ERR_R_BUF_LIB, "bio_from_file");
            return 0;
        }
        // SAFETY: the new file BIO; the caller's file, not closed.
        unsafe { BIO_ctrl(b, BIO_C_SET_FILE_PTR, c_long::from(BIO_NOCLOSE), fp.cast()) };
        // SAFETY: the caller's guarantee; the BIO.
        let ret = unsafe { to_bio(ctx_, b) };
        // SAFETY: made above.
        unsafe { BIO_free(b) };
        ret
    }
}

ffi_export! {
    /// Encodes into memory: a new buffer for `*pdata` (or, if it points to room of
    /// `*pdata_len`, there, moving both on). 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `pdata` is NULL or holds NULL or room of `*pdata_len`;
    /// `pdata_len` is writable.
    pub unsafe extern "C" fn OSSL_ENCODER_to_data(ctx_: *mut OSSL_ENCODER_CTX, pdata: *mut *mut c_uchar, pdata_len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        if pdata_len.is_null() {
            null_arg("OSSL_ENCODER_to_data");
            return 0;
        }
        // SAFETY: no preconditions.
        let method = unsafe { crate::bio::mem::BIO_s_mem() };
        // SAFETY: a static method.
        let out = unsafe { BIO_new(method) };
        let mut ret = 0;
        let mut buf: *mut BUF_MEM = ptr::null_mut();
        // SAFETY: the caller's guarantee; the new BIO.
        if !out.is_null() && unsafe { to_bio(ctx_, out) } != 0
            // SAFETY: the BIO; a local.
            && unsafe { BIO_ctrl(out, BIO_C_GET_BUF_MEM_PTR, 0, (&raw mut buf).cast()) } > 0
            && !buf.is_null()
        {
            // SAFETY: the BIO's buffer.
            let m = unsafe { &mut *buf };
            ret = 1;
            // SAFETY: the caller's guarantee.
            let given = if pdata.is_null() { ptr::null_mut() } else { unsafe { pdata.read() } };
            if !given.is_null() {
                // SAFETY: the caller's guarantee.
                let room = unsafe { pdata_len.read() };
                if room < m.length {
                    ret = 0;
                } else {
                    // SAFETY: as above.
                    unsafe { pdata_len.write(room - m.length) };
                }
            } else {
                // SAFETY: as above.
                unsafe { pdata_len.write(m.length) };
            }
            if ret != 0 && !pdata.is_null() {
                if given.is_null() {
                    // The buffer's data passes to the caller.
                    // SAFETY: as above.
                    unsafe { pdata.write(m.data.cast()) };
                    m.data = ptr::null_mut();
                } else {
                    // SAFETY: the caller's room; the buffer's octets.
                    unsafe { ptr::copy_nonoverlapping(m.data.cast::<u8>(), given, m.length) };
                    // SAFETY: as above.
                    unsafe { pdata.write(given.wrapping_add(m.length)) };
                }
            }
        }
        // SAFETY: made above, or NULL.
        unsafe { BIO_free(out) };
        ret
    }
}

/// The context's passphrase data, changed by `f`; 0 for a NULL context.
///
/// # Safety
/// `ctx_` is NULL or a live context.
unsafe fn with_pw(ctx_: *mut OSSL_ENCODER_CTX, f: impl FnOnce(&mut PwData) -> bool) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(ctx_) }) else {
        return 0;
    };
    // SAFETY: the context's own data, changed only here and never during an encode.
    c_int::from(f(unsafe { &mut *c.pw() }))
}

ffi_export! {
    /// Sets the cipher (by name, NULL for none) and its properties the encoders encrypt with.
    /// 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; the strings are NULL or strings.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_cipher(ctx_: *mut OSSL_ENCODER_CTX, cipher_name: *const c_char, propquery: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        let params = [
            // SAFETY: a static name; the caller's string, read during the call.
            unsafe { OSSL_PARAM_construct_utf8_string(OSSL_ENCODER_PARAM_CIPHER.as_ptr(), cipher_name.cast_mut(), 0) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES.as_ptr(), propquery.cast_mut(), 0) },
            // SAFETY: no preconditions.
            unsafe { OSSL_PARAM_construct_end() },
        ];
        // SAFETY: the caller's guarantee; the array.
        unsafe { OSSL_ENCODER_CTX_set_params(ctx_, params.as_ptr()) }
    }
}

ffi_export! {
    /// Sets a copy of the passphrase. 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `kstr` is NULL or holds `klen` octets.
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_passphrase(ctx_: *mut OSSL_ENCODER_CTX, kstr: *const c_uchar, klen: usize) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
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
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_passphrase_ui(ctx_: *mut OSSL_ENCODER_CTX, ui_method: *const UI_METHOD, ui_data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
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
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_pem_password_cb(ctx_: *mut OSSL_ENCODER_CTX, cb: pem_password_cb, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
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
    pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_passphrase_cb(ctx_: *mut OSSL_ENCODER_CTX, cb: OSSL_PASSPHRASE_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { with_pw(ctx_, |pw| pw.set_ossl_passphrase_cb(cb, cbarg)) }
    }
}
