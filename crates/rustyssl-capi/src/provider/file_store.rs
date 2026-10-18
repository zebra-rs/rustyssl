//! The default and base providers' `file` store (`file_store.c`, `file_store_any2obj.c`): a file
//! (its PEM, DER, MSBLOB, or PVK objects through the decoders) or a directory (its entries'
//! names, or with a subject searched for, the hashed names `X509_LOOKUP_hash_dir` uses).
//!
//! As OpenSSL's:
//! - `file:` URIs take an absolute path (`file:/p`, `file:///p`, `file://localhost/p`); a
//!   bare path is tried as given first.
//! - A file's objects come from a decoder chain ending in the private "to object" decoders,
//!   which pass the DER (or the MSBLOB or PVK blob) on without interpreting it; `OSSL_STORE`
//!   makes keys, certificates, and CRLs of them.
//! - A directory search by subject gives the `<hash>.<n>` (and for CRLs `<hash>.r<n>`) entries.

use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    BIO, ERR_LIB_PROV, ERR_LIB_SYS, ERR_R_OSSL_DECODER_LIB, OPENSSL_DIR_CTX, OSSL_ALGORITHM,
    OSSL_CALLBACK, OSSL_CORE_BIO, OSSL_DECODER_CTX, OSSL_DECODER_INSTANCE,
    OSSL_FUNC_DECODER_DECODE, OSSL_FUNC_DECODER_FREECTX, OSSL_FUNC_DECODER_NEWCTX,
    OSSL_FUNC_DECODER_SET_CTX_PARAMS, OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_STORE_ATTACH, OSSL_FUNC_STORE_CLOSE, OSSL_FUNC_STORE_EOF, OSSL_FUNC_STORE_LOAD,
    OSSL_FUNC_STORE_OPEN, OSSL_FUNC_STORE_SET_CTX_PARAMS, OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
    OSSL_OBJECT_NAME, OSSL_OBJECT_PARAM_DATA, OSSL_OBJECT_PARAM_DATA_STRUCTURE,
    OSSL_OBJECT_PARAM_DATA_TYPE, OSSL_OBJECT_PARAM_INPUT_TYPE, OSSL_OBJECT_PARAM_TYPE,
    OSSL_OBJECT_PKEY, OSSL_OBJECT_UNKNOWN, OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UTF8_STRING, OSSL_PASSPHRASE_CALLBACK, OSSL_STORE_INFO_CERT, OSSL_STORE_INFO_CRL,
    OSSL_STORE_INFO_PKEY, OSSL_STORE_INFO_PUBKEY, OSSL_STORE_PARAM_EXPECT,
    OSSL_STORE_PARAM_INPUT_TYPE, OSSL_STORE_PARAM_PROPERTIES, OSSL_STORE_PARAM_SUBJECT,
    PROV_R_PATH_MUST_BE_ABSOLUTE, PROV_R_SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES,
    PROV_R_URI_AUTHORITY_UNSUPPORTED, X509_NAME,
};

use super::builtin::{libctx_of, provider_of};
use super::tables::{Algorithms, Dispatch, END, PARAM_END, Params, defn, entry};
use crate::asn1::tpl::io::read_der;
use crate::bio::file::BIO_new_file;
use crate::bio::{BIO_ctrl, BIO_free, BIO_read};
use crate::decoder::ctx::{
    OSSL_DECODER_CTX_add_extra, OSSL_DECODER_CTX_free, OSSL_DECODER_CTX_new,
    OSSL_DECODER_CTX_set_cleanup, OSSL_DECODER_CTX_set_construct,
    OSSL_DECODER_CTX_set_construct_data, OSSL_DECODER_CTX_set_input_structure,
    OSSL_DECODER_CTX_set_input_type, OSSL_DECODER_CTX_set_passphrase_cb, OSSL_DECODER_from_bio,
    add_decoder_inst, bio_new_from_core_bio, ctx as decoder_ctx, instance, instance_new_forprov,
};
use crate::decoder::{OSSL_DECODER_free, from_algorithm};
use crate::dir::{OPENSSL_DIR_end, OPENSSL_DIR_read};
use crate::err::{self, ERR_clear_last_mark, ERR_peek_last_error, ERR_pop_to_mark, ERR_set_mark};
use crate::ffi::ffi_callback;
use crate::handle::Handle;
use crate::mem;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string_ptr,
    OSSL_PARAM_get_utf8_string, OSSL_PARAM_locate_const,
};
use crate::pvkfmt::{BLOB_MAX_LENGTH, Cursor, blob_header, blob_length, pvk_header};
use crate::x509::name::{X509_NAME_free, X509_NAME_hash_ex, d2i_X509_NAME};

/// `OSSL_MAX_CODEC_STRUCT_SIZE`.
const MAX_CODEC_STRUCT: usize = 32;

/// What a store context reads.
enum Source {
    File {
        bio: *mut BIO,
        decoderctx: *mut OSSL_DECODER_CTX,
        /// From `CRYPTO_malloc`, or NULL.
        input_type: *mut c_char,
        propq: *mut c_char,
    },
    Dir {
        ctx: *mut OPENSSL_DIR_CTX,
        end_reached: bool,
        /// `%08lx` of the subject's hash, or empty.
        search_name: Vec<u8>,
        /// The next entry (in the directory context), or NULL.
        last_entry: *const c_char,
        last_errno: c_int,
    },
}

/// `file_ctx_st`.
struct FileCtx {
    provctx: *mut c_void,
    /// The URI, or `None` for an attached BIO.
    uri: Option<Vec<u8>>,
    source: Source,
    expected_type: c_int,
    fatal_error: bool,
}

/// The context behind a pointer.
///
/// # Safety
/// `p` is NULL or a live context.
unsafe fn ctx_of<'a>(p: *mut c_void) -> Option<&'a mut FileCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<FileCtx>().as_mut() }
}

/// `errno`.
fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Sets `errno` to 0, as `OPENSSL_DIR_read`'s callers read it after.
fn clear_errno() {
    #[cfg(target_os = "macos")]
    // SAFETY: no preconditions.
    let e = unsafe { libc::__error() };
    #[cfg(not(target_os = "macos"))]
    // SAFETY: no preconditions.
    let e = unsafe { libc::__errno_location() };
    // SAFETY: the thread's errno.
    unsafe { *e = 0 };
}

/// `file_open_dir`.
///
/// # Safety
/// `path` is a C string; `provctx` the provider's context.
unsafe fn open_dir(path: *const c_char, uri: &[u8], provctx: *mut c_void) -> *mut c_void {
    let mut dctx: *mut OPENSSL_DIR_CTX = ptr::null_mut();
    clear_errno();
    // SAFETY: room for the context; the caller's path.
    let last_entry = unsafe { OPENSSL_DIR_read(&raw mut dctx, path) };
    let last_errno = errno();
    if last_entry.is_null() && last_errno != 0 {
        // SAFETY: as above.
        let p = unsafe { CStr::from_ptr(path) }.to_string_lossy();
        err::raise_with_text(
            ERR_LIB_SYS,
            last_errno,
            "file_open_dir",
            &format!("Calling OPENSSL_DIR_read(\"{p}\")"),
        );
        // SAFETY: the context opened, or NULL.
        unsafe { OPENSSL_DIR_end(&raw mut dctx) };
        return ptr::null_mut();
    }
    let c = FileCtx {
        provctx,
        uri: Some(uri.to_vec()),
        source: Source::Dir {
            ctx: dctx,
            end_reached: last_entry.is_null(),
            search_name: Vec::new(),
            last_entry,
            last_errno,
        },
        expected_type: 0,
        fatal_error: false,
    };
    Box::into_raw(Box::new(c)).cast()
}

/// `file_open_stream`.
fn open_stream(bio: *mut BIO, uri: Option<&[u8]>, provctx: *mut c_void) -> *mut c_void {
    let c = FileCtx {
        provctx,
        uri: uri.map(<[u8]>::to_vec),
        source: Source::File {
            bio,
            decoderctx: ptr::null_mut(),
            input_type: ptr::null_mut(),
            propq: ptr::null_mut(),
        },
        expected_type: 0,
        fatal_error: false,
    };
    Box::into_raw(Box::new(c)).cast()
}

/// The paths `file_open` tries for the URI: the URI as given, then for a `file:` one the path
/// it names (which must be absolute). `Err` with the error for an authority it doesn't take.
fn paths_of(uri: &[u8]) -> Result<Vec<(Vec<u8>, bool)>, ()> {
    let mut paths = vec![(uri.to_vec(), false)];
    let Some(mut p) = uri
        .get(..5)
        .filter(|p| p.eq_ignore_ascii_case(b"file:"))
        .and(uri.get(5..))
    else {
        return Ok(paths);
    };
    if let Some(q) = p.strip_prefix(b"//") {
        paths.pop();
        if q.get(..10)
            .is_some_and(|x| x.eq_ignore_ascii_case(b"localhost/"))
        {
            p = q.get(9..).unwrap_or_default();
        } else if q.first() == Some(&b'/') {
            p = q;
        } else {
            err::raise(ERR_LIB_PROV, PROV_R_URI_AUTHORITY_UNSUPPORTED, "file_open");
            return Err(());
        }
    }
    paths.push((p.to_vec(), true));
    Ok(paths)
}

ffi_callback! {
    /// `file_open`: the file or directory the URI names, or NULL.
    ///
    /// # Safety
    /// `provctx` is the provider's context; `uri` a C string.
    pub(crate) unsafe extern "C" fn file_open(provctx: *mut c_void, uri: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the caller's string.
        let u = unsafe { CStr::from_ptr(uri) }.to_bytes();
        let Ok(paths) = paths_of(u) else {
            // SAFETY: the mark set above; the error raised after it stays.
            unsafe { ERR_clear_last_mark() };
            return ptr::null_mut();
        };
        let mut found = None;
        for (path, check_absolute) in paths {
            if check_absolute && path.first() != Some(&b'/') {
                // SAFETY: as above.
                unsafe { ERR_clear_last_mark() };
                let p = String::from_utf8_lossy(&path);
                err::raise_with_text(ERR_LIB_PROV, PROV_R_PATH_MUST_BE_ABSOLUTE, "file_open", &format!("Given path={p}"));
                return ptr::null_mut();
            }
            let Ok(cpath) = std::ffi::CString::new(path.clone()) else { continue };
            // SAFETY: an all-zero `stat` is valid.
            let mut st: libc::stat = unsafe { core::mem::zeroed() };
            // SAFETY: a C string; room for the status.
            if unsafe { libc::stat(cpath.as_ptr(), &raw mut st) } < 0 {
                let e = errno();
                let p = String::from_utf8_lossy(&path);
                err::raise_with_text(ERR_LIB_SYS, e, "file_open", &format!("calling stat({p})"));
            } else {
                found = Some((cpath, st));
                break;
            }
        }
        let Some((path, st)) = found else {
            // SAFETY: as above.
            unsafe { ERR_clear_last_mark() };
            return ptr::null_mut();
        };
        // SAFETY: as above.
        unsafe { ERR_pop_to_mark() };
        if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            // SAFETY: a C string; the provider's context.
            return unsafe { open_dir(path.as_ptr(), u, provctx) };
        }
        // SAFETY: a C string.
        let bio = unsafe { BIO_new_file(path.as_ptr(), c"rb".as_ptr()) };
        if bio.is_null() {
            return ptr::null_mut();
        }
        open_stream(bio, Some(u), provctx)
    }
}

ffi_callback! {
    /// `file_attach`: reads the core BIO.
    ///
    /// # Safety
    /// `provctx` is the provider's context; `cin` a live core BIO.
    pub(crate) unsafe extern "C" fn file_attach(provctx: *mut c_void, cin: *mut OSSL_CORE_BIO) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's core BIO.
        let bio = unsafe { bio_new_from_core_bio(cin) };
        if bio.is_null() {
            return ptr::null_mut();
        }
        open_stream(bio, None, provctx)
    }
}

static SETTABLE: Params<5> = Params([
    defn(OSSL_STORE_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_STORE_PARAM_EXPECT,
        OSSL_PARAM_INTEGER,
        size_of::<c_int>(),
    ),
    defn(OSSL_STORE_PARAM_SUBJECT, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_STORE_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `file_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn file_settable_ctx_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

/// A string parameter's value into `*slot` (replacing it), from `CRYPTO_malloc`.
///
/// # Safety
/// `p` is a parameter; `*slot` NULL or from `CRYPTO_malloc`.
unsafe fn set_string(p: *const OSSL_PARAM, slot: &mut *mut c_char) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { mem::release(slot.cast()) };
    *slot = ptr::null_mut();
    // SAFETY: as above; room for the copy.
    (unsafe { OSSL_PARAM_get_utf8_string(p, slot, 0) }) != 0
}

/// The `%08lx` hash of the DER subject name, or `None`.
///
/// # Safety
/// `p` is a parameter; `provctx` the provider's context.
unsafe fn subject_hash(p: *const OSSL_PARAM, provctx: *mut c_void) -> Option<Vec<u8>> {
    let (mut der, mut der_len): (*const c_void, usize) = (ptr::null(), 0);
    // SAFETY: the caller's parameter; rooms for its value.
    if unsafe { OSSL_PARAM_get_octet_string_ptr(p, &raw mut der, &raw mut der_len) } == 0 {
        return None;
    }
    let mut q = der.cast::<u8>();
    let len = core::ffi::c_long::try_from(der_len).ok()?;
    // SAFETY: the octets.
    let name: *mut X509_NAME = unsafe { d2i_X509_NAME(ptr::null_mut(), &raw mut q, len) };
    if name.is_null() {
        return None;
    }
    let mut ok: c_int = 0;
    // SAFETY: the provider's context.
    let libctx = unsafe { libctx_of(provctx) };
    // SAFETY: the name; the library context; room for the result.
    let hash: c_ulong = unsafe { X509_NAME_hash_ex(name, libctx, ptr::null(), &raw mut ok) };
    // SAFETY: decoded here.
    unsafe { X509_NAME_free(name) };
    if ok == 0 {
        return None;
    }
    // `BIO_snprintf` into 9 octets.
    let mut s = format!("{hash:08x}").into_bytes();
    s.truncate(8);
    Some(s)
}

ffi_callback! {
    /// `file_set_ctx_params`: the properties and input type (files), the expected type, and the
    /// subject to search for (directories): 1, or 0.
    ///
    /// # Safety
    /// `loaderctx` is a live context; `params` NULL or a parameter array.
    pub(crate) unsafe extern "C" fn file_set_ctx_params(loaderctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(loaderctx) }) else { return 0 };
        // SAFETY: as above.
        if params.is_null() || unsafe { (*params).key }.is_null() {
            return 1;
        }
        let locate = |k: &CStr| {
            // SAFETY: the caller's array.
            unsafe { OSSL_PARAM_locate_const(params, k.as_ptr()) }
        };
        let is_dir = matches!(c.source, Source::Dir { .. });
        if let Source::File { propq, input_type, .. } = &mut c.source {
            let p = locate(OSSL_STORE_PARAM_PROPERTIES);
            // SAFETY: a located parameter; its own string, or NULL.
            if !p.is_null() && !unsafe { set_string(p, propq) } {
                return 0;
            }
            let p = locate(OSSL_STORE_PARAM_INPUT_TYPE);
            // SAFETY: as above.
            if !p.is_null() && !unsafe { set_string(p, input_type) } {
                return 0;
            }
        }
        let p = locate(OSSL_STORE_PARAM_EXPECT);
        // SAFETY: as above; room for the value.
        if !p.is_null() && unsafe { OSSL_PARAM_get_int(p, &raw mut c.expected_type) } == 0 {
            return 0;
        }
        let p = locate(OSSL_STORE_PARAM_SUBJECT);
        if !p.is_null() {
            if !is_dir {
                err::raise(ERR_LIB_PROV, PROV_R_SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES, "file_set_ctx_params");
                return 0;
            }
            // SAFETY: as above; the provider's context.
            let Some(h) = (unsafe { subject_hash(p, c.provctx) }) else { return 0 };
            if let Source::Dir { search_name, .. } = &mut c.source {
                *search_name = h;
            }
        }
        1
    }
}

/// `file_load_data_st`.
struct LoadData {
    object_cb: OSSL_CALLBACK,
    object_cbarg: *mut c_void,
}

ffi_callback! {
    /// `file_load_construct`: passes the object's parameters to the store.
    ///
    /// # Safety
    /// `params` is a parameter array; `construct_data` a live [`LoadData`].
    pub(crate) unsafe extern "C" fn file_load_construct(_decoder_inst: *mut OSSL_DECODER_INSTANCE, params: *const OSSL_PARAM, construct_data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { construct_data.cast::<LoadData>().as_ref() }) else { return 0 };
        let Some(cb) = d.object_cb else { return 0 };
        // SAFETY: the store's callback with the decoder's parameters.
        unsafe { cb(params, d.object_cbarg) }
    }
}

ffi_callback! {
    /// `file_load_cleanup`: nothing to clean.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn file_load_cleanup(_construct_data: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {}
}

/// The decoder input structure for the expected type.
fn input_structure(expected_type: c_int) -> Option<&'static CStr> {
    match expected_type {
        OSSL_STORE_INFO_PUBKEY => Some(c"SubjectPublicKeyInfo"),
        OSSL_STORE_INFO_PKEY => Some(c"EncryptedPrivateKeyInfo"),
        OSSL_STORE_INFO_CERT => Some(c"Certificate"),
        OSSL_STORE_INFO_CRL => Some(c"CertificateList"),
        _ => None,
    }
}

/// Adds the "to object" decoders the input type allows to the decoder context.
///
/// # Safety
/// `dctx` is a live decoder context; `provctx` the provider's context; `input_type` NULL or a
/// C string.
unsafe fn add_to_obj(
    dctx: *mut OSSL_DECODER_CTX,
    provctx: *mut c_void,
    structure: Option<&CStr>,
    input_type: *const c_char,
) -> bool {
    // SAFETY: the provider's context.
    let prov = unsafe { provider_of(provctx) };
    let want = (!input_type.is_null()).then(|| {
        // SAFETY: the caller's string.
        unsafe { CStr::from_ptr(input_type) }.to_bytes()
    });
    for algo in ANY_TO_OBJ
        .0
        .iter()
        .take_while(|a| !a.algorithm_names.is_null())
    {
        // SAFETY: a static algorithm of the provider.
        let to_obj = unsafe { from_algorithm(0, algo, prov) }.cast::<rustyssl_abi::OSSL_DECODER>();
        let inst = if to_obj.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: the decoder made here; the structure, or NULL.
            unsafe { instance_new_forprov(to_obj, structure.map_or(ptr::null(), CStr::as_ptr)) }
        };
        // SAFETY: made here, or NULL; the instance holds its own reference.
        unsafe { OSSL_DECODER_free(to_obj) };
        if inst.is_null() {
            return false;
        }
        // SAFETY: the instance made here.
        let it = unsafe { instance(inst) }
            .map(|i| i.input_type().to_bytes().to_vec())
            .unwrap_or_default();
        if let Some(w) = want
            && !it.eq_ignore_ascii_case(w)
            && (!w.eq_ignore_ascii_case(b"PEM") || !it.eq_ignore_ascii_case(b"der"))
        {
            // SAFETY: as above.
            unsafe { OSSL_DECODER_INSTANCE::free(inst) };
            continue;
        }
        // SAFETY: the context; the instance, which it takes.
        let Some(c) = (unsafe { decoder_ctx(dctx) }) else {
            // SAFETY: as above.
            unsafe { OSSL_DECODER_INSTANCE::free(inst) };
            return false;
        };
        add_decoder_inst(c, inst);
    }
    true
}

/// `file_setup_decoders`.
///
/// # Safety
/// `c`'s members are live.
unsafe fn setup_decoders(c: &mut FileCtx) -> bool {
    let (provctx, expected) = (c.provctx, c.expected_type);
    let Source::File {
        decoderctx,
        input_type,
        propq,
        ..
    } = &mut c.source
    else {
        return false;
    };
    if !decoderctx.is_null() {
        return true;
    }
    // SAFETY: no preconditions.
    *decoderctx = unsafe { OSSL_DECODER_CTX_new() };
    let dctx = *decoderctx;
    let fail = || {
        err::raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB, "file_setup_decoders");
        false
    };
    // SAFETY: the context made here, or NULL; its input type, or NULL.
    if dctx.is_null() || unsafe { OSSL_DECODER_CTX_set_input_type(dctx, *input_type) } == 0 {
        return fail();
    }
    let structure = input_structure(expected);
    if let Some(s) = structure
        // SAFETY: as above; a static string.
        && unsafe { OSSL_DECODER_CTX_set_input_structure(dctx, s.as_ptr()) } == 0
    {
        return fail();
    }
    // SAFETY: as above; the provider's context.
    if !unsafe { add_to_obj(dctx, provctx, structure, *input_type) } {
        return false;
    }
    // SAFETY: the provider's context.
    let libctx = unsafe { libctx_of(provctx) };
    // SAFETY: as above; the library context; the properties, or NULL.
    if unsafe { OSSL_DECODER_CTX_add_extra(dctx, libctx, *propq) } == 0 {
        return fail();
    }
    // SAFETY: as above.
    if unsafe { OSSL_DECODER_CTX_set_construct(dctx, Some(file_load_construct)) } == 0
        // SAFETY: as above.
        || unsafe { OSSL_DECODER_CTX_set_cleanup(dctx, Some(file_load_cleanup)) } == 0
    {
        return fail();
    }
    true
}

/// `file_load_file`.
///
/// # Safety
/// `ctx` is a live context reading a file.
unsafe fn load_file(
    ctx: *mut c_void,
    object_cb: OSSL_CALLBACK,
    object_cbarg: *mut c_void,
    pw_cb: OSSL_PASSPHRASE_CALLBACK,
    pw_cbarg: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    // SAFETY: its members.
    if !unsafe { setup_decoders(c) } {
        c.fatal_error = true;
        return 0;
    }
    let Source::File {
        bio, decoderctx, ..
    } = c.source
    else {
        return 0;
    };
    let mut data = LoadData {
        object_cb,
        object_cbarg,
    };
    // SAFETY: its decoder context; the data, which outlives the decode.
    if unsafe { OSSL_DECODER_CTX_set_construct_data(decoderctx, (&raw mut data).cast()) } == 0 {
        return 0;
    }
    // SAFETY: as above; the store's callback.
    unsafe { OSSL_DECODER_CTX_set_passphrase_cb(decoderctx, pw_cb, pw_cbarg) };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the decoder context and the file; the callbacks run with no reference held here.
    let ret = unsafe { OSSL_DECODER_from_bio(decoderctx, bio) };
    // SAFETY: the file.
    let eof = unsafe { BIO_ctrl(bio, rustyssl_abi::BIO_CTRL_EOF, 0, ptr::null_mut()) } != 0;
    // SAFETY: no preconditions.
    let e = unsafe { ERR_peek_last_error() };
    if eof
        && e != 0
        && err::library_of(e) == rustyssl_abi::ERR_LIB_OSSL_DECODER
        && err::reason_of(e) == rustyssl_abi::ERR_R_UNSUPPORTED
    {
        // SAFETY: the mark set above.
        unsafe { ERR_pop_to_mark() };
    } else {
        // SAFETY: as above.
        unsafe { ERR_clear_last_mark() };
    }
    ret
}

/// `file_name_check`: whether a directory entry is what the search asks for.
fn name_check(search_name: &[u8], expected_type: c_int, name: &[u8]) -> bool {
    if search_name.is_empty() {
        return true;
    }
    if expected_type != 0
        && expected_type != OSSL_STORE_INFO_CERT
        && expected_type != OSSL_STORE_INFO_CRL
    {
        return false;
    }
    let len = search_name.len();
    if !name
        .get(..len)
        .is_some_and(|n| n.eq_ignore_ascii_case(search_name))
        || name.get(len) != Some(&b'.')
    {
        return false;
    }
    let mut p = name.get(len + 1..).unwrap_or_default();
    if let Some(rest) = p.strip_prefix(b"r") {
        p = rest;
        if expected_type != 0 && expected_type != OSSL_STORE_INFO_CRL {
            return false;
        }
    } else if expected_type == OSSL_STORE_INFO_CRL {
        return false;
    }
    !p.is_empty() && p.iter().all(u8::is_ascii_digit)
}

/// `file_name_to_uri`: the entry's URI under the directory's.
fn name_to_uri(uri: &[u8], name: &[u8]) -> Vec<u8> {
    let mut d = uri.to_vec();
    if uri.last() != Some(&b'/') {
        d.push(b'/');
    }
    d.extend_from_slice(name);
    d
}

/// `file_load_dir_entry`: the next matching entry's URI, as a name.
///
/// # Safety
/// `ctx` is a live context reading a directory.
unsafe fn load_dir_entry(
    ctx: *mut c_void,
    object_cb: OSSL_CALLBACK,
    object_cbarg: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    let uri = c.uri.clone().unwrap_or_default();
    let expected = c.expected_type;
    let Source::Dir {
        ctx: dctx,
        end_reached,
        search_name,
        last_entry,
        last_errno,
    } = &mut c.source
    else {
        return 0;
    };
    let Ok(curi) = std::ffi::CString::new(uri.clone()) else {
        return 0;
    };
    let newname = loop {
        if last_entry.is_null() {
            if !*end_reached {
                err::raise(ERR_LIB_SYS, *last_errno, "file_load_dir_entry");
            }
            return 0;
        }
        // SAFETY: the directory context's name.
        let entry = unsafe { CStr::from_ptr(*last_entry) }.to_bytes();
        let newname = (entry.first() != Some(&b'.') && name_check(search_name, expected, entry))
            .then(|| name_to_uri(&uri, entry));
        clear_errno();
        // SAFETY: the directory context; the URI.
        *last_entry = unsafe { OPENSSL_DIR_read(dctx, curi.as_ptr()) };
        *last_errno = errno();
        if last_entry.is_null() && *last_errno == 0 {
            *end_reached = true;
        }
        if let Some(n) = newname {
            break n;
        }
    };
    let mut object_type = OSSL_OBJECT_NAME;
    let mut name = newname;
    let len = name.len();
    name.push(0);
    // SAFETY: the keys; the values, which outlive the call.
    let object = [
        unsafe { OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE.as_ptr(), &raw mut object_type) },
        // SAFETY: as above.
        unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA.as_ptr(),
                name.as_mut_ptr().cast(),
                len,
            )
        },
        // SAFETY: no preconditions.
        unsafe { OSSL_PARAM_construct_end() },
    ];
    let Some(cb) = object_cb else { return 0 };
    // SAFETY: the store's callback with the parameters.
    unsafe { cb(object.as_ptr(), object_cbarg) }
}

ffi_callback! {
    /// `file_load`: the next object of the file, or the next entry of the directory.
    ///
    /// # Safety
    /// `loaderctx` is a live context; the callbacks the store's.
    pub(crate) unsafe extern "C" fn file_load(loaderctx: *mut c_void, object_cb: OSSL_CALLBACK, object_cbarg: *mut c_void, pw_cb: OSSL_PASSPHRASE_CALLBACK, pw_cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let is_dir = match unsafe { ctx_of(loaderctx) } {
            Some(c) => matches!(c.source, Source::Dir { .. }),
            None => return 0,
        };
        if is_dir {
            // SAFETY: as above.
            unsafe { load_dir_entry(loaderctx, object_cb, object_cbarg) }
        } else {
            // SAFETY: as above.
            unsafe { load_file(loaderctx, object_cb, object_cbarg, pw_cb, pw_cbarg) }
        }
    }
}

ffi_callback! {
    /// `file_eof`.
    ///
    /// # Safety
    /// `loaderctx` is a live context.
    pub(crate) unsafe extern "C" fn file_eof(loaderctx: *mut c_void) -> c_int
    where failure = 1, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(loaderctx) }) else { return 1 };
        if c.fatal_error {
            return 1;
        }
        match c.source {
            Source::Dir { end_reached, .. } => c_int::from(end_reached),
            Source::File { bio, .. } => {
                // SAFETY: the file.
                let pending = unsafe { BIO_ctrl(bio, rustyssl_abi::BIO_CTRL_PENDING, 0, ptr::null_mut()) };
                // SAFETY: as above.
                let eof = unsafe { BIO_ctrl(bio, rustyssl_abi::BIO_CTRL_EOF, 0, ptr::null_mut()) };
                c_int::from(pending == 0 && eof != 0)
            }
        }
    }
}

ffi_callback! {
    /// `file_close`.
    ///
    /// # Safety
    /// `loaderctx` is a live context, not used again.
    pub(crate) unsafe extern "C" fn file_close(loaderctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        if loaderctx.is_null() {
            return 1;
        }
        // SAFETY: made by `file_open` or `file_attach`, freed once.
        let c = unsafe { Box::from_raw(loaderctx.cast::<FileCtx>()) };
        match c.source {
            Source::Dir { mut ctx, .. } => {
                if !ctx.is_null() {
                    // SAFETY: its directory context.
                    unsafe { OPENSSL_DIR_end(&raw mut ctx) };
                }
            }
            Source::File { bio, decoderctx, input_type, propq } => {
                // SAFETY: its own, or NULL.
                unsafe { OSSL_DECODER_CTX_free(decoderctx) };
                // SAFETY: as above.
                unsafe { mem::release(propq.cast()) };
                // SAFETY: as above.
                unsafe { mem::release(input_type.cast()) };
                // SAFETY: as above.
                unsafe { BIO_free(bio) };
            }
        }
        1
    }
}

static FILE_STORE: Dispatch<8> = Dispatch([
    entry!(
        OSSL_FUNC_STORE_OPEN,
        file_open,
        unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void
    ),
    entry!(
        OSSL_FUNC_STORE_ATTACH,
        file_attach,
        unsafe extern "C" fn(*mut c_void, *mut OSSL_CORE_BIO) -> *mut c_void
    ),
    entry!(
        OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
        file_settable_ctx_params,
        unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM
    ),
    entry!(
        OSSL_FUNC_STORE_SET_CTX_PARAMS,
        file_set_ctx_params,
        unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int
    ),
    entry!(
        OSSL_FUNC_STORE_LOAD,
        file_load,
        unsafe extern "C" fn(
            *mut c_void,
            OSSL_CALLBACK,
            *mut c_void,
            OSSL_PASSPHRASE_CALLBACK,
            *mut c_void,
        ) -> c_int
    ),
    entry!(
        OSSL_FUNC_STORE_EOF,
        file_eof,
        unsafe extern "C" fn(*mut c_void) -> c_int
    ),
    entry!(
        OSSL_FUNC_STORE_CLOSE,
        file_close,
        unsafe extern "C" fn(*mut c_void) -> c_int
    ),
    END,
]);

static DEFAULT_STORES: Algorithms<2> = Algorithms([
    OSSL_ALGORITHM {
        algorithm_names: c"file".as_ptr(),
        property_definition: c"provider=default,fips=yes".as_ptr(),
        implementation: FILE_STORE.0.as_ptr(),
        algorithm_description: ptr::null(),
    },
    OSSL_ALGORITHM {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
]);

static BASE_STORES: Algorithms<2> = Algorithms([
    OSSL_ALGORITHM {
        algorithm_names: c"file".as_ptr(),
        property_definition: c"provider=base,fips=yes".as_ptr(),
        implementation: FILE_STORE.0.as_ptr(),
        algorithm_description: ptr::null(),
    },
    OSSL_ALGORITHM {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
]);

/// `deflt_store`.
pub(crate) fn default_stores() -> *const OSSL_ALGORITHM {
    DEFAULT_STORES.0.as_ptr()
}

/// `base_store`.
pub(crate) fn base_stores() -> *const OSSL_ALGORITHM {
    BASE_STORES.0.as_ptr()
}

// The "to object" decoders (`file_store_any2obj.c`).

/// `any2obj_ctx_st`.
struct Any2Obj {
    data_structure: [c_char; MAX_CODEC_STRUCT],
}

ffi_callback! {
    /// `any2obj_newctx`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn any2obj_newctx(_provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        Box::into_raw(Box::new(Any2Obj { data_structure: [0; MAX_CODEC_STRUCT] })).cast()
    }
}

ffi_callback! {
    /// `any2obj_freectx`.
    ///
    /// # Safety
    /// `ctx` is NULL or a context from `any2obj_newctx`, not used again.
    pub(crate) unsafe extern "C" fn any2obj_freectx(ctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !ctx.is_null() {
            // SAFETY: the caller's guarantee.
            drop(unsafe { Box::from_raw(ctx.cast::<Any2Obj>()) });
        }
    }
}

ffi_callback! {
    /// `any2obj_set_ctx_params`: the data structure to pass on.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` NULL or a parameter array.
    pub(crate) unsafe extern "C" fn any2obj_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { vctx.cast::<Any2Obj>().as_mut() }) else { return 0 };
        // SAFETY: the caller's array.
        let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_STRUCTURE.as_ptr()) };
        let mut s = c.data_structure.as_mut_ptr();
        // SAFETY: a located parameter; the buffer's room.
        c_int::from(p.is_null() || unsafe { OSSL_PARAM_get_utf8_string(p, &raw mut s, MAX_CODEC_STRUCT) } != 0)
    }
}

static ANY2OBJ_SETTABLE: Params<2> = Params([
    defn(OSSL_OBJECT_PARAM_DATA_STRUCTURE, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `any2obj_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn any2obj_settable_ctx_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        ANY2OBJ_SETTABLE.0.as_ptr()
    }
}

/// `any2obj_decode_final`: passes the octets on as an object of the type.
///
/// # Safety
/// `c` is a live context; `data_cb` the decoder's callback for `data_cbarg`.
unsafe fn decode_final(
    c: &mut Any2Obj,
    mut objtype: c_int,
    input_type: Option<&CStr>,
    data_type: Option<&CStr>,
    mem: Option<Vec<u8>>,
    data_cb: OSSL_CALLBACK,
    data_cbarg: *mut c_void,
) -> c_int {
    let Some(mut mem) = mem else { return 1 };
    let mut params = Vec::with_capacity(6);
    if let Some(d) = data_type {
        // SAFETY: the key; a static string the array only points to.
        params.push(unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA_TYPE.as_ptr(),
                d.as_ptr().cast_mut(),
                0,
            )
        });
    }
    if let Some(i) = input_type {
        // SAFETY: as above.
        params.push(unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_INPUT_TYPE.as_ptr(),
                i.as_ptr().cast_mut(),
                0,
            )
        });
    }
    if c.data_structure[0] != 0 {
        // SAFETY: as above; the context's NUL-terminated buffer.
        params.push(unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA_STRUCTURE.as_ptr(),
                c.data_structure.as_mut_ptr(),
                0,
            )
        });
    }
    // SAFETY: as above; `objtype`, which outlives the call.
    params.push(unsafe {
        OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE.as_ptr(), &raw mut objtype)
    });
    // SAFETY: as above; the octets, which outlive the call.
    params.push(unsafe {
        OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_DATA.as_ptr(),
            mem.as_mut_ptr().cast(),
            mem.len(),
        )
    });
    // SAFETY: no preconditions.
    params.push(unsafe { OSSL_PARAM_construct_end() });
    let Some(cb) = data_cb else { return 0 };
    // SAFETY: the decoder's callback with the parameters.
    unsafe { cb(params.as_ptr(), data_cbarg) }
}

/// The context and a BIO over the core BIO, for a decode.
///
/// # Safety
/// `vctx` is a live context; `cin` a live core BIO.
unsafe fn decode_input<'a>(
    vctx: *mut c_void,
    cin: *mut OSSL_CORE_BIO,
) -> Option<(&'a mut Any2Obj, *mut BIO)> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { vctx.cast::<Any2Obj>().as_mut() }?;
    // SAFETY: as above.
    let bio = unsafe { bio_new_from_core_bio(cin) };
    (!bio.is_null()).then_some((c, bio))
}

ffi_callback! {
    /// `der2obj_decode`: one DER element, passed on as an unknown object.
    ///
    /// # Safety
    /// As for a decoder's `decode`.
    pub(crate) unsafe extern "C" fn der2obj_decode(vctx: *mut c_void, cin: *mut OSSL_CORE_BIO, _selection: c_int, data_cb: OSSL_CALLBACK, data_cbarg: *mut c_void, _pw_cb: OSSL_PASSPHRASE_CALLBACK, _pw_cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some((c, bio)) = (unsafe { decode_input(vctx, cin) }) else { return 0 };
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the BIO made here.
        let mem = unsafe { read_der(bio) };
        // SAFETY: the mark set above.
        unsafe { ERR_pop_to_mark() };
        // SAFETY: as above.
        unsafe { BIO_free(bio) };
        // SAFETY: the context; the caller's callback.
        unsafe { decode_final(c, OSSL_OBJECT_UNKNOWN, None, None, mem, data_cb, data_cbarg) }
    }
}

/// Reads exactly `n` more octets onto `mem`: whether all came.
///
/// # Safety
/// `bio` is a live BIO.
unsafe fn read_more(bio: *mut BIO, mem: &mut Vec<u8>, n: usize) -> bool {
    let at = mem.len();
    mem.resize(at + n, 0);
    let Ok(want) = c_int::try_from(n) else {
        return false;
    };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the caller's BIO; the `n` octets of room.
    let got = unsafe { BIO_read(bio, mem.as_mut_ptr().wrapping_add(at).cast(), want) };
    // SAFETY: the mark set above.
    unsafe { ERR_pop_to_mark() };
    got == want
}

ffi_callback! {
    /// `msblob2obj_decode`: an MSBLOB's header and body, passed on as an RSA or DSA key.
    ///
    /// # Safety
    /// As for a decoder's `decode`.
    pub(crate) unsafe extern "C" fn msblob2obj_decode(vctx: *mut c_void, cin: *mut OSSL_CORE_BIO, _selection: c_int, data_cb: OSSL_CALLBACK, data_cbarg: *mut c_void, _pw_cb: OSSL_PASSPHRASE_CALLBACK, _pw_cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some((c, bio)) = (unsafe { decode_input(vctx, cin) }) else { return 0 };
        let mut mem = Vec::new();
        let mut isdss = true;
        // SAFETY: the BIO made here.
        let mut ok = unsafe { read_more(bio, &mut mem, 16) };
        if ok {
            // SAFETY: no preconditions.
            unsafe { ERR_set_mark() };
            let (r, h) = blob_header(&mut Cursor(&mem), 16, -1, -1);
            // SAFETY: the mark set above.
            unsafe { ERR_pop_to_mark() };
            ok = false;
            if let (true, Some(h)) = (r > 0, h) {
                isdss = h.isdss;
                let want = blob_length(h.bitlen, h.isdss, h.ispub);
                if want <= BLOB_MAX_LENGTH {
                    // SAFETY: as above.
                    ok = unsafe { read_more(bio, &mut mem, want as usize) };
                }
            }
        }
        // SAFETY: as above.
        unsafe { BIO_free(bio) };
        let data_type = if isdss { c"DSA" } else { c"RSA" };
        // SAFETY: the context; the caller's callback.
        unsafe { decode_final(c, OSSL_OBJECT_PKEY, Some(c"msblob"), Some(data_type), ok.then_some(mem), data_cb, data_cbarg) }
    }
}

ffi_callback! {
    /// `pvk2obj_decode`: a PVK's header, salt, and key blob, passed on as an RSA or DSA key.
    ///
    /// # Safety
    /// As for a decoder's `decode`.
    pub(crate) unsafe extern "C" fn pvk2obj_decode(vctx: *mut c_void, cin: *mut OSSL_CORE_BIO, _selection: c_int, data_cb: OSSL_CALLBACK, data_cbarg: *mut c_void, _pw_cb: OSSL_PASSPHRASE_CALLBACK, _pw_cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some((c, bio)) = (unsafe { decode_input(vctx, cin) }) else { return 0 };
        let mut mem = Vec::new();
        let mut isdss = true;
        // SAFETY: the BIO made here.
        let mut ok = unsafe { read_more(bio, &mut mem, 24) };
        if ok {
            // SAFETY: no preconditions.
            unsafe { ERR_set_mark() };
            let h = pvk_header(&mut Cursor(&mem), 24, false, -1);
            // SAFETY: the mark set above.
            unsafe { ERR_pop_to_mark() };
            ok = false;
            if let Some(h) = h {
                isdss = h.isdss;
                let want = h.saltlen as usize + h.keylen as usize;
                // SAFETY: as above.
                ok = unsafe { read_more(bio, &mut mem, want) };
            }
        }
        // SAFETY: as above.
        unsafe { BIO_free(bio) };
        let data_type = ok.then_some(if isdss { c"DSA" } else { c"RSA" });
        // SAFETY: the context; the caller's callback.
        unsafe { decode_final(c, OSSL_OBJECT_PKEY, Some(c"pvk"), data_type, ok.then_some(mem), data_cb, data_cbarg) }
    }
}

type DecodeFn = unsafe extern "C" fn(
    *mut c_void,
    *mut OSSL_CORE_BIO,
    c_int,
    OSSL_CALLBACK,
    *mut c_void,
    OSSL_PASSPHRASE_CALLBACK,
    *mut c_void,
) -> c_int;

/// A "to object" decoder's dispatch table.
macro_rules! to_obj {
    ($name:ident, $decode:ident) => {
        static $name: Dispatch<6> = Dispatch([
            entry!(
                OSSL_FUNC_DECODER_NEWCTX,
                any2obj_newctx,
                unsafe extern "C" fn(*mut c_void) -> *mut c_void
            ),
            entry!(
                OSSL_FUNC_DECODER_FREECTX,
                any2obj_freectx,
                unsafe extern "C" fn(*mut c_void)
            ),
            entry!(OSSL_FUNC_DECODER_DECODE, $decode, DecodeFn),
            entry!(
                OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
                any2obj_settable_ctx_params,
                unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM
            ),
            entry!(
                OSSL_FUNC_DECODER_SET_CTX_PARAMS,
                any2obj_set_ctx_params,
                unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int
            ),
            END,
        ]);
    };
}

to_obj!(DER_TO_OBJ, der2obj_decode);
to_obj!(MSBLOB_TO_OBJ, msblob2obj_decode);
to_obj!(PVK_TO_OBJ, pvk2obj_decode);

/// `ossl_any_to_obj_algorithm`.
static ANY_TO_OBJ: Algorithms<4> = Algorithms([
    OSSL_ALGORITHM {
        algorithm_names: c"obj".as_ptr(),
        property_definition: c"input=DER".as_ptr(),
        implementation: DER_TO_OBJ.0.as_ptr(),
        algorithm_description: ptr::null(),
    },
    OSSL_ALGORITHM {
        algorithm_names: c"obj".as_ptr(),
        property_definition: c"input=MSBLOB".as_ptr(),
        implementation: MSBLOB_TO_OBJ.0.as_ptr(),
        algorithm_description: ptr::null(),
    },
    OSSL_ALGORITHM {
        algorithm_names: c"obj".as_ptr(),
        property_definition: c"input=PVK".as_ptr(),
        implementation: PVK_TO_OBJ.0.as_ptr(),
        algorithm_description: ptr::null(),
    },
    OSSL_ALGORITHM {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_uris_name_absolute_paths() {
        assert_eq!(paths_of(b"/a/b"), Ok(vec![(b"/a/b".to_vec(), false)]));
        assert_eq!(
            paths_of(b"file:/a"),
            Ok(vec![(b"file:/a".to_vec(), false), (b"/a".to_vec(), true)])
        );
        assert_eq!(paths_of(b"FILE:///a"), Ok(vec![(b"/a".to_vec(), true)]));
        assert_eq!(
            paths_of(b"file://localhost/a"),
            Ok(vec![(b"/a".to_vec(), true)])
        );
        assert_eq!(
            paths_of(b"file:rel"),
            Ok(vec![(b"file:rel".to_vec(), false), (b"rel".to_vec(), true)])
        );
    }

    #[test]
    fn hashed_names_match_as_lookups_name_them() {
        assert!(name_check(b"", 0, b"anything"));
        assert!(name_check(b"1a2b3c4d", 0, b"1A2B3C4D.0"));
        assert!(name_check(
            b"1a2b3c4d",
            OSSL_STORE_INFO_CRL,
            b"1a2b3c4d.r12"
        ));
        assert!(!name_check(b"1a2b3c4d", OSSL_STORE_INFO_CRL, b"1a2b3c4d.0"));
        assert!(!name_check(
            b"1a2b3c4d",
            OSSL_STORE_INFO_CERT,
            b"1a2b3c4d.r0"
        ));
        assert!(!name_check(b"1a2b3c4d", 0, b"1a2b3c4d."));
        assert!(!name_check(b"1a2b3c4d", 0, b"1a2b3c4d.0x"));
        assert!(!name_check(
            b"1a2b3c4d",
            OSSL_STORE_INFO_PKEY,
            b"1a2b3c4d.0"
        ));
        assert_eq!(name_to_uri(b"/d", b"x"), b"/d/x");
        assert_eq!(name_to_uri(b"/d/", b"x"), b"/d/x");
    }
}
