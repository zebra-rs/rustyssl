//! Control commands (`eng_ctrl.c`): `ENGINE_ctrl` answers the `ENGINE_CTRL_*` questions about an
//! engine's command definitions itself (unless the engine asks to, with
//! `ENGINE_FLAGS_MANUAL_CMD_CTRL`), and passes everything else to the engine's control
//! function.

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    ENGINE, ENGINE_CMD_DEFN, ENGINE_CMD_FLAG_NO_INPUT, ENGINE_CMD_FLAG_NUMERIC,
    ENGINE_CMD_FLAG_STRING, ENGINE_CTRL_GET_CMD_FLAGS, ENGINE_CTRL_GET_CMD_FROM_NAME,
    ENGINE_CTRL_GET_DESC_FROM_CMD, ENGINE_CTRL_GET_DESC_LEN_FROM_CMD,
    ENGINE_CTRL_GET_FIRST_CMD_TYPE, ENGINE_CTRL_GET_NAME_FROM_CMD,
    ENGINE_CTRL_GET_NAME_LEN_FROM_CMD, ENGINE_CTRL_GET_NEXT_CMD_TYPE,
    ENGINE_CTRL_HAS_CTRL_FUNCTION, ENGINE_FLAGS_MANUAL_CMD_CTRL, ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER,
    ENGINE_R_CMD_NOT_EXECUTABLE, ENGINE_R_COMMAND_TAKES_INPUT, ENGINE_R_COMMAND_TAKES_NO_INPUT,
    ENGINE_R_INTERNAL_LIST_ERROR, ENGINE_R_INVALID_CMD_NAME, ENGINE_R_INVALID_CMD_NUMBER,
    ENGINE_R_NO_CONTROL_FUNCTION, ERR_LIB_ENGINE,
};

use super::{fields, null_parameter};
use crate::err;
use crate::ffi::ffi_export;

/// The most definitions read from one engine's table, which ends with an entry whose number
/// is 0 or whose name is NULL (a bound on a table missing its end).
const MAX_DEFNS: usize = 4096;

/// The engine's command definitions, up to the end marker.
///
/// # Safety
/// `defns` is NULL or an array of definitions ending as OpenSSL's must.
unsafe fn definitions<'a>(defns: *const ENGINE_CMD_DEFN) -> Vec<&'a ENGINE_CMD_DEFN> {
    let mut out = Vec::new();
    if defns.is_null() {
        return out;
    }
    for i in 0..MAX_DEFNS {
        // SAFETY: the caller's guarantee: the entries up to the end marker exist.
        let at = unsafe { defns.add(i) };
        // SAFETY: as above.
        let d = unsafe { &*at };
        if d.cmd_num == 0 || d.cmd_name.is_null() {
            break;
        }
        out.push(d);
    }
    out
}

/// The length of a C string as `int` (`strlen`).
///
/// # Safety
/// `s` is a C string.
unsafe fn c_len(s: *const c_char) -> c_int {
    // SAFETY: the caller's guarantee.
    let n = unsafe { CStr::from_ptr(s) }.to_bytes().len();
    c_int::try_from(n).unwrap_or(c_int::MAX)
}

/// Copies the C string `src` with its NUL into `dst` (`strcpy`): its length.
///
/// # Safety
/// `src` is a C string; `dst` has room for it and its NUL (the caller asked for the length
/// first, as OpenSSL's interface requires).
unsafe fn copy_out(dst: *mut c_char, src: *const c_char) -> c_int {
    // SAFETY: the caller's guarantee.
    let s = unsafe { CStr::from_ptr(src) }.to_bytes_with_nul();
    // SAFETY: as above: `dst` has room for `s`, and the two don't overlap.
    unsafe { ptr::copy_nonoverlapping(s.as_ptr().cast::<c_char>(), dst, s.len()) };
    // SAFETY: as above.
    unsafe { c_len(src) }
}

/// `int_ctrl_helper`: the answers about the command definitions.
///
/// # Safety
/// `defns` as for [`definitions`]; `p` is what the command takes.
unsafe fn helper(defns: *const ENGINE_CMD_DEFN, cmd: c_int, i: c_long, p: *mut c_void) -> c_int {
    // SAFETY: the caller's guarantee.
    let table = unsafe { definitions(defns) };
    let s = p.cast::<c_char>();
    if cmd == ENGINE_CTRL_GET_FIRST_CMD_TYPE {
        return table
            .first()
            .map_or(0, |d| c_int::try_from(d.cmd_num).unwrap_or(c_int::MAX));
    }
    if matches!(
        cmd,
        ENGINE_CTRL_GET_CMD_FROM_NAME
            | ENGINE_CTRL_GET_NAME_FROM_CMD
            | ENGINE_CTRL_GET_DESC_FROM_CMD
    ) && s.is_null()
    {
        null_parameter("int_ctrl_helper");
        return -1;
    }
    if cmd == ENGINE_CTRL_GET_CMD_FROM_NAME {
        // SAFETY: a C string (the caller's guarantee).
        let name = unsafe { CStr::from_ptr(s) };
        // SAFETY: the definitions' names are C strings.
        let found = table
            .iter()
            .find(|d| unsafe { CStr::from_ptr(d.cmd_name) } == name);
        return match found {
            Some(d) => c_int::try_from(d.cmd_num).unwrap_or(c_int::MAX),
            None => {
                err::raise(ERR_LIB_ENGINE, ENGINE_R_INVALID_CMD_NAME, "int_ctrl_helper");
                -1
            }
        };
    }
    // `int_ctrl_cmd_by_num`: the first definition numbered at least `i` (the table is in
    // order), if it's numbered exactly `i`.
    // `(unsigned int)i`: the low 32 bits.
    let num =
        c_uint::try_from(i.cast_unsigned() & c_ulong::from(c_uint::MAX)).unwrap_or(c_uint::MAX);
    let idx = table.iter().position(|d| d.cmd_num >= num);
    let Some(idx) = idx.filter(|&k| table.get(k).is_some_and(|d| d.cmd_num == num)) else {
        err::raise(
            ERR_LIB_ENGINE,
            ENGINE_R_INVALID_CMD_NUMBER,
            "int_ctrl_helper",
        );
        return -1;
    };
    let Some(d) = table.get(idx) else {
        return -1;
    };
    let desc = if d.cmd_desc.is_null() {
        c"".as_ptr()
    } else {
        d.cmd_desc
    };
    match cmd {
        ENGINE_CTRL_GET_NEXT_CMD_TYPE => table
            .get(idx.saturating_add(1))
            .map_or(0, |n| c_int::try_from(n.cmd_num).unwrap_or(c_int::MAX)),
        // SAFETY: the definition's strings are C strings; `s` has room (the caller's
        // guarantee).
        ENGINE_CTRL_GET_NAME_LEN_FROM_CMD => unsafe { c_len(d.cmd_name) },
        // SAFETY: as above.
        ENGINE_CTRL_GET_NAME_FROM_CMD => unsafe { copy_out(s, d.cmd_name) },
        // SAFETY: as above.
        ENGINE_CTRL_GET_DESC_LEN_FROM_CMD => unsafe { c_len(desc) },
        // SAFETY: as above.
        ENGINE_CTRL_GET_DESC_FROM_CMD => unsafe { copy_out(s, desc) },
        ENGINE_CTRL_GET_CMD_FLAGS => c_int::try_from(d.cmd_flags).unwrap_or(c_int::MAX),
        _ => {
            err::raise(
                ERR_LIB_ENGINE,
                ENGINE_R_INTERNAL_LIST_ERROR,
                "int_ctrl_helper",
            );
            -1
        }
    }
}

ffi_export! {
    /// Runs the control command `cmd` on the engine: the `ENGINE_CTRL_*` questions about its
    /// command definitions are answered here, everything else goes to its control function.
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `i`, `p` and `f` are what the command takes.
    pub unsafe extern "C" fn ENGINE_ctrl(e: *mut ENGINE, cmd: c_int, i: c_long, p: *mut c_void, f: Option<unsafe extern "C" fn()>) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(fl) = (unsafe { fields(e) }) else {
            null_parameter("ENGINE_ctrl");
            return 0;
        };
        let exists = fl.ctrl.is_some();
        match cmd {
            ENGINE_CTRL_HAS_CTRL_FUNCTION => return c_int::from(exists),
            ENGINE_CTRL_GET_FIRST_CMD_TYPE
            | ENGINE_CTRL_GET_NEXT_CMD_TYPE
            | ENGINE_CTRL_GET_CMD_FROM_NAME
            | ENGINE_CTRL_GET_NAME_LEN_FROM_CMD
            | ENGINE_CTRL_GET_NAME_FROM_CMD
            | ENGINE_CTRL_GET_DESC_LEN_FROM_CMD
            | ENGINE_CTRL_GET_DESC_FROM_CMD
            | ENGINE_CTRL_GET_CMD_FLAGS => {
                if exists && fl.flags & ENGINE_FLAGS_MANUAL_CMD_CTRL == 0 {
                    // SAFETY: the engine's definitions; `p` as the command takes it.
                    return unsafe { helper(fl.cmd_defns, cmd, i, p) };
                }
                if !exists {
                    err::raise(ERR_LIB_ENGINE, ENGINE_R_NO_CONTROL_FUNCTION, "ENGINE_ctrl");
                    return -1;
                }
            }
            _ => {}
        }
        let Some(ctrl) = fl.ctrl else {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_NO_CONTROL_FUNCTION, "ENGINE_ctrl");
            return 0;
        };
        // SAFETY: the engine's own function, with the caller's arguments; no lock is held.
        unsafe { ctrl(e, cmd, i, p, f) }
    }
}

ffi_export! {
    /// Whether the command numbered `cmd` can be run (takes no input, a number or a string):
    /// 1, or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_cmd_is_executable(e: *mut ENGINE, cmd: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let flags = unsafe { ENGINE_ctrl(e, ENGINE_CTRL_GET_CMD_FLAGS, c_long::from(cmd), ptr::null_mut(), None) };
        if flags < 0 {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_INVALID_CMD_NUMBER, "ENGINE_cmd_is_executable");
            return 0;
        }
        let flags = flags.cast_unsigned();
        let any = ENGINE_CMD_FLAG_NO_INPUT | ENGINE_CMD_FLAG_NUMERIC | ENGINE_CMD_FLAG_STRING;
        c_int::from(flags & any != 0)
    }
}

/// The number of the command named `name`, or the error OpenSSL's callers raise: `Ok(None)`
/// when the command is optional and missing (the queue cleared).
///
/// # Safety
/// `e` is a live engine; `name` a C string.
unsafe fn number(
    e: *mut ENGINE,
    name: *const c_char,
    optional: c_int,
    function: &str,
) -> Result<Option<c_int>, ()> {
    // SAFETY: the caller's guarantee.
    let has_ctrl = unsafe { fields(e) }.is_some_and(|f| f.ctrl.is_some());
    let num = if has_ctrl {
        // SAFETY: as above.
        unsafe {
            ENGINE_ctrl(
                e,
                ENGINE_CTRL_GET_CMD_FROM_NAME,
                0,
                name.cast_mut().cast(),
                None,
            )
        }
    } else {
        0
    };
    if num > 0 {
        return Ok(Some(num));
    }
    if optional != 0 {
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
        return Ok(None);
    }
    err::raise(ERR_LIB_ENGINE, ENGINE_R_INVALID_CMD_NAME, function);
    Err(())
}

ffi_export! {
    /// Runs the command named `cmd_name` with `i`, `p` and `f`: 1 if the engine returned
    /// more than 0, else 0. A missing command succeeds when `cmd_optional` is set.
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `cmd_name` NULL or a C string; the rest what the command
    /// takes.
    pub unsafe extern "C" fn ENGINE_ctrl_cmd(e: *mut ENGINE, cmd_name: *const c_char, i: c_long, p: *mut c_void, f: Option<unsafe extern "C" fn()>, cmd_optional: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if unsafe { fields(e) }.is_none() || cmd_name.is_null() {
            null_parameter("ENGINE_ctrl_cmd");
            return 0;
        }
        // SAFETY: as above.
        let num = match unsafe { number(e, cmd_name, cmd_optional, "ENGINE_ctrl_cmd") } {
            Ok(Some(n)) => n,
            Ok(None) => return 1,
            Err(()) => return 0,
        };
        // SAFETY: as above.
        c_int::from(unsafe { ENGINE_ctrl(e, num, i, p, f) } > 0)
    }
}

/// `strtol(arg, &end, 10)` with the whole string a number: its value, or `None`.
fn decimal(arg: &[u8]) -> Option<c_long> {
    // strtol skips leading white space and takes a sign; an empty number or anything after
    // it fails here.
    let s = core::str::from_utf8(arg).ok()?;
    let t = s.trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r']);
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, t.get(1..)?),
        Some(b'+') => (false, t.get(1..)?),
        _ => (false, t),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Out of range saturates, as strtol's does.
    let mut v: c_long = 0;
    for b in digits.bytes() {
        let d = c_long::from(b - b'0');
        v = v
            .saturating_mul(10)
            .saturating_add(if neg { -d } else { d });
    }
    Some(v)
}

ffi_export! {
    /// Runs the command named `cmd_name` with the text `arg`, as its definition says to take
    /// it (no input, a number, or a string): 1, or 0. A missing command succeeds when
    /// `cmd_optional` is set.
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `cmd_name` and `arg` NULL or C strings.
    pub unsafe extern "C" fn ENGINE_ctrl_cmd_string(e: *mut ENGINE, cmd_name: *const c_char, arg: *const c_char, cmd_optional: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        const F: &str = "ENGINE_ctrl_cmd_string";
        // SAFETY: the caller's guarantee.
        if unsafe { fields(e) }.is_none() || cmd_name.is_null() {
            null_parameter(F);
            return 0;
        }
        // SAFETY: as above.
        let num = match unsafe { number(e, cmd_name, cmd_optional, F) } {
            Ok(Some(n)) => n,
            Ok(None) => return 1,
            Err(()) => return 0,
        };
        // SAFETY: as above.
        if unsafe { ENGINE_cmd_is_executable(e, num) } == 0 {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_CMD_NOT_EXECUTABLE, F);
            return 0;
        }
        // SAFETY: as above.
        let flags = unsafe { ENGINE_ctrl(e, ENGINE_CTRL_GET_CMD_FLAGS, c_long::from(num), ptr::null_mut(), None) };
        if flags < 0 {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_INTERNAL_LIST_ERROR, F);
            return 0;
        }
        let flags = flags.cast_unsigned();
        if flags & ENGINE_CMD_FLAG_NO_INPUT != 0 {
            if !arg.is_null() {
                err::raise(ERR_LIB_ENGINE, ENGINE_R_COMMAND_TAKES_NO_INPUT, F);
                return 0;
            }
            // SAFETY: as above.
            return c_int::from(unsafe { ENGINE_ctrl(e, num, 0, ptr::null_mut(), None) } > 0);
        }
        if arg.is_null() {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_COMMAND_TAKES_INPUT, F);
            return 0;
        }
        if flags & ENGINE_CMD_FLAG_STRING != 0 {
            // SAFETY: as above.
            return c_int::from(unsafe { ENGINE_ctrl(e, num, 0, arg.cast_mut().cast(), None) } > 0);
        }
        if flags & ENGINE_CMD_FLAG_NUMERIC == 0 {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_INTERNAL_LIST_ERROR, F);
            return 0;
        }
        // SAFETY: a C string (the caller's guarantee).
        let Some(l) = decimal(unsafe { CStr::from_ptr(arg) }.to_bytes()) else {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER, F);
            return 0;
        };
        // SAFETY: as above.
        c_int::from(unsafe { ENGINE_ctrl(e, num, l, ptr::null_mut(), None) } > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::decimal;

    #[test]
    fn decimal_reads_as_strtol_does() {
        assert_eq!(decimal(b"12"), Some(12));
        assert_eq!(decimal(b" -3"), Some(-3));
        assert_eq!(decimal(b"+7"), Some(7));
        assert_eq!(decimal(b""), None);
        assert_eq!(decimal(b"-"), None);
        assert_eq!(decimal(b"1x"), None);
        assert_eq!(
            decimal(b"99999999999999999999999"),
            Some(core::ffi::c_long::MAX)
        );
    }
}
