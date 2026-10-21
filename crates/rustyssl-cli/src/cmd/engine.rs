//! `openssl engine` (`apps/engine.c`): engines, their capabilities and control commands.

use std::io::Write;

use rustyssl_ossl::abi::{
    ENGINE_CMD_FLAG_INTERNAL, ENGINE_CMD_FLAG_NO_INPUT, ENGINE_CMD_FLAG_NUMERIC,
    ENGINE_CMD_FLAG_STRING, ENGINE_CTRL_GET_CMD_FLAGS, ENGINE_CTRL_GET_DESC_FROM_CMD,
    ENGINE_CTRL_GET_DESC_LEN_FROM_CMD, ENGINE_CTRL_GET_FIRST_CMD_TYPE,
    ENGINE_CTRL_GET_NAME_FROM_CMD, ENGINE_CTRL_GET_NAME_LEN_FROM_CMD,
    ENGINE_CTRL_GET_NEXT_CMD_TYPE, ENGINE_CTRL_HAS_CTRL_FUNCTION,
};
use rustyssl_ossl::engine::{self, Engine};
use rustyssl_ossl::err;

use crate::generated::options::engine::{OPTIONS, Opt};
use crate::lib::io;
use crate::lib::opt::{self, Parser, eprintf};

/// The indent of the per-engine lines.
const INDENT: &str = "     ";

/// Writes to standard output (`out` of `engine_main`, a `BIO` on `stdout`).
fn put(text: &str) -> usize {
    let _ = io::out().write_all(text.as_bytes());
    text.len()
}

/// `ERR_print_errors(out)`.
fn print_errors_out() {
    if let Some(b) = io::bio_out() {
        err::print_errors(b);
    }
}

/// `util_flags`: a command's input flags.
fn util_flags(flags: u32, indent: &str) {
    let mut text = format!("{indent}{indent}(input flags): ");
    if flags == 0 {
        put(&format!("{text}<no flags>\n"));
        return;
    }
    let (mut started, mut bad) = (false, false);
    if flags & ENGINE_CMD_FLAG_INTERNAL != 0 {
        text.push_str("[Internal] ");
    }
    if flags & ENGINE_CMD_FLAG_NUMERIC != 0 {
        text.push_str("NUMERIC");
        started = true;
    }
    // NUMERIC, STRING, and NO_INPUT exclude each other.
    for (flag, name) in [
        (ENGINE_CMD_FLAG_STRING, "STRING"),
        (ENGINE_CMD_FLAG_NO_INPUT, "NO_INPUT"),
    ] {
        if flags & flag != 0 {
            if started {
                text.push('|');
                bad = true;
            }
            text.push_str(name);
            started = true;
        }
    }
    let unknown = flags
        & !(ENGINE_CMD_FLAG_NUMERIC
            | ENGINE_CMD_FLAG_STRING
            | ENGINE_CMD_FLAG_NO_INPUT
            | ENGINE_CMD_FLAG_INTERNAL);
    if unknown != 0 {
        if started {
            text.push('|');
        }
        text.push_str(&format!("<0x{unknown:04X}>"));
    }
    if bad {
        text.push_str("  <illegal flags!>");
    }
    text.push('\n');
    put(&text);
}

/// `util_verbose`: the engine's control commands, at the given verbosity (1 to 4).
fn util_verbose(e: &Engine, verbose: i32, indent: &str) -> bool {
    const LINE_WRAP: usize = 78;
    if e.ctrl_num(ENGINE_CTRL_HAS_CTRL_FUNCTION, 0) == 0 {
        return true;
    }
    let mut num = e.ctrl_num(ENGINE_CTRL_GET_FIRST_CMD_TYPE, 0);
    if num <= 0 {
        return true;
    }
    let mut xpos = 0usize;
    loop {
        let flags = e.ctrl_num(ENGINE_CTRL_GET_CMD_FLAGS, num.into());
        let Ok(flags) = u32::try_from(flags) else {
            return false;
        };
        if flags & ENGINE_CMD_FLAG_INTERNAL == 0 || verbose >= 4 {
            let Ok(len) =
                usize::try_from(e.ctrl_num(ENGINE_CTRL_GET_NAME_LEN_FROM_CMD, num.into()))
            else {
                return false;
            };
            if len == 0 {
                return false;
            }
            let (r, name) = e.ctrl_text(ENGINE_CTRL_GET_NAME_FROM_CMD, num.into(), len);
            if r <= 0 {
                return false;
            }
            let Ok(len) =
                usize::try_from(e.ctrl_num(ENGINE_CTRL_GET_DESC_LEN_FROM_CMD, num.into()))
            else {
                return false;
            };
            let mut desc = None;
            if len > 0 {
                let (r, d) = e.ctrl_text(ENGINE_CTRL_GET_DESC_FROM_CMD, num.into(), len);
                if r <= 0 {
                    return false;
                }
                desc = Some(d);
            }
            if xpos == 0 {
                xpos = put(indent);
            } else {
                xpos += put(", ");
            }
            if verbose == 1 {
                // Names only, comma-separated, wrapped.
                if xpos > indent.len() && xpos + name.len() > LINE_WRAP {
                    put("\n");
                    xpos = put(indent);
                }
                xpos += put(&name);
            } else {
                let desc = desc.as_deref().unwrap_or("<no description>");
                put(&format!("{name}: {desc}\n"));
                if verbose >= 3 {
                    util_flags(flags, indent);
                }
                xpos = 0;
            }
        }
        num = e.ctrl_num(ENGINE_CTRL_GET_NEXT_CMD_TYPE, num.into());
        if num <= 0 {
            break;
        }
    }
    if xpos > 0 {
        put("\n");
    }
    true
}

/// `util_do_cmds`: each `CMD` or `CMD:ARG` against the engine.
fn util_do_cmds(e: &Engine, cmds: &[String]) {
    for cmd in cmds {
        let bytes = cmd.as_bytes();
        let ok = match bytes.iter().position(|&b| b == b':') {
            None => e.ctrl_cmd_string_ret(bytes, None) != 0,
            Some(colon) => {
                if colon > 254 {
                    put("[Error]: command name too long\n");
                    return;
                }
                let (name, arg) = bytes.split_at(colon);
                e.ctrl_cmd_string_ret(name, arg.get(1..)) != 0
            }
        };
        if ok {
            put(&format!("[Success]: {cmd}\n"));
        } else {
            put(&format!("[Failure]: {cmd}\n"));
            print_errors_out();
        }
    }
}

pub fn main(argv: &[String]) -> i32 {
    let ret = run(argv);
    io::print_errors();
    ret
}

fn run(argv: &[String]) -> i32 {
    // Leading engine names, then the options.
    let prog = argv.first().cloned().unwrap_or_default();
    let mut engines: Vec<String> = Vec::new();
    let mut rest = argv.get(1..).unwrap_or_default();
    while let Some((first, tail)) = rest.split_first() {
        if first.starts_with('-') {
            break;
        }
        engines.push(first.clone());
        rest = tail;
    }
    let mut args = vec![prog.clone()];
    args.extend_from_slice(rest);

    let mut p = Parser::new(&args, OPTIONS);
    let (mut verbose, mut list_cap, mut test_avail, mut test_avail_noise) = (0, false, 0, 0);
    let (mut pre_cmds, mut post_cmds) = (Vec::new(), Vec::new());
    loop {
        let o = p.next();
        match o {
            Opt::EOF => break,
            Opt::ERR => {
                eprintf!("{prog}: Use -help for summary.\n");
                return 1;
            }
            Opt::HELP => {
                opt::help(OPTIONS);
                return 0;
            }
            Opt::V | Opt::VV | Opt::VVV | Opt::VVVV => {
                let i = match o {
                    Opt::V => 1,
                    Opt::VV => 2,
                    Opt::VVV => 3,
                    _ => 4,
                };
                verbose = verbose.max(i);
            }
            Opt::C => list_cap = true,
            Opt::TT => {
                test_avail_noise += 1;
                test_avail += 1;
            }
            Opt::T => test_avail += 1,
            Opt::PRE => pre_cmds.push(p.arg().to_owned()),
            Opt::POST => post_cmds.push(p.arg().to_owned()),
        }
    }

    // Whatever remains are engine names.
    for a in p.rest() {
        if a.starts_with('-') {
            eprintf!("{prog}: Cannot mix flags and engine names.\n");
            eprintf!("{prog}: Use -help for summary.\n");
            return 1;
        }
        engines.push(a.clone());
    }
    if engines.is_empty() {
        engines = engine::ids();
    }

    let mut ret = 0;
    for id in &engines {
        let Some(e) = Engine::by_id(id) else {
            io::print_errors();
            // Exit codes above 127 mean something else on Unix.
            ret = (ret + 1).min(127);
            continue;
        };
        put(&format!("({id}) {}\n", e.name()));
        util_do_cmds(&e, &pre_cmds);
        if e.id() != *id {
            put(&format!("Loaded: ({}) {}\n", e.id(), e.name()));
        }
        if list_cap {
            // `append_buf`: ", " goes between non-empty parts only.
            let mut buf = String::new();
            for cap in e.capabilities() {
                if !buf.is_empty() {
                    buf.push_str(", ");
                }
                buf.push_str(&cap);
            }
            if !buf.is_empty() {
                put(&format!(" [{buf}]\n"));
            }
        }
        if test_avail > 0 {
            put(INDENT);
            if e.init() != 0 {
                put("[ available ]\n");
                util_do_cmds(&e, &post_cmds);
                e.finish();
            } else {
                put("[ unavailable ]\n");
                if test_avail_noise > 0 {
                    let _ = io::out().write_all(&err::errors_text());
                }
                err::clear();
            }
        }
        if verbose > 0 && !util_verbose(&e, verbose, INDENT) {
            return ret;
        }
    }
    ret
}
