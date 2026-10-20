//! `apps/lib/engine.c`: the `-engine` option and engine key URIs.

use rustyssl_ossl::engine;

pub use rustyssl_ossl::engine::Engine;

use super::io;
use super::opt::eprintf;

/// `ENGINE_METHOD_ALL` of `engine.h`.
const ENGINE_METHOD_ALL: u32 = rustyssl_ossl::abi::ENGINE_METHOD_ALL;

/// `ENGINE_SCHEME_COLON` of `engine_loader.h`.
const ENGINE_SCHEME_COLON: &str = "org.openssl.engine:";

/// `try_load_engine`: a shared library through the `dynamic` engine.
fn try_load_engine(id: &str) -> Option<Engine> {
    let e = Engine::by_id("dynamic")?;
    if !e.ctrl_cmd_string("SO_PATH", Some(id)) || !e.ctrl_cmd_string("LOAD", None) {
        return None;
    }
    Some(e)
}

/// `setup_engine_methods(id, methods, debug)`.
pub fn setup_engine_methods(id: Option<&str>, methods: u32, debug: bool) -> Option<Engine> {
    let id = id?;
    if id == "auto" {
        eprintf!("Enabling auto ENGINE support\n");
        engine::register_all_complete();
        return None;
    }
    let Some(e) = Engine::by_id(id).or_else(|| try_load_engine(id)) else {
        eprintf!("Invalid engine \"{id}\"\n");
        io::print_errors();
        return None;
    };
    if debug && let Some(b) = io::bio_err() {
        e.set_logstream(b);
    }
    if !e.set_user_interface() || !e.set_default(methods) {
        eprintf!("Cannot use engine \"{}\"\n", e.id());
        io::print_errors();
        return None;
    }
    eprintf!("Engine \"{}\" set.\n", e.id());
    Some(e)
}

/// `setup_engine(id, debug)`: every method.
pub fn setup_engine(id: Option<&str>, debug: bool) -> Option<Engine> {
    setup_engine_methods(id, ENGINE_METHOD_ALL, debug)
}

/// `init_engine`.
pub fn init_engine(e: Option<&Engine>) -> bool {
    e.is_none_or(|e| e.init() == 1)
}

/// `finish_engine`.
pub fn finish_engine(e: Option<&Engine>) -> bool {
    e.is_none_or(|e| e.finish() == 1)
}

/// `make_engine_uri`: `org.openssl.engine:<id>:<key_id>`.
pub fn make_engine_uri(e: Option<&Engine>, key_id: Option<&str>, desc: &str) -> Option<String> {
    let Some(e) = e else {
        eprintf!("No engine specified for loading {desc}\n");
        return None;
    };
    let Some(key_id) = key_id else {
        eprintf!("No engine key id specified for loading {desc}\n");
        return None;
    };
    Some(format!("{ENGINE_SCHEME_COLON}{}:{key_id}", e.id()))
}
