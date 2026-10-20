//! `apps/lib/app_libctx.c` and `app_provider.c`: the library context and property query the
//! commands fetch with, and the `-provider`, `-provider-path`, `-provparam`, `-propquery`
//! options.

use std::cell::RefCell;
use std::rc::Rc;

use rustyssl_ossl::provider::{self, LibCtx, Provider};

use super::io;
use super::opt::{eprintf, prog};
use crate::generated::options::Prov;

#[derive(Default)]
struct State {
    libctx: Option<Rc<LibCtx>>,
    propq: Option<String>,
    providers: Vec<Provider>,
    provider_option_given: bool,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// `app_set_propq`.
pub fn set_propq(arg: &str) -> bool {
    STATE.with(|s| s.borrow_mut().propq = Some(arg.to_owned()));
    true
}

/// `app_get0_propq`.
pub fn propq() -> Option<String> {
    STATE.with(|s| s.borrow().propq.clone())
}

/// `app_get0_libctx`: `None` is the default context.
pub fn libctx() -> Option<Rc<LibCtx>> {
    STATE.with(|s| s.borrow().libctx.clone())
}

/// `app_create_libctx`: loads the null provider into the default context and makes the
/// context the provider options then apply to.
pub fn create_libctx() -> Option<Rc<LibCtx>> {
    if libctx().is_none() {
        if !provider_load(None, "null") {
            eprintf!("Failed to create null provider\n");
            return None;
        }
        let ctx = LibCtx::new().map(Rc::new);
        STATE.with(|s| s.borrow_mut().libctx = ctx);
    }
    let ctx = libctx();
    if ctx.is_none() {
        eprintf!("Failed to create library context\n");
    }
    ctx
}

/// `app_provider_load`.
pub fn provider_load(libctx: Option<&LibCtx>, name: &str) -> bool {
    let Some(p) = Provider::load(libctx, name) else {
        let prog = prog();
        eprintf!(
            "{prog}: unable to load provider {name}\n\
             Hint: use -provider-path option or OPENSSL_MODULES environment variable.\n"
        );
        io::print_errors();
        return false;
    };
    STATE.with(|s| s.borrow_mut().providers.push(p));
    true
}

/// `app_providers_cleanup`, and the context freed (`apps_shutdown`).
pub fn cleanup() {
    let providers = STATE.with(|s| std::mem::take(&mut s.borrow_mut().providers));
    // Unloaded first to last, as sk_OSSL_PROVIDER_pop_free does.
    drop(providers);
    STATE.with(|s| s.borrow_mut().libctx = None);
}

/// `opt_provider_path`.
fn provider_path(path: &str) -> bool {
    let path = if path.is_empty() { None } else { Some(path) };
    provider::set_default_search_path(libctx().as_deref(), path)
}

/// `opt_provider_param`: `[provider:]key=value`.
fn provider_param(arg: &str) -> bool {
    let prog = prog();
    let malformed = || {
        eprintf!("{prog}: malformed '-provparam' option value: '{arg}'\n");
        false
    };
    let Some((key, value)) = arg.split_once('=') else {
        return malformed();
    };
    let key = key.trim_end_matches(|c: char| c.is_ascii_whitespace());
    let value = value.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let (name, key) = match key.split_once(':') {
        Some((n, k)) => (if n.is_empty() { None } else { Some(n) }, k),
        None => (None, key),
    };
    if key.is_empty() {
        return malformed();
    }
    let mut found = false;
    let ok = provider::for_each(libctx().as_deref(), |p| {
        if name.is_some_and(|n| p.name() != n) {
            return true;
        }
        found = true;
        p.add_conf_parameter(key, value)
    });
    let shown = name.unwrap_or("(null)");
    if !ok {
        eprintf!("{prog}: Error setting provider '{shown}' parameter '{key}'\n");
        return false;
    }
    if !found {
        eprintf!("{prog}: No provider named '{shown}' is loaded\n");
        return false;
    }
    true
}

/// `opt_provider`: one of the provider options, with its value.
pub fn opt_provider(o: Prov, arg: &str) -> bool {
    STATE.with(|s| s.borrow_mut().provider_option_given = true);
    match o {
        Prov::PROVIDER => provider_load(libctx().as_deref(), arg),
        Prov::PROVIDER_PATH => provider_path(arg),
        Prov::PARAM => provider_param(arg),
        Prov::PROPQUERY => set_propq(arg),
    }
}

/// `opt_provider_option_given`.
pub fn provider_option_given() -> bool {
    STATE.with(|s| s.borrow().provider_option_given)
}

/// `opt_legacy_okay`: whether the legacy lookups (`EVP_get_digestbyname`, ...) may be used.
pub fn legacy_okay() -> bool {
    !(provider_option_given() || libctx().is_some() || propq().is_some())
}
