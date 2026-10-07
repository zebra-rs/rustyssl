//! `cargo xtask codegen`: regenerate everything derived from the vendored OpenSSL ABI in
//! `abi/`. Phase 0.3 adds the `rustssl-abi` bindings; Phase 0.4 adds the remaining generators.

mod abi;

use crate::util::{Result, workspace_root};

pub fn run(args: &[String]) -> Result {
    if !args.is_empty() {
        return Err("usage: cargo xtask codegen".into());
    }
    abi::generate(&workspace_root())
}
