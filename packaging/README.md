# Packaging recipes

Each recipe builds with `cargo xtask package <layout>` (which needs the pinned Rust toolchain,
`rust-toolchain.toml`, and a C compiler) and installs the staged tree, side by side with the
distribution's OpenSSL. Nothing of the system's OpenSSL is replaced until an administrator runs
`rustyssl-select rustyssl`; removing the package selects the system's OpenSSL again. See
[docs/MIGRATION.md](../docs/MIGRATION.md).

| Recipe | Distribution | Layout |
|---|---|---|
| `debian/` | Debian 13, Ubuntu 24.04 and later | `debian` |
| `rpm/rustyssl.spec` | Fedora; RHEL 10 and its rebuilds (`%rhel` selects `el`) | `fedora`, `el` |
| `alpine/APKBUILD` | Alpine | `alpine` |
| `homebrew/rustyssl.rb` | Homebrew on macOS (a keg-only formula) | `homebrew` |

`cargo xtask test-distro` installs the same trees in each distribution's container and runs the
system tests (docs/TEST_PLAN.md, L11). The recipes themselves are templates for packagers: the
version and source URL are this repository's.
