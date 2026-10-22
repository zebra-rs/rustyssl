# Migrating to rustyssl

rustyssl is a drop-in replacement for OpenSSL 3's `libcrypto.so.3` and `libssl.so.3` (macOS:
`libcrypto.3.dylib`, `libssl.3.dylib`) and its `openssl` tool. Programs built against OpenSSL 3
run on it unchanged: no rebuild, no source change. This guide covers installing it, switching
programs to it, checking that they use it, and switching back.

## Install

Build the package for your distribution with `cargo xtask package <layout>` (it needs the Rust
toolchain pinned in `rust-toolchain.toml` and a C compiler), or use the recipes in
[`packaging/`](../packaging/README.md).

| Distribution | Layout | rustyssl's directory | OPENSSLDIR (shared with the system) |
|---|---|---|---|
| Debian 13, Ubuntu 24.04 and later | `debian` | `/usr/lib/<arch>-linux-gnu/rustyssl` | `/usr/lib/ssl` |
| Fedora | `fedora` | `/usr/lib64/rustyssl` | `/etc/pki/tls` |
| RHEL 10 and its rebuilds (AlmaLinux, Rocky) | `el` | `/usr/lib64/rustyssl` | `/etc/pki/tls` |
| Alpine | `alpine` | `/usr/lib/rustyssl` | `/etc/ssl` |
| Homebrew (macOS) | `homebrew` | the keg (`opt/rustyssl`) | `etc/rustyssl` |

The tarball `target/package/rustyssl-<version>-<layout>-<arch>.tar.gz` unpacks at `/`; use GNU
tar's `--keep-directory-symlink` (Fedora 42 and later have `/usr/sbin` as a symlink, for
example). On Alpine the package depends on `llvm-libunwind` (Rust's unwinder on musl).

rustyssl's directory holds the libraries and their development links and archives,
`ossl-modules/legacy.so` (the legacy provider, MODULESDIR), `engines-3/` (ENGINESDIR, empty),
`bin/openssl`, `bin/rustyssl-select`, `include/openssl/`, and `pkgconfig/`. It reads the system's
OPENSSLDIR, so the distribution's `openssl.cnf` applies, Fedora's and RHEL's crypto policies
included; upstream's defaults are installed beside it as `openssl.cnf.dist` and
`ct_log_list.cnf.dist`. Installing changes nothing for running programs.

### Fedora and RHEL: the Fedora profile

Fedora's libcrypto exports more than upstream's default build: MD2 (`EVP_md2`, `MD2_*`), the
SCTP datagram BIO's functions, and `EVP_MD_CTX_dup`/`EVP_CIPHER_CTX_dup` at `OPENSSL_3.1.0`.
Fedora's binaries that import them (ipmitool, perl-Net-SSLeay, qca, dpdk, ...) need them to load,
so the `fedora` and `el` layouts build `cargo xtask dist --profile fedora`, which exports them
too. MD2 is the legacy provider's, as in Fedora. rustyssl has no SCTP transport: those functions
fail as OpenSSL's do on a kernel without SCTP-AUTH (docs/DEVIATIONS.md).

## Switch

```sh
rustyssl-select rustyssl   # rustyssl's libraries first for every program, and its openssl
rustyssl-select status     # rustyssl or system
rustyssl-select system     # the system's OpenSSL again
```

(`rustyssl-select` is in rustyssl's directory, `bin/`.) Selecting rustyssl puts its directory
ahead of the system's in the dynamic loader's search, for every program, setuid ones included:
a drop-in `/etc/ld.so.conf.d/00-rustyssl.conf` and `ldconfig` with glibc, or
`/etc/ld-musl-<arch>.path` with musl. It also links `/usr/local/bin/openssl` to rustyssl's tool.
The system's files are never modified, so going back is `rustyssl-select system`, and removing
the package does that first. Programs already running keep the libraries they loaded: restart
services (sshd, nginx, httpd, PostgreSQL, ...) after switching.

To try one program without switching the system, run it with `LD_LIBRARY_PATH` set to
rustyssl's directory (`DYLD_LIBRARY_PATH` on macOS, for programs outside SIP).

## Check

- `openssl version` prints `Library: OpenSSL 3.6.5+rustyssl.<version>`.
- A program's mapped libraries name rustyssl's directory: `grep libssl /proc/<pid>/maps`, or
  `ldd <program>` for a new process.
- `OpenSSL_version(OPENSSL_VERSION)` in a program returns the same text.

`cargo xtask test-distro` runs these checks and the system tests (package managers over HTTPS,
sshd, nginx, httpd, curl, wget, git, pip, PostgreSQL with `sslmode=verify-full`, and Fedora's
crypto policies) in each distribution's container, on the system's OpenSSL and on rustyssl.

## Homebrew

`homebrew/rustyssl.rb` is keg-only: it never replaces `openssl@3`. Its libraries carry their
install names in the keg, so a program built against it uses it, and a program built against
`openssl@3` uses it with `DYLD_LIBRARY_PATH=$(brew --prefix rustyssl)/lib`. Homebrew's newer
programs (curl, Python 3.15) link `openssl@4`, whose ABI rustyssl doesn't provide yet (Phase 13).

## What differs

rustyssl matches OpenSSL's behavior, error codes, and output byte for byte wherever programs can
observe them; the exceptions, each for a security reason, are in
[docs/DEVIATIONS.md](DEVIATIONS.md). Third-party providers load as with OpenSSL. There is no FIPS
provider, and no ENGINE implementations (the ENGINE API is there and reports no engines).
