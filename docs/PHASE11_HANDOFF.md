# Phase 11 hand-off: the `openssl` command-line tool in Rust

For whoever continues Phase 11 (a person, or a Claude session in the cloud or locally). The
design is [ADR 0007](adr/0007-openssl-cli.md); read it in full first. This note says where the
work stands, how to run it, and the brief for each piece.

## Where it stands (2026-10-20)

- `main` has Phases 1–10: libcrypto implements all 5899 exports of OpenSSL 3.6.5's
  `libcrypto.num`, and libssl all 603. The reference build is OpenSSL 3.6.5.
- Branch `apps-design`: ADR 0007.
- Branch `cli-f0` (this one): ADR 0007 plus the user's four decisions (ADR section 7), upstream's
  `apps/` and `doc/man1/` vendored into `abi/openssl-3.6/`, `scripts/gates.sh`, `CLAUDE.md`,
  and this note. Nothing of F0's code exists yet: the next step is F0 (below).

## How to work

- **Rules:** [AGENTS.md](../AGENTS.md). In particular: `unsafe` only in `rustyssl-capi`, `libs/*`
  and `rustyssl-ossl` (with a `// SAFETY:` comment on each block); never hand-type ABI facts
  (option tables come from codegen); every behavior is measured against the reference.
- **Gates:** `bash scripts/gates.sh` runs everything CI does, with one summary line per gate. A
  failing gate doesn't stop the run; check every `exit` value, not just the last line.
- **One piece per session.** Each fork below is a separate session on its own branch. Commit in
  reviewable steps as you go (a session can be stopped at any time), and end with a short status:
  what's done, test results, what's left.
- **When a piece is done:** all gates pass, the plan (`docs/IMPLEMENTATION_PLAN.md`, Phase 11) is
  updated, and the branch goes up as a PR against `main`. Commit messages and PR descriptions
  end with the attribution lines the session's own instructions give.

### Pitfalls learned in earlier phases

- **Read exit codes, not colored output.** Run cargo with `--color never` (or `CARGO_TERM_COLOR=never`)
  and check `$?`; colored or word-split output once hid clippy failures.
- **CI's GCC is stricter than clang.** It rejects unused macro values (cast them to `(void)`:
  `(void)BIO_reset(b);`) and, with glibc under `-std=c99`, POSIX functions like `setenv` unless the
  file starts with `#define _POSIX_C_SOURCE 200809L`. `scripts/gates.sh` runs this check.
- **C argument evaluation order is unspecified.** Never pass two calls with side effects (an
  `up_ref` and a `free`) as arguments to one call; GCC on x86_64 evaluates right to left.
- **`ERR_print_errors` lines carry the thread id and `file:line`.** Mask them in any golden output.
- **`c_char` is `u8` on aarch64 Linux.** Compare bytes with `to_ne_bytes()`, not casts.
- **Don't run two gate runs at once** in one checkout: they share `target/dist`.
- **A random `test-differential` failure** names its seed; replay it with `--seed` before deciding
  whether it's real. Some sessions reach recorded deviations (`docs/DEVIATIONS.md`); the fix there
  is in the generator, not the library.

## The pieces

Run **F0 first, alone**; G1–G6 start from F0's merged result and run in parallel; 11.2 is last.

### F0: the foundation

Per ADR 0007 sections 2–6:
- **Crates:** `crates/rustyssl-ossl` (generated bindings, loaded at start-up by soname,
  fail-closed) and `crates/rustyssl-cli` (`#![forbid(unsafe_code)]`), plus codegen of the
  bindings and of every command's option table from `abi/openssl-3.6/apps/*.c`.
- **Shared code:** `cli::opt` (opt.c's semantics and exact help/usage/error texts), dispatch, and
  the shared helpers in section 5 apart from `s_cb`/`s_socket`.
- **First command:** `version`, complete. Unported commands print
  `openssl: <cmd> is not implemented in rustyssl's CLI yet` and exit 1.
- **Build and harness:** `cargo xtask dist` installs the binary as
  `target/dist/bin/openssl-rs`; `test-apps` gets the three-run model and per-command corpora;
  `test-openssl-suite --all` gets `--cli ours`.
- **AGENTS.md:** rule 1 and the architecture listing name `rustyssl-ossl`.
- **Tests:** golden tests for `version` and for every command's `-help` (byte-comparable as soon
  as the tables are generated), and unit tests for the parser.

### G1–G6: the commands (in parallel, after F0)

Each owns `crates/rustyssl-cli/src/cmd/<command>.rs` and `tests/apps/<command>.txt` for its
commands, and doesn't edit `cli::opt` or `src/lib/` (a new shared helper goes in the command
file; ask for it to be moved). Every option is covered by the corpus, output is byte-exact in
all three `test-apps` runs, and exit codes match.

| Fork | Commands |
|---|---|
| G1 | `dgst`, `enc`, `rand`, `mac`, `kdf`, `passwd`, `prime`, `errstr`, `asn1parse`, `list`, `rehash`, `info`, `nseq` |
| G2 | `genpkey`, `pkey`, `pkeyparam`, `pkeyutl`, `skeyutl`, `genrsa`, `rsa`, `rsautl`, `dsa`, `dsaparam`, `gendsa`, `ec`, `ecparam`, `dhparam`, `pkcs8` |
| G3 | `x509`, `req`, `verify`, `crl`, `crl2pkcs7`, `ca`, `spkac`, `storeutl` |
| G4 | `pkcs12`, `pkcs7`, `cms`, `smime`, `ocsp`, `ts`, `cmp` (with `cmp_mock_srv`), `sess_id` |
| G5 | `s_client`, `s_server`, `s_time`, `ciphers`, `srp`, plus the shared `s_cb`/`s_socket` |
| G6 | `speed`, `engine`, `fipsinstall` (as on the reference, which has no FIPS module), `configutl` |

Not byte-compared (decision 4): `speed`'s numbers, interactive `s_client`/`s_server` sessions
(script them with `-ign_eof`/`-naccept` and fixed input), and TTY password prompts (test with
`-passin`/`-passout`). Their runs must still succeed with the same exit codes.

### 11.2: the upstream recipes with our CLI (last)

Once every command is ported: switch `target/dist/bin/openssl` to our binary (decision 3), run
`cargo xtask test-openssl-suite --all --cli ours`, and match upstream's binary on our libraries
(4334 of 4334 eligible subtests on macOS today). Then mark Phase 11 done with its exit status.

## Running in Claude Code's cloud

- **Environment:** network access **Custom** with the default package-manager list plus
  `openssl-library.org` (OpenSSL's signing keys and checksums); GitHub release downloads are
  already allowed. Set `BASH_DEFAULT_TIMEOUT_MS=600000` and `BASH_MAX_TIMEOUT_MS=3600000`.
- **Setup script:**
  ```bash
  #!/bin/bash
  set -e
  apt-get update -qq && apt-get install -y -qq gpgv gnupg perl make pkg-config libclang-dev netbase
  curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
  source "$HOME/.cargo/env"
  ( cargo install --locked bindgen-cli --version 0.73.2 ) &
  ( cargo install --locked cargo-deny@0.20.2 cargo-vet@0.10.2 ) &
  wait
  ```
  `rust-toolchain.toml` installs the pinned toolchain on first use. For Miri, add
  `rustup toolchain install nightly --profile minimal --component miri,rust-src`.
- **First commands in a fresh session:** `cargo xtask ref-openssl` (builds the 3.6.5 reference
  into `target/ref/`), then `cargo xtask dist`.
- **The cloud is x86_64 Linux only.** macOS (aarch64) runs, including `abi-check`'s `otool`
  checks, need a Mac; CI covers x86_64 Linux.
