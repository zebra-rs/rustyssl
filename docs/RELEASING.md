# Releasing rustyssl

A release is a `v<version>` tag on `main`. The tag runs `.github/workflows/release.yml`: the whole
CI gate on Linux x86_64 and arm64 and macOS arm64, then the packages, then a **draft** GitHub
release, which a maintainer checks and publishes. On crates.io only the `rustyssl` crate is
published: it has no API and holds the name, pointing to the releases (the user's decision,
2026-10-23). The other crates keep `publish = false`: their Rust APIs are internal, and the
drop-in libraries come from `cargo xtask dist`, not from cargo.

## Before tagging

1. `main` is green: CI's last run on it passed, and so did the weekly run (arm64 and macOS).
2. Locally, on macOS: `bash scripts/gates.sh` with every `== ... -> exit 0` and Miri's
   `0 failed`; `cargo xtask test-openssl-suite --all --cli ours` matches the reference.
3. The version: `version` in the workspace's `Cargo.toml` (it becomes `+rustyssl.<version>` in
   `OpenSSL_version()`), the entries in `packaging/debian/changelog` and
   `packaging/rpm/rustyssl.spec`, and `url` in `packaging/homebrew/rustyssl.rb`.
4. `CHANGELOG.md` has the version's section with its date, and the version has its own release
   notes, `docs/RELEASE-NOTES-<version>.md` (`release.yml` makes them the release's description,
   and a dry run fails without them). They describe that release only: a patch release's notes
   say what changed since the last one and link to the earlier releases for the rest. GitHub
   shows the release's title above them and keeps their line breaks, so they have no `#` title
   and put each paragraph and list item on one line.
5. A dry run: Actions → Release → Run workflow on `main`. It runs everything but the draft and
   keeps the packages as the `release-dry-run` artifact; check them as below.

## Tagging

```sh
git switch main && git pull
git tag -s v1.0.0 -m "rustyssl 1.0.0"   # signed; -a if you don't sign tags
git push origin v1.0.0
```

## Checking the draft

The draft has, for `<version>`:

| File | Built on |
|---|---|
| `rustyssl-<version>-{debian,fedora,el}-x86_64.tar.gz` | Ubuntu 22.04 (glibc 2.35; the libraries need at most 2.34) |
| `rustyssl-<version>-{debian,fedora,el}-aarch64.tar.gz` | Ubuntu 22.04 arm64 |
| `rustyssl-<version>-alpine-{x86_64,aarch64}.tar.gz` | Alpine (musl) |
| `rustyssl-<version>-homebrew-arm64.tar.gz` | macOS 15, prefix `/opt/homebrew/Cellar/rustyssl/<version>` |
| `rustyssl-<version>-source.tar.gz` | `git archive` of the tag |
| `SHA256SUMS` | |

1. `sha256sum -c SHA256SUMS` in a directory with the downloads.
2. On Ubuntu 22.04 and 24.04, one architecture each at least: unpack the debian tarball into a
   scratch directory and run `LD_LIBRARY_PATH=<dir>/usr/lib/<triplet>/rustyssl openssl version`
   (it reads `+rustyssl.<version>`) and `curl -sI https://example.com`; on macOS, the keg's
   `bin/openssl version`.
3. Publish the draft.

## After publishing

- crates.io: `cargo publish -p rustyssl` from the tag, with the maintainer's token
  (`cargo login`). A version can be published only once. (1.0.0 was published from `main`: the
  crate was added after the tag.)
- Homebrew: set `sha256` in `packaging/homebrew/rustyssl.rb` to the source tarball's (GitHub's
  `archive/refs/tags/v<version>.tar.gz`, which differs from `rustyssl-<version>-source.tar.gz`).
- Start the next version's section in `CHANGELOG.md` (`## [Unreleased]`).
- Rerun `cargo xtask usage-scan` before the next release, to see what distributions import.
