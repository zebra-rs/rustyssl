# Trying rustyssl on Ubuntu 22.04 and 24.04

rustyssl replaces OpenSSL 3's `libcrypto.so.3` and `libssl.so.3`. Programs built against
OpenSSL 3, which on Ubuntu means everything using the `libssl3` package (`libssl3t64` on
24.04): curl, wget, git, Python, OpenSSH, ..., run on it unchanged. This guide builds it from source and tries it, first on one program at a
time with `LD_LIBRARY_PATH`, then system-wide with an install you can switch off again.

Everything here was run on `ubuntu:22.04` (OpenSSL 3.0.2, glibc 2.35, OpenSSH 8.9p1) and
`ubuntu:24.04` (OpenSSL 3.0.13, glibc 2.39, OpenSSH 9.6p1) containers, on x86_64 (amd64) and
aarch64 (arm64). The commands are the same on both architectures. There are no prebuilt
packages yet (rustyssl 1.0 isn't released), so you build it yourself; it takes a few minutes.

**Read [SSH](#ssh) before switching a whole system on 22.04**: Ubuntu 22.04's OpenSSH refuses
any libcrypto other than 3.0.x, so selecting rustyssl system-wide there stops `sshd`.

## What you get

`cargo xtask dist` builds into `target/dist/`:

| Path | What |
|---|---|
| `lib/libcrypto.so.3`, `lib/libssl.so.3` | the drop-in libraries (symbol versions `OPENSSL_3.0.0` to `OPENSSL_3.6.0`, so programs built against 3.0 load them) |
| `lib/ossl-modules/legacy.so` | the legacy provider (MD4, RC4, DES, ...) |
| `bin/openssl` | rustyssl's `openssl` command-line tool |
| `include/openssl/`, `lib/pkgconfig/`, `lib/*.a` | headers, pkg-config files, and static archives for building against it |

rustyssl reports itself as OpenSSL 3.6.5 with a `+rustyssl` suffix, so you can always tell
which library a program loaded:

```console
$ LD_LIBRARY_PATH=$HOME/rustyssl/target/dist/lib openssl version
OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.6.5+rustyssl.1.0.0 29 Sep 2026)
```

(That is Ubuntu's own `openssl` binary, 3.0.2, running on rustyssl's library.)

## Build

```sh
sudo apt-get update
sudo apt-get install -y build-essential curl ca-certificates git

# Rust: rustup installs the toolchain pinned in rust-toolchain.toml on first use.
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
. "$HOME/.cargo/env"

git clone https://github.com/zebra-rs/rustyssl.git ~/rustyssl
cd ~/rustyssl
RUSTYSSL_OPENSSLDIR=/usr/lib/ssl cargo xtask dist
```

- `cargo xtask dist` always builds the libraries and the tool optimized (`--release`); there's
  no separate release step.
- `RUSTYSSL_OPENSSLDIR=/usr/lib/ssl` makes rustyssl use Ubuntu's OpenSSL directory: its
  `openssl.cnf` and its CA certificates (`/usr/lib/ssl/certs`, which links to
  `/etc/ssl/certs`). Without it rustyssl uses upstream OpenSSL's default, `/usr/local/ssl`,
  which doesn't exist on Ubuntu; programs that rely on OpenSSL's default trust store
  (Python's `ssl`, `openssl s_client`) then fail with `unable to get local issuer certificate`
  unless you set `SSL_CERT_DIR=/etc/ssl/certs` (or
  `SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt`) when you run them. (Ubuntu's curl and
  wget set their own CA path and work either way.) `OPENSSL_CONF` selects a configuration file
  at run time the same way.
- The legacy provider is looked for in MODULESDIR, which defaults to
  `/usr/local/lib/ossl-modules` (`/usr/local/lib64/ossl-modules` on x86_64). To use it from
  the build tree, set `OPENSSL_MODULES=$HOME/rustyssl/target/dist/lib/ossl-modules` at run time
  (or build with `RUSTYSSL_MODULESDIR=...`). The [side-by-side install](#install-side-by-side)
  sets both directories for you.

The build needs glibc 2.34 or later at run time (Ubuntu 22.04 has 2.35), whichever of the two
releases you build on: libraries built on 24.04 run on 22.04 and the other way round. To check
a build:

```sh
objdump -T target/dist/lib/libcrypto.so.3 | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1
```

## Try it on one program: LD_LIBRARY_PATH

`LD_LIBRARY_PATH` puts rustyssl's directory ahead of the system's for the programs you start
with it, and nothing else. Nothing is installed and nothing changes for the rest of the system.

```sh
R=$HOME/rustyssl/target/dist/lib

LD_LIBRARY_PATH=$R openssl version                  # Library: OpenSSL 3.6.5+rustyssl...
LD_LIBRARY_PATH=$R curl -sS -o /dev/null -w '%{http_code}\n' https://www.openssl.org/
LD_LIBRARY_PATH=$R curl -V | head -1                # ... libcurl/... OpenSSL/3.6.5 ...
LD_LIBRARY_PATH=$R wget -q -O /dev/null https://github.com/ && echo ok
LD_LIBRARY_PATH=$R git ls-remote https://github.com/openssl/openssl HEAD
LD_LIBRARY_PATH=$R python3 -c 'import ssl; print(ssl.OPENSSL_VERSION)'
LD_LIBRARY_PATH=$R python3 -c 'import urllib.request; print(urllib.request.urlopen("https://www.python.org/").status)'

# rustyssl's own openssl tool
echo | LD_LIBRARY_PATH=$R ~/rustyssl/target/dist/bin/openssl s_client \
    -connect www.openssl.org:443 -servername www.openssl.org -brief
echo hi | LD_LIBRARY_PATH=$R OPENSSL_MODULES=$R/ossl-modules \
    ~/rustyssl/target/dist/bin/openssl dgst -md4 -provider legacy -provider default
```

To make a whole shell use it, `export LD_LIBRARY_PATH=$R` (and close the shell to stop).

### Check which library a program loaded

```sh
LD_LIBRARY_PATH=$R ldd /usr/bin/curl | grep -E 'libssl|libcrypto'
#   libssl.so.3 => /home/you/rustyssl/target/dist/lib/libssl.so.3
#   libcrypto.so.3 => /home/you/rustyssl/target/dist/lib/libcrypto.so.3

LD_DEBUG=libs LD_LIBRARY_PATH=$R openssl version 2>&1 | grep 'calling init:.*libcrypto'
#   calling init: /home/you/rustyssl/target/dist/lib/libcrypto.so.3

grep -E 'libssl|libcrypto' /proc/<pid>/maps       # a program that's already running
```

### When LD_LIBRARY_PATH doesn't apply

- **setuid and setgid programs** ignore it (the loader's secure-execution mode): a setuid-root
  binary run by a normal user loads the system's OpenSSL even with `LD_LIBRARY_PATH` set. Use the
  side-by-side install for them.
- **Binaries with `DT_RPATH`** pointing at the system's library directory search that first;
  `RUNPATH` (what current toolchains write) comes after `LD_LIBRARY_PATH`. Check with
  `readelf -d <binary> | grep -E 'RPATH|RUNPATH'`.
- **Programs that load OpenSSL by full path** with `dlopen()`, and **statically linked**
  programs, never look it up.
- **Snaps and Flatpaks** run confined with their own libraries, not the host's.
- **apt doesn't use OpenSSL**: its HTTPS transport links GnuTLS (`ldd
  /usr/lib/apt/methods/https`), so apt isn't a test of rustyssl.
- **Services** started by systemd don't inherit your shell's environment; see
  [SSH](#ssh) for a service example.

## SSH

OpenSSH (`ssh`, `sshd`, `ssh-keygen`) links `libcrypto.so.3` only, not `libssl`:

```sh
ldd /usr/bin/ssh /usr/sbin/sshd | grep -E 'libcrypto|libssl'
```

Which of SSH's algorithms reach libcrypto (measured on both releases' OpenSSH by intercepting
libcrypto's entry points during logins):

| Through libcrypto | Built into OpenSSH |
|---|---|
| ciphers `aes*-ctr`, `aes*-gcm@openssh.com`; the ChaCha20 part of `chacha20-poly1305@openssh.com` | Poly1305 |
| key exchange `ecdh-sha2-nistp*`, `diffie-hellman-group*` | `curve25519-sha256`, `sntrup761x25519-sha512@openssh.com` |
| host and user keys `ecdsa-sha2-nistp*`, `rsa-sha2-*` | `ssh-ed25519` |
| the SHA-1 and SHA-2 digests (the key exchange's hashes, `hmac-sha2-*`) | |

So to exercise rustyssl from SSH, choose libcrypto's algorithms explicitly; the defaults
(curve25519 and Ed25519 on these versions) mostly bypass it.

### Ubuntu 22.04: OpenSSH 8.9 refuses rustyssl

OpenSSH 8.9 accepts only an OpenSSL with the same major and minor version it was built
against (3.0), and rustyssl is 3.6.5:

```console
$ LD_LIBRARY_PATH=$R ssh -V
OpenSSL version mismatch. Built against 30000020, you have 30600050
```

The same happens to `sshd` and `ssh-keygen`, and to every one of them once rustyssl is selected
system-wide: **don't run `rustyssl-select rustyssl` on a 22.04 machine you reach over SSH**
(`sshd -t` fails, and the next `sshd` restart locks you out). It's OpenSSH 8.9's check, not
rustyssl's: upstream OpenSSL 3.6 is refused the same way. OpenSSH 9.4 and later (24.04 has
9.6p1) only require the same major version.

### Ubuntu 24.04: client

```sh
LD_LIBRARY_PATH=$R ssh -V
#   OpenSSH_9.6p1 Ubuntu-3ubuntu13.x, OpenSSL 3.6.5+rustyssl.1.0.0 29 Sep 2026

LD_LIBRARY_PATH=$R ssh -c aes256-gcm@openssh.com -o KexAlgorithms=ecdh-sha2-nistp256 \
    -o HostKeyAlgorithms=ecdsa-sha2-nistp256 -i ~/.ssh/id_ecdsa user@host
```

(An RSA key, `-o KexAlgorithms=diffie-hellman-group14-sha256` or `-c aes128-ctr` work the same
way.) `LD_DEBUG=libs LD_LIBRARY_PATH=$R ssh ... 2>&1 | grep 'calling init:.*libcrypto'`
confirms the client loaded rustyssl.

### Ubuntu 24.04: a test sshd

Run a second `sshd` on another port, so the system's sshd stays as it is:

```sh
sudo env LD_LIBRARY_PATH=$R /usr/sbin/sshd -D -e -p 2222
```

From another terminal, log in to port 2222 with the options above. sshd re-executes itself for
every connection and the new process keeps `LD_LIBRARY_PATH`: the per-connection processes
(`sshd: user [priv]`, `sshd: user@pts/0`) map rustyssl's library
(`sudo grep libcrypto /proc/<pid>/maps`). OpenSSH 9.6 starts without a version complaint.

To run the system's sshd on rustyssl, give the service the variable with a systemd drop-in
(`sudo systemctl edit ssh.service`; on 24.04 `ssh.socket` starts it on demand):

```ini
[Service]
Environment=LD_LIBRARY_PATH=/home/you/rustyssl/target/dist/lib
```

then `sudo systemctl restart ssh`. Keep a console, or the test sshd on another port, open while
you do this on a remote machine. Undo it with `sudo systemctl revert ssh.service` and a restart.
(The drop-in is standard systemd; the containers this guide was tested in run no systemd, so
it wasn't exercised there.)

`ssh-keysign` (host-based authentication) is setuid root, so it ignores `LD_LIBRARY_PATH` and
stays on the system's OpenSSL unless rustyssl is selected system-wide.

## Install side by side

`cargo xtask package debian` builds an install tree for Debian and Ubuntu, with the directories
set for Ubuntu (`OPENSSLDIR` `/usr/lib/ssl`, rustyssl's own MODULESDIR), and packs it into a
tarball. Installing it changes nothing for running programs; `rustyssl-select` then switches
the whole system to rustyssl and back. On 22.04, read [SSH](#ssh) first.

```sh
cd ~/rustyssl
cargo xtask package debian
#   Staged ... and target/package/rustyssl-3.6.5-debian-<arch>.tar.gz

sudo tar -xzf target/package/rustyssl-3.6.5-debian-$(uname -m).tar.gz -C / --keep-directory-symlink
H=/usr/lib/$(uname -m)-linux-gnu/rustyssl     # rustyssl's directory

sudo $H/bin/rustyssl-select rustyssl   # every program, setuid ones included; /usr/local/bin/openssl
$H/bin/rustyssl-select status          # rustyssl
openssl version                        # Library: OpenSSL 3.6.5+rustyssl...
/usr/bin/openssl version               # Ubuntu's tool, on rustyssl's library
```

It installs `$H` (the libraries, `ossl-modules/legacy.so`, `bin/openssl`,
`bin/rustyssl-select`, headers, pkg-config files) and two reference files,
`/usr/lib/ssl/openssl.cnf.dist` and `/usr/lib/ssl/ct_log_list.cnf.dist`; Ubuntu's own files are
never modified. `rustyssl-select rustyssl` adds `/etc/ld.so.conf.d/00-rustyssl.conf` and runs
`ldconfig`, and links `/usr/local/bin/openssl` to rustyssl's tool. Restart long-running
services (nginx, PostgreSQL, ...) for them to load it.

To go back, and to remove it:

```sh
sudo $H/bin/rustyssl-select system      # the system's OpenSSL again (restart services)
sudo rm -rf $H /usr/lib/ssl/openssl.cnf.dist /usr/lib/ssl/ct_log_list.cnf.dist
```

More on the install layout, other distributions, and what differs from OpenSSL:
[MIGRATION.md](MIGRATION.md).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `OpenSSL version mismatch. Built against 30000020, you have 30600050` | OpenSSH 8.9 on 22.04; see [SSH](#ssh). |
| `certificate verify failed` in Python or `openssl s_client` | rustyssl isn't using Ubuntu's CA certificates: build with `RUSTYSSL_OPENSSLDIR=/usr/lib/ssl`, or set `SSL_CERT_DIR=/etc/ssl/certs`. |
| `DSO_load:could not load the shared library ... name=legacy`, then `provider_init:reason(37)` | the legacy provider isn't in MODULESDIR: set `OPENSSL_MODULES=<dist>/lib/ossl-modules`, or use the side-by-side install. (`reason(37)` has no text in OpenSSL either: it prints the same line.) |
| `version 'GLIBC_2.xx' not found` | the build needs a newer glibc than the machine has; build on the oldest release you run it on. |
| A program still shows the system's OpenSSL | it's setuid, has an `RPATH`, is a snap, or was started before; see [the caveats](#when-ld_library_path-doesnt-apply). |

rustyssl matches OpenSSL's behavior and output; where it deliberately doesn't (always for a
security reason) is listed in [DEVIATIONS.md](DEVIATIONS.md). If something behaves differently
from Ubuntu's OpenSSL, please open an issue at
<https://github.com/zebra-rs/rustyssl/issues> with the Ubuntu release, the architecture
(`uname -m`), the output of `LD_LIBRARY_PATH=$R openssl version -a`, and the command that differs
with and without `LD_LIBRARY_PATH`.
