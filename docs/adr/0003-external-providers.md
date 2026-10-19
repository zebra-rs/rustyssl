# ADR 0003: External C providers run behind the same dispatch model as the built-in ones

- **Status:** Accepted, 2026-10-18 (implementation plan step 9.1)

## Context

OpenSSL 3 lets an application or a configuration file load a provider: a shared module
(`OSSL_PROVIDER_load(libctx, "oqsprovider")`, found in `MODULESDIR` or the context's search
path) or an init function the application links in (`OSSL_PROVIDER_add_builtin`). The provider
gets the core's dispatch table (about fifty upcalls: parameters, errors, BIOs, memory, entropy,
child-provider callbacks, object creation), returns its own, and from then on every
`EVP_*_fetch` may pick its algorithms. pkcs11-provider, oqs-provider, tpm2-openssl and the FIPS
provider work this way, as do the test providers upstream's own tests link in (`p_test.c`,
`tls-provider.c`, `filterprov.c`, `fake_rsaprov.c`).

rustyssl's provider layer was built for this from Phase 3 (step 3.1d, 3.1e): the built-in
providers (`default`, `base`, `null`) are init functions handing out `OSSL_ALGORITHM` and
`OSSL_DISPATCH` tables, and every EVP method (`EVP_MD`, `EVP_CIPHER`, `EVP_KEYMGMT`, ...) is made
from an algorithm's dispatch table and calls the provider through its function pointers, exactly
as `evp_fetch.c` and the `*_meth.c` files do. Keys move between providers by export and import
(`evp_keymgmt_util_export_to_provider` and its operation cache), and libssl learns groups and
signature algorithms from `OSSL_PROVIDER_get_capabilities`. What was missing is the core's half:
running a module's `OSSL_provider_init`, and the upcalls beyond `core_get_libctx`.

## Decision

1. **No wrapping layer.** An external provider's algorithms go into the same method store and
   make the same EVP methods as a built-in's; the built-ins keep going through their dispatch
   tables too, so the code path every external provider takes is the one the whole test suite
   already exercises. Nothing in `evp/` may recognize a built-in provider and take a shortcut
   past its dispatch table (a provider's context and objects are opaque `void *` outside its own
   module).

2. **Modules.** `provider/module.rs` resolves the file as OpenSSL's DSO loader does
   (`DSO_FLAG_NAME_TRANSLATION_EXT_ONLY`, the context's search path, else `$OPENSSL_MODULES`,
   else `MODULESDIR`), opens it with `dlopen(RTLD_NOW)`, binds `OSSL_provider_init`, and keeps
   the handle in the `Provider`. The handle is closed only after the provider's `teardown` has
   run, when its last reference goes, as OpenSSL's `DSO_free` follows `teardown`. The DSO API
   itself (`DSO_*`) is a separate family (step 9.4); this code uses `libc` directly and raises the
   same errors.

3. **The core's dispatch table is OpenSSL's** (`core_dispatch_` in `crypto/provider_core.c`),
   entry for entry, in `provider/upcalls.rs`: `core_gettable_params`/`get_params` (core version,
   provider name, module filename, configuration parameters), `core_get_libctx`,
   `core_thread_start`, the error functions (a reason with no library is the provider's own, in
   the library number it was given at creation, and its `get_reason_strings` are loaded into that
   library), the error marks, the core BIO functions, `BIO_vsnprintf`, the self-test and
   indicator callbacks, the entropy and nonce functions (system and user), the memory functions
   (`CRYPTO_malloc` and the others are the exported ones, so provider allocations honor
   `CRYPTO_set_mem_functions`), `OPENSSL_cleanse`, the child-provider functions, and
   `obj_add_sigid`/`obj_create`. Each upcall is an `ffi_callback!`: it can't unwind into the
   provider, and a NULL handle or argument where OpenSSL would crash fails with its failure value.

4. **Library contexts made by providers.** `OSSL_LIB_CTX_new_from_dispatch` makes a context that
   keeps the core BIO functions found in the table it's given, so `BIO_s_core` and
   `BIO_new_from_core_bio` in that context reach the parent's BIOs. `OSSL_LIB_CTX_new_child`
   also registers child-provider callbacks with the parent (`provider_child.c`): each provider
   the parent activates appears in the child as a provider of the same name whose init function
   reuses the parent's dispatch table and context (`ossl_child_provider_init`), and goes when the
   parent's does. `OSSL_LIB_CTX_get_data` returns OpenSSL's internal stores by internal index;
   rustyssl's stores have another layout, so it returns NULL for every index (the result for an
   index a build doesn't have), recorded in `docs/DEVIATIONS.md`.

5. **Ownership.** As in OpenSSL: an `OSSL_PROVIDER` has references (its store's, each fetched
   method's, each key's keymgmt's, the application's) and activations; methods keep their
   provider alive, so a module is never closed while a method from it can still be called. A
   provider's objects (algorithm contexts, key data, decoder and store contexts) are created and
   freed only through its own functions; rustyssl never frees them itself, and never hands a
   built-in's object to another provider's function: a key goes across by `export` and `import`
   into the other provider's key manager (the per-key operation cache).

6. **Thread safety.** A provider's functions may be called from any thread at any time, as
   OpenSSL calls them. No rustyssl lock is held while a provider function, an upcall's callback,
   or a child-provider callback runs (rule 7): the provider's state is copied out under the
   lock, and the call made after releasing it. The callbacks a provider registers with
   `core_thread_start` run at the thread's stop (`OPENSSL_thread_stop`, thread exit), and are
   dropped, not run, when the provider is torn down first.

7. **A provider is trusted code, but its output is still checked.** A module runs in the process
   and can do anything, so rustyssl can't defend against a malicious one. What it does guarantee
   is that a *buggy* provider can't make rustyssl's own code undefined: every length a provider
   reports is checked against the buffer rustyssl gave it before any slice is formed (a digest's
   `final` output against its size, a cipher's `update` against the room given, a parameter's
   `return_size` against `data_size`), strings it returns are read with a bound, tables it hands
   over (dispatch, algorithms, parameter lists, reason strings) are walked with a cap on their
   length, and a NULL where a pointer is required fails the operation with OpenSSL's error
   instead of being dereferenced.

8. **The `legacy` provider is a module, as OpenSSL ships it.** Its algorithms are implemented in
   libcrypto, next to the default provider's (`provider/digests.rs`, `ciphers.rs`, `kdfs.rs`),
   behind an init function that libcrypto exports to the module only
   (`rustyssl_private_legacy_provider_init`, in the `RUSTYSSL_PRIVATE` version node, as ADR
   0001's libssl forwarders do). The module is `libs/legacy/legacy.c`, a C file that defines
   only `OSSL_provider_init`, a one-branch forwarder to it. `cargo xtask dist` compiles it
   against the installed headers and links it against libcrypto into `lib/ossl-modules/`:
   `legacy.dylib` (a bundle, as OpenSSL's) on macOS, `legacy.so` elsewhere. It exports only
   `OSSL_provider_init`, as `providers.num` asks. So `OSSL_PROVIDER_load(NULL, "legacy")` needs
   the module file to be present, and finds it where OpenSSL would: the search path, else
   `$OPENSSL_MODULES`, else `MODULESDIR`. The test harnesses point each run at its own library's
   modules (`OPENSSL_MODULES`), since the reference's module and ours aren't interchangeable.

9. **Two consequences of rule 7, recorded.** OpenSSL calls the child-provider callbacks
   holding its store's lock; rustyssl copies the callbacks and providers out and calls with
   no lock held. So a provider activated in the parent while a child context is registering
   can be missed by that child, where OpenSSL would serialize the two. And an object being
   destroyed can't be held (`Handle::hold` fails once its last reference is gone): a
   provider's teardown that frees a child context finds its parent gone, as the parent is
   being freed.

10. **The built-ins' provider context begins as OpenSSL's `PROV_CTX`** (handle, then library
    context). A provider compiled with OpenSSL's `provider_ctx.c` can pass its own context to
    the built-ins' functions, as upstream's `filterprov.c` does, and they read it where
    OpenSSL's would.

## Consequences

- Third-party providers built against OpenSSL's headers load unchanged. They are validated with
  upstream's test providers and test programs (`cargo xtask test-openssl-suite`) and with
  oqs-provider, pkcs11-provider and tpm2-openssl where they can be built (TEST_PLAN.md).
- A provider's C code runs inside rustyssl operations with whatever rustyssl state is current
  (for example Arm's DIT mode, which is restored afterwards), and may call any rustyssl export,
  including re-entering the library on the same objects.
- Every new upcall is an export-like surface: it gets a C conformance test through a test
  provider in `tests/c/modules/`.
