/*
 * The legacy provider's module (lib/ossl-modules/legacy.so, legacy.dylib on macOS), as OpenSSL's
 * default build ships it: OSSL_PROVIDER_load(NULL, "legacy") opens it from MODULESDIR, the
 * search path, or $OPENSSL_MODULES.
 *
 * Its algorithms are implemented in libcrypto, next to the default provider's; libcrypto exports
 * their init function to this module only, in its private version node. The module defines
 * nothing but OSSL_provider_init, a one-branch forwarder (docs/adr/0003-external-providers.md).
 * `cargo xtask dist` compiles and links it.
 */

#include <openssl/core.h>

int rustyssl_private_legacy_provider_init(const OSSL_CORE_HANDLE *handle,
                                          const OSSL_DISPATCH *in,
                                          const OSSL_DISPATCH **out, void **provctx);

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx)
{
    return rustyssl_private_legacy_provider_init(handle, in, out, provctx);
}
