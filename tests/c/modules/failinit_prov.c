/* A provider module whose init function fails (tests/c/provider_ext.c). */

#include <openssl/core.h>

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx)
{
    (void)handle;
    (void)in;
    (void)out;
    (void)provctx;
    return 0;
}
