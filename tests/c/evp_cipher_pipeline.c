/*
 * Conformance test for the cipher pipeline API (EVP_CipherPipelineEncryptInit(3) and the rest),
 * in TAP format: a provider of the test's own whose cipher pipelines (each pipeline XORs with
 * the key and its IV, so the output shows which key and IV reached it), encrypting and
 * decrypting three pipelines with each pipeline's lengths; what the provider is given; a
 * re-initialization with another cipher, which resets the context (and its pipeline count, as
 * OpenSSL's reset does); and the errors: too many pipelines, a cipher without pipelining (the
 * default provider's), NULL lengths, no cipher, and a context set up without pipelines.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The queued entries: library, reason, and the function that raised each. */
static void errors(void)
{
    unsigned long code;
    const char *func;

    printf("  errors:");
    while ((code = ERR_get_error_all(NULL, NULL, &func, NULL, NULL)) != 0)
        printf(" %d/%d(%s)", ERR_GET_LIB(code), ERR_GET_REASON(code), func);
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* ---- The test's provider: "TEST-PIPE", which pipelines, and "TEST-PLAIN", which doesn't. ---- */

#define MAXP 4
struct pctx {
    unsigned char key[16];
    unsigned char iv[MAXP][8];
    size_t numpipes;
    int enc;
};

/* What the provider was last given, for the test to print. */
static size_t seen_numpipes, seen_keylen, seen_ivlen;

static void *p_newctx(void *provctx)
{
    (void)provctx;
    return calloc(1, sizeof(struct pctx));
}
static void p_freectx(void *vctx) { free(vctx); }

static int p_init(void *vctx, const unsigned char *key, size_t keylen, size_t numpipes,
                  const unsigned char **iv, size_t ivlen, const OSSL_PARAM params[], int enc)
{
    struct pctx *c = vctx;
    size_t i;

    (void)params;
    seen_numpipes = numpipes;
    seen_keylen = keylen;
    seen_ivlen = ivlen;
    if (numpipes > MAXP || keylen != sizeof(c->key) || ivlen != sizeof(c->iv[0]))
        return 0;
    memcpy(c->key, key, keylen);
    for (i = 0; i < numpipes; i++)
        memcpy(c->iv[i], iv[i], ivlen);
    c->numpipes = numpipes;
    c->enc = enc;
    return 1;
}
static int p_einit(void *vctx, const unsigned char *key, size_t keylen, size_t numpipes,
                   const unsigned char **iv, size_t ivlen, const OSSL_PARAM params[])
{
    return p_init(vctx, key, keylen, numpipes, iv, ivlen, params, 1);
}
static int p_dinit(void *vctx, const unsigned char *key, size_t keylen, size_t numpipes,
                   const unsigned char **iv, size_t ivlen, const OSSL_PARAM params[])
{
    return p_init(vctx, key, keylen, numpipes, iv, ivlen, params, 0);
}

static int p_update(void *vctx, size_t numpipes, unsigned char **out, size_t *outl,
                    const size_t *outsize, const unsigned char **in, const size_t *inl)
{
    struct pctx *c = vctx;
    size_t i, j;

    seen_numpipes = numpipes;
    if (numpipes != c->numpipes)
        return 0;
    for (i = 0; i < numpipes; i++) {
        if (inl[i] > outsize[i])
            return 0;
        for (j = 0; j < inl[i]; j++)
            out[i][j] = in[i][j] ^ c->key[j % 16] ^ c->iv[i][j % 8] ^ (unsigned char)i;
        outl[i] = inl[i];
    }
    return 1;
}
static int p_final(void *vctx, size_t numpipes, unsigned char **out, size_t *outl,
                   const size_t *outsize)
{
    struct pctx *c = vctx;
    size_t i;

    (void)outsize;
    seen_numpipes = numpipes;
    /* A one-octet trailer per pipeline when encrypting: its index. */
    for (i = 0; i < numpipes; i++) {
        if (c->enc) {
            out[i][0] = (unsigned char)(0xa0 + i);
            outl[i] = 1;
        }
    }
    return 1;
}
static int p_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE)) != NULL)
        OSSL_PARAM_set_uint(p, EVP_CIPH_CTR_MODE);
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL)
        OSSL_PARAM_set_size_t(p, 16);
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL)
        OSSL_PARAM_set_size_t(p, 8);
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)) != NULL)
        OSSL_PARAM_set_size_t(p, 1);
    return 1;
}
/* The ordinary functions, which a cipher must have besides its pipeline ones. */
static int o_init(void *vctx, const unsigned char *k, size_t kl, const unsigned char *v,
                  size_t vl, const OSSL_PARAM params[])
{
    (void)vctx, (void)k, (void)kl, (void)v, (void)vl, (void)params;
    return 1;
}
static int o_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                    const unsigned char *in, size_t inl)
{
    (void)vctx, (void)outsize;
    memcpy(out, in, inl);
    *outl = inl;
    return 1;
}
static int o_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    (void)vctx, (void)out, (void)outsize;
    *outl = 0;
    return 1;
}

static const OSSL_DISPATCH pipe_cipher[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))p_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))p_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))o_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))o_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))o_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))o_final },
    { OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT, (void (*)(void))p_einit },
    { OSSL_FUNC_CIPHER_PIPELINE_DECRYPT_INIT, (void (*)(void))p_dinit },
    { OSSL_FUNC_CIPHER_PIPELINE_UPDATE, (void (*)(void))p_update },
    { OSSL_FUNC_CIPHER_PIPELINE_FINAL, (void (*)(void))p_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))p_get_params },
    OSSL_DISPATCH_END
};
/* Encrypt-only pipelining: no pipeline decrypt init. */
static const OSSL_DISPATCH half_cipher[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))p_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))p_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))o_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))o_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))o_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))o_final },
    { OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT, (void (*)(void))p_einit },
    { OSSL_FUNC_CIPHER_PIPELINE_UPDATE, (void (*)(void))p_update },
    { OSSL_FUNC_CIPHER_PIPELINE_FINAL, (void (*)(void))p_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))p_get_params },
    OSSL_DISPATCH_END
};
static const OSSL_DISPATCH plain_cipher[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))p_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))p_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))o_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))o_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))o_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))o_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))p_get_params },
    OSSL_DISPATCH_END
};
static const OSSL_ALGORITHM test_ciphers[] = {
    { "TEST-PIPE", "provider=pipetest", pipe_cipher, NULL },
    { "TEST-HALF", "provider=pipetest", half_cipher, NULL },
    { "TEST-PLAIN", "provider=pipetest", plain_cipher, NULL },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM *test_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    return operation_id == OSSL_OP_CIPHER ? test_ciphers : NULL;
}
static const OSSL_DISPATCH test_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))test_query },
    OSSL_DISPATCH_END
};
static int test_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                     const OSSL_DISPATCH **out, void **provctx)
{
    (void)in;
    *out = test_dispatch;
    *provctx = (void *)handle;
    return 1;
}

/* ------------------------------------------------------------------------------------------ */

static const unsigned char key[17] = "0123456789abcdef";
static const unsigned char ivs[3][9] = { "iv-zero.", "iv-one..", "iv-two.." };

/* Three pipelines of different lengths, encrypted then decrypted with the same key and IVs. */
static void test_round_trip(EVP_CIPHER *pipe)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const unsigned char *iv[3] = { ivs[0], ivs[1], ivs[2] };
    const unsigned char *msg[3] = { (const unsigned char *)"first pipeline",
                                    (const unsigned char *)"second",
                                    (const unsigned char *)"" };
    const size_t msgl[3] = { 14, 6, 0 };
    unsigned char ct[3][32], pt[3][32];
    unsigned char *out[3] = { ct[0], ct[1], ct[2] };
    unsigned char *tail[3];
    const unsigned char *in[3];
    size_t outl[3] = { 99, 99, 99 }, tl[3] = { 99, 99, 99 }, size[3] = { 32, 32, 32 };
    size_t i;

    printf("# encrypting three pipelines\n");
    check(EVP_CipherPipelineEncryptInit(ctx, pipe, key, 16, 3, iv, 8) == 1,
          "the encrypt init");
    printf("  the provider got %zu pipelines, a %zu-octet key, %zu-octet IVs\n", seen_numpipes,
           seen_keylen, seen_ivlen);
    check(EVP_CipherPipelineUpdate(ctx, out, outl, size, msg, msgl) == 1, "the update");
    printf("  lengths %zu %zu %zu, the provider saw %zu pipelines\n", outl[0], outl[1], outl[2],
           seen_numpipes);
    for (i = 0; i < 3; i++) {
        tail[i] = ct[i] + outl[i];
        size[i] = sizeof(ct[i]) - outl[i];
    }
    check(EVP_CipherPipelineFinal(ctx, tail, tl, size) == 1, "the final");
    printf("  final lengths %zu %zu %zu\n", tl[0], tl[1], tl[2]);
    for (i = 0; i < 3; i++) {
        hex("pipeline", ct[i], outl[i] + tl[i]);
        size[i] = 32;
    }
    check(EVP_CIPHER_CTX_is_encrypting(ctx) == 1, "the context encrypts");
    EVP_CIPHER_CTX_free(ctx);

    /* A fresh context: re-initializing one that has a cipher resets its pipeline count. */
    printf("# decrypting them\n");
    ctx = EVP_CIPHER_CTX_new();
    check(EVP_CipherPipelineDecryptInit(ctx, pipe, key, 16, 3, iv, 8) == 1,
          "the decrypt init");
    for (i = 0; i < 3; i++) {
        in[i] = ct[i];
        out[i] = pt[i];
    }
    check(EVP_CipherPipelineUpdate(ctx, out, outl, size, in, msgl) == 1, "the update");
    check(EVP_CipherPipelineFinal(ctx, out, tl, size) == 1, "the final");
    printf("  final lengths %zu %zu %zu\n", tl[0], tl[1], tl[2]);
    for (i = 0; i < 3; i++)
        check(outl[i] == msgl[i] && memcmp(pt[i], msg[i], msgl[i]) == 0, "a pipeline back");
    check(EVP_CIPHER_CTX_is_encrypting(ctx) == 0, "the context decrypts");
    EVP_CIPHER_CTX_free(ctx);
}

/* A context reused with another cipher is reset first, which clears its pipeline count. */
static void test_reinit(EVP_CIPHER *pipe, EVP_CIPHER *half)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const unsigned char *iv[2] = { ivs[0], ivs[1] };
    const unsigned char *in[2] = { (const unsigned char *)"ab", (const unsigned char *)"cd" };
    const size_t inl[2] = { 2, 2 };
    unsigned char o[2][8];
    unsigned char *out[2] = { o[0], o[1] };
    size_t outl[2] = { 7, 7 }, size[2] = { 8, 8 };
    int r;

    printf("# re-initializing with another cipher\n");
    check(EVP_CipherPipelineEncryptInit(ctx, pipe, key, 16, 2, iv, 8) == 1,
          "the first init");
    r = EVP_CipherPipelineEncryptInit(ctx, half, key, 16, 2, iv, 8);
    printf("  the second init: %d, the provider got %zu pipelines\n", r, seen_numpipes);
    errors();
    r = EVP_CipherPipelineUpdate(ctx, out, outl, size, in, inl);
    printf("  the update: %d, the provider saw %zu pipelines, lengths %zu %zu\n", r,
           seen_numpipes, outl[0], outl[1]);
    errors();
    /* A NULL cipher keeps the context's, with no reset: the count stays. */
    r = EVP_CipherPipelineEncryptInit(ctx, NULL, key, 16, 2, iv, 8);
    printf("  init keeping the cipher: %d, the provider got %zu pipelines\n", r, seen_numpipes);
    r = EVP_CipherPipelineUpdate(ctx, out, outl, size, in, inl);
    printf("  the update: %d, the provider saw %zu pipelines, lengths %zu %zu\n", r,
           seen_numpipes, outl[0], outl[1]);
    errors();
    check(EVP_CipherPipelineDecryptInit(ctx, half, key, 16, 2, iv, 8) == 0,
          "no decrypt pipelining in a cipher without its init");
    errors();
    EVP_CIPHER_CTX_free(ctx);
}

static void test_errors(EVP_CIPHER *pipe, EVP_CIPHER *plain)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER *aes = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    const unsigned char *iv[1] = { ivs[0] };
    const unsigned char *in[1] = { (const unsigned char *)"x" };
    const size_t inl[1] = { 1 };
    unsigned char o[8];
    unsigned char *out[1] = { o };
    size_t outl[1] = { 5 }, size[1] = { 8 };

    printf("# errors\n");
    check(EVP_CIPHER_can_pipeline(pipe, 1) == 1 && EVP_CIPHER_can_pipeline(pipe, 0) == 1,
          "the test cipher pipelines both ways");
    check(EVP_CIPHER_can_pipeline(plain, 1) == 0 && EVP_CIPHER_can_pipeline(aes, 1) == 0,
          "the others don't");
    check(EVP_CipherPipelineEncryptInit(ctx, pipe, key, 16, EVP_MAX_PIPES + 1, iv, 8)
              == 0,
          "more than EVP_MAX_PIPES");
    errors();
    check(EVP_CipherPipelineEncryptInit(ctx, aes, key, 16, 1, iv, 16) == 0,
          "the default provider's AES");
    errors();
    check(EVP_CipherPipelineDecryptInit(ctx, plain, key, 16, 1, iv, 8) == 0,
          "a cipher without pipelining");
    errors();
    EVP_CIPHER_CTX_free(ctx);

    ctx = EVP_CIPHER_CTX_new();
    check(EVP_CipherPipelineUpdate(ctx, out, NULL, size, in, inl) == 0, "NULL output lengths");
    errors();
    check(EVP_CipherPipelineUpdate(ctx, out, outl, size, in, NULL) == 0, "NULL input lengths");
    errors();
    check(EVP_CipherPipelineFinal(ctx, out, NULL, size) == 0, "NULL final lengths");
    errors();
    check(EVP_CipherPipelineUpdate(ctx, out, outl, size, in, inl) == 0, "no cipher");
    errors();
    check(EVP_CipherPipelineFinal(ctx, out, outl, size) == 0, "no cipher to finish");
    errors();
    check(EVP_EncryptInit_ex2(ctx, aes, key, ivs[0], NULL) == 1, "AES set up the usual way");
    check(EVP_CipherPipelineUpdate(ctx, out, outl, size, in, inl) == 0,
          "no pipelined update for it");
    errors();
    check(EVP_CipherPipelineFinal(ctx, out, outl, size) == 0, "nor final");
    errors();
    printf("  the length left: %zu\n", outl[0]);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(aes);
}

int main(void)
{
    OSSL_LIB_CTX *lib = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *prov = NULL;
    EVP_CIPHER *pipe, *half, *plain;

    check(OSSL_PROVIDER_add_builtin(lib, "pipetest", test_init) == 1, "add_builtin");
    prov = OSSL_PROVIDER_load(lib, "pipetest");
    check(prov != NULL, "the provider loads");
    pipe = EVP_CIPHER_fetch(lib, "TEST-PIPE", NULL);
    half = EVP_CIPHER_fetch(lib, "TEST-HALF", NULL);
    plain = EVP_CIPHER_fetch(lib, "TEST-PLAIN", NULL);
    check(pipe != NULL && half != NULL && plain != NULL, "its ciphers fetch");
    if (pipe != NULL && half != NULL && plain != NULL) {
        test_round_trip(pipe);
        test_reinit(pipe, half);
        test_errors(pipe, plain);
    }
    EVP_CIPHER_free(pipe);
    EVP_CIPHER_free(half);
    EVP_CIPHER_free(plain);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(lib);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
