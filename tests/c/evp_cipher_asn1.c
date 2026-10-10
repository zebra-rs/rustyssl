/*
 * Conformance test for a cipher context's AlgorithmIdentifier parameters
 * (EVP_CIPHER_param_to_asn1(3), EVP_CIPHER_CTX_get_algor(3)), in TAP format: the IV as an OCTET
 * STRING for the default provider's block and stream modes, both ways; what the key wraps,
 * GCM, CCM, XTS, and OCB give; the IV helpers; the errors; and, through a provider of the
 * test's own whose cipher answers `alg_id_param` and `algorithm-id`, the provider's own DER
 * (EVP_CIPH_FLAG_CUSTOM_ASN1) and AlgorithmIdentifier, with X509_ALGOR's DER both ways.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void errors(void)
{
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, int n)
{
    int i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* An ASN1_TYPE's DER. */
static void show_type(const char *label, const ASN1_TYPE *t)
{
    unsigned char *der = NULL;
    int n;

    if (t == NULL) {
        printf("  %s: none\n", label);
        return;
    }
    n = i2d_ASN1_TYPE(t, &der);
    printf("  %s (type %d, %d):", label, ASN1_TYPE_get(t), n);
    hex("", der, n > 0 ? n : 0);
    OPENSSL_free(der);
}

static unsigned char key[64], iv[16], data[64];

/* ------------------------------------------------------------------------------------------ */
/* The test's provider: one cipher with its own AlgorithmIdentifier parameters. */

struct tctx {
    unsigned char der[64];
    size_t derlen;
    int inits;
};

static void *t_newctx(void *provctx)
{
    struct tctx *c = calloc(1, sizeof(*c));

    (void)provctx;
    /* INTEGER 5, until set. */
    if (c != NULL) {
        memcpy(c->der, "\x02\x01\x05", 3);
        c->derlen = 3;
    }
    return c;
}
static void t_freectx(void *vctx) { free(vctx); }
static int t_init(void *vctx, const unsigned char *k, size_t kl, const unsigned char *v, size_t vl,
                  const OSSL_PARAM params[])
{
    (void)k, (void)kl, (void)v, (void)vl, (void)params;
    ((struct tctx *)vctx)->inits++;
    return 1;
}
static int t_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                    const unsigned char *in, size_t inl)
{
    (void)vctx, (void)outsize;
    memcpy(out, in, inl);
    *outl = inl;
    return 1;
}
static int t_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    (void)vctx, (void)out, (void)outsize;
    *outl = 0;
    return 1;
}
static int t_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE)) != NULL)
        OSSL_PARAM_set_uint(p, EVP_CIPH_CBC_MODE);
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL)
        OSSL_PARAM_set_size_t(p, 16);
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL)
        OSSL_PARAM_set_size_t(p, 8);
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)) != NULL)
        OSSL_PARAM_set_size_t(p, 1);
    return 1;
}

/* SEQUENCE { OID 2.5.29.99 (an arbitrary one), the parameters }. */
static size_t aid_der(const struct tctx *c, unsigned char *out)
{
    out[0] = 0x30;
    out[1] = (unsigned char)(5 + c->derlen);
    memcpy(out + 2, "\x06\x03\x55\x1d\x63", 5);
    memcpy(out + 7, c->der, c->derlen);
    return 7 + c->derlen;
}

static int t_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct tctx *c = vctx;
    unsigned char aid[80];
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS)) != NULL
        && !OSSL_PARAM_set_octet_string(p, c->der, c->derlen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_ALGORITHM_ID)) != NULL
        && !OSSL_PARAM_set_octet_string(p, aid, aid_der(c, aid)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL)
        OSSL_PARAM_set_size_t(p, 8);
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL)
        OSSL_PARAM_set_size_t(p, 16);
    return 1;
}
static int t_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct tctx *c = vctx;
    const OSSL_PARAM *p;
    void *d = c->der;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS)) != NULL
        && !OSSL_PARAM_get_octet_string(p, &d, sizeof(c->der), &c->derlen))
        return 0;
    return 1;
}
static const OSSL_PARAM gettable_ctx[] = {
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *t_gettable_ctx(void *cctx, void *provctx)
{
    (void)cctx, (void)provctx;
    return gettable_ctx;
}

static const OSSL_DISPATCH test_cipher[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))t_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))t_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))t_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))t_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))t_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))t_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))t_get_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))t_get_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))t_set_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))t_gettable_ctx },
    OSSL_DISPATCH_END
};
static const OSSL_ALGORITHM test_ciphers[] = {
    { "TEST-ALGID", "provider=algtest", test_cipher, NULL },
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

/* The parameters `name` gives (from an encrypting context with the IV), then read back. */
static void each(const char *name)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(), *back = EVP_CIPHER_CTX_new();
    ASN1_TYPE *t = ASN1_TYPE_new();
    unsigned char got[16];
    int r;

    if (c == NULL) {
        ERR_clear_error();
        printf("  %s: absent\n", name);
        goto end;
    }
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    check(EVP_EncryptInit_ex(ctx, c, NULL, key, iv), name);
    r = EVP_CIPHER_param_to_asn1(ctx, t);
    printf("  %s param_to_asn1 %d\n", name, r);
    errors();
    show_type("parameters", ASN1_TYPE_get(t) != 0 ? t : NULL);
    check(EVP_DecryptInit_ex(back, c, NULL, key, NULL), "decrypting, no IV");
    r = EVP_CIPHER_asn1_to_param(back, t);
    printf("  asn1_to_param %d\n", r);
    errors();
    memset(got, 0, sizeof(got));
    if (EVP_CIPHER_CTX_get_iv_length(back) > 0 && EVP_CIPHER_CTX_get_iv_length(back) <= 16) {
        /* Some have no IV to get when no parameters set it (GCM). */
        printf("  original iv %d\n",
               EVP_CIPHER_CTX_get_original_iv(back, got, EVP_CIPHER_CTX_get_iv_length(back)));
        hex("iv", got, EVP_CIPHER_CTX_get_iv_length(back));
        errors();
    }
end:
    ASN1_TYPE_free(t);
    EVP_CIPHER_CTX_free(back);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static void default_provider(void)
{
    static const char *names[] = {
        "AES-128-CBC", "AES-256-ECB", "AES-192-CFB", "AES-128-CFB8", "AES-128-OFB",
        "AES-256-CTR", "ARIA-128-CBC", "CAMELLIA-256-CFB1", "SM4-CBC", "DES-EDE3-CBC",
        "DES-EDE3-ECB", "ChaCha20", "NULL", "AES-128-GCM", "AES-128-CCM", "AES-128-OCB",
        "AES-128-XTS", "AES-128-WRAP", "AES-128-WRAP-PAD", "DES3-WRAP", "AES-128-SIV",
        "AES-128-GCM-SIV", "AES-128-CBC-CTS", "ChaCha20-Poly1305", "AES-128-CBC-HMAC-SHA1", NULL
    };
    int i;

    for (i = 0; names[i] != NULL; i++)
        each(names[i]);
}

static void helpers(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(), *empty = EVP_CIPHER_CTX_new();
    ASN1_TYPE *t = ASN1_TYPE_new();
    ASN1_INTEGER *n = ASN1_INTEGER_new();
    unsigned char short_iv[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, got[16];
    X509_ALGOR *alg = NULL;

    check(EVP_EncryptInit_ex(ctx, c, NULL, key, iv), "init");
    check(EVP_CIPHER_set_asn1_iv(ctx, NULL) == 0, "set_asn1_iv: no type");
    check(EVP_CIPHER_get_asn1_iv(ctx, NULL) == 0, "get_asn1_iv: no type");
    check(EVP_CIPHER_set_asn1_iv(ctx, t) == 1, "set_asn1_iv");
    show_type("iv", t);
    check(EVP_CIPHER_get_asn1_iv(ctx, t) == 16, "get_asn1_iv");
    check(ASN1_TYPE_set_octetstring(t, short_iv, 8), "a short IV");
    check(EVP_CIPHER_get_asn1_iv(ctx, t) == -1, "get_asn1_iv: the wrong length");
    check(EVP_CIPHER_asn1_to_param(ctx, t) == -1, "asn1_to_param: the wrong length");
    errors();
    ASN1_INTEGER_set(n, 7);
    ASN1_TYPE_set(t, V_ASN1_INTEGER, n);
    check(EVP_CIPHER_get_asn1_iv(ctx, t) == -1, "get_asn1_iv: not an OCTET STRING");
    check(EVP_CIPHER_CTX_get_original_iv(ctx, got, 16) && memcmp(got, iv, 16) == 0,
          "the IV as it was");
    check(EVP_CIPHER_param_to_asn1(ctx, NULL) == 0, "param_to_asn1: no type");
    errors();
    check(EVP_CIPHER_param_to_asn1(empty, t) == -1, "param_to_asn1: no cipher");
    errors();
    check(EVP_CIPHER_asn1_to_param(empty, t) == -1, "asn1_to_param: no cipher");
    errors();

    /* The default provider has no AlgorithmIdentifier of its own. */
    check(EVP_CIPHER_CTX_get_algor(ctx, &alg) == -2 && alg == NULL, "get_algor: none");
    errors();
    check(EVP_CIPHER_CTX_get_algor(ctx, NULL) == -2, "get_algor: none, no X509_ALGOR");
    errors();
    alg = X509_ALGOR_new();
    check(EVP_CIPHER_CTX_get_algor_params(ctx, alg) == -1, "get_algor_params: none");
    errors();
    check(EVP_CIPHER_CTX_set_algor_params(ctx, alg) == 1, "set_algor_params: ignored");
    errors();
    X509_ALGOR_free(alg);
    ASN1_TYPE_free(t);
    EVP_CIPHER_CTX_free(empty);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static void algor_der(void)
{
    static const unsigned char with[] = { 0x30, 0x0f, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                                          0x03, 0x04, 0x01, 0x02, 0x04, 0x02, 0xab, 0xcd };
    static const unsigned char without[] = { 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                             0x65, 0x03, 0x04, 0x01, 0x02 };
    static const unsigned char bad[] = { 0x30, 0x03, 0x04, 0x01, 0x00 };
    const unsigned char *p;
    unsigned char *der = NULL;
    X509_ALGOR *a = NULL, *b;
    int n;

    check(X509_ALGOR_it() != NULL, "X509_ALGOR_it");
    b = X509_ALGOR_new();
    check(b != NULL && b->algorithm != NULL && b->parameter == NULL, "a new one");
    X509_ALGOR_free(b);
    X509_ALGOR_free(NULL);
    p = with;
    a = d2i_X509_ALGOR(NULL, &p, sizeof(with));
    check(a != NULL && p == with + sizeof(with), "d2i, with parameters");
    printf("  nid %d parameters type %d\n", OBJ_obj2nid(a->algorithm), ASN1_TYPE_get(a->parameter));
    n = i2d_X509_ALGOR(a, &der);
    check(n == (int)sizeof(with) && memcmp(der, with, n) == 0, "i2d back");
    OPENSSL_free(der);
    der = NULL;
    p = without;
    check(d2i_X509_ALGOR(&a, &p, sizeof(without)) == a && a->parameter == NULL,
          "d2i into it, without parameters");
    n = i2d_X509_ALGOR(a, NULL);
    check(n == (int)sizeof(without), "i2d's length");
    p = bad;
    check(d2i_X509_ALGOR(NULL, &p, sizeof(bad)) == NULL, "not an OID");
    errors();
    p = with;
    check(d2i_X509_ALGOR(NULL, &p, 10) == NULL, "short");
    errors();
    n = ASN1_item_i2d((ASN1_VALUE *)a, &der, X509_ALGOR_it());
    hex("item", der, n);
    OPENSSL_free(der);
    X509_ALGOR_free(a);
}

static void own_provider(void)
{
    OSSL_LIB_CTX *lib = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *prov;
    EVP_CIPHER *c;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    ASN1_TYPE *t = ASN1_TYPE_new();
    X509_ALGOR *alg = NULL, *given;
    ASN1_OCTET_STRING *o = ASN1_OCTET_STRING_new();
    unsigned char *der = NULL;
    int n;

    check(OSSL_PROVIDER_add_builtin(lib, "algtest", test_init), "add_builtin");
    prov = OSSL_PROVIDER_load(lib, "algtest");
    c = EVP_CIPHER_fetch(lib, "TEST-ALGID", NULL);
    check(c != NULL, "fetched");
    printf("  flags %#lx\n", EVP_CIPHER_get_flags(c));
    check((EVP_CIPHER_get_flags(c) & EVP_CIPH_FLAG_CUSTOM_ASN1) != 0, "custom ASN.1");
    check(EVP_EncryptInit_ex(ctx, c, NULL, key, iv), "init");

    /* The provider's DER both ways. */
    check(EVP_CIPHER_param_to_asn1(ctx, t) == 1, "param_to_asn1");
    show_type("parameters", t);
    ASN1_OCTET_STRING_set(o, (const unsigned char *)"\x11\x22\x33", 3);
    ASN1_TYPE_set(t, V_ASN1_OCTET_STRING, o);
    check(EVP_CIPHER_asn1_to_param(ctx, t) == 1, "asn1_to_param");
    check(EVP_CIPHER_param_to_asn1(ctx, t) == 1, "param_to_asn1 again");
    show_type("parameters", t);

    /* The whole AlgorithmIdentifier: into a new one, then into the one given. */
    check(EVP_CIPHER_CTX_get_algor(ctx, &alg) == 1 && alg != NULL, "get_algor");
    n = i2d_X509_ALGOR(alg, &der);
    hex("algor", der, n);
    OPENSSL_free(der);
    der = NULL;
    given = alg;
    check(EVP_CIPHER_CTX_get_algor(ctx, &alg) == 1 && alg == given, "get_algor into it");
    check(EVP_CIPHER_CTX_get_algor(ctx, NULL) == -1, "get_algor with nowhere to put it");
    errors();

    /* get_algor_params into the X509_ALGOR's parameters; set_algor_params from them. */
    check(EVP_CIPHER_CTX_get_algor_params(ctx, alg) == 1, "get_algor_params");
    show_type("algor parameters", alg->parameter);
    ASN1_TYPE_free(alg->parameter);
    alg->parameter = NULL;
    check(EVP_CIPHER_CTX_get_algor_params(ctx, alg) == 1 && alg->parameter != NULL,
          "get_algor_params into none");
    ASN1_TYPE_set(alg->parameter, V_ASN1_NULL, NULL);
    check(EVP_CIPHER_CTX_set_algor_params(ctx, alg) == 1, "set_algor_params");
    check(EVP_CIPHER_param_to_asn1(ctx, t) == 1, "param_to_asn1");
    show_type("parameters", t);
    errors();

    X509_ALGOR_free(alg);
    ASN1_TYPE_free(t);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(lib);
}

int main(void)
{
    int i;

    for (i = 0; i < (int)sizeof(key); i++)
        key[i] = (unsigned char)(i * 7 + 3);
    for (i = 0; i < (int)sizeof(iv); i++)
        iv[i] = (unsigned char)(0xa0 + i);
    for (i = 0; i < (int)sizeof(data); i++)
        data[i] = (unsigned char)(i * 13 + 1);
    default_provider();
    helpers();
    algor_der();
    own_provider();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
