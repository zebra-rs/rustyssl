/*
 * Conformance test for the functions OpenSSL 3.6 added to libcrypto (the OPENSSL_3.6.0 node), in
 * TAP format: the overflow-checked array allocators (CRYPTO_malloc_array(3) and the others),
 * OPENSSL_sk_set_thunks (which every typed stack the 3.6 headers make calls),
 * OSSL_PARAM_set_octet_string_or_ptr, EVP_PKEY_get_security_category, i2d_PKCS8PrivateKey,
 * OSSL_STORE_LOADER_settable_ctx_params, and X509_CRL_get0_tbs_sigalg; and the 3.6 change to
 * CRYPTO_aligned_alloc (a power-of-two alignment).
 *
 * Built against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: the output must match (TEST_PLAN.md, layer L4).
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/safestack.h>
#include <openssl/store.h>
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

/* The queued entries' library and reason, oldest first, then clears the queue. */
static void errors(const char *what)
{
    unsigned long e;

    printf("# %s:", what);
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static void test_arrays(void)
{
    void *p, *freeptr = (void *)1;
    size_t i;
    unsigned char *z;

    p = OPENSSL_malloc_array(4, 8);
    check(p != NULL, "malloc_array(4, 8)");
    OPENSSL_free(p);
    check(OPENSSL_malloc_array(SIZE_MAX, 2) == NULL, "malloc_array overflowing");
    errors("malloc_array overflowing");
    check(OPENSSL_malloc_array(0, 8) == NULL, "malloc_array of nothing");
    errors("malloc_array of nothing");

    z = OPENSSL_calloc(16, 4);
    for (i = 0; z != NULL && i < 64 && z[i] == 0; i++)
        ;
    check(z != NULL && i == 64, "calloc zeroes");
    z = OPENSSL_realloc_array(z, 32, 4);
    check(z != NULL, "realloc_array grows");
    check(OPENSSL_realloc_array(z, SIZE_MAX / 2, 4) == NULL, "realloc_array overflowing");
    errors("realloc_array overflowing");
    z = OPENSSL_clear_realloc_array(z, 32, 8, 4);
    check(z != NULL, "clear_realloc_array shrinks");
    check(OPENSSL_clear_realloc_array(z, SIZE_MAX, 8, 4) == NULL, "clear_realloc_array old count overflowing");
    errors("clear_realloc_array overflowing");
    OPENSSL_free(z);

    p = OPENSSL_aligned_alloc_array(10, 10, 64, &freeptr);
    check(p != NULL && ((uintptr_t)p % 64) == 0 && freeptr != NULL, "aligned_alloc_array");
    OPENSSL_free(freeptr);
    freeptr = (void *)1;
    check(OPENSSL_aligned_alloc_array(SIZE_MAX, 3, 64, &freeptr) == NULL && freeptr == NULL,
          "aligned_alloc_array overflowing clears freeptr");
    errors("aligned_alloc_array overflowing");

    /* 3.6: the alignment must be a power of two. */
    freeptr = (void *)1;
    p = OPENSSL_aligned_alloc(100, 0, &freeptr);
    check(p == NULL && freeptr == NULL, "aligned_alloc with alignment 0");
    errors("aligned_alloc alignment 0");
    freeptr = (void *)1;
    p = OPENSSL_aligned_alloc(100, 24, &freeptr);
    check(p == NULL && freeptr == NULL, "aligned_alloc with alignment 24");
    errors("aligned_alloc alignment 24");
    p = OPENSSL_aligned_alloc(100, 2, &freeptr);
    check(p != NULL && ((uintptr_t)p % 2) == 0 && freeptr != NULL, "aligned_alloc with alignment 2");
    OPENSSL_free(freeptr);

    p = OPENSSL_secure_malloc_array(4, 4);
    check(p != NULL, "secure_malloc_array");
    OPENSSL_secure_free(p);
    z = OPENSSL_secure_calloc(8, 2);
    for (i = 0; z != NULL && i < 16 && z[i] == 0; i++)
        ;
    check(z != NULL && i == 16, "secure_calloc zeroes");
    OPENSSL_secure_free(z);
    check(OPENSSL_secure_calloc(SIZE_MAX, 3) == NULL, "secure_calloc overflowing");
    errors("secure_calloc overflowing");
}

static int freed = 0;

static void free_string(char *s)
{
    freed++;
    OPENSSL_free(s);
}

static void test_stacks(void)
{
    STACK_OF(OPENSSL_STRING) *sk = sk_OPENSSL_STRING_new(NULL), *copy;
    OPENSSL_STACK *raw;

    check(sk != NULL, "a typed stack (its constructor sets the thunk)");
    sk_OPENSSL_STRING_push(sk, OPENSSL_strdup("one"));
    sk_OPENSSL_STRING_push(sk, OPENSSL_strdup("two"));
    copy = sk_OPENSSL_STRING_dup(sk);
    sk_OPENSSL_STRING_pop_free(sk, free_string);
    check(freed == 2, "pop_free frees each element through the thunk");
    sk_OPENSSL_STRING_free(copy);

    raw = OPENSSL_sk_new_null();
    check(OPENSSL_sk_set_thunks(raw, NULL) == raw, "set_thunks returns the stack");
    check(OPENSSL_sk_set_thunks(NULL, NULL) == NULL, "set_thunks of NULL");
    OPENSSL_sk_free(raw);
}

static void test_params(void)
{
    unsigned char data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, out[8];
    void *ptr = NULL;
    int i = 0;
    OSSL_PARAM p[2];

    p[0] = OSSL_PARAM_construct_octet_string("x", out, sizeof(out));
    p[1] = OSSL_PARAM_construct_end();
    check(OSSL_PARAM_set_octet_string_or_ptr(p, data, 5) == 1 && p[0].return_size == 5
          && memcmp(out, data, 5) == 0, "or_ptr on an octet string copies");
    p[0] = OSSL_PARAM_construct_octet_ptr("x", &ptr, 0);
    check(OSSL_PARAM_set_octet_string_or_ptr(p, data, 6) == 1 && ptr == data
          && p[0].return_size == 6, "or_ptr on an octet pointer points");
    p[0] = OSSL_PARAM_construct_int("x", &i);
    check(OSSL_PARAM_set_octet_string_or_ptr(p, data, 6) == 0, "or_ptr on an integer fails");
    errors("or_ptr on an integer");
    check(OSSL_PARAM_set_octet_string_or_ptr(NULL, data, 6) == 0, "or_ptr on NULL fails");
    errors("or_ptr on NULL");
}

static EVP_PKEY *keygen(const char *alg, const char *param)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *k = NULL;

    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0)
        goto done;
    if (param != NULL && EVP_PKEY_CTX_set_group_name(ctx, param) <= 0)
        goto done;
    EVP_PKEY_generate(ctx, &k);
done:
    EVP_PKEY_CTX_free(ctx);
    return k;
}

static void test_category(void)
{
    static const char *const algs[][2] = {
        { "EC", "P-256" }, { "X25519", NULL }, { "ED448", NULL }, { "ML-KEM-512", NULL },
        { "ML-KEM-768", NULL }, { "ML-KEM-1024", NULL }, { "ML-DSA-44", NULL },
        { "ML-DSA-65", NULL }, { "ML-DSA-87", NULL }, { "SLH-DSA-SHA2-128f", NULL },
        { "SLH-DSA-SHAKE-192f", NULL }, { "SLH-DSA-SHA2-256f", NULL }, { "X25519MLKEM768", NULL },
        { "SecP384r1MLKEM1024", NULL },
    };
    size_t i;
    EVP_PKEY *k, *empty = EVP_PKEY_new();

    for (i = 0; i < sizeof(algs) / sizeof(algs[0]); i++) {
        k = keygen(algs[i][0], algs[i][1]);
        printf("# %s: category %d\n", algs[i][0], EVP_PKEY_get_security_category(k));
        EVP_PKEY_free(k);
    }
    check(EVP_PKEY_get_security_category(NULL) == -1, "category of NULL");
    printf("# an empty key: category %d\n", EVP_PKEY_get_security_category(empty));
    EVP_PKEY_free(empty);
}

static void test_pkcs8(void)
{
    EVP_PKEY *k = keygen("EC", "P-256");
    unsigned char *der = NULL, *trad = NULL;
    const unsigned char *q;
    int n, m;
    PKCS8_PRIV_KEY_INFO *p8;

    n = i2d_PKCS8PrivateKey(k, &der);
    m = i2d_PrivateKey(k, &trad);
    q = der;
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &q, n);
    check(n > 0 && p8 != NULL && q == der + n, "an EC key as PKCS #8");
    check(m > 0 && m != n, "i2d_PrivateKey keeps the traditional form");
    check(i2d_PKCS8PrivateKey(k, NULL) == n, "the length alone");
    PKCS8_PRIV_KEY_INFO_free(p8);
    OPENSSL_free(der);
    OPENSSL_free(trad);
    EVP_PKEY_free(k);
}

static void test_store_loader(void)
{
    OSSL_STORE_LOADER *l = OSSL_STORE_LOADER_fetch(NULL, "file", NULL);
    const OSSL_PARAM *p = OSSL_STORE_LOADER_settable_ctx_params(l);

    printf("# file loader settable:");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u", p->key, p->data_type);
    printf("\n");
    check(OSSL_STORE_LOADER_settable_ctx_params(NULL) == NULL, "settable of NULL");
    OSSL_STORE_LOADER_free(l);
}

static void test_crl(void)
{
    X509_CRL *crl = X509_CRL_new();
    EVP_PKEY *k = keygen("EC", "P-256");
    const X509_ALGOR *tbs, *outer;
    const ASN1_OBJECT *obj;

    X509_CRL_sign(crl, k, EVP_sha256());
    tbs = X509_CRL_get0_tbs_sigalg(crl);
    X509_CRL_get0_signature(crl, NULL, &outer);
    X509_ALGOR_get0(&obj, NULL, NULL, tbs);
    check(tbs != NULL && tbs != outer, "the TBSCertList's algorithm is its own");
    check(OBJ_obj2nid(obj) == NID_ecdsa_with_SHA256, "and holds the signing algorithm");
    X509_CRL_free(crl);
    EVP_PKEY_free(k);
}

int main(void)
{
    test_arrays();
    test_stacks();
    test_params();
    test_category();
    test_pkcs8();
    test_store_loader();
    test_crl();
    printf("1..%d\n", number);
    return failures != 0;
}
