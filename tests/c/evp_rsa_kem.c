/*
 * Conformance test for the RSA KEM (EVP_KEM-RSA(7), EVP_PKEY_encapsulate(3)), in TAP format:
 * RSASVE with a key from a generator of known output, so the secret and its encapsulation are
 * the reference's; the size queries; decapsulation; the operation's name (any case, unknown
 * names refused); the errors for short buffers, wrong lengths, and ciphertexts out of range;
 * keys that can't be used (an RSA-PSS key, a public exponent of 1); and the parameter lists.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The error queue, emptied: each entry's library, reason, and text. */
static void errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf("  errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && *data != '\0')
            printf(" (%s)", data);
    }
    printf("\n");
}

/* A CTR-DRBG under a TEST-RAND parent with known entropy and nonce. */
static EVP_RAND_CTX *known_drbg(unsigned char seed)
{
    EVP_RAND *rand = EVP_RAND_fetch(NULL, "TEST-RAND", NULL);
    EVP_RAND_CTX *parent = EVP_RAND_CTX_new(rand, NULL), *ctx;
    unsigned char entropy[64], nonce[32];
    unsigned int strength = 256;
    OSSL_PARAM params[4];

    EVP_RAND_free(rand);
    memset(entropy, seed, sizeof(entropy));
    memset(nonce, seed ^ 0x5a, sizeof(nonce));
    params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, entropy,
                                                  sizeof(entropy));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE, nonce,
                                                  sizeof(nonce));
    params[3] = OSSL_PARAM_construct_end();
    EVP_RAND_instantiate(parent, 256, 0, NULL, 0, params);
    rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    ctx = EVP_RAND_CTX_new(rand, parent);
    EVP_RAND_free(rand);
    EVP_RAND_CTX_free(parent);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, "AES-256-CTR", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_RAND_instantiate(ctx, 256, 0, NULL, 0, params)) {
        EVP_RAND_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s(%zu):", label, n);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static EVP_PKEY *generate(const char *type, int bits)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    EVP_PKEY *k = NULL;

    EVP_PKEY_keygen_init(c);
    EVP_PKEY_CTX_set_rsa_keygen_bits(c, bits);
    EVP_PKEY_keygen(c, &k);
    EVP_PKEY_CTX_free(c);
    return k;
}

/* A public key from n and e. */
static EVP_PKEY *public_key(const BIGNUM *n, const char *e_hex)
{
    BIGNUM *e = NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY *k = NULL;

    BN_hex2bn(&e, e_hex);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
    params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_fromdata_init(c);
    EVP_PKEY_fromdata(c, &k, EVP_PKEY_PUBLIC_KEY, params);
    EVP_PKEY_CTX_free(c);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(e);
    return k;
}

static void test_round_trip(EVP_PKEY *k)
{
    unsigned char wrapped[256], secret[256], got[256];
    size_t wlen = 0, slen = 0, glen = sizeof(got);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(k, NULL);
    int i, ok = 1;

    printf("# encapsulate and decapsulate\n");
    check(EVP_PKEY_encapsulate_init(c, NULL) == 1, "encapsulate init");
    check(EVP_PKEY_CTX_set_kem_op(c, "RSASVE") == 1, "the operation");
    check(EVP_PKEY_encapsulate(c, NULL, &wlen, NULL, &slen) == 1 && wlen == 256 && slen == 256,
          "the sizes");
    check(EVP_PKEY_encapsulate(c, wrapped, &wlen, secret, &slen) == 1, "encapsulate");
    hex("wrapped", wrapped, wlen);
    hex("secret", secret, slen);
    errors();
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new(k, NULL);
    check(EVP_PKEY_decapsulate_init(c, NULL) == 1 && EVP_PKEY_CTX_set_kem_op(c, "rsasve") == 1,
          "decapsulate init, the operation in lower case");
    glen = 0;
    check(EVP_PKEY_decapsulate(c, NULL, &glen, wrapped, wlen) == 1, "the size query");
    printf("  size %zu\n", glen);
    glen = sizeof(got);
    check(EVP_PKEY_decapsulate(c, got, &glen, wrapped, wlen) == 1 && glen == slen
          && memcmp(got, secret, slen) == 0, "decapsulate gives the secret");
    errors();
    EVP_PKEY_CTX_free(c);

    /*
     * Forty more: the key's blinding is squared between uses and made again at the 33rd, from
     * the private generator, so the next secret (from it too) shows where the generator is.
     */
    c = EVP_PKEY_CTX_new(k, NULL);
    EVP_PKEY_decapsulate_init(c, NULL);
    for (i = 0; i < 40; i++) {
        glen = sizeof(got);
        ok = ok && EVP_PKEY_decapsulate(c, got, &glen, wrapped, wlen) == 1
            && memcmp(got, secret, slen) == 0;
    }
    check(ok, "forty decapsulations");
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new(k, NULL);
    EVP_PKEY_encapsulate_init(c, NULL);
    check(EVP_PKEY_encapsulate(c, wrapped, &wlen, secret, &slen) == 1, "encapsulate again");
    hex("secret", secret, slen);
    errors();
    EVP_PKEY_CTX_free(c);
}

static void test_errors(EVP_PKEY *k)
{
    unsigned char wrapped[256], secret[256], got[256], in[256];
    size_t wlen, slen, glen;
    BIGNUM *n = NULL, *t = BN_new();
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(k, NULL), *d;
    EVP_PKEY *pk;

    printf("# errors\n");
    EVP_PKEY_encapsulate_init(c, NULL);
    check(EVP_PKEY_CTX_set_kem_op(c, "DHKEM") == 0, "an unknown operation");
    errors();
    wlen = 100;
    slen = sizeof(secret);
    check(EVP_PKEY_encapsulate(c, wrapped, &wlen, secret, &slen) == 0, "a short output");
    errors();
    d = EVP_PKEY_CTX_dup(c);
    check(d != NULL, "a copy");
    EVP_PKEY_CTX_free(d);
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new(k, NULL);
    EVP_PKEY_decapsulate_init(c, NULL);
    EVP_PKEY_CTX_set_kem_op(c, "RSASVE");
    memset(in, 0, sizeof(in));
    glen = sizeof(got);
    check(EVP_PKEY_decapsulate(c, got, &glen, in, 255) == 0, "a short ciphertext");
    errors();
    glen = 10;
    check(EVP_PKEY_decapsulate(c, got, &glen, in, 256) == 0, "a short output");
    errors();
    glen = sizeof(got);
    check(EVP_PKEY_decapsulate(c, got, &glen, in, 256) == 0, "zero");
    errors();
    in[255] = 1;
    check(EVP_PKEY_decapsulate(c, got, &glen, in, 256) == 0, "one");
    errors();
    in[255] = 2;
    check(EVP_PKEY_decapsulate(c, got, &glen, in, 256) == 1, "two");
    hex("secret", got, glen);
    errors();
    EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_RSA_N, &n);
    BN_copy(t, n);
    BN_sub_word(t, 1);
    BN_bn2binpad(t, in, 256);
    check(EVP_PKEY_decapsulate(c, got, &glen, in, 256) == 0, "n - 1");
    errors();
    BN_sub_word(t, 1);
    BN_bn2binpad(t, in, 256);
    check(EVP_PKEY_decapsulate(c, got, &glen, in, 256) == 1, "n - 2");
    errors();
    BN_bn2binpad(n, in, 256);
    check(EVP_PKEY_decapsulate(c, got, &glen, in, 256) == 0, "n");
    errors();
    memset(in, 0xff, sizeof(in));
    check(EVP_PKEY_decapsulate(c, got, &glen, in, 256) == 0, "all ones");
    errors();
    EVP_PKEY_CTX_free(c);

    pk = public_key(n, "1");
    c = EVP_PKEY_CTX_new(pk, NULL);
    check(EVP_PKEY_encapsulate_init(c, NULL) <= 0, "a public exponent of 1");
    errors();
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(pk);
    pk = public_key(n, "10001");
    c = EVP_PKEY_CTX_new(pk, NULL);
    wlen = sizeof(wrapped);
    slen = sizeof(secret);
    check(EVP_PKEY_encapsulate_init(c, NULL) == 1
          && EVP_PKEY_encapsulate(c, wrapped, &wlen, secret, &slen) == 1,
          "a public key encapsulates");
    hex("secret", secret, slen);
    errors();
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new(pk, NULL);
    glen = sizeof(got);
    check(EVP_PKEY_decapsulate_init(c, NULL) == 1
          && EVP_PKEY_decapsulate(c, got, &glen, wrapped, wlen) <= 0,
          "a public key can't decapsulate");
    errors();
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(pk);
    BN_free(n);
    BN_free(t);

    pk = generate("RSA-PSS", 1024);
    c = EVP_PKEY_CTX_new(pk, NULL);
    check(EVP_PKEY_encapsulate_init(c, NULL) <= 0, "an RSA-PSS key");
    errors();
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(pk);
}

static void names(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u", p->key, p->data_type);
    printf("\n");
}

static void name_cb(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static void test_method(void)
{
    EVP_KEM *kem = EVP_KEM_fetch(NULL, "RSA", NULL);

    printf("# the method\n");
    check(kem != NULL && EVP_KEM_is_a(kem, "rsaEncryption"), "fetch RSA");
    printf("  names:");
    EVP_KEM_names_do_all(kem, name_cb, NULL);
    printf("\n");
    names("settable", EVP_KEM_settable_ctx_params(kem));
    names("gettable", EVP_KEM_gettable_ctx_params(kem));
    EVP_KEM_free(kem);
}

int main(void)
{
    EVP_PKEY *k;

    check(RAND_set0_public(NULL, known_drbg(31)) == 1
          && RAND_set0_private(NULL, known_drbg(32)) == 1, "known generators");
    k = generate("RSA", 2048);
    check(k != NULL, "a key");
    test_round_trip(k);
    test_errors(k);
    test_method();
    EVP_PKEY_free(k);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
