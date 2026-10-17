/*
 * Conformance test for the default provider's DHKEMs (EVP_PKEY_encapsulate(3) and
 * EVP_PKEY_decapsulate(3) with the "DHKEM" operation, and their auth_ forms), in TAP format:
 * keys over P-256, P-384, P-521, X25519, and X448 made from fixed input key material, each
 * encapsulation with a fixed ephemeral seed (its encapsulated key and secret printed) and
 * decapsulated back, with and without a sender's authentication key; random encapsulations
 * round-tripped; and the errors: rooms too small, an encapsulated key of the wrong length or
 * off the curve, short input key material, an unknown operation, keys of other groups or types,
 * a public key where a private one is needed, and a curve no KEM uses.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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
    unsigned long e;
    const char *data;
    int flags;

    printf("  errors:");
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s (%zu):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 && i > 0 ? "\n    " : " ", p[i]);
    printf("\n");
}

static unsigned char IKM[80];

/* A key of the type (and group) made from IKM with the first octet changed to `tag`. */
static EVP_PKEY *dhkem_key(const char *type, const char *group, unsigned char tag, size_t ikmlen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    EVP_PKEY *k = NULL;
    OSSL_PARAM params[3], *p = params;
    unsigned char ikm[80];

    memcpy(ikm, IKM, sizeof(ikm));
    ikm[0] = tag;
    if (group != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM, ikm, ikmlen);
    *p = OSSL_PARAM_construct_end();
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_params(ctx, params) <= 0
        || EVP_PKEY_generate(ctx, &k) <= 0)
        k = NULL;
    EVP_PKEY_CTX_free(ctx);
    return k;
}

/* The public part only. */
static EVP_PKEY *public_of(EVP_PKEY *k)
{
    unsigned char *der = NULL;
    const unsigned char *p;
    int n = i2d_PUBKEY(k, &der);
    EVP_PKEY *pub;

    p = der;
    pub = n > 0 ? d2i_PUBKEY(NULL, &p, n) : NULL;
    OPENSSL_free(der);
    return pub;
}

/* Encapsulates to `to` (from `auth` when not NULL) with the seed (none for NULL): the result,
 * with the encapsulated key and secret. */
static int encap(EVP_PKEY *to, EVP_PKEY *auth, const unsigned char *seed, size_t seedlen,
                 const char *op, unsigned char *enc, size_t *enclen, unsigned char *secret,
                 size_t *secretlen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, to, NULL);
    OSSL_PARAM params[3], *p = params;
    int r;

    if (op != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KEM_PARAM_OPERATION, (char *)op, 0);
    if (seed != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, (void *)seed, seedlen);
    *p = OSSL_PARAM_construct_end();
    r = auth != NULL ? EVP_PKEY_auth_encapsulate_init(ctx, auth, params)
                     : EVP_PKEY_encapsulate_init(ctx, params);
    if (r <= 0) {
        printf("  encapsulate_init: %d\n", r);
        EVP_PKEY_CTX_free(ctx);
        return r;
    }
    r = EVP_PKEY_encapsulate(ctx, enc, enclen, secret, secretlen);
    EVP_PKEY_CTX_free(ctx);
    return r;
}

static int decap(EVP_PKEY *to, EVP_PKEY *auth, const unsigned char *enc, size_t enclen,
                 unsigned char *secret, size_t *secretlen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, to, NULL);
    OSSL_PARAM params[2];
    int r;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KEM_PARAM_OPERATION, "DHKEM", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = auth != NULL ? EVP_PKEY_auth_decapsulate_init(ctx, auth, params)
                     : EVP_PKEY_decapsulate_init(ctx, params);
    if (r <= 0) {
        printf("  decapsulate_init: %d\n", r);
        EVP_PKEY_CTX_free(ctx);
        return r;
    }
    r = EVP_PKEY_decapsulate(ctx, secret, secretlen, enc, enclen);
    EVP_PKEY_CTX_free(ctx);
    return r;
}

static void test_kem(const char *type, const char *group)
{
    char name[64], what[160];
    EVP_PKEY *r = dhkem_key(type, group, 1, 66), *s = dhkem_key(type, group, 2, 66);
    EVP_PKEY *rpub = r != NULL ? public_of(r) : NULL, *spub = s != NULL ? public_of(s) : NULL;
    unsigned char enc[200], secret[100], back[100], seed[66];
    size_t enclen, secretlen, backlen, nenc = 0, nsecret = 0;
    EVP_PKEY_CTX *ctx;
    int auth, ret;

    snprintf(name, sizeof(name), "%s%s%s", type, group != NULL ? " " : "", group != NULL ? group : "");
    printf("# %s\n", name);
    memcpy(seed, IKM + 3, sizeof(seed));
    snprintf(what, sizeof(what), "%s keys", name);
    check(r != NULL && s != NULL && rpub != NULL && spub != NULL, what);
    if (r == NULL || s == NULL || rpub == NULL || spub == NULL) {
        errors();
        goto end;
    }

    /* The sizes. */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, rpub, NULL);
    ret = EVP_PKEY_encapsulate_init(ctx, NULL);
    printf("  init %d\n", ret);
    ret = EVP_PKEY_encapsulate(ctx, NULL, &nenc, NULL, &nsecret);
    printf("  sizes: %d, enc %zu, secret %zu\n", ret, nenc, nsecret);
    nenc = 0;
    ret = EVP_PKEY_encapsulate(ctx, NULL, &nenc, NULL, NULL);
    printf("  enc size only: %d, %zu\n", ret, nenc);
    ret = EVP_PKEY_encapsulate(ctx, NULL, NULL, NULL, NULL);
    printf("  no sizes: %d\n", ret);
    ERR_clear_error();
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, r, NULL);
    EVP_PKEY_decapsulate_init(ctx, NULL);
    backlen = 0;
    ret = EVP_PKEY_decapsulate(ctx, NULL, &backlen, enc, nenc);
    printf("  decapsulate size: %d, %zu\n", ret, backlen);
    EVP_PKEY_CTX_free(ctx);

    for (auth = 0; auth < 2; auth++) {
        printf("  %s\n", auth ? "auth" : "base");
        enclen = sizeof(enc);
        secretlen = sizeof(secret);
        ret = encap(rpub, auth ? s : NULL, seed, sizeof(seed), "DHKEM", enc, &enclen, secret, &secretlen);
        snprintf(what, sizeof(what), "%s %s encapsulation", name, auth ? "auth" : "base");
        check(ret == 1, what);
        if (ret != 1) {
            errors();
            continue;
        }
        hex("enc", enc, enclen);
        hex("secret", secret, secretlen);
        backlen = sizeof(back);
        ret = decap(r, auth ? spub : NULL, enc, enclen, back, &backlen);
        snprintf(what, sizeof(what), "%s %s decapsulated back", name, auth ? "auth" : "base");
        check(ret == 1 && backlen == secretlen && memcmp(back, secret, secretlen) == 0, what);
        if (ret != 1)
            errors();
        /* Without the auth key, or with it where there was none: another secret. */
        backlen = sizeof(back);
        ret = decap(r, auth ? NULL : spub, enc, enclen, back, &backlen);
        printf("  other mode: %d, same %d\n", ret,
               ret == 1 && backlen == secretlen && memcmp(back, secret, secretlen) == 0);
        ERR_clear_error();
    }

    /* Random ephemeral keys, round-tripped. */
    enclen = sizeof(enc);
    secretlen = sizeof(secret);
    ret = encap(rpub, NULL, NULL, 0, NULL, enc, &enclen, secret, &secretlen);
    backlen = sizeof(back);
    snprintf(what, sizeof(what), "%s random encapsulation decapsulated", name);
    check(ret == 1 && decap(r, NULL, enc, enclen, back, &backlen) == 1 && backlen == secretlen
              && memcmp(back, secret, secretlen) == 0, what);
    ERR_clear_error();
    /* An empty seed is no seed. */
    enclen = sizeof(enc);
    secretlen = sizeof(secret);
    ret = encap(rpub, NULL, seed, 0, "dhkem", enc, &enclen, secret, &secretlen);
    printf("  empty seed, lowercase operation: %d, enc %zu\n", ret, enclen);
    ERR_clear_error();

    /* Errors. */
    enclen = sizeof(enc);
    secretlen = nsecret - 1;
    ret = encap(rpub, NULL, seed, sizeof(seed), "DHKEM", enc, &enclen, secret, &secretlen);
    printf("  secret room short: %d\n", ret);
    errors();
    enclen = nenc - 1;
    secretlen = sizeof(secret);
    ret = encap(rpub, NULL, seed, sizeof(seed), "DHKEM", enc, &enclen, secret, &secretlen);
    printf("  enc room short: %d\n", ret);
    errors();
    enclen = sizeof(enc);
    secretlen = sizeof(secret);
    ret = encap(rpub, NULL, seed, 8, "DHKEM", enc, &enclen, secret, &secretlen);
    printf("  short seed: %d\n", ret);
    errors();
    ret = encap(rpub, NULL, seed, sizeof(seed), "NOTDHKEM", enc, &enclen, secret, &secretlen);
    printf("  unknown operation: %d\n", ret);
    errors();
    ret = encap(rpub, spub, seed, sizeof(seed), "DHKEM", enc, &enclen, secret, &secretlen);
    printf("  public auth key to encapsulate: %d\n", ret);
    errors();
    backlen = sizeof(back);
    ret = decap(rpub, NULL, enc, nenc, back, &backlen);
    printf("  public key to decapsulate: %d\n", ret);
    errors();
    enclen = sizeof(enc);
    secretlen = sizeof(secret);
    encap(rpub, NULL, seed, sizeof(seed), "DHKEM", enc, &enclen, secret, &secretlen);
    backlen = sizeof(back);
    ret = decap(r, NULL, enc, enclen - 1, back, &backlen);
    printf("  enc one short: %d\n", ret);
    errors();
    backlen = nsecret - 1;
    ret = decap(r, NULL, enc, enclen, back, &backlen);
    printf("  decapsulated room short: %d\n", ret);
    errors();
    enc[enclen - 1] ^= 1;
    backlen = sizeof(back);
    ret = decap(r, NULL, enc, enclen, back, &backlen);
    printf("  enc changed: %d\n", ret);
    if (ret == 1)
        hex("secret", back, backlen);
    errors();
    memset(enc, 0, enclen);
    backlen = sizeof(back);
    ret = decap(r, NULL, enc, enclen, back, &backlen);
    printf("  enc zeros: %d\n", ret);
    errors();
end:
    EVP_PKEY_free(r);
    EVP_PKEY_free(s);
    EVP_PKEY_free(rpub);
    EVP_PKEY_free(spub);
}

static void test_mismatches(void)
{
    EVP_PKEY *p256 = dhkem_key("EC", "P-256", 1, 66), *p384 = dhkem_key("EC", "P-384", 2, 66);
    EVP_PKEY *x25519 = dhkem_key("X25519", NULL, 1, 66), *x448 = dhkem_key("X448", NULL, 2, 66);
    EVP_PKEY *k1 = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "secp256k1");
    EVP_PKEY *bp = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "brainpoolP256r1");
    EVP_PKEY_CTX *ctx;
    unsigned char enc[200], secret[100];
    size_t enclen = sizeof(enc), secretlen = sizeof(secret);

    printf("# mismatches\n");
    check(p256 != NULL && p384 != NULL && x25519 != NULL && x448 != NULL && k1 != NULL && bp != NULL,
          "the keys");
    printf("  P-256 to P-384's auth: %d\n",
           encap(p256, p384, NULL, 0, NULL, enc, &enclen, secret, &secretlen));
    errors();
    printf("  X25519 to X448's auth: %d\n",
           encap(x25519, x448, NULL, 0, NULL, enc, &enclen, secret, &secretlen));
    errors();
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, k1, NULL);
    printf("  secp256k1: %d\n", EVP_PKEY_encapsulate_init(ctx, NULL));
    errors();
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, bp, NULL);
    printf("  brainpoolP256r1 decapsulate: %d\n", EVP_PKEY_decapsulate_init(ctx, NULL));
    errors();
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, p256, NULL);
    printf("  P-256 init: %d, set_kem_op DHKEM: %d, RSASVE: %d\n", EVP_PKEY_encapsulate_init(ctx, NULL),
           EVP_PKEY_CTX_set_kem_op(ctx, "DHKEM"), EVP_PKEY_CTX_set_kem_op(ctx, "RSASVE"));
    errors();
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(p256);
    EVP_PKEY_free(p384);
    EVP_PKEY_free(x25519);
    EVP_PKEY_free(x448);
    EVP_PKEY_free(k1);
    EVP_PKEY_free(bp);
}

int main(void)
{
    size_t i;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    for (i = 0; i < sizeof(IKM); i++)
        IKM[i] = (unsigned char)(i * 7 + 3);
    test_kem("EC", "P-256");
    test_kem("EC", "P-384");
    test_kem("EC", "P-521");
    test_kem("X25519", NULL);
    test_kem("X448", NULL);
    test_mismatches();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
