/*
 * Conformance test for the default provider's ML-DSA-44, ML-DSA-65, and ML-DSA-87 signatures
 * (EVP_SIGNATURE-ML-DSA(7), provider-signature(7)), in TAP format: their names and parameter
 * lists; deterministic signatures with and without a context string, of the raw message, and
 * of an external mu (of 64 octets and of other lengths); test entropy (of 32 octets, of other
 * lengths, and gone after a new init); hedged signatures; size queries and rooms too small;
 * verification of changed signatures, messages, and context strings and of signatures of
 * other lengths; context strings of 255 and 256 octets; the EVP_DigestSign route (with and
 * without a digest name); the algorithm identifier; copies of an operation; public keys;
 * keys of another parameter set; and the inits ML-DSA doesn't offer.
 *
 * Keys come from fixed seeds and the deterministic signatures are fixed, so they're printed
 * as SHA-256 digests. Hedged signatures print only whether they verify.
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
#include <openssl/params.h>

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

/* The first 8 octets of the SHA-256 of the octets, with their length. */
static void digest(const char *label, const unsigned char *p, size_t len)
{
    unsigned char d[32];
    unsigned int dl = 0;
    int i;

    EVP_Digest(p, len, d, &dl, EVP_sha256(), NULL);
    printf("  %s (%zu):", label, len);
    for (i = 0; i < 8; i++)
        printf("%02x", d[i]);
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, size_t len)
{
    size_t i;

    printf("  %s (%zu):", label, len);
    for (i = 0; i < len; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void names(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    if (p == NULL)
        printf(" (none)");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u", p->key, p->data_type);
    printf("\n");
}

static void print_name(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static const char *const VARIANTS[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };

static const unsigned char MSG[] = "The quick brown fox jumps over the lazy dog";
#define MSGLEN (sizeof(MSG) - 1)

static void fill(unsigned char *p, size_t n, unsigned char start)
{
    size_t i;

    for (i = 0; i < n; i++)
        p[i] = (unsigned char)(start + i);
}

/* A key generated from a seed of 32 octets starting at |start|. */
static EVP_PKEY *from_seed(const char *alg, unsigned char start)
{
    unsigned char seed[32];
    OSSL_PARAM p[2];
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *k = NULL;

    fill(seed, sizeof(seed), start);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, seed, sizeof(seed));
    p[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_keygen_init(c) <= 0 || EVP_PKEY_CTX_set_params(c, p) <= 0
        || EVP_PKEY_generate(c, &k) <= 0)
        k = NULL;
    EVP_PKEY_CTX_free(c);
    return k;
}

/* The public half of |k|, as a key of its own. */
static EVP_PKEY *public_of(const char *alg, EVP_PKEY *k)
{
    unsigned char pub[4096];
    size_t len = 0;
    OSSL_PARAM p[2];
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *out = NULL;

    EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub), &len);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub, len);
    p[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_fromdata_init(c) <= 0
        || EVP_PKEY_fromdata(c, &out, EVP_PKEY_PUBLIC_KEY, p) <= 0)
        out = NULL;
    EVP_PKEY_CTX_free(c);
    return out;
}

/*
 * A signature of |msg| through EVP_PKEY_sign_message_init with |sigalg| (or the key's own
 * algorithm) and |params|, into room of |*siglen| octets; returns the init's and the sign's
 * results as two digits.
 */
static int sign_with(EVP_PKEY *k, const char *sigalg, const OSSL_PARAM *params,
                     const unsigned char *msg, size_t msglen, unsigned char *sig, size_t *siglen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, sigalg != NULL ? sigalg
                                                                : EVP_PKEY_get0_type_name(k),
                                           NULL);
    int r = EVP_PKEY_sign_message_init(c, s, params);

    if (r == 1)
        r = r * 10 + EVP_PKEY_sign(c, sig, siglen, msg, msglen);
    EVP_SIGNATURE_free(s);
    EVP_PKEY_CTX_free(c);
    return r;
}

/* Whether |sig| signs |msg| (the init's and the verify's results as two digits). */
static int verify_with(EVP_PKEY *k, const OSSL_PARAM *params, const unsigned char *msg,
                       size_t msglen, const unsigned char *sig, size_t siglen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, EVP_PKEY_get0_type_name(k), NULL);
    int r = EVP_PKEY_verify_message_init(c, s, params);

    if (r == 1)
        r = r * 10 + EVP_PKEY_verify(c, sig, siglen, msg, msglen);
    EVP_SIGNATURE_free(s);
    EVP_PKEY_CTX_free(c);
    return r;
}

/* Parameters: a context string (unless |ctx| is NULL), deterministic, and an encoding. */
static void det_params(OSSL_PARAM *p, const unsigned char *ctx, size_t ctxlen, int *det,
                       int *encode)
{
    int n = 0;

    if (ctx != NULL)
        p[n++] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                   (void *)ctx, ctxlen);
    if (det != NULL)
        p[n++] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, det);
    if (encode != NULL)
        p[n++] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, encode);
    p[n] = OSSL_PARAM_construct_end();
}

static void test_names(const char *alg)
{
    EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, alg, NULL);
    const char *desc = s == NULL ? NULL : EVP_SIGNATURE_get0_description(s);

    printf("  names:");
    if (s != NULL)
        EVP_SIGNATURE_names_do_all(s, print_name, NULL);
    printf("\n  description: %s\n", desc == NULL ? "(null)" : desc);
    if (s != NULL) {
        names("settable", EVP_SIGNATURE_settable_ctx_params(s));
        names("gettable", EVP_SIGNATURE_gettable_ctx_params(s));
    }
    check(s != NULL, "the signature fetches, with its names and parameters");
    EVP_SIGNATURE_free(s);
    errors();
}

static void test_deterministic(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 1);
    unsigned char sig[5000], ctx[255];
    size_t siglen = sizeof(sig);
    int det = 1, raw = 0, other = 7, r, r2, r3;
    OSSL_PARAM p[4];

    fill(ctx, sizeof(ctx), 0x40);
    det_params(p, NULL, 0, &det, NULL);
    siglen = 0;
    r = sign_with(k, NULL, p, MSG, MSGLEN, NULL, &siglen);
    printf("  size query: %d %zu\n", r, siglen);
    siglen = sizeof(sig);
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    printf("  sign: %d\n", r);
    digest("pure", sig, siglen);
    r = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    printf("  verify: %d\n", r);

    det_params(p, ctx, 5, &det, NULL);
    siglen = sizeof(sig);
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    digest("with a context string", sig, siglen);
    r2 = verify_with(k, p, MSG, MSGLEN, sig, siglen);
    det_params(p, ctx, 4, NULL, NULL);
    r3 = verify_with(k, p, MSG, MSGLEN, sig, siglen);
    printf("  sign, verify, verify with another context: %d %d %d\n", r, r2, r3);

    det_params(p, ctx, 255, &det, NULL);
    siglen = sizeof(sig);
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    digest("a context string of 255", sig, siglen);
    r2 = verify_with(k, p, MSG, MSGLEN, sig, siglen);
    printf("  sign, verify: %d %d\n", r, r2);

    det_params(p, NULL, 0, &det, &raw);
    siglen = sizeof(sig);
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    digest("raw", sig, siglen);
    r2 = verify_with(k, p, MSG, MSGLEN, sig, siglen);
    r3 = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    printf("  sign, verify, verify as pure: %d %d %d\n", r, r2, r3);

    det_params(p, NULL, 0, &det, &other);
    siglen = sizeof(sig);
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    digest("encoding 7", sig, siglen);
    r2 = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    printf("  sign, verify as pure: %d %d\n", r, r2);

    det = 2;
    det_params(p, NULL, 0, &det, NULL);
    siglen = sizeof(sig);
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    r2 = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    printf("  deterministic 2 (hedged): %d %d\n", r, r2);
    check(k != NULL, "deterministic signatures, with context strings and encodings");
    EVP_PKEY_free(k);
    errors();
}

static void test_verify(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 2);
    unsigned char sig[5000], msg[sizeof(MSG)], ctx[256];
    size_t siglen = sizeof(sig);
    int det = 1, r, r2, r3;
    OSSL_PARAM p[4];

    det_params(p, NULL, 0, &det, NULL);
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    printf("  sign: %d\n", r);
    r = verify_with(k, NULL, MSG, MSGLEN, sig, siglen - 1);
    r2 = verify_with(k, NULL, MSG, MSGLEN, sig, siglen + 1);
    r3 = verify_with(k, NULL, MSG, MSGLEN, sig, 0);
    printf("  shorter, longer, empty: %d %d %d\n", r, r2, r3);
    sig[0] ^= 1;
    r = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    sig[0] ^= 1;
    sig[siglen / 2] ^= 0x80;
    r2 = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    sig[siglen / 2] ^= 0x80;
    /* The hints' counts are the last k octets; a decreasing count is an invalid encoding. */
    sig[siglen - 1] ^= 0xff;
    r3 = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    sig[siglen - 1] ^= 0xff;
    printf("  changed c, z, hints: %d %d %d\n", r, r2, r3);
    memcpy(msg, MSG, sizeof(MSG));
    msg[3] ^= 1;
    r = verify_with(k, NULL, msg, MSGLEN, sig, siglen);
    r2 = verify_with(k, NULL, MSG, MSGLEN - 1, sig, siglen);
    r3 = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    printf("  changed message, shorter message, as is: %d %d %d\n", r, r2, r3);
    fill(ctx, sizeof(ctx), 0);
    det_params(p, ctx, 256, NULL, NULL);
    r = verify_with(k, p, MSG, MSGLEN, sig, siglen);
    printf("  a context string of 256: %d\n", r);
    errors();
    det_params(p, ctx, 0, NULL, NULL);
    r = verify_with(k, p, MSG, MSGLEN, sig, siglen);
    printf("  an empty context string: %d\n", r);
    check(k != NULL, "verification of changed signatures, messages, and context strings");
    EVP_PKEY_free(k);
    errors();
}

/* mu = SHAKE256(SHAKE256(pk, 64) || M', 64) for the pure encoding with no context string. */
static void compute_mu(EVP_PKEY *k, const unsigned char *msg, size_t msglen, unsigned char *mu)
{
    unsigned char pub[4096], tr[64], hdr[2] = { 0, 0 };
    size_t len = 0;
    EVP_MD_CTX *c = EVP_MD_CTX_new();

    EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub), &len);
    EVP_DigestInit_ex(c, EVP_shake256(), NULL);
    EVP_DigestUpdate(c, pub, len);
    EVP_DigestFinalXOF(c, tr, sizeof(tr));
    EVP_DigestInit_ex(c, EVP_shake256(), NULL);
    EVP_DigestUpdate(c, tr, sizeof(tr));
    EVP_DigestUpdate(c, hdr, sizeof(hdr));
    EVP_DigestUpdate(c, msg, msglen);
    EVP_DigestFinalXOF(c, mu, 64);
    EVP_MD_CTX_free(c);
}

static void test_mu(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 3);
    unsigned char sig[5000], sig2[5000], mu[65];
    size_t siglen = sizeof(sig), siglen2 = sizeof(sig2);
    int det = 1, one = 1, r, r2, r3;
    OSSL_PARAM p[3];

    p[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    p[1] = OSSL_PARAM_construct_end();
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    compute_mu(k, MSG, MSGLEN, mu);
    p[1] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MU, &one);
    p[2] = OSSL_PARAM_construct_end();
    r2 = sign_with(k, NULL, p, mu, 64, sig2, &siglen2);
    printf("  sign, sign mu: %d %d, the same: %d\n", r, r2,
           siglen == siglen2 && memcmp(sig, sig2, siglen) == 0);
    r = verify_with(k, p + 1, mu, 64, sig, siglen);
    r2 = verify_with(k, p + 1, mu, 63, sig, siglen);
    r3 = verify_with(k, p + 1, mu, 65, sig, siglen);
    printf("  verify mu of 64, 63, 65: %d %d %d\n", r, r2, r3);
    siglen2 = 1;
    r = sign_with(k, NULL, p, mu, 63, sig2, &siglen2);
    printf("  sign mu of 63 into room too small: %d %zu\n", r, siglen2);
    siglen2 = sizeof(sig2);
    r = sign_with(k, NULL, p, mu, 63, sig2, &siglen2);
    printf("  sign mu of 63: %d %zu\n", r, siglen2);
    siglen2 = 0;
    r = sign_with(k, NULL, p, mu, 65, NULL, &siglen2);
    printf("  size query with mu of 65: %d %zu\n", r, siglen2);
    check(k != NULL, "an external mu");
    EVP_PKEY_free(k);
    errors();
}

static void test_entropy(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 4);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, alg, NULL);
    unsigned char sig[5000], sig2[5000], ent[33];
    size_t siglen = sizeof(sig), siglen2 = sizeof(sig2);
    int r, r2, det = 1;
    OSSL_PARAM p[3];

    fill(ent, sizeof(ent), 0x80);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, ent, 32);
    p[1] = OSSL_PARAM_construct_end();
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    digest("test entropy", sig, siglen);
    r2 = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    printf("  sign, verify: %d %d\n", r, r2);
    p[1] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    p[2] = OSSL_PARAM_construct_end();
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig2, &siglen2);
    printf("  with deterministic too, the same: %d %d\n", r,
           memcmp(sig, sig2, siglen) == 0);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, ent, 31);
    p[1] = OSSL_PARAM_construct_end();
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig2, &siglen2);
    printf("  of 31: %d\n", r);
    errors();
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, ent, 33);
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig2, &siglen2);
    printf("  of 33: %d\n", r);
    errors();

    /* A new init starts a fresh operation, without the entropy. */
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, ent, 32);
    r = EVP_PKEY_sign_message_init(c, s, p);
    r = r * 10 + EVP_PKEY_sign_message_init(c, s, NULL);
    siglen2 = sizeof(sig2);
    r = r * 10 + EVP_PKEY_sign(c, sig2, &siglen2, MSG, MSGLEN);
    printf("  init with, init without, sign: %d, the same: %d\n", r,
           siglen == siglen2 && memcmp(sig, sig2, siglen) == 0);
    check(r == 111, "test entropy");
    EVP_SIGNATURE_free(s);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(k);
    errors();
}

static void test_hedged(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 5);
    unsigned char sig[5000], sig2[5000];
    size_t siglen = sizeof(sig), siglen2 = sizeof(sig2);
    int r, r2;

    r = sign_with(k, NULL, NULL, MSG, MSGLEN, sig, &siglen);
    r2 = sign_with(k, NULL, NULL, MSG, MSGLEN, sig2, &siglen2);
    printf("  sign twice: %d %d, lengths %zu %zu, differ: %d\n", r, r2, siglen, siglen2,
           memcmp(sig, sig2, siglen) != 0);
    r = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    r2 = verify_with(k, NULL, MSG, MSGLEN, sig2, siglen2);
    printf("  verify both: %d %d\n", r, r2);
    check(r == 11 && r2 == 11, "hedged signatures");
    EVP_PKEY_free(k);
    errors();
}

static void test_rooms(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 6);
    EVP_PKEY *pub = public_of(alg, k);
    unsigned char sig[5000];
    size_t siglen, need = 0;
    int r, det = 1;
    OSSL_PARAM p[2];

    p[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    p[1] = OSSL_PARAM_construct_end();
    r = sign_with(k, NULL, p, MSG, MSGLEN, NULL, &need);
    printf("  size: %d %zu\n", r, need);
    siglen = need - 1;
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    printf("  room one too small: %d %zu\n", r, siglen);
    errors();
    siglen = need;
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    printf("  room exactly: %d %zu\n", r, siglen);
    siglen = 0;
    r = sign_with(pub, NULL, p, MSG, MSGLEN, NULL, &siglen);
    printf("  a public key's size query: %d %zu\n", r, siglen);
    errors();
    siglen = sizeof(sig);
    r = sign_with(pub, NULL, p, MSG, MSGLEN, sig, &siglen);
    printf("  a public key's sign: %d %zu\n", r, siglen);
    errors();
    siglen = need;
    sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    r = verify_with(pub, NULL, MSG, MSGLEN, sig, siglen);
    printf("  a public key verifies: %d\n", r);
    check(pub != NULL, "sizes, rooms, and public keys");
    EVP_PKEY_free(pub);
    EVP_PKEY_free(k);
    errors();
}

static void test_mismatch(const char *alg, const char *other)
{
    EVP_PKEY *k = from_seed(alg, 7);
    unsigned char sig[5000];
    size_t siglen = sizeof(sig);
    int r;

    r = sign_with(k, other, NULL, MSG, MSGLEN, sig, &siglen);
    printf("  signing with %s: %d\n", other, r);
    errors();
    r = sign_with(k, "ED25519", NULL, MSG, MSGLEN, sig, &siglen);
    printf("  signing with ED25519: %d\n", r);
    errors();
    check(k != NULL, "keys of another algorithm");
    EVP_PKEY_free(k);
}

static void test_digest_sign(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 1);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    unsigned char sig[5000], aid[64];
    size_t siglen = 0;
    int r, det = 1;
    OSSL_PARAM p[2], g[2];

    p[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    p[1] = OSSL_PARAM_construct_end();
    r = EVP_DigestSignInit_ex(m, &pc, NULL, NULL, NULL, k, p);
    r = r * 10 + EVP_DigestSign(m, NULL, &siglen, MSG, MSGLEN);
    printf("  init, size: %d %zu\n", r, siglen);
    siglen = sizeof(sig);
    r = EVP_DigestSign(m, sig, &siglen, MSG, MSGLEN);
    digest("digest sign", sig, siglen);
    printf("  sign: %d\n", r);
    g[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid));
    g[1] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_get_params(pc, g);
    printf("  algorithm identifier: %d\n", r);
    if (r == 1)
        hex("aid", aid, g[0].return_size);
    EVP_MD_CTX_free(m);
    errors();

    m = EVP_MD_CTX_new();
    r = EVP_DigestVerifyInit_ex(m, NULL, NULL, NULL, NULL, k, NULL);
    r = r * 10 + EVP_DigestVerify(m, sig, siglen, MSG, MSGLEN);
    printf("  digest verify: %d\n", r);
    EVP_MD_CTX_free(m);
    errors();

    m = EVP_MD_CTX_new();
    r = EVP_DigestSignInit_ex(m, NULL, "SHA256", NULL, NULL, k, NULL);
    printf("  with SHA256: %d\n", r);
    EVP_MD_CTX_free(m);
    errors();

    m = EVP_MD_CTX_new();
    r = EVP_DigestSignInit_ex(m, NULL, NULL, NULL, NULL, k, NULL);
    r = r * 10 + EVP_DigestSignUpdate(m, MSG, MSGLEN);
    printf("  init, update: %d\n", r);
    EVP_MD_CTX_free(m);
    check(k != NULL, "the EVP_DigestSign route");
    EVP_PKEY_free(k);
    errors();
}

static void test_ctx(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 8);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL), *d = NULL;
    EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, alg, NULL);
    unsigned char sig[5000], sig2[5000], ctx[256], aid[64];
    size_t siglen = sizeof(sig), siglen2 = sizeof(sig2);
    int r, det = 1;
    OSSL_PARAM p[3], g[2];

    fill(ctx, sizeof(ctx), 0x11);
    g[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid));
    g[1] = OSSL_PARAM_construct_end();
    p[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    p[1] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx, 9);
    p[2] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_sign_message_init(c, s, p);
    r = r * 10 + EVP_PKEY_CTX_get_params(c, g);
    printf("  init, aid: %d\n", r);
    if (r == 11)
        hex("aid", aid, g[0].return_size);
    d = EVP_PKEY_CTX_dup(c);
    r = EVP_PKEY_sign(c, sig, &siglen, MSG, MSGLEN);
    r = r * 10 + EVP_PKEY_sign(d, sig2, &siglen2, MSG, MSGLEN);
    printf("  sign with the original and the copy: %d, the same: %d\n", r,
           siglen == siglen2 && memcmp(sig, sig2, siglen) == 0);
    digest("context string of 9", sig, siglen);

    /* A new init starts a fresh operation, without the context string. */
    r = EVP_PKEY_sign_message_init(c, s, NULL);
    siglen2 = sizeof(sig2);
    r = r * 10 + EVP_PKEY_sign(c, sig2, &siglen2, MSG, MSGLEN);
    printf("  init again, sign: %d, the same: %d\n", r,
           siglen == siglen2 && memcmp(sig, sig2, siglen) == 0);

    p[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx, 256);
    p[1] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    r = EVP_PKEY_CTX_set_params(c, p);
    printf("  a context string of 256: %d\n", r);
    errors();
    siglen2 = sizeof(sig2);
    r = EVP_PKEY_sign(c, sig2, &siglen2, MSG, MSGLEN);
    r = r * 10 + verify_with(k, NULL, MSG, MSGLEN, sig2, siglen2);
    printf("  sign then (an empty context) verify: %d\n", r);
    names("settable from the operation", EVP_PKEY_CTX_settable_params(c));
    names("gettable from the operation", EVP_PKEY_CTX_gettable_params(c));

    EVP_PKEY_CTX_free(d);
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    r = EVP_PKEY_sign_init(c);
    printf("  sign init: %d\n", r);
    errors();
    r = EVP_PKEY_verify_init(c);
    printf("  verify init: %d\n", r);
    errors();
    r = EVP_PKEY_sign_message_init(c, s, NULL);
    r = r * 10 + EVP_PKEY_sign_message_update(c, MSG, MSGLEN);
    printf("  message init, update: %d\n", r);
    {
        /* 3.6: a message in pieces, signed deterministically, then verified in pieces. */
        unsigned char sig1[4627], sig2[4627];
        size_t l1 = sizeof(sig1), l2 = sizeof(sig2), q = 0;
        int det = 1;
        OSSL_PARAM dp[2], sp[2];

        dp[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
        dp[1] = OSSL_PARAM_construct_end();
        r = EVP_PKEY_sign_message_init(c, s, dp);
        r = r * 10 + EVP_PKEY_sign_message_update(c, MSG, 3);
        r = r * 10 + EVP_PKEY_sign_message_update(c, MSG + 3, MSGLEN - 3);
        r = r * 10 + EVP_PKEY_sign_message_final(c, NULL, &q);
        r = r * 10 + EVP_PKEY_sign_message_final(c, sig1, &l1);
        printf("  in pieces: %d, length query %zu, %zu\n", r, q, l1);
        errors();
        r = EVP_PKEY_sign_message_init(c, s, dp) * 10 + EVP_PKEY_sign(c, sig2, &l2, MSG, MSGLEN);
        printf("  one-shot: %d, the same %d\n", r, l1 == l2 && memcmp(sig1, sig2, l1) == 0);
        sp[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, sig2, l2);
        sp[1] = OSSL_PARAM_construct_end();
        r = EVP_PKEY_verify_message_init(c, s, NULL);
        r = r * 10 + EVP_PKEY_CTX_set_params(c, sp);
        r = r * 10 + EVP_PKEY_verify_message_update(c, MSG, MSGLEN);
        r = r * 10 + EVP_PKEY_verify_message_final(c);
        printf("  verified in pieces: %d\n", r);
        r = EVP_PKEY_verify_message_init(c, s, NULL);
        sig2[0] ^= 1;
        r = r * 10 + EVP_PKEY_CTX_set_params(c, sp);
        r = r * 10 + EVP_PKEY_verify_message_update(c, MSG, MSGLEN);
        r = r * 10 + EVP_PKEY_verify_message_final(c);
        printf("  a changed signature: %d\n", r);
        errors();
    }
    check(c != NULL, "the operation's context: parameters, copies, inits");
    EVP_SIGNATURE_free(s);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(k);
    errors();
}

int main(void)
{
    size_t i;

    for (i = 0; i < 3; i++) {
        printf("# %s\n", VARIANTS[i]);
        test_names(VARIANTS[i]);
        test_deterministic(VARIANTS[i]);
        test_verify(VARIANTS[i]);
        test_mu(VARIANTS[i]);
        test_entropy(VARIANTS[i]);
        test_hedged(VARIANTS[i]);
        test_rooms(VARIANTS[i]);
        test_mismatch(VARIANTS[i], VARIANTS[(i + 1) % 3]);
        test_digest_sign(VARIANTS[i]);
        test_ctx(VARIANTS[i]);
    }
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
