/*
 * Conformance test for the default provider's twelve SLH-DSA signatures
 * (EVP_SIGNATURE-SLH-DSA(7), provider-signature(7)), in TAP format: every parameter set's
 * names and deterministic signature; then, on two of them, deterministic signatures with and
 * without a context string and of the raw message, test entropy (of n octets and of other
 * lengths), hedged signatures, size queries and rooms too small, public keys, verification of
 * changed signatures, messages, and context strings and of signatures of other lengths, keys of
 * another parameter set, the EVP_DigestSign route (with and without a digest name), the
 * algorithm identifier, copies of an operation, and the inits SLH-DSA doesn't offer.
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

static const char *const VARIANTS[] = {
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
};

/* The parameter sets every check runs on. */
static const char *const FULL[] = { "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-192f" };

static const unsigned char MSG[] = "The quick brown fox jumps over the lazy dog";
#define MSGLEN (sizeof(MSG) - 1)
#define SIGROOM 50000

static unsigned char sig[SIGROOM], sig2[SIGROOM];

static size_t n_of(const char *alg)
{
    return strstr(alg, "128") != NULL ? 16 : strstr(alg, "192") != NULL ? 24 : 32;
}

static void fill(unsigned char *p, size_t n, unsigned char start)
{
    size_t i;

    for (i = 0; i < n; i++)
        p[i] = (unsigned char)(start + i);
}

/* A key generated from seeds starting at |start|. */
static EVP_PKEY *from_seed(const char *alg, unsigned char start)
{
    unsigned char seed[96];
    OSSL_PARAM p[2];
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *k = NULL;

    fill(seed, sizeof(seed), start);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_SLH_DSA_SEED, seed, 3 * n_of(alg));
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
    unsigned char pub[100];
    size_t len = sizeof(pub);

    EVP_PKEY_get_raw_public_key(k, pub, &len);
    return EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, pub, len);
}

/*
 * A signature of |msg| through EVP_PKEY_sign_message_init with |sigalg| (or the key's own
 * algorithm) and |params|, into room of |*siglen| octets; returns the init's and the sign's
 * results as two digits.
 */
static int sign_with(EVP_PKEY *k, const char *sigalg, const OSSL_PARAM *params,
                     const unsigned char *msg, size_t msglen, unsigned char *out, size_t *outlen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, sigalg != NULL ? sigalg
                                                                : EVP_PKEY_get0_type_name(k),
                                           NULL);
    int r = EVP_PKEY_sign_message_init(c, s, params);

    if (r == 1)
        r = r * 10 + EVP_PKEY_sign(c, out, outlen, msg, msglen);
    EVP_SIGNATURE_free(s);
    EVP_PKEY_CTX_free(c);
    return r;
}

/* Whether |in| signs |msg| (the init's and the verify's results as two digits). */
static int verify_with(EVP_PKEY *k, const OSSL_PARAM *params, const unsigned char *msg,
                       size_t msglen, const unsigned char *in, size_t inlen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, EVP_PKEY_get0_type_name(k), NULL);
    int r = EVP_PKEY_verify_message_init(c, s, params);

    if (r == 1)
        r = r * 10 + EVP_PKEY_verify(c, in, inlen, msg, msglen);
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
    EVP_PKEY *k = from_seed(alg, 1);
    size_t siglen = SIGROOM;
    int det = 1, r, r2;
    OSSL_PARAM p[2];

    printf("  names:");
    if (s != NULL)
        EVP_SIGNATURE_names_do_all(s, print_name, NULL);
    printf("\n  description: %s\n", desc == NULL ? "(null)" : desc);
    if (s != NULL) {
        names("settable", EVP_SIGNATURE_settable_ctx_params(s));
        names("gettable", EVP_SIGNATURE_gettable_ctx_params(s));
    }
    det_params(p, NULL, 0, &det, NULL);
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    digest("deterministic", sig, siglen);
    r2 = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    printf("  sign, verify: %d %d\n", r, r2);
    check(s != NULL && r == 11 && r2 == 11, alg);
    EVP_SIGNATURE_free(s);
    EVP_PKEY_free(k);
    errors();
}

static void test_deterministic(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 1);
    unsigned char ctx[255];
    size_t siglen;
    int det = 1, raw = 0, other = 7, r, r2, r3;
    OSSL_PARAM p[4];

    fill(ctx, sizeof(ctx), 0x40);
    det_params(p, NULL, 0, &det, NULL);
    siglen = 0;
    r = sign_with(k, NULL, p, MSG, MSGLEN, NULL, &siglen);
    printf("  size query: %d %zu\n", r, siglen);
    det_params(p, ctx, 5, &det, NULL);
    siglen = SIGROOM;
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    digest("with a context string", sig, siglen);
    r2 = verify_with(k, p, MSG, MSGLEN, sig, siglen);
    det_params(p, ctx, 4, NULL, NULL);
    r3 = verify_with(k, p, MSG, MSGLEN, sig, siglen);
    printf("  sign, verify, verify with another context: %d %d %d\n", r, r2, r3);

    det_params(p, ctx, 255, &det, NULL);
    siglen = SIGROOM;
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    digest("a context string of 255", sig, siglen);
    r2 = verify_with(k, p, MSG, MSGLEN, sig, siglen);
    printf("  sign, verify: %d %d\n", r, r2);

    det_params(p, NULL, 0, &det, &raw);
    siglen = SIGROOM;
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    digest("raw", sig, siglen);
    r2 = verify_with(k, p, MSG, MSGLEN, sig, siglen);
    r3 = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    printf("  sign, verify, verify as pure: %d %d %d\n", r, r2, r3);

    det_params(p, NULL, 0, &det, &other);
    siglen = SIGROOM;
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    digest("encoding 7", sig, siglen);
    r2 = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    printf("  sign, verify as pure: %d %d\n", r, r2);

    det = -3;
    det_params(p, NULL, 0, &det, NULL);
    siglen = SIGROOM;
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig, &siglen);
    digest("deterministic -3", sig, siglen);
    printf("  sign: %d\n", r);
    check(k != NULL, "deterministic signatures, with context strings and encodings");
    EVP_PKEY_free(k);
    errors();
}

static void test_verify(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 2), *other;
    unsigned char msg[sizeof(MSG)], ctx[256];
    size_t siglen = SIGROOM;
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
    sig[siglen / 3] ^= 0x80;
    r2 = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    sig[siglen / 3] ^= 0x80;
    sig[siglen - 1] ^= 0xff;
    r3 = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    sig[siglen - 1] ^= 0xff;
    printf("  changed R, FORS, the hypertree: %d %d %d\n", r, r2, r3);
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
    other = from_seed(alg, 3);
    r = verify_with(other, NULL, MSG, MSGLEN, sig, siglen);
    printf("  another key: %d\n", r);
    EVP_PKEY_free(other);
    check(k != NULL, "verification of changed signatures, messages, and context strings");
    EVP_PKEY_free(k);
    errors();
}

static void test_entropy(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 4);
    size_t n = n_of(alg), siglen = SIGROOM, siglen2 = SIGROOM;
    unsigned char ent[33];
    int r, r2, det = 1;
    OSSL_PARAM p[3];

    fill(ent, sizeof(ent), 0x80);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, ent, n);
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
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, ent, n - 1);
    p[1] = OSSL_PARAM_construct_end();
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig2, &siglen2);
    printf("  of n - 1: %d\n", r);
    errors();
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, ent, n + 1);
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig2, &siglen2);
    printf("  of n + 1: %d\n", r);
    errors();
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, ent, 0);
    r = sign_with(k, NULL, p, MSG, MSGLEN, sig2, &siglen2);
    printf("  empty: %d\n", r);
    check(k != NULL, "test entropy");
    EVP_PKEY_free(k);
    errors();
}

static void test_hedged(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 5);
    size_t siglen = SIGROOM, siglen2 = SIGROOM;
    int r, r2, det = 0;
    OSSL_PARAM p[2];

    r = sign_with(k, NULL, NULL, MSG, MSGLEN, sig, &siglen);
    p[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    p[1] = OSSL_PARAM_construct_end();
    r2 = sign_with(k, NULL, p, MSG, MSGLEN, sig2, &siglen2);
    printf("  sign twice: %d %d, lengths %zu %zu, differ: %d\n", r, r2, siglen, siglen2,
           memcmp(sig, sig2, siglen) != 0);
    r = verify_with(k, NULL, MSG, MSGLEN, sig, siglen);
    r2 = verify_with(k, NULL, MSG, MSGLEN, sig2, siglen2);
    printf("  verify both: %d %d\n", r, r2);
    check(r == 11 && r2 == 11, "hedged signatures");
    EVP_PKEY_free(k);
    errors();
}

static void test_rooms(const char *alg, const char *other)
{
    EVP_PKEY *k = from_seed(alg, 6);
    EVP_PKEY *pub = public_of(alg, k);
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
    siglen = SIGROOM;
    r = sign_with(pub, NULL, p, MSG, MSGLEN, sig2, &siglen);
    printf("  a public key's sign: %d %zu\n", r, siglen);
    errors();
    r = verify_with(pub, NULL, MSG, MSGLEN, sig, need);
    printf("  a public key verifies: %d\n", r);
    siglen = SIGROOM;
    r = sign_with(k, other, NULL, MSG, MSGLEN, sig2, &siglen);
    printf("  signing with %s: %d\n", other, r);
    errors();
    r = sign_with(k, "ML-DSA-44", NULL, MSG, MSGLEN, sig2, &siglen);
    printf("  signing with ML-DSA-44: %d\n", r);
    errors();
    check(pub != NULL, "sizes, rooms, public keys, and other algorithms");
    EVP_PKEY_free(pub);
    EVP_PKEY_free(k);
    errors();
}

static void test_digest_sign(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 1);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    unsigned char aid[64];
    size_t siglen = 0;
    int r, det = 1;
    OSSL_PARAM p[2], g[2];

    p[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    p[1] = OSSL_PARAM_construct_end();
    r = EVP_DigestSignInit_ex(m, &pc, NULL, NULL, NULL, k, p);
    r = r * 10 + EVP_DigestSign(m, NULL, &siglen, MSG, MSGLEN);
    printf("  init, size: %d %zu\n", r, siglen);
    siglen = SIGROOM;
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
    unsigned char ctx[256], aid[64];
    size_t siglen = SIGROOM, siglen2 = SIGROOM;
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

    p[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx, 256);
    p[1] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    r = EVP_PKEY_CTX_set_params(c, p);
    printf("  a context string of 256: %d\n", r);
    errors();
    siglen2 = SIGROOM;
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
    check(c != NULL, "the operation's context: parameters, copies, inits");
    EVP_SIGNATURE_free(s);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(k);
    errors();
}

int main(void)
{
    size_t i;

    for (i = 0; i < 12; i++) {
        printf("# %s\n", VARIANTS[i]);
        test_names(VARIANTS[i]);
    }
    for (i = 0; i < 2; i++) {
        printf("# %s\n", FULL[i]);
        test_deterministic(FULL[i]);
        test_verify(FULL[i]);
        test_entropy(FULL[i]);
        test_hedged(FULL[i]);
        test_rooms(FULL[i], FULL[1 - i]);
        test_digest_sign(FULL[i]);
        test_ctx(FULL[i]);
    }
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
