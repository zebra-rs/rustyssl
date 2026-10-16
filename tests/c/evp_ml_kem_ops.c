/*
 * Conformance test for the default provider's ML-KEM KEM (EVP_KEM-ML-KEM(7),
 * EVP_PKEY_encapsulate(3), EVP_PKEY_decapsulate(3)), in TAP format, for ML-KEM-512, -768, and
 * -1024: the KEM's names and parameters; encapsulation with a fixed ikmE (used once) and its
 * sizes, rooms too small, and missing buffers and lengths; ikmE of the wrong length, and set
 * for a decapsulation; decapsulation of it, of a changed ciphertext (the implicit rejection
 * secret), and of ciphertexts of the wrong length; random encapsulations; and keys without the
 * part an operation needs.
 *
 * Keys come from fixed seeds and the entropy is fixed, so the outputs are the same every run;
 * they're printed as SHA-256 digests. Random outputs print only whether they agree.
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

static void fill(unsigned char *p, size_t n, unsigned char start)
{
    size_t i;

    for (i = 0; i < n; i++)
        p[i] = (unsigned char)(start + i);
}

static EVP_PKEY *from_seed(const char *alg, unsigned char start)
{
    unsigned char seed[64];
    OSSL_PARAM p[2];
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *k = NULL;

    fill(seed, sizeof(seed), start);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, seed, sizeof(seed));
    p[1] = OSSL_PARAM_construct_end();
    if (c == NULL || EVP_PKEY_keygen_init(c) != 1 || EVP_PKEY_CTX_set_params(c, p) != 1
        || EVP_PKEY_generate(c, &k) != 1)
        k = NULL;
    EVP_PKEY_CTX_free(c);
    return k;
}

static void test_kem(const char *alg)
{
    EVP_KEM *kem = EVP_KEM_fetch(NULL, alg, NULL);

    check(kem != NULL, alg);
    if (kem == NULL)
        return;
    printf("  names:");
    EVP_KEM_names_do_all(kem, print_name, NULL);
    printf("\n  description: %s\n", EVP_KEM_get0_description(kem));
    names("settable", EVP_KEM_settable_ctx_params(kem));
    names("gettable", EVP_KEM_gettable_ctx_params(kem));
    EVP_KEM_free(kem);
}

static OSSL_PARAM *ikme(unsigned char *e, size_t n)
{
    static OSSL_PARAM p[2];

    p[0] = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, e, n);
    p[1] = OSSL_PARAM_construct_end();
    return p;
}

static void test_ops(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 0), *pub = NULL, *empty = NULL;
    EVP_PKEY_CTX *c, *d;
    unsigned char e[40], ct[2000], ct2[2000], ss[64], ss2[64], raw[2000];
    size_t clen, slen, cl2, sl2, rl = sizeof(raw);
    int r;

    check(k != NULL, "a key");
    if (k == NULL)
        return;
    fill(e, sizeof(e), 64);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);

    /* Sizes. */
    r = EVP_PKEY_encapsulate_init(c, ikme(e, 32));
    clen = slen = 0;
    printf("  init %d sizes %d", r, EVP_PKEY_encapsulate(c, NULL, &clen, NULL, &slen));
    printf(" %zu %zu", clen, slen);
    clen = 0;
    printf(" ciphertext only %d %zu", EVP_PKEY_encapsulate(c, NULL, &clen, NULL, NULL), clen);
    slen = 0;
    printf(" secret only %d %zu", EVP_PKEY_encapsulate(c, NULL, NULL, NULL, &slen), slen);
    printf(" neither %d\n", EVP_PKEY_encapsulate(c, NULL, NULL, NULL, NULL));
    errors();

    /* Rooms too small, and no secret buffer; the ikmE is gone after each. */
    clen = 100;
    slen = 32;
    printf("  small ciphertext %d %zu", EVP_PKEY_encapsulate(c, ct, &clen, ss, &slen), clen);
    clen = sizeof(ct);
    slen = 31;
    printf(" small secret %d %zu %zu", EVP_PKEY_encapsulate(c, ct, &clen, ss, &slen), clen, slen);
    clen = sizeof(ct);
    slen = sizeof(ss);
    printf(" no secret buffer %d\n", EVP_PKEY_encapsulate(c, ct, &clen, NULL, &slen));
    errors();

    /* The fixed encapsulation, and the same again without the ikmE (random). */
    r = EVP_PKEY_encapsulate_init(c, ikme(e, 32));
    clen = sizeof(ct);
    slen = sizeof(ss);
    r = r * 10 + EVP_PKEY_encapsulate(c, ct, &clen, ss, &slen);
    check(r == 11, "an encapsulation with ikmE");
    digest("ciphertext", ct, clen);
    digest("secret", ss, slen);
    cl2 = sizeof(ct2);
    sl2 = sizeof(ss2);
    r = EVP_PKEY_encapsulate(c, ct2, &cl2, ss2, &sl2);
    printf("  again %d same %d %d\n", r, cl2 == clen && memcmp(ct, ct2, clen) == 0,
           memcmp(ss, ss2, 32) == 0);
    errors();

    /* ikmE of the wrong length; set again by EVP_PKEY_CTX_set_params. */
    printf("  ikmE of 31 %d", EVP_PKEY_encapsulate_init(c, ikme(e, 31)));
    printf(" of 33 %d", EVP_PKEY_encapsulate_init(c, ikme(e, 33)));
    printf(" of 0 %d\n", EVP_PKEY_encapsulate_init(c, ikme(e, 0)));
    errors();
    r = EVP_PKEY_encapsulate_init(c, NULL);
    r = r * 10 + EVP_PKEY_CTX_set_params(c, ikme(e, 32));
    cl2 = sizeof(ct2);
    sl2 = sizeof(ss2);
    r = r * 10 + EVP_PKEY_encapsulate(c, ct2, &cl2, ss2, &sl2);
    printf("  set later %d same %d\n", r, memcmp(ct, ct2, clen) == 0);
    errors();

    /* Decapsulation (an ikmE given to it is ignored). */
    d = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    r = EVP_PKEY_decapsulate_init(d, ikme(e, 5));
    sl2 = 0;
    printf("  decap init %d size %d", r, EVP_PKEY_decapsulate(d, NULL, &sl2, ct, clen));
    printf(" %zu", sl2);
    sl2 = 31;
    printf(" small %d %zu", EVP_PKEY_decapsulate(d, ss2, &sl2, ct, clen), sl2);
    sl2 = sizeof(ss2);
    r = EVP_PKEY_decapsulate(d, ss2, &sl2, ct, clen);
    printf(" decap %d %zu same %d\n", r, sl2, memcmp(ss, ss2, 32) == 0);
    errors();
    check(r == 1 && memcmp(ss, ss2, 32) == 0, "the secret decapsulated");
    ct[clen - 1] ^= 0x10;
    sl2 = sizeof(ss2);
    r = EVP_PKEY_decapsulate(d, ss2, &sl2, ct, clen);
    printf("  changed %d", r);
    digest("rejection secret", ss2, sl2);
    ct[clen - 1] ^= 0x10;
    sl2 = sizeof(ss2);
    printf("  short %d", EVP_PKEY_decapsulate(d, ss2, &sl2, ct, clen - 1));
    sl2 = sizeof(ss2);
    printf(" long %d", EVP_PKEY_decapsulate(d, ss2, &sl2, ct, clen + 1));
    sl2 = sizeof(ss2);
    printf(" empty %d\n", EVP_PKEY_decapsulate(d, ss2, &sl2, ct, 0));
    errors();

    /* A random encapsulation decapsulates to its secret. */
    r = EVP_PKEY_encapsulate_init(c, NULL);
    cl2 = sizeof(ct2);
    sl2 = sizeof(ss2);
    r = r * 10 + EVP_PKEY_encapsulate(c, ct2, &cl2, ss2, &sl2);
    slen = sizeof(ss);
    r = r * 10 + EVP_PKEY_decapsulate(d, ss, &slen, ct2, cl2);
    printf("  random %d same %d\n", r, memcmp(ss, ss2, 32) == 0);
    errors();
    EVP_PKEY_CTX_free(d);
    EVP_PKEY_CTX_free(c);

    /* A public key encapsulates the same, and can't decapsulate. */
    EVP_PKEY_get_raw_public_key(k, raw, &rl);
    pub = EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, raw, rl);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL);
    r = EVP_PKEY_encapsulate_init(c, ikme(e, 32));
    cl2 = sizeof(ct2);
    sl2 = sizeof(ss2);
    r = r * 10 + EVP_PKEY_encapsulate(c, ct2, &cl2, ss2, &sl2);
    printf("  public key %d same %d", r, memcmp(ct, ct2, clen) == 0);
    printf(" decap init %d\n", EVP_PKEY_decapsulate_init(c, NULL));
    errors();
    EVP_PKEY_CTX_free(c);

    /* A key without key material. */
    c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY_paramgen_init(c);
    EVP_PKEY_paramgen(c, &empty);
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, empty, NULL);
    printf("  empty key encap init %d", EVP_PKEY_encapsulate_init(c, NULL));
    printf(" decap init %d\n", EVP_PKEY_decapsulate_init(c, NULL));
    errors();
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(empty);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(k);
}

int main(void)
{
    static const char *const variants[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
    size_t i;

    for (i = 0; i < 3; i++) {
        printf("# %s\n", variants[i]);
        test_kem(variants[i]);
        test_ops(variants[i]);
    }
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
