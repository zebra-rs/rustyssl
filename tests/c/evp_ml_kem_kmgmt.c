/*
 * Conformance test for the default provider's ML-KEM-512, ML-KEM-768, and ML-KEM-1024 key
 * managers (EVP_PKEY-ML-KEM(7), provider-keymgmt(7)), in TAP format: their names and parameter
 * lists; keys generated from a seed (their sizes, strengths, raw keys, seed, and every
 * gettable parameter, into room too small too); keys from data (a seed, an expanded private
 * key, a public key, each combination, mismatched, of the wrong length, with a coefficient of
 * q, with a wrong public key hash, and a private key whose halves don't belong together); raw
 * keys; exports by selection; an encoded public key given to an empty key; the checks;
 * comparisons and copies; seeds of the wrong length; properties without SHA-3; and the
 * provider's ml-kem.* configuration (retain_seed, prefer_seed, import_pct_type).
 *
 * Keys come from fixed seeds, so their encodings are the same every run; they're printed as
 * SHA-256 digests. Random keys print only what they have.
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

static const char *const VARIANTS[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };

static void fill(unsigned char *p, size_t n, unsigned char start)
{
    size_t i;

    for (i = 0; i < n; i++)
        p[i] = (unsigned char)(start + i);
}

/* A key generated in |libctx| from a seed starting at |start|. */
static EVP_PKEY *from_seed(OSSL_LIB_CTX *libctx, const char *alg, unsigned char start)
{
    unsigned char seed[64];
    OSSL_PARAM p[2];
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(libctx, alg, NULL);
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

/* A key from |params| (selection |sel|), in |libctx|, with what fromdata returned. */
static EVP_PKEY *fromdata(OSSL_LIB_CTX *libctx, const char *alg, int sel, OSSL_PARAM *params,
                          int *r)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(libctx, alg, NULL);
    EVP_PKEY *k = NULL;

    *r = EVP_PKEY_fromdata_init(c);
    *r = *r * 10 + EVP_PKEY_fromdata(c, &k, sel, params);
    EVP_PKEY_CTX_free(c);
    return k;
}

/* What the key has, as the octet-string parameters it gives. */
static void parts(const char *label, EVP_PKEY *k)
{
    unsigned char buf[4000];
    size_t n;

    printf("  %s:", label);
    if (k == NULL) {
        printf(" (no key)\n");
        return;
    }
    n = 0;
    printf(" seed %d", EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_ML_KEM_SEED, buf,
                                                       sizeof(buf), &n));
    printf(" %zu", n);
    n = 0;
    printf(" priv %d", EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PRIV_KEY, buf,
                                                       sizeof(buf), &n));
    printf(" %zu", n);
    n = 0;
    printf(" pub %d", EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY, buf,
                                                      sizeof(buf), &n));
    printf(" %zu\n", n);
}

static void test_keymgmt(const char *alg)
{
    EVP_KEYMGMT *km = EVP_KEYMGMT_fetch(NULL, alg, NULL);

    check(km != NULL, alg);
    if (km == NULL)
        return;
    printf("  names:");
    EVP_KEYMGMT_names_do_all(km, print_name, NULL);
    printf("\n  description: %s\n", EVP_KEYMGMT_get0_description(km));
    names("gettable", EVP_KEYMGMT_gettable_params(km));
    names("settable", EVP_KEYMGMT_settable_params(km));
    names("gen settable", EVP_KEYMGMT_gen_settable_params(km));
    EVP_KEYMGMT_free(km);
}

static void test_generated(const char *alg)
{
    EVP_PKEY *k = from_seed(NULL, alg, 0), *r = NULL;
    unsigned char buf[4000], *enc = NULL;
    size_t n, en;
    int bits = 0, sec = 0, max = 0;

    check(k != NULL, "a key from a seed");
    errors();
    if (k == NULL)
        return;
    printf("  id %d type %s is_a %d %d bits %d security %d size %d\n", EVP_PKEY_get_id(k),
           EVP_PKEY_get0_type_name(k), EVP_PKEY_is_a(k, alg), EVP_PKEY_is_a(k, "X25519"),
           EVP_PKEY_get_bits(k), EVP_PKEY_get_security_bits(k), EVP_PKEY_get_size(k));
    printf("  ints %d", EVP_PKEY_get_int_param(k, OSSL_PKEY_PARAM_BITS, &bits));
    printf(" %d", EVP_PKEY_get_int_param(k, OSSL_PKEY_PARAM_SECURITY_BITS, &sec));
    printf(" %d %d %d %d\n", EVP_PKEY_get_int_param(k, OSSL_PKEY_PARAM_MAX_SIZE, &max), bits,
           sec, max);
    parts("parts", k);
    n = sizeof(buf);
    printf("  raw private %d", EVP_PKEY_get_raw_private_key(k, buf, &n));
    digest("priv", buf, n);
    n = sizeof(buf);
    EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_ML_KEM_SEED, buf, sizeof(buf), &n);
    digest("seed", buf, n);
    en = EVP_PKEY_get1_encoded_public_key(k, &enc);
    digest("encoded", enc, en);
    OPENSSL_free(enc);
    n = 0;
    printf("  into too little: pub %d",
           EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY, buf, 10, &n));
    printf(" priv %d", EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PRIV_KEY, buf, 10, &n));
    printf(" seed %d", EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_ML_KEM_SEED, buf, 63,
                                                       &n));
    printf(" as int %d\n", EVP_PKEY_get_int_param(k, OSSL_PKEY_PARAM_PUB_KEY, &bits));
    errors();
    {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);

        printf("  checks %d %d %d %d\n", EVP_PKEY_check(c), EVP_PKEY_public_check(c),
               EVP_PKEY_private_check(c), EVP_PKEY_pairwise_check(c));
        EVP_PKEY_CTX_free(c);
    }
    errors();

    /* The same seed again, another seed, and a random key. */
    r = from_seed(NULL, alg, 0);
    printf("  same seed eq %d", EVP_PKEY_eq(k, r));
    EVP_PKEY_free(r);
    r = from_seed(NULL, alg, 1);
    printf(" another eq %d", EVP_PKEY_eq(k, r));
    EVP_PKEY_free(r);
    r = EVP_PKEY_Q_keygen(NULL, NULL, alg);
    printf(" random eq %d\n", EVP_PKEY_eq(k, r));
    parts("random", r);
    EVP_PKEY_free(r);
    errors();
    EVP_PKEY_free(k);
}

static EVP_PKEY *import(const char *alg, int sel, const unsigned char *seed, size_t seedlen,
                        const unsigned char *priv, size_t privlen, const unsigned char *pub,
                        size_t publen, const char *what)
{
    OSSL_PARAM p[4];
    int i = 0, r;
    EVP_PKEY *k;

    if (seed != NULL)
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, (void *)seed,
                                                   seedlen);
    if (priv != NULL)
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)priv,
                                                   privlen);
    if (pub != NULL)
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pub,
                                                   publen);
    p[i] = OSSL_PARAM_construct_end();
    k = fromdata(NULL, alg, sel, p, &r);
    printf("  %s: %d\n", what, r);
    parts("  has", k);
    errors();
    return k;
}

static void test_fromdata(const char *alg)
{
    EVP_PKEY *k = from_seed(NULL, alg, 0), *k2 = from_seed(NULL, alg, 100), *x;
    unsigned char seed[64], priv[4000], pub[2000], priv2[4000], pub2[2000], bad[4000];
    size_t privlen = sizeof(priv), publen = sizeof(pub), n2 = sizeof(priv2), p2 = sizeof(pub2);
    size_t off;

    check(k != NULL && k2 != NULL, "keys to import");
    if (k == NULL || k2 == NULL)
        goto end;
    fill(seed, sizeof(seed), 0);
    EVP_PKEY_get_raw_private_key(k, priv, &privlen);
    EVP_PKEY_get_raw_public_key(k, pub, &publen);
    EVP_PKEY_get_raw_private_key(k2, priv2, &n2);
    EVP_PKEY_get_raw_public_key(k2, pub2, &p2);
    off = privlen - 64 - publen;

    x = import(alg, EVP_PKEY_KEYPAIR, seed, 64, NULL, 0, NULL, 0, "seed");
    printf("  eq %d\n", EVP_PKEY_eq(x, k));
    EVP_PKEY_free(x);
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, priv, privlen, NULL, 0, "private"));
    x = import(alg, EVP_PKEY_PUBLIC_KEY, NULL, 0, NULL, 0, pub, publen, "public");
    printf("  eq %d\n", EVP_PKEY_eq(x, k));
    EVP_PKEY_free(x);
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, seed, 64, priv, privlen, pub, publen, "all"));
    EVP_PKEY_free(import(alg, EVP_PKEY_PUBLIC_KEY, seed, 64, priv, privlen, NULL, 0,
                         "private parts, public selected"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEY_PARAMETERS, seed, 64, NULL, 0, NULL, 0,
                         "parameters selected"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, NULL, 0, NULL, 0, "nothing"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, seed, 0, NULL, 0, NULL, 0, "an empty seed"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, seed, 63, NULL, 0, NULL, 0, "a short seed"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, priv, privlen - 1, NULL, 0,
                         "a short private key"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, NULL, 0, pub, publen + 1,
                         "a long public key"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, priv, privlen, pub2, publen,
                         "another's public key"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, seed, 64, priv2, privlen, NULL, 0,
                         "another's private key"));
    /* The other key's private key with this one's z: the implicit rejection secrets match. */
    memcpy(bad, priv2, privlen);
    memcpy(bad + privlen - 32, priv + privlen - 32, 32);
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, seed, 64, bad, privlen, NULL, 0,
                         "another's private key with this z"));

    /* A coefficient of q (0xd01) first in t, then in s. */
    memcpy(bad, pub, publen);
    bad[0] = 0x01;
    bad[1] = (unsigned char)((bad[1] & 0xf0) | 0x0d);
    EVP_PKEY_free(import(alg, EVP_PKEY_PUBLIC_KEY, NULL, 0, NULL, 0, bad, publen, "t of q"));
    memcpy(bad, priv, privlen);
    bad[0] = 0x01;
    bad[1] = (unsigned char)((bad[1] & 0xf0) | 0x0d);
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, bad, privlen, NULL, 0, "s of q"));
    memcpy(bad, priv, privlen);
    bad[off] = 0x01;
    bad[off + 1] = (unsigned char)((bad[off + 1] & 0xf0) | 0x0d);
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, bad, privlen, NULL, 0,
                         "t of q in a private key"));
    memcpy(bad, priv, privlen);
    bad[privlen - 40] ^= 1;
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, bad, privlen, NULL, 0,
                         "a wrong public key hash"));
    /* This key's s with the other key's public key and hash: the pairwise test fails. */
    memcpy(bad, priv, privlen);
    memcpy(bad + off, priv2 + off, publen + 32);
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, bad, privlen, NULL, 0,
                         "halves of two keys"));

    /* Raw keys. */
    x = EVP_PKEY_new_raw_private_key_ex(NULL, alg, NULL, priv, privlen);
    printf("  raw private %d eq %d", x != NULL, EVP_PKEY_eq(x, k));
    EVP_PKEY_free(x);
    x = EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, pub, publen);
    printf(" raw public %d eq %d", x != NULL, EVP_PKEY_eq(x, k));
    EVP_PKEY_free(x);
    x = EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, pub, publen - 1);
    printf(" short %d\n", x != NULL);
    EVP_PKEY_free(x);
    errors();
end:
    EVP_PKEY_free(k);
    EVP_PKEY_free(k2);
}

static void print_params(const char *label, OSSL_PARAM *p)
{
    printf("  %s:", label);
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%zu", p->key, p->data_size);
    printf("\n");
}

static void test_export(const char *alg)
{
    EVP_PKEY *k = from_seed(NULL, alg, 0), *pubk, *d, *e = NULL;
    static const int sels[] = { EVP_PKEY_KEYPAIR, EVP_PKEY_PUBLIC_KEY, EVP_PKEY_PRIVATE_KEY,
                                EVP_PKEY_KEY_PARAMETERS };
    unsigned char pub[2000], *enc = NULL;
    size_t publen = sizeof(pub), i, en;
    OSSL_PARAM *p;
    EVP_PKEY_CTX *c;

    check(k != NULL, "a key to export");
    if (k == NULL)
        return;
    for (i = 0; i < 4; i++) {
        p = NULL;
        printf("  todata %zu: %d", i, EVP_PKEY_todata(k, sels[i], &p));
        print_params("", p);
        OSSL_PARAM_free(p);
    }
    errors();
    EVP_PKEY_get_raw_public_key(k, pub, &publen);
    pubk = EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, pub, publen);
    for (i = 0; i < 3; i++) {
        p = NULL;
        printf("  public todata %zu: %d", i, EVP_PKEY_todata(pubk, sels[i], &p));
        print_params("", p);
        OSSL_PARAM_free(p);
    }
    errors();

    /* Copies. */
    d = EVP_PKEY_dup(k);
    printf("  dup eq %d", EVP_PKEY_eq(d, k));
    parts("dup", d);
    EVP_PKEY_free(d);
    printf("  public eq private %d cmp %d\n", EVP_PKEY_eq(pubk, k),
           EVP_PKEY_parameters_eq(pubk, k));
    errors();

    /* An empty key (parameter generation) given an encoded public key, once. */
    c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    printf("  paramgen %d", EVP_PKEY_paramgen_init(c));
    printf(" %d\n", EVP_PKEY_paramgen(c, &e));
    EVP_PKEY_CTX_free(c);
    parts("empty", e);
    printf("  empty bits %d security %d size %d eq %d\n", EVP_PKEY_get_bits(e),
           EVP_PKEY_get_security_bits(e), EVP_PKEY_get_size(e), EVP_PKEY_eq(e, k));
    errors();
    p = NULL;
    printf("  empty todata %d\n", EVP_PKEY_todata(e, EVP_PKEY_KEYPAIR, &p));
    OSSL_PARAM_free(p);
    errors();
    printf("  set short %d", EVP_PKEY_set1_encoded_public_key(e, pub, publen - 1));
    printf(" set %d eq %d", EVP_PKEY_set1_encoded_public_key(e, pub, publen), EVP_PKEY_eq(e, k));
    printf(" again %d\n", EVP_PKEY_set1_encoded_public_key(e, pub, publen));
    errors();
    en = EVP_PKEY_get1_encoded_public_key(e, &enc);
    printf("  encoded %zu same %d\n", en, en == publen && memcmp(enc, pub, en) == 0);
    OPENSSL_free(enc);
    printf("  on a full key %d\n", EVP_PKEY_set1_encoded_public_key(k, pub, publen));
    errors();
    c = EVP_PKEY_CTX_new_from_pkey(NULL, pubk, NULL);
    printf("  public key checks %d %d %d %d\n", EVP_PKEY_check(c), EVP_PKEY_public_check(c),
           EVP_PKEY_private_check(c), EVP_PKEY_pairwise_check(c));
    EVP_PKEY_CTX_free(c);
    errors();
    EVP_PKEY_free(e);
    EVP_PKEY_free(pubk);
    EVP_PKEY_free(k);
}

static void test_gen_params(const char *alg)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    unsigned char seed[65];
    OSSL_PARAM p[2];
    EVP_PKEY *k = NULL;
    int r;

    fill(seed, sizeof(seed), 0);
    r = EVP_PKEY_keygen_init(c);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, seed, 65);
    p[1] = OSSL_PARAM_construct_end();
    r = r * 10 + EVP_PKEY_CTX_set_params(c, p);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, seed, 32);
    r = r * 10 + EVP_PKEY_CTX_set_params(c, p);
    printf("  seeds of 65 and 32: %d\n", r);
    errors();
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, "provider=none", 0);
    r = EVP_PKEY_CTX_set_params(c, p);
    r = r * 10 + EVP_PKEY_generate(c, &k);
    printf("  properties without SHA-3: %d %d\n", r, k != NULL);
    errors();
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
}

static void test_conf(void)
{
    OSSL_LIB_CTX *lc = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(lc, "default");
    EVP_PKEY *k, *k2, *x;
    unsigned char seed[64], priv[4000], priv2[4000], pub[2000], pub2[2000];
    size_t privlen = sizeof(priv), n2 = sizeof(priv2), publen = sizeof(pub), p2 = sizeof(pub2);
    size_t off;
    OSSL_PARAM p[3];
    int r;

    check(lc != NULL && prov != NULL, "a library context of its own");
    k = from_seed(lc, "ML-KEM-768", 0);
    k2 = from_seed(lc, "ML-KEM-768", 100);
    parts("defaults", k);
    EVP_PKEY_get_raw_private_key(k, priv, &privlen);
    EVP_PKEY_get_raw_private_key(k2, priv2, &n2);
    EVP_PKEY_get_raw_public_key(k, pub, &publen);
    EVP_PKEY_get_raw_public_key(k2, pub2, &p2);
    off = privlen - 64 - publen;
    fill(seed, sizeof(seed), 0);

    printf("  retain_seed no %d\n",
           OSSL_PROVIDER_add_conf_parameter(prov, "ml-kem.retain_seed", "no"));
    x = from_seed(lc, "ML-KEM-768", 0);
    parts("generated", x);
    EVP_PKEY_free(x);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, seed, 64);
    p[1] = OSSL_PARAM_construct_end();
    x = fromdata(lc, "ML-KEM-768", EVP_PKEY_KEYPAIR, p, &r);
    printf("  imported %d", r);
    parts("", x);
    EVP_PKEY_free(x);
    errors();

    /* The other key's private key with this seed's z: the seed wins unless it's not preferred. */
    memcpy(priv2 + n2 - 32, priv + privlen - 32, 32);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, seed, 64);
    p[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, priv2, n2);
    p[2] = OSSL_PARAM_construct_end();
    x = fromdata(lc, "ML-KEM-768", EVP_PKEY_KEYPAIR, p, &r);
    printf("  preferred seed %d\n", r);
    EVP_PKEY_free(x);
    errors();
    printf("  prefer_seed off %d\n",
           OSSL_PROVIDER_add_conf_parameter(prov, "ml-kem.prefer_seed", "off"));
    x = fromdata(lc, "ML-KEM-768", EVP_PKEY_KEYPAIR, p, &r);
    printf("  unpreferred seed %d eq %d eq other %d\n", r, EVP_PKEY_eq(x, k),
           EVP_PKEY_eq(x, k2));
    EVP_PKEY_free(x);
    errors();
    printf("  prefer_seed maybe %d\n",
           OSSL_PROVIDER_add_conf_parameter(prov, "ml-kem.prefer_seed", "maybe"));
    x = fromdata(lc, "ML-KEM-768", EVP_PKEY_KEYPAIR, p, &r);
    printf("  defaulted %d\n", r);
    EVP_PKEY_free(x);
    errors();

    /* Halves of two keys: refused with a pairwise test, of either type, not without one. */
    memcpy(priv + off, pub2, p2);
    EVP_PKEY_get_raw_private_key(k2, priv2, &n2);
    memcpy(priv + off + publen, priv2 + off + publen, 32);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, priv, privlen);
    p[1] = OSSL_PARAM_construct_end();
    printf("  pct fixed %d\n",
           OSSL_PROVIDER_add_conf_parameter(prov, "ml-kem.import_pct_type", "FIXED"));
    x = fromdata(lc, "ML-KEM-768", EVP_PKEY_KEYPAIR, p, &r);
    printf("  fixed %d\n", r);
    EVP_PKEY_free(x);
    errors();
    printf("  pct none %d\n",
           OSSL_PROVIDER_add_conf_parameter(prov, "ml-kem.import_pct_type", "none"));
    x = fromdata(lc, "ML-KEM-768", EVP_PKEY_KEYPAIR, p, &r);
    printf("  none %d", r);
    if (x != NULL) {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(lc, x, NULL);

        printf(" checks %d %d %d", EVP_PKEY_check(c), EVP_PKEY_public_check(c),
               EVP_PKEY_pairwise_check(c));
        EVP_PKEY_CTX_free(c);
    }
    printf("\n");
    EVP_PKEY_free(x);
    errors();
    EVP_PKEY_free(k);
    EVP_PKEY_free(k2);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(lc);
}

int main(void)
{
    size_t i;

    for (i = 0; i < 3; i++) {
        printf("# %s\n", VARIANTS[i]);
        test_keymgmt(VARIANTS[i]);
        test_generated(VARIANTS[i]);
        test_fromdata(VARIANTS[i]);
        test_export(VARIANTS[i]);
        test_gen_params(VARIANTS[i]);
    }
    test_conf();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
