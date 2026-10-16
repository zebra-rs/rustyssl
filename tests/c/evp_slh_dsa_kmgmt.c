/*
 * Conformance test for the default provider's twelve SLH-DSA key managers (EVP_PKEY-SLH-DSA(7),
 * provider-keymgmt(7)), in TAP format: their names and parameter lists; keys generated from
 * seeds (SK.seed || SK.prf || PK.seed: their sizes, strengths, raw keys, and every gettable
 * parameter, into room too small too) and from seeds of other lengths; keys from data (a whole
 * private key, half of one with a public key, a public key, each with the wrong length or
 * missing its other half, and a private key with another's public key or a changed root); raw
 * keys; exports by selection; comparisons, copies, and the checks; parameter generation; and
 * properties without the digests.
 *
 * Keys come from fixed seeds, so their encodings are the same every run; they're printed as
 * SHA-256 digests. Random keys print only what they have. Every parameter set's key is
 * generated; the other checks run on four of them (both families, each size, and both trees),
 * since the "s" sets' keys are slow to make.
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

static const char *const VARIANTS[] = {
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
};

/* The parameter sets every check runs on. */
static const char *const FULL[] = { "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-192f",
                                    "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-256f" };

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

/* A key generated from seeds of |len| octets starting at |start|. */
static EVP_PKEY *from_seed_len(const char *alg, unsigned char start, size_t len)
{
    unsigned char seed[100];
    OSSL_PARAM p[2];
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *k = NULL;
    int r;

    fill(seed, sizeof(seed), start);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_SLH_DSA_SEED, seed, len);
    p[1] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_keygen_init(c);
    r = r * 10 + EVP_PKEY_CTX_set_params(c, p);
    r = r * 10 + EVP_PKEY_generate(c, &k);
    if (len != 3 * n_of(alg))
        printf("  seeds of %zu: %d\n", len, r);
    EVP_PKEY_CTX_free(c);
    return k;
}

static EVP_PKEY *from_seed(const char *alg, unsigned char start)
{
    return from_seed_len(alg, start, 3 * n_of(alg));
}

static EVP_PKEY *fromdata(const char *alg, int sel, OSSL_PARAM *params, int *r)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *k = NULL;

    *r = EVP_PKEY_fromdata_init(c);
    *r = *r * 10 + EVP_PKEY_fromdata(c, &k, sel, params);
    EVP_PKEY_CTX_free(c);
    return k;
}

static void parts(const char *label, EVP_PKEY *k)
{
    unsigned char buf[200];
    size_t n;

    printf("  %s:", label);
    if (k == NULL) {
        printf(" (no key)\n");
        return;
    }
    n = 0;
    printf(" priv %d", EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PRIV_KEY, buf,
                                                       sizeof(buf), &n));
    printf(" %zu", n);
    n = 0;
    printf(" pub %d", EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY, buf,
                                                      sizeof(buf), &n));
    printf(" %zu", n);
    if (n > 0)
        digest("", buf, n);
    else
        printf("\n");
}

static void checks(EVP_PKEY *k)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);

    printf("  checks %d %d %d %d\n", EVP_PKEY_check(c), EVP_PKEY_public_check(c),
           EVP_PKEY_private_check(c), EVP_PKEY_pairwise_check(c));
    EVP_PKEY_CTX_free(c);
}

static void test_keymgmt(const char *alg)
{
    EVP_KEYMGMT *km = EVP_KEYMGMT_fetch(NULL, alg, NULL);
    EVP_PKEY *k;
    unsigned char buf[200];
    size_t n = sizeof(buf);

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
    k = from_seed(alg, 0);
    printf("  bits %d security %d size %d\n", EVP_PKEY_get_bits(k), EVP_PKEY_get_security_bits(k),
           EVP_PKEY_get_size(k));
    printf("  raw private %d", EVP_PKEY_get_raw_private_key(k, buf, &n));
    digest("priv", buf, n);
    EVP_PKEY_free(k);
    errors();
}

static void test_generated(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 0), *r = NULL;
    unsigned char buf[200];
    size_t n, len = 3 * n_of(alg);
    int bits = 0, sec = 0, max = 0;
    char md[50] = "?";

    check(k != NULL, "a key from seeds");
    errors();
    if (k == NULL)
        return;
    printf("  id %d type %s is_a %d\n", EVP_PKEY_get_id(k), EVP_PKEY_get0_type_name(k),
           EVP_PKEY_is_a(k, alg));
    printf("  ints %d", EVP_PKEY_get_int_param(k, OSSL_PKEY_PARAM_BITS, &bits));
    printf(" %d", EVP_PKEY_get_int_param(k, OSSL_PKEY_PARAM_SECURITY_BITS, &sec));
    printf(" %d %d %d %d", EVP_PKEY_get_int_param(k, OSSL_PKEY_PARAM_MAX_SIZE, &max), bits,
           sec, max);
    printf(" digest %d [%s]\n",
           EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_MANDATORY_DIGEST, md, sizeof(md),
                                          NULL),
           md);
    printf("  default digest %d", EVP_PKEY_get_default_digest_name(k, md, sizeof(md)));
    printf(" [%s]\n", md);
    parts("parts", k);
    n = sizeof(buf);
    printf("  raw public %d", EVP_PKEY_get_raw_public_key(k, buf, &n));
    digest("pub", buf, n);
    n = 0;
    printf("  into too little: pub %d",
           EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY, buf, 10, &n));
    printf(" priv %d", EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PRIV_KEY, buf, 10, &n));
    printf(" as int %d\n", EVP_PKEY_get_int_param(k, OSSL_PKEY_PARAM_PUB_KEY, &bits));
    errors();
    checks(k);
    errors();
    r = from_seed(alg, 0);
    printf("  same seeds eq %d", EVP_PKEY_eq(k, r));
    EVP_PKEY_free(r);
    r = from_seed(alg, 1);
    printf(" others eq %d", EVP_PKEY_eq(k, r));
    EVP_PKEY_free(r);
    r = EVP_PKEY_Q_keygen(NULL, NULL, alg);
    printf(" random eq %d\n", EVP_PKEY_eq(k, r));
    printf("  random:");
    n = 0;
    printf(" priv %d %zu", EVP_PKEY_get_octet_string_param(r, OSSL_PKEY_PARAM_PRIV_KEY, buf,
                                                          sizeof(buf), &n), n);
    checks(r);
    EVP_PKEY_free(r);
    errors();
    EVP_PKEY_free(from_seed_len(alg, 0, len - 1));
    errors();
    EVP_PKEY_free(from_seed_len(alg, 0, len + 1));
    errors();
    EVP_PKEY_free(from_seed_len(alg, 0, 96));
    errors();
    EVP_PKEY_free(from_seed_len(alg, 0, 97));
    errors();
    r = from_seed_len(alg, 0, 0);
    printf("  empty seeds:");
    n = 0;
    printf(" priv %d %zu\n", EVP_PKEY_get_octet_string_param(r, OSSL_PKEY_PARAM_PRIV_KEY, buf,
                                                            sizeof(buf), &n), n);
    EVP_PKEY_free(r);
    errors();
    EVP_PKEY_free(k);
}

static EVP_PKEY *import(const char *alg, int sel, const unsigned char *priv, size_t privlen,
                        const unsigned char *pub, size_t publen, const char *what)
{
    OSSL_PARAM p[3];
    int i = 0, r;
    EVP_PKEY *k;

    if (priv != NULL)
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)priv,
                                                   privlen);
    if (pub != NULL)
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pub,
                                                   publen);
    p[i] = OSSL_PARAM_construct_end();
    k = fromdata(alg, sel, p, &r);
    printf("  %s: %d\n", what, r);
    parts("  has", k);
    errors();
    return k;
}

static void test_fromdata(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 0), *k2 = from_seed(alg, 100), *x;
    unsigned char priv[200], pub[100], priv2[200], pub2[100], bad[200];
    size_t privlen = sizeof(priv), publen = sizeof(pub), n2 = sizeof(priv2), p2 = sizeof(pub2);
    size_t n = n_of(alg);

    check(k != NULL && k2 != NULL, "keys to import");
    if (k == NULL || k2 == NULL)
        goto end;
    EVP_PKEY_get_raw_private_key(k, priv, &privlen);
    EVP_PKEY_get_raw_public_key(k, pub, &publen);
    EVP_PKEY_get_raw_private_key(k2, priv2, &n2);
    EVP_PKEY_get_raw_public_key(k2, pub2, &p2);

    x = import(alg, EVP_PKEY_KEYPAIR, priv, privlen, NULL, 0, "private");
    printf("  eq %d\n", EVP_PKEY_eq(x, k));
    checks(x);
    EVP_PKEY_free(x);
    errors();
    x = import(alg, EVP_PKEY_KEYPAIR, priv, 2 * n, pub, publen, "half a private key, public");
    printf("  eq %d\n", EVP_PKEY_eq(x, k));
    checks(x);
    EVP_PKEY_free(x);
    errors();
    x = import(alg, EVP_PKEY_PUBLIC_KEY, NULL, 0, pub, publen, "public");
    printf("  eq %d\n", EVP_PKEY_eq(x, k));
    checks(x);
    EVP_PKEY_free(x);
    errors();
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, priv, privlen, pub2, publen,
                         "private, another's public"));
    x = import(alg, EVP_PKEY_KEYPAIR, priv, 2 * n, pub2, publen,
               "half a private key, another's public");
    checks(x);
    EVP_PKEY_free(x);
    errors();
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, priv, 2 * n, NULL, 0, "half a private key"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, priv, 3 * n, NULL, 0, "three quarters"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, priv, privlen + 1, NULL, 0, "a long private key"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, priv, 0, pub, publen, "an empty private key"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, priv, 2 * n, pub, publen - 1,
                         "half a private key, a short public"));
    EVP_PKEY_free(import(alg, EVP_PKEY_PUBLIC_KEY, priv, privlen, NULL, 0,
                         "private, public selected"));
    EVP_PKEY_free(import(alg, EVP_PKEY_PUBLIC_KEY, priv, privlen, pub, publen,
                         "both, public selected"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEY_PARAMETERS, priv, privlen, pub, publen,
                         "parameters selected"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, NULL, 0, "nothing"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, pub, 0, "an empty public key"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, pub, publen + 1, "a long public key"));
    memcpy(bad, priv, privlen);
    bad[privlen - 1] ^= 1;
    x = import(alg, EVP_PKEY_KEYPAIR, bad, privlen, NULL, 0, "root changed");
    printf("  eq %d\n", EVP_PKEY_eq(x, k));
    checks(x);
    EVP_PKEY_free(x);
    errors();
    memcpy(bad, priv, privlen);
    bad[0] ^= 1;
    x = import(alg, EVP_PKEY_KEYPAIR, bad, privlen, NULL, 0, "SK.seed changed");
    printf("  eq %d\n", EVP_PKEY_eq(x, k));
    checks(x);
    EVP_PKEY_free(x);
    errors();

    x = EVP_PKEY_new_raw_private_key_ex(NULL, alg, NULL, priv, privlen);
    printf("  raw private %d eq %d", x != NULL, EVP_PKEY_eq(x, k));
    EVP_PKEY_free(x);
    x = EVP_PKEY_new_raw_private_key_ex(NULL, alg, NULL, priv, 2 * n);
    printf(" half %d", x != NULL);
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

static void print_params(OSSL_PARAM *p)
{
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%zu", p->key, p->data_size);
    printf("\n");
}

static void test_export(const char *alg)
{
    EVP_PKEY *k = from_seed(alg, 0), *pubk, *d, *e = NULL;
    static const int sels[] = { EVP_PKEY_KEYPAIR, EVP_PKEY_PUBLIC_KEY, EVP_PKEY_PRIVATE_KEY,
                                EVP_PKEY_KEY_PARAMETERS };
    unsigned char pub[100];
    size_t publen = sizeof(pub), i;
    OSSL_PARAM *p;
    EVP_PKEY_CTX *c;

    check(k != NULL, "a key to export");
    if (k == NULL)
        return;
    for (i = 0; i < 4; i++) {
        p = NULL;
        printf("  todata %zu: %d", i, EVP_PKEY_todata(k, sels[i], &p));
        print_params(p);
        OSSL_PARAM_free(p);
    }
    errors();
    EVP_PKEY_get_raw_public_key(k, pub, &publen);
    pubk = EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, pub, publen);
    for (i = 0; i < 3; i++) {
        p = NULL;
        printf("  public todata %zu: %d", i, EVP_PKEY_todata(pubk, sels[i], &p));
        print_params(p);
        OSSL_PARAM_free(p);
    }
    errors();
    d = EVP_PKEY_dup(k);
    printf("  dup eq %d", EVP_PKEY_eq(d, k));
    parts("dup", d);
    EVP_PKEY_free(d);
    d = EVP_PKEY_dup(pubk);
    printf("  public dup eq %d", EVP_PKEY_eq(d, k));
    parts("dup", d);
    EVP_PKEY_free(d);
    printf("  public eq private %d %d parameters %d\n", EVP_PKEY_eq(pubk, k),
           EVP_PKEY_eq(k, pubk), EVP_PKEY_parameters_eq(pubk, k));
    errors();
    d = from_seed(strcmp(alg, FULL[0]) == 0 ? FULL[1] : FULL[0], 0);
    printf("  another set eq %d\n", EVP_PKEY_eq(k, d));
    EVP_PKEY_free(d);
    errors();
    printf("  set encoded %d\n", EVP_PKEY_set1_encoded_public_key(k, pub, publen));
    errors();

    c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    printf("  paramgen %d", EVP_PKEY_paramgen_init(c));
    printf(" %d\n", EVP_PKEY_paramgen(c, &e));
    EVP_PKEY_CTX_free(c);
    printf("  paramgen key %d\n", e != NULL);
    errors();
    EVP_PKEY_free(e);
    EVP_PKEY_free(pubk);
    EVP_PKEY_free(k);
}

static void test_gen_params(const char *alg)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    OSSL_PARAM p[2];
    EVP_PKEY *k = NULL;
    int r, i = 7;

    r = EVP_PKEY_keygen_init(c);
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, "provider=none", 0);
    p[1] = OSSL_PARAM_construct_end();
    r = r * 10 + EVP_PKEY_CTX_set_params(c, p);
    r = r * 10 + EVP_PKEY_generate(c, &k);
    printf("  properties without the digests: %d %d\n", r, k != NULL);
    errors();
    EVP_PKEY_free(k);
    p[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_PROPERTIES, &i);
    printf("  properties as an integer: %d\n", EVP_PKEY_CTX_set_params(c, p));
    errors();
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new_from_name(NULL, alg, "provider=none");
    printf("  a context without the digests: %d\n", c != NULL);
    EVP_PKEY_CTX_free(c);
    errors();
}

int main(void)
{
    size_t i;

    for (i = 0; i < 12; i++) {
        printf("# %s\n", VARIANTS[i]);
        test_keymgmt(VARIANTS[i]);
    }
    for (i = 0; i < 4; i++) {
        printf("# %s\n", FULL[i]);
        test_generated(FULL[i]);
        test_fromdata(FULL[i]);
        test_export(FULL[i]);
        test_gen_params(FULL[i]);
    }
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
