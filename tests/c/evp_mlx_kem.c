/*
 * Conformance test for the default provider's hybrid ML-KEM key managers and KEM
 * (X25519MLKEM768, X448MLKEM1024, SecP256r1MLKEM768, SecP384r1MLKEM1024; provider-keymgmt(7),
 * provider-kem(7)), in TAP format: their names and parameter lists; generated keys (sizes,
 * strengths, the encoded public key and private key, into room too small too); exports by
 * selection and imports of each part, of the wrong length, and of nothing; an encoded public key
 * set on a key made empty by parameter generation, and set again; comparisons and copies;
 * encapsulations and decapsulations (size queries, rooms too small, missing buffers, ciphertexts
 * changed and of other lengths, public keys); and properties without the components.
 *
 * Keys and secrets are random, so only lengths, results, and comparisons are printed.
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

static const char *const HYBRIDS[] = { "X25519MLKEM768", "X448MLKEM1024", "SecP256r1MLKEM768",
                                       "SecP384r1MLKEM1024" };

static unsigned char ct[4000], ct2[4000], ss[200], ss2[200], buf[8000];

static void print_params(OSSL_PARAM *p)
{
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%zu", p->key, p->data_size);
    printf("\n");
}

static void parts(const char *label, EVP_PKEY *k)
{
    size_t n;

    printf("  %s:", label);
    if (k == NULL) {
        printf(" (no key)\n");
        return;
    }
    n = 0;
    printf(" encoded %d", EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                                          buf, sizeof(buf), &n));
    printf(" %zu", n);
    n = 0;
    printf(" priv %d", EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PRIV_KEY, buf,
                                                       sizeof(buf), &n));
    printf(" %zu\n", n);
}

static void test_names(const char *alg)
{
    EVP_KEYMGMT *km = EVP_KEYMGMT_fetch(NULL, alg, NULL);
    EVP_KEM *kem = EVP_KEM_fetch(NULL, alg, NULL);

    check(km != NULL && kem != NULL, alg);
    if (km != NULL) {
        printf("  names:");
        EVP_KEYMGMT_names_do_all(km, print_name, NULL);
        printf("\n  description: %s\n", EVP_KEYMGMT_get0_description(km));
        names("gettable", EVP_KEYMGMT_gettable_params(km));
        names("settable", EVP_KEYMGMT_settable_params(km));
        names("gen settable", EVP_KEYMGMT_gen_settable_params(km));
    }
    if (kem != NULL) {
        printf("  kem:");
        EVP_KEM_names_do_all(kem, print_name, NULL);
        printf("\n  kem description: %s\n", EVP_KEM_get0_description(kem) == NULL ? "(null)"
                                                                           : EVP_KEM_get0_description(kem));
        names("kem settable", EVP_KEM_settable_ctx_params(kem));
    }
    EVP_KEYMGMT_free(km);
    EVP_KEM_free(kem);
    errors();
}

/* An encapsulation to |k| and its decapsulation with |d|: the results, lengths, and match. */
static void round_trip(const char *label, EVP_PKEY *k, EVP_PKEY *d)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    EVP_PKEY_CTX *e = EVP_PKEY_CTX_new_from_pkey(NULL, d, NULL);
    size_t cl = sizeof(ct), sl = sizeof(ss), s2 = sizeof(ss2);
    int r, r2;

    r = EVP_PKEY_encapsulate_init(c, NULL);
    r = r * 10 + EVP_PKEY_encapsulate(c, ct, &cl, ss, &sl);
    r2 = EVP_PKEY_decapsulate_init(e, NULL);
    r2 = r2 * 10 + EVP_PKEY_decapsulate(e, ss2, &s2, ct, cl);
    printf("  %s: encap %d %zu %zu decap %d %zu same %d\n", label, r, cl, sl, r2, s2,
           sl == s2 && memcmp(ss, ss2, sl) == 0);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_CTX_free(e);
}

static EVP_PKEY *import(const char *alg, int sel, const unsigned char *priv, size_t privlen,
                        const unsigned char *pub, size_t publen, const char *what)
{
    OSSL_PARAM p[3];
    int i = 0, r;
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);

    if (priv != NULL)
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)priv,
                                                   privlen);
    if (pub != NULL)
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pub,
                                                   publen);
    p[i] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_fromdata_init(c);
    r = r * 10 + EVP_PKEY_fromdata(c, &k, sel, p);
    EVP_PKEY_CTX_free(c);
    printf("  %s: %d\n", what, r);
    parts("  has", k);
    errors();
    return k;
}

static void test_keys(const char *alg)
{
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, alg), *k2 = EVP_PKEY_Q_keygen(NULL, NULL, alg);
    EVP_PKEY *x, *e = NULL;
    static unsigned char pub[3000], priv[4000];
    size_t publen = 0, privlen = 0, n;
    static const int sels[] = { EVP_PKEY_KEYPAIR, EVP_PKEY_PUBLIC_KEY, EVP_PKEY_PRIVATE_KEY,
                                EVP_PKEY_KEY_PARAMETERS };
    OSSL_PARAM *p;
    EVP_PKEY_CTX *c;
    size_t i;
    int r;

    check(k != NULL && k2 != NULL, "generated keys");
    if (k == NULL || k2 == NULL)
        goto end;
    printf("  bits %d security %d size %d\n", EVP_PKEY_get_bits(k), EVP_PKEY_get_security_bits(k),
           EVP_PKEY_get_size(k));
    parts("parts", k);
    errors();
    n = 0;
    printf("  into too little: encoded %d",
           EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, buf, 10, &n));
    printf(" %zu priv %d\n", n, EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PRIV_KEY, buf,
                                                               10, &n));
    errors();
    for (i = 0; i < 4; i++) {
        p = NULL;
        printf("  todata %zu: %d", i, EVP_PKEY_todata(k, sels[i], &p));
        print_params(p);
        OSSL_PARAM_free(p);
    }
    errors();
    EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub, sizeof(pub),
                                    &publen);
    EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PRIV_KEY, priv, sizeof(priv), &privlen);
    ERR_clear_error();
    printf("  eq self %d other %d\n", EVP_PKEY_eq(k, k), EVP_PKEY_eq(k, k2));
    round_trip("generated", k, k);

    x = import(alg, EVP_PKEY_KEYPAIR, NULL, 0, pub, publen, "public");
    printf("  eq %d\n", EVP_PKEY_eq(x, k));
    round_trip("to the public key", x, k);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, x, NULL);
    printf("  decapsulate with it: %d\n", EVP_PKEY_decapsulate_init(c, NULL));
    EVP_PKEY_CTX_free(c);
    errors();
    EVP_PKEY_free(x);
    if (privlen != 0) {
        x = import(alg, EVP_PKEY_KEYPAIR, priv, privlen, NULL, 0, "private");
        printf("  eq %d\n", EVP_PKEY_eq(x, k));
        round_trip("with the private key", k, x);
        EVP_PKEY_free(x);
        EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, priv, privlen - 1, NULL, 0, "a short private key"));
        EVP_PKEY_free(import(alg, EVP_PKEY_PUBLIC_KEY, priv, privlen, NULL, 0,
                             "private, public selected"));
    }
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, pub, publen + 1, "a long public key"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEYPAIR, NULL, 0, NULL, 0, "nothing"));
    EVP_PKEY_free(import(alg, EVP_PKEY_KEY_PARAMETERS, NULL, 0, pub, publen, "parameters selected"));
    memcpy(buf, pub, publen);
    buf[publen - 1] ^= 1;
    x = import(alg, EVP_PKEY_KEYPAIR, NULL, 0, buf, publen, "the last octet changed");
    EVP_PKEY_free(x);
    memcpy(buf, pub, publen);
    buf[0] ^= 1;
    x = import(alg, EVP_PKEY_KEYPAIR, NULL, 0, buf, publen, "the first octet changed");
    EVP_PKEY_free(x);

    /* An empty key from parameter generation, then an encoded public key. */
    c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    r = EVP_PKEY_paramgen_init(c);
    r = r * 10 + EVP_PKEY_paramgen(c, &e);
    printf("  paramgen %d\n", r);
    EVP_PKEY_CTX_free(c);
    parts("empty", e);
    printf("  eq empty %d\n", EVP_PKEY_eq(e, k));
    printf("  set encoded %d\n", EVP_PKEY_set1_encoded_public_key(e, pub, publen));
    parts("set", e);
    printf("  eq %d\n", EVP_PKEY_eq(e, k));
    printf("  set again %d\n", EVP_PKEY_set1_encoded_public_key(e, pub, publen));
    errors();
    EVP_PKEY_free(e);
    e = NULL;
    c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY_paramgen_init(c);
    EVP_PKEY_paramgen(c, &e);
    EVP_PKEY_CTX_free(c);
    printf("  set short %d\n", EVP_PKEY_set1_encoded_public_key(e, pub, publen - 1));
    errors();
    EVP_PKEY_free(e);

    x = EVP_PKEY_dup(k);
    printf("  dup eq %d\n", EVP_PKEY_eq(x, k));
    round_trip("to the copy", x, k);
    EVP_PKEY_free(x);
    errors();
end:
    EVP_PKEY_free(k);
    EVP_PKEY_free(k2);
}

static void test_kem(const char *alg)
{
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, alg);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    size_t cl, sl, s2, need_c = 0, need_s = 0;
    int r;

    check(k != NULL, "the KEM");
    printf("  encap init %d", EVP_PKEY_encapsulate_init(c, NULL));
    printf(" sizes %d", EVP_PKEY_encapsulate(c, NULL, &need_c, NULL, &need_s));
    printf(" %zu %zu", need_c, need_s);
    cl = 0;
    printf(" ciphertext size only %d %zu", EVP_PKEY_encapsulate(c, NULL, &cl, NULL, NULL), cl);
    errors();
    cl = need_c - 1;
    sl = need_s;
    printf("  ciphertext room too small %d %zu", EVP_PKEY_encapsulate(c, ct, &cl, ss, &sl), cl);
    errors();
    cl = need_c;
    sl = need_s - 1;
    printf("  secret room too small %d %zu %zu", EVP_PKEY_encapsulate(c, ct, &cl, ss, &sl), cl, sl);
    errors();
    cl = need_c;
    printf("  no secret %d", EVP_PKEY_encapsulate(c, ct, &cl, NULL, &sl));
    errors();
    cl = sizeof(ct);
    sl = sizeof(ss);
    r = EVP_PKEY_encapsulate(c, ct, &cl, ss, &sl);
    printf("  encapsulate %d %zu %zu\n", r, cl, sl);

    printf("  decap init %d", EVP_PKEY_decapsulate_init(c, NULL));
    s2 = 0;
    printf(" size %d %zu", EVP_PKEY_decapsulate(c, NULL, &s2, ct, cl), s2);
    s2 = need_s - 1;
    printf(" room too small %d", EVP_PKEY_decapsulate(c, ss2, &s2, ct, cl));
    errors();
    s2 = sizeof(ss2);
    printf("  shorter %d", EVP_PKEY_decapsulate(c, ss2, &s2, ct, cl - 1));
    errors();
    s2 = sizeof(ss2);
    printf("  longer %d", EVP_PKEY_decapsulate(c, ss2, &s2, ct, cl + 1));
    errors();
    memcpy(ct2, ct, cl);
    s2 = sizeof(ss2);
    r = EVP_PKEY_decapsulate(c, ss2, &s2, ct2, cl);
    printf("  as is %d %zu same %d\n", r, s2, memcmp(ss, ss2, sl) == 0);
    ct2[strncmp(alg, "SecP", 4) == 0 ? cl - 1 : 0] ^= 1;
    s2 = sizeof(ss2);
    r = EVP_PKEY_decapsulate(c, ss2, &s2, ct2, cl);
    printf("  ML-KEM's part changed %d same %d\n", r, memcmp(ss, ss2, sl) == 0);
    memcpy(ct2, ct, cl);
    ct2[strncmp(alg, "SecP", 4) == 0 ? 0 : cl - 1] ^= 0x40;
    s2 = sizeof(ss2);
    r = EVP_PKEY_decapsulate(c, ss2, &s2, ct2, cl);
    printf("  ECDH's part changed %d same %d\n", r, r == 1 && memcmp(ss, ss2, sl) == 0);
    errors();
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(k);
}

static void test_gen(const char *alg)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    OSSL_PARAM p[2];
    EVP_PKEY *k = NULL;
    int r;

    r = EVP_PKEY_keygen_init(c);
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, "provider=none", 0);
    p[1] = OSSL_PARAM_construct_end();
    r = r * 10 + EVP_PKEY_CTX_set_params(c, p);
    r = r * 10 + EVP_PKEY_generate(c, &k);
    printf("  properties without the components: %d %d\n", r, k != NULL);
    errors();
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
}

int main(void)
{
    size_t i;

    for (i = 0; i < 4; i++) {
        printf("# %s\n", HYBRIDS[i]);
        test_names(HYBRIDS[i]);
        test_keys(HYBRIDS[i]);
        test_kem(HYBRIDS[i]);
        test_gen(HYBRIDS[i]);
    }
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
