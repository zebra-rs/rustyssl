/*
 * Conformance test for EC keys in EVP_PKEY (EVP_PKEY_set1_EC_KEY(3), EVP_PKEY_assign(3),
 * EVP_PKEY_get0_EC_KEY, EVP_PKEY_get1_EC_KEY), in TAP format: an EC_KEY given to a key (its type,
 * SM2's type for SM2's curve whatever is asked, sizes and security bits, default digests, the
 * EC_KEY back, the same object), printed (public, private, parameters), compared and its
 * parameters compared, copied, missing and copied into a key without them, its encoded public
 * key both ways, and its parameters through the legacy payload table; keys of other types.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
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

static void hex(const char *label, const unsigned char *p, size_t len)
{
    size_t i;

    printf("  %s (%zu):", label, len);
    for (i = 0; i < len; i++)
        printf("%s%02x", i % 40 == 0 && i > 0 ? "\n    " : "", p[i]);
    printf("\n");
}

static void show(BIO *mem)
{
    char *text;
    long n = BIO_get_mem_data(mem, &text);

    printf("%.*s", (int)n, text);
    (void)BIO_reset(mem);
}

static EC_KEY *fixed_key(int nid, const char *priv_hex)
{
    EC_KEY *k = EC_KEY_new_by_curve_name(nid);
    BIGNUM *priv = NULL;
    EC_POINT *P = EC_POINT_new(EC_KEY_get0_group(k));

    BN_hex2bn(&priv, priv_hex);
    EC_POINT_mul(EC_KEY_get0_group(k), P, priv, NULL, NULL, NULL);
    EC_KEY_set_private_key(k, priv);
    EC_KEY_set_public_key(k, P);
    BN_free(priv);
    EC_POINT_free(P);
    return k;
}

/* The key's numbers and names through EVP_PKEY_get_params. */
static void legacy_params(EVP_PKEY *k)
{
    char group[80] = "";
    unsigned char pub[200];
    BIGNUM *priv = NULL, *x = NULL, *y = NULL;
    int decoded = -1;
    size_t publen = 0;
    OSSL_PARAM ps[2];
    char *s;

    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group));
    ps[1] = OSSL_PARAM_construct_end();
    printf("  group name: %d %s\n", EVP_PKEY_get_params(k, ps), group);
    errors();
    ps[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub));
    printf("  public key: %d", EVP_PKEY_get_params(k, ps));
    publen = ps[0].return_size;
    hex("octets", pub, publen <= sizeof(pub) ? publen : 0);
    errors();
    printf("  private key: %d", EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_PRIV_KEY, &priv));
    s = priv != NULL ? BN_bn2hex(priv) : NULL;
    printf(" %s\n", s != NULL ? s : "-");
    OPENSSL_free(s);
    errors();
    printf("  qx: %d, qy: %d\n", EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_EC_PUB_X, &x),
           EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_EC_PUB_Y, &y));
    s = x != NULL ? BN_bn2hex(x) : NULL;
    printf("  x: %s\n", s != NULL ? s : "-");
    OPENSSL_free(s);
    errors();
    printf("  decoded from explicit: %d %d\n",
           EVP_PKEY_get_int_param(k, OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, &decoded),
           decoded);
    errors();
    printf("  rsa n: %d\n", EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_RSA_N, &x));
    errors();
    ps[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_GROUP_NAME, &decoded);
    printf("  group name as an int: %d\n", EVP_PKEY_get_params(k, ps));
    errors();
    BN_free(priv);
    BN_free(x);
    BN_free(y);
}

static void test_curve(int nid, const char *priv_hex)
{
    EC_KEY *ec = fixed_key(nid, priv_hex), *got;
    EVP_PKEY *k = EVP_PKEY_new(), *d, *e;
    BIO *mem = BIO_new(BIO_s_mem());
    int md = 0;
    char mdname[80] = "";
    unsigned char *enc = NULL;
    size_t enclen;

    printf("# %s\n", OBJ_nid2sn(nid));
    check(EVP_PKEY_set1_EC_KEY(k, ec) == 1, "EVP_PKEY_set1_EC_KEY");
    printf("  id %d base %d, bits %d, size %d, security %d\n", EVP_PKEY_get_id(k),
           EVP_PKEY_get_base_id(k), EVP_PKEY_get_bits(k), EVP_PKEY_get_size(k),
           EVP_PKEY_get_security_bits(k));
    printf("  default digest: %d", EVP_PKEY_get_default_digest_nid(k, &md));
    printf(" %s", OBJ_nid2sn(md));
    printf(", name %d %s\n", EVP_PKEY_get_default_digest_name(k, mdname, sizeof(mdname)),
           mdname);
    errors();
    got = (EC_KEY *)EVP_PKEY_get0_EC_KEY(k);
    check(got == ec, "EVP_PKEY_get0_EC_KEY: the same object");
    got = EVP_PKEY_get1_EC_KEY(k);
    check(got == ec, "EVP_PKEY_get1_EC_KEY");
    EC_KEY_free(got);
    check(EVP_PKEY_missing_parameters(k) == 0, "not missing parameters");

    check(EVP_PKEY_print_public(mem, k, 2, NULL) == 1, "EVP_PKEY_print_public");
    show(mem);
    check(EVP_PKEY_print_private(mem, k, 0, NULL) == 1, "EVP_PKEY_print_private");
    show(mem);
    check(EVP_PKEY_print_params(mem, k, 4, NULL) == 1, "EVP_PKEY_print_params");
    show(mem);

    enclen = EVP_PKEY_get1_encoded_public_key(k, &enc);
    hex("encoded public key", enc, enclen);
    errors();

    d = EVP_PKEY_dup(k);
    check(d != NULL, "EVP_PKEY_dup");
    if (d != NULL) {
        check(EVP_PKEY_get0_EC_KEY(d) != ec, "with its own EC_KEY");
        printf("  eq: %d, parameters eq: %d\n", EVP_PKEY_eq(k, d), EVP_PKEY_parameters_eq(k, d));
    }
    {
        /* A key with the same group, a different private key. */
        EC_KEY *other = fixed_key(nid, "1234");

        e = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(e, other);
        printf("  another key: eq %d, parameters eq %d\n", EVP_PKEY_eq(k, e),
               EVP_PKEY_parameters_eq(k, e));
        errors();
    }
    {
        /* A key without parameters gets them. */
        EVP_PKEY *n = EVP_PKEY_new();
        EC_KEY *empty = EC_KEY_new();

        EVP_PKEY_assign_EC_KEY(n, empty);
        printf("  empty: missing %d", EVP_PKEY_missing_parameters(n));
        printf(", copy %d", EVP_PKEY_copy_parameters(n, k));
        printf(", missing %d, parameters eq %d\n", EVP_PKEY_missing_parameters(n),
               EVP_PKEY_parameters_eq(n, k));
        errors();
        /* (An SM2 key's parameters don't copy into an EC one, so it has no group to decode
         * the public key on.) */
        printf("  EVP_PKEY_set1_encoded_public_key: %d\n",
               EVP_PKEY_set1_encoded_public_key(n, enc, enclen));
        errors();
        printf("  eq with the original: %d\n", EVP_PKEY_eq(n, k));
        errors();
        EVP_PKEY_free(n);
    }
    legacy_params(k);
    OPENSSL_free(enc);
    EVP_PKEY_free(d);
    EVP_PKEY_free(e);
    EVP_PKEY_free(k);
    EC_KEY_free(ec);
    BIO_free(mem);
}

static void test_types(void)
{
    EC_KEY *sm2 = fixed_key(NID_sm2, "1"), *p256 = fixed_key(NID_X9_62_prime256v1, "1");
    EVP_PKEY *k = EVP_PKEY_new();
    int md = 0;

    printf("# types\n");
    check(EVP_PKEY_assign(k, EVP_PKEY_EC, sm2) == 1, "SM2's curve, assigned as EC");
    printf("  id %d, is SM2 %d\n", EVP_PKEY_get_id(k), EVP_PKEY_is_a(k, "SM2"));
    printf("  default digest: %d %s\n", EVP_PKEY_get_default_digest_nid(k, &md), OBJ_nid2sn(md));
    check(EVP_PKEY_get0_EC_KEY(k) == sm2, "its EC_KEY");
    errors();
    check(EVP_PKEY_assign(k, EVP_PKEY_SM2, p256) == 1, "P-256, assigned as SM2");
    printf("  id %d\n", EVP_PKEY_get_id(k));
    EVP_PKEY_free(k);

    k = EVP_PKEY_new();
    check(EVP_PKEY_assign_EC_KEY(k, NULL) == 0, "assigning NULL");
    printf("  id %d\n", EVP_PKEY_get_id(k));
    /* Not EVP_PKEY_set1_EC_KEY of NULL: OpenSSL's takes a reference to it. */
    EVP_PKEY_free(k);

    k = EVP_PKEY_new();
    check(EVP_PKEY_get0_EC_KEY(k) == NULL, "an empty key has no EC_KEY");
    errors();
    {
        EVP_PKEY *mac = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL,
                                                     (const unsigned char *)"key", 3);

        check(EVP_PKEY_get0_EC_KEY(mac) == NULL, "an HMAC key has none");
        errors();
        check(EVP_PKEY_get1_EC_KEY(mac) == NULL, "get1 neither");
        errors();
        EVP_PKEY_free(mac);
    }
    EVP_PKEY_free(k);
    {
        /* A key with an application's method. */
        EC_KEY_METHOD *m = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
        EC_KEY *f = fixed_key(NID_secp384r1, "42");
        EVP_PKEY *fk = EVP_PKEY_new();

        EC_KEY_set_method(f, m);
        check(EVP_PKEY_set1_EC_KEY(fk, f) == 1, "an EC_KEY with an application's method");
        printf("  bits %d, get0 the same %d\n", EVP_PKEY_get_bits(fk),
               EVP_PKEY_get0_EC_KEY(fk) == f);
        EVP_PKEY_free(fk);
        EC_KEY_free(f);
        EC_KEY_METHOD_free(m);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_curve(NID_X9_62_prime256v1,
               "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    test_curve(NID_secp521r1, "1A2B3C");
    test_curve(NID_sect163k1, "3A41434AA99C2EF40C8495B2ED9739CB2155A1E0D");
    test_curve(NID_secp112r1, "AB");
    test_curve(NID_sm2, "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
    test_types();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
