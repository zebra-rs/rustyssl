/*
 * Conformance test for the default provider's SM2 key manager (EVP_PKEY-SM2(7),
 * provider-keymgmt(7)), in TAP format: its names and parameter lists; keys made from data
 * (only on SM2's curve), every gettable parameter, exports, the checks (the private key's
 * range is [1, n-2]), generation (of keys and parameters, by default on SM2's curve),
 * comparison, copies, the encoded public key set, and a legacy EC_KEY on SM2's curve in a key.
 *
 * The fixed key is GB/T 32918's example key; generated keys are random, so only what they have
 * and whether they check is printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/param_build.h>
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

static void names(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    if (p == NULL)
        printf(" (none)");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u", p->key, p->data_type);
    printf("\n");
}

static void dump(const OSSL_PARAM *p, int got)
{
    for (; p != NULL && p->key != NULL; p++) {
        size_t n = got ? p->return_size : p->data_size;

        if (got && p->return_size == OSSL_PARAM_UNMODIFIED)
            continue;
        printf("  %s:", p->key);
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: {
            int v = 0;

            OSSL_PARAM_get_int(p, &v);
            printf(" int %d\n", v);
            break;
        }
        case OSSL_PARAM_UNSIGNED_INTEGER: {
            BIGNUM *b = NULL;
            char *s = NULL;

            if (OSSL_PARAM_get_BN(p, &b))
                s = BN_bn2hex(b);
            printf(" bn %s (%zu)\n", s != NULL ? s : "?", n);
            OPENSSL_free(s);
            BN_free(b);
            break;
        }
        case OSSL_PARAM_UTF8_STRING:
            printf(" utf8 %.*s\n", (int)n, (const char *)p->data);
            break;
        case OSSL_PARAM_OCTET_STRING:
            printf("\n");
            hex("octets", p->data, n);
            break;
        default:
            printf(" type %u\n", p->data_type);
        }
    }
}

static void print_name(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static const char PRIV[] = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";

/* The public point of a private key on a curve, uncompressed, into out. */
static size_t pub_of(int nid, const char *priv, unsigned char *out)
{
    EC_GROUP *g = EC_GROUP_new_by_curve_name(nid);
    EC_POINT *q = EC_POINT_new(g);
    BIGNUM *d = NULL;
    size_t n;

    BN_hex2bn(&d, priv);
    EC_POINT_mul(g, q, d, NULL, NULL, NULL);
    n = EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED, out, 200, NULL);
    BN_free(d);
    EC_POINT_free(q);
    EC_GROUP_free(g);
    return n;
}

/* A key of type from data: a group name, and a private key with its public key on pub_nid. */
static EVP_PKEY *make(const char *type, int selection, const char *group, const char *priv,
                      int pub_nid)
{
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    OSSL_PARAM *ps;
    BIGNUM *d = NULL;
    unsigned char pub[200];
    size_t publen;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    EVP_PKEY *k = NULL;
    int r;

    if (group != NULL)
        OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
    if (priv != NULL) {
        BN_hex2bn(&d, priv);
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PRIV_KEY, d);
        publen = pub_of(pub_nid, priv, pub);
        OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_PUB_KEY, pub, publen);
    }
    ps = OSSL_PARAM_BLD_to_param(b);
    r = EVP_PKEY_fromdata_init(c);
    printf("  fromdata %s %s: %d", type, group != NULL ? group : "-", r);
    r = EVP_PKEY_fromdata(c, &k, selection, ps);
    printf(" %d\n", r);
    errors();
    OSSL_PARAM_free(ps);
    OSSL_PARAM_BLD_free(b);
    BN_free(d);
    EVP_PKEY_CTX_free(c);
    return k;
}

static void get_all(EVP_PKEY *k)
{
    const OSSL_PARAM *g = EVP_PKEY_gettable_params(k);
    static long long bufs[64][40];
    OSSL_PARAM ps[64];
    size_t n;

    for (n = 0; g != NULL && g[n].key != NULL && n < 63; n++) {
        ps[n] = g[n];
        ps[n].data = bufs[n];
        ps[n].data_size = ps[n].data_type == OSSL_PARAM_INTEGER ? sizeof(int) : sizeof(bufs[n]);
        ps[n].return_size = OSSL_PARAM_UNMODIFIED;
    }
    ps[n] = OSSL_PARAM_construct_end();
    printf("  get_params: %d\n", EVP_PKEY_get_params(k, ps));
    errors();
    dump(ps, 1);
}

static void checks(EVP_PKEY *k, const char *what)
{
    EVP_PKEY_CTX *v = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);

    printf("  %s: check %d", what, EVP_PKEY_check(v));
    printf(" public %d", EVP_PKEY_public_check(v));
    printf(" quick %d", EVP_PKEY_public_check_quick(v));
    printf(" private %d", EVP_PKEY_private_check(v));
    printf(" pairwise %d", EVP_PKEY_pairwise_check(v));
    printf(" params %d\n", EVP_PKEY_param_check(v));
    errors();
    EVP_PKEY_CTX_free(v);
}

static void test_keymgmt(void)
{
    EVP_KEYMGMT *km = EVP_KEYMGMT_fetch(NULL, "SM2", NULL);

    check(km != NULL, "the SM2 key manager");
    if (km == NULL) {
        errors();
        return;
    }
    printf("  names:");
    EVP_KEYMGMT_names_do_all(km, print_name, NULL);
    printf("\n  description: %s\n", EVP_KEYMGMT_get0_description(km));
    check(EVP_KEYMGMT_is_a(km, "1.2.156.10197.1.301"), "its OID");
    names("gettable", EVP_KEYMGMT_gettable_params(km));
    names("settable", EVP_KEYMGMT_settable_params(km));
    names("gen settable", EVP_KEYMGMT_gen_settable_params(km));
    EVP_KEYMGMT_free(km);
}

static void test_fromdata(void)
{
    EVP_PKEY *k = make("SM2", EVP_PKEY_KEYPAIR, "SM2", PRIV, NID_sm2);
    EVP_PKEY *p256 = make("SM2", EVP_PKEY_KEYPAIR, "prime256v1", PRIV, NID_X9_62_prime256v1);
    EVP_PKEY *none = make("SM2", EVP_PKEY_KEYPAIR, NULL, PRIV, NID_sm2);
    EVP_PKEY *params = make("SM2", EVP_PKEY_KEY_PARAMETERS, "SM2", NULL, 0);
    EVP_PKEY *ec_sm2 = make("EC", EVP_PKEY_KEYPAIR, "SM2", PRIV, NID_sm2);
    OSSL_PARAM *out = NULL;
    EVP_PKEY *dup;

    check(k != NULL, "a key on SM2's curve");
    check(p256 == NULL, "not on P-256");
    check(none == NULL, "not without a group");
    check(params != NULL, "parameters alone");
    check(ec_sm2 == NULL, "the EC key manager refuses SM2's curve");
    if (k == NULL)
        return;
    printf("  id %d type %s is_a SM2 %d EC %d bits %d security %d size %d\n",
           EVP_PKEY_get_id(k), EVP_PKEY_get0_type_name(k), EVP_PKEY_is_a(k, "SM2"),
           EVP_PKEY_is_a(k, "EC"), EVP_PKEY_get_bits(k), EVP_PKEY_get_security_bits(k),
           EVP_PKEY_get_size(k));
    {
        char md[40] = "";
        int r = EVP_PKEY_get_default_digest_name(k, md, sizeof(md));

        printf("  default digest %d %s\n", r, md);
    }
    get_all(k);
    printf("  todata %d\n", EVP_PKEY_todata(k, EVP_PKEY_KEYPAIR, &out));
    errors();
    dump(out, 0);
    OSSL_PARAM_free(out);
    if (params != NULL)
        get_all(params);
    checks(k, "the key");
    if (params != NULL)
        checks(params, "the parameters");
    dup = EVP_PKEY_dup(k);
    printf("  dup %d eq %d params eq %d\n", dup != NULL, EVP_PKEY_eq(k, dup),
           params != NULL ? EVP_PKEY_parameters_eq(k, params) : -9);
    errors();
    {
        unsigned char pub[200];
        size_t n = pub_of(NID_sm2, "01", pub);
        OSSL_PARAM s[2];

        s[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub, n);
        s[1] = OSSL_PARAM_construct_end();
        printf("  set encoded public key %d eq %d\n", EVP_PKEY_set_params(dup, s),
               EVP_PKEY_eq(k, dup));
        errors();
        checks(dup, "with another public key");
    }
    EVP_PKEY_free(dup);
    EVP_PKEY_free(k);
    EVP_PKEY_free(params);
    EVP_PKEY_free(p256);
    EVP_PKEY_free(none);
    EVP_PKEY_free(ec_sm2);
}

/* The private key's range: 1 to n-2. */
static void test_private_range(void)
{
    static const char *const privs[] = {
        "01",
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54121",
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122",
    };
    size_t i;

    for (i = 0; i < sizeof(privs) / sizeof(privs[0]); i++) {
        EVP_PKEY *k = make("SM2", EVP_PKEY_KEYPAIR, "SM2", privs[i], NID_sm2);

        printf("  private %s\n", privs[i]);
        if (k != NULL)
            checks(k, "range");
        EVP_PKEY_free(k);
    }
}

static void test_gen(void)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    EVP_PKEY *k = NULL, *p = NULL;
    int r;

    r = EVP_PKEY_keygen_init(c);
    r = r * 10 + EVP_PKEY_keygen(c, &k);
    check(r == 11 && k != NULL, "a generated key, by default on SM2's curve");
    errors();
    if (k != NULL) {
        char group[40] = "";
        size_t len = 0;

        EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group),
                                       &len);
        printf("  group %s type %s\n", group, EVP_PKEY_get0_type_name(k));
        checks(k, "generated");
    }
    EVP_PKEY_free(k);
    k = NULL;
    {
        OSSL_PARAM ps[2];

        ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
        ps[1] = OSSL_PARAM_construct_end();
        r = EVP_PKEY_keygen_init(c);
        r = r * 10 + EVP_PKEY_CTX_set_params(c, ps);
        r = r * 10 + EVP_PKEY_keygen(c, &k);
        printf("  SM2's generation on P-256: %d\n", r);
        errors();
        if (k != NULL) {
            char group[40] = "";
            size_t len = 0;

            EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_GROUP_NAME, group,
                                           sizeof(group), &len);
            printf("  group %s type %s\n", group, EVP_PKEY_get0_type_name(k));
        }
        EVP_PKEY_free(k);
        k = NULL;
    }
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    r = EVP_PKEY_paramgen_init(c);
    r = r * 10 + EVP_PKEY_paramgen(c, &p);
    check(r == 11 && p != NULL, "generated parameters");
    errors();
    if (p != NULL) {
        printf("  has private %d\n",
               EVP_PKEY_get_bn_param(p, OSSL_PKEY_PARAM_PRIV_KEY, &(BIGNUM *){ NULL }));
        ERR_clear_error();
        EVP_PKEY_CTX_free(c);
        c = EVP_PKEY_CTX_new_from_pkey(NULL, p, NULL);
        r = EVP_PKEY_keygen_init(c);
        r = r * 10 + EVP_PKEY_keygen(c, &k);
        check(r == 11 && k != NULL, "a key from the parameters");
        errors();
        if (k != NULL)
            checks(k, "from the parameters");
    }
    EVP_PKEY_free(k);
    EVP_PKEY_free(p);
    EVP_PKEY_CTX_free(c);
}

/* A legacy EC_KEY on SM2's curve is an SM2 key, which the SM2 key manager takes. */
static void test_legacy(void)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_sm2);
    EVP_PKEY *k = EVP_PKEY_new();
    BIGNUM *d = NULL;
    EC_POINT *q = EC_POINT_new(EC_KEY_get0_group(ec));
    EVP_PKEY *prov = NULL;
    EVP_PKEY_CTX *c;

    BN_hex2bn(&d, PRIV);
    EC_POINT_mul(EC_KEY_get0_group(ec), q, d, NULL, NULL, NULL);
    EC_KEY_set_private_key(ec, d);
    EC_KEY_set_public_key(ec, q);
    check(EVP_PKEY_set1_EC_KEY(k, ec) == 1, "a legacy EC_KEY on SM2's curve");
    printf("  id %d type %s\n", EVP_PKEY_get_id(k), EVP_PKEY_get0_type_name(k));
    checks(k, "legacy");
    c = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    {
        OSSL_PARAM *out = NULL;
        int r = EVP_PKEY_todata(k, EVP_PKEY_KEYPAIR, &out);

        printf("  todata %d\n", r);
        errors();
        if (r == 1) {
            r = EVP_PKEY_fromdata_init(c);
            r = r * 10 + EVP_PKEY_fromdata(c, &prov, EVP_PKEY_KEYPAIR, out);
            printf("  into the SM2 key manager %d eq %d\n", r, EVP_PKEY_eq(k, prov));
            errors();
        }
        OSSL_PARAM_free(out);
    }
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(prov);
    EC_POINT_free(q);
    BN_free(d);
    EC_KEY_free(ec);
    EVP_PKEY_free(k);
}

int main(void)
{
    test_keymgmt();
    test_fromdata();
    test_private_range();
    test_gen();
    test_legacy();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
