/*
 * Conformance test for the default provider's EC key manager (EVP_PKEY-EC(7),
 * provider-keymgmt(7)), in TAP format: its names and parameter lists; keys made from data
 * (named and explicit groups, each part alone, the other parameters, and the errors), every
 * gettable parameter, exports of each selection, parameters set on a key (point format,
 * encoding, encoded public key, seed, check type, cofactor mode), generated keys and
 * parameters (by name, from explicit parameters, from a template, and from an RFC 9180 DHKEM
 * input key), comparison, validation, copies, and the moves between an EC_KEY in a key and
 * the key manager's data (EVP_PKEY_get_field_type, EVP_PKEY_get_ec_point_conv_form).
 *
 * The fixed key is RFC 6979's P-256 key (A.2.5); the DHKEM input is RFC 9180's (A.3.1).
 * Generated keys are random, so only what they have and whether they check is printed.
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

static const char PRIV[] = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
static const char PUB[] =
    "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
    "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
static const char OTHER_PRIV[] = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20";
static const char IKM[] = "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e";

static BIGNUM *bn(const char *h)
{
    BIGNUM *b = NULL;

    BN_hex2bn(&b, h);
    return b;
}

/* The uncompressed P-256 public point of a private key, in hex. */
static char *pub_of(const char *priv)
{
    EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *q = EC_POINT_new(g);
    BIGNUM *d = bn(priv);
    char *h;

    EC_POINT_mul(g, q, d, NULL, NULL, NULL);
    h = EC_POINT_point2hex(g, q, POINT_CONVERSION_UNCOMPRESSED, NULL);
    BN_free(d);
    EC_POINT_free(q);
    EC_GROUP_free(g);
    return h;
}

static unsigned char *octets(const char *h, long *len)
{
    return OPENSSL_hexstr2buf(h, len);
}

/*
 * Every parameter of an array: its name and its value (with `got`, those a get left alone are
 * skipped).
 */
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

            if (OSSL_PARAM_get_int(p, &v))
                printf(" int %d\n", v);
            else
                printf(" int ?\n");
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

static void names(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u", p->key, p->data_type);
    printf("\n");
}

/* Asks for every gettable parameter at once. */
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

static void todata(EVP_PKEY *k, int selection, const char *label)
{
    OSSL_PARAM *out = NULL;

    printf("  todata %s: %d\n", label, EVP_PKEY_todata(k, selection, &out));
    errors();
    dump(out, 0);
    OSSL_PARAM_free(out);
}

static EVP_PKEY *fromdata(int selection, const OSSL_PARAM *params)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *k = NULL;
    int r;

    r = EVP_PKEY_fromdata_init(c);
    printf("  fromdata: %d", r);
    r = EVP_PKEY_fromdata(c, &k, selection, (OSSL_PARAM *)params);
    printf(" %d\n", r);
    errors();
    EVP_PKEY_CTX_free(c);
    return k;
}

/* A key from a group name and optional private and public parts, and other parameters. */
static EVP_PKEY *make(int selection, const char *group, const char *priv, const char *pub,
                      const char *more_key, const char *more_val)
{
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    OSSL_PARAM *ps;
    BIGNUM *d = priv != NULL ? bn(priv) : NULL;
    unsigned char *q = NULL;
    long qlen = 0;
    EVP_PKEY *k;

    if (group != NULL)
        OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
    if (d != NULL)
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PRIV_KEY, d);
    if (pub != NULL) {
        q = octets(pub, &qlen);
        OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_PUB_KEY, q, qlen);
    }
    if (more_key != NULL) {
        if (more_val[0] == '#')
            OSSL_PARAM_BLD_push_int(b, more_key, atoi(more_val + 1));
        else
            OSSL_PARAM_BLD_push_utf8_string(b, more_key, more_val, 0);
    }
    ps = OSSL_PARAM_BLD_to_param(b);
    k = fromdata(selection, ps);
    OSSL_PARAM_free(ps);
    OSSL_PARAM_BLD_free(b);
    BN_free(d);
    OPENSSL_free(q);
    return k;
}

static void print_names(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static void test_keymgmt(void)
{
    EVP_KEYMGMT *km = EVP_KEYMGMT_fetch(NULL, "EC", NULL);
    static const int sels[] = { 0, 1, 2, 3, 4, 5, 6, 7, 0x80, 0x81, 0x83, 0x84, 0x87, 0x86 };
    size_t i;

    check(km != NULL, "the EC key manager");
    printf("  names:");
    EVP_KEYMGMT_names_do_all(km, print_names, NULL);
    printf("\n  description: %s\n", EVP_KEYMGMT_get0_description(km));
    check(EVP_KEYMGMT_is_a(km, "id-ecPublicKey") && EVP_KEYMGMT_is_a(km, "1.2.840.10045.2.1"),
          "its other names");
    names("gettable", EVP_KEYMGMT_gettable_params(km));
    names("settable", EVP_KEYMGMT_settable_params(km));
    names("gen settable", EVP_KEYMGMT_gen_settable_params(km));
    for (i = 0; i < sizeof(sels) / sizeof(sels[0]); i++) {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

        EVP_PKEY_fromdata_init(c);
        printf("  selection %#x", sels[i]);
        names("", EVP_PKEY_fromdata_settable(c, sels[i]));
        EVP_PKEY_CTX_free(c);
    }
    EVP_KEYMGMT_free(km);
}

static void test_fromdata(void)
{
    EVP_PKEY *k, *k2;
    OSSL_PARAM_BLD *b;
    OSSL_PARAM *ps, *ex = NULL;

    k = make(EVP_PKEY_KEYPAIR, "P-256", PRIV, PUB, NULL, NULL);
    check(k != NULL, "a key pair from data");
    printf("  bits %d, security bits %d, size %d, type %d %s\n", EVP_PKEY_get_bits(k),
           EVP_PKEY_get_security_bits(k), EVP_PKEY_get_size(k), EVP_PKEY_get_id(k),
           EVP_PKEY_get0_type_name(k));
    get_all(k);
    todata(k, EVP_PKEY_KEYPAIR, "keypair");
    todata(k, EVP_PKEY_PUBLIC_KEY, "public");
    todata(k, EVP_PKEY_KEY_PARAMETERS, "parameters");
    todata(k, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, "other only");
    todata(k, OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
           "private without public");

    /* The explicit parameters back to a key: the group is found by its parameters. */
    EVP_PKEY_todata(k, EVP_PKEY_KEY_PARAMETERS, &ex);
    b = OSSL_PARAM_BLD_new();
    {
        BIGNUM *p = NULL, *a = NULL, *bb = NULL, *o = NULL, *h = NULL;
        unsigned char gen[200];
        size_t genlen = 0;
        const OSSL_PARAM *q;

        EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_EC_P, &p);
        EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_EC_A, &a);
        EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_EC_B, &bb);
        EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_EC_ORDER, &o);
        EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_EC_COFACTOR, &h);
        EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_EC_GENERATOR, gen, sizeof(gen),
                                        &genlen);
        OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_EC_FIELD_TYPE, SN_X9_62_prime_field,
                                        0);
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_EC_P, p);
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_EC_A, a);
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_EC_B, bb);
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_EC_ORDER, o);
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_EC_COFACTOR, h);
        OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_EC_GENERATOR, gen, genlen);
        ps = OSSL_PARAM_BLD_to_param(b);
        k2 = fromdata(EVP_PKEY_KEY_PARAMETERS, ps);
        check(k2 != NULL, "parameters from explicit data");
        get_all(k2);
        check(EVP_PKEY_parameters_eq(k, k2) == 1, "the same parameters");
        errors();
        EVP_PKEY_free(k2);
        OSSL_PARAM_free(ps);
        q = OSSL_PARAM_locate_const(ex, OSSL_PKEY_PARAM_EC_ENCODING);
        printf("  encoding exported: %s\n", q != NULL ? (const char *)q->data : "-");
        BN_free(p);
        BN_free(a);
        BN_free(bb);
        BN_free(o);
        BN_free(h);
    }
    OSSL_PARAM_BLD_free(b);
    OSSL_PARAM_free(ex);
    EVP_PKEY_free(k);

    k = make(EVP_PKEY_PUBLIC_KEY, "prime256v1", PRIV, PUB, NULL, NULL);
    check(k != NULL, "a public key, the private part ignored");
    todata(k, EVP_PKEY_KEYPAIR, "keypair");
    EVP_PKEY_free(k);
    k = make(EVP_PKEY_KEYPAIR, "P-256", PRIV, NULL, NULL, NULL);
    check(k != NULL, "a private key without its public key");
    todata(k, EVP_PKEY_KEYPAIR, "keypair");
    get_all(k);
    EVP_PKEY_free(k);
    k = make(EVP_PKEY_KEY_PARAMETERS, "secp384r1", NULL, NULL, NULL, NULL);
    check(k != NULL, "parameters by name");
    printf("  bits %d, security bits %d, size %d\n", EVP_PKEY_get_bits(k),
           EVP_PKEY_get_security_bits(k), EVP_PKEY_get_size(k));
    get_all(k);
    EVP_PKEY_free(k);
    k = make(EVP_PKEY_KEY_PARAMETERS, "sect163k1", NULL, NULL,
             OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, "#1");
    check(k != NULL, "a characteristic-two curve with a cofactor");
    get_all(k);
    EVP_PKEY_free(k);

    k = make(EVP_PKEY_KEYPAIR, NULL, PRIV, PUB, NULL, NULL);
    check(k == NULL, "no group");
    k = make(EVP_PKEY_KEYPAIR, "no-such-curve", PRIV, PUB, NULL, NULL);
    check(k == NULL, "an unknown group");
    k = make(EVP_PKEY_KEY_PARAMETERS, "SM2", NULL, NULL, NULL, NULL);
    check(k == NULL, "SM2's curve isn't EC's");
    k = make(EVP_PKEY_KEYPAIR, "P-256", NULL, "04010203", NULL, NULL);
    check(k == NULL, "a public key that isn't a point");
    k = make(EVP_PKEY_KEYPAIR, "P-384", NULL, PUB, NULL, NULL);
    check(k == NULL, "a point of another curve");
    k = make(EVP_PKEY_KEYPAIR, "P-256", PRIV, PUB, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, "#2");
    check(k == NULL, "a cofactor mode of 2");
    k = make(EVP_PKEY_KEYPAIR, "P-256", PRIV, PUB, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
             "bogus");
    check(k == NULL, "an unknown point format");
    k = make(EVP_PKEY_KEYPAIR, "P-256", PRIV, PUB, OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE, "bogus");
    check(k == NULL, "an unknown check type");
    k = make(EVP_PKEY_KEYPAIR, "P-256", PRIV, PUB, OSSL_PKEY_PARAM_EC_ENCODING, "bogus");
    check(k == NULL, "an unknown encoding");

    k = make(EVP_PKEY_KEYPAIR, "P-256", PRIV, PUB, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
             "compressed");
    check(k != NULL, "a compressed point format");
    todata(k, EVP_PKEY_KEYPAIR, "keypair");
    printf("  conversion form %d, field type %d\n", EVP_PKEY_get_ec_point_conv_form(k),
           EVP_PKEY_get_field_type(k));
    EVP_PKEY_free(k);
    k = make(EVP_PKEY_KEYPAIR, "P-256", PRIV, PUB, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, "#0");
    check(k != NULL, "without the public key in encodings");
    todata(k, OSSL_KEYMGMT_SELECT_ALL, "all");
    EVP_PKEY_free(k);
    k = make(EVP_PKEY_KEYPAIR, "P-256", PRIV, PUB, OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE,
             "named-nist");
    check(k != NULL, "the NIST check");
    todata(k, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
           "other");
    EVP_PKEY_free(k);
    k = make(EVP_PKEY_KEYPAIR, "P-256", PRIV, PUB, OSSL_PKEY_PARAM_EC_ENCODING, "explicit");
    check(k != NULL, "explicit encoding");
    todata(k, EVP_PKEY_KEY_PARAMETERS, "parameters");
    EVP_PKEY_free(k);
}

static void test_set_params(void)
{
    EVP_PKEY *k = make(EVP_PKEY_KEYPAIR, "P-256", PRIV, PUB, NULL, NULL);
    char *other_pub = pub_of(OTHER_PRIV);
    EVP_PKEY *o = make(EVP_PKEY_KEYPAIR, "P-256", OTHER_PRIV, other_pub, NULL, NULL);
    unsigned char *enc = NULL;
    size_t n;
    OSSL_PARAM ps[2];
    unsigned char seed[3] = { 1, 2, 3 };

    names("settable", EVP_PKEY_settable_params(k));
    check(EVP_PKEY_set_utf8_string_param(k, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                         "compressed"),
          "set the point format");
    errors();
    n = EVP_PKEY_get1_encoded_public_key(k, &enc);
    hex("encoded public key", enc, n);
    OPENSSL_free(enc);
    todata(k, EVP_PKEY_PUBLIC_KEY, "public");
    check(EVP_PKEY_set_utf8_string_param(k, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                         "nope") == 0,
          "an unknown point format");
    errors();
    check(EVP_PKEY_set_utf8_string_param(k, OSSL_PKEY_PARAM_EC_ENCODING, "explicit"),
          "set the encoding");
    errors();
    check(EVP_PKEY_set_octet_string_param(k, OSSL_PKEY_PARAM_EC_SEED, seed, sizeof(seed)),
          "set the seed");
    errors();
    check(EVP_PKEY_set_utf8_string_param(k, OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE, "named"),
          "set the check type");
    errors();
    check(EVP_PKEY_set_int_param(k, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, 0),
          "leave out the public key");
    errors();
    check(EVP_PKEY_set_int_param(k, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, 1),
          "the cofactor mode on a curve without a cofactor");
    errors();
    check(EVP_PKEY_set_int_param(k, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, -1) == 0,
          "a cofactor mode of -1");
    errors();
    todata(k, OSSL_KEYMGMT_SELECT_ALL, "all");

    /* Another key's public point. */
    n = EVP_PKEY_get1_encoded_public_key(o, &enc);
    check(EVP_PKEY_set1_encoded_public_key(k, enc, n), "set an encoded public key");
    errors();
    OPENSSL_free(enc);
    todata(k, EVP_PKEY_PUBLIC_KEY, "public");
    check(EVP_PKEY_set1_encoded_public_key(k, (const unsigned char *)"\x04\x01", 2) == 0,
          "an encoded public key that isn't a point");
    errors();
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, "x", 1);
    ps[1] = OSSL_PARAM_construct_end();
    check(EVP_PKEY_set_params(k, ps) == 0, "an encoded public key as a string");
    errors();
    check(EVP_PKEY_set_params(k, NULL) == 1, "no parameters");
    errors();
    EVP_PKEY_free(k);
    EVP_PKEY_free(o);
    OPENSSL_free(other_pub);
}

static EVP_PKEY *generate(int params_only, const OSSL_PARAM *ps, EVP_PKEY *templ)
{
    EVP_PKEY_CTX *c = templ != NULL ? EVP_PKEY_CTX_new_from_pkey(NULL, templ, NULL)
                                    : EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *k = NULL;
    int r;

    r = params_only ? EVP_PKEY_paramgen_init(c) : EVP_PKEY_keygen_init(c);
    printf("  init %d,", r);
    if (ps != NULL)
        printf(" set %d,", EVP_PKEY_CTX_set_params(c, ps));
    r = params_only ? EVP_PKEY_paramgen(c, &k) : EVP_PKEY_keygen(c, &k);
    printf(" generate %d\n", r);
    errors();
    EVP_PKEY_CTX_free(c);
    return k;
}

static void has(EVP_PKEY *k)
{
    BIGNUM *d = NULL;
    unsigned char q[200];
    size_t qlen = 0;
    char group[80] = "";
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);

    printf("  group %d %s, private %d, public %d (%zu)",
           EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group),
                                          NULL),
           group, EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_PRIV_KEY, &d),
           EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY, q, sizeof(q), &qlen),
           qlen);
    printf(", check %d, param check %d\n", EVP_PKEY_check(c), EVP_PKEY_param_check(c));
    errors();
    BN_free(d);
    EVP_PKEY_CTX_free(c);
}

static void test_generate(void)
{
    OSSL_PARAM ps[4];
    EVP_PKEY *k, *p;
    EVP_PKEY_CTX *c;
    unsigned char *ikm;
    long ikmlen;
    int cofactor = 1;

    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    ps[1] = OSSL_PARAM_construct_end();
    k = generate(0, ps, NULL);
    check(k != NULL, "a generated key");
    has(k);
    EVP_PKEY_free(k);

    k = generate(0, NULL, NULL);
    check(k == NULL, "a generated key needs a group");

    c = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY_keygen_init(c);
    check(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, NID_secp384r1) == 1, "a curve by NID");
    k = NULL;
    printf("  keygen %d\n", EVP_PKEY_keygen(c, &k));
    errors();
    has(k);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(k);

    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "sect163k1", 0);
    ps[1] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, &cofactor);
    ps[2] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE, "named", 0);
    ps[3] = OSSL_PARAM_construct_end();
    p = generate(1, ps, NULL);
    check(p != NULL, "generated parameters");
    has(p);
    todata(p, OSSL_KEYMGMT_SELECT_ALL, "all");
    k = generate(0, NULL, p);
    check(k != NULL, "a key from a template");
    has(k);
    todata(k, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, "other");
    EVP_PKEY_free(k);
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, "explicit", 0);
    ps[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                             "compressed", 0);
    ps[2] = OSSL_PARAM_construct_end();
    k = generate(0, ps, p);
    check(k != NULL, "a template's group, encoded explicitly");
    todata(k, EVP_PKEY_KEY_PARAMETERS, "parameters");
    EVP_PKEY_free(k);
    EVP_PKEY_free(p);

    /* RFC 9180, A.3.1: the sender's ephemeral key from its input key material. */
    ikm = octets(IKM, &ikmlen);
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    ps[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM, ikm, ikmlen);
    ps[2] = OSSL_PARAM_construct_end();
    k = generate(0, ps, NULL);
    check(k != NULL, "a DHKEM key");
    todata(k, EVP_PKEY_KEYPAIR, "keypair");
    EVP_PKEY_free(k);
    ps[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM, ikm, 31);
    k = generate(0, ps, NULL);
    check(k == NULL, "a DHKEM input that's too short");
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "P-521", 0);
    ps[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM, ikm, ikmlen);
    k = generate(0, ps, NULL);
    check(k == NULL, "a DHKEM input shorter than P-521's");
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "P-224", 0);
    k = generate(0, ps, NULL);
    check(k == NULL, "no DHKEM for P-224");
    OPENSSL_free(ikm);

    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, "prime-field", 0);
    ps[1] = OSSL_PARAM_construct_end();
    p = generate(1, ps, NULL);
    check(p == NULL, "a field type without the parameters");
    ps[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE, &cofactor);
    p = generate(1, ps, NULL);
    check(p == NULL, "a check type that isn't a string");
}

static void test_compare_validate(void)
{
    EVP_PKEY *k = make(EVP_PKEY_KEYPAIR, "P-256", PRIV, PUB, NULL, NULL);
    EVP_PKEY *same = make(EVP_PKEY_PUBLIC_KEY, "P-256", NULL, PUB, NULL, NULL);
    char *other_pub = pub_of(OTHER_PRIV);
    EVP_PKEY *o = make(EVP_PKEY_KEYPAIR, "P-256", OTHER_PRIV, other_pub, NULL, NULL);
    EVP_PKEY *priv_only = make(EVP_PKEY_KEYPAIR, "P-256", OTHER_PRIV, NULL, NULL, NULL);
    EVP_PKEY *bad = make(EVP_PKEY_KEYPAIR, "P-256", OTHER_PRIV, PUB, NULL, NULL);
    EVP_PKEY *p384 = make(EVP_PKEY_KEY_PARAMETERS, "P-384", NULL, NULL, NULL, NULL);
    EVP_PKEY *dup;
    EVP_PKEY_CTX *c;

    printf("  eq: same %d, other %d, private only %d, other group %d\n", EVP_PKEY_eq(k, same),
           EVP_PKEY_eq(k, o), EVP_PKEY_eq(priv_only, bad), EVP_PKEY_eq(k, p384));
    errors();
    printf("  parameters_eq: %d %d\n", EVP_PKEY_parameters_eq(k, o),
           EVP_PKEY_parameters_eq(k, p384));
    errors();
    c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    printf("  good: check %d, public %d, quick %d, private %d, params %d, quick %d, pairwise %d\n",
           EVP_PKEY_check(c), EVP_PKEY_public_check(c), EVP_PKEY_public_check_quick(c),
           EVP_PKEY_private_check(c), EVP_PKEY_param_check(c), EVP_PKEY_param_check_quick(c),
           EVP_PKEY_pairwise_check(c));
    errors();
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, bad, NULL);
    printf("  mismatched: check %d", EVP_PKEY_check(c));
    errors();
    printf("  public %d, private %d, pairwise %d\n", EVP_PKEY_public_check(c),
           EVP_PKEY_private_check(c), EVP_PKEY_pairwise_check(c));
    errors();
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, p384, NULL);
    printf("  parameters only: check %d", EVP_PKEY_check(c));
    errors();
    printf("  public %d", EVP_PKEY_public_check(c));
    errors();
    printf("  private %d", EVP_PKEY_private_check(c));
    errors();
    printf("  params %d\n", EVP_PKEY_param_check(c));
    errors();
    EVP_PKEY_CTX_free(c);

    dup = EVP_PKEY_dup(k);
    check(dup != NULL && EVP_PKEY_eq(dup, k) == 1, "a copy");
    todata(dup, OSSL_KEYMGMT_SELECT_ALL, "all");
    EVP_PKEY_free(dup);
    dup = EVP_PKEY_new();
    check(EVP_PKEY_copy_parameters(dup, p384) == 1, "parameters copied");
    todata(dup, OSSL_KEYMGMT_SELECT_ALL, "all");
    errors();
    EVP_PKEY_free(dup);

    EVP_PKEY_free(k);
    EVP_PKEY_free(same);
    EVP_PKEY_free(o);
    EVP_PKEY_free(priv_only);
    EVP_PKEY_free(bad);
    OPENSSL_free(other_pub);
    EVP_PKEY_free(p384);
}

static void test_legacy(void)
{
    EVP_PKEY *k = make(EVP_PKEY_KEYPAIR, "P-256", PRIV, PUB, NULL, NULL);
    EVP_PKEY *l = EVP_PKEY_new();
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_KEY *got;
    BIGNUM *d = bn(PRIV);
    char *s;

    EC_KEY_set_private_key(ec, d);
    EC_KEY_set_conv_form(ec, POINT_CONVERSION_COMPRESSED);
    {
        EC_POINT *q = EC_POINT_new(EC_KEY_get0_group(ec));

        EC_POINT_mul(EC_KEY_get0_group(ec), q, d, NULL, NULL, NULL);
        EC_KEY_set_public_key(ec, q);
        EC_POINT_free(q);
    }
    EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH);
    EVP_PKEY_set1_EC_KEY(l, ec);
    todata(l, OSSL_KEYMGMT_SELECT_ALL, "legacy");
    printf("  eq legacy and provided: %d\n", EVP_PKEY_eq(l, k));
    errors();
    printf("  legacy: conversion form %d, field type %d\n", EVP_PKEY_get_ec_point_conv_form(l),
           EVP_PKEY_get_field_type(l));
    printf("  provided: conversion form %d, field type %d\n",
           EVP_PKEY_get_ec_point_conv_form(k), EVP_PKEY_get_field_type(k));
    errors();

    got = EVP_PKEY_get0_EC_KEY(k);
    check(got != NULL, "a provided key's EC_KEY");
    s = got != NULL ? BN_bn2hex(EC_KEY_get0_private_key(got)) : NULL;
    printf("  private key %s, curve %d, form %d\n", s != NULL ? s : "-",
           got != NULL ? EC_GROUP_get_curve_name(EC_KEY_get0_group(got)) : 0,
           got != NULL ? (int)EC_KEY_get_conv_form(got) : -1);
    OPENSSL_free(s);
    check(EVP_PKEY_get0_EC_KEY(k) == got, "the same one again");
    errors();

    check(EVP_PKEY_get_ec_point_conv_form(NULL) == 0 && EVP_PKEY_get_field_type(NULL) == 0,
          "NULL keys");
    {
        EVP_PKEY *blank = EVP_PKEY_new();

        printf("  blank: %d %d\n", EVP_PKEY_get_ec_point_conv_form(blank),
               EVP_PKEY_get_field_type(blank));
        errors();
        EVP_PKEY_free(blank);
    }
    {
        EVP_PKEY *c2 = make(EVP_PKEY_KEY_PARAMETERS, "sect163k1", NULL, NULL, NULL, NULL);
        EVP_PKEY *lc2 = EVP_PKEY_new();
        EC_KEY *e2 = EC_KEY_new_by_curve_name(NID_sect163k1);

        EVP_PKEY_set1_EC_KEY(lc2, e2);
        printf("  char2: provided %d %d, legacy %d %d\n", EVP_PKEY_get_ec_point_conv_form(c2),
               EVP_PKEY_get_field_type(c2), EVP_PKEY_get_ec_point_conv_form(lc2),
               EVP_PKEY_get_field_type(lc2));
        errors();
        EC_KEY_free(e2);
        EVP_PKEY_free(lc2);
        EVP_PKEY_free(c2);
    }
    {
        EVP_PKEY *r = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)512);

        printf("  rsa: %d %d\n", EVP_PKEY_get_ec_point_conv_form(r), EVP_PKEY_get_field_type(r));
        errors();
        EVP_PKEY_free(r);
    }

    BN_free(d);
    EC_KEY_free(ec);
    EVP_PKEY_free(l);
    EVP_PKEY_free(k);
}

int main(void)
{
    test_keymgmt();
    test_fromdata();
    test_set_params();
    test_generate();
    test_compare_validate();
    test_legacy();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
