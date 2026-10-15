/*
 * Conformance test for the default provider's ECDH key exchange (EVP_KEYEXCH-ECDH(7),
 * provider-keyexch(7)), in TAP format: the algorithm and its parameter lists; shared secrets
 * of fixed keys (whole, sized, cut short), the peer checks, the cofactor mode (the key's flag
 * and the context's override, on a curve with a cofactor), X9.63's KDF (its digest, output
 * length, and user keying material, and their errors), every context parameter, copies of a
 * context, keys without a private part, and legacy EC_KEYs in keys.
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

static void print_name(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

/*
 * A key on the named curve from a private number (with only its public point for !priv), and
 * the cofactor flag for cofactor >= 0.
 */
static EVP_PKEY *ec_key(const char *group, const char *x, int priv, int cofactor)
{
    EC_GROUP *g = EC_GROUP_new_by_curve_name(OBJ_sn2nid(group));
    EC_POINT *q = EC_POINT_new(g);
    BIGNUM *d = NULL;
    unsigned char pub[200];
    size_t publen;
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    OSSL_PARAM *ps;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *k = NULL;

    BN_hex2bn(&d, x);
    EC_POINT_mul(g, q, d, NULL, NULL, NULL);
    publen = EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED, pub, sizeof(pub), NULL);
    OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
    OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_PUB_KEY, pub, publen);
    if (priv)
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PRIV_KEY, d);
    if (cofactor >= 0)
        OSSL_PARAM_BLD_push_int(b, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, cofactor);
    ps = OSSL_PARAM_BLD_to_param(b);
    if (EVP_PKEY_fromdata_init(c) != 1
        || EVP_PKEY_fromdata(c, &k, priv ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, ps) != 1)
        k = NULL;
    OSSL_PARAM_free(ps);
    OSSL_PARAM_BLD_free(b);
    EVP_PKEY_CTX_free(c);
    BN_free(d);
    EC_POINT_free(q);
    EC_GROUP_free(g);
    return k;
}

static const char A256[] = "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433";
static const char B256[] = "C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53";
static const char A163[] = "03A41434AA99C2EF40C8495B2ED9739CB2155A1E0D";
static const char B163[] = "0057E8A78E842BF4ACD5C315AA0569DB1703541D96";

/* A context for k with peer and params; NULL (errors printed) if any step fails. */
static EVP_PKEY_CTX *exchange(EVP_PKEY *k, EVP_PKEY *peer, const OSSL_PARAM *params)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    int r = EVP_PKEY_derive_init_ex(c, params);

    if (r == 1 && peer != NULL)
        r = EVP_PKEY_derive_set_peer(c, peer);
    if (r != 1) {
        printf("  exchange: %d\n", r);
        errors();
        EVP_PKEY_CTX_free(c);
        return NULL;
    }
    return c;
}

/* Derives into a buffer of room octets, printing the result. */
static int derive(EVP_PKEY_CTX *c, size_t room, unsigned char *out, size_t *len)
{
    int r;

    *len = room;
    r = EVP_PKEY_derive(c, out, len);
    printf("  derive %d", r);
    if (r == 1)
        hex("secret", out, *len);
    else
        printf("\n");
    errors();
    return r;
}

static void test_algorithm(void)
{
    EVP_KEYEXCH *x = EVP_KEYEXCH_fetch(NULL, "ECDH", NULL);

    check(x != NULL, "ECDH");
    if (x == NULL) {
        errors();
        return;
    }
    printf("  names:");
    EVP_KEYEXCH_names_do_all(x, print_name, NULL);
    printf("\n  name %s, provider %s\n", EVP_KEYEXCH_get0_name(x),
           OSSL_PROVIDER_get0_name(EVP_KEYEXCH_get0_provider(x)));
    names("gettable", EVP_KEYEXCH_gettable_ctx_params(x));
    names("settable", EVP_KEYEXCH_settable_ctx_params(x));
    EVP_KEYEXCH_free(x);
}

static void test_plain(EVP_PKEY *a, EVP_PKEY *b, EVP_PKEY *other, EVP_PKEY *apub)
{
    EVP_PKEY_CTX *c = exchange(a, b, NULL), *d;
    unsigned char s1[100], s2[100];
    size_t l1, l2;
    int r;

    check(c != NULL, "a P-256 exchange");
    l1 = 0;
    r = EVP_PKEY_derive(c, NULL, &l1);
    printf("  size %d %zu\n", r, l1);
    derive(c, sizeof(s1), s1, &l1);
    d = exchange(b, a, NULL);
    derive(d, sizeof(s2), s2, &l2);
    check(l1 == l2 && memcmp(s1, s2, l1) == 0, "both sides agree");
    derive(c, 20, s2, &l2);
    check(l2 == 20 && memcmp(s1, s2, 20) == 0, "a short buffer takes the start");
    derive(c, 0, s2, &l2);
    names("settable", EVP_PKEY_CTX_settable_params(c));
    names("gettable", EVP_PKEY_CTX_gettable_params(c));
    EVP_PKEY_CTX_free(d);

    r = EVP_PKEY_derive_set_peer(c, other);
    check(r <= 0, "a peer on another curve is refused");
    errors();
    r = EVP_PKEY_derive_set_peer_ex(c, apub, 1);
    printf("  a public peer, validated %d\n", r);
    errors();
    derive(c, sizeof(s2), s2, &l2);
    EVP_PKEY_CTX_free(c);

    c = exchange(a, NULL, NULL);
    r = EVP_PKEY_derive(c, s2, &l2);
    check(r <= 0, "no peer");
    errors();
    EVP_PKEY_CTX_free(c);

    c = exchange(apub, b, NULL);
    check(c != NULL, "a public key's exchange starts");
    if (c != NULL) {
        r = derive(c, sizeof(s2), s2, &l2);
        check(r <= 0, "but can't derive");
        EVP_PKEY_CTX_free(c);
    }
}

/* Cofactor ECDH on sect163k1 (cofactor 2): the key's flag and the context's override. */
static void test_cofactor(void)
{
    EVP_PKEY *a = ec_key("sect163k1", A163, 1, -1);
    EVP_PKEY *af = ec_key("sect163k1", A163, 1, 1);
    EVP_PKEY *b = ec_key("sect163k1", B163, 1, -1);
    static const int modes[] = { -1, 0, 1, 2, -2 };
    unsigned char s[100];
    size_t l;
    size_t i;

    check(a != NULL && af != NULL && b != NULL, "sect163k1 keys");
    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        EVP_PKEY *keys[2];
        size_t j;

        keys[0] = a;
        keys[1] = af;
        for (j = 0; j < 2; j++) {
            EVP_PKEY_CTX *c = exchange(keys[j], b, NULL);
            int got = 99, r;
            OSSL_PARAM g[2];

            printf("  key flag %zu, mode %d: set %d", j, modes[i],
                   EVP_PKEY_CTX_set_ecdh_cofactor_mode(c, modes[i]));
            r = EVP_PKEY_CTX_get_ecdh_cofactor_mode(c);
            g[0] = OSSL_PARAM_construct_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, &got);
            g[1] = OSSL_PARAM_construct_end();
            printf(" get %d param %d %d\n", r, EVP_PKEY_CTX_get_params(c, g), got);
            errors();
            derive(c, sizeof(s), s, &l);
            EVP_PKEY_CTX_free(c);
        }
    }
    EVP_PKEY_free(a);
    EVP_PKEY_free(af);
    EVP_PKEY_free(b);
}

/* X9.63's KDF over the shared secret. */
static void test_kdf(EVP_PKEY *a, EVP_PKEY *b)
{
    EVP_PKEY_CTX *c = exchange(a, b, NULL), *d;
    unsigned char s[200], s2[200], ukm[] = "user keying material";
    unsigned char *got = NULL;
    const EVP_MD *md = NULL;
    size_t l, l2, outlen = 0;
    int r;
    char kdf[40] = "?", mdname[40] = "?";
    void *ukmp = NULL;
    OSSL_PARAM g[6], p[4];

    r = EVP_PKEY_CTX_set_ecdh_kdf_type(c, EVP_PKEY_ECDH_KDF_X9_63);
    r = r * 10 + EVP_PKEY_CTX_set_ecdh_kdf_md(c, EVP_sha256());
    r = r * 10 + EVP_PKEY_CTX_set_ecdh_kdf_outlen(c, 40);
    check(r == 111, "X9.63 with SHA-256 for 40 octets");
    errors();
    l = 0;
    printf("  size %d %zu\n", EVP_PKEY_derive(c, NULL, &l), l);
    derive(c, sizeof(s), s, &l);
    derive(c, 39, s2, &l2);
    r = EVP_PKEY_CTX_set0_ecdh_kdf_ukm(c, OPENSSL_memdup(ukm, 20), 20);
    printf("  set0 ukm %d\n", r);
    errors();
    derive(c, sizeof(s), s, &l);
    printf("  get type %d md %d", EVP_PKEY_CTX_get_ecdh_kdf_type(c),
           EVP_PKEY_CTX_get_ecdh_kdf_md(c, &md));
    printf(" %s", md != NULL ? EVP_MD_get0_name(md) : "(null)");
    printf(" outlen %d %zu", EVP_PKEY_CTX_get_ecdh_kdf_outlen(c, (int *)&outlen), outlen);
    r = EVP_PKEY_CTX_get0_ecdh_kdf_ukm(c, &got);
    printf(" ukm %d\n", r);
    if (got != NULL && r > 0)
        hex("ukm", got, (size_t)r);
    errors();
    g[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, kdf, sizeof(kdf));
    g[1] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, mdname,
                                            sizeof(mdname));
    g[2] = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &outlen);
    g[3] = OSSL_PARAM_construct_octet_ptr(OSSL_EXCHANGE_PARAM_KDF_UKM, &ukmp, 0);
    g[4] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_get_params(c, g);
    printf("  get_params %d type [%s] digest [%s] outlen %zu ukm %zu %d\n", r, kdf, mdname,
           outlen, g[3].return_size, ukmp != NULL && memcmp(ukmp, ukm, 20) == 0);
    errors();

    d = EVP_PKEY_CTX_dup(c);
    check(d != NULL, "a copy");
    derive(d, sizeof(s2), s2, &l2);
    check(l == l2 && memcmp(s, s2, l) == 0, "derives the same");
    EVP_PKEY_CTX_free(d);

    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, "SHA3-384", 0);
    p[1] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS,
                                            "provider=default", 0);
    p[2] = OSSL_PARAM_construct_end();
    printf("  SHA3-384 with properties %d\n", EVP_PKEY_CTX_set_params(c, p));
    errors();
    derive(c, sizeof(s), s, &l);
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, "SHAKE128", 0);
    p[1] = OSSL_PARAM_construct_end();
    printf("  SHAKE128 %d\n", EVP_PKEY_CTX_set_params(c, p));
    errors();
    derive(c, sizeof(s), s, &l);
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, "nosuchdigest", 0);
    printf("  nosuchdigest %d\n", EVP_PKEY_CTX_set_params(c, p));
    errors();
    derive(c, sizeof(s), s, &l);
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, "SHA1", 0);
    printf("  SHA1 %d\n", EVP_PKEY_CTX_set_params(c, p));
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, "HKDF", 0);
    printf("  type HKDF %d\n", EVP_PKEY_CTX_set_params(c, p));
    errors();
    derive(c, sizeof(s), s, &l);
    outlen = 0;
    p[0] = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &outlen);
    printf("  outlen 0 %d\n", EVP_PKEY_CTX_set_params(c, p));
    derive(c, sizeof(s), s, &l);
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, "", 0);
    printf("  type none %d\n", EVP_PKEY_CTX_set_params(c, p));
    derive(c, sizeof(s), s, &l);
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, "X963KDF", 0);
    printf("  type X963KDF %d\n", EVP_PKEY_CTX_set_params(c, p));
    outlen = 300;
    p[0] = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &outlen);
    printf("  outlen 300 %d\n", EVP_PKEY_CTX_set_params(c, p));
    derive(c, sizeof(s), s, &l);
    p[0] = OSSL_PARAM_construct_end();
    printf("  empty %d\n", EVP_PKEY_CTX_set_params(c, p));
    EVP_PKEY_CTX_free(c);

    c = exchange(a, b, NULL);
    r = EVP_PKEY_CTX_set_ecdh_kdf_type(c, EVP_PKEY_ECDH_KDF_X9_63);
    r = r * 10 + EVP_PKEY_CTX_set_ecdh_kdf_outlen(c, 16);
    printf("  X9.63 without a digest %d\n", r);
    errors();
    derive(c, sizeof(s), s, &l);
    mdname[0] = '?';
    g[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, mdname,
                                            sizeof(mdname));
    g[1] = OSSL_PARAM_construct_octet_ptr(OSSL_EXCHANGE_PARAM_KDF_UKM, &ukmp, 0);
    g[2] = OSSL_PARAM_construct_end();
    printf("  get_params %d digest [%s] ukm %zu\n", EVP_PKEY_CTX_get_params(c, g), mdname,
           g[1].return_size);
    errors();
    /* A new init goes back to no KDF and the key's cofactor mode. */
    r = EVP_PKEY_derive_init(c);
    printf("  init again %d type %d\n", r, EVP_PKEY_CTX_get_ecdh_kdf_type(c));
    errors();
    EVP_PKEY_CTX_free(c);

    {
        int bad = 2;

        p[0] = OSSL_PARAM_construct_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, &bad);
        p[1] = OSSL_PARAM_construct_end();
        c = EVP_PKEY_CTX_new_from_pkey(NULL, a, NULL);
        printf("  init with a bad cofactor mode %d\n", EVP_PKEY_derive_init_ex(c, p));
        errors();
        EVP_PKEY_CTX_free(c);
    }
}

/* Legacy EC_KEYs in keys exchange through the provider. */
static void test_legacy(void)
{
    EC_KEY *e1 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY *e2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EVP_PKEY *k1 = EVP_PKEY_new(), *k2 = EVP_PKEY_new();
    BIGNUM *d = NULL;
    EC_POINT *q = EC_POINT_new(EC_KEY_get0_group(e1));
    EVP_PKEY_CTX *c;
    unsigned char s[100];
    size_t l;

    BN_hex2bn(&d, A256);
    EC_POINT_mul(EC_KEY_get0_group(e1), q, d, NULL, NULL, NULL);
    EC_KEY_set_private_key(e1, d);
    EC_KEY_set_public_key(e1, q);
    BN_hex2bn(&d, B256);
    EC_POINT_mul(EC_KEY_get0_group(e2), q, d, NULL, NULL, NULL);
    EC_KEY_set_private_key(e2, d);
    EC_KEY_set_public_key(e2, q);
    check(EVP_PKEY_set1_EC_KEY(k1, e1) == 1 && EVP_PKEY_set1_EC_KEY(k2, e2) == 1,
          "legacy EC keys");
    c = exchange(k1, k2, NULL);
    check(c != NULL, "exchange");
    derive(c, sizeof(s), s, &l);
    EVP_PKEY_CTX_free(c);
    EC_POINT_free(q);
    BN_free(d);
    EC_KEY_free(e1);
    EC_KEY_free(e2);
    EVP_PKEY_free(k1);
    EVP_PKEY_free(k2);
}

int main(void)
{
    EVP_PKEY *a = ec_key("prime256v1", A256, 1, -1);
    EVP_PKEY *b = ec_key("prime256v1", B256, 1, -1);
    EVP_PKEY *apub = ec_key("prime256v1", A256, 0, -1);
    EVP_PKEY *other = ec_key("secp384r1", A256, 1, -1);

    check(a != NULL && b != NULL && apub != NULL && other != NULL, "the keys");
    test_algorithm();
    test_plain(a, b, other, apub);
    test_cofactor();
    test_kdf(a, b);
    test_legacy();
    errors();
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    EVP_PKEY_free(apub);
    EVP_PKEY_free(other);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
