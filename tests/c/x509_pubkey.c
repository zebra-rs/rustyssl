/*
 * Conformance test for SubjectPublicKeyInfo (X509_PUBKEY_new(3), X509_PUBKEY_set0_param(3),
 * d2i_RSA_PUBKEY(3), i2d_PUBKEY(3)) with legacy keys, in TAP format: X509_PUBKEY made, set,
 * read, copied, compared, and encoded; the typed d2i_/i2d_ of RSA (and RSA-PSS, with and
 * without restrictions), DSA (with and without saved parameters), and EC (named and explicit
 * curves) keys, through BIOs and files too; i2d_PUBKEY and X509_PUBKEY_set of legacy keys
 * (RSA, RSA-PSS, DSA, DH, DHX, EC); and the errors of wrong types, bad parameters, and
 * truncated input.
 *
 * Keys made by providers are encoded by encoders (step 4.7c), and decoding a key otherwise than
 * through the typed functions uses decoders (step 4.7b), so neither is here yet.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

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

static void hex(const char *label, const unsigned char *p, long len)
{
    long i;

    printf("  %s (%ld): ", label, len);
    for (i = 0; i < len; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static unsigned char *unhex(const char *h, long *n)
{
    return OPENSSL_hexstr2buf(h, n);
}

static BIGNUM *hexbn(const char *h)
{
    BIGNUM *b = NULL;

    BN_hex2bn(&b, h);
    return b;
}

/* A SubjectPublicKeyInfo's algorithm, parameter type, and key octets. */
static void spki_info(const char *label, const X509_PUBKEY *x)
{
    ASN1_OBJECT *o = NULL;
    const unsigned char *pk = NULL;
    int pklen = -1;
    X509_ALGOR *a = NULL;
    unsigned char *der = NULL;
    int n;

    X509_PUBKEY_get0_param(&o, &pk, &pklen, &a, x);
    printf("  %s: alg %d ptype %d keylen %d\n", label, OBJ_obj2nid(o),
           a != NULL && a->parameter != NULL ? a->parameter->type : -1, pklen);
    n = i2d_X509_PUBKEY(x, &der);
    if (n > 0)
        hex("  der", der, n);
    else
        printf("    i2d %d\n", n);
    OPENSSL_free(der);
}

/* i2d_PUBKEY of a key, printed. */
static void pubkey_der(const char *label, const EVP_PKEY *k)
{
    unsigned char *der = NULL;
    int n = i2d_PUBKEY(k, &der);

    if (n > 0)
        hex(label, der, n);
    else
        printf("  %s: %d\n", label, n);
    OPENSSL_free(der);
    errors();
}

static const char RSA_N[] =
    "C5E1A6C9D1B9DF44DB57CB1C3D5DC3C6C19A63A2D5B5E0A50A9C1D36F7D3B91D2D53DDFDE8F0F6B0D9C02BDD"
    "B1B9E3D78B83D3CBB61B4F9B1A6DCAB8C76D9BD2F7";
static const char PSS_PUB[] =
    "308190304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a8648"
    "86f70d010108300d06096086480165030402020500a203020120034b003048024100e1b325a60c7e05feeffc"
    "00ae0fc13f7bf126ffd27d373353159749fb88ab0a5782dc3a96b471992155a0c9b051cb28f376f5a1c3034d"
    "6ea0736c855997bb3d650203010001";
static const char PSS0_PUB[] =
    "305a300b06092a864886f70d01010a034b003048024100d36ac8b93123f820f364faaf06b9c4d5ce6eecaee2"
    "b091439b2f5f4867f1f7c51e1444fb3540da370539f38367bc32c2bb05bf9a2888a2e61f69be2add14628d02"
    "03010001";
/* RSA-PSS with a NULL parameter, which isn't PSS's. */
static const char PSS_NULL_PUB[] =
    "305c300d06092a864886f70d01010a0500034b003048024100d36ac8b93123f820f364faaf06b9c4d5ce6eec"
    "aee2b091439b2f5f4867f1f7c51e1444fb3540da370539f38367bc32c2bb05bf9a2888a2e61f69be2add1462"
    "8d0203010001";

static void test_structure(void)
{
    X509_PUBKEY *x = X509_PUBKEY_new(), *y, *z = X509_PUBKEY_new_ex(NULL, "provider=default");
    unsigned char *key = OPENSSL_malloc(3);

    check(x != NULL && z != NULL, "X509_PUBKEY_new and _new_ex");
    spki_info("empty", x);
    printf("  get0 of an empty one: %s\n", X509_PUBKEY_get0(x) == NULL ? "NULL" : "?");
    printf("  get of NULL: %s\n", X509_PUBKEY_get(NULL) == NULL ? "NULL" : "?");
    errors();
    memcpy(key, "\x01\x02\x03", 3);
    check(X509_PUBKEY_set0_param(x, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, NULL, key, 3)
              == 1,
          "set0_param");
    spki_info("set", x);
    printf("  set0_param without octets: %d\n",
           X509_PUBKEY_set0_param(x, OBJ_nid2obj(NID_dsa), V_ASN1_UNDEF, NULL, NULL, 0));
    spki_info("kept octets", x);
    key = OPENSSL_malloc(2);
    memcpy(key, "\xaa\xbb", 2);
    X509_PUBKEY_set0_public_key(x, key, 2);
    spki_info("set0_public_key", x);
    y = X509_PUBKEY_dup(x);
    check(y != NULL, "dup without a key");
    spki_info("dup", y);
    printf("  eq: same %d copies %d NULL %d\n", X509_PUBKEY_eq(x, x), X509_PUBKEY_eq(x, y),
           X509_PUBKEY_eq(x, NULL));
    errors();
    printf("  item %s\n", ASN1_ITEM_rptr(X509_PUBKEY)->sname);
    X509_PUBKEY_free(x);
    X509_PUBKEY_free(y);
    X509_PUBKEY_free(z);
    X509_PUBKEY_free(NULL);
}

static void test_rsa(void)
{
    RSA *r = RSA_new(), *back = NULL, *got;
    EVP_PKEY *k = EVP_PKEY_new(), *got_k;
    X509_PUBKEY *x = NULL, *y;
    unsigned char *der = NULL;
    const unsigned char *p;
    int n;
    long l;

    RSA_set0_key(r, hexbn(RSA_N), hexbn("010001"), NULL);
    n = i2d_RSA_PUBKEY(r, &der);
    check(n > 0, "i2d_RSA_PUBKEY");
    hex("RSA SPKI", der, n);
    printf("  i2d_RSA_PUBKEY(NULL) %d, size only %d\n", i2d_RSA_PUBKEY(NULL, NULL),
           i2d_RSA_PUBKEY(r, NULL));
    p = der;
    got = d2i_RSA_PUBKEY(&back, &p, n);
    check(got != NULL && got == back && p == der + n
              && BN_cmp(RSA_get0_n(got), RSA_get0_n(r)) == 0,
          "d2i_RSA_PUBKEY");
    printf("  flags type %d\n", RSA_test_flags(got, RSA_FLAG_TYPE_MASK));
    p = der;
    printf("  short: %s\n", d2i_RSA_PUBKEY(NULL, &p, n - 1) == NULL ? "fails" : "ok");
    printf("  consumed after failing %ld\n", (long)(p - der));
    errors();

    EVP_PKEY_set1_RSA(k, r);
    pubkey_der("i2d_PUBKEY", k);
    check(X509_PUBKEY_set(&x, k) == 1, "X509_PUBKEY_set of a legacy RSA key");
    spki_info("set", x);
    got_k = X509_PUBKEY_get0(x);
    printf("  get0 is the key %d, get %d\n", got_k == k, X509_PUBKEY_get(x) == k);
    EVP_PKEY_free(k); /* the reference X509_PUBKEY_get took */
    y = X509_PUBKEY_dup(x);
    check(y != NULL && X509_PUBKEY_get0(y) != NULL && X509_PUBKEY_get0(y) != k, "dup with a key");
    printf("  eq %d\n", X509_PUBKEY_eq(x, y));
    printf("  set NULL: %d %d\n", X509_PUBKEY_set(NULL, k), X509_PUBKEY_set(&x, NULL));
    errors();
    {
        BIO *b = BIO_new(BIO_s_mem());
        RSA *rb;
        FILE *fp = tmpfile();

        printf("  i2d bio %d\n", i2d_RSA_PUBKEY_bio(b, r));
        rb = d2i_RSA_PUBKEY_bio(b, NULL);
        check(rb != NULL && BN_cmp(RSA_get0_n(rb), RSA_get0_n(r)) == 0, "d2i_RSA_PUBKEY_bio");
        RSA_free(rb);
        printf("  empty bio: %s\n", d2i_RSA_PUBKEY_bio(b, NULL) == NULL ? "fails" : "ok");
        errors();
        BIO_free(b);
        if (fp != NULL) {
            printf("  i2d fp %d\n", i2d_RSA_PUBKEY_fp(fp, r));
            rewind(fp);
            rb = d2i_RSA_PUBKEY_fp(fp, NULL);
            check(rb != NULL && BN_cmp(RSA_get0_e(rb), RSA_get0_e(r)) == 0, "d2i_RSA_PUBKEY_fp");
            RSA_free(rb);
            fclose(fp);
        }
        b = BIO_new(BIO_s_mem());
        printf("  i2d_PUBKEY_bio %d pending %d\n", i2d_PUBKEY_bio(b, k), BIO_pending(b));
        BIO_free(b);
        fp = tmpfile();
        if (fp != NULL) {
            printf("  i2d_PUBKEY_fp %d\n", i2d_PUBKEY_fp(fp, k));
            fclose(fp);
        }
    }
    OPENSSL_free(der);
    {
        unsigned char *pss = unhex(PSS_PUB, &l);
        RSA *q;

        p = pss;
        q = d2i_RSA_PUBKEY(NULL, &p, l);
        check(q != NULL, "d2i_RSA_PUBKEY of RSA-PSS with restrictions");
        if (q != NULL) {
            const RSA_PSS_PARAMS *pp = RSA_get0_pss_params(q);
            EVP_PKEY *pk = EVP_PKEY_new();

            printf("  flags type %d params %s\n", RSA_test_flags(q, RSA_FLAG_TYPE_MASK),
                   pp != NULL ? "set" : "none");
            der = NULL;
            n = i2d_RSA_PUBKEY(q, &der);
            printf("  re-encoded as RSA: same %d\n", n == l && memcmp(der, pss, l) == 0);
            hex("as RSA", der, n);
            OPENSSL_free(der);
            EVP_PKEY_assign(pk, EVP_PKEY_RSA_PSS, q);
            pubkey_der("as an RSA-PSS key", pk);
            EVP_PKEY_free(pk);
        }
        errors();
        OPENSSL_free(pss);
        pss = unhex(PSS0_PUB, &l);
        p = pss;
        q = d2i_RSA_PUBKEY(NULL, &p, l);
        check(q != NULL && RSA_get0_pss_params(q) == NULL, "RSA-PSS without restrictions");
        if (q != NULL) {
            EVP_PKEY *pk = EVP_PKEY_new();

            EVP_PKEY_assign(pk, EVP_PKEY_RSA_PSS, q);
            pubkey_der("unrestricted RSA-PSS", pk);
            EVP_PKEY_free(pk);
        }
        OPENSSL_free(pss);
        pss = unhex(PSS_NULL_PUB, &l);
        p = pss;
        q = d2i_RSA_PUBKEY(NULL, &p, l);
        printf("  RSA-PSS with a NULL parameter: %s\n", q == NULL ? "fails" : "ok");
        errors();
        RSA_free(q);
        OPENSSL_free(pss);
    }
    RSA_free(r);
    RSA_free(back);
    X509_PUBKEY_free(x);
    X509_PUBKEY_free(y);
}

/* RFC 6979's DSA-1024 key's parameters and public key. */
static DSA *rfc_dsa(void)
{
    DSA *d = DSA_new();

    DSA_set0_pqg(d,
                 hexbn("86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447E653"
                       "3B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED8873ABFD3F5BA"
                       "2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C881870B7B19B2B58F9"
                       "BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779"),
                 hexbn("996F967F6C8E388D9E28D01E205FBA957A5698B1"),
                 hexbn("07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D89BB"
                       "CD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD87995A10A1C"
                       "27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA417BE5DCE2F40D10A46"
                       "A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD"));
    DSA_set0_key(d,
                 hexbn("5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F6539219"
                       "5A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D4CE935437DC"
                       "11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E682F65CBDC4FAE93C2E"
                       "A212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B"),
                 NULL);
    return d;
}

static void test_dsa(void)
{
    DSA *d = rfc_dsa(), *got;
    EVP_PKEY *k = EVP_PKEY_new();
    unsigned char *der = NULL;
    const unsigned char *p;
    int n;

    n = i2d_DSA_PUBKEY(d, &der);
    check(n > 0, "i2d_DSA_PUBKEY");
    hex("DSA SPKI", der, n);
    p = der;
    got = d2i_DSA_PUBKEY(NULL, &p, n);
    check(got != NULL && BN_cmp(DSA_get0_pub_key(got), DSA_get0_pub_key(d)) == 0
              && DSA_get0_p(got) != NULL,
          "d2i_DSA_PUBKEY with parameters");
    DSA_free(got);
    p = der;
    printf("  as RSA: %s\n", d2i_RSA_PUBKEY(NULL, &p, n) == NULL ? "fails" : "ok");
    errors();
    OPENSSL_free(der);
    EVP_PKEY_set1_DSA(k, d);
    pubkey_der("saving parameters", k);
    printf("  save_parameters %d\n", EVP_PKEY_save_parameters(k, 0));
    pubkey_der("without parameters", k);
    der = NULL;
    n = i2d_PUBKEY(k, &der);
    p = der;
    got = d2i_DSA_PUBKEY(NULL, &p, n);
    check(got != NULL && DSA_get0_p(got) == NULL, "d2i_DSA_PUBKEY without parameters");
    DSA_free(got);
    OPENSSL_free(der);
    {
        BIO *b = BIO_new(BIO_s_mem());
        FILE *fp = tmpfile();

        printf("  i2d bio %d", i2d_DSA_PUBKEY_bio(b, d));
        got = d2i_DSA_PUBKEY_bio(b, NULL);
        printf(" d2i bio %s\n", got != NULL ? "ok" : "fails");
        DSA_free(got);
        BIO_free(b);
        if (fp != NULL) {
            printf("  i2d fp %d", i2d_DSA_PUBKEY_fp(fp, d));
            rewind(fp);
            got = d2i_DSA_PUBKEY_fp(fp, NULL);
            printf(" d2i fp %s\n", got != NULL ? "ok" : "fails");
            DSA_free(got);
            fclose(fp);
        }
    }
    errors();
    EVP_PKEY_free(k);
    DSA_free(d);
}

static void test_dh(void)
{
    DH *dh = DH_new_by_nid(NID_ffdhe2048), *x942 = DH_get_2048_256();
    EVP_PKEY *k = EVP_PKEY_new(), *kx = EVP_PKEY_new();
    X509_PUBKEY *xp = NULL;

    DH_set0_key(dh, hexbn("0123456789ABCDEF0123456789ABCDEF"), NULL);
    DH_set0_key(x942, hexbn("FEDCBA9876543210FEDCBA9876543210"), NULL);
    EVP_PKEY_set1_DH(k, dh);
    EVP_PKEY_assign(kx, EVP_PKEY_DHX, x942);
    pubkey_der("DH", k);
    pubkey_der("DHX", kx);
    check(X509_PUBKEY_set(&xp, kx) == 1, "X509_PUBKEY_set of a DHX key");
    spki_info("DHX", xp);
    X509_PUBKEY_free(xp);
    EVP_PKEY_free(k);
    EVP_PKEY_free(kx);
    DH_free(dh);
}

static void test_ec(void)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), *got;
    EVP_PKEY *k = EVP_PKEY_new();
    BIGNUM *x = hexbn("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    EC_POINT *q = EC_POINT_new(EC_KEY_get0_group(ec));
    unsigned char *der = NULL;
    const unsigned char *p;
    int n;

    EC_POINT_mul(EC_KEY_get0_group(ec), q, x, NULL, NULL, NULL);
    EC_KEY_set_public_key(ec, q);
    n = i2d_EC_PUBKEY(ec, &der);
    check(n > 0, "i2d_EC_PUBKEY, named curve");
    hex("EC SPKI", der, n);
    p = der;
    got = d2i_EC_PUBKEY(NULL, &p, n);
    check(got != NULL
              && EC_POINT_cmp(EC_KEY_get0_group(ec), EC_KEY_get0_public_key(got), q, NULL) == 0,
          "d2i_EC_PUBKEY");
    printf("  curve %d\n", got != NULL ? EC_GROUP_get_curve_name(EC_KEY_get0_group(got)) : -1);
    EC_KEY_free(got);
    OPENSSL_free(der);
    EC_KEY_set_asn1_flag(ec, 0);
    der = NULL;
    n = i2d_EC_PUBKEY(ec, &der);
    check(n > 0, "i2d_EC_PUBKEY, explicit parameters");
    hex("explicit", der, n);
    p = der;
    got = d2i_EC_PUBKEY(NULL, &p, n);
    check(got != NULL, "d2i_EC_PUBKEY of explicit parameters");
    printf("  curve %d\n", got != NULL ? EC_GROUP_get_curve_name(EC_KEY_get0_group(got)) : -1);
    EC_KEY_free(got);
    p = der;
    printf("  as DSA: %s\n", d2i_DSA_PUBKEY(NULL, &p, n) == NULL ? "fails" : "ok");
    errors();
    OPENSSL_free(der);
    EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);
    EVP_PKEY_set1_EC_KEY(k, ec);
    pubkey_der("i2d_PUBKEY", k);
    {
        EC_KEY *empty = EC_KEY_new();

        printf("  i2d_EC_PUBKEY without a group %d\n", i2d_EC_PUBKEY(empty, NULL));
        errors();
        EC_KEY_free(empty);
    }
    {
        /* An unknown curve's OID, and a NULL parameter (neither OID nor SEQUENCE). */
        static const char *const bad[] = {
            "3019301306072a8648ce3d020106082a8648ce3d03017f0302000a",
            "300f300906072a8648ce3d020105000302000a",
        };
        size_t i;

        for (i = 0; i < 2; i++) {
            long l;
            unsigned char *b = unhex(bad[i], &l);

            p = b;
            printf("  bad parameters %zu: %s\n", i,
                   d2i_EC_PUBKEY(NULL, &p, l) == NULL ? "fails" : "ok");
            errors();
            OPENSSL_free(b);
        }
    }
    {
        BIO *b = BIO_new(BIO_s_mem());
        FILE *fp = tmpfile();

        printf("  i2d bio %d", i2d_EC_PUBKEY_bio(b, ec));
        got = d2i_EC_PUBKEY_bio(b, NULL);
        printf(" d2i bio %s\n", got != NULL ? "ok" : "fails");
        EC_KEY_free(got);
        BIO_free(b);
        if (fp != NULL) {
            printf("  i2d fp %d", i2d_EC_PUBKEY_fp(fp, ec));
            rewind(fp);
            got = d2i_EC_PUBKEY_fp(fp, NULL);
            printf(" d2i fp %s\n", got != NULL ? "ok" : "fails");
            EC_KEY_free(got);
            fclose(fp);
        }
    }
    errors();
    EC_POINT_free(q);
    BN_free(x);
    EVP_PKEY_free(k);
    EC_KEY_free(ec);
}

int main(void)
{
    test_structure();
    test_rsa();
    test_dsa();
    test_dh();
    test_ec();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
