/*
 * Conformance test for the structures step 4.7a1 adds (X509_ALGOR_set0(3), X509_ATTRIBUTE,
 * X509at_get_attr(3), X509_SIG_get0(3), PKCS8_pkey_get0(3)), in TAP format: AlgorithmIdentifiers
 * set, read, compared, copied, and encoded (alone and as a SEQUENCE OF); attributes made each
 * way (by NID, object, and name; strings, multibyte strings, copies of values, none), read, and
 * encoded, with their errors; stacks of attributes searched, added to (refusing duplicates),
 * and cut; X509_SIG's DER and getters; and PKCS#8's PrivateKeyInfo set, read, given attributes,
 * and encoded and decoded (with the version checks, through BIOs and files too).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

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

static void hex(const char *label, const unsigned char *p, int len)
{
    int i;

    printf("  %s (%d): ", label, len);
    for (i = 0; i < len; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void obj(const char *label, const ASN1_OBJECT *o)
{
    char buf[80];

    if (o == NULL) {
        printf("  %s: (null)\n", label);
        return;
    }
    OBJ_obj2txt(buf, sizeof(buf), o, 1);
    printf("  %s: %s nid %d\n", label, buf, OBJ_obj2nid(o));
}

#define DER(label, i2d, x)                                                                \
    do {                                                                                  \
        unsigned char *der_ = NULL;                                                       \
        int n_ = i2d(x, &der_);                                                           \
                                                                                          \
        if (n_ > 0)                                                                       \
            hex(label, der_, n_);                                                         \
        else                                                                              \
            printf("  %s: %d\n", label, n_);                                              \
        OPENSSL_free(der_);                                                               \
    } while (0)

static void algor_info(const char *label, const X509_ALGOR *a)
{
    const ASN1_OBJECT *o = NULL;
    int ptype = -99;
    const void *pval = NULL;

    X509_ALGOR_get0(&o, &ptype, &pval, a);
    printf("  %s: ptype %d pval %s\n", label, ptype, pval != NULL ? "set" : "NULL");
    obj("  object", o);
    DER("  der", i2d_X509_ALGOR, a);
}

static void test_algor(void)
{
    X509_ALGOR *a = X509_ALGOR_new(), *b, *c = X509_ALGOR_new();
    STACK_OF(X509_ALGOR) *sk = sk_X509_ALGOR_new_null(), *sk2 = NULL;
    const unsigned char *p;
    unsigned char *der = NULL;
    int n;
    const ASN1_OBJECT *o = NULL;
    int ptype = -99;

    check(a != NULL && c != NULL, "X509_ALGOR_new");
    X509_ALGOR_get0(&o, &ptype, NULL, a);
    printf("  empty: object %s ptype %d\n", o == NULL ? "NULL" : "set", ptype);
    check(X509_ALGOR_set0(a, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, NULL) == 1,
          "set0 rsaEncryption with NULL");
    algor_info("rsa", a);
    check(X509_ALGOR_set0(a, OBJ_nid2obj(NID_sha256), V_ASN1_UNDEF, NULL) == 1,
          "set0 sha256 without parameters");
    algor_info("sha256", a);
    check(X509_ALGOR_set0(a, OBJ_nid2obj(NID_X9_62_id_ecPublicKey), V_ASN1_OBJECT,
                          OBJ_nid2obj(NID_X9_62_prime256v1)) == 1,
          "set0 with an object parameter");
    algor_info("ec", a);
    check(X509_ALGOR_set0(a, OBJ_nid2obj(NID_dsa), V_ASN1_EOC, NULL) == 1,
          "set0 keeping the parameter (V_ASN1_EOC)");
    algor_info("kept", a);
    printf("  set0 NULL: %d\n", X509_ALGOR_set0(NULL, NULL, V_ASN1_NULL, NULL));

    X509_ALGOR_set_md(c, EVP_sha256());
    algor_info("set_md sha256", c);
    X509_ALGOR_set_md(c, EVP_sha1());
    algor_info("set_md sha1", c);
    X509_ALGOR_set_md(c, EVP_md5());
    algor_info("set_md md5", c);
    X509_ALGOR_set_md(c, EVP_sha3_256());
    algor_info("set_md sha3-256", c);

    b = X509_ALGOR_dup(a);
    check(b != NULL && X509_ALGOR_cmp(a, b) == 0, "dup compares equal");
    printf("  cmp a c %d c a %d\n", X509_ALGOR_cmp(a, c) < 0 ? -1 : X509_ALGOR_cmp(a, c) > 0,
           X509_ALGOR_cmp(c, a) < 0 ? -1 : X509_ALGOR_cmp(c, a) > 0);
    X509_ALGOR_set0(b, OBJ_nid2obj(NID_dsa), V_ASN1_UNDEF, NULL);
    printf("  cmp without a parameter %d\n", X509_ALGOR_cmp(a, b) != 0);
    check(X509_ALGOR_copy(b, c) == 1 && X509_ALGOR_cmp(b, c) == 0, "copy");
    algor_info("copied", b);
    printf("  copy NULL: %d %d\n", X509_ALGOR_copy(NULL, c), X509_ALGOR_copy(b, NULL));
    errors();

    sk_X509_ALGOR_push(sk, X509_ALGOR_dup(a));
    sk_X509_ALGOR_push(sk, X509_ALGOR_dup(c));
    n = i2d_X509_ALGORS(sk, &der);
    check(n > 0, "i2d_X509_ALGORS");
    hex("algors", der, n);
    p = der;
    sk2 = d2i_X509_ALGORS(NULL, &p, n);
    check(sk2 != NULL && sk_X509_ALGOR_num(sk2) == 2 && p == der + n, "d2i_X509_ALGORS");
    if (sk2 != NULL)
        check(X509_ALGOR_cmp(sk_X509_ALGOR_value(sk2, 1), c) == 0, "the second compares");
    printf("  item %s\n", ASN1_ITEM_rptr(X509_ALGORS)->sname);
    OPENSSL_free(der);
    {
        static const unsigned char bad[] = { 0x30, 0x03, 0x06, 0x01, 0x00 };
        X509_ALGOR *d;

        p = bad;
        d = d2i_X509_ALGOR(NULL, &p, sizeof(bad));
        printf("  d2i of a bad OID: %s\n", d == NULL ? "fails" : "ok");
        errors();
        X509_ALGOR_free(d);
    }
    sk_X509_ALGOR_pop_free(sk, X509_ALGOR_free);
    sk_X509_ALGOR_pop_free(sk2, X509_ALGOR_free);
    X509_ALGOR_free(a);
    X509_ALGOR_free(b);
    X509_ALGOR_free(c);
    errors();
}

static void attr_info(const char *label, X509_ATTRIBUTE *at)
{
    int i, n = X509_ATTRIBUTE_count(at);

    printf("  %s: count %d\n", label, n);
    obj("  object", X509_ATTRIBUTE_get0_object(at));
    for (i = 0; i < n; i++) {
        ASN1_TYPE *t = X509_ATTRIBUTE_get0_type(at, i);

        printf("    value %d type %d\n", i, t != NULL ? t->type : -1);
    }
    DER("  der", i2d_X509_ATTRIBUTE, at);
}

static void test_attribute(void)
{
    ASN1_IA5STRING *email = ASN1_IA5STRING_new();
    X509_ATTRIBUTE *a, *b, *c, *d, *e, *f = NULL;
    const unsigned char *p;
    unsigned char *der = NULL;
    int n;
    void *data;

    ASN1_STRING_set(email, "a@example.com", -1);
    a = X509_ATTRIBUTE_create(NID_pkcs9_emailAddress, V_ASN1_IA5STRING, email);
    check(a != NULL, "X509_ATTRIBUTE_create");
    attr_info("create", a);
    printf("  create with a bad NID: %s\n",
           X509_ATTRIBUTE_create(99999, V_ASN1_NULL, NULL) == NULL ? "NULL" : "made");
    errors();

    b = X509_ATTRIBUTE_create_by_NID(NULL, NID_pkcs9_challengePassword, MBSTRING_ASC,
                                     (const unsigned char *)"secret", -1);
    check(b != NULL, "create_by_NID with MBSTRING_ASC");
    attr_info("by NID", b);
    printf("  set1_data utf8 %d\n",
           X509_ATTRIBUTE_set1_data(b, MBSTRING_UTF8, "second", 6));
    printf("  set1_data octets %d\n", X509_ATTRIBUTE_set1_data(b, V_ASN1_OCTET_STRING, "\x01\x02", 2));
    printf("  set1_data type 0 %d\n", X509_ATTRIBUTE_set1_data(b, 0, NULL, 0));
    printf("  set1_data NULL %d\n", X509_ATTRIBUTE_set1_data(NULL, V_ASN1_NULL, NULL, -1));
    errors();
    attr_info("three values", b);

    c = X509_ATTRIBUTE_create_by_OBJ(NULL, OBJ_nid2obj(NID_pkcs9_contentType), V_ASN1_OBJECT,
                                     OBJ_nid2obj(NID_pkcs7_data), -1);
    check(c != NULL, "create_by_OBJ with a copy of an object");
    attr_info("by OBJ", c);
    data = X509_ATTRIBUTE_get0_data(c, 0, V_ASN1_OBJECT, NULL);
    printf("  get0_data object %s\n", data != NULL ? "found" : "NULL");
    printf("  get0_data wrong type %s\n",
           X509_ATTRIBUTE_get0_data(c, 0, V_ASN1_IA5STRING, NULL) == NULL ? "NULL" : "found");
    printf("  get0_data NULL type %s\n",
           X509_ATTRIBUTE_get0_data(c, 0, V_ASN1_NULL, NULL) == NULL ? "NULL" : "found");
    printf("  get0_data out of range %s\n",
           X509_ATTRIBUTE_get0_data(c, 5, V_ASN1_OBJECT, NULL) == NULL ? "NULL" : "found");
    errors();

    d = X509_ATTRIBUTE_create_by_txt(NULL, "localKeyID", V_ASN1_OCTET_STRING,
                                     (const unsigned char *)"\x0a\x0b", 2);
    check(d != NULL, "create_by_txt by name");
    attr_info("by txt", d);
    e = X509_ATTRIBUTE_create_by_txt(NULL, "1.2.3.4.5", 0, NULL, 0);
    check(e != NULL, "create_by_txt by OID, no value");
    attr_info("empty", e);
    printf("  create_by_txt unknown: %s\n",
           X509_ATTRIBUTE_create_by_txt(NULL, "noSuchAttr", V_ASN1_NULL, NULL, -1) == NULL
               ? "NULL"
               : "made");
    printf("  create_by_NID unknown: %s\n",
           X509_ATTRIBUTE_create_by_NID(NULL, -5, V_ASN1_NULL, NULL, -1) == NULL ? "NULL"
                                                                                  : "made");
    errors();
    printf("  into an existing one: %d\n",
           X509_ATTRIBUTE_create_by_NID(&f, NID_friendlyName, MBSTRING_ASC,
                                        (const unsigned char *)"name", -1) == f && f != NULL);
    attr_info("into", f);
    printf("  set1_object %d", X509_ATTRIBUTE_set1_object(f, OBJ_nid2obj(NID_ms_csp_name)));
    printf(" NULL %d\n", X509_ATTRIBUTE_set1_object(f, NULL));
    errors();
    printf("  getters of NULL: count %d object %s type %s\n", X509_ATTRIBUTE_count(NULL),
           X509_ATTRIBUTE_get0_object(NULL) == NULL ? "NULL" : "?",
           X509_ATTRIBUTE_get0_type(NULL, 0) == NULL ? "NULL" : "?");
    errors();

    n = i2d_X509_ATTRIBUTE(b, &der);
    p = der;
    {
        X509_ATTRIBUTE *r = d2i_X509_ATTRIBUTE(NULL, &p, n);
        X509_ATTRIBUTE *dup = X509_ATTRIBUTE_dup(b);

        check(r != NULL && p == der + n, "d2i_X509_ATTRIBUTE");
        attr_info("decoded", r);
        attr_info("dup", dup);
        X509_ATTRIBUTE_free(r);
        X509_ATTRIBUTE_free(dup);
    }
    OPENSSL_free(der);
    {
        /* A SET of no values decodes; a SEQUENCE where the SET goes doesn't. */
        static const unsigned char empty[] = { 0x30, 0x06, 0x06, 0x02, 0x2a, 0x03, 0x31, 0x00 };
        static const unsigned char wrong[] = { 0x30, 0x06, 0x06, 0x02, 0x2a, 0x03, 0x30, 0x00 };
        X509_ATTRIBUTE *r;

        p = empty;
        r = d2i_X509_ATTRIBUTE(NULL, &p, sizeof(empty));
        printf("  empty SET: %s count %d\n", r == NULL ? "fails" : "ok", X509_ATTRIBUTE_count(r));
        X509_ATTRIBUTE_free(r);
        p = wrong;
        r = d2i_X509_ATTRIBUTE(NULL, &p, sizeof(wrong));
        printf("  SEQUENCE for SET: %s\n", r == NULL ? "fails" : "ok");
        errors();
        X509_ATTRIBUTE_free(r);
    }
    {
        X509_ATTRIBUTE *g = X509_ATTRIBUTE_new();

        attr_info("new", g);
        printf("  item %s\n", ASN1_ITEM_rptr(X509_ATTRIBUTE)->sname);
        X509_ATTRIBUTE_free(g);
        errors();
    }
    X509_ATTRIBUTE_free(a);
    X509_ATTRIBUTE_free(b);
    X509_ATTRIBUTE_free(c);
    X509_ATTRIBUTE_free(d);
    X509_ATTRIBUTE_free(e);
    X509_ATTRIBUTE_free(f);
}

static void test_x509at(void)
{
    STACK_OF(X509_ATTRIBUTE) *sk = NULL;
    X509_ATTRIBUTE *a = X509_ATTRIBUTE_create_by_NID(NULL, NID_pkcs9_emailAddress, MBSTRING_ASC,
                                                     (const unsigned char *)"x@y", -1);
    X509_ATTRIBUTE *got;
    const ASN1_OBJECT *email = OBJ_nid2obj(NID_pkcs9_emailAddress);
    void *data;

    printf("  count of NULL %d\n", X509at_get_attr_count(NULL));
    check(X509at_add1_attr(&sk, a) == sk && sk != NULL, "add1_attr makes the stack");
    printf("  a duplicate: %s\n", X509at_add1_attr(&sk, a) == NULL ? "refused" : "added");
    errors();
    check(X509at_add1_attr_by_NID(&sk, NID_friendlyName, MBSTRING_ASC,
                                  (const unsigned char *)"friend", -1) != NULL,
          "add1_attr_by_NID");
    printf("  by_NID duplicate: %s\n",
           X509at_add1_attr_by_NID(&sk, NID_friendlyName, V_ASN1_NULL, NULL, -1) == NULL
               ? "refused"
               : "added");
    errors();
    check(X509at_add1_attr_by_OBJ(&sk, OBJ_nid2obj(NID_localKeyID), V_ASN1_OCTET_STRING,
                                  (const unsigned char *)"\x01", 1) != NULL,
          "add1_attr_by_OBJ");
    printf("  by_OBJ duplicate: %s\n",
           X509at_add1_attr_by_OBJ(&sk, OBJ_nid2obj(NID_localKeyID), V_ASN1_NULL, NULL, -1)
                   == NULL
               ? "refused"
               : "added");
    errors();
    check(X509at_add1_attr_by_txt(&sk, "contentType", V_ASN1_OBJECT,
                                  (const unsigned char *)OBJ_nid2obj(NID_pkcs7_data), -1)
              != NULL,
          "add1_attr_by_txt");
    printf("  by_txt duplicate: %s\n",
           X509at_add1_attr_by_txt(&sk, "contentType", V_ASN1_NULL, NULL, -1) == NULL
               ? "refused"
               : "added");
    printf("  by_txt unknown: %s\n",
           X509at_add1_attr_by_txt(&sk, "nope", V_ASN1_NULL, NULL, -1) == NULL ? "refused"
                                                                               : "added");
    errors();
    printf("  NULL arguments: %s %s %s\n", X509at_add1_attr(NULL, a) == NULL ? "NULL" : "?",
           X509at_add1_attr(&sk, NULL) == NULL ? "NULL" : "?",
           X509at_add1_attr_by_OBJ(&sk, NULL, V_ASN1_NULL, NULL, -1) == NULL ? "NULL" : "?");
    errors();
    printf("  count %d\n", X509at_get_attr_count(sk));
    printf("  by NID email %d friendly %d after 0 %d unknown NID %d none %d\n",
           X509at_get_attr_by_NID(sk, NID_pkcs9_emailAddress, -1),
           X509at_get_attr_by_NID(sk, NID_friendlyName, -1),
           X509at_get_attr_by_NID(sk, NID_pkcs9_emailAddress, 0),
           X509at_get_attr_by_NID(sk, 99999, -1),
           X509at_get_attr_by_NID(sk, NID_commonName, -5));
    printf("  by OBJ %d on NULL %d\n", X509at_get_attr_by_OBJ(sk, email, -10),
           X509at_get_attr_by_OBJ(NULL, email, -1));
    got = X509at_get_attr(sk, 1);
    obj("get_attr 1", got != NULL ? X509_ATTRIBUTE_get0_object(got) : NULL);
    printf("  get_attr 9 %s -1 %s NULL %s\n", X509at_get_attr(sk, 9) == NULL ? "NULL" : "?",
           X509at_get_attr(sk, -1) == NULL ? "NULL" : "?",
           X509at_get_attr(NULL, 0) == NULL ? "NULL" : "?");
    errors();
    data = X509at_get0_data_by_OBJ(sk, email, -1, V_ASN1_IA5STRING);
    printf("  get0_data email -1: %s\n", data != NULL ? (char *)ASN1_STRING_get0_data(data) : "NULL");
    data = X509at_get0_data_by_OBJ(sk, email, -2, V_ASN1_IA5STRING);
    printf("  get0_data email -2: %s\n", data != NULL ? "found" : "NULL");
    data = X509at_get0_data_by_OBJ(sk, email, -3, V_ASN1_IA5STRING);
    printf("  get0_data email -3: %s\n", data != NULL ? "found" : "NULL");
    data = X509at_get0_data_by_OBJ(sk, email, -1, V_ASN1_UTF8STRING);
    printf("  get0_data email as UTF8: %s\n", data != NULL ? "found" : "NULL");
    errors();
    /* A second email attribute (added unchecked through a copy at the stack) makes -2 fail. */
    sk_X509_ATTRIBUTE_push(sk, X509_ATTRIBUTE_dup(a));
    data = X509at_get0_data_by_OBJ(sk, email, -2, V_ASN1_IA5STRING);
    printf("  get0_data email -2 with two: %s\n", data != NULL ? "found" : "NULL");
    got = X509at_delete_attr(sk, 0);
    check(got != NULL && X509at_get_attr_count(sk) == 4, "delete_attr");
    X509_ATTRIBUTE_free(got);
    printf("  delete 7 %s NULL %s\n", X509at_delete_attr(sk, 7) == NULL ? "NULL" : "?",
           X509at_delete_attr(NULL, 0) == NULL ? "NULL" : "?");
    errors();
    sk_X509_ATTRIBUTE_pop_free(sk, X509_ATTRIBUTE_free);
    X509_ATTRIBUTE_free(a);
}

static void test_sig(void)
{
    X509_SIG *s = X509_SIG_new();
    X509_ALGOR *alg = NULL;
    ASN1_OCTET_STRING *dg = NULL;
    const X509_ALGOR *calg = NULL;
    const ASN1_OCTET_STRING *cdg = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    int n;

    check(s != NULL, "X509_SIG_new");
    X509_SIG_getm(s, &alg, &dg);
    check(alg != NULL && dg != NULL, "getm");
    X509_ALGOR_set_md(alg, EVP_sha256());
    ASN1_OCTET_STRING_set(dg, (const unsigned char *)"0123456789abcdef0123456789abcdef", 32);
    n = i2d_X509_SIG(s, &der);
    check(n > 0, "i2d_X509_SIG");
    hex("DigestInfo", der, n);
    p = der;
    {
        X509_SIG *r = d2i_X509_SIG(NULL, &p, n);

        check(r != NULL && p == der + n, "d2i_X509_SIG");
        X509_SIG_get0(r, &calg, &cdg);
        obj("algorithm", calg != NULL ? calg->algorithm : NULL);
        printf("  digest length %d\n", cdg != NULL ? ASN1_STRING_length(cdg) : -1);
        X509_SIG_get0(r, NULL, NULL);
        X509_SIG_free(r);
    }
    OPENSSL_free(der);
    printf("  item %s\n", ASN1_ITEM_rptr(X509_SIG)->sname);
    X509_SIG_free(s);
    errors();
}

static void p8_info(const char *label, const PKCS8_PRIV_KEY_INFO *p8)
{
    const ASN1_OBJECT *o = NULL;
    const unsigned char *pk = NULL;
    int pklen = -1;
    const X509_ALGOR *pa = NULL;

    printf("  %s: get0 %d", label, PKCS8_pkey_get0(&o, &pk, &pklen, &pa, p8));
    printf(" pklen %d attrs %d\n", pklen, X509at_get_attr_count(PKCS8_pkey_get0_attrs(p8)));
    obj("  algorithm", o);
    if (pa != NULL)
        printf("    ptype %d\n", pa->parameter != NULL ? pa->parameter->type : -1);
    DER("  der", i2d_PKCS8_PRIV_KEY_INFO, p8);
}

static void decode_p8(const char *label, const unsigned char *der, long n)
{
    const unsigned char *p = der;
    PKCS8_PRIV_KEY_INFO *r = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, n);

    printf("  %s: %s consumed %ld\n", label, r == NULL ? "fails" : "ok", (long)(p - der));
    errors();
    if (r != NULL)
        p8_info(label, r);
    PKCS8_PRIV_KEY_INFO_free(r);
}

static void test_p8(void)
{
    PKCS8_PRIV_KEY_INFO *p8 = PKCS8_PRIV_KEY_INFO_new();
    unsigned char *key = OPENSSL_malloc(4);
    unsigned char *der = NULL;
    int n;

    check(p8 != NULL, "PKCS8_PRIV_KEY_INFO_new");
    p8_info("empty", p8);
    memcpy(key, "\x02\x01\x05\x00", 4);
    check(PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_rsaEncryption), 0, V_ASN1_NULL, NULL, key, 4) == 1,
          "pkey_set0");
    p8_info("set", p8);
    printf("  set0 version 2: %d, version -1: %d\n",
           PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_rsaEncryption), 2, V_ASN1_NULL, NULL, NULL, 0),
           PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_dsa), -1, V_ASN1_UNDEF, NULL, NULL, 0));
    p8_info("after", p8);
    printf("  get0 with nothing asked: %d\n", PKCS8_pkey_get0(NULL, NULL, NULL, NULL, p8));
    check(PKCS8_add_keyusage(p8, KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT) == 1,
          "add_keyusage");
    printf("  add_keyusage again: %d\n", PKCS8_add_keyusage(p8, 0x1ff));
    printf("  by_NID friendlyName: %d\n",
           PKCS8_pkey_add1_attr_by_NID(p8, NID_friendlyName, MBSTRING_ASC,
                                       (const unsigned char *)"key", -1));
    printf("  by_OBJ localKeyID: %d again %d\n",
           PKCS8_pkey_add1_attr_by_OBJ(p8, OBJ_nid2obj(NID_localKeyID), V_ASN1_OCTET_STRING,
                                       (const unsigned char *)"\x01\x02", 2),
           PKCS8_pkey_add1_attr_by_OBJ(p8, OBJ_nid2obj(NID_localKeyID), V_ASN1_NULL, NULL, -1));
    {
        X509_ATTRIBUTE *at = X509_ATTRIBUTE_create(NID_pkcs9_unstructuredName, V_ASN1_NULL, NULL);

        printf("  add1_attr: %d again %d\n", PKCS8_pkey_add1_attr(p8, at),
               PKCS8_pkey_add1_attr(p8, at));
        X509_ATTRIBUTE_free(at);
    }
    errors();
    {
        const ASN1_TYPE *t = PKCS8_get_attr(p8, NID_key_usage);

        printf("  get_attr key usage: type %d", t != NULL ? t->type : -1);
        if (t != NULL && t->type == V_ASN1_BIT_STRING)
            hex("", t->value.bit_string->data, t->value.bit_string->length);
        else
            printf("\n");
        printf("  get_attr none: %s\n",
               PKCS8_get_attr(p8, NID_commonName) == NULL ? "NULL" : "found");
    }
    p8_info("with attributes", p8);

    n = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
    decode_p8("decoded", der, n);
    OPENSSL_free(der);
    {
        /* Version 1 (0), 2 (1), 3 (2), and 1 with a public key. */
        static const unsigned char v1[] = {
            0x30, 0x10, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            0x04, 0x04, 0x04, 0x02, 0x01, 0x02,
        };
        static const unsigned char v2pub[] = {
            0x30, 0x15, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            0x04, 0x04, 0x04, 0x02, 0x01, 0x02, 0x81, 0x03, 0x00, 0x0a, 0x0b,
        };
        static const unsigned char v3[] = {
            0x30, 0x10, 0x02, 0x01, 0x02, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            0x04, 0x04, 0x04, 0x02, 0x01, 0x02,
        };
        static const unsigned char v1pub[] = {
            0x30, 0x15, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            0x04, 0x04, 0x04, 0x02, 0x01, 0x02, 0x81, 0x03, 0x00, 0x0a, 0x0b,
        };
        static const unsigned char vneg[] = {
            0x30, 0x10, 0x02, 0x01, 0xff, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            0x04, 0x04, 0x04, 0x02, 0x01, 0x02,
        };
        static const unsigned char attrs[] = {
            0x30, 0x1d, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            0x04, 0x04, 0x04, 0x02, 0x01, 0x02, 0xa0, 0x0b, 0x30, 0x09, 0x06, 0x03,
            0x55, 0x1d, 0x0f, 0x31, 0x02, 0x05, 0x00,
        };

        decode_p8("v1", v1, sizeof(v1));
        decode_p8("v2 with a public key", v2pub, sizeof(v2pub));
        decode_p8("v3", v3, sizeof(v3));
        decode_p8("v1 with a public key", v1pub, sizeof(v1pub));
        decode_p8("version -1", vneg, sizeof(vneg));
        decode_p8("attributes", attrs, sizeof(attrs));
        decode_p8("cut", v1, sizeof(v1) - 1);
    }
    {
        BIO *b = BIO_new(BIO_s_mem());
        PKCS8_PRIV_KEY_INFO *r;
        FILE *fp = tmpfile();

        printf("  i2d bio %d\n", i2d_PKCS8_PRIV_KEY_INFO_bio(b, p8));
        r = d2i_PKCS8_PRIV_KEY_INFO_bio(b, NULL);
        check(r != NULL, "d2i_PKCS8_PRIV_KEY_INFO_bio");
        PKCS8_PRIV_KEY_INFO_free(r);
        r = d2i_PKCS8_PRIV_KEY_INFO_bio(b, NULL);
        printf("  from an empty BIO: %s\n", r == NULL ? "fails" : "ok");
        errors();
        BIO_free(b);
        if (fp != NULL) {
            printf("  i2d fp %d\n", i2d_PKCS8_PRIV_KEY_INFO_fp(fp, p8));
            rewind(fp);
            r = NULL;
            check(d2i_PKCS8_PRIV_KEY_INFO_fp(fp, &r) == r && r != NULL,
                  "d2i_PKCS8_PRIV_KEY_INFO_fp");
            if (r != NULL)
                p8_info("from the file", r);
            PKCS8_PRIV_KEY_INFO_free(r);
            fclose(fp);
        }
    }
    printf("  item %s\n", ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO)->sname);
    PKCS8_PRIV_KEY_INFO_free(p8);
    errors();
}

int main(void)
{
    test_algor();
    test_attribute();
    test_x509at();
    test_sig();
    test_p8();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
