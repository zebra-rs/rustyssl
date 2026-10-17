/*
 * Conformance test for names (X509_NAME_new(3), X509_NAME_add_entry_by_txt(3),
 * X509_NAME_get_index_by_NID(3), X509_NAME_ENTRY_get_object(3), X509_NAME_print_ex(3),
 * X509_NAME_oneline, X509_NAME_cmp, X509_NAME_hash_ex, X509_NAME_digest), in TAP format: names
 * built every way (each entry function, each string type, multi-valued RDNs, entries put at
 * each place), their DER, hashes, and digests; comparisons that ignore case and spacing;
 * entries deleted with their RDNs renumbered; names decoded from crafted DER (multi-valued
 * RDNs, GeneralStrings of four-octet characters, BMP and Universal strings, empty and
 * malformed names); the one-line form into buffers of every size; and print_ex under each
 * separator, field-name, and string flag.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
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

static void hex(const char *label, const unsigned char *p, long n)
{
    long i;

    printf("  %s (%ld):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 && i > 0 ? "\n    " : " ", p[i]);
    printf("\n");
}

static BIO *out;

static void flush_out(void)
{
    char *data;
    long n = BIO_get_mem_data(out, &data);

    long i;

    /* Octets above 0x7f (print_ex without ESC_MSB) shown in hex, so the output is text. */
    for (i = 0; i < n; i++) {
        if ((unsigned char)data[i] > 0x7f)
            printf("<%02x>", (unsigned char)data[i]);
        else
            putchar(data[i]);
    }
    (void)BIO_reset(out);
}

static void show_der(const X509_NAME *n)
{
    unsigned char *der = NULL;
    int len = i2d_X509_NAME(n, &der);

    hex("der", der, len);
    OPENSSL_free(der);
}

static void show_oneline(const char *label, const X509_NAME *n)
{
    char *s = X509_NAME_oneline(n, NULL, 0);

    printf("  %s: %s\n", label, s != NULL ? s : "(null)");
    OPENSSL_free(s);
}

static void show_entries(const X509_NAME *n)
{
    int i, c = X509_NAME_entry_count(n);

    printf("  %d entries:", c);
    for (i = 0; i < c; i++) {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(n, i);
        const ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
        char obj[80];

        OBJ_obj2txt(obj, sizeof(obj), X509_NAME_ENTRY_get_object(e), 0);
        printf(" [%d %s type %d len %d]", X509_NAME_ENTRY_set(e), obj, ASN1_STRING_type(d),
               ASN1_STRING_length(d));
    }
    printf("\n");
}

static void show_print_ex(const X509_NAME *n)
{
    static const struct {
        unsigned long flags;
        const char *name;
    } styles[] = {
        { XN_FLAG_ONELINE, "ONELINE" },
        { XN_FLAG_RFC2253, "RFC2253" },
        { XN_FLAG_MULTILINE, "MULTILINE" },
        { XN_FLAG_COMPAT, "COMPAT" },
        { XN_FLAG_SEP_COMMA_PLUS, "SEP_COMMA_PLUS" },
        { XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_LN, "CPLUS_SPC|FN_LN" },
        { XN_FLAG_SEP_SPLUS_SPC | XN_FLAG_FN_OID | XN_FLAG_SPC_EQ, "SPLUS_SPC|FN_OID|SPC_EQ" },
        { XN_FLAG_SEP_MULTILINE | XN_FLAG_FN_SN | XN_FLAG_FN_ALIGN, "MULTILINE|FN_SN|ALIGN" },
        { XN_FLAG_SEP_MULTILINE | XN_FLAG_FN_LN | XN_FLAG_FN_ALIGN, "MULTILINE|FN_LN|ALIGN" },
        { XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_NONE, "FN_NONE" },
        { XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_DN_REV, "DN_REV" },
        { XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_DUMP_UNKNOWN_FIELDS, "DUMP_UNKNOWN" },
        { XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_SHOW_TYPE, "SHOW_TYPE" },
        { XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_DUMP_ALL | ASN1_STRFLGS_DUMP_DER, "DUMP_DER" },
        { XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_ESC_MSB, "ESC_MSB" },
        { XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_ESC_CTRL, "UTF8|CTRL" },
        { XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_ESC_QUOTE | ASN1_STRFLGS_ESC_2253, "QUOTE|2253" },
        { 0, "zero (no separator)" },
    };
    size_t i;

    for (i = 0; i < sizeof(styles) / sizeof(styles[0]); i++) {
        int r;

        printf("  %s: [", styles[i].name);
        r = X509_NAME_print_ex(out, n, 2, styles[i].flags);
        flush_out();
        printf("] %d\n", r);
    }
    printf("  print: [");
    printf("%d", X509_NAME_print(out, n, 0));
    flush_out();
    printf("]\n");
    ERR_clear_error();
}

static void show_hashes(const X509_NAME *n)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    int ok = -1;
    unsigned long h = X509_NAME_hash_ex(n, NULL, NULL, &ok);

    printf("  hash %08lx ok %d, old %08lx\n", h, ok, X509_NAME_hash_old(n));
    if (X509_NAME_digest(n, EVP_sha256(), md, &mdlen))
        hex("sha256", md, mdlen);
    else
        errors();
}

static void show(const char *label, const X509_NAME *n)
{
    printf("# %s\n", label);
    show_entries(n);
    show_der(n);
    show_oneline("oneline", n);
    show_hashes(n);
    show_print_ex(n);
}

static X509_NAME *built(void)
{
    X509_NAME *n = X509_NAME_new();
    static const unsigned char bmp[] = { 0x00, 'B', 0x00, 'm', 0x04, 0x10 };

    check(X509_NAME_add_entry_by_txt(n, "C", MBSTRING_ASC, (const unsigned char *)"JP", -1, -1, 0),
          "C by txt");
    check(X509_NAME_add_entry_by_txt(n, "ST", MBSTRING_UTF8,
                                     (const unsigned char *)"T\xc5\x8dky\xc5\x8d", -1, -1, 0),
          "ST in UTF-8");
    check(X509_NAME_add_entry_by_NID(n, NID_organizationName, V_ASN1_APP_CHOOSE,
                                     (const unsigned char *)"Example, Inc.", -1, -1, 0),
          "O by NID (app choose)");
    check(X509_NAME_add_entry_by_NID(n, NID_organizationalUnitName, V_ASN1_UTF8STRING,
                                     (const unsigned char *)"R&D+Ops", -1, -1, 0),
          "OU (UTF8String)");
    check(X509_NAME_add_entry_by_NID(n, NID_commonName, MBSTRING_ASC,
                                     (const unsigned char *)" Name  With   Spaces ", -1, -1, 0),
          "CN");
    check(X509_NAME_add_entry_by_NID(n, NID_pkcs9_emailAddress, MBSTRING_ASC,
                                     (const unsigned char *)"Root@Example.COM", -1, -1, -1),
          "email in the same RDN");
    check(X509_NAME_add_entry_by_txt(n, "1.2.3.4.5", V_ASN1_PRINTABLESTRING,
                                     (const unsigned char *)"an OID", -1, -1, 0),
          "an unknown OID");
    check(X509_NAME_add_entry_by_txt(n, "2.5.4.41", MBSTRING_BMP, bmp, sizeof(bmp), 1, 0),
          "a BMP entry at 1, in a new RDN");
    check(X509_NAME_add_entry_by_txt(n, "L", V_ASN1_IA5STRING,
                                     (const unsigned char *)"line\nfeed\x01\x7f\xff", 9, 0, 0),
          "an IA5 entry at 0 with control octets");
    check(X509_NAME_add_entry_by_txt(n, "serialNumber", MBSTRING_ASC,
                                     (const unsigned char *)"42", -1, 3, -1),
          "joining the RDN before 3");
    check(X509_NAME_add_entry_by_txt(n, "street", MBSTRING_ASC,
                                     (const unsigned char *)"Main St", -1, 2, 1),
          "joining the RDN at 2");
    return n;
}

static void test_build(void)
{
    X509_NAME *n = built(), *d, *set = NULL;
    X509_NAME_ENTRY *e;
    char buf[64];
    int i;

    show("built", n);
    printf("  index of CN %d, after it %d, of O %d, unknown nid %d, by OBJ C %d\n",
           X509_NAME_get_index_by_NID(n, NID_commonName, -1),
           X509_NAME_get_index_by_NID(n, NID_commonName,
                                      X509_NAME_get_index_by_NID(n, NID_commonName, -1)),
           X509_NAME_get_index_by_NID(n, NID_organizationName, -5),
           X509_NAME_get_index_by_NID(n, 99999, -1),
           X509_NAME_get_index_by_OBJ(n, OBJ_nid2obj(NID_countryName), -1));
    for (i = 0; i < 4; i++) {
        static const int lens[] = { 0, 1, 5, 64 };
        int r;

        memset(buf, '#', sizeof(buf));
        r = X509_NAME_get_text_by_NID(n, NID_commonName, buf, lens[i]);
        printf("  text CN into %d: %d [%.*s]\n", lens[i], r, r > 0 ? r : 0, buf);
    }
    printf("  text length CN %d, of none %d\n", X509_NAME_get_text_by_NID(n, NID_commonName, NULL, 0),
           X509_NAME_get_text_by_NID(n, NID_title, buf, sizeof(buf)));
    printf("  get_entry -1 %p, count %p, NULL %p, count(NULL) %d\n",
           (void *)X509_NAME_get_entry(n, -1), (void *)X509_NAME_get_entry(n, X509_NAME_entry_count(n)),
           (void *)X509_NAME_get_entry(NULL, 0), X509_NAME_entry_count(NULL));

    d = X509_NAME_dup(n);
    check(d != NULL && X509_NAME_cmp(n, d) == 0, "a copy compares equal");
    check(X509_NAME_set(&set, n) == 1 && X509_NAME_cmp(set, n) == 0, "X509_NAME_set");
    check(X509_NAME_set(&set, set) == 1, "X509_NAME_set to itself");

    /* Deleting entries renumbers the RDNs after a lone one. */
    e = X509_NAME_delete_entry(d, 0);
    printf("  deleted 0: %s\n", e != NULL ? "an entry" : "none");
    X509_NAME_ENTRY_free(e);
    show_entries(d);
    e = X509_NAME_delete_entry(d, 3);
    X509_NAME_ENTRY_free(e);
    show_entries(d);
    e = X509_NAME_delete_entry(d, X509_NAME_entry_count(d) - 1);
    X509_NAME_ENTRY_free(e);
    show_entries(d);
    printf("  delete -1 %p, past the end %p\n", (void *)X509_NAME_delete_entry(d, -1),
           (void *)X509_NAME_delete_entry(d, 50));
    show_oneline("after deletions", d);
    show_der(d);
    printf("  cmp after deletions %d %d\n", X509_NAME_cmp(n, d), X509_NAME_cmp(d, n));
    X509_NAME_free(d);
    X509_NAME_free(set);
    X509_NAME_free(n);
}

static void test_cmp(void)
{
    X509_NAME *a = X509_NAME_new(), *b = X509_NAME_new(), *c = X509_NAME_new(), *e = X509_NAME_new();

    printf("# comparisons\n");
    X509_NAME_add_entry_by_txt(a, "CN", MBSTRING_ASC, (const unsigned char *)"Hello   World", -1, -1, 0);
    X509_NAME_add_entry_by_txt(b, "CN", V_ASN1_PRINTABLESTRING, (const unsigned char *)"  hello world ", -1, -1, 0);
    X509_NAME_add_entry_by_txt(c, "CN", V_ASN1_UTF8STRING, (const unsigned char *)"hello worlds", -1, -1, 0);
    printf("  a~b %d, b~a %d, a~c %d, c~a %d, a~empty %d, empty~empty %d\n", X509_NAME_cmp(a, b),
           X509_NAME_cmp(b, a), X509_NAME_cmp(a, c), X509_NAME_cmp(c, a), X509_NAME_cmp(a, e),
           X509_NAME_cmp(e, e));
    printf("  NULLs: %d %d %d\n", X509_NAME_cmp(NULL, a), X509_NAME_cmp(a, NULL),
           X509_NAME_cmp(NULL, NULL));
    printf("  hashes: a %08lx b %08lx c %08lx empty %08lx\n", X509_NAME_hash_ex(a, NULL, NULL, NULL),
           X509_NAME_hash_ex(b, NULL, NULL, NULL), X509_NAME_hash_ex(c, NULL, NULL, NULL),
           X509_NAME_hash_ex(e, NULL, NULL, NULL));
    printf("  old hashes: a %08lx b %08lx\n", X509_NAME_hash_old(a), X509_NAME_hash_old(b));
    show("empty", e);
    X509_NAME_free(a);
    X509_NAME_free(b);
    X509_NAME_free(c);
    X509_NAME_free(e);
}

static void test_entries(void)
{
    X509_NAME_ENTRY *e = NULL, *r;
    unsigned char *der = NULL;
    const unsigned char *p;
    int len;

    printf("# entries\n");
    r = X509_NAME_ENTRY_create_by_txt(&e, "nosuchfield", MBSTRING_ASC, (const unsigned char *)"x", -1);
    printf("  unknown field: %p\n", (void *)r);
    errors();
    r = X509_NAME_ENTRY_create_by_NID(&e, 77777, MBSTRING_ASC, (const unsigned char *)"x", -1);
    printf("  unknown NID: %p\n", (void *)r);
    errors();
    r = X509_NAME_ENTRY_create_by_NID(&e, NID_countryName, MBSTRING_ASC, (const unsigned char *)"JPN", -1);
    printf("  C=JPN (too long): %p\n", (void *)r);
    errors();
    r = X509_NAME_ENTRY_create_by_NID(&e, NID_countryName, MBSTRING_ASC, (const unsigned char *)"JP", -1);
    check(r != NULL && r == e, "created into *ne");
    len = i2d_X509_NAME_ENTRY(e, &der);
    hex("entry der", der, len);
    p = der;
    r = d2i_X509_NAME_ENTRY(NULL, &p, len);
    check(r != NULL && p == der + len, "decoded back");
    X509_NAME_ENTRY_free(r);
    OPENSSL_free(der);
    printf("  set_object NULL %d, set_data NULL %d, set_data bytes NULL len 0 %d\n",
           X509_NAME_ENTRY_set_object(e, NULL), X509_NAME_ENTRY_set_data(NULL, 0, NULL, 0),
           X509_NAME_ENTRY_set_data(e, V_ASN1_UTF8STRING, NULL, 0));
    errors();
    X509_NAME_ENTRY_set_data(e, V_ASN1_UNDEF, (const unsigned char *)"keeps its type", -1);
    printf("  undef keeps type %d len %d\n", ASN1_STRING_type(X509_NAME_ENTRY_get_data(e)),
           ASN1_STRING_length(X509_NAME_ENTRY_get_data(e)));
    X509_NAME_ENTRY_set_data(e, V_ASN1_APP_CHOOSE, (const unsigned char *)"a*b", -1);
    printf("  app choose a*b type %d\n", ASN1_STRING_type(X509_NAME_ENTRY_get_data(e)));
    r = X509_NAME_ENTRY_dup(e);
    check(r != NULL && OBJ_cmp(X509_NAME_ENTRY_get_object(r), X509_NAME_ENTRY_get_object(e)) == 0,
          "an entry copied");
    printf("  getters of NULL: %p %p\n", (void *)X509_NAME_ENTRY_get_object(NULL),
           (void *)X509_NAME_ENTRY_get_data(NULL));
    X509_NAME_ENTRY_free(r);
    X509_NAME_ENTRY_free(e);
    X509_NAME_ENTRY_free(NULL);
    X509_NAME_free(NULL);
}

static void test_objects(void)
{
    X509_NAME *n = X509_NAME_new();
    X509_NAME_ENTRY *e = X509_NAME_ENTRY_new(), *r;
    ASN1_OBJECT *cn = OBJ_nid2obj(NID_commonName), *o = OBJ_nid2obj(NID_organizationName);
    unsigned char *der = NULL;
    char buf[16];
    int len;

    printf("# by object\n");
    printf("  new entry: object %d data length %d\n", OBJ_obj2nid(X509_NAME_ENTRY_get_object(e)),
           ASN1_STRING_length(X509_NAME_ENTRY_get_data(e)));
    len = ASN1_item_i2d((ASN1_VALUE *)e, &der, ASN1_ITEM_rptr(X509_NAME_ENTRY));
    printf("  empty entry der %d\n", len);
    errors();
    OPENSSL_free(der);
    der = NULL;
    r = X509_NAME_ENTRY_create_by_OBJ(&e, cn, MBSTRING_ASC, (const unsigned char *)"Alice", -1);
    check(r == e, "create_by_OBJ into *ne");
    len = ASN1_item_i2d((ASN1_VALUE *)e, &der, ASN1_ITEM_rptr(X509_NAME_ENTRY));
    hex("entry der", der, len);
    OPENSSL_free(der);
    r = X509_NAME_ENTRY_create_by_OBJ(NULL, NULL, MBSTRING_ASC, (const unsigned char *)"x", -1);
    printf("  NULL object: %p\n", (void *)r);
    errors();
    check(X509_NAME_add_entry(n, e, -1, 0) == 1, "add_entry appends a copy");
    check(X509_NAME_add_entry(n, e, 0, 1) == 1, "add_entry joins the first RDN");
    check(X509_NAME_add_entry(n, e, 99, -1) == 1, "add_entry past the end appends");
    printf("  add_entry NULL: %d\n", X509_NAME_add_entry(NULL, e, -1, 0));
    check(X509_NAME_add_entry_by_OBJ(n, o, MBSTRING_ASC, (const unsigned char *)"Org", -1, 1, 0) == 1,
          "add_entry_by_OBJ");
    printf("  add_entry_by_OBJ NULL object: %d\n",
           X509_NAME_add_entry_by_OBJ(n, NULL, MBSTRING_ASC, (const unsigned char *)"x", -1, -1, 0));
    errors();
    show("by object", n);
    printf("  text by OBJ: %d [%s]\n", X509_NAME_get_text_by_OBJ(n, o, buf, sizeof(buf)), buf);
    printf("  text by OBJ short: %d [%s]\n", X509_NAME_get_text_by_OBJ(n, cn, buf, 3), buf);
    printf("  text by OBJ length: %d\n", X509_NAME_get_text_by_OBJ(n, cn, NULL, 0));
    printf("  text by OBJ absent: %d\n",
           X509_NAME_get_text_by_OBJ(n, OBJ_nid2obj(NID_localityName), buf, sizeof(buf)));
    X509_NAME_ENTRY_free(e);
    X509_NAME_free(n);
}

static void decode(const char *label, const unsigned char *der, long len)
{
    const unsigned char *p = der;
    X509_NAME *n = d2i_X509_NAME(NULL, &p, len);

    if (n == NULL) {
        printf("# %s: no name\n", label);
        errors();
        return;
    }
    printf("  consumed %ld of %ld\n", (long)(p - der), len);
    show(label, n);
    X509_NAME_free(n);
}

static void test_decode(void)
{
    /* CN=a+O=b (one RDN), C=US */
    static const unsigned char multi[] = {
        0x30, 0x23, 0x31, 0x16, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, 'a', 'b', 'c',
        0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x01, 'O', 0x31, 0x09, 0x30, 0x07, 0x06,
        0x03, 0x55, 0x04, 0x06, 0x13, 0x00,
    };
    /* CN as a GeneralString of four-octet characters, then one with high octets. */
    static const unsigned char general[] = {
        0x30, 0x27, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x1b, 0x08, 0, 0, 0, 'h',
        0, 0, 0, 'i', 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x1b, 0x09, 'x', '/',
        '+', 0x80, 0xff, 0x00, '=', '\\', ',',
    };
    /* A UniversalString and a T61String with an accented octet. */
    static const unsigned char universal[] = {
        0x30, 0x2b, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x1c, 0x0c, 0, 0, 0, 'A',
        0, 0, 0x30, 0x42, 0, 0, 0, ' ', 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x14,
        0x09, 'Z', 0xfc, 'r', 'i', 'c', 'h', ' ', ' ', 'X',
    };
    static const unsigned char empty[] = { 0x30, 0x00 };
    static const unsigned char bad_set[] = { 0x30, 0x04, 0x31, 0x02, 0x05, 0x00 };
    static const unsigned char truncated[] = { 0x30, 0x0a, 0x31, 0x08, 0x30, 0x06, 0x06 };
    static const unsigned char trailing[] = { 0x30, 0x00, 0x30, 0x00 };
    static const unsigned char wrong_tag[] = { 0x31, 0x00 };

    decode("multi-valued", multi, sizeof(multi));
    decode("GeneralString", general, sizeof(general));
    decode("Universal and T61", universal, sizeof(universal));
    decode("empty", empty, sizeof(empty));
    decode("bad RDN", bad_set, sizeof(bad_set));
    decode("truncated", truncated, sizeof(truncated));
    decode("trailing (first one taken)", trailing, sizeof(trailing));
    decode("a SET, not a SEQUENCE", wrong_tag, sizeof(wrong_tag));
}

static void test_oneline(void)
{
    X509_NAME *n = built();
    char buf[128];
    int sizes[] = { 1, 2, 5, 10, 20, 40, 80, 128 };
    size_t i;
    const unsigned char *der;
    size_t derlen = 0;

    printf("# oneline\n");
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        char *r;

        memset(buf, '#', sizeof(buf));
        r = X509_NAME_oneline(n, buf, sizes[i]);
        printf("  into %d: %s [%s]\n", sizes[i], r == buf ? "buf" : "other", r != NULL ? r : "(null)");
    }
    printf("  into 0: %p\n", (void *)X509_NAME_oneline(n, buf, 0));
    {
        char *r = X509_NAME_oneline(NULL, NULL, 0);

        printf("  NULL name: [%s]\n", r);
        OPENSSL_free(r);
        r = X509_NAME_oneline(NULL, buf, 6);
        printf("  NULL name into 6: [%s]\n", r);
    }
    check(X509_NAME_get0_der(n, &der, &derlen) == 1, "get0_der");
    printf("  der length %zu\n", derlen);
    X509_NAME_free(n);
}

static void test_item(void)
{
    X509_NAME *n = built();
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;

    printf("# items\n");
    check(ASN1_item_print(out, (ASN1_VALUE *)n, 2, ASN1_ITEM_rptr(X509_NAME), NULL) == 1, "ASN1_item_print");
    flush_out();
    check(ASN1_item_digest(ASN1_ITEM_rptr(X509_NAME), EVP_sha1(), n, md, &mdlen) == 1, "ASN1_item_digest");
    hex("sha1", md, mdlen);
    check(ASN1_digest((i2d_of_void *)i2d_X509_NAME, EVP_md5(), (char *)n, md, &mdlen) == 1, "ASN1_digest");
    hex("md5", md, mdlen);
    printf("  print_ex_fp: [");
    fflush(stdout);
    printf("] %d\n", X509_NAME_print_ex_fp(stdout, n, 0, XN_FLAG_RFC2253));
    fflush(stdout);
    X509_NAME_free(n);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    out = BIO_new(BIO_s_mem());
    test_build();
    test_cmp();
    test_entries();
    test_objects();
    test_decode();
    test_oneline();
    test_item();
    BIO_free(out);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
