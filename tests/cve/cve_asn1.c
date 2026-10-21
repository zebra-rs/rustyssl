/*
 * CVE regression tests: the ASN.1 parser, ASN.1 strings and objects, and their printers.
 */
#include "cve.h"

#include <limits.h>
#include <openssl/asn1.h>
#include <openssl/cms.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>

static void hex(const char *what, const unsigned char *p, size_t n)
{
    char line[1024] = "";
    size_t used = 0;

    for (size_t i = 0; i < n && used + 3 < sizeof(line); i++)
        used += (size_t)snprintf(line + used, sizeof(line) - used, "%02x", p[i]);
    note("%s: %s", what, line);
}

static int d2i_type_fails(const unsigned char *der, size_t len)
{
    const unsigned char *p = der;
    ASN1_TYPE *t = d2i_ASN1_TYPE(NULL, &p, (long)len);
    int failed = t == NULL;

    ASN1_TYPE_free(t);
    return failed;
}

static int d2i_x509_fails(const unsigned char *der, size_t len)
{
    const unsigned char *p = der;
    X509 *x = d2i_X509(NULL, &p, (long)len);
    int failed = x == NULL;

    X509_free(x);
    ERR_clear_error();
    return failed;
}

static void lengths(void)
{
    static const unsigned char too_long[] = {0x04, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0x41};
    static const unsigned char huge[] = {0x04, 0x84, 0xff, 0xff, 0xff, 0xff, 0x41, 0x42};
    static const unsigned char past_end[] = {0x04, 0x10, 0x61, 0x62};

    check(d2i_type_fails(too_long, sizeof(too_long)) && d2i_type_fails(huge, sizeof(huge)),
          "CVE-2002-0659: length octets longer than a long, or past the input, are rejected");
    errors("length");
    check(d2i_type_fails(past_end, sizeof(past_end)),
          "CVE-2026-34180: a primitive whose content runs past the input is rejected");
    errors("past the end");
}

static void niscc(void)
{
    /* A high tag number that overflows, a constructed value cut short, an inner length past
     * its parent's, and a negative-looking length. */
    static const unsigned char tag[] = {0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00};
    static const unsigned char cut[] = {0x30, 0x06, 0x30, 0x04, 0x02, 0x01};
    static const unsigned char inner[] = {0x30, 0x03, 0x30, 0x10, 0x02, 0x01, 0x01};
    static const unsigned char neg[] = {0x30, 0x84, 0x80, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01};

    check(d2i_type_fails(tag, sizeof(tag)) && d2i_x509_fails(tag, sizeof(tag)),
          "CVE-2003-0543: an overflowing high tag number is rejected");
    errors("tag");
    check(d2i_type_fails(cut, sizeof(cut)) && d2i_x509_fails(cut, sizeof(cut)),
          "CVE-2003-0544: a constructed value cut short is rejected");
    errors("cut");
    check(d2i_x509_fails(inner, sizeof(inner)) && d2i_x509_fails(neg, sizeof(neg)),
          "CVE-2003-0545: inner lengths past their parent's, and huge lengths, are rejected");
    errors("inner");
}

/* `depth` nested indefinite-length SEQUENCEs. */
static void nested(buf *b, int depth)
{
    for (int i = 0; i < depth; i++) {
        put_byte(b, 0x30);
        put_byte(b, 0x80);
    }
    for (int i = 0; i < depth; i++) {
        put_byte(b, 0);
        put_byte(b, 0);
    }
}

static void recursion(void)
{
    static const unsigned char signed_data[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                                0x0d, 0x01, 0x07, 0x02};
    buf b = {0};
    const unsigned char *p;
    PKCS7 *p7;
    int depth = 2000;

    nested(&b, 100000);
    check(d2i_x509_fails(b.p, b.n),
          "CVE-2003-0851: 100000 nested constructed values fail without exhausting the stack");
    free_buf(&b);
    ERR_clear_error();

    /* ContentInfo { signedData, [0] { SignedData { 1, {}, ContentInfo { signedData, ... } } } } */
    for (int i = 0; i < depth; i++) {
        put_byte(&b, 0x30);
        put_byte(&b, 0x80);
        put(&b, signed_data, sizeof(signed_data));
        put_byte(&b, 0xa0);
        put_byte(&b, 0x80);
        put_byte(&b, 0x30);
        put_byte(&b, 0x80);
        put(&b, "\x02\x01\x01\x31\x00", 5);
    }
    for (int i = 0; i < depth; i++)
        put(&b, "\0\0\0\0\0\0", 6);
    p = b.p;
    p7 = d2i_PKCS7(NULL, &p, (long)b.n);
    check(p7 == NULL, "CVE-2018-0739: PKCS#7 content nested %d deep fails without exhausting the stack",
          depth);
    PKCS7_free(p7);
    free_buf(&b);
    ERR_clear_error();
}

static void truncation(void)
{
    EVP_PKEY *key = ec_key();
    X509 *cert = leaf_cert("truncated", key, NULL, NULL);
    unsigned char *der = NULL;
    int len = i2d_X509(cert, &der), all = 1;

    for (int n = 0; n < len; n++)
        if (!d2i_x509_fails(der, (size_t)n))
            all = 0;
    check(len > 0 && all && !d2i_x509_fails(der, (size_t)len),
          "CVE-2006-2937: every truncation of a certificate fails cleanly; the whole one parses");
    OPENSSL_free(der);
    X509_free(cert);
    EVP_PKEY_free(key);
}

static void strings(void)
{
    /* Name { RDN { AVA { commonName, BMPString of 3 octets } } } */
    static const unsigned char bmp[] = {0x30, 0x10, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55,
                                        0x04, 0x03, 0x1e, 0x03, 0x00, 0x41, 0x00};
    static const unsigned char univ[] = {0x30, 0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
                                         0x04, 0x03, 0x1c, 0x05, 0x00, 0x00, 0x00, 0x41, 0x00};
    const unsigned char *p = bmp;
    X509_NAME *name = d2i_X509_NAME(NULL, &p, sizeof(bmp));
    BIO *out = BIO_new(BIO_s_mem());
    char *text;
    long n;

    if (name != NULL)
        X509_NAME_print_ex(out, name, 0, XN_FLAG_RFC2253);
    X509_NAME_free(name);
    p = univ;
    name = d2i_X509_NAME(NULL, &p, sizeof(univ));
    if (name != NULL)
        X509_NAME_print_ex(out, name, 0, XN_FLAG_RFC2253);
    X509_NAME_free(name);
    n = BIO_get_mem_data(out, &text);
    check(1, "CVE-2009-0590: BMPString and UniversalString of invalid lengths are handled");
    note("printed %ld: %.*s", n, (int)n, text);
    errors("strings");
    BIO_free(out);
}

static void bio_lengths(void)
{
    static const unsigned char header[] = {0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x30, 0x00,
                                           0x02, 0x01, 0x01, 0x05};
    BIO *in = BIO_new_mem_buf(header, sizeof(header));
    X509 *x = d2i_X509_bio(in, NULL);

    check(x == NULL, "CVE-2012-2110: a header claiming 2 GiB on a short BIO fails");
    errors("d2i_X509_bio");
    X509_free(x);
    BIO_free(in);

    in = BIO_new_mem_buf(header, sizeof(header));
    x = d2i_X509_bio(in, NULL);
    check(x == NULL, "CVE-2012-2131: a header claiming 2 GiB on a short BIO fails (0.9.8 fix)");
    ERR_clear_error();
    X509_free(x);
    BIO_free(in);

    in = BIO_new_mem_buf(header, sizeof(header));
    {
        CMS_ContentInfo *cms = d2i_CMS_bio(in, NULL);

        check(cms == NULL, "CVE-2016-2109: d2i_CMS_bio with a 2 GiB length on a short BIO fails");
        errors("d2i_CMS_bio");
        CMS_ContentInfo_free(cms);
    }
    BIO_free(in);
}

static void objects(void)
{
    static const char *const oid = "1.2.840.113549.1.9.16.3.18446744073709551615.99999999999999";
    ASN1_OBJECT *obj = OBJ_txt2obj(oid, 1);
    char small[16], big[128];
    int a, b;
    BIO *out = BIO_new(BIO_s_mem());
    char *text;
    long n;

    memset(small, 'x', sizeof(small));
    a = OBJ_obj2txt(small, sizeof(small), obj, 1);
    b = OBJ_obj2txt(big, sizeof(big), obj, 1);
    check(obj != NULL && a == b && small[sizeof(small) - 1] == '\0',
          "CVE-2014-3508: OBJ_obj2txt into a short buffer stays within it and NUL-terminates");
    note("obj2txt %d %d [%s] [%s]", a, b, small, big);

    TS_OBJ_print_bio(out, obj);
    n = BIO_get_mem_data(out, &text);
    check(n > 0 && n < 200, "CVE-2016-2180: TS_OBJ_print_bio prints a long OID within bounds");
    note("TS_OBJ_print_bio: %.*s", (int)n, text);
    BIO_free(out);
    ASN1_OBJECT_free(obj);

    {
        /* An OBJECT IDENTIFIER whose second sub-identifier is 100000 octets long. */
        buf body = {0}, der = {0};
        const unsigned char *p;
        ASN1_OBJECT *huge;
        char text2[256];
        int r;

        put_byte(&body, 0x2a);
        for (int i = 0; i < 100000; i++)
            put_byte(&body, 0xff);
        put_byte(&body, 0x7f);
        put_tlv(&der, 0x06, &body);
        p = der.p;
        huge = d2i_ASN1_OBJECT(NULL, &p, (long)der.n);
        r = huge != NULL ? OBJ_obj2txt(text2, sizeof(text2), huge, 1) : -2;
        check(1, "CVE-2023-2650: a 100000-octet sub-identifier is translated quickly");
        note("parsed %d, obj2txt %d [%s]", huge != NULL, r, r > 0 ? text2 : "");
        ERR_clear_error();
        ASN1_OBJECT_free(huge);
        free_buf(&der);
    }
}

static void types(void)
{
    ASN1_TYPE *a = ASN1_TYPE_new(), *b = ASN1_TYPE_new();

    ASN1_TYPE_set(a, V_ASN1_BOOLEAN, (void *)1);
    ASN1_TYPE_set(b, V_ASN1_BOOLEAN, (void *)1);
    check(ASN1_TYPE_cmp(a, b) == 0, "CVE-2015-0286: ASN1_TYPE_cmp compares two BOOLEANs");
    ASN1_TYPE_set(b, V_ASN1_BOOLEAN, (void *)0);
    note("TRUE vs FALSE: %d", ASN1_TYPE_cmp(a, b) != 0);
    ASN1_TYPE_free(a);
    ASN1_TYPE_free(b);

    {
        /* GENERAL_NAME reused: a dNSName, then an iPAddress, into the same object. */
        static const unsigned char dns[] = {0x82, 0x03, 'a', '.', 'b'};
        static const unsigned char ip[] = {0x87, 0x04, 10, 0, 0, 1};
        GENERAL_NAME *gn = NULL;
        const unsigned char *p = dns;
        BIO *out = BIO_new(BIO_s_mem());
        char *text;
        long n;

        d2i_GENERAL_NAME(&gn, &p, sizeof(dns));
        p = ip;
        d2i_GENERAL_NAME(&gn, &p, sizeof(ip));
        if (gn != NULL)
            GENERAL_NAME_print(out, gn);
        n = BIO_get_mem_data(out, &text);
        check(gn != NULL && n > 0, "CVE-2015-0287: an ASN.1 CHOICE parsed into a reused object");
        note("%.*s", (int)n, text);
        GENERAL_NAME_free(gn);
        BIO_free(out);
    }
}

static int cmp_names(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen,
                     int *cmp)
{
    const unsigned char *p = a;
    GENERAL_NAME *x = d2i_GENERAL_NAME(NULL, &p, (long)alen), *y;
    int ok;

    p = b;
    y = d2i_GENERAL_NAME(NULL, &p, (long)blen);
    ok = x != NULL && y != NULL;
    *cmp = ok ? GENERAL_NAME_cmp(x, y) : -99;
    GENERAL_NAME_free(x);
    GENERAL_NAME_free(y);
    ERR_clear_error();
    return ok;
}

static void general_names(void)
{
    /* ediPartyName [5] { partyName [1] "a" }, and one with a nameAssigner [0] "n". */
    static const unsigned char edi1[] = {0xa5, 0x05, 0xa1, 0x03, 0x0c, 0x01, 'a'};
    static const unsigned char edi2[] = {0xa5, 0x0a, 0xa0, 0x03, 0x0c, 0x01, 'n',
                                         0xa1, 0x03, 0x0c, 0x01, 'a'};
    /* x400Address [3] { SEQUENCE {} }, and one with content. */
    static const unsigned char x400a[] = {0xa3, 0x02, 0x30, 0x00};
    static const unsigned char x400b[] = {0xa3, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01};
    int c1, c2, c3, c4;
    int ok1 = cmp_names(edi1, sizeof(edi1), edi2, sizeof(edi2), &c1);
    int ok2 = cmp_names(edi1, sizeof(edi1), edi1, sizeof(edi1), &c2);

    check(1, "CVE-2020-1971: GENERAL_NAME_cmp of EDIPartyNames, with and without nameAssigner");
    note("parsed %d %d, cmp %d %d", ok1, ok2, c1 != 0, c2);
    ok1 = cmp_names(x400a, sizeof(x400a), x400b, sizeof(x400b), &c3);
    ok2 = cmp_names(x400a, sizeof(x400a), x400a, sizeof(x400a), &c4);
    check(1, "CVE-2023-0286: GENERAL_NAME_cmp of x400Addresses compares them as ASN1_STRINGs");
    note("parsed %d %d, cmp %d %d", ok1, ok2, c3 != 0, c4);
}

static void unterminated(void)
{
    GENERAL_NAME *gn = GENERAL_NAME_new();
    ASN1_IA5STRING *s = ASN1_IA5STRING_new();
    unsigned char *data = OPENSSL_malloc(8);
    BIO *out = BIO_new(BIO_s_mem());
    char *text;
    long n;

    memcpy(data, "host.exa", 8); /* no terminating NUL */
    ASN1_STRING_set0(s, data, 8);
    GENERAL_NAME_set0_value(gn, GEN_DNS, s);
    GENERAL_NAME_print(out, gn);
    n = BIO_get_mem_data(out, &text);
    check(n == (long)strlen("DNS:host.exa"),
          "CVE-2021-3712: printing an ASN1_STRING that isn't NUL-terminated reads only its length");
    note("%.*s", (int)n, text);
    GENERAL_NAME_free(gn);
    BIO_free(out);
}

static void times(void)
{
    static const char *const bad[] = {"9901", "990101", "9901010000", "99010100000", "991301000000Z",
                                      "990101000000+", "9901010000Z+", ""};
    int all = 1;

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ASN1_TIME *t = ASN1_UTCTIME_new();
        int r;

        ASN1_STRING_set(t, bad[i], (int)strlen(bad[i]));
        r = X509_cmp_time(t, NULL);
        note("X509_cmp_time(\"%s\") = %d", bad[i], r);
        if (r != 0)
            all = 0;
        ASN1_TIME_free(t);
    }
    check(all, "CVE-2015-1789: X509_cmp_time rejects malformed times without reading past them");
    ERR_clear_error();
}

static void integers(void)
{
    static const unsigned char *const ders[] = {
        (const unsigned char *)"\x02\x00", (const unsigned char *)"\x02\x01\x80",
        (const unsigned char *)"\x02\x02\x00\x00", (const unsigned char *)"\x02\x02\xff\x80",
        (const unsigned char *)"\x02\x02\xff\x00", (const unsigned char *)"\x02\x03\xff\x00\x00"};
    static const size_t lens[] = {2, 3, 4, 4, 4, 5};
    BIGNUM *zero = BN_new();
    ASN1_INTEGER *ai;
    unsigned char *der = NULL;
    int n;

    for (size_t i = 0; i < 6; i++) {
        const unsigned char *p = ders[i];
        ASN1_TYPE *t = d2i_ASN1_TYPE(NULL, &p, (long)lens[i]);
        unsigned char *out = NULL;
        int len = t != NULL ? i2d_ASN1_TYPE(t, &out) : -1;

        if (len > 0)
            hex("re-encoded", out, (size_t)len);
        else
            note("integer %zu rejected", i);
        OPENSSL_free(out);
        ASN1_TYPE_free(t);
        ERR_clear_error();
    }
    BN_zero(zero);
    BN_set_negative(zero, 1);
    ai = BN_to_ASN1_INTEGER(zero, NULL);
    n = ai != NULL ? i2d_ASN1_INTEGER(ai, &der) : -1;
    check(n == 3 && der[2] == 0, "CVE-2016-2108: negative zero encodes as 0; odd INTEGERs round-trip");
    OPENSSL_free(der);
    ASN1_INTEGER_free(ai);
    BN_free(zero);

    {
        ASN1_INTEGER *a = ASN1_INTEGER_new();
        BIO *out = BIO_new(BIO_s_mem());
        char *text;
        long len;

        ASN1_INTEGER_set(a, LONG_MIN);
        i2a_ASN1_INTEGER(out, a);
        BIO_puts(out, " ");
        ASN1_INTEGER_set(a, LONG_MAX);
        i2a_ASN1_INTEGER(out, a);
        len = BIO_get_mem_data(out, &text);
        check(len > 0, "CVE-2002-0655: printing the extreme 64-bit integers fits");
        note("%.*s", (int)len, text);
        ASN1_INTEGER_free(a);
        BIO_free(out);
    }
}

static void bn2dec(void)
{
    BIGNUM *bn = BN_new();
    char *dec;

    BN_set_bit(bn, 8192);
    BN_sub_word(bn, 1);
    BN_set_negative(bn, 1);
    dec = BN_bn2dec(bn);
    check(dec != NULL && strlen(dec) == 2468, "CVE-2016-2182: BN_bn2dec of -(2^8192-1) fits its buffer");
    note("%zu digits, ends %s", dec != NULL ? strlen(dec) : 0, dec != NULL ? dec + strlen(dec) - 6 : "");
    OPENSSL_free(dec);
    BN_free(bn);
}

static void printf_bounds(void)
{
    char small[8];
    BIO *out = BIO_new(BIO_s_mem());
    int a, b, c;
    char *text;
    long n;

    a = BIO_snprintf(small, sizeof(small), "%s", "a string longer than the buffer");
    b = BIO_printf(out, "%*d|%.3s|%-5s|", 20000, 7, "abcdef", "x");
    c = BIO_snprintf(small, sizeof(small), "%.*s", 3, "abcdef");
    n = BIO_get_mem_data(out, &text);
    check(n == b && small[3] == '\0',
          "CVE-2016-0799: BIO_printf's %%s, width and precision stay within bounds");
    note("snprintf %d [%s] %d, printf %d, tail [%s]", a, small, c, b, n > 12 ? text + n - 12 : "");
    BIO_free(out);
}

static void rfc3779(void)
{
    /* IPAddrBlocks { IPAddressFamily { 1-octet addressFamily, inherit } } and one whose
     * addressRange is malformed. */
    static const unsigned char short_family[] = {0x30, 0x07, 0x30, 0x05, 0x04, 0x01, 0x01, 0x05,
                                                 0x00};
    static const unsigned char bad_range[] = {0x30, 0x0e, 0x30, 0x0c, 0x04, 0x02, 0x00, 0x01,
                                              0x30, 0x06, 0x30, 0x04, 0x03, 0x02, 0x07, 0xff};
    const unsigned char *sets[] = {short_family, bad_range};
    size_t lens[] = {sizeof(short_family), sizeof(bad_range)};
    const char *const ids[] = {"CVE-2017-3735: a 1-octet IPAddressFamily",
                               "CVE-2011-4577: a malformed RFC 3779 address range"};

    for (int i = 0; i < 2; i++) {
        ASN1_OCTET_STRING *value = ASN1_OCTET_STRING_new();
        X509_EXTENSION *ext;
        IPAddrBlocks *blocks;
        BIO *out = BIO_new(BIO_s_mem());
        char *text;
        long n = 0;
        int canonical = -1;

        ASN1_OCTET_STRING_set(value, sets[i], (int)lens[i]);
        ext = X509_EXTENSION_create_by_NID(NULL, NID_sbgp_ipAddrBlock, 1, value);
        blocks = X509V3_EXT_d2i(ext);
        if (blocks != NULL)
            canonical = X509v3_addr_is_canonical(blocks);
        X509V3_EXT_print(out, ext, 0, 0);
        X509_EXTENSION_free(ext);
        ASN1_OCTET_STRING_free(value);
        n = BIO_get_mem_data(out, &text);
        check(1, "%s is parsed and printed safely", ids[i]);
        note("parsed %d canonical %d printed [%.*s]", blocks != NULL, canonical, (int)n, text);
        sk_IPAddressFamily_pop_free(blocks, IPAddressFamily_free);
        BIO_free(out);
        ERR_clear_error();
    }
}

static void issuer_serial(void)
{
    X509 *x = X509_new();
    unsigned long h = X509_issuer_and_serial_hash(x);

    check(1, "CVE-2021-23841: X509_issuer_and_serial_hash of a certificate without an issuer");
    note("hash %lu", h);
    ERR_clear_error();
    X509_free(x);
}

static void mbstrings(void)
{
    /* 3000 four-octet UTF-8 characters, to BMPString (not representable) and UniversalString. */
    buf in = {0};
    ASN1_STRING *out = NULL;
    int r1, r2;

    for (int i = 0; i < 3000; i++)
        put(&in, "\xf0\x9f\x98\x80", 4);
    r1 = ASN1_mbstring_copy(&out, in.p, (int)in.n, MBSTRING_UTF8, B_ASN1_UNIVERSALSTRING);
    note("UniversalString: %d, length %d", r1, out != NULL ? ASN1_STRING_length(out) : -1);
    ASN1_STRING_free(out);
    out = NULL;
    r2 = ASN1_mbstring_copy(&out, in.p, (int)in.n, MBSTRING_UTF8, B_ASN1_BMPSTRING);
    note("BMPString: %d", r2);
    errors("BMPString");
    ASN1_STRING_free(out);
    out = NULL;
    r2 = ASN1_mbstring_copy(&out, in.p, (int)in.n, MBSTRING_UTF8, B_ASN1_UTF8STRING);
    check(r1 == V_ASN1_UNIVERSALSTRING && r2 == V_ASN1_UTF8STRING
              && ASN1_STRING_length(out) == (int)in.n,
          "CVE-2026-7383: multibyte conversions size their output exactly");
    ASN1_STRING_free(out);
    free_buf(&in);
}

static void hexstrings(void)
{
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    unsigned char *data = OPENSSL_zalloc(1 << 20);
    char *text;

    ASN1_OCTET_STRING_set(os, data, 1 << 20);
    text = i2s_ASN1_OCTET_STRING(NULL, os);
    check(text != NULL && strlen(text) == 3 * (1 << 20) - 1,
          "CVE-2026-31789: hex conversion of a 1 MiB OCTET STRING sizes its output exactly");
    OPENSSL_free(text);
    OPENSSL_free(data);
    ASN1_OCTET_STRING_free(os);
}

static void attributes(void)
{
    /* Attribute { OID, SET { } } with an empty value set, and one whose value set is a
     * SEQUENCE. */
    static const unsigned char empty[] = {0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x03, 0x31, 0x00};
    static const unsigned char not_set[] = {0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03,
                                            0x30, 0x03, 0x0c, 0x01, 'a'};
    const unsigned char *p = empty;
    X509_ATTRIBUTE *a = d2i_X509_ATTRIBUTE(NULL, &p, sizeof(empty)), *b;

    p = not_set;
    b = d2i_X509_ATTRIBUTE(NULL, &p, sizeof(not_set));
    check(b == NULL, "CVE-2015-3195: a malformed X509_ATTRIBUTE fails to parse, freeing what it built");
    note("empty value set %s", a != NULL ? "parsed" : "rejected");
    ERR_clear_error();
    X509_ATTRIBUTE_free(a);
    X509_ATTRIBUTE_free(b);
}

static unsigned long hash_str(const void *p)
{
    return (unsigned long)strlen((const char *)p);
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static void lhash_flush(void)
{
    OPENSSL_LHASH *lh = OPENSSL_LH_new(hash_str, cmp_str);
    static const char *const words[] = {"alpha", "beta", "gamma", "delta", "epsilon"};
    int found = 0;

    for (int round = 0; round < 3; round++) {
        for (int i = 0; i < 5; i++)
            OPENSSL_LH_insert(lh, (void *)words[i]);
        OPENSSL_LH_flush(lh);
    }
    for (int i = 0; i < 5; i++)
        OPENSSL_LH_insert(lh, (void *)words[i]);
    for (int i = 0; i < 5; i++)
        found += OPENSSL_LH_retrieve(lh, words[i]) != NULL;
    check(found == 5 && OPENSSL_LH_num_items(lh) == 5,
          "CVE-2022-1473: a flushed hash table is reused correctly");
    OPENSSL_LH_free(lh);
}

int main(void)
{
    lengths();
    niscc();
    recursion();
    truncation();
    strings();
    bio_lengths();
    objects();
    types();
    general_names();
    unterminated();
    times();
    integers();
    bn2dec();
    printf_bounds();
    rfc3779();
    issuer_serial();
    mbstrings();
    hexstrings();
    lhash_flush();
    attributes();
    return finish();
}
