/*
 * Conformance test for the RFC 3779 extensions (X509v3_addr_add_inherit(3) and the rest of
 * the IP address and AS identifier functions), in TAP format: IP address blocks and AS
 * identifiers made from text (prefixes, ranges, SAFIs, inheritance, and the errors of bad
 * input), through the API (adding, canonical form, subsets, ranges), and decoded from DER
 * (out of order, odd lengths, unknown families), with their items.
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
#include <openssl/objects.h>
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

    fwrite(data, 1, (size_t)n, stdout);
    (void)BIO_reset(out);
}

static void print_out(const char *label)
{
    printf("  %s: [", label);
    flush_out();
    printf("]\n");
}

static void show_ext(const char *label, X509_EXTENSION *e)
{
    unsigned char *der = NULL;
    int len;

    if (e == NULL) {
        printf("  %s: none\n", label);
        errors();
        return;
    }
    len = i2d_X509_EXTENSION(e, &der);
    hex(label, der, len);
    OPENSSL_free(der);
    printf("  print: %d\n", X509V3_EXT_print(out, e, 0, 2));
    print_out("printed");
    printf("  multiline: %d\n", X509V3_EXT_print(out, e, X509V3_EXT_MULTILINE, 2));
    print_out("printed");
    errors();
}

/* An extension of `nid` made from `text` through its method's v2i. */
static void make(const char *label, int nid, const char *text)
{
    const X509V3_EXT_METHOD *m = X509V3_EXT_get_nid(nid);
    STACK_OF(CONF_VALUE) *in = X509V3_parse_list(text);
    void *v = m->v2i(m, NULL, in);
    X509_EXTENSION *e = v == NULL ? NULL : X509V3_EXT_i2d(nid, 0, v);

    sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
    printf("# %s\n", label);
    show_ext("extension", e);
    X509_EXTENSION_free(e);
    if (v != NULL)
        ASN1_item_free(v, ASN1_ITEM_ptr(m->it));
}

/* An extension decoded from DER and printed. */
static void decoded(const char *label, int nid, const unsigned char *der, int len)
{
    ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new();
    X509_EXTENSION *e;

    ASN1_OCTET_STRING_set(oct, der, len);
    e = X509_EXTENSION_create_by_NID(NULL, nid, 0, oct);
    printf("# %s\n", label);
    show_ext("extension", e);
    X509_EXTENSION_free(e);
    ASN1_OCTET_STRING_free(oct);
}


static void test_addr_text(void)
{
    printf("# IP address blocks from text\n");
    make("v4 prefixes", NID_sbgp_ipAddrBlock, "IPv4:10.0.0.0/8,IPv4:192.168.0.0/24,IPv4:192.168.1.0/24,IPv4:1.2.3.4");
    make("v4 range", NID_sbgp_ipAddrBlock, "IPv4:10.0.0.1-10.0.0.6,IPv4:172.16.0.0-172.31.255.255");
    make("v4 ranges merged", NID_sbgp_ipAddrBlock, "IPv4:10.0.0.0-10.0.0.9,IPv4:10.0.0.10-10.0.0.20");
    make("v6", NID_sbgp_ipAddrBlock, "IPv6:2001:db8::/32,IPv6:::1,IPv6:fe80::-fe80::ffff,IPv6:fe80::1:0-fe80::1:5,IPv6:1:2:3:4:5:6:7:8");
    make("v6 everything", NID_sbgp_ipAddrBlock, "IPv6:::/0");
    make("v6 overlap", NID_sbgp_ipAddrBlock, "IPv6:::/0,IPv6:::1");
    make("v6 all zero", NID_sbgp_ipAddrBlock, "IPv6:::/128");
    make("inherit", NID_sbgp_ipAddrBlock, "IPv6:inherit,IPv4:inherit");
    make("SAFI", NID_sbgp_ipAddrBlock, "IPv4-SAFI:1:10.0.0.0/8,IPv4-SAFI: 0x80 : 1.2.3.0/24,IPv6-SAFI:2:inherit,IPv4-SAFI:010:1.0.0.0/8,IPv4-SAFI:99:2.0.0.0/8");
    make("SAFI without a number", NID_sbgp_ipAddrBlock, "IPv4-SAFI::10.0.0.0/8");
    make("SAFI too big", NID_sbgp_ipAddrBlock, "IPv4-SAFI:256:10.0.0.0/8");
    make("SAFI wrapping", NID_sbgp_ipAddrBlock, "IPv4-SAFI:4294967297:10.0.0.0/8");
    make("SAFI no colon", NID_sbgp_ipAddrBlock, "IPv4-SAFI:1 10.0.0.0/8");
    make("SAFI no value", NID_sbgp_ipAddrBlock, "IPv4-SAFI");
    make("dotted name", NID_sbgp_ipAddrBlock, "IPv4.1:10.0.0.0/8");
    make("overlap", NID_sbgp_ipAddrBlock, "IPv4:10.0.0.0/8,IPv4:10.1.0.0/16");
    make("inherit and list", NID_sbgp_ipAddrBlock, "IPv4:10.0.0.0/8,IPv4:inherit");
    make("list and inherit", NID_sbgp_ipAddrBlock, "IPv4:inherit,IPv4:10.0.0.0/8");
    make("bad name", NID_sbgp_ipAddrBlock, "IPv5:10.0.0.0/8");
    make("bad address", NID_sbgp_ipAddrBlock, "IPv4:10.0.0/8");
    make("v6 as v4", NID_sbgp_ipAddrBlock, "IPv6:1.2.3.4");
    make("v4 with colons", NID_sbgp_ipAddrBlock, "IPv4:::1");
    make("prefix too long", NID_sbgp_ipAddrBlock, "IPv4:1.2.3.4/33");
    make("prefix negative", NID_sbgp_ipAddrBlock, "IPv4:1.2.3.4/-1");
    make("prefix wrapping", NID_sbgp_ipAddrBlock, "IPv4:1.0.0.0/4294967304");
    make("prefix empty", NID_sbgp_ipAddrBlock, "IPv4:1.2.3.4/");
    make("prefix with space", NID_sbgp_ipAddrBlock, "IPv4:1.2.3.0 / 24");
    make("prefix trailing", NID_sbgp_ipAddrBlock, "IPv4:1.2.3.0/24x");
    make("range spaces", NID_sbgp_ipAddrBlock, "IPv4:1.2.3.0 - 1.2.3.9");
    make("range reversed", NID_sbgp_ipAddrBlock, "IPv4:5.0.0.0-4.0.0.0");
    make("range open", NID_sbgp_ipAddrBlock, "IPv4:5.0.0.0-");
    make("range bad", NID_sbgp_ipAddrBlock, "IPv4:5.0.0.0-5.0.0");
    make("bad delimiter", NID_sbgp_ipAddrBlock, "IPv4:5.0.0.0+3");
    make("no value", NID_sbgp_ipAddrBlock, "IPv4");
    make("empty", NID_sbgp_ipAddrBlock, "");
}

static void show_range(IPAddressOrRange *aor, unsigned afi, int length)
{
    unsigned char min[16], max[16];
    int n = X509v3_addr_get_range(aor, afi, min, max, length);

    if (n <= 0) {
        printf("  range: %d\n", n);
        return;
    }
    hex("min", min, n);
    hex("max", max, n);
}

static void print_blocks(const char *label, IPAddrBlocks *addr)
{
    X509_EXTENSION *e = X509V3_EXT_i2d(NID_sbgp_ipAddrBlock, 0, addr);

    printf("# %s\n", label);
    show_ext("extension", e);
    X509_EXTENSION_free(e);
}

static void test_addr_api(void)
{
    IPAddrBlocks *addr = sk_IPAddressFamily_new_null(), *other = sk_IPAddressFamily_new_null();
    unsigned char a[16] = {10, 1, 2, 3}, b[16] = {10, 1, 2, 200}, z[16] = {0};
    unsigned safi = 7;
    IPAddressFamily *f;

    printf("# IP address API\n");
    check(X509v3_addr_add_prefix(addr, IANA_AFI_IPV4, NULL, a, 16) == 1, "add a /16");
    check(X509v3_addr_add_prefix(addr, IANA_AFI_IPV4, NULL, a, 33) == 0, "a /33 fails");
    check(X509v3_addr_add_prefix(addr, IANA_AFI_IPV4, NULL, a, -1) == 0, "a /-1 fails");
    check(X509v3_addr_add_range(addr, IANA_AFI_IPV4, NULL, a, b) == 1, "add a range");
    check(X509v3_addr_add_range(addr, IANA_AFI_IPV4, NULL, b, a) == 0, "a reversed range fails");
    check(X509v3_addr_add_range(addr, IANA_AFI_IPV4, &safi, z, b) == 1, "add a range with a SAFI");
    check(X509v3_addr_add_inherit(addr, IANA_AFI_IPV6, NULL) == 1, "inherit v6");
    check(X509v3_addr_add_inherit(addr, IANA_AFI_IPV6, NULL) == 1, "inherit v6 again");
    check(X509v3_addr_add_prefix(addr, IANA_AFI_IPV6, NULL, a, 8) == 0, "a prefix in an inheriting family fails");
    check(X509v3_addr_add_inherit(addr, IANA_AFI_IPV4, NULL) == 0, "inherit in a listing family fails");
    check(X509v3_addr_add_prefix(addr, 3, NULL, a, 0) == 1, "an unknown AFI's empty prefix");
    check(X509v3_addr_add_prefix(addr, 3, NULL, a, 1) == 0, "an unknown AFI's longer prefix fails");
    printf("  families: %d, inherits %d, canonical %d\n", sk_IPAddressFamily_num(addr),
           X509v3_addr_inherits(addr), X509v3_addr_is_canonical(addr));
    f = sk_IPAddressFamily_value(addr, 0);
    printf("  afi %u, entries %d\n", X509v3_addr_get_afi(f),
           sk_IPAddressOrRange_num(f->ipAddressChoice->u.addressesOrRanges));
    show_range(sk_IPAddressOrRange_value(f->ipAddressChoice->u.addressesOrRanges, 0), IANA_AFI_IPV4, 16);
    show_range(sk_IPAddressOrRange_value(f->ipAddressChoice->u.addressesOrRanges, 1), IANA_AFI_IPV4, 4);
    show_range(sk_IPAddressOrRange_value(f->ipAddressChoice->u.addressesOrRanges, 1), IANA_AFI_IPV4, 3);
    show_range(sk_IPAddressOrRange_value(f->ipAddressChoice->u.addressesOrRanges, 1), IANA_AFI_IPV6, 16);
    show_range(sk_IPAddressOrRange_value(f->ipAddressChoice->u.addressesOrRanges, 1), 9, 16);
    show_range(NULL, IANA_AFI_IPV4, 4);
    printf("  canonize: %d\n", X509v3_addr_canonize(addr));
    errors();
    printf("  canonical %d, families %d\n", X509v3_addr_is_canonical(addr), sk_IPAddressFamily_num(addr));
    print_blocks("API blocks", addr);
    printf("  canonize NULL: %d\n", X509v3_addr_canonize(NULL));
    errors();
    printf("  NULL: canonical %d, inherits %d, afi %u\n", X509v3_addr_is_canonical(NULL), X509v3_addr_inherits(NULL),
           X509v3_addr_get_afi(NULL));

    /* Subsets. */
    check(X509v3_addr_add_prefix(other, IANA_AFI_IPV4, NULL, a, 8) == 1, "a /8");
    check(X509v3_addr_canonize(other) == 1, "canonized");
    printf("  subset NULL %d, self %d, inherits %d\n", X509v3_addr_subset(NULL, other), X509v3_addr_subset(other, other),
           X509v3_addr_subset(other, addr));
    {
        IPAddrBlocks *big = sk_IPAddressFamily_new_null(), *small = sk_IPAddressFamily_new_null();

        X509v3_addr_add_prefix(big, IANA_AFI_IPV4, NULL, z, 1);
        X509v3_addr_add_prefix(big, IANA_AFI_IPV6, NULL, z, 8);
        X509v3_addr_add_prefix(small, IANA_AFI_IPV4, NULL, a, 24);
        X509v3_addr_add_range(small, IANA_AFI_IPV4, NULL, z, a);
        X509v3_addr_canonize(big);
        X509v3_addr_canonize(small);
        printf("  small in big %d, big in small %d, small in NULL %d, other in big %d\n", X509v3_addr_subset(small, big),
               X509v3_addr_subset(big, small), X509v3_addr_subset(small, NULL), X509v3_addr_subset(other, big));
        X509v3_addr_add_prefix(small, IANA_AFI_IPV6, &safi, z, 8);
        printf("  with a SAFI family: %d\n", X509v3_addr_subset(small, big));
        sk_IPAddressFamily_pop_free(big, IPAddressFamily_free);
        sk_IPAddressFamily_pop_free(small, IPAddressFamily_free);
    }
    sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
    sk_IPAddressFamily_pop_free(other, IPAddressFamily_free);
}

static void test_addr_der(void)
{
    /* Two v4 prefixes out of order, then an unknown AFI with a SAFI, then a one-octet AFI. */
    static const unsigned char unsorted[] = {
        0x30, 0x2a,
        0x30, 0x10, 0x04, 0x02, 0x00, 0x01, 0x30, 0x0a, 0x03, 0x03, 0x00, 0x0b, 0x01, 0x03, 0x03, 0x00, 0x0a, 0x01,
        0x30, 0x0c, 0x04, 0x03, 0x00, 0x05, 0x42, 0x30, 0x05, 0x03, 0x03, 0x04, 0xab, 0xc0,
        0x30, 0x08, 0x04, 0x01, 0x01, 0x30, 0x03, 0x03, 0x01, 0x00,
    };
    /* A v4 range whose bounds are a prefix, and a v6 prefix longer than 16 octets. */
    static const unsigned char odd[] = {
        0x30, 0x34,
        0x30, 0x13, 0x04, 0x02, 0x00, 0x01, 0x30, 0x0d, 0x30, 0x0b, 0x03, 0x03, 0x00, 0x0a, 0x00, 0x03, 0x04, 0x00, 0x0a, 0x00, 0xff,
        0x30, 0x1d, 0x04, 0x02, 0x00, 0x02, 0x30, 0x17, 0x03, 0x15, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    /* A v4 family with SAFI 1 and an inheriting v6 family. */
    static const unsigned char inherits[] = {
        0x30, 0x15, 0x30, 0x0b, 0x04, 0x03, 0x00, 0x01, 0x01, 0x30, 0x04, 0x03, 0x02, 0x07, 0x80,
        0x30, 0x06, 0x04, 0x02, 0x00, 0x02, 0x05, 0x00,
    };
    const unsigned char *q;
    IPAddrBlocks *addr;
    X509V3_EXT_METHOD const *m = X509V3_EXT_get_nid(NID_sbgp_ipAddrBlock);

    printf("# IP address blocks from DER\n");
    decoded("unsorted", NID_sbgp_ipAddrBlock, unsorted, sizeof(unsorted));
    q = unsorted;
    addr = (IPAddrBlocks *)ASN1_item_d2i(NULL, &q, sizeof(unsorted), ASN1_ITEM_ptr(m->it));
    check(addr != NULL, "decoded");
    printf("  canonical %d, afi of the last %u\n", X509v3_addr_is_canonical(addr),
           X509v3_addr_get_afi(sk_IPAddressFamily_value(addr, 2)));
    printf("  canonize %d\n", X509v3_addr_canonize(addr));
    errors();
    ASN1_item_free((ASN1_VALUE *)addr, ASN1_ITEM_ptr(m->it));
    decoded("odd", NID_sbgp_ipAddrBlock, odd, sizeof(odd));
    q = odd;
    addr = (IPAddrBlocks *)ASN1_item_d2i(NULL, &q, sizeof(odd), ASN1_ITEM_ptr(m->it));
    printf("  canonical %d\n", X509v3_addr_is_canonical(addr));
    ASN1_item_free((ASN1_VALUE *)addr, ASN1_ITEM_ptr(m->it));
    decoded("inherits", NID_sbgp_ipAddrBlock, inherits, sizeof(inherits));
    q = inherits;
    addr = (IPAddrBlocks *)ASN1_item_d2i(NULL, &q, sizeof(inherits), ASN1_ITEM_ptr(m->it));
    printf("  canonical %d, inherits %d, canonize %d\n", X509v3_addr_is_canonical(addr), X509v3_addr_inherits(addr),
           X509v3_addr_canonize(addr));
    ASN1_item_free((ASN1_VALUE *)addr, ASN1_ITEM_ptr(m->it));
}

static void test_addr_items(void)
{
    IPAddressRange *r = IPAddressRange_new();
    IPAddressOrRange *aor = IPAddressOrRange_new();
    IPAddressChoice *c = IPAddressChoice_new();
    IPAddressFamily *f = IPAddressFamily_new();
    unsigned char *der = NULL;
    const unsigned char *q;
    int len;

    printf("# IP address items\n");
    len = i2d_IPAddressRange(r, &der);
    hex("empty range", der, len);
    q = der;
    IPAddressRange_free(d2i_IPAddressRange(NULL, &q, len));
    OPENSSL_free(der);
    der = NULL;
    printf("  empty choice: %d, %d\n", i2d_IPAddressOrRange(aor, &der), i2d_IPAddressChoice(c, NULL));
    OPENSSL_free(der);
    der = NULL;
    printf("  family type %d, afi %u\n", f->ipAddressChoice->type, X509v3_addr_get_afi(f));
    len = i2d_IPAddressFamily(f, &der);
    printf("  empty family: %d\n", len);
    OPENSSL_free(der);
    {
        static const unsigned char pfx[] = {0x03, 0x02, 0x04, 0xa0};
        static const unsigned char ch[] = {0x30, 0x04, 0x03, 0x02, 0x04, 0xa0};
        static const unsigned char fam[] = {0x30, 0x09, 0x04, 0x02, 0x00, 0x01, 0x30, 0x03, 0x03, 0x01, 0x00};

        q = pfx;
        IPAddressOrRange_free(aor);
        aor = d2i_IPAddressOrRange(NULL, &q, sizeof(pfx));
        printf("  prefix: type %d\n", aor == NULL ? -2 : aor->type);
        q = ch;
        IPAddressChoice_free(c);
        c = d2i_IPAddressChoice(NULL, &q, sizeof(ch));
        printf("  choice: type %d\n", c == NULL ? -2 : c->type);
        q = fam;
        IPAddressFamily_free(f);
        f = d2i_IPAddressFamily(NULL, &q, sizeof(fam));
        printf("  family: afi %u\n", X509v3_addr_get_afi(f));
        der = NULL;
        len = i2d_IPAddressFamily(f, &der);
        hex("family again", der, len);
        OPENSSL_free(der);
    }
    IPAddressRange_free(r);
    IPAddressOrRange_free(aor);
    IPAddressChoice_free(c);
    IPAddressFamily_free(f);
}

static void test_asid_text(void)
{
    printf("# AS identifiers from text\n");
    make("numbers", NID_sbgp_autonomousSysNum, "AS:1,AS:3-5,AS:2,AS:10,RDI:inherit");
    make("ranges", NID_sbgp_autonomousSysNum, "AS:64496-64511,AS:64512 - 65534,RDI:7,RDI:8-9");
    make("big", NID_sbgp_autonomousSysNum, "AS:4294967295,AS:99999999999999999999");
    make("dotted name", NID_sbgp_autonomousSysNum, "AS.x:1,RDI.y:2");
    make("overlap", NID_sbgp_autonomousSysNum, "AS:1-10,AS:5");
    make("inherit and list", NID_sbgp_autonomousSysNum, "AS:1,AS:inherit");
    make("list and inherit", NID_sbgp_autonomousSysNum, "AS:inherit,AS:1");
    make("inherit twice", NID_sbgp_autonomousSysNum, "AS:inherit,AS:inherit");
    make("bad name", NID_sbgp_autonomousSysNum, "ASN:1");
    make("no value", NID_sbgp_autonomousSysNum, "AS");
    make("bad number", NID_sbgp_autonomousSysNum, "AS:x");
    make("bad range", NID_sbgp_autonomousSysNum, "AS:1-x");
    make("range open", NID_sbgp_autonomousSysNum, "AS:1-");
    make("range reversed", NID_sbgp_autonomousSysNum, "AS:5-1");
    make("negative", NID_sbgp_autonomousSysNum, "AS:-5");
    make("hex", NID_sbgp_autonomousSysNum, "AS:0x10");
    make("empty", NID_sbgp_autonomousSysNum, "");
}

static ASN1_INTEGER *num(long v)
{
    ASN1_INTEGER *i = ASN1_INTEGER_new();

    ASN1_INTEGER_set(i, v);
    return i;
}

static void print_asid(const char *label, ASIdentifiers *asid)
{
    X509_EXTENSION *e = X509V3_EXT_i2d(NID_sbgp_autonomousSysNum, 0, asid);

    printf("# %s\n", label);
    show_ext("extension", e);
    X509_EXTENSION_free(e);
}

static void test_asid_api(void)
{
    ASIdentifiers *a = ASIdentifiers_new(), *b = ASIdentifiers_new();
    ASN1_INTEGER *lo, *hi;

    printf("# AS identifier API\n");
    check(X509v3_asid_add_id_or_range(a, V3_ASID_ASNUM, num(20), NULL) == 1, "add 20");
    check(X509v3_asid_add_id_or_range(a, V3_ASID_ASNUM, num(10), num(15)) == 1, "add 10-15");
    check(X509v3_asid_add_id_or_range(a, V3_ASID_ASNUM, num(16), num(19)) == 1, "add 16-19");
    check(X509v3_asid_add_id_or_range(a, V3_ASID_RDI, num(5), NULL) == 1, "add RDI 5");
    check(X509v3_asid_add_id_or_range(a, V3_ASID_RDI, num(6), NULL) == 1, "add RDI 6");
    lo = num(1);
    check(X509v3_asid_add_id_or_range(a, 7, lo, NULL) == 0, "an unknown kind fails");
    check(X509v3_asid_add_id_or_range(NULL, V3_ASID_ASNUM, lo, NULL) == 0, "no identifiers fail");
    check(X509v3_asid_add_inherit(a, V3_ASID_ASNUM) == 0, "inherit in a list fails");
    check(X509v3_asid_add_inherit(a, 7) == 0, "inherit of an unknown kind fails");
    check(X509v3_asid_add_inherit(NULL, V3_ASID_ASNUM) == 0, "inherit without identifiers fails");
    ASN1_INTEGER_free(lo);
    printf("  canonical %d, inherits %d\n", X509v3_asid_is_canonical(a), X509v3_asid_inherits(a));
    printf("  canonize %d\n", X509v3_asid_canonize(a));
    errors();
    printf("  canonical %d, AS entries %d, RDI entries %d\n", X509v3_asid_is_canonical(a),
           sk_ASIdOrRange_num(a->asnum->u.asIdsOrRanges), sk_ASIdOrRange_num(a->rdi->u.asIdsOrRanges));
    print_asid("API identifiers", a);
    check(X509v3_asid_add_id_or_range(a, V3_ASID_ASNUM, num(12), NULL) == 1, "add 12 again");
    printf("  canonize with an overlap %d\n", X509v3_asid_canonize(a));
    errors();
    printf("  NULL: canonical %d, canonize %d, inherits %d\n", X509v3_asid_is_canonical(NULL), X509v3_asid_canonize(NULL),
           X509v3_asid_inherits(NULL));

    check(X509v3_asid_add_id_or_range(b, V3_ASID_ASNUM, num(1), num(100)) == 1, "b: 1-100");
    X509v3_asid_canonize(b);
    {
        ASIdentifiers *c = ASIdentifiers_new();

        X509v3_asid_add_id_or_range(c, V3_ASID_ASNUM, num(50), NULL);
        X509v3_asid_add_id_or_range(c, V3_ASID_ASNUM, num(2), num(3));
        X509v3_asid_canonize(c);
        printf("  c in b %d, b in c %d, NULL in b %d, c in NULL %d, b in b %d\n", X509v3_asid_subset(c, b),
               X509v3_asid_subset(b, c), X509v3_asid_subset(NULL, b), X509v3_asid_subset(c, NULL), X509v3_asid_subset(b, b));
        X509v3_asid_add_id_or_range(c, V3_ASID_RDI, num(1), NULL);
        printf("  with RDIs: %d\n", X509v3_asid_subset(c, b));
        check(X509v3_asid_add_inherit(b, V3_ASID_RDI) == 1, "b inherits RDIs");
        check(X509v3_asid_add_inherit(b, V3_ASID_RDI) == 1, "again");
        printf("  inherits %d, c in b %d, canonical %d\n", X509v3_asid_inherits(b), X509v3_asid_subset(c, b),
               X509v3_asid_is_canonical(b));
        ASIdentifiers_free(c);
    }
    hi = num(7);
    lo = num(9);
    {
        ASIdentifiers *d = ASIdentifiers_new();

        check(X509v3_asid_add_id_or_range(d, V3_ASID_ASNUM, lo, hi) == 1, "a reversed range is added");
        printf("  reversed: canonical %d, canonize %d\n", X509v3_asid_is_canonical(d), X509v3_asid_canonize(d));
        errors();
        ASIdentifiers_free(d);
    }
    ASIdentifiers_free(a);
    ASIdentifiers_free(b);
}

static void test_asid_der(void)
{
    /* AS numbers out of order: 5, then 1-3; RDIs 1, 2 (adjacent), and 4. */
    static const unsigned char unsorted[] = {
        0x30, 0x1c,
        0xa0, 0x0d, 0x30, 0x0b, 0x02, 0x01, 0x05, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x03,
        0xa1, 0x0b, 0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x04,
    };
    /* Inheriting AS numbers, and an empty RDI list. */
    static const unsigned char inherits[] = {0x30, 0x08, 0xa0, 0x02, 0x05, 0x00, 0xa1, 0x02, 0x30, 0x00};
    const unsigned char *q;
    ASIdentifiers *asid;

    printf("# AS identifiers from DER\n");
    {
        ASIdentifiers *e = ASIdentifiers_new();
        unsigned char *der = NULL;
        int len = i2d_ASIdentifiers(e, &der);

        hex("empty ASIdentifiers", der, len);
        OPENSSL_free(der);
        ASIdentifiers_free(e);
    }
    decoded("unsorted", NID_sbgp_autonomousSysNum, unsorted, sizeof(unsorted));
    q = unsorted;
    asid = d2i_ASIdentifiers(NULL, &q, sizeof(unsorted));
    check(asid != NULL, "decoded");
    printf("  canonical %d, canonize %d\n", X509v3_asid_is_canonical(asid), X509v3_asid_canonize(asid));
    errors();
    ASIdentifiers_free(asid);
    decoded("inherits", NID_sbgp_autonomousSysNum, inherits, sizeof(inherits));
    q = inherits;
    asid = d2i_ASIdentifiers(NULL, &q, sizeof(inherits));
    printf("  canonical %d, inherits %d, canonize %d\n", X509v3_asid_is_canonical(asid), X509v3_asid_inherits(asid),
           X509v3_asid_canonize(asid));
    errors();
    ASIdentifiers_free(asid);
    {
        ASRange *r = ASRange_new();
        ASIdOrRange *aor = ASIdOrRange_new();
        ASIdentifierChoice *c = ASIdentifierChoice_new();
        unsigned char *der = NULL;
        int len = i2d_ASRange(r, &der);
        static const unsigned char id[] = {0x02, 0x01, 0x07};
        static const unsigned char ch[] = {0x05, 0x00};

        hex("empty ASRange", der, len);
        q = der;
        ASRange_free(d2i_ASRange(NULL, &q, len));
        OPENSSL_free(der);
        printf("  empty choices: %d %d\n", i2d_ASIdOrRange(aor, NULL), i2d_ASIdentifierChoice(c, NULL));
        ASIdOrRange_free(aor);
        ASIdentifierChoice_free(c);
        q = id;
        aor = d2i_ASIdOrRange(NULL, &q, sizeof(id));
        printf("  id: type %d, %ld\n", aor->type, ASN1_INTEGER_get(aor->u.id));
        ASIdOrRange_free(aor);
        q = ch;
        c = d2i_ASIdentifierChoice(NULL, &q, sizeof(ch));
        printf("  choice: type %d\n", c->type);
        ASIdentifierChoice_free(c);
        ASRange_free(r);
    }
}

/* Each item: a new value encoded through it. */
static void items(void)
{
    const struct {
        const char *name;
        const ASN1_ITEM *it;
    } list[] = {
        {"ASRange", ASN1_ITEM_rptr(ASRange)},
        {"ASIdOrRange", ASN1_ITEM_rptr(ASIdOrRange)},
        {"ASIdentifierChoice", ASN1_ITEM_rptr(ASIdentifierChoice)},
        {"ASIdentifiers", ASN1_ITEM_rptr(ASIdentifiers)},
        {"IPAddressRange", ASN1_ITEM_rptr(IPAddressRange)},
        {"IPAddressOrRange", ASN1_ITEM_rptr(IPAddressOrRange)},
        {"IPAddressChoice", ASN1_ITEM_rptr(IPAddressChoice)},
        {"IPAddressFamily", ASN1_ITEM_rptr(IPAddressFamily)},
    };
    size_t i;

    printf("# items\n");
    for (i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        ASN1_VALUE *v = ASN1_item_new(list[i].it);
        unsigned char *der = NULL;
        int len = ASN1_item_i2d(v, &der, list[i].it);

        printf("  %s: %d\n", list[i].name, len);
        OPENSSL_free(der);
        ASN1_item_free(v, list[i].it);
    }
    ERR_clear_error();
}

int main(void)
{
    out = BIO_new(BIO_s_mem());
    test_addr_text();
    test_addr_api();
    test_addr_der();
    test_addr_items();
    test_asid_text();
    test_asid_api();
    test_asid_der();
    items();
    BIO_free(out);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
