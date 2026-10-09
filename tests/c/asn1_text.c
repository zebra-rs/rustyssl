/*
 * Conformance test for character strings: ASN1_mbstring_copy(3), ASN1_mbstring_ncopy,
 * ASN1_STRING_set_by_NID(3), ASN1_STRING_TABLE_add(3), the default mask,
 * ASN1_STRING_to_UTF8, ASN1_STRING_print_ex(3) and _fp, ASN1_STRING_print,
 * ASN1_PRINTABLE_type, ASN1_UNIVERSALSTRING_to_string, UTF8_getc, UTF8_putc, ASN1_tag2bit,
 * and ASN1_tag2str, in TAP format. Every conversion and printout is printed escaped, so all of
 * it is compared.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void escaped(const unsigned char *data, long len)
{
    long i;

    printf("\"");
    for (i = 0; i < len; i++) {
        if (data[i] >= ' ' && data[i] <= '~' && data[i] != '"' && data[i] != '\\')
            putchar(data[i]);
        else
            printf("\\x%02x", data[i]);
    }
    printf("\"");
}

static void errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf(" errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) && *data)
            printf("(%s)", data);
    }
    printf("\n");
}

static void utf8(void)
{
    static const unsigned char *const inputs[] = {
        (const unsigned char *)"A", (const unsigned char *)"\xc3\xa9", (const unsigned char *)"\xe2\x82\xac",
        (const unsigned char *)"\xf0\x9f\x98\x80", (const unsigned char *)"\xc3", (const unsigned char *)"\xc3\x41",
        (const unsigned char *)"\xc1\x81", (const unsigned char *)"\xed\xa0\x80", (const unsigned char *)"\xf4\x90\x80\x80",
        (const unsigned char *)"\xff", (const unsigned char *)"\x80",
    };
    static const unsigned long values[] = { 0, 0x7f, 0x80, 0x7ff, 0x800, 0xd800, 0xdfff, 0xffff, 0x10000, 0x10ffff, 0x110000 };
    unsigned char buf[8];
    size_t i;

    printf("# UTF8_getc:");
    for (i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        unsigned long v = 7;
        int n = UTF8_getc(inputs[i], (int)strlen((const char *)inputs[i]), &v);

        printf(" %d:%lx", n, v);
    }
    printf(" empty:%d\n# UTF8_putc:", UTF8_getc((const unsigned char *)"", 0, NULL));
    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        int n = UTF8_putc(buf, sizeof(buf), values[i]), j;

        printf(" %d:", n);
        for (j = 0; j < n; j++)
            printf("%02x", buf[j]);
        printf("/%d/%d", UTF8_putc(NULL, 0, values[i]), UTF8_putc(buf, 1, values[i]));
    }
    printf(" %d\n", UTF8_putc(buf, 0, 'a'));
    check(1, "UTF8_getc and UTF8_putc");
}

static void convert(const char *what, const void *in, int len, int inform, unsigned long mask, long min, long max)
{
    ASN1_STRING *out = NULL;
    int r = ASN1_mbstring_ncopy(&out, in, len, inform, mask, min, max);

    printf("# %s: %d", what, r);
    if (out != NULL) {
        printf(" type=%d ", out->type);
        escaped(out->data, out->length);
    }
    errors();
    ASN1_STRING_free(out);
}

static void mbstrings(void)
{
    ASN1_STRING *keep = ASN1_STRING_new(), *p;

    convert("ascii", "Hello 42", -1, MBSTRING_ASC, 0, 0, 0);
    convert("ascii digits, numeric allowed", "12 34", -1, MBSTRING_ASC, B_ASN1_NUMERICSTRING | B_ASN1_UTF8STRING, 0, 0);
    convert("ascii with @", "a@b", -1, MBSTRING_ASC, B_ASN1_PRINTABLESTRING | B_ASN1_IA5STRING, 0, 0);
    convert("latin1 as T61", "caf\xe9", -1, MBSTRING_ASC, B_ASN1_PRINTABLESTRING | B_ASN1_T61STRING, 0, 0);
    convert("latin1 to UTF8", "caf\xe9", -1, MBSTRING_ASC, B_ASN1_UTF8STRING, 0, 0);
    convert("latin1 to BMP", "caf\xe9", -1, MBSTRING_ASC, B_ASN1_BMPSTRING, 0, 0);
    convert("utf8 euro", "\xe2\x82\xac", -1, MBSTRING_UTF8, DIRSTRING_TYPE, 0, 0);
    convert("utf8 euro to BMP", "\xe2\x82\xac", -1, MBSTRING_UTF8, B_ASN1_BMPSTRING, 0, 0);
    convert("utf8 emoji to UNIV", "\xf0\x9f\x98\x80", -1, MBSTRING_UTF8, B_ASN1_BMPSTRING | B_ASN1_UNIVERSALSTRING, 0, 0);
    convert("utf8 emoji, BMP only", "\xf0\x9f\x98\x80", -1, MBSTRING_UTF8, B_ASN1_BMPSTRING, 0, 0);
    convert("bad utf8", "\xc3\x41", -1, MBSTRING_UTF8, 0, 0, 0);
    convert("bmp", "\x00h\x00i", 4, MBSTRING_BMP, B_ASN1_PRINTABLESTRING, 0, 0);
    convert("bmp odd", "\x00h\x00", 3, MBSTRING_BMP, 0, 0, 0);
    convert("bmp surrogate to UTF8", "\xd8\x00", 2, MBSTRING_BMP, B_ASN1_UTF8STRING, 0, 0);
    convert("univ", "\x00\x00\x00h", 4, MBSTRING_UNIV, 0, 0, 0);
    convert("univ odd", "\x00\x00\x00", 3, MBSTRING_UNIV, 0, 0, 0);
    convert("univ past unicode", "\x00\x11\x00\x00", 4, MBSTRING_UNIV, 0, 0, 0);
    convert("univ past unicode, univ ok", "\x00\x11\x00\x00", 4, MBSTRING_UNIV, B_ASN1_UNIVERSALSTRING, 0, 0);
    convert("too short", "ab", -1, MBSTRING_ASC, 0, 3, 0);
    convert("too long", "abcd", -1, MBSTRING_ASC, 0, 0, 3);
    convert("empty", "", 0, MBSTRING_ASC, B_ASN1_NUMERICSTRING, 0, 0);
    convert("unknown form", "x", 1, 0x1234, 0, 0, 0);
    convert("negative length", "x", -5, MBSTRING_ASC, 0, 0, 0);
    convert("other types in mask", "a", 1, MBSTRING_ASC, B_ASN1_OCTET_STRING, 0, 0);
    check(ASN1_mbstring_copy(NULL, (const unsigned char *)"abc", 3, MBSTRING_ASC, 0) == V_ASN1_PRINTABLESTRING,
          "NULL out gives only the type");
    keep->type = V_ASN1_OCTET_STRING;
    ASN1_STRING_set(keep, "old", 3);
    p = keep;
    check(ASN1_mbstring_copy(&p, (const unsigned char *)"new", 3, MBSTRING_ASC, B_ASN1_IA5STRING) == V_ASN1_IA5STRING
              && p == keep && keep->type == V_ASN1_IA5STRING && memcmp(keep->data, "new", 3) == 0,
          "an existing string is reused");
    check(ASN1_mbstring_copy(&p, (const unsigned char *)"\xc3", 1, MBSTRING_UTF8, 0) == -1 && p == keep, "and kept on failure");
    ERR_clear_error();
    ASN1_STRING_free(keep);
}

static void tables(void)
{
    ASN1_STRING_TABLE *t = ASN1_STRING_TABLE_get(NID_countryName), *cn;
    ASN1_STRING *s;
    unsigned long saved = ASN1_STRING_get_default_mask();

    check(t != NULL && t->minsize == 2 && t->maxsize == 2 && t->mask == B_ASN1_PRINTABLESTRING
              && t->flags == STABLE_NO_MASK,
          "the built-in countryName entry");
    cn = ASN1_STRING_TABLE_get(NID_commonName);
    printf("# CN entry: %ld %ld %lx %lx; unknown: %p\n", cn->minsize, cn->maxsize, cn->mask, cn->flags,
           (void *)ASN1_STRING_TABLE_get(NID_sha256));
    printf("# default mask %lx\n", saved);
    s = ASN1_STRING_set_by_NID(NULL, (const unsigned char *)"US", -1, MBSTRING_ASC, NID_countryName);
    printf("# set_by_NID C=US: type=%d", s ? s->type : -1);
    errors();
    ASN1_STRING_free(s);
    s = ASN1_STRING_set_by_NID(NULL, (const unsigned char *)"USA", -1, MBSTRING_ASC, NID_countryName);
    printf("# set_by_NID C=USA: %s", s ? "made" : "NULL");
    errors();
    ASN1_STRING_free(s);
    s = ASN1_STRING_set_by_NID(NULL, (const unsigned char *)"Name", -1, MBSTRING_ASC, NID_commonName);
    printf("# set_by_NID CN: type=%d", s ? s->type : -1);
    errors();
    ASN1_STRING_free(s);
    s = ASN1_STRING_set_by_NID(NULL, (const unsigned char *)"x", -1, MBSTRING_ASC, NID_sha256);
    printf("# set_by_NID unknown NID: type=%d", s ? s->type : -1);
    errors();
    ASN1_STRING_free(s);

    check(ASN1_STRING_TABLE_add(NID_commonName, 3, -1, 0, 0) == 1 && ASN1_STRING_TABLE_get(NID_commonName) != cn,
          "ASN1_STRING_TABLE_add copies a built-in entry");
    t = ASN1_STRING_TABLE_get(NID_commonName);
    printf("# added CN: %ld %ld %lx %lx\n", t->minsize, t->maxsize, t->mask, t->flags);
    check(ASN1_STRING_TABLE_add(NID_commonName, -1, 10, B_ASN1_IA5STRING, STABLE_NO_MASK) == 1
              && ASN1_STRING_TABLE_get(NID_commonName) == t,
          "and changes the added one");
    printf("# changed CN: %ld %ld %lx %lx\n", t->minsize, t->maxsize, t->mask, t->flags);
    check(ASN1_STRING_TABLE_add(NID_sha256, -1, -1, 0, 0) == 1, "an entry for a new NID");
    t = ASN1_STRING_TABLE_get(NID_sha256);
    printf("# new entry: %ld %ld %lx %lx\n", t->minsize, t->maxsize, t->mask, t->flags);
    s = ASN1_STRING_set_by_NID(NULL, (const unsigned char *)"ab", -1, MBSTRING_ASC, NID_commonName);
    printf("# set_by_NID short CN: %s", s ? "made" : "NULL");
    errors();
    ASN1_STRING_free(s);
    ASN1_STRING_TABLE_cleanup();
    check(ASN1_STRING_TABLE_get(NID_commonName) == cn && ASN1_STRING_TABLE_get(NID_sha256) == NULL,
          "ASN1_STRING_TABLE_cleanup forgets the added entries");

    check(ASN1_STRING_set_default_mask_asc("nombstr") == 1, "nombstr");
    printf("# masks: %lx", ASN1_STRING_get_default_mask());
    ASN1_STRING_set_default_mask_asc("pkix");
    printf(" %lx", ASN1_STRING_get_default_mask());
    ASN1_STRING_set_default_mask_asc("utf8only");
    printf(" %lx", ASN1_STRING_get_default_mask());
    ASN1_STRING_set_default_mask_asc("default");
    printf(" %lx", ASN1_STRING_get_default_mask());
    ASN1_STRING_set_default_mask_asc("MASK:0x1234");
    printf(" %lx", ASN1_STRING_get_default_mask());
    ASN1_STRING_set_default_mask_asc("MASK: -1");
    printf(" %lx", ASN1_STRING_get_default_mask());
    printf(" bad=%d %d %d %d\n", ASN1_STRING_set_default_mask_asc("MASK:"), ASN1_STRING_set_default_mask_asc("MASK:12x"),
           ASN1_STRING_set_default_mask_asc("bogus"), ASN1_STRING_set_default_mask_asc("mask:1"));
    s = ASN1_STRING_set_by_NID(NULL, (const unsigned char *)"Name", -1, MBSTRING_ASC, NID_commonName);
    printf("# set_by_NID CN with mask: type=%d", s ? s->type : -1);
    errors();
    ASN1_STRING_free(s);
    ASN1_STRING_set_default_mask(saved);
}

static ASN1_STRING *make(int type, const void *data, int len)
{
    ASN1_STRING *s = ASN1_STRING_type_new(type);

    ASN1_STRING_set(s, data, len);
    return s;
}

static void print_all(const char *what, ASN1_STRING *s)
{
    static const unsigned long flags[] = {
        0,
        ASN1_STRFLGS_RFC2253,
        ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_QUOTE,
        ASN1_STRFLGS_ESC_CTRL | ASN1_STRFLGS_ESC_MSB,
        ASN1_STRFLGS_ESC_2254,
        ASN1_STRFLGS_SHOW_TYPE | ASN1_STRFLGS_UTF8_CONVERT,
        ASN1_STRFLGS_DUMP_ALL,
        ASN1_STRFLGS_DUMP_ALL | ASN1_STRFLGS_DUMP_DER,
        ASN1_STRFLGS_DUMP_UNKNOWN | ASN1_STRFLGS_DUMP_DER | ASN1_STRFLGS_SHOW_TYPE,
        ASN1_STRFLGS_IGNORE_TYPE | ASN1_STRFLGS_ESC_MSB,
        ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_ESC_MSB,
    };
    size_t i;

    printf("# %s:\n", what);
    for (i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        BIO *mem = BIO_new(BIO_s_mem());
        char *out;
        long len;
        int n = ASN1_STRING_print_ex(mem, s, flags[i]), m = ASN1_STRING_print_ex(NULL, s, flags[i]);

        len = BIO_get_mem_data(mem, &out);
        printf("#   %lx: %d/%d ", flags[i], n, m);
        escaped((const unsigned char *)out, len);
        errors();
        BIO_free(mem);
    }
}

static void printing(void)
{
    ASN1_STRING *s;
    BIO *mem;
    char *out;
    long len;
    FILE *f;
    char buf[64];
    size_t got;

    s = make(V_ASN1_UTF8STRING, " a,b+c\"d\\e<f>g;h#i ", -1);
    print_all("RFC 2253 specials", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_UTF8STRING, "#lead", -1);
    print_all("leading #", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_UTF8STRING, "caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80", -1);
    print_all("UTF-8", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_UTF8STRING, "x\xc3", -1);
    print_all("bad UTF-8", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_T61STRING, "caf\xe9\x01\x7f(*)\\", -1);
    print_all("T61 with controls", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_BMPSTRING, "\x00h\x01\x00\x20\xac", 6);
    print_all("BMP", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_BMPSTRING, "\x00h\x01", 3);
    print_all("BMP odd", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_UNIVERSALSTRING, "\x00\x00\x00h\x00\x01\xf6\x00", 8);
    print_all("Universal", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_OCTET_STRING, "\x01\x02\xff", 3);
    print_all("OCTET STRING", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_INTEGER, "\x80\x01", 2);
    print_all("INTEGER", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_NEG_INTEGER, "\x05", 1);
    print_all("negative INTEGER", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_BIT_STRING, "\xa0\x00", 2);
    print_all("BIT STRING", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_SEQUENCE, "\x30\x00", 2);
    print_all("SEQUENCE", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_NULL, "", 0);
    print_all("NULL", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_IA5STRING, "", 0);
    print_all("empty", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_IA5STRING, " ", 1);
    print_all("one space", s);
    ASN1_STRING_free(s);
    s = make(99, "\x01", 1);
    print_all("type 99", s);
    ASN1_STRING_free(s);

    s = make(V_ASN1_IA5STRING, "file, out", -1);
    f = tmpfile();
    check(ASN1_STRING_print_ex_fp(f, s, ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_ESC_QUOTE) == 11
              && ASN1_STRING_print_ex_fp(NULL, s, 0) == 9,
          "ASN1_STRING_print_ex_fp");
    rewind(f);
    got = fread(buf, 1, sizeof(buf), f);
    printf("# fp: ");
    escaped((const unsigned char *)buf, (long)got);
    printf("\n");
    fclose(f);
    ASN1_STRING_free(s);

    mem = BIO_new(BIO_s_mem());
    s = make(V_ASN1_OCTET_STRING, "ab\x01\n\r\x7f\xc3\xa9~", -1);
    check(ASN1_STRING_print(mem, s) == 1 && ASN1_STRING_print(mem, NULL) == 0, "ASN1_STRING_print");
    len = BIO_get_mem_data(mem, &out);
    printf("# print: ");
    escaped((const unsigned char *)out, len);
    printf("\n");
    ASN1_STRING_free(s);
    BIO_free(mem);
}

static void utf8_conversion(const char *what, ASN1_STRING *s)
{
    unsigned char *out = NULL;
    int n = ASN1_STRING_to_UTF8(&out, s);

    printf("# to_UTF8 %s: %d ", what, n);
    if (n >= 0)
        escaped(out, n);
    errors();
    OPENSSL_free(out);
}

static void misc(void)
{
    ASN1_STRING *s;
    int t;

    s = make(V_ASN1_BMPSTRING, "\x00h\x20\xac", 4);
    utf8_conversion("BMP", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_T61STRING, "caf\xe9", -1);
    utf8_conversion("T61", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_UTF8STRING, "\xc3\xa9", -1);
    utf8_conversion("UTF8", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_UTF8STRING, "\xc3", -1);
    utf8_conversion("bad UTF8", s);
    ASN1_STRING_free(s);
    s = make(V_ASN1_OCTET_STRING, "x", -1);
    utf8_conversion("OCTET STRING", s);
    ASN1_STRING_free(s);
    check(ASN1_STRING_to_UTF8(&(unsigned char *){ NULL }, NULL) == -1, "to_UTF8 of NULL");

    printf("# PRINTABLE_type: %d %d %d %d %d\n", ASN1_PRINTABLE_type((const unsigned char *)"Abc 1", -1),
           ASN1_PRINTABLE_type((const unsigned char *)"a@b", -1),
           ASN1_PRINTABLE_type((const unsigned char *)"caf\xe9", -1),
           ASN1_PRINTABLE_type((const unsigned char *)"a@b", 1), ASN1_PRINTABLE_type(NULL, 0));
    s = make(V_ASN1_UNIVERSALSTRING, "\x00\x00\x00h\x00\x00\x00i", 8);
    check(ASN1_UNIVERSALSTRING_to_string(s) == 1 && s->length == 2 && memcmp(s->data, "hi", 3) == 0
              && s->type == V_ASN1_PRINTABLESTRING,
          "ASN1_UNIVERSALSTRING_to_string narrows");
    ASN1_STRING_free(s);
    s = make(V_ASN1_UNIVERSALSTRING, "\x00\x00\x01h", 4);
    t = ASN1_UNIVERSALSTRING_to_string(s);
    check(t == 0 && s->length == 4, "but not past one octet");
    s->type = V_ASN1_BMPSTRING;
    check(ASN1_UNIVERSALSTRING_to_string(s) == 0, "nor another type");
    ASN1_STRING_free(s);

    printf("# tag2bit:");
    for (t = -1; t <= 31; t++)
        printf(" %lx", ASN1_tag2bit(t));
    printf("\n# tag2str:");
    for (t = -1; t <= 31; t++)
        printf(" %s,", ASN1_tag2str(t));
    printf(" %s %s %s\n", ASN1_tag2str(V_ASN1_NEG_INTEGER), ASN1_tag2str(V_ASN1_NEG_ENUMERATED), ASN1_tag2str(0x102));
    check(1, "ASN1_tag2bit and ASN1_tag2str");
}

int main(void)
{
    utf8();
    mbstrings();
    tables();
    printing();
    misc();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
