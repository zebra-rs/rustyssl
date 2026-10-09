/*
 * Conformance test for ASN1_parse(3) and ASN1_parse_dump, in TAP format: the asn1parse listing
 * of DER and BER of every kind of element (universal, context, application, private, and high
 * tags; printable and unprintable strings with each dump setting; good and bad INTEGERs,
 * BOOLEANs, and OBJECTs; indefinite lengths and end-of-contents octets; indentation), of
 * malformed input, and of nesting past the limit, through a memory BIO and through one that
 * already has a prefix. Every listing is printed, so the outputs are compared byte for byte.
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

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static size_t unhex(const char *hex, unsigned char *out)
{
    size_t n = 0;
    unsigned int byte;

    while (*hex != '\0') {
        if (*hex == ' ') {
            hex++;
            continue;
        }
        sscanf(hex, "%2x", &byte);
        out[n++] = (unsigned char)byte;
        hex += 2;
    }
    return n;
}

/* Prints the BIO's contents line by line, each after "# | ". */
static void show(BIO *mem)
{
    char *p, *end;
    long len = BIO_get_mem_data(mem, &p);

    end = p + len;
    while (p < end) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t n = nl != NULL ? (size_t)(nl - p) : (size_t)(end - p);

        printf("# | %.*s%s\n", (int)n, p, nl != NULL ? "" : "<no newline>");
        p += n + (nl != NULL ? 1 : 0);
    }
}

/* Lists `hex` with ASN1_parse_dump (dump < -1 means ASN1_parse), printing the result. */
static int listing(const char *what, const char *hex, int indent, int dump)
{
    static unsigned char buf[4096];
    size_t n = unhex(hex, buf);
    BIO *mem = BIO_new(BIO_s_mem());
    int r;
    unsigned long code;

    r = dump < -1 ? ASN1_parse(mem, buf, (long)n, indent) : ASN1_parse_dump(mem, buf, (long)n, indent, dump);
    printf("# %s: %d\n", what, r);
    show(mem);
    printf("# errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
    BIO_free(mem);
    return r;
}

static const char *const record =
    "30 81 c0"
    " 06 09 2a 86 48 86 f7 0d 01 01 0b"
    " 05 00"
    " 02 01 00 02 02 ff 7f 02 09 00 80 00 00 00 00 00 00 00"
    " 0a 01 85"
    " 01 01 ff"
    " 04 05 68 65 6c 6c 6f"
    " 04 06 00 01 02 7f 80 ff"
    " 04 05 30 03 02 01 05"
    " 03 03 06 00 40"
    " 13 03 61 62 63 0c 02 c3 a9 16 01 7e 17 0d 32 34 30 31 30 31 30 30 30 30 30 30 5a"
    " 18 0f 32 30 32 34 30 31 30 31 30 30 30 30 30 30 5a"
    " 1e 04 00 41 00 42"
    " a0 03 02 01 07"
    " 81 02 61 62"
    " 62 03 01 01 00"
    " c2 01 05"
    " 1f 1f 01 aa"
    " 3f 81 00 03 02 01 01"
    " 31 06 02 01 01 02 01 02"
    " 30 80 02 01 01 30 80 05 00 00 00 00 00"
    " 12 03 31 32 33 1a 01 41 14 01 54"
    " 07 02 41 42 08 00 09 00 0b 00 0d 00 1c 04 00 00 00 41";

static void listings(void)
{
    int dump;

    check(listing("record", record, 0, -2) == 1, "ASN1_parse of every kind of element");
    check(listing("record indented", record, 1, -2) == 1, "indented by depth");
    for (dump = -1; dump <= 4; dump += 5)
        check(listing(dump == -1 ? "dump all" : "dump 4", record, 0, dump) == 1, "ASN1_parse_dump");
    check(listing("dump 0", record, 0, 0) == 1, "ASN1_parse_dump with no dump writes hex");
}

static void bad(void)
{
    char deep[1200] = "", *q = deep;
    int i;

    check(listing("bad INTEGER", "30 0b 02 00 02 02 00 05 02 03 ff 80 00", 0, -2) == 1, "bad INTEGERs are dumped");
    check(listing("bad ENUMERATED", "0a 00 0a 02 00 01", 0, -2) == 1, "and bad ENUMERATEDs");
    check(listing("bad BOOLEAN", "01 02 00 ff 01 00", 0, -2) == 1, "and bad BOOLEANs");
    check(listing("bad OBJECT", "06 02 80 80 06 00", 0, -2) == 1, "and bad OBJECTs");
    check(listing("overrun", "30 05 02 01 01 04 05 61", 0, -2) == 0, "a length past the input");
    check(listing("bad header", "04 84 ff ff ff ff 00", 0, -2) == 0, "a bad header");
    check(listing("top EOC", "02 01 01 00 00 02 01 02", 0, -2) == 2, "an EOC at the top stops with 2");
    check(listing("missing EOC", "30 80 02 01 01", 0, -2) == 1, "an indefinite element without its EOC");
    check(listing("primitive indefinite", "04 80 00 00", 0, -2) == 0, "an indefinite primitive");
    check(listing("trailing", "02 01 01 ff", 0, -2) == 0, "a stray octet after an element");
    for (i = 0; i < 131; i++)
        q += sprintf(q, "30 80 ");
    check(listing("too deep", deep, 1, -2) == 0, "nesting past 128");
    check(listing("empty", "", 0, -2) == 1, "no input");
}

static void prefixed(void)
{
    static unsigned char buf[64];
    size_t n = unhex("30 06 02 01 05 0c 01 41", buf);
    BIO *mem = BIO_new(BIO_s_mem()), *pre = BIO_new(BIO_f_prefix());
    int r;

    BIO_push(pre, mem);
    BIO_set_prefix(pre, "PFX> ");
    BIO_set_indent(pre, 3);
    r = ASN1_parse(pre, buf, (long)n, 1);
    BIO_puts(pre, "after\n");
    show(mem);
    check(r == 1 && BIO_get_indent(pre) == 3, "a prefix BIO keeps its indent, and its prefix is replaced");
    BIO_free_all(pre);
    check(ASN1_parse(NULL, buf, (long)n, 0) == 0, "a NULL BIO fails");
    ERR_clear_error();
}

int main(void)
{
    listings();
    bad();
    prefixed();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
