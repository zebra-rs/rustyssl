/*
 * Conformance test for i2a_ASN1_STRING, a2i_ASN1_STRING(3), and ASN1_buf_print, in TAP format:
 * strings written as hex (with the line breaks after 35 octets) and read back, hex lines with
 * continuations, CR/LF, trailing junk, and each error, through a small line buffer too; and
 * octets printed for key components at several indents. Every output and error is printed.
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

static void errors(const char *what)
{
    unsigned long code;

    printf("# %s errors:", what);
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

/* Prints the BIO's contents with newlines as "|", and empties it. */
static void show(const char *what, BIO *mem)
{
    char *p;
    long len = BIO_get_mem_data(mem, &p), i;

    printf("# %s: \"", what);
    for (i = 0; i < len; i++)
        putchar(p[i] == '\n' ? '|' : p[i]);
    printf("\"\n");
    (void)BIO_reset(mem);
}

/* Reads `text` with a2i_ASN1_STRING through a buffer of `size`, printing the result. */
static int read_hex(const char *what, const char *text, int size)
{
    BIO *in = BIO_new_mem_buf(text, -1);
    ASN1_STRING *s = ASN1_STRING_new();
    char buf[256];
    int r, i;

    memset(buf, 'Z', sizeof(buf));
    r = a2i_ASN1_STRING(in, s, buf, size);
    printf("# %s: %d, %d octets:", what, r, s->length);
    for (i = 0; i < s->length; i++)
        printf(" %02x", s->data[i]);
    printf(", left %d\n", (int)BIO_pending(in));
    errors(what);
    ASN1_STRING_free(s);
    BIO_free(in);
    return r;
}

static void writing(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    ASN1_STRING *s = ASN1_STRING_new();
    unsigned char octets[80];
    int i, n;

    check(i2a_ASN1_STRING(mem, NULL, 0) == 0, "i2a_ASN1_STRING of NULL writes nothing");
    n = i2a_ASN1_STRING(mem, s, V_ASN1_OCTET_STRING);
    show("empty", mem);
    check(n == 1, "an empty string is 0");
    for (i = 0; i < 80; i++)
        octets[i] = (unsigned char)(i * 7 + 1);
    ASN1_STRING_set(s, octets, 3);
    n = i2a_ASN1_STRING(mem, s, V_ASN1_OCTET_STRING);
    show("three", mem);
    check(n == 6, "uppercase hex");
    ASN1_STRING_set(s, octets, 80);
    n = i2a_ASN1_STRING(mem, s, V_ASN1_OCTET_STRING);
    show("eighty", mem);
    check(n == 164, "a backslash and newline after each 35 octets");
    ASN1_STRING_free(s);
    BIO_free(mem);
}

static void reading(void)
{
    check(read_hex("one line", "0aFf10\n", 256) == 1, "a2i_ASN1_STRING reads a line");
    check(read_hex("crlf", "0102\r\n", 256) == 1, "and drops CR LF");
    check(read_hex("continued", "0102\\\n0304\\\n05\n", 256) == 0, "a backslash takes the digit before it, leaving an odd count");
    check(read_hex("continued even", "01020\\\n0304\n", 256) == 1, "so the digit before it is dropped");
    check(read_hex("trailing junk", "0a0b junk\n", 256) == 0, "a line is cut only at its last character, so junk is read");
    check(read_hex("junk inside", "0a x0b\n", 256) == 0, "so non-hex before it is an error");
    check(read_hex("leading junk", "x0a0\n", 256) == 0, "the first character isn't looked at");
    check(read_hex("odd", "abc\n", 256) == 0, "an odd count");
    check(read_hex("short", "a\n", 256) == 0, "a line of one");
    check(read_hex("blank", "\n", 256) == 0, "a blank line");
    check(read_hex("nothing", "", 256) == 1, "no input at all is an empty string");
    check(read_hex("no newline", "0102", 256) == 1, "a last line without a newline");
    check(read_hex("unfinished", "0102\\\n", 256) == 0, "a continuation with no next line");
    check(read_hex("small buffer", "0102030405060708\n", 5) == 1, "a buffer shorter than the line");
    check(read_hex("round trip", "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223\\\n2425\n", 256) == 0,
          "so what i2a_ASN1_STRING writes doesn't read back");
}

static void buf_print(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    unsigned char octets[40];
    int i;

    for (i = 0; i < 40; i++)
        octets[i] = (unsigned char)(255 - i);
    check(ASN1_buf_print(mem, octets, 1, 0) == 1, "ASN1_buf_print of one octet");
    show("one", mem);
    check(ASN1_buf_print(mem, octets, 40, 4) == 1, "of 40, 15 to a line, indented");
    show("forty", mem);
    check(ASN1_buf_print(mem, octets, 15, 200) == 1, "indent capped at 128");
    show("capped", mem);
    check(ASN1_buf_print(mem, octets, 0, 4) == 1, "of none, a newline");
    show("none", mem);
    BIO_free(mem);
}

int main(void)
{
    writing();
    reading();
    buf_print();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
