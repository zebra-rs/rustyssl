/*
 * Conformance test for BIT STRING bits and named bits (ASN1_BIT_STRING_set_bit(3),
 * ASN1_BIT_STRING_get_bit, ASN1_BIT_STRING_check, ASN1_BIT_STRING_set,
 * ASN1_BIT_STRING_num_asc, ASN1_BIT_STRING_set_asc, ASN1_BIT_STRING_name_print), in TAP format.
 * The octets and flags after each change are printed, so they're compared too.
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

static void show(const char *what, const ASN1_BIT_STRING *s)
{
    int i;

    printf("# %s: len=%d flags=%#lx [", what, s->length, s->flags);
    for (i = 0; i < s->length; i++)
        printf("%02x", s->data[i]);
    printf("]\n");
}

static void bits(void)
{
    ASN1_BIT_STRING *s = ASN1_BIT_STRING_new();
    int ok = 1, i;

    check(ASN1_BIT_STRING_set_bit(s, 0, 0) == 1 && s->length == 0 && s->data == NULL,
          "clearing a bit past the end does nothing");
    check(ASN1_BIT_STRING_set_bit(s, 9, 1) == 1, "setting bit 9 grows the string");
    show("bit 9", s);
    check(ASN1_BIT_STRING_set_bit(s, 0, 1) == 1 && ASN1_BIT_STRING_set_bit(s, 23, 7) == 1, "more bits");
    show("bits 0, 9, 23", s);
    for (i = 0; i < 30; i++)
        ok = ok && ASN1_BIT_STRING_get_bit(s, i) == (i == 0 || i == 9 || i == 23);
    check(ok, "get_bit reads them back, 0 past the end");
    check(ASN1_BIT_STRING_set_bit(s, 23, 0) == 1, "clearing the last bit");
    show("trailing zeros dropped", s);
    s->flags = ASN1_STRING_FLAG_BITS_LEFT | 3 | 0x100;
    check(ASN1_BIT_STRING_set_bit(s, 1, 1) == 1, "any change");
    show("drops the unused-bits flags", s);
    check(ASN1_BIT_STRING_set_bit(s, -1, 1) == 0 && ASN1_BIT_STRING_get_bit(s, -1) == 0
              && ASN1_BIT_STRING_set_bit(NULL, 1, 1) == 0 && ASN1_BIT_STRING_get_bit(NULL, 1) == 0,
          "negative bits and NULL");
    check(ASN1_BIT_STRING_set_bit(s, 0, 0) == 1 && ASN1_BIT_STRING_set_bit(s, 1, 0) == 1
              && ASN1_BIT_STRING_set_bit(s, 9, 0) == 1,
          "clearing every bit");
    show("empty again", s);
    check(ASN1_BIT_STRING_set(s, (unsigned char *)"\x00\x01\x00", 3) == 1 && s->length == 3,
          "ASN1_BIT_STRING_set keeps the octets as given");
    check(ASN1_BIT_STRING_set_bit(s, 0, 0) == 1, "and a change trims them");
    show("trimmed", s);
    ASN1_BIT_STRING_free(s);
}

static void checking(void)
{
    ASN1_BIT_STRING *s = ASN1_BIT_STRING_new();
    unsigned char allowed[] = { 0xc0, 0x01 };

    check(ASN1_BIT_STRING_check(NULL, allowed, 2) == 1 && ASN1_BIT_STRING_check(s, allowed, 2) == 1,
          "nothing set passes");
    ASN1_BIT_STRING_set_bit(s, 0, 1);
    ASN1_BIT_STRING_set_bit(s, 15, 1);
    check(ASN1_BIT_STRING_check(s, allowed, 2) == 1, "only allowed bits");
    check(ASN1_BIT_STRING_check(s, allowed, 1) == 0, "a bit past the flags fails");
    ASN1_BIT_STRING_set_bit(s, 2, 1);
    check(ASN1_BIT_STRING_check(s, allowed, 2) == 0, "a bit not allowed fails");
    ASN1_BIT_STRING_free(s);
}

static BIT_STRING_BITNAME usages[] = {
    { 0, "Digital Signature", "digitalSignature" },
    { 1, "Non Repudiation", "nonRepudiation" },
    { 2, "Key Encipherment", "keyEncipherment" },
    { 8, "Decipher Only", "decipherOnly" },
    { -1, NULL, NULL },
};

static void names(void)
{
    ASN1_BIT_STRING *s = ASN1_BIT_STRING_new();
    BIO *mem = BIO_new(BIO_s_mem());
    char *text;
    long len;

    check(ASN1_BIT_STRING_num_asc("keyEncipherment", usages) == 2
              && ASN1_BIT_STRING_num_asc("Decipher Only", usages) == 8
              && ASN1_BIT_STRING_num_asc("nope", usages) == -1,
          "ASN1_BIT_STRING_num_asc by short or long name");
    check(ASN1_BIT_STRING_set_asc(s, "digitalSignature", 1, usages) == 1
              && ASN1_BIT_STRING_set_asc(s, "Decipher Only", 1, usages) == 1
              && ASN1_BIT_STRING_set_asc(s, "nope", 1, usages) == 0
              && ASN1_BIT_STRING_set_asc(NULL, "nonRepudiation", 1, usages) == 1,
          "ASN1_BIT_STRING_set_asc");
    show("named bits", s);
    check(ASN1_BIT_STRING_name_print(mem, s, usages, 4) == 1 && ASN1_BIT_STRING_name_print(mem, s, usages, 0) == 1
              && ASN1_BIT_STRING_name_print(mem, s, usages, -3) == 1,
          "ASN1_BIT_STRING_name_print");
    ASN1_BIT_STRING_set_bit(s, 0, 0);
    ASN1_BIT_STRING_set_bit(s, 8, 0);
    ASN1_BIT_STRING_name_print(mem, s, usages, 2);
    len = BIO_get_mem_data(mem, &text);
    printf("# printed: \"");
    fwrite(text, 1, (size_t)len, stdout);
    printf("\"\n");
    BIO_free(mem);
    ASN1_BIT_STRING_free(s);
}

int main(void)
{
    bits();
    checking();
    names();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
