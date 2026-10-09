/*
 * Conformance test for ASN.1 identifier and length octets (ASN1_get_object(3), ASN1_put_object,
 * ASN1_put_eoc, ASN1_object_size, ASN1_check_infinite_end) and for d2i_ASN1_OBJECT and
 * i2d_ASN1_OBJECT, in TAP format. Every header read is printed (result, outputs, octets used,
 * and error), outputs preset to -7 so that which ones are written is compared too.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
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

static void errors(void)
{
    unsigned long code;

    printf(" errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void read_header(const char *what, const unsigned char *in, long omax)
{
    const unsigned char *p = in;
    long length = -7;
    int tag = -7, class = -7;
    int ret = ASN1_get_object(&p, &length, &tag, &class, omax);

    printf("# %s: ret=%#x tag=%d class=%#x length=%ld used=%d", what, ret, tag, class, length, (int)(p - in));
    errors();
}

static void headers(void)
{
    static const unsigned char seq[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
    static const unsigned char long_form[] = { 0x04, 0x84, 0x00, 0x00, 0x00, 0x01, 0xaa };
    static const unsigned char high_tag[] = { 0x9f, 0x80, 0x80, 0x81, 0x01, 0x00 };
    static const unsigned char big_tag[] = { 0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00 };
    static const unsigned char small_high[] = { 0x5f, 0x05, 0x01, 0xbb };
    static const unsigned char indefinite[] = { 0x30, 0x80, 0x00, 0x00 };
    static const unsigned char prim_indef[] = { 0x04, 0x80, 0x00, 0x00 };
    static const unsigned char nine[] = { 0x04, 0x89, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
    static const unsigned char huge[] = { 0x04, 0x88, 0x80, 0, 0, 0, 0, 0, 0, 0 };
    static const unsigned char max_long[] = { 0x04, 0x88, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    static const unsigned char zeros[] = { 0x04, 0x8a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 1, 2 };
    static const unsigned char private_tag[] = { 0xff, 0x01, 0x00 };

    read_header("seq", seq, sizeof(seq));
    read_header("seq, claimed huge", seq, LONG_MAX);
    read_header("seq, short", seq, 4);
    read_header("seq, header only", seq, 2);
    read_header("seq, one octet", seq, 1);
    read_header("seq, none", seq, 0);
    read_header("seq, negative", seq, -1);
    read_header("long form", long_form, sizeof(long_form));
    read_header("long form, cut", long_form, 4);
    read_header("high tag with 0x80s", high_tag, sizeof(high_tag));
    read_header("high tag too big", big_tag, sizeof(big_tag));
    read_header("small high tag", small_high, sizeof(small_high));
    read_header("high tag, cut", small_high, 2);
    read_header("indefinite", indefinite, sizeof(indefinite));
    read_header("primitive indefinite", prim_indef, sizeof(prim_indef));
    read_header("nine length octets", nine, sizeof(nine));
    read_header("past LONG_MAX", huge, sizeof(huge));
    read_header("LONG_MAX", max_long, sizeof(max_long));
    read_header("leading zeros", zeros, sizeof(zeros));
    read_header("leading zeros, cut", zeros, 10);
    read_header("private", private_tag, sizeof(private_tag));
    check(1, "headers read");
}

static void put(const char *what, int constructed, int length, int tag, int xclass)
{
    unsigned char buf[32], *p = buf;
    int i, size = ASN1_object_size(constructed, length, tag);

    memset(buf, 0xee, sizeof(buf));
    ASN1_put_object(&p, constructed, length, tag, xclass);
    printf("# put %s: size=%d wrote", what, size);
    for (i = 0; i < (int)(p - buf); i++)
        printf(" %02x", buf[i]);
    printf("\n");
}

static void writing(void)
{
    unsigned char buf[4] = { 0xee, 0xee, 0xee, 0xee }, *p = buf;
    const unsigned char *c;
    unsigned char *m;

    put("primitive", 0, 5, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL);
    put("constructed", 1, 300, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    put("indefinite", 2, 300, V_ASN1_SEQUENCE, V_ASN1_CONTEXT_SPECIFIC);
    put("tag 30", 0, 0, 30, V_ASN1_APPLICATION);
    put("tag 31", 0, 0, 31, V_ASN1_APPLICATION);
    put("tag 128", 1, 128, 128, V_ASN1_PRIVATE);
    put("tag 2^20", 0, 70000, 1 << 20, V_ASN1_CONTEXT_SPECIFIC);
    put("big length", 0, INT_MAX - 10, 4, 0);
    put("constructed 5", 5, 1, 4, 0);
    put("class bits only", 0, 1, 4, 0x1ff);
    check(ASN1_object_size(0, -1, 4) == -1 && ASN1_object_size(0, INT_MAX - 5, 4) == -1
              && ASN1_object_size(0, INT_MAX - 7, 4) == INT_MAX - 1,
          "ASN1_object_size's limits");
    check(ASN1_put_eoc(&p) == 2 && p == buf + 2 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0xee,
          "ASN1_put_eoc");
    c = buf;
    check(ASN1_const_check_infinite_end(&c, 4) == 1 && c == buf + 2, "the end of contents is found");
    check(ASN1_const_check_infinite_end(&c, 2) == 0 && c == buf + 2, "and nothing else");
    check(ASN1_const_check_infinite_end(&c, 1) == 0 && ASN1_const_check_infinite_end(&c, 0) == 1
              && ASN1_const_check_infinite_end(&c, -3) == 1,
          "one octet isn't an end, none is");
    m = buf;
    check(ASN1_check_infinite_end(&m, 2) == 1 && m == buf + 2, "ASN1_check_infinite_end");
}

static void show_object(const char *what, const unsigned char *in, long len, ASN1_OBJECT **a)
{
    const unsigned char *p = in;
    ASN1_OBJECT *o = d2i_ASN1_OBJECT(a, &p, len);
    char text[80] = "";

    if (o != NULL)
        OBJ_obj2txt(text, sizeof(text), o, 1);
    printf("# d2i %s: %s nid=%d \"%s\" used=%d", what, o == NULL ? "NULL" : "object", OBJ_obj2nid(o), text,
           (int)(p - in));
    errors();
    if (a == NULL && o != NULL && o != OBJ_nid2obj(OBJ_obj2nid(o)))
        ASN1_OBJECT_free(o);
}

static void objects(void)
{
    static const unsigned char cn[] = { 0x06, 0x03, 0x55, 0x04, 0x03, 0xff };
    static const unsigned char unknown[] = { 0x06, 0x04, 0x2a, 0x03, 0x04, 0x05 };
    static const unsigned char tagged[] = { 0x86, 0x03, 0x55, 0x04, 0x03 };
    static const unsigned char constructed[] = { 0x26, 0x03, 0x55, 0x04, 0x03 };
    static const unsigned char indefinite[] = { 0x26, 0x80, 0x00, 0x00 };
    static const unsigned char wrong[] = { 0x04, 0x01, 0x00 };
    static const unsigned char empty[] = { 0x06, 0x00 };
    static const unsigned char open_end[] = { 0x06, 0x02, 0x2a, 0x83 };
    static const unsigned char leading80[] = { 0x06, 0x03, 0x2a, 0x80, 0x01 };
    static const unsigned char overrun[] = { 0x06, 0x05, 0x2a, 0x03 };
    unsigned char *der = NULL, buf[16], *p;
    ASN1_OBJECT *a = NULL, *kept;
    int n;

    show_object("CN", cn, sizeof(cn), NULL);
    show_object("unknown", unknown, sizeof(unknown), NULL);
    show_object("context tag", tagged, sizeof(tagged), NULL);
    show_object("constructed", constructed, sizeof(constructed), NULL);
    show_object("indefinite", indefinite, sizeof(indefinite), NULL);
    show_object("wrong tag", wrong, sizeof(wrong), NULL);
    show_object("empty", empty, sizeof(empty), NULL);
    show_object("open end", open_end, sizeof(open_end), NULL);
    show_object("leading 0x80", leading80, sizeof(leading80), NULL);
    show_object("overrun", overrun, sizeof(overrun), NULL);
    show_object("no length", cn, 0, NULL);
    check(d2i_ASN1_OBJECT(NULL, &(const unsigned char *){ cn }, sizeof(cn)) == OBJ_nid2obj(NID_commonName),
          "a known OID gives the shared object");

    a = ASN1_OBJECT_create(5000, (unsigned char *)"\x2a\x03\x05\x06\x07", 5, "sn", "ln");
    kept = a;
    show_object("into a dynamic object", unknown, sizeof(unknown), &a);
    check(a == kept && OBJ_obj2nid(a) == 5000 && OBJ_nid2sn(5000) == NULL, "it is reused, keeping its NID");
    ERR_clear_error();
    show_object("a known one replaces it", cn, sizeof(cn), &a);
    check(a == OBJ_nid2obj(NID_commonName), "with the shared object");
    a = OBJ_nid2obj(NID_sha1);
    show_object("into a built-in object", unknown, sizeof(unknown), &a);
    check(a != OBJ_nid2obj(NID_sha1), "which is left alone");
    ASN1_OBJECT_free(a);

    a = OBJ_txt2obj("1.2.3.4.5", 1);
    n = i2d_ASN1_OBJECT(a, NULL);
    check(n == 6, "i2d_ASN1_OBJECT measures");
    check(i2d_ASN1_OBJECT(a, &der) == 6 && der != NULL && memcmp(der, "\x06\x04\x2a\x03\x04\x05", 6) == 0,
          "allocates");
    OPENSSL_free(der);
    p = buf;
    check(i2d_ASN1_OBJECT(OBJ_nid2obj(NID_sha256), &p) == 11 && p == buf + 11 && buf[0] == 0x06 && buf[1] == 9,
          "and writes in place");
    check(i2d_ASN1_OBJECT(NULL, &p) == 0 && i2d_ASN1_OBJECT(OBJ_nid2obj(NID_iso), &p) == 0
              && i2d_ASN1_OBJECT(OBJ_nid2obj(NID_undef), NULL) == 0,
          "objects without content encode to nothing");
    ASN1_OBJECT_free(a);
    errors();
}

int main(void)
{
    headers();
    writing();
    objects();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
