/*
 * Conformance test for the rest of the item API: ASN1_item_dup(3) and ASN1_dup, the time
 * types' _dup functions, ASN1_item_pack(3)/unpack/unpack_ex, ASN1_TYPE_pack_sequence(3) and
 * unpack_sequence, ASN1_TYPE_set_int_octetstring(3)/get, and encoding to and decoding from BIOs
 * and FILEs (ASN1_item_i2d_bio(3), ASN1_item_d2i_bio and _ex, the _fp forms,
 * ASN1_item_i2d_mem_bio, ASN1_i2d_bio/ASN1_d2i_bio and their _fp forms), in TAP format. Reads
 * go through a memory BIO and through one that gives an octet at a time, over DER, BER,
 * concatenated elements, large content, and truncated or impossible lengths.
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

static void errors(const char *what)
{
    unsigned long code;
    const char *data;
    int flags;

    printf("# %s errors:", what);
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && data[0] != '\0')
            printf("[%s]", data);
    }
    printf("\n");
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

/* A SEQUENCE whose aux callback records each operation. */
typedef struct {
    ASN1_INTEGER *n;
    ASN1_UTF8STRING *s;
} TRACED;

static char trace[256];
static int veto = -1;

static int traced_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it, void *exarg)
{
    size_t used = strlen(trace);

    (void)in;
    (void)it;
    snprintf(trace + used, sizeof(trace) - used, " %d%s", operation, exarg != NULL ? "+" : "");
    return operation == veto ? 0 : 1;
}

ASN1_SEQUENCE_cb(TRACED, traced_cb) = {
    ASN1_SIMPLE(TRACED, n, ASN1_INTEGER),
    ASN1_OPT(TRACED, s, ASN1_UTF8STRING)
} ASN1_SEQUENCE_END_cb(TRACED, TRACED)

/* A BIO that reads from a buffer one octet at a time. */
static const unsigned char *trickle_data;
static size_t trickle_left;

static int trickle_read(BIO *b, char *out, int len)
{
    (void)b;
    if (len <= 0 || trickle_left == 0)
        return 0;
    *out = (char)*trickle_data++;
    trickle_left--;
    return 1;
}

static long trickle_ctrl(BIO *b, int cmd, long larg, void *parg)
{
    (void)b;
    (void)cmd;
    (void)larg;
    (void)parg;
    return 0;
}

static BIO *trickle(const unsigned char *data, size_t len)
{
    static BIO_METHOD *meth = NULL;
    BIO *b;

    if (meth == NULL) {
        meth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "trickle");
        BIO_meth_set_read(meth, trickle_read);
        BIO_meth_set_ctrl(meth, trickle_ctrl);
    }
    trickle_data = data;
    trickle_left = len;
    b = BIO_new(meth);
    BIO_set_init(b, 1);
    return b;
}

static void dups(void)
{
    const ASN1_ITEM *it = ASN1_ITEM_rptr(TRACED);
    TRACED *t = (TRACED *)ASN1_item_new(it), *c;
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new(), *os2;
    ASN1_TIME *tm = ASN1_TIME_new(), *tm2;
    ASN1_UTCTIME *u, *u2;
    ASN1_GENERALIZEDTIME *g, *g2;

    ASN1_INTEGER_set(t->n, 42);
    trace[0] = 0;
    c = (TRACED *)ASN1_item_dup(it, t);
    printf("# dup trace:%s\n", trace);
    check(c != NULL && c != t && ASN1_INTEGER_get(c->n) == 42 && c->s == NULL, "ASN1_item_dup copies");
    check(strcmp(trace, " 14 16+ 17+ 6 6 7 0 1 4 5 15+") == 0,
          "DUP_PRE, GET0_LIBCTX, GET0_PROPQ, the encoding and decoding, then DUP_POST with the original");
    ASN1_item_free((ASN1_VALUE *)c, it);
    veto = ASN1_OP_DUP_POST;
    trace[0] = 0;
    c = (TRACED *)ASN1_item_dup(it, t);
    errors("DUP_POST vetoed");
    check(c == NULL, "a callback's 0 fails it");
    veto = ASN1_OP_DUP_PRE;
    check(ASN1_item_dup(it, t) == NULL, "before encoding too");
    errors("DUP_PRE vetoed");
    veto = -1;
    check(ASN1_item_dup(it, NULL) == NULL, "NULL gives NULL");
    ASN1_item_free((ASN1_VALUE *)t, it);

    ASN1_STRING_set(os, "abc", 3);
    os2 = ASN1_dup((i2d_of_void *)i2d_ASN1_OCTET_STRING, (d2i_of_void *)d2i_ASN1_OCTET_STRING, os);
    check(os2 != NULL && ASN1_STRING_cmp(os, os2) == 0, "ASN1_dup through i2d and d2i functions");
    check(ASN1_dup((i2d_of_void *)i2d_ASN1_OCTET_STRING, (d2i_of_void *)d2i_ASN1_OCTET_STRING, NULL) == NULL,
          "and NULL gives NULL");
    ASN1_OCTET_STRING_free(os2);

    ASN1_TIME_set_string(tm, "20240229123456Z");
    tm2 = ASN1_TIME_dup(tm);
    check(tm2 != NULL && tm2->type == V_ASN1_GENERALIZEDTIME && ASN1_TIME_compare(tm, tm2) == 0, "ASN1_TIME_dup");
    u = ASN1_UTCTIME_set(NULL, 0);
    u2 = ASN1_UTCTIME_dup(u);
    check(u2 != NULL && ASN1_STRING_cmp(u, u2) == 0, "ASN1_UTCTIME_dup");
    g = ASN1_GENERALIZEDTIME_set(NULL, 0);
    g2 = ASN1_GENERALIZEDTIME_dup(g);
    check(g2 != NULL && ASN1_STRING_cmp(g, g2) == 0, "ASN1_GENERALIZEDTIME_dup");
    check(ASN1_TIME_dup(NULL) == NULL, "of NULL, NULL");
    ASN1_OCTET_STRING_free(os);
    ASN1_TIME_free(tm);
    ASN1_TIME_free(tm2);
    ASN1_UTCTIME_free(u);
    ASN1_UTCTIME_free(u2);
    ASN1_GENERALIZEDTIME_free(g);
    ASN1_GENERALIZEDTIME_free(g2);
}

static void packing(void)
{
    const ASN1_ITEM *it = ASN1_ITEM_rptr(TRACED);
    TRACED *t = (TRACED *)ASN1_item_new(it), *back;
    ASN1_STRING *oct, *oct2 = NULL, *bad;
    ASN1_TYPE *at = NULL, *at2;
    unsigned char data[8];
    long num = 0;
    int n;

    ASN1_INTEGER_set(t->n, 7);
    oct = ASN1_item_pack(t, it, NULL);
    check(oct != NULL && oct->type == V_ASN1_OCTET_STRING && oct->length == 5
              && memcmp(oct->data, "\x30\x03\x02\x01\x07", 5) == 0,
          "ASN1_item_pack into a new OCTET STRING");
    check(ASN1_item_pack(t, it, &oct2) == oct2 && oct2 != NULL && ASN1_STRING_cmp(oct, oct2) == 0,
          "storing it in *oct");
    ASN1_INTEGER_set(t->n, 300);
    check(ASN1_item_pack(t, it, &oct2) == oct2 && oct2->length == 6, "or replacing what *oct held");
    back = (TRACED *)ASN1_item_unpack(oct, it);
    check(back != NULL && ASN1_INTEGER_get(back->n) == 7, "ASN1_item_unpack");
    ASN1_item_free((ASN1_VALUE *)back, it);
    back = (TRACED *)ASN1_item_unpack_ex(oct2, it, NULL, NULL);
    check(back != NULL && ASN1_INTEGER_get(back->n) == 300, "ASN1_item_unpack_ex");
    ASN1_item_free((ASN1_VALUE *)back, it);
    bad = ASN1_OCTET_STRING_new();
    ASN1_STRING_set(bad, "\x30\x05", 2);
    check(ASN1_item_unpack(bad, it) == NULL, "bad octets don't unpack");
    errors("unpack");
    ASN1_INTEGER_free(t->n);
    t->n = NULL;
    check(ASN1_item_pack(t, it, NULL) == NULL, "a value that doesn't encode doesn't pack");
    errors("pack");
    t->n = ASN1_INTEGER_new();

    ASN1_INTEGER_set(t->n, 9);
    check(ASN1_TYPE_pack_sequence(it, t, &at) == at && at != NULL && at->type == V_ASN1_SEQUENCE,
          "ASN1_TYPE_pack_sequence makes an ASN1_TYPE");
    at2 = ASN1_TYPE_pack_sequence(it, t, NULL);
    check(at2 != NULL && ASN1_TYPE_cmp(at, at2) == 0, "or returns one");
    back = (TRACED *)ASN1_TYPE_unpack_sequence(it, at);
    check(back != NULL && ASN1_INTEGER_get(back->n) == 9, "ASN1_TYPE_unpack_sequence");
    ASN1_item_free((ASN1_VALUE *)back, it);
    ASN1_TYPE_set(at2, V_ASN1_NULL, NULL);
    check(ASN1_TYPE_unpack_sequence(it, at2) == NULL && ASN1_TYPE_unpack_sequence(it, NULL) == NULL,
          "but not from another type");

    check(ASN1_TYPE_set_int_octetstring(at, 0x100000005L, (unsigned char *)"hello", 5) == 1,
          "ASN1_TYPE_set_int_octetstring");
    memset(data, 0xee, sizeof(data));
    n = ASN1_TYPE_get_int_octetstring(at, &num, data, 3);
    printf("# int octetstring: %d %ld\n", n, num);
    check(n == 5 && num == 5 && memcmp(data, "hel\xee", 4) == 0, "get: the length, the number (32 bits), the octets");
    check(ASN1_TYPE_set_int_octetstring(at, -2, (unsigned char *)"", 0) == 1
              && ASN1_TYPE_get_int_octetstring(at, &num, NULL, 0) == 0 && num == -2,
          "a negative number and no octets");
    check(ASN1_TYPE_get_int_octetstring(at2, &num, data, 8) == -1, "not from a NULL");
    errors("int octetstring");
    ASN1_TYPE_set(at2, V_ASN1_SEQUENCE, ASN1_STRING_dup(bad));
    check(ASN1_TYPE_get_int_octetstring(at2, &num, data, 8) == -1, "nor from a bad SEQUENCE");
    errors("bad sequence");
    check(ASN1_TYPE_set_int_octetstring(NULL, 1, (unsigned char *)"x", 1) == 1, "with NULL, made and dropped");
    ASN1_STRING_free(bad);
    ASN1_STRING_free(oct);
    ASN1_STRING_free(oct2);
    ASN1_TYPE_free(at);
    ASN1_TYPE_free(at2);
    ASN1_item_free((ASN1_VALUE *)t, it);
}

/* Reads elements from `der` (hex) through a memory BIO, or a trickle BIO, until one fails. */
static int read_all(const char *what, const char *hex, int slow)
{
    static unsigned char buf[70000];
    size_t n = unhex(hex, buf);
    BIO *b = slow ? trickle(buf, n) : BIO_new_mem_buf(buf, (int)n);
    ASN1_TYPE *t;
    int count = 0;

    printf("# %s%s:", what, slow ? " (trickle)" : "");
    while ((t = (ASN1_TYPE *)ASN1_item_d2i_bio(ASN1_ITEM_rptr(ASN1_ANY), b, NULL)) != NULL) {
        printf(" %d", t->type);
        count++;
        ASN1_TYPE_free(t);
    }
    printf(" (%d)\n", count);
    errors(what);
    BIO_free(b);
    return count;
}

static void bios(void)
{
    static unsigned char big[40010];
    const ASN1_ITEM *os = ASN1_ITEM_rptr(ASN1_OCTET_STRING);
    ASN1_OCTET_STRING *s = ASN1_OCTET_STRING_new(), *back;
    BIO *mem = BIO_new(BIO_s_mem()), *b;
    int slow;
    char *p;
    long len;

    check(read_all("empty", "", 0) == 0, "no input: nothing, and no error");
    for (slow = 0; slow <= 1; slow++) {
        check(read_all("three", "02 01 05 05 00 04 02 61 62", slow) == 3, "concatenated elements, then a clean end");
        check(read_all("BER", "30 80 24 80 04 01 61 00 00 02 01 01 00 00 05 00", slow) == 2,
              "an indefinite element is read to its EOC");
        check(read_all("high tag", "1f 81 01 01 00 9f 82 03 00", slow) == 2, "high tag numbers");
        check(read_all("long length", "04 82 00 02 61 62", slow) == 1, "a long-form length");
        check(read_all("truncated", "02 01 05 04 05 61 62", slow) == 1, "a truncated element is NOT_ENOUGH_DATA");
        check(read_all("truncated header", "02 01 05 04", slow) == 1, "so is a truncated header");
        check(read_all("missing EOC", "30 80 02 01 05", slow) == 0, "and a missing EOC");
        check(read_all("huge length", "04 84 7f ff ff ff 61", slow) == 0, "a length the input doesn't back");
        check(read_all("too long", "04 89 01 00 00 00 00 00 00 00 00", slow) == 0, "a length of 9 octets");
        check(read_all("tag too long", "1f 81 81 81 81 81 01 00", slow) == 0, "a tag number of 6 octets");
    }

    memset(big, 'z', sizeof(big));
    ASN1_STRING_set(s, big, 40000);
    check(ASN1_item_i2d_bio(os, mem, s) == 1, "ASN1_item_i2d_bio");
    len = BIO_get_mem_data(mem, &p);
    check(len == 40004 && (unsigned char)p[1] == 0x82, "writes the encoding");
    back = (ASN1_OCTET_STRING *)ASN1_item_d2i_bio(os, mem, NULL);
    check(back != NULL && ASN1_STRING_cmp(s, back) == 0, "and ASN1_item_d2i_bio reads 40000 octets back");
    ASN1_OCTET_STRING_free(back);
    b = ASN1_item_i2d_mem_bio(os, (ASN1_VALUE *)s);
    check(b != NULL && BIO_pending(b) == 40004, "ASN1_item_i2d_mem_bio");
    back = NULL;
    check(ASN1_item_d2i_bio_ex(os, b, &back, NULL, NULL) == back && back != NULL, "ASN1_item_d2i_bio_ex into *x");
    ASN1_OCTET_STRING_free(back);
    BIO_free(b);
    check(ASN1_item_i2d_mem_bio(os, NULL) == NULL && ASN1_item_d2i_bio(os, NULL, NULL) == NULL, "NULL arguments");
    errors("NULL");

    ASN1_STRING_set(s, "xyz", 3);
    check(ASN1_i2d_bio((i2d_of_void *)i2d_ASN1_OCTET_STRING, mem, s) == 1, "ASN1_i2d_bio");
    back = ASN1_d2i_bio((void *(*)(void))ASN1_OCTET_STRING_new, (d2i_of_void *)d2i_ASN1_OCTET_STRING, mem, NULL);
    check(back != NULL && ASN1_STRING_cmp(s, back) == 0, "ASN1_d2i_bio");
    ASN1_OCTET_STRING_free(back);
    ASN1_OCTET_STRING_free(s);
    BIO_free(mem);
}

static void files(void)
{
    const ASN1_ITEM *in = ASN1_ITEM_rptr(ASN1_INTEGER);
    FILE *f = tmpfile();
    ASN1_INTEGER *a = ASN1_INTEGER_new(), *b, *c = NULL;

    ASN1_INTEGER_set(a, 123456);
    check(ASN1_item_i2d_fp(in, f, a) == 1 && ASN1_i2d_fp((i2d_of_void *)i2d_ASN1_INTEGER, f, a) == 1
              && ASN1_item_i2d_fp(in, f, a) == 1,
          "ASN1_item_i2d_fp and ASN1_i2d_fp");
    rewind(f);
    b = (ASN1_INTEGER *)ASN1_item_d2i_fp(in, f, NULL);
    check(b != NULL && ASN1_INTEGER_get(b) == 123456, "ASN1_item_d2i_fp");
    ASN1_INTEGER_free(b);
    b = ASN1_d2i_fp((void *(*)(void))ASN1_INTEGER_new, (d2i_of_void *)d2i_ASN1_INTEGER, f, NULL);
    check(b != NULL && ASN1_INTEGER_get(b) == 123456, "ASN1_d2i_fp");
    ASN1_INTEGER_free(b);
    check(ASN1_item_d2i_fp_ex(in, f, &c, NULL, NULL) == c && c != NULL && ASN1_INTEGER_get(c) == 123456,
          "ASN1_item_d2i_fp_ex");
    check(ASN1_item_d2i_fp(in, f, NULL) == NULL, "then the end of the file");
    errors("end of file");
    ASN1_INTEGER_free(a);
    ASN1_INTEGER_free(c);
    fclose(f);
}

int main(void)
{
    dups();
    packing();
    bios();
    files();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
