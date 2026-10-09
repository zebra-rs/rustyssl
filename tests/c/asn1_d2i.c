/*
 * Conformance test for the template engine's decoding (ASN1_item_d2i(3), ASN1_item_d2i_ex,
 * ASN1_item_ex_d2i, and the universal types' d2i functions), in TAP format. Application types
 * are defined with the asn1t.h macros, so the engine walks this program's own tables. Inputs
 * cover DER and BER (indefinite lengths, constructed strings), OPTIONAL and tagged fields, SET OF,
 * a CHOICE, ANY DEFINED BY, the cached encoding, aux callbacks, and malformed input, whose error
 * queues (reasons and the "Field=, Type=" data) are printed for comparison.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
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

/* Prints and clears the error queue: library/reason and any data. */
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

static void hex(const char *what, const unsigned char *p, int len)
{
    int i;

    printf("# %s (%d):", what, len);
    for (i = 0; i < len; i++)
        printf(" %02x", p[i]);
    printf("\n");
}

/* Decodes `in` (hex) with `it`, printing what happened; returns the value (or NULL). */
static ASN1_VALUE *decode(const char *what, const char *in, const ASN1_ITEM *it, long *used)
{
    unsigned char buf[1024];
    size_t n = unhex(in, buf);
    const unsigned char *p = buf;
    ASN1_VALUE *v = ASN1_item_d2i(NULL, &p, (long)n, it);

    *used = (long)(p - buf);
    printf("# %s: %s, used %ld of %zu\n", what, v != NULL ? "decoded" : "failed", *used, n);
    if (v == NULL)
        errors(what);
    return v;
}

/* Decodes and re-encodes, returning whether the DER matches `expected` (hex, or NULL for the input). */
static int roundtrip(const char *what, const char *in, const ASN1_ITEM *it, const char *expected)
{
    unsigned char want[1024], *der = NULL;
    long used;
    ASN1_VALUE *v = decode(what, in, it, &used);
    size_t n = unhex(expected != NULL ? expected : in, want);
    int len, ok;

    if (v == NULL)
        return 0;
    len = ASN1_item_i2d(v, &der, it);
    hex(what, der, len);
    ok = len == (int)n && memcmp(der, want, n) == 0;
    OPENSSL_free(der);
    ASN1_item_free(v, it);
    return ok;
}

/* Returns whether decoding fails, printing the errors. */
static int refused(const char *what, const char *in, const ASN1_ITEM *it)
{
    long used;
    ASN1_VALUE *v = decode(what, in, it, &used);

    ASN1_item_free(v, it);
    return v == NULL && used == 0;
}

typedef struct {
    int type;
    union {
        ASN1_INTEGER *num;
        ASN1_UTF8STRING *str;
    } d;
} PICK;

ASN1_CHOICE(PICK) = {
    ASN1_SIMPLE(PICK, d.num, ASN1_INTEGER),
    ASN1_EXP(PICK, d.str, ASN1_UTF8STRING, 3)
} ASN1_CHOICE_END(PICK)

typedef struct {
    ASN1_INTEGER *version;
    ASN1_OCTET_STRING *opt;
    ASN1_IA5STRING *imp;
    ASN1_BOOLEAN fflag;
    STACK_OF(ASN1_INTEGER) *set;
    STACK_OF(ASN1_UTF8STRING) *seq;
    ASN1_STRING *dir;
    ASN1_TYPE *any;
    int32_t *i32;
    uint64_t *u64;
    uint32_t zu32;
    long l;
    long zl;
    ASN1_OCTET_STRING emb;
    PICK *pick;
    ASN1_TIME *when;
} RECORD;

ASN1_SEQUENCE(RECORD) = {
    ASN1_SIMPLE(RECORD, version, ASN1_INTEGER),
    ASN1_EXP_OPT(RECORD, opt, ASN1_OCTET_STRING, 0),
    ASN1_IMP_OPT(RECORD, imp, ASN1_IA5STRING, 1),
    ASN1_OPT(RECORD, fflag, ASN1_FBOOLEAN),
    ASN1_SET_OF(RECORD, set, ASN1_INTEGER),
    ASN1_IMP_SEQUENCE_OF(RECORD, seq, ASN1_UTF8STRING, 2),
    ASN1_SIMPLE(RECORD, dir, DIRECTORYSTRING),
    ASN1_SIMPLE(RECORD, any, ASN1_ANY),
    ASN1_SIMPLE(RECORD, i32, INT32),
    ASN1_SIMPLE(RECORD, u64, UINT64),
    ASN1_OPT_EMBED(RECORD, zu32, ZUINT32),
    ASN1_OPT(RECORD, l, LONG),
    ASN1_OPT(RECORD, zl, ZLONG),
    ASN1_EMBED(RECORD, emb, ASN1_OCTET_STRING),
    ASN1_SIMPLE(RECORD, pick, PICK),
    ASN1_OPT(RECORD, when, ASN1_TIME)
} ASN1_SEQUENCE_END(RECORD)

typedef struct {
    ASN1_OBJECT *type;
    void *value;
} ADBREC;

ASN1_ADB_TEMPLATE(ADBREC_default) = ASN1_SIMPLE(ADBREC, value, ASN1_ANY);

ASN1_ADB(ADBREC) = {
    ADB_ENTRY(NID_sha256, ASN1_SIMPLE(ADBREC, value, ASN1_INTEGER)),
    ADB_ENTRY(NID_sha1, ASN1_SIMPLE(ADBREC, value, ASN1_UTF8STRING))
} ASN1_ADB_END(ADBREC, 0, type, 0, &ADBREC_default_tt, NULL);

ASN1_SEQUENCE(ADBREC) = {
    ASN1_SIMPLE(ADBREC, type, ASN1_OBJECT),
    ASN1_ADB_OBJECT(ADBREC)
} ASN1_SEQUENCE_END(ADBREC)

/* A SEQUENCE keeping the encoding it was decoded from. */
typedef struct {
    ASN1_INTEGER *n;
    ASN1_OCTET_STRING *s;
    ASN1_ENCODING enc;
} CACHED;

ASN1_SEQUENCE_enc(CACHED, enc, NULL) = {
    ASN1_SIMPLE(CACHED, n, ASN1_INTEGER),
    ASN1_SIMPLE(CACHED, s, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END_enc(CACHED, CACHED)

/* A SEQUENCE whose aux callback records each operation. */
typedef struct {
    ASN1_INTEGER *n;
} TRACED;

static char trace[256];
static int veto = -1;

static int traced_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it, void *exarg)
{
    size_t used = strlen(trace);

    (void)in;
    (void)it;
    (void)exarg;
    snprintf(trace + used, sizeof(trace) - used, " %d", operation);
    return operation == veto ? 0 : 1;
}

ASN1_SEQUENCE_cb(TRACED, traced_cb) = {
    ASN1_SIMPLE(TRACED, n, ASN1_INTEGER)
} ASN1_SEQUENCE_END_cb(TRACED, TRACED)

/* A SEQUENCE that may hold itself, for the nesting limit. */
typedef struct NEST_st NEST;
struct NEST_st {
    NEST *inner;
};
DECLARE_ASN1_ITEM(NEST)

ASN1_SEQUENCE(NEST) = {
    ASN1_OPT(NEST, inner, NEST)
} ASN1_SEQUENCE_END(NEST)

static void universal(void)
{
    unsigned char buf[64];
    const unsigned char *p;
    ASN1_OCTET_STRING *os = NULL, *os2;
    ASN1_INTEGER *in;
    ASN1_BIT_STRING *bs;
    ASN1_TYPE *t;
    ASN1_STRING *s;
    ASN1_TIME *tm;
    ASN1_NULL *null;
    size_t n;

    n = unhex("04 03 61 62 63 ff", buf);
    p = buf;
    os = d2i_ASN1_OCTET_STRING(NULL, &p, (long)n);
    check(os != NULL && os->length == 3 && memcmp(os->data, "abc", 3) == 0 && p == buf + 5,
          "d2i_ASN1_OCTET_STRING reads one value and moves the pointer");
    p = buf;
    os2 = d2i_ASN1_OCTET_STRING(&os, &p, (long)n);
    check(os2 == os, "and decodes into an existing one");
    ASN1_OCTET_STRING_free(os);

    n = unhex("02 02 ff 7f", buf);
    p = buf;
    in = d2i_ASN1_INTEGER(NULL, &p, (long)n);
    check(in != NULL && in->type == V_ASN1_NEG_INTEGER && ASN1_INTEGER_get(in) == -129, "d2i_ASN1_INTEGER, negative");
    ASN1_INTEGER_free(in);
    n = unhex("0a 01 05", buf);
    p = buf;
    in = d2i_ASN1_ENUMERATED(NULL, &p, (long)n);
    check(in != NULL && in->type == V_ASN1_ENUMERATED && ASN1_ENUMERATED_get(in) == 5, "d2i_ASN1_ENUMERATED");
    ASN1_ENUMERATED_free(in);
    n = unhex("03 03 06 00 40", buf);
    p = buf;
    bs = d2i_ASN1_BIT_STRING(NULL, &p, (long)n);
    check(bs != NULL && bs->length == 2 && (bs->flags & 0x0f) == (ASN1_STRING_FLAG_BITS_LEFT | 6)
              && ASN1_BIT_STRING_get_bit(bs, 9) == 1,
          "d2i_ASN1_BIT_STRING keeps the unused-bits count");
    ASN1_BIT_STRING_free(bs);
    n = unhex("03 01 00", buf);
    p = buf;
    bs = d2i_ASN1_BIT_STRING(NULL, &p, (long)n);
    check(bs != NULL && bs->length == 0 && bs->data == NULL, "an empty BIT STRING has no data");
    ASN1_BIT_STRING_free(bs);

#define STRING_D2I(fn, freefn, der, len_)              \
    n = unhex(der, buf);                               \
    p = buf;                                           \
    s = fn(NULL, &p, (long)n);                         \
    check(s != NULL && s->length == len_ && p == buf + n, #fn); \
    freefn(s)
    STRING_D2I(d2i_ASN1_UTF8STRING, ASN1_UTF8STRING_free, "0c 02 c3 a9", 2);
    STRING_D2I(d2i_ASN1_PRINTABLESTRING, ASN1_PRINTABLESTRING_free, "13 01 41", 1);
    STRING_D2I(d2i_ASN1_T61STRING, ASN1_T61STRING_free, "14 01 41", 1);
    STRING_D2I(d2i_ASN1_IA5STRING, ASN1_IA5STRING_free, "16 01 41", 1);
    STRING_D2I(d2i_ASN1_GENERALSTRING, ASN1_GENERALSTRING_free, "1b 01 41", 1);
    STRING_D2I(d2i_ASN1_UTCTIME, ASN1_UTCTIME_free, "17 0d 32 34 30 31 30 31 30 30 30 30 30 30 5a", 13);
    STRING_D2I(d2i_ASN1_GENERALIZEDTIME, ASN1_GENERALIZEDTIME_free,
               "18 0f 32 30 32 34 30 31 30 31 30 30 30 30 30 30 5a", 15);
    STRING_D2I(d2i_ASN1_VISIBLESTRING, ASN1_VISIBLESTRING_free, "1a 01 41", 1);
    STRING_D2I(d2i_ASN1_UNIVERSALSTRING, ASN1_UNIVERSALSTRING_free, "1c 04 00 00 00 41", 4);
    STRING_D2I(d2i_ASN1_BMPSTRING, ASN1_BMPSTRING_free, "1e 02 00 41", 2);
    STRING_D2I(d2i_ASN1_PRINTABLE, ASN1_PRINTABLE_free, "16 01 41", 1);
    STRING_D2I(d2i_DIRECTORYSTRING, DIRECTORYSTRING_free, "0c 01 41", 1);
    STRING_D2I(d2i_DISPLAYTEXT, DISPLAYTEXT_free, "1a 01 41", 1);

    n = unhex("05 00", buf);
    p = buf;
    null = d2i_ASN1_NULL(NULL, &p, (long)n);
    check(null == (ASN1_NULL *)1 && p == buf + 2, "d2i_ASN1_NULL gives the pointer 1");
    ASN1_NULL_free(null);
    n = unhex("17 0d 35 30 30 31 30 31 30 30 30 30 30 30 5a", buf);
    p = buf;
    tm = d2i_ASN1_TIME(NULL, &p, (long)n);
    check(tm != NULL && tm->type == V_ASN1_UTCTIME, "d2i_ASN1_TIME takes a UTCTime");
    ASN1_TIME_free(tm);

    n = unhex("01 01 ff", buf);
    p = buf;
    t = d2i_ASN1_TYPE(NULL, &p, (long)n);
    check(t != NULL && t->type == V_ASN1_BOOLEAN && t->value.boolean == 0xff, "d2i_ASN1_TYPE of a BOOLEAN");
    n = unhex("05 00", buf);
    p = buf;
    check(d2i_ASN1_TYPE(&t, &p, (long)n) == t && t->type == V_ASN1_NULL && t->value.ptr == NULL,
          "into the same ASN1_TYPE, a NULL");
    n = unhex("06 03 2a 03 04", buf);
    p = buf;
    check(d2i_ASN1_TYPE(&t, &p, (long)n) == t && t->type == V_ASN1_OBJECT && OBJ_length(t->value.object) == 3,
          "an OBJECT");
    n = unhex("a1 03 02 01 05", buf);
    p = buf;
    check(d2i_ASN1_TYPE(&t, &p, (long)n) == t && t->type == V_ASN1_OTHER && t->value.asn1_string->length == 5,
          "a context-tagged value is kept whole as OTHER");
    n = unhex("30 80 02 01 05 00 00 ff", buf);
    p = buf;
    check(d2i_ASN1_TYPE(&t, &p, (long)n) == t && t->type == V_ASN1_SEQUENCE && t->value.sequence->length == 7
              && p == buf + 7,
          "an indefinite SEQUENCE is kept whole to its EOC");
    ASN1_TYPE_free(t);
}

static void any_stacks(void)
{
    unsigned char buf[64];
    const unsigned char *p;
    ASN1_SEQUENCE_ANY *sk;
    size_t n = unhex("30 05 02 01 05 05 00 ff", buf);

    p = buf;
    sk = d2i_ASN1_SEQUENCE_ANY(NULL, &p, (long)n);
    check(sk != NULL && sk_ASN1_TYPE_num(sk) == 2 && sk_ASN1_TYPE_value(sk, 1)->type == V_ASN1_NULL,
          "d2i_ASN1_SEQUENCE_ANY");
    sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
    n = unhex("31 05 05 00 02 01 05", buf);
    p = buf;
    sk = d2i_ASN1_SET_ANY(NULL, &p, (long)n);
    check(sk != NULL && sk_ASN1_TYPE_num(sk) == 2 && sk_ASN1_TYPE_value(sk, 0)->type == V_ASN1_NULL,
          "d2i_ASN1_SET_ANY keeps the order read");
    sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
}

static void ber(void)
{
    const ASN1_ITEM *os = ASN1_ITEM_rptr(ASN1_OCTET_STRING);

    check(roundtrip("constructed OCTET STRING", "24 80 04 02 61 62 04 01 63 00 00", os, "04 03 61 62 63"),
          "a constructed OCTET STRING is collected");
    check(roundtrip("definite constructed", "24 07 04 01 61 24 02 04 00", os, "04 01 61"),
          "with nested pieces and empty ones");
    check(roundtrip("long form length", "04 81 01 61", os, "04 01 61"), "a long-form length is accepted");
    check(refused("too deep string", "24 80 24 80 24 80 24 80 24 80 24 80 24 80 04 01 61 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                  os),
          "constructed strings nest at most 5 deep");
    check(refused("constructed INTEGER", "22 03 02 01 05", ASN1_ITEM_rptr(ASN1_INTEGER)),
          "an INTEGER can't be constructed");
    check(refused("missing EOC", "24 80 04 01 61", os), "an indefinite string needs its EOC");
    check(refused("EOC in definite", "24 04 00 00 04 00", os), "and a definite one can't have one");
}

static void malformed(void)
{
    const ASN1_ITEM *os = ASN1_ITEM_rptr(ASN1_OCTET_STRING);
    unsigned char buf[8];
    const unsigned char *p = buf;
    ASN1_VALUE *v;

    check(refused("wrong tag", "02 01 05", os), "a wrong tag");
    check(refused("too long", "04 05 61", os), "a length past the input");
    check(refused("bad header", "04 84 ff ff ff ff", os), "a bad header");
    check(refused("padded INTEGER", "02 02 00 05", ASN1_ITEM_rptr(ASN1_INTEGER)), "a padded INTEGER");
    check(refused("empty INTEGER", "02 00", ASN1_ITEM_rptr(ASN1_INTEGER)), "an empty INTEGER");
    check(refused("bits left", "03 02 08 00", ASN1_ITEM_rptr(ASN1_BIT_STRING)), "unused bits over 7");
    check(refused("empty BIT STRING", "03 00", ASN1_ITEM_rptr(ASN1_BIT_STRING)), "no unused-bits octet");
    check(refused("NULL with content", "05 01 00", ASN1_ITEM_rptr(ASN1_NULL)), "a NULL with content");
    check(refused("BOOLEAN length", "01 02 00 00", ASN1_ITEM_rptr(ASN1_ANY)), "a BOOLEAN of 2 octets");
    check(refused("odd BMPString", "1e 01 41", ASN1_ITEM_rptr(ASN1_BMPSTRING)), "an odd BMPString");
    check(refused("UniversalString", "1c 02 00 41", ASN1_ITEM_rptr(ASN1_UNIVERSALSTRING)), "a short UniversalString");
    check(refused("short UTCTime", "17 02 32 34", ASN1_ITEM_rptr(ASN1_UTCTIME)), "a short UTCTime");
    check(refused("short GeneralizedTime", "18 02 32 34", ASN1_ITEM_rptr(ASN1_GENERALIZEDTIME)),
          "a short GeneralizedTime");
    check(refused("MSTRING tag", "16 01 41", ASN1_ITEM_rptr(DIRECTORYSTRING)), "a DirectoryString can't be IA5");
    check(refused("MSTRING class", "80 01 41", ASN1_ITEM_rptr(DIRECTORYSTRING)), "nor context-specific");
    check(refused("primitive SEQUENCE", "10 00", ASN1_ITEM_rptr(ASN1_SEQUENCE)), "a SEQUENCE must be constructed");
    buf[0] = 0x04;
    v = ASN1_item_d2i(NULL, &p, 0, os);
    errors("zero length");
    check(v == NULL && p == buf, "no input at all");
    v = ASN1_item_d2i(NULL, &p, -5, os);
    errors("negative length");
    check(v == NULL, "a negative length");
}

static void record(void)
{
    const ASN1_ITEM *it = ASN1_ITEM_rptr(RECORD);
    RECORD *r = (RECORD *)ASN1_item_new(it), *back;
    unsigned char *der = NULL;
    const unsigned char *p;
    int len;
    long used;

    ASN1_INTEGER_set(r->version, 2);
    r->opt = ASN1_OCTET_STRING_new();
    ASN1_STRING_set(r->opt, "op", 2);
    r->imp = ASN1_IA5STRING_new();
    ASN1_STRING_set(r->imp, "im", 2);
    r->fflag = 0xff;
    sk_ASN1_INTEGER_push(r->set, ASN1_INTEGER_new());
    ASN1_INTEGER_set(sk_ASN1_INTEGER_value(r->set, 0), 7);
    sk_ASN1_UTF8STRING_push(r->seq, ASN1_UTF8STRING_new());
    ASN1_STRING_set(sk_ASN1_UTF8STRING_value(r->seq, 0), "u", 1);
    ASN1_STRING_set(r->dir, "dir", 3);
    r->dir->type = V_ASN1_PRINTABLESTRING;
    ASN1_TYPE_set(r->any, V_ASN1_NULL, NULL);
    *r->i32 = -129;
    *r->u64 = 0x8000000000000000ULL;
    r->zu32 = 9;
    r->l = -2;
    r->zl = 300;
    ASN1_STRING_set(&r->emb, "emb", 3);
    r->pick->type = 1;
    r->pick->d.str = ASN1_UTF8STRING_new();
    ASN1_STRING_set(r->pick->d.str, "pick", 4);
    len = ASN1_item_i2d((ASN1_VALUE *)r, &der, it);
    hex("record", der, len);
    p = der;
    back = (RECORD *)ASN1_item_d2i(NULL, &p, len, it);
    check(back != NULL && p == der + len, "the record decodes");
    check(ASN1_INTEGER_get(back->version) == 2 && back->opt != NULL && back->opt->length == 2 && back->imp != NULL
              && back->imp->type == V_ASN1_IA5STRING && back->fflag == 0xff,
          "with its tagged and optional fields");
    check(sk_ASN1_INTEGER_num(back->set) == 1 && sk_ASN1_UTF8STRING_num(back->seq) == 1
              && back->dir->type == V_ASN1_PRINTABLESTRING && back->any->type == V_ASN1_NULL,
          "its stacks, MSTRING, and ANY");
    check(*back->i32 == -129 && *back->u64 == 0x8000000000000000ULL && back->zu32 == 9 && back->l == -2
              && back->zl == 300,
          "its native integers");
    check(back->emb.length == 3 && (back->emb.flags & ASN1_STRING_FLAG_EMBED) != 0 && back->pick->type == 1
              && back->when == NULL,
          "its embedded string and CHOICE; the absent time is NULL");
    ASN1_item_free((ASN1_VALUE *)back, it);
    OPENSSL_free(der);
    ASN1_item_free((ASN1_VALUE *)r, it);

    /* Minimal: only the required fields; then broken variants. */
    check(roundtrip("minimal", "30 16 02 01 00 31 00 a2 00 13 00 05 00 02 01 00 02 01 00 04 00 02 01 01",
                    it, "30 16 02 01 00 31 00 a2 00 13 00 05 00 02 01 00 02 01 00 04 00 02 01 01"),
          "a record with the optional fields absent");
    check(refused("missing field", "30 07 02 01 00 31 00 a2 00", it), "a required field missing");
    check(refused("length mismatch", "30 03 02 01 00 05 00", it), "a SEQUENCE shorter than its content");
    check(refused("trailing", "30 18 02 01 00 31 00 a2 00 13 00 05 00 02 01 00 02 01 00 04 00 02 01 01 05 00", it),
          "data left in a SEQUENCE");
    check(refused("bad INT32", "30 1a 02 01 00 31 00 a2 00 13 00 05 00 02 05 01 00 00 00 00 02 01 00 04 00 02 01 01", it),
          "an INT32 that doesn't fit");
    check(refused("negative UINT64", "30 16 02 01 00 31 00 a2 00 13 00 05 00 02 01 00 02 01 ff 04 00 02 01 01", it),
          "a negative UINT64");
    check(refused("wrong CHOICE", "30 15 02 01 00 31 00 a2 00 13 00 05 00 02 01 00 02 01 00 04 00 05 00", it),
          "no CHOICE alternative matches");
    check(refused("unexpected EOC", "30 07 02 01 00 31 00 00 00", it), "an EOC in a definite SEQUENCE");
    check(roundtrip("indefinite", "30 80 02 01 00 31 00 a2 00 13 00 05 00 02 01 00 02 01 00 04 00 02 01 01 00 00",
                    it, "30 16 02 01 00 31 00 a2 00 13 00 05 00 02 01 00 02 01 00 04 00 02 01 01"),
          "an indefinite-length record");
    (void)used;
}

static void adb(void)
{
    const ASN1_ITEM *it = ASN1_ITEM_rptr(ADBREC);
    long used;
    ADBREC *a;

    a = (ADBREC *)decode("ADB sha256", "30 0e 06 09 60 86 48 01 65 03 04 02 01 02 01 2a", it, &used);
    check(a != NULL && ASN1_INTEGER_get(a->value) == 42, "the OID picks INTEGER");
    ASN1_item_free((ASN1_VALUE *)a, it);
    a = (ADBREC *)decode("ADB sha1", "30 0a 06 05 2b 0e 03 02 1a 0c 01 78", it, &used);
    check(a != NULL && ((ASN1_STRING *)a->value)->type == V_ASN1_UTF8STRING, "or UTF8String");
    ASN1_item_free((ASN1_VALUE *)a, it);
    a = (ADBREC *)decode("ADB default", "30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00", it, &used);
    check(a != NULL && ((ASN1_TYPE *)a->value)->type == V_ASN1_NULL, "or the default ANY");
    ASN1_item_free((ASN1_VALUE *)a, it);
    check(refused("ADB wrong", "30 0b 06 05 2b 0e 03 02 1a 02 02 00 01", it), "a value of the wrong type");
}

static void cached(void)
{
    const ASN1_ITEM *it = ASN1_ITEM_rptr(CACHED);
    unsigned char buf[32], *der = NULL;
    const unsigned char *p = buf;
    size_t n = unhex("30 80 02 01 07 24 80 04 01 61 00 00 00 00", buf);
    CACHED *c = (CACHED *)ASN1_item_d2i(NULL, &p, (long)n, it);
    int len;

    check(c != NULL && c->enc.enc != NULL && c->enc.len == (long)n && c->enc.modified == 0,
          "a SEQUENCE with ASN1_AFLG_ENCODING keeps what it was decoded from");
    len = ASN1_item_i2d((ASN1_VALUE *)c, &der, it);
    check(len == (int)n && memcmp(der, buf, n) == 0, "and encodes as that, BER and all");
    OPENSSL_free(der);
    der = NULL;
    c->enc.modified = 1;
    len = ASN1_item_i2d((ASN1_VALUE *)c, &der, it);
    hex("modified", der, len);
    check(len == 8, "until it's marked modified");
    OPENSSL_free(der);
    ASN1_item_free((ASN1_VALUE *)c, it);
}

static void traced(void)
{
    const ASN1_ITEM *it = ASN1_ITEM_rptr(TRACED);
    unsigned char buf[8];
    const unsigned char *p = buf;
    size_t n = unhex("30 03 02 01 01", buf);
    TRACED *t;

    trace[0] = 0;
    t = (TRACED *)ASN1_item_d2i(NULL, &p, (long)n, it);
    printf("# d2i trace:%s\n", trace);
    check(t != NULL && strcmp(trace, " 0 1 4 5") == 0, "NEW_PRE, NEW_POST, D2I_PRE, D2I_POST");
    trace[0] = 0;
    p = buf;
    check(ASN1_item_d2i((ASN1_VALUE **)&t, &p, (long)n, it) == (ASN1_VALUE *)t && strcmp(trace, " 4 5") == 0,
          "decoding into a value makes no new one");
    trace[0] = 0;
    veto = ASN1_OP_D2I_POST;
    p = buf;
    check(ASN1_item_d2i((ASN1_VALUE **)&t, &p, (long)n, it) == NULL && t == NULL, "a callback's 0 fails it, freeing the value");
    printf("# vetoed trace:%s\n", trace);
    errors("vetoed");
    veto = -1;
}

static void nesting(void)
{
    char in[400] = "", *q = in;
    int i;
    long used;
    NEST *n;

    /* 29 levels decode; 31 don't. */
    for (i = 0; i < 29; i++)
        q += sprintf(q, "30 %02x ", 2 * (28 - i));
    n = (NEST *)decode("29 deep", in, ASN1_ITEM_rptr(NEST), &used);
    check(n != NULL, "29 nested SEQUENCEs decode");
    ASN1_item_free((ASN1_VALUE *)n, ASN1_ITEM_rptr(NEST));
    q = in;
    for (i = 0; i < 31; i++)
        q += sprintf(q, "30 %02x ", 2 * (30 - i));
    check(refused("31 deep", in, ASN1_ITEM_rptr(NEST)), "31 don't");
}

static void ex_d2i(void)
{
    unsigned char buf[8];
    const unsigned char *p = buf;
    ASN1_VALUE *v = NULL;
    size_t n = unhex("85 01 07", buf);
    int ret;

    ret = ASN1_item_ex_d2i(&v, &p, (long)n, ASN1_ITEM_rptr(ASN1_INTEGER), 5, V_ASN1_CONTEXT_SPECIFIC, 0, NULL);
    check(ret == 1 && v != NULL && ASN1_INTEGER_get((ASN1_INTEGER *)v) == 7 && p == buf + 3,
          "ASN1_item_ex_d2i with an implicit tag");
    p = buf;
    ret = ASN1_item_ex_d2i(&v, &p, (long)n, ASN1_ITEM_rptr(ASN1_INTEGER), 6, V_ASN1_CONTEXT_SPECIFIC, 1, NULL);
    check(ret == -1 && v == NULL && p == buf, "an absent OPTIONAL value is -1, and the value is freed");
    ret = ASN1_item_ex_d2i(&v, &p, (long)n, ASN1_ITEM_rptr(ASN1_INTEGER), 6, V_ASN1_CONTEXT_SPECIFIC, 0, NULL);
    errors("not optional");
    check(ret == 0, "or an error when not OPTIONAL");
    ret = ASN1_item_ex_d2i(NULL, &p, (long)n, ASN1_ITEM_rptr(ASN1_INTEGER), -1, 0, 0, NULL);
    errors("NULL pval");
    check(ret == 0, "NULL pval");
    p = buf;
    v = ASN1_item_d2i_ex(NULL, &p, (long)n, ASN1_ITEM_rptr(ASN1_ANY), NULL, NULL);
    check(v != NULL && ((ASN1_TYPE *)v)->type == V_ASN1_OTHER, "ASN1_item_d2i_ex");
    ASN1_item_free(v, ASN1_ITEM_rptr(ASN1_ANY));
}

int main(void)
{
    universal();
    any_stacks();
    ber();
    malformed();
    record();
    adb();
    cached();
    traced();
    nesting();
    ex_d2i();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
