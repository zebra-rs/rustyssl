/*
 * Conformance test for the template engine's allocation and encoding (ASN1_item_new(3),
 * ASN1_item_free, ASN1_item_i2d, ASN1_item_ex_i2d, ASN1_item_ndef_i2d, the universal items, and
 * their new/free/i2d functions), in TAP format. The application types are defined here with the
 * asn1t.h macros, so the engine walks this program's own tables: SEQUENCEs with optional,
 * tagged, embedded, SET OF and SEQUENCE OF fields, a CHOICE, ANY DEFINED BY, a reference count,
 * an indefinite-length SEQUENCE, and an aux callback whose calls are traced.
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

static void errors(void)
{
    unsigned long code;

    printf(" errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void hex(const char *what, const unsigned char *p, int len)
{
    int i;

    printf("# %s (%d):", what, len);
    for (i = 0; i < len; i++)
        printf(" %02x", p[i]);
    printf("\n");
}

/* Encodes into a new buffer, prints it, and returns whether it matches `expected`. */
static int encodes(const char *what, const void *val, const ASN1_ITEM *it, const char *expected)
{
    unsigned char *der = NULL;
    int len = ASN1_item_i2d((const ASN1_VALUE *)val, &der, it);
    int ok;
    char got[1024] = "";
    size_t off = 0;
    int i;

    if (len > 0)
        hex(what, der, len);
    else
        printf("# %s: %d\n", what, len);
    for (i = 0; i < len && off + 4 < sizeof(got); i++)
        off += (size_t)snprintf(got + off, sizeof(got) - off, i == 0 ? "%02x" : " %02x", der[i]);
    ok = expected == NULL ? len > 0 : len > 0 && strcmp(got, expected) == 0;
    if (expected != NULL && !ok)
        printf("# expected: %s\n", expected);
    OPENSSL_free(der);
    return ok;
}

static ASN1_INTEGER *integer(long v)
{
    ASN1_INTEGER *a = ASN1_INTEGER_new();

    ASN1_INTEGER_set(a, v);
    return a;
}

static ASN1_STRING *text(int type, const char *s)
{
    ASN1_STRING *str = ASN1_STRING_type_new(type);

    ASN1_STRING_set(str, s, -1);
    return str;
}

/* A CHOICE: an INTEGER or an explicitly tagged UTF8String. */
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

/* A SEQUENCE using most kinds of field. */
typedef struct {
    ASN1_INTEGER *version;
    ASN1_OCTET_STRING *opt;
    ASN1_IA5STRING *imp;
    ASN1_BOOLEAN fflag;
    ASN1_BOOLEAN tflag;
    ASN1_BOOLEAN bflag;
    STACK_OF(ASN1_INTEGER) *set;
    STACK_OF(ASN1_INTEGER) *ordered;
    STACK_OF(ASN1_UTF8STRING) *seq;
    ASN1_STRING *dir;
    ASN1_TYPE *any;
    int32_t *i32;
    uint64_t *u64;
    uint32_t zu32;
    long l;
    long zl;
    long zl2;
    ASN1_OCTET_STRING emb;
    PICK *pick;
    ASN1_TIME *when;
} RECORD;

ASN1_SEQUENCE(RECORD) = {
    ASN1_SIMPLE(RECORD, version, ASN1_INTEGER),
    ASN1_EXP_OPT(RECORD, opt, ASN1_OCTET_STRING, 0),
    ASN1_IMP_OPT(RECORD, imp, ASN1_IA5STRING, 1),
    ASN1_OPT(RECORD, fflag, ASN1_FBOOLEAN),
    ASN1_OPT(RECORD, tflag, ASN1_TBOOLEAN),
    ASN1_SIMPLE(RECORD, bflag, ASN1_BOOLEAN),
    ASN1_SET_OF(RECORD, set, ASN1_INTEGER),
    ASN1_EX_TYPE(ASN1_TFLG_SET_ORDER, 0, RECORD, ordered, ASN1_INTEGER),
    ASN1_IMP_SEQUENCE_OF(RECORD, seq, ASN1_UTF8STRING, 2),
    ASN1_SIMPLE(RECORD, dir, DIRECTORYSTRING),
    ASN1_SIMPLE(RECORD, any, ASN1_ANY),
    ASN1_SIMPLE(RECORD, i32, INT32),
    ASN1_SIMPLE(RECORD, u64, UINT64),
    ASN1_OPT_EMBED(RECORD, zu32, ZUINT32),
    ASN1_OPT(RECORD, l, LONG),
    ASN1_OPT(RECORD, zl, ZLONG),
    ASN1_SIMPLE(RECORD, zl2, ZLONG),
    ASN1_EMBED(RECORD, emb, ASN1_OCTET_STRING),
    ASN1_SIMPLE(RECORD, pick, PICK),
    ASN1_OPT(RECORD, when, ASN1_TIME)
} ASN1_SEQUENCE_END(RECORD)

/* ANY DEFINED BY an OID: an INTEGER for sha256, a UTF8String for sha1, else ANY. */
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

/* A reference-counted SEQUENCE. */
typedef struct {
    ASN1_INTEGER *n;
    int references;
    CRYPTO_RWLOCK *lock;
} REFD;

ASN1_SEQUENCE_ref(REFD, NULL) = {
    ASN1_SIMPLE(REFD, n, ASN1_INTEGER)
} ASN1_SEQUENCE_END_ref(REFD, REFD)

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
    (void)exarg;
    snprintf(trace + used, sizeof(trace) - used, " %d", operation);
    return operation == veto ? 0 : 1;
}

ASN1_SEQUENCE_cb(TRACED, traced_cb) = {
    ASN1_SIMPLE(TRACED, n, ASN1_INTEGER),
    ASN1_OPT(TRACED, s, ASN1_UTF8STRING)
} ASN1_SEQUENCE_END_cb(TRACED, TRACED)

/* An indefinite-length SEQUENCE with an indefinite-length explicit tag. */
typedef struct {
    ASN1_INTEGER *n;
    ASN1_UTF8STRING *s;
} NDEFSEQ;

ASN1_NDEF_SEQUENCE(NDEFSEQ) = {
    ASN1_SIMPLE(NDEFSEQ, n, ASN1_INTEGER),
    ASN1_NDEF_EXP(NDEFSEQ, s, ASN1_UTF8STRING, 0)
} ASN1_NDEF_SEQUENCE_END(NDEFSEQ)

static void items(void)
{
    static const struct {
        const char *name;
        const ASN1_ITEM *(*it)(void);
    } table[] = {
        { "ASN1_OCTET_STRING", ASN1_OCTET_STRING_it },
        { "ASN1_INTEGER", ASN1_INTEGER_it },
        { "ASN1_ENUMERATED", ASN1_ENUMERATED_it },
        { "ASN1_BIT_STRING", ASN1_BIT_STRING_it },
        { "ASN1_UTF8STRING", ASN1_UTF8STRING_it },
        { "ASN1_PRINTABLESTRING", ASN1_PRINTABLESTRING_it },
        { "ASN1_T61STRING", ASN1_T61STRING_it },
        { "ASN1_IA5STRING", ASN1_IA5STRING_it },
        { "ASN1_GENERALSTRING", ASN1_GENERALSTRING_it },
        { "ASN1_UTCTIME", ASN1_UTCTIME_it },
        { "ASN1_GENERALIZEDTIME", ASN1_GENERALIZEDTIME_it },
        { "ASN1_VISIBLESTRING", ASN1_VISIBLESTRING_it },
        { "ASN1_UNIVERSALSTRING", ASN1_UNIVERSALSTRING_it },
        { "ASN1_BMPSTRING", ASN1_BMPSTRING_it },
        { "ASN1_NULL", ASN1_NULL_it },
        { "ASN1_OBJECT", ASN1_OBJECT_it },
        { "ASN1_ANY", ASN1_ANY_it },
        { "ASN1_SEQUENCE", ASN1_SEQUENCE_it },
        { "ASN1_BOOLEAN", ASN1_BOOLEAN_it },
        { "ASN1_TBOOLEAN", ASN1_TBOOLEAN_it },
        { "ASN1_FBOOLEAN", ASN1_FBOOLEAN_it },
        { "ASN1_OCTET_STRING_NDEF", ASN1_OCTET_STRING_NDEF_it },
        { "ASN1_PRINTABLE", ASN1_PRINTABLE_it },
        { "DISPLAYTEXT", DISPLAYTEXT_it },
        { "DIRECTORYSTRING", DIRECTORYSTRING_it },
        { "ASN1_TIME", ASN1_TIME_it },
        { "ASN1_SEQUENCE_ANY", ASN1_SEQUENCE_ANY_it },
        { "ASN1_SET_ANY", ASN1_SET_ANY_it },
        { "INT32", INT32_it },
        { "UINT32", UINT32_it },
        { "INT64", INT64_it },
        { "UINT64", UINT64_it },
        { "ZINT32", ZINT32_it },
        { "ZUINT32", ZUINT32_it },
        { "ZINT64", ZINT64_it },
        { "ZUINT64", ZUINT64_it },
        { "LONG", LONG_it },
        { "ZLONG", ZLONG_it },
    };
    size_t i;
    int named = 1;

    for (i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        const ASN1_ITEM *it = table[i].it();

        named = named && it == table[i].it() && strcmp(it->sname, table[i].name) == 0;
        printf("# %s: itype %d utype %ld size %ld tcount %ld templates %d funcs %d\n", it->sname,
               it->itype, it->utype, it->size, it->tcount, it->templates != NULL, it->funcs != NULL);
    }
    check(named, "each item function returns its one item, named");
    check(ASN1_ITEM_rptr(ASN1_SET_ANY)->templates->flags == ASN1_TFLG_SET_OF
              && ASN1_ITEM_rptr(ASN1_SET_ANY)->templates->item() == ASN1_ITEM_rptr(ASN1_ANY)
              && strcmp(ASN1_ITEM_rptr(ASN1_SEQUENCE_ANY)->templates->field_name, "ASN1_SEQUENCE_ANY") == 0,
          "SEQUENCE OF / SET OF ANY are templates over ASN1_ANY");
}

static void universal(void)
{
    ASN1_NULL *null = ASN1_NULL_new();
    ASN1_TYPE *t = ASN1_TYPE_new();
    ASN1_TIME *tm = ASN1_TIME_new();
    ASN1_STRING *p = ASN1_PRINTABLE_new(), *d = DIRECTORYSTRING_new(), *x = DISPLAYTEXT_new();
    ASN1_STRING *s;
    ASN1_BIT_STRING *bits = ASN1_BIT_STRING_new();
    unsigned char buf[64], *q;
    int len;

    check(null == (ASN1_NULL *)1, "ASN1_NULL_new returns the pointer 1");
    check(i2d_ASN1_NULL(null, NULL) == 2 && encodes("NULL", null, ASN1_ITEM_rptr(ASN1_NULL), "05 00"),
          "i2d_ASN1_NULL");
    ASN1_NULL_free(null);
    check(t != NULL && t->type == -1 && t->value.ptr == NULL, "ASN1_TYPE_new: type -1, no value");
    len = i2d_ASN1_TYPE(t, NULL);
    printf("# i2d of an empty ASN1_TYPE: %d\n", len);
    ASN1_TYPE_set(t, V_ASN1_BOOLEAN, (void *)1);
    check(encodes("ANY BOOLEAN", t, ASN1_ITEM_rptr(ASN1_ANY), "01 01 ff"), "an ANY encodes its BOOLEAN");
    ASN1_TYPE_set(t, V_ASN1_BOOLEAN, NULL);
    check(encodes("ANY FALSE", t, ASN1_ITEM_rptr(ASN1_ANY), "01 01 00"), "even FALSE");
    ASN1_TYPE_set(t, V_ASN1_OBJECT, OBJ_nid2obj(NID_sha256));
    check(encodes("ANY OBJECT", t, ASN1_ITEM_rptr(ASN1_ANY), "06 09 60 86 48 01 65 03 04 02 01"),
          "and its OBJECT");
    ASN1_TYPE_set(t, V_ASN1_SEQUENCE, text(V_ASN1_SEQUENCE, "\x30\x03\x02\x01\x07"));
    check(encodes("ANY SEQUENCE", t, ASN1_ITEM_rptr(ASN1_ANY), "30 03 02 01 07"),
          "a SEQUENCE's string is its whole encoding");
    ASN1_TYPE_set(t, V_ASN1_NULL, NULL);
    check(encodes("ANY NULL", t, ASN1_ITEM_rptr(ASN1_ANY), "05 00"), "a NULL needs no value");
    ASN1_TYPE_free(t);
    ASN1_TYPE_free(NULL);

    check(tm != NULL && tm->type == -1 && (tm->flags & ASN1_STRING_FLAG_MSTRING) != 0,
          "ASN1_TIME_new: an MSTRING of type -1");
    ASN1_TIME_set(tm, 86400 * 365);
    check(encodes("TIME", tm, ASN1_ITEM_rptr(ASN1_TIME), "17 0d 37 31 30 31 30 31 30 30 30 30 30 30 5a")
              && i2d_ASN1_TIME(tm, NULL) == 15,
          "a Time encodes as its type");
    ASN1_TIME_free(tm);
    check(p->type == -1 && d->type == -1 && x->type == -1, "the other MSTRING types start at -1 too");
    ASN1_STRING_set(d, "dir", 3);
    d->type = V_ASN1_UTF8STRING;
    check(i2d_DIRECTORYSTRING(d, NULL) == 5 && i2d_ASN1_PRINTABLE(d, NULL) == 5 && i2d_DISPLAYTEXT(d, NULL) == 5,
          "and encode as their type");
    check(ASN1_item_ex_i2d((const ASN1_VALUE **)&d, NULL, ASN1_ITEM_rptr(DIRECTORYSTRING), 4, 0) == -1
              && ERR_GET_REASON(ERR_peek_error()) == ASN1_R_BAD_TEMPLATE,
          "an MSTRING can't be implicitly tagged");
    ERR_clear_error();
    ASN1_PRINTABLE_free(p);
    DIRECTORYSTRING_free(d);
    DISPLAYTEXT_free(x);

    q = buf;
    s = text(V_ASN1_OCTET_STRING, "abc");
    len = i2d_ASN1_OCTET_STRING(s, &q);
    check(len == 5 && q == buf + 5 && memcmp(buf, "\x04\x03" "abc", 5) == 0,
          "into a caller's buffer, moving the pointer");
    ASN1_STRING_free(s);
    s = integer(-129);
    check(encodes("INTEGER -129", s, ASN1_ITEM_rptr(ASN1_INTEGER), "02 02 ff 7f") && i2d_ASN1_INTEGER(s, NULL) == 4,
          "i2d_ASN1_INTEGER");
    s->type = V_ASN1_NEG_ENUMERATED;
    check(encodes("ENUMERATED", s, ASN1_ITEM_rptr(ASN1_ENUMERATED), "0a 02 ff 7f") && i2d_ASN1_ENUMERATED(s, NULL) == 4,
          "i2d_ASN1_ENUMERATED");
    ASN1_STRING_free(s);
    ASN1_BIT_STRING_set_bit(bits, 9, 1);
    check(encodes("BIT STRING", bits, ASN1_ITEM_rptr(ASN1_BIT_STRING), "03 03 06 00 40")
              && i2d_ASN1_BIT_STRING(bits, NULL) == 5,
          "i2d_ASN1_BIT_STRING trims and counts unused bits");
    ASN1_BIT_STRING_free(bits);

#define STRING_I2D(fn, type, tag)                                                     \
    s = text(type, "x");                                                              \
    q = buf;                                                                          \
    check(fn(s, &q) == 3 && buf[0] == tag && buf[1] == 1 && buf[2] == 'x', #fn); \
    ASN1_STRING_free(s)
    STRING_I2D(i2d_ASN1_UTF8STRING, V_ASN1_UTF8STRING, 0x0c);
    STRING_I2D(i2d_ASN1_PRINTABLESTRING, V_ASN1_PRINTABLESTRING, 0x13);
    STRING_I2D(i2d_ASN1_T61STRING, V_ASN1_T61STRING, 0x14);
    STRING_I2D(i2d_ASN1_IA5STRING, V_ASN1_IA5STRING, 0x16);
    STRING_I2D(i2d_ASN1_GENERALSTRING, V_ASN1_GENERALSTRING, 0x1b);
    STRING_I2D(i2d_ASN1_UTCTIME, V_ASN1_UTCTIME, 0x17);
    STRING_I2D(i2d_ASN1_GENERALIZEDTIME, V_ASN1_GENERALIZEDTIME, 0x18);
    STRING_I2D(i2d_ASN1_VISIBLESTRING, V_ASN1_VISIBLESTRING, 0x1a);
    STRING_I2D(i2d_ASN1_UNIVERSALSTRING, V_ASN1_UNIVERSALSTRING, 0x1c);
    STRING_I2D(i2d_ASN1_BMPSTRING, V_ASN1_BMPSTRING, 0x1e);
}

static void any_stacks(void)
{
    ASN1_SEQUENCE_ANY *sk = sk_ASN1_TYPE_new_null();
    ASN1_TYPE *a = ASN1_TYPE_new(), *b = ASN1_TYPE_new(), *c = ASN1_TYPE_new();

    ASN1_TYPE_set(a, V_ASN1_INTEGER, integer(300));
    ASN1_TYPE_set(b, V_ASN1_NULL, NULL);
    ASN1_TYPE_set(c, V_ASN1_INTEGER, integer(5));
    sk_ASN1_TYPE_push(sk, a);
    sk_ASN1_TYPE_push(sk, b);
    sk_ASN1_TYPE_push(sk, c);
    check(encodes("SEQUENCE OF ANY", sk, ASN1_ITEM_rptr(ASN1_SEQUENCE_ANY), "30 09 02 02 01 2c 05 00 02 01 05")
              && i2d_ASN1_SEQUENCE_ANY(sk, NULL) == 11,
          "SEQUENCE OF ANY keeps the order");
    check(encodes("SET OF ANY", sk, ASN1_ITEM_rptr(ASN1_SET_ANY), "31 09 02 01 05 02 02 01 2c 05 00")
              && i2d_ASN1_SET_ANY(sk, NULL) == 11,
          "SET OF ANY is in DER order");
    check(sk_ASN1_TYPE_value(sk, 0) == a, "without reordering the stack");
    sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
}

static void record(void)
{
    RECORD *r = (RECORD *)ASN1_item_new(ASN1_ITEM_rptr(RECORD));
    unsigned char *der = NULL, *q;
    int len, len2;

    check(r != NULL, "ASN1_item_new of an application SEQUENCE");
    check(r->version != NULL && r->version->type == V_ASN1_INTEGER && r->opt == NULL && r->imp == NULL,
          "required fields are made, optional ones left NULL");
    check(r->fflag == 0 && r->tflag == 1 && r->bflag == -1, "BOOLEANs start at their item's size");
    check(r->set != NULL && sk_ASN1_INTEGER_num(r->set) == 0 && r->seq != NULL, "SET OF and SEQUENCE OF are empty stacks");
    check(r->dir != NULL && r->dir->type == -1 && (r->dir->flags & ASN1_STRING_FLAG_MSTRING) != 0,
          "an MSTRING field is a string of type -1");
    check(r->any != NULL && r->any->type == -1, "an ANY field is an empty ASN1_TYPE");
    check(r->i32 != NULL && *r->i32 == 0 && r->u64 != NULL && *r->u64 == 0, "INT32 and UINT64 point to zero");
    check(r->l == 0x7fffffffL && r->zl == 0, "LONG starts at ASN1_LONG_UNDEF, ZLONG at 0");
    check(r->emb.type == V_ASN1_OCTET_STRING && r->emb.flags == ASN1_STRING_FLAG_EMBED && r->emb.data == NULL,
          "an embedded string is set up in place");
    check(r->pick != NULL && r->pick->type == -1, "a CHOICE starts with no selection");
    check(r->when == NULL, "an optional MSTRING is NULL");

    len = ASN1_item_i2d((ASN1_VALUE *)r, NULL, ASN1_ITEM_rptr(RECORD));
    printf("# incomplete record:");
    errors();
    check(len == -1, "an unset ANY and CHOICE can't be encoded");

    ASN1_INTEGER_set(r->version, 2);
    r->opt = text(V_ASN1_OCTET_STRING, "op");
    r->imp = text(V_ASN1_IA5STRING, "im");
    r->fflag = 0xff;
    r->tflag = 0;
    r->bflag = 0;
    sk_ASN1_INTEGER_push(r->set, integer(300));
    sk_ASN1_INTEGER_push(r->set, integer(5));
    sk_ASN1_INTEGER_push(r->set, integer(70000));
    sk_ASN1_INTEGER_push(r->ordered, integer(-1));
    sk_ASN1_INTEGER_push(r->ordered, integer(1));
    sk_ASN1_INTEGER_push(r->ordered, integer(0));
    sk_ASN1_UTF8STRING_push(r->seq, text(V_ASN1_UTF8STRING, "b"));
    sk_ASN1_UTF8STRING_push(r->seq, text(V_ASN1_UTF8STRING, "a"));
    ASN1_STRING_set(r->dir, "dir", 3);
    r->dir->type = V_ASN1_PRINTABLESTRING;
    ASN1_TYPE_set(r->any, V_ASN1_NULL, NULL);
    *r->i32 = -129;
    *r->u64 = 0x8000000000000000ULL;
    r->zu32 = 0;
    r->l = -1;
    r->zl = 0;
    r->zl2 = -32768;
    ASN1_STRING_set(&r->emb, "emb", 3);
    r->pick->type = 1;
    r->pick->d.str = text(V_ASN1_UTF8STRING, "pick");

    check(encodes("record", r, ASN1_ITEM_rptr(RECORD), NULL), "the whole record encodes");
    len = ASN1_item_i2d((ASN1_VALUE *)r, NULL, ASN1_ITEM_rptr(RECORD));
    der = OPENSSL_malloc(len);
    q = der;
    len2 = ASN1_item_i2d((ASN1_VALUE *)r, &q, ASN1_ITEM_rptr(RECORD));
    check(len2 == len && q == der + len, "measuring, then writing into a caller's buffer");
    OPENSSL_free(der);
    check(ASN1_INTEGER_get(sk_ASN1_INTEGER_value(r->set, 0)) == 300,
          "a SET OF is written sorted, its stack left alone");
    check(ASN1_INTEGER_get(sk_ASN1_INTEGER_value(r->ordered, 0)) == 0
              && ASN1_INTEGER_get(sk_ASN1_INTEGER_value(r->ordered, 1)) == 1
              && ASN1_INTEGER_get(sk_ASN1_INTEGER_value(r->ordered, 2)) == -1,
          "with ASN1_TFLG_SET_ORDER the stack is sorted too");

    r->tflag = 1;
    r->fflag = 0;
    r->bflag = 1;
    r->zu32 = 7;
    r->l = 0x7fffffffL;
    r->zl = 128;
    r->pick->type = 0;
    r->pick->d.num = integer(9);
    r->when = ASN1_TIME_new();
    ASN1_TIME_set_string(r->when, "20500101000000Z");
    ASN1_STRING_free(r->opt);
    r->opt = NULL;
    check(encodes("record 2", r, ASN1_ITEM_rptr(RECORD), NULL), "defaults left out, others put in");
    ASN1_STRING_free(r->pick->d.str);
    r->pick->d.str = NULL;
    r->pick->type = 5;
    ERR_clear_error();
    len = ASN1_item_i2d((ASN1_VALUE *)r, NULL, ASN1_ITEM_rptr(RECORD));
    printf("# out-of-range CHOICE: %d", len);
    errors();
    r->pick->type = 0;
    r->pick->d.num = integer(9);
    ASN1_item_free((ASN1_VALUE *)r, ASN1_ITEM_rptr(RECORD));
    ASN1_item_free(NULL, ASN1_ITEM_rptr(RECORD));
    check(1, "ASN1_item_free frees it all");
}

static void adb(void)
{
    ADBREC *a = (ADBREC *)ASN1_item_new(ASN1_ITEM_rptr(ADBREC));
    ASN1_TYPE *t;

    check(a != NULL && a->type == NULL && a->value == NULL,
          "an ANY DEFINED BY field starts NULL, as does the field at its offset 0");
    a->type = OBJ_nid2obj(NID_sha256);
    a->value = integer(42);
    check(encodes("ADB sha256", a, ASN1_ITEM_rptr(ADBREC), "30 0e 06 09 60 86 48 01 65 03 04 02 01 02 01 2a"),
          "the OID picks INTEGER");
    ASN1_INTEGER_free(a->value);
    a->type = OBJ_nid2obj(NID_sha1);
    a->value = text(V_ASN1_UTF8STRING, "x");
    check(encodes("ADB sha1", a, ASN1_ITEM_rptr(ADBREC), "30 0a 06 05 2b 0e 03 02 1a 0c 01 78"),
          "or UTF8String");
    ASN1_STRING_free(a->value);
    a->type = OBJ_nid2obj(NID_md5);
    t = ASN1_TYPE_new();
    ASN1_TYPE_set(t, V_ASN1_NULL, NULL);
    a->value = t;
    check(encodes("ADB default", a, ASN1_ITEM_rptr(ADBREC), "30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00"),
          "or the default ANY");
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ADBREC));
}

static void refcount(void)
{
    REFD *r = (REFD *)ASN1_item_new(ASN1_ITEM_rptr(REFD));
    ASN1_VALUE *v = (ASN1_VALUE *)r;

    check(r != NULL && r->references == 1 && r->lock != NULL, "a counted SEQUENCE starts at 1, with a lock");
    r->references = 2;
    ASN1_item_ex_free(&v, ASN1_ITEM_rptr(REFD));
    check(v == NULL && r->references == 1 && r->lock != NULL, "freeing drops a reference");
    v = (ASN1_VALUE *)r;
    ASN1_item_ex_free(&v, ASN1_ITEM_rptr(REFD));
    check(v == NULL, "and the last one frees it");
}

static void traced(void)
{
    TRACED *t = NULL;
    unsigned char *der = NULL;
    int len;

    trace[0] = 0;
    check(ASN1_item_ex_new((ASN1_VALUE **)&t, ASN1_ITEM_rptr(TRACED)) == 1, "ASN1_item_ex_new");
    ASN1_INTEGER_set(t->n, 1);
    len = ASN1_item_i2d((ASN1_VALUE *)t, &der, ASN1_ITEM_rptr(TRACED));
    check(len == 5, "encoded");
    OPENSSL_free(der);
    printf("# trace:%s\n", trace);
    check(strcmp(trace, " 0 1 6 6 7") == 0, "NEW_PRE, NEW_POST, I2D_PRE on both passes, I2D_POST on the write");
    trace[0] = 0;
    veto = ASN1_OP_I2D_POST;
    der = NULL;
    len = ASN1_item_i2d((ASN1_VALUE *)t, &der, ASN1_ITEM_rptr(TRACED));
    printf("# vetoed I2D_POST: %d %s, trace:%s\n", len, der == NULL ? "NULL" : "buffer", trace);
    OPENSSL_free(der);
    veto = -1;
    trace[0] = 0;
    ASN1_item_free((ASN1_VALUE *)t, ASN1_ITEM_rptr(TRACED));
    check(strcmp(trace, " 2 3") == 0, "FREE_PRE, FREE_POST");
    trace[0] = 0;
    veto = ASN1_OP_NEW_POST;
    t = (TRACED *)ASN1_item_new(ASN1_ITEM_rptr(TRACED));
    printf("# vetoed NEW_POST:%s\n", trace);
    check(t == NULL && ERR_GET_REASON(ERR_peek_error()) == ASN1_R_AUX_ERROR, "a callback's 0 fails ASN1_item_new");
    ERR_clear_error();
    veto = -1;
}

static void ndef(void)
{
    NDEFSEQ *n = (NDEFSEQ *)ASN1_item_new_ex(ASN1_ITEM_rptr(NDEFSEQ), NULL, NULL);
    unsigned char *der = NULL;
    int len;

    ASN1_INTEGER_set(n->n, 3);
    ASN1_STRING_set(n->s, "s", 1);
    check(encodes("NDEF as DER", n, ASN1_ITEM_rptr(NDEFSEQ), "30 08 02 01 03 a0 03 0c 01 73"),
          "ASN1_item_i2d uses definite lengths");
    len = ASN1_item_ndef_i2d((ASN1_VALUE *)n, &der, ASN1_ITEM_rptr(NDEFSEQ));
    hex("NDEF", der, len);
    check(len == 14 && memcmp(der, "\x30\x80\x02\x01\x03\xa0\x80\x0c\x01\x73\x00\x00\x00\x00", 14) == 0
              && ASN1_item_ndef_i2d((ASN1_VALUE *)n, NULL, ASN1_ITEM_rptr(NDEFSEQ)) == len,
          "ASN1_item_ndef_i2d uses indefinite ones");
    OPENSSL_free(der);
    ASN1_item_free((ASN1_VALUE *)n, ASN1_ITEM_rptr(NDEFSEQ));
}

static void ex_i2d(void)
{
    ASN1_INTEGER *a = integer(1);
    const ASN1_VALUE *v = (const ASN1_VALUE *)a;
    unsigned char buf[8], *q = buf;
    int len;

    len = ASN1_item_ex_i2d(&v, &q, ASN1_ITEM_rptr(ASN1_INTEGER), 5, V_ASN1_CONTEXT_SPECIFIC);
    check(len == 3 && q == buf + 3 && memcmp(buf, "\x85\x01\x01", 3) == 0, "ASN1_item_ex_i2d with an implicit tag");
    v = NULL;
    check(ASN1_item_ex_i2d(&v, NULL, ASN1_ITEM_rptr(ASN1_INTEGER), -1, 0) == 0,
          "a primitive with no value is left out");
    ASN1_INTEGER_free(a);
}

int main(void)
{
    items();
    universal();
    any_stacks();
    record();
    adb();
    refcount();
    traced();
    ndef();
    ex_i2d();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
