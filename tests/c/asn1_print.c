/*
 * Conformance test for ASN1_item_print(3), the ASN1_PCTX functions, and the X509V3 string
 * conversions it uses (i2s_ASN1_INTEGER, i2s_ASN1_ENUMERATED, i2s_ASN1_ENUMERATED_TABLE,
 * i2s_ASN1_OCTET_STRING, s2i_ASN1_INTEGER, s2i_ASN1_OCTET_STRING), in TAP format. An application
 * type with most kinds of field (native integers, a CHOICE, ANY values, SET OF, an extern item,
 * a long OID) is printed under each print-context flag, and every listing is printed, so the
 * outputs are compared byte for byte.
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

static void errors(const char *what)
{
    unsigned long code;

    printf("# %s errors:", what);
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

/* Prints the BIO's contents line by line, each after "# | " (octets past ASCII as \xNN), and
 * empties it. */
static void show(BIO *mem)
{
    char *p, *end;
    long len = BIO_get_mem_data(mem, &p);

    end = p + len;
    while (p < end) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t n = nl != NULL ? (size_t)(nl - p) : (size_t)(end - p);

        size_t i;

        printf("# | ");
        for (i = 0; i < n; i++) {
            if ((unsigned char)p[i] >= 0x80)
                printf("\\x%02x", (unsigned char)p[i]);
            else
                putchar(p[i]);
        }
        printf("%s\n", nl != NULL ? "" : "<no newline>");
        p += n + (nl != NULL ? 1 : 0);
    }
    (void)BIO_reset(mem);
}

/* An extern type: a heap int, printed by its own function or not at all. */
static int ext_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    (void)it;
    *pval = OPENSSL_zalloc(sizeof(int));
    return *pval != NULL;
}

static void ext_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    (void)it;
    OPENSSL_free(*pval);
    *pval = NULL;
}

static int ext_print(BIO *out, const ASN1_VALUE **pval, int indent, const char *fname, const ASN1_PCTX *pctx)
{
    (void)pctx;
    return BIO_printf(out, "<ext %d at %d, fname '%s'>", **(const int **)pval, indent, fname) > 0 ? 2 : 0;
}

static const ASN1_EXTERN_FUNCS ext_funcs = { NULL, ext_new, ext_free, 0, 0, 0, ext_print, 0, 0 };
static const ASN1_EXTERN_FUNCS mute_funcs = { NULL, ext_new, ext_free, 0, 0, 0, 0, 0, 0 };

IMPLEMENT_EXTERN_ASN1(EXT, V_ASN1_SEQUENCE, ext_funcs)
IMPLEMENT_EXTERN_ASN1(MUTE, V_ASN1_SEQUENCE, mute_funcs)

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
    ASN1_INTEGER *small;
    ASN1_INTEGER *big;
    ASN1_INTEGER *negbig;
    ASN1_ENUMERATED *enumerated;
    ASN1_BOOLEAN flag;
    ASN1_BOOLEAN tflag;
    ASN1_OCTET_STRING *octets;
    ASN1_BIT_STRING *bits;
    ASN1_UTCTIME *utc;
    ASN1_GENERALIZEDTIME *gen;
    ASN1_OBJECT *oid;
    ASN1_OBJECT *longoid;
    ASN1_TYPE *any_null;
    ASN1_TYPE *any_seq;
    ASN1_TYPE *any_bool;
    ASN1_TYPE *any_other;
    ASN1_STRING *dir;
    STACK_OF(ASN1_INTEGER) *set;
    STACK_OF(ASN1_INTEGER) *empty;
    STACK_OF(ASN1_INTEGER) *absent;
    PICK *pick;
    int32_t *i32;
    uint64_t *u64;
    long l;
    ASN1_OCTET_STRING *missing;
    int *ext;
    int *mute;
} RECORD;

ASN1_SEQUENCE(RECORD) = {
    ASN1_SIMPLE(RECORD, small, ASN1_INTEGER),
    ASN1_SIMPLE(RECORD, big, ASN1_INTEGER),
    ASN1_SIMPLE(RECORD, negbig, ASN1_INTEGER),
    ASN1_OPT(RECORD, enumerated, ASN1_ENUMERATED),
    ASN1_SIMPLE(RECORD, flag, ASN1_BOOLEAN),
    ASN1_SIMPLE(RECORD, tflag, ASN1_TBOOLEAN),
    ASN1_SIMPLE(RECORD, octets, ASN1_OCTET_STRING),
    ASN1_SIMPLE(RECORD, bits, ASN1_BIT_STRING),
    ASN1_SIMPLE(RECORD, utc, ASN1_UTCTIME),
    ASN1_SIMPLE(RECORD, gen, ASN1_GENERALIZEDTIME),
    ASN1_SIMPLE(RECORD, oid, ASN1_OBJECT),
    ASN1_SIMPLE(RECORD, longoid, ASN1_OBJECT),
    ASN1_SIMPLE(RECORD, any_null, ASN1_ANY),
    ASN1_SIMPLE(RECORD, any_seq, ASN1_ANY),
    ASN1_SIMPLE(RECORD, any_bool, ASN1_ANY),
    ASN1_SIMPLE(RECORD, any_other, ASN1_ANY),
    ASN1_SIMPLE(RECORD, dir, DIRECTORYSTRING),
    ASN1_SET_OF(RECORD, set, ASN1_INTEGER),
    ASN1_SEQUENCE_OF(RECORD, empty, ASN1_INTEGER),
    ASN1_SEQUENCE_OF_OPT(RECORD, absent, ASN1_INTEGER),
    ASN1_SIMPLE(RECORD, pick, PICK),
    ASN1_SIMPLE(RECORD, i32, INT32),
    ASN1_SIMPLE(RECORD, u64, UINT64),
    ASN1_SIMPLE(RECORD, l, LONG),
    ASN1_OPT(RECORD, missing, ASN1_OCTET_STRING),
    ASN1_SIMPLE(RECORD, ext, EXT),
    ASN1_SIMPLE(RECORD, mute, MUTE)
} ASN1_SEQUENCE_END(RECORD)

/* A SEQUENCE whose aux callback can take over printing. */
typedef struct {
    ASN1_INTEGER *n;
} TRACED;

static int print_cb_result = 1;

static int traced_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it, void *exarg)
{
    (void)in;
    (void)it;
    if (operation == ASN1_OP_PRINT_PRE || operation == ASN1_OP_PRINT_POST) {
        ASN1_PRINT_ARG *parg = exarg;

        BIO_printf(parg->out, "%*s[callback %d at %d]\n", parg->indent, "", operation, parg->indent);
        return print_cb_result;
    }
    return 1;
}

ASN1_SEQUENCE_cb(TRACED, traced_cb) = {
    ASN1_SIMPLE(TRACED, n, ASN1_INTEGER)
} ASN1_SEQUENCE_END_cb(TRACED, TRACED)

static ASN1_INTEGER *integer_hex(const char *hex)
{
    return s2i_ASN1_INTEGER(NULL, hex);
}

static ASN1_TYPE *any_of(int type, void *value)
{
    ASN1_TYPE *t = ASN1_TYPE_new();

    ASN1_TYPE_set(t, type, value);
    return t;
}

static RECORD *make_record(void)
{
    RECORD *r = (RECORD *)ASN1_item_new(ASN1_ITEM_rptr(RECORD));
    ASN1_STRING *seq = ASN1_STRING_type_new(V_ASN1_SEQUENCE), *other = ASN1_STRING_type_new(V_ASN1_OTHER);
    int i;

    ASN1_INTEGER_free(r->small);
    r->small = integer_hex("-42");
    ASN1_INTEGER_free(r->big);
    r->big = integer_hex("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    ASN1_INTEGER_free(r->negbig);
    r->negbig = integer_hex("-0x80000000000000000000000000000000");
    r->enumerated = ASN1_ENUMERATED_new();
    ASN1_ENUMERATED_set(r->enumerated, 3);
    r->flag = 0;
    r->tflag = -1;
    ASN1_STRING_set(r->octets, "\x01\x02printable? no\xff", 16);
    ASN1_BIT_STRING_set_bit(r->bits, 13, 1);
    ASN1_UTCTIME_set_string(r->utc, "240229123456Z");
    ASN1_GENERALIZEDTIME_set_string(r->gen, "20240229123456Z");
    r->oid = OBJ_nid2obj(NID_sha256WithRSAEncryption);
    r->longoid = OBJ_txt2obj("1.2.3.4444444444.5555555555.6666666666.7777777777.8888888888.9999999999.1111111111.2222222222", 1);
    ASN1_TYPE_free(r->any_null);
    r->any_null = any_of(V_ASN1_NULL, NULL);
    ASN1_STRING_set(seq, "\x30\x06\x02\x01\x05\x0c\x01\x41", 8);
    ASN1_TYPE_free(r->any_seq);
    r->any_seq = any_of(V_ASN1_SEQUENCE, seq);
    ASN1_TYPE_free(r->any_bool);
    r->any_bool = any_of(V_ASN1_BOOLEAN, (void *)1);
    ASN1_STRING_set(other, "\xa1\x03\x02\x01\x07", 5);
    ASN1_TYPE_free(r->any_other);
    r->any_other = any_of(V_ASN1_OTHER, other);
    ASN1_STRING_set(r->dir, "caf\xc3\xa9", 5);
    r->dir->type = V_ASN1_UTF8STRING;
    for (i = 0; i < 3; i++) {
        ASN1_INTEGER *n = ASN1_INTEGER_new();

        ASN1_INTEGER_set(n, 1000 * i);
        sk_ASN1_INTEGER_push(r->set, n);
    }
    sk_ASN1_INTEGER_free(r->absent);
    r->absent = NULL;
    r->pick->type = 1;
    r->pick->d.str = ASN1_UTF8STRING_new();
    ASN1_STRING_set(r->pick->d.str, "chosen", 6);
    *r->i32 = -2147483647 - 1;
    *r->u64 = 18446744073709551615ULL;
    r->l = -7;
    *r->ext = 99;
    return r;
}

static void printing(void)
{
    static const struct {
        const char *name;
        unsigned long flags;
        unsigned long str_flags;
    } contexts[] = {
        { "no flags", 0, 0 },
        { "show absent, sequence, SET OF, types", ASN1_PCTX_FLAGS_SHOW_ABSENT | ASN1_PCTX_FLAGS_SHOW_SEQUENCE
              | ASN1_PCTX_FLAGS_SHOW_SSOF | ASN1_PCTX_FLAGS_SHOW_TYPE, 0 },
        { "field struct names, no struct name", ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME | ASN1_PCTX_FLAGS_NO_STRUCT_NAME, 0 },
        { "no field names, no ANY type", ASN1_PCTX_FLAGS_NO_FIELD_NAME | ASN1_PCTX_FLAGS_NO_ANY_TYPE, ASN1_STRFLGS_RFC2253 },
    };
    const ASN1_ITEM *it = ASN1_ITEM_rptr(RECORD);
    RECORD *r = make_record();
    BIO *mem = BIO_new(BIO_s_mem());
    ASN1_PCTX *pctx = ASN1_PCTX_new();
    size_t i;
    int ret;

    ret = ASN1_item_print(mem, (ASN1_VALUE *)r, 0, it, NULL);
    printf("# default context: %d\n", ret);
    show(mem);
    errors("default");
    check(ret == 0, "an ENUMERATED field stops the print, as i2s_ASN1_INTEGER refuses it");
    ASN1_ENUMERATED_free(r->enumerated);
    r->enumerated = NULL;
    for (i = 0; i < sizeof(contexts) / sizeof(contexts[0]); i++) {
        ASN1_PCTX_set_flags(pctx, contexts[i].flags);
        ASN1_PCTX_set_str_flags(pctx, contexts[i].str_flags);
        ret = ASN1_item_print(mem, (ASN1_VALUE *)r, (int)i * 3, it, pctx);
        printf("# %s, indent %d: %d\n", contexts[i].name, (int)i * 3, ret);
        show(mem);
        errors(contexts[i].name);
        check(ret == 1, contexts[i].name);
    }
    r->pick->type = 7;
    ret = ASN1_item_print(mem, (ASN1_VALUE *)r->pick, 2, ASN1_ITEM_rptr(PICK), NULL);
    show(mem);
    check(ret == 1, "a CHOICE with a bad selector says so");
    r->pick->type = 1;
    ASN1_item_free((ASN1_VALUE *)r, it);

    ret = ASN1_item_print(mem, NULL, 4, ASN1_ITEM_rptr(ASN1_OCTET_STRING), NULL);
    show(mem);
    check(ret == 1, "an absent value prints <ABSENT>");
    ret = ASN1_item_print(mem, (ASN1_VALUE *)(intptr_t)12345, 0, ASN1_ITEM_rptr(ZLONG), NULL);
    show(mem);
    check(ret == 1, "a LONG in the slot itself");
    ASN1_PCTX_free(pctx);
    BIO_free(mem);
}

static void callbacks(void)
{
    const ASN1_ITEM *it = ASN1_ITEM_rptr(TRACED);
    TRACED *t = (TRACED *)ASN1_item_new(it);
    BIO *mem = BIO_new(BIO_s_mem());
    int ret;

    ASN1_INTEGER_set(t->n, 5);
    ret = ASN1_item_print(mem, (ASN1_VALUE *)t, 2, it, NULL);
    show(mem);
    check(ret == 1, "PRINT_PRE and PRINT_POST, with the BIO and indent");
    print_cb_result = 2;
    ret = ASN1_item_print(mem, (ASN1_VALUE *)t, 2, it, NULL);
    show(mem);
    check(ret == 1, "a PRINT_PRE of 2 prints nothing more");
    print_cb_result = 0;
    ret = ASN1_item_print(mem, (ASN1_VALUE *)t, 2, it, NULL);
    show(mem);
    check(ret == 0, "and 0 fails");
    print_cb_result = 1;
    ASN1_item_free((ASN1_VALUE *)t, it);
    BIO_free(mem);
}

static void contexts(void)
{
    ASN1_PCTX *p = ASN1_PCTX_new();

    check(p != NULL && ASN1_PCTX_get_flags(p) == 0 && ASN1_PCTX_get_nm_flags(p) == 0
              && ASN1_PCTX_get_cert_flags(p) == 0 && ASN1_PCTX_get_oid_flags(p) == 0 && ASN1_PCTX_get_str_flags(p) == 0,
          "ASN1_PCTX_new: all flags 0");
    ASN1_PCTX_set_flags(p, 1);
    ASN1_PCTX_set_nm_flags(p, 2);
    ASN1_PCTX_set_cert_flags(p, 3);
    ASN1_PCTX_set_oid_flags(p, 4);
    ASN1_PCTX_set_str_flags(p, 5);
    check(ASN1_PCTX_get_flags(p) == 1 && ASN1_PCTX_get_nm_flags(p) == 2 && ASN1_PCTX_get_cert_flags(p) == 3
              && ASN1_PCTX_get_oid_flags(p) == 4 && ASN1_PCTX_get_str_flags(p) == 5,
          "each flag set and read back");
    ASN1_PCTX_free(p);
    ASN1_PCTX_free(NULL);
}

static void conversions(void)
{
    static const char *const values[] = {
        "0", "-0", "42", "-42", "--5", "0x-5", "0xff", "-0X1F", "170141183460469231731687303715884105727",
        "170141183460469231731687303715884105728", "-340282366920938463463374607431768211456",
        "0x0000000000000000000000000000000000000001", "12a", "", "-", "0x", " 1", "1 ",
    };
    static ENUMERATED_NAMES names[] = { { 1, "one", "1" }, { 5, "five", "5" }, { -1, NULL, NULL } };
    X509V3_EXT_METHOD method;
    ASN1_INTEGER *a;
    ASN1_ENUMERATED *e = ASN1_ENUMERATED_new();
    ASN1_OCTET_STRING *os;
    char *s;
    size_t i;

    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        a = s2i_ASN1_INTEGER(NULL, values[i]);
        s = a != NULL ? i2s_ASN1_INTEGER(NULL, a) : NULL;
        printf("# s2i \"%s\": %s", values[i], a != NULL ? s : "NULL");
        if (a != NULL)
            printf(" (type %d, %d octets)", a->type, a->length);
        printf("\n");
        errors("s2i");
        OPENSSL_free(s);
        ASN1_INTEGER_free(a);
    }
    check(s2i_ASN1_INTEGER(NULL, NULL) == NULL, "s2i_ASN1_INTEGER of NULL");
    errors("NULL");
    check(i2s_ASN1_INTEGER(NULL, NULL) == NULL, "i2s_ASN1_INTEGER of NULL");

    ASN1_ENUMERATED_set(e, 5);
    s = i2s_ASN1_INTEGER(NULL, e);
    check(s == NULL, "i2s_ASN1_INTEGER refuses an ENUMERATED");
    errors("wrong type");
    s = i2s_ASN1_ENUMERATED(NULL, e);
    check(s != NULL && strcmp(s, "5") == 0, "i2s_ASN1_ENUMERATED");
    OPENSSL_free(s);
    memset(&method, 0, sizeof(method));
    method.usr_data = names;
    s = i2s_ASN1_ENUMERATED_TABLE(&method, e);
    check(s != NULL && strcmp(s, "five") == 0, "i2s_ASN1_ENUMERATED_TABLE names a known value");
    OPENSSL_free(s);
    ASN1_ENUMERATED_set(e, 7);
    s = i2s_ASN1_ENUMERATED_TABLE(&method, e);
    check(s != NULL && strcmp(s, "7") == 0, "and gives the number for an unknown one");
    OPENSSL_free(s);
    ASN1_ENUMERATED_free(e);

    os = s2i_ASN1_OCTET_STRING(NULL, NULL, "01:ab:FF");
    s = os != NULL ? i2s_ASN1_OCTET_STRING(NULL, os) : NULL;
    check(os != NULL && os->length == 3 && s != NULL && strcmp(s, "01:AB:FF") == 0,
          "s2i_ASN1_OCTET_STRING and i2s_ASN1_OCTET_STRING");
    OPENSSL_free(s);
    ASN1_OCTET_STRING_free(os);
    os = s2i_ASN1_OCTET_STRING(NULL, NULL, "0g");
    check(os == NULL, "bad hex");
    errors("bad hex");
    os = s2i_ASN1_OCTET_STRING(NULL, NULL, "");
    s = os != NULL ? i2s_ASN1_OCTET_STRING(NULL, os) : NULL;
    printf("# empty hex: %s %d \"%s\"\n", os != NULL ? "string" : "NULL", os != NULL ? os->length : -1, s != NULL ? s : "NULL");
    errors("empty hex");
    OPENSSL_free(s);
    ASN1_OCTET_STRING_free(os);
}

int main(void)
{
    contexts();
    conversions();
    printing();
    callbacks();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
