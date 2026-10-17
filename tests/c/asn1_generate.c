/*
 * Conformance test for ASN1_generate_nconf(3) and ASN1_generate_v3: every universal type and
 * its formats (ASCII, UTF8, HEX, BITLIST), the modifiers (IMP, EXP with each class, SEQWRAP,
 * SETWRAP, OCTWRAP, BITWRAP), SEQUENCE and SET from configuration sections (nested, and too
 * deep), and every kind of bad input; and their users: ASN1: extension values, otherName
 * alternative names, and ASN1: attribute certificate attributes.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_acert.h>
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
        if ((flags & ERR_TXT_STRING) != 0 && *data != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

static void hex(const unsigned char *p, int n)
{
    int i;

    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
}

static void gen(const char *str, CONF *conf)
{
    ASN1_TYPE *t = ASN1_generate_nconf(str, conf);

    printf("[%s]: ", str);
    if (t == NULL) {
        printf("NULL\n");
    } else {
        unsigned char *der = NULL;
        int n = i2d_ASN1_TYPE(t, &der);

        printf("type %d, ", ASN1_TYPE_get(t));
        hex(der, n);
        printf("\n");
        OPENSSL_free(der);
        ASN1_TYPE_free(t);
    }
    errors();
}

static const char CONFIG[] =
    "[seq]\n"
    "a = INTEGER:1\n"
    "b = UTF8:hello\n"
    "c = SEQUENCE:inner\n"
    "[inner]\n"
    "x = BOOLEAN:TRUE\n"
    "y = NULL\n"
    "[set]\n"
    "z = PRINTABLE:b\n"
    "a = PRINTABLE:a\n"
    "[empty]\n"
    "[bad]\n"
    "a = NOSUCHTYPE:1\n"
    "[loop]\n"
    "a = SEQUENCE:loop\n"
    "[san]\n"
    "otherName.1 = 1.2.3.4;UTF8:hello world\n"
    "otherName.2 = 1.3.6.1.4.1.311.20.2.3;UTF8:user@example.com\n"
    "[attrs]\n"
    "role = ASN1:SEQUENCE:seq\n"
    "plain = some text\n";

int main(void)
{
    static const char *const strings[] = {
        "BOOLEAN:TRUE", "BOOL:no", "BOOLEAN:maybe", "NULL", "NULL:x", "INTEGER:42", "INT:-0x100",
        "INTEGER:12345678901234567890", "INTEGER:abc", "ENUMERATED:7", "ENUM:-1", "OBJECT:1.2.3.4",
        "OID:commonName", "OBJECT:not an oid", "UTCTIME:250101000000Z", "UTC:bad",
        "GENERALIZEDTIME:20250101000000Z", "GENTIME:2025", "OCTETSTRING:hello", "OCT:",
        "FORMAT:HEX,OCTETSTRING:0102ff", "FORMAT:HEX,OCT:zz", "BITSTRING:abc", "BITSTR:",
        "FORMAT:HEX,BITSTRING:0f", "FORMAT:BITLIST,BITSTRING:1,3,5,7", "FORMAT:BITLIST,BITSTR:0",
        "FORMAT:BITLIST,BITSTRING:x", "FORMAT:BITLIST,OCTETSTRING:1", "FORMAT:BITLIST,BITSTRING:1,-2",
        "UTF8:hello, world", "UTF8String:caf\xc3\xa9", "FORMAT:UTF8,UTF8:caf\xc3\xa9",
        "FORMAT:UTF8,BMP:caf\xc3\xa9", "BMPSTRING:hi", "PRINTABLESTRING:Hello", "PRINTABLE:a@b",
        "IA5STRING:a@b", "IA5:\xc3\xa9", "T61STRING:t61", "TELETEXSTRING:t", "VISIBLESTRING:v",
        "VISIBLE:v", "UNIVERSALSTRING:u", "UNIV:u", "GENERALSTRING:g", "GenStr:g",
        "NUMERICSTRING:123", "NUMERIC:12a", "FORMAT:HEX,UTF8:00", "FORMAT:HEX,INTEGER:1",
        "FORMAT:HEX,OID:1.2", "FORMAT:HEX,UTC:x", "FORMAT:HEX,BOOL:TRUE", "FORMAT:WRONG,UTF8:x",
        "FORMAT,UTF8:x", "FORMAT:ASCIIx,UTF8:x", "IMP:0,INTEGER:5", "IMPLICIT:1A,INTEGER:5",
        "IMP:2P,UTF8:x", "IMP:3U,UTF8:x", "IMP:4C,UTF8:x", "IMP:5X,UTF8:x", "IMP:,UTF8:x",
        "IMP:abc,UTF8:x", "IMP:4294967297,UTF8:x", "IMP:-1,UTF8:x", "IMP:1,IMP:2,UTF8:x",
        "EXP:0,INTEGER:5", "EXPLICIT:1A,EXP:2P,INTEGER:5", "IMP:0,EXP:1,UTF8:x", "EXP:1,IMP:0,UTF8:x",
        "IMP:1,SEQWRAP,INTEGER:1", "SEQWRAP,INTEGER:1", "SETWRAP,INTEGER:1", "OCTWRAP,INTEGER:1",
        "BITWRAP,INTEGER:1", "OCTWRAP,BITWRAP,SEQWRAP,INTEGER:1", "IMP:16U,OCTWRAP,UTF8:x",
        "IMP:16U,UTF8:x", "IMP:17U,UTF8:x", "IMP:31,UTF8:x", "IMP:300,UTF8:x",
        "EXP:1,EXP:2,EXP:3,EXP:4,EXP:5,EXP:6,EXP:7,EXP:8,EXP:9,EXP:10,EXP:11,EXP:12,EXP:13,EXP:14,"
        "EXP:15,EXP:16,EXP:17,EXP:18,EXP:19,EXP:20,INTEGER:1",
        "EXP:1,EXP:2,EXP:3,EXP:4,EXP:5,EXP:6,EXP:7,EXP:8,EXP:9,EXP:10,EXP:11,EXP:12,EXP:13,EXP:14,"
        "EXP:15,EXP:16,EXP:17,EXP:18,EXP:19,EXP:20,EXP:21,INTEGER:1",
        "NOSUCH:1", "INTEGER", "INTEGER,", "UTF8", " INTEGER : 3 ", "integer:9", "IMP:0", "",
        ",", "SEQWRAP", "SEQUENCE:seq", "SET:set", "SEQ:empty", "SEQUENCE", "SEQUENCE:nosection",
        "SEQUENCE:bad", "SEQUENCE:loop", "IMP:3,SEQUENCE:inner", "EXP:3,SET:set", "IMP:16U,SET:set",
        "SEQUENCE:seq,extra", "UTF8:a:b:c", "DIRECTORYSTRING:x",
    };
    BIO *b = BIO_new_mem_buf(CONFIG, -1);
    CONF *conf = NCONF_new(NULL);
    size_t i;

    NCONF_load_bio(conf, b, NULL);
    BIO_free(b);

    printf("# without a configuration\n");
    for (i = 0; i < sizeof(strings) / sizeof(strings[0]); i++)
        gen(strings[i], NULL);
    check(1, "without a configuration");
    printf("# with a configuration\n");
    for (i = 0; i < sizeof(strings) / sizeof(strings[0]); i++)
        if (strstr(strings[i], "SEQ") != NULL || strstr(strings[i], "SET") != NULL)
            gen(strings[i], conf);
    check(1, "with a configuration");

    printf("# ASN1_generate_v3\n");
    {
        X509V3_CTX ctx;
        ASN1_TYPE *t;

        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_nconf(&ctx, conf);
        t = ASN1_generate_v3("SEQUENCE:seq", &ctx);
        printf("  with sections: %s\n", t == NULL ? "NULL" : "value");
        ASN1_TYPE_free(t);
        t = ASN1_generate_v3("UTF8:x", NULL);
        printf("  without a context: %s\n", t == NULL ? "NULL" : "value");
        ASN1_TYPE_free(t);
        errors();
    }
    check(1, "ASN1_generate_v3");

    printf("# extensions\n");
    {
        X509V3_CTX ctx;
        static const char *const values[] = {
            "ASN1:UTF8:hello", "critical,ASN1:SEQUENCE:seq", "ASN1:NOSUCH:1", "DER:0102",
            "ASN1:FORMAT:HEX,OCT:00ff",
        };
        size_t k;

        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_nconf(&ctx, conf);
        for (k = 0; k < sizeof(values) / sizeof(values[0]); k++) {
            X509_EXTENSION *ex = X509V3_EXT_nconf(conf, &ctx, "1.2.3.4.5", values[k]);

            printf("  %s: ", values[k]);
            if (ex == NULL) {
                printf("NULL\n");
            } else {
                printf("critical %d, ", X509_EXTENSION_get_critical(ex));
                hex(ASN1_STRING_get0_data(X509_EXTENSION_get_data(ex)), ASN1_STRING_length(X509_EXTENSION_get_data(ex)));
                printf("\n");
            }
            X509_EXTENSION_free(ex);
            errors();
        }
        {
            X509_EXTENSION *ex = X509V3_EXT_nconf_nid(conf, &ctx, NID_subject_alt_name, "@san");
            BIO *out = BIO_new(BIO_s_mem());
            char *text;
            long len;

            printf("  otherNames: %s\n", ex == NULL ? "NULL" : "made");
            if (ex != NULL) {
                X509V3_EXT_print(out, ex, 0, 4);
                len = BIO_get_mem_data(out, &text);
                printf("%.*s\n", (int)len, text);
                hex(ASN1_STRING_get0_data(X509_EXTENSION_get_data(ex)), ASN1_STRING_length(X509_EXTENSION_get_data(ex)));
                printf("\n");
            }
            BIO_free(out);
            X509_EXTENSION_free(ex);
            errors();
            ex = X509V3_EXT_nconf_nid(conf, &ctx, NID_subject_alt_name, "otherName:1.2.3;NOSUCH:x");
            printf("  a bad otherName: %s\n", ex == NULL ? "NULL" : "made");
            errors();
            ex = X509V3_EXT_nconf_nid(conf, &ctx, NID_subject_alt_name, "otherName:1.2.3");
            printf("  an otherName without a value: %s\n", ex == NULL ? "NULL" : "made");
            errors();
            ex = X509V3_EXT_nconf_nid(conf, &ctx, NID_subject_alt_name, "otherName:not.an.oid;UTF8:x");
            printf("  an otherName with a bad OID: %s\n", ex == NULL ? "NULL" : "made");
            errors();
        }
    }
    check(1, "extensions");

    printf("# attribute certificate attributes\n");
    {
        X509_ACERT *a = X509_ACERT_new();
        int k;

        printf("  added: %d, count %d\n", X509_ACERT_add_attr_nconf(conf, "attrs", a), X509_ACERT_get_attr_count(a));
        for (k = 0; k < X509_ACERT_get_attr_count(a); k++) {
            X509_ATTRIBUTE *at = X509_ACERT_get_attr(a, k);
            ASN1_TYPE *t = X509_ATTRIBUTE_get0_type(at, 0);
            unsigned char *der = NULL;
            int n = i2d_ASN1_TYPE(t, &der);

            printf("  %d: type %d, ", k, ASN1_TYPE_get(t));
            hex(der, n);
            printf("\n");
            OPENSSL_free(der);
        }
        errors();
        X509_ACERT_free(a);
    }
    check(1, "attribute certificate attributes");

    NCONF_free(conf);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
