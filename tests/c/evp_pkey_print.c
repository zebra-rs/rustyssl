/*
 * Conformance test for printing keys and reading PEM blocks by name (EVP_PKEY_print_public(3),
 * PEM_bytes_read_bio(3), PEM_ASN1_read(3)), in TAP format.
 *
 * Printing: provided keys whose providers have no text encoder for them, a blank key, and keys
 * of the test's own type (an ASN.1 method it adds, with print functions and without) print what
 * OpenSSL prints, with and without indentation, to memory BIOs, BIOs already indenting, and
 * files. Reading: PEM blocks found by the name asked for, the names that stand for others
 * ("ANY PRIVATE KEY" and "PARAMETERS" consult the ASN.1 methods), an encrypted block, the
 * secure-heap variant, and PEM_ASN1_read(_bio) decoding what's found.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* Each queued error: library, reason, and its data. */
static void errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf("  errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0)
        printf(" %d/%d%s%s", ERR_GET_LIB(code), ERR_GET_REASON(code),
               (flags & ERR_TXT_STRING) != 0 ? ":" : "",
               (flags & ERR_TXT_STRING) != 0 ? data : "");
    printf("\n");
}

/* What the memory BIO holds, line by line (shown with '|' at each end), then emptied. */
static void show(BIO *b)
{
    char *p = NULL;
    long n = BIO_get_mem_data(b, &p);
    long i, start = 0;

    for (i = 0; i < n; i++)
        if (p[i] == '\n') {
            printf("  |%.*s|\n", (int)(i - start), p + start);
            start = i + 1;
        }
    if (start < n)
        printf("  |%.*s (no newline)\n", (int)(n - start), p + start);
    (void)BIO_reset(b);
}

/* The print functions of the test's own ASN.1 method. */
static int toy_nid;

static int pub_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)
{
    (void)pctx;
    return BIO_printf(out, "%*sToy public key (%d)\n  data: %s\n", indent, "",
                      indent, (const char *)EVP_PKEY_get0(pkey)) > 0;
}

static int priv_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)
{
    (void)pkey, (void)pctx;
    BIO_printf(out, "Toy private key, no newline (%d)", indent);
    return 7;
}

static int param_print(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)
{
    (void)out, (void)pkey, (void)indent, (void)pctx;
    return 0;
}

static int param_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen)
{
    (void)pkey, (void)pder, (void)derlen;
    return 0;
}

static void print_all(const char *label, BIO *b, EVP_PKEY *k, int indent)
{
    int r1 = EVP_PKEY_print_public(b, k, indent, NULL);
    int r2, r3;

    printf("  %s public %d\n", label, r1);
    show(b);
    r2 = EVP_PKEY_print_private(b, k, indent, NULL);
    printf("  %s private %d\n", label, r2);
    show(b);
    r3 = EVP_PKEY_print_params(b, k, indent, NULL);
    printf("  %s params %d\n", label, r3);
    show(b);
    errors();
}

static void test_print(void)
{
    BIO *b = BIO_new(BIO_s_mem()), *pre;
    EVP_PKEY *k, *blank = EVP_PKEY_new(), *toy = EVP_PKEY_new(), *bare = EVP_PKEY_new();
    EVP_PKEY_CTX *c;
    EVP_PKEY_ASN1_METHOD *am;
    static char data[] = "toy data";
    FILE *fp;
    char line[200];

    k = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, (const unsigned char *)"0123456789",
                                     10);
    check(k != NULL, "an HMAC key");
    print_all("hmac", b, k, 0);
    print_all("hmac indent 3", b, k, 3);
    print_all("hmac indent -2", b, k, -2);
    EVP_PKEY_free(k);

    k = NULL;
    c = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, NULL);
    EVP_PKEY_keygen_init(c);
    EVP_PKEY_CTX_set_mac_key(c, (const unsigned char *)"key", 3);
    EVP_PKEY_keygen(c, &k);
    EVP_PKEY_CTX_free(c);
    check(k != NULL, "an HMAC key by key generation");
    print_all("generated", b, k, 1);
    EVP_PKEY_free(k);

    k = EVP_PKEY_new_raw_private_key_ex(NULL, "SIPHASH", NULL,
                                        (const unsigned char *)"0123456789abcdef", 16);
    print_all("siphash", b, k, 0);
    EVP_PKEY_free(k);

    print_all("blank", b, blank, 2);

    /* A BIO that indents already keeps its indentation. */
    pre = BIO_push(BIO_new(BIO_f_prefix()), BIO_new(BIO_s_mem()));
    BIO_set_indent(pre, 5);
    k = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, (const unsigned char *)"k", 1);
    printf("  prefix public %d\n", EVP_PKEY_print_public(pre, k, 2, NULL));
    printf("  prefix indent %ld\n", (long)BIO_get_indent(pre));
    BIO_puts(pre, "after\n");
    /* Without indentation, the BIO's is reset to 0. */
    printf("  prefix again %d", EVP_PKEY_print_params(pre, k, 0, NULL));
    printf(" indent %ld\n", (long)BIO_get_indent(pre));
    show(BIO_next(pre));
    EVP_PKEY_free(k);
    BIO_free_all(pre);

    /* A key type of the test's own. */
    toy_nid = OBJ_create("1.3.6.1.4.1.99999.11", "PRINTTOY", "print toy algorithm");
    am = EVP_PKEY_asn1_new(toy_nid, 0, "PRINTTOY", "print toy");
    EVP_PKEY_asn1_set_public(am, NULL, NULL, NULL, pub_print, NULL, NULL);
    EVP_PKEY_asn1_set_private(am, NULL, NULL, priv_print);
    EVP_PKEY_asn1_set_param(am, param_decode, NULL, NULL, NULL, NULL, param_print);
    check(EVP_PKEY_asn1_add0(am) == 1, "the ASN.1 method");
    EVP_PKEY_assign(toy, toy_nid, data);
    print_all("toy", b, toy, 0);
    print_all("toy indent 4", b, toy, 4);
    am = EVP_PKEY_asn1_new(toy_nid + 1, 0, "BARETOY", "bare toy");
    check(EVP_PKEY_asn1_add0(am) == 1, "a method without print functions");
    EVP_PKEY_set_type(bare, toy_nid + 1);
    print_all("bare", b, bare, 1);

    /* The FILE forms. */
    fp = tmpfile();
    printf("  fp %d %d %d\n", EVP_PKEY_print_public_fp(fp, toy, 2, NULL),
           EVP_PKEY_print_private_fp(fp, bare, 0, NULL), EVP_PKEY_print_params_fp(fp, blank, 1, NULL));
    rewind(fp);
    while (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        printf("  fp |%s|\n", line);
    }
    fclose(fp);
    errors();

    EVP_PKEY_assign(toy, toy_nid, NULL);
    EVP_PKEY_free(toy);
    EVP_PKEY_free(bare);
    EVP_PKEY_free(blank);
    BIO_free(b);
}

/* PEM ------------------------------------------------------------------------------------ */

static const char blocks[] =
    "junk before\n"
    "-----BEGIN RSA PRIVATE KEY-----\nAgEB\n-----END RSA PRIVATE KEY-----\n"
    "-----BEGIN DH PRIVATE KEY-----\nAgEC\n-----END DH PRIVATE KEY-----\n"
    "-----BEGIN PRINTTOY PRIVATE KEY-----\nAgED\n-----END PRINTTOY PRIVATE KEY-----\n"
    "-----BEGIN EC PRIVATE KEY-----\nAgEE\n-----END EC PRIVATE KEY-----\n"
    "-----BEGIN PRIVATE KEY-----\nAgEF\n-----END PRIVATE KEY-----\n"
    "-----BEGIN RSA PARAMETERS-----\nAgEG\n-----END RSA PARAMETERS-----\n"
    "-----BEGIN PRINTTOY PARAMETERS-----\nAgEH\n-----END PRINTTOY PARAMETERS-----\n"
    "-----BEGIN BARETOY PARAMETERS-----\nAgEI\n-----END BARETOY PARAMETERS-----\n"
    "-----BEGIN X9.42 DH PARAMETERS-----\nAgEJ\n-----END X9.42 DH PARAMETERS-----\n"
    "-----BEGIN X509 CERTIFICATE-----\nAgEK\n-----END X509 CERTIFICATE-----\n"
    "-----BEGIN NEW CERTIFICATE REQUEST-----\nAgEL\n-----END NEW CERTIFICATE REQUEST-----\n"
    "-----BEGIN CERTIFICATE-----\nAgEM\n-----END CERTIFICATE-----\n"
    "-----BEGIN PKCS7-----\nAgEN\n-----END PKCS7-----\n"
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAgEO\n-----END ENCRYPTED PRIVATE KEY-----\n"
    "-----BEGIN X9.42 DH PARAMETERS-----\nAgEP\n-----END X9.42 DH PARAMETERS-----\n"
    "-----BEGIN PKCS #7 SIGNED DATA-----\nAgEQ\n-----END PKCS #7 SIGNED DATA-----\n";

static const char encrypted[] =
    "-----BEGIN TOY DATA-----\n"
    "Proc-Type: 4,ENCRYPTED\n"
    "DEK-Info: AES-128-CBC,0102030405060708090A0B0C0D0E0F10\n"
    "\n"
    "VOGllYKrd7ZG2bkwqdZBDg==\n"
    "-----END TOY DATA-----\n";

static int password(char *buf, int size, int rwflag, void *u)
{
    (void)rwflag;
    printf("  [password %d %s]\n", size, (const char *)u);
    if (strcmp((const char *)u, "none") == 0)
        return -1;
    strncpy(buf, (const char *)u, (size_t)size);
    return (int)strlen((const char *)u);
}

/* Reads every block named `name` from the blocks above, in order. */
static void read_all(const char *name, int secure)
{
    BIO *b = BIO_new_mem_buf(blocks, -1);
    unsigned char *d;
    char *nm;
    long len;
    int r;

    printf("  %s:", name);
    for (;;) {
        d = NULL;
        nm = NULL;
        r = secure ? PEM_bytes_read_bio_secmem(&d, &len, &nm, name, b, NULL, NULL)
                   : PEM_bytes_read_bio(&d, &len, &nm, name, b, NULL, NULL);
        if (r != 1)
            break;
        printf(" [%s %ld %02x]", nm, len, d[len - 1]);
        if (secure)
            OPENSSL_secure_clear_free(d, (size_t)len);
        else
            OPENSSL_free(d);
        OPENSSL_free(nm);
    }
    printf(" end %d\n", r);
    errors();
    BIO_free(b);
}

static void test_pem(void)
{
    BIO *b;
    unsigned char *d = NULL;
    long len = 0;
    ASN1_INTEGER *ai = NULL, *got;
    FILE *fp;
    int r;

    read_all(PEM_STRING_EVP_PKEY, 0);
    read_all(PEM_STRING_PARAMETERS, 0);
    read_all(PEM_STRING_DHPARAMS, 0);
    read_all(PEM_STRING_X509, 0);
    read_all(PEM_STRING_X509_TRUSTED, 0);
    read_all(PEM_STRING_X509_REQ, 0);
    read_all(PEM_STRING_PKCS7, 0);
    read_all(PEM_STRING_CMS, 0);
    read_all("NOTHING HERE", 0);
    read_all(PEM_STRING_EVP_PKEY, 1);

    /* Without a place for the name. */
    b = BIO_new_mem_buf(blocks, -1);
    r = PEM_bytes_read_bio(&d, &len, NULL, PEM_STRING_PKCS8, b, NULL, NULL);
    printf("  no name %d %ld %02x\n", r, len, r == 1 ? d[len - 1] : 0);
    OPENSSL_free(d);
    BIO_free(b);

    /* An encrypted block. */
    b = BIO_new_mem_buf(encrypted, -1);
    d = NULL;
    r = PEM_bytes_read_bio(&d, &len, NULL, "TOY DATA", b, password, "secret");
    printf("  decrypted %d %ld", r, len);
    for (long i = 0; r == 1 && i < len; i++)
        printf(" %02x", d[i]);
    printf("\n");
    OPENSSL_free(d);
    BIO_free(b);
    b = BIO_new_mem_buf(encrypted, -1);
    d = NULL;
    r = PEM_bytes_read_bio(&d, &len, NULL, "TOY DATA", b, password, "wrong");
    printf("  wrong password %d\n", r);
    errors();
    BIO_free(b);
    b = BIO_new_mem_buf(encrypted, -1);
    r = PEM_bytes_read_bio(&d, &len, NULL, "TOY DATA", b, password, "none");
    printf("  no password %d\n", r);
    errors();
    BIO_free(b);

    /* Decoding what's found. */
    b = BIO_new_mem_buf(encrypted, -1);
    got = PEM_ASN1_read_bio((d2i_of_void *)d2i_ASN1_INTEGER, "TOY DATA", b, (void **)&ai,
                            password, "secret");
    printf("  integer %d %ld\n", got != NULL && got == ai, ASN1_INTEGER_get(ai));
    BIO_free(b);
    b = BIO_new_mem_buf(blocks, -1);
    got = PEM_ASN1_read_bio((d2i_of_void *)d2i_ASN1_INTEGER, PEM_STRING_PKCS7, b, NULL, NULL,
                            NULL);
    printf("  pkcs7 integer %ld\n", got == NULL ? -1 : ASN1_INTEGER_get(got));
    ASN1_INTEGER_free(got);
    BIO_free(b);
    b = BIO_new_mem_buf(blocks, -1);
    got = PEM_ASN1_read_bio((d2i_of_void *)d2i_ASN1_OBJECT, PEM_STRING_PKCS7, b, NULL, NULL,
                            NULL);
    printf("  wrong type %d\n", got != NULL);
    errors();
    BIO_free(b);

    fp = tmpfile();
    fputs(encrypted, fp);
    rewind(fp);
    got = PEM_ASN1_read((d2i_of_void *)d2i_ASN1_INTEGER, "TOY DATA", fp, NULL, password,
                        "secret");
    printf("  from a file %ld\n", got == NULL ? -1 : ASN1_INTEGER_get(got));
    ASN1_INTEGER_free(got);
    got = PEM_ASN1_read((d2i_of_void *)d2i_ASN1_INTEGER, "TOY DATA", fp, NULL, password,
                        "secret");
    printf("  at the end %d\n", got != NULL);
    errors();
    fclose(fp);
    ASN1_INTEGER_free(ai);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    test_print();
    test_pem();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
