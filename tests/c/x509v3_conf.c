/*
 * Conformance test for extensions from configuration text (X509V3_EXT_nconf(3),
 * X509V3_EXT_nconf_nid, X509V3_EXT_add_nconf_sk, X509V3_EXT_add_nconf, X509V3_EXT_REQ_add_nconf,
 * and their legacy CONF forms), in TAP format: extensions made from values (critical, raw
 * DER, sections, lists, strings, policies through the configuration), the errors of unknown
 * names, empty values, and methods that can't be set; a section added to a certificate (with
 * the key identifiers in their order, and replacing), to a request, and to a list.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
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
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, long n)
{
    long i;

    printf("  %s (%ld):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 && i > 0 ? "\n    " : " ", p[i]);
    printf("\n");
}

static BIO *out;

static void flush_out(void)
{
    char *data;
    long n = BIO_get_mem_data(out, &data);

    fwrite(data, 1, (size_t)n, stdout);
    (void)BIO_reset(out);
}

static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBmTCCAT+gAwIBAgIIEjRWeJCrze8wCgYIKoZIzj0EAwIwMjELMAkGA1UEBhMC\n"
    "SlAxETAPBgNVBAoMCHJ1c3R5c3NsMRAwDgYDVQQDDAdUZXN0IENBMB4XDTI2MTAx\n"
    "NzExNTcyOVoXDTM2MTAxNDExNTcyOVowMjELMAkGA1UEBhMCSlAxETAPBgNVBAoM\n"
    "CHJ1c3R5c3NsMRAwDgYDVQQDDAdUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
    "AQcDQgAEG8QBqFVH9Y13H0s9Copsp8sUXZPYdQ3axAVnbqLSRU4/Ee5md40Qwqqy\n"
    "B/0BFFHesy61jWDP6FAWuBKm/Hibu6M/MD0wDwYDVR0TAQH/BAUwAwEB/zALBgNV\n"
    "HQ8EBAMCAQYwHQYDVR0OBBYEFFT/pnuNPm1SB+yJgcMJY5Cw5uK3MAoGCCqGSM49\n"
    "BAMCA0gAMEUCIHcVN0GtOf7I7yBYW9wwXEqBZhVMdJVutI2PwKohj1fhAiEA/yez\n"
    "gwPyEeIQYZLF0ykw0qkc1dxRgdA6ClD8WGALKOM=\n"
    "-----END CERTIFICATE-----\n";

static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static void print_out(const char *label)
{
    printf("  %s: [", label);
    flush_out();
    printf("]\n");
}

static const char CONF_TEXT[] =
    "[exts]\n"
    "authorityKeyIdentifier = keyid:always\n"
    "basicConstraints = critical, CA:FALSE\n"
    "subjectKeyIdentifier = hash\n"
    "keyUsage = digitalSignature, keyEncipherment\n"
    "subjectAltName = @alt\n"
    "1.2.3.4 = DER:0500\n"
    "certificatePolicies = 1.2.3.4, @pol\n"
    "[alt]\n"
    "DNS.1 = a.example\n"
    "DNS.2 = b.example\n"
    "[pol]\n"
    "policyIdentifier = 1.2.3.5\n"
    "CPS.1 = http://cps.example/\n"
    "[more]\n"
    "keyUsage = critical, keyCertSign\n"
    "nsComment = replaced\n"
    "[badsec]\n"
    "keyUsage = notAUsage\n"
    "[unknown]\n"
    "noSuchExtension = x\n"
    "[empty]\n";

static void show_ext(const char *label, X509_EXTENSION *e)
{
    unsigned char *der = NULL;
    int len;

    printf("# %s\n", label);
    if (e == NULL) {
        printf("  none\n");
        errors();
        return;
    }
    len = i2d_X509_EXTENSION(e, &der);
    hex("extension", der, len);
    OPENSSL_free(der);
    X509V3_EXT_print(out, e, 0, 2);
    print_out("printed");
    X509_EXTENSION_free(e);
    errors();
}

static void show_exts(const char *label, const STACK_OF(X509_EXTENSION) *exts)
{
    printf("  %s: %d extensions\n", label, sk_X509_EXTENSION_num(exts));
    X509V3_extensions_print(out, NULL, exts, 0, 4);
    print_out("printed");
}

int main(void)
{
    BIO *b = BIO_new_mem_buf(CONF_TEXT, -1);
    CONF *conf = NCONF_new(NULL);
    LHASH_OF(CONF_VALUE) *lh;
    X509V3_CTX ctx;
    X509 *ca = read_cert(CA_PEM), *x = X509_new();
    X509_REQ *req = X509_REQ_new();
    STACK_OF(X509_EXTENSION) *list = NULL;
    long eline = -1;

    out = BIO_new(BIO_s_mem());
    check(NCONF_load_bio(conf, b, &eline) == 1, "loaded the configuration");
    BIO_free(b);

    show_ext("basicConstraints", X509V3_EXT_nconf(conf, NULL, "basicConstraints", "critical,CA:TRUE,pathlen:1"));
    show_ext("critical with spaces", X509V3_EXT_nconf(conf, NULL, "keyUsage", "critical,   digitalSignature"));
    show_ext("long name", X509V3_EXT_nconf(conf, NULL, "X509v3 Key Usage", "digitalSignature"));
    show_ext("DER", X509V3_EXT_nconf(conf, NULL, "1.2.3.4", "DER:01:02:03"));
    show_ext("DER, critical, by name", X509V3_EXT_nconf(conf, NULL, "keyUsage", "critical,DER: 03020780"));
    show_ext("DER, bad hex", X509V3_EXT_nconf(conf, NULL, "1.2.3.4", "DER:0g"));
    show_ext("DER, bad name", X509V3_EXT_nconf(conf, NULL, "not an object", "DER:00"));
    show_ext("section", X509V3_EXT_nconf(conf, NULL, "subjectAltName", "@alt"));
    show_ext("missing section", X509V3_EXT_nconf(conf, NULL, "subjectAltName", "@nothing"));
    show_ext("empty list", X509V3_EXT_nconf(conf, NULL, "subjectAltName", ""));
    show_ext("s2i", X509V3_EXT_nconf(conf, NULL, "nsComment", "a comment"));
    show_ext("r2i", X509V3_EXT_nconf(conf, NULL, "certificatePolicies", "1.2.3.4, @pol"));
    show_ext("r2i without a configuration", X509V3_EXT_nconf(NULL, NULL, "certificatePolicies", "1.2.3.4"));
    show_ext("not settable", X509V3_EXT_nconf(conf, NULL, "x509ExtAdmission", "x"));
    show_ext("unknown name", X509V3_EXT_nconf(conf, NULL, "noSuchExtension", "x"));
    show_ext("no method", X509V3_EXT_nconf(conf, NULL, "commonName", "x"));
    show_ext("bad value", X509V3_EXT_nconf(conf, NULL, "basicConstraints", "CA:maybe"));
    show_ext("by NID", X509V3_EXT_nconf_nid(conf, NULL, NID_key_usage, "critical,cRLSign"));
    show_ext("by NID, DER", X509V3_EXT_nconf_nid(conf, NULL, NID_key_usage, "DER:03020106"));
    show_ext("by NID, unknown", X509V3_EXT_nconf_nid(conf, NULL, NID_commonName, "x"));
    show_ext("by NID, undefined", X509V3_EXT_nconf_nid(conf, NULL, NID_undef, "x"));

    X509V3_set_ctx(&ctx, ca, x, NULL, NULL, 0);
    X509V3_set_nconf(&ctx, conf);
    X509_set_pubkey(x, X509_get0_pubkey(ca));
    check(X509V3_EXT_add_nconf(conf, &ctx, "exts", x) == 1, "added a section to a certificate");
    show_exts("certificate", X509_get0_extensions(x));
    check(X509V3_EXT_add_nconf(conf, &ctx, "more", x) == 1, "added more");
    show_exts("appended", X509_get0_extensions(x));
    X509V3_set_ctx(&ctx, ca, x, NULL, NULL, X509V3_CTX_REPLACE);
    X509V3_set_nconf(&ctx, conf);
    check(X509V3_EXT_add_nconf(conf, &ctx, "more", x) == 1, "replaced");
    show_exts("replaced", X509_get0_extensions(x));
    check(X509V3_EXT_add_nconf(conf, &ctx, "badsec", x) == 0, "a bad value fails");
    errors();
    check(X509V3_EXT_add_nconf(conf, &ctx, "unknown", x) == 0, "an unknown name fails");
    errors();
    check(X509V3_EXT_add_nconf(conf, &ctx, "nothing", x) == 0, "a missing section fails");
    errors();
    check(X509V3_EXT_add_nconf(conf, &ctx, "empty", x) == 1, "an empty section adds nothing");
    check(X509V3_EXT_add_nconf(conf, NULL, "more", NULL) == 1, "made without a certificate");
    errors();

    X509V3_set_ctx(&ctx, ca, NULL, req, NULL, 0);
    X509V3_set_nconf(&ctx, conf);
    check(X509V3_EXT_REQ_add_nconf(conf, &ctx, "more", req) == 1, "added to a request");
    {
        STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);

        show_exts("request", exts);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
    check(X509V3_EXT_REQ_add_nconf(conf, &ctx, "empty", req) == 1, "an empty section");
    printf("  request attributes: %d\n", X509_REQ_get_attr_count(req));
    check(X509V3_EXT_add_nconf_sk(conf, NULL, "more", &list) == 1, "added to a list");
    show_exts("list", list);
    check(X509V3_EXT_add_nconf_sk(conf, NULL, "more", NULL) == 1, "made without a list");

    /* The legacy CONF forms. */
    b = BIO_new_mem_buf(CONF_TEXT, -1);
    lh = CONF_load_bio(NULL, b, &eline);
    BIO_free(b);
    check(lh != NULL, "loaded a legacy configuration");
    show_ext("legacy", X509V3_EXT_conf(lh, NULL, "subjectAltName", "@alt"));
    show_ext("legacy by NID", X509V3_EXT_conf_nid(lh, NULL, NID_basic_constraints, "CA:TRUE"));
    show_ext("legacy, no hash", X509V3_EXT_conf(NULL, NULL, "subjectAltName", "@alt"));
    {
        X509 *y = X509_new();
        X509_REQ *r = X509_REQ_new();

        X509V3_set_ctx(&ctx, ca, y, NULL, NULL, 0);
        X509V3_set_conf_lhash(&ctx, lh);
        check(X509V3_EXT_add_conf(lh, &ctx, "more", y) == 1, "legacy, to a certificate");
        show_exts("legacy certificate", X509_get0_extensions(y));
        check(X509V3_EXT_REQ_add_conf(lh, &ctx, "more", r) == 1, "legacy, to a request");
        printf("  request attributes: %d\n", X509_REQ_get_attr_count(r));
        X509_free(y);
        X509_REQ_free(r);
    }
    CONF_free(lh);

    sk_X509_EXTENSION_pop_free(list, X509_EXTENSION_free);
    NCONF_free(conf);
    X509_free(ca);
    X509_free(x);
    X509_REQ_free(req);
    BIO_free(out);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
