/*
 * Conformance test for custom TLS extensions and server information
 * (SSL_CTX_add_custom_ext(3), SSL_CTX_add_client_custom_ext(3),
 * SSL_CTX_add_server_custom_ext(3), SSL_CTX_has_client_custom_ext(3),
 * SSL_extension_supported(3), SSL_CTX_use_serverinfo(3), SSL_CTX_use_serverinfo_ex(3),
 * SSL_CTX_use_serverinfo_file(3)): the registration rules (libssl's own types, duplicates,
 * roles, CT's SCT extension), handshakes over a BIO pair calling the old and new callbacks
 * in TLS 1.2 and 1.3 (the messages, the certificate entries, skipping, failing), and server
 * information of both versions, from memory and from PEM files.
 *
 * Only deterministic output is printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
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

/* Prints and clears the error queue: library/reason and any data. */
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

static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBmzCCAUCgAwIBAgIUHfTNPsE5lGD3nT8fR1Nd24C0BsgwCgYIKoZIzj0EAwIw\n"
    "KjEQMA4GA1UECgwHRXhhbXBsZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDAgFw0y\n"
    "NjEwMTgwOTMyNDZaGA8yMTI2MDkyNDA5MzI0NlowKjEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"
    "A0IABLfBhwdOVIbIOwWlwBUmASMV1CS8SOnPi/viY8J5Ml2EwP5wOJe2mtSxgMlo\n"
    "COh/RepmP8BAKwLO40zMoIv99xOjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P\n"
    "AQH/BAQDAgEGMB0GA1UdDgQWBBQ6zTauzjp1rC8vPBSILXAK3pm9PjAKBggqhkjO\n"
    "PQQDAgNJADBGAiEA8n+eFk52ddsEdBxGgskm6aD0for7v4Ys0o0bN2t9wq8CIQDY\n"
    "V8DuzBptykbkta8E/bbLFVRo0LjIzjF/bGH+iqEMeA==\n"
    "-----END CERTIFICATE-----\n";

static const char SERVER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBxDCCAWqgAwIBAgICA+kwCgYIKoZIzj0EAwIwKjEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDAgFw0yNjEwMTgwOTMyNDZaGA8yMTI2\n"
    "MDkyNDA5MzI0NlowGTEXMBUGA1UEAwwOc2VydmVyLmV4YW1wbGUwWTATBgcqhkjO\n"
    "PQIBBggqhkjOPQMBBwNCAARQwBruuNdz4xCD1gvolSn84T4lhmxXimDiZyo55Kdd\n"
    "rfRyA09qPpfiXyudWm0VDT2tdis7qXDPv2njo4sH3xHko4GOMIGLMAkGA1UdEwQC\n"
    "MAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBkGA1UdEQQS\n"
    "MBCCDnNlcnZlci5leGFtcGxlMB0GA1UdDgQWBBTJhnvwTSY1MKJTWPQEV8hTOvQj\n"
    "CzAfBgNVHSMEGDAWgBQ6zTauzjp1rC8vPBSILXAK3pm9PjAKBggqhkjOPQQDAgNI\n"
    "ADBFAiA9HtDZKkG58jRwUNQ4CbP61ozryZRRkz7W3RF94vEpSQIhAKwrnOIS/FEg\n"
    "N7iBJyOB+Buj5UbPic6SYxuj11J3f/PG\n"
    "-----END CERTIFICATE-----\n";

static const char SERVER_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvhwC7sEHpNUtRIwR\n"
    "1HpSoTfsfnL+ayakODf8YQkvzpKhRANCAARQwBruuNdz4xCD1gvolSn84T4lhmxX\n"
    "imDiZyo55KddrfRyA09qPpfiXyudWm0VDT2tdis7qXDPv2njo4sH3xHk\n"
    "-----END PRIVATE KEY-----\n";

static X509 *cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static EVP_PKEY *key(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);

    BIO_free(b);
    return k;
}

/* A server context with the server's certificate and key. */
static SSL_CTX *server_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    X509 *x = cert(SERVER_PEM);
    EVP_PKEY *k = key(SERVER_KEY_PEM);

    if (ctx == NULL || x == NULL || k == NULL || SSL_CTX_use_certificate(ctx, x) != 1
        || SSL_CTX_use_PrivateKey(ctx, k) != 1) {
        printf("Bail out! server context\n");
        exit(1);
    }
    X509_free(x);
    EVP_PKEY_free(k);
    return ctx;
}

/* A client context that trusts the test root and checks the server's certificate. */
static SSL_CTX *client_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    X509 *ca = cert(CA_PEM);

    if (ctx == NULL || ca == NULL || X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ca) != 1) {
        printf("Bail out! client context\n");
        exit(1);
    }
    X509_free(ca);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;
}

/* Runs a client and a server from the contexts over a BIO pair: 0 when both finish. */
static int handshake(SSL_CTX *cctx, SSL_CTX *sctx, int version)
{
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    BIO *a = NULL, *b = NULL;
    int cdone = 0, sdone = 0, round, ret = -1;

    BIO_new_bio_pair(&a, 0, &b, 0);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    SSL_set_max_proto_version(c, version);
    for (round = 0; round < 64 && (!cdone || !sdone); round++) {
        int i;

        for (i = 0; i < 2; i++) {
            SSL *x = i == 0 ? c : s;
            int *done = i == 0 ? &cdone : &sdone, r, e;

            if (*done)
                continue;
            r = SSL_do_handshake(x);
            if (r == 1) {
                *done = 1;
                continue;
            }
            e = SSL_get_error(x, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                printf("  %s stopped: %d\n", i == 0 ? "client" : "server", e);
                goto end;
            }
        }
    }
    ret = cdone && sdone ? 0 : -1;
end:
    SSL_free(c);
    SSL_free(s);
    return ret;
}

/* What the callbacks do. */
static int add_result = 1;
static int parse_result = 1;
static int add_alert = SSL_AD_ILLEGAL_PARAMETER;

static int old_add(SSL *s, unsigned int type, const unsigned char **out, size_t *outlen,
                   int *al, void *arg)
{
    static const unsigned char data[] = "old";

    printf("  old add %u (%s, arg %s)\n", type, SSL_is_server(s) ? "server" : "client",
           (const char *)arg);
    if (add_result <= 0) {
        *al = add_alert;
        return add_result;
    }
    *out = data;
    *outlen = 3;
    return 1;
}

static void old_free(SSL *s, unsigned int type, const unsigned char *out, void *arg)
{
    (void)arg;
    printf("  old free %u (%s, %s)\n", type, SSL_is_server(s) ? "server" : "client",
           out != NULL ? "data" : "NULL");
}

static int old_parse(SSL *s, unsigned int type, const unsigned char *in, size_t inlen, int *al,
                     void *arg)
{
    printf("  old parse %u (%s): \"%.*s\" (arg %s)\n", type,
           SSL_is_server(s) ? "server" : "client", (int)inlen, in, (const char *)arg);
    if (parse_result <= 0)
        *al = SSL_AD_DECODE_ERROR;
    return parse_result;
}

static const char *ctx_name(unsigned int context)
{
    if (context & SSL_EXT_CLIENT_HELLO)
        return "ClientHello";
    if (context & SSL_EXT_TLS1_2_SERVER_HELLO)
        return "ServerHello(1.2)";
    if (context & SSL_EXT_TLS1_3_SERVER_HELLO)
        return "ServerHello";
    if (context & SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS)
        return "EncryptedExtensions";
    if (context & SSL_EXT_TLS1_3_CERTIFICATE)
        return "Certificate";
    if (context & SSL_EXT_TLS1_3_CERTIFICATE_REQUEST)
        return "CertificateRequest";
    if (context & SSL_EXT_TLS1_3_NEW_SESSION_TICKET)
        return "NewSessionTicket";
    return "?";
}

static int new_add(SSL *s, unsigned int type, unsigned int context, const unsigned char **out,
                   size_t *outlen, X509 *x, size_t chainidx, int *al, void *arg)
{
    static const unsigned char data[] = "new";

    printf("  new add %u in %s (%s, x %s, chainidx %zu, arg %s)\n", type, ctx_name(context),
           SSL_is_server(s) ? "server" : "client", x != NULL ? "set" : "NULL", chainidx,
           (const char *)arg);
    if (x != NULL) {
        char cn[64] = "";

        X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, cn, sizeof(cn));
        printf("    certificate %s\n", cn);
    }
    if (add_result <= 0) {
        *al = add_alert;
        return add_result;
    }
    *out = data;
    *outlen = 3;
    return 1;
}

static void new_free(SSL *s, unsigned int type, unsigned int context,
                     const unsigned char *out, void *arg)
{
    (void)arg;
    printf("  new free %u in %s (%s, %s)\n", type, ctx_name(context),
           SSL_is_server(s) ? "server" : "client", out != NULL ? "data" : "NULL");
}

static int new_parse(SSL *s, unsigned int type, unsigned int context, const unsigned char *in,
                     size_t inlen, X509 *x, size_t chainidx, int *al, void *arg)
{
    printf("  new parse %u in %s (%s): \"%.*s\" (x %s, chainidx %zu, arg %s)\n", type,
           ctx_name(context), SSL_is_server(s) ? "server" : "client", (int)inlen, in,
           x != NULL ? "set" : "NULL", chainidx, (const char *)arg);
    if (parse_result <= 0)
        *al = SSL_AD_DECODE_ERROR;
    return parse_result;
}

static void test_registration(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    unsigned int types[] = { 0, 1, 5, 10, 11, 13, 14, 15, 16, 18, 21, 22, 23, 35, 41, 42, 43, 44,
                             45, 47, 49, 51, 13172, 65281, 1000, 0xfffe };
    size_t i;

    printf("# registration\n");
    printf("  supported:");
    for (i = 0; i < sizeof(types) / sizeof(types[0]); i++)
        printf(" %u=%d", types[i], SSL_extension_supported(types[i]));
    printf("\n");
    printf("  a built-in type: %d\n",
           SSL_CTX_add_custom_ext(ctx, 0, SSL_EXT_CLIENT_HELLO, new_add, NULL, NULL, NULL, NULL));
    printf("  over 16 bits: %d\n", SSL_CTX_add_custom_ext(ctx, 0x10000, SSL_EXT_CLIENT_HELLO,
                                                           new_add, NULL, NULL, NULL, NULL));
    printf("  free without add: %d\n",
           SSL_CTX_add_custom_ext(ctx, 1000, SSL_EXT_CLIENT_HELLO, NULL, new_free, NULL, NULL,
                                  NULL));
    printf("  new: %d, again: %d\n",
           SSL_CTX_add_custom_ext(ctx, 1000, SSL_EXT_CLIENT_HELLO, new_add, NULL, NULL, NULL, NULL),
           SSL_CTX_add_custom_ext(ctx, 1000, SSL_EXT_CLIENT_HELLO, new_add, NULL, NULL, NULL, NULL));
    printf("  old client for it: %d, old server: %d\n",
           SSL_CTX_add_client_custom_ext(ctx, 1000, old_add, NULL, NULL, NULL, NULL),
           SSL_CTX_add_server_custom_ext(ctx, 1000, old_add, NULL, NULL, NULL, NULL));
    printf("  old client 1001: %d, old server 1001: %d, client again: %d\n",
           SSL_CTX_add_client_custom_ext(ctx, 1001, old_add, NULL, NULL, NULL, NULL),
           SSL_CTX_add_server_custom_ext(ctx, 1001, old_add, NULL, NULL, NULL, NULL),
           SSL_CTX_add_client_custom_ext(ctx, 1001, NULL, NULL, NULL, NULL, NULL));
    printf("  old server 1002: %d\n",
           SSL_CTX_add_server_custom_ext(ctx, 1002, NULL, NULL, NULL, NULL, NULL));
    printf("  has client: 1000 %d, 1001 %d, 1002 %d, 1003 %d\n",
           SSL_CTX_has_client_custom_ext(ctx, 1000), SSL_CTX_has_client_custom_ext(ctx, 1001),
           SSL_CTX_has_client_custom_ext(ctx, 1002), SSL_CTX_has_client_custom_ext(ctx, 1003));
    errors();
    SSL_CTX_free(ctx);

    printf("# the SCT extension and CT\n");
    ctx = SSL_CTX_new(TLS_method());
    printf("  enable CT: %d\n", SSL_CTX_enable_ct(ctx, SSL_CT_VALIDATION_PERMISSIVE));
    printf("  client SCT extension: %d, in a ServerHello only: %d\n",
           SSL_CTX_add_custom_ext(ctx, 18, SSL_EXT_CLIENT_HELLO, new_add, NULL, NULL, NULL, NULL),
           SSL_CTX_add_custom_ext(ctx, 18, SSL_EXT_TLS1_2_SERVER_HELLO, new_add, NULL, NULL,
                                  NULL, NULL));
    errors();
    SSL_CTX_free(ctx);
    ctx = SSL_CTX_new(TLS_method());
    printf("  old client SCT extension: %d\n",
           SSL_CTX_add_client_custom_ext(ctx, 18, old_add, NULL, NULL, NULL, NULL));
    printf("  then enable CT: %d\n", SSL_CTX_enable_ct(ctx, SSL_CT_VALIDATION_PERMISSIVE));
    errors();
    {
        SSL *s = SSL_new(ctx);

        printf("  on a connection: %d\n", SSL_enable_ct(s, SSL_CT_VALIDATION_PERMISSIVE));
        errors();
        SSL_free(s);
    }
    SSL_CTX_free(ctx);
}

static void test_old_tls12(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();

    printf("# the old callbacks in TLS 1.2\n");
    SSL_CTX_add_client_custom_ext(cctx, 1000, old_add, old_free, "c-add", old_parse, "c-parse");
    SSL_CTX_add_server_custom_ext(sctx, 1000, old_add, old_free, "s-add", old_parse, "s-parse");
    /* Only the client has this one: the server ignores it. */
    SSL_CTX_add_client_custom_ext(cctx, 1001, NULL, NULL, NULL, NULL, NULL);
    check(handshake(cctx, sctx, TLS1_2_VERSION) == 0, "the handshake");
    printf("# not in TLS 1.3\n");
    check(handshake(cctx, sctx, TLS1_3_VERSION) == 0, "a TLS 1.3 handshake");
    printf("# the server skips its own\n");
    add_result = 0;
    check(handshake(cctx, sctx, TLS1_2_VERSION) == 0, "the handshake");
    add_result = 1;
    printf("# the client's parse fails\n");
    parse_result = 0;
    printf("  handshake: %d\n", handshake(cctx, sctx, TLS1_2_VERSION));
    errors();
    parse_result = 1;
    printf("# the client's add fails\n");
    add_result = -1;
    printf("  handshake: %d\n", handshake(cctx, sctx, TLS1_2_VERSION));
    errors();
    add_result = 1;
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_new_tls13(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    unsigned int context = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS
                           | SSL_EXT_TLS1_3_CERTIFICATE | SSL_EXT_TLS1_2_SERVER_HELLO;

    printf("# the new callbacks in TLS 1.3\n");
    SSL_CTX_add_custom_ext(cctx, 2000, context, new_add, new_free, "c-add", new_parse, "c-parse");
    SSL_CTX_add_custom_ext(sctx, 2000, context, new_add, new_free, "s-add", new_parse, "s-parse");
    /* A server extension the client never asks for. */
    SSL_CTX_add_custom_ext(sctx, 2001, context, new_add, NULL, "s2", new_parse, "s2");
    check(handshake(cctx, sctx, TLS1_3_VERSION) == 0, "the handshake");
    printf("# and in TLS 1.2\n");
    check(handshake(cctx, sctx, TLS1_2_VERSION) == 0, "the handshake");
    printf("# the server's parse fails\n");
    parse_result = -1;
    printf("  handshake: %d\n", handshake(cctx, sctx, TLS1_3_VERSION));
    errors();
    parse_result = 1;
    printf("# the server's add fails (no alert set)\n");
    add_result = -1;
    add_alert = SSL_AD_HANDSHAKE_FAILURE;
    printf("  handshake: %d\n", handshake(cctx, sctx, TLS1_3_VERSION));
    errors();
    add_result = 1;
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_unsolicited(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();

    printf("# a client extension without callbacks in TLS 1.3\n");
    SSL_CTX_add_custom_ext(cctx, 3000, SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                           NULL, NULL, NULL, NULL, NULL);
    SSL_CTX_add_custom_ext(sctx, 3000, SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                           new_add, NULL, "s", new_parse, "s");
    check(handshake(cctx, sctx, TLS1_3_VERSION) == 0, "the handshake");
    errors();
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

/* Writes a PEM file of one block. */
static void pem_file(const char *path, const char *name, const unsigned char *data, long len)
{
    FILE *fp = fopen(path, "w");

    if (fp == NULL) {
        printf("Bail out! %s\n", path);
        exit(1);
    }
    PEM_write(fp, name, "", data, len);
    fclose(fp);
}

static void test_serverinfo(void)
{
    static const unsigned char v1[] = { 0x03, 0xe8, 0x00, 0x03, 'a', 'b', 'c',
                                        0x03, 0xe9, 0x00, 0x00 };
    static const unsigned char v2[] = { 0x00, 0x00, 0x04, 0x80, 0x07, 0xd0, 0x00, 0x02, 'v', '2' };
    static const unsigned char bad[] = { 0x03, 0xe8, 0x00, 0x09, 'a' };
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx(), *empty = SSL_CTX_new(TLS_server_method());
    char path[128];

    printf("# server information\n");
    printf("  NULL: %d, empty: %d, bad: %d, bad version: %d\n",
           SSL_CTX_use_serverinfo(sctx, NULL, 0), SSL_CTX_use_serverinfo(sctx, v1, 0),
           SSL_CTX_use_serverinfo(sctx, bad, sizeof(bad)),
           SSL_CTX_use_serverinfo_ex(sctx, 3, v2, sizeof(v2)));
    errors();
    printf("  no certificate yet: %d\n", SSL_CTX_use_serverinfo(empty, v1, sizeof(v1)));
    errors();
    printf("  version 1: %d\n", SSL_CTX_use_serverinfo(sctx, v1, sizeof(v1)));
    printf("  version 2: %d\n", SSL_CTX_use_serverinfo_ex(sctx, SSL_SERVERINFOV2, v2, sizeof(v2)));
    printf("  again: %d\n", SSL_CTX_use_serverinfo(sctx, v1, sizeof(v1)));
    errors();
    SSL_CTX_add_client_custom_ext(cctx, 1000, NULL, NULL, NULL, old_parse, "c");
    SSL_CTX_add_client_custom_ext(cctx, 1001, NULL, NULL, NULL, old_parse, "c");
    SSL_CTX_add_custom_ext(cctx, 2000, SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                           NULL, NULL, NULL, new_parse, "c");
    printf("# TLS 1.2\n");
    check(handshake(cctx, sctx, TLS1_2_VERSION) == 0, "the handshake");
    printf("# TLS 1.3\n");
    check(handshake(cctx, sctx, TLS1_3_VERSION) == 0, "the handshake");
    SSL_CTX_free(sctx);

    printf("# server information files\n");
    sctx = server_ctx();
    snprintf(path, sizeof(path), "/tmp/rustyssl-serverinfo-%ld.pem", (long)getpid());
    printf("  NULL: %d\n", SSL_CTX_use_serverinfo_file(sctx, NULL));
    errors();
    printf("  missing: %d\n", SSL_CTX_use_serverinfo_file(sctx, "/nonexistent/rustyssl.pem"));
    errors();
    pem_file(path, "CERTIFICATE", v1, 7);
    printf("  bad prefix: %d\n", SSL_CTX_use_serverinfo_file(sctx, path));
    errors();
    pem_file(path, "SERVERINFO", v1, 7);
    printf("  too short: %d\n", SSL_CTX_use_serverinfo_file(sctx, path));
    errors();
    pem_file(path, "SERVERINFO FOR test", bad, sizeof(bad));
    printf("  bad length: %d\n", SSL_CTX_use_serverinfo_file(sctx, path));
    errors();
    {
        FILE *fp = fopen(path, "w");

        fclose(fp);
    }
    printf("  empty: %d\n", SSL_CTX_use_serverinfo_file(sctx, path));
    errors();
    {
        FILE *fp = fopen(path, "w");

        PEM_write(fp, "SERVERINFO FOR one", "", v1, 7);
        PEM_write(fp, "SERVERINFOV2 FOR two", "", v2, sizeof(v2));
        fclose(fp);
    }
    printf("  two blocks: %d\n", SSL_CTX_use_serverinfo_file(sctx, path));
    errors();
    check(handshake(cctx, sctx, TLS1_3_VERSION) == 0, "a TLS 1.3 handshake");
    check(handshake(cctx, sctx, TLS1_2_VERSION) == 0, "a TLS 1.2 handshake");
    remove(path);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    SSL_CTX_free(empty);
}

int main(void)
{
    test_registration();
    test_old_tls12();
    test_new_tls13();
    test_unsolicited();
    test_serverinfo();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
