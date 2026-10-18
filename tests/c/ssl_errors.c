/*
 * Conformance test for TLS failures' error queues (ERR_error_string_n(3), SSL_get_error(3)):
 * handshakes that fail in many ways (no shared version, cipher, or group; verification
 * failures; missing client certificates; corrupted, truncated, oversized, and injected
 * records; HTTP requests; alerts from callbacks; refused renegotiation; unexpected EOF) and
 * configuration errors (cipher lists, mismatched keys, SSL_CONF), each printing every queued
 * error with ERR_error_string_n (library, function, reason) and its data, at the call that
 * raised it, with the function ERR_print_errors names (ERR_get_error_all's `func`).
 *
 * The client and server talk through memory BIOs and a relay that can corrupt, truncate,
 * replace, or inject traffic. Only deterministic output is printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Prints and clears the error queue, one ERR_error_string_n line per entry, with its data. */
static void errors(const char *who)
{
    unsigned long e;
    const char *data, *func;
    int flags;
    char buf[256];

    while ((e = ERR_get_error_all(NULL, NULL, &func, &data, &flags)) != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
        printf("  %s: %s (%s)", who, buf, func != NULL ? func : "");
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0')
            printf(" [%s]", data);
        printf("\n");
    }
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

static SSL_CTX *client_ctx(int trust)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    X509 *ca = cert(CA_PEM);

    if (ctx == NULL || ca == NULL) {
        printf("Bail out! client context\n");
        exit(1);
    }
    if (trust)
        X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ca);
    X509_free(ca);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;
}

/*
 * The relay: what each side wrote goes to the other, through `mangle` when set. `dir` is 0 for
 * client to server, 1 for server to client; `n` counts the chunks relayed in that direction.
 */
typedef void (*mangle_fn)(int dir, int n, unsigned char *buf, int *len);

struct link {
    SSL *c, *s;
    BIO *c_in, *c_out, *s_in, *s_out;
    int count[2];
    mangle_fn mangle;
};

static BIO *mem(void)
{
    BIO *b = BIO_new(BIO_s_mem());

    BIO_set_mem_eof_return(b, -1);
    return b;
}

static void link_up(struct link *l, SSL_CTX *cctx, SSL_CTX *sctx, mangle_fn m)
{
    memset(l, 0, sizeof(*l));
    l->c = SSL_new(cctx);
    l->s = SSL_new(sctx);
    l->c_in = mem();
    l->c_out = mem();
    l->s_in = mem();
    l->s_out = mem();
    SSL_set_bio(l->c, l->c_in, l->c_out);
    SSL_set_bio(l->s, l->s_in, l->s_out);
    SSL_set_connect_state(l->c);
    SSL_set_accept_state(l->s);
    l->mangle = m;
}

/* Moves what one side wrote to the other; returns whether anything moved. */
static int relay(struct link *l, int dir)
{
    BIO *from = dir == 0 ? l->c_out : l->s_out, *to = dir == 0 ? l->s_in : l->c_in;
    unsigned char buf[65536];
    int len = BIO_read(from, buf, sizeof(buf));

    if (len <= 0)
        return 0;
    if (l->mangle != NULL)
        l->mangle(dir, l->count[dir], buf, &len);
    l->count[dir]++;
    if (len > 0)
        BIO_write(to, buf, len);
    return 1;
}

/* One end's handshake step: 1 done, 0 waiting, -1 stopped (printing what it said). */
static int step(SSL *x, const char *who, int *done)
{
    int r, e;

    if (*done)
        return 1;
    r = SSL_do_handshake(x);
    if (r == 1) {
        *done = 1;
        errors(who);
        return 1;
    }
    e = SSL_get_error(x, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
        errors(who);
        return 0;
    }
    printf("  %s: SSL_do_handshake %d, SSL_get_error %d\n", who, r, e);
    errors(who);
    return -1;
}

/* Runs both handshakes through the relay until both finish or one stops; prints the outcome. */
static int handshake(struct link *l)
{
    int cdone = 0, sdone = 0, cstop = 0, sstop = 0, round;

    for (round = 0; round < 64; round++) {
        int moved;

        if (!cstop && step(l->c, "client", &cdone) < 0)
            cstop = 1;
        moved = relay(l, 0);
        if (!sstop && step(l->s, "server", &sdone) < 0)
            sstop = 1;
        moved |= relay(l, 1);
        if ((cdone || cstop) && (sdone || sstop) && !moved)
            break;
        if (!moved && (cstop || sstop))
            break;
    }
    printf("  outcome: client %s, server %s\n", cdone ? "done" : cstop ? "failed" : "waiting",
           sdone ? "done" : sstop ? "failed" : "waiting");
    return cdone && sdone;
}

static void link_down(struct link *l)
{
    SSL_free(l->c);
    SSL_free(l->s);
}

/* Runs a failing handshake between the two contexts (which it frees). */
static void scenario(const char *name, SSL_CTX *cctx, SSL_CTX *sctx, mangle_fn m)
{
    struct link l;

    printf("# %s\n", name);
    link_up(&l, cctx, sctx, m);
    check(!handshake(&l), name);
    link_down(&l);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

/* Mangling functions. */

static void flip_second_server_chunk(int dir, int n, unsigned char *buf, int *len)
{
    /* The server's first flight; flip the last octet (inside its last protected record). */
    if (dir == 1 && n == 0 && *len > 0)
        buf[*len - 1] ^= 0x01;
}

static void flip_client_finished(int dir, int n, unsigned char *buf, int *len)
{
    /* The client's second flight (TLS 1.2: CKE, CCS, Finished): flip the last octet. */
    if (dir == 0 && n == 1 && *len > 0)
        buf[*len - 1] ^= 0x80;
}

static void truncate_client_hello(int dir, int n, unsigned char *buf, int *len)
{
    /* Shorten the ClientHello's handshake length by one, keeping the record intact. */
    (void)len;
    if (dir == 0 && n == 0)
        buf[8] = (unsigned char)(buf[8] - 1);
}

static void bad_record_type(int dir, int n, unsigned char *buf, int *len)
{
    (void)len;
    if (dir == 0 && n == 0)
        buf[0] = 0x63;
}

static void wrong_version(int dir, int n, unsigned char *buf, int *len)
{
    (void)len;
    if (dir == 0 && n == 0) {
        buf[1] = 0x05;
        buf[2] = 0x00;
    }
}

static void oversized(int dir, int n, unsigned char *buf, int *len)
{
    if (dir == 0 && n == 0) {
        memset(buf + 5, 0, (size_t)*len - 5);
        buf[3] = 0x48;
        buf[4] = 0x01;
        *len = 5 + 32;
    }
}

static void http_request(int dir, int n, unsigned char *buf, int *len)
{
    if (dir == 0 && n == 0) {
        memcpy(buf, "GET / HTTP/1.0\r\n\r\n", 18);
        *len = 18;
    }
}

static void unexpected_hello_done(int dir, int n, unsigned char *buf, int *len)
{
    /* The server's flight replaced by a plaintext ServerHelloDone. */
    static const unsigned char done[] = { 0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00 };

    if (dir == 1 && n == 0) {
        memcpy(buf, done, sizeof(done));
        *len = (int)sizeof(done);
    }
}

static void cut_server_flight(int dir, int n, unsigned char *buf, int *len)
{
    /* The server's ServerHello record cut short: its body ends early (a record shorter than
     * its handshake header says). */
    (void)buf;
    if (dir == 1 && n == 0 && *len > 60) {
        buf[3] = 0x00;
        buf[4] = 0x30;
        *len = 5 + 0x30;
    }
}

/* Callbacks. */

static int sni_fatal(SSL *s, int *al, void *arg)
{
    (void)s;
    (void)arg;
    *al = SSL_AD_UNRECOGNIZED_NAME;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static int alpn_fatal(SSL *s, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                      unsigned int inlen, void *arg)
{
    (void)s;
    (void)out;
    (void)outlen;
    (void)in;
    (void)inlen;
    (void)arg;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/* Accepts with an empty selection, which the server can't use. */
static int alpn_empty(SSL *s, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                      unsigned int inlen, void *arg)
{
    (void)s;
    (void)out;
    (void)in;
    (void)inlen;
    (void)arg;
    *outlen = 0;
    return SSL_TLSEXT_ERR_OK;
}

static int cert_cb_fail(SSL *s, void *arg)
{
    (void)s;
    (void)arg;
    return 0;
}

static void test_handshakes(void)
{
    SSL_CTX *c, *s;

    c = client_ctx(1);
    s = server_ctx();
    SSL_CTX_set_max_proto_version(c, TLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(s, TLS1_3_VERSION);
    scenario("no shared version (client 1.2, server 1.3)", c, s, NULL);

    c = client_ctx(1);
    s = server_ctx();
    SSL_CTX_set_min_proto_version(c, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(s, TLS1_2_VERSION);
    scenario("no shared version (client 1.3, server 1.2)", c, s, NULL);

    c = client_ctx(1);
    s = server_ctx();
    SSL_CTX_set_max_proto_version(c, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(c, "AES128-GCM-SHA256");
    scenario("no shared cipher (TLS 1.2, RSA key exchange vs an EC key)", c, s, NULL);

    c = client_ctx(1);
    s = server_ctx();
    SSL_CTX_set_ciphersuites(c, "TLS_AES_128_GCM_SHA256");
    SSL_CTX_set_ciphersuites(s, "TLS_CHACHA20_POLY1305_SHA256");
    scenario("no shared TLS 1.3 ciphersuite", c, s, NULL);

    c = client_ctx(1);
    s = server_ctx();
    SSL_CTX_set1_groups_list(c, "P-384");
    SSL_CTX_set1_groups_list(s, "X25519");
    scenario("no shared group", c, s, NULL);

    c = client_ctx(0);
    s = server_ctx();
    scenario("unknown CA (TLS 1.3)", c, s, NULL);

    c = client_ctx(0);
    s = server_ctx();
    SSL_CTX_set_max_proto_version(c, TLS1_2_VERSION);
    scenario("unknown CA (TLS 1.2)", c, s, NULL);

    c = client_ctx(1);
    s = server_ctx();
    {
        X509_VERIFY_PARAM *vpm = SSL_CTX_get0_param(c);

        X509_VERIFY_PARAM_set1_host(vpm, "other.example", 0);
    }
    scenario("hostname mismatch", c, s, NULL);

    c = client_ctx(1);
    s = server_ctx();
    SSL_CTX_set_verify(s, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    scenario("client certificate required (TLS 1.3)", c, s, NULL);

    c = client_ctx(1);
    s = server_ctx();
    SSL_CTX_set_max_proto_version(c, TLS1_2_VERSION);
    SSL_CTX_set_verify(s, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    scenario("client certificate required (TLS 1.2)", c, s, NULL);

    c = client_ctx(1);
    s = server_ctx();
    scenario("a corrupted protected record (TLS 1.3)", c, s, flip_second_server_chunk);

    c = client_ctx(1);
    s = server_ctx();
    SSL_CTX_set_max_proto_version(c, TLS1_2_VERSION);
    scenario("a corrupted Finished record (TLS 1.2)", c, s, flip_client_finished);

    c = client_ctx(1);
    s = server_ctx();
    scenario("a truncated ClientHello", c, s, truncate_client_hello);

    c = client_ctx(1);
    s = server_ctx();
    scenario("an unknown record type", c, s, bad_record_type);

    c = client_ctx(1);
    s = server_ctx();
    scenario("a wrong record version", c, s, wrong_version);

    c = client_ctx(1);
    s = server_ctx();
    scenario("an oversized record", c, s, oversized);

    c = client_ctx(1);
    s = server_ctx();
    scenario("an HTTP request", c, s, http_request);

    c = client_ctx(1);
    s = server_ctx();
    scenario("an unexpected ServerHelloDone", c, s, unexpected_hello_done);

    c = client_ctx(1);
    s = server_ctx();
    scenario("a ServerHello cut short", c, s, cut_server_flight);

    c = client_ctx(1);
    s = server_ctx();
    SSL_CTX_set_tlsext_servername_callback(s, sni_fatal);
    scenario("the servername callback fails", c, s, NULL);

    c = client_ctx(1);
    s = server_ctx();
    SSL_CTX_set_alpn_protos(c, (const unsigned char *)"\x02h2", 3);
    SSL_CTX_set_alpn_select_cb(s, alpn_fatal, NULL);
    scenario("the ALPN callback fails", c, s, NULL);

    c = client_ctx(1);
    s = server_ctx();
    SSL_CTX_set_alpn_protos(c, (const unsigned char *)"\x02h2", 3);
    SSL_CTX_set_alpn_select_cb(s, alpn_empty, NULL);
    scenario("the ALPN callback selects nothing", c, s, NULL);

    c = client_ctx(1);
    s = server_ctx();
    SSL_CTX_set_cert_cb(s, cert_cb_fail, NULL);
    scenario("the certificate callback fails", c, s, NULL);
}

static void test_renegotiation_refused(void)
{
    SSL_CTX *c = client_ctx(1), *s = server_ctx();
    struct link l;
    unsigned char buf[16];
    int r, i;

    printf("# renegotiation refused\n");
    SSL_CTX_set_max_proto_version(c, TLS1_2_VERSION);
    SSL_CTX_set_options(s, SSL_OP_NO_RENEGOTIATION);
    link_up(&l, c, s, NULL);
    check(handshake(&l), "handshake");
    check(SSL_renegotiate(l.c) == 1, "SSL_renegotiate");
    for (i = 0; i < 6; i++) {
        r = SSL_do_handshake(l.c);
        if (r <= 0 && SSL_get_error(l.c, r) != SSL_ERROR_WANT_READ) {
            printf("  client: SSL_do_handshake %d, SSL_get_error %d\n", r, SSL_get_error(l.c, r));
            errors("client");
            break;
        }
        errors("client");
        relay(&l, 0);
        r = SSL_read(l.s, buf, sizeof(buf));
        if (r <= 0 && SSL_get_error(l.s, r) != SSL_ERROR_WANT_READ) {
            printf("  server: SSL_read %d, SSL_get_error %d\n", r, SSL_get_error(l.s, r));
            errors("server");
            break;
        }
        errors("server");
        relay(&l, 1);
    }
    link_down(&l);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
}

static void test_unexpected_eof(void)
{
    SSL_CTX *c = client_ctx(1), *s = server_ctx();
    struct link l;
    unsigned char buf[16];
    int r;

    printf("# unexpected EOF\n");
    link_up(&l, c, s, NULL);
    check(handshake(&l), "handshake");
    BIO_set_mem_eof_return(l.c_in, 0);
    r = SSL_read(l.c, buf, sizeof(buf));
    printf("  client: SSL_read %d, SSL_get_error %d\n", r, SSL_get_error(l.c, r));
    errors("client");
    link_down(&l);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
}

static void test_configuration(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *x;
    X509 *crt = cert(SERVER_PEM);
    EVP_PKEY *other = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    SSL_CONF_CTX *cctx;

    printf("# configuration errors\n");
    check(SSL_CTX_set_cipher_list(ctx, "NOTHING-MATCHES") == 0, "SSL_CTX_set_cipher_list");
    errors("ctx");
    check(SSL_CTX_set_ciphersuites(ctx, "TLS_NOT_A_SUITE") == 0, "SSL_CTX_set_ciphersuites");
    errors("ctx");
    check(SSL_CTX_set1_groups_list(ctx, "nonsense") == 0, "SSL_CTX_set1_groups_list");
    errors("ctx");
    check(SSL_CTX_set1_sigalgs_list(ctx, "RSA+NOTAHASH") == 0, "SSL_CTX_set1_sigalgs_list");
    errors("ctx");
    check(SSL_CTX_set_min_proto_version(ctx, 0x0999) == 0, "SSL_CTX_set_min_proto_version");
    errors("ctx");
    check(SSL_CTX_use_certificate(ctx, crt) == 1, "SSL_CTX_use_certificate");
    check(SSL_CTX_use_PrivateKey(ctx, other) == 0, "a key that isn't the certificate's");
    errors("ctx");
    check(SSL_CTX_check_private_key(ctx) == 0, "SSL_CTX_check_private_key with no key");
    errors("ctx");
    check(SSL_CTX_use_certificate_file(ctx, "/nonexistent/cert.pem", SSL_FILETYPE_PEM) == 0,
          "SSL_CTX_use_certificate_file");
    errors("ctx");
    check(SSL_CTX_use_PrivateKey_file(ctx, "/nonexistent/key.pem", SSL_FILETYPE_PEM) == 0,
          "SSL_CTX_use_PrivateKey_file");
    errors("ctx");
    check(SSL_CTX_load_verify_locations(ctx, "/nonexistent/ca.pem", NULL) == 0,
          "SSL_CTX_load_verify_locations");
    errors("ctx");

    cctx = SSL_CONF_CTX_new();
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_SHOW_ERRORS);
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    printf("  SSL_CONF_cmd unknown: %d\n", SSL_CONF_cmd(cctx, "NoSuchCommand", "x"));
    errors("conf");
    printf("  SSL_CONF_cmd bad value: %d\n", SSL_CONF_cmd(cctx, "MinProtocol", "TLSv9"));
    errors("conf");
    printf("  SSL_CONF_cmd bad options: %d\n", SSL_CONF_cmd(cctx, "Options", "NoSuchOption"));
    errors("conf");
    SSL_CONF_CTX_free(cctx);

    x = SSL_new(ctx);
    check(SSL_do_handshake(x) == -1, "a handshake with no role");
    errors("ssl");
    check(SSL_shutdown(x) == -1, "SSL_shutdown before the handshake");
    errors("ssl");
    SSL_set_connect_state(x);
    check(SSL_write(x, "x", 1) <= 0, "a write with no BIO");
    errors("ssl");

    /* The ctrl commands' errors come from ssl3_ctrl and ssl3_ctx_ctrl. */
    {
        char longname[300];
        unsigned char keys[10] = {0};

        memset(longname, 'a', sizeof(longname) - 1);
        longname[sizeof(longname) - 1] = '\0';
        check(SSL_ctrl(x, SSL_CTRL_SET_TLSEXT_HOSTNAME, 99, (void *)"a") == 0,
              "a host name of an unknown type");
        errors("ssl");
        check(SSL_set_tlsext_host_name(x, longname) == 0, "a host name over 255 octets");
        errors("ssl");
        check(SSL_set_tlsext_host_name(x, "") == 0, "an empty host name");
        errors("ssl");
        check(SSL_ctrl(x, SSL_CTRL_SET_TMP_DH_CB, 0, NULL) == 0, "SSL_CTRL_SET_TMP_DH_CB");
        errors("ssl");
        check(SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_DH_CB, 0, NULL) == 0,
              "SSL_CTX's SSL_CTRL_SET_TMP_DH_CB");
        errors("ctx");
        check(SSL_CTX_set_tlsext_ticket_keys(ctx, keys, sizeof(keys)) == 0,
              "ticket keys of the wrong length");
        errors("ctx");
        check(SSL_CTX_get_tlsext_ticket_keys(ctx, keys, sizeof(keys)) == 0,
              "a ticket-key buffer of the wrong length");
        errors("ctx");
    }
    SSL_free(x);
    SSL_CTX_free(ctx);
    X509_free(crt);
    EVP_PKEY_free(other);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_handshakes();
    test_renegotiation_refused();
    test_unexpected_eof();
    test_configuration();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
