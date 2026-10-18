/*
 * Conformance test for DTLS (DTLS_client_method(3), DTLSv1_listen(3), DTLS_set_timer_cb(3),
 * DTLS_get_data_mtu(3), SSL_set_mtu(3)): DTLS 1.2 and 1.0 handshakes and application data over
 * a datagram BIO pair, the MTU controls and the data MTU, the retransmission timer (its
 * callback, DTLSv1_get_timeout, DTLSv1_handle_timeout after a lost datagram), and
 * DTLSv1_listen's cookie exchange.
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

/* A self-signed P-256 certificate for a new key. */
static X509 *ec_cert(EVP_PKEY **pk)
{
    X509 *x = X509_new();
    X509_NAME *n = X509_NAME_new();

    *pk = EVP_EC_gen("P-256");
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"dtls", -1, -1, 0);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 7);
    X509_set_version(x, X509_VERSION_3);
    X509_set_subject_name(x, n);
    X509_set_issuer_name(x, n);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, *pk);
    X509_sign(x, *pk, EVP_sha256());
    X509_NAME_free(n);
    return x;
}

static X509 *cert;
static EVP_PKEY *key;

static SSL_CTX *server_ctx(int version)
{
    SSL_CTX *s = SSL_CTX_new(DTLS_server_method());

    SSL_CTX_use_certificate(s, cert);
    SSL_CTX_use_PrivateKey(s, key);
    if (version != 0) {
        SSL_CTX_set_min_proto_version(s, version);
        SSL_CTX_set_max_proto_version(s, version);
    }
    return s;
}

static SSL_CTX *client_ctx(int version)
{
    SSL_CTX *c = SSL_CTX_new(DTLS_client_method());

    if (version != 0) {
        SSL_CTX_set_min_proto_version(c, version);
        SSL_CTX_set_max_proto_version(c, version);
    }
    return c;
}

struct link {
    SSL *c, *s;
    BIO *cb, *sb; /* each end's half of the datagram pair */
};

static void link_up(struct link *l, SSL_CTX *cctx, SSL_CTX *sctx)
{
    l->c = SSL_new(cctx);
    l->s = SSL_new(sctx);
    BIO_new_bio_dgram_pair(&l->cb, 0, &l->sb, 0);
    SSL_set_bio(l->c, l->cb, l->cb);
    SSL_set_bio(l->s, l->sb, l->sb);
    SSL_set_connect_state(l->c);
    SSL_set_accept_state(l->s);
}

static void link_down(struct link *l)
{
    SSL_free(l->c);
    SSL_free(l->s);
}

/* Steps both ends until both finished their handshakes; 1 on success. */
static int pump(struct link *l)
{
    int i, cdone = 0, sdone = 0;

    for (i = 0; i < 40 && !(cdone && sdone); i++) {
        int r;

        if (!cdone) {
            r = SSL_do_handshake(l->c);
            if (r == 1)
                cdone = 1;
            else if (SSL_get_error(l->c, r) != SSL_ERROR_WANT_READ)
                return 0;
        }
        if (!sdone) {
            r = SSL_do_handshake(l->s);
            if (r == 1)
                sdone = 1;
            else if (SSL_get_error(l->s, r) != SSL_ERROR_WANT_READ)
                return 0;
        }
    }
    return cdone && sdone;
}

/* A message from the client to the server; 1 if it arrived intact. */
static int talk(struct link *l)
{
    char buf[64];
    int n;

    if (SSL_write(l->c, "datagram", 8) != 8)
        return 0;
    n = SSL_read(l->s, buf, sizeof(buf));
    return n == 8 && memcmp(buf, "datagram", 8) == 0;
}

static void test_handshakes(void)
{
    SSL_CTX *c, *s;
    struct link l;

    printf("# DTLS 1.2\n");
    c = client_ctx(0);
    s = server_ctx(0);
    link_up(&l, c, s);
    check(SSL_is_dtls(l.c) == 1 && SSL_is_dtls(l.s) == 1, "both ends are DTLS");
    check(pump(&l), "handshake");
    printf("  version %s %s, cipher %s\n", SSL_get_version(l.c), SSL_get_version(l.s),
           SSL_CIPHER_get_name(SSL_get_current_cipher(l.c)));
    check(talk(&l), "application data");
    link_down(&l);
    SSL_CTX_free(c);
    SSL_CTX_free(s);

    printf("# DTLS 1.0\n");
    c = client_ctx(DTLS1_VERSION);
    s = server_ctx(DTLS1_VERSION);
    SSL_CTX_set_cipher_list(c, "ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0");
    SSL_CTX_set_cipher_list(s, "ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0");
    link_up(&l, c, s);
    check(pump(&l), "handshake");
    printf("  version %s, cipher %s\n", SSL_get_version(l.c),
           SSL_CIPHER_get_name(SSL_get_current_cipher(l.c)));
    check(talk(&l), "application data");
    link_down(&l);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
}

static void test_mtu(void)
{
    SSL_CTX *c = client_ctx(DTLS1_2_VERSION), *s = server_ctx(DTLS1_2_VERSION);
    const char *suites[] = { "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES128-SHA256",
                             "ECDHE-ECDSA-CHACHA20-POLY1305" };
    size_t i;

    printf("# MTU\n");
    for (i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) {
        struct link l;

        SSL_CTX_set_cipher_list(c, suites[i]);
        link_up(&l, c, s);
        printf("  before a handshake: data mtu %zu\n", DTLS_get_data_mtu(l.c));
        SSL_set_options(l.c, SSL_OP_NO_QUERY_MTU);
        printf("  set_mtu 100: %ld, 1000: %ld\n", (long)SSL_set_mtu(l.c, 100),
               (long)SSL_set_mtu(l.c, 1000));
        printf("  set_link_mtu 100: %ld, 1500: %ld, link min %ld\n",
               (long)DTLS_set_link_mtu(l.c, 100), (long)DTLS_set_link_mtu(l.c, 1500),
               (long)DTLS_get_link_min_mtu(l.c));
        SSL_set_mtu(l.c, 1000);
        check(pump(&l), suites[i]);
        printf("  %s: data mtu %zu\n", suites[i], DTLS_get_data_mtu(l.c));
        link_down(&l);
    }
    SSL_CTX_free(c);
    SSL_CTX_free(s);
}

static int timer_calls = 0;

/* The timer: 1 ms at first (due at once), then 10 seconds. */
static unsigned int timer_cb(SSL *s, unsigned int last)
{
    (void)s;
    timer_calls++;
    return last == 0 ? 1000 : 10000000;
}

static void test_timer(void)
{
    SSL_CTX *c = client_ctx(0), *s = server_ctx(0);
    struct link l;
    struct timeval tv;
    char drop[2048];
    int r;

    printf("# timer\n");
    link_up(&l, c, s);
    printf("  get_timeout before: %ld\n", DTLSv1_get_timeout(l.c, &tv));
    DTLS_set_timer_cb(l.c, timer_cb);
    r = SSL_do_handshake(l.c);
    printf("  connect %d error %d\n", r, SSL_get_error(l.c, r));
    check(timer_calls > 0, "the timer callback ran when the ClientHello went out");
    printf("  get_timeout running: %ld, due %d\n", DTLSv1_get_timeout(l.c, &tv),
           tv.tv_sec == 0 && tv.tv_usec == 0);
    /* The ClientHello is lost. */
    r = BIO_read(l.sb, drop, sizeof(drop));
    check(r > 0, "the ClientHello is dropped");
    printf("  handle_timeout: %ld\n", DTLSv1_handle_timeout(l.c));
    check(pump(&l), "the handshake completes after the retransmission");
    check(talk(&l), "application data");
    link_down(&l);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
}

static int gen_cookie(SSL *s, unsigned char *cookie, unsigned int *len)
{
    (void)s;
    memcpy(cookie, "cookie-123", 10);
    *len = 10;
    return 1;
}

static int verify_cookie(SSL *s, const unsigned char *cookie, unsigned int len)
{
    (void)s;
    return len == 10 && memcmp(cookie, "cookie-123", 10) == 0;
}

static void test_listen(void)
{
    SSL_CTX *c = client_ctx(0), *s = server_ctx(0);
    struct link l;
    BIO_ADDR *peer = BIO_ADDR_new();
    int r;

    printf("# listen\n");
    SSL_CTX_set_cookie_generate_cb(s, gen_cookie);
    SSL_CTX_set_cookie_verify_cb(s, verify_cookie);
    link_up(&l, c, s);
    printf("  listen with nothing: %d\n", DTLSv1_listen(l.s, peer));
    r = SSL_do_handshake(l.c);
    printf("  client hello: %d error %d\n", r, SSL_get_error(l.c, r));
    printf("  listen answers with a HelloVerifyRequest: %d\n", DTLSv1_listen(l.s, peer));
    r = SSL_do_handshake(l.c);
    printf("  client hello with the cookie: %d error %d\n", r, SSL_get_error(l.c, r));
    printf("  listen accepts it: %d\n", DTLSv1_listen(l.s, peer));
    check(pump(&l), "handshake after listen");
    check(talk(&l), "application data");
    link_down(&l);
    BIO_ADDR_free(peer);
    SSL_CTX_free(c);
    SSL_CTX_free(s);

    printf("# listen on TLS\n");
    {
        SSL_CTX *t = SSL_CTX_new(TLS_server_method());
        SSL *x = SSL_new(t);
        BIO *m = BIO_new(BIO_s_mem());

        SSL_set_bio(x, m, m);
        printf("  listen: %d\n", DTLSv1_listen(x, NULL));
        printf("  error %d\n", ERR_GET_REASON(ERR_get_error()));
        ERR_clear_error();
        SSL_free(x);
        SSL_CTX_free(t);
    }
}

int main(void)
{
    cert = ec_cert(&key);
    test_handshakes();
    test_mtu();
    test_timer();
    test_listen();
    X509_free(cert);
    EVP_PKEY_free(key);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
