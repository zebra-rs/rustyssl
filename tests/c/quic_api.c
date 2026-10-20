/*
 * Conformance test for the OpenSSL QUIC API (openssl-quic(7), SSL_new_listener(3),
 * SSL_handle_events(3), SSL_new_stream(3), ...): a QUIC client and a listener in one process,
 * over a BIO_s_dgram_pair with an address bound on each end, as upstream's quicapitest does. It
 * prints what both libraries must agree on: which calls succeed, SSL_get_error's states while
 * the handshake runs without blocking, the accepted connection, data on the default stream both
 * ways, stream ids and types, and the error queue's codes. Timing values are printed only as
 * whether they are set.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/quic.h>
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

/* The queue's codes, oldest first (no texts: they carry file names). */
static void errors(const char *who)
{
    unsigned long e;

    printf("  %s errors:", who);
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

/* A self-signed Ed25519 certificate for a new key. */
static X509 *ed_cert(EVP_PKEY **pk)
{
    X509 *x = X509_new();
    X509_NAME *n = X509_NAME_new();

    *pk = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"quic", -1, -1, 0);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 12);
    X509_set_version(x, X509_VERSION_3);
    X509_set_subject_name(x, n);
    X509_set_issuer_name(x, n);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, *pk);
    X509_sign(x, *pk, NULL);
    X509_NAME_free(n);
    return x;
}

static X509 *cert;
static EVP_PKEY *key;
static const unsigned char alpn[] = { 8, 'o', 's', 's', 'l', 't', 'e', 's', 't' };

static int select_alpn(SSL *s, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)s;
    (void)arg;
    if (SSL_select_next_proto((unsigned char **)out, outlen, alpn, sizeof(alpn), in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *server_ctx(void)
{
    SSL_CTX *c = SSL_CTX_new(OSSL_QUIC_server_method());

    SSL_CTX_use_certificate(c, cert);
    SSL_CTX_use_PrivateKey(c, key);
    SSL_CTX_set_alpn_select_cb(c, select_alpn, NULL);
    return c;
}

static SSL_CTX *client_ctx(void)
{
    SSL_CTX *c = SSL_CTX_new(OSSL_QUIC_client_method());

    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);
    return c;
}

static BIO_ADDR *addr(unsigned short port)
{
    BIO_ADDR *a = BIO_ADDR_new();
    struct in_addr ina;

    ina.s_addr = htonl(0x7f000001);
    BIO_ADDR_rawmake(a, AF_INET, &ina, sizeof(ina), htons(port));
    return a;
}

/* Binds `port` to one end of the pair and gives it destination addressing. */
static int bind_end(BIO *b, unsigned short port)
{
    if (!BIO_dgram_set_caps(b, BIO_DGRAM_CAP_HANDLES_DST_ADDR | BIO_DGRAM_CAP_HANDLES_SRC_ADDR))
        return 0;
    return BIO_dgram_set0_local_addr(b, addr(port)) == 1;
}

struct pair {
    SSL_CTX *cctx, *sctx;
    SSL *client, *listener, *server;
};

static const char *err_name(int e)
{
    switch (e) {
    case SSL_ERROR_NONE: return "none";
    case SSL_ERROR_SSL: return "ssl";
    case SSL_ERROR_WANT_READ: return "want-read";
    case SSL_ERROR_WANT_WRITE: return "want-write";
    case SSL_ERROR_SYSCALL: return "syscall";
    case SSL_ERROR_ZERO_RETURN: return "zero-return";
    default: return "other";
    }
}

/* Sets up a listener and a client over a datagram pair; 1 if all the calls succeed. */
static int setup(struct pair *p)
{
    BIO *cb = NULL, *sb = NULL;
    BIO_ADDR *peer;
    int ok;

    memset(p, 0, sizeof(*p));
    p->cctx = client_ctx();
    p->sctx = server_ctx();
    if (!BIO_new_bio_dgram_pair(&cb, 65535, &sb, 65535))
        return 0;
    ok = bind_end(cb, 4433) && bind_end(sb, 8443);
    p->listener = SSL_new_listener(p->sctx, SSL_LISTENER_FLAG_NO_VALIDATE);
    SSL_set_bio(p->listener, sb, sb);
    ok = ok && p->listener != NULL && SSL_listen(p->listener) == 1;
    p->client = SSL_new(p->cctx);
    SSL_set_bio(p->client, cb, cb);
    peer = addr(8443);
    ok = ok && p->client != NULL && SSL_set1_initial_peer_addr(p->client, peer) == 1;
    BIO_ADDR_free(peer);
    ok = ok && SSL_set_alpn_protos(p->client, alpn, sizeof(alpn)) == 0;
    ok = ok && SSL_set_blocking_mode(p->listener, 0) == 1 && SSL_set_blocking_mode(p->client, 0) == 1;
    return ok;
}

/* Runs the handshake without blocking; prints the client's first SSL_get_error. */
static int handshake(struct pair *p)
{
    int r, i, first = 1;

    for (i = 0; i < 200; i++) {
        r = SSL_connect(p->client);
        if (r == 1)
            return 1;
        if (first) {
            printf("  first connect: %d, %s\n", r, err_name(SSL_get_error(p->client, r)));
            first = 0;
        }
        if (SSL_get_error(p->client, r) != SSL_ERROR_WANT_READ) {
            printf("  connect stopped: %d, %s\n", r, err_name(SSL_get_error(p->client, r)));
            errors("client");
            return 0;
        }
        SSL_handle_events(p->listener);
    }
    printf("  still waiting after %d rounds: %s\n", i, SSL_state_string_long(p->client));
    errors("client");
    return 0;
}

static void free_pair(struct pair *p)
{
    SSL_free(p->server);
    SSL_free(p->client);
    SSL_free(p->listener);
    SSL_CTX_free(p->cctx);
    SSL_CTX_free(p->sctx);
}

static void test_objects(void)
{
    SSL_CTX *c = SSL_CTX_new(OSSL_QUIC_client_method());
    SSL_CTX *s = SSL_CTX_new(OSSL_QUIC_server_method());
    SSL_CTX *t = SSL_CTX_new(OSSL_QUIC_client_thread_method());
    SSL *x;

    printf("# objects\n");
    check(c != NULL && s != NULL && t != NULL, "the three QUIC methods make contexts");
    x = SSL_new(c);
    check(x != NULL, "SSL_new on a client context");
    printf("  is_connection %d is_stream %d is_listener %d is_domain %d is_tls %d is_quic %d\n",
           SSL_is_connection(x), SSL_is_stream_local(x), SSL_is_listener(x), SSL_is_domain(x),
           SSL_is_tls(x), SSL_is_quic(x));
    printf("  blocking %d, version %s\n", SSL_get_blocking_mode(x), SSL_get_version(x));
    SSL_free(x);
    ERR_clear_error();
    x = SSL_new(s);
    printf("  SSL_new on a server context: %s\n", x != NULL ? "an object" : "NULL");
    errors("server SSL_new");
    SSL_free(x);
    x = SSL_new_listener(s, 0);
    check(x != NULL, "SSL_new_listener on a server context");
    printf("  listener: is_listener %d is_connection %d\n", SSL_is_listener(x), SSL_is_connection(x));
    SSL_free(x);
    x = SSL_new_listener(c, 0);
    printf("  SSL_new_listener on a client context: %s\n", x != NULL ? "an object" : "NULL");
    errors("client listener");
    SSL_free(x);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    SSL_CTX_free(t);
}

static void test_connection(void)
{
    struct pair p;
    char buf[64];
    size_t n = 0, w = 0;
    int r, i;
    SSL *st;

    printf("# a connection\n");
    check(setup(&p), "a listener and a client over a datagram pair");
    check(handshake(&p), "the handshake completes without blocking");
    p.server = SSL_accept_connection(p.listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    check(p.server != NULL, "the listener accepts the connection");
    {
        const unsigned char *sel = NULL;
        unsigned int sel_len = 0;

        SSL_get0_alpn_selected(p.client, &sel, &sel_len);
        printf("  client version %s, alpn \"%.*s\", server is_connection %d\n",
               SSL_get_version(p.client), (int)sel_len, sel != NULL ? (const char *)sel : "",
               SSL_is_connection(p.server));
    }
    check(SSL_write_ex(p.client, "hello", 5, &w) == 1 && w == 5, "the client writes on its default stream");
    st = NULL;
    for (i = 0; i < 50 && st == NULL; i++) {
        SSL_handle_events(p.client);
        SSL_handle_events(p.server);
        st = SSL_accept_stream(p.server, SSL_ACCEPT_STREAM_NO_BLOCK);
    }
    check(st != NULL, "the server accepts the client's stream");
    if (st != NULL) {
        printf("  stream id %llu, type %d, local %d\n", (unsigned long long)SSL_get_stream_id(st),
               SSL_get_stream_type(st), SSL_is_stream_local(st));
        r = SSL_read_ex(st, buf, sizeof(buf), &n);
        printf("  server read: %d, %zu \"%.*s\"\n", r, n, (int)n, buf);
        check(SSL_write_ex(st, "world", 5, &w) == 1, "the server answers on that stream");
        r = 0;
        for (i = 0; i < 50 && r != 1; i++) {
            SSL_handle_events(p.server);
            r = SSL_read_ex(p.client, buf, sizeof(buf), &n);
            if (r != 1 && SSL_get_error(p.client, r) != SSL_ERROR_WANT_READ)
                break;
        }
        printf("  client read: %d, %zu \"%.*s\"\n", r, n, (int)n, buf);
        r = SSL_read_ex(p.client, buf, sizeof(buf), &n);
        printf("  client read again: %d, %s\n", r, err_name(SSL_get_error(p.client, r)));
        SSL_free(st);
    }
    ERR_clear_error();
    free_pair(&p);
}

int main(void)
{
    cert = ed_cert(&key);
    test_objects();
    test_connection();
    X509_free(cert);
    EVP_PKEY_free(key);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
