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

/*
 * A listener that validates addresses (Retry, the default), as quicapitest's
 * test_ssl_accept_connection: the connection is accepted before its handshake completes, then
 * SSL_connect and SSL_accept run it.
 */
static void test_validated(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *listener, *client, *server = NULL;
    BIO *cb = NULL, *sb = NULL;
    BIO_ADDR *peer;
    int r, i, cdone = 0, sdone = 0;

    printf("# a validating listener\n");
    BIO_new_bio_dgram_pair(&cb, 0, &sb, 0);
    bind_end(sb, 8040);
    listener = SSL_new_listener(sctx, 0);
    SSL_set_bio(listener, sb, sb);
    check(SSL_listen(listener) == 1, "SSL_listen");
    client = SSL_new(cctx);
    bind_end(cb, 8040);
    peer = addr(8040);
    SSL_set1_initial_peer_addr(client, peer);
    BIO_ADDR_free(peer);
    SSL_set_alpn_protos(client, alpn, sizeof(alpn));
    SSL_set_bio(client, cb, cb);

    r = SSL_accept(listener);
    printf("  SSL_accept on the listener: %d, %s\n", r, err_name(SSL_get_error(listener, r)));
    errors("listener accept");
    for (i = 0; i < 2; i++) {
        r = SSL_connect(client);
        printf("  connect %d: %d, %s\n", i, r, err_name(SSL_get_error(client, r)));
        SSL_handle_events(listener);
    }
    server = SSL_accept_connection(listener, 0);
    check(server != NULL, "the connection is accepted before its handshake completes");
    if (server != NULL) {
        printf("  server init finished: %d\n", SSL_is_init_finished(server));
        for (i = 0; i < 1000000 && !(cdone && sdone); i++) {
            if (!cdone && SSL_connect(client) == 1)
                cdone = 1;
            if (!sdone && SSL_accept(server) == 1)
                sdone = 1;
        }
        check(cdone && sdone, "SSL_connect and SSL_accept complete the handshake");
    }
    ERR_clear_error();
    SSL_free(server);
    SSL_free(client);
    SSL_free(listener);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void pump(struct pair *p, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        SSL_handle_events(p->client);
        SSL_handle_events(p->listener);
    }
}

static uint64_t poll_one(SSL *s, uint64_t events)
{
    SSL_POLL_ITEM it;
    struct timeval tv = { 0, 0 };
    size_t n = 0;

    memset(&it, 0, sizeof(it));
    it.desc = SSL_as_poll_descriptor(s);
    it.events = events;
    if (!SSL_poll(&it, 1, sizeof(it), &tv, 0, &n))
        return ~(uint64_t)0;
    return it.revents;
}

static void print_close(const char *who, SSL *s)
{
    SSL_CONN_CLOSE_INFO info;
    int r = SSL_get_conn_close_info(s, &info, sizeof(info));

    if (r != 1) {
        printf("  %s close info: %d\n", who, r);
        return;
    }
    printf("  %s close info: code %llu, frame type %llu, reason \"%.*s\", flags %u\n", who,
           (unsigned long long)info.error_code, (unsigned long long)info.frame_type,
           (int)info.reason_len, info.reason != NULL ? info.reason : "", info.flags);
}

/* Streams both ways, their states, SSL_poll, values, and the close. */
static void test_streams(void)
{
    struct pair p;
    SSL *cs = NULL, *ss = NULL, *cu = NULL, *su = NULL;
    SSL_SHUTDOWN_EX_ARGS args;
    unsigned char buf[64];
    size_t n = 0, w = 0;
    uint64_t v = 0, aec = 0;
    int r, i;

    printf("# streams, SSL_poll and the close\n");
    check(setup(&p) && handshake(&p), "a connection");
    p.server = SSL_accept_connection(p.listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    check(p.server != NULL, "accepted");
    if (p.server == NULL) {
        free_pair(&p);
        return;
    }
    SSL_set_default_stream_mode(p.client, SSL_DEFAULT_STREAM_MODE_NONE);
    SSL_set_incoming_stream_policy(p.client, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
    r = SSL_write_ex(p.client, "x", 1, &w);
    printf("  write with no default stream: %d, %s\n", r, err_name(SSL_get_error(p.client, r)));
    errors("client");
    printf("  client poll W|OSB|OSU|EC|ISB|ISU: %#llx\n",
           (unsigned long long)poll_one(p.client, SSL_POLL_EVENT_W | SSL_POLL_EVENT_OS
                                                  | SSL_POLL_EVENT_EC | SSL_POLL_EVENT_IS));
    check(SSL_get_value_uint(p.client, SSL_VALUE_CLASS_GENERIC,
                             SSL_VALUE_QUIC_STREAM_BIDI_LOCAL_AVAIL, &v) == 1, "streams available");
    printf("  bidi local avail %llu\n", (unsigned long long)v);
    check(SSL_get_value_uint(p.client, SSL_VALUE_CLASS_FEATURE_NEGOTIATED,
                             SSL_VALUE_QUIC_IDLE_TIMEOUT, &v) == 1, "negotiated idle timeout");
    printf("  idle timeout %llu\n", (unsigned long long)v);
    r = SSL_set_value_uint(p.client, SSL_VALUE_CLASS_FEATURE_REQUEST, SSL_VALUE_QUIC_IDLE_TIMEOUT, 5000);
    printf("  idle timeout after the handshake: %d\n", r);
    errors("client");

    cs = SSL_new_stream(p.client, 0);
    cu = SSL_new_stream(p.client, SSL_STREAM_FLAG_UNI);
    check(cs != NULL && cu != NULL, "two client streams");
    printf("  ids %llu %llu, types %d %d, local %d %d\n",
           (unsigned long long)SSL_get_stream_id(cs), (unsigned long long)SSL_get_stream_id(cu),
           SSL_get_stream_type(cs), SSL_get_stream_type(cu), SSL_is_stream_local(cs),
           SSL_is_stream_local(cu));
    printf("  uni read state %d, write state %d\n", SSL_get_stream_read_state(cu),
           SSL_get_stream_write_state(cu));
    check(SSL_write_ex(cs, "ping", 4, &w) == 1 && SSL_write_ex(cu, "one-way", 7, &w) == 1,
          "writes on both");
    check(SSL_stream_conclude(cu, 0) == 1, "the uni stream concluded");
    printf("  uni write state after conclude %d\n", SSL_get_stream_write_state(cu));
    for (i = 0; i < 50 && SSL_get_accept_stream_queue_len(p.server) < 2; i++)
        pump(&p, 1);
    printf("  server accept queue %zu, poll ISB|ISU %#llx\n", SSL_get_accept_stream_queue_len(p.server),
           (unsigned long long)poll_one(p.server, SSL_POLL_EVENT_IS));
    su = SSL_accept_stream(p.server, SSL_ACCEPT_STREAM_UNI);
    ss = SSL_accept_stream(p.server, 0);
    printf("  accepted uni %d, then any %d\n", su != NULL, ss != NULL);
    /* Accepting a stream touched the default stream: the AUTO policy now rejects. */
    errors("server accept");
    if (ss == NULL) {
        SSL_set_incoming_stream_policy(p.server, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
        ss = SSL_accept_stream(p.server, SSL_ACCEPT_STREAM_NO_BLOCK);
    }
    check(ss != NULL && su != NULL, "the server accepts both by direction");
    if (ss == NULL || su == NULL)
        goto out;
    printf("  server ids %llu %llu, types %d %d\n", (unsigned long long)SSL_get_stream_id(ss),
           (unsigned long long)SSL_get_stream_id(su), SSL_get_stream_type(ss), SSL_get_stream_type(su));
    printf("  server uni poll R %#llx\n", (unsigned long long)poll_one(su, SSL_POLL_EVENT_R));
    r = SSL_peek_ex(su, buf, sizeof(buf), &n);
    printf("  peek: %d, %zu \"%.*s\"\n", r, n, (int)n, buf);
    r = SSL_read_ex(su, buf, sizeof(buf), &n);
    printf("  read: %d, %zu \"%.*s\"\n", r, n, (int)n, buf);
    r = SSL_read_ex(su, buf, sizeof(buf), &n);
    printf("  read at the end: %d, %s\n", r, err_name(SSL_get_error(su, r)));
    printf("  uni read state %d, error code %d\n", SSL_get_stream_read_state(su),
           SSL_get_stream_read_error_code(su, &aec));
    r = SSL_write_ex(su, "no", 2, &w);
    printf("  write on the server's receive-only stream: %d\n", r);
    errors("server");
    r = SSL_read_ex(ss, buf, sizeof(buf), &n);
    printf("  bidi read: %d, %zu \"%.*s\"\n", r, n, (int)n, buf);
    {
        SSL_STREAM_RESET_ARGS ra;

        ra.quic_error_code = 77;
        check(SSL_stream_reset(ss, &ra, sizeof(ra)) == 1, "the server resets its send part");
    }
    printf("  server write state %d, error %d code %llu\n", SSL_get_stream_write_state(ss),
           SSL_get_stream_write_error_code(ss, &aec), (unsigned long long)aec);
    for (i = 0; i < 50 && SSL_get_stream_read_state(cs) == SSL_STREAM_STATE_OK; i++)
        pump(&p, 1);
    aec = 0;
    printf("  client read state %d, error %d code %llu, poll ER %#llx\n", SSL_get_stream_read_state(cs),
           SSL_get_stream_read_error_code(cs, &aec), (unsigned long long)aec,
           (unsigned long long)poll_one(cs, SSL_POLL_EVENT_ER));
    r = SSL_read_ex(cs, buf, sizeof(buf), &n);
    printf("  read after the reset: %d, %s\n", r, err_name(SSL_get_error(cs, r)));
    errors("client");

    check(SSL_inject_net_dgram(p.client, (const unsigned char *)"junk", 4, NULL, NULL) == 1,
          "a datagram injected");
    SSL_handle_events(p.client);

    memset(&args, 0, sizeof(args));
    args.quic_error_code = 42;
    args.quic_reason = "bye";
    r = SSL_shutdown_ex(p.client, SSL_SHUTDOWN_FLAG_NO_STREAM_FLUSH, &args, sizeof(args));
    printf("  shutdown: %d, get_shutdown %d\n", r, SSL_get_shutdown(p.client));
    for (i = 0; i < 50; i++)
        pump(&p, 1);
    print_close("client", p.client);
    print_close("server", p.server);
    printf("  server poll EC %#llx, write: %d\n", (unsigned long long)poll_one(p.server, SSL_POLL_EVENT_EC),
           SSL_write_ex(ss, "z", 1, &w));
    errors("server");
out:
    ERR_clear_error();
    SSL_free(cs);
    SSL_free(cu);
    SSL_free(ss);
    SSL_free(su);
    free_pair(&p);
}

/*
 * A large response, as an HTTP/0.9 server sends it: written in chunks (retrying when the send
 * buffer is full), concluded, and the stream object freed at once. Everything must arrive.
 */
static void test_large_transfer(void)
{
    struct pair p;
    SSL *cs = NULL, *ss = NULL;
    static unsigned char out[3 << 20], in[8192];
    size_t total = sizeof(out), sent = 0, got = 0, n = 0, w = 0;
    unsigned long sum_out = 0, sum_in = 0;
    int r, i, fin = 0;

    printf("# a large transfer, the stream freed after its conclusion\n");
    for (n = 0; n < total; n++) {
        out[n] = (unsigned char)(n * 7 + (n >> 11));
        sum_out = sum_out * 31 + out[n];
    }
    check(setup(&p) && handshake(&p), "a connection");
    p.server = SSL_accept_connection(p.listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    cs = SSL_new_stream(p.client, 0);
    check(cs != NULL && SSL_write_ex(cs, "GET /big\r\n", 10, &w) == 1, "a request");
    SSL_stream_conclude(cs, 0);
    for (i = 0; i < 100 && ss == NULL; i++) {
        pump(&p, 1);
        ss = SSL_accept_stream(p.server, SSL_ACCEPT_STREAM_NO_BLOCK);
    }
    check(ss != NULL, "the server accepts it");
    if (ss == NULL)
        goto out;
    /* The server writes all of it, the client reading as it goes. */
    for (i = 0; i < 2000000 && (sent < total || !fin); i++) {
        if (sent < total) {
            size_t chunk = total - sent > 65536 ? 65536 : total - sent;

            r = SSL_write_ex(ss, out + sent, chunk, &w);
            if (r == 1)
                sent += w;
            else if (SSL_get_error(ss, r) != SSL_ERROR_WANT_WRITE)
                break;
            if (sent == total) {
                SSL_stream_conclude(ss, 0);
                SSL_free(ss);
                ss = NULL;
            }
        }
        r = SSL_read_ex(cs, in, sizeof(in), &n);
        if (r == 1) {
            size_t k;

            for (k = 0; k < n; k++)
                sum_in = sum_in * 31 + in[k];
            got += n;
        } else if (SSL_get_error(cs, r) == SSL_ERROR_ZERO_RETURN) {
            fin = 1;
        } else if (SSL_get_error(cs, r) != SSL_ERROR_WANT_READ) {
            break;
        }
        SSL_handle_events(p.listener);
    }
    check(sent == total, "the server wrote all of it");
    check(got == total && fin, "the client read all of it and the end");
    check(sum_in == sum_out, "unchanged");
    printf("  sent %zu, received %zu, end %d\n", sent, got, fin);
out:
    ERR_clear_error();
    SSL_free(ss);
    SSL_free(cs);
    free_pair(&p);
}

/*
 * Streams opened before the handshake with SSL_STREAM_FLAG_ADVANCE, as an HTTP/3 client opens
 * its control and QPACK streams (curl's OpenSSL QUIC backend): they get their ids at once, and
 * what is written on them arrives once the connection is up.
 */
static void test_streams_before_handshake(void)
{
    struct pair p;
    SSL *u[3] = { NULL, NULL, NULL }, *su = NULL;
    unsigned char buf[16];
    size_t w = 0, n = 0;
    int i, r;

    printf("# streams opened before the handshake\n");
    check(setup(&p), "a listener and a client");
    SSL_set_incoming_stream_policy(p.client, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
    r = SSL_set_value_uint(p.client, SSL_VALUE_CLASS_FEATURE_REQUEST, SSL_VALUE_QUIC_IDLE_TIMEOUT, 0);
    printf("  idle timeout request before the handshake: %d\n", r);
    for (i = 0; i < 3; i++)
        u[i] = SSL_new_stream(p.client, SSL_STREAM_FLAG_ADVANCE | SSL_STREAM_FLAG_UNI);
    check(u[0] != NULL && u[1] != NULL && u[2] != NULL, "three uni streams with ADVANCE");
    printf("  ids %llu %llu %llu, type %d\n", (unsigned long long)SSL_get_stream_id(u[0]),
           (unsigned long long)SSL_get_stream_id(u[1]), (unsigned long long)SSL_get_stream_id(u[2]),
           u[0] != NULL ? SSL_get_stream_type(u[0]) : -1);
    errors("client");
    if (u[0] == NULL)
        goto out;
    r = SSL_write_ex(u[0], "ctrl", 4, &w);
    printf("  write before the handshake: %d, %s\n", r, err_name(SSL_get_error(u[0], r)));
    check(handshake(&p), "the handshake completes");
    p.server = SSL_accept_connection(p.listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    check(p.server != NULL, "accepted");
    if (r != 1)
        r = SSL_write_ex(u[0], "ctrl", 4, &w);
    check(r == 1, "the control stream is written");
    for (i = 0; i < 100 && su == NULL; i++) {
        pump(&p, 1);
        su = SSL_accept_stream(p.server, SSL_ACCEPT_STREAM_NO_BLOCK);
    }
    check(su != NULL, "the server accepts it");
    if (su != NULL) {
        for (i = 0; i < 100; i++) {
            r = SSL_read_ex(su, buf, sizeof(buf), &n);
            if (r == 1)
                break;
            pump(&p, 1);
        }
        printf("  server read on stream %llu: %d, %zu \"%.*s\"\n",
               (unsigned long long)SSL_get_stream_id(su), r, n, (int)n, buf);
    }
out:
    ERR_clear_error();
    SSL_free(su);
    for (i = 0; i < 3; i++)
        SSL_free(u[i]);
    free_pair(&p);
}

/* SSL_poll on what it can't poll. */
static void test_poll_errors(void)
{
    SSL_CTX *t = SSL_CTX_new(TLS_method());
    SSL *s = SSL_new(t);
    SSL_POLL_ITEM it[2];
    size_t n = 99;
    struct timeval tv = { 0, 0 };
    int r;

    printf("# SSL_poll errors\n");
    memset(it, 0, sizeof(it));
    it[0].desc = SSL_as_poll_descriptor(NULL);
    it[1].desc = SSL_as_poll_descriptor(s);
    it[1].events = SSL_POLL_EVENT_R;
    r = SSL_poll(it, 2, sizeof(it[0]), &tv, 0, &n);
    printf("  a TLS object: %d, count %zu, revents %#llx %#llx\n", r, n,
           (unsigned long long)it[0].revents, (unsigned long long)it[1].revents);
    errors("poll");
    r = SSL_poll(NULL, 0, sizeof(it[0]), &tv, 0, &n);
    printf("  no items: %d, count %zu\n", r, n);
    SSL_free(s);
    SSL_CTX_free(t);
}

static SSL *info_ssl;

static void info_cb(const SSL *s, int where, int ret)
{
    (void)ret;
    if (where == SSL_CB_HANDSHAKE_DONE)
        info_ssl = (SSL *)s;
}

/* A client connection on a listener's port (SSL_new_from_listener) to another listener. */
static void test_from_listener(void)
{
    SSL_CTX *lctx = server_ctx(), *sctx = server_ctx();
    SSL *l1, *l2, *conn;
    BIO *b1 = NULL, *b2 = NULL;
    BIO_ADDR *peer;
    int r, i;

    printf("# a connection from a listener\n");
    SSL_CTX_set_info_callback(lctx, info_cb);
    BIO_new_bio_dgram_pair(&b1, 0, &b2, 0);
    bind_end(b1, 8041);
    bind_end(b2, 4081);
    l1 = SSL_new_listener(lctx, 0);
    SSL_set_bio(l1, b1, b1);
    l2 = SSL_new_listener(sctx, 0);
    SSL_set_bio(l2, b2, b2);
    check(SSL_listen(l1) == 1 && SSL_listen(l2) == 1, "two listeners");
    check(SSL_new_from_listener(l1, 1) == NULL, "SSL_new_from_listener refuses flags");
    conn = SSL_new_from_listener(l1, 0);
    check(conn != NULL, "SSL_new_from_listener");
    printf("  is_connection %d, listener is its listener %d\n", SSL_is_connection(conn),
           SSL_get0_listener(conn) == l1);
    peer = addr(4081);
    SSL_set1_initial_peer_addr(conn, peer);
    BIO_ADDR_free(peer);
    SSL_set_alpn_protos(conn, alpn, sizeof(alpn));
    for (i = 0; i < 1000000 && (r = SSL_do_handshake(conn)) == -1; i++) {
        SSL_handle_events(l2);
        SSL_handle_events(l1);
    }
    check(r == 1, "the handshake completes");
    check(info_ssl == conn, "the info callback gets the connection object");
    ERR_clear_error();
    SSL_free(conn);
    SSL_free(l1);
    SSL_free(l2);
    SSL_CTX_free(lctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    cert = ed_cert(&key);
    test_objects();
    test_connection();
    test_validated();
    test_from_listener();
    test_streams();
    test_large_transfer();
    test_streams_before_handshake();
    test_poll_errors();
    X509_free(cert);
    EVP_PKEY_free(key);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
