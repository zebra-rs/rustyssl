/*
 * Conformance test for the QUIC API's blocking mode (openssl-quic(7), SSL_set_blocking_mode(3),
 * OSSL_QUIC_client_thread_method(3)) over real UDP sockets on the loopback: a listener in a
 * thread of its own accepts a connection and a stream and echoes it, all with blocking calls,
 * while a thread-assisted client connects, writes, reads and shuts down with blocking calls.
 * It prints what both libraries must agree on.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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
    fflush(stdout);
}

static X509 *cert;
static EVP_PKEY *key;
static const unsigned char alpn[] = { 8, 'o', 's', 's', 'l', 't', 'e', 's', 't' };

static X509 *ed_cert(EVP_PKEY **pk)
{
    X509 *x = X509_new();
    X509_NAME *n = X509_NAME_new();

    *pk = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"quic", -1, -1, 0);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 7);
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

/* A UDP socket bound to 127.0.0.1 (port 0: any), and its port. */
static int udp_socket(unsigned short *port)
{
    struct sockaddr_in a;
    socklen_t l = sizeof(a);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0)
        return -1;
    getsockname(fd, (struct sockaddr *)&a, &l);
    *port = ntohs(a.sin_port);
    return fd;
}

struct server {
    SSL *listener;
    char got[64];
    int ok;
};

static void *serve(void *arg)
{
    struct server *sv = arg;
    SSL *conn, *st;
    size_t n = 0, w = 0;
    int r;

    conn = SSL_accept_connection(sv->listener, 0);
    if (conn == NULL)
        return NULL;
    st = SSL_accept_stream(conn, 0);
    if (st != NULL) {
        if (SSL_read_ex(st, sv->got, sizeof(sv->got) - 1, &n) == 1)
            sv->got[n] = '\0';
        r = SSL_write_ex(st, sv->got, n, &w);
        SSL_stream_conclude(st, 0);
        sv->ok = r == 1 && w == n;
    }
    /* Wait for the client's close. */
    while (SSL_shutdown_ex(conn, SSL_SHUTDOWN_FLAG_WAIT_PEER, NULL, 0) == 0)
        ;
    SSL_free(st);
    SSL_free(conn);
    return NULL;
}

int main(void)
{
    SSL_CTX *cctx, *sctx;
    SSL *client, *cs;
    BIO *sb, *cb;
    BIO_ADDR *peer;
    struct in_addr lo;
    struct server sv;
    pthread_t th;
    unsigned short sport = 0, cport = 0;
    int sfd, cfd, r;
    char buf[64];
    size_t n = 0, w = 0;
    SSL_CONN_CLOSE_INFO info;

    cert = ed_cert(&key);
    sctx = SSL_CTX_new(OSSL_QUIC_server_method());
    SSL_CTX_use_certificate(sctx, cert);
    SSL_CTX_use_PrivateKey(sctx, key);
    SSL_CTX_set_alpn_select_cb(sctx, select_alpn, NULL);
    cctx = SSL_CTX_new(OSSL_QUIC_client_thread_method());
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);

    sfd = udp_socket(&sport);
    cfd = udp_socket(&cport);
    check(sfd >= 0 && cfd >= 0, "two UDP sockets");

    memset(&sv, 0, sizeof(sv));
    sv.listener = SSL_new_listener(sctx, 0);
    sb = BIO_new_dgram(sfd, BIO_CLOSE);
    SSL_set_bio(sv.listener, sb, sb);
    check(SSL_get_blocking_mode(sv.listener) == 1, "a listener over a socket blocks");
    check(SSL_listen(sv.listener) == 1, "SSL_listen");

    client = SSL_new(cctx);
    cb = BIO_new_dgram(cfd, BIO_CLOSE);
    SSL_set_bio(client, cb, cb);
    lo.s_addr = htonl(0x7f000001);
    peer = BIO_ADDR_new();
    BIO_ADDR_rawmake(peer, AF_INET, &lo, sizeof(lo), htons(sport));
    SSL_set1_initial_peer_addr(client, peer);
    BIO_ADDR_free(peer);
    SSL_set_alpn_protos(client, alpn, sizeof(alpn));
    check(SSL_get_blocking_mode(client) == 1, "a client over a socket blocks");

    pthread_create(&th, NULL, serve, &sv);
    r = SSL_connect(client);
    check(r == 1, "a blocking SSL_connect completes");
    printf("  version %s\n", SSL_get_version(client));
    cs = SSL_new_stream(client, 0);
    check(cs != NULL, "a stream");
    check(SSL_write_ex(cs, "echo me", 7, &w) == 1 && w == 7, "a blocking write");
    SSL_stream_conclude(cs, 0);
    r = SSL_read_ex(cs, buf, sizeof(buf), &n);
    printf("  read: %d, %zu \"%.*s\"\n", r, n, (int)n, buf);
    r = SSL_read_ex(cs, buf, sizeof(buf), &n);
    printf("  read at the end: %d, %d\n", r, SSL_get_error(cs, r));
    SSL_free(cs);
    printf("  close info before the shutdown: %d\n", SSL_get_conn_close_info(client, &info, sizeof(info)));
    {
        /*
         * With a close set (whether the streams' flush ends it or the close itself: whether the
         * peer acknowledged the stream's end yet is a matter of timing).
         */
        SSL_SHUTDOWN_EX_ARGS args;

        memset(&args, 0, sizeof(args));
        args.quic_error_code = 7;
        args.quic_reason = "done";
        r = SSL_shutdown_ex(client, 0, &args, sizeof(args));
    }
    check(r == 1, "a blocking SSL_shutdown_ex completes");
    pthread_join(th, NULL);
    check(sv.ok, "the server echoed");
    printf("  server got \"%s\"\n", sv.got);
    if (SSL_get_conn_close_info(client, &info, sizeof(info)) == 1)
        printf("  close: code %llu, frame %llu, reason \"%.*s\", flags %u\n", (unsigned long long)info.error_code, (unsigned long long)info.frame_type, (int)info.reason_len, info.reason ? info.reason : "", info.flags);
    SSL_free(client);
    SSL_free(sv.listener);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    X509_free(cert);
    EVP_PKEY_free(key);
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
