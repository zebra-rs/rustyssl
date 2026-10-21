/*
 * CVE regression checks for DTLS associations: a client and a server in one process over
 * datagram memory BIOs, with this program relaying their datagrams. It can split a datagram into
 * its records, drop, reorder or inject records, and fire the retransmission timers, so the checks
 * cover what happens after a handshake, on lost flights, and on suspended writes. Each prints
 * what both libraries must agree on: whether the handshake completes, what arrives, and alerts.
 */
#include "cve.h"

#include <time.h>

static EVP_PKEY *server_key;
static X509 *server_cert;

typedef struct {
    SSL *ssl;
    BIO *in, *out;
} dend;

typedef struct {
    SSL_CTX *cctx, *sctx;
    dend c, s;
} dpair;

/* Retransmission timers of 200 ms, so the checks can fire them by sleeping briefly (and a
 * handshake never runs into them otherwise). */
static unsigned int short_timer(SSL *s, unsigned int us)
{
    (void)s;
    (void)us;
    return 200 * 1000;
}

static void dend_init(dend *e, SSL_CTX *ctx, int server)
{
    e->ssl = SSL_new(ctx);
    e->in = BIO_new(BIO_s_dgram_mem());
    e->out = BIO_new(BIO_s_dgram_mem());
    SSL_set_bio(e->ssl, e->in, e->out);
    SSL_set_options(e->ssl, SSL_OP_NO_QUERY_MTU);
    SSL_set_mtu(e->ssl, 1200);
    DTLS_set_timer_cb(e->ssl, short_timer);
    if (server)
        SSL_set_accept_state(e->ssl);
    else
        SSL_set_connect_state(e->ssl);
}

/* A client and a server; `ciphers` for both (TLS 1.2 suites), the client's options. */
static void dpair_init(dpair *p, const char *ciphers, uint64_t client_options)
{
    memset(p, 0, sizeof(*p));
    p->sctx = SSL_CTX_new(DTLS_server_method());
    SSL_CTX_use_certificate(p->sctx, server_cert);
    SSL_CTX_use_PrivateKey(p->sctx, server_key);
    p->cctx = SSL_CTX_new(DTLS_client_method());
    SSL_CTX_set_verify(p->cctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_session_cache_mode(p->cctx, SSL_SESS_CACHE_CLIENT);
    if (ciphers != NULL) {
        SSL_CTX_set_cipher_list(p->sctx, ciphers);
        SSL_CTX_set_cipher_list(p->cctx, ciphers);
    }
    SSL_CTX_set_options(p->cctx, client_options);
    dend_init(&p->c, p->cctx, 0);
    dend_init(&p->s, p->sctx, 1);
}

static void dpair_free(dpair *p)
{
    SSL_free(p->c.ssl);
    SSL_free(p->s.ssl);
    SSL_CTX_free(p->cctx);
    SSL_CTX_free(p->sctx);
}

/* Moves one datagram from `from` to `to`; its length, or 0 if none was waiting. */
static size_t move_one(dend *from, dend *to)
{
    unsigned char d[16384];
    int n = BIO_read(from->out, d, sizeof(d));

    if (n <= 0)
        return 0;
    BIO_write(to->in, d, n);
    return (size_t)n;
}

static size_t move_all(dend *from, dend *to)
{
    size_t total = 0, n;

    while ((n = move_one(from, to)) > 0)
        total += n;
    return total;
}

/* Drops every datagram `from` has sent; how many. */
static int drop_all(dend *from)
{
    unsigned char d[16384];
    int count = 0;

    while (BIO_read(from->out, d, sizeof(d)) > 0)
        count++;
    return count;
}

/* Runs both handshakes, relaying everything; 1 when both finish. */
static int dhandshake(dpair *p)
{
    for (int i = 0; i < 64; i++) {
        int c = SSL_do_handshake(p->c.ssl);
        size_t moved = move_all(&p->c, &p->s);
        int s = SSL_do_handshake(p->s.ssl);

        moved += move_all(&p->s, &p->c);
        if (c == 1 && s == 1)
            return 1;
        if (moved == 0 && SSL_get_error(p->c.ssl, c) != SSL_ERROR_WANT_READ)
            return 0;
        if (moved == 0 && SSL_get_error(p->s.ssl, s) != SSL_ERROR_WANT_READ)
            return 0;
    }
    return 0;
}

/* Waits past the 200 ms timer, then lets `e` retransmit. */
static int fire_timer(dend *e)
{
    struct timespec t = { 0, 250 * 1000 * 1000 };

    nanosleep(&t, NULL);
    return (int)DTLSv1_handle_timeout(e->ssl);
}

/* `msg` from the client to the server: what the server read ("<n octets: text>" or the error). */
static void send_and_read(dpair *p, const char *msg, char *out, size_t outlen)
{
    char got[256];
    int n;

    SSL_write(p->c.ssl, msg, (int)strlen(msg));
    move_all(&p->c, &p->s);
    n = SSL_read(p->s.ssl, got, sizeof(got) - 1);
    if (n > 0) {
        got[n] = '\0';
        snprintf(out, outlen, "%d octets: %s", n, got);
    } else {
        snprintf(out, outlen, "read %d, error %d", n, SSL_get_error(p->s.ssl, n));
    }
    move_all(&p->s, &p->c);
}

/* An application-data record of epoch 1 with `len` octets of filler, as an attacker who knows
 * no key would send it. */
static void forged_record(buf *b, size_t len, unsigned seq)
{
    unsigned char h[13] = { 0x17, 0xfe, 0xfd, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
                            0x00, 0x00 };

    h[9] = (unsigned char)(seq >> 8);
    h[10] = (unsigned char)seq;
    h[11] = (unsigned char)(len >> 8);
    h[12] = (unsigned char)len;
    put(b, h, sizeof(h));
    for (size_t i = 0; i < len; i++)
        put_byte(b, (unsigned char)(0xa5 ^ i));
}

/*
 * CVE-2012-2333 (a CBC record shorter than its explicit IV), CVE-2012-0050 (the padding check's
 * DoS) and CVE-2026-75806 (an AEAD record shorter than its nonce and tag): unauthenticated
 * records sent into an established association are dropped, and the association lives on.
 */
static void short_records(const char *cve, const char *what, const char *ciphers,
                          uint64_t client_options)
{
    static const size_t lens[] = { 0, 1, 7, 8, 15, 16, 20, 23, 24, 31, 32, 36, 47, 48, 64 };
    dpair p;
    char got[300], alert[16];
    int ok;

    dpair_init(&p, ciphers, client_options);
    ok = dhandshake(&p);
    note("%s: handshake %s, cipher %s", what, ok ? "done" : "failed",
         ok ? SSL_get_cipher_name(p.s.ssl) : "none");
    for (size_t i = 0; ok && i < sizeof(lens) / sizeof(lens[0]); i++) {
        buf b = {0};

        forged_record(&b, lens[i], (unsigned)(100 + i));
        BIO_write(p.s.in, b.p, (int)b.n);
        free_buf(&b);
    }
    {
        char one[8];
        int n = SSL_read(p.s.ssl, one, sizeof(one));
        buf sent = {0};
        unsigned char d[2048];
        int len;

        note("%s: the server's read of the forged records: %d, error %d", what, n,
             SSL_get_error(p.s.ssl, n));
        while ((len = BIO_read(p.s.out, d, sizeof(d))) > 0)
            put(&sent, d, (size_t)len);
        note("%s: the server sent %s", what, sent.n == 0 ? "nothing" : alert_in(&sent, alert,
             sizeof(alert)));
        free_buf(&sent);
    }
    errors(what);
    send_and_read(&p, "still here", got, sizeof(got));
    note("%s: then the server read %s", what, got);
    if (cve != NULL)
        check(ok && strcmp(got, "10 octets: still here") == 0,
              "%s: forged short records don't end an established association (%s)", cve, what);
    dpair_free(&p);
    ERR_clear_error();
}

/* CVE-2013-6450: the server's last flight is lost; the client retransmits its own, and the
 * server answers it with the right epoch's keys. */
static void lost_final_flight(void)
{
    dpair p;
    char got[300];
    int c = 0, s = 0, done = 0, dropped = -1;

    dpair_init(&p, NULL, 0);
    for (int i = 0; i < 64 && !done; i++) {
        c = SSL_do_handshake(p.c.ssl);
        move_all(&p.c, &p.s);
        s = SSL_do_handshake(p.s.ssl);
        if (s == 1 && dropped < 0) {
            dropped = drop_all(&p.s);
            fire_timer(&p.c);
            move_all(&p.c, &p.s);
            SSL_read(p.s.ssl, got, sizeof(got));
        }
        move_all(&p.s, &p.c);
        done = c == 1 && s == 1;
    }
    note("lost final flight: %d datagrams dropped, client %d, server %d", dropped, c, s);
    errors("lost final flight");
    if (done)
        send_and_read(&p, "after the retransmission", got, sizeof(got));
    else
        snprintf(got, sizeof(got), "nothing");
    note("lost final flight: the server read %s", got);
    check(done && strcmp(got, "24 octets: after the retransmission") == 0,
          "CVE-2013-6450: a retransmitted final flight after the handshake uses the right keys");
    dpair_free(&p);
    ERR_clear_error();
}

/* CVE-2026-84782: the server's flight is suspended part-way by a full datagram pair, its timer
 * fires while it is suspended, and the handshake still completes with intact messages. */
static void suspended_retransmission(void)
{
    SSL_CTX *sctx = SSL_CTX_new(DTLS_server_method());
    SSL_CTX *cctx = SSL_CTX_new(DTLS_client_method());
    SSL *c, *s;
    BIO *cb, *sb;
    int rc = 0, rs = 0, suspended = 0, fired = 0, results[3] = { 9, 9, 9 };
    char got[64];
    size_t n = 0;

    SSL_CTX_use_certificate(sctx, server_cert);
    SSL_CTX_use_PrivateKey(sctx, server_key);
    /* A long chain, so the server's flight is many datagrams. */
    for (int i = 0; i < 12; i++) {
        X509_up_ref(server_cert);
        SSL_CTX_add_extra_chain_cert(sctx, server_cert);
    }
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    /* The server's datagrams wait in 2048 octets of buffer: its flight can't all be written. */
    BIO_new_bio_dgram_pair(&cb, 0, &sb, 2048);
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    SSL_set_bio(c, cb, cb);
    SSL_set_bio(s, sb, sb);
    for (SSL *x = c; x != NULL; x = x == c ? s : NULL) {
        SSL_set_options(x, SSL_OP_NO_QUERY_MTU);
        SSL_set_mtu(x, 256);
        DTLS_set_timer_cb(x, short_timer);
    }
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    for (int i = 0; i < 400 && !(rc == 1 && rs == 1); i++) {
        rc = SSL_do_handshake(c);
        rs = SSL_do_handshake(s);
        /* A full pair queues a transient BIO error; what counts is that the write waits. */
        ERR_clear_error();
        if (rs <= 0 && SSL_want_write(s)) {
            suspended++;
            /* Retransmit while the write is suspended, then let the client drain a little. */
            if (fired < 3) {
                results[fired++] = fire_timer(&(dend){ s, NULL, NULL });
                ERR_clear_error();
            }
        }
    }
    note("suspended retransmission: client %d, server %d, the server's write %s; "
         "DTLSv1_handle_timeout while it waited: %d %d %d", rc, rs,
         suspended > 0 ? "was suspended" : "never suspended", results[0], results[1], results[2]);
    errors("suspended retransmission");
    if (rc == 1 && rs == 1) {
        SSL_write(c, "intact", 6);
        for (int i = 0; i < 10 && n == 0; i++)
            SSL_read_ex(s, got, sizeof(got), &n);
    }
    check(suspended > 0 && fired > 0 && rc == 1 && rs == 1 && n == 6 && memcmp(got, "intact", 6) == 0,
          "CVE-2026-84782: retransmitting a flight whose write was suspended keeps it intact");
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    ERR_clear_error();
}

/* Splits a datagram into its records: their offsets and lengths, up to `max`. */
static int records(const unsigned char *d, size_t n, size_t *off, size_t *len, int max)
{
    int count = 0;
    size_t p = 0;

    while (p + 13 <= n && count < max) {
        size_t l = 13 + (((size_t)d[p + 11] << 8) | d[p + 12]);

        if (p + l > n)
            break;
        off[count] = p;
        len[count] = l;
        count++;
        p += l;
    }
    return count;
}

/* CVE-2014-8176: in a resumed handshake, the client's application data arrives between its
 * ChangeCipherSpec and its Finished. */
static void data_between_ccs_and_finished(void)
{
    dpair p;
    SSL_SESSION *sess;
    unsigned char d[16384], held[16384];
    size_t off[16], len[16], held_len = 0;
    char got[64];
    int ok, n, c = 0, s = 0, resumed;

    dpair_init(&p, NULL, 0);
    ok = dhandshake(&p);
    sess = SSL_get1_session(p.c.ssl);
    SSL_set_shutdown(p.c.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_set_shutdown(p.s.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_free(p.c.ssl);
    SSL_free(p.s.ssl);
    dend_init(&p.c, p.cctx, 0);
    dend_init(&p.s, p.sctx, 1);
    SSL_set_session(p.c.ssl, sess);
    SSL_SESSION_free(sess);
    /* ClientHello; the server's ServerHello, ChangeCipherSpec and Finished. */
    for (int i = 0; i < 4 && c != 1; i++) {
        c = SSL_do_handshake(p.c.ssl);
        move_all(&p.c, &p.s);
        s = SSL_do_handshake(p.s.ssl);
        move_all(&p.s, &p.c);
        c = SSL_do_handshake(p.c.ssl);
    }
    resumed = SSL_session_reused(p.c.ssl);
    /* The client's ChangeCipherSpec and Finished are held; its data is written after them. */
    while ((n = BIO_read(p.c.out, d, sizeof(d))) > 0 && held_len + (size_t)n <= sizeof(held)) {
        memcpy(held + held_len, d, (size_t)n);
        held_len += (size_t)n;
    }
    SSL_write(p.c.ssl, "early", 5);
    {
        int count = records(held, held_len, off, len, 16);

        /* Everything but the last record (the Finished), then the data, then the Finished. */
        for (int i = 0; i + 1 < count; i++)
            BIO_write(p.s.in, held + off[i], (int)len[i]);
        move_all(&p.c, &p.s);
        if (count > 0)
            BIO_write(p.s.in, held + off[count - 1], (int)len[count - 1]);
        note("data between CCS and Finished: %d records held from the client", count);
    }
    s = SSL_do_handshake(p.s.ssl);
    n = SSL_read(p.s.ssl, got, sizeof(got) - 1);
    if (n > 0)
        got[n] = '\0';
    note("data between CCS and Finished: first handshake %s, resumed %d, client %d, server %d, "
         "read %d%s%s", ok ? "done" : "failed", resumed, c, s, n, n > 0 ? ": " : "",
         n > 0 ? got : "");
    errors("data between CCS and Finished");
    check(ok && resumed && c == 1, "CVE-2014-8176: data between ChangeCipherSpec and Finished "
          "in a resumed DTLS handshake is handled without an invalid free");
    dpair_free(&p);
    ERR_clear_error();
}

static void u8(buf *b, unsigned v)
{
    put_byte(b, (unsigned char)v);
}

static void u16(buf *b, unsigned v)
{
    u8(b, v >> 8);
    u8(b, v & 0xff);
}

static void u24(buf *b, size_t v)
{
    u8(b, (unsigned)(v >> 16) & 0xff);
    u16(b, (unsigned)(v & 0xffff));
}

/* A DTLS handshake record of epoch 0 holding one whole message. */
static void dtls_message(buf *out, unsigned type, unsigned msg_seq, unsigned rec_seq, buf *body)
{
    u8(out, 0x16);
    u16(out, 0xfefd);
    u16(out, 0);
    u16(out, 0);
    u16(out, 0);
    u16(out, rec_seq);
    u16(out, (unsigned)(body->n + 12));
    u8(out, type);
    u24(out, body->n);
    u16(out, msg_seq);
    u24(out, 0);
    u24(out, body->n);
    put(out, body->p, body->n);
}

/* CVE-2014-3510: a DTLS client offering anonymous ECDH gets a ServerHello choosing it, then
 * ServerHelloDone without the ServerKeyExchange that suite needs. */
static void anonymous_client(void)
{
    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
    dend c;
    buf hello = {0}, done = {0}, flight = {0}, sent = {0};
    unsigned char d[16384];
    char alert[16];
    int r, n;

    SSL_CTX_set_cipher_list(ctx, "AECDH-AES128-SHA:@SECLEVEL=0");
    SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);
    dend_init(&c, ctx, 0);
    r = SSL_do_handshake(c.ssl);
    while (BIO_read(c.out, d, sizeof(d)) > 0)
        ;
    u16(&hello, 0xfefd);
    for (int i = 0; i < 32; i++)
        u8(&hello, (unsigned)(0x20 + i));
    u8(&hello, 0);
    u16(&hello, 0xc018); /* TLS_ECDH_anon_WITH_AES_128_CBC_SHA */
    u8(&hello, 0);
    u16(&hello, 5); /* extensions: an empty renegotiation_info */
    u16(&hello, 0xff01);
    u16(&hello, 1);
    u8(&hello, 0);
    dtls_message(&flight, 2, 0, 0, &hello);
    dtls_message(&flight, 14, 1, 1, &done);
    BIO_write(c.in, flight.p, (int)flight.n);
    r = SSL_do_handshake(c.ssl);
    while ((n = BIO_read(c.out, d, sizeof(d))) > 0)
        put(&sent, d, (size_t)n);
    note("anonymous client: handshake %d, error %d, alert %s", r, SSL_get_error(c.ssl, r),
         alert_in(&sent, alert, sizeof(alert)));
    errors("anonymous client");
    check(r <= 0, "CVE-2014-3510: a DTLS client with anonymous ECDH refuses a missing "
          "ServerKeyExchange without a crash");
    free_buf(&hello);
    free_buf(&done);
    free_buf(&flight);
    free_buf(&sent);
    SSL_free(c.ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
}

int main(void)
{
    server_key = ec_key();
    server_cert = leaf_cert("server.example", server_key, NULL, NULL);

    short_records("CVE-2012-2333", "CBC, MAC then encrypt", "ECDHE-ECDSA-AES128-SHA",
                  SSL_OP_NO_ENCRYPT_THEN_MAC);
    short_records("CVE-2012-0050", "CBC padding, MAC then encrypt", "ECDHE-ECDSA-AES128-SHA",
                  SSL_OP_NO_ENCRYPT_THEN_MAC);
    /* With encrypt-then-MAC, OpenSSL ends the association on a record too short for its MAC
     * (LENGTH_TOO_SHORT): compared, not checked. */
    short_records(NULL, "CBC, encrypt then MAC", "ECDHE-ECDSA-AES128-SHA", 0);
    short_records("CVE-2026-75806", "AES-GCM", "ECDHE-ECDSA-AES128-GCM-SHA256", 0);
    short_records("CVE-2026-75806", "ChaCha20-Poly1305", "ECDHE-ECDSA-CHACHA20-POLY1305", 0);
    lost_final_flight();
    suspended_retransmission();
    data_between_ccs_and_finished();
    anonymous_client();

    X509_free(server_cert);
    EVP_PKEY_free(server_key);
    return finish();
}
