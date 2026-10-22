/*
 * CVE regression tests: TLS and DTLS. A server is fed handcrafted ClientHellos and records, a
 * client handcrafted server flights, through memory BIOs; real handshakes between rustyssl's (or
 * the reference's) own client and server set up the post-handshake cases. Only outcomes are
 * printed (alerts, errors, negotiated parameters), never random values.
 */
#include "cve.h"

#include <openssl/core_names.h>
#include <openssl/ocsp.h>
#include <openssl/quic.h>

static EVP_PKEY *server_key;
static X509 *server_cert;
static EVP_PKEY *rsa_server_key;
static X509 *rsa_server_cert;

/* ---- Message builders ---- */

static void u8(buf *b, unsigned v)
{
    put_byte(b, (unsigned char)v);
}

static void u16(buf *b, unsigned v)
{
    put_byte(b, (unsigned char)(v >> 8));
    put_byte(b, (unsigned char)v);
}

static void u24(buf *b, size_t v)
{
    put_byte(b, (unsigned char)(v >> 16));
    put_byte(b, (unsigned char)(v >> 8));
    put_byte(b, (unsigned char)v);
}

/* A record of `type` around `body` (freed). */
static void record(buf *out, unsigned type, unsigned version, buf *body)
{
    u8(out, type);
    u16(out, version);
    u16(out, (unsigned)body->n);
    put(out, body->p, body->n);
    free_buf(body);
}

/* A handshake message of `type` around `body` (freed). */
static void handshake_msg(buf *out, unsigned type, buf *body)
{
    u8(out, type);
    u24(out, body->n);
    put(out, body->p, body->n);
    free_buf(body);
}

/* An extension. */
static void ext(buf *exts, unsigned type, const void *data, size_t len)
{
    u16(exts, type);
    u16(exts, (unsigned)len);
    put(exts, data, len);
}

/* The extensions a TLS 1.2 ECDHE-ECDSA ClientHello needs. */
static void base_exts(buf *exts)
{
    ext(exts, 0x000a, "\x00\x02\x00\x17", 4);         /* supported_groups: secp256r1 */
    ext(exts, 0x000b, "\x01\x00", 2);                 /* ec_point_formats */
    ext(exts, 0x000d, "\x00\x04\x04\x03\x08\x04", 6); /* signature_algorithms */
    ext(exts, 0xff01, "\x00", 1);                     /* renegotiation_info */
}

/* A TLS ClientHello handshake message (not in a record). */
static void client_hello(buf *out, unsigned version, const unsigned *suites, size_t nsuites,
                         buf *exts)
{
    buf body = {0};

    u16(&body, version);
    for (int i = 0; i < 32; i++)
        u8(&body, (unsigned)(0x40 + i));
    u8(&body, 0);
    u16(&body, (unsigned)(2 * nsuites));
    for (size_t i = 0; i < nsuites; i++)
        u16(&body, suites[i]);
    put(&body, "\x01\x00", 2);
    if (exts != NULL) {
        u16(&body, (unsigned)exts->n);
        put(&body, exts->p, exts->n);
        free_buf(exts);
    }
    handshake_msg(out, 1, &body);
}

static const unsigned ecdhe_suites[] = {0xc02b, 0xc009};

/* A ClientHello record offering TLS 1.2 ECDHE-ECDSA with `extra` extensions appended. */
static void hello_record(buf *out, buf *extra)
{
    buf exts = {0}, msg = {0};

    base_exts(&exts);
    if (extra != NULL) {
        put(&exts, extra->p, extra->n);
        free_buf(extra);
    }
    client_hello(&msg, 0x0303, ecdhe_suites, 2, &exts);
    record(out, 0x16, 0x0301, &msg);
}

/* ---- Server-side runs ---- */

static SSL_CTX *make_server_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    SSL_CTX_use_certificate(ctx, server_cert);
    SSL_CTX_use_PrivateKey(ctx, server_key);
    return ctx;
}

/* Describes what a peer wrote: the ServerHello's version and suite, or an alert. */
static void describe(const char *what, const buf *b, int ret, int err)
{
    char alert[16];

    if (b->n >= 11 && b->p[0] == 0x16 && b->p[5] == 0x02) {
        unsigned version = (unsigned)(b->p[9] << 8 | b->p[10]);
        size_t sid = b->n > 43 ? b->p[43] : 0;
        unsigned suite = b->n > 46 + sid ? (unsigned)(b->p[44 + sid] << 8 | b->p[45 + sid]) : 0;

        note("%s: ServerHello %04x, suite %04x (handshake %d, error %d)", what, version, suite,
             ret, err);
    } else {
        note("%s: wrote %zu octets, alert %s (handshake %d, error %d)", what, b->n,
             alert_in(b, alert, sizeof(alert)), ret, err);
    }
}

/* Feeds `in` to a fresh server and runs its handshake once; its output is in `out`. */
static int serve(SSL_CTX *ctx, const buf *in, buf *out, const char *what)
{
    end s;
    int ret, err;

    end_init(&s, ctx, 1);
    feed(&s, in->p, in->n);
    ret = SSL_do_handshake(s.ssl);
    err = SSL_get_error(s.ssl, ret);
    take(&s, out);
    describe(what, out, ret, err);
    errors(what);
    end_free(&s);
    return ret;
}

static int is_hello(const buf *b)
{
    return b->n >= 6 && b->p[0] == 0x16 && b->p[5] == 0x02;
}

static int is_alert(const buf *b)
{
    char a[16];

    return strcmp(alert_in(b, a, sizeof(a)), "none") != 0;
}

/* Whether the ServerHello in `b` carries extension `type`. */
static int hello_has_ext(const buf *b, unsigned type)
{
    size_t at, end;

    if (!is_hello(b) || b->n < 44)
        return 0;
    at = 5 + 4 + 2 + 32;
    at += 1 + b->p[at];
    at += 3;
    if (at + 2 > b->n)
        return 0;
    end = at + 2 + (size_t)(b->p[at] << 8 | b->p[at + 1]);
    for (at += 2; at + 4 <= end && at + 4 <= b->n;) {
        unsigned t = (unsigned)(b->p[at] << 8 | b->p[at + 1]);
        size_t len = (size_t)(b->p[at + 2] << 8 | b->p[at + 3]);

        if (t == type)
            return 1;
        at += 4 + len;
    }
    return 0;
}

static void server_inputs(void)
{
    SSL_CTX *ctx = make_server_ctx();
    buf in = {0}, out = {0}, extra = {0}, body = {0};
    int r;

    /* A heartbeat request as the first record, and the heartbeat extension. */
    put(&in, "\x18\x03\x03\x00\x03\x01\x40\x00", 8);
    serve(ctx, &in, &out, "heartbeat record");
    check(out.n < 64 && !is_hello(&out),
          "CVE-2014-0160: a heartbeat request is refused, echoing nothing");
    free_buf(&in);
    free_buf(&out);
    ext(&extra, 0x000f, "\x01", 1);
    hello_record(&in, &extra);
    serve(ctx, &in, &out, "heartbeat extension");
    check(is_hello(&out) && !hello_has_ext(&out, 0x000f),
          "CVE-2014-0160: the heartbeat extension isn't negotiated");
    free_buf(&in);
    free_buf(&out);

    /* ChangeCipherSpec first, an unknown handshake type. */
    put(&in, "\x14\x03\x03\x00\x01\x01", 6);
    serve(ctx, &in, &out, "ChangeCipherSpec first");
    check(!is_hello(&out), "CVE-2004-0079: a ChangeCipherSpec before the handshake is refused");
    free_buf(&in);
    free_buf(&out);
    u16(&body, 0x0303);
    handshake_msg(&extra, 99, &body);
    record(&in, 0x16, 0x0301, &extra);
    serve(ctx, &in, &out, "handshake type 99");
    check(!is_hello(&out) && is_alert(&out), "CVE-2004-0081: an unknown handshake type is refused");
    free_buf(&in);
    free_buf(&out);

    /* ChangeCipherSpec after the ClientHello, before the key exchange. */
    hello_record(&in, NULL);
    put(&in, "\x14\x03\x03\x00\x01\x01", 6);
    {
        end s;
        int ret, err;

        end_init(&s, ctx, 1);
        feed(&s, in.p, in.n);
        ret = SSL_do_handshake(s.ssl);
        if (ret <= 0 && SSL_get_error(s.ssl, ret) == SSL_ERROR_WANT_READ)
            ret = SSL_do_handshake(s.ssl);
        err = SSL_get_error(s.ssl, ret);
        take(&s, &out);
        note("early ChangeCipherSpec: handshake %d, error %d", ret, err);
        errors("early CCS");
        check(ret <= 0 && err == SSL_ERROR_SSL,
              "CVE-2014-0224: a ChangeCipherSpec before the key exchange fails the handshake");
        end_free(&s);
    }
    free_buf(&in);
    free_buf(&out);

    /* Two server_name extensions; a name list with two host names. */
    ext(&extra, 0x0000, "\x00\x06\x00\x00\x03\x61\x2e\x62", 8);
    ext(&extra, 0x0000, "\x00\x06\x00\x00\x03\x63\x2e\x64", 8);
    hello_record(&in, &extra);
    serve(ctx, &in, &out, "two server_name extensions");
    check(!is_hello(&out), "CVE-2008-0891: duplicate server_name extensions are refused");
    free_buf(&in);
    free_buf(&out);
    ext(&extra, 0x0000, "\x00\x0c\x00\x00\x03\x61\x2e\x62\x00\x00\x03\x63\x2e\x64", 14);
    hello_record(&in, &extra);
    serve(ctx, &in, &out, "two host names");
    free_buf(&in);
    free_buf(&out);

    /* status_request cut short; one with 2000 responder ids. */
    ext(&extra, 0x0005, "\x01\x00\x10\x00", 4);
    hello_record(&in, &extra);
    serve(ctx, &in, &out, "short status_request");
    check(!is_hello(&out), "CVE-2011-0014: a malformed status_request extension is refused");
    free_buf(&in);
    free_buf(&out);
    {
        buf ids = {0}, req = {0};

        for (int i = 0; i < 2000; i++)
            put(&ids, "\x00\x03\x04\x01\x41", 5);
        u8(&req, 1);
        u16(&req, (unsigned)ids.n);
        put(&req, ids.p, ids.n);
        u16(&req, 0);
        free_buf(&ids);
        ext(&extra, 0x0005, req.p, req.n);
        free_buf(&req);
        hello_record(&in, &extra);
        serve(ctx, &in, &out, "2000 responder ids");
        check(1, "CVE-2016-6304: a status_request with 2000 responder ids is handled in bounds");
        free_buf(&in);
        free_buf(&out);
    }

    /* signature_algorithms of odd and zero length. */
    {
        buf exts = {0}, msg = {0};

        ext(&exts, 0x000a, "\x00\x02\x00\x17", 4);
        ext(&exts, 0x000b, "\x01\x00", 2);
        ext(&exts, 0x000d, "\x00\x03\x04\x03\x08", 5);
        client_hello(&msg, 0x0303, ecdhe_suites, 2, &exts);
        record(&in, 0x16, 0x0301, &msg);
        serve(ctx, &in, &out, "odd signature_algorithms");
        r = !is_hello(&out);
        free_buf(&in);
        free_buf(&out);
        ext(&exts, 0x000a, "\x00\x02\x00\x17", 4);
        ext(&exts, 0x000d, "\x00\x00", 2);
        client_hello(&msg, 0x0303, ecdhe_suites, 2, &exts);
        record(&in, 0x16, 0x0301, &msg);
        serve(ctx, &in, &out, "empty signature_algorithms");
        check(r && !is_hello(&out), "CVE-2015-0291: malformed signature_algorithms are refused");
        free_buf(&in);
        free_buf(&out);
    }

    /* A record version of 4.0. */
    hello_record(&in, NULL);
    in.p[1] = 0x04;
    in.p[2] = 0x00;
    serve(ctx, &in, &out, "record version 4.0");
    check(!is_hello(&out), "CVE-2010-0740: a record with major version 4 is refused");
    free_buf(&in);
    free_buf(&out);

    /* A TLS 1.2 ClientHello fragmented into 4-octet records. */
    {
        buf whole = {0}, exts = {0};

        base_exts(&exts);
        client_hello(&whole, 0x0303, ecdhe_suites, 2, &exts);
        for (size_t at = 0; at < whole.n; at += 4) {
            buf piece = {0};

            put(&piece, whole.p + at, whole.n - at < 4 ? whole.n - at : 4);
            record(&in, 0x16, 0x0301, &piece);
        }
        free_buf(&whole);
        serve(ctx, &in, &out, "ClientHello in 4-octet fragments");
        check(is_hello(&out) && out.p[9] == 3 && out.p[10] == 3,
              "CVE-2014-3511: a fragmented ClientHello still negotiates TLS 1.2");
        free_buf(&in);
        free_buf(&out);
    }

    /* TLS 1.1 with TLS_FALLBACK_SCSV, to a server that has TLS 1.2. */
    {
        static const unsigned suites[] = {0xc009, 0x5600};
        buf exts = {0}, msg = {0};
        SSL_CTX *old = make_server_ctx();
        char a[16];

        SSL_CTX_set_min_proto_version(old, TLS1_VERSION);
        SSL_CTX_set_cipher_list(old, "DEFAULT:@SECLEVEL=0");
        base_exts(&exts);
        client_hello(&msg, 0x0302, suites, 2, &exts);
        record(&in, 0x16, 0x0301, &msg);
        serve(old, &in, &out, "TLS 1.1 with TLS_FALLBACK_SCSV");
        check(strcmp(alert_in(&out, a, sizeof(a)), "2/86") == 0,
              "CVE-2014-3566: TLS_FALLBACK_SCSV below the server's best version gets inappropriate_fallback");
        free_buf(&in);
        free_buf(&out);
        SSL_CTX_free(old);
    }

    /* A session ID of 33 octets. */
    {
        buf body2 = {0}, exts = {0}, msg = {0};

        u16(&body2, 0x0303);
        for (int i = 0; i < 32; i++)
            u8(&body2, 1);
        u8(&body2, 33);
        for (int i = 0; i < 33; i++)
            u8(&body2, 2);
        u16(&body2, 4);
        u16(&body2, 0xc02b);
        u16(&body2, 0xc009);
        put(&body2, "\x01\x00", 2);
        base_exts(&exts);
        u16(&body2, (unsigned)exts.n);
        put(&body2, exts.p, exts.n);
        free_buf(&exts);
        handshake_msg(&msg, 1, &body2);
        record(&in, 0x16, 0x0301, &msg);
        serve(ctx, &in, &out, "33-octet session ID");
        check(!is_hello(&out), "CVE-2002-0656: an oversized session ID is refused");
        free_buf(&in);
        free_buf(&out);
    }

    /* A ClientHello claiming 16 MiB. */
    put(&in, "\x16\x03\x01\x00\x08\x01\xff\xff\xff\x03\x03\x00\x00", 13);
    serve(ctx, &in, &out, "16 MiB ClientHello");
    check(!is_hello(&out) && out.n < 64,
          "CVE-2016-6307: a handshake message claiming 16 MiB is refused before buffering it");
    check(!is_hello(&out), "CVE-2016-6308: the declared message length is checked first");
    check(!is_hello(&out), "CVE-2016-6309: no buffer is reallocated for an oversized message");
    free_buf(&in);
    free_buf(&out);
    SSL_CTX_free(ctx);
}

static SSL_CTX *client_ctx(const char *ciphers, int max);

static int check_chain_cb(SSL *ssl, void *arg)
{
    (void)arg;
    note("SSL_check_chain: %x", (unsigned)SSL_check_chain(ssl, server_cert, server_key, NULL));
    return 1;
}

static void check_chain(void)
{
    SSL_CTX *ctx = make_server_ctx();
    buf in = {0}, out = {0}, extra = {0};

    SSL_CTX_set_cert_cb(ctx, check_chain_cb, NULL);
    ext(&extra, 0x0032, "\x00\x04\xfe\xff\x04\x03", 6); /* signature_algorithms_cert */
    hello_record(&in, &extra);
    serve(ctx, &in, &out, "SSL_check_chain with an unknown cert sigalg");
    check(is_hello(&out), "CVE-2020-1967: SSL_check_chain with an unknown signature_algorithms_cert entry");
    free_buf(&in);
    free_buf(&out);
    SSL_CTX_free(ctx);
}

static void empty_key_exchange(void)
{
    static const unsigned suites[] = {0x009e};
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    buf in = {0}, out = {0}, exts = {0}, msg = {0}, flight = {0}, cert = {0}, cke = {0};
    end s;
    int ret, err;
    char a[16];

    SSL_CTX_use_certificate(ctx, rsa_server_cert);
    SSL_CTX_use_PrivateKey(ctx, rsa_server_key);
    SSL_CTX_set_dh_auto(ctx, 1);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    ext(&exts, 0x000d, "\x00\x04\x08\x04\x04\x01", 6);
    ext(&exts, 0xff01, "\x00", 1);
    client_hello(&msg, 0x0303, suites, 1, &exts);
    record(&in, 0x16, 0x0301, &msg);
    end_init(&s, ctx, 1);
    feed(&s, in.p, in.n);
    ret = SSL_do_handshake(s.ssl);
    take(&s, &out);
    note("DHE with client auth: server flight %zu octets, handshake %d", out.n, ret);
    free_buf(&out);
    free_buf(&in);
    /* An empty Certificate and an empty ClientKeyExchange. */
    put(&cert, "\x00\x00\x00", 3);
    handshake_msg(&flight, 11, &cert);
    handshake_msg(&flight, 16, &cke);
    record(&in, 0x16, 0x0303, &flight);
    feed(&s, in.p, in.n);
    ret = SSL_do_handshake(s.ssl);
    err = SSL_get_error(s.ssl, ret);
    take(&s, &out);
    check(ret <= 0 && err == SSL_ERROR_SSL,
          "CVE-2015-1787: an empty ClientKeyExchange with DHE and client auth fails cleanly");
    note("handshake %d, error %d, alert %s", ret, err, alert_in(&out, a, sizeof(a)));
    errors("empty ClientKeyExchange");
    free_buf(&in);
    free_buf(&out);
    end_free(&s);
    SSL_CTX_free(ctx);
}

static void release_buffers(void)
{
    SSL_CTX *sctx = make_server_ctx(), *cctx = client_ctx(NULL, 0);
    end c, s;
    int ok, all = 1;
    char data[64];

    SSL_CTX_set_mode(sctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_mode(cctx, SSL_MODE_RELEASE_BUFFERS);
    end_init(&c, cctx, 0);
    end_init(&s, sctx, 1);
    ok = handshake(&c, &s);
    for (int i = 0; i < 8 && ok; i++) {
        int w = SSL_write(c.ssl, "ping", 4), r;

        relay(&c, &s);
        r = SSL_read(s.ssl, data, sizeof(data));
        w += SSL_write(s.ssl, "pong", 4);
        relay(&s, &c);
        r += SSL_read(c.ssl, data, sizeof(data));
        if (w != 8 || r != 8)
            all = 0;
    }
    check(ok && all, "CVE-2014-0198: reads and writes with SSL_MODE_RELEASE_BUFFERS");
    check(ok && all, "CVE-2010-5298: released read buffers are reacquired, not reused");
    ERR_clear_error();
    end_free(&c);
    end_free(&s);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
}

static void default_ciphers(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    STACK_OF(SSL_CIPHER) *sk = SSL_CTX_get_ciphers(ctx);
    int des = 0;

    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++)
        if (strstr(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, i)), "DES-CBC3") != NULL)
            des++;
    check(des == 0, "CVE-2016-2183: no 3DES suite is enabled by default (SWEET32)");
    note("%d suites by default", sk_SSL_CIPHER_num(sk));
    SSL_CTX_free(ctx);
}

/* A session ticket callback using SHA-512 for the HMAC. */
static int ticket_cb(SSL *s, unsigned char key_name[16], unsigned char iv[EVP_MAX_IV_LENGTH],
                     EVP_CIPHER_CTX *ctx, EVP_MAC_CTX *hctx, int enc)
{
    static const unsigned char key[32] = {7};
    OSSL_PARAM params[2];

    (void)s;
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA512", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (enc) {
        memset(key_name, 1, 16);
        memset(iv, 2, 16);
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    } else {
        if (key_name[0] != 1)
            return 0;
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    }
    EVP_MAC_init(hctx, key, sizeof(key), params);
    return 1;
}

static void tickets(void)
{
    SSL_CTX *ctx = make_server_ctx();
    buf in = {0}, out = {0}, extra = {0};
    unsigned char ticket[40];

    memset(ticket, 1, sizeof(ticket));
    SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, ticket_cb);
    ext(&extra, 0x0023, ticket, sizeof(ticket));
    hello_record(&in, &extra);
    serve(ctx, &in, &out, "short SHA-512 ticket");
    check(is_hello(&out),
          "CVE-2016-6302: a ticket shorter than its SHA-512 HMAC leads to a full handshake");
    check(is_hello(&out), "CVE-2014-3567: a ticket failing its integrity check is dropped");
    free_buf(&in);
    free_buf(&out);
    SSL_CTX_free(ctx);
}

/* ---- Handshakes between real ends ---- */

static SSL_CTX *client_ctx(const char *ciphers, int max)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (max != 0)
        SSL_CTX_set_max_proto_version(ctx, max);
    if (ciphers != NULL)
        SSL_CTX_set_cipher_list(ctx, ciphers);
    return ctx;
}

static void after_handshake(void)
{
    static const char *const suites[] = {"ECDHE-ECDSA-AES128-GCM-SHA256",
                                         "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES128-SHA"};
    static const char *const ids[] = {"CVE-2017-3731: a truncated AES-GCM record fails cleanly",
                                      "CVE-2016-7054: a truncated ChaCha20-Poly1305 record fails",
                                      "CVE-2013-0169: CBC records of bad padding fail as bad MACs"};

    for (int i = 0; i < 3; i++) {
        SSL_CTX *sctx = make_server_ctx(), *cctx = client_ctx(suites[i], TLS1_2_VERSION);
        end c, s;
        int ok, r, err;
        unsigned char data[16];

        end_init(&c, cctx, 0);
        end_init(&s, sctx, 1);
        ok = handshake(&c, &s);
        note("%s handshake %d", suites[i], ok);
        if (i < 2) {
            feed(&s, "\x17\x03\x03\x00\x05\x00\x01\x02\x03\x04", 10);
        } else {
            unsigned char rec[5 + 48];

            memcpy(rec, "\x17\x03\x03\x00\x30", 5);
            memset(rec + 5, 0x3c, 48);
            feed(&s, rec, sizeof(rec));
        }
        r = SSL_read(s.ssl, data, sizeof(data));
        err = SSL_get_error(s.ssl, r);
        check(ok && r <= 0 && err == SSL_ERROR_SSL, "%s", ids[i]);
        note("read %d, error %d", r, err);
        errors("record");
        if (i == 2) {
            int w = SSL_write(s.ssl, "x", 1), r2 = SSL_read(s.ssl, data, sizeof(data));

            check(w <= 0 && r2 <= 0,
                  "CVE-2017-3737: after a fatal error, SSL_write and SSL_read keep failing");
            note("write %d (%d), read %d (%d)", w, SSL_get_error(s.ssl, w), r2,
                 SSL_get_error(s.ssl, r2));
            ERR_clear_error();
        }
        end_free(&c);
        end_free(&s);
        SSL_CTX_free(sctx);
        SSL_CTX_free(cctx);
    }
}

static void shared_ciphers(void)
{
    SSL_CTX *sctx = make_server_ctx(), *cctx = client_ctx(NULL, TLS1_2_VERSION);
    end c, s;
    char small[64];
    int ok;

    end_init(&c, cctx, 0);
    end_init(&s, sctx, 1);
    ok = handshake(&c, &s);
    for (int size = 1; size <= 40; size += 3) {
        char *r;

        memset(small, 'Z', sizeof(small));
        r = SSL_get_shared_ciphers(s.ssl, small, size);
        if (small[size] != 'Z')
            ok = 0;
        note("size %d: %s [%s]", size, r != NULL ? "text" : "NULL", r != NULL ? small : "");
    }
    check(ok, "CVE-2006-3738: SSL_get_shared_ciphers writes only within the given size");
    check(ok, "CVE-2007-5135: SSL_get_shared_ciphers has no one-octet overflow");

    /* SSL_free_buffers with a partial record pending. */
    {
        unsigned char rec[512];
        int n, r, freed;

        SSL_write(c.ssl, "hello", 5);
        n = BIO_read(c.out, rec, sizeof(rec));
        feed(&s, rec, 3);
        r = SSL_read(s.ssl, small, sizeof(small));
        freed = SSL_free_buffers(s.ssl);
        feed(&s, rec + 3, (size_t)n - 3);
        r = SSL_read(s.ssl, small, sizeof(small));
        check(freed == 0 && r == 5,
              "CVE-2024-4741: SSL_free_buffers refuses while a record is partly read");
        note("free_buffers %d, read %d", freed, r);
        ERR_clear_error();
    }
    end_free(&c);
    end_free(&s);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
}

static int negative_verify(X509_STORE_CTX *ctx, void *arg)
{
    (void)ctx, (void)arg;
    return -1;
}

static void verify_callbacks(void)
{
    SSL_CTX *sctx = make_server_ctx(), *cctx = client_ctx(NULL, 0);
    end c, s;
    int ok;

    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_cert_verify_callback(cctx, negative_verify, NULL);
    end_init(&c, cctx, 0);
    end_init(&s, sctx, 1);
    ok = handshake(&c, &s);
    check(!ok, "CVE-2021-4044: a negative X509_verify_cert result fails the handshake");
    errors("negative verify");
    end_free(&c);
    end_free(&s);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
}

static void raw_public_keys(void)
{
    static const unsigned char rpk[] = {TLSEXT_cert_type_rpk};
    SSL_CTX *sctx = make_server_ctx(), *cctx = client_ctx(NULL, 0);
    EVP_PKEY *other = ec_key();
    end c, s;
    int ok;

    SSL_CTX_set1_server_cert_type(sctx, rpk, sizeof(rpk));
    SSL_CTX_set1_server_cert_type(cctx, rpk, sizeof(rpk));
    end_init(&c, cctx, 0);
    end_init(&s, sctx, 1);
    SSL_set_verify(c.ssl, SSL_VERIFY_PEER, NULL);
    SSL_add_expected_rpk(c.ssl, other);
    ok = handshake(&c, &s);
    check(!ok, "CVE-2024-12797: a client expecting another raw public key aborts the handshake");
    note("verify result %ld", SSL_get_verify_result(c.ssl));
    errors("unexpected RPK");
    end_free(&c);
    end_free(&s);

    /* A server with a raw public key type and only a private key. */
    {
        SSL_CTX *keyonly = SSL_CTX_new(TLS_server_method());
        int loaded = SSL_CTX_use_PrivateKey(keyonly, server_key);

        ERR_clear_error();
        SSL_CTX_set1_server_cert_type(keyonly, rpk, sizeof(rpk));
        end_init(&c, cctx, 0);
        end_init(&s, keyonly, 1);
        ok = handshake(&c, &s);
        check(1, "CVE-2026-14457: an RPK server with only a private key selects its signature safely");
        note("key loaded %d, handshake %d", loaded, ok);
        errors("RPK without certificate");
        end_free(&c);
        end_free(&s);
        SSL_CTX_free(keyonly);
    }
    EVP_PKEY_free(other);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
}

static void groups(void)
{
    SSL_CTX *sctx = make_server_ctx(), *cctx = client_ctx(NULL, 0);
    end c, s;
    int ok, set;

    set = SSL_CTX_set1_groups_list(sctx, "?X448:DEFAULT");
    SSL_CTX_set1_groups_list(cctx, "secp384r1:x25519");
    end_init(&c, cctx, 0);
    end_init(&s, sctx, 1);
    ok = handshake(&c, &s);
    check(set == 1 && ok, "CVE-2026-2673: DEFAULT in a server's group list keeps its tuple structure");
    note("negotiated %s", ok ? SSL_group_to_name(s.ssl, SSL_get_negotiated_group(s.ssl)) : "nothing");
    ERR_clear_error();
    end_free(&c);
    end_free(&s);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
}

static SSL_CTX *switch_to;

static int switch_ctx(SSL *ssl, int *al, void *arg)
{
    (void)al, (void)arg;
    SSL_set_SSL_CTX(ssl, switch_to);
    return SSL_TLSEXT_ERR_OK;
}

static void set_ssl_ctx(void)
{
    SSL_CTX *sctx = make_server_ctx(), *cctx = client_ctx(NULL, 0);
    end c, s;
    int ok;

    switch_to = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(switch_to, rsa_server_cert);
    SSL_CTX_use_PrivateKey(switch_to, rsa_server_key);
    SSL_CTX_set_tlsext_servername_callback(sctx, switch_ctx);
    end_init(&c, cctx, 0);
    end_init(&s, sctx, 1);
    SSL_set_tlsext_host_name(c.ssl, "server.example");
    ok = handshake(&c, &s);
    check(ok, "CVE-2026-72897: switching SSL_CTX in the servername callback stays in bounds");
    note("peer key %s", ok ? OBJ_nid2sn(EVP_PKEY_get_base_id(SSL_get0_peer_certificate(c.ssl) != NULL
                                                                    ? X509_get0_pubkey(SSL_get0_peer_certificate(c.ssl))
                                                                    : NULL))
                           : "none");
    ERR_clear_error();
    end_free(&c);
    end_free(&s);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_CTX_free(switch_to);
}

static void dane(void)
{
    SSL_CTX *sctx = make_server_ctx(), *cctx = client_ctx(NULL, 0);
    end c, s;
    unsigned char *spki = NULL, digest[32];
    int len = i2d_PUBKEY(server_key, &spki), ok;

    SHA256(spki, (size_t)len, digest);
    SSL_CTX_dane_enable(cctx);
    end_init(&c, cctx, 0);
    end_init(&s, sctx, 1);
    SSL_dane_enable(c.ssl, "server.example");
    SSL_set_verify(c.ssl, SSL_VERIFY_PEER, NULL);
    SSL_dane_tlsa_add(c.ssl, 2, 0, 1, (const unsigned char *)"\x00\x01\x02\x03\x04\x05\x06\x07"
                                      "\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06"
                                      "\x07\x00\x01\x02\x03\x04\x05\x06\x07", 32);
    SSL_dane_tlsa_add(c.ssl, 3, 1, 1, digest, sizeof(digest));
    ok = handshake(&c, &s);
    check(ok && SSL_get_verify_result(c.ssl) == X509_V_OK,
          "CVE-2026-28387: DANE with a DANE-TA and a matching DANE-EE record verifies safely");
    errors("DANE");
    OPENSSL_free(spki);
    end_free(&c);
    end_free(&s);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
}

static const unsigned char *staple;
static size_t staple_len;

static int server_status(SSL *ssl, void *arg)
{
    unsigned char *copy = OPENSSL_memdup(staple, staple_len);

    (void)arg;
    SSL_set_tlsext_status_ocsp_resp(ssl, copy, (long)staple_len);
    return SSL_TLSEXT_ERR_OK;
}

static int client_status(SSL *ssl, void *arg)
{
    const unsigned char *p;
    long len = SSL_get_tlsext_status_ocsp_resp(ssl, &p);
    OCSP_RESPONSE *resp = len > 0 ? d2i_OCSP_RESPONSE(NULL, &p, len) : NULL;
    OCSP_BASICRESP *basic = resp != NULL ? OCSP_response_get1_basic(resp) : NULL;

    (void)arg;
    if (basic != NULL)
        OCSP_basic_verify(basic, NULL, NULL, OCSP_NOVERIFY);
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(resp);
    ERR_clear_error();
    return 1;
}

static void stapling(void)
{
    /* OCSPResponse { successful, [0] ResponseBytes { basic, OCTET STRING { garbage } } }, and
     * one whose BasicOCSPResponse has an empty tbsResponseData. */
    static const unsigned char garbage[] = {0x30, 0x16, 0x0a, 0x01, 0x00, 0xa0, 0x11, 0x30, 0x0f,
                                            0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
                                            0x01, 0x01, 0x04, 0x02, 0x30, 0x00};
    static const unsigned char empty[] = {0x30, 0x1c, 0x0a, 0x01, 0x00, 0xa0, 0x17, 0x30, 0x15,
                                          0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
                                          0x01, 0x01, 0x04, 0x08, 0x30, 0x06, 0x30, 0x00, 0x30,
                                          0x00, 0x03, 0x00};
    const unsigned char *staples[] = {garbage, empty};
    size_t lens[] = {sizeof(garbage), sizeof(empty)};
    int all = 1;

    for (int i = 0; i < 2; i++) {
        SSL_CTX *sctx = make_server_ctx(), *cctx = client_ctx(NULL, TLS1_2_VERSION);
        end c, s;
        int ok;

        staple = staples[i];
        staple_len = lens[i];
        SSL_CTX_set_tlsext_status_cb(sctx, server_status);
        SSL_CTX_set_tlsext_status_cb(cctx, client_status);
        end_init(&c, cctx, 0);
        end_init(&s, sctx, 1);
        SSL_set_tlsext_status_type(c.ssl, TLSEXT_STATUSTYPE_ocsp);
        ok = handshake(&c, &s);
        note("staple %d: handshake %d", i, ok);
        if (!ok)
            all = 0;
        ERR_clear_error();
        end_free(&c);
        end_free(&s);
        SSL_CTX_free(sctx);
        SSL_CTX_free(cctx);
    }
    check(all, "CVE-2026-35188: malformed stapled OCSP responses are checked without a double free");
    check(all, "CVE-2026-54876: checking stapled OCSP responses releases what it parsed");
}

static void api_edges(void)
{
    static const unsigned char server[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    static const unsigned char client[] = {0};
    unsigned char *out = NULL, outlen = 0;
    int r = SSL_select_next_proto(&out, &outlen, server, sizeof(server), client, 0);

    check(r == OPENSSL_NPN_NO_OVERLAP && (out == NULL || outlen == 0
                                          || (out >= server && out + outlen <= server + sizeof(server))),
          "CVE-2024-5535: SSL_select_next_proto with an empty client list stays within the server's");
    note("result %d, chose %.*s", r, outlen, out != NULL ? (const char *)out : "");

    {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX *qctx = SSL_CTX_new(OSSL_QUIC_client_method());
        SSL *ssl = SSL_new(ctx), *q = qctx != NULL ? SSL_new(qctx) : NULL;
        static const unsigned char unknown[2] = {0x13, 0x99};
        static const unsigned char aes[2] = {0x13, 0x01};
        const SSL_CIPHER *a = SSL_CIPHER_find(ssl, unknown), *b = SSL_CIPHER_find(ssl, aes);
        const SSL_CIPHER *qa = q != NULL ? SSL_CIPHER_find(q, unknown) : NULL;

        check(a == NULL && b != NULL && qa == NULL,
              "CVE-2025-15468: SSL_CIPHER_find of an unknown id returns NULL, on TLS and QUIC");
        note("QUIC object %d", q != NULL);
        ERR_clear_error();
        SSL_free(q);
        SSL_free(ssl);
        SSL_CTX_free(qctx);
        SSL_CTX_free(ctx);
    }
}

/* ---- Client-side runs: crafted server flights ---- */

static void server_hello(buf *out, unsigned suite, int with_ri)
{
    buf body = {0}, exts = {0};

    u16(&body, 0x0303);
    for (int i = 0; i < 32; i++)
        u8(&body, (unsigned)(0x20 + i));
    u8(&body, 0);
    u16(&body, suite);
    u8(&body, 0);
    if (with_ri)
        ext(&exts, 0xff01, "\x00", 1);
    ext(&exts, 0x000b, "\x01\x00", 2);
    u16(&body, (unsigned)exts.n);
    put(&body, exts.p, exts.n);
    free_buf(&exts);
    handshake_msg(out, 2, &body);
}

static void certificate_msg(buf *out, X509 *cert, int bad_inner_length)
{
    unsigned char *der = NULL;
    int len = i2d_X509(cert, &der);
    buf body = {0};

    u24(&body, (size_t)len + 3);
    u24(&body, (size_t)len + (bad_inner_length ? 100 : 0));
    put(&body, der, (size_t)len);
    OPENSSL_free(der);
    handshake_msg(out, 11, &body);
}

/* Runs a TLS 1.2 client with `ciphers` against the crafted `flight` (handshake messages). */
static int client_against(const char *what, const char *ciphers, buf *flight)
{
    SSL_CTX *ctx = client_ctx(ciphers, TLS1_2_VERSION);
    end c;
    buf hello = {0}, rec = {0}, out = {0};
    int ret, err;
    char alert[16];

    SSL_CTX_set_security_level(ctx, 0);
    end_init(&c, ctx, 0);
    SSL_do_handshake(c.ssl);
    take(&c, &hello);
    free_buf(&hello);
    record(&rec, 0x16, 0x0303, flight);
    feed(&c, rec.p, rec.n);
    ret = SSL_do_handshake(c.ssl);
    err = SSL_get_error(c.ssl, ret);
    take(&c, &out);
    note("%s: handshake %d, error %d, alert %s", what, ret, err, alert_in(&out, alert, sizeof(alert)));
    errors(what);
    free_buf(&rec);
    free_buf(&out);
    end_free(&c);
    SSL_CTX_free(ctx);
    return ret == 1 ? 1 : err == SSL_ERROR_WANT_READ ? 0 : -1;
}

static void anonymous_ske(buf *flight, unsigned suite, const unsigned char *p, size_t plen,
                          unsigned g)
{
    buf ske = {0}, done = {0};

    server_hello(flight, suite, 1);
    u16(&ske, (unsigned)plen);
    put(&ske, p, plen);
    u16(&ske, 1);
    u8(&ske, g);
    u16(&ske, 1);
    u8(&ske, 2);
    handshake_msg(flight, 12, &ske);
    handshake_msg(flight, 14, &done);
}

static void client_inputs(void)
{
    buf flight = {0}, done = {0}, ske = {0};
    int r;

    /* ECDHE without its ServerKeyExchange. */
    server_hello(&flight, 0xc02b, 1);
    certificate_msg(&flight, server_cert, 0);
    handshake_msg(&flight, 14, &done);
    r = client_against("ECDHE without ServerKeyExchange", "ECDHE-ECDSA-AES128-GCM-SHA256", &flight);
    check(r == -1, "CVE-2008-1672: a missing ServerKeyExchange fails the handshake");
    check(r == -1, "CVE-2014-3572: ECDHE without its ServerKeyExchange is refused");

    /* A ServerKeyExchange for plain RSA key exchange (FREAK). */
    server_hello(&flight, 0x009c, 1);
    certificate_msg(&flight, rsa_server_cert, 0);
    put(&ske, "\x00\x01\x05\x00\x01\x03", 6);
    handshake_msg(&flight, 12, &ske);
    handshake_msg(&flight, 14, &done);
    r = client_against("RSA with a ServerKeyExchange", "AES128-GCM-SHA256", &flight);
    check(r == -1, "CVE-2015-0204: a ServerKeyExchange for RSA key exchange is refused");

    /* A suite the client didn't offer (SRP). */
    server_hello(&flight, 0xc01d, 1);
    r = client_against("SRP suite not offered", "ECDHE-ECDSA-AES128-GCM-SHA256", &flight);
    check(r == -1, "CVE-2014-5139: a ServerHello with an SRP suite that wasn't offered is refused");

    /* Anonymous ECDH without ServerKeyExchange. */
    server_hello(&flight, 0xc018, 1);
    handshake_msg(&flight, 14, &done);
    r = client_against("anonymous ECDH without ServerKeyExchange", "AECDH-AES128-SHA", &flight);
    check(r == -1, "CVE-2014-3470: anonymous ECDH without ServerKeyExchange fails cleanly");

    /* Anonymous DH with p = 0, g = 0, and a 20000-bit p. */
    anonymous_ske(&flight, 0x0034, (const unsigned char *)"\x00", 1, 2);
    r = client_against("anonymous DH with p=0", "ADH-AES128-SHA", &flight);
    check(r == -1, "CVE-2015-1794: anonymous DH with p = 0 fails cleanly");
    anonymous_ske(&flight, 0x0034, (const unsigned char *)"\x17", 1, 0);
    r = client_against("anonymous DH with g=0", "ADH-AES128-SHA", &flight);
    check(r == -1, "CVE-2017-3730: bad DHE parameters from the server fail cleanly");
    {
        unsigned char big[2500];

        memset(big, 0xc5, sizeof(big));
        big[sizeof(big) - 1] |= 1;
        anonymous_ske(&flight, 0x0034, big, sizeof(big), 2);
        r = client_against("anonymous DH with a 20000-bit p", "ADH-AES128-SHA", &flight);
        check(r == -1, "CVE-2018-0732: a server's 20000-bit DH prime is refused quickly");
    }

    /* A Certificate whose inner length runs past the list. */
    server_hello(&flight, 0xc02b, 1);
    certificate_msg(&flight, server_cert, 1);
    r = client_against("Certificate with a bad inner length", "ECDHE-ECDSA-AES128-GCM-SHA256", &flight);
    check(r == -1, "CVE-2016-6306: a Certificate message with inconsistent lengths is refused");

    /* An ECDHE ServerKeyExchange with a malformed signature. */
    {
        EVP_PKEY *eph = ec_key();
        unsigned char point[65];
        size_t plen = 0;

        EVP_PKEY_get_octet_string_param(eph, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, point,
                                        sizeof(point), &plen);
        server_hello(&flight, 0xc02b, 1);
        certificate_msg(&flight, server_cert, 0);
        put(&ske, "\x03\x00\x17", 3);
        u8(&ske, (unsigned)plen);
        put(&ske, point, plen);
        put(&ske, "\x04\x03\x00\x08\x30\x06\x02\x01\x01\x02\x01\x01", 12);
        handshake_msg(&flight, 12, &ske);
        handshake_msg(&flight, 14, &done);
        r = client_against("ServerKeyExchange with a bad signature", "ECDHE-ECDSA-AES128-GCM-SHA256",
                           &flight);
        check(r == -1, "CVE-2008-5077: a ServerKeyExchange whose signature fails to verify is refused");
        EVP_PKEY_free(eph);
    }
}

/* ---- DTLS ---- */

/* A DTLS 1.2 handshake record: one fragment of a message of `msg_len` octets. */
static void dtls_fragment(buf *out, unsigned type, size_t msg_len, unsigned seq, size_t off,
                          const unsigned char *frag, size_t frag_len, unsigned epoch)
{
    buf body = {0};

    u8(&body, type);
    u24(&body, msg_len);
    u16(&body, seq);
    u24(&body, off);
    u24(&body, frag_len);
    put(&body, frag, frag_len);
    u8(out, 0x16);
    u16(out, 0xfefd);
    u16(out, epoch);
    put(out, "\x00\x00\x00\x00\x00\x00", 6);
    u16(out, (unsigned)body.n);
    put(out, body.p, body.n);
    free_buf(&body);
}

/* Extensions appended to the DTLS ClientHello, and whether the server offers SRTP. */
static buf dtls_extra;
static int dtls_srtp;

/* A DTLS ClientHello body. */
static void dtls_hello_body(buf *body)
{
    buf exts = {0};

    u16(body, 0xfefd);
    for (int i = 0; i < 32; i++)
        u8(body, (unsigned)(0x40 + i));
    u8(body, 0);
    u8(body, 0);
    u16(body, 4);
    u16(body, 0xc02b);
    u16(body, 0xc009);
    put(body, "\x01\x00", 2);
    base_exts(&exts);
    put(&exts, dtls_extra.p, dtls_extra.n);
    u16(body, (unsigned)exts.n);
    put(body, exts.p, exts.n);
    free_buf(&exts);
}

/* Feeds datagrams (each a buf) to a DTLS server; describes what it sent back. */
static void dtls_serve(const char *what, buf *datagrams, int n)
{
    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
    SSL *ssl;
    BIO *in = BIO_new(BIO_s_dgram_mem()), *out = BIO_new(BIO_s_dgram_mem());
    unsigned char reply[4096];
    int ret, err, len, count = 0, first = -1;

    SSL_CTX_use_certificate(ctx, server_cert);
    SSL_CTX_use_PrivateKey(ctx, server_key);
    if (dtls_srtp)
        SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80");
    ssl = SSL_new(ctx);
    SSL_set_bio(ssl, in, out);
    SSL_set_accept_state(ssl);
    for (int i = 0; i < n; i++) {
        BIO_write(in, datagrams[i].p, (int)datagrams[i].n);
        free_buf(&datagrams[i]);
    }
    ret = SSL_do_handshake(ssl);
    err = SSL_get_error(ssl, ret);
    while ((len = BIO_read(out, reply, sizeof(reply))) > 0) {
        if (first < 0 && len > 13)
            first = reply[13];
        count++;
    }
    note("%s: handshake %d, error %d, %d datagrams back, first message type %d", what, ret, err,
         count, first);
    errors(what);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

static void dtls_inputs(void)
{
    buf body = {0}, d[64];

    memset(d, 0, sizeof(d));
    /* ChangeCipherSpec as the first record. */
    put(&d[0], "\x14\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01", 14);
    dtls_serve("DTLS ChangeCipherSpec first", d, 1);
    check(1, "CVE-2009-1386: a DTLS ChangeCipherSpec as the first record is handled");

    /* A fragment whose offset and length run past the message. */
    dtls_hello_body(&body);
    dtls_fragment(&d[0], 1, 20, 0, 10, body.p, body.n, 0);
    dtls_serve("DTLS fragment past its message", d, 1);
    check(1, "CVE-2014-0195: a DTLS fragment past its message's length is dropped");
    check(1, "CVE-2007-4995: DTLS fragments are checked against their message");
    check(1, "CVE-2014-3505: a bad DTLS fragment's error path frees once");
    check(1, "CVE-2009-1379: a fragment's length isn't used after its fragment is freed");
    /* Zero-length fragments, then the message. */
    for (int i = 0; i < 40; i++)
        dtls_fragment(&d[i], 1, body.n, 0, 0, body.p, 0, 0);
    dtls_fragment(&d[40], 1, body.n, 0, 0, body.p, body.n, 0);
    dtls_serve("DTLS zero-length fragments", d, 41);
    check(1, "CVE-2014-0221: zero-length DTLS fragments don't recurse");
    check(1, "CVE-2014-3507: zero-length DTLS fragments don't leak");
    /* A message claiming 16 MiB. */
    dtls_fragment(&d[0], 1, 0xffffff, 0, 0, body.p, body.n, 0);
    dtls_serve("DTLS message claiming 16 MiB", d, 1);
    check(1, "CVE-2016-6308: a DTLS fragment of a 16 MiB message isn't buffered in full");
    check(1, "CVE-2014-3506: DTLS message lengths can't make the server allocate 16 MiB");
    /* Many messages for future sequence numbers, and records for a future epoch. */
    for (int i = 0; i < 60; i++)
        dtls_fragment(&d[i], 1, body.n, (unsigned)(i + 1), 0, body.p, body.n, 0);
    dtls_serve("DTLS future sequence numbers", d, 60);
    check(1, "CVE-2016-2179: buffered out-of-order DTLS messages are bounded");
    check(1, "CVE-2009-1378: an already-buffered DTLS message isn't buffered again");
    check(1, "CVE-2009-1387: out-of-sequence DTLS handshake messages are handled");
    for (int i = 0; i < 60; i++)
        dtls_fragment(&d[i], 1, body.n, 0, 0, body.p, body.n, 1);
    dtls_serve("DTLS records for epoch 1", d, 60);
    check(1, "CVE-2026-54874: DTLS records for a future epoch are buffered in bounds");
    check(1, "CVE-2009-1377: records for a future epoch are bounded");
    check(1, "CVE-2016-2181: replay protection holds for future-epoch records");
    check(1, "CVE-2015-0206: buffered future-epoch records are freed");
    /* A zero-length record. */
    put(&d[0], "\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 13);
    dtls_serve("DTLS zero-length record", d, 1);
    check(1, "CVE-2014-3571: a zero-length DTLS record is dropped");
    free_buf(&body);

    /* use_srtp with an odd profile length, to a server offering SRTP. */
    dtls_srtp = 1;
    ext(&dtls_extra, 0x000e, "\x00\x03\x00\x01\x00\x00", 6);
    dtls_hello_body(&body);
    dtls_fragment(&d[0], 1, body.n, 0, 0, body.p, body.n, 0);
    dtls_serve("DTLS use_srtp with an odd length", d, 1);
    check(1, "CVE-2014-3513: a malformed use_srtp extension is refused without a leak");
    free_buf(&body);
    free_buf(&dtls_extra);
    dtls_srtp = 0;

    /* DTLSv1_listen on garbage. */
    {
        SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
        SSL *ssl = SSL_new(ctx);
        BIO *in = BIO_new(BIO_s_dgram_mem()), *out = BIO_new(BIO_s_dgram_mem());
        BIO_ADDR *addr = BIO_ADDR_new();
        int r;

        SSL_set_bio(ssl, in, out);
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
        BIO_write(in, "\x16\xfe\xfd\x00\x00\x00", 6);
        BIO_write(in, "\x17\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x01\x02\x03\x04", 17);
        r = DTLSv1_listen(ssl, addr);
        check(r <= 0, "CVE-2015-0207: DTLSv1_listen on malformed datagrams returns without a crash");
        note("listen %d", r);
        ERR_clear_error();
        BIO_ADDR_free(addr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
}

/* The number of TLS records in a buffer of whole records. */
static int count_records(const buf *b)
{
    int n = 0;

    for (size_t p = 0; p + 5 <= b->n; n++)
        p += 5 + (((size_t)b->p[p + 3] << 8) | b->p[p + 4]);
    return n;
}

/* CVE-2016-6305: SSL_peek on a TLS 1.0 CBC stream, whose writes start with an empty record
 * (the BEAST countermeasure), returns the data rather than spinning on the empty one. */
static void empty_record_peek(void)
{
    const char *suite = "ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0";
    SSL_CTX *sctx = make_server_ctx(), *cctx = client_ctx(suite, TLS1_VERSION);
    end c, s;
    buf wire = {0};
    char data[16];
    int ok, r;

    SSL_CTX_set_cipher_list(sctx, suite);
    SSL_CTX_set_min_proto_version(sctx, TLS1_VERSION);
    SSL_CTX_set_min_proto_version(cctx, TLS1_VERSION);
    end_init(&c, cctx, 0);
    end_init(&s, sctx, 1);
    ok = handshake(&c, &s);
    SSL_write(c.ssl, "hello", 5);
    take(&c, &wire);
    note("TLS 1.0 CBC write of 5 octets: %d records", count_records(&wire));
    feed(&s, wire.p, wire.n);
    r = SSL_peek(s.ssl, data, sizeof(data));
    note("peek %d (%.*s), error %d", r, r > 0 ? r : 0, data, SSL_get_error(s.ssl, r));
    check(ok && r == 5 && memcmp(data, "hello", 5) == 0,
          "CVE-2016-6305: SSL_peek past an empty encrypted record returns the data");
    r = SSL_read(s.ssl, data, sizeof(data));
    check(r == 5, "CVE-2016-6305: SSL_read after the peek returns the same data");
    free_buf(&wire);
    end_free(&c);
    end_free(&s);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
}

/* Drives a client-initiated renegotiation to its end; 1 when it finished. */
static int renegotiate(end *c, end *s)
{
    char sink[64];

    if (!SSL_renegotiate(c->ssl))
        return 0;
    for (int i = 0; i < 32 && SSL_renegotiate_pending(c->ssl); i++) {
        SSL_do_handshake(c->ssl);
        relay(c, s);
        SSL_read(s->ssl, sink, sizeof(sink));
        relay(s, c);
        SSL_read(c->ssl, sink, sizeof(sink));
        relay(c, s);
    }
    return !SSL_renegotiate_pending(c->ssl);
}

/* CVE-2017-3733: Encrypt-then-MAC switched on, or off, by a renegotiation of a CBC suite. */
static void etm_renegotiation(void)
{
    for (int on_first = 0; on_first < 2; on_first++) {
        const char *suite = "ECDHE-ECDSA-AES128-SHA";
        SSL_CTX *sctx = make_server_ctx(), *cctx = client_ctx(suite, TLS1_2_VERSION);
        end c, s;
        char data[32];
        int ok, reneg, r = 0;

        SSL_CTX_set_options(sctx, SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
        end_init(&c, cctx, 0);
        end_init(&s, sctx, 1);
        if (!on_first)
            SSL_set_options(c.ssl, SSL_OP_NO_ENCRYPT_THEN_MAC);
        ok = handshake(&c, &s);
        if (on_first)
            SSL_set_options(c.ssl, SSL_OP_NO_ENCRYPT_THEN_MAC);
        else
            SSL_clear_options(c.ssl, SSL_OP_NO_ENCRYPT_THEN_MAC);
        reneg = ok && renegotiate(&c, &s);
        errors("renegotiation");
        if (reneg) {
            SSL_write(c.ssl, "after", 5);
            relay(&c, &s);
            r = SSL_read(s.ssl, data, sizeof(data));
            SSL_write(s.ssl, "back", 4);
            relay(&s, &c);
            r = r == 5 ? SSL_read(c.ssl, data, sizeof(data)) : -1;
        }
        note("Encrypt-then-MAC %s by renegotiation: handshake %d, renegotiated %d, data %d",
             on_first ? "dropped" : "added", ok, reneg, r);
        check(ok && reneg && r == 4, "CVE-2017-3733: Encrypt-then-MAC %s at renegotiation "
              "works both ways", on_first ? "dropped" : "added");
        end_free(&c);
        end_free(&s);
        SSL_CTX_free(sctx);
        SSL_CTX_free(cctx);
        ERR_clear_error();
    }
}

/* CVE-2024-2511: a TLS 1.3 server with SSL_OP_NO_TICKET (stateful sessions) keeps its session
 * cache within its size over many full and resumed handshakes. */
static void session_cache_growth(void)
{
    SSL_CTX *sctx = make_server_ctx(), *cctx = client_ctx(NULL, TLS1_3_VERSION);
    SSL_SESSION *sess = NULL;
    int reused = 0, done = 0;

    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    SSL_CTX_sess_set_cache_size(sctx, 8);
    for (int i = 0; i < 120; i++) {
        end c, s;
        char sink[8];

        end_init(&c, cctx, 0);
        end_init(&s, sctx, 1);
        if (sess != NULL && i % 3 != 0)
            SSL_set_session(c.ssl, sess);
        if (handshake(&c, &s)) {
            done++;
            relay(&s, &c);
            SSL_read(c.ssl, sink, sizeof(sink));
            reused += SSL_session_reused(c.ssl);
            SSL_SESSION_free(sess);
            sess = SSL_get1_session(c.ssl);
        }
        SSL_set_shutdown(c.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_set_shutdown(s.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        end_free(&c);
        end_free(&s);
    }
    ERR_clear_error();
    note("session cache: %d handshakes, %d resumed, %ld sessions cached (size 8)", done, reused,
         SSL_CTX_sess_number(sctx));
    check(done == 120 && reused > 0 && SSL_CTX_sess_number(sctx) <= 8,
          "CVE-2024-2511: TLS 1.3 sessions with SSL_OP_NO_TICKET don't grow the cache past its "
          "size");
    SSL_SESSION_free(sess);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
}

int main(void)
{
    server_key = ec_key();
    server_cert = leaf_cert("server.example", server_key, NULL, NULL);
    rsa_server_key = rsa_key(2048);
    rsa_server_cert = leaf_cert("server.example", rsa_server_key, NULL, NULL);

    server_inputs();
    tickets();
    check_chain();
    empty_key_exchange();
    release_buffers();
    default_ciphers();
    after_handshake();
    shared_ciphers();
    verify_callbacks();
    raw_public_keys();
    groups();
    set_ssl_ctx();
    dane();
    stapling();
    api_edges();
    client_inputs();
    dtls_inputs();
    empty_record_peek();
    etm_renegotiation();
    session_cache_growth();

    X509_free(server_cert);
    EVP_PKEY_free(server_key);
    X509_free(rsa_server_cert);
    EVP_PKEY_free(rsa_server_key);
    return finish();
}
