/*
 * CVE regression checks for thread races: several threads run in-memory handshakes at once,
 * sharing an SSL_CTX, its session cache, and one SSL_SESSION they all resume, in the ways the
 * racy code paths did (extension data in the server's session cache, ECDH state, a resumed
 * session's point formats, a renewed ticket written into the shared session, a PSK identity
 * hint). A race can't be forced deterministically; many iterations make it likely, and each
 * check needs every handshake to succeed, resume as it should, and nothing to crash. The
 * output is the same on every run: counts are compared with the number expected.
 */
#include "cve.h"

#include <pthread.h>

#include <openssl/core_names.h>

enum { THREADS = 8, ROUNDS = 40 };

static EVP_PKEY *server_key;
static X509 *server_cert;

typedef struct {
    SSL_CTX *cctx, *sctx;
    SSL_SESSION *sess; /* resumed by every handshake, if set */
    const char *sni;
    int ok, resumed;
} job;

static void *worker(void *arg)
{
    job *j = arg;

    for (int i = 0; i < ROUNDS; i++) {
        end c, s;

        end_init(&c, j->cctx, 0);
        end_init(&s, j->sctx, 1);
        if (j->sess != NULL)
            SSL_set_session(c.ssl, j->sess);
        if (j->sni != NULL)
            SSL_set_tlsext_host_name(c.ssl, j->sni);
        if (handshake(&c, &s)) {
            j->ok++;
            j->resumed += SSL_session_reused(c.ssl);
        }
        ERR_clear_error();
        SSL_set_shutdown(c.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_set_shutdown(s.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        end_free(&c);
        end_free(&s);
    }
    ERR_clear_error();
    return NULL;
}

/* Runs THREADS workers on the contexts; checks every handshake completed (and resumed, when
 * `resume`). */
static void race(const char *cve, const char *what, SSL_CTX *cctx, SSL_CTX *sctx,
                 SSL_SESSION *sess, const char *sni, int resume)
{
    pthread_t t[THREADS];
    job jobs[THREADS];
    int ok = 0, resumed = 0, started = 0;

    for (int i = 0; i < THREADS; i++) {
        jobs[i] = (job){ cctx, sctx, sess, sni, 0, 0 };
        if (pthread_create(&t[i], NULL, worker, &jobs[i]) == 0)
            started++;
        else
            break;
    }
    for (int i = 0; i < started; i++) {
        pthread_join(t[i], NULL);
        ok += jobs[i].ok;
        resumed += jobs[i].resumed;
    }
    note("%s: %d threads, %s of %d handshakes completed, %s resumed", what, started,
         ok == THREADS * ROUNDS ? "all" : "not all", THREADS * ROUNDS,
         resumed == THREADS * ROUNDS ? "all" : resumed == 0 ? "none" : "some");
    check(started == THREADS && ok == THREADS * ROUNDS
          && (!resume || resumed == THREADS * ROUNDS),
          "%s: %s, concurrently, without a race", cve, what);
}

static SSL_CTX *server_ctx2(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    SSL_CTX_use_certificate(ctx, server_cert);
    SSL_CTX_use_PrivateKey(ctx, server_key);
    return ctx;
}

static SSL_CTX *client_ctx2(int max, const char *ciphers)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    SSL_CTX_set_max_proto_version(ctx, max);
    if (ciphers != NULL)
        SSL_CTX_set_cipher_list(ctx, ciphers);
    return ctx;
}

/* One handshake on this thread; the client's session (to share), or NULL. */
static SSL_SESSION *first_session(SSL_CTX *cctx, SSL_CTX *sctx, const char *sni)
{
    end c, s;
    SSL_SESSION *sess = NULL;

    end_init(&c, cctx, 0);
    end_init(&s, sctx, 1);
    if (sni != NULL)
        SSL_set_tlsext_host_name(c.ssl, sni);
    if (handshake(&c, &s))
        sess = SSL_get1_session(c.ssl);
    SSL_set_shutdown(c.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_set_shutdown(s.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    end_free(&c);
    end_free(&s);
    ERR_clear_error();
    return sess;
}

/* A ticket key callback that asks for a new ticket on every resumption. */
static int renewing_ticket_cb(SSL *s, unsigned char key_name[16],
                              unsigned char iv[EVP_MAX_IV_LENGTH], EVP_CIPHER_CTX *ctx,
                              EVP_MAC_CTX *hctx, int enc)
{
    static const unsigned char key[32] = {9};
    OSSL_PARAM params[2];

    (void)s;
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (enc) {
        memset(key_name, 3, 16);
        memset(iv, 4, 16);
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    } else {
        if (key_name[0] != 3)
            return 0;
        EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    }
    EVP_MAC_init(hctx, key, sizeof(key), params);
    return enc ? 1 : 2;
}

static unsigned int psk_client(SSL *ssl, const char *hint, char *identity,
                               unsigned int max_identity_len, unsigned char *psk,
                               unsigned int max_psk_len)
{
    (void)ssl;
    if (hint == NULL || strcmp(hint, "the hint") != 0 || max_identity_len < 8 || max_psk_len < 16)
        return 0;
    strcpy(identity, "client");
    memset(psk, 0x42, 16);
    return 16;
}

static unsigned int psk_server(SSL *ssl, const char *identity, unsigned char *psk,
                               unsigned int max_psk_len)
{
    (void)ssl;
    if (strcmp(identity, "client") != 0 || max_psk_len < 16)
        return 0;
    memset(psk, 0x42, 16);
    return 16;
}

int main(void)
{
    SSL_CTX *sctx, *cctx;
    SSL_SESSION *sess;

    server_key = ec_key();
    server_cert = leaf_cert("server.example", server_key, NULL, NULL);

    /* CVE-2010-3864: the server's session cache and extension data (SNI), shared. */
    sctx = server_ctx2();
    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    cctx = client_ctx2(TLS1_2_VERSION, NULL);
    sess = first_session(cctx, sctx, "server.example");
    race("CVE-2010-3864", "full handshakes with SNI against one server's session cache", cctx,
         sctx, NULL, "server.example", 0);
    race("CVE-2010-3864", "resumptions from one server's session cache", cctx, sctx, sess,
         "server.example", 1);
    SSL_SESSION_free(sess);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);

    /* CVE-2011-3210: ephemeral ECDH on one server context. */
    sctx = server_ctx2();
    cctx = client_ctx2(TLS1_2_VERSION, "ECDHE-ECDSA-AES128-GCM-SHA256");
    race("CVE-2011-3210", "ECDHE handshakes on one server context", cctx, sctx, NULL, NULL, 0);

    /* CVE-2014-3509: one session, with its EC point formats, resumed by every thread. */
    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    sess = first_session(cctx, sctx, NULL);
    race("CVE-2014-3509", "one ECDHE session resumed on every thread", cctx, sctx, sess, NULL, 1);
    SSL_SESSION_free(sess);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);

    /* CVE-2015-1791: one TLS 1.2 session resumed by every thread, its ticket renewed each time. */
    sctx = server_ctx2();
    SSL_CTX_set_tlsext_ticket_key_evp_cb(sctx, renewing_ticket_cb);
    cctx = client_ctx2(TLS1_2_VERSION, NULL);
    sess = first_session(cctx, sctx, NULL);
    note("ticket renewal: the first session %s a ticket", sess != NULL
         && SSL_SESSION_has_ticket(sess) ? "has" : "has no");
    race("CVE-2015-1791", "one session whose ticket is renewed on every resumption", cctx, sctx,
         sess, NULL, 1);
    SSL_SESSION_free(sess);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);

    /* CVE-2015-3196: a PSK session with an identity hint, resumed by every thread. */
    sctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_cipher_list(sctx, "PSK-AES128-CBC-SHA");
    SSL_CTX_use_psk_identity_hint(sctx, "the hint");
    SSL_CTX_set_psk_server_callback(sctx, psk_server);
    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    cctx = client_ctx2(TLS1_2_VERSION, "PSK-AES128-CBC-SHA");
    SSL_CTX_set_psk_client_callback(cctx, psk_client);
    sess = first_session(cctx, sctx, NULL);
    race("CVE-2015-3196", "one PSK session with an identity hint resumed on every thread", cctx,
         sctx, sess, NULL, 1);
    SSL_SESSION_free(sess);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);

    X509_free(server_cert);
    EVP_PKEY_free(server_key);
    return finish();
}
