/*
 * Conformance test for TLS 1.0-1.2's stitched CBC-and-HMAC ciphers: when an engine supplies
 * AES-128-CBC-HMAC-SHA1 (a CBC cipher flagged EVP_CIPH_FLAG_AEAD_CIPHER), libssl uses it in
 * place of AES-128-CBC and HMAC-SHA1 for a MAC-then-encrypt suite: it keys it with
 * EVP_CTRL_AEAD_SET_MAC_KEY, passes each record's header with EVP_CTRL_AEAD_TLS1_AAD, and lets
 * EVP_Cipher MAC, pad and encrypt the record (and check it on the way in). The engine's cipher
 * here, like OpenSSL's ossltest engine's, encrypts nothing and writes a known MAC, so the
 * records it sees can be printed; TLS 1.2 (explicit IVs) and TLS 1.0 (chained IVs and empty
 * fragments).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
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

/* ---- The stitched cipher: no encryption, a known MAC (0xAA octets), real padding. ---- */

#define MAC_LEN 20
#define BLOCK 16
#define NO_PAYLOAD ((size_t)-1)

struct stitched_ctx {
    size_t payload; /* the next record's payload length (encrypting), or NO_PAYLOAD */
    unsigned int version;
};

static int inits, mac_keys, aads, seals, opens, bad_opens;
static unsigned char last_payload[64];
static size_t last_payload_len;

static struct stitched_ctx *state(EVP_CIPHER_CTX *ctx)
{
    return EVP_CIPHER_CTX_get_cipher_data(ctx);
}

static int stitched_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                         const unsigned char *iv, int enc)
{
    (void)key;
    (void)iv;
    (void)enc;
    inits++;
    state(ctx)->payload = NO_PAYLOAD;
    return 1;
}

static int stitched_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
                           size_t len)
{
    struct stitched_ctx *s = state(ctx);
    size_t plen = s->payload, eiv = s->version >= TLS1_1_VERSION ? BLOCK : 0, i;
    unsigned int pad;

    s->payload = NO_PAYLOAD;
    if (len % BLOCK != 0)
        return 0;
    memmove(out, in, len);
    if (EVP_CIPHER_CTX_is_encrypting(ctx)) {
        if (plen == NO_PAYLOAD)
            return 1;
        seals++;
        last_payload_len = plen - eiv < sizeof(last_payload) ? plen - eiv : sizeof(last_payload);
        memcpy(last_payload, out + eiv, last_payload_len);
        memset(out + plen, 0xAA, MAC_LEN);
        pad = (unsigned int)(len - plen - MAC_LEN - 1);
        for (i = plen + MAC_LEN; i < len; i++)
            out[i] = (unsigned char)pad;
        return 1;
    }
    opens++;
    if (len < eiv + MAC_LEN + 1)
        return 0;
    pad = out[len - 1];
    if (pad + 1 + MAC_LEN > len - eiv) {
        bad_opens++;
        return 0;
    }
    for (i = len - pad - 1; i < len; i++)
        if (out[i] != pad) {
            bad_opens++;
            return 0;
        }
    return 1;
}

static int stitched_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    struct stitched_ctx *s = state(ctx);
    unsigned char *p = ptr;
    size_t len;

    switch (type) {
    case EVP_CTRL_AEAD_SET_MAC_KEY:
        mac_keys++;
        return arg == MAC_LEN;
    case EVP_CTRL_AEAD_TLS1_AAD:
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return -1;
        aads++;
        len = (size_t)p[arg - 2] << 8 | p[arg - 1];
        s->version = (unsigned int)p[arg - 4] << 8 | p[arg - 3];
        if (EVP_CIPHER_CTX_is_encrypting(ctx)) {
            s->payload = len;
            /* The room for the MAC and the padding the record needs. */
            return (int)(((len + MAC_LEN + BLOCK) & ~(size_t)(BLOCK - 1)) - len);
        }
        return MAC_LEN;
    default:
        return -1;
    }
}

static EVP_CIPHER *stitched;

static int engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    static const int list[] = { NID_aes_128_cbc_hmac_sha1 };

    (void)e;
    if (cipher == NULL) {
        *nids = list;
        return 1;
    }
    *cipher = nid == NID_aes_128_cbc_hmac_sha1 ? stitched : NULL;
    return *cipher != NULL;
}

/* ---- TLS ---- */

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

static SSL_CTX *context(int server, int version)
{
    SSL_CTX *ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    X509 *x = cert(server ? SERVER_PEM : CA_PEM);

    if (ctx == NULL || x == NULL) {
        printf("Bail out! context\n");
        exit(1);
    }
    if (server) {
        EVP_PKEY *k = key(SERVER_KEY_PEM);

        if (k == NULL || SSL_CTX_use_certificate(ctx, x) != 1
            || SSL_CTX_use_PrivateKey(ctx, k) != 1) {
            printf("Bail out! server key\n");
            exit(1);
        }
        EVP_PKEY_free(k);
    } else {
        X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), x);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }
    X509_free(x);
    SSL_CTX_set_min_proto_version(ctx, version);
    SSL_CTX_set_max_proto_version(ctx, version);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0");
    /* MAC-then-encrypt: encrypt-then-MAC would keep the cipher and the MAC apart. */
    SSL_CTX_set_options(ctx, SSL_OP_NO_ENCRYPT_THEN_MAC);
    return ctx;
}

static int run(SSL *c, SSL *s)
{
    int cdone = 0, sdone = 0, round;

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
                return e;
            }
        }
    }
    return cdone && sdone ? 0 : -1;
}

static void counts(const char *when)
{
    printf("  %s: inits %d, MAC keys %d, AADs %d, seals %d, opens %d (bad %d)\n", when, inits,
           mac_keys, aads, seals, opens, bad_opens);
}

static void connection(const char *label, int version)
{
    SSL_CTX *cctx = context(0, version), *sctx = context(1, version);
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    BIO *a = NULL, *b = NULL;
    char buf[64];
    int n;

    printf("# %s\n", label);
    inits = mac_keys = aads = seals = opens = bad_opens = 0;
    if (c == NULL || s == NULL || BIO_new_bio_pair(&a, 0, &b, 0) != 1) {
        printf("Bail out! connection\n");
        exit(1);
    }
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    check(run(c, s) == 0, "the handshake through the stitched cipher");
    printf("  suite %s, %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(c)), SSL_get_version(c));
    counts("handshake");
    n = SSL_write(c, "stitched hello", 14);
    printf("  client wrote %d; the cipher saw %d octets: %.*s\n", n, (int)last_payload_len,
           (int)last_payload_len, (const char *)last_payload);
    n = SSL_read(s, buf, sizeof(buf));
    printf("  server read %d: %.*s\n", n, n > 0 ? n : 0, buf);
    counts("one write");
    check(n == 14 && memcmp(buf, "stitched hello", 14) == 0, "application data both ways");
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    ENGINE *e = ENGINE_new();

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    stitched = EVP_CIPHER_meth_new(NID_aes_128_cbc_hmac_sha1, BLOCK, 16);
    if (e == NULL || stitched == NULL
        || !EVP_CIPHER_meth_set_iv_length(stitched, BLOCK)
        || !EVP_CIPHER_meth_set_flags(stitched, EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1
                                                    | EVP_CIPH_FLAG_AEAD_CIPHER)
        || !EVP_CIPHER_meth_set_init(stitched, stitched_init)
        || !EVP_CIPHER_meth_set_do_cipher(stitched, stitched_cipher)
        || !EVP_CIPHER_meth_set_ctrl(stitched, stitched_ctrl)
        || !EVP_CIPHER_meth_set_impl_ctx_size(stitched, sizeof(struct stitched_ctx))) {
        printf("Bail out! cipher\n");
        return 1;
    }
    check(ENGINE_set_id(e, "rustyssl-stitched") == 1 && ENGINE_set_name(e, "stitched") == 1
              && ENGINE_set_ciphers(e, engine_ciphers) == 1 && ENGINE_init(e) == 1
              && ENGINE_set_default_ciphers(e) == 1,
          "an engine with AES-128-CBC-HMAC-SHA1 as the default");
    connection("TLS 1.2", TLS1_2_VERSION);
    connection("TLS 1.0", TLS1_VERSION);
    ENGINE_finish(e);
    ENGINE_free(e);
    EVP_CIPHER_meth_free(stitched);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
