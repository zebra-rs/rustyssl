/*
 * Shared helpers of the CVE regression programs (tests/cve/), in TAP format.
 *
 * Each program is built once against the vendored headers, then run on the reference OpenSSL
 * (which has every fix) and on rustyssl, in tests/cve/data: both runs must pass every check and
 * print the same output (`cargo xtask test-cve`). A check's description starts with the CVE it
 * guards. Output must not depend on randomness or time: print results, error codes and lengths,
 * never keys, signatures or nonces.
 */
#ifndef CVE_H
#define CVE_H

#define _POSIX_C_SOURCE 200809L
/* Several CVEs are in deprecated functions, which applications still call. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static int failures = 0;
static int number = 0;

/* One TAP check; the description is a printf format. */
static inline void check(int ok, const char *fmt, ...)
{
    va_list ap;

    number++;
    if (!ok)
        failures++;
    printf("%s %d - ", ok ? "ok" : "not ok", number);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

/* A TAP comment, compared between the runs like everything else. */
static inline void note(const char *fmt, ...)
{
    va_list ap;

    printf("# ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static inline int finish(void)
{
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}

/* The error queue as "lib/reason" pairs (no function names, files or lines), then cleared. */
static inline void errors(const char *what)
{
    unsigned long e;
    char line[512] = "";
    size_t used = 0;

    while ((e = ERR_get_error()) != 0 && used < sizeof(line) - 32)
        used += (size_t)snprintf(line + used, sizeof(line) - used, " %d/%d",
                                 ERR_GET_LIB(e), ERR_GET_REASON(e));
    ERR_clear_error();
    note("%s errors:%s", what, line);
}

/* Whether the error queue holds an error; clears it. */
static inline int had_error(void)
{
    int any = ERR_peek_error() != 0;

    ERR_clear_error();
    return any;
}

/* ---- A DER builder ---- */

typedef struct {
    unsigned char *p;
    size_t n, cap;
} buf;

static inline void put(buf *b, const void *data, size_t len)
{
    if (b->n + len > b->cap) {
        b->cap = (b->n + len) * 2 + 64;
        b->p = realloc(b->p, b->cap);
        if (b->p == NULL)
            abort();
    }
    if (len != 0)
        memcpy(b->p + b->n, data, len);
    b->n += len;
}

static inline void put_byte(buf *b, unsigned char c)
{
    put(b, &c, 1);
}

/* A DER length. */
static inline void put_len(buf *b, size_t len)
{
    if (len < 0x80) {
        put_byte(b, (unsigned char)len);
    } else {
        unsigned char tmp[8];
        int n = 0;

        while (len != 0) {
            tmp[n++] = (unsigned char)(len & 0xff);
            len >>= 8;
        }
        put_byte(b, (unsigned char)(0x80 | n));
        while (n > 0)
            put_byte(b, tmp[--n]);
    }
}

/* tag, length, then the contents of `content` (freed). */
static inline void put_tlv(buf *b, unsigned char tag, buf *content)
{
    put_byte(b, tag);
    put_len(b, content->n);
    put(b, content->p, content->n);
    free(content->p);
    content->p = NULL;
    content->n = content->cap = 0;
}

static inline void put_raw_tlv(buf *b, unsigned char tag, const void *data, size_t len)
{
    put_byte(b, tag);
    put_len(b, len);
    put(b, data, len);
}

static inline void free_buf(buf *b)
{
    free(b->p);
    b->p = NULL;
    b->n = b->cap = 0;
}

/* Reads a file of tests/cve/data; NULL when missing. */
static inline unsigned char *read_file(const char *name, size_t *len)
{
    FILE *f = fopen(name, "rb");
    buf b = {0};
    unsigned char chunk[4096];
    size_t n;

    if (f == NULL)
        return NULL;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0)
        put(&b, chunk, n);
    fclose(f);
    put_byte(&b, 0); /* a terminator, not counted */
    *len = b.n - 1;
    return b.p;
}

/* ---- Keys and certificates ---- */

static inline EVP_PKEY *ec_key(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
}

static inline EVP_PKEY *rsa_key(size_t bits)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", bits);
}

/* Adds an extension from its configuration text ("critical,CA:TRUE"). */
static inline int add_ext(X509 *cert, X509 *issuer, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509_EXTENSION *ext;
    int ok;

    X509V3_set_ctx(&ctx, issuer != NULL ? issuer : cert, cert, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (ext == NULL)
        return 0;
    ok = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return ok;
}

/*
 * A certificate for `key` named CN=`cn`, issued by `issuer` (NULL: self-signed) whose key is
 * `issuer_key`, valid from a year ago for ten years, with the extensions in `exts`: pairs of
 * a NID and its configuration text, ended by 0.
 */
static inline X509 *make_cert(const char *cn, long serial, EVP_PKEY *key, X509 *issuer,
                       EVP_PKEY *issuer_key, const int *nids, const char *const *values)
{
    X509 *cert = X509_new();
    X509_NAME *name = X509_NAME_new();

    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, issuer != NULL ? X509_get_subject_name(issuer) : name);
    X509_NAME_free(name);
    X509_gmtime_adj(X509_getm_notBefore(cert), -365L * 24 * 3600);
    X509_gmtime_adj(X509_getm_notAfter(cert), 10L * 365 * 24 * 3600);
    X509_set_pubkey(cert, key);
    for (int i = 0; nids != NULL && nids[i] != 0; i++)
        if (!add_ext(cert, issuer, nids[i], values[i])) {
            X509_free(cert);
            return NULL;
        }
    if (!X509_sign(cert, issuer_key != NULL ? issuer_key : key, EVP_sha256())) {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

static inline X509 *ca_cert(const char *cn, EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key)
{
    static const int nids[] = {NID_basic_constraints, NID_key_usage, 0};
    static const char *const values[] = {"critical,CA:TRUE", "critical,keyCertSign,cRLSign"};

    return make_cert(cn, 1, key, issuer, issuer_key, nids, values);
}

static inline X509 *leaf_cert(const char *cn, EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key)
{
    static const int nids[] = {NID_basic_constraints, NID_subject_alt_name, 0};
    static const char *const values[] = {"CA:FALSE", "DNS:server.example"};

    return make_cert(cn, 2, key, issuer, issuer_key, nids, values);
}

/* Verifies `cert` against `trusted` with `untrusted`, `crls` and `flags`; returns the error. */
static inline int verify(X509 *cert, STACK_OF(X509) *trusted, STACK_OF(X509) *untrusted,
                  STACK_OF(X509_CRL) *crls, unsigned long flags, int *result)
{
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int ok, err;

    for (int i = 0; i < sk_X509_num(trusted); i++)
        X509_STORE_add_cert(store, sk_X509_value(trusted, i));
    X509_STORE_CTX_init(ctx, store, cert, untrusted);
    if (crls != NULL)
        X509_STORE_CTX_set0_crls(ctx, crls);
    X509_STORE_CTX_set_flags(ctx, flags);
    ok = X509_verify_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    ERR_clear_error();
    if (result != NULL)
        *result = ok;
    return err;
}

/* ---- TLS in memory ---- */

typedef struct {
    SSL *ssl;
    BIO *in;  /* what the peer sent, for this end to read */
    BIO *out; /* what this end sent */
} end;

static inline void end_init(end *e, SSL_CTX *ctx, int server)
{
    e->ssl = SSL_new(ctx);
    e->in = BIO_new(BIO_s_mem());
    e->out = BIO_new(BIO_s_mem());
    (void)BIO_set_mem_eof_return(e->in, -1);
    SSL_set_bio(e->ssl, e->in, e->out);
    if (server)
        SSL_set_accept_state(e->ssl);
    else
        SSL_set_connect_state(e->ssl);
}

static inline void end_free(end *e)
{
    SSL_free(e->ssl);
    e->ssl = NULL;
}

/* Moves everything `from` has written to `to`'s input; returns the number of bytes. */
static inline size_t relay(end *from, end *to)
{
    char chunk[16384];
    size_t total = 0;
    int n;

    while ((n = BIO_read(from->out, chunk, sizeof(chunk))) > 0) {
        BIO_write(to->in, chunk, n);
        total += (size_t)n;
    }
    return total;
}

/* Takes what `e` has written, into `b`. */
static inline void take(end *e, buf *b)
{
    char chunk[16384];
    int n;

    while ((n = BIO_read(e->out, chunk, sizeof(chunk))) > 0)
        put(b, chunk, (size_t)n);
}

/* Feeds bytes to `e`'s input. */
static inline void feed(end *e, const void *data, size_t len)
{
    BIO_write(e->in, data, (int)len);
}

/* Runs both ends' handshakes until both finish or neither makes progress; 1 if both did. */
static inline int handshake(end *client, end *server)
{
    for (int round = 0; round < 64; round++) {
        int c = SSL_do_handshake(client->ssl);
        size_t moved = relay(client, server);
        int s = SSL_do_handshake(server->ssl);

        moved += relay(server, client);
        if (c == 1 && s == 1)
            return 1;
        if (moved == 0 && (c <= 0 && SSL_get_error(client->ssl, c) != SSL_ERROR_WANT_READ))
            return 0;
        if (moved == 0 && (s <= 0 && SSL_get_error(server->ssl, s) != SSL_ERROR_WANT_READ))
            return 0;
        if (moved == 0 && c <= 0 && s <= 0)
            return 0;
    }
    return 0;
}

/* The alert in the bytes an end wrote: "level/description", or "none". */
static inline const char *alert_in(const buf *b, char *out, size_t outlen)
{
    /* A plaintext alert record: 15 03 0x 00 02 level desc. */
    for (size_t i = 0; i + 7 <= b->n; i++) {
        if (b->p[i] == 0x15 && b->p[i + 1] == 0x03 && b->p[i + 3] == 0x00 && b->p[i + 4] == 0x02) {
            snprintf(out, outlen, "%d/%d", b->p[i + 5], b->p[i + 6]);
            return out;
        }
    }
    snprintf(out, outlen, "none");
    return out;
}

/* A server context with a fresh EC P-256 certificate (its key in *key when key isn't NULL). */
static inline SSL_CTX *server_ctx(const SSL_METHOD *method, EVP_PKEY *key, X509 *cert)
{
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (cert != NULL) {
        SSL_CTX_use_certificate(ctx, cert);
        SSL_CTX_use_PrivateKey(ctx, key);
    }
    return ctx;
}

#endif
