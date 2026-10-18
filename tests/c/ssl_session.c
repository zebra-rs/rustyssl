/*
 * Conformance test for SSL_SESSION objects (SSL_SESSION_new(3), SSL_SESSION_free(3),
 * SSL_SESSION_get_master_key(3), SSL_SESSION_set1_id(3), SSL_SESSION_get_time(3),
 * SSL_SESSION_get_protocol_version(3), SSL_SESSION_get0_cipher(3), SSL_SESSION_get0_hostname(3),
 * SSL_SESSION_has_ticket(3), SSL_SESSION_get0_peer(3), SSL_SESSION_is_resumable(3),
 * SSL_SESSION_set1_ticket_appdata(3), SSL_SESSION_get_ex_new_index(3), SSL_SESSION_print(3),
 * d2i_SSL_SESSION(3), PEM_read_bio_SSL_SESSION(3)): the getters of a new session, every setter,
 * the DER and PEM encodings (byte for byte), decoding errors, the text and key log forms,
 * copies, and application data.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
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

/* Prints and clears the error queue: library/reason only. */
static void errors(void)
{
    unsigned long e;

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static void hex(const char *what, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s (%zu):", what, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 ? "\n    " : "", p[i]);
    printf("\n");
}

/* Prints what a BIO collected and empties it. */
static void dump_bio(BIO *b)
{
    char *p;
    long n = BIO_get_mem_data(b, &p);

    printf("%.*s", (int)n, p);
    (void)BIO_reset(b);
}

/* A cipher by its two-octet id, from a client connection's list. */
static const SSL_CIPHER *cipher(SSL *ssl, unsigned char a, unsigned char b)
{
    const unsigned char id[2] = { a, b };

    return SSL_CIPHER_find(ssl, id);
}

/* The getters on a session. */
static void show(SSL_SESSION *s)
{
    unsigned int len = 0;
    const unsigned char *p;
    const SSL_CIPHER *c;
    unsigned char mk[64];
    size_t n;

    printf("  protocol %#x\n", SSL_SESSION_get_protocol_version(s));
    c = SSL_SESSION_get0_cipher(s);
    printf("  cipher %s\n", c == NULL ? "(none)" : SSL_CIPHER_get_name(c));
    p = SSL_SESSION_get_id(s, &len);
    hex("id", p, len);
    p = SSL_SESSION_get0_id_context(s, &len);
    hex("id context", p, len);
    n = SSL_SESSION_get_master_key(s, NULL, 0);
    printf("  master key length %zu\n", n);
    n = SSL_SESSION_get_master_key(s, mk, sizeof(mk));
    hex("master key", mk, n);
    printf("  timeout %ld\n", SSL_SESSION_get_timeout(s));
    printf("  hostname %s\n", SSL_SESSION_get0_hostname(s) == NULL ? "(none)" : SSL_SESSION_get0_hostname(s));
    printf("  has ticket %d, lifetime hint %lu\n", SSL_SESSION_has_ticket(s),
        SSL_SESSION_get_ticket_lifetime_hint(s));
    printf("  compress id %u\n", SSL_SESSION_get_compress_id(s));
    printf("  max early data %u\n", SSL_SESSION_get_max_early_data(s));
    printf("  max fragment length %u\n", SSL_SESSION_get_max_fragment_length(s));
    printf("  peer %s, peer rpk %s\n", SSL_SESSION_get0_peer(s) == NULL ? "none" : "some",
        SSL_SESSION_get0_peer_rpk(s) == NULL ? "none" : "some");
    printf("  resumable %d\n", SSL_SESSION_is_resumable(s));
}

static void test_new(void)
{
    SSL_SESSION *s = SSL_SESSION_new();
    const unsigned char *p;
    size_t n;
    unsigned char *der = NULL;

    printf("# a new session\n");
    check(s != NULL, "SSL_SESSION_new");
    show(s);
    p = (const unsigned char *)"x";
    n = 1;
    SSL_SESSION_get0_alpn_selected(s, &p, &n);
    check(p == NULL && n == 0, "no ALPN");
    p = (const unsigned char *)"x";
    n = 1;
    SSL_SESSION_get0_ticket(s, &p, &n);
    check(p == NULL && n == 0, "no ticket");
    check(i2d_SSL_SESSION(s, &der) == 0 && der == NULL, "no cipher: nothing to encode");
    check(SSL_SESSION_up_ref(s) == 1, "SSL_SESSION_up_ref");
    SSL_SESSION_free(s);
    SSL_SESSION_free(s);
    SSL_SESSION_free(NULL);
    check(i2d_SSL_SESSION(NULL, NULL) == 0, "i2d of NULL");
    errors();
}

/* A session with every field set, for the encodings. */
static SSL_SESSION *full(SSL *ssl, int tls13)
{
    SSL_SESSION *s = SSL_SESSION_new();
    unsigned char mk[48];
    unsigned char id[32];
    size_t i;

    for (i = 0; i < sizeof(mk); i++)
        mk[i] = (unsigned char)(i * 7 + 1);
    for (i = 0; i < sizeof(id); i++)
        id[i] = (unsigned char)(0xa0 + i);
    SSL_SESSION_set_protocol_version(s, tls13 ? TLS1_3_VERSION : TLS1_2_VERSION);
    SSL_SESSION_set_cipher(s, tls13 ? cipher(ssl, 0x13, 0x01) : cipher(ssl, 0xc0, 0x2b));
    SSL_SESSION_set1_id(s, id, sizeof(id));
    SSL_SESSION_set1_id_context(s, (const unsigned char *)"ctx", 3);
    SSL_SESSION_set1_master_key(s, mk, tls13 ? 32 : sizeof(mk));
    SSL_SESSION_set_time_ex(s, 1700000000);
    SSL_SESSION_set_timeout(s, 7200);
    SSL_SESSION_set1_hostname(s, "server.example");
    SSL_SESSION_set1_alpn_selected(s, (const unsigned char *)"h2", 2);
    if (tls13)
        SSL_SESSION_set_max_early_data(s, 16384);
    SSL_SESSION_set1_ticket_appdata(s, "app", 3);
    return s;
}

static void test_setters(SSL *ssl)
{
    SSL_SESSION *s = SSL_SESSION_new();
    unsigned char big[64] = { 0 };
    unsigned char mk[600] = { 0 };
    const unsigned char *p;
    void *data;
    size_t n;

    printf("# setters\n");
    check(SSL_SESSION_set1_id(s, big, 33) == 0, "an ID of 33 octets");
    errors();
    check(SSL_SESSION_set1_id(s, big, 32) == 1, "an ID of 32 octets");
    check(SSL_SESSION_set1_id_context(s, big, 33) == 0, "an ID context of 33 octets");
    errors();
    check(SSL_SESSION_set1_master_key(s, mk, sizeof(mk)) == 0, "a master key of 600 octets");
    errors();
    check(SSL_SESSION_set1_master_key(s, mk, 512) == 1, "a master key of 512 octets");
    check(SSL_SESSION_get_master_key(s, NULL, 0) == 512, "its length");
    check(SSL_SESSION_set_timeout(s, -1) == 0, "a negative timeout");
    check(SSL_SESSION_set_timeout(s, 100) == 1, "a timeout");
    check(SSL_SESSION_get_timeout(s) == 100, "the timeout");
    check(SSL_SESSION_set_time(s, 1234567) == 1234567, "SSL_SESSION_set_time");
    check(SSL_SESSION_get_time(s) == 1234567, "SSL_SESSION_get_time");
    check(SSL_SESSION_get_time_ex(s) == 1234567, "SSL_SESSION_get_time_ex");
    check(SSL_SESSION_set_protocol_version(s, TLS1_1_VERSION) == 1, "a protocol version");
    check(SSL_SESSION_get_protocol_version(s) == TLS1_1_VERSION, "the version");
    check(SSL_SESSION_set_cipher(s, cipher(ssl, 0xc0, 0x2f)) == 1, "a cipher");
    printf("  cipher %s\n", SSL_CIPHER_get_name(SSL_SESSION_get0_cipher(s)));
    check(SSL_SESSION_set1_hostname(s, "a.example") == 1, "a host name");
    check(strcmp(SSL_SESSION_get0_hostname(s), "a.example") == 0, "the host name");
    check(SSL_SESSION_set1_hostname(s, NULL) == 1 && SSL_SESSION_get0_hostname(s) == NULL,
        "no host name");
    check(SSL_SESSION_set1_alpn_selected(s, (const unsigned char *)"http/1.1", 8) == 1, "ALPN");
    SSL_SESSION_get0_alpn_selected(s, &p, &n);
    check(n == 8 && memcmp(p, "http/1.1", 8) == 0, "the ALPN");
    check(SSL_SESSION_set1_alpn_selected(s, NULL, 0) == 1, "no ALPN");
    SSL_SESSION_get0_alpn_selected(s, &p, &n);
    check(p == NULL && n == 0, "none");
    check(SSL_SESSION_set_max_early_data(s, 99) == 1 && SSL_SESSION_get_max_early_data(s) == 99,
        "max early data");
    check(SSL_SESSION_set1_ticket_appdata(s, "abc", 3) == 1, "ticket appdata");
    check(SSL_SESSION_get0_ticket_appdata(s, &data, &n) == 1 && n == 3
            && memcmp(data, "abc", 3) == 0,
        "the ticket appdata");
    check(SSL_SESSION_set1_ticket_appdata(s, NULL, 0) == 1, "no ticket appdata");
    check(SSL_SESSION_get0_ticket_appdata(s, &data, &n) == 1 && data == NULL && n == 0, "none");
    check(SSL_SESSION_is_resumable(s) == 1, "an ID makes it resumable");
    errors();
    SSL_SESSION_free(s);
}

static void test_encoding(SSL *ssl, int tls13)
{
    SSL_SESSION *s = full(ssl, tls13), *d, *again = NULL;
    unsigned char *der = NULL, *der2 = NULL, *q;
    const unsigned char *p;
    int n, n2;
    BIO *b = BIO_new(BIO_s_mem());

    printf("# the encodings, TLS %s\n", tls13 ? "1.3" : "1.2");
    show(s);
    n = i2d_SSL_SESSION(s, NULL);
    check(n > 0, "the encoding's length");
    n = i2d_SSL_SESSION(s, &der);
    hex("DER", der, (size_t)n);
    q = OPENSSL_malloc((size_t)n);
    der2 = q;
    check(i2d_SSL_SESSION(s, &q) == n && q == der2 + n && memcmp(der, der2, (size_t)n) == 0,
        "into a buffer, advancing");
    OPENSSL_free(der2);
    p = der;
    d = d2i_SSL_SESSION(NULL, &p, n);
    check(d != NULL && p == der + n, "d2i_SSL_SESSION");
    der2 = NULL;
    n2 = i2d_SSL_SESSION(d, &der2);
    check(n2 == n && memcmp(der, der2, (size_t)n) == 0, "re-encodes the same");
    OPENSSL_free(der2);
    show(d);
    p = der;
    again = SSL_SESSION_new();
    {
        SSL_SESSION *into = again;

        check(d2i_SSL_SESSION_ex(&into, &p, n, NULL, NULL) == again && into == again,
            "d2i_SSL_SESSION_ex into a session");
    }
    printf("  into: hostname %s\n", SSL_SESSION_get0_hostname(again));
    SSL_SESSION_free(again);
    check(SSL_SESSION_print(b, s) == 1, "SSL_SESSION_print");
    dump_bio(b);
    check(SSL_SESSION_print_keylog(b, s) == 1, "SSL_SESSION_print_keylog");
    dump_bio(b);
    check(PEM_write_bio_SSL_SESSION(b, s) == 1, "PEM_write_bio_SSL_SESSION");
    {
        char *pem;
        long len = BIO_get_mem_data(b, &pem);

        printf("%.*s", (int)len, pem);
    }
    {
        SSL_SESSION *r = PEM_read_bio_SSL_SESSION(b, NULL, NULL, NULL);

        der2 = NULL;
        n2 = r == NULL ? 0 : i2d_SSL_SESSION(r, &der2);
        check(n2 == n && memcmp(der, der2, (size_t)n) == 0, "PEM_read_bio_SSL_SESSION");
        OPENSSL_free(der2);
        SSL_SESSION_free(r);
    }
    errors();
    {
        SSL_SESSION *c = SSL_SESSION_dup(s);

        der2 = NULL;
        n2 = i2d_SSL_SESSION(c, &der2);
        check(c != s && n2 == n && memcmp(der, der2, (size_t)n) == 0, "SSL_SESSION_dup");
        OPENSSL_free(der2);
        SSL_SESSION_free(c);
    }
    OPENSSL_free(der);
    SSL_SESSION_free(d);
    SSL_SESSION_free(s);
    BIO_free(b);
}

/* Decodes `der` with one octet changed at `at` to `v` (or truncated to `len`). */
static void bad(const char *what, const unsigned char *der, int n, int at, int v, int len)
{
    unsigned char buf[512];
    const unsigned char *p = buf;
    SSL_SESSION *s;

    memcpy(buf, der, (size_t)n);
    if (at >= 0)
        buf[at] = (unsigned char)v;
    s = d2i_SSL_SESSION(NULL, &p, len);
    check(s == NULL, what);
    errors();
    SSL_SESSION_free(s);
}

static void test_bad(SSL *ssl)
{
    SSL_SESSION *s = full(ssl, 0);
    unsigned char *der = NULL;
    int n = i2d_SSL_SESSION(s, &der);

    printf("# decoding errors\n");
    /* 30 81 LL | 02 01 01 (version) | 02 02 03 03 (ssl_version) | 04 02 c0 2b (cipher) */
    bad("version 2", der, n, 5, 2, n);
    bad("SSL version 0x0203", der, n, 8, 2, n);
    bad("truncated", der, n, -1, 0, n - 1);
    bad("a cipher id of one octet", der, n, 11, 1, n);
    OPENSSL_free(der);
    SSL_SESSION_free(s);
}

static void free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    (void)parent;
    (void)ad;
    (void)idx;
    (void)argp;
    if (ptr != NULL)
        printf("  free_cb %ld %s\n", argl, (const char *)ptr);
}

static void test_ex_data(void)
{
    int idx = SSL_SESSION_get_ex_new_index(7, NULL, NULL, NULL, free_cb);
    SSL_SESSION *s = SSL_SESSION_new();

    printf("# application data\n");
    check(idx >= 0, "SSL_SESSION_get_ex_new_index");
    check(SSL_SESSION_get_ex_data(s, idx) == NULL, "none yet");
    check(SSL_SESSION_set_ex_data(s, idx, "value") == 1, "SSL_SESSION_set_ex_data");
    check(strcmp(SSL_SESSION_get_ex_data(s, idx), "value") == 0, "SSL_SESSION_get_ex_data");
    SSL_SESSION_free(s);
}

static void test_print_fp(SSL *ssl)
{
    SSL_SESSION *s = full(ssl, 1);

    printf("# SSL_SESSION_print_fp\n");
    fflush(stdout);
    check(SSL_SESSION_print_fp(stdout, s) == 1, "to stdout");
    check(PEM_write_SSL_SESSION(stdout, s) == 1, "PEM_write_SSL_SESSION");
    fflush(stdout);
    SSL_SESSION_free(s);
}

static void test_pem_fp(SSL *ssl)
{
    SSL_SESSION *s = full(ssl, 0), *r;
    FILE *f = tmpfile();
    unsigned char *a = NULL, *b = NULL;
    int n, m;

    printf("# PEM through a FILE\n");
    check(f != NULL && PEM_write_SSL_SESSION(f, s) == 1, "PEM_write_SSL_SESSION");
    rewind(f);
    r = PEM_read_SSL_SESSION(f, NULL, NULL, NULL);
    n = i2d_SSL_SESSION(s, &a);
    m = r == NULL ? 0 : i2d_SSL_SESSION(r, &b);
    check(n == m && memcmp(a, b, (size_t)n) == 0, "PEM_read_SSL_SESSION");
    OPENSSL_free(a);
    OPENSSL_free(b);
    SSL_SESSION_free(r);
    SSL_SESSION_free(s);
    fclose(f);
}

int main(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);

    test_new();
    test_setters(ssl);
    test_encoding(ssl, 0);
    test_encoding(ssl, 1);
    test_bad(ssl);
    test_ex_data();
    test_pem_fp(ssl);
    test_print_fp(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
