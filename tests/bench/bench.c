/*
 * The C side of `cargo xtask bench` (TEST_PLAN.md L10): what `openssl speed` doesn't measure.
 * Built once against each library, as an application would be. Each mode prints lines of
 * `<metric> <value> <unit>`; the driver takes the medians of repeated runs.
 *
 *   bench handshake <tls1.2|tls1.3> <rsa|ecdsa> <full|resume> <group> <seconds> <certdir>
 *       handshakes/s, client and server in one thread over a BIO pair, the client verifying
 *       the server's chain
 *   bench bulk <seconds> <certdir>          TLS 1.3 AES-128-GCM throughput over a BIO pair
 *   bench memory <certdir>                  heap per SSL_CTX and per idle connection
 *   bench init                              OPENSSL_init_ssl's time in this process
 *   bench drbg <seconds>                    RAND_bytes throughput (32 and 4096 octets)
 *   bench rsa-keygen <count>                RSA-2048 key generation times
 *   bench threads <seconds> <certdir>       scaling over 1, 2, 4, and 8 threads: full and
 *       resumed TLS 1.3 handshakes on a shared SSL_CTX, and RAND_bytes
 *
 * Copyright the rustyssl authors. Licensed under the Apache License 2.0.
 */
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE /* malloc/malloc.h's types */
#endif
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#if defined(__APPLE__)
#include <malloc/malloc.h>
#elif defined(__GLIBC__)
#include <malloc.h>
#endif

static double now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Bytes the process's allocator holds (all of them: C and Rust allocations alike). */
static double heap_in_use(void)
{
#if defined(__APPLE__)
    malloc_statistics_t st;

    malloc_zone_statistics(NULL, &st);
    return (double)st.size_in_use;
#elif defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
    struct mallinfo2 mi = mallinfo2();

    return (double)mi.uordblks;
#else
    return -1;
#endif
}

static void die(const char *what)
{
    fprintf(stderr, "bench: %s failed\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static char certdir[1024];

static const char *path(const char *file)
{
    static char buf[1200];

    snprintf(buf, sizeof(buf), "%s/%s", certdir, file);
    return buf;
}

static SSL_CTX *server_ctx(const char *kind, int version)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    int ecdsa = strcmp(kind, "ecdsa") == 0;

    if (ctx == NULL
        || !SSL_CTX_use_certificate_file(ctx, path(ecdsa ? "server-ecdsa-cert.pem" : "servercert.pem"),
                                         SSL_FILETYPE_PEM)
        || !SSL_CTX_use_PrivateKey_file(ctx, path(ecdsa ? "server-ecdsa-key.pem" : "serverkey.pem"),
                                        SSL_FILETYPE_PEM)
        || !SSL_CTX_set_min_proto_version(ctx, version)
        || !SSL_CTX_set_max_proto_version(ctx, version))
        die("server context");
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    return ctx;
}

static SSL_CTX *client_ctx(int version, const char *group)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (ctx == NULL || !SSL_CTX_load_verify_locations(ctx, path("rootcert.pem"), NULL)
        || !SSL_CTX_set_min_proto_version(ctx, version)
        || !SSL_CTX_set_max_proto_version(ctx, version)
        || (group != NULL && strcmp(group, "-") != 0 && !SSL_CTX_set1_groups_list(ctx, group)))
        die("client context");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
    return ctx;
}

/* Runs both sides' handshakes to completion over a BIO pair. 1 on success. */
static int pair(SSL *c, SSL *s)
{
    BIO *cb, *sb;
    int cdone = 0, sdone = 0, rounds = 0;

    if (!BIO_new_bio_pair(&cb, 0, &sb, 0))
        return 0;
    SSL_set_bio(c, cb, cb);
    SSL_set_bio(s, sb, sb);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    while ((!cdone || !sdone) && rounds++ < 100) {
        if (!cdone) {
            int r = SSL_do_handshake(c);

            if (r == 1)
                cdone = 1;
            else if (SSL_get_error(c, r) != SSL_ERROR_WANT_READ)
                return 0;
        }
        if (!sdone) {
            int r = SSL_do_handshake(s);

            if (r == 1)
                sdone = 1;
            else if (SSL_get_error(s, r) != SSL_ERROR_WANT_READ)
                return 0;
        }
    }
    return cdone && sdone;
}

/* Lets the client read what the server sent after the handshake (TLS 1.3's tickets). */
static void drain(SSL *c)
{
    char b;

    (void)SSL_read(c, &b, 1);
    ERR_clear_error();
}

/* A session the client can resume with, from one full handshake. */
static SSL_SESSION *first_session(SSL_CTX *cctx, SSL_CTX *sctx)
{
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    SSL_SESSION *sess;

    if (c == NULL || s == NULL || !pair(c, s))
        die("first handshake");
    drain(c);
    sess = SSL_get1_session(c);
    SSL_shutdown(c);
    SSL_shutdown(s);
    SSL_free(c);
    SSL_free(s);
    return sess;
}

/* One handshake, resuming `*sess` if it's set; then `*sess` becomes the connection's newest
 * session, as a client keeps the latest ticket (TLS 1.3's are used once). 1 on success. */
static int handshake_once(SSL_CTX *cctx, SSL_CTX *sctx, SSL_SESSION **sess, int want_reuse)
{
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    int ok;

    if (c == NULL || s == NULL)
        return 0;
    if (sess != NULL && *sess != NULL)
        SSL_set_session(c, *sess);
    ok = pair(c, s) && (!want_reuse || SSL_session_reused(c));
    if (ok && sess != NULL) {
        drain(c);
        SSL_SESSION_free(*sess);
        *sess = SSL_get1_session(c);
    }
    /* Closed as after close_notify: freeing a live connection makes its session unusable. */
    SSL_set_shutdown(c, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_set_shutdown(s, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_free(c);
    SSL_free(s);
    return ok;
}

static int version_of(const char *v)
{
    return strcmp(v, "tls1.2") == 0 ? TLS1_2_VERSION : TLS1_3_VERSION;
}

static int mode_handshake(char **argv)
{
    int version = version_of(argv[0]);
    const char *kind = argv[1];
    int resume = strcmp(argv[2], "resume") == 0;
    const char *group = argv[3];
    double secs = atof(argv[4]), start, el;
    SSL_CTX *sctx, *cctx;
    SSL_SESSION *sess = NULL;
    long n = 0;

    snprintf(certdir, sizeof(certdir), "%s", argv[5]);
    sctx = server_ctx(kind, version);
    cctx = client_ctx(version, group);
    if (resume)
        sess = first_session(cctx, sctx);
    start = now();
    do {
        if (!handshake_once(cctx, sctx, resume ? &sess : NULL, resume))
            die("handshake");
        n++;
        el = now() - start;
    } while (el < secs);
    printf("handshakes %.1f /s\n", (double)n / el);
    SSL_SESSION_free(sess);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return 0;
}

static int mode_bulk(char **argv)
{
    double secs = atof(argv[0]), start, el;
    SSL_CTX *sctx, *cctx;
    SSL *c, *s;
    static unsigned char buf[16384], in[16384];
    double total = 0;

    snprintf(certdir, sizeof(certdir), "%s", argv[1]);
    sctx = server_ctx("ecdsa", TLS1_3_VERSION);
    cctx = client_ctx(TLS1_3_VERSION, NULL);
    if (!SSL_CTX_set_ciphersuites(cctx, "TLS_AES_128_GCM_SHA256"))
        die("ciphersuites");
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    if (c == NULL || s == NULL || !pair(c, s))
        die("bulk handshake");
    drain(c);
    memset(buf, 0x5a, sizeof(buf));
    start = now();
    do {
        /* The pair's buffer holds one record at a time: write one, read it. */
        if (SSL_write(s, buf, sizeof(buf)) != (int)sizeof(buf))
            die("SSL_write");
        int got = 0;

        while (got < (int)sizeof(buf)) {
            int r = SSL_read(c, in, sizeof(in));

            if (r <= 0)
                die("SSL_read");
            got += r;
        }
        total += got;
        el = now() - start;
    } while (el < secs);
    printf("bulk %.1f MB/s\n", total / el / 1e6);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return 0;
}

#define CONNS 64

static int mode_memory(char **argv)
{
    double before, after_ctx, after_conns;
    SSL_CTX *sctx, *cctx;
    SSL *c[CONNS], *s[CONNS];
    int i;

    snprintf(certdir, sizeof(certdir), "%s", argv[0]);
    OPENSSL_init_ssl(0, NULL);
    /* Warm up: the first handshake loads algorithms and caches that every one shares. */
    sctx = server_ctx("ecdsa", TLS1_3_VERSION);
    cctx = client_ctx(TLS1_3_VERSION, NULL);
    handshake_once(cctx, sctx, NULL, 0);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);

    before = heap_in_use();
    sctx = server_ctx("ecdsa", TLS1_3_VERSION);
    after_ctx = heap_in_use();
    cctx = client_ctx(TLS1_3_VERSION, NULL);
    for (i = 0; i < CONNS; i++) {
        c[i] = SSL_new(cctx);
        s[i] = SSL_new(sctx);
        if (c[i] == NULL || s[i] == NULL || !pair(c[i], s[i]))
            die("memory handshake");
        drain(c[i]);
    }
    after_conns = heap_in_use();
    printf("ctx_bytes %.0f B\n", after_ctx - before);
    /* Each connection counts both of its ends; the client context is small and shared. */
    printf("conn_bytes %.0f B\n", (after_conns - after_ctx) / CONNS);
    for (i = 0; i < CONNS; i++) {
        SSL_free(c[i]);
        SSL_free(s[i]);
    }
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return 0;
}

static int mode_init(void)
{
    double start = now();

    if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL))
        die("OPENSSL_init_ssl");
    printf("init %.1f us\n", (now() - start) * 1e6);
    return 0;
}

static double drbg_rate(size_t len, double secs)
{
    static unsigned char buf[4096];
    double start = now(), el, total = 0;

    do {
        if (RAND_bytes(buf, (int)len) != 1)
            die("RAND_bytes");
        total += (double)len;
        el = now() - start;
    } while (el < secs);
    return total / el;
}

static int mode_drbg(char **argv)
{
    double secs = atof(argv[0]);

    printf("drbg_32 %.1f MB/s\n", drbg_rate(32, secs) / 1e6);
    printf("drbg_4096 %.1f MB/s\n", drbg_rate(4096, secs) / 1e6);
    return 0;
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;

    return (x > y) - (x < y);
}

static int mode_rsa_keygen(char **argv)
{
    int count = atoi(argv[0]), i;
    double *t = calloc((size_t)count, sizeof(double));

    if (t == NULL || count < 1)
        die("rsa-keygen count");
    for (i = 0; i < count; i++) {
        double start = now();
        EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);

        if (k == NULL)
            die("RSA keygen");
        t[i] = (now() - start) * 1e3;
        EVP_PKEY_free(k);
    }
    qsort(t, (size_t)count, sizeof(double), cmp_double);
    printf("rsa_keygen_p10 %.2f ms\n", t[count / 10]);
    printf("rsa_keygen_median %.2f ms\n", t[count / 2]);
    printf("rsa_keygen_p90 %.2f ms\n", t[(count * 9) / 10]);
    free(t);
    return 0;
}

struct worker {
    int what; /* 0 full handshakes, 1 resumed, 2 RAND_bytes */
    double secs;
    SSL_CTX *cctx, *sctx;
    SSL_SESSION *sess;
    long ops;
};

static void *work(void *arg)
{
    struct worker *w = arg;
    double start = now();
    unsigned char buf[32];

    do {
        int ok = w->what == 2 ? RAND_bytes(buf, sizeof(buf)) == 1
                              : handshake_once(w->cctx, w->sctx, w->what == 1 ? &w->sess : NULL, w->what == 1);

        if (!ok)
            die("threaded operation");
        w->ops++;
    } while (now() - start < w->secs);
    return NULL;
}

static int mode_threads(char **argv)
{
    static const char *names[] = { "full", "resume", "drbg" };
    double secs = atof(argv[0]);
    SSL_CTX *sctx, *cctx;
    int what, n;

    snprintf(certdir, sizeof(certdir), "%s", argv[1]);
    sctx = server_ctx("ecdsa", TLS1_3_VERSION);
    cctx = client_ctx(TLS1_3_VERSION, NULL);
    for (what = 0; what < 3; what++) {
        for (n = 1; n <= 8; n *= 2) {
            pthread_t th[8];
            struct worker w[8];
            long total = 0;
            int i;

            for (i = 0; i < n; i++) {
                w[i] = (struct worker){ what, secs, cctx, sctx, NULL, 0 };
                if (what == 1) /* a ticket of its own: TLS 1.3's are used once */
                    w[i].sess = first_session(cctx, sctx);
                if (pthread_create(&th[i], NULL, work, &w[i]) != 0)
                    die("pthread_create");
            }
            for (i = 0; i < n; i++) {
                pthread_join(th[i], NULL);
                total += w[i].ops;
                SSL_SESSION_free(w[i].sess);
            }
            printf("threads_%s_%d %.1f /s\n", names[what], n, (double)total / secs);
        }
    }
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: bench <mode> [args...]\n");
        return 2;
    }
    if (strcmp(argv[1], "handshake") == 0 && argc == 8)
        return mode_handshake(argv + 2);
    if (strcmp(argv[1], "bulk") == 0 && argc == 4)
        return mode_bulk(argv + 2);
    if (strcmp(argv[1], "memory") == 0 && argc == 3)
        return mode_memory(argv + 2);
    if (strcmp(argv[1], "init") == 0)
        return mode_init();
    if (strcmp(argv[1], "drbg") == 0 && argc == 3)
        return mode_drbg(argv + 2);
    if (strcmp(argv[1], "rsa-keygen") == 0 && argc == 3)
        return mode_rsa_keygen(argv + 2);
    if (strcmp(argv[1], "threads") == 0 && argc == 4)
        return mode_threads(argv + 2);
    fprintf(stderr, "bench: unknown mode or arguments\n");
    return 2;
}
