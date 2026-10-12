/*
 * Conformance test for the RAND layer (RAND_bytes(3), RAND_get0_primary(3), RAND_set_DRBG_type(3),
 * RAND_set_rand_method(3), RAND_load_file(3), BIO_f_nbio_test), in TAP format: the
 * DRBG hierarchy of each library context (its types, parameters, and settings, per thread),
 * the generators replaced by DRBGs under TEST-RAND (so output can be compared), the library's
 * and an application's RAND_METHOD, a random provider, seed files, and the non-blocking IO
 * test filter. Output that is random is checked, not printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The queue, oldest first, with each entry's data. */
static void errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf("  errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && data[0] != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

/* The queue's codes only (a failed fetch's data has the name's number, which differs). */
static void codes(void)
{
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static const char *rand_name(EVP_RAND_CTX *ctx)
{
    return ctx == NULL ? "(none)" : EVP_RAND_get0_name(EVP_RAND_CTX_get0_rand(ctx));
}

/* A DRBG's type, algorithm, strength, state, and reseed settings. */
static void describe(const char *label, EVP_RAND_CTX *ctx)
{
    char alg[32] = "-", digest[32] = "-";
    unsigned int strength = 0, requests = 0;
    uint64_t interval = 0;
    int state = -1;
    OSSL_PARAM params[7];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, alg, sizeof(alg));
    params[1] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    params[2] = OSSL_PARAM_construct_int(OSSL_RAND_PARAM_STATE, &state);
    params[3] = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS, &requests);
    params[4] = OSSL_PARAM_construct_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, &interval);
    params[5] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, digest, sizeof(digest));
    params[6] = OSSL_PARAM_construct_end();
    if (ctx != NULL && strcmp(rand_name(ctx), "CTR-DRBG") != 0)
        params[0] = OSSL_PARAM_construct_utf8_string("nothing", alg, sizeof(alg));
    if (ctx != NULL && strcmp(rand_name(ctx), "HASH-DRBG") != 0)
        params[5] = OSSL_PARAM_construct_end();
    printf("  %s: %s", label, rand_name(ctx));
    if (ctx != NULL && EVP_RAND_CTX_get_params(ctx, params))
        printf(" %s %s strength %u state %d requests %u interval %llu", alg, digest, strength,
               state, requests, (unsigned long long)interval);
    printf("\n");
}

/* A CTR-DRBG under a TEST-RAND parent with known entropy and nonce: its output is the same on
 * both libraries. */
static EVP_RAND_CTX *known_drbg(unsigned char seed)
{
    EVP_RAND *rand = EVP_RAND_fetch(NULL, "TEST-RAND", NULL);
    EVP_RAND_CTX *parent = EVP_RAND_CTX_new(rand, NULL), *ctx;
    unsigned char entropy[64], nonce[32];
    unsigned int strength = 256;
    OSSL_PARAM params[4];

    EVP_RAND_free(rand);
    memset(entropy, seed, sizeof(entropy));
    memset(nonce, seed ^ 0x5a, sizeof(nonce));
    params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, entropy, sizeof(entropy));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE, nonce, sizeof(nonce));
    params[3] = OSSL_PARAM_construct_end();
    EVP_RAND_instantiate(parent, 256, 0, NULL, 0, params);
    rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    ctx = EVP_RAND_CTX_new(rand, parent);
    EVP_RAND_free(rand);
    EVP_RAND_CTX_free(parent);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, "AES-256-CTR", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_RAND_instantiate(ctx, 256, 0, NULL, 0, params)) {
        EVP_RAND_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/* ---------------------------------------------------------------------------------------- */

static void *other_thread(void *arg)
{
    EVP_RAND_CTX **out = arg;
    unsigned char buf[16];

    out[0] = RAND_get0_public(NULL);
    out[1] = RAND_get0_private(NULL);
    out[2] = RAND_get0_primary(NULL);
    out[3] = (EVP_RAND_CTX *)(size_t)RAND_bytes(buf, sizeof(buf));
    OPENSSL_thread_stop();
    return NULL;
}

static void hierarchy(void)
{
    EVP_RAND_CTX *primary, *pub, *priv, *seen[4];
    unsigned char buf[64];
    pthread_t t;

    check(RAND_status() == 1, "seeded");
    primary = RAND_get0_primary(NULL);
    pub = RAND_get0_public(NULL);
    priv = RAND_get0_private(NULL);
    check(primary != NULL && pub != NULL && priv != NULL && primary != pub && pub != priv,
          "a primary, a public, and a private DRBG");
    describe("primary", primary);
    describe("public", pub);
    describe("private", priv);
    check(RAND_get0_public(NULL) == pub && RAND_get0_primary(NULL) == primary, "the same again");
    check(RAND_bytes(buf, 0) == 1 && RAND_bytes(buf, -1) == 0 && RAND_bytes(buf, 64) == 1
          && RAND_priv_bytes(buf, 64) == 1 && RAND_priv_bytes(buf, -5) == 0, "RAND_bytes and RAND_priv_bytes");
    check(RAND_bytes_ex(NULL, buf, 64, 256) == 1 && RAND_priv_bytes_ex(NULL, buf, 1, 0) == 1,
          "the _ex forms");
    check(RAND_bytes_ex(NULL, buf, 8, 257) == 0, "but not above the strength");
    errors();
    check(RAND_pseudo_bytes(buf, 16) == 1, "RAND_pseudo_bytes");
    check(RAND_poll() == 1, "RAND_poll");
    RAND_seed("seed", 4);
    RAND_add("more", 4, 2.0);
    RAND_keep_random_devices_open(1);
    RAND_keep_random_devices_open(0);
    check(RAND_status() == 1, "still seeded");
    pthread_create(&t, NULL, other_thread, seen);
    pthread_join(t, NULL);
    check(seen[0] != NULL && seen[0] != pub && seen[1] != NULL && seen[1] != priv
          && seen[2] == primary && seen[3] == (EVP_RAND_CTX *)1,
          "another thread has DRBGs of its own, under the same primary");
    OPENSSL_thread_stop_ex(NULL);
    check(RAND_get0_primary(NULL) == primary && RAND_get0_public(NULL) != NULL,
          "a thread's DRBGs are made again after it stops");
    check(RAND_set_DRBG_type(NULL, "HASH-DRBG", NULL, NULL, "SHA256") == 0,
          "the type can't change once the primary exists");
    errors();
    check(RAND_set_seed_source_type(NULL, "SEED-SRC", NULL) == 0, "nor the seed source");
    errors();
    errors();
}

static void contexts(void)
{
    OSSL_LIB_CTX *lc = OSSL_LIB_CTX_new();
    unsigned char buf[32];

    check(RAND_set_DRBG_type(lc, "HASH-DRBG", NULL, NULL, "SHA256") == 1, "HASH-DRBG in a new context");
    check(RAND_bytes_ex(lc, buf, sizeof(buf), 0) == 1, "which generates");
    describe("primary", RAND_get0_primary(lc));
    describe("public", RAND_get0_public(lc));
    check(RAND_set_DRBG_type(lc, "CTR-DRBG", NULL, NULL, NULL) == 0, "and is set");
    errors();
    OSSL_LIB_CTX_free(lc);

    lc = OSSL_LIB_CTX_new();
    check(RAND_set_DRBG_type(lc, "HMAC-DRBG", "provider=default", NULL, "SHA512") == 1,
          "HMAC-DRBG with a query");
    check(RAND_priv_bytes_ex(lc, buf, sizeof(buf), 256) == 1, "generates");
    describe("private", RAND_get0_private(lc));
    OSSL_LIB_CTX_free(lc);

    lc = OSSL_LIB_CTX_new();
    check(RAND_set_DRBG_type(lc, "CTR-DRBG", NULL, "AES-128-CTR", NULL) == 1, "CTR-DRBG over AES-128");
    check(RAND_bytes_ex(lc, buf, sizeof(buf), 256) == 0, "too weak for 256 bits");
    errors();
    check(RAND_bytes_ex(lc, buf, sizeof(buf), 128) == 1, "but fine for 128");
    describe("public", RAND_get0_public(lc));
    OSSL_LIB_CTX_free(lc);

    lc = OSSL_LIB_CTX_new();
    check(RAND_set_seed_source_type(lc, "NO-SUCH-SEED", NULL) == 1, "an unknown seed source");
    check(RAND_bytes_ex(lc, buf, sizeof(buf), 0) == 1, "the primary seeds itself without one");
    errors();
    OSSL_LIB_CTX_free(lc);

    lc = OSSL_LIB_CTX_new();
    check(RAND_set_DRBG_type(lc, "NO-SUCH-DRBG", NULL, NULL, NULL) == 1, "an unknown DRBG");
    check(RAND_get0_primary(lc) == NULL && RAND_bytes_ex(lc, buf, sizeof(buf), 0) == 0,
          "can't be made");
    codes();
    check(RAND_set_seed_source_type(lc, "SEED-SRC", NULL) == 0, "though the seed source was");
    errors();
    OSSL_LIB_CTX_free(lc);

    lc = OSSL_LIB_CTX_new();
    check(RAND_set_seed_source_type(lc, "TEST-RAND", NULL) == 1, "TEST-RAND as the seed source");
    check(RAND_get0_primary(lc) == NULL, "is too weak for the primary");
    errors();
    OSSL_LIB_CTX_free(lc);
}

/* ---------------------------------------------------------------------------------------- */

static void replaced(void)
{
    EVP_RAND_CTX *mine = known_drbg(7), *mine2 = known_drbg(9);
    unsigned char buf[48];
    char text[] = "the quick brown fox jumps over the lazy dog";
    char back[64];
    BIO *nbio, *mem;
    int n, done, tries;

    check(mine != NULL && mine2 != NULL, "two DRBGs under TEST-RAND");
    check(RAND_set0_public(NULL, mine) == 1 && RAND_get0_public(NULL) == mine, "one as the public");
    check(RAND_bytes(buf, 48) == 1, "RAND_bytes from it");
    hex("public", buf, 48);
    check(RAND_set0_private(NULL, mine2) == 1, "the other as the private");
    check(RAND_priv_bytes(buf, 16) == 1, "RAND_priv_bytes from it");
    hex("private", buf, 16);

    nbio = BIO_new(BIO_f_nbio_test());
    mem = BIO_new(BIO_s_mem());
    check(nbio != NULL && mem != NULL && BIO_push(nbio, mem) == nbio, "an nbio test filter");
    printf("  writes:");
    for (done = 0, tries = 0; done < (int)strlen(text) && tries < 100; tries++) {
        n = BIO_write(nbio, text + done, (int)strlen(text) - done);
        printf(" %d%s", n, n < 0 && BIO_should_retry(nbio) ? "r" : "");
        if (n > 0)
            done += n;
    }
    printf("\n");
    check(done == (int)strlen(text), "all written");
    printf("  reads:");
    for (done = 0, tries = 0; done < (int)strlen(text) && tries < 100; tries++) {
        n = BIO_read(nbio, back + done, (int)sizeof(back) - done);
        printf(" %d%s", n, n < 0 && BIO_should_retry(nbio) ? "r" : "");
        if (n > 0)
            done += n;
    }
    printf("\n");
    check(done == (int)strlen(text) && memcmp(back, text, done) == 0, "all read back");
    check(BIO_puts(nbio, "puts") == 4 && BIO_gets(nbio, back, sizeof(back)) == 4
          && BIO_ctrl_pending(nbio) == 0, "puts and gets pass through");
    check(BIO_write(nbio, NULL, 4) == 0 && BIO_write(nbio, text, 0) == 0
          && BIO_read(nbio, NULL, 4) == 0, "NULL and empty buffers");
    check(BIO_dup_chain(nbio) == NULL, "no copies");
    BIO_free_all(nbio);
    nbio = BIO_new(BIO_f_nbio_test());
    check(BIO_write(nbio, text, 4) == 0 && BIO_read(nbio, back, 4) == 0
          && BIO_ctrl(nbio, BIO_CTRL_PENDING, 0, NULL) == 0, "without a next BIO");
    BIO_free(nbio);

    check(RAND_set0_public(NULL, NULL) == 1 && RAND_set0_private(NULL, NULL) == 1,
          "the thread's DRBGs dropped");
    check(RAND_get0_public(NULL) != NULL && RAND_get0_public(NULL) != mine, "a new public one");
}

/* ---------------------------------------------------------------------------------------- */

static int seeds, adds, statuses, bytes_calls;
static double last_randomness;
static int last_add_len;

static int my_seed(const void *buf, int num)
{
    (void)buf;
    seeds += num;
    return 1;
}

static int my_bytes(unsigned char *buf, int num)
{
    bytes_calls++;
    memset(buf, 0x42, num);
    return 1;
}

static int my_add(const void *buf, int num, double randomness)
{
    (void)buf;
    adds++;
    last_add_len = num;
    last_randomness = randomness;
    return 1;
}

static int my_status(void)
{
    statuses++;
    return 7;
}

static void methods(void)
{
    RAND_METHOD m = { my_seed, my_bytes, NULL, my_add, NULL, my_status };
    RAND_METHOD nobytes = { NULL, NULL, NULL, NULL, NULL, NULL };
    const RAND_METHOD *lib = RAND_get_rand_method();
    unsigned char buf[8];

    check(lib == RAND_OpenSSL() && lib->seed != NULL && lib->bytes != NULL && lib->cleanup == NULL
          && lib->add != NULL && lib->pseudorand != NULL && lib->status != NULL,
          "the library's method");
    check(RAND_set_rand_method(&m) == 1 && RAND_get_rand_method() == &m, "an application's");
    check(RAND_bytes(buf, 8) == 1 && buf[0] == 0x42 && RAND_priv_bytes(buf, 8) == 1
          && RAND_bytes_ex(NULL, buf, 8, 0) == 1 && bytes_calls == 3, "its bytes");
    check(RAND_status() == 7 && statuses == 1, "its status");
    RAND_seed("abc", 3);
    RAND_add("abcdef", 6, 1.5);
    printf("  seeds %d adds %d len %d randomness %.1f\n", seeds, adds, last_add_len, last_randomness);
    check(RAND_poll() == 1, "polling through its add");
    printf("  adds %d len %d randomness %.1f\n", adds, last_add_len, last_randomness);
    check(RAND_pseudo_bytes(buf, 8) == -1, "no pseudorand");
    errors();
    check(RAND_set_rand_method(&nobytes) == 1 && RAND_bytes(buf, 8) == -1
          && RAND_priv_bytes_ex(NULL, buf, 8, 0) == -1, "no bytes");
    errors();
    check(RAND_status() == 0 && RAND_poll() == 0, "no status, no add");
    check(RAND_set_rand_method(NULL) == 1 && RAND_get_rand_method() == RAND_OpenSSL()
          && RAND_status() == 1, "back to the library's");
    check(RAND_set_rand_engine(NULL) == 1, "no engine");
    errors();
}

static void random_provider(void)
{
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    unsigned char buf[8];

    check(RAND_set1_random_provider(NULL, deflt) == 1, "the default provider as the random provider");
    check(RAND_bytes(buf, 8) == 0 && RAND_priv_bytes(buf, 8) == 0, "which has no random_bytes");
    errors();
    check(RAND_set1_random_provider(NULL, NULL) == 1 && RAND_bytes(buf, 8) == 1, "none again");
    OSSL_PROVIDER_unload(deflt);
}

/* ---------------------------------------------------------------------------------------- */

static void files(void)
{
    char dir[] = "/tmp/rustyssl-rand-XXXXXX";
    char path[200], name[256];
    struct stat st;
    const char *got;

    if (mkdtemp(dir) == NULL)
        return;
    snprintf(path, sizeof(path), "%s/seed", dir);
    check(RAND_write_file(path) == 1024, "a seed file written");
    check(stat(path, &st) == 0 && st.st_size == 1024 && (st.st_mode & 0777) == 0600,
          "1024 octets, mode 0600");
    check(RAND_load_file(path, -1) == 1024, "loaded whole");
    check(RAND_load_file(path, 100) == 100 && RAND_load_file(path, 2000) == 1024
          && RAND_load_file(path, 0) == 0, "or in part");
    check(RAND_write_file(path) == 1024, "written again");
    check(RAND_load_file("/dev/zero", -1) == 256, "256 octets of a device");
    check(RAND_load_file(dir, -1) == 0, "nothing of a directory");
    errors();
    check(RAND_write_file(dir) == -1, "a directory can't be written");
    codes();
    check(RAND_load_file("/nonexistent/seed", -1) == -1, "a missing file");
    errors();
    unlink(path);
    rmdir(dir);

    setenv("RANDFILE", "/some/where/random", 1);
    setenv("HOME", "/home/someone", 1);
    got = RAND_file_name(name, sizeof(name));
    printf("  RANDFILE: %s\n", got != NULL ? got : "(null)");
    check(RAND_file_name(name, 19) == NULL && RAND_file_name(name, 20) != NULL, "it must fit");
    setenv("RANDFILE", "", 1);
    got = RAND_file_name(name, sizeof(name));
    printf("  HOME: %s\n", got != NULL ? got : "(null)");
    check(RAND_file_name(name, 19) == NULL && RAND_file_name(name, 20) != NULL, "with .rnd");
    unsetenv("RANDFILE");
    unsetenv("HOME");
    check(RAND_file_name(name, sizeof(name)) == NULL, "none without either");
}

int main(void)
{
    hierarchy();
    contexts();
    replaced();
    methods();
    random_provider();
    files();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
