/*
 * A third-party provider, built as a loadable module by `cargo xtask test-c` (tests/c/modules/):
 * what tests/c/provider_ext.c loads to exercise the core's half of the provider interface.
 *
 * Its init function keeps every function of the core's dispatch table and records their ids. It
 * offers a digest (TEST-SUM: the octets' sum as four big-endian octets), reason strings, and,
 * beyond the provider functions OpenSSL defines, one function of its own (TEST_PROV_RUN) that
 * the test program finds through OSSL_PROVIDER_get0_dispatch and calls to have the provider make
 * one kind of upcall and report what came back.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include "test_prov.h"

static const OSSL_CORE_HANDLE *core_handle;
static const OSSL_DISPATCH *core_in;
static int core_ids[256];
static size_t core_count;

static OSSL_FUNC_core_gettable_params_fn *c_gettable_params;
static OSSL_FUNC_core_get_params_fn *c_get_params;
static OSSL_FUNC_core_get_libctx_fn *c_get_libctx;
static OSSL_FUNC_core_thread_start_fn *c_thread_start;
static OSSL_FUNC_core_new_error_fn *c_new_error;
static OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug;
static OSSL_FUNC_core_vset_error_fn *c_vset_error;
static OSSL_FUNC_core_set_error_mark_fn *c_set_error_mark;
static OSSL_FUNC_core_clear_last_error_mark_fn *c_clear_last_error_mark;
static OSSL_FUNC_core_pop_error_to_mark_fn *c_pop_error_to_mark;
static OSSL_FUNC_core_count_to_mark_fn *c_count_to_mark;
static OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid;
static OSSL_FUNC_core_obj_create_fn *c_obj_create;
static OSSL_FUNC_CRYPTO_malloc_fn *c_malloc;
static OSSL_FUNC_CRYPTO_zalloc_fn *c_zalloc;
static OSSL_FUNC_CRYPTO_free_fn *c_free;
static OSSL_FUNC_CRYPTO_clear_free_fn *c_clear_free;
static OSSL_FUNC_CRYPTO_realloc_fn *c_realloc;
static OSSL_FUNC_CRYPTO_clear_realloc_fn *c_clear_realloc;
static OSSL_FUNC_CRYPTO_secure_malloc_fn *c_secure_malloc;
static OSSL_FUNC_CRYPTO_secure_zalloc_fn *c_secure_zalloc;
static OSSL_FUNC_CRYPTO_secure_free_fn *c_secure_free;
static OSSL_FUNC_CRYPTO_secure_clear_free_fn *c_secure_clear_free;
static OSSL_FUNC_CRYPTO_secure_allocated_fn *c_secure_allocated;
static OSSL_FUNC_OPENSSL_cleanse_fn *c_cleanse;
static OSSL_FUNC_BIO_new_file_fn *c_bio_new_file;
static OSSL_FUNC_BIO_new_membuf_fn *c_bio_new_membuf;
static OSSL_FUNC_BIO_read_ex_fn *c_bio_read_ex;
static OSSL_FUNC_BIO_write_ex_fn *c_bio_write_ex;
static OSSL_FUNC_BIO_gets_fn *c_bio_gets;
static OSSL_FUNC_BIO_puts_fn *c_bio_puts;
static OSSL_FUNC_BIO_ctrl_fn *c_bio_ctrl;
static OSSL_FUNC_BIO_up_ref_fn *c_bio_up_ref;
static OSSL_FUNC_BIO_free_fn *c_bio_free;
static OSSL_FUNC_BIO_vprintf_fn *c_bio_vprintf;
static OSSL_FUNC_BIO_vsnprintf_fn *c_bio_vsnprintf;
static OSSL_FUNC_self_test_cb_fn *c_self_test_cb;
static OSSL_FUNC_indicator_cb_fn *c_indicator_cb;
static OSSL_FUNC_get_entropy_fn *c_get_entropy;
static OSSL_FUNC_get_user_entropy_fn *c_get_user_entropy;
static OSSL_FUNC_cleanup_entropy_fn *c_cleanup_entropy;
static OSSL_FUNC_cleanup_user_entropy_fn *c_cleanup_user_entropy;
static OSSL_FUNC_get_nonce_fn *c_get_nonce;
static OSSL_FUNC_get_user_nonce_fn *c_get_user_nonce;
static OSSL_FUNC_cleanup_nonce_fn *c_cleanup_nonce;
static OSSL_FUNC_cleanup_user_nonce_fn *c_cleanup_user_nonce;
static OSSL_FUNC_provider_register_child_cb_fn *c_register_child_cb;
static OSSL_FUNC_provider_deregister_child_cb_fn *c_deregister_child_cb;
static OSSL_FUNC_provider_name_fn *c_prov_name;
static OSSL_FUNC_provider_get0_provider_ctx_fn *c_prov_get0_provider_ctx;
static OSSL_FUNC_provider_get0_dispatch_fn *c_prov_get0_dispatch;
static OSSL_FUNC_provider_up_ref_fn *c_prov_up_ref;
static OSSL_FUNC_provider_free_fn *c_prov_free;

/* The provider's context. */
struct provctx {
    OSSL_LIB_CTX *libctx; /* made from the core's table, for BIO_new_from_core_bio */
    int thread_stops;
    int teardowns;
};

static const OSSL_DISPATCH *own_dispatch;

/* Appends to the report in `out` (`len` octets, kept NUL-terminated). */
static void say(char *out, size_t len, const char *fmt, ...)
{
    size_t used = strlen(out);
    va_list ap;

    if (used + 1 >= len)
        return;
    va_start(ap, fmt);
    vsnprintf(out + used, len - used, fmt, ap);
    va_end(ap);
}

static void raise_error(uint32_t reason, const char *fmt, ...)
{
    va_list ap;

    c_new_error(core_handle);
    c_set_error_debug(core_handle, "test_prov.c", 42, "test_func");
    va_start(ap, fmt);
    c_vset_error(core_handle, reason, fmt, ap);
    va_end(ap);
}

static int bio_printf(OSSL_CORE_BIO *bio, const char *fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = c_bio_vprintf(bio, fmt, ap);
    va_end(ap);
    return n;
}

static int core_snprintf(char *buf, size_t n, const char *fmt, ...)
{
    va_list ap;
    int r;

    va_start(ap, fmt);
    r = c_bio_vsnprintf(buf, n, fmt, ap);
    va_end(ap);
    return r;
}

/* ---- TEST-SUM ---- */

struct sumctx {
    unsigned long sum;
};

static void *sum_newctx(void *provctx)
{
    (void)provctx;
    return c_zalloc(sizeof(struct sumctx), "test_prov.c", __LINE__);
}

static void sum_freectx(void *vctx)
{
    c_free(vctx, "test_prov.c", __LINE__);
}

static void *sum_dupctx(void *vctx)
{
    struct sumctx *n = c_malloc(sizeof(struct sumctx), "test_prov.c", __LINE__);

    if (n != NULL)
        memcpy(n, vctx, sizeof(*n));
    return n;
}

static int sum_init(void *vctx, const OSSL_PARAM params[])
{
    (void)params;
    ((struct sumctx *)vctx)->sum = 0;
    return 1;
}

static int sum_update(void *vctx, const unsigned char *in, size_t inl)
{
    struct sumctx *c = vctx;
    size_t i;

    for (i = 0; i < inl; i++)
        c->sum += in[i];
    return 1;
}

static int sum_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz)
{
    struct sumctx *c = vctx;

    if (outsz < 4)
        return 0;
    out[0] = (unsigned char)(c->sum >> 24);
    out[1] = (unsigned char)(c->sum >> 16);
    out[2] = (unsigned char)(c->sum >> 8);
    out[3] = (unsigned char)c->sum;
    *outl = 4;
    return 1;
}

static int sum_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, 1))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, 4))
        return 0;
    return 1;
}

static const OSSL_PARAM sum_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sum_gettable_params(void *provctx)
{
    (void)provctx;
    return sum_params;
}

static const OSSL_DISPATCH sum_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))sum_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))sum_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))sum_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))sum_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))sum_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))sum_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))sum_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))sum_gettable_params },
    OSSL_DISPATCH_END
};

/* TEST-ODD's property definition names a property no one registered, which fails to parse. */
static const OSSL_ALGORITHM digests[] = {
    { "TEST-SUM:1.3.6.1.4.1.99999.2.1", "provider=test_prov", sum_functions, "a test digest" },
    { "TEST-ODD", "provider=test_prov,test=yes", sum_functions, "an unparsable definition" },
    { NULL, NULL, NULL, NULL }
};

/* ---- the provider's own functions ---- */

static const OSSL_ALGORITHM *query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    return operation_id == OSSL_OP_DIGEST ? digests : NULL;
}

static const OSSL_ITEM reasons[] = {
    { TEST_PROV_R_ONE, "test reason one" },
    { TEST_PROV_R_TWO, "test reason two" },
    { 0, NULL }
};

static const OSSL_ITEM *reason_strings(void *provctx)
{
    (void)provctx;
    return reasons;
}

static const OSSL_PARAM gettable[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
    OSSL_PARAM_int(TEST_PROV_PARAM_THREAD_STOPS, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *gettable_params(void *provctx)
{
    (void)provctx;
    return gettable;
}

static int get_params(void *provctx, OSSL_PARAM params[])
{
    struct provctx *ctx = provctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME)) != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, "test_prov"))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION)) != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, "1.0"))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS)) != NULL
        && !OSSL_PARAM_set_int(p, 1))
        return 0;
    if ((p = OSSL_PARAM_locate(params, TEST_PROV_PARAM_THREAD_STOPS)) != NULL
        && !OSSL_PARAM_set_int(p, ctx->thread_stops))
        return 0;
    return 1;
}

static void thread_stop(void *arg)
{
    ((struct provctx *)arg)->thread_stops++;
}

static void report_core(char *out, size_t len)
{
    const OSSL_PARAM *p;
    char *version = NULL, *name = NULL, *file = NULL, *extra = NULL;
    OSSL_PARAM params[5];
    size_t i;

    say(out, len, "core functions (%zu):", core_count);
    for (i = 0; i < core_count; i++)
        say(out, len, " %d", core_ids[i]);
    say(out, len, "\ncore gettable:");
    for (p = c_gettable_params(core_handle); p != NULL && p->key != NULL; p++)
        say(out, len, " %s/%u", p->key, p->data_type);
    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_CORE_VERSION, &version, 0);
    params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_CORE_PROV_NAME, &name, 0);
    params[2] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_CORE_MODULE_FILENAME, &file, 0);
    params[3] = OSSL_PARAM_construct_utf8_ptr("extra", &extra, 0);
    params[4] = OSSL_PARAM_construct_end();
    say(out, len, "\nget_params %d: version %s name %s module %s extra %s\n",
        c_get_params(core_handle, params), version != NULL ? version : "(none)",
        name != NULL ? name : "(none)",
        file != NULL ? (strrchr(file, '/') != NULL ? strrchr(file, '/') + 1 : file) : "(none)",
        extra != NULL ? extra : "(none)");
}

static void run_errors(char *out, size_t len)
{
    raise_error(TEST_PROV_R_ONE, "value %d", 7);
    raise_error(ERR_PACK(ERR_LIB_EVP, 0, EVP_R_BAD_DECRYPT), "lib %s", "evp");
    raise_error(TEST_PROV_R_TWO, NULL);
    say(out, len, "raised three errors\n");
}

static void run_marks(char *out, size_t len)
{
    int a, b, c, d, e;

    a = c_set_error_mark(core_handle);
    raise_error(TEST_PROV_R_ONE, "marked");
    b = c_count_to_mark(core_handle);
    c = c_pop_error_to_mark(core_handle);
    d = c_count_to_mark(core_handle);
    e = c_set_error_mark(core_handle) && c_clear_last_error_mark(core_handle);
    say(out, len, "marks: set %d count %d pop %d count %d clear %d\n", a, b, c, d, e);
}

static void run_bio(struct provctx *ctx, char *out, size_t len, const char *path)
{
    static const char text[] = "first line\nsecond line\n";
    OSSL_CORE_BIO *m, *f;
    BIO *b;
    char buf[64];
    size_t n = 0;
    int r, up, f1, f2;

    m = c_bio_new_membuf(text, (int)strlen(text));
    say(out, len, "membuf %s", m != NULL ? "made" : "missing");
    if (m != NULL) {
        r = c_bio_gets(m, buf, sizeof(buf));
        say(out, len, ", gets %d \"%.*s\"", r, r > 0 ? r - 1 : 0, buf);
        r = c_bio_read_ex(m, buf, 6, &n);
        say(out, len, ", read_ex %d %zu \"%.*s\"", r, n, (int)n, buf);
        /* One call per statement: argument order is unspecified, and the last free ends m. */
        up = c_bio_up_ref(m);
        f1 = c_bio_free(m);
        f2 = c_bio_free(m);
        say(out, len, ", up_ref %d free %d free %d\n", up, f1, f2);
    }
    f = c_bio_new_file(path, "w");
    say(out, len, "file %s", f != NULL ? "made" : "missing");
    if (f != NULL) {
        r = c_bio_write_ex(f, "abc", 3, &n);
        say(out, len, ", write_ex %d %zu", r, n);
        say(out, len, ", puts %d", c_bio_puts(f, "defg\n"));
        say(out, len, ", vprintf %d", bio_printf(f, "%d-%s\n", 12, "xy"));
        b = BIO_new_from_core_bio(ctx->libctx, f);
        say(out, len, ", from core %s", b != NULL ? "made" : "missing");
        if (b != NULL) {
            say(out, len, " printf %d", BIO_printf(b, "via BIO_s_core %d\n", 3));
            say(out, len, " flush %d", BIO_flush(b));
            BIO_free(b);
        }
        say(out, len, ", ctrl flush %d", (int)c_bio_ctrl(f, BIO_CTRL_FLUSH, 0, NULL));
        say(out, len, ", free %d\n", c_bio_free(f));
    }
    f = c_bio_new_file(path, "r");
    if (f != NULL) {
        memset(buf, 0, sizeof(buf));
        r = c_bio_read_ex(f, buf, sizeof(buf) - 1, &n);
        say(out, len, "read back %d %zu: %s", r, n, buf);
        c_bio_free(f);
    }
    say(out, len, "missing file %s\n",
        c_bio_new_file("/nonexistent/rustyssl/none", "r") == NULL ? "fails" : "opens");
    r = core_snprintf(buf, sizeof(buf), "%s=%05d", "n", 42);
    say(out, len, "vsnprintf %d \"%s\"\n", r, buf);
}

static void run_memory(char *out, size_t len)
{
    unsigned char *p, *z, *s;
    int zeros = 1;
    size_t i;

    p = c_malloc(16, "test_prov.c", __LINE__);
    z = c_zalloc(16, "test_prov.c", __LINE__);
    for (i = 0; z != NULL && i < 16; i++)
        zeros &= z[i] == 0;
    p = c_realloc(p, 64, "test_prov.c", __LINE__);
    z = c_clear_realloc(z, 16, 32, "test_prov.c", __LINE__);
    say(out, len, "malloc %d zalloc zeros %d realloc %d clear_realloc %d", p != NULL, zeros,
        p != NULL, z != NULL);
    if (p != NULL)
        c_cleanse(p, 64);
    c_free(p, "test_prov.c", __LINE__);
    c_clear_free(z, 32, "test_prov.c", __LINE__);
    s = c_secure_malloc(32, "test_prov.c", __LINE__);
    say(out, len, ", secure %d allocated %d", s != NULL, c_secure_allocated(s));
    c_secure_free(s, "test_prov.c", __LINE__);
    s = c_secure_zalloc(32, "test_prov.c", __LINE__);
    say(out, len, ", secure zalloc %d\n", s != NULL && s[0] == 0 && s[31] == 0);
    c_secure_clear_free(s, 32, "test_prov.c", __LINE__);
}

static void run_seeds(char *out, size_t len)
{
    unsigned char *buf = NULL;
    size_t n;

    n = c_get_entropy(core_handle, &buf, 128, 16, 64);
    say(out, len, "entropy %s", n >= 16 && n <= 64 && buf != NULL ? "in range" : "out of range");
    c_cleanup_entropy(core_handle, buf, n);
    buf = NULL;
    n = c_get_user_entropy(core_handle, &buf, 128, 16, 64);
    say(out, len, ", user entropy %s",
        n >= 16 && n <= 64 && buf != NULL ? "in range" : "out of range");
    c_cleanup_user_entropy(core_handle, buf, n);
    buf = NULL;
    n = c_get_nonce(core_handle, &buf, 16, 64, "salt", 4);
    say(out, len, ", nonce %s", n >= 16 && n <= 64 && buf != NULL ? "in range" : "out of range");
    c_cleanup_nonce(core_handle, buf, n);
    buf = NULL;
    n = c_get_user_nonce(core_handle, &buf, 16, 64, "salt", 4);
    say(out, len, ", user nonce %s\n",
        n >= 16 && n <= 64 && buf != NULL ? "in range" : "out of range");
    c_cleanup_user_nonce(core_handle, buf, n);
}

static void run_objects(char *out, size_t len)
{
    say(out, len, "obj_create %d", c_obj_create(core_handle, "1.3.6.1.4.1.99999.3.1", "testSig",
                                                "test signature"));
    say(out, len, " again %d", c_obj_create(core_handle, "1.3.6.1.4.1.99999.3.1", "testSig",
                                            "test signature"));
    say(out, len, " digest %d", c_obj_create(core_handle, "1.3.6.1.4.1.99999.3.2", "testDgst",
                                             "test digest"));
    say(out, len, ", add_sigid %d", c_obj_add_sigid(core_handle, "testSig", "testDgst", "RSA"));
    say(out, len, " again %d", c_obj_add_sigid(core_handle, "testSig", "testDgst", "RSA"));
    say(out, len, " unknown sign %d", c_obj_add_sigid(core_handle, "noSuchSig", "SHA256", "RSA"));
    say(out, len, " unknown digest %d",
        c_obj_add_sigid(core_handle, "testSig", "noSuchDigest", "RSA"));
    say(out, len, " no digest %d\n", c_obj_add_sigid(core_handle, "testSig", "", "RSA"));
}

static void run_provider(struct provctx *ctx, char *out, size_t len)
{
    int up, fr;

    /* up_ref returns the count, which counts the library's own references: only its sign. One
       call per statement, as argument order is unspecified and each free undoes an up_ref. */
    up = c_prov_up_ref(core_handle, 0);
    fr = c_prov_free(core_handle, 0);
    say(out, len, "name %s, own context %d, own dispatch %d, up_ref %s, free %d",
        c_prov_name(core_handle), c_prov_get0_provider_ctx(core_handle) == ctx,
        c_prov_get0_dispatch(core_handle) == own_dispatch, up > 1 ? "counts" : "fails", fr);
    up = c_prov_up_ref(core_handle, 1);
    fr = c_prov_free(core_handle, 1);
    say(out, len, ", activating up_ref %d, deactivating free %d\n", up, fr);
}

static void run_callbacks(char *out, size_t len)
{
    OPENSSL_CORE_CTX *core_ctx = c_get_libctx(core_handle);
    OSSL_CALLBACK *cb = NULL;
    OSSL_INDICATOR_CALLBACK *icb = NULL;
    void *arg = NULL;
    OSSL_PARAM params[3];

    c_self_test_cb(core_ctx, &cb, &arg);
    say(out, len, "self-test callback %s", cb != NULL ? "set" : "unset");
    if (cb != NULL) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PROV_PARAM_SELF_TEST_PHASE,
                                                     "Start", 0);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PROV_PARAM_SELF_TEST_TYPE,
                                                     "KAT", 0);
        params[2] = OSSL_PARAM_construct_end();
        say(out, len, " returns %d", cb(params, arg));
    }
    c_indicator_cb(core_ctx, &icb);
    say(out, len, ", indicator callback %s", icb != NULL ? "set" : "unset");
    if (icb != NULL)
        say(out, len, " returns %d", icb("test_prov", "TEST-SUM", NULL));
    say(out, len, "\n");
}

static void run_threads(struct provctx *ctx, char *out, size_t len)
{
    say(out, len, "thread_start %d\n", c_thread_start(core_handle, thread_stop, ctx));
}

static int child_create(const OSSL_CORE_HANDLE *prov, void *cbdata)
{
    char *out = cbdata;

    say(out, 2048, "  child create %s\n", c_prov_name(prov));
    return 1;
}

static int child_remove(const OSSL_CORE_HANDLE *prov, void *cbdata)
{
    char *out = cbdata;

    say(out, 2048, "  child remove %s\n", c_prov_name(prov));
    return 1;
}

static int child_props(const char *props, void *cbdata)
{
    char *out = cbdata;

    say(out, 2048, "  child props \"%s\"\n", props);
    return 1;
}

static void run_children(char *out, size_t len)
{
    say(out, len, "register_child_cb %d\n",
        c_register_child_cb(core_handle, child_create, child_remove, child_props, out));
    c_deregister_child_cb(core_handle);
}

static int child_name(OSSL_PROVIDER *prov, void *arg)
{
    char *out = arg;

    say(out, 2048, " %s", OSSL_PROVIDER_get0_name(prov));
    return 1;
}

/* A child context: the parent's providers in it, a fetch through one, its default properties. */
static void run_child_ctx(struct provctx *ctx, char *out, size_t len)
{
    OSSL_LIB_CTX *child = OSSL_LIB_CTX_new_child(core_handle, core_in);
    EVP_MD *md;
    char *props;
    BIO *b;

    say(out, len, "child context %s", child != NULL ? "made" : "missing");
    if (child == NULL) {
        say(out, len, "\n");
        return;
    }
    say(out, len, ", providers:");
    OSSL_PROVIDER_do_all(child, child_name, out);
    md = EVP_MD_fetch(child, "SHA256", NULL);
    say(out, len, "; SHA256 %s", md != NULL ? OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)) : "missing");
    EVP_MD_free(md);
    props = EVP_get1_default_properties(child);
    say(out, len, "; default properties \"%s\"", props != NULL ? props : "(null)");
    OPENSSL_free(props);
    OSSL_LIB_CTX_free(child);
    /*
     * The BIO method behind BIO_new_from_core_bio (in the provider's context, whose core frees
     * the BIO's empty data), and the context's internal data at an index there's none.
     */
    b = BIO_new_ex(ctx->libctx, BIO_s_core());
    say(out, len, "; core BIO %s", b != NULL && BIO_method_type(b) == BIO_TYPE_CORE_TO_PROV ? "of its type" : "missing");
    BIO_free(b);
    say(out, len, ", get_data %s\n", OSSL_LIB_CTX_get_data(ctx->libctx, 1000) == NULL ? "NULL" : "data");
}

static int run(void *provctx, int which, char *out, size_t len, const char *arg)
{
    struct provctx *ctx = provctx;

    out[0] = '\0';
    switch (which) {
    case TEST_PROV_RUN_CORE:
        report_core(out, len);
        break;
    case TEST_PROV_RUN_ERRORS:
        run_errors(out, len);
        break;
    case TEST_PROV_RUN_MARKS:
        run_marks(out, len);
        break;
    case TEST_PROV_RUN_BIO:
        run_bio(ctx, out, len, arg);
        break;
    case TEST_PROV_RUN_MEMORY:
        run_memory(out, len);
        break;
    case TEST_PROV_RUN_SEEDS:
        run_seeds(out, len);
        break;
    case TEST_PROV_RUN_OBJECTS:
        run_objects(out, len);
        break;
    case TEST_PROV_RUN_PROVIDER:
        run_provider(ctx, out, len);
        break;
    case TEST_PROV_RUN_CALLBACKS:
        run_callbacks(out, len);
        break;
    case TEST_PROV_RUN_THREADS:
        run_threads(ctx, out, len);
        break;
    case TEST_PROV_RUN_CHILDREN:
        run_children(out, len);
        break;
    case TEST_PROV_RUN_CHILD_CTX:
        run_child_ctx(ctx, out, len);
        break;
    default:
        return 0;
    }
    return 1;
}

static void teardown(void *provctx)
{
    struct provctx *ctx = provctx;

    OSSL_LIB_CTX_free(ctx->libctx);
    c_free(ctx, "test_prov.c", __LINE__);
}

static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))query },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))reason_strings },
    { TEST_PROV_RUN, (void (*)(void))run },
    OSSL_DISPATCH_END
};

static void keep(const OSSL_DISPATCH *d)
{
    switch (d->function_id) {
    case OSSL_FUNC_CORE_GETTABLE_PARAMS: c_gettable_params = OSSL_FUNC_core_gettable_params(d); break;
    case OSSL_FUNC_CORE_GET_PARAMS: c_get_params = OSSL_FUNC_core_get_params(d); break;
    case OSSL_FUNC_CORE_GET_LIBCTX: c_get_libctx = OSSL_FUNC_core_get_libctx(d); break;
    case OSSL_FUNC_CORE_THREAD_START: c_thread_start = OSSL_FUNC_core_thread_start(d); break;
    case OSSL_FUNC_CORE_NEW_ERROR: c_new_error = OSSL_FUNC_core_new_error(d); break;
    case OSSL_FUNC_CORE_SET_ERROR_DEBUG: c_set_error_debug = OSSL_FUNC_core_set_error_debug(d); break;
    case OSSL_FUNC_CORE_VSET_ERROR: c_vset_error = OSSL_FUNC_core_vset_error(d); break;
    case OSSL_FUNC_CORE_SET_ERROR_MARK: c_set_error_mark = OSSL_FUNC_core_set_error_mark(d); break;
    case OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK:
        c_clear_last_error_mark = OSSL_FUNC_core_clear_last_error_mark(d);
        break;
    case OSSL_FUNC_CORE_POP_ERROR_TO_MARK: c_pop_error_to_mark = OSSL_FUNC_core_pop_error_to_mark(d); break;
    case OSSL_FUNC_CORE_COUNT_TO_MARK: c_count_to_mark = OSSL_FUNC_core_count_to_mark(d); break;
    case OSSL_FUNC_CORE_OBJ_ADD_SIGID: c_obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(d); break;
    case OSSL_FUNC_CORE_OBJ_CREATE: c_obj_create = OSSL_FUNC_core_obj_create(d); break;
    case OSSL_FUNC_CRYPTO_MALLOC: c_malloc = OSSL_FUNC_CRYPTO_malloc(d); break;
    case OSSL_FUNC_CRYPTO_ZALLOC: c_zalloc = OSSL_FUNC_CRYPTO_zalloc(d); break;
    case OSSL_FUNC_CRYPTO_FREE: c_free = OSSL_FUNC_CRYPTO_free(d); break;
    case OSSL_FUNC_CRYPTO_CLEAR_FREE: c_clear_free = OSSL_FUNC_CRYPTO_clear_free(d); break;
    case OSSL_FUNC_CRYPTO_REALLOC: c_realloc = OSSL_FUNC_CRYPTO_realloc(d); break;
    case OSSL_FUNC_CRYPTO_CLEAR_REALLOC: c_clear_realloc = OSSL_FUNC_CRYPTO_clear_realloc(d); break;
    case OSSL_FUNC_CRYPTO_SECURE_MALLOC: c_secure_malloc = OSSL_FUNC_CRYPTO_secure_malloc(d); break;
    case OSSL_FUNC_CRYPTO_SECURE_ZALLOC: c_secure_zalloc = OSSL_FUNC_CRYPTO_secure_zalloc(d); break;
    case OSSL_FUNC_CRYPTO_SECURE_FREE: c_secure_free = OSSL_FUNC_CRYPTO_secure_free(d); break;
    case OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE:
        c_secure_clear_free = OSSL_FUNC_CRYPTO_secure_clear_free(d);
        break;
    case OSSL_FUNC_CRYPTO_SECURE_ALLOCATED:
        c_secure_allocated = OSSL_FUNC_CRYPTO_secure_allocated(d);
        break;
    case OSSL_FUNC_OPENSSL_CLEANSE: c_cleanse = OSSL_FUNC_OPENSSL_cleanse(d); break;
    case OSSL_FUNC_BIO_NEW_FILE: c_bio_new_file = OSSL_FUNC_BIO_new_file(d); break;
    case OSSL_FUNC_BIO_NEW_MEMBUF: c_bio_new_membuf = OSSL_FUNC_BIO_new_membuf(d); break;
    case OSSL_FUNC_BIO_READ_EX: c_bio_read_ex = OSSL_FUNC_BIO_read_ex(d); break;
    case OSSL_FUNC_BIO_WRITE_EX: c_bio_write_ex = OSSL_FUNC_BIO_write_ex(d); break;
    case OSSL_FUNC_BIO_GETS: c_bio_gets = OSSL_FUNC_BIO_gets(d); break;
    case OSSL_FUNC_BIO_PUTS: c_bio_puts = OSSL_FUNC_BIO_puts(d); break;
    case OSSL_FUNC_BIO_CTRL: c_bio_ctrl = OSSL_FUNC_BIO_ctrl(d); break;
    case OSSL_FUNC_BIO_UP_REF: c_bio_up_ref = OSSL_FUNC_BIO_up_ref(d); break;
    case OSSL_FUNC_BIO_FREE: c_bio_free = OSSL_FUNC_BIO_free(d); break;
    case OSSL_FUNC_BIO_VPRINTF: c_bio_vprintf = OSSL_FUNC_BIO_vprintf(d); break;
    case OSSL_FUNC_BIO_VSNPRINTF: c_bio_vsnprintf = OSSL_FUNC_BIO_vsnprintf(d); break;
    case OSSL_FUNC_SELF_TEST_CB: c_self_test_cb = OSSL_FUNC_self_test_cb(d); break;
    case OSSL_FUNC_INDICATOR_CB: c_indicator_cb = OSSL_FUNC_indicator_cb(d); break;
    case OSSL_FUNC_GET_ENTROPY: c_get_entropy = OSSL_FUNC_get_entropy(d); break;
    case OSSL_FUNC_GET_USER_ENTROPY: c_get_user_entropy = OSSL_FUNC_get_user_entropy(d); break;
    case OSSL_FUNC_CLEANUP_ENTROPY: c_cleanup_entropy = OSSL_FUNC_cleanup_entropy(d); break;
    case OSSL_FUNC_CLEANUP_USER_ENTROPY:
        c_cleanup_user_entropy = OSSL_FUNC_cleanup_user_entropy(d);
        break;
    case OSSL_FUNC_GET_NONCE: c_get_nonce = OSSL_FUNC_get_nonce(d); break;
    case OSSL_FUNC_GET_USER_NONCE: c_get_user_nonce = OSSL_FUNC_get_user_nonce(d); break;
    case OSSL_FUNC_CLEANUP_NONCE: c_cleanup_nonce = OSSL_FUNC_cleanup_nonce(d); break;
    case OSSL_FUNC_CLEANUP_USER_NONCE: c_cleanup_user_nonce = OSSL_FUNC_cleanup_user_nonce(d); break;
    case OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB:
        c_register_child_cb = OSSL_FUNC_provider_register_child_cb(d);
        break;
    case OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB:
        c_deregister_child_cb = OSSL_FUNC_provider_deregister_child_cb(d);
        break;
    case OSSL_FUNC_PROVIDER_NAME: c_prov_name = OSSL_FUNC_provider_name(d); break;
    case OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX:
        c_prov_get0_provider_ctx = OSSL_FUNC_provider_get0_provider_ctx(d);
        break;
    case OSSL_FUNC_PROVIDER_GET0_DISPATCH:
        c_prov_get0_dispatch = OSSL_FUNC_provider_get0_dispatch(d);
        break;
    case OSSL_FUNC_PROVIDER_UP_REF: c_prov_up_ref = OSSL_FUNC_provider_up_ref(d); break;
    case OSSL_FUNC_PROVIDER_FREE: c_prov_free = OSSL_FUNC_provider_free(d); break;
    default: break;
    }
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx)
{
    const OSSL_DISPATCH *start = in;
    struct provctx *ctx;

    core_handle = handle;
    core_in = in;
    core_count = 0;
    for (; in->function_id != 0; in++) {
        if (core_count < sizeof(core_ids) / sizeof(core_ids[0]))
            core_ids[core_count++] = in->function_id;
        keep(in);
    }
    if (c_zalloc == NULL || (ctx = c_zalloc(sizeof(*ctx), "test_prov.c", __LINE__)) == NULL)
        return 0;
    ctx->libctx = OSSL_LIB_CTX_new_from_dispatch(handle, start);
    if (ctx->libctx == NULL) {
        c_free(ctx, "test_prov.c", __LINE__);
        return 0;
    }
    own_dispatch = provider_functions;
    *out = provider_functions;
    *provctx = ctx;
    return 1;
}
