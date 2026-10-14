/*
 * Conformance test for application-defined digests (EVP_MD_meth_new(3)), in TAP format:
 *   - EVP_MD_meth_new, the setters (each sets once: a second call fails), the getters, and
 *     EVP_MD_meth_dup and EVP_MD_meth_free, of a digest of the test's own and of the static
 *     and fetched ones (whose functions the getters report, and which dup and free refuse);
 *   - digesting with it: every call of its functions is logged, so the order and count of
 *     init, update, final, copy, cleanup, and ctrl are compared, through EVP_DigestInit_ex,
 *     EVP_DigestUpdate in pieces, EVP_DigestFinal_ex, EVP_Digest, EVP_MD_CTX_copy_ex (to a
 *     fresh context and to one with the same digest), EVP_MD_CTX_reset, EVP_MD_CTX_ctrl, an
 *     XOF through EVP_DigestFinalXOF, EVP_MD_CTX_set_update_fn, EVP_MD_CTX_FLAG_NO_INIT, and
 *     a digest with no application data;
 *   - the method's properties through the EVP_MD getters, and the context's;
 *   - a copy of EVP_sha256() given its state's size, which digests as SHA-256 does, through
 *     the static digest's own functions; and so for each static digest whose state is a public
 *     structure (MD4, MD5, SHA-1, SHA-2, RIPEMD-160, MDC2, Whirlpool, and MD5+SHA-1, whose
 *     state is MD5's then SHA-1's), against its own one-shot function, with SHA-1's and
 *     MD5+SHA-1's SSLv3 master secret ctrl.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/mdc2.h>
#include <openssl/objects.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/whrlpool.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("# %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* Prints and clears the error queue: library and reason of each entry. */
static void errors(const char *what)
{
    unsigned long e;

    printf("# errors after %s:", what);
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

/*
 * The test's digest: an 8-octet sum. Its state is in the context's application data; each
 * function logs its call, and checks that the state is where it should be.
 */
struct toy_state {
    unsigned char sum[8];
    unsigned long count;
    int xoflen;
};

static int toy_init(EVP_MD_CTX *ctx)
{
    struct toy_state *s = EVP_MD_CTX_md_data(ctx);

    printf("# toy init (state %s)\n", s == NULL ? "NULL" : "set");
    if (s != NULL) {
        memset(s, 0, sizeof(*s));
        s->xoflen = 8;
    }
    return 1;
}

static int toy_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    struct toy_state *s = EVP_MD_CTX_md_data(ctx);
    const unsigned char *p = data;
    size_t i;

    printf("# toy update %zu\n", count);
    if (s == NULL)
        return 0;
    for (i = 0; i < count; i++)
        s->sum[(s->count + i) % 8] += p[i];
    s->count += count;
    return 1;
}

static int toy_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct toy_state *s = EVP_MD_CTX_md_data(ctx);
    int i;

    printf("# toy final (state %s)\n", s == NULL ? "NULL" : "set");
    if (s == NULL)
        return 0;
    for (i = 0; i < s->xoflen; i++)
        md[i] = (unsigned char)(s->sum[i % 8] + i / 8 + s->count);
    return 1;
}

static int toy_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    struct toy_state *t = EVP_MD_CTX_md_data(to);
    const struct toy_state *f = EVP_MD_CTX_md_data((EVP_MD_CTX *)from);

    printf("# toy copy (states %s, %s; %s)\n", t == NULL ? "NULL" : "set", f == NULL ? "NULL" : "set",
        t != NULL && f != NULL && t != f && memcmp(t, f, sizeof(*t)) == 0 ? "already copied" : "not copied");
    return 1;
}

static int toy_cleanup(EVP_MD_CTX *ctx)
{
    printf("# toy cleanup (state %s)\n", EVP_MD_CTX_md_data(ctx) == NULL ? "NULL" : "set");
    return 1;
}

static int toy_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    struct toy_state *s = EVP_MD_CTX_md_data(ctx);

    printf("# toy ctrl %d %d %s\n", cmd, p1, p2 == NULL ? "NULL" : "set");
    if (cmd == EVP_MD_CTRL_XOF_LEN && s != NULL && p1 <= 32) {
        s->xoflen = p1;
        return 1;
    }
    return cmd == 0x1000 ? 7 : 0;
}

static EVP_MD *make_toy(unsigned long flags, int datasize)
{
    EVP_MD *md = EVP_MD_meth_new(NID_undef, NID_undef);

    check(md != NULL, "EVP_MD_meth_new");
    check(EVP_MD_meth_set_result_size(md, 8) == 1 && EVP_MD_meth_set_input_blocksize(md, 16) == 1
            && EVP_MD_meth_set_app_datasize(md, datasize) == 1
            && EVP_MD_meth_set_flags(md, flags) == 1
            && EVP_MD_meth_set_init(md, toy_init) == 1 && EVP_MD_meth_set_update(md, toy_update) == 1
            && EVP_MD_meth_set_final(md, toy_final) == 1 && EVP_MD_meth_set_copy(md, toy_copy) == 1
            && EVP_MD_meth_set_cleanup(md, toy_cleanup) == 1 && EVP_MD_meth_set_ctrl(md, toy_ctrl) == 1,
        "the setters");
    return md;
}

static void setters_and_getters(void)
{
    EVP_MD *md = make_toy(0, sizeof(struct toy_state)), *dup;
    EVP_MD *fetched = EVP_MD_fetch(NULL, "SHA256", NULL);

    /* Each setter sets once. */
    printf("# again: size %d block %d data %d flags %d init %d update %d final %d copy %d cleanup %d ctrl %d\n",
        EVP_MD_meth_set_result_size(md, 9), EVP_MD_meth_set_input_blocksize(md, 9),
        EVP_MD_meth_set_app_datasize(md, 9), EVP_MD_meth_set_flags(md, 4), EVP_MD_meth_set_init(md, toy_init),
        EVP_MD_meth_set_update(md, toy_update), EVP_MD_meth_set_final(md, toy_final),
        EVP_MD_meth_set_copy(md, toy_copy), EVP_MD_meth_set_cleanup(md, toy_cleanup),
        EVP_MD_meth_set_ctrl(md, toy_ctrl));
    printf("# flags can be set after none: %d, then %lx\n", EVP_MD_meth_set_flags(md, 4), EVP_MD_meth_get_flags(md));
    check(EVP_MD_meth_get_result_size(md) == 8 && EVP_MD_meth_get_input_blocksize(md) == 16
            && EVP_MD_meth_get_app_datasize(md) == (int)sizeof(struct toy_state)
            && EVP_MD_meth_get_init(md) == toy_init && EVP_MD_meth_get_update(md) == toy_update
            && EVP_MD_meth_get_final(md) == toy_final && EVP_MD_meth_get_copy(md) == toy_copy
            && EVP_MD_meth_get_cleanup(md) == toy_cleanup && EVP_MD_meth_get_ctrl(md) == toy_ctrl,
        "the getters");
    printf("# EVP_MD: type %d pkey %d size %d block %d flags %lx name %s, is_a UNDEF %d, xof %d\n",
        EVP_MD_get_type(md), EVP_MD_get_pkey_type(md), EVP_MD_get_size(md), EVP_MD_get_block_size(md),
        EVP_MD_get_flags(md), EVP_MD_get0_name(md) == NULL ? "NULL" : EVP_MD_get0_name(md),
        EVP_MD_is_a(md, "UNDEF"), EVP_MD_xof(md));
    printf("# provider %s, description %s, up_ref %d\n", EVP_MD_get0_provider(md) == NULL ? "NULL" : "set",
        EVP_MD_get0_description(md) == NULL ? "NULL" : "set", EVP_MD_up_ref(md));
    EVP_MD_free(md);

    /* Copies. */
    dup = EVP_MD_meth_dup(md);
    check(dup != NULL && dup != md && EVP_MD_meth_get_update(dup) == toy_update
            && EVP_MD_meth_get_app_datasize(dup) == (int)sizeof(struct toy_state),
        "EVP_MD_meth_dup of the test's digest");
    EVP_MD_meth_free(dup);
    printf("# dup of a fetched digest: %s\n", EVP_MD_meth_dup(fetched) == NULL ? "NULL" : "a copy");
    errors("a dup of a fetched digest");

    /* The static digests' own functions, and the fetched ones' (none). */
    printf("# static sha256: init %s update %s final %s copy %s cleanup %s ctrl %s, size %d block %d data %d flags %lx\n",
        EVP_MD_meth_get_init(EVP_sha256()) == NULL ? "NULL" : "set",
        EVP_MD_meth_get_update(EVP_sha256()) == NULL ? "NULL" : "set",
        EVP_MD_meth_get_final(EVP_sha256()) == NULL ? "NULL" : "set",
        EVP_MD_meth_get_copy(EVP_sha256()) == NULL ? "NULL" : "set",
        EVP_MD_meth_get_cleanup(EVP_sha256()) == NULL ? "NULL" : "set",
        EVP_MD_meth_get_ctrl(EVP_sha256()) == NULL ? "NULL" : "set", EVP_MD_meth_get_result_size(EVP_sha256()),
        EVP_MD_meth_get_input_blocksize(EVP_sha256()), EVP_MD_meth_get_app_datasize(EVP_sha256()),
        EVP_MD_meth_get_flags(EVP_sha256()));
    printf("# static sha1: ctrl %s; md5 init %s; fetched sha256: init %s, size %d data %d\n",
        EVP_MD_meth_get_ctrl(EVP_sha1()) == NULL ? "NULL" : "set",
        EVP_MD_meth_get_init(EVP_md5()) == NULL ? "NULL" : "set",
        EVP_MD_meth_get_init(fetched) == NULL ? "NULL" : "set", EVP_MD_meth_get_result_size(fetched),
        EVP_MD_meth_get_app_datasize(fetched));
    /* Freeing a static or fetched digest this way does nothing. */
    EVP_MD_meth_free((EVP_MD *)EVP_sha256());
    EVP_MD_meth_free(fetched);
    printf("# sha256 still works: size %d\n", EVP_MD_get_size(fetched));
    EVP_MD_meth_free(NULL);
    EVP_MD_free(fetched);
    EVP_MD_meth_free(md);
    errors("the setters and getters");
}

static void digesting(void)
{
    EVP_MD *md = make_toy(0, sizeof(struct toy_state));
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(), *ctx2 = EVP_MD_CTX_new();
    unsigned char out[64], out2[64];
    unsigned int len = 0, len2 = 0;
    int r;

    printf("# -- init, update in pieces, final\n");
    r = EVP_DigestInit_ex(ctx, md, NULL);
    printf("# init %d; ctx: size %d block %d md %s data %s\n", r, EVP_MD_CTX_get_size(ctx),
        EVP_MD_CTX_get_block_size(ctx), EVP_MD_CTX_get0_md(ctx) == md ? "ours" : "other",
        EVP_MD_CTX_md_data(ctx) == NULL ? "NULL" : "set");
    EVP_DigestUpdate(ctx, "hello ", 6);
    EVP_DigestUpdate(ctx, "", 0);
    EVP_DigestUpdate(ctx, "world", 5);
    r = EVP_DigestFinal_ex(ctx, out, &len);
    printf("# final %d, %u octets\n", r, len);
    hex("toy of \"hello world\"", out, len);
    r = EVP_DigestUpdate(ctx, "more", 4);
    printf("# update after final %d\n", r);
    r = EVP_DigestFinal_ex(ctx, out, &len);
    printf("# final after final %d\n", r);
    errors("finals");

    printf("# -- EVP_Digest\n");
    r = EVP_Digest("hello world", 11, out2, &len2, md, NULL);
    printf("# EVP_Digest %d, %u octets\n", r, len2);
    hex("EVP_Digest", out2, len2);

    printf("# -- copies\n");
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, "abc", 3);
    r = EVP_MD_CTX_copy_ex(ctx2, ctx);
    printf("# copy to a fresh context %d\n", r);
    EVP_DigestUpdate(ctx2, "def", 3);
    EVP_DigestFinal_ex(ctx2, out2, &len2);
    hex("copy + def", out2, len2);
    r = EVP_MD_CTX_copy_ex(ctx2, ctx);
    printf("# copy to a context with the same digest %d\n", r);
    EVP_DigestFinal_ex(ctx2, out2, &len2);
    hex("copy", out2, len2);
    EVP_DigestFinal_ex(ctx, out, &len);
    check(len == len2 && memcmp(out, out2, len) == 0, "the copy digests as the original");

    printf("# -- reset and free\n");
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, "x", 1);
    r = EVP_MD_CTX_reset(ctx);
    printf("# reset %d, md %s\n", r, EVP_MD_CTX_get0_md(ctx) == NULL ? "NULL" : "set");
    EVP_DigestInit_ex(ctx, md, NULL);
    printf("# init again with the same digest\n");
    EVP_DigestInit_ex(ctx, md, NULL);
    printf("# init with another digest\n");
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    printf("# and back\n");
    EVP_DigestInit_ex(ctx, md, NULL);

    printf("# -- ctrl\n");
    r = EVP_MD_CTX_ctrl(ctx, 0x1000, 3, out);
    printf("# ctrl 0x1000: %d\n", r);
    r = EVP_MD_CTX_ctrl(ctx, 0x1001, 0, NULL);
    printf("# ctrl 0x1001: %d\n", r);
    errors("ctrl");

    printf("# -- XOF length on a digest that isn't one\n");
    r = EVP_DigestFinalXOF(ctx, out, 12);
    printf("# EVP_DigestFinalXOF %d\n", r);
    errors("an XOF final of a fixed digest");

    printf("# -- update function\n");
    EVP_DigestInit_ex(ctx, md, NULL);
    check(EVP_MD_CTX_update_fn(ctx) == toy_update, "EVP_MD_CTX_update_fn is the digest's");
    EVP_MD_CTX_set_update_fn(ctx, NULL);
    r = EVP_DigestUpdate(ctx, "abc", 3);
    printf("# update with no update function %d\n", r);
    EVP_MD_CTX_set_update_fn(ctx, toy_update);
    r = EVP_DigestUpdate(ctx, "abc", 3);
    printf("# update with it back %d\n", r);

    printf("# -- no init\n");
    EVP_MD_CTX_free(ctx);
    ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NO_INIT);
    r = EVP_DigestInit_ex(ctx, md, NULL);
    printf("# init with NO_INIT %d, data %s, update fn %s\n", r, EVP_MD_CTX_md_data(ctx) == NULL ? "NULL" : "set",
        EVP_MD_CTX_update_fn(ctx) == NULL ? "NULL" : "set");

    printf("# -- free\n");
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ctx2);
    EVP_MD_meth_free(md);
    errors("digesting");
}

static void xof(void)
{
    EVP_MD *md = make_toy(EVP_MD_FLAG_XOF, sizeof(struct toy_state));
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char out[64];
    int r;

    printf("# -- an XOF: xof %d\n", EVP_MD_xof(md));
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, "abc", 3);
    r = EVP_DigestFinalXOF(ctx, out, 20);
    printf("# EVP_DigestFinalXOF 20: %d\n", r);
    hex("20 octets", out, 20);
    EVP_DigestInit_ex(ctx, md, NULL);
    r = EVP_DigestFinalXOF(ctx, out, 40);
    printf("# EVP_DigestFinalXOF 40 (refused by its ctrl): %d\n", r);
    errors("an XOF");
    EVP_MD_CTX_free(ctx);
    EVP_MD_meth_free(md);
}

static void no_data(void)
{
    EVP_MD *md = make_toy(0, 0);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char out[64];
    unsigned int len = 0;
    int r;

    printf("# -- a digest without application data\n");
    r = EVP_DigestInit_ex(ctx, md, NULL);
    printf("# init %d, data %s, update fn %s\n", r, EVP_MD_CTX_md_data(ctx) == NULL ? "NULL" : "set",
        EVP_MD_CTX_update_fn(ctx) == NULL ? "NULL" : "set");
    r = EVP_DigestUpdate(ctx, "abc", 3);
    printf("# update %d\n", r);
    r = EVP_DigestFinal_ex(ctx, out, &len);
    printf("# final %d\n", r);
    errors("a digest without data");
    EVP_MD_CTX_free(ctx);
    EVP_MD_meth_free(md);
}

static void sha256_copy(void)
{
    EVP_MD *md = EVP_MD_meth_dup(EVP_sha256());
    unsigned char out[64], want[64];
    unsigned int len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int r;

    printf("# -- a copy of EVP_sha256()\n");
    check(md != NULL, "EVP_MD_meth_dup of EVP_sha256()");
    printf("# its data size %d, then set %d\n", EVP_MD_meth_get_app_datasize(md),
        EVP_MD_meth_set_app_datasize(md, sizeof(SHA256_CTX)));
    printf("# type %d size %d block %d name %s\n", EVP_MD_get_type(md), EVP_MD_get_size(md),
        EVP_MD_get_block_size(md), EVP_MD_get0_name(md));
    r = EVP_DigestInit_ex(ctx, md, NULL) && EVP_DigestUpdate(ctx, "abc", 3) && EVP_DigestFinal_ex(ctx, out, &len);
    SHA256((const unsigned char *)"abc", 3, want);
    check(r == 1 && len == 32 && memcmp(out, want, 32) == 0, "the copy digests as SHA-256");
    /* The static digest's own functions, called on the context directly. */
    EVP_DigestInit_ex(ctx, md, NULL);
    r = EVP_MD_meth_get_update(EVP_sha256())(ctx, "abc", 3) && EVP_MD_meth_get_final(EVP_sha256())(ctx, out);
    check(r == 1 && memcmp(out, want, 32) == 0, "the static digest's functions on the copy's state");
    EVP_MD_CTX_free(ctx);
    EVP_MD_meth_free(md);
    errors("the copy of EVP_sha256()");
}

/* A copy of a static digest, given its state's size, over "abc" (and the SSLv3 ctrl). */
static int copy_digest(const EVP_MD *from, int datasize, int ssl3, unsigned char *out)
{
    EVP_MD *md = EVP_MD_meth_dup(from);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char ms[48];
    unsigned int len = 0;
    int r;

    memset(ms, 0x77, sizeof(ms));
    EVP_MD_meth_set_app_datasize(md, datasize);
    r = EVP_DigestInit_ex(ctx, md, NULL) && EVP_DigestUpdate(ctx, "abc", 3);
    if (r && ssl3) {
        int c = EVP_MD_CTX_ctrl(ctx, EVP_CTRL_SSL3_MASTER_SECRET, 48, ms);

        printf("# %s ssl3 ctrl %d, with a short secret %d\n", EVP_MD_get0_name(from), c,
            EVP_MD_CTX_ctrl(ctx, EVP_CTRL_SSL3_MASTER_SECRET, 47, ms));
    }
    r = r && EVP_DigestFinal_ex(ctx, out, &len);
    EVP_MD_CTX_free(ctx);
    EVP_MD_meth_free(md);
    return r ? (int)len : -1;
}

static void static_copies(void)
{
    struct md5_sha1 {
        MD5_CTX md5;
        SHA_CTX sha1;
    };
    unsigned char got[64], want[64];
    const unsigned char *abc = (const unsigned char *)"abc";
    unsigned int wl = 0;
    int n;

    printf("# -- copies of the static digests\n");
    n = copy_digest(EVP_md4(), sizeof(MD4_CTX), 0, got);
    MD4(abc, 3, want);
    check(n == 16 && memcmp(got, want, 16) == 0, "a copy of EVP_md4()");
    n = copy_digest(EVP_md5(), sizeof(MD5_CTX), 0, got);
    MD5(abc, 3, want);
    check(n == 16 && memcmp(got, want, 16) == 0, "a copy of EVP_md5()");
    n = copy_digest(EVP_sha1(), sizeof(SHA_CTX), 0, got);
    SHA1(abc, 3, want);
    check(n == 20 && memcmp(got, want, 20) == 0, "a copy of EVP_sha1()");
    n = copy_digest(EVP_sha224(), sizeof(SHA256_CTX), 0, got);
    SHA224(abc, 3, want);
    check(n == 28 && memcmp(got, want, 28) == 0, "a copy of EVP_sha224()");
    n = copy_digest(EVP_sha384(), sizeof(SHA512_CTX), 0, got);
    SHA384(abc, 3, want);
    check(n == 48 && memcmp(got, want, 48) == 0, "a copy of EVP_sha384()");
    n = copy_digest(EVP_sha512(), sizeof(SHA512_CTX), 0, got);
    SHA512(abc, 3, want);
    check(n == 64 && memcmp(got, want, 64) == 0, "a copy of EVP_sha512()");
    n = copy_digest(EVP_sha512_224(), sizeof(SHA512_CTX), 0, got);
    EVP_Digest(abc, 3, want, &wl, EVP_sha512_224(), NULL);
    check(n == 28 && wl == 28 && memcmp(got, want, 28) == 0, "a copy of EVP_sha512_224()");
    n = copy_digest(EVP_sha512_256(), sizeof(SHA512_CTX), 0, got);
    EVP_Digest(abc, 3, want, &wl, EVP_sha512_256(), NULL);
    check(n == 32 && wl == 32 && memcmp(got, want, 32) == 0, "a copy of EVP_sha512_256()");
    n = copy_digest(EVP_ripemd160(), sizeof(RIPEMD160_CTX), 0, got);
    RIPEMD160(abc, 3, want);
    check(n == 20 && memcmp(got, want, 20) == 0, "a copy of EVP_ripemd160()");
    n = copy_digest(EVP_mdc2(), sizeof(MDC2_CTX), 0, got);
    MDC2(abc, 3, want);
    check(n == 16 && memcmp(got, want, 16) == 0, "a copy of EVP_mdc2()");
    n = copy_digest(EVP_whirlpool(), sizeof(WHIRLPOOL_CTX), 0, got);
    WHIRLPOOL(abc, 3, want);
    check(n == 64 && memcmp(got, want, 64) == 0, "a copy of EVP_whirlpool()");
    n = copy_digest(EVP_md5_sha1(), sizeof(struct md5_sha1), 0, got);
    MD5(abc, 3, want);
    SHA1(abc, 3, want + 16);
    check(n == 36 && memcmp(got, want, 36) == 0, "a copy of EVP_md5_sha1()");
    n = copy_digest(EVP_sha1(), sizeof(SHA_CTX), 1, got);
    hex("SHA-1 with the SSLv3 step", got, n < 0 ? 0 : (size_t)n);
    n = copy_digest(EVP_md5_sha1(), sizeof(struct md5_sha1), 1, got);
    hex("MD5+SHA-1 with the SSLv3 step", got, n < 0 ? 0 : (size_t)n);
    errors("the static digests' copies");
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setters_and_getters();
    digesting();
    xof();
    no_data();
    sha256_copy();
    static_copies();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
