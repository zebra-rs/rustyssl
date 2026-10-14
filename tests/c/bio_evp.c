/*
 * Conformance test for the EVP filter BIOs (BIO_f_md(3), BIO_f_cipher(3), BIO_f_reliable), in
 * TAP format:
 *   - the digest filter: digests what is written through it (as much as the next BIO took) and
 *     what is read, finished by BIO_gets (refusing a short buffer); BIO_set_md, BIO_get_md,
 *     BIO_get_md_ctx, BIO_set_md_ctx, BIO_reset, a filter without a digest or a next BIO, two
 *     digest filters in a chain, a next BIO that takes part of a write, and BIO_dup_chain;
 *   - the cipher filter: encrypts what is written, finished by BIO_flush, and decrypts what is
 *     read in chunks of several sizes (around ENC_MIN_CHUNK and the 4 KiB block), with a block
 *     cipher and a stream cipher; BIO_get_cipher_status after good and bad padding,
 *     BIO_get_cipher_ctx, BIO_reset, the pending counts and BIO_eof, BIO_set_cipher's calls to
 *     the BIO's callback, a filter without a cipher, and BIO_dup_chain;
 *   - the reliable filter's controls, without the writes and reads that crash OpenSSL 3 (they
 *     need a legacy digest's state, which provided digests don't have).
 * Every output is printed, so the results are compared byte for byte.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void hex(const char *label, const void *p, long n)
{
    const unsigned char *b = p;
    long i;

    printf("# %s (%ld):", label, n);
    for (i = 0; i < n; i++)
        printf("%02x", b[i]);
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

static unsigned char data[20000];

static int digest(const EVP_MD *md, const unsigned char *p, size_t n, unsigned char *out)
{
    unsigned int len = 0;

    EVP_Digest(p, n, out, &len, md, NULL);
    return (int)len;
}

static void md_filter(void)
{
    BIO *md = BIO_new(BIO_f_md()), *mem = BIO_new(BIO_s_mem()), *md2, *dup;
    const EVP_MD *got = (const EVP_MD *)1;
    EVP_MD_CTX *ctx = NULL, *own;
    unsigned char buf[EVP_MAX_MD_SIZE], want[EVP_MAX_MD_SIZE], in[600];
    char *p;
    int n, w, r, i;
    long l;

    /* No digest yet. */
    l = BIO_get_md(md, &got);
    printf("# get_md before set: %ld %s\n", l, got == NULL ? "NULL" : "set");
    check(BIO_write(md, "abc", 3) == 0, "md: no next BIO takes nothing");
    r = BIO_gets(md, (char *)buf, sizeof(buf));
    printf("# gets without a digest: %d\n", r);
    errors("gets without a digest");
    l = BIO_reset(md);
    printf("# reset without a digest: %ld\n", l);
    errors("reset without a digest");

    check(BIO_set_md(md, EVP_sha256()) == 1, "BIO_set_md");
    (void)BIO_get_md(md, &got);
    check(got == EVP_sha256(), "BIO_get_md");
    (void)BIO_get_md_ctx(md, &ctx);
    check(ctx != NULL && EVP_MD_CTX_get0_md(ctx) == EVP_sha256(), "BIO_get_md_ctx");
    BIO_push(md, mem);
    for (i = 0, w = 0; i < 1000; i += 37)
        w += BIO_write(md, data + i, i + 37 > 1000 ? 1000 - i : 37);
    check(w == 1000, "md: writes pass through");
    l = BIO_get_mem_data(mem, &p);
    check(l == 1000 && memcmp(p, data, 1000) == 0, "md: the next BIO got the data");
    r = BIO_gets(md, (char *)buf, 31);
    check(r == 0, "md: BIO_gets refuses a buffer shorter than the digest");
    r = BIO_gets(md, (char *)buf, 32);
    n = digest(EVP_sha256(), data, 1000, want);
    check(r == 32 && n == 32 && memcmp(buf, want, 32) == 0, "md: BIO_gets is the digest of what was written");
    r = BIO_gets(md, (char *)buf, 32);
    printf("# gets again: %d\n", r);
    errors("gets again");

    /* Reading digests what is read. */
    check(BIO_reset(md) == 1, "md: BIO_reset");
    BIO_write(mem, data + 1000, 777);
    for (n = 0; (r = BIO_read(md, in, 100)) > 0;)
        n += r;
    printf("# read %d, then %d, eof %d\n", n, r, BIO_eof(md));
    r = BIO_gets(md, (char *)buf, sizeof(buf));
    digest(EVP_sha256(), data + 1000, 1777 - 1000, want);
    check(r == 32 && memcmp(buf, want, 32) == 0, "md: BIO_gets is the digest of what was read");

    /* Two digests in a chain. */
    md2 = BIO_new(BIO_f_md());
    (void)BIO_set_md(md2, EVP_sha1());
    (void)BIO_reset(md);
    BIO_push(md2, md);
    BIO_write(md2, "chained", 7);
    r = BIO_gets(md2, (char *)buf, sizeof(buf));
    hex("sha1 of the chain", buf, r);
    r = BIO_gets(md, (char *)buf, sizeof(buf));
    hex("sha256 of the chain", buf, r);
    (void)BIO_pop(md2);
    BIO_free(md2);

    /* BIO_set_md_ctx: the filter takes the context. */
    own = EVP_MD_CTX_new();
    EVP_DigestInit_ex(own, EVP_sha512(), NULL);
    l = BIO_set_md_ctx(md, own);
    printf("# set_md_ctx: %ld\n", l);
    (void)BIO_get_md_ctx(md, &ctx);
    check(ctx == own, "md: BIO_set_md_ctx sets the context");
    BIO_write(md, "abc", 3);
    r = BIO_gets(md, (char *)buf, sizeof(buf));
    hex("sha512 through the set context", buf, r);

    /* A copy carries the digest's state. */
    EVP_DigestInit_ex(own, EVP_sha384(), NULL);
    BIO_write(md, "first half ", 11);
    dup = BIO_dup_chain(md);
    check(dup != NULL, "md: BIO_dup_chain");
    BIO_write(md, "second", 6);
    BIO_write(dup, "second", 6);
    r = BIO_gets(md, (char *)buf, sizeof(buf));
    n = BIO_gets(dup, (char *)want, sizeof(want));
    check(r == 48 && n == 48 && memcmp(buf, want, 48) == 0, "md: the copy digests on from the same state");
    BIO_free_all(dup);
    BIO_free_all(md);
    errors("the digest filter");
}

static void md_partial(void)
{
    BIO *md = BIO_new(BIO_f_md()), *b1 = NULL, *b2 = NULL;
    unsigned char buf[EVP_MAX_MD_SIZE], want[EVP_MAX_MD_SIZE], sink[64];
    int w, r;

    /* A pair with room for 10: the filter digests what the next BIO took. */
    BIO_new_bio_pair(&b1, 10, &b2, 10);
    (void)BIO_set_md(md, EVP_sha1());
    BIO_push(md, b1);
    w = BIO_write(md, data, 25);
    printf("# partial write %d, should_retry %d\n", w, BIO_should_retry(md));
    w = BIO_write(md, data + 10, 15);
    printf("# full pair: write %d, should_retry %d, should_write %d\n", w, BIO_should_retry(md), BIO_should_write(md));
    r = BIO_read(b2, sink, sizeof(sink));
    w = BIO_write(md, data + 10, 15);
    printf("# after %d read: write %d\n", r, w);
    r = BIO_gets(md, (char *)buf, sizeof(buf));
    digest(EVP_sha1(), data, 20, want);
    check(r == 20 && memcmp(buf, want, 20) == 0, "md: only what the next BIO took is digested");
    BIO_free_all(md);
    BIO_free(b2);
}

static void callback_note(BIO *b, int oper, const char *argp, size_t len, int argi, long argl, int ret, size_t *processed)
{
    (void)b;
    (void)len;
    (void)processed;
    printf("# callback oper %#x argp %s argi %d argl %ld ret %d\n", oper,
        argp == NULL ? "NULL" : argp == (const char *)EVP_aes_128_cbc() ? "cipher" : "other",
        argi, argl, ret);
}

static long callback(BIO *b, int oper, const char *argp, size_t len, int argi, long argl, int ret, size_t *processed)
{
    callback_note(b, oper, argp, len, argi, argl, ret, processed);
    return ret;
}

static void cipher_filter(void)
{
    static const unsigned char key[32] = "0123456789abcdef0123456789abcde";
    static const unsigned char iv[17] = "fedcba9876543210";
    static const int chunks[] = { 1, 7, 16, 255, 256, 257, 300, 4096, 5000, 20000 };
    unsigned char *want = OPENSSL_malloc(sizeof(data) + 64), *out = OPENSSL_malloc(sizeof(data) + 64);
    EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new(), *got = NULL;
    BIO *enc, *mem, *dup;
    char *p;
    int wl = 0, fl = 0, i, n, r;
    long l;
    size_t c;

    EVP_EncryptInit_ex(e, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(e, want, &wl, data, 10000);
    EVP_EncryptFinal_ex(e, want + wl, &fl);
    wl += fl;

    /* Encrypting writes. */
    enc = BIO_new(BIO_f_cipher());
    mem = BIO_new(BIO_s_mem());
    check(BIO_set_cipher(enc, EVP_aes_128_cbc(), key, iv, 1) == 1, "BIO_set_cipher");
    (void)BIO_get_cipher_ctx(enc, &got);
    check(got != NULL && EVP_CIPHER_CTX_get_block_size(got) == 16, "BIO_get_cipher_ctx");
    BIO_push(enc, mem);
    for (i = 0, n = 0; i < 10000; i += 333)
        n += BIO_write(enc, data + i, i + 333 > 10000 ? 10000 - i : 333);
    printf("# wrote %d, wpending %ld, pending %ld\n", n, (long)BIO_wpending(enc), (long)BIO_pending(enc));
    l = BIO_get_mem_data(mem, &p);
    printf("# before flush the next BIO has %ld\n", l);
    check(BIO_flush(enc) == 1, "cipher: BIO_flush");
    l = BIO_get_mem_data(mem, &p);
    check(l == wl && memcmp(p, want, wl) == 0, "cipher: the written data, encrypted and finished");
    printf("# status %ld, flush again %d\n", BIO_get_cipher_status(enc), BIO_flush(enc));
    l = BIO_get_mem_data(mem, &p);
    printf("# after a second flush the next BIO has %ld\n", l);

    /* BIO_reset starts again with the same key. */
    (void)BIO_reset(enc);
    BIO_write(enc, data, 100);
    (void)BIO_flush(enc);
    l = BIO_get_mem_data(mem, &p);
    printf("# reset (the memory BIO too), wrote 100: %ld\n", l);
    BIO_free_all(enc);

    /* Decrypting reads, in chunks of each size. */
    for (c = 0; c < sizeof(chunks) / sizeof(chunks[0]); c++) {
        char label[64];

        enc = BIO_new(BIO_f_cipher());
        BIO_set_cipher(enc, EVP_aes_128_cbc(), key, iv, 0);
        BIO_push(enc, BIO_new_mem_buf(want, wl));
        for (n = 0; n < (int)sizeof(data) && (r = BIO_read(enc, out + n, chunks[c])) > 0;)
            n += r;
        snprintf(label, sizeof(label), "cipher: decrypting reads of %d", chunks[c]);
        printf("# chunks of %d: %d octets, last %d, eof %d, status %ld\n", chunks[c], n, r,
            BIO_eof(enc), BIO_get_cipher_status(enc));
        check(n == 10000 && memcmp(out, data, 10000) == 0, label);
        BIO_free_all(enc);
    }

    /* Bad padding: the last block is corrupt. */
    want[wl - 1] ^= 1;
    enc = BIO_new(BIO_f_cipher());
    BIO_set_cipher(enc, EVP_aes_128_cbc(), key, iv, 0);
    BIO_push(enc, BIO_new_mem_buf(want, wl));
    for (n = 0; (r = BIO_read(enc, out + n, 1000)) > 0;)
        n += r;
    printf("# bad padding: %d octets, last %d, status %ld\n", n, r, BIO_get_cipher_status(enc));
    errors("bad padding");
    BIO_free_all(enc);
    want[wl - 1] ^= 1;

    /* A stream cipher (block size 1), read and written. */
    enc = BIO_new(BIO_f_cipher());
    mem = BIO_new(BIO_s_mem());
    BIO_set_cipher(enc, EVP_aes_256_ctr(), key, iv, 1);
    BIO_push(enc, mem);
    BIO_write(enc, data, 4500);
    BIO_write(enc, data + 4500, 9);
    l = BIO_get_mem_data(mem, &p);
    printf("# ctr: %ld before flush, flush %d\n", l, BIO_flush(enc));
    l = BIO_get_mem_data(mem, &p);
    memcpy(out, p, (size_t)l);
    hex("ctr start", out, 32);
    BIO_free_all(enc);
    enc = BIO_new(BIO_f_cipher());
    BIO_set_cipher(enc, EVP_aes_256_ctr(), key, iv, 0);
    BIO_push(enc, BIO_new_mem_buf(out, (int)l));
    for (n = 0; (r = BIO_read(enc, want + n, 513)) > 0;)
        n += r;
    check(n == 4509 && memcmp(want, data, 4509) == 0, "cipher: a stream cipher read back");
    BIO_free_all(enc);

    /* BIO_set_cipher calls the BIO's callback. */
    enc = BIO_new(BIO_f_cipher());
    BIO_set_callback_ex(enc, callback);
    r = BIO_set_cipher(enc, EVP_aes_128_cbc(), key, iv, 1);
    printf("# set_cipher with a callback: %d\n", r);
    BIO_set_callback_ex(enc, NULL);

    /* A copy carries the cipher's state. */
    mem = BIO_new(BIO_s_mem());
    BIO_push(enc, mem);
    BIO_write(enc, data, 40);
    dup = BIO_dup_chain(enc);
    check(dup != NULL, "cipher: BIO_dup_chain");
    BIO_write(enc, data + 40, 24);
    (void)BIO_flush(enc);
    BIO_write(dup, data + 40, 24);
    (void)BIO_flush(dup);
    l = BIO_get_mem_data(mem, &p);
    hex("original", p, l);
    l = BIO_get_mem_data(BIO_next(dup), &p);
    hex("copy", p, l);
    BIO_free_all(dup);
    BIO_free_all(enc);

    /* No cipher set. */
    enc = BIO_new(BIO_f_cipher());
    mem = BIO_new(BIO_s_mem());
    BIO_push(enc, mem);
    r = BIO_write(enc, data, 10);
    printf("# no cipher: write %d, status %ld\n", r, BIO_get_cipher_status(enc));
    errors("a write without a cipher");
    BIO_write(mem, data, 10);
    r = BIO_read(enc, out, 10);
    printf("# no cipher: read %d\n", r);
    errors("a read without a cipher");
    BIO_free_all(enc);
    enc = BIO_new(BIO_f_cipher());
    r = BIO_write(enc, data, 10);
    n = BIO_read(enc, out, 10);
    printf("# no next BIO: write %d, read %d\n", r, n);
    BIO_free(enc);

    EVP_CIPHER_CTX_free(e);
    OPENSSL_free(want);
    OPENSSL_free(out);
    errors("the cipher filter");
}

static void reliable_filter(void)
{
    BIO *ok = BIO_new(BIO_f_reliable()), *mem = BIO_new(BIO_s_mem());
    const EVP_MD *got = (const EVP_MD *)1;
    unsigned char buf[16];
    long l;
    int r;

    BIO_push(ok, mem);
    l = BIO_get_md(ok, &got);
    printf("# reliable: get_md before set %ld %s\n", l, got == (const EVP_MD *)1 ? "untouched" : "set");
    printf("# reliable: info %ld, eof %d, pending %ld, wpending %ld\n", BIO_ctrl(ok, BIO_CTRL_INFO, 0, NULL),
        BIO_eof(ok), (long)BIO_pending(ok), (long)BIO_wpending(ok));
    r = BIO_write(ok, "abc", 3);
    printf("# reliable: write before a digest %d\n", r);
    r = BIO_read(ok, buf, sizeof(buf));
    printf("# reliable: read before a digest %d\n", r);
    r = BIO_flush(ok);
    printf("# reliable: flush before a digest %d\n", r);
    errors("the reliable filter without a digest");
    check(BIO_set_md(ok, EVP_sha256()) == 1, "reliable: BIO_set_md");
    (void)BIO_get_md(ok, &got);
    check(got == EVP_sha256(), "reliable: BIO_get_md");
    printf("# reliable: reset %d, info %ld\n", BIO_reset(ok), BIO_ctrl(ok, BIO_CTRL_INFO, 0, NULL));
    BIO_free_all(ok);
    errors("the reliable filter");
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7 + 3);
    {
        const BIO_METHOD *m[3];
        int k;

        m[0] = BIO_f_md();
        m[1] = BIO_f_cipher();
        m[2] = BIO_f_reliable();
        for (k = 0; k < 3; k++) {
            BIO *b = BIO_new(m[k]);

            printf("# method %#x \"%s\", init %d\n", BIO_method_type(b), BIO_method_name(b), BIO_get_init(b));
            BIO_free(b);
        }
    }
    md_filter();
    md_partial();
    cipher_filter();
    reliable_filter();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
