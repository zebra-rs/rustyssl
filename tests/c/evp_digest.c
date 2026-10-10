/*
 * Conformance test for digesting (EVP_DigestInit(3), EVP_MD_CTX_new(3), provider-digest(7)) with
 * the default provider's digests, in TAP format. For every digest it prints the sizes, flags,
 * and context parameter lists, and the digest of messages around the block size, one-shot and
 * in chunks. Then it walks the paths where OpenSSL's behavior is particular:
 *   - SHAKE without a length (EVP_DigestFinal_ex fails), with xoflen set, and squeezed in
 *     pieces; squeezing after a final, finalizing after a squeeze, and updating after a squeeze
 *     (which the provider ignores, shifting the buffered output);
 *   - EVP_DigestFinalXOF on fixed-size digests, which finalizes them anyway;
 *   - BLAKE2's size parameter, which applies at the next init while the gettable size follows
 *     the parameter at once;
 *   - SSLv3's master secret on SHA-1 and MD5-SHA1;
 *   - re-initialization (the algorithm context, and an XOF's length, are kept), the NO_INIT
 *     legacy path, copies onto contexts with the same and other digests, reset, and finals
 *     after finals and updates after finals;
 *   - flags, ctrl, EVP_Q_digest, EVP_Digest, and the get0/get1 accessors.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
/* EVP_MD_CTX_md and EVP_MD_CTX_update_fn are deprecated. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* Prints and clears the error queue as library/reason pairs. */
static void errors(void)
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

static unsigned char data[1200];

static void keys(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    if (p == NULL)
        printf(" (none)");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u", p->key, p->data_type);
    printf("\n");
}

static const char *names[] = {
    "SHA1", "SHA224", "SHA256", "SHA2-256/192", "SHA384", "SHA512", "SHA512-224", "SHA512-256",
    "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "KECCAK-224", "KECCAK-256", "KECCAK-384",
    "KECCAK-512", "KECCAK-KMAC-128", "KECCAK-KMAC-256", "SHAKE128", "SHAKE256", "BLAKE2s256",
    "BLAKE2b512", "SM3", "MD5", "MD5-SHA1", "RIPEMD160", "NULL", NULL
};

/* Digests data[0..len] in pieces of `piece` (whole if 0); prints the result. */
static int digest_in_pieces(const EVP_MD *md, size_t len, size_t piece, unsigned char *out,
                            unsigned int *outl)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t done = 0;
    int ok = EVP_DigestInit_ex(ctx, md, NULL);

    while (ok && done < len) {
        size_t n = piece == 0 || len - done < piece ? len - done : piece;

        ok = EVP_DigestUpdate(ctx, data + done, n);
        done += n;
    }
    ok = ok && EVP_DigestFinal_ex(ctx, out, outl);
    EVP_MD_CTX_free(ctx);
    return ok;
}

static void every_digest(void)
{
    static const size_t lens[] = { 0, 1, 63, 64, 65, 135, 136, 137, 1200 };
    const char **name;

    for (name = names; *name != NULL; name++) {
        EVP_MD *md = EVP_MD_fetch(NULL, *name, NULL);
        char what[128];
        size_t i;
        int same = 1;

        snprintf(what, sizeof(what), "fetch %s", *name);
        check(md != NULL, what);
        if (md == NULL) {
            errors();
            continue;
        }
        printf("  %s: size %d block %d flags %lx xof %d\n", EVP_MD_get0_name(md),
               EVP_MD_get_size(md), EVP_MD_get_block_size(md), EVP_MD_get_flags(md),
               EVP_MD_xof(md));
        keys("settable", EVP_MD_settable_ctx_params(md));
        keys("gettable", EVP_MD_gettable_ctx_params(md));
        if (EVP_MD_xof(md) && EVP_MD_get_size(md) == 0) {
            EVP_MD_free(md);
            continue;
        }
        for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
            unsigned char a[EVP_MAX_MD_SIZE], b[EVP_MAX_MD_SIZE], c[EVP_MAX_MD_SIZE];
            unsigned int al = 0, bl = 0, cl = 0;
            char label[32];

            memset(a, 0xee, sizeof(a));
            if (!EVP_Digest(data, lens[i], a, &al, md, NULL)
                || !digest_in_pieces(md, lens[i], 7, b, &bl)
                || !digest_in_pieces(md, lens[i], 64, c, &cl)) {
                same = 0;
                errors();
                continue;
            }
            same = same && al == bl && al == cl && memcmp(a, b, al) == 0
                && memcmp(a, c, al) == 0;
            snprintf(label, sizeof(label), "%zu", lens[i]);
            hex(label, a, al);
            if (al < sizeof(a))
                printf("  after: %02x\n", a[al]);
        }
        snprintf(what, sizeof(what), "%s whole and in pieces agree", *name);
        check(same, what);
        EVP_MD_free(md);
    }
}

static void shake(void)
{
    EVP_MD *md = EVP_MD_fetch(NULL, "SHAKE128", NULL);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(), *copy;
    unsigned char out[600], whole[600];
    unsigned int outl = 0;
    size_t xoflen = 0;
    OSSL_PARAM params[2];
    int i;
    static const size_t pieces[] = { 1, 7, 168, 3, 200, 121 };
    size_t at;

    check(EVP_DigestInit_ex(ctx, md, NULL) == 1 && EVP_DigestUpdate(ctx, data, 300) == 1,
          "SHAKE128 init and update");
    keys("ctx settable", EVP_MD_CTX_settable_params(ctx));
    keys("ctx gettable", EVP_MD_CTX_gettable_params(ctx));
    printf("  size_ex without a length: %d\n", EVP_MD_CTX_get_size_ex(ctx));
    check(EVP_DigestFinal_ex(ctx, out, &outl) == 0, "SHAKE128 final without a length fails");
    errors();
    check(EVP_DigestFinal_ex(ctx, out, &outl) == 0, "and again");
    errors();

    /* A length set by parameter. */
    check(EVP_DigestInit_ex(ctx, md, NULL) == 1, "init again");
    xoflen = 40;
    params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &xoflen);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_MD_CTX_set_params(ctx, params) == 1, "set xoflen 40");
    printf("  size_ex: %d\n", EVP_MD_CTX_get_size_ex(ctx));
    xoflen = 0;
    params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &xoflen);
    check(EVP_MD_CTX_get_params(ctx, params) == 1 && xoflen == 40, "get size 40");
    EVP_DigestUpdate(ctx, data, 300);
    check(EVP_DigestFinal_ex(ctx, out, &outl) == 1 && outl == 40, "final with xoflen 40");
    hex("final 40", out, outl);
    /* Re-initializing keeps the length. */
    check(EVP_DigestInit_ex(ctx, NULL, NULL) == 1, "init with the same digest");
    printf("  size_ex after init: %d\n", EVP_MD_CTX_get_size_ex(ctx));
    check(EVP_DigestFinal_ex(ctx, out, &outl) == 1 && outl == 40, "final of nothing, 40");
    hex("empty 40", out, outl);
    /* A fresh context through EVP_DigestInit (which resets) has no length again. */
    check(EVP_DigestInit(ctx, md) == 1, "EVP_DigestInit");
    printf("  size_ex after EVP_DigestInit: %d\n", EVP_MD_CTX_get_size_ex(ctx));

    /* FinalXOF, then squeezing in pieces. */
    EVP_DigestUpdate(ctx, data, 300);
    copy = EVP_MD_CTX_dup(ctx);
    check(EVP_DigestFinalXOF(ctx, whole, sizeof(whole)) == 1, "FinalXOF 600");
    hex("xof", whole, 64);
    check(EVP_DigestFinalXOF(ctx, out, 10) == 0, "FinalXOF twice fails");
    errors();
    check(EVP_DigestSqueeze(ctx, out, 10) == 0, "squeeze after a final fails");
    errors();
    for (i = 0, at = 0; i < 6; i++) {
        check(EVP_DigestSqueeze(copy, out + at, pieces[i]) == 1, "squeeze a piece");
        at += pieces[i];
    }
    check(memcmp(out, whole, at) == 0, "pieces equal the whole");
    check(EVP_DigestFinal_ex(copy, out, &outl) == 0, "final after a squeeze fails");
    errors();
    printf("  finalised flag: %d\n", EVP_MD_CTX_test_flags(copy, 0x0800) != 0);
    EVP_MD_CTX_free(copy);

    /* Updating after a squeeze: accepted, not absorbed, and it shifts the buffered output. */
    check(EVP_DigestInit_ex(ctx, md, NULL) == 1, "init again");
    EVP_DigestUpdate(ctx, data, 100);
    check(EVP_DigestSqueeze(ctx, out, 10) == 1, "squeeze 10");
    hex("10", out, 10);
    check(EVP_DigestUpdate(ctx, data, 5) == 1, "update after a squeeze");
    check(EVP_DigestSqueeze(ctx, out, 20) == 1, "squeeze 20 more");
    hex("20", out, 20);
    check(EVP_DigestUpdate(ctx, data, 400) == 1, "a longer update after a squeeze");
    check(EVP_DigestSqueeze(ctx, out, 30) == 1, "squeeze 30 more");
    hex("30", out, 30);

    /* The ctrl interface sets the length too. */
    check(EVP_DigestInit_ex(ctx, md, NULL) == 1, "init again");
    check(EVP_MD_CTX_ctrl(ctx, EVP_MD_CTRL_XOF_LEN, 17, NULL) == 1, "ctrl XOF_LEN 17");
    check(EVP_DigestFinal_ex(ctx, out, &outl) == 1 && outl == 17, "final 17");
    hex("17", out, outl);
    printf("  ctrl MICALG: %d\n", EVP_MD_CTX_ctrl(ctx, EVP_MD_CTRL_MICALG, 0, out));
    check(EVP_MD_CTX_ctrl(ctx, 12345, 0, NULL) == 0, "an unknown ctrl fails");
    errors();

    /* KECCAK-KMAC has a default length. */
    EVP_MD_free(md);
    md = EVP_MD_fetch(NULL, "KECCAK-KMAC-256", NULL);
    check(EVP_DigestInit_ex(ctx, md, NULL) == 1 && EVP_DigestUpdate(ctx, data, 50) == 1,
          "KECCAK-KMAC-256");
    printf("  size_ex: %d\n", EVP_MD_CTX_get_size_ex(ctx));
    /* Its squeeze always fails, without an error, even for nothing. */
    check(EVP_DigestSqueeze(ctx, out, 0) == 0, "KECCAK-KMAC squeeze of nothing fails");
    check(EVP_DigestSqueeze(ctx, out, 8) == 0, "KECCAK-KMAC squeeze fails");
    errors();
    check(EVP_DigestFinal_ex(ctx, out, &outl) == 1, "final");
    hex("kmac", out, outl);
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
}

static void final_xof_on_fixed(void)
{
    EVP_MD *sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    EVP_MD *sha3 = EVP_MD_fetch(NULL, "SHA3-256", NULL);
    EVP_MD *sha1 = EVP_MD_fetch(NULL, "SHA1", NULL);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char out[64];

    memset(out, 0xee, sizeof(out));
    EVP_DigestInit_ex(ctx, sha256, NULL);
    check(EVP_DigestFinalXOF(ctx, out, 64) == 1, "FinalXOF 64 on SHA256 succeeds");
    hex("sha256", out, 40);
    errors();
    EVP_DigestInit_ex(ctx, sha256, NULL);
    check(EVP_DigestFinalXOF(ctx, out, 16) == 0, "FinalXOF 16 on SHA256 fails");
    errors();
    memset(out, 0xee, sizeof(out));
    EVP_DigestInit_ex(ctx, sha3, NULL);
    check(EVP_DigestFinalXOF(ctx, out, 64) == 1, "FinalXOF 64 on SHA3-256 succeeds");
    hex("sha3", out, 40);
    memset(out, 0xee, sizeof(out));
    EVP_DigestInit_ex(ctx, sha1, NULL);
    check(EVP_DigestFinalXOF(ctx, out, 64) == 1, "FinalXOF 64 on SHA1 succeeds");
    hex("sha1", out, 24);
    EVP_DigestInit_ex(ctx, sha256, NULL);
    check(EVP_DigestSqueeze(ctx, out, 8) == 0, "squeezing SHA256 fails");
    errors();
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(sha256);
    EVP_MD_free(sha3);
    EVP_MD_free(sha1);
}

static void blake2(void)
{
    EVP_MD *md = EVP_MD_fetch(NULL, "BLAKE2b512", NULL);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char out[64];
    unsigned int outl = 0, size = 0;
    size_t want = 20;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &want);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_DigestInit_ex2(ctx, md, params) == 1, "BLAKE2b512 init with size 20");
    printf("  size_ex: %d\n", EVP_MD_CTX_get_size_ex(ctx));
    EVP_DigestUpdate(ctx, data, 200);
    check(EVP_DigestFinal_ex(ctx, out, &outl) == 1 && outl == 20, "final 20");
    hex("20", out, outl);
    /* The parameter changes the gettable size at once, the hash only at the next init. */
    check(EVP_DigestInit_ex(ctx, NULL, NULL) == 1, "init again (size stays 20)");
    want = 32;
    check(EVP_MD_CTX_set_params(ctx, params) == 1, "set size 32");
    params[0] = OSSL_PARAM_construct_uint(OSSL_DIGEST_PARAM_SIZE, &size);
    check(EVP_MD_CTX_get_params(ctx, params) == 1, "get size");
    printf("  size param %u, size_ex %d\n", size, EVP_MD_CTX_get_size_ex(ctx));
    EVP_DigestUpdate(ctx, data, 200);
    outl = 0;
    printf("  final: %d\n", EVP_DigestFinal_ex(ctx, out, &outl));
    printf("  outl %u\n", outl);
    hex("after", out, outl);
    errors();
    want = 65;
    params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &want);
    check(EVP_DigestInit_ex2(ctx, md, params) == 0, "size 65 is refused");
    errors();
    want = 0;
    check(EVP_DigestInit_ex2(ctx, md, params) == 0, "size 0 is refused");
    errors();
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
}

static void ssl3(void)
{
    static const char *mds[] = { "SHA1", "MD5-SHA1", "SHA256" };
    unsigned char ms[48], out[64];
    unsigned int outl = 0;
    int i;

    memcpy(ms, data + 500, sizeof(ms));
    for (i = 0; i < 3; i++) {
        EVP_MD *md = EVP_MD_fetch(NULL, mds[i], NULL);
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        int r;

        EVP_DigestInit_ex(ctx, md, NULL);
        EVP_DigestUpdate(ctx, data, 100);
        printf("  %s ssl3-ms 47: %d\n", mds[i],
               EVP_MD_CTX_ctrl(ctx, EVP_CTRL_SSL3_MASTER_SECRET, 47, ms));
        r = EVP_MD_CTX_ctrl(ctx, EVP_CTRL_SSL3_MASTER_SECRET, 48, ms);
        printf("  %s ssl3-ms 48: %d\n", mds[i], r);
        EVP_DigestFinal_ex(ctx, out, &outl);
        hex(mds[i], out, outl);
        errors();
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
    }
}

static size_t legacy_count;

/* A legacy update function: counts the octets it's given. */
static int count_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    (void)ctx;
    (void)data;
    legacy_count += count;
    return 1;
}

static void contexts(void)
{
    EVP_MD *sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    EVP_MD *sha512 = EVP_MD_fetch(NULL, "SHA512", NULL);
    EVP_MD *null = EVP_MD_fetch(NULL, "NULL", NULL);
    EVP_MD_CTX *a = EVP_MD_CTX_new(), *b = EVP_MD_CTX_new(), *c;
    unsigned char out[64], want[64];
    unsigned int outl = 0, wantl = 0;
    EVP_MD *got;

    check(EVP_DigestInit_ex(a, NULL, NULL) == 0, "init with no digest fails");
    errors();
    check(EVP_MD_CTX_get0_md(a) == NULL, "no digest yet");
    check(EVP_DigestUpdate(a, data, 0) == 1, "an empty update succeeds uninitialized");
    check(EVP_DigestUpdate(a, data, 1) == 0, "an update fails uninitialized");
    errors();
    check(EVP_DigestFinal_ex(a, out, &outl) == 0, "a final fails uninitialized");
    errors();

    EVP_Digest(data, 300, want, &wantl, sha256, NULL);
    EVP_DigestInit_ex(a, sha256, NULL);
    EVP_DigestUpdate(a, data, 100);
    /* Copy onto a context with another digest, onto one with the same, and dup. */
    EVP_DigestInit_ex(b, sha512, NULL);
    check(EVP_MD_CTX_copy_ex(b, a) == 1, "copy onto a SHA512 context");
    check(EVP_MD_CTX_get0_md(b) == sha256, "it has SHA256");
    EVP_DigestUpdate(b, data + 100, 200);
    check(EVP_DigestFinal_ex(b, out, &outl) == 1 && outl == wantl
              && memcmp(out, want, outl) == 0, "and finishes the same");
    EVP_DigestInit_ex(b, sha256, NULL);
    EVP_DigestUpdate(b, data, 7);
    check(EVP_MD_CTX_copy_ex(b, a) == 1, "copy onto a SHA256 context");
    EVP_DigestUpdate(b, data + 100, 200);
    check(EVP_DigestFinal_ex(b, out, &outl) == 1 && memcmp(out, want, outl) == 0,
          "and finishes the same");
    c = EVP_MD_CTX_dup(a);
    EVP_DigestUpdate(c, data + 100, 200);
    check(EVP_DigestFinal(c, out, &outl) == 1 && memcmp(out, want, outl) == 0, "dup");
    check(EVP_MD_CTX_get0_md(c) == NULL, "EVP_DigestFinal resets");
    check(EVP_MD_CTX_copy(c, a) == 1, "EVP_MD_CTX_copy");
    check(EVP_MD_CTX_copy_ex(c, NULL) == 0, "copying NULL fails");
    errors();
    EVP_MD_CTX_free(c);
    c = EVP_MD_CTX_new();
    check(EVP_MD_CTX_copy_ex(b, c) == 1, "copy an empty context");
    check(EVP_MD_CTX_get0_md(b) == NULL, "the copy is empty");
    EVP_MD_CTX_free(c);

    /* After a final: updates and finals fail; an init starts again. */
    EVP_DigestUpdate(a, data + 100, 200);
    check(EVP_DigestFinal_ex(a, out, &outl) == 1, "final");
    printf("  finalised flag: %d\n", EVP_MD_CTX_test_flags(a, 0x0800) != 0);
    check(EVP_DigestUpdate(a, data, 1) == 0, "update after a final fails");
    errors();
    check(EVP_DigestUpdate(a, data, 0) == 1, "an empty update after a final succeeds");
    check(EVP_DigestFinal_ex(a, out, &outl) == 0, "a second final fails");
    errors();
    check(EVP_DigestInit_ex(a, NULL, NULL) == 1, "init with the same digest");
    printf("  finalised flag: %d\n", EVP_MD_CTX_test_flags(a, 0x0800) != 0);
    EVP_DigestUpdate(a, data, 300);
    check(EVP_DigestFinal_ex(a, out, &outl) == 1 && memcmp(out, want, outl) == 0,
          "digests again");

    /* get1_md takes a reference. */
    got = EVP_MD_CTX_get1_md(a);
    check(got == sha256, "get1_md");
    EVP_MD_free(got);
    check(EVP_MD_CTX_md(a) == sha256, "EVP_MD_CTX_md");

    /* Flags. */
    EVP_MD_CTX_set_flags(a, EVP_MD_CTX_FLAG_ONESHOT | 0x10000);
    printf("  flags: %x\n", EVP_MD_CTX_test_flags(a, 0xffffff));
    EVP_MD_CTX_clear_flags(a, 0x10000);
    printf("  flags: %x\n", EVP_MD_CTX_test_flags(a, 0xffffff));
    check(EVP_MD_CTX_reset(a) == 1, "reset");
    printf("  flags after reset: %x\n", EVP_MD_CTX_test_flags(a, 0xffffff));
    check(EVP_MD_CTX_get0_md(a) == NULL, "reset empties");
    check(EVP_MD_CTX_get0_md_data(a) == NULL, "no md_data");

    /* NO_INIT: the legacy path, which with a provided digest initializes nothing. */
    EVP_MD_CTX_set_flags(a, EVP_MD_CTX_FLAG_NO_INIT);
    check(EVP_DigestInit_ex(a, sha256, NULL) == 1, "init with NO_INIT");
    check(EVP_MD_CTX_get0_md(a) == sha256, "it has the digest");
    check(EVP_DigestUpdate(a, data, 10) == 0, "update with no update function fails");
    errors();
    printf("  update_fn: %d\n", EVP_MD_CTX_update_fn(a) == NULL);
    EVP_MD_CTX_set_update_fn(a, count_update);
    check(EVP_DigestUpdate(a, data, 10) == 1 && EVP_DigestUpdate(a, data, 5) == 1,
          "updates go to the legacy update function");
    check(legacy_count == 15 && EVP_MD_CTX_update_fn(a) == count_update, "it saw 15 octets");
    EVP_MD_CTX_reset(a);
    check(EVP_MD_CTX_update_fn(a) == NULL, "reset clears it");

    /* The NULL digest. */
    outl = 99;
    check(EVP_Digest(data, 10, out, &outl, null, NULL) == 1 && outl == 0, "the NULL digest");
    {
        size_t len = 99;

        check(EVP_Q_digest(NULL, "SHA2-256/192", NULL, data, 64, out, &len) == 1 && len == 24,
              "EVP_Q_digest SHA2-256/192");
        hex("q", out, len);
        len = 99;
        check(EVP_Q_digest(NULL, "nonesuch", NULL, data, 64, out, &len) == 0 && len == 0,
              "EVP_Q_digest of an unknown digest");
        ERR_clear_error();
    }
    check(EVP_DigestSqueeze(a, out, 1) == 0, "squeeze with no digest");
    errors();
    check(EVP_DigestFinalXOF(a, out, 1) == 0, "FinalXOF with no digest");
    errors();
    check(EVP_MD_CTX_get_params(a, NULL) == 0, "get params with no digest");
    check(EVP_MD_CTX_settable_params(a) == NULL, "no settables with no digest");
    printf("  size_ex with no digest: %d\n", EVP_MD_CTX_get_size_ex(a));
    errors();
    check(EVP_MD_xof(NULL) == 0, "EVP_MD_xof(NULL)");
    check(EVP_MD_CTX_get0_md(NULL) == NULL && EVP_MD_CTX_get1_md(NULL) == NULL,
          "accessors of NULL");
    check(EVP_MD_CTX_reset(NULL) == 1, "reset NULL");
    EVP_MD_CTX_free(NULL);

    EVP_MD_CTX_free(a);
    EVP_MD_CTX_free(b);
    EVP_MD_free(sha256);
    EVP_MD_free(sha512);
    EVP_MD_free(null);
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7 + 3);
    every_digest();
    shake();
    final_xof_on_fixed();
    blake2();
    ssl3();
    contexts();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
