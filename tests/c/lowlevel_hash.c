/*
 * Conformance test for the deprecated low-level hashes (SHA1(3), SHA256_Init(3), MD5(3),
 * MD4(3), RIPEMD160(3), MDC2(3), WHIRLPOOL(3)), in TAP format. Applications keep these contexts
 * themselves, so besides the digests (one-shot, and through the context in pieces of several
 * sizes) it prints the whole context, octet for octet, after the calls that leave something
 * particular in it:
 *   - init over a context full of junk (SHA512_Init and MDC2_Init keep the buffer's);
 *   - the buffer and counts after updates, after the bit count's low word carries, and after
 *     finals (the MD4-like hashes zero their buffer; SHA-512 and MDC2 keep theirs and their
 *     counts; WHIRLPOOL_Final zeroes the whole context, but only with somewhere to write);
 *   - transforms, aligned and not, which touch only the chaining state;
 *   - SHA256_Final and SHA512_Final with other digest lengths in md_len, which write fewer
 *     octets or fail, and SHA512_Final and WHIRLPOOL_Final without a digest buffer;
 *   - finals after finals and updates after finals;
 *   - MDC2's two paddings, and WHIRLPOOL_BitUpdate with bit counts that split octets;
 *   - the one-shots into their static buffers, and the SHA ones failing when the default
 *     library context has no SHA (the others don't use providers).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/mdc2.h>
#include <openssl/provider.h>
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

/* Prints and clears the error queue as library/reason pairs. */
static void errors(void)
{
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void hex(const char *label, const void *p, size_t n)
{
    const unsigned char *b = p;
    size_t i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

static unsigned char data[1300];

/* One hash, through wrappers taking the context as void *. */
struct hash {
    const char *name;
    size_t ctx_size, md_size;
    int (*init)(void *c);
    int (*update)(void *c, const void *d, size_t n);
    int (*final)(unsigned char *md, void *c);
    unsigned char *(*oneshot)(const unsigned char *d, size_t n, unsigned char *md);
};

#define WRAP(P, T)                                                                   \
    static int P##_init_(void *c) { return P##_Init((T *)c); }                         \
    static int P##_update_(void *c, const void *d, size_t n)                           \
    {                                                                                  \
        return P##_Update((T *)c, d, n);                                               \
    }                                                                                  \
    static int P##_final_(unsigned char *md, void *c) { return P##_Final(md, (T *)c); }

WRAP(SHA1, SHA_CTX)
WRAP(SHA224, SHA256_CTX)
WRAP(SHA256, SHA256_CTX)
WRAP(SHA384, SHA512_CTX)
WRAP(SHA512, SHA512_CTX)
WRAP(MD4, MD4_CTX)
WRAP(MD5, MD5_CTX)
WRAP(RIPEMD160, RIPEMD160_CTX)
WRAP(MDC2, MDC2_CTX)
WRAP(WHIRLPOOL, WHIRLPOOL_CTX)

static unsigned char *WHIRLPOOL_(const unsigned char *d, size_t n, unsigned char *md)
{
    return WHIRLPOOL(d, n, md);
}

#define HASH(P, T, SIZE, ONE) { #P, sizeof(T), SIZE, P##_init_, P##_update_, P##_final_, ONE }

static const struct hash hashes[] = {
    HASH(SHA1, SHA_CTX, SHA_DIGEST_LENGTH, SHA1),
    HASH(SHA224, SHA256_CTX, SHA224_DIGEST_LENGTH, SHA224),
    HASH(SHA256, SHA256_CTX, SHA256_DIGEST_LENGTH, SHA256),
    HASH(SHA384, SHA512_CTX, SHA384_DIGEST_LENGTH, SHA384),
    HASH(SHA512, SHA512_CTX, SHA512_DIGEST_LENGTH, SHA512),
    HASH(MD4, MD4_CTX, MD4_DIGEST_LENGTH, MD4),
    HASH(MD5, MD5_CTX, MD5_DIGEST_LENGTH, MD5),
    HASH(RIPEMD160, RIPEMD160_CTX, RIPEMD160_DIGEST_LENGTH, RIPEMD160),
    HASH(MDC2, MDC2_CTX, MDC2_DIGEST_LENGTH, MDC2),
    HASH(WHIRLPOOL, WHIRLPOOL_CTX, WHIRLPOOL_DIGEST_LENGTH, WHIRLPOOL_),
};

#define NHASHES (sizeof(hashes) / sizeof(hashes[0]))

/* A context buffer big enough for any of them, aligned for any. */
static union {
    SHA512_CTX s;
    WHIRLPOOL_CTX w;
    unsigned char b[512];
} ctx;

/* Digests data[0..len] through the context in pieces of `piece`. */
static int in_pieces(const struct hash *h, size_t len, size_t piece, unsigned char *md)
{
    size_t done = 0;
    int ok;

    memset(&ctx, 0xa5, sizeof(ctx));
    ok = h->init(&ctx);
    while (ok && done < len) {
        size_t n = len - done < piece ? len - done : piece;

        ok = h->update(&ctx, data + done, n);
        done += n;
    }
    return ok && h->final(md, &ctx);
}

static void digests(void)
{
    static const size_t lens[] = { 0, 1, 7, 8, 55, 56, 63, 64, 65, 111, 112, 119, 120, 127, 128,
                                   129, 300, 1300 };
    static const size_t pieces[] = { 1, 7, 64, 129, 1300 };
    size_t i, j, k;

    for (i = 0; i < NHASHES; i++) {
        const struct hash *h = &hashes[i];
        int same = 1;
        char what[64];

        for (j = 0; j < sizeof(lens) / sizeof(lens[0]); j++) {
            unsigned char one[64], two[64];
            char label[32];

            memset(one, 0xee, sizeof(one));
            if (h->oneshot(data, lens[j], one) != one) {
                same = 0;
                continue;
            }
            snprintf(label, sizeof(label), "%zu", lens[j]);
            hex(label, one, h->md_size);
            for (k = 0; k < sizeof(pieces) / sizeof(pieces[0]); k++) {
                memset(two, 0xee, sizeof(two));
                if (!in_pieces(h, lens[j], pieces[k], two) || memcmp(one, two, sizeof(one)) != 0)
                    same = 0;
            }
        }
        snprintf(what, sizeof(what), "%s one-shot and in pieces agree", h->name);
        check(same, what);
    }
}

/* The context after init over junk, after updates, and after a final. */
static void contexts(void)
{
    size_t i;

    for (i = 0; i < NHASHES; i++) {
        const struct hash *h = &hashes[i];
        unsigned char md[64];
        char what[64];
        int ok;

        printf("  %s (%zu octets)\n", h->name, h->ctx_size);
        memset(&ctx, 0xa5, sizeof(ctx));
        ok = h->init(&ctx);
        hex("init", &ctx, h->ctx_size);
        ok = ok && h->update(&ctx, data, 3) && h->update(&ctx, NULL, 0);
        hex("3", &ctx, h->ctx_size);
        ok = ok && h->update(&ctx, data + 3, 200);
        hex("203", &ctx, h->ctx_size);
        memset(md, 0xee, sizeof(md));
        ok = ok && h->final(md, &ctx);
        hex("final", &ctx, h->ctx_size);
        hex("md", md, h->md_size);
        if (strcmp(h->name, "WHIRLPOOL") != 0) {
            /* A final after a final, then an update and another. */
            ok = ok && h->final(md, &ctx);
            hex("again", md, h->md_size);
            ok = ok && h->update(&ctx, data, 10) && h->final(md, &ctx);
            hex("after", md, h->md_size);
            hex("context", &ctx, h->ctx_size);
        }
        snprintf(what, sizeof(what), "%s contexts", h->name);
        check(ok, what);
    }
}

static void transforms(void)
{
    SHA_CTX s1;
    SHA256_CTX s256;
    SHA512_CTX s512;
    MD4_CTX m4;
    MD5_CTX m5;
    RIPEMD160_CTX r;
    int ok;

    ok = SHA1_Init(&s1) && SHA1_Update(&s1, data, 5);
    SHA1_Transform(&s1, data);
    SHA1_Transform(&s1, data + 1);
    hex("SHA1_Transform", &s1, sizeof(s1));
    ok = ok && SHA256_Init(&s256) && SHA256_Update(&s256, data, 5);
    SHA256_Transform(&s256, data + 1);
    hex("SHA256_Transform", &s256, sizeof(s256));
    memset(&s512, 0xa5, sizeof(s512));
    ok = ok && SHA512_Init(&s512) && SHA512_Update(&s512, data, 5);
    SHA512_Transform(&s512, data);
    SHA512_Transform(&s512, data + 3);
    hex("SHA512_Transform", &s512, sizeof(s512));
    ok = ok && MD4_Init(&m4) && MD4_Update(&m4, data, 5);
    MD4_Transform(&m4, data + 1);
    hex("MD4_Transform", &m4, sizeof(m4));
    ok = ok && MD5_Init(&m5) && MD5_Update(&m5, data, 5);
    MD5_Transform(&m5, data + 1);
    hex("MD5_Transform", &m5, sizeof(m5));
    ok = ok && RIPEMD160_Init(&r) && RIPEMD160_Update(&r, data, 5);
    RIPEMD160_Transform(&r, data + 1);
    hex("RIPEMD160_Transform", &r, sizeof(r));
    check(ok, "transforms");
}

/* The bit counts' carries, and the other digest lengths. */
static void counts_and_lengths(void)
{
    static const unsigned int lens256[] = { 0, 2, 20, 23, 24, 28, 32, 33 };
    static const unsigned int lens512[] = { 20, 28, 32, 48, 64, 65 };
    SHA256_CTX s;
    SHA512_CTX t;
    MD5_CTX m;
    unsigned char md[80];
    size_t i;
    int ret;

    SHA256_Init(&s);
    s.Nl = 0xfffffff0;
    SHA256_Update(&s, data, 3);
    printf("  SHA256 Nl %08x Nh %08x\n", s.Nl, s.Nh);
    MD5_Init(&m);
    m.Nl = 0xffffffff;
    m.Nh = 0xffffffff;
    MD5_Update(&m, data, 1);
    printf("  MD5 Nl %08x Nh %08x\n", m.Nl, m.Nh);
    hex("MD5 with the count wrapped", md, MD5_Final(md, &m) ? MD5_DIGEST_LENGTH : 0);
    SHA512_Init(&t);
    t.Nl = ~(SHA_LONG64)0 - 7;
    SHA512_Update(&t, data, 2);
    printf("  SHA512 Nl %016llx Nh %016llx\n", (unsigned long long)t.Nl,
           (unsigned long long)t.Nh);

    for (i = 0; i < sizeof(lens256) / sizeof(lens256[0]); i++) {
        char label[32];

        SHA256_Init(&s);
        SHA256_Update(&s, data, 100);
        s.md_len = lens256[i];
        memset(md, 0xee, sizeof(md));
        ret = SHA256_Final(md, &s);
        snprintf(label, sizeof(label), "SHA256 md_len %u -> %d", lens256[i], ret);
        hex(label, md, 36);
        hex("context", &s, sizeof(s));
    }
    for (i = 0; i < sizeof(lens512) / sizeof(lens512[0]); i++) {
        char label[32];

        SHA512_Init(&t);
        SHA512_Update(&t, data, 100);
        t.md_len = lens512[i];
        memset(md, 0xee, sizeof(md));
        ret = SHA512_Final(md, &t);
        snprintf(label, sizeof(label), "SHA512 md_len %u -> %d", lens512[i], ret);
        hex(label, md, 68);
        hex("context", &t, sizeof(t));
    }
    SHA384_Init(&t);
    SHA384_Update(&t, data, 100);
    check(SHA512_Final(NULL, &t) == 0, "SHA512_Final without a buffer");
    hex("context", &t, sizeof(t));
}

static void mdc2(void)
{
    static const unsigned char now[] = "Now is the time for all ";
    MDC2_CTX c;
    unsigned char md[MDC2_DIGEST_LENGTH];
    int ok;
    unsigned int pad;

    for (pad = 0; pad <= 3; pad++) {
        char label[32];

        ok = MDC2_Init(&c);
        c.pad_type = pad;
        ok = ok && MDC2_Update(&c, now, sizeof(now) - 1) && MDC2_Final(md, &c);
        snprintf(label, sizeof(label), "pad_type %u", pad);
        hex(label, md, sizeof(md));
        ok = ok && MDC2_Init(&c);
        c.pad_type = pad;
        ok = ok && MDC2_Update(&c, now, 5) && MDC2_Final(md, &c);
        hex("5 octets", md, sizeof(md));
        hex("context", &c, sizeof(c));
        check(ok, label);
    }
}

static void whirlpool(void)
{
    static const size_t a[] = { 3, 5, 8, 16, 1000, 7, 1, 0 };
    static const size_t b[] = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0 };
    static const size_t c[] = { 505, 7, 0 };
    static const size_t d[] = { 511, 1, 513, 7, 0 };
    static const size_t e[] = { 9, 9, 9, 9, 9, 9, 9, 1, 1000, 4, 4, 0 };
    static const size_t f[] = { 13, 600, 13, 6, 0 };
    static const size_t g[] = { 4, 12, 17, 3, 9, 12, 0 };
    static const size_t *splits[] = { a, b, c, d, e, f, g };
    WHIRLPOOL_CTX w;
    unsigned char md[WHIRLPOOL_DIGEST_LENGTH];
    size_t i;

    for (i = 0; i < sizeof(splits) / sizeof(splits[0]); i++) {
        const size_t *s;
        size_t at = 0;
        int ok = WHIRLPOOL_Init(&w);
        char what[32];

        for (s = splits[i]; *s != 0; s++) {
            WHIRLPOOL_BitUpdate(&w, data + at, *s);
            at += (*s + 7) / 8;
            printf("  %zu: bitoff %u bitlen %zu\n", *s, w.bitoff, w.bitlen[0]);
            hex("data", w.data, sizeof(w.data));
        }
        ok = ok && WHIRLPOOL_Final(md, &w);
        hex("md", md, sizeof(md));
        snprintf(what, sizeof(what), "bit split %zu", i);
        check(ok, what);
    }
    WHIRLPOOL_Init(&w);
    WHIRLPOOL_Update(&w, data, 70);
    check(WHIRLPOOL_Final(NULL, &w) == 0, "WHIRLPOOL_Final without a buffer");
    hex("context", &w, sizeof(w));
    check(WHIRLPOOL_Update(&w, NULL, 0) == 1, "WHIRLPOOL_Update with nothing");
}

/* The one-shots without a buffer, and the SHA ones without a SHA provider. */
static void oneshots(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *null = OSSL_PROVIDER_load(libctx, "null");
    OSSL_LIB_CTX *old;
    unsigned char md[64];
    size_t i;

    for (i = 0; i < NHASHES; i++) {
        const struct hash *h = &hashes[i];
        unsigned char *a = h->oneshot(data, 10, NULL);
        unsigned char *b = h->oneshot(data, 20, NULL);
        char what[64];

        snprintf(what, sizeof(what), "%s into its static buffer", h->name);
        check(a != NULL && a == b, what);
        if (a != NULL)
            hex("static", a, h->md_size);
    }
    check(SHA1(data, 1, NULL) != MD5(data, 1, NULL), "each one-shot has its own buffer");

    old = OSSL_LIB_CTX_set0_default(libctx);
    for (i = 0; i < NHASHES; i++) {
        const struct hash *h = &hashes[i];

        memset(md, 0xee, sizeof(md));
        printf("  %s without the default provider: %s\n", h->name,
               h->oneshot(data, 10, md) == md ? "md" : "NULL");
        errors();
    }
    OSSL_LIB_CTX_set0_default(old);
    OSSL_PROVIDER_unload(null);
    OSSL_LIB_CTX_free(libctx);
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7 + 3);
    digests();
    contexts();
    transforms();
    counts_and_lengths();
    mdc2();
    whirlpool();
    oneshots();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
