/*
 * Conformance test for the legacy digest names (EVP_get_digestbyname(3), EVP_sha256(3),
 * EVP_MD_do_all(3), EVP_MD_get_type(3)), in TAP format: the static digests the EVP_sha256()
 * getters return (their names, NIDs, sizes, flags, and references that aren't counted), the
 * names OPENSSL_INIT_ADD_ALL_DIGESTS adds and EVP_MD_do_all lists, EVP_get_digestbyname by
 * short, long, provider, OID, alias, and unknown names, the NIDs and names of fetched digests,
 * EVP_MD_is_a on static digests, and digesting through static digests (fetched implicitly,
 * except the legacy provider's, which isn't loaded).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
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

static void errors(void)
{
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static unsigned char data[300];

struct getter {
    const char *label;
    const EVP_MD *(*get)(void);
};

static const struct getter getters[] = {
    { "md4", EVP_md4 }, { "md5", EVP_md5 }, { "md5_sha1", EVP_md5_sha1 },
    { "sha1", EVP_sha1 }, { "mdc2", EVP_mdc2 }, { "ripemd160", EVP_ripemd160 },
    { "sha224", EVP_sha224 }, { "sha256", EVP_sha256 }, { "sha384", EVP_sha384 },
    { "sha512", EVP_sha512 }, { "sha512_224", EVP_sha512_224 },
    { "sha512_256", EVP_sha512_256 }, { "whirlpool", EVP_whirlpool }, { "sm3", EVP_sm3 },
    { "blake2b512", EVP_blake2b512 }, { "blake2s256", EVP_blake2s256 },
    { "sha3_224", EVP_sha3_224 }, { "sha3_256", EVP_sha3_256 }, { "sha3_384", EVP_sha3_384 },
    { "sha3_512", EVP_sha3_512 }, { "shake128", EVP_shake128 }, { "shake256", EVP_shake256 },
    { "md_null", EVP_md_null }, { NULL, NULL }
};

static void hex(const unsigned char *p, unsigned int n)
{
    unsigned int i;

    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
}

static void statics(void)
{
    const struct getter *g;

    for (g = getters; g->label != NULL; g++) {
        const EVP_MD *md = g->get();
        unsigned char a[EVP_MAX_MD_SIZE], b[EVP_MAX_MD_SIZE];
        unsigned int al = 0, bl = 0;
        int ok;

        printf("  %s: name %s type %d pkey %d size %d block %d flags %lx xof %d prov %d desc %s\n",
               g->label, EVP_MD_get0_name(md), EVP_MD_get_type(md), EVP_MD_get_pkey_type(md),
               EVP_MD_get_size(md), EVP_MD_get_block_size(md), EVP_MD_get_flags(md),
               EVP_MD_xof(md), EVP_MD_get0_provider(md) == NULL, EVP_MD_get0_description(md));
        check(md == g->get(), "the same static digest each time");
        check(EVP_MD_up_ref((EVP_MD *)md) == 1, "up_ref");
        EVP_MD_free((EVP_MD *)md);
        EVP_MD_free((EVP_MD *)md);
        EVP_MD_free((EVP_MD *)md);
        printf("  params %d gettable %d\n", EVP_MD_get_params(md, NULL),
               EVP_MD_gettable_params(md) == NULL);
        ok = EVP_Digest(data, sizeof(data), a, &al, md, NULL);
        printf("  digest: %d %u ", ok, al);
        hex(a, ok ? al : 0);
        printf("\n");
        if (!ok) {
            errors();
            continue;
        }
        {
            EVP_MD *f = EVP_MD_fetch(NULL, EVP_MD_get0_name(md), NULL);

            if (f == NULL) {
                printf("  %s can't be fetched\n", EVP_MD_get0_name(md));
                ERR_clear_error();
            } else {
                check(EVP_Digest(data, sizeof(data), b, &bl, f, NULL) && al == bl
                          && memcmp(a, b, al) == 0,
                      "the same as the fetched digest");
            }
            EVP_MD_free(f);
        }
    }
}

static void print_name(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static void fetched(void)
{
    static const char *names[] = {
        "SHA1", "SHA224", "SHA256", "SHA2-256/192", "SHA384", "SHA512", "SHA512-224",
        "SHA512-256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "KECCAK-256",
        "KECCAK-KMAC-128", "SHAKE128", "SHAKE256", "BLAKE2s256", "BLAKE2b512", "SM3", "MD5",
        "MD5-SHA1", "RIPEMD160", "NULL", NULL
    };
    const char **n;

    for (n = names; *n != NULL; n++) {
        EVP_MD *md = EVP_MD_fetch(NULL, *n, NULL);

        printf("  %s: type %d pkey %d names", *n, EVP_MD_get_type(md),
               EVP_MD_get_pkey_type(md));
        EVP_MD_names_do_all(md, print_name, NULL);
        printf("\n");
        EVP_MD_free(md);
    }
    printf("  static names_do_all: %d", EVP_MD_names_do_all(EVP_sha256(), print_name, NULL));
    printf("\n");
    check(EVP_MD_is_a(EVP_sha256(), "SHA2-256") == 1, "EVP_sha256() is SHA2-256");
    check(EVP_MD_is_a(EVP_sha256(), "sha256WithRSAEncryption") == 0, "but not RSA-SHA256");
    check(EVP_MD_is_a(EVP_sha256(), "SHA512") == 0, "nor SHA512");
    printf("  md_null is a nonesuch: %d\n", EVP_MD_is_a(EVP_md_null(), "nonesuch"));
    printf("  shake128 is a SHAKE-128: %d\n", EVP_MD_is_a(EVP_shake128(), "SHAKE-128"));
}

static void by_name(void)
{
    static const char *names[] = {
        "SHA256", "sha256", "SHA2-256", "SHA-256", "2.16.840.1.101.3.4.2.1", "RSA-SHA256",
        "sha256WithRSAEncryption", "ssl3-md5", "SSL3-SHA1", "RSA-SHA1-2", "RIPEMD", "rmd160",
        "RIPEMD-160", "SHA3-256", "SHAKE128", "SHAKE-128", "KECCAK-256", "SHA2-256/192",
        "BLAKE2b512", "blake2b512", "BLAKE2B-512", "NULL", "UNDEF", "MD4", "WHIRLPOOL", "MDC2",
        "nonesuch", "", NULL
    };
    const char **n;

    for (n = names; *n != NULL; n++) {
        const EVP_MD *md = EVP_get_digestbyname(*n);

        printf("  '%s': %s\n", *n, md == NULL ? "NULL" : EVP_MD_get0_name(md));
        if (md != NULL)
            check(EVP_MD_get0_provider(md) == NULL, "a static digest");
    }
    check(EVP_get_digestbyname(NULL) == NULL, "NULL");
    check(EVP_get_digestbynid(NID_sha384) == EVP_sha384(), "by NID");
    check(EVP_get_digestbyobj(OBJ_nid2obj(NID_sha1)) == EVP_sha1(), "by object");
    errors();
}

static void list(const EVP_MD *md, const char *from, const char *to, void *arg)
{
    (void)arg;
    if (md != NULL)
        printf("  %s: %s\n", from, EVP_MD_get0_name(md));
    else
        printf("  %s -> %s\n", from, to);
}

/*
 * EVP_MD_do_all walks the OBJ_NAME table, which holds the cipher names too, so its order
 * depends on them: the entries are collected and printed sorted.
 */
static char entries[200][96];
static int count;

static void collect(const EVP_MD *md, const char *from, const char *to, void *arg)
{
    (void)arg;
    if (count < 200)
        snprintf(entries[count++], sizeof(entries[0]), "%s %s", from,
                 md != NULL ? EVP_MD_get0_name(md) : to);
}

static int compare(const void *a, const void *b)
{
    return strcmp(a, b);
}

static void contexts(void)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char out[64];
    unsigned int outl = 0;
    size_t xoflen = 20;
    OSSL_PARAM params[2];
    EVP_MD *got;

    check(EVP_DigestInit_ex(ctx, EVP_md4(), NULL) == 0, "MD4 needs the legacy provider");
    errors();
    check(EVP_DigestInit_ex(ctx, EVP_whirlpool(), NULL) == 0, "and Whirlpool");
    errors();
    check(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1, "init with EVP_sha256()");
    check(EVP_MD_CTX_get0_md(ctx) == EVP_sha256(), "get0_md is the static digest");
    got = EVP_MD_CTX_get1_md(ctx);
    check(got == EVP_sha256(), "get1_md too");
    EVP_MD_free(got);
    EVP_DigestUpdate(ctx, data, 10);
    check(EVP_DigestFinal_ex(ctx, out, &outl) == 1 && outl == 32, "final");

    check(EVP_DigestInit_ex(ctx, EVP_shake128(), NULL) == 1, "init with EVP_shake128()");
    printf("  size_ex: %d\n", EVP_MD_CTX_get_size_ex(ctx));
    check(EVP_DigestFinal_ex(ctx, out, &outl) == 0, "final without a length fails");
    errors();
    check(EVP_DigestInit_ex(ctx, EVP_shake128(), NULL) == 1, "init again");
    params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &xoflen);
    params[1] = OSSL_PARAM_construct_end();
    EVP_MD_CTX_set_params(ctx, params);
    printf("  size_ex with xoflen: %d\n", EVP_MD_CTX_get_size_ex(ctx));
    check(EVP_DigestInit_ex(ctx, NULL, NULL) == 1, "init with NULL keeps the algorithm context");
    printf("  size_ex: %d\n", EVP_MD_CTX_get_size_ex(ctx));
    check(EVP_DigestInit_ex(ctx, EVP_shake128(), NULL) == 1, "init with the static digest");
    printf("  size_ex: %d\n", EVP_MD_CTX_get_size_ex(ctx));
    check(EVP_DigestInit_ex(ctx, EVP_md_null(), NULL) == 1, "the NULL digest");
    check(EVP_DigestFinal_ex(ctx, out, &outl) == 1 && outl == 0, "finishes empty");
    EVP_MD_CTX_free(ctx);
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7 + 3);
    check(OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL) == 1, "add all digests");
    statics();
    fetched();
    by_name();
    EVP_MD_do_all(collect, NULL);
    qsort(entries, count, sizeof(entries[0]), compare);
    printf("  do_all: %d entries\n", count);
    for (i = 0; i < (size_t)count; i++)
        printf("  %s\n", entries[i]);
    printf("  do_all_sorted:\n");
    EVP_MD_do_all_sorted(list, NULL);
    check(EVP_add_digest(EVP_sha256()) == 1, "adding a digest again");
    contexts();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
