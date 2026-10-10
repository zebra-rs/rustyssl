/*
 * Conformance test for the legacy cipher names (EVP_get_cipherbyname(3), EVP_aes_128_cbc(3),
 * EVP_CIPHER_do_all(3), EVP_CIPHER_get_type(3)), in TAP format: the static ciphers the
 * EVP_aes_128_cbc() getters return (their names, NIDs, lengths, flags, and references that
 * aren't counted), the names OPENSSL_INIT_ADD_ALL_CIPHERS adds and EVP_CIPHER_do_all lists,
 * EVP_get_cipherbyname by short, long, provider, OID, alias, and unknown names, the NIDs, types,
 * and names of fetched ciphers, EVP_CIPHER_is_a on static ciphers, and encrypting through
 * static ciphers (fetched implicitly, except the legacy provider's, which isn't loaded).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

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

static void hex(const unsigned char *p, int n)
{
    int i;

    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
}

struct getter {
    const char *label;
    const EVP_CIPHER *(*get)(void);
};

static const struct getter getters[] = {
    { "enc_null", EVP_enc_null }, { "des_ecb", EVP_des_ecb }, { "des_ede", EVP_des_ede },
    { "des_ede3", EVP_des_ede3 }, { "des_ede_ecb", EVP_des_ede_ecb }, { "des_ede3_ecb", EVP_des_ede3_ecb },
    { "des_cfb64", EVP_des_cfb64 }, { "des_cfb1", EVP_des_cfb1 }, { "des_cfb8", EVP_des_cfb8 },
    { "des_ede_cfb64", EVP_des_ede_cfb64 }, { "des_ede3_cfb64", EVP_des_ede3_cfb64 }, { "des_ede3_cfb1", EVP_des_ede3_cfb1 },
    { "des_ede3_cfb8", EVP_des_ede3_cfb8 }, { "des_ofb", EVP_des_ofb }, { "des_ede_ofb", EVP_des_ede_ofb },
    { "des_ede3_ofb", EVP_des_ede3_ofb }, { "des_cbc", EVP_des_cbc }, { "des_ede_cbc", EVP_des_ede_cbc },
    { "des_ede3_cbc", EVP_des_ede3_cbc }, { "desx_cbc", EVP_desx_cbc }, { "des_ede3_wrap", EVP_des_ede3_wrap },
    { "rc4", EVP_rc4 }, { "rc4_40", EVP_rc4_40 }, { "rc4_hmac_md5", EVP_rc4_hmac_md5 },
    { "idea_ecb", EVP_idea_ecb }, { "idea_cfb64", EVP_idea_cfb64 }, { "idea_ofb", EVP_idea_ofb },
    { "idea_cbc", EVP_idea_cbc }, { "rc2_ecb", EVP_rc2_ecb }, { "rc2_cbc", EVP_rc2_cbc },
    { "rc2_40_cbc", EVP_rc2_40_cbc }, { "rc2_64_cbc", EVP_rc2_64_cbc }, { "rc2_cfb64", EVP_rc2_cfb64 },
    { "rc2_ofb", EVP_rc2_ofb }, { "bf_ecb", EVP_bf_ecb }, { "bf_cbc", EVP_bf_cbc },
    { "bf_cfb64", EVP_bf_cfb64 }, { "bf_ofb", EVP_bf_ofb }, { "cast5_ecb", EVP_cast5_ecb },
    { "cast5_cbc", EVP_cast5_cbc }, { "cast5_cfb64", EVP_cast5_cfb64 }, { "cast5_ofb", EVP_cast5_ofb },
    { "aes_128_ecb", EVP_aes_128_ecb }, { "aes_128_cbc", EVP_aes_128_cbc }, { "aes_128_cfb1", EVP_aes_128_cfb1 },
    { "aes_128_cfb8", EVP_aes_128_cfb8 }, { "aes_128_cfb128", EVP_aes_128_cfb128 }, { "aes_128_ofb", EVP_aes_128_ofb },
    { "aes_128_ctr", EVP_aes_128_ctr }, { "aes_128_ccm", EVP_aes_128_ccm }, { "aes_128_gcm", EVP_aes_128_gcm },
    { "aes_128_xts", EVP_aes_128_xts }, { "aes_128_wrap", EVP_aes_128_wrap }, { "aes_128_wrap_pad", EVP_aes_128_wrap_pad },
    { "aes_128_ocb", EVP_aes_128_ocb }, { "aes_192_ecb", EVP_aes_192_ecb }, { "aes_192_cbc", EVP_aes_192_cbc },
    { "aes_192_cfb1", EVP_aes_192_cfb1 }, { "aes_192_cfb8", EVP_aes_192_cfb8 }, { "aes_192_cfb128", EVP_aes_192_cfb128 },
    { "aes_192_ofb", EVP_aes_192_ofb }, { "aes_192_ctr", EVP_aes_192_ctr }, { "aes_192_ccm", EVP_aes_192_ccm },
    { "aes_192_gcm", EVP_aes_192_gcm }, { "aes_192_wrap", EVP_aes_192_wrap }, { "aes_192_wrap_pad", EVP_aes_192_wrap_pad },
    { "aes_192_ocb", EVP_aes_192_ocb }, { "aes_256_ecb", EVP_aes_256_ecb }, { "aes_256_cbc", EVP_aes_256_cbc },
    { "aes_256_cfb1", EVP_aes_256_cfb1 }, { "aes_256_cfb8", EVP_aes_256_cfb8 }, { "aes_256_cfb128", EVP_aes_256_cfb128 },
    { "aes_256_ofb", EVP_aes_256_ofb }, { "aes_256_ctr", EVP_aes_256_ctr }, { "aes_256_ccm", EVP_aes_256_ccm },
    { "aes_256_gcm", EVP_aes_256_gcm }, { "aes_256_xts", EVP_aes_256_xts }, { "aes_256_wrap", EVP_aes_256_wrap },
    { "aes_256_wrap_pad", EVP_aes_256_wrap_pad }, { "aes_256_ocb", EVP_aes_256_ocb }, { "aes_128_cbc_hmac_sha1", EVP_aes_128_cbc_hmac_sha1 },
    { "aes_256_cbc_hmac_sha1", EVP_aes_256_cbc_hmac_sha1 }, { "aes_128_cbc_hmac_sha256", EVP_aes_128_cbc_hmac_sha256 }, { "aes_256_cbc_hmac_sha256", EVP_aes_256_cbc_hmac_sha256 },
    { "aria_128_ecb", EVP_aria_128_ecb }, { "aria_128_cbc", EVP_aria_128_cbc }, { "aria_128_cfb1", EVP_aria_128_cfb1 },
    { "aria_128_cfb8", EVP_aria_128_cfb8 }, { "aria_128_cfb128", EVP_aria_128_cfb128 }, { "aria_128_ctr", EVP_aria_128_ctr },
    { "aria_128_ofb", EVP_aria_128_ofb }, { "aria_128_gcm", EVP_aria_128_gcm }, { "aria_128_ccm", EVP_aria_128_ccm },
    { "aria_192_ecb", EVP_aria_192_ecb }, { "aria_192_cbc", EVP_aria_192_cbc }, { "aria_192_cfb1", EVP_aria_192_cfb1 },
    { "aria_192_cfb8", EVP_aria_192_cfb8 }, { "aria_192_cfb128", EVP_aria_192_cfb128 }, { "aria_192_ctr", EVP_aria_192_ctr },
    { "aria_192_ofb", EVP_aria_192_ofb }, { "aria_192_gcm", EVP_aria_192_gcm }, { "aria_192_ccm", EVP_aria_192_ccm },
    { "aria_256_ecb", EVP_aria_256_ecb }, { "aria_256_cbc", EVP_aria_256_cbc }, { "aria_256_cfb1", EVP_aria_256_cfb1 },
    { "aria_256_cfb8", EVP_aria_256_cfb8 }, { "aria_256_cfb128", EVP_aria_256_cfb128 }, { "aria_256_ctr", EVP_aria_256_ctr },
    { "aria_256_ofb", EVP_aria_256_ofb }, { "aria_256_gcm", EVP_aria_256_gcm }, { "aria_256_ccm", EVP_aria_256_ccm },
    { "camellia_128_ecb", EVP_camellia_128_ecb }, { "camellia_128_cbc", EVP_camellia_128_cbc }, { "camellia_128_cfb1", EVP_camellia_128_cfb1 },
    { "camellia_128_cfb8", EVP_camellia_128_cfb8 }, { "camellia_128_cfb128", EVP_camellia_128_cfb128 }, { "camellia_128_ofb", EVP_camellia_128_ofb },
    { "camellia_128_ctr", EVP_camellia_128_ctr }, { "camellia_192_ecb", EVP_camellia_192_ecb }, { "camellia_192_cbc", EVP_camellia_192_cbc },
    { "camellia_192_cfb1", EVP_camellia_192_cfb1 }, { "camellia_192_cfb8", EVP_camellia_192_cfb8 }, { "camellia_192_cfb128", EVP_camellia_192_cfb128 },
    { "camellia_192_ofb", EVP_camellia_192_ofb }, { "camellia_192_ctr", EVP_camellia_192_ctr }, { "camellia_256_ecb", EVP_camellia_256_ecb },
    { "camellia_256_cbc", EVP_camellia_256_cbc }, { "camellia_256_cfb1", EVP_camellia_256_cfb1 }, { "camellia_256_cfb8", EVP_camellia_256_cfb8 },
    { "camellia_256_cfb128", EVP_camellia_256_cfb128 }, { "camellia_256_ofb", EVP_camellia_256_ofb }, { "camellia_256_ctr", EVP_camellia_256_ctr },
    { "chacha20", EVP_chacha20 }, { "chacha20_poly1305", EVP_chacha20_poly1305 }, { "seed_ecb", EVP_seed_ecb },
    { "seed_cbc", EVP_seed_cbc }, { "seed_cfb128", EVP_seed_cfb128 }, { "seed_ofb", EVP_seed_ofb },
    { "sm4_ecb", EVP_sm4_ecb }, { "sm4_cbc", EVP_sm4_cbc }, { "sm4_cfb128", EVP_sm4_cfb128 },
    { "sm4_ofb", EVP_sm4_ofb }, { "sm4_ctr", EVP_sm4_ctr },
    { NULL, NULL }
};

static unsigned char key[64], iv[16], data[100];

/* The modes of this step; the AEADs, XTS, OCB, and the key wraps come with steps 3.4b and c. */
static int plain(const EVP_CIPHER *c)
{
    int mode = EVP_CIPHER_get_mode(c);

    return (EVP_CIPHER_get_flags(c) & (EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_CTS)) == 0
           && mode <= EVP_CIPH_CTR_MODE && mode != EVP_CIPH_GCM_MODE;
}

static void statics(void)
{
    const struct getter *g;

    for (g = getters; g->label != NULL; g++) {
        const EVP_CIPHER *c = g->get();
        EVP_CIPHER_CTX *ctx;
        unsigned char out[160];
        int n = 0, m = 0;

        if (c == NULL) {
            printf("  %s: NULL\n", g->label);
            continue;
        }
        printf("  %s: name %s nid %d type %d block %d key %d iv %d flags %lx mode %d prov %d"
               " desc %s\n",
               g->label, EVP_CIPHER_get0_name(c), EVP_CIPHER_get_nid(c), EVP_CIPHER_get_type(c),
               EVP_CIPHER_get_block_size(c), EVP_CIPHER_get_key_length(c),
               EVP_CIPHER_get_iv_length(c), EVP_CIPHER_get_flags(c), EVP_CIPHER_get_mode(c),
               EVP_CIPHER_get0_provider(c) == NULL, EVP_CIPHER_get0_description(c));
        check(c == g->get(), "the same static cipher each time");
        check(EVP_CIPHER_up_ref((EVP_CIPHER *)c) == 1, "up_ref");
        EVP_CIPHER_free((EVP_CIPHER *)c);
        EVP_CIPHER_free((EVP_CIPHER *)c);
        printf("  params %d gettable %d settable %d names %d pipeline %d\n",
               EVP_CIPHER_get_params((EVP_CIPHER *)c, NULL), EVP_CIPHER_gettable_params(c) == NULL,
               EVP_CIPHER_settable_ctx_params(c) == NULL, EVP_CIPHER_names_do_all(c, NULL, NULL),
               EVP_CIPHER_can_pipeline(c, 1));
        if (!plain(c))
            continue;
        ctx = EVP_CIPHER_CTX_new();
        if (EVP_EncryptInit_ex(ctx, c, NULL, key, iv) && EVP_EncryptUpdate(ctx, out, &n, data, 40)
            && EVP_EncryptFinal_ex(ctx, out + n, &m)) {
            printf("  encrypted: %d ", n + m);
            hex(out, n + m);
            printf("\n");
            check(EVP_CIPHER_CTX_get0_cipher(ctx) != c
                      && EVP_CIPHER_get0_provider(EVP_CIPHER_CTX_get0_cipher(ctx)) != NULL,
                  "the context fetched the provider's cipher");
        } else {
            printf("  can't encrypt:");
            errors();
        }
        EVP_CIPHER_CTX_free(ctx);
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
        "AES-128-CBC", "AES-256-ECB", "AES-192-CFB", "AES-128-CFB1", "AES-256-CFB8",
        "AES-128-OFB", "AES-128-CTR", "ARIA-192-CBC", "ARIA-256-CTR", "ARIA-128-CFB1",
        "CAMELLIA-128-ECB", "CAMELLIA-256-CTR", "CAMELLIA-192-CFB8", "DES-EDE3-CBC",
        "DES-EDE3-ECB", "DES-EDE3-CFB1", "DES-EDE3-CFB8", "DES-EDE3-OFB", "DES-EDE-ECB",
        "DES-EDE-CFB", "SM4-CBC", "SM4-OFB", "SM4-CFB", "SM4-CTR", "ChaCha20", "NULL", NULL
    };
    const char **n;

    for (n = names; *n != NULL; n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, *n, NULL);

        printf("  %s: nid %d type %d names", *n, EVP_CIPHER_get_nid(c), EVP_CIPHER_get_type(c));
        EVP_CIPHER_names_do_all(c, print_name, NULL);
        printf("\n");
        EVP_CIPHER_free(c);
    }
    check(EVP_CIPHER_is_a(EVP_aes_128_cbc(), "AES-128-CBC") == 1, "EVP_aes_128_cbc() is AES-128-CBC");
    check(EVP_CIPHER_is_a(EVP_aes_128_cbc(), "aes128") == 1, "and aes128");
    check(EVP_CIPHER_is_a(EVP_aes_128_cbc(), "AES-192-CBC") == 0, "but not AES-192-CBC");
    printf("  enc_null is a nonesuch: %d\n", EVP_CIPHER_is_a(EVP_enc_null(), "nonesuch"));
    printf("  des_cbc is a DES: %d\n", EVP_CIPHER_is_a(EVP_des_cbc(), "DES"));
}

static void by_name(void)
{
    static const char *names[] = {
        "AES-128-CBC", "aes-128-cbc", "AES128", "aes128", "2.16.840.1.101.3.4.1.2", "id-aes128-GCM",
        "AES-128-GCM", "aes128-wrap", "DES3", "des3", "DES-EDE3", "des-ede3-ecb", "DES", "desx",
        "BF", "blowfish", "CAST-cbc", "rc2-40", "rc2-128", "SEED", "SM4", "sm4-ofb128",
        "SM4-OFB128", "ChaCha20", "chacha20", "ChaCha20-Poly1305", "CAMELLIA256", "aria256",
        "AES-128-CFB1", "aes-128-cfb1", "AES-128-CTR", "AES-256-XTS", "id-smime-alg-CMS3DESwrap",
        "des3-wrap", "NULL", "UNDEF", "SHA256", "nonesuch", "", NULL
    };
    const char **n;

    for (n = names; *n != NULL; n++) {
        const EVP_CIPHER *c = EVP_get_cipherbyname(*n);

        printf("  '%s': %s\n", *n, c == NULL ? "NULL" : EVP_CIPHER_get0_name(c));
        if (c != NULL)
            check(EVP_CIPHER_get0_provider(c) == NULL, "a static cipher");
    }
    check(EVP_get_cipherbyname(NULL) == NULL, "NULL");
    check(EVP_get_cipherbynid(NID_aes_256_cbc) == EVP_aes_256_cbc(), "by NID");
    check(EVP_get_cipherbyobj(OBJ_nid2obj(NID_des_ede3_cbc)) == EVP_des_ede3_cbc(), "by object");
    check(EVP_des_ede() == EVP_des_ede_ecb() && EVP_des_ede3() == EVP_des_ede3_ecb(),
          "DES-EDE and DES-EDE3 are their ECB ciphers");
    errors();
}

static void list(const EVP_CIPHER *c, const char *from, const char *to, void *arg)
{
    (void)arg;
    if (c != NULL)
        printf("  %s: %s\n", from, EVP_CIPHER_get0_name(c));
    else
        printf("  %s -> %s\n", from, to);
}

/*
 * EVP_CIPHER_do_all walks the OBJ_NAME table, which holds the digest names too, so its order
 * depends on them: the entries are collected and printed sorted.
 */
static char entries[600][96];
static int count;

static void collect(const EVP_CIPHER *c, const char *from, const char *to, void *arg)
{
    (void)arg;
    if (count < 600)
        snprintf(entries[count++], sizeof(entries[0]), "%s %s", from,
                 c != NULL ? EVP_CIPHER_get0_name(c) : to);
}

static int compare(const void *a, const void *b)
{
    return strcmp(a, b);
}

/* The store's order depends on every algorithm it holds: collected and sorted. */
static void provided(EVP_CIPHER *c, void *arg)
{
    (void)arg;
    if (plain(c) && count < 600)
        snprintf(entries[count++], sizeof(entries[0]), "%s", EVP_CIPHER_get0_name(c));
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(i * 11 + 5);
    for (i = 0; i < sizeof(iv); i++)
        iv[i] = (unsigned char)(i * 3 + 1);
    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7 + 3);
    check(OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL) == 1, "add all ciphers");
    statics();
    fetched();
    by_name();
    EVP_CIPHER_do_all(collect, NULL);
    qsort(entries, count, sizeof(entries[0]), compare);
    printf("  do_all: %d entries\n", count);
    for (i = 0; i < (size_t)count; i++)
        printf("  %s\n", entries[i]);
    printf("  do_all_sorted:\n");
    EVP_CIPHER_do_all_sorted(list, NULL);
    count = 0;
    EVP_CIPHER_do_all_provided(NULL, provided, NULL);
    qsort(entries, count, sizeof(entries[0]), compare);
    printf("  do_all_provided: %d of this step's\n", count);
    for (i = 0; i < (size_t)count; i++)
        printf("  %s\n", entries[i]);
    check(EVP_add_cipher(EVP_aes_128_cbc()) == 1, "adding a cipher again");
    check(EVP_add_cipher(NULL) == 0, "adding NULL");
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
