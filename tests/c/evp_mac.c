/*
 * Conformance test for MACs (EVP_MAC(3), EVP_Q_mac, HMAC(3), CMAC_Init(3)), in TAP format:
 * the HMAC, CMAC, and GMAC methods (fetching, names, parameters), contexts through their
 * lifecycle (init with parameters, update in pieces, final, sizes, copies, reinit), the legacy
 * HMAC_* and CMAC_* contexts, the one-shot functions, the RFC 4231 and RFC 4493 vectors, and
 * the errors.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/cmac.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/provider.h>

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

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static int unhex(const char *s, unsigned char *out)
{
    int n = 0;
    unsigned int b;

    while (s[0] != '\0' && s[1] != '\0' && sscanf(s, "%2x", &b) == 1) {
        out[n++] = (unsigned char)b;
        s += 2;
    }
    return n;
}

static int same_hex(const unsigned char *p, size_t n, const char *want)
{
    unsigned char w[256];

    return (size_t)unhex(want, w) == n && memcmp(p, w, n) == 0;
}

static void list(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    if (p == NULL)
        printf(" NULL");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u/%zu", p->key, p->data_type, p->data_size);
    printf("\n");
}

static void name_cb(const char *name, void *arg)
{
    printf("  %s name: %s\n", (const char *)arg, name);
}

static int seen_hmac, seen_cmac, seen_gmac;

static void provided_cb(EVP_MAC *mac, void *arg)
{
    (void)arg;
    if (EVP_MAC_is_a(mac, "HMAC"))
        seen_hmac++;
    if (EVP_MAC_is_a(mac, "CMAC"))
        seen_cmac++;
    if (EVP_MAC_is_a(mac, "GMAC"))
        seen_gmac++;
}

static const char *rfc4493_key = "2b7e151628aed2a6abf7158809cf4f3c";
static const char *rfc4493_msg =
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

static void methods(void)
{
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC *gmac = EVP_MAC_fetch(NULL, "1.0.9797.3.4", "provider=default");
    EVP_MAC *none = EVP_MAC_fetch(NULL, "NO-SUCH-MAC", NULL);
    EVP_MAC *cmac = EVP_MAC_fetch(NULL, "cmac", NULL);
    OSSL_PARAM params[2];
    size_t size = 0;

    check(hmac != NULL && cmac != NULL && gmac != NULL, "HMAC, CMAC, and GMAC fetch");
    check(none == NULL, "an unknown MAC doesn't");
    errors();
    printf("  names: %s %s %s\n", EVP_MAC_get0_name(hmac), EVP_MAC_get0_name(cmac),
           EVP_MAC_get0_name(gmac));
    check(EVP_MAC_get0_description(hmac) == NULL, "no description");
    printf("  provider: %s\n", OSSL_PROVIDER_get0_name(EVP_MAC_get0_provider(cmac)));
    check(EVP_MAC_is_a(gmac, "GMAC") && EVP_MAC_is_a(gmac, "1.0.9797.3.4")
          && !EVP_MAC_is_a(gmac, "HMAC"), "is_a by every name");
    check(EVP_MAC_names_do_all(gmac, name_cb, "GMAC") == 1, "names_do_all");
    EVP_MAC_do_all_provided(NULL, provided_cb, NULL);
    check(seen_hmac == 1 && seen_cmac == 1 && seen_gmac == 1, "do_all_provided");

    list("HMAC gettable", EVP_MAC_gettable_params(hmac));
    list("HMAC gettable ctx", EVP_MAC_gettable_ctx_params(hmac));
    list("HMAC settable ctx", EVP_MAC_settable_ctx_params(hmac));
    list("CMAC gettable", EVP_MAC_gettable_params(cmac));
    list("CMAC gettable ctx", EVP_MAC_gettable_ctx_params(cmac));
    list("CMAC settable ctx", EVP_MAC_settable_ctx_params(cmac));
    list("GMAC gettable", EVP_MAC_gettable_params(gmac));
    list("GMAC gettable ctx", EVP_MAC_gettable_ctx_params(gmac));
    list("GMAC settable ctx", EVP_MAC_settable_ctx_params(gmac));

    params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_MAC_get_params(gmac, params) == 1 && size == 16, "GMAC's size is 16");
    size = 7;
    check(EVP_MAC_get_params(hmac, params) == 1 && size == 7, "HMAC has no method parameters");

    check(EVP_MAC_up_ref(hmac) == 1, "up_ref");
    EVP_MAC_free(hmac);
    EVP_MAC_free(hmac);
    EVP_MAC_free(cmac);
    EVP_MAC_free(gmac);
    EVP_MAC_free(NULL);
    errors();
}

static EVP_MAC_CTX *context(const char *name)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, name, NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);

    EVP_MAC_free(mac);
    return ctx;
}

static void hmac_contexts(void)
{
    static const char *want = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    const char *data = "what do ya want for nothing?";
    EVP_MAC_CTX *ctx = context("HMAC"), *dup;
    OSSL_PARAM params[3];
    unsigned char out[64], out2[64];
    size_t outl = 0;
    int r;

    check(ctx != NULL, "an HMAC context");
    printf("  before: size %zu block %zu\n", EVP_MAC_CTX_get_mac_size(ctx),
           EVP_MAC_CTX_get_block_size(ctx));
    check(EVP_MAC_CTX_get0_mac(ctx) != NULL
          && EVP_MAC_is_a(EVP_MAC_CTX_get0_mac(ctx), "HMAC"), "get0_mac");
    dup = EVP_MAC_CTX_dup(ctx);
    check(dup != NULL, "an unkeyed HMAC copies");
    errors();
    EVP_MAC_CTX_free(dup);
    r = EVP_MAC_init(ctx, NULL, 0, NULL);
    check(r == 0, "init without a digest or key fails");
    errors();

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_MAC_init(ctx, (const unsigned char *)"Jefe", 4, params);
    check(r == 1, "init with SHA256 and a key");
    printf("  after: size %zu block %zu\n", EVP_MAC_CTX_get_mac_size(ctx),
           EVP_MAC_CTX_get_block_size(ctx));
    check(EVP_MAC_update(ctx, (const unsigned char *)data, 10) == 1
          && EVP_MAC_update(ctx, NULL, 0) == 1
          && EVP_MAC_update(ctx, (const unsigned char *)data + 10, strlen(data) - 10) == 1,
          "update in pieces");
    dup = EVP_MAC_CTX_dup(ctx);
    check(dup != NULL, "a keyed HMAC copies");
    check(EVP_MAC_final(ctx, NULL, &outl, 0) == 1 && outl == 32, "final with NULL reports the size");
    r = EVP_MAC_final(ctx, out, &outl, 31);
    check(r == 0, "final into too small a buffer fails");
    errors();
    check(EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1 && same_hex(out, outl, want),
          "RFC 4231 case 2");
    hex("mac", out, outl);
    /* HMAC ignores the XOF parameter, so this is a final. */
    check(EVP_MAC_finalXOF(dup, out2, 32) == 1 && memcmp(out, out2, 32) == 0,
          "finalXOF of the copy");
    errors();
    EVP_MAC_CTX_free(dup);

    /* Init again with the same key. */
    check(EVP_MAC_init(ctx, NULL, 0, NULL) == 1
          && EVP_MAC_update(ctx, (const unsigned char *)data, strlen(data)) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1 && same_hex(out, outl, want),
          "reinit keeps the key");

    /* A key parameter, and a key longer than the block (hashed). */
    {
        unsigned char key[131];

        memset(key, 0xaa, sizeof(key));
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA2-512", 0);
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, key, sizeof(key));
        params[2] = OSSL_PARAM_construct_end();
        check(EVP_MAC_CTX_set_params(ctx, params) == 1, "digest and key parameters");
        check(EVP_MAC_init(ctx, NULL, 0, NULL) == 1
              && EVP_MAC_update(ctx, (const unsigned char *)
                                "Test Using Larger Than Block-Size Key - Hash Key First", 54) == 1
              && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1
              && same_hex(out, outl,
                          "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
                          "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"),
              "RFC 4231 case 6, SHA-512");
        printf("  SHA-512: size %zu block %zu\n", EVP_MAC_CTX_get_mac_size(ctx),
               EVP_MAC_CTX_get_block_size(ctx));
    }

    /* Bad parameters. */
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "NO-SUCH-MD", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_MAC_CTX_set_params(ctx, params);
    check(r == 0, "an unknown digest");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_KEY, "abc", 0);
    r = EVP_MAC_CTX_set_params(ctx, params);
    check(r == 0, "a key that isn't an octet string");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHAKE-128", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, "k", 1);
    params[2] = OSSL_PARAM_construct_end();
    r = EVP_MAC_CTX_set_params(ctx, params);
    check(r == 0, "an XOF digest");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA1", 0);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES, "provider=default", 0);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_MAC_CTX_set_params(ctx, params) == 1, "a digest with properties");
    check(EVP_MAC_CTX_set_params(ctx, NULL) == 1, "no parameters");
    list("ctx gettable", EVP_MAC_CTX_gettable_params(ctx));
    list("ctx settable", EVP_MAC_CTX_settable_params(ctx));
    {
        size_t size = 0, block = 0;

        params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
        params[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, &block);
        params[2] = OSSL_PARAM_construct_end();
        check(EVP_MAC_CTX_get_params(ctx, params) == 1, "get_params");
        printf("  params: size %zu block %zu\n", size, block);
    }
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_CTX_free(NULL);
}

static void cmac_contexts(void)
{
    static const char *wants[] = {
        "bb1d6929e95937287fa37d129b756746", "070a16b46b4d4144f79bdd9dd04a287c",
        "dfa66747de9ae63030ca32611497c827", "51f0bebf7e3b9d92fc49741779363cfe",
    };
    static const int lens[] = { 0, 16, 40, 64 };
    unsigned char key[16], msg[64], out[32];
    EVP_MAC_CTX *ctx = context("CMAC"), *dup;
    OSSL_PARAM params[3];
    size_t outl = 0;
    int i, r;

    unhex(rfc4493_key, key);
    unhex(rfc4493_msg, msg);
    check(ctx != NULL, "a CMAC context");
    printf("  before: size %zu block %zu\n", EVP_MAC_CTX_get_mac_size(ctx),
           EVP_MAC_CTX_get_block_size(ctx));
    dup = EVP_MAC_CTX_dup(ctx);
    check(dup == NULL, "an unkeyed CMAC doesn't copy");
    errors();
    r = EVP_MAC_init(ctx, key, 16, NULL);
    check(r == 0, "a key without a cipher fails");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "AES-128-ECB", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_MAC_init(ctx, key, 16, params);
    check(r == 0, "an ECB cipher fails");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "AES-128-CBC", 0);
    for (i = 0; i < 4; i++) {
        r = i == 0 ? EVP_MAC_init(ctx, key, 16, params) : EVP_MAC_init(ctx, NULL, 0, NULL);
        check(r == 1 && EVP_MAC_update(ctx, msg, lens[i] / 3) == 1
              && EVP_MAC_update(ctx, msg + lens[i] / 3, lens[i] - lens[i] / 3) == 1
              && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1
              && same_hex(out, outl, wants[i]), "RFC 4493 vector");
        hex("mac", out, outl);
    }
    printf("  after: size %zu block %zu\n", EVP_MAC_CTX_get_mac_size(ctx),
           EVP_MAC_CTX_get_block_size(ctx));
    check(EVP_MAC_init(ctx, NULL, 0, NULL) == 1 && EVP_MAC_update(ctx, msg, 20) == 1,
          "a partial MAC");
    dup = EVP_MAC_CTX_dup(ctx);
    check(dup != NULL, "a keyed CMAC copies");
    check(EVP_MAC_update(dup, msg + 20, 20) == 1
          && EVP_MAC_final(dup, out, &outl, sizeof(out)) == 1 && same_hex(out, outl, wants[2]),
          "the copy goes on");
    EVP_MAC_CTX_free(dup);
    r = EVP_MAC_final(ctx, out, &outl, 8);
    check(r == 0, "final into too small a buffer");
    errors();

    /* A 256-bit key, through the key parameter, and a 3-block cipher change. */
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "AES-256-CBC", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
        "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4", 32);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_MAC_CTX_set_params(ctx, params) == 1
          && EVP_MAC_init(ctx, NULL, 0, NULL) == 1 && EVP_MAC_update(ctx, msg, 64) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1
          && same_hex(out, outl, "e1992190549f6ed5696a2c056c315410"), "AES-256 CMAC");
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "DES-EDE3-CBC", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, "0123456789abcdefghijklmn", 24);
    check(EVP_MAC_CTX_set_params(ctx, params) == 1
          && EVP_MAC_update(ctx, msg, 13) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1 && outl == 8, "a 64-bit block");
    hex("3DES", out, outl);
    printf("  3DES: size %zu block %zu\n", EVP_MAC_CTX_get_mac_size(ctx),
           EVP_MAC_CTX_get_block_size(ctx));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, "short", 5);
    r = EVP_MAC_CTX_set_params(ctx, params);
    check(r == 0, "a key of the wrong length");
    errors();
    r = EVP_MAC_update(ctx, msg, 1);
    check(r == 0, "unusable after a failed key");
    errors();
    EVP_MAC_CTX_free(ctx);
}

static void gmac_contexts(void)
{
    unsigned char key[16], iv[12], out[32];
    EVP_MAC_CTX *ctx = context("GMAC"), *dup;
    OSSL_PARAM params[4];
    size_t outl = 0;
    int r;

    memset(key, 0x11, sizeof(key));
    memset(iv, 0x22, sizeof(iv));
    check(ctx != NULL, "a GMAC context");
    printf("  size %zu block %zu\n", EVP_MAC_CTX_get_mac_size(ctx),
           EVP_MAC_CTX_get_block_size(ctx));
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "AES-128-CBC", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_MAC_CTX_set_params(ctx, params);
    check(r == 0, "a CBC cipher fails");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "AES-128-GCM", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV, iv, sizeof(iv));
    params[2] = OSSL_PARAM_construct_end();
    r = EVP_MAC_init(ctx, key, 15, params);
    check(r == 0, "a key of the wrong length");
    errors();
    check(EVP_MAC_init(ctx, key, 16, params) == 1, "init with a cipher, IV, and key");
    check(EVP_MAC_update(ctx, (const unsigned char *)"additional data", 15) == 1
          && EVP_MAC_update(ctx, (const unsigned char *)" more", 5) == 1, "update");
    dup = EVP_MAC_CTX_dup(ctx);
    check(dup != NULL, "GMAC copies");
    check(EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1 && outl == 16, "final");
    hex("mac", out, outl);
    {
        unsigned char out2[16];
        size_t outl2 = 0;

        check(EVP_MAC_final(dup, out2, &outl2, sizeof(out2)) == 1 && outl2 == 16
              && memcmp(out, out2, 16) == 0, "the copy finishes the same");
    }
    EVP_MAC_CTX_free(dup);

    /* A 16-octet IV (GHASHed), and nothing to authenticate. */
    {
        unsigned char longiv[16];

        memset(longiv, 0x33, sizeof(longiv));
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV, longiv, sizeof(longiv));
        params[1] = OSSL_PARAM_construct_end();
        check(EVP_MAC_init(ctx, NULL, 0, params) == 1
              && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1 && outl == 16,
              "a long IV, no data");
        hex("long IV", out, outl);
    }
    EVP_MAC_CTX_free(ctx);
}

static void legacy_hmac(void)
{
    HMAC_CTX *ctx = HMAC_CTX_new(), *copy = HMAC_CTX_new();
    unsigned char out[EVP_MAX_MD_SIZE], *p;
    unsigned int len = 0;
    const char *data = "what do ya want for nothing?";

    check(ctx != NULL && copy != NULL, "HMAC_CTX_new");
    check(HMAC_size(ctx) == 0 && HMAC_CTX_get_md(ctx) == NULL, "no digest yet");
    check(HMAC_Init_ex(ctx, NULL, 0, NULL, NULL) == 0, "init without anything");
    check(HMAC_Update(ctx, (const unsigned char *)"x", 1) == 0, "update without a digest");
    check(HMAC_Final(ctx, out, &len) == 0, "final without a digest");
    check(HMAC_Init_ex(ctx, NULL, 0, EVP_sha256(), NULL) == 0, "a new digest needs a key");
    check(HMAC_Init_ex(ctx, "Jefe", -1, EVP_sha256(), NULL) == 0, "a negative key length");
    check(HMAC_Init_ex(ctx, "k", 1, EVP_shake128(), NULL) == 0, "an XOF digest");
    check(HMAC_CTX_get_md(ctx) == EVP_shake128(), "which it keeps");
    check(HMAC_Init_ex(ctx, "Jefe", 4, EVP_sha256(), NULL) == 1, "HMAC_Init_ex");
    check(HMAC_size(ctx) == 32 && HMAC_CTX_get_md(ctx) == EVP_sha256(), "size and digest");
    check(HMAC_Update(ctx, (const unsigned char *)data, 5) == 1, "update");
    check(HMAC_CTX_copy(copy, ctx) == 1, "copy");
    check(HMAC_Update(ctx, (const unsigned char *)data + 5, strlen(data) - 5) == 1
          && HMAC_Final(ctx, out, &len) == 1 && len == 32
          && same_hex(out, len, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
          "RFC 4231 case 2");
    check(HMAC_Update(copy, (const unsigned char *)data + 5, strlen(data) - 5) == 1
          && HMAC_Final(copy, out, NULL) == 1
          && same_hex(out, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
          "the copy finishes the same");
    check(HMAC_Init_ex(ctx, NULL, 0, NULL, NULL) == 1
          && HMAC_Update(ctx, (const unsigned char *)data, strlen(data)) == 1
          && HMAC_Final(ctx, out, &len) == 1
          && same_hex(out, len, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
          "init again, same key");
    check(HMAC_Init_ex(ctx, NULL, 0, EVP_sha256(), NULL) == 1, "the same digest needs no key");
    HMAC_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT);
    check(HMAC_Init(ctx, "key", 3, EVP_md5()) == 1
          && HMAC_Update(ctx, (const unsigned char *)"The quick brown fox jumps over the lazy dog", 43) == 1
          && HMAC_Final(ctx, out, &len) == 1 && len == 16
          && same_hex(out, len, "80070713463e7749b90c2dc24911e275"), "HMAC_Init, MD5");
    check(HMAC_CTX_reset(ctx) == 1 && HMAC_size(ctx) == 0, "reset");
    check(HMAC_Init(ctx, NULL, 0, NULL) == 0, "nothing after a reset");

    p = HMAC(EVP_sha1(), "key", 3, (const unsigned char *)"The quick brown fox jumps over the lazy dog",
             43, out, &len);
    check(p == out && len == 20
          && same_hex(out, len, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"), "HMAC, SHA-1");
    len = 99;
    p = HMAC(EVP_sha256(), "", 0, (const unsigned char *)"", 0, NULL, &len);
    check(p != NULL && p != out && len == 32
          && same_hex(p, len, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"),
          "HMAC into its static buffer, empty key and data");
    len = 99;
    p = HMAC(EVP_shake128(), "k", 1, (const unsigned char *)"d", 1, out, &len);
    check(p == NULL, "HMAC with an XOF digest");
    printf("  len after XOF: %u\n", len);
    errors();
    HMAC_CTX_free(ctx);
    HMAC_CTX_free(copy);
    HMAC_CTX_free(NULL);
}

static void legacy_cmac(void)
{
    CMAC_CTX *ctx = CMAC_CTX_new(), *copy = CMAC_CTX_new();
    unsigned char key[16], msg[64], out[32], *big;
    size_t len = 0;
    int i;

    unhex(rfc4493_key, key);
    unhex(rfc4493_msg, msg);
    check(ctx != NULL && copy != NULL, "CMAC_CTX_new");
    check(CMAC_CTX_get0_cipher_ctx(ctx) != NULL, "a cipher context");
    check(CMAC_Update(ctx, msg, 1) == 0, "update without a key");
    check(CMAC_Final(ctx, out, &len) == 0, "final without a key");
    check(CMAC_resume(ctx) == 0, "resume without a key");
    check(CMAC_Init(ctx, NULL, 0, NULL, NULL) == 0, "restart without a key");
    check(CMAC_CTX_copy(copy, ctx) == 0, "copy without a key");
    check(CMAC_Init(ctx, key, 16, NULL, NULL) == 0, "a key without a cipher");
    check(CMAC_Init(ctx, NULL, 0, EVP_aes_128_cbc(), NULL) == 1, "a cipher without a key");
    check(CMAC_Update(ctx, msg, 1) == 0, "is not yet usable");
    check(CMAC_Init(ctx, key, 15, NULL, NULL) == 0, "a key of the wrong length");
    errors();
    check(CMAC_Init(ctx, key, 16, NULL, NULL) == 1, "the key");
    check(CMAC_Final(ctx, NULL, &len) == 1 && len == 16, "final with NULL reports the size");
    for (i = 0; i < 64; i++)
        check(CMAC_Update(ctx, msg + i, 1) == 1 || i < 0, "update an octet at a time") ;
    check(CMAC_Final(ctx, out, &len) == 1
          && same_hex(out, len, "51f0bebf7e3b9d92fc49741779363cfe"), "RFC 4493, 64 octets");

    /* Resume: the MAC of more data. */
    check(CMAC_Init(ctx, NULL, 0, NULL, NULL) == 1 && CMAC_Update(ctx, msg, 16) == 1
          && CMAC_Final(ctx, out, &len) == 1
          && same_hex(out, len, "070a16b46b4d4144f79bdd9dd04a287c"), "16 octets");
    check(CMAC_resume(ctx) == 1 && CMAC_Update(ctx, msg + 16, 24) == 1
          && CMAC_Final(ctx, out, &len) == 1
          && same_hex(out, len, "dfa66747de9ae63030ca32611497c827"), "resumed to 40 octets");

    /* Large inputs: more than a local buffer at once. */
    big = malloc(5000);
    for (i = 0; i < 5000; i++)
        big[i] = (unsigned char)(i * 7);
    check(CMAC_Init(ctx, NULL, 0, NULL, NULL) == 1 && CMAC_Update(ctx, big, 3) == 1
          && CMAC_Update(ctx, big + 3, 4997) == 1, "5000 octets");
    check(CMAC_CTX_copy(copy, ctx) == 1, "copy");
    check(CMAC_Final(ctx, out, &len) == 1, "final");
    hex("5000", out, len);
    {
        unsigned char out2[16];

        check(CMAC_Final(copy, out2, &len) == 1 && memcmp(out, out2, 16) == 0, "the copy agrees");
    }
    check(CMAC_Init(ctx, NULL, 0, NULL, NULL) == 1 && CMAC_Update(ctx, big, 4096) == 1
          && CMAC_Update(ctx, big + 4096, 904) == 1 && CMAC_Final(ctx, out, &len) == 1,
          "the same, a block-aligned split");
    hex("5000", out, len);
    free(big);

    CMAC_CTX_cleanup(ctx);
    check(CMAC_Update(ctx, msg, 1) == 0, "nothing after cleanup");
    check(CMAC_Init(ctx, "0123456789abcdefghijklmn", 24, EVP_des_ede3_cbc(), NULL) == 1
          && CMAC_Update(ctx, msg, 17) == 1 && CMAC_Final(ctx, out, &len) == 1 && len == 8,
          "Triple-DES");
    hex("3DES", out, len);
    CMAC_CTX_free(ctx);
    CMAC_CTX_free(copy);
    CMAC_CTX_free(NULL);
}

static void quick(void)
{
    unsigned char out[64], *p;
    size_t len = 0;
    unsigned char key[16];
    OSSL_PARAM params[2];

    unhex(rfc4493_key, key);
    p = EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, "Jefe", 4,
                  (const unsigned char *)"what do ya want for nothing?", 28, out, sizeof(out), &len);
    check(p == out && same_hex(out, len,
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"), "EVP_Q_mac HMAC");
    p = EVP_Q_mac(NULL, "CMAC", NULL, "AES-128-CBC", NULL, key, 16, NULL, 0, NULL, 0, &len);
    check(p != NULL && same_hex(p, len, "bb1d6929e95937287fa37d129b756746"),
          "EVP_Q_mac CMAC, allocated");
    OPENSSL_free(p);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV, "123456789012", 12);
    params[1] = OSSL_PARAM_construct_end();
    p = EVP_Q_mac(NULL, "GMAC", NULL, "AES-128-GCM", params, key, 16,
                  (const unsigned char *)"aad", 3, out, sizeof(out), &len);
    check(p == out && len == 16, "EVP_Q_mac GMAC");
    hex("gmac", out, len);
    p = EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, NULL, 0,
                  (const unsigned char *)"data", 4, out, sizeof(out), &len);
    check(p == out && len == 32, "EVP_Q_mac without a key");
    hex("no key", out, len);
    len = 99;
    p = EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, "k", 1,
                  (const unsigned char *)"d", 1, out, 31, &len);
    check(p == NULL, "too small a buffer");
    printf("  len: %zu\n", len);
    errors();
    p = EVP_Q_mac(NULL, "NO-SUCH-MAC", NULL, NULL, NULL, "k", 1,
                  (const unsigned char *)"d", 1, out, sizeof(out), &len);
    check(p == NULL, "an unknown MAC");
    errors();
    p = EVP_Q_mac(NULL, "HMAC", NULL, "NO-SUCH-MD", NULL, "k", 1,
                  (const unsigned char *)"d", 1, out, sizeof(out), &len);
    check(p == NULL, "an unknown digest");
    errors();
}

int main(void)
{
    methods();
    hmac_contexts();
    cmac_contexts();
    gmac_contexts();
    legacy_hmac();
    legacy_cmac();
    quick();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
