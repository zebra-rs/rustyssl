/*
 * Conformance test for HPKE (OSSL_HPKE_CTX_new(3) and the rest of the OSSL_HPKE_* functions),
 * in TAP format: every suite (each KEM, KDF, and AEAD, export-only included) in every mode,
 * with recipient and sender keys from fixed input key material and a fixed ephemeral seed, so
 * the encapsulated key, two ciphertexts, and an exported secret are printed (as hashes) and
 * opened back; then each function's argument checks and errors, the string parser, the
 * sizes, and GREASE.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>

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
    unsigned long e;
    const char *data;
    int flags;

    printf("  errors:");
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

/* The first octets of the SHA-256 of the octets. */
static void digest(const char *label, const unsigned char *p, size_t n)
{
    unsigned char md[32];
    unsigned int mdlen = 0;
    int i;

    EVP_Digest(p, n, md, &mdlen, EVP_sha256(), NULL);
    printf(" %s(%zu)=", label, n);
    for (i = 0; i < 6; i++)
        printf("%02x", md[i]);
}

static unsigned char IKM[80], PSK[40];
static const char PSKID[] = "an identity";
static const unsigned char INFO[] = "some info", AAD[] = "aad";
static const unsigned char PT1[] = "the first message", PT2[] = "a second one, a bit longer";

static const uint16_t KEMS[] = { 0x10, 0x11, 0x12, 0x20, 0x21 };
static const uint16_t KDFS[] = { 1, 2, 3 };
static const uint16_t AEADS[] = { 1, 2, 3, 0xffff };

/* Keys of the suite from IKM tagged with `tag`. */
static EVP_PKEY *keygen(OSSL_HPKE_SUITE suite, unsigned char tag, unsigned char *pub, size_t *publen)
{
    unsigned char ikm[66];
    EVP_PKEY *k = NULL;

    memcpy(ikm, IKM, sizeof(ikm));
    ikm[0] = tag;
    if (OSSL_HPKE_keygen(suite, pub, publen, &k, ikm, OSSL_HPKE_get_recommended_ikmelen(suite), NULL,
                         NULL) != 1)
        return NULL;
    return k;
}

static int round_trip(OSSL_HPKE_SUITE suite, int mode, int print)
{
    unsigned char rpub[200], spub[200], enc[200], ct1[100], ct2[100], pt[100], exp1[32], exp2[32];
    size_t rpublen = sizeof(rpub), spublen = sizeof(spub), enclen = sizeof(enc);
    size_t ct1len = sizeof(ct1), ct2len = sizeof(ct2), ptlen;
    EVP_PKEY *r = keygen(suite, 1, rpub, &rpublen), *s = keygen(suite, 2, spub, &spublen);
    OSSL_HPKE_CTX *sctx = OSSL_HPKE_CTX_new(mode, suite, OSSL_HPKE_ROLE_SENDER, NULL, NULL);
    OSSL_HPKE_CTX *rctx = OSSL_HPKE_CTX_new(mode, suite, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL);
    int psk = mode == OSSL_HPKE_MODE_PSK || mode == OSSL_HPKE_MODE_PSKAUTH;
    int auth = mode == OSSL_HPKE_MODE_AUTH || mode == OSSL_HPKE_MODE_PSKAUTH;
    int exponly = suite.aead_id == 0xffff, ok = 0;
    uint64_t seq = 0;

    if (r == NULL || s == NULL || sctx == NULL || rctx == NULL)
        goto end;
    if (psk && (OSSL_HPKE_CTX_set1_psk(sctx, PSKID, PSK, 32) != 1
                || OSSL_HPKE_CTX_set1_psk(rctx, PSKID, PSK, 32) != 1))
        goto end;
    if (auth && (OSSL_HPKE_CTX_set1_authpriv(sctx, s) != 1
                 || OSSL_HPKE_CTX_set1_authpub(rctx, spub, spublen) != 1))
        goto end;
    if (print && OSSL_HPKE_CTX_set1_ikme(sctx, IKM + 5, OSSL_HPKE_get_recommended_ikmelen(suite)) != 1)
        goto end;
    if (OSSL_HPKE_encap(sctx, enc, &enclen, rpub, rpublen, INFO, sizeof(INFO) - 1) != 1)
        goto end;
    if (OSSL_HPKE_decap(rctx, enc, enclen, r, INFO, sizeof(INFO) - 1) != 1)
        goto end;
    if (!exponly) {
        if (OSSL_HPKE_seal(sctx, ct1, &ct1len, AAD, sizeof(AAD) - 1, PT1, sizeof(PT1) - 1) != 1
            || OSSL_HPKE_seal(sctx, ct2, &ct2len, NULL, 0, PT2, sizeof(PT2) - 1) != 1)
            goto end;
        ptlen = sizeof(pt);
        if (OSSL_HPKE_open(rctx, pt, &ptlen, AAD, sizeof(AAD) - 1, ct1, ct1len) != 1
            || ptlen != sizeof(PT1) - 1 || memcmp(pt, PT1, ptlen) != 0)
            goto end;
        ptlen = sizeof(pt);
        if (OSSL_HPKE_open(rctx, pt, &ptlen, NULL, 0, ct2, ct2len) != 1
            || ptlen != sizeof(PT2) - 1 || memcmp(pt, PT2, ptlen) != 0)
            goto end;
        if (OSSL_HPKE_CTX_get_seq(rctx, &seq) != 1 || seq != 2)
            goto end;
    }
    if (OSSL_HPKE_export(sctx, exp1, sizeof(exp1), (const unsigned char *)"label", 5) != 1
        || OSSL_HPKE_export(rctx, exp2, sizeof(exp2), (const unsigned char *)"label", 5) != 1
        || memcmp(exp1, exp2, sizeof(exp1)) != 0)
        goto end;
    if (print) {
        printf("  %04x,%04x,%04x mode %d:", suite.kem_id, suite.kdf_id, suite.aead_id, mode);
        digest("pkR", rpub, rpublen);
        digest("enc", enc, enclen);
        if (!exponly) {
            digest("ct1", ct1, ct1len);
            digest("ct2", ct2, ct2len);
        }
        digest("exp", exp1, sizeof(exp1));
        printf("\n");
    }
    ok = 1;
end:
    if (!ok)
        errors();
    EVP_PKEY_free(r);
    EVP_PKEY_free(s);
    OSSL_HPKE_CTX_free(sctx);
    OSSL_HPKE_CTX_free(rctx);
    return ok;
}

static void test_suites(void)
{
    size_t a, b, c;
    int mode, all = 1, random_ok = 1;

    printf("# every suite and mode\n");
    for (a = 0; a < sizeof(KEMS) / sizeof(KEMS[0]); a++)
        for (b = 0; b < sizeof(KDFS) / sizeof(KDFS[0]); b++)
            for (c = 0; c < sizeof(AEADS) / sizeof(AEADS[0]); c++)
                for (mode = 0; mode < 4; mode++) {
                    OSSL_HPKE_SUITE suite;

                    suite.kem_id = KEMS[a];
                    suite.kdf_id = KDFS[b];
                    suite.aead_id = AEADS[c];
                    if (!round_trip(suite, mode, 1)) {
                        printf("  %04x,%04x,%04x mode %d failed\n", suite.kem_id, suite.kdf_id,
                               suite.aead_id, mode);
                        all = 0;
                    }
                    if (mode == 0 && !round_trip(suite, mode, 0))
                        random_ok = 0;
                }
    check(all, "every suite and mode round-trips");
    check(random_ok, "random ephemeral keys round-trip");
}

static void test_errors(void)
{
    OSSL_HPKE_SUITE def = OSSL_HPKE_SUITE_DEFAULT, bad = def;
    unsigned char rpub[100], enc[100], ct[100], pt[100], out[32], big[70];
    size_t rpublen = sizeof(rpub), enclen, ctlen, ptlen;
    EVP_PKEY *r = keygen(def, 1, rpub, &rpublen), *k = NULL;
    OSSL_HPKE_CTX *ctx, *rctx;
    uint64_t seq = 7;
    int ret;

    printf("# errors\n");
    memset(big, 'a', sizeof(big));
    printf("  new mode 4: %p\n", (void *)OSSL_HPKE_CTX_new(4, def, 0, NULL, NULL));
    errors();
    printf("  new role 2: %p\n", (void *)OSSL_HPKE_CTX_new(0, def, 2, NULL, NULL));
    errors();
    bad.kem_id = 0;
    printf("  new kem 0: %p\n", (void *)OSSL_HPKE_CTX_new(0, bad, 0, NULL, NULL));
    errors();
    bad = def;
    bad.kdf_id = 4;
    printf("  new kdf 4: %p\n", (void *)OSSL_HPKE_CTX_new(0, bad, 0, NULL, NULL));
    errors();
    bad = def;
    bad.aead_id = 4;
    printf("  new aead 4: %p\n", (void *)OSSL_HPKE_CTX_new(0, bad, 0, NULL, NULL));
    errors();
    printf("  new with a property no one has: %p\n",
           (void *)OSSL_HPKE_CTX_new(0, def, 0, NULL, "provider=nobody"));
    errors();
    OSSL_HPKE_CTX_free(NULL);

    ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, def, OSSL_HPKE_ROLE_SENDER, NULL, NULL);
    rctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, def, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL);
    check(ctx != NULL && rctx != NULL && r != NULL, "contexts");
    printf("  psk in base mode: %d\n", OSSL_HPKE_CTX_set1_psk(ctx, PSKID, PSK, 32));
    errors();
    printf("  authpriv in base mode: %d\n", OSSL_HPKE_CTX_set1_authpriv(ctx, r));
    errors();
    printf("  authpub in base mode: %d\n", OSSL_HPKE_CTX_set1_authpub(rctx, rpub, rpublen));
    errors();
    printf("  ikme: %d, receiver %d, NULL %d, 0 %d, 67 %d\n",
           OSSL_HPKE_CTX_set1_ikme(ctx, IKM, 32), OSSL_HPKE_CTX_set1_ikme(rctx, IKM, 32),
           OSSL_HPKE_CTX_set1_ikme(ctx, NULL, 32), OSSL_HPKE_CTX_set1_ikme(ctx, IKM, 0),
           OSSL_HPKE_CTX_set1_ikme(ctx, IKM, 67));
    errors();
    printf("  seq: get %d (%llu), set sender %d, set receiver %d, NULL %d\n",
           OSSL_HPKE_CTX_get_seq(ctx, &seq), (unsigned long long)seq,
           OSSL_HPKE_CTX_set_seq(ctx, 5), OSSL_HPKE_CTX_set_seq(rctx, 5),
           OSSL_HPKE_CTX_get_seq(ctx, NULL));
    errors();
    OSSL_HPKE_CTX_set_seq(rctx, 0);
    ctlen = sizeof(ct);
    printf("  seal before encap: %d\n", OSSL_HPKE_seal(ctx, ct, &ctlen, NULL, 0, PT1, 4));
    errors();
    printf("  export before encap: %d\n", OSSL_HPKE_export(ctx, out, 32, NULL, 0));
    errors();
    enclen = 10;
    printf("  encap, room 10: %d\n", OSSL_HPKE_encap(ctx, enc, &enclen, rpub, rpublen, NULL, 0));
    errors();
    enclen = sizeof(enc);
    printf("  encap, info NULL with a length: %d\n",
           OSSL_HPKE_encap(ctx, enc, &enclen, rpub, rpublen, NULL, 3));
    errors();
    printf("  encap, info too long: %d\n",
           OSSL_HPKE_encap(ctx, enc, &enclen, rpub, rpublen, big, 1025));
    errors();
    printf("  encap by a receiver: %d\n", OSSL_HPKE_encap(rctx, enc, &enclen, rpub, rpublen, NULL, 0));
    errors();
    printf("  encap to a short key: %d\n", OSSL_HPKE_encap(ctx, enc, &enclen, rpub, 31, NULL, 0));
    errors();
    enclen = sizeof(enc);
    ret = OSSL_HPKE_encap(ctx, enc, &enclen, rpub, rpublen, NULL, 0);
    printf("  encap: %d, enc %zu\n", ret, enclen);
    printf("  encap again: %d\n", OSSL_HPKE_encap(ctx, enc, &enclen, rpub, rpublen, NULL, 0));
    errors();
    printf("  decap short: %d\n", OSSL_HPKE_decap(rctx, enc, 31, r, NULL, 0));
    errors();
    printf("  decap by a sender: %d\n", OSSL_HPKE_decap(ctx, enc, enclen, r, NULL, 0));
    errors();
    printf("  decap, no key: %d\n", OSSL_HPKE_decap(rctx, enc, enclen, NULL, NULL, 0));
    errors();
    printf("  decap: %d\n", OSSL_HPKE_decap(rctx, enc, enclen, r, NULL, 0));
    printf("  decap again: %d\n", OSSL_HPKE_decap(rctx, enc, enclen, r, NULL, 0));
    errors();
    ctlen = 16;
    printf("  seal, room for the tag only: %d\n", OSSL_HPKE_seal(ctx, ct, &ctlen, NULL, 0, PT1, 4));
    errors();
    ctlen = sizeof(ct);
    printf("  seal, empty plaintext: %d\n", OSSL_HPKE_seal(ctx, ct, &ctlen, NULL, 0, PT1, 0));
    errors();
    printf("  seal by a receiver: %d\n", OSSL_HPKE_seal(rctx, ct, &ctlen, NULL, 0, PT1, 4));
    errors();
    ctlen = sizeof(ct);
    ret = OSSL_HPKE_seal(ctx, ct, &ctlen, NULL, 3, PT1, 4);
    printf("  seal, AAD NULL with a length: %d, %zu\n", ret, ctlen);
    ptlen = sizeof(pt);
    printf("  open: %d, %zu\n", OSSL_HPKE_open(rctx, pt, &ptlen, NULL, 0, ct, ctlen), ptlen);
    ctlen = sizeof(ct);
    OSSL_HPKE_seal(ctx, ct, &ctlen, AAD, 3, PT1, 4);
    ptlen = sizeof(pt);
    printf("  open, other AAD: %d\n", OSSL_HPKE_open(rctx, pt, &ptlen, NULL, 0, ct, ctlen));
    errors();
    ptlen = 3;
    printf("  open, room short: %d\n", OSSL_HPKE_open(rctx, pt, &ptlen, AAD, 3, ct, ctlen));
    errors();
    ptlen = sizeof(pt);
    printf("  open, only a tag: %d\n", OSSL_HPKE_open(rctx, pt, &ptlen, AAD, 3, ct, 16));
    errors();
    ptlen = sizeof(pt);
    ct[0] ^= 1;
    printf("  open, changed: %d\n", OSSL_HPKE_open(rctx, pt, &ptlen, AAD, 3, ct, ctlen));
    errors();
    ct[0] ^= 1;
    ptlen = sizeof(pt);
    printf("  open: %d\n", OSSL_HPKE_open(rctx, pt, &ptlen, AAD, 3, ct, ctlen));
    OSSL_HPKE_CTX_get_seq(rctx, &seq);
    printf("  receiver seq %llu\n", (unsigned long long)seq);
    OSSL_HPKE_CTX_set_seq(rctx, UINT64_MAX);
    ptlen = sizeof(pt);
    printf("  open at the last seq: %d\n", OSSL_HPKE_open(rctx, pt, &ptlen, AAD, 3, ct, ctlen));
    errors();
    printf("  export, label too long: %d, label NULL with a length: %d, no room: %d\n",
           OSSL_HPKE_export(ctx, out, 32, big, 67), OSSL_HPKE_export(ctx, out, 32, NULL, 1),
           OSSL_HPKE_export(ctx, out, 0, NULL, 0));
    errors();
    {
        unsigned char *huge = malloc(66000);

        printf("  export 66000 octets: %d\n", OSSL_HPKE_export(ctx, huge, 66000, NULL, 0));
        errors();
        free(huge);
    }
    OSSL_HPKE_CTX_free(ctx);
    OSSL_HPKE_CTX_free(rctx);

    /* psk and auth arguments. */
    ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_PSKAUTH, def, OSSL_HPKE_ROLE_SENDER, NULL, NULL);
    rctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_PSKAUTH, def, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL);
    printf("  psk: 31 %d, 67 %d, empty id %d, long id %d, NULL id %d, ok %d\n",
           OSSL_HPKE_CTX_set1_psk(ctx, PSKID, PSK, 31), OSSL_HPKE_CTX_set1_psk(ctx, PSKID, big, 67),
           OSSL_HPKE_CTX_set1_psk(ctx, "", PSK, 32),
           OSSL_HPKE_CTX_set1_psk(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PSK, 32),
           OSSL_HPKE_CTX_set1_psk(ctx, NULL, PSK, 32), OSSL_HPKE_CTX_set1_psk(ctx, PSKID, PSK, 40));
    errors();
    printf("  authpriv by a receiver: %d, NULL %d\n", OSSL_HPKE_CTX_set1_authpriv(rctx, r),
           OSSL_HPKE_CTX_set1_authpriv(ctx, NULL));
    errors();
    printf("  authpub by a sender: %d, bad %d, empty %d\n", OSSL_HPKE_CTX_set1_authpub(ctx, rpub, rpublen),
           OSSL_HPKE_CTX_set1_authpub(rctx, rpub, 5), OSSL_HPKE_CTX_set1_authpub(rctx, rpub, 0));
    errors();
    enclen = sizeof(enc);
    printf("  encap without an authpriv: %d\n", OSSL_HPKE_encap(ctx, enc, &enclen, rpub, rpublen, NULL, 0));
    errors();
    OSSL_HPKE_CTX_free(ctx);
    ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_PSK, def, OSSL_HPKE_ROLE_SENDER, NULL, NULL);
    enclen = sizeof(enc);
    printf("  encap without a psk: %d\n", OSSL_HPKE_encap(ctx, enc, &enclen, rpub, rpublen, NULL, 0));
    errors();
    OSSL_HPKE_CTX_free(ctx);
    OSSL_HPKE_CTX_free(rctx);

    /* keygen's arguments. */
    rpublen = 0;
    printf("  keygen, no room: %d\n", OSSL_HPKE_keygen(def, rpub, &rpublen, &k, NULL, 0, NULL, NULL));
    rpublen = sizeof(rpub);
    printf("  keygen, ikm NULL with a length: %d\n", OSSL_HPKE_keygen(def, rpub, &rpublen, &k, NULL, 32, NULL, NULL));
    printf("  keygen, ikm with 0: %d\n", OSSL_HPKE_keygen(def, rpub, &rpublen, &k, IKM, 0, NULL, NULL));
    printf("  keygen, ikm 67: %d\n", OSSL_HPKE_keygen(def, rpub, &rpublen, &k, IKM, 67, NULL, NULL));
    printf("  keygen, short ikm: %d\n", OSSL_HPKE_keygen(def, rpub, &rpublen, &k, IKM, 8, NULL, NULL));
    errors();
    rpublen = 10;
    printf("  keygen, small room: %d\n", OSSL_HPKE_keygen(def, rpub, &rpublen, &k, NULL, 0, NULL, NULL));
    errors();
    EVP_PKEY_free(r);
}

static void test_strings_and_sizes(void)
{
    static const char *strs[] = {
        "x25519,hkdf-sha256,aes-128-gcm", "0x10,0x01,0x01", "P-256,1,ff", "16,2,3", "0X21,3,0XFF",
        "p-521,HKDF-SHA512,ChaCha20-Poly1305", "x448,hkdf-sha384,exporter", "x25519,hkdf-sha256,",
        "x25519,hkdf-sha256", "x25519,hkdf-sha256,1,1", "x25519,,1", "x25519,hkdf-sha256,aes-128-gcm-",
        "0x22,1,1", "0x20,0x04,1", "0x20,1,4", "", "x25519,hkdf-sha256,chacha20-poly1305x",
        "32 ,1,1",
    };
    OSSL_HPKE_SUITE suite, bad = OSSL_HPKE_SUITE_DEFAULT;
    size_t i;

    printf("# strings\n");
    for (i = 0; i < sizeof(strs) / sizeof(strs[0]); i++) {
        int r;

        memset(&suite, 0, sizeof(suite));
        r = OSSL_HPKE_str2suite(strs[i], &suite);
        printf("  \"%s\": %d %04x,%04x,%04x", strs[i], r, suite.kem_id, suite.kdf_id, suite.aead_id);
        errors();
    }
    printf("  NULL: %d, NULL suite: %d\n", OSSL_HPKE_str2suite(NULL, &suite),
           OSSL_HPKE_str2suite("1,1,1", NULL));
    errors();

    printf("# sizes\n");
    for (i = 0; i < sizeof(KEMS) / sizeof(KEMS[0]); i++) {
        suite.kem_id = KEMS[i];
        suite.kdf_id = 1;
        suite.aead_id = 0xffff;
        printf("  kem %04x: ct %zu, enc %zu, ikme %zu, check %d\n", KEMS[i],
               OSSL_HPKE_get_ciphertext_size(suite, 100), OSSL_HPKE_get_public_encap_size(suite),
               OSSL_HPKE_get_recommended_ikmelen(suite), OSSL_HPKE_suite_check(suite));
        suite.aead_id = 3;
        printf("    with chacha: ct %zu\n", OSSL_HPKE_get_ciphertext_size(suite, 100));
    }
    bad.kem_id = 0x13;
    printf("  bad kem: ct %zu, enc %zu, ikme %zu, check %d\n",
           OSSL_HPKE_get_ciphertext_size(bad, 100), OSSL_HPKE_get_public_encap_size(bad),
           OSSL_HPKE_get_recommended_ikmelen(bad), OSSL_HPKE_suite_check(bad));
    errors();
    bad.kem_id = 0x20;
    bad.aead_id = 0;
    printf("  bad aead: check %d\n", OSSL_HPKE_suite_check(bad));
    errors();
}

static void test_grease(void)
{
    OSSL_HPKE_SUITE in = { 0x10, 2, 1 }, out = { 0, 0, 0 };
    unsigned char enc[200], ct[64];
    size_t enclen = sizeof(enc);
    int i, all = 1;

    printf("# grease\n");
    printf("  given: %d", OSSL_HPKE_get_grease_value(&in, &out, enc, &enclen, ct, sizeof(ct), NULL, NULL));
    printf(" %04x,%04x,%04x enc %zu first %02x\n", out.kem_id, out.kdf_id, out.aead_id, enclen, enc[0]);
    for (i = 0; i < 50; i++) {
        enclen = sizeof(enc);
        if (OSSL_HPKE_get_grease_value(NULL, &out, enc, &enclen, ct, sizeof(ct), NULL, NULL) != 1
            || OSSL_HPKE_suite_check(out) != 1 || out.aead_id == 0xffff
            || enclen != OSSL_HPKE_get_public_encap_size(out))
            all = 0;
    }
    check(all, "random GREASE suites are real ones, never export-only");
    enclen = 10;
    printf("  small enc room: %d\n", OSSL_HPKE_get_grease_value(&in, &out, enc, &enclen, ct, sizeof(ct), NULL, NULL));
    errors();
    enclen = sizeof(enc);
    printf("  ct of the tag's length: %d\n", OSSL_HPKE_get_grease_value(&in, &out, enc, &enclen, ct, 16, NULL, NULL));
    errors();
    printf("  NULLs: %d %d\n", OSSL_HPKE_get_grease_value(&in, NULL, enc, &enclen, ct, 16, NULL, NULL),
           OSSL_HPKE_get_grease_value(&in, &out, enc, &enclen, NULL, 16, NULL, NULL));
    errors();
    in.kem_id = 7;
    printf("  bad suite: %d\n", OSSL_HPKE_get_grease_value(&in, &out, enc, &enclen, ct, sizeof(ct), NULL, NULL));
    errors();
}

int main(void)
{
    size_t i;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    for (i = 0; i < sizeof(IKM); i++)
        IKM[i] = (unsigned char)(i * 13 + 5);
    for (i = 0; i < sizeof(PSK); i++)
        PSK[i] = (unsigned char)(0xa0 + i);
    test_suites();
    test_errors();
    test_strings_and_sizes();
    test_grease();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
