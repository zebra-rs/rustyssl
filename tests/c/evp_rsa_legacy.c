/*
 * Conformance test for the legacy RSA key method (EVP_PKEY_meth_find(3) for EVP_PKEY_RSA and
 * EVP_PKEY_RSA_PSS; OpenSSL's rsa_pmeth.c), in TAP format. An RSA key with an application's
 * method stays a legacy ("foreign") key, so its EVP operations go through the key type's
 * built-in EVP_PKEY_METHOD instead of a provider: signing (raw, with a digest, PKCS #1, X9.31,
 * PSS, MDC2's OCTET STRING), verifying, recovering, encrypting and decrypting (PKCS #1 with and
 * without implicit rejection, OAEP with a label, none), EVP_DigestSign, and the ctrls and
 * ctrl strings with their errors; the application's method counts the operations it sees. Then
 * key generation through an application's copy of the built-in methods, for RSA (bits,
 * primes, exponent, the callback) and RSA-PSS (with and without parameter restrictions, which
 * the key keeps, prints, and enforces).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The error queue, emptied: each entry's library and reason. */
static void errors(void)
{
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, size_t len)
{
    size_t i;

    printf("  %s (%zu):", label, len);
    for (i = 0; i < len; i++)
        printf("%s%02x", i % 32 == 0 && i > 0 ? "\n    " : "", p[i]);
    printf("\n");
}

static const char *key_hex =
    "3082025d02010002818100db67d93db3d51b942ecd08d264f2bad903d9ae7e13"
    "031ec86a94ab7c691fe236f0916d6cf025ad000da8658129e99592a914897f49"
    "083b7962f05be187e704fa1a093bda59e4cb1aa2c2f0021e36006c0349264ad3"
    "540c162bc217aca642769e28a79a6d8b859f09a1aa1cf81469ef78600fe9ae55"
    "8a6303af46bc5a00a471790203010001028181008748ff60d673feef5df43b0e"
    "50048345b0e4167dd2874801d80617bf3caad6377e1a8dd870332afb2f70b835"
    "ee7c03284d6d4662dfcb5db0b95aefac9eb9ca0cb02c18bfc9f2e4a42245bd9f"
    "94855315e033420539e6037b57bc210935ac85151fd6263a6822082a9c06df54"
    "b0ae2054309f90cfc40a29bd6d67f012ad8ceaa1024100fa93e51adf737d0e0b"
    "ad2925d1f39dcd04822865f261aedf4959d80381bad97e12b2490071b0f247fc"
    "d84eebfe46bbcde12378cf257a6086aa0905fab8e36f15024100e02745b853f2"
    "4877c2d2ba24df19b4358898876cde238735109b1a08dc6cfd314936ab92152d"
    "94494d3bf594aedeea84f2baeabcc530c0302b3aea64500e31d50240184f3ccc"
    "cc9cd1a7092ef56cfbdf5c91c53c335b2096a57678114549a1ce54c74c5d0b84"
    "05839b1dacc3f77421a90f133c224ad81dd4af84a0fe5b1c25cfbab902402873"
    "8de674e7cd62277b85f22f7ce103a431fa869014134b6542c850ff0e8026cbd2"
    "9ce5d10297b71ec40a4e99bc4ad05149a0210ee8fc55f5073dd37a8b053d0241"
    "00e4dd1cdd3f24d005d583dacd944914dfec2b705ad4773a82213f095e57b2e2"
    "1c423b3d35df6721b5c3d329d792396b5c470ba1c6514ee18a52ff5765edd0b5"
    "11";

/* The application's method: the default one's functions, counting their calls. */
static int counts[4];

static int count_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
                         int padding)
{
    counts[0]++;
    return RSA_meth_get_pub_enc(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
}

static int count_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
                         int padding)
{
    counts[1]++;
    return RSA_meth_get_pub_dec(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
}

static int count_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
                          int padding)
{
    counts[2]++;
    return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
}

static int count_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
                          int padding)
{
    counts[3]++;
    return RSA_meth_get_priv_dec(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
}

static void show_counts(void)
{
    printf("  method calls: pub_enc %d, pub_dec %d, priv_enc %d, priv_dec %d\n", counts[0],
           counts[1], counts[2], counts[3]);
}

/* The fixed key, with the counting method. */
static EVP_PKEY *foreign_key(RSA_METHOD *meth)
{
    unsigned char der[1024];
    const unsigned char *p = der;
    size_t len = strlen(key_hex) / 2, i;
    RSA *rsa;
    EVP_PKEY *pk;

    for (i = 0; i < len; i++) {
        unsigned int v;

        sscanf(key_hex + 2 * i, "%2x", &v);
        der[i] = (unsigned char)v;
    }
    rsa = d2i_RSAPrivateKey(NULL, &p, (long)len);
    RSA_set_method(rsa, meth);
    pk = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pk, rsa);
    return pk;
}

static EVP_PKEY_CTX *ctx_for(EVP_PKEY *pk, int (*init)(EVP_PKEY_CTX *))
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk, NULL);

    if (ctx == NULL || init(ctx) <= 0) {
        printf("  context failed\n");
        errors();
    }
    return ctx;
}

static void test_sign(EVP_PKEY *pk)
{
    unsigned char tbs[64], sig[256], rec[256];
    size_t siglen = 0, reclen;
    EVP_PKEY_CTX *ctx;
    int ret, i;

    for (i = 0; i < 64; i++)
        tbs[i] = (unsigned char)(i * 7 + 1);

    ctx = ctx_for(pk, EVP_PKEY_sign_init);
    ret = EVP_PKEY_sign(ctx, NULL, &siglen, tbs, 20);
    check(ret == 1 && siglen == 128, "sign: the size, from the key (AUTOARGLEN)");
    siglen = 10;
    ret = EVP_PKEY_sign(ctx, sig, &siglen, tbs, 20);
    check(ret <= 0, "sign: a buffer too small");
    printf("  ret %d\n", ret);
    errors();
    siglen = sizeof(sig);
    ret = EVP_PKEY_sign(ctx, sig, &siglen, tbs, 20);
    check(ret == 1, "sign: raw PKCS #1 (no digest)");
    hex("sig", sig, siglen);
    {
        int pad = -1;

        check(EVP_PKEY_CTX_get_rsa_padding(ctx, &pad) == 1 && pad == RSA_PKCS1_PADDING,
              "the padding is PKCS #1 by default");
    }

    check(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) == 1, "set the digest: SHA-256");
    siglen = sizeof(sig);
    ret = EVP_PKEY_sign(ctx, sig, &siglen, tbs, 20);
    check(ret == -1, "sign: a length that isn't the digest's");
    errors();
    siglen = sizeof(sig);
    ret = EVP_PKEY_sign(ctx, sig, &siglen, tbs, 32);
    check(ret == 1, "sign: PKCS #1 with SHA-256");
    hex("sig", sig, siglen);
    {
        const EVP_MD *md = NULL;

        check(EVP_PKEY_CTX_get_signature_md(ctx, &md) == 1 && md == EVP_sha256(),
              "get the digest");
    }
    EVP_PKEY_CTX_free(ctx);

    ctx = ctx_for(pk, EVP_PKEY_verify_init);
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
    check(EVP_PKEY_verify(ctx, sig, siglen, tbs, 32) == 1, "verify: PKCS #1 with SHA-256");
    sig[5] ^= 1;
    ret = EVP_PKEY_verify(ctx, sig, siglen, tbs, 32);
    check(ret == 0, "verify: a changed signature");
    errors();
    sig[5] ^= 1;
    ret = EVP_PKEY_verify(ctx, sig, siglen, tbs, 31);
    check(ret <= 0, "verify: a short digest");
    printf("  ret %d\n", ret);
    errors();
    EVP_PKEY_CTX_free(ctx);

    ctx = ctx_for(pk, EVP_PKEY_verify_recover_init);
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
    reclen = sizeof(rec);
    ret = EVP_PKEY_verify_recover(ctx, rec, &reclen, sig, siglen);
    check(ret == 1 && reclen == 32 && memcmp(rec, tbs, 32) == 0,
          "verify_recover: the digest, out of the DigestInfo");
    reclen = 0;
    ret = EVP_PKEY_verify_recover(ctx, NULL, &reclen, sig, siglen);
    check(ret == 1, "verify_recover: the size");
    printf("  size %zu\n", reclen);
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha1());
    reclen = sizeof(rec);
    ret = EVP_PKEY_verify_recover(ctx, rec, &reclen, sig, siglen);
    check(ret == 0, "verify_recover: another digest");
    errors();
    EVP_PKEY_CTX_free(ctx);

    /* X9.31 with SHA-1. */
    ctx = ctx_for(pk, EVP_PKEY_sign_init);
    check(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_X931_PADDING) == 1
          && EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha1()) == 1, "X9.31 with SHA-1");
    siglen = sizeof(sig);
    ret = EVP_PKEY_sign(ctx, sig, &siglen, tbs, 20);
    check(ret == 1, "sign: X9.31");
    hex("sig", sig, siglen);
    check(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha3_256()) == 0,
          "X9.31 takes no SHA3-256");
    errors();
    EVP_PKEY_CTX_free(ctx);
    ctx = ctx_for(pk, EVP_PKEY_verify_init);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_X931_PADDING);
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha1());
    check(EVP_PKEY_verify(ctx, sig, siglen, tbs, 20) == 1, "verify: X9.31");
    check(EVP_PKEY_verify(ctx, sig, siglen, tbs + 1, 20) == 0, "verify: X9.31, another digest");
    errors();
    EVP_PKEY_CTX_free(ctx);
    ctx = ctx_for(pk, EVP_PKEY_verify_recover_init);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_X931_PADDING);
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha1());
    reclen = sizeof(rec);
    ret = EVP_PKEY_verify_recover(ctx, rec, &reclen, sig, siglen);
    check(ret == 1 && reclen == 20 && memcmp(rec, tbs, 20) == 0, "verify_recover: X9.31");
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
    reclen = sizeof(rec);
    ret = EVP_PKEY_verify_recover(ctx, rec, &reclen, sig, siglen);
    check(ret == 0, "verify_recover: X9.31 with the wrong hash identifier");
    errors();
    EVP_PKEY_CTX_free(ctx);

    /* MDC2: an OCTET STRING, not a DigestInfo. */
    ctx = ctx_for(pk, EVP_PKEY_sign_init);
    check(EVP_PKEY_CTX_set_signature_md(ctx, EVP_mdc2()) == 1, "MDC2");
    siglen = sizeof(sig);
    ret = EVP_PKEY_sign(ctx, sig, &siglen, tbs, 16);
    check(ret == 1, "sign: MDC2's OCTET STRING");
    hex("sig", sig, siglen);
    EVP_PKEY_CTX_free(ctx);

    /* PSS. */
    ctx = ctx_for(pk, EVP_PKEY_sign_init);
    check(EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 20) == -2, "a salt length without PSS");
    errors();
    check(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) == 1, "PSS");
    {
        const EVP_MD *md = NULL;
        int saltlen = 0;

        check(EVP_PKEY_CTX_get_signature_md(ctx, &md) == 1 && md == EVP_sha1(),
              "PSS sets SHA-1 when there's no digest");
        check(EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &md) == 1 && md == EVP_sha1(),
              "the MGF1 digest is the digest");
        check(EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &saltlen) == 1, "the salt length");
        printf("  saltlen %d\n", saltlen);
    }
    check(EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -5) == -2, "a salt length below -4");
    errors();
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha384());
    EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 20);
    siglen = sizeof(sig);
    ret = EVP_PKEY_sign(ctx, sig, &siglen, tbs, 32);
    check(ret == 1 && siglen == 128, "sign: PSS");
    EVP_PKEY_CTX_free(ctx);
    ctx = ctx_for(pk, EVP_PKEY_verify_init);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha384());
    check(EVP_PKEY_verify(ctx, sig, siglen, tbs, 32) == 1, "verify: PSS, the salt length found");
    EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 20);
    check(EVP_PKEY_verify(ctx, sig, siglen, tbs, 32) == 1, "verify: PSS, salt length 20");
    EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 30);
    check(EVP_PKEY_verify(ctx, sig, siglen, tbs, 32) == 0, "verify: PSS, salt length 30");
    errors();
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_AUTO);
    check(EVP_PKEY_verify(ctx, sig, siglen, tbs, 32) == 0, "verify: PSS, another MGF1 digest");
    errors();
    EVP_PKEY_CTX_free(ctx);

    /* Paddings and digests that don't go together. */
    ctx = ctx_for(pk, EVP_PKEY_sign_init);
    check(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == -2, "OAEP for signing");
    errors();
    check(EVP_PKEY_CTX_set_rsa_padding(ctx, 99) == -2, "padding 99");
    errors();
    check(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) == 1, "no padding");
    check(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) == 0, "no padding takes no digest");
    errors();
    check(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 1
          && EVP_PKEY_CTX_set_signature_md(ctx, EVP_sm3()) == 0, "PKCS #1 takes no SM3");
    errors();
    check(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) == -2, "an MGF1 digest for PKCS #1");
    errors();
    ret = EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    check(ret <= 0, "an OAEP digest for signing");
    printf("  ret %d\n", ret);
    errors();
    check(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == -2, "key bits while signing");
    errors();
    memset(sig, 0, sizeof(sig));
    siglen = sizeof(sig);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);
    ret = EVP_PKEY_sign(ctx, sig, &siglen, tbs, 64);
    check(ret <= 0, "sign: no padding, input shorter than the key");
    printf("  ret %d\n", ret);
    errors();
    EVP_PKEY_CTX_free(ctx);
}

static void test_crypt(EVP_PKEY *pk)
{
    unsigned char in[128], out[256], back[256];
    size_t outlen, backlen;
    EVP_PKEY_CTX *ctx, *dctx;
    int ret, i;

    for (i = 0; i < 128; i++)
        in[i] = (unsigned char)(i * 3 + 5);
    in[0] = 0;

    ctx = ctx_for(pk, EVP_PKEY_encrypt_init);
    dctx = ctx_for(pk, EVP_PKEY_decrypt_init);
    outlen = 0;
    check(EVP_PKEY_encrypt(ctx, NULL, &outlen, in, 20) == 1 && outlen == 128,
          "encrypt: the size");
    outlen = sizeof(out);
    ret = EVP_PKEY_encrypt(ctx, out, &outlen, in, 20);
    backlen = sizeof(back);
    check(ret == 1 && EVP_PKEY_decrypt(dctx, back, &backlen, out, outlen) == 1
          && backlen == 20 && memcmp(back, in, 20) == 0, "PKCS #1: encrypted and decrypted");
    outlen = sizeof(out);
    ret = EVP_PKEY_encrypt(ctx, out, &outlen, in, 118);
    check(ret <= 0, "encrypt: PKCS #1, too long");
    printf("  ret %d\n", ret);
    errors();

    /* Implicit rejection: a bad ciphertext decrypts to a synthetic message. */
    memset(out, 0x55, 128);
    backlen = sizeof(back);
    ret = EVP_PKEY_decrypt(dctx, back, &backlen, out, 128);
    check(ret == 1, "decrypt: a bad ciphertext, implicit rejection");
    hex("message", back, backlen);
    check(EVP_PKEY_CTX_ctrl(dctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION, 0,
                            NULL) == 1, "implicit rejection off");
    backlen = 77;
    ret = EVP_PKEY_decrypt(dctx, back, &backlen, out, 128);
    check(ret <= 0 && backlen == 77, "decrypt: a bad ciphertext fails, the length untouched");
    printf("  ret %d\n", ret);
    errors();

    /* No padding. */
    check(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) == 1, "no padding");
    outlen = sizeof(out);
    ret = EVP_PKEY_encrypt(ctx, out, &outlen, in, 128);
    check(ret == 1, "encrypt: no padding");
    hex("ciphertext", out, outlen);
    EVP_PKEY_CTX_set_rsa_padding(dctx, RSA_NO_PADDING);
    backlen = sizeof(back);
    check(EVP_PKEY_decrypt(dctx, back, &backlen, out, outlen) == 1 && backlen == 128
          && memcmp(back, in, 128) == 0, "decrypt: no padding");

    /* OAEP with a label. */
    check(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == 1
          && EVP_PKEY_CTX_set_rsa_padding(dctx, RSA_PKCS1_OAEP_PADDING) == 1, "OAEP");
    {
        const EVP_MD *md = NULL;
        unsigned char *label;

        check(EVP_PKEY_CTX_get_rsa_oaep_md(ctx, &md) == 1 && md == EVP_sha1(),
              "OAEP sets SHA-1");
        check(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) == 1
              && EVP_PKEY_CTX_set_rsa_oaep_md(dctx, EVP_sha256()) == 1, "OAEP with SHA-256");
        label = OPENSSL_memdup("label", 5);
        check(EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label, 5) == 1, "a label");
        label = OPENSSL_memdup("label", 5);
        EVP_PKEY_CTX_set0_rsa_oaep_label(dctx, label, 5);
        label = NULL;
        ret = EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, &label);
        check(ret == 5 && memcmp(label, "label", 5) == 0, "get the label");
    }
    outlen = sizeof(out);
    ret = EVP_PKEY_encrypt(ctx, out, &outlen, in, 40);
    backlen = sizeof(back);
    check(ret == 1 && EVP_PKEY_decrypt(dctx, back, &backlen, out, outlen) == 1
          && backlen == 40 && memcmp(back, in, 40) == 0, "OAEP: encrypted and decrypted");
    EVP_PKEY_CTX_set0_rsa_oaep_label(dctx, NULL, 0);
    backlen = sizeof(back);
    ret = EVP_PKEY_decrypt(dctx, back, &backlen, out, outlen);
    check(ret <= 0, "OAEP: another label");
    printf("  ret %d\n", ret);
    errors();
    {
        EVP_PKEY_CTX *copy = EVP_PKEY_CTX_dup(ctx);
        unsigned char *label = NULL;

        check(copy != NULL && EVP_PKEY_CTX_get0_rsa_oaep_label(copy, &label) == 5
              && memcmp(label, "label", 5) == 0, "a copy keeps the label");
        EVP_PKEY_CTX_free(copy);
    }
    check(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) == -2, "PSS for encrypting");
    errors();
    check(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_X931_PADDING) == 1, "X9.31 for encrypting");
    outlen = sizeof(out);
    ret = EVP_PKEY_encrypt(ctx, out, &outlen, in, 20);
    check(ret <= 0, "encrypt: X9.31");
    printf("  ret %d\n", ret);
    errors();
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(dctx);
}

static void test_ctrl_str(EVP_PKEY *pk)
{
    EVP_PKEY_CTX *ctx = ctx_for(pk, EVP_PKEY_encrypt_init);
    static const char *const pairs[][2] = {
        { "rsa_padding_mode", "oeap" },
        { "rsa_padding_mode", "oaep" },
        { "rsa_oaep_md", "sha256" },
        { "rsa_oaep_md", "nosuchmd" },
        { "rsa_oaep_label", "0102ff" },
        { "rsa_oaep_label", "zz" },
        { "rsa_mgf1_md", "sha384" },
        { "rsa_pss_saltlen", "max" },
        { "rsa_padding_mode", "pss" },
        { "rsa_padding_mode", "nonesuch" },
        { "rsa_padding_mode", "none" },
        { "rsa_keygen_bits", "2048" },
        { "rsa_pss_keygen_md", "sha256" },
        { "nonsense", "1" },
    };
    size_t i;

    for (i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        int ret = EVP_PKEY_CTX_ctrl_str(ctx, pairs[i][0], pairs[i][1]);

        check(1, "ctrl_str");
        printf("  %s=%s: %d\n", pairs[i][0], pairs[i][1] ? pairs[i][1] : "(null)", ret);
        errors();
    }
    {
        int (*ctrl)(EVP_PKEY_CTX *, int, int, void *) = NULL;
        int (*ctrl_str)(EVP_PKEY_CTX *, const char *, const char *) = NULL;

        /* EVP_PKEY_CTX_ctrl_str crashes on a NULL value; the method's function refuses it. */
        EVP_PKEY_meth_get_ctrl(EVP_PKEY_meth_find(EVP_PKEY_RSA), &ctrl, &ctrl_str);
        check(ctrl_str != NULL && ctrl_str(ctx, "rsa_padding_mode", NULL) == 0,
              "the method's ctrl_str: no value");
        errors();
    }
    {
        int pad = 0;
        unsigned char *label = NULL;

        EVP_PKEY_CTX_get_rsa_padding(ctx, &pad);
        printf("  padding %d\n", pad);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        printf("  label length %d\n", EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, &label));
    }
    EVP_PKEY_CTX_free(ctx);

    ctx = ctx_for(pk, EVP_PKEY_sign_init);
    check(EVP_PKEY_CTX_ctrl_str(ctx, "rsa_padding_mode", "pss") == 1, "pss by name");
    {
        static const char *const lens[] = { "digest", "max", "auto", "33", "-4", "-7", "x" };
        size_t j;

        for (j = 0; j < sizeof(lens) / sizeof(lens[0]); j++) {
            int saltlen = 99, ret = EVP_PKEY_CTX_ctrl_str(ctx, "rsa_pss_saltlen", lens[j]);

            EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &saltlen);
            check(1, "rsa_pss_saltlen");
            printf("  %s: %d, saltlen %d\n", lens[j], ret, saltlen);
            errors();
        }
    }
    EVP_PKEY_CTX_free(ctx);
}

static void test_digest_sign(EVP_PKEY *pk)
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned char sig[256];
    size_t siglen = sizeof(sig);
    EVP_PKEY_CTX *pctx = NULL;
    int ret;

    ret = EVP_DigestSignInit(md, &pctx, EVP_sha256(), NULL, pk);
    check(ret == 1, "EVP_DigestSignInit");
    ret = EVP_DigestSign(md, sig, &siglen, (const unsigned char *)"message", 7);
    check(ret == 1, "EVP_DigestSign: PKCS #1 with SHA-256");
    hex("sig", sig, siglen);
    EVP_MD_CTX_reset(md);
    ret = EVP_DigestVerifyInit(md, &pctx, EVP_sha256(), NULL, pk);
    check(ret == 1 && EVP_DigestVerify(md, sig, siglen, (const unsigned char *)"message", 7) == 1,
          "EVP_DigestVerify");
    check(EVP_DigestVerify(md, sig, siglen, (const unsigned char *)"messagf", 7) == 0,
          "EVP_DigestVerify: another message");
    errors();
    EVP_MD_CTX_reset(md);
    ret = EVP_DigestSignInit(md, &pctx, EVP_sha384(), NULL, pk);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    siglen = sizeof(sig);
    ret = EVP_DigestSign(md, sig, &siglen, (const unsigned char *)"message", 7);
    check(ret == 1 && siglen == 128, "EVP_DigestSign: PSS with SHA-384");
    EVP_MD_CTX_reset(md);
    EVP_DigestVerifyInit(md, &pctx, EVP_sha384(), NULL, pk);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    check(EVP_DigestVerify(md, sig, siglen, (const unsigned char *)"message", 7) == 1,
          "EVP_DigestVerify: PSS");
    EVP_MD_CTX_free(md);
}

static int gen_calls;

static int gen_cb(EVP_PKEY_CTX *ctx)
{
    (void)ctx;
    gen_calls++;
    return 1;
}

static void test_keygen(void)
{
    EVP_PKEY_METHOD *m = EVP_PKEY_meth_new(EVP_PKEY_RSA, EVP_PKEY_FLAG_AUTOARGLEN);
    EVP_PKEY_METHOD *pm = EVP_PKEY_meth_new(EVP_PKEY_RSA_PSS, EVP_PKEY_FLAG_AUTOARGLEN);
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pk = NULL;
    BIGNUM *e = BN_new();

    EVP_PKEY_meth_copy(m, EVP_PKEY_meth_find(EVP_PKEY_RSA));
    EVP_PKEY_meth_copy(pm, EVP_PKEY_meth_find(EVP_PKEY_RSA_PSS));
    check(EVP_PKEY_meth_add0(m) == 1 && EVP_PKEY_meth_add0(pm) == 1,
          "an application's copies of the methods");

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    check(ctx != NULL && EVP_PKEY_keygen_init(ctx) == 1, "keygen with the RSA copy");
    {
        int ret = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 256);

        check(ret <= 0, "256 bits: too small");
        printf("  ret %d\n", ret);
        errors();
        ret = EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, 6);
        check(ret <= 0, "six primes: too many");
        printf("  ret %d\n", ret);
        errors();
    }
    BN_set_word(e, 4);
    check(EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) == -2, "an even exponent");
    errors();
    BN_set_word(e, 3);
    check(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024) == 1
          && EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, 3) == 1
          && EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) == 1, "1024 bits, 3 primes, e = 3");
    EVP_PKEY_CTX_set_cb(ctx, gen_cb);
    check(EVP_PKEY_keygen(ctx, &pk) == 1, "generated");
    if (pk != NULL) {
        const RSA *r = EVP_PKEY_get0_RSA(pk);

        printf("  bits %d, id %d, extra primes %d, e %lu, check %d, callback %s\n",
               EVP_PKEY_get_bits(pk), EVP_PKEY_get_id(pk), RSA_get_multi_prime_extra_count(r),
               (unsigned long)BN_get_word(RSA_get0_e(r)), RSA_check_key(r),
               gen_calls > 0 ? "called" : "not called");
    }
    EVP_PKEY_free(pk);
    pk = NULL;
    {
        EVP_PKEY_CTX *copy = EVP_PKEY_CTX_dup(ctx);

        check(copy == NULL, "no copy of a generation context");
        if (copy != NULL && EVP_PKEY_keygen(copy, &pk) == 1)
            printf("  the copy's: bits %d, extra primes %d\n", EVP_PKEY_get_bits(pk),
                   RSA_get_multi_prime_extra_count(EVP_PKEY_get0_RSA(pk)));
        EVP_PKEY_free(pk);
        pk = NULL;
        EVP_PKEY_CTX_free(copy);
    }
    EVP_PKEY_CTX_free(ctx);

    /* RSA-PSS without and with restrictions. */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
    check(ctx != NULL && EVP_PKEY_keygen_init(ctx) == 1, "keygen with the RSA-PSS copy");
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024);
    check(EVP_PKEY_keygen(ctx, &pk) == 1 && EVP_PKEY_get_id(pk) == EVP_PKEY_RSA_PSS,
          "an RSA-PSS key without restrictions");
    EVP_PKEY_free(pk);
    pk = NULL;
    {
        int pad = 0;

        EVP_PKEY_CTX_get_rsa_padding(ctx, &pad);
        printf("  padding %d\n", pad);
    }
    check(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == -2,
          "an RSA-PSS context takes only PSS");
    errors();
    check(EVP_PKEY_CTX_ctrl_str(ctx, "rsa_pss_keygen_md", "sha256") == 1
          && EVP_PKEY_CTX_ctrl_str(ctx, "rsa_pss_keygen_mgf1_md", "sha384") == 1
          && EVP_PKEY_CTX_ctrl_str(ctx, "rsa_pss_keygen_saltlen", "32") == 1,
          "restrictions: SHA-256, MGF1 with SHA-384, salt length at least 32");
    errors();
    check(EVP_PKEY_keygen(ctx, &pk) == 1, "an RSA-PSS key with restrictions");
    if (pk != NULL) {
        EVP_PKEY_CTX *sctx;
        const EVP_MD *md = NULL;
        const RSA_PSS_PARAMS *params = RSA_get0_pss_params(EVP_PKEY_get0_RSA(pk));
        unsigned char tbs[32] = { 1 }, sig[256];
        size_t siglen = sizeof(sig);
        int saltlen = 0, ret;

        {
            BIO *mem = BIO_new(BIO_s_mem());
            char *text, *from;

            EVP_PKEY_print_public(mem, pk, 2, NULL);
            BIO_write(mem, "", 1);
            BIO_get_mem_data(mem, &text);
            from = strstr(text, "  PSS parameter");
            check(from != NULL, "printed with its restrictions");
            printf("%s", from != NULL ? from : text);
            BIO_free(mem);
        }
        check(params != NULL, "RSA_get0_pss_params: the restrictions");
        if (params != NULL) {
            unsigned char *der = NULL;
            int len = i2d_RSA_PSS_PARAMS(params, &der);

            hex("params", der, len > 0 ? (size_t)len : 0);
            printf("  mask hash %s\n", params->maskHash != NULL ? "kept" : "none");
            OPENSSL_free(der);
        }
        sctx = EVP_PKEY_CTX_new(pk, NULL);
        check(sctx != NULL && EVP_PKEY_sign_init(sctx) == 1, "signing with it");
        EVP_PKEY_CTX_get_signature_md(sctx, &md);
        EVP_PKEY_CTX_get_rsa_pss_saltlen(sctx, &saltlen);
        printf("  md %s, saltlen %d\n", md != NULL ? EVP_MD_get0_name(md) : "(none)", saltlen);
        EVP_PKEY_CTX_get_rsa_mgf1_md(sctx, &md);
        printf("  mgf1 %s\n", md != NULL ? EVP_MD_get0_name(md) : "(none)");
        check(EVP_PKEY_CTX_set_signature_md(sctx, EVP_sha384()) == 0, "another digest");
        errors();
        check(EVP_PKEY_CTX_set_signature_md(sctx, EVP_sha256()) == 1, "the same digest");
        check(EVP_PKEY_CTX_set_rsa_mgf1_md(sctx, EVP_sha256()) == 0, "another MGF1 digest");
        errors();
        check(EVP_PKEY_CTX_set_rsa_pss_saltlen(sctx, 16) == 0, "a salt length below 32");
        errors();
        check(EVP_PKEY_CTX_set_rsa_pss_saltlen(sctx, RSA_PSS_SALTLEN_DIGEST) == 1,
              "the digest's length (32)");
        ret = EVP_PKEY_sign(sctx, sig, &siglen, tbs, 32);
        check(ret == 1, "signed");
        EVP_PKEY_CTX_free(sctx);
        sctx = EVP_PKEY_CTX_new(pk, NULL);
        EVP_PKEY_verify_init(sctx);
        check(EVP_PKEY_CTX_set_rsa_pss_saltlen(sctx, RSA_PSS_SALTLEN_AUTO) == -2,
              "verify: auto with restrictions");
        errors();
        check(EVP_PKEY_verify(sctx, sig, siglen, tbs, 32) == 1, "verified");
        EVP_PKEY_CTX_free(sctx);
        sctx = EVP_PKEY_CTX_new(pk, NULL);
        check(EVP_PKEY_encrypt_init(sctx) <= 0, "an RSA-PSS key doesn't encrypt");
        errors();
        EVP_PKEY_CTX_free(sctx);
    }
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);

    check(EVP_PKEY_meth_remove(m) == 1 && EVP_PKEY_meth_remove(pm) == 1, "removed");
    EVP_PKEY_meth_free(m);
    EVP_PKEY_meth_free(pm);
    BN_free(e);
}

int main(void)
{
    RSA_METHOD *meth = RSA_meth_dup(RSA_PKCS1_OpenSSL());
    EVP_PKEY *pk;

    RSA_meth_set1_name(meth, "counting");
    RSA_meth_set_pub_enc(meth, count_pub_enc);
    RSA_meth_set_pub_dec(meth, count_pub_dec);
    RSA_meth_set_priv_enc(meth, count_priv_enc);
    RSA_meth_set_priv_dec(meth, count_priv_dec);
    pk = foreign_key(meth);
    check(pk != NULL, "a key with an application's method");
    check(RSA_get0_pss_params(EVP_PKEY_get0_RSA(pk)) == NULL, "RSA_get0_pss_params: none");

    test_sign(pk);
    show_counts();
    test_crypt(pk);
    show_counts();
    test_ctrl_str(pk);
    test_digest_sign(pk);
    show_counts();
    test_keygen();

    EVP_PKEY_free(pk);
    RSA_meth_free(meth);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
