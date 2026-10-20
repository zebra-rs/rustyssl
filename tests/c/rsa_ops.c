/*
 * Conformance test for what the RSA operations are built into (RSA_padding_add_PKCS1_type_1(3),
 * RSA_sign(3), RSA_verify(3), RSA_sign_ASN1_OCTET_STRING(3), RSA_padding_add_PKCS1_PSS(3),
 * RSA_X931_derive_ex(3), RSA_generate_key(3), RSA_check_key(3)), in TAP format, with known
 * generators so every random output is the reference's: each padding added and checked, with
 * its errors; PSS with each salt length; signatures over digests (MD5-SHA1's bare one too) and
 * as OCTET STRINGs, short and long; X9.31 keys generated and derived; keys generated (two and
 * three primes, the deprecated call with its old-style callback) and checked; and an
 * application's method seen by RSA_sign, RSA_verify, key generation, and EVP's operations.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The error queue, emptied: each entry's library, reason, and text. */
static void errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf("  errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && *data != '\0')
            printf(" (%s)", data);
    }
    printf("\n");
}

/* A CTR-DRBG under a TEST-RAND parent with known entropy and nonce. */
static EVP_RAND_CTX *known_drbg(unsigned char seed)
{
    EVP_RAND *rand = EVP_RAND_fetch(NULL, "TEST-RAND", NULL);
    EVP_RAND_CTX *parent = EVP_RAND_CTX_new(rand, NULL), *ctx;
    unsigned char entropy[64], nonce[32];
    unsigned int strength = 256;
    OSSL_PARAM params[4];

    EVP_RAND_free(rand);
    memset(entropy, seed, sizeof(entropy));
    memset(nonce, seed ^ 0x5a, sizeof(nonce));
    params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, entropy,
                                                  sizeof(entropy));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE, nonce,
                                                  sizeof(nonce));
    params[3] = OSSL_PARAM_construct_end();
    EVP_RAND_instantiate(parent, 256, 0, NULL, 0, params);
    rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    ctx = EVP_RAND_CTX_new(rand, parent);
    EVP_RAND_free(rand);
    EVP_RAND_CTX_free(parent);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, "AES-256-CTR", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_RAND_instantiate(ctx, 256, 0, NULL, 0, params)) {
        EVP_RAND_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static const char KEY_N[] =
    "c8cc839714098da56caa23640f93dc8997c16372968fc1b0c6df5113c1c94e8b"
    "21e48ad2297e65419011b4e6d8f5e73b1b78b257400321d1ef6b602d4ec8ce8d"
    "141c94905eb4ad306639a49206534b6e7f2607423e97dffd133c88d721399def"
    "bc7e96ccdcbd7f3aae1fe892712bfb4929817d511666440a1facb7a208f5ea16"
    "5910add8a3f2d497202360ccb632024f0d07169c1918f316f794b143aef54ec8"
    "7522a4c02978f9689980bffbf649c307e81819bff88409638d48bd94be152b59"
    "ff649fa0bd629d0ffa1813c3abf4b56bd3c2ea5465dffa14589292a9d8a24ad2"
    "6be7ee0510741b6382d43c83d5bfa40a46613d062be445517dbcaf0cb4e1a769";
static const char KEY_E[] =
    "10001";
static const char KEY_D[] =
    "1455010e0f2d587663a666a6ff1ccdbbf0edd8100646d02a023922908992c4ad"
    "39e5565929726ef6508c3a71158ef0b6ff751d39d07580bb2d2f063210442d06"
    "03ff50dbbd7b35fe2c9bb19a47a1af85a4c24901e02ca8b58b7919b20edf32aa"
    "cfbf51adb4bc4b61b9b7e968caa4d570f70ef18d8063228893e47d439efca793"
    "259bcf2cd108a3d8688cdf078e7ac799969f2339d2c1f522b969684629a933ba"
    "aec2681625eab84f4e56f4447e9d88fb9a199cf71023e0e257b14441b33c84d3"
    "bc67ca8031d2612618103a7a0a40844262f75d8890cd616e51f9035488fd6e09"
    "9de8ff6d65a4ff118254807c9f58d2fbba8ba151dc8c68be349c977a204e04c1";
static const char KEY_P[] =
    "f8f5ad6ba828931bea459b8a3f6dc041d23482409c2571e963f31f748602a256"
    "371b3883ed459ecf970526459edd16e05522f5a45d94751b2ec2daf272c7f881"
    "6a52c00d18080171634da899d7973222f51b937630548696a9f7d8c24a59497c"
    "1efcd455cfb97ee86d2b6d34972b332fda303f04999b4eb6b5cc0bb33e7761dd";
static const char KEY_Q[] =
    "ce7a2e3b49a90b96330a12dc682bdfbdfbae8dd6dc03b6147aefbd575743f0f6"
    "da4d86235061b71afd9cad2d34025e56ac86b0f7743eb35e1acbca2378954244"
    "65b706ed22175e5718c8c70b6703ea8f6b510f945be48e5a36bb3c3c91732b58"
    "9dfc05d72d80903194452bda21348647ec72943f11a846e62faebe8eb536b0fd";
static const char KEY_DMP1[] =
    "76fe15f18ae239cdf1df6b445ca4bc6bb968d788c21933a4f5dcd280033d6712"
    "062cc08a6df204c1fbd0be46307443e6dd4a6456375429d4e038ca256faf1c9b"
    "de91c6b17b76f81995f91c48cbbebc7bf0e3494c08359e4e8cd6a587d7b96d62"
    "21fd7e0fb5c5575f082ee57769798071b2bbb4a32238151b47314bb654790311";
static const char KEY_DMQ1[] =
    "998848b055499a1009cbc7d294b36b1ffdf2020e6e7364053e94de1a000dc934"
    "0587f7e27276f68cdf608d753b63377b03b6f4084d2c027c4b38960a6233ba9e"
    "d9738b76f10ea75be456078bf701f67cc6b3f3fdc186e64336c76b372e80910e"
    "c80b0adcc23d02fb9ae10486a28248075b4ea7e56ddfcf3882e451561471a291";
static const char KEY_IQMP[] =
    "643bf746429f7d83667a0653021347efbfc05e6351f821a9debb60e0eccde500"
    "5ad9e9ec31e558f7e92c29328e74569d7cef7c74cabc2b355ed401a1a0914b4e"
    "3cbb06484e58196051169ed14caa2efa6ea044e054d26144cc1629c55010558a"
    "04e133f44b7c244dac25bf913c57b890ee49f548259cd63404fef6859dcf975a";
static void hex(const char *label, const unsigned char *p, int n)
{
    int i;

    printf("  %s(%d):", label, n);
    for (i = 0; i < n && i < 48; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static BIGNUM *bn(const char *h)
{
    BIGNUM *b = NULL;

    BN_hex2bn(&b, h);
    return b;
}

/* The test key, built number by number. */
static RSA *make_key(void)
{
    RSA *r = RSA_new();

    RSA_set0_key(r, bn(KEY_N), bn(KEY_E), bn(KEY_D));
    RSA_set0_factors(r, bn(KEY_P), bn(KEY_Q));
    RSA_set0_crt_params(r, bn(KEY_DMP1), bn(KEY_DMQ1), bn(KEY_IQMP));
    return r;
}

static void show_bytes(const char *label, const unsigned char *p, int n)
{
    hex(label, p, n);
}

static void test_paddings(void)
{
    unsigned char from[64], to[256], out[256];
    int n;

    printf("# paddings\n");
    memset(from, 0x5c, sizeof(from));
    check(RSA_padding_add_PKCS1_type_1(to, 128, from, 20) == 1, "type 1");
    show_bytes("block", to, 128);
    n = RSA_padding_check_PKCS1_type_1(out, 128, to + 1, 127, 128);
    check(n == 20 && memcmp(out, from, 20) == 0, "type 1 back, no leading zero");
    n = RSA_padding_check_PKCS1_type_1(out, 128, to, 128, 128);
    check(n == 20, "type 1 back, with it");
    check(RSA_padding_add_PKCS1_type_1(to, 128, from, 118) == 0, "too long for type 1");
    errors();
    to[3] = 0x00;
    n = RSA_padding_check_PKCS1_type_1(out, 128, to + 1, 127, 128);
    printf("  a short padding: %d\n", n);
    errors();

    check(RSA_padding_add_PKCS1_type_2(to, 128, from, 20) == 1, "type 2");
    show_bytes("block", to, 128);
    n = RSA_padding_check_PKCS1_type_2(out, 128, to + 1, 127, 128);
    check(n == 20 && memcmp(out, from, 20) == 0, "type 2 back");
    to[1] = 3;
    n = RSA_padding_check_PKCS1_type_2(out, 128, to + 1, 127, 128);
    check(n == -1, "a bad type 2 block");
    errors();

    check(RSA_padding_add_PKCS1_OAEP(to, 128, from, 20, (const unsigned char *)"label", 5) == 1,
          "OAEP, SHA-1");
    show_bytes("block", to, 128);
    n = RSA_padding_check_PKCS1_OAEP(out, 128, to + 1, 127, 128, (const unsigned char *)"label", 5);
    check(n == 20 && memcmp(out, from, 20) == 0, "OAEP back");
    n = RSA_padding_check_PKCS1_OAEP(out, 128, to + 1, 127, 128, (const unsigned char *)"other", 5);
    check(n == -1, "another label");
    errors();
    check(RSA_padding_add_PKCS1_OAEP_mgf1(to, 128, from, 20, NULL, 0, EVP_sha256(), EVP_sha1()) == 1,
          "OAEP, SHA-256 and MGF1 with SHA-1");
    n = RSA_padding_check_PKCS1_OAEP_mgf1(out, 128, to + 1, 127, 128, NULL, 0, EVP_sha256(),
                                          EVP_sha1());
    check(n == 20, "back");
    n = RSA_padding_check_PKCS1_OAEP_mgf1(out, 128, to + 1, 127, 128, NULL, 0, EVP_sha256(), NULL);
    check(n == -1, "MGF1 with SHA-256 instead");
    errors();
    check(RSA_padding_add_PKCS1_OAEP(to, 128, from, 100, NULL, 0) == 0, "too long for OAEP");
    errors();

    check(RSA_padding_add_none(to, 64, from, 64) == 1 && memcmp(to, from, 64) == 0, "none");
    check(RSA_padding_add_none(to, 64, from, 63) == 0, "too short for none");
    errors();
    check(RSA_padding_add_none(to, 63, from, 64) == 0, "too long for none");
    errors();
    n = RSA_padding_check_none(out, 64, from, 60, 64);
    check(n == 64 && out[0] == 0 && out[4] == 0x5c, "none back, right-aligned");
    check(RSA_padding_check_none(out, 60, from, 64, 64) == -1, "too long back");
    errors();

    check(RSA_padding_add_X931(to, 64, from, 20) == 1, "X9.31");
    show_bytes("block", to, 64);
    n = RSA_padding_check_X931(out, 64, to, 64, 64);
    check(n == 20 && memcmp(out, from, 20) == 0, "X9.31 back");
    to[0] = 0x6c;
    check(RSA_padding_check_X931(out, 64, to, 64, 64) == -1, "a bad header");
    errors();
    printf("  hash ids: sha1 %d sha256 %d sha512 %d md5 %d\n", RSA_X931_hash_id(NID_sha1),
           RSA_X931_hash_id(NID_sha256), RSA_X931_hash_id(NID_sha512), RSA_X931_hash_id(NID_md5));
}

static void test_pss(RSA *r)
{
    unsigned char mhash[32], em[256];
    int slens[] = { -1, -2, -3, 0, 20, 222 }, i;

    printf("# PSS\n");
    memset(mhash, 0x33, sizeof(mhash));
    for (i = 0; i < 6; i++) {
        int ok = RSA_padding_add_PKCS1_PSS(r, em, mhash, EVP_sha256(), slens[i]);

        printf("  salt length %d: add %d", slens[i], ok);
        if (ok)
            printf(" verify %d auto %d", RSA_verify_PKCS1_PSS(r, mhash, EVP_sha256(), em, slens[i]),
                   RSA_verify_PKCS1_PSS(r, mhash, EVP_sha256(), em, -2));
        printf("\n");
        errors();
    }
    check(RSA_padding_add_PKCS1_PSS_mgf1(r, em, mhash, EVP_sha256(), EVP_sha1(), 20) == 1, "MGF1 SHA-1");
    show_bytes("encoded", em, 256);
    check(RSA_verify_PKCS1_PSS_mgf1(r, mhash, EVP_sha256(), EVP_sha1(), em, 20) == 1, "verifies");
    check(RSA_verify_PKCS1_PSS_mgf1(r, mhash, EVP_sha256(), NULL, em, 20) == 0, "not with SHA-256");
    errors();
    em[255] = 0xbd;
    check(RSA_verify_PKCS1_PSS(r, mhash, EVP_sha256(), em, 20) == 0, "a bad trailer");
    errors();
}

static void test_sign(RSA *r)
{
    unsigned char m[240], sig[256];
    unsigned int sl = 0;

    printf("# sign and verify\n");
    memset(m, 0x21, sizeof(m));
    check(RSA_sign(NID_sha256, m, 32, sig, &sl, r) == 1 && sl == 256, "SHA-256");
    show_bytes("signature", sig, (int)sl);
    check(RSA_verify(NID_sha256, m, 32, sig, sl, r) == 1, "verifies");
    check(RSA_verify(NID_sha256, m, 31, sig, sl, r) == 0, "not another digest");
    errors();
    check(RSA_verify(NID_sha1, m, 20, sig, sl, r) == 0, "not as SHA-1");
    errors();
    check(RSA_verify(NID_sha256, m, 32, sig, 255, r) == 0, "a short signature");
    errors();
    check(RSA_sign(NID_md5_sha1, m, 36, sig, &sl, r) == 1, "MD5-SHA1");
    check(RSA_verify(NID_md5_sha1, m, 36, sig, sl, r) == 1, "verifies");
    check(RSA_sign(NID_md5_sha1, m, 35, sig, &sl, r) == 0, "MD5-SHA1 of 35 octets");
    errors();
    check(RSA_sign(NID_undef, m, 32, sig, &sl, r) == 0, "no digest");
    errors();
    check(RSA_sign(NID_sha512, m, 240, sig, &sl, r) == 0, "too big a digest");
    errors();
    check(RSA_sign_ASN1_OCTET_STRING(0, m, 16, sig, &sl, r) == 1, "an OCTET STRING");
    show_bytes("signature", sig, (int)sl);
    check(RSA_verify_ASN1_OCTET_STRING(0, m, 16, sig, sl, r) == 1, "verifies");
    check(RSA_verify_ASN1_OCTET_STRING(0, m, 15, sig, sl, r) == 0, "not 15 octets");
    errors();
    check(RSA_sign_ASN1_OCTET_STRING(0, m, 200, sig, &sl, r) == 1, "a long OCTET STRING");
    check(RSA_verify_ASN1_OCTET_STRING(0, m, 200, sig, sl, r) == 1, "verifies");
    check(RSA_sign_ASN1_OCTET_STRING(0, m, 250, sig, &sl, r) == 0, "too long");
    errors();
    check(RSA_sign(NID_sha256, m, 32, sig, &sl, r) == 1, "signed again");
    check(RSA_verify_ASN1_OCTET_STRING(0, m, 32, sig, sl, r) == 0, "not an OCTET STRING");
    errors();
}

static long events[4];

static void old_cb(int a, int b, void *arg)
{
    (void)b, (void)arg;
    if (a >= 0 && a < 4)
        events[a]++;
}

static void show_key(const RSA *r)
{
    char *h = BN_bn2hex(RSA_get0_n(r));

    printf("  n=%.32s.. (%d bits)\n", h, RSA_bits(r));
    OPENSSL_free(h);
}

static void test_generation(void)
{
    RSA *r = RSA_new();
    BIGNUM *e = BN_new();
    BN_GENCB *cb = BN_GENCB_new();

    printf("# generation\n");
    BN_set_word(e, RSA_F4);
    check(RSA_generate_key_ex(r, 1024, e, NULL) == 1, "1024 bits");
    show_key(r);
    check(RSA_check_key(r) == 1, "checks");
    RSA_free(r);
    r = RSA_new();
    check(RSA_generate_multi_prime_key(r, 1024, 3, e, NULL) == 1
          && RSA_get_multi_prime_extra_count(r) == 1, "three primes");
    show_key(r);
    check(RSA_check_key_ex(r, NULL) == 1, "checks");
    RSA_free(r);
    r = RSA_new();
    check(RSA_generate_key_ex(r, 1024, NULL, NULL) == 0, "no exponent");
    errors();
    check(RSA_generate_key_ex(r, 2048, NULL, NULL) == 1, "no exponent at 2048 bits: 65537");
    printf("  e %lu\n", BN_get_word(RSA_get0_e(r)));
    RSA_free(r);
    memset(events, 0, sizeof(events));
    r = RSA_generate_key(512, 3, old_cb, NULL);
    check(r != NULL && RSA_bits(r) == 512, "the deprecated call");
    printf("  events %ld %ld %ld %ld\n", events[0], events[1], events[2], events[3]);
    RSA_free(r);
    r = RSA_generate_key(512, 4, NULL, NULL);
    check(r == NULL, "an even exponent");
    errors();

    printf("# X9.31\n");
    r = RSA_new();
    check(RSA_X931_generate_key_ex(r, 1024, e, NULL) == 1, "a 1024-bit X9.31 key");
    {
        RSA *x = RSA_new();

        check(RSA_X931_generate_key_ex(x, 1024, e, cb) == 0, "an unset callback stops it");
        errors();
        RSA_free(x);
    }
    show_key(r);
    check(RSA_check_key(r) == 1, "checks");
    {
        RSA *d = RSA_new();
        const BIGNUM *p, *q;

        RSA_get0_factors(r, &p, &q);
        check(RSA_X931_derive_ex(d, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, e,
                                 NULL) == 2, "nothing to derive from");
        RSA_set0_factors(d, BN_dup(p), BN_dup(q));
        check(RSA_X931_derive_ex(d, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, e,
                                 NULL) == 1, "derived from p and q");
        check(BN_cmp(RSA_get0_n(d), RSA_get0_n(r)) == 0 && BN_cmp(RSA_get0_d(d), RSA_get0_d(r)) == 0,
              "the same key");
        RSA_free(d);
    }
    RSA_free(r);
    errors();

    printf("# checks\n");
    r = make_key();
    check(RSA_check_key(r) == 1, "the test key");
    RSA_set0_key(r, NULL, NULL, bn("5"));
    check(RSA_check_key(r) == 0, "a wrong d");
    errors();
    RSA_free(r);
    BN_GENCB_free(cb);
    BN_free(e);
}

static int priv_enc_calls, sign_calls, verify_calls, keygen_calls;

static int counting_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
                             int padding)
{
    priv_enc_calls++;
    return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
}

static int counting_sign(int type, const unsigned char *m, unsigned int m_length,
                         unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    (void)type, (void)m, (void)m_length, (void)rsa;
    sign_calls++;
    memset(sigret, 0x77, 4);
    *siglen = 4;
    return 1;
}

static int counting_verify(int type, const unsigned char *m, unsigned int m_length,
                           const unsigned char *sig, unsigned int siglen, const RSA *rsa)
{
    (void)type, (void)m, (void)m_length, (void)sig, (void)siglen, (void)rsa;
    verify_calls++;
    return 7;
}

static int counting_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    (void)rsa, (void)bits, (void)e, (void)cb;
    keygen_calls++;
    return 1;
}

static void test_methods(void)
{
    RSA_METHOD *m = RSA_meth_dup(RSA_PKCS1_OpenSSL()), *s = RSA_meth_dup(RSA_PKCS1_OpenSSL());
    unsigned char md[32], sig[256];
    unsigned int sl = 0;
    size_t slen = sizeof(sig);
    RSA *r;
    EVP_PKEY_CTX *c;
    EVP_PKEY *k = NULL;

    printf("# methods\n");
    memset(md, 0x44, sizeof(md));
    RSA_meth_set_priv_enc(m, counting_priv_enc);
    r = make_key();
    RSA_set_method(r, m);
    check(RSA_sign(NID_sha256, md, 32, sig, &sl, r) == 1 && priv_enc_calls == 1,
          "RSA_sign through the method's private encryption");
    RSA_free(r);

    RSA_meth_set_sign(s, counting_sign);
    RSA_meth_set_verify(s, counting_verify);
    RSA_meth_set_keygen(s, counting_keygen);
    r = make_key();
    RSA_set_method(r, s);
    check(RSA_sign(NID_sha256, md, 32, sig, &sl, r) == 1 && sl == 4 && sign_calls == 1,
          "the method's rsa_sign");
    check(RSA_verify(NID_sha256, md, 32, sig, sl, r) == 7 && verify_calls == 1,
          "the method's rsa_verify, its result as it is");
    check(RSA_generate_key_ex(r, 512, NULL, NULL) == 1 && keygen_calls == 1, "its keygen");
    check(RSA_generate_multi_prime_key(r, 1024, 3, NULL, NULL) == 0 && keygen_calls == 1,
          "no multi-prime keygen: none for three primes");
    RSA_free(r);

    /* Keys the provider makes get the default method, which EVP's operations go through. */
    RSA_set_default_method(m);
    c = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY_keygen_init(c);
    EVP_PKEY_CTX_set_rsa_keygen_bits(c, 1024);
    EVP_PKEY_keygen(c, &k);
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new(k, NULL);
    priv_enc_calls = 0;
    check(EVP_PKEY_sign_init(c) == 1 && EVP_PKEY_CTX_set_signature_md(c, EVP_sha256()) == 1
          && EVP_PKEY_sign(c, sig, &slen, md, 32) == 1 && priv_enc_calls == 1,
          "EVP's signature through the method");
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(k);
    RSA_set_default_method(RSA_PKCS1_OpenSSL());
    RSA_meth_free(m);
    RSA_meth_free(s);
    errors();
}

/* A public key with an even modulus: no Montgomery form, so the public operations fail. */
static void test_even_modulus(void)
{
    RSA *r = RSA_new();
    BIGNUM *n = bn(KEY_N);
    unsigned char from[256], to[256];
    int size;

    printf("# an even modulus\n");
    BN_clear_bit(n, 0);
    check(RSA_set0_key(r, n, bn(KEY_E), NULL) == 1, "the key");
    size = RSA_size(r);
    memset(from, 0x5c, sizeof(from));
    check(RSA_public_encrypt(20, from, to, r, RSA_PKCS1_PADDING) == -1, "no encryption");
    errors();
    memset(from, 0, sizeof(from));
    from[size - 1] = 1;
    check(RSA_public_decrypt(size, from, to, r, RSA_NO_PADDING) == -1, "no verification");
    errors();
    RSA_free(r);
}

int main(void)
{
    RSA *r;

    setvbuf(stdout, NULL, _IONBF, 0);
    check(RAND_set0_public(NULL, known_drbg(51)) == 1
          && RAND_set0_private(NULL, known_drbg(52)) == 1, "known generators");
    test_paddings();
    test_even_modulus();
    r = make_key();
    test_pss(r);
    test_sign(r);
    RSA_free(r);
    test_generation();
    test_methods();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
