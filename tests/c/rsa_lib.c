/*
 * Conformance test for the RSA object (RSA_new(3), RSA_get0_key(3), RSA_set_method(3),
 * RSA_meth_new(3), RSA_blinding_on(3), RSA_public_encrypt(3)), in TAP format: keys made from
 * their numbers, the numbers given back (the same BIGNUMs, with their flags), the size, bits,
 * security bits, version, and flags; multi-prime keys; the four operations with each padding
 * (from known generators, so every output is the reference's); blinding off and on;
 * application data and its free callback; references; and methods: copies, names, flags,
 * application data, every function's getter and setter, an application's method that counts
 * its calls and hands them to OpenSSL's, its init and finish, and the default method.
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

static void test_numbers(void)
{
    RSA *r = RSA_new();
    BIGNUM *n = bn(KEY_N), *e = bn(KEY_E), *d = bn(KEY_D), *p = bn(KEY_P), *q = bn(KEY_Q);
    BIGNUM *dp = bn(KEY_DMP1), *dq = bn(KEY_DMQ1), *qi = bn(KEY_IQMP), *e2;
    const BIGNUM *gn = NULL, *ge = NULL, *gd = NULL, *gp = NULL, *gq = NULL;
    const BIGNUM *gdp = NULL, *gdq = NULL, *gqi = NULL;

    printf("# numbers\n");
    /* (RSA_size and RSA_bits of a key without a modulus crash OpenSSL's.) */
    check(r != NULL && RSA_get0_n(r) == NULL && RSA_get0_d(r) == NULL, "an empty key");
    printf("  flags %x, the method's %x, version %d\n", RSA_test_flags(r, ~0), RSA_flags(r),
           RSA_get_version(r));
    check(RSA_set0_key(r, NULL, NULL, NULL) == 0, "no n or e");
    check(RSA_set0_key(r, n, NULL, NULL) == 0, "no e");
    check(RSA_set0_factors(r, p, NULL) == 0, "no q");
    check(RSA_set0_crt_params(r, dp, dq, NULL) == 0, "no coefficient");
    check(RSA_set0_key(r, n, e, d) == 1, "set n, e, d");
    check(RSA_set0_factors(r, p, q) == 1, "set p, q");
    check(RSA_set0_crt_params(r, dp, dq, qi) == 1, "set the CRT numbers");
    RSA_get0_key(r, &gn, &ge, &gd);
    RSA_get0_factors(r, &gp, &gq);
    RSA_get0_crt_params(r, &gdp, &gdq, &gqi);
    check(gn == n && ge == e && gd == d && gp == p && gq == q && gdp == dp && gdq == dq
          && gqi == qi, "the same numbers back");
    check(RSA_get0_n(r) == n && RSA_get0_e(r) == e && RSA_get0_d(r) == d
          && RSA_get0_p(r) == p && RSA_get0_q(r) == q && RSA_get0_dmp1(r) == dp
          && RSA_get0_dmq1(r) == dq && RSA_get0_iqmp(r) == qi, "one by one");
    printf("  constant time: n %d e %d d %d p %d dmp1 %d iqmp %d\n",
           BN_get_flags(n, BN_FLG_CONSTTIME) != 0, BN_get_flags(e, BN_FLG_CONSTTIME) != 0,
           BN_get_flags(d, BN_FLG_CONSTTIME) != 0, BN_get_flags(p, BN_FLG_CONSTTIME) != 0,
           BN_get_flags(dp, BN_FLG_CONSTTIME) != 0, BN_get_flags(qi, BN_FLG_CONSTTIME) != 0);
    check(RSA_size(r) == 256 && RSA_bits(r) == 2048 && RSA_security_bits(r) == 112,
          "size, bits, security bits");
    check(RSA_get_multi_prime_extra_count(r) == 0 && RSA_get_version(r) == 0, "two primes");
    e2 = BN_new();
    BN_set_word(e2, 3);
    check(RSA_set0_key(r, NULL, e2, NULL) == 1 && RSA_get0_e(r) == e2, "a new e alone");
    check(RSA_get0_engine(r) == NULL && RSA_get0_pss_params(r) == NULL, "no engine, no PSS");
    errors();
    RSA_free(r);
}

static void test_operations(void)
{
    RSA *r = make_key();
    unsigned char msg[32], ct[256], pt[256];
    int pads[] = { RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_NO_PADDING };
    int i, n, m;

    printf("# operations\n");
    memset(msg, 0x42, sizeof(msg));
    for (i = 0; i < 3; i++) {
        unsigned char in[256];
        int inlen = pads[i] == RSA_NO_PADDING ? 256 : 32;

        memset(in, 0, sizeof(in));
        memcpy(in + (inlen == 256 ? 1 : 0), msg, sizeof(msg));
        n = RSA_public_encrypt(inlen, in, ct, r, pads[i]);
        printf("  padding %d\n", pads[i]);
        hex("encrypted", ct, n);
        m = RSA_private_decrypt(n, ct, pt, r, pads[i]);
        check(n == 256 && m == inlen && memcmp(pt, in, inlen) == 0, "a round trip");
        errors();
    }
    n = RSA_private_encrypt(32, msg, ct, r, RSA_PKCS1_PADDING);
    hex("signed", ct, n);
    m = RSA_public_decrypt(n, ct, pt, r, RSA_PKCS1_PADDING);
    check(n == 256 && m == 32 && memcmp(pt, msg, 32) == 0, "sign and recover");
    errors();
    n = RSA_private_encrypt(32, msg, ct, r, RSA_PKCS1_OAEP_PADDING);
    check(n == -1, "no OAEP for signing");
    errors();
    n = RSA_public_encrypt(250, msg, ct, r, RSA_PKCS1_PADDING);
    check(n == -1, "too long");
    errors();
    n = RSA_public_encrypt(32, msg, ct, r, 99);
    check(n == -1, "an unknown padding");
    errors();
    m = RSA_private_decrypt(256, msg, pt, r, RSA_PKCS1_OAEP_PADDING);
    check(m == -1, "a bad OAEP block");
    errors();

    printf("# blinding\n");
    printf("  flags %x\n", RSA_test_flags(r, ~0));
    RSA_blinding_off(r);
    printf("  off: flags %x\n", RSA_test_flags(r, ~0));
    n = RSA_private_encrypt(32, msg, ct, r, RSA_PKCS1_PADDING);
    check(n == 256, "signs without blinding");
    check(RSA_blinding_on(r, NULL) == 1, "blinding on");
    printf("  on: flags %x\n", RSA_test_flags(r, ~0));
    n = RSA_private_encrypt(32, msg, ct, r, RSA_PKCS1_PADDING);
    hex("signed", ct, n);
    {
        BN_BLINDING *b = RSA_setup_blinding(r, NULL);

        check(b != NULL, "RSA_setup_blinding");
        BN_BLINDING_free(b);
    }
    RSA_set_flags(r, RSA_FLAG_NO_BLINDING);
    check(RSA_test_flags(r, RSA_FLAG_NO_BLINDING) == RSA_FLAG_NO_BLINDING, "set a flag");
    RSA_clear_flags(r, RSA_FLAG_NO_BLINDING | RSA_FLAG_CACHE_PUBLIC);
    printf("  flags %x\n", RSA_test_flags(r, ~0));
    errors();
    RSA_free(r);
}

/* A 1024-bit three-prime key from the generator, as a legacy key. */
static void test_multi_prime(void)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY *k = NULL;
    const char *names[] = {
        "n", "e", "d", "rsa-factor1", "rsa-factor2", "rsa-factor3", "rsa-exponent1",
        "rsa-exponent2", "rsa-exponent3", "rsa-coefficient1", "rsa-coefficient2"
    };
    BIGNUM *v[11] = { NULL };
    BIGNUM *primes[1], *exps[1], *coeffs[1];
    const BIGNUM *gp[2] = { NULL, NULL }, *ge[2] = { NULL, NULL }, *gc[2] = { NULL, NULL };
    unsigned char msg[20], ct[128], pt[128];
    RSA *r = RSA_new();
    int i, n, m;

    printf("# multi-prime\n");
    EVP_PKEY_keygen_init(c);
    EVP_PKEY_CTX_set_rsa_keygen_bits(c, 1024);
    EVP_PKEY_CTX_set_rsa_keygen_primes(c, 3);
    EVP_PKEY_keygen(c, &k);
    for (i = 0; i < 11; i++)
        EVP_PKEY_get_bn_param(k, names[i], &v[i]);
    primes[0] = v[5];
    exps[0] = v[8];
    coeffs[0] = v[10];
    /* (Without p and q, RSA_set0_multi_prime_params crashes OpenSSL's.) */
    RSA_set0_key(r, v[0], v[1], v[2]);
    RSA_set0_factors(r, v[3], v[4]);
    RSA_set0_crt_params(r, v[6], v[7], v[9]);
    check(RSA_set0_multi_prime_params(r, primes, exps, coeffs, 0) == 0, "no primes");
    check(RSA_set0_multi_prime_params(r, primes, exps, coeffs, 1) == 1, "one extra prime");
    check(RSA_get_multi_prime_extra_count(r) == 1 && RSA_get_version(r) == 1,
          "a multi-prime key");
    check(RSA_get0_multi_prime_factors(r, gp) == 1 && gp[0] == primes[0], "its prime");
    check(RSA_get0_multi_prime_crt_params(r, ge, gc) == 1 && ge[0] == exps[0]
          && gc[0] == coeffs[0], "its exponent and coefficient");
    check(RSA_get0_multi_prime_crt_params(r, NULL, NULL) == 1, "no arrays");
    printf("  security bits %d\n", RSA_security_bits(r));
    memset(msg, 0x17, sizeof(msg));
    n = RSA_public_encrypt(20, msg, ct, r, RSA_PKCS1_PADDING);
    m = RSA_private_decrypt(n, ct, pt, r, RSA_PKCS1_PADDING);
    check(n == 128 && m == 20 && memcmp(pt, msg, 20) == 0, "a round trip");
    n = RSA_private_encrypt(20, msg, ct, r, RSA_PKCS1_PADDING);
    hex("signed", ct, n);
    errors();
    RSA_free(r);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
}

static int freed = 0;

static void free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    (void)parent, (void)ad, (void)idx, (void)argl, (void)argp;
    if (ptr != NULL)
        freed++;
}

static void test_references_and_data(void)
{
    RSA *r = RSA_new();
    int idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, free_cb);
    static int marker;

    printf("# references and data\n");
    check(idx > 0, "an index");
    check(RSA_set_ex_data(r, idx, &marker) == 1 && RSA_get_ex_data(r, idx) == &marker,
          "set and get");
    check(RSA_up_ref(r) == 1, "up_ref");
    RSA_free(r);
    check(freed == 0 && RSA_get_ex_data(r, idx) == &marker, "still alive");
    RSA_free(r);
    check(freed == 1, "the data freed with the key");
    RSA_free(NULL);
    check(1, "RSA_free(NULL) does nothing");
}

static int priv_enc_calls = 0, inits = 0, finishes = 0;

static int counting_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
                             int padding)
{
    priv_enc_calls++;
    return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
}

static int counting_init(RSA *rsa)
{
    (void)rsa;
    inits++;
    return 1;
}

static int counting_finish(RSA *rsa)
{
    (void)rsa;
    finishes++;
    return 1;
}

static void test_methods(void)
{
    const RSA_METHOD *ossl = RSA_PKCS1_OpenSSL();
    RSA_METHOD *m = RSA_meth_dup(ossl), *n2;
    RSA *r;
    unsigned char msg[32], sig[256], sig2[256];
    int len;

    printf("# methods\n");
    check(ossl != NULL && RSA_get_default_method() == ossl, "the default is OpenSSL's");
    check(RSA_null_method() == NULL, "no null method");
    printf("  name %s flags %x\n", RSA_meth_get0_name(ossl), RSA_meth_get_flags(ossl));
    check(RSA_meth_get_pub_enc(ossl) != NULL && RSA_meth_get_pub_dec(ossl) != NULL
          && RSA_meth_get_priv_enc(ossl) != NULL && RSA_meth_get_priv_dec(ossl) != NULL
          && RSA_meth_get_mod_exp(ossl) != NULL && RSA_meth_get_bn_mod_exp(ossl) != NULL
          && RSA_meth_get_init(ossl) != NULL && RSA_meth_get_finish(ossl) != NULL,
          "OpenSSL's functions");
    check(RSA_meth_get_sign(ossl) == NULL && RSA_meth_get_verify(ossl) == NULL
          && RSA_meth_get_keygen(ossl) == NULL && RSA_meth_get_multi_prime_keygen(ossl) == NULL,
          "and the ones it hasn't");
    check(RSA_meth_get_bn_mod_exp(ossl) == BN_mod_exp_mont, "BN_mod_exp_mont");
    check(m != NULL && strcmp(RSA_meth_get0_name(m), RSA_meth_get0_name(ossl)) == 0
          && RSA_meth_get_priv_enc(m) == RSA_meth_get_priv_enc(ossl), "a copy");
    check(RSA_meth_set1_name(m, "counting") == 1 && strcmp(RSA_meth_get0_name(m), "counting") == 0,
          "renamed");
    check(RSA_meth_set_flags(m, 7) == 1 && RSA_meth_get_flags(m) == 7, "flags");
    check(RSA_meth_set0_app_data(m, &priv_enc_calls) == 1
          && RSA_meth_get0_app_data(m) == &priv_enc_calls, "application data");
    check(RSA_meth_set_priv_enc(m, counting_priv_enc) == 1
          && RSA_meth_get_priv_enc(m) == counting_priv_enc, "a private encryption");
    check(RSA_meth_set_init(m, counting_init) == 1 && RSA_meth_set_finish(m, counting_finish) == 1,
          "init and finish");
    check(RSA_meth_set_pub_enc(m, NULL) == 1 && RSA_meth_get_pub_enc(m) == NULL, "none");
    check(RSA_meth_set_pub_enc(m, RSA_meth_get_pub_enc(ossl)) == 1, "back");
    check(RSA_meth_set_pub_dec(m, RSA_meth_get_pub_dec(ossl)) == 1
          && RSA_meth_set_priv_dec(m, RSA_meth_get_priv_dec(ossl)) == 1
          && RSA_meth_set_mod_exp(m, RSA_meth_get_mod_exp(ossl)) == 1
          && RSA_meth_set_bn_mod_exp(m, RSA_meth_get_bn_mod_exp(ossl)) == 1
          && RSA_meth_set_sign(m, NULL) == 1 && RSA_meth_set_verify(m, NULL) == 1
          && RSA_meth_set_keygen(m, NULL) == 1 && RSA_meth_set_multi_prime_keygen(m, NULL) == 1,
          "the other setters");

    /*
     * The method goes on a fresh key: OpenSSL's built-in finish frees a used key's cached
     * Montgomery contexts without forgetting them, so a used key's next operation through the
     * built-in functions reads freed memory.
     */
    memset(msg, 0x61, sizeof(msg));
    r = make_key();
    len = RSA_private_encrypt(32, msg, sig, r, RSA_PKCS1_PADDING);
    RSA_free(r);
    r = make_key();
    check(RSA_set_method(r, m) == 1 && RSA_get_method(r) == m && inits == 1, "set the method");
    check(RSA_private_encrypt(32, msg, sig2, r, RSA_PKCS1_PADDING) == len && priv_enc_calls == 1
          && memcmp(sig, sig2, len) == 0, "the method signs, the same");
    errors();
    RSA_free(r);
    check(finishes == 1, "finish at the last free");

    RSA_set_default_method(m);
    r = RSA_new();
    check(RSA_get_method(r) == m && inits == 2, "the default method");
    printf("  flags %x\n", RSA_test_flags(r, ~0));
    RSA_free(r);
    RSA_set_default_method(ossl);
    check(RSA_get_default_method() == ossl, "back to OpenSSL's");
    r = RSA_new_method(NULL);
    check(r != NULL && RSA_get_method(r) == ossl, "RSA_new_method");
    RSA_free(r);
    n2 = RSA_meth_new("empty", 0);
    check(n2 != NULL && RSA_meth_get_priv_enc(n2) == NULL && RSA_meth_get_flags(n2) == 0,
          "a new method");
    RSA_meth_free(n2);
    RSA_meth_free(m);
    RSA_meth_free(NULL);
    errors();
}

static void test_pkey_ctx_ctrl(void)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY *k = NULL;

    printf("# RSA_pkey_ctx_ctrl\n");
    EVP_PKEY_keygen_init(c);
    check(RSA_pkey_ctx_ctrl(c, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, 512, NULL) == 1,
          "the key size");
    errors();
    check(EVP_PKEY_keygen(c, &k) == 1 && EVP_PKEY_get_bits(k) == 512, "a 512-bit key");
    printf("  a sign-only control on a key generation: %d\n",
           RSA_pkey_ctx_ctrl(c, EVP_PKEY_OP_SIGN, EVP_PKEY_CTRL_RSA_PADDING, RSA_PKCS1_PSS_PADDING,
                             NULL));
    errors();
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    check(RAND_set0_public(NULL, known_drbg(41)) == 1
          && RAND_set0_private(NULL, known_drbg(42)) == 1, "known generators");
    test_numbers();
    test_operations();
    test_multi_prime();
    test_references_and_data();
    test_methods();
    test_pkey_ctx_ctrl();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
