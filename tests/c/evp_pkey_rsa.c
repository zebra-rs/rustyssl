/*
 * Conformance test for RSA keys in EVP_PKEY (EVP_PKEY_set1_RSA(3), EVP_PKEY_assign(3),
 * EVP_PKEY_get0_RSA, EVP_PKEY_get1_RSA), in TAP format: an RSA given to a key (its type, sizes,
 * default digest, and RSA back, the same object), operations on it through the providers (and
 * again after the RSA changes, which makes them copy it anew), its parameters through the
 * legacy payload table (each number, missing ones, other types' parameters, unknown names),
 * comparisons with provided keys, copies, RSA-PSS, a generated key's RSA (made once and kept),
 * and keys of other types.
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

static const unsigned char msg[32] = { 1, 2, 3 };

/* A PKCS #1 v1.5 SHA-256 signature of `msg` with `k`, printed; its length. */
static size_t sign(EVP_PKEY *k, unsigned char *sig, const char *what)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(k, NULL);
    size_t sl = 512;
    int ok = c != NULL && EVP_PKEY_sign_init(c) == 1
        && EVP_PKEY_CTX_set_signature_md(c, EVP_sha256()) == 1
        && EVP_PKEY_sign(c, sig, &sl, msg, sizeof(msg)) == 1;

    check(ok, what);
    if (ok)
        hex("signature", sig, (int)sl);
    errors();
    EVP_PKEY_CTX_free(c);
    return ok ? sl : 0;
}

static void test_legacy_key(void)
{
    RSA *r = make_key(), *r2;
    EVP_PKEY *k = EVP_PKEY_new(), *p;
    EVP_PKEY_CTX *c;
    unsigned char sig[512], ct[512], pt[512];
    char name[32];
    size_t sl, cl = sizeof(ct), pl = sizeof(pt);
    BIGNUM *bn = NULL;

    printf("# a legacy key\n");
    check(EVP_PKEY_set1_RSA(k, r) == 1, "EVP_PKEY_set1_RSA");
    check(EVP_PKEY_get_id(k) == EVP_PKEY_RSA && EVP_PKEY_get_base_id(k) == EVP_PKEY_RSA,
          "an RSA key");
    check(EVP_PKEY_get_bits(k) == 2048 && EVP_PKEY_get_size(k) == 256
          && EVP_PKEY_get_security_bits(k) == 112, "bits, size, security bits");
    check(EVP_PKEY_get0_RSA(k) == r, "the same RSA back");
    r2 = EVP_PKEY_get1_RSA(k);
    check(r2 == r, "with a reference");
    RSA_free(r2);
    check(EVP_PKEY_get_default_digest_name(k, name, sizeof(name)) > 0, "a default digest");
    printf("  %s\n", name);
    errors();

    sl = sign(k, sig, "signs through the provider");
    c = EVP_PKEY_CTX_new(k, NULL);
    check(EVP_PKEY_verify_init(c) == 1 && EVP_PKEY_CTX_set_signature_md(c, EVP_sha256()) == 1
          && EVP_PKEY_verify(c, sig, sl, msg, sizeof(msg)) == 1, "verifies");
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new(k, NULL);
    check(EVP_PKEY_encrypt_init(c) == 1 && EVP_PKEY_encrypt(c, ct, &cl, msg, 20) == 1,
          "encrypts");
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new(k, NULL);
    check(EVP_PKEY_decrypt_init(c) == 1 && EVP_PKEY_decrypt(c, pt, &pl, ct, cl) == 1 && pl == 20
          && memcmp(pt, msg, 20) == 0, "decrypts");
    EVP_PKEY_CTX_free(c);
    errors();

    printf("# its parameters\n");
    check(EVP_PKEY_get_bn_param(k, "n", &bn) == 1 && BN_cmp(bn, RSA_get0_n(r)) == 0, "n");
    BN_free(bn);
    bn = NULL;
    check(EVP_PKEY_get_bn_param(k, "RSA-FACTOR2", &bn) == 1 && BN_cmp(bn, RSA_get0_q(r)) == 0,
          "the second prime, by any case");
    BN_free(bn);
    bn = NULL;
    check(EVP_PKEY_get_bn_param(k, "rsa-coefficient1", &bn) == 1, "the coefficient");
    BN_free(bn);
    bn = NULL;
    check(EVP_PKEY_get_bn_param(k, "rsa-factor3", &bn) == 0, "no third prime");
    errors();
    check(EVP_PKEY_get_bn_param(k, "bits", &bn) == 0, "not in the table");
    errors();
    check(EVP_PKEY_get_bn_param(k, "p", &bn) == 0, "a DH or DSA parameter");
    errors();
    check(EVP_PKEY_get_bn_param(k, "priv", &bn) == 0, "a private key");
    errors();
    check(EVP_PKEY_get_utf8_string_param(k, "group", name, sizeof(name), NULL) == 0,
          "a group name");
    errors();
    {
        BIGNUM *n = NULL, *e = NULL;
        unsigned char nb[256], eb[8];
        OSSL_PARAM ps[3];

        ps[0] = OSSL_PARAM_construct_BN("n", nb, sizeof(nb));
        ps[1] = OSSL_PARAM_construct_BN("q", eb, sizeof(eb));
        ps[2] = OSSL_PARAM_construct_end();
        printf("  n then q: %d\n", EVP_PKEY_get_params(k, ps));
        ps[0] = OSSL_PARAM_construct_BN("q", eb, sizeof(eb));
        ps[1] = OSSL_PARAM_construct_BN("e", nb, sizeof(nb));
        printf("  q then e: %d, e's size %zu\n", EVP_PKEY_get_params(k, ps), ps[1].return_size);
        errors();
        BN_free(n);
        BN_free(e);
    }

    printf("# the RSA changes\n");
    {
        RSA *other = RSA_new();
        BIGNUM *e = BN_new();
        unsigned char sig2[512], sig3[512];
        size_t s2, s3;

        BN_set_word(e, RSA_F4);
        RSA_generate_key_ex(other, 1024, e, NULL);
        /* The test key's numbers become another key's: the provider copy is made again. */
        RSA_set0_key(r, BN_dup(RSA_get0_n(other)), BN_dup(RSA_get0_e(other)),
                     BN_dup(RSA_get0_d(other)));
        RSA_set0_factors(r, BN_dup(RSA_get0_p(other)), BN_dup(RSA_get0_q(other)));
        RSA_set0_crt_params(r, BN_dup(RSA_get0_dmp1(other)), BN_dup(RSA_get0_dmq1(other)),
                            BN_dup(RSA_get0_iqmp(other)));
        s2 = sign(k, sig2, "signs with the new numbers");
        p = EVP_PKEY_new();
        EVP_PKEY_set1_RSA(p, other);
        s3 = sign(p, sig3, "as the other key does");
        check(s2 == 128 && s2 == s3 && memcmp(sig2, sig3, s2) == 0, "the same signature");
        EVP_PKEY_free(p);
        RSA_free(other);
        BN_free(e);
    }
    RSA_free(r);
    EVP_PKEY_free(k);
}

static void test_provided_key(void)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY *k = NULL, *l, *d;
    const RSA *r;
    RSA *r1;
    BIGNUM *n = NULL;
    unsigned char sig[512], sig2[512];
    unsigned int sl2 = 0;
    size_t sl;

    printf("# a provided key\n");
    EVP_PKEY_keygen_init(c);
    EVP_PKEY_CTX_set_rsa_keygen_bits(c, 1024);
    EVP_PKEY_keygen(c, &k);
    EVP_PKEY_CTX_free(c);
    r = EVP_PKEY_get0_RSA(k);
    check(r != NULL, "its RSA");
    check(EVP_PKEY_get0_RSA(k) == r, "made once");
    EVP_PKEY_get_bn_param(k, "n", &n);
    check(BN_cmp(RSA_get0_n(r), n) == 0 && RSA_get0_d(r) != NULL && RSA_check_key(r) == 1,
          "the key's numbers");
    r1 = EVP_PKEY_get1_RSA(k);
    check(r1 == r, "get1");
    RSA_free(r1);
    sl = sign(k, sig, "the key signs");
    check(RSA_sign(NID_sha256, msg, 32, sig2, &sl2, (RSA *)r) == 1 && sl2 == sl
          && memcmp(sig, sig2, sl) == 0, "and its RSA the same");

    l = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(l, (RSA *)r);
    check(EVP_PKEY_eq(l, k) == 1 && EVP_PKEY_eq(k, l) == 1, "a legacy key with its RSA: equal");
    d = EVP_PKEY_dup(l);
    check(d != NULL && EVP_PKEY_get0_RSA(d) != r && EVP_PKEY_eq(d, l) == 1,
          "a copy: another RSA, equal");
    check(EVP_PKEY_eq(d, k) == 1, "equal to the provided key");
    EVP_PKEY_free(d);
    EVP_PKEY_free(l);
    errors();
    BN_free(n);
    EVP_PKEY_free(k);
}

static void test_pss_and_others(void)
{
    RSA *r = make_key();
    EVP_PKEY *k = EVP_PKEY_new(), *h;
    EVP_PKEY_CTX *c;
    unsigned char sig[512];
    size_t sl = sizeof(sig);
    char name[32];
    int ok;

    printf("# RSA-PSS\n");
    RSA_up_ref(r);
    check(EVP_PKEY_assign(k, EVP_PKEY_RSA_PSS, r) == 1 && EVP_PKEY_get_id(k) == EVP_PKEY_RSA_PSS,
          "an RSA-PSS key");
    check(EVP_PKEY_get0_RSA(k) == r, "its RSA");
    check(EVP_PKEY_get_default_digest_name(k, name, sizeof(name)) > 0, "a default digest");
    printf("  %s\n", name);
    c = EVP_PKEY_CTX_new(k, NULL);
    ok = EVP_PKEY_sign_init(c) == 1 && EVP_PKEY_CTX_set_signature_md(c, EVP_sha256()) == 1
        && EVP_PKEY_sign(c, sig, &sl, msg, sizeof(msg)) == 1;
    check(ok && sl == 256, "signs (PSS)");
    errors();
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(k);

    printf("# other types\n");
    h = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, msg, 16);
    check(EVP_PKEY_get0_RSA(h) == NULL && EVP_PKEY_get1_RSA(h) == NULL, "an HMAC key has no RSA");
    errors();
    k = EVP_PKEY_new();
    check(EVP_PKEY_assign(k, EVP_PKEY_RSA, NULL) == 0 && EVP_PKEY_get_id(k) == EVP_PKEY_RSA,
          "assigning NULL types the key");
    check(EVP_PKEY_get0_RSA(k) == NULL, "with no RSA");
    errors();
    EVP_PKEY_free(k);
    EVP_PKEY_free(h);
    RSA_free(r);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    check(RAND_set0_public(NULL, known_drbg(61)) == 1
          && RAND_set0_private(NULL, known_drbg(62)) == 1, "known generators");
    test_legacy_key();
    test_provided_key();
    test_pss_and_others();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
