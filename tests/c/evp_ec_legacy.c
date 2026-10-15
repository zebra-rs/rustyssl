/*
 * Conformance test for the legacy EC key method (EVP_PKEY_meth_find(3) for EVP_PKEY_EC;
 * OpenSSL's ec_pmeth.c), in TAP format. An EC_KEY with an application's EC_KEY_METHOD stays a
 * legacy ("foreign") key, so its EVP operations go through the key type's built-in
 * EVP_PKEY_METHOD instead of a provider: signing and verifying (with and without a digest,
 * EVP_DigestSign), deriving (plain, cut short, with each cofactor mode, through X9.63's KDF),
 * and the ctrls and ctrl strings with their errors; the application's method counts the calls
 * it sees. Then parameter and key generation through an application's copy of the built-in
 * method, and EVP_PKEY_can_sign of legacy keys.
 *
 * Signatures have random nonces, so only their verification is printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
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

static void hex(const char *label, const unsigned char *p, size_t len)
{
    size_t i;

    printf("  %s (%zu):", label, len);
    for (i = 0; i < len; i++)
        printf("%s%02x", i % 40 == 0 && i > 0 ? "\n    " : "", p[i]);
    printf("\n");
}

/* The application's method: OpenSSL's, counting signatures, verifications, and secrets. */
static int counts[3];
static int (*orig_sign)(int, const unsigned char *, int, unsigned char *, unsigned int *,
                        const BIGNUM *, const BIGNUM *, EC_KEY *);
static int (*orig_verify)(int, const unsigned char *, int, const unsigned char *, int,
                          EC_KEY *);
static int (*orig_compute)(unsigned char **, size_t *, const EC_POINT *, const EC_KEY *);

static int count_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig,
                      unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    counts[0]++;
    printf("  method sign: type %d, %d octets\n", type, dlen);
    return orig_sign(type, dgst, dlen, sig, siglen, kinv, r, eckey);
}

static int count_verify(int type, const unsigned char *dgst, int dlen,
                        const unsigned char *sig, int siglen, EC_KEY *eckey)
{
    counts[1]++;
    printf("  method verify: type %d, %d octets\n", type, dlen);
    return orig_verify(type, dgst, dlen, sig, siglen, eckey);
}

static int count_compute(unsigned char **psec, size_t *pseclen, const EC_POINT *pub,
                         const EC_KEY *ecdh)
{
    counts[2]++;
    return orig_compute(psec, pseclen, pub, ecdh);
}

static void show_counts(void)
{
    printf("  method calls: sign %d, verify %d, compute_key %d\n", counts[0], counts[1],
           counts[2]);
}

static EC_KEY_METHOD *counting_method(void)
{
    EC_KEY_METHOD *m = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    int (*setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **);
    ECDSA_SIG *(*sign_sig)(const unsigned char *, int, const BIGNUM *, const BIGNUM *,
                           EC_KEY *);
    int (*verify_sig)(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *);

    EC_KEY_METHOD_get_sign(m, &orig_sign, &setup, &sign_sig);
    EC_KEY_METHOD_set_sign(m, count_sign, setup, sign_sig);
    EC_KEY_METHOD_get_verify(m, &orig_verify, &verify_sig);
    EC_KEY_METHOD_set_verify(m, count_verify, verify_sig);
    EC_KEY_METHOD_get_compute_key(m, &orig_compute);
    EC_KEY_METHOD_set_compute_key(m, count_compute);
    return m;
}

/* A key on the curve from a private number, with the method (none for NULL). */
static EVP_PKEY *legacy_key(int nid, const char *x, const EC_KEY_METHOD *meth)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(nid);
    EC_POINT *q = EC_POINT_new(EC_KEY_get0_group(ec));
    BIGNUM *d = NULL;
    EVP_PKEY *pk = EVP_PKEY_new();

    BN_hex2bn(&d, x);
    EC_POINT_mul(EC_KEY_get0_group(ec), q, d, NULL, NULL, NULL);
    EC_KEY_set_private_key(ec, d);
    EC_KEY_set_public_key(ec, q);
    if (meth != NULL)
        EC_KEY_set_method(ec, meth);
    EVP_PKEY_assign_EC_KEY(pk, ec);
    EC_POINT_free(q);
    BN_free(d);
    return pk;
}

static const char A256[] = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
static const char B256[] = "C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53";
static const char A163[] = "03A41434AA99C2EF40C8495B2ED9739CB2155A1E0D";
static const char B163[] = "0057E8A78E842BF4ACD5C315AA0569DB1703541D96";

static EVP_PKEY_CTX *ctx_for(EVP_PKEY *pk, int (*init)(EVP_PKEY_CTX *))
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk, NULL);
    int r = ctx != NULL ? init(ctx) : -9;

    if (r <= 0) {
        printf("  context failed %d\n", r);
        errors();
    }
    return ctx;
}

static void test_sign(EVP_PKEY *pk)
{
    EVP_PKEY_CTX *ctx = ctx_for(pk, EVP_PKEY_sign_init);
    unsigned char dg[64], sig[200];
    size_t len;
    const EVP_MD *md = NULL;
    int r;

    memset(dg, 0x5a, sizeof(dg));
    printf("  provided %d\n", EVP_PKEY_get0_provider(pk) != NULL);
    len = 0;
    r = EVP_PKEY_sign(ctx, NULL, &len, dg, 32);
    check(r == 1 && len == 72, "the signature's size");
    len = 71;
    r = EVP_PKEY_sign(ctx, sig, &len, dg, 32);
    check(r <= 0, "a buffer too small");
    errors();
    len = sizeof(sig);
    r = EVP_PKEY_sign(ctx, sig, &len, dg, 20);
    check(r == 1, "20 octets, no digest set");
    errors();
    r = EVP_PKEY_verify_init(ctx);
    printf("  verify %d %d\n", r, EVP_PKEY_verify(ctx, sig, len, dg, 20));
    printf("  verify of 19 octets %d\n", EVP_PKEY_verify(ctx, sig, len, dg, 19));
    errors();
    sig[len - 1] ^= 1;
    printf("  verify of a changed signature %d\n", EVP_PKEY_verify(ctx, sig, len, dg, 20));
    printf("  verify of garbage %d\n", EVP_PKEY_verify(ctx, dg, 10, dg, 20));
    errors();

    r = EVP_PKEY_sign_init(ctx);
    r = r * 10 + EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha384());
    r = r * 10 + EVP_PKEY_CTX_get_signature_md(ctx, &md);
    printf("  SHA384 %d %s\n", r, md != NULL ? EVP_MD_get0_name(md) : "(null)");
    errors();
    len = sizeof(sig);
    r = EVP_PKEY_sign(ctx, sig, &len, dg, 48);
    check(r == 1, "a SHA-384 digest");
    errors();
    len = sizeof(sig);
    r = EVP_PKEY_sign(ctx, sig, &len, dg, 64);
    printf("  64 octets with SHA384 set %d\n", r);
    errors();
    r = EVP_PKEY_CTX_set_signature_md(ctx, EVP_md5());
    printf("  MD5 %d\n", r);
    errors();
    r = EVP_PKEY_CTX_set_signature_md(ctx, EVP_sm3());
    printf("  SM3 %d\n", r);
    errors();
    r = EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha512_256());
    printf("  SHA512-256 %d\n", r);
    errors();
    show_counts();
    EVP_PKEY_CTX_free(ctx);

    {
        EVP_MD_CTX *m = EVP_MD_CTX_new();

        len = sizeof(sig);
        r = EVP_DigestSignInit(m, NULL, EVP_sha256(), NULL, pk);
        r = r * 10 + EVP_DigestSign(m, sig, &len, (const unsigned char *)"sample", 6);
        check(r == 11, "EVP_DigestSign");
        errors();
        r = EVP_DigestVerifyInit(m, NULL, EVP_sha256(), NULL, pk);
        r = r * 10 + EVP_DigestVerify(m, sig, len, (const unsigned char *)"sample", 6);
        printf("  EVP_DigestVerify %d\n", r);
        errors();
        EVP_MD_CTX_free(m);
    }
    show_counts();
    printf("  can_sign %d\n", EVP_PKEY_can_sign(pk));
}

static void derive(EVP_PKEY_CTX *ctx, size_t room)
{
    unsigned char s[200];
    size_t len = room;
    int r = EVP_PKEY_derive(ctx, s, &len);

    printf("  derive into %zu: %d", room, r);
    if (r == 1)
        hex("secret", s, len);
    else
        printf("\n");
    errors();
}

static void test_derive(EVP_PKEY *a, EVP_PKEY *b)
{
    EVP_PKEY_CTX *ctx = ctx_for(a, EVP_PKEY_derive_init);
    unsigned char ukm[] = "keying", *got = NULL;
    const EVP_MD *md = NULL;
    size_t len = 0;
    int r, outlen = 0;

    r = EVP_PKEY_derive(ctx, NULL, &len);
    printf("  without a peer: size %d %zu\n", r, len);
    errors();
    derive(ctx, 32);
    check(EVP_PKEY_derive_set_peer(ctx, b) == 1, "the peer");
    errors();
    len = 0;
    printf("  size %d %zu\n", EVP_PKEY_derive(ctx, NULL, &len), len);
    derive(ctx, 32);
    derive(ctx, 10);
    derive(ctx, 100);
    printf("  cofactor get %d set 1: %d set 5: %d\n", EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx),
           EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, 1),
           EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, 5));
    printf("  get %d\n", EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx));
    errors();
    derive(ctx, 32);

    r = EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, EVP_PKEY_ECDH_KDF_X9_63);
    r = r * 10 + EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, EVP_sha256());
    r = r * 10 + EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx, 40);
    check(r == 111, "X9.63 with SHA-256 for 40 octets");
    errors();
    len = 0;
    printf("  size %d %zu\n", EVP_PKEY_derive(ctx, NULL, &len), len);
    derive(ctx, 40);
    derive(ctx, 41);
    derive(ctx, 39);
    r = EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx, OPENSSL_memdup(ukm, 6), 6);
    printf("  ukm %d\n", r);
    derive(ctx, 40);
    printf("  type %d\n", EVP_PKEY_CTX_get_ecdh_kdf_type(ctx));
    r = EVP_PKEY_CTX_get_ecdh_kdf_md(ctx, &md);
    printf("  md %d %s\n", r, md != NULL ? EVP_MD_get0_name(md) : "(null)");
    /*
     * EVP_PKEY_CTX_get_ecdh_kdf_outlen gives the method's ctrl a NULL pointer to write the
     * length through, which crashes the reference; the ctrl itself works.
     */
    r = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN,
                          0, &outlen);
    printf("  outlen %d %d", r, outlen);
    r = EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx, &got);
    printf(" ukm %d %s\n", r, got != NULL && memcmp(got, ukm, 6) == 0 ? "same" : "other");
    errors();
    printf("  outlen 0: %d, type 7: %d\n", EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx, 0),
           EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, 7));
    errors();
    {
        EVP_PKEY_CTX *copy = EVP_PKEY_CTX_dup(ctx);

        check(copy != NULL, "a copy");
        if (copy != NULL)
            derive(copy, 40);
        EVP_PKEY_CTX_free(copy);
    }
    r = EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, NULL);
    printf("  no KDF digest %d\n", r);
    derive(ctx, 40);
    r = EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, EVP_PKEY_ECDH_KDF_NONE);
    printf("  no KDF %d\n", r);
    derive(ctx, 40);
    show_counts();
    EVP_PKEY_CTX_free(ctx);
}

static void test_cofactor(const EC_KEY_METHOD *meth)
{
    EVP_PKEY *a = legacy_key(NID_sect163k1, A163, meth);
    EVP_PKEY *b = legacy_key(NID_sect163k1, B163, meth);
    static const int modes[] = { -1, 1, 0, -1, 2 };
    EVP_PKEY_CTX *ctx = ctx_for(a, EVP_PKEY_derive_init);
    size_t i;

    EVP_PKEY_derive_set_peer(ctx, b);
    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        int r = EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, modes[i]);

        printf("  mode %d: set %d get %d\n", modes[i], r,
               EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx));
        errors();
        derive(ctx, 21);
    }
    {
        EVP_PKEY_CTX *copy;

        EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, 1);
        copy = EVP_PKEY_CTX_dup(ctx);
        printf("  copy with mode 1: get %d\n", EVP_PKEY_CTX_get_ecdh_cofactor_mode(copy));
        derive(copy, 21);
        EVP_PKEY_CTX_free(copy);
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
}

static void test_ctrl_str(EVP_PKEY *pk)
{
    static const char *const pairs[][2] = {
        { "ec_paramgen_curve", "P-256" },
        { "ec_paramgen_curve", "secp384r1" },
        { "ec_paramgen_curve", "prime256v1" },
        { "ec_paramgen_curve", "nosuchcurve" },
        { "ec_param_enc", "explicit" },
        { "ec_param_enc", "named_curve" },
        { "ec_param_enc", "bogus" },
        { "ecdh_kdf_md", "SHA256" },
        { "ecdh_kdf_md", "nosuchdigest" },
        { "ecdh_cofactor_mode", "1" },
        { "ecdh_cofactor_mode", "7" },
        { "ecdh_cofactor_mode", "x" },
        { "digest", "SHA256" },
        { "nosuchsetting", "1" },
    };
    EVP_PKEY_CTX *ctx = ctx_for(pk, EVP_PKEY_derive_init);
    size_t i;

    for (i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        printf("  %s=%s: %d\n", pairs[i][0], pairs[i][1],
               EVP_PKEY_CTX_ctrl_str(ctx, pairs[i][0], pairs[i][1]));
        errors();
    }
    printf("  ctrl unknown %d\n", EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, 9999, 0, NULL));
    errors();
    EVP_PKEY_CTX_free(ctx);
}

/* Parameters and keys from an application's copy of the built-in method. */
static void test_gen(void)
{
    EVP_PKEY_METHOD *m = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
    EVP_PKEY_CTX *ctx, *kctx;
    EVP_PKEY *params = NULL, *pk = NULL;
    int r;

    EVP_PKEY_meth_copy(m, EVP_PKEY_meth_find(EVP_PKEY_EC));
    check(EVP_PKEY_meth_add0(m) == 1, "an application's copy of the EC method");

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    r = EVP_PKEY_paramgen_init(ctx);
    printf("  paramgen init %d\n", r);
    r = EVP_PKEY_paramgen(ctx, &params);
    check(r <= 0, "no curve");
    errors();
    r = EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE);
    printf("  param_enc without a curve %d\n", r);
    errors();
    r = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_undef);
    printf("  curve NID_undef %d\n", r);
    errors();
    r = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1);
    r = r * 10 + EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_EXPLICIT_CURVE);
    r = r * 10 + EVP_PKEY_paramgen(ctx, &params);
    check(r == 111 && params != NULL, "secp384r1 parameters, explicit");
    errors();
    if (params != NULL) {
        const EC_GROUP *g = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(params));

        printf("  curve %d asn1 flag %d bits %d\n", EC_GROUP_get_curve_name(g),
               EC_GROUP_get_asn1_flag(g), EVP_PKEY_get_bits(params));
    }

    kctx = EVP_PKEY_CTX_new(params, NULL);
    r = EVP_PKEY_keygen_init(kctx);
    r = r * 10 + EVP_PKEY_keygen(kctx, &pk);
    check(r == 11 && pk != NULL, "a key from the parameters");
    errors();
    if (pk != NULL) {
        const EC_KEY *k = EVP_PKEY_get0_EC_KEY(pk);

        printf("  curve %d check %d bits %d\n",
               EC_GROUP_get_curve_name(EC_KEY_get0_group(k)), EC_KEY_check_key(k),
               EVP_PKEY_get_bits(pk));
    }
    EVP_PKEY_free(pk);
    pk = NULL;
    EVP_PKEY_CTX_free(kctx);

    r = EVP_PKEY_keygen_init(ctx);
    r = r * 10 + EVP_PKEY_keygen(ctx, &pk);
    check(r == 11 && pk != NULL, "a key from the curve set");
    errors();
    if (pk != NULL) {
        const EC_KEY *k = EVP_PKEY_get0_EC_KEY(pk);

        printf("  curve %d check %d can_sign %d\n",
               EC_GROUP_get_curve_name(EC_KEY_get0_group(k)), EC_KEY_check_key(k),
               EVP_PKEY_can_sign(pk));
    }
    {
        EVP_PKEY_CTX *copy = EVP_PKEY_CTX_dup(ctx);
        EVP_PKEY *pk2 = NULL;

        printf("  copy %d", copy != NULL);
        if (copy != NULL) {
            r = EVP_PKEY_keygen(copy, &pk2);
            printf(" keygen %d curve %d", r,
                   pk2 != NULL ? EC_GROUP_get_curve_name(
                                     EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pk2)))
                               : 0);
        }
        printf("\n");
        errors();
        EVP_PKEY_free(pk2);
        EVP_PKEY_CTX_free(copy);
    }
    EVP_PKEY_free(pk);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    r = EVP_PKEY_keygen_init(ctx);
    pk = NULL;
    r = r * 10 + EVP_PKEY_keygen(ctx, &pk);
    check(r <= 10, "no curve for a key");
    errors();
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
}

int main(void)
{
    EC_KEY_METHOD *meth;

    setvbuf(stdout, NULL, _IOLBF, 0);
    meth = counting_method();
    EVP_PKEY *a = legacy_key(NID_X9_62_prime256v1, A256, meth);
    EVP_PKEY *b = legacy_key(NID_X9_62_prime256v1, B256, meth);
    EVP_PKEY *plain = legacy_key(NID_X9_62_prime256v1, A256, NULL);

    check(a != NULL && b != NULL && plain != NULL, "keys with the application's method");
    printf("  plain can_sign %d\n", EVP_PKEY_can_sign(plain));
    test_sign(a);
    test_derive(a, b);
    test_cofactor(meth);
    test_ctrl_str(a);
    test_gen();
    errors();
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    EVP_PKEY_free(plain);
    EC_KEY_METHOD_free(meth);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
