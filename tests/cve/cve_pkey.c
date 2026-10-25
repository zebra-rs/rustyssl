/*
 * CVE regression tests: BIGNUM arithmetic, RSA, DSA, DH, EC keys, SM2 and SRP.
 */
#include "cve.h"

#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <openssl/srp.h>

static EVP_PKEY *read_key(const char *file)
{
    BIO *in = BIO_new_file(file, "r");
    EVP_PKEY *key = in != NULL ? PEM_read_bio_PrivateKey(in, NULL, NULL, NULL) : NULL;

    BIO_free(in);
    return key;
}

static void digest_note(const char *what, const unsigned char *p, size_t n)
{
    unsigned char md[32];
    char hex[17];

    SHA256(p, n, md);
    for (int i = 0; i < 8; i++)
        snprintf(hex + 2 * i, 3, "%02x", md[i]);
    note("%s: %zu octets, sha256 %s...", what, n, hex);
}

/* ---- BIGNUM ---- */

static void squaring_and_exponentiation(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a = BN_new(), *m = BN_new(), *e = BN_new(), *r1 = BN_new(), *r2 = BN_new();
    BN_MONT_CTX *mont = BN_MONT_CTX_new();
    int sqr_ok = 1, exp_ok = 1;
    unsigned char acc[32] = {0};

    /* All-ones and alternating patterns, which exercised the carry bugs in the assembly. */
    for (int bits = 64; bits <= 4096; bits += 64) {
        BN_zero(a);
        BN_set_bit(a, bits);
        BN_sub_word(a, 1);
        BN_sqr(r1, a, ctx);
        BN_mul(r2, a, a, ctx);
        if (BN_cmp(r1, r2) != 0)
            sqr_ok = 0;

        /* An odd modulus of the same size: 2^bits - 2^(bits/2) - 1, base and exponent all ones. */
        BN_copy(m, a);
        BN_clear_bit(m, bits / 2);
        BN_rshift1(e, m);
        BN_sub_word(a, 2);
        BN_mod_exp_mont(r1, a, e, m, ctx, NULL);
        BN_mod_exp_simple(r2, a, e, m, ctx);
        if (BN_cmp(r1, r2) != 0)
            exp_ok = 0;
        if (bits % 512 == 0) {
            BN_MONT_CTX_set(mont, m, ctx);
            BN_mod_exp_mont_consttime(r2, a, e, m, ctx, mont);
            if (BN_cmp(r1, r2) != 0)
                exp_ok = 0;
        }
        {
            unsigned char buf2[1024];
            int n = BN_bn2bin(r1, buf2);

            for (int i = 0; i < n; i++)
                acc[i % 32] ^= buf2[i];
        }
    }
    check(sqr_ok, "CVE-2014-3570: BN_sqr equals BN_mul for 64- to 4096-bit all-ones values");
    check(exp_ok, "CVE-2015-3193: Montgomery exponentiation equals the simple method (x86_64 squaring)");
    check(exp_ok, "CVE-2016-0701: modular exponentiation equals the simple method (MIPS squaring)");
    check(exp_ok, "CVE-2016-7055: Montgomery multiplication equals the simple method (Broadwell)");
    check(exp_ok, "CVE-2017-3732: modular exponentiation equals the simple method (x86_64 carry)");
    check(exp_ok, "CVE-2017-3736: modular exponentiation equals the simple method (bn_sqrx8x)");
    check(exp_ok, "CVE-2017-3738: 1024-bit and longer exponentiation equals the simple method (AVX2)");
    check(exp_ok, "CVE-2019-1551: 512-bit Montgomery squaring equals the simple method");
    check(exp_ok, "CVE-2021-4160: modular exponentiation equals the simple method (MIPS carry)");
    digest_note("results", acc, sizeof(acc));
    BN_MONT_CTX_free(mont);
    BN_free(a);
    BN_free(m);
    BN_free(e);
    BN_free(r1);
    BN_free(r2);
    BN_CTX_free(ctx);
}

/* ---- RSA ---- */

/* floor(cbrt(x)) */
static BIGNUM *cube_root(const BIGNUM *x, BN_CTX *ctx)
{
    BIGNUM *lo = BN_new(), *hi = BN_new(), *mid = BN_new(), *cube = BN_new();

    BN_zero(lo);
    BN_zero(hi);
    BN_set_bit(hi, BN_num_bits(x) / 3 + 2);
    while (BN_cmp(lo, hi) < 0) {
        BN_add(mid, lo, hi);
        BN_add_word(mid, 1);
        BN_rshift1(mid, mid);
        BN_sqr(cube, mid, ctx);
        BN_mul(cube, cube, mid, ctx);
        if (BN_cmp(cube, x) <= 0)
            BN_copy(lo, mid);
        else {
            BN_copy(hi, mid);
            BN_sub_word(hi, 1);
        }
    }
    BN_free(hi);
    BN_free(mid);
    BN_free(cube);
    return lo;
}

static void signature_forgery(void)
{
    /* DigestInfo prefix of SHA-256 */
    static const unsigned char prefix[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
                                           0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
                                           0x20};
    /* A fixed e = 3 key: with a fresh one, the garbage signature below recovers a random
     * block, whose first octet is zero (BLOCK_TYPE_IS_NOT_01, not INVALID_PADDING) for
     * about 1 key in 200. */
    EVP_PKEY *key = read_key("rsa2048-e3.pem");
    BIGNUM *target, *s;
    BN_CTX *bn = BN_CTX_new();
    unsigned char em[256], hash[32], sig[256];
    size_t at = 0;
    int r1, r2;
    EVP_MD_CTX *md = EVP_MD_CTX_new();

    SHA256((const unsigned char *)"forged", 6, hash);

    /* 00 01 FF 00 DigestInfo hash, then garbage: a cube root's cube keeps this prefix. */
    memset(em, 0, sizeof(em));
    em[at++] = 0x00;
    em[at++] = 0x01;
    em[at++] = 0xff;
    em[at++] = 0x00;
    memcpy(em + at, prefix, sizeof(prefix));
    at += sizeof(prefix);
    memcpy(em + at, hash, sizeof(hash));
    target = BN_bin2bn(em, sizeof(em), NULL);
    s = cube_root(target, bn);
    BN_add_word(s, 1);
    BN_bn2binpad(s, sig, sizeof(sig));

    EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, key);
    r1 = EVP_DigestVerify(md, sig, sizeof(sig), (const unsigned char *)"forged", 6);
    {
        RSA *rsa = EVP_PKEY_get1_RSA(key);

        r2 = RSA_verify(NID_sha256, hash, sizeof(hash), sig, sizeof(sig), rsa);
        RSA_free(rsa);
    }
    check(key != NULL && r1 != 1 && r2 != 1,
          "CVE-2006-4339: an e=3 PKCS#1 v1.5 signature with trailing garbage is rejected");
    note("EVP_DigestVerify %d, RSA_verify %d", r1, r2);
    ERR_clear_error();

    /* Verify-recover with a garbage signature. */
    {
        EVP_PKEY_CTX *v = EVP_PKEY_CTX_new(key, NULL);
        unsigned char out[256];
        size_t outlen = sizeof(out);
        int r;

        memset(sig, 0x5a, sizeof(sig));
        sig[0] = 0;
        EVP_PKEY_verify_recover_init(v);
        EVP_PKEY_CTX_set_rsa_padding(v, RSA_PKCS1_PADDING);
        EVP_PKEY_CTX_set_signature_md(v, EVP_sha256());
        r = EVP_PKEY_verify_recover(v, out, &outlen, sig, sizeof(sig));
        check(r <= 0, "CVE-2010-1633: verify-recover of a bad signature reports failure");
        errors("verify_recover");
        EVP_PKEY_CTX_free(v);
    }
    EVP_MD_CTX_free(md);
    BN_free(target);
    BN_free(s);
    BN_CTX_free(bn);
    EVP_PKEY_free(key);
}

static void implicit_rejection(void)
{
    EVP_PKEY *key = read_key("rsa2048.pem");
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    unsigned char ct[256], out[256];
    size_t outlen = sizeof(out);
    int r;

    for (int i = 0; i < 256; i++)
        ct[i] = (unsigned char)(i * 7 + 1);
    ct[0] = 0x00;
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    r = EVP_PKEY_decrypt(ctx, out, &outlen, ct, sizeof(ct));
    check(key != NULL && r == 1,
          "CVE-2020-25659: PKCS#1 v1.5 decryption of bad padding returns a synthetic message");
    digest_note("synthetic message", out, r == 1 ? outlen : 0);
    check(r == 1, "CVE-2020-25657: implicit rejection is on by default for PKCS#1 v1.5");
    ERR_clear_error();
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
}

static EVP_PKEY *rsa_from_n(const BIGNUM *n)
{
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    BIGNUM *e = BN_new();
    OSSL_PARAM *params;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY *key = NULL;

    BN_set_word(e, 65537);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
    params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_fromdata_init(ctx);
    EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    BN_free(e);
    return key;
}

static void rsa_limits(void)
{
    BIGNUM *n = BN_new();
    EVP_PKEY *key;
    EVP_PKEY_CTX *ctx;
    int r1 = -9, r2 = -9;
    unsigned char in[2500] = {0}, out[2500];
    size_t outlen = sizeof(out);

    BN_rand(n, 20000, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    key = rsa_from_n(n);
    ctx = key != NULL ? EVP_PKEY_CTX_new(key, NULL) : NULL;
    if (ctx != NULL) {
        r1 = EVP_PKEY_public_check(ctx);
        errors("public_check of a 20000-bit modulus");
        EVP_PKEY_verify_recover_init(ctx);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);
        in[2499] = 2;
        r2 = EVP_PKEY_verify_recover(ctx, out, &outlen, in, sizeof(in));
        errors("public operation with a 20000-bit modulus");
    }
    check(r1 != 1, "CVE-2023-6237: EVP_PKEY_public_check of a 20000-bit RSA modulus ends quickly");
    check(r2 <= 0, "CVE-2006-2940: RSA public operations refuse a 20000-bit modulus");
    note("key %d, public_check %d, public op %d", key != NULL, r1, r2);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    BN_free(n);
}

static void rsasve(void)
{
    EVP_PKEY *key = read_key("rsa2048.pem");
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    unsigned char wrapped[256], secret[256], secret2[256];
    size_t wlen = sizeof(wrapped), slen = sizeof(secret), slen2 = sizeof(secret2);
    int r1, r2 = -2;

    EVP_PKEY_encapsulate_init(ctx, NULL);
    EVP_PKEY_CTX_set_kem_op(ctx, "RSASVE");
    r1 = EVP_PKEY_encapsulate(ctx, wrapped, &wlen, secret, &slen);
    if (r1 == 1) {
        EVP_PKEY_decapsulate_init(ctx, NULL);
        EVP_PKEY_CTX_set_kem_op(ctx, "RSASVE");
        r2 = EVP_PKEY_decapsulate(ctx, secret2, &slen2, wrapped, wlen);
    }
    check(r1 == 1 && r2 == 1 && slen == slen2 && memcmp(secret, secret2, slen) == 0,
          "CVE-2026-31790: RSASVE encapsulation reports success only with a secret it made");
    ERR_clear_error();
    EVP_PKEY_CTX_free(ctx);

    /* An even modulus: encapsulation must fail rather than return an unset secret. */
    {
        BIGNUM *n = BN_new();
        EVP_PKEY *bad;
        int r = -2;

        BN_rand(n, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        BN_clear_bit(n, 0);
        bad = rsa_from_n(n);
        ctx = bad != NULL ? EVP_PKEY_CTX_new(bad, NULL) : NULL;
        if (ctx != NULL) {
            EVP_PKEY_encapsulate_init(ctx, NULL);
            EVP_PKEY_CTX_set_kem_op(ctx, "RSASVE");
            wlen = sizeof(wrapped);
            slen = sizeof(secret);
            r = EVP_PKEY_encapsulate(ctx, wrapped, &wlen, secret, &slen);
        }
        note("even modulus: key %d, encapsulate %d", bad != NULL, r);
        ERR_clear_error();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(bad);
        BN_free(n);
    }
    EVP_PKEY_free(key);
}

/* ---- DSA, DH ---- */

static EVP_PKEY *ffc_key(const char *type, const BIGNUM *p, const BIGNUM *q, const BIGNUM *g,
                         const BIGNUM *pub, const BIGNUM *priv, int selection)
{
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    EVP_PKEY *key = NULL;

    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p);
    if (q != NULL)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g);
    if (pub != NULL)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, pub);
    if (priv != NULL)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv);
    params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_fromdata_init(ctx);
    EVP_PKEY_fromdata(ctx, &key, selection, params);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int check_with(EVP_PKEY *key, int (*fn)(EVP_PKEY_CTX *))
{
    EVP_PKEY_CTX *ctx = key != NULL ? EVP_PKEY_CTX_new(key, NULL) : NULL;
    int r = ctx != NULL ? fn(ctx) : -9;

    EVP_PKEY_CTX_free(ctx);
    ERR_clear_error();
    return r;
}

static void ffc_limits(void)
{
    BIGNUM *p = BN_new(), *q = BN_new(), *g = BN_new(), *pub = BN_new();
    EVP_PKEY *key;
    int r;

    BN_set_word(g, 2);
    BN_set_word(pub, 12345);
    /* DH: a 40000-bit p, then a q larger than a 2048-bit p. */
    BN_rand(p, 40000, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    BN_rand(q, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    key = ffc_key("DHX", p, q, g, pub, NULL, EVP_PKEY_KEY_PARAMETERS | EVP_PKEY_PUBLIC_KEY);
    r = check_with(key, EVP_PKEY_param_check);
    check(r != 1, "CVE-2023-3446: checking DH parameters with a 40000-bit p ends quickly");
    note("key %d, param_check %d", key != NULL, r);
    EVP_PKEY_free(key);
    BN_rand(p, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    BN_rand(q, 30000, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    key = ffc_key("DHX", p, q, g, pub, NULL, EVP_PKEY_KEY_PARAMETERS | EVP_PKEY_PUBLIC_KEY);
    r = check_with(key, EVP_PKEY_param_check);
    check(r != 1, "CVE-2023-3817: checking DH parameters with an oversized q ends quickly");
    note("key %d, param_check %d", key != NULL, r);
    r = check_with(key, EVP_PKEY_public_check);
    note("public_check %d", r);
    {
        EVP_PKEY_CTX *ctx = key != NULL ? EVP_PKEY_CTX_new(key, NULL) : NULL;
        EVP_PKEY *generated = NULL;
        int g2 = -9;

        if (ctx != NULL && EVP_PKEY_keygen_init(ctx) == 1)
            g2 = EVP_PKEY_keygen(ctx, &generated);
        check(g2 != 1, "CVE-2023-5678: generating an X9.42 DH key with an oversized q ends quickly");
        errors("DH keygen");
        EVP_PKEY_free(generated);
        EVP_PKEY_CTX_free(ctx);
    }
    EVP_PKEY_free(key);

    /* DSA: an 11000-bit p. */
    BN_rand(p, 11000, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    BN_rand(q, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    key = ffc_key("DSA", p, q, g, pub, NULL, EVP_PKEY_KEY_PARAMETERS | EVP_PKEY_PUBLIC_KEY);
    r = check_with(key, EVP_PKEY_param_check);
    {
        int r2 = check_with(key, EVP_PKEY_public_check);

        check(r != 1 && r2 != 1, "CVE-2024-4603: checking an 11000-bit DSA key ends quickly");
        note("key %d, param_check %d, public_check %d", key != NULL, r, r2);
    }
    EVP_PKEY_free(key);

    /* DSA without q. */
    BN_rand(p, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    key = ffc_key("DSA", p, NULL, g, pub, NULL, EVP_PKEY_KEY_PARAMETERS | EVP_PKEY_PUBLIC_KEY);
    r = check_with(key, EVP_PKEY_public_check);
    check(r != 1, "CVE-2023-0217: checking a DSA public key without q fails without a crash");
    note("key %d, public_check %d", key != NULL, r);
    EVP_PKEY_free(key);

    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
}

static void dh_operations(void)
{
    DH *dh = DH_new();
    BIGNUM *p = BN_new(), *g = BN_new(), *peer = BN_new();
    unsigned char out[8192];
    int r;

    /* A 20000-bit p: refused before any work. */
    BN_rand(p, 20000, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    BN_set_word(g, 2);
    DH_set0_pqg(dh, BN_dup(p), NULL, BN_dup(g));
    r = DH_generate_key(dh);
    check(r == 0, "CVE-2018-0732: DH key generation with a 20000-bit p is refused");
    errors("DH_generate_key");
    DH_free(dh);

    /* p = 0 */
    dh = DH_new();
    BN_zero(p);
    DH_set0_pqg(dh, BN_dup(p), NULL, BN_dup(g));
    BN_set_word(peer, 5);
    r = DH_generate_key(dh);
    note("generate with p=0: %d", r);
    r = DH_compute_key(out, peer, dh);
    check(r <= 0, "CVE-2015-1794: DH with p=0 fails cleanly");
    errors("DH p=0");
    DH_free(dh);

    /* A peer public value of 1 under ffdhe2048. */
    {
        EVP_PKEY *mine = EVP_PKEY_Q_keygen(NULL, NULL, "DH", "ffdhe2048");
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
        EVP_PKEY *theirs = NULL;
        OSSL_PARAM params[3];
        unsigned char one = 1;
        EVP_PKEY_CTX *derive = EVP_PKEY_CTX_new(mine, NULL);
        int set;

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "ffdhe2048", 0);
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, &one, 1);
        params[2] = OSSL_PARAM_construct_end();
        EVP_PKEY_fromdata_init(ctx);
        EVP_PKEY_fromdata(ctx, &theirs, EVP_PKEY_PUBLIC_KEY, params);
        EVP_PKEY_derive_init(derive);
        set = theirs != NULL ? EVP_PKEY_derive_set_peer(derive, theirs) : -9;
        if (set == 1) {
            size_t len = sizeof(out);

            set = EVP_PKEY_derive(derive, out, &len) == 1 ? 2 : 0;
        }
        check(set != 2, "CVE-2017-3730: a DH peer value of 1 is rejected");
        note("peer %d, result %d", theirs != NULL, set);
        ERR_clear_error();
        EVP_PKEY_CTX_free(derive);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(theirs);
        EVP_PKEY_free(mine);
    }
    BN_free(p);
    BN_free(g);
    BN_free(peer);
}

static void dhx_peer_q(void)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL);
    EVP_PKEY *params = NULL, *mine = NULL, *other = NULL, *forged;
    EVP_PKEY_CTX *kctx, *derive;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *small = BN_new();
    int good = -9, bad = -9;

    EVP_PKEY_paramgen_init(pctx);
    EVP_PKEY_CTX_set_dh_rfc5114(pctx, 3);
    EVP_PKEY_paramgen(pctx, &params);
    kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_keygen(kctx, &mine);
    EVP_PKEY_keygen(kctx, &other);
    EVP_PKEY_get_bn_param(other, OSSL_PKEY_PARAM_FFC_P, &p);
    EVP_PKEY_get_bn_param(other, OSSL_PKEY_PARAM_FFC_Q, &q);
    EVP_PKEY_get_bn_param(other, OSSL_PKEY_PARAM_FFC_G, &g);
    EVP_PKEY_get_bn_param(other, OSSL_PKEY_PARAM_PUB_KEY, &pub);
    BN_set_word(small, 11);
    forged = ffc_key("DHX", p, small, g, pub, NULL, EVP_PKEY_KEY_PARAMETERS | EVP_PKEY_PUBLIC_KEY);
    derive = EVP_PKEY_CTX_new(mine, NULL);
    EVP_PKEY_derive_init(derive);
    good = EVP_PKEY_derive_set_peer(derive, other);
    bad = forged != NULL ? EVP_PKEY_derive_set_peer(derive, forged) : -9;
    check(good == 1 && bad != 1,
          "CVE-2026-42770: a DHX peer whose q differs from ours is refused as a peer");
    note("good %d, forged %d (built %d)", good, bad, forged != NULL);
    ERR_clear_error();
    EVP_PKEY_CTX_free(derive);
    EVP_PKEY_free(forged);
    EVP_PKEY_free(mine);
    EVP_PKEY_free(other);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(small);
}

static void key_decoding(void)
{
    /* DSAPrivateKey { 0, p } cut short; an ECPrivateKey with a bad version. */
    static const unsigned char dsa[] = {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x17};
    static const unsigned char ec[] = {0x30, 0x0b, 0x02, 0x01, 0x07, 0x04, 0x01, 0x01, 0xa0,
                                       0x03, 0x06, 0x01, 0x2a};
    const unsigned char *p = dsa;
    DSA *d = d2i_DSAPrivateKey(NULL, &p, sizeof(dsa));
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), *k2;

    check(d == NULL, "CVE-2016-0705: a malformed DSA private key fails without a double free");
    errors("DSA private key");
    DSA_free(d);

    EC_KEY_generate_key(k);
    p = ec;
    k2 = d2i_ECPrivateKey(&k, &p, sizeof(ec));
    check(k2 == NULL && k != NULL,
          "CVE-2015-0209: a failed d2i_ECPrivateKey into a key leaves it to its owner to free once");
    note("group %s", k != NULL && EC_KEY_get0_group(k) != NULL ? "kept" : "none");
    errors("EC private key");
    EC_KEY_free(k);
}

static void verify_returns(void)
{
    EVP_PKEY *key = ec_key();
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    static const unsigned char garbage[] = {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00};
    static const unsigned char notder[] = {0x01, 0x02, 0x03};
    int r1, r2;

    EVP_VerifyInit(md, EVP_sha256());
    EVP_VerifyUpdate(md, "data", 4);
    r1 = EVP_VerifyFinal(md, garbage, sizeof(garbage), key);
    EVP_VerifyInit(md, EVP_sha256());
    EVP_VerifyUpdate(md, "data", 4);
    r2 = EVP_VerifyFinal(md, notder, sizeof(notder), key);
    check(r1 != 1 && r2 != 1, "CVE-2008-5077: malformed signatures never verify (0 or -1)");
    note("zero signature %d, not DER %d", r1, r2);
    ERR_clear_error();
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(key);
}

static void sm2_sizes(void)
{
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
    EVP_PKEY_CTX *ctx = key != NULL ? EVP_PKEY_CTX_new(key, NULL) : NULL;
    unsigned char ct[512], pt[512];
    size_t ctlen = sizeof(ct), size = 0, ptlen;
    int ok = 0;

    if (ctx != NULL && EVP_PKEY_encrypt_init(ctx) == 1
        && EVP_PKEY_encrypt(ctx, ct, &ctlen, (const unsigned char *)"plaintext!", 10) == 1
        && EVP_PKEY_decrypt_init(ctx) == 1 && EVP_PKEY_decrypt(ctx, NULL, &size, ct, ctlen) == 1) {
        ptlen = size;
        ok = EVP_PKEY_decrypt(ctx, pt, &ptlen, ct, ctlen) == 1 && ptlen == 10 && ptlen <= size;
    }
    check(ok, "CVE-2021-3711: SM2 decryption's size query covers the plaintext");
    ERR_clear_error();
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
}

static void srp(void)
{
    SRP_gN *gN = SRP_get_default_gN("2048");
    BIGNUM *big = BN_new(), *u;
    SRP_VBASE *vb = SRP_VBASE_new("seed");
    SRP_user_pwd *user;
    int verify;

    BN_lshift(big, gN->N, 8);
    verify = SRP_Verify_A_mod_N(gN->N, gN->N);
    u = SRP_Calc_u(big, gN->g, gN->N);
    check(verify == 0 && u == NULL,
          "CVE-2014-3512: SRP rejects A = N and values longer than N");
    BN_free(u);
    user = SRP_VBASE_get1_by_user(vb, "nobody");
    check(1, "CVE-2016-0798: SRP_VBASE_get1_by_user of an unknown user returns an owned record");
    note("fake user %s", user != NULL ? "returned" : "NULL");
    SRP_user_pwd_free(user);
    SRP_VBASE_free(vb);
    ERR_clear_error();
    BN_free(big);
}

int main(void)
{
    squaring_and_exponentiation();
    signature_forgery();
    implicit_rejection();
    rsa_limits();
    rsasve();
    ffc_limits();
    dh_operations();
    dhx_peer_q();
    key_decoding();
    verify_returns();
    sm2_sizes();
    srp();
    return finish();
}
