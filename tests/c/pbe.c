/*
 * Conformance test for password-based encryption (EVP_PBE_CipherInit(3), PKCS5_pbe2_set(3),
 * PKCS5_PBE_keyivgen(3)), in TAP format: the built-in PBE table listed and searched; an
 * application's algorithms added, used, and cleaned up; the parameter structures (PBEPARAM,
 * PBE2PARAM, PBKDF2PARAM, PBMAC1PARAM, SCRYPT_PARAMS) built with fixed salts and IVs, encoded,
 * and decoded; encryption and decryption through each algorithm (PBES2 with PBKDF2 and every
 * PRF, PBES2 with scrypt, PKCS#12's PBEs, PBES1); the key derivations called directly; and the
 * errors of bad parameters.
 *
 * Only the default provider is loaded: PBES1 and the PBEs over legacy ciphers fail, as they
 * should without the legacy provider.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs12.h>
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

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s (%zu):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 && i > 0 ? "\n    " : " ", p[i]);
    printf("\n");
}

static const unsigned char SALT[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static unsigned char IV[16] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                                0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf };
static const unsigned char PLAIN[] = "The quick brown fox jumps over the lazy dog";

static void show_algor(const char *label, const X509_ALGOR *a)
{
    unsigned char *der = NULL;
    int n = a == NULL ? -1 : i2d_X509_ALGOR(a, &der);

    if (n > 0)
        hex(label, der, (size_t)n);
    else {
        printf("  %s: none\n", label);
        errors();
    }
    OPENSSL_free(der);
}

/* Encrypts the plaintext under the AlgorithmIdentifier and the password, then decrypts it. */
static void roundtrip(const char *label, const X509_ALGOR *a, const char *pass, int passlen)
{
    /* A random salt or IV makes a random ciphertext: shown only when both are fixed. */
    int show = strstr(label, "random") == NULL && strstr(label, "2des") == NULL;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[256], back[256];
    int n = 0, m = 0, r;
    char what[150];

    snprintf(what, sizeof(what), "%s: CipherInit to encrypt", label);
    r = a != NULL && EVP_PBE_CipherInit(a->algorithm, pass, passlen, a->parameter, ctx, 1);
    printf("  %s: CipherInit %d\n", label, r);
    if (!r) {
        errors();
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    if (EVP_CipherUpdate(ctx, out, &n, PLAIN, sizeof(PLAIN) - 1) && EVP_CipherFinal_ex(ctx, out + n, &m)) {
        if (show)
            hex("ciphertext", out, (size_t)(n + m));
    } else
        errors();
    EVP_CIPHER_CTX_free(ctx);
    ctx = EVP_CIPHER_CTX_new();
    n += m;
    m = 0;
    if (EVP_PBE_CipherInit(a->algorithm, pass, passlen, a->parameter, ctx, 0)) {
        int k = 0, f = 0;

        r = EVP_CipherUpdate(ctx, back, &k, out, n) && EVP_CipherFinal_ex(ctx, back + k, &f);
        snprintf(what, sizeof(what), "%s: decrypts back", label);
        check(r && (size_t)(k + f) == sizeof(PLAIN) - 1 && memcmp(back, PLAIN, sizeof(PLAIN) - 1) == 0,
              what);
    } else {
        errors();
    }
    EVP_CIPHER_CTX_free(ctx);
}

static void test_table(void)
{
    static const int finds[][2] = {
        { EVP_PBE_TYPE_OUTER, NID_pbes2 },
        { EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And3_Key_TripleDES_CBC },
        { EVP_PBE_TYPE_OUTER, NID_pbeWithMD5AndDES_CBC },
        { EVP_PBE_TYPE_OUTER, NID_id_pbkdf2 },
        { EVP_PBE_TYPE_PRF, NID_hmacWithSHA256 },
        { EVP_PBE_TYPE_PRF, NID_hmacWithSM3 },
        { EVP_PBE_TYPE_KDF, NID_id_scrypt },
        { EVP_PBE_TYPE_KDF, NID_id_pbkdf2 },
        { EVP_PBE_TYPE_OUTER, NID_sha256 },
        { EVP_PBE_TYPE_PRF, NID_undef },
        { 7, NID_pbes2 },
    };
    int type, nid;
    size_t i;

    for (i = 0; EVP_PBE_get(&type, &nid, i); i++)
        printf("  builtin %zu: type %d nid %d %s\n", i, type, nid, OBJ_nid2sn(nid));
    printf("  builtins: %zu; past the end %d\n", i, EVP_PBE_get(NULL, NULL, i));
    for (i = 0; i < sizeof(finds) / sizeof(finds[0]); i++) {
        int cnid = 99, mnid = 99, r;
        EVP_PBE_KEYGEN *kg = NULL;
        EVP_PBE_KEYGEN_EX *kgx = NULL;

        r = EVP_PBE_find_ex(finds[i][0], finds[i][1], &cnid, &mnid, &kg, &kgx);
        printf("  find %d/%d: %d cipher %d md %d keygen %s keygen_ex %s\n", finds[i][0], finds[i][1],
               r, cnid, mnid, kg != NULL ? "set" : "NULL", kgx != NULL ? "set" : "NULL");
        r = EVP_PBE_find(finds[i][0], finds[i][1], NULL, NULL, NULL);
        printf("    find without outputs: %d\n", r);
    }
}

static int custom_calls = 0;

static int custom_keygen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen, ASN1_TYPE *param,
                         const EVP_CIPHER *cipher, const EVP_MD *md, int en_de)
{
    static const unsigned char key[16] = { 0 };

    (void)pass;
    custom_calls++;
    printf("  custom keygen: passlen %d param %s cipher %s md %s en_de %d\n", passlen,
           param != NULL ? "set" : "NULL", cipher != NULL ? EVP_CIPHER_get0_name(cipher) : "NULL",
           md != NULL ? EVP_MD_get0_name(md) : "NULL", en_de);
    return EVP_CipherInit_ex(ctx, cipher, NULL, key, key, en_de);
}

static void test_added(void)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_PBE_KEYGEN *kg = NULL;
    EVP_PBE_KEYGEN_EX *kgx = NULL;
    int cnid = 0, mnid = 0;

    check(EVP_PBE_alg_add(NID_sha256, EVP_aes_128_cbc(), EVP_sha256(), custom_keygen),
          "EVP_PBE_alg_add");
    check(EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER, NID_pbes2, NID_aes_256_cbc, -1, custom_keygen),
          "EVP_PBE_alg_add_type over a built-in");
    check(EVP_PBE_find_ex(EVP_PBE_TYPE_OUTER, NID_sha256, &cnid, &mnid, &kg, &kgx), "found");
    printf("  added: cipher %d md %d keygen %s keygen_ex %s\n", cnid, mnid,
           kg == custom_keygen ? "custom" : "other", kgx != NULL ? "set" : "NULL");
    check(EVP_PBE_find(EVP_PBE_TYPE_OUTER, NID_pbes2, &cnid, NULL, &kg) && kg == custom_keygen
              && cnid == NID_aes_256_cbc,
          "the addition overrides the built-in");
    check(EVP_PBE_CipherInit(OBJ_nid2obj(NID_sha256), "pw", -1, NULL, ctx, 1), "CipherInit through it");
    printf("  custom calls %d\n", custom_calls);
    EVP_PBE_cleanup();
    check(EVP_PBE_find(EVP_PBE_TYPE_OUTER, NID_sha256, NULL, NULL, NULL) == 0, "cleaned up");
    check(EVP_PBE_find(EVP_PBE_TYPE_OUTER, NID_pbes2, NULL, NULL, &kg) && kg != custom_keygen,
          "the built-in again");
    EVP_CIPHER_CTX_free(ctx);
    PKCS5_PBE_add();
    PKCS12_PBE_add();
}

static void test_structures(void)
{
    static const int prfs[] = { -1, NID_hmacWithSHA1, NID_hmacWithSHA224, NID_hmacWithSHA256,
                                NID_hmacWithSHA384, NID_hmacWithSHA512, NID_hmacWithSHA512_224,
                                NID_hmacWithSHA512_256, NID_hmac_sha3_256, NID_hmacWithSM3,
                                NID_hmacWithMD5, NID_sha256 };
    X509_ALGOR *a;
    size_t i;
    char label[100];

    /* PBES2 with PBKDF2, each PRF. */
    for (i = 0; i < sizeof(prfs) / sizeof(prfs[0]); i++) {
        a = PKCS5_pbe2_set_iv(EVP_aes_128_cbc(), 1000, (unsigned char *)SALT, 16, IV, prfs[i]);
        snprintf(label, sizeof(label), "pbes2 aes-128-cbc prf %d", prfs[i]);
        show_algor(label, a);
        roundtrip(label, a, "password", -1);
        X509_ALGOR_free(a);
    }
    a = PKCS5_pbe2_set_iv_ex(EVP_aes_256_cbc(), 0, (unsigned char *)SALT, 8, IV, -1, NULL);
    show_algor("pbes2 aes-256-cbc default iterations", a);
    roundtrip("pbes2 aes-256-cbc", a, "pw", 2);
    X509_ALGOR_free(a);
    a = PKCS5_pbe2_set_iv(EVP_des_ede3_cbc(), 2048, (unsigned char *)SALT, 16, IV, NID_hmacWithSHA256);
    show_algor("pbes2 des-ede3-cbc", a);
    roundtrip("pbes2 des-ede3-cbc", a, NULL, 0);
    X509_ALGOR_free(a);
    a = PKCS5_pbe2_set(EVP_aes_128_cbc(), 10, NULL, 0);
    check(a != NULL, "PKCS5_pbe2_set with a random salt and IV");
    roundtrip("pbes2 random", a, "pw", -1);
    X509_ALGOR_free(a);
    a = PKCS5_pbe2_set_iv(EVP_aes_128_gcm(), 10, (unsigned char *)SALT, 16, IV, -1);
    show_algor("pbes2 aes-128-gcm", a);
    X509_ALGOR_free(a);
    a = PKCS5_pbe2_set_iv(EVP_enc_null(), 10, (unsigned char *)SALT, 16, IV, -1);
    show_algor("pbes2 of the null cipher", a);
    X509_ALGOR_free(a);

    /* PBKDF2 alone. */
    a = PKCS5_pbkdf2_set(5, (unsigned char *)SALT, 16, NID_hmacWithSHA512, 32);
    show_algor("pbkdf2 sha512 keylen 32", a);
    X509_ALGOR_free(a);
    a = PKCS5_pbkdf2_set_ex(0, (unsigned char *)SALT, 4, -1, 0, NULL);
    show_algor("pbkdf2 defaults", a);
    X509_ALGOR_free(a);
    a = PKCS5_pbkdf2_set(5, (unsigned char *)SALT, -1, -1, 0);
    show_algor("pbkdf2 negative salt length", a);
    X509_ALGOR_free(a);

    /* PBES2 with scrypt. */
    a = PKCS5_pbe2_set_scrypt(EVP_aes_128_cbc(), SALT, 16, IV, 1024, 8, 1);
    show_algor("pbes2 scrypt", a);
    roundtrip("pbes2 scrypt", a, "password", -1);
    X509_ALGOR_free(a);
    a = PKCS5_pbe2_set_scrypt(EVP_aes_128_cbc(), SALT, 16, IV, 1000, 8, 1);
    show_algor("scrypt with N not a power of two", a);
    X509_ALGOR_free(a);
    a = PKCS5_pbe2_set_scrypt(NULL, SALT, 16, IV, 1024, 8, 1);
    show_algor("scrypt without a cipher", a);
    X509_ALGOR_free(a);

    /* PKCS#12's PBEs and PBES1. */
    a = PKCS5_pbe_set(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, 2048, SALT, 8);
    show_algor("pkcs12 3des", a);
    roundtrip("pkcs12 3des", a, "password", -1);
    X509_ALGOR_free(a);
    a = PKCS5_pbe_set_ex(NID_pbe_WithSHA1And2_Key_TripleDES_CBC, 0, SALT, 0, NULL);
    check(a != NULL, "pkcs12 2des with defaults (a random salt)");
    roundtrip("pkcs12 2des", a, "pw", -1);
    X509_ALGOR_free(a);
    a = PKCS5_pbe_set(NID_pbe_WithSHA1And128BitRC4, 2048, SALT, 8);
    show_algor("pkcs12 rc4", a);
    roundtrip("pkcs12 rc4 (legacy)", a, "password", -1);
    X509_ALGOR_free(a);
    a = PKCS5_pbe_set(NID_pbeWithSHA1AndDES_CBC, 2048, SALT, 8);
    show_algor("pbes1 sha1 des", a);
    roundtrip("pbes1 sha1 des (legacy)", a, "password", -1);
    X509_ALGOR_free(a);
    a = X509_ALGOR_new();
    check(PKCS5_pbe_set0_algor(a, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, 7, SALT, 8), "PKCS5_pbe_set0_algor");
    show_algor("set0", a);
    check(PKCS5_pbe_set0_algor_ex(a, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, 7, SALT, -2, NULL) == 0,
          "a negative salt length fails");
    X509_ALGOR_free(a);

    /* An algorithm nothing knows. */
    a = X509_ALGOR_new();
    X509_ALGOR_set0(a, OBJ_nid2obj(NID_sha256), V_ASN1_NULL, NULL);
    roundtrip("an unknown PBE", a, "pw", -1);
    X509_ALGOR_free(a);
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        printf("  no object: %d\n", EVP_PBE_CipherInit_ex(NULL, "pw", -1, NULL, ctx, 1, NULL, NULL));
        errors();
        EVP_CIPHER_CTX_free(ctx);
    }
}

static void test_types(void)
{
    PBEPARAM *pbe = PBEPARAM_new();
    PBE2PARAM *pbe2 = PBE2PARAM_new();
    PBKDF2PARAM *kdf = PBKDF2PARAM_new();
    PBMAC1PARAM *mac = PBMAC1PARAM_new();
    SCRYPT_PARAMS *sc = SCRYPT_PARAMS_new();
    unsigned char *der = NULL;
    const unsigned char *p;
    int n;

    check(pbe && pbe2 && kdf && mac && sc, "the parameter structures");
    printf("  items: %s %s %s %s %s\n", PBEPARAM_it()->sname, PBE2PARAM_it()->sname,
           PBKDF2PARAM_it()->sname, PBMAC1PARAM_it()->sname, SCRYPT_PARAMS_it()->sname);
    ASN1_STRING_set(pbe->salt, SALT, 8);
    ASN1_INTEGER_set(pbe->iter, 2048);
    n = i2d_PBEPARAM(pbe, &der);
    hex("PBEPARAM", der, (size_t)n);
    p = der;
    PBEPARAM_free(pbe);
    pbe = d2i_PBEPARAM(NULL, &p, n);
    check(pbe != NULL && ASN1_INTEGER_get(pbe->iter) == 2048, "PBEPARAM decodes");
    OPENSSL_free(der);
    der = NULL;
    n = i2d_PBE2PARAM(pbe2, &der);
    printf("  empty PBE2PARAM: %d\n", n);
    if (n > 0)
        hex("PBE2PARAM", der, (size_t)n);
    else
        errors();
    OPENSSL_free(der);
    der = NULL;
    n = i2d_PBKDF2PARAM(kdf, &der);
    printf("  empty PBKDF2PARAM: %d\n", n);
    ERR_clear_error();
    OPENSSL_free(der);
    der = NULL;
    n = i2d_PBMAC1PARAM(mac, &der);
    printf("  empty PBMAC1PARAM: %d\n", n);
    if (n > 0) {
        hex("PBMAC1PARAM", der, (size_t)n);
        p = der;
        PBMAC1PARAM_free(mac);
        mac = d2i_PBMAC1PARAM(NULL, &p, n);
        check(mac != NULL, "PBMAC1PARAM decodes");
    }
    ERR_clear_error();
    OPENSSL_free(der);
    der = NULL;
    ASN1_STRING_set(sc->salt, SALT, 16);
    ASN1_INTEGER_set(sc->costParameter, 1024);
    ASN1_INTEGER_set(sc->blockSize, 8);
    ASN1_INTEGER_set(sc->parallelizationParameter, 1);
    n = i2d_SCRYPT_PARAMS(sc, &der);
    hex("SCRYPT_PARAMS", der, (size_t)n);
    p = der;
    SCRYPT_PARAMS_free(sc);
    sc = d2i_SCRYPT_PARAMS(NULL, &p, n);
    check(sc != NULL && sc->keyLength == NULL, "SCRYPT_PARAMS decodes");
    OPENSSL_free(der);
    der = NULL;
    {
        /* A PBES2 parameter decoded, then a PBKDF2 one. */
        X509_ALGOR *a = PKCS5_pbe2_set_iv(EVP_aes_128_cbc(), 1000, (unsigned char *)SALT, 16, IV, -1);
        PBE2PARAM *dec = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBE2PARAM), a->parameter);
        PBKDF2PARAM *k2 = dec == NULL ? NULL
                          : ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBKDF2PARAM), dec->keyfunc->parameter);

        check(k2 != NULL && ASN1_INTEGER_get(k2->iter) == 1000 && k2->prf != NULL
                  && OBJ_obj2nid(k2->prf->algorithm) == NID_hmacWithSHA256,
              "the PBES2 parameters decode to PBKDF2's");
        PBKDF2PARAM_free(k2);
        PBE2PARAM_free(dec);
        X509_ALGOR_free(a);
        PBE2PARAM_free(d2i_PBE2PARAM(NULL, &p, 0));
        PBKDF2PARAM_free(d2i_PBKDF2PARAM(NULL, &p, 0));
        ERR_clear_error();
    }
    PBEPARAM_free(pbe);
    PBE2PARAM_free(pbe2);
    PBKDF2PARAM_free(kdf);
    PBMAC1PARAM_free(mac);
    SCRYPT_PARAMS_free(sc);
}

/* The PBKDF2 parameters of a PBES2 AlgorithmIdentifier, changed, then used. */
static void bad_pbkdf2(const char *label, int keylen, int prf, int salt_not_octets)
{
    X509_ALGOR *a = PKCS5_pbe2_set_iv(EVP_aes_128_cbc(), 10, (unsigned char *)SALT, 16, IV, -1);
    PBE2PARAM *pbe2 = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBE2PARAM), a->parameter);
    PBKDF2PARAM *k = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBKDF2PARAM), pbe2->keyfunc->parameter);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int r;

    if (keylen) {
        k->keylength = ASN1_INTEGER_new();
        ASN1_INTEGER_set(k->keylength, keylen);
    }
    if (prf) {
        X509_ALGOR_free(k->prf);
        k->prf = X509_ALGOR_new();
        X509_ALGOR_set0(k->prf, OBJ_nid2obj(prf), V_ASN1_NULL, NULL);
    }
    if (salt_not_octets)
        ASN1_TYPE_set(k->salt, V_ASN1_NULL, NULL);
    ASN1_TYPE_free(pbe2->keyfunc->parameter);
    pbe2->keyfunc->parameter = NULL;
    ASN1_TYPE_pack_sequence(ASN1_ITEM_rptr(PBKDF2PARAM), k, &pbe2->keyfunc->parameter);
    r = EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, 1)
        && PKCS5_v2_PBE_keyivgen(ctx, "pw", 2, a->parameter, NULL, NULL, 1);
    printf("  %s (v2 keyivgen of the whole): %d\n", label, r);
    errors();
    PBKDF2PARAM_free(k);
    PBE2PARAM_free(pbe2);
    X509_ALGOR_free(a);
    EVP_CIPHER_CTX_free(ctx);
}

static void test_keyivgen(void)
{
    X509_ALGOR *a;
    EVP_CIPHER_CTX *ctx;
    int r;

    /* PBES2, directly. */
    a = PKCS5_pbe2_set_iv(EVP_aes_128_cbc(), 10, (unsigned char *)SALT, 16, IV, -1);
    ctx = EVP_CIPHER_CTX_new();
    r = PKCS5_v2_PBE_keyivgen(ctx, "pw", -1, a->parameter, NULL, NULL, 1);
    printf("  PKCS5_v2_PBE_keyivgen %d, key length %d\n", r, EVP_CIPHER_CTX_get_key_length(ctx));
    EVP_CIPHER_CTX_free(ctx);
    ctx = EVP_CIPHER_CTX_new();
    r = PKCS5_v2_PBE_keyivgen_ex(ctx, "pw", -1, a->parameter, NULL, NULL, 0, NULL, NULL);
    printf("  PKCS5_v2_PBE_keyivgen_ex %d\n", r);
    EVP_CIPHER_CTX_free(ctx);
    ctx = EVP_CIPHER_CTX_new();
    printf("  PKCS5_v2_PBE_keyivgen of no parameters %d\n",
           PKCS5_v2_PBE_keyivgen(ctx, "pw", -1, NULL, NULL, NULL, 1));
    errors();
    EVP_CIPHER_CTX_free(ctx);
    X509_ALGOR_free(a);

    /* scrypt, directly: its parameters inside the PBES2 ones. */
    a = PKCS5_pbe2_set_scrypt(EVP_aes_128_cbc(), SALT, 16, IV, 1024, 8, 1);
    {
        PBE2PARAM *pbe2 = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBE2PARAM), a->parameter);

        ctx = EVP_CIPHER_CTX_new();
        printf("  scrypt without a cipher set %d\n",
               PKCS5_v2_scrypt_keyivgen(ctx, "pw", 2, pbe2->keyfunc->parameter, NULL, NULL, 1));
        errors();
        EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, IV, 1);
        printf("  PKCS5_v2_scrypt_keyivgen %d\n",
               PKCS5_v2_scrypt_keyivgen(ctx, "pw", 2, pbe2->keyfunc->parameter, NULL, NULL, 1));
        EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, IV, 1);
        printf("  PKCS5_v2_scrypt_keyivgen_ex %d\n",
               PKCS5_v2_scrypt_keyivgen_ex(ctx, "pw", 2, pbe2->keyfunc->parameter, NULL, NULL, 1, NULL, NULL));
        EVP_CIPHER_CTX_free(ctx);
        PBE2PARAM_free(pbe2);
    }
    X509_ALGOR_free(a);

    /* PKCS#12's. */
    a = PKCS5_pbe_set(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, 100, SALT, 8);
    ctx = EVP_CIPHER_CTX_new();
    r = PKCS12_PBE_keyivgen(ctx, "pw", -1, a->parameter, EVP_des_ede3_cbc(), EVP_sha1(), 1);
    printf("  PKCS12_PBE_keyivgen %d\n", r);
    r = PKCS12_PBE_keyivgen_ex(ctx, "pw", 2, a->parameter, EVP_des_ede3_cbc(), EVP_sha256(), 1, NULL, NULL);
    printf("  PKCS12_PBE_keyivgen_ex %d\n", r);
    printf("  PKCS12_PBE_keyivgen without a cipher %d\n",
           PKCS12_PBE_keyivgen(ctx, "pw", -1, a->parameter, NULL, EVP_sha1(), 1));
    printf("  PKCS12_PBE_keyivgen of no parameters %d\n",
           PKCS12_PBE_keyivgen(ctx, "pw", -1, NULL, EVP_des_ede3_cbc(), EVP_sha1(), 1));
    errors();

    /* PBES1's (PBKDF1, the legacy provider's). */
    r = PKCS5_PBE_keyivgen(ctx, "pw", -1, a->parameter, EVP_aes_128_cbc(), EVP_sha1(), 1);
    printf("  PKCS5_PBE_keyivgen %d\n", r);
    errors();
    r = PKCS5_PBE_keyivgen_ex(ctx, "pw", -1, NULL, EVP_aes_128_cbc(), EVP_sha1(), 1, NULL, NULL);
    printf("  PKCS5_PBE_keyivgen_ex of no parameters %d\n", r);
    errors();
    EVP_CIPHER_CTX_free(ctx);
    X509_ALGOR_free(a);

    bad_pbkdf2("a key length that isn't the cipher's", 32, 0, 0);
    bad_pbkdf2("an unknown PRF", 0, NID_sha256, 0);
    bad_pbkdf2("a salt that isn't an OCTET STRING", 0, 0, 1);
    bad_pbkdf2("HMAC-SHA1 explicitly", 0, NID_hmacWithSHA1, 0);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    test_table();
    test_added();
    test_structures();
    test_types();
    test_keyivgen();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
