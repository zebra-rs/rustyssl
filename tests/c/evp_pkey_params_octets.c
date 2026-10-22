/*
 * Conformance test for octet-string parameters set on a context whose key method is the
 * application's (EVP_PKEY_CTX_set_params(3) translated to EVP_PKEY_METHOD ctrls), in TAP
 * format. The method logs each ctrl's command, length and octets, and, like OpenSSL's own
 * methods, keeps the octets of the commands that take them over ("set0": the KDF UKMs and the
 * OAEP label), freeing them when replaced or when its context goes; the others' octets it only
 * reads ("set1": the HKDF and TLS PRF inputs, passwords, salts, distinguishing IDs, MAC keys).
 * Each parameter is set with the method succeeding and failing, so the library must free the
 * copy it makes except when a set0 command succeeds; ASan and LeakSanitizer check that there.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
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

/* What the method's ctrl answers, and the octets a set0 command handed it. */
static int answer = 1;
static void *kept = NULL;

static int takes_octets(int cmd)
{
    return cmd == EVP_PKEY_CTRL_DH_KDF_UKM || cmd == EVP_PKEY_CTRL_EC_KDF_UKM
        || cmd == EVP_PKEY_CTRL_RSA_OAEP_LABEL;
}

static int pm_ctrl(EVP_PKEY_CTX *ctx, int cmd, int p1, void *p2)
{
    int i;

    (void)ctx;
    printf("  ctrl 0x%x, %d octets:", cmd, p1);
    if (p2 != NULL)
        for (i = 0; i < p1; i++)
            printf("%02x", ((unsigned char *)p2)[i]);
    printf(" -> %d\n", answer);
    if (answer > 0 && takes_octets(cmd)) {
        OPENSSL_free(kept);
        kept = p2;
    }
    return answer;
}

static void pm_cleanup(EVP_PKEY_CTX *ctx)
{
    (void)ctx;
    OPENSSL_free(kept);
    kept = NULL;
}

static int pm_init(EVP_PKEY_CTX *ctx)
{
    (void)ctx;
    return 1;
}

static int pm_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
    (void)ctx, (void)out, (void)outlen, (void)in, (void)inlen;
    return 0;
}

static int pm_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
    (void)ctx, (void)key, (void)keylen;
    return 0;
}

static int pm_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
    const unsigned char *tbs, size_t tbslen)
{
    (void)ctx, (void)sig, (void)siglen, (void)tbs, (void)tbslen;
    return 0;
}

static int pm_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pk)
{
    (void)ctx, (void)pk;
    return 0;
}

/* Sets one octet-string parameter of `len` octets with the method answering 1, then 0. */
static void set_octets(EVP_PKEY_CTX *c, const char *key, size_t len)
{
    unsigned char octets[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    OSSL_PARAM params[2];
    char what[80];
    int r;

    for (answer = 1; answer >= 0; answer--) {
        params[0] = OSSL_PARAM_construct_octet_string(key, octets, len);
        params[1] = OSSL_PARAM_construct_end();
        r = EVP_PKEY_CTX_set_params(c, params);
        snprintf(what, sizeof(what), "\"%s\" of %d octets, the method answering %d: %d", key,
            (int)len, answer, r);
        check(r == (answer > 0), what);
        ERR_clear_error();
    }
}

static EVP_PKEY_METHOD *method(int id)
{
    EVP_PKEY_METHOD *m = EVP_PKEY_meth_new(id, 0);

    EVP_PKEY_meth_set_ctrl(m, pm_ctrl, NULL);
    EVP_PKEY_meth_set_cleanup(m, pm_cleanup);
    EVP_PKEY_meth_set_encrypt(m, pm_init, pm_encrypt);
    EVP_PKEY_meth_set_derive(m, pm_init, pm_derive);
    EVP_PKEY_meth_set_sign(m, pm_init, pm_sign);
    EVP_PKEY_meth_set_keygen(m, pm_init, pm_keygen);
    check(EVP_PKEY_meth_add0(m) == 1, "EVP_PKEY_meth_add0");
    return m;
}

int main(void)
{
    static const char *const set1[] = {
        OSSL_KDF_PARAM_SALT, OSSL_KDF_PARAM_KEY, OSSL_KDF_PARAM_INFO, OSSL_KDF_PARAM_SECRET,
        OSSL_KDF_PARAM_SEED, OSSL_KDF_PARAM_PASSWORD,
    };
    EVP_PKEY_METHOD *rsa = method(EVP_PKEY_RSA);
    EVP_PKEY_METHOD *ec = method(EVP_PKEY_EC);
    EVP_PKEY_METHOD *dhx = method(EVP_PKEY_DHX);
    EVP_PKEY_CTX *c;
    size_t i;

    printf("# the OAEP label (set0), encrypting with RSA's method\n");
    c = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    check(c != NULL && EVP_PKEY_encrypt_init(c) == 1, "an RSA context, encrypting");
    set_octets(c, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, 5);
    set_octets(c, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, 0);
    EVP_PKEY_CTX_free(c);

    printf("# the UKM (set0) and the KDF inputs (set1), deriving with EC's method\n");
    c = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    check(c != NULL && EVP_PKEY_derive_init(c) == 1, "an EC context, deriving");
    set_octets(c, OSSL_EXCHANGE_PARAM_KDF_UKM, 8);
    set_octets(c, OSSL_EXCHANGE_PARAM_KDF_UKM, 0);
    for (i = 0; i < sizeof(set1) / sizeof(set1[0]); i++)
        set_octets(c, set1[i], 3);
    EVP_PKEY_CTX_free(c);

    printf("# the UKM (set0), deriving with DHX's method\n");
    c = EVP_PKEY_CTX_new_id(EVP_PKEY_DHX, NULL);
    check(c != NULL && EVP_PKEY_derive_init(c) == 1, "a DHX context, deriving");
    set_octets(c, OSSL_EXCHANGE_PARAM_KDF_UKM, 4);
    EVP_PKEY_CTX_free(c);

    printf("# the distinguishing ID (set1), signing with EC's method\n");
    c = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    check(c != NULL && EVP_PKEY_sign_init(c) == 1, "an EC context, signing");
    set_octets(c, OSSL_PKEY_PARAM_DIST_ID, 6);
    EVP_PKEY_CTX_free(c);

    printf("# the MAC key (set1), generating with EC's method\n");
    c = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    check(c != NULL && EVP_PKEY_keygen_init(c) == 1, "an EC context, generating");
    set_octets(c, OSSL_PKEY_PARAM_PRIV_KEY, 7);
    EVP_PKEY_CTX_free(c);

    check(EVP_PKEY_meth_remove(rsa) == 1 && EVP_PKEY_meth_remove(ec) == 1
            && EVP_PKEY_meth_remove(dhx) == 1,
        "EVP_PKEY_meth_remove");
    EVP_PKEY_meth_free(rsa);
    EVP_PKEY_meth_free(ec);
    EVP_PKEY_meth_free(dhx);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
