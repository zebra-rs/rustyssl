/*
 * Conformance test for reading keys from PEM (PEM_read_bio_PrivateKey(3), PEM_read_bio_PUBKEY,
 * PEM_read_bio_Parameters, their _ex and FILE forms, and the type-specific readers:
 * PEM_read_bio_RSAPrivateKey, _RSAPublicKey, _RSA_PUBKEY, _DSAPrivateKey, _DSA_PUBKEY,
 * _ECPrivateKey, _EC_PUBKEY, _ECPKParameters, _X509_PUBKEY, _PKCS8, _PKCS8_PRIV_KEY_INFO), in
 * TAP format: each kind of PEM block (PKCS#8, traditional, public keys, parameters) through each
 * reader that takes it and those that don't; several blocks in one input, read one after
 * another and past blocks of other kinds; a BIO that can't tell its position; replacing *x;
 * the password callback (never asked for an unencrypted key); and the errors.
 *
 * The keys are described through their parameters, as printing a provided key needs the
 * encoders (step 4.7c). Encrypted keys need step 4.7d. The fixtures were made with the
 * reference's openssl command.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

static const char dh_params_pem[] =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz\n"
    "+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a\n"
    "87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7\n"
    "YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi\n"
    "7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD\n"
    "ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==\n"
    "-----END DH PARAMETERS-----\n";

static const char dhx_params_pem[] =
    "-----BEGIN X9.42 DH PARAMETERS-----\n"
    "MIIBOwKBgQCBb2Uho9GIAGeai9LXHrV0LtizgNwfK8eX6oGwvsy/YKLS5QQ6ALpZ\n"
    "qhM3SzRYocu7R53oBVNzvlJw6mjYHKIBRCEYDaoawYEzSbTpw7frA9QzX+3vxUea\n"
    "52zuQiG1PLN8xW/z4EKmbHVVwAiPYLxgcyybqZcKiGmANpyaZFdOfwKBgFPgogMl\n"
    "GZbpMpaOSoYEExkajqV/zKRoOeCUAXSL+aIaLf5zrs5XCJxKvto/7PsbIW5o5dzQ\n"
    "svXIO9omuKVDD5fEo2SBtBPgtCSVbvZrE3et9tM0DqaYpb2cWCYxWjLpGs774AV+\n"
    "JN9r8i9QiTPegOCOMJWqJtvjiQcsnCcldYBiAhUAoduZR5GgdGZos2IoTBhTyDIp\n"
    "1OkwGwMVAOOu7fDjSazt44/Dj35eruooRwOIAgICOg==\n"
    "-----END X9.42 DH PARAMETERS-----\n";

static const char dsa_params_pem[] =
    "-----BEGIN DSA PARAMETERS-----\n"
    "MIIBHgKBgQCEsgSUHWY9Uu+iMCUrxRI/e4f+lYTQuFlxxLEckpYGCI+1gT7QRPWJ\n"
    "qd66rSqyX+711j58R83OzdaBV+WeHVQoJ9eM0tWhoVKE/MoxToSY3hrOZmCW16fN\n"
    "NteeNurwBVQINaVo/zzHnGRdLW0OyPyzoVmZNlJ609NlFW47sS0C2QIVANfepvd8\n"
    "WbSCUHkKeI3I53oZTusHAoGAXRr8BVo2HURkRRQk8UHXwBKuJOF/LN9CPmNNtx0Q\n"
    "77YOBLzUqIMTDfYykOTTrigUsO2iZgLjVBlQLJz0aoocxBoulW/Wq5Fr/k132j0k\n"
    "/VQMTGiByuWWNs/3+pqZ+mxhDyiS+EKBlazlmeVi3KEOUZq/wEC0zj10JDC73xLG\n"
    "JSw=\n"
    "-----END DSA PARAMETERS-----\n";

static const char dsa_trad_pem[] =
    "-----BEGIN DSA PRIVATE KEY-----\n"
    "MIIBugIBAAKBgQCEsgSUHWY9Uu+iMCUrxRI/e4f+lYTQuFlxxLEckpYGCI+1gT7Q\n"
    "RPWJqd66rSqyX+711j58R83OzdaBV+WeHVQoJ9eM0tWhoVKE/MoxToSY3hrOZmCW\n"
    "16fNNteeNurwBVQINaVo/zzHnGRdLW0OyPyzoVmZNlJ609NlFW47sS0C2QIVANfe\n"
    "pvd8WbSCUHkKeI3I53oZTusHAoGAXRr8BVo2HURkRRQk8UHXwBKuJOF/LN9CPmNN\n"
    "tx0Q77YOBLzUqIMTDfYykOTTrigUsO2iZgLjVBlQLJz0aoocxBoulW/Wq5Fr/k13\n"
    "2j0k/VQMTGiByuWWNs/3+pqZ+mxhDyiS+EKBlazlmeVi3KEOUZq/wEC0zj10JDC7\n"
    "3xLGJSwCgYAwAi2/NRvGHsaYDER+gr4rjAZtZtrrUAmorUNioTK1W7J/jc1ShF5k\n"
    "VR4WUa8CfWi1ND/+SKMKRMWO+hGGwIishQ4tcY4YDbA/LPqn52eO9RMDymonH8P0\n"
    "cvfG0Lv39JFgD5FmT1oGMvHwa0gmLgDIM2IUG5ay5mRkYfEvX9kvHwIUNd0XWu5I\n"
    "vFBsAL0uCzhzawkUFus=\n"
    "-----END DSA PRIVATE KEY-----\n";

static const char ec_pem[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNRqCK7qOS02hTBMC\n"
    "XN3o08M82cxxFFLVBBcuoHWAG5OhRANCAAQ/XaaTWrQ2Va3Z4jOTKS48esGf+hT7\n"
    "hRytZ1VbBw9A+de727HIiCtdw5bkzkpvIDgyvMwAlXoZtDYB4Mi2/r2x\n"
    "-----END PRIVATE KEY-----\n";

static const char ec_params_pem[] =
    "-----BEGIN EC PARAMETERS-----\n"
    "BggqhkjOPQMBBw==\n"
    "-----END EC PARAMETERS-----\n";

static const char ec_pub_pem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP12mk1q0NlWt2eIzkykuPHrBn/oU\n"
    "+4UcrWdVWwcPQPnXu9uxyIgrXcOW5M5KbyA4MrzMAJV6GbQ2AeDItv69sQ==\n"
    "-----END PUBLIC KEY-----\n";

static const char ec_trad_pem[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIDUagiu6jktNoUwTAlzd6NPDPNnMcRRS1QQXLqB1gBuToAoGCCqGSM49\n"
    "AwEHoUQDQgAEP12mk1q0NlWt2eIzkykuPHrBn/oU+4UcrWdVWwcPQPnXu9uxyIgr\n"
    "XcOW5M5KbyA4MrzMAJV6GbQ2AeDItv69sQ==\n"
    "-----END EC PRIVATE KEY-----\n";

static const char ed448_pub_pem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MEMwBQYDK2VxAzoAoLv4rLaYVBH8kWhktEHAbsxCB7m5OrAJbPk1mwk0ur4O0EkZ\n"
    "zrj9P+0bNtUGluy4I3VpqxUOZRAA\n"
    "-----END PUBLIC KEY-----\n";

static const char mldsa_pem[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MDQCAQAwCwYJYIZIAWUDBAMRBCKAIDQyuIo63Kf70TyE71Xyg9BQcJ0asbz4n7fv\n"
    "l7QljkAY\n"
    "-----END PRIVATE KEY-----\n";

static const char rsa_pem[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEArN0UodqeYEyl37Zh\n"
    "Q99y0AchT4vGgVr/onYhxCqBSv3H3it/453IWFZOTw1b5ze4koTKm8JkgazISV9O\n"
    "PFMAHQIDAQABAkEAkQPqohln0bubT8CNekYC6FeC71uADNaNK/pUO1+5FXHNIivr\n"
    "T65lUBVImMs+kEVlPIfxFjMsVD2jrUZIreMGoQIhAOGETOUW/JrWi3uNUPMZSQIY\n"
    "Tg7d9Hg1TB+eGFekD6oFAiEAxDrJ0Q1RDUFMpwFvalkReXwMLSVAsb0OW9Xgyi6V\n"
    "oTkCIG9Xp7Nv/vXfuWwd4Hq14DL1lwyGD16OSfBOWQxkRwuVAiEAqx4Q6+pO6d4t\n"
    "t9z6iaTOJkBUZfH8boJMySzDb8wb05ECIBxRkJHvJW32pwDp0qcAqNvOdPKyOila\n"
    "zyXMNv2OfG3d\n"
    "-----END PRIVATE KEY-----\n";

static const char rsa_pub_pem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKzdFKHanmBMpd+2YUPfctAHIU+LxoFa\n"
    "/6J2IcQqgUr9x94rf+OdyFhWTk8NW+c3uJKEypvCZIGsyElfTjxTAB0CAwEAAQ==\n"
    "-----END PUBLIC KEY-----\n";

static const char rsa_pub1_pem[] =
    "-----BEGIN RSA PUBLIC KEY-----\n"
    "MEgCQQCs3RSh2p5gTKXftmFD33LQByFPi8aBWv+idiHEKoFK/cfeK3/jnchYVk5P\n"
    "DVvnN7iShMqbwmSBrMhJX048UwAdAgMBAAE=\n"
    "-----END RSA PUBLIC KEY-----\n";

static const char rsa_trad_pem[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOwIBAAJBAKzdFKHanmBMpd+2YUPfctAHIU+LxoFa/6J2IcQqgUr9x94rf+Od\n"
    "yFhWTk8NW+c3uJKEypvCZIGsyElfTjxTAB0CAwEAAQJBAJED6qIZZ9G7m0/AjXpG\n"
    "AuhXgu9bgAzWjSv6VDtfuRVxzSIr60+uZVAVSJjLPpBFZTyH8RYzLFQ9o61GSK3j\n"
    "BqECIQDhhEzlFvya1ot7jVDzGUkCGE4O3fR4NUwfnhhXpA+qBQIhAMQ6ydENUQ1B\n"
    "TKcBb2pZEXl8DC0lQLG9DlvV4MoulaE5AiBvV6ezb/7137lsHeB6teAy9ZcMhg9e\n"
    "jknwTlkMZEcLlQIhAKseEOvqTuneLbfc+omkziZAVGXx/G6CTMksw2/MG9ORAiAc\n"
    "UZCR7yVt9qcA6dKnAKjbznTysjopWs8lzDb9jnxt3Q==\n"
    "-----END RSA PRIVATE KEY-----\n";

static const char sm2_pem[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgFaIfwRbbQsxNcRKE\n"
    "HlWJ+oQj5sppHihbPtvzFPKs1JmhRANCAAR+/61pbS9YT69zw83oMjP4QFfhUOrl\n"
    "nzk2YXpKZWPkD/pKM/8jghmdE5LdnQ/Qxev3+w5ts3iab82SJboefdy4\n"
    "-----END PRIVATE KEY-----\n";

static const char x25519_pem[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VuBCIEIKApDZJ7VJtpAnwGbscLe0Nog9Bd4vOPxef8DQ7P4fF3\n"
    "-----END PRIVATE KEY-----\n";

static int failures = 0;
static int number = 0;
static int asked = 0;

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

static int password(char *buf, int size, int rwflag, void *u)
{
    (void)buf;
    (void)size;
    (void)rwflag;
    (void)u;
    asked++;
    return -1;
}

static void describe(const char *label, EVP_PKEY *pk)
{
    unsigned char buf[4096];
    size_t len = 0;
    BIGNUM *bn = NULL;

    printf("  %s:", label);
    if (pk == NULL) {
        printf(" NULL\n");
        return;
    }
    printf(" %s id %d bits %d", EVP_PKEY_get0_type_name(pk) != NULL ? EVP_PKEY_get0_type_name(pk) : "-",
           EVP_PKEY_get_id(pk), EVP_PKEY_get_bits(pk));
    if (EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, buf, sizeof(buf),
                                        &len))
        printf(" enc %02x%02x%02x(%zu)", buf[0], buf[1], buf[2], len);
    else if (EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_N, &bn)
             || EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_PUB_KEY, &bn))
        printf(" pubbits %d", BN_num_bits(bn));
    BN_free(bn);
    bn = NULL;
    printf(" priv %d\n",
           EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_D, &bn)
           || EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_PRIV_KEY, &bn)
           || EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PRIV_KEY, buf, sizeof(buf),
                                              &len));
    BN_free(bn);
    ERR_clear_error();
}

struct pem {
    const char *name;
    const char *text;
};

static const struct pem pems[] = {
    { "PKCS#8 RSA", rsa_pem }, { "RSA PRIVATE KEY", rsa_trad_pem },
    { "RSA PUBLIC KEY", rsa_pub1_pem }, { "PUBLIC KEY (RSA)", rsa_pub_pem },
    { "DSA PRIVATE KEY", dsa_trad_pem }, { "DSA PARAMETERS", dsa_params_pem },
    { "PKCS#8 EC", ec_pem }, { "EC PRIVATE KEY", ec_trad_pem },
    { "PUBLIC KEY (EC)", ec_pub_pem }, { "EC PARAMETERS", ec_params_pem },
    { "DH PARAMETERS", dh_params_pem }, { "X9.42 DH PARAMETERS", dhx_params_pem },
    { "PKCS#8 X25519", x25519_pem }, { "PKCS#8 SM2", sm2_pem },
    { "PUBLIC KEY (ED448)", ed448_pub_pem }, { "PKCS#8 ML-DSA-44", mldsa_pem },
};

static BIO *mem(const char *text)
{
    return BIO_new_mem_buf(text, -1);
}

static void generic(const struct pem *p)
{
    BIO *b;
    EVP_PKEY *k;

    printf("# %s\n", p->name);
    b = mem(p->text);
    k = PEM_read_bio_PrivateKey(b, NULL, password, NULL);
    describe("PrivateKey", k);
    EVP_PKEY_free(k);
    BIO_free(b);
    errors();
    b = mem(p->text);
    k = PEM_read_bio_PUBKEY(b, NULL, password, NULL);
    describe("PUBKEY", k);
    EVP_PKEY_free(k);
    BIO_free(b);
    errors();
    b = mem(p->text);
    k = PEM_read_bio_Parameters(b, NULL);
    describe("Parameters", k);
    EVP_PKEY_free(k);
    BIO_free(b);
    errors();
}

/* Each type-specific reader on a PEM block. */
static void typed(const struct pem *p)
{
    BIO *b;
    void *v;
    EC_KEY *ec;

    printf("# %s, typed\n", p->name);
#define TRY(fn, freefn)                                    \
    b = mem(p->text);                                      \
    v = fn(b, NULL, password, NULL);                       \
    printf("  " #fn ": %s\n", v != NULL ? "read" : "-");   \
    freefn(v);                                             \
    BIO_free(b);                                           \
    ERR_clear_error();
    TRY(PEM_read_bio_RSAPrivateKey, RSA_free)
    TRY(PEM_read_bio_RSAPublicKey, RSA_free)
    TRY(PEM_read_bio_RSA_PUBKEY, RSA_free)
    TRY(PEM_read_bio_DSAPrivateKey, DSA_free)
    TRY(PEM_read_bio_DSA_PUBKEY, DSA_free)
    TRY(PEM_read_bio_ECPrivateKey, EC_KEY_free)
    TRY(PEM_read_bio_EC_PUBKEY, EC_KEY_free)
    TRY(PEM_read_bio_ECPKParameters, EC_GROUP_free)
    TRY(PEM_read_bio_X509_PUBKEY, X509_PUBKEY_free)
    TRY(PEM_read_bio_PKCS8, X509_SIG_free)
    TRY(PEM_read_bio_PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free)
#undef TRY
    b = mem(p->text);
    ec = PEM_read_bio_ECPrivateKey(b, NULL, password, NULL);
    if (ec != NULL)
        printf("  ec bits %d\n", EC_GROUP_get_degree(EC_KEY_get0_group(ec)));
    EC_KEY_free(ec);
    BIO_free(b);
    ERR_clear_error();
}

static void several(void)
{
    static char text[20000];
    BIO *b;
    EVP_PKEY *k, *x = NULL;
    int i;

    printf("# several blocks\n");
    snprintf(text, sizeof(text), "%s%s%s%s%s%s",
             "-----BEGIN FOO-----\nAAAA\n-----END FOO-----\n", ec_pub_pem,
             "junk between\n", rsa_trad_pem, dh_params_pem, x25519_pem);
    b = mem(text);
    for (i = 0; i < 5; i++) {
        k = PEM_read_bio_PrivateKey(b, NULL, password, NULL);
        describe("next private key", k);
        errors();
        EVP_PKEY_free(k);
    }
    BIO_free(b);
    b = mem(text);
    for (i = 0; i < 4; i++) {
        k = PEM_read_bio_PUBKEY(b, NULL, password, NULL);
        describe("next public key", k);
        errors();
        EVP_PKEY_free(k);
    }
    BIO_free(b);
    b = mem(text);
    for (i = 0; i < 3; i++) {
        k = PEM_read_bio_Parameters(b, &x);
        check(k == NULL || k == x, "Parameters into *x");
        describe("next parameters", k);
        errors();
    }
    EVP_PKEY_free(x);
    BIO_free(b);
    printf("  asked %d\n", asked);
}

/* A BIO over a pipe can't tell its position: the reading goes through a read buffer. */
static void unseekable(void)
{
    int fds[2];
    BIO *b;
    EVP_PKEY *k;

    printf("# a pipe\n");
    if (pipe(fds) != 0) {
        check(0, "pipe");
        return;
    }
    if (write(fds[1], ec_trad_pem, strlen(ec_trad_pem)) < 0
        || write(fds[1], rsa_pem, strlen(rsa_pem)) < 0) {
        check(0, "write");
    }
    close(fds[1]);
    b = BIO_new_fd(fds[0], BIO_CLOSE);
    printf("  tell %d\n", (int)BIO_tell(b));
    k = PEM_read_bio_PrivateKey(b, NULL, password, NULL);
    check(k != NULL, "EC from a pipe");
    describe("pipe 1", k);
    EVP_PKEY_free(k);
    k = PEM_read_bio_PrivateKey(b, NULL, password, NULL);
    describe("pipe 2", k);
    EVP_PKEY_free(k);
    errors();
    BIO_free(b);
}

static void files(void)
{
    FILE *f = tmpfile();
    EVP_PKEY *k;
    RSA *r;
    DSA *d;
    EC_KEY *e;
    void *v;

    printf("# files\n");
    if (f == NULL) {
        check(0, "tmpfile");
        return;
    }
    fputs(rsa_trad_pem, f);
    fputs(rsa_pub_pem, f);
    fputs(rsa_pub1_pem, f);
    fputs(dsa_trad_pem, f);
    fputs(ec_trad_pem, f);
    fputs(ec_pub_pem, f);
    fputs(ec_params_pem, f);
    fputs(rsa_pem, f);
    rewind(f);
    k = PEM_read_PrivateKey(f, NULL, password, NULL);
    describe("PEM_read_PrivateKey", k);
    EVP_PKEY_free(k);
    k = PEM_read_PUBKEY(f, NULL, password, NULL);
    describe("PEM_read_PUBKEY", k);
    EVP_PKEY_free(k);
    r = PEM_read_RSAPublicKey(f, NULL, password, NULL);
    check(r != NULL, "PEM_read_RSAPublicKey");
    RSA_free(r);
    d = PEM_read_DSAPrivateKey(f, NULL, password, NULL);
    check(d != NULL, "PEM_read_DSAPrivateKey");
    DSA_free(d);
    e = PEM_read_ECPrivateKey(f, NULL, password, NULL);
    check(e != NULL, "PEM_read_ECPrivateKey");
    EC_KEY_free(e);
    e = PEM_read_EC_PUBKEY(f, NULL, password, NULL);
    check(e != NULL, "PEM_read_EC_PUBKEY");
    EC_KEY_free(e);
    v = PEM_read_ECPKParameters(f, NULL, password, NULL);
    check(v != NULL, "PEM_read_ECPKParameters");
    EC_GROUP_free(v);
    k = PEM_read_PrivateKey_ex(f, NULL, password, NULL, NULL, "provider=default");
    describe("PEM_read_PrivateKey_ex", k);
    EVP_PKEY_free(k);
    errors();
    rewind(f);
    r = PEM_read_RSAPrivateKey(f, NULL, password, NULL);
    check(r != NULL, "PEM_read_RSAPrivateKey");
    RSA_free(r);
    r = PEM_read_RSA_PUBKEY(f, NULL, password, NULL);
    check(r != NULL, "PEM_read_RSA_PUBKEY");
    RSA_free(r);
    v = PEM_read_X509_PUBKEY(f, NULL, password, NULL);
    check(v != NULL, "PEM_read_X509_PUBKEY");
    X509_PUBKEY_free(v);
    v = PEM_read_DSA_PUBKEY(f, NULL, password, NULL);
    check(v == NULL, "PEM_read_DSA_PUBKEY of an RSA key");
    errors();
    rewind(f);
    k = PEM_read_PUBKEY_ex(f, NULL, password, NULL, NULL, NULL);
    describe("PEM_read_PUBKEY_ex", k);
    EVP_PKEY_free(k);
    v = PEM_read_PKCS8_PRIV_KEY_INFO(f, NULL, password, NULL);
    check(v != NULL, "PEM_read_PKCS8_PRIV_KEY_INFO");
    PKCS8_PRIV_KEY_INFO_free(v);
    v = PEM_read_PKCS8(f, NULL, password, NULL);
    check(v == NULL, "PEM_read_PKCS8 without one");
    errors();
    fclose(f);
}

static void replacing(void)
{
    BIO *b = mem(ec_pem);
    EVP_PKEY *x = EVP_PKEY_new(), *k;
    RSA *r = RSA_new(), *r2;

    printf("# replacing\n");
    k = PEM_read_bio_PrivateKey_ex(b, &x, password, NULL, NULL, NULL);
    check(k != NULL && k == x, "PrivateKey into *x");
    BIO_free(b);
    b = mem(ec_pub_pem);
    k = PEM_read_bio_PUBKEY_ex(b, &x, password, NULL, NULL, NULL);
    check(k != NULL && k == x, "PUBKEY into *x");
    describe("x", x);
    EVP_PKEY_free(x);
    BIO_free(b);
    b = mem(rsa_trad_pem);
    r2 = PEM_read_bio_RSAPrivateKey(b, &r, password, NULL);
    check(r2 != NULL && r2 == r, "RSAPrivateKey into *x");
    RSA_free(r);
    BIO_free(b);
    b = mem("-----BEGIN PRIVATE KEY-----\nMAMCAQA=\n-----END PRIVATE KEY-----\n");
    k = PEM_read_bio_PrivateKey(b, NULL, password, NULL);
    check(k == NULL, "a broken PKCS#8");
    errors();
    BIO_free(b);
    b = mem("-----BEGIN RSA PRIVATE KEY-----\nMAMCAQA=\n-----END RSA PRIVATE KEY-----\n");
    k = PEM_read_bio_PrivateKey(b, NULL, password, NULL);
    check(k == NULL, "a broken traditional key");
    errors();
    BIO_free(b);
    b = mem(ec_params_pem);
    k = PEM_read_bio_Parameters_ex(b, NULL, NULL, "provider=default");
    check(k != NULL, "Parameters_ex");
    describe("params ex", k);
    EVP_PKEY_free(k);
    BIO_free(b);
    b = mem("");
    k = PEM_read_bio_PrivateKey(b, NULL, password, NULL);
    check(k == NULL, "nothing");
    errors();
    BIO_free(b);
    printf("  asked %d\n", asked);
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(pems) / sizeof(pems[0]); i++)
        generic(&pems[i]);
    for (i = 0; i < sizeof(pems) / sizeof(pems[0]); i++)
        typed(&pems[i]);
    several();
    unseekable();
    files();
    replacing();
    printf("1..%d\n", number);
    return failures != 0;
}
