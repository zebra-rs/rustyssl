/*
 * Conformance test for Netscape's signed public keys and certificate sequences
 * (NETSCAPE_SPKI_new(3), NETSCAPE_SPKI_b64_decode, NETSCAPE_SPKI_b64_encode, NETSCAPE_SPKI_sign,
 * NETSCAPE_SPKI_verify, NETSCAPE_SPKI_print, NETSCAPE_CERT_SEQUENCE_new), in TAP format: the
 * reference tool's SPKAC decoded, printed, verified, and encoded again; one built, signed with
 * RSA (deterministically), and checked; bad base64; and a certificate sequence through DER and
 * PEM.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
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

static const char SPKAC[] = "MIIBPzCBqTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtNHu/NHcf1SOFsySbXH/pxAgh7RB7bEOk42SJ2t3rJlI3WJSa4WSUbHzpmtuevRwWbDKhfiPadeLEn2N7LA200oYWM/M2P2YpwesO3WSaL7Z3Gl7bPVgCYY9rveW7yGE/R68cMUbReTd1eF/70jx1pCatt6uwa3VtHvC6PBHbXUCAwEAARYFaGVsbG8wDQYJKoZIhvcNAQEEBQADgYEAgqdtV1nBn5qpKCXX4m7+FOscXKeseehyaiPEpzild/SPkbkAr5nIyouvM2JG9Akw5P/72NnEykNCVtz6mU8qXiqdJiIky2XxswAmPz5ssdTdtL2B2U+XGaVcW1ytkMYH8PkXXFupR2yFWPtNxoZ0GEomepZARMCL29/W479c7FQ=";

static const char KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALTR7vzR3H9UjhbM\n"
    "km1x/6cQIIe0Qe2xDpONkidrd6yZSN1iUmuFklGx86Zrbnr0cFmwyoX4j2nXixJ9\n"
    "jeywNtNKGFjPzNj9mKcHrDt1kmi+2dxpe2z1YAmGPa73lu8hhP0evHDFG0Xk3dXh\n"
    "f+9I8daQmrbersGt1bR7wujwR211AgMBAAECgYAqXBfpoFxQdAWJb8lJ3G/wukV0\n"
    "pRTg0x7AEGVR2MpDY/F+836tc7AwdUjIDtjl8wey60i2k+E9AWKyJTmvXiSpe3qa\n"
    "BFjyVxwkSeGucWcXWz86ZxVYCL9teAkfj8Qwh1HEu0Yu9jiKXstkdx7p2hejGkv4\n"
    "9lidB0UCX6m2jpNeYQJBAPDVRXavcq8KlCIjF1Ew3hZSnoUeBnNDtV8BKF5cod2l\n"
    "Cjbpb8yuk09rNEHXg+Zoo1nThc2TLzgeM2kWrIrFxkkCQQDANSCr9ATx41bgkTkI\n"
    "l8Dxr2p5TbmC3ra1BkZBIASsbyWHJfRO0oA0inihOA1TRVUhasdQNc+oBb7sWphV\n"
    "Zn3NAkBoKjajQPt/jjnIEhlxuos0aIO72+K6VBzMfLmzJqm0LkAexBThGNkKTroJ\n"
    "iGe6bqPIpF6JLhIMWbOuzmnOlABRAkAD9xSdd4NCmjYIm/ZZPwgz9DJ2Hixdjsqm\n"
    "IWMBpO9zvzc++oF3vs/2RYUHjmh3904ySkmiVfnatYOizJun511hAkEAmERMHVCW\n"
    "FockGCsXmm84RRgXct4bv3JhUltBl9zf10BNYtF6Dw1oNJCPmQOt+5V4zUBZ2amD\n"
    "AGdfRBcHqbXOfQ==\n"
    "-----END PRIVATE KEY-----\n";

static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBXzCCAQSgAwIBAgIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowFTETMBEGA1UEAwwK\n"
    "UHVycG9zZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBWjWIRih6WIPZH9\n"
    "yyM92OMGrP0IA1y4D9r8UFgmiVhQ2yk9byExM1oXjHDR9dt6q1lEA9jpqNZ3bnJc\n"
    "62luj0mjRTBDMBIGA1UdEwEB/wQIMAYBAf8CAQIwDgYDVR0PAQH/BAQDAgEGMB0G\n"
    "A1UdDgQWBBQ0lsw8dOxP91kYhXzdnHH3mpLhNTAKBggqhkjOPQQDAgNJADBGAiEA\n"
    "kj2rk1mD4ySwCZoobiJ9MdfoCxdvK6omAzn5TXDujQ8CIQD+Ns1YYa12PfODJ3Fy\n"
    "twUt2FgdVL8c5pnN7he1zcvVCQ==\n"
    "-----END CERTIFICATE-----\n";

static const char SERVER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBvjCCAWSgAwIBAgIBBzAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowETEPMA0GA1UEAwwG\n"
    "c2VydmVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEJmU/wZeX86icApfkgw1\n"
    "Vpwhan4WCwtpPNtvP4/ErxhATPYxrjMQqlv00olStwd324fXxDMKZEuBAO3ucJmK\n"
    "lqOBqDCBpTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggr\n"
    "BgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFCQZP0LkcWQzli7s4uZl9Y/W6N11\n"
    "MB8GA1UdIwQYMBaAFDSWzDx07E/3WRiFfN2ccfeakuE1MBYGA1UdEQQPMA2CC3d3\n"
    "dy5leGFtcGxlMBEGCWCGSAGG+EIBAQQEAwIGwDAKBggqhkjOPQQDAgNIADBFAiEA\n"
    "xpq7e4/INYzqjxGr0AfLJor5LyrRKl9ea0cR7htWCh4CIECo8YuCNq4t5xl6eRH1\n"
    "xspB6WRZ5yKS6EC7pnA7E+4o\n"
    "-----END CERTIFICATE-----\n";

static void print(NETSCAPE_SPKI *spki)
{
    BIO *mem = BIO_new(BIO_s_mem());
    char *data;
    long n;

    printf("  print %d\n", NETSCAPE_SPKI_print(mem, spki));
    n = BIO_get_mem_data(mem, &data);
    fwrite(data, 1, (size_t)n, stdout);
    BIO_free(mem);
}

static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

/* Each item: a new value encoded through it. */
static void items(void)
{
    const struct {
        const char *name;
        const ASN1_ITEM *it;
    } list[] = {
        {"NETSCAPE_SPKI", ASN1_ITEM_rptr(NETSCAPE_SPKI)},
        {"NETSCAPE_SPKAC", ASN1_ITEM_rptr(NETSCAPE_SPKAC)},
        {"NETSCAPE_CERT_SEQUENCE", ASN1_ITEM_rptr(NETSCAPE_CERT_SEQUENCE)},
    };
    size_t i;

    printf("# items\n");
    for (i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        ASN1_VALUE *v = ASN1_item_new(list[i].it);
        unsigned char *der = NULL;
        int len = ASN1_item_i2d(v, &der, list[i].it);

        printf("  %s: %d\n", list[i].name, len);
        OPENSSL_free(der);
        ASN1_item_free(v, list[i].it);
    }
    ERR_clear_error();
}

int main(void)
{
    BIO *b = BIO_new_mem_buf(KEY_PEM, -1);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL), *pub;
    NETSCAPE_SPKI *spki = NETSCAPE_SPKI_b64_decode(SPKAC, -1), *mine, *back;
    char *b64;

    BIO_free(b);
    printf("# the tool's SPKAC\n");
    check(spki != NULL, "decoded");
    print(spki);
    pub = NETSCAPE_SPKI_get_pubkey(spki);
    check(pub != NULL && EVP_PKEY_eq(pub, key) == 1, "its key");
    check(NETSCAPE_SPKI_verify(spki, pub) == 1, "verifies");
    b64 = NETSCAPE_SPKI_b64_encode(spki);
    check(b64 != NULL && strcmp(b64, SPKAC) == 0, "encodes back the same");
    OPENSSL_free(b64);
    back = NETSCAPE_SPKI_b64_decode(SPKAC, 40);
    check(back == NULL, "cut short");
    errors();
    back = NETSCAPE_SPKI_b64_decode("not base64!", 0);
    check(back == NULL, "bad base64");
    errors();

    printf("# built\n");
    mine = NETSCAPE_SPKI_new();
    check(NETSCAPE_SPKI_set_pubkey(mine, key) == 1, "key set");
    ASN1_STRING_set(mine->spkac->challenge, "challenge me", -1);
    printf("  signed %d\n", NETSCAPE_SPKI_sign(mine, key, EVP_sha256()));
    check(NETSCAPE_SPKI_verify(mine, pub) == 1, "verifies");
    b64 = NETSCAPE_SPKI_b64_encode(mine);
    printf("  b64 %s\n", b64);
    back = NETSCAPE_SPKI_b64_decode(b64, 0);
    check(back != NULL && NETSCAPE_SPKI_verify(back, pub) == 1, "decoded and verified");
    print(back);
    NETSCAPE_SPKI_free(back);
    OPENSSL_free(b64);
    mine->spkac->challenge->data[0] = 'C';
    check(NETSCAPE_SPKI_verify(mine, pub) == 0, "a changed challenge fails");
    errors();
    {
        NETSCAPE_SPKAC *ac = NETSCAPE_SPKAC_new();
        unsigned char *der = NULL;
        int len = i2d_NETSCAPE_SPKAC(mine->spkac, &der);
        const unsigned char *q = der;

        NETSCAPE_SPKAC_free(ac);
        ac = d2i_NETSCAPE_SPKAC(NULL, &q, len);
        check(ac != NULL, "the PublicKeyAndChallenge decoded");
        NETSCAPE_SPKAC_free(ac);
        OPENSSL_free(der);
        der = NULL;
        len = i2d_NETSCAPE_SPKI(mine, &der);
        q = der;
        back = d2i_NETSCAPE_SPKI(NULL, &q, len);
        check(back != NULL, "the SPKI decoded");
        NETSCAPE_SPKI_free(back);
        OPENSSL_free(der);
    }
    {
        NETSCAPE_SPKI *empty = NETSCAPE_SPKI_new();

        printf("  empty: key %d, encoding %d\n", NETSCAPE_SPKI_get_pubkey(empty) != NULL, i2d_NETSCAPE_SPKI(empty, NULL));
        errors();
        NETSCAPE_SPKI_free(empty);
    }

    printf("# certificate sequence\n");
    {
        NETSCAPE_CERT_SEQUENCE *seq = NETSCAPE_CERT_SEQUENCE_new(), *again;
        unsigned char *der = NULL;
        const unsigned char *q;
        int len;
        BIO *mem;

        printf("  type %d, certs %d\n", OBJ_obj2nid(seq->type), seq->certs == NULL ? -1 : sk_X509_num(seq->certs));
        len = i2d_NETSCAPE_CERT_SEQUENCE(seq, &der);
        printf("  empty: %d\n", len);
        OPENSSL_free(der);
        seq->certs = sk_X509_new_null();
        sk_X509_push(seq->certs, read_cert(CA_PEM));
        sk_X509_push(seq->certs, read_cert(SERVER_PEM));
        der = NULL;
        len = i2d_NETSCAPE_CERT_SEQUENCE(seq, &der);
        q = der;
        again = d2i_NETSCAPE_CERT_SEQUENCE(NULL, &q, len);
        check(again != NULL && sk_X509_num(again->certs) == 2, "decoded with two certificates");
        NETSCAPE_CERT_SEQUENCE_free(again);
        OPENSSL_free(der);
        mem = BIO_new(BIO_s_mem());
        check(PEM_write_bio_NETSCAPE_CERT_SEQUENCE(mem, seq) == 1, "PEM written");
        again = PEM_read_bio_NETSCAPE_CERT_SEQUENCE(mem, NULL, NULL, NULL);
        check(again != NULL && sk_X509_num(again->certs) == 2, "PEM read back");
        NETSCAPE_CERT_SEQUENCE_free(again);
        BIO_free(mem);
        {
            FILE *fp = tmpfile();

            if (fp != NULL) {
                check(PEM_write_NETSCAPE_CERT_SEQUENCE(fp, seq) == 1, "FILE written");
                rewind(fp);
                again = PEM_read_NETSCAPE_CERT_SEQUENCE(fp, NULL, NULL, NULL);
                check(again != NULL, "FILE read back");
                NETSCAPE_CERT_SEQUENCE_free(again);
                fclose(fp);
            }
        }
        NETSCAPE_CERT_SEQUENCE_free(seq);
    }

    NETSCAPE_SPKI_free(spki);
    NETSCAPE_SPKI_free(mine);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(key);
    items();
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
