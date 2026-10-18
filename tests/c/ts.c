/*
 * Conformance test for time stamping (TS_REQ_new(3), TS_RESP_CTX_new(3), TS_RESP_verify_response(3),
 * TS_VERIFY_CTX_new(3), TS_CONF_set_*, and the print functions): the reference tool's request,
 * reply, and token read, printed, re-encoded, and verified; requests, TSTInfos, and statuses
 * built field by field and compared by their DER; responses made here with fixed times and
 * serials, printed, and verified; rejections (bad requests, digests, policies, extensions)
 * and verification failures (signature, nonce, policy, imprint, data) with their error
 * entries and texts; and a TSA set up from a configuration file.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static int failures = 0;
static int number = 0;
static BIO *out;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The error queue: each entry's library and reason, and its text when it has one. */
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

/*
 * Made with the reference's openssl tool: the EC root of the CMS and OCSP tests (ca.pem), its
 * RSA end entity with no extended key usage (rsa.pem), and an RSA TSA with a critical
 * timeStamping usage, a key identifier, and DNS:tsa.example (tsa.pem, serial 0x88); ts -query
 * of msg.txt with SHA-256, -cert, -no_nonce, and -tspolicy 1.2.3.4.1 (req.der), and without
 * -cert or a policy (req_nocert.der); and ts -reply answering req.der with accuracy 1 s
 * 500 ms 100 us, 3 digits, ordering, and the TSA's name (resp.der, and its token, token.der).
 */
static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBlDCCATqgAwIBAgIUQs8ZErMWPIenaD/uOzlwoxywlnkwCgYIKoZIzj0EAwIw\n"
    "JzEQMA4GA1UECgwHRXhhbXBsZTETMBEGA1UEAwwKU01JTUUgUm9vdDAgFw0yNjEw\n"
    "MTcyMjE3MTVaGA8yMTI2MDkyMzIyMTcxNVowJzEQMA4GA1UECgwHRXhhbXBsZTET\n"
    "MBEGA1UEAwwKU01JTUUgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB/A\n"
    "LTVcONUfVNJW+I8m+pFZZv2E1nueaotIxtyuCuU7vgtX+B5ipx7qLqbCpXc7uTw5\n"
    "+VUU035P3665HlhlE0+jQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD\n"
    "AgEGMB0GA1UdDgQWBBR1tdNQedtUtDillwMhWwDwHWigRTAKBggqhkjOPQQDAgNI\n"
    "ADBFAiEAmd7Q2H6po4/J8cf3XXtIff8eg2y6AK2SNxOz6Q0JHJkCIHMhga44JyLn\n"
    "b8qaJPtNes6gug+NZqD0WNA58tYqngmQ\n"
    "-----END CERTIFICATE-----\n";

static const char RSA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICaTCCAg+gAwIBAgIBZTAKBggqhkjOPQQDAjAnMRAwDgYDVQQKDAdFeGFtcGxl\n"
    "MRMwEQYDVQQDDApTTUlNRSBSb290MCAXDTI2MTAxNzIyMTcxNVoYDzIxMjYwOTIz\n"
    "MjIxNzE1WjAUMRIwEAYDVQQDDAlTTUlNRSByc2EwggEiMA0GCSqGSIb3DQEBAQUA\n"
    "A4IBDwAwggEKAoIBAQCTF3DR1lrRhjc9u1jEVzgYclC+L3X6x88IGgzCdKPaNwhL\n"
    "QlWsDXmluMlqa0Tvb4Ob392Ufxmkn1W30XhYTypLjGOL5bksoiGDiQZn1ovA/Gnd\n"
    "mCq1J47pSNhz6SL1/uOZvmj6vdpr0p26BtqGCr1hXowWKIvmJGdr5JV4fPgRXO/n\n"
    "FCqYvwzm0hxCCWF+cpACJgB/NkB54nSqeYdRhwJvU9D8glmTuwO4UY035FDYcYKa\n"
    "jiIMtnJnGlo/IJMEyI1+lQGWWFOSCPhld5B3etvb8Yz+LC51w4jlroXJw7q1HmTG\n"
    "i2IR4fugKC8lLugmbONeFXjeCawPRVhZPR2/1AHNAgMBAAGjcjBwMAkGA1UdEwQC\n"
    "MAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMEMB0GA1UdDgQW\n"
    "BBQTEOssjmFffw9DHdfYXG+4qmqEvDAfBgNVHSMEGDAWgBR1tdNQedtUtDillwMh\n"
    "WwDwHWigRTAKBggqhkjOPQQDAgNIADBFAiAJ6N2sNNdSNa+IDpskcT9WoVcNF5gK\n"
    "YOWbDzbJFIJTZQIhAOTlwtgT1PhcURW6WGxpnKHrkg8l+RbzadUEJJAksG/w\n"
    "-----END CERTIFICATE-----\n";

static const char TSA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICmTCCAj+gAwIBAgICAIgwCgYIKoZIzj0EAwIwJzEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTETMBEGA1UEAwwKU01JTUUgUm9vdDAgFw0yNjEwMTgwMjQ2MzFaGA8yMTI2MDky\n"
    "NDAyNDYzMVowJjERMA8GA1UEAwwIVGVzdCBUU0ExETAPBgNVBAoMCHJ1c3R5c3Ns\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1O/PeXxUz+lRqkNTLCF0\n"
    "pUvIRC8/c0ozNeX9VAEOZ2ggi99xq644kyRtRrUKTo/ekD9iWJFeD18JVhUBUPTG\n"
    "cg2evi8m4NrJ8qWKE47OLpnb0B1GTO/xK+eKH5tMJsNKkQV/qaGpTE9hQxKlfBwS\n"
    "BWdwwps+SnZY7qZTsSRD0/l7rj1lhOu5qLlJZkssxxRqN1qF+pFXzj1DUfuiMFMX\n"
    "b6gfJro/SrJxziMOIWqHCifIrxLvnGodVhBCz6x2B5PuogLfyKjfxrULTNNuq+WF\n"
    "FyrdyqXNKjyeeOyOg0b9tKB9BJVALLe1ofSe2ZEeLPbUJ95TL2KANJ/aHNMqkigl\n"
    "TwIDAQABo4GOMIGLMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB\n"
    "/wQMMAoGCCsGAQUFBwMIMB0GA1UdDgQWBBSv82qjGJ9iBmWKO/8X1UN8RlXoLzAf\n"
    "BgNVHSMEGDAWgBR1tdNQedtUtDillwMhWwDwHWigRTAWBgNVHREEDzANggt0c2Eu\n"
    "ZXhhbXBsZTAKBggqhkjOPQQDAgNIADBFAiA9rnO3qvI84NSR5xUQUeiB+rN/iGdQ\n"
    "urwjelmA9mfBKQIhAO2yGxBf+mpnnfkxvaC5gV2cmBlTy9wHvfmFT3aianFQ\n"
    "-----END CERTIFICATE-----\n";

static const char CA_PEM_AND_RSA[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBlDCCATqgAwIBAgIUQs8ZErMWPIenaD/uOzlwoxywlnkwCgYIKoZIzj0EAwIw\n"
    "JzEQMA4GA1UECgwHRXhhbXBsZTETMBEGA1UEAwwKU01JTUUgUm9vdDAgFw0yNjEw\n"
    "MTcyMjE3MTVaGA8yMTI2MDkyMzIyMTcxNVowJzEQMA4GA1UECgwHRXhhbXBsZTET\n"
    "MBEGA1UEAwwKU01JTUUgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB/A\n"
    "LTVcONUfVNJW+I8m+pFZZv2E1nueaotIxtyuCuU7vgtX+B5ipx7qLqbCpXc7uTw5\n"
    "+VUU035P3665HlhlE0+jQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD\n"
    "AgEGMB0GA1UdDgQWBBR1tdNQedtUtDillwMhWwDwHWigRTAKBggqhkjOPQQDAgNI\n"
    "ADBFAiEAmd7Q2H6po4/J8cf3XXtIff8eg2y6AK2SNxOz6Q0JHJkCIHMhga44JyLn\n"
    "b8qaJPtNes6gug+NZqD0WNA58tYqngmQ\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIICaTCCAg+gAwIBAgIBZTAKBggqhkjOPQQDAjAnMRAwDgYDVQQKDAdFeGFtcGxl\n"
    "MRMwEQYDVQQDDApTTUlNRSBSb290MCAXDTI2MTAxNzIyMTcxNVoYDzIxMjYwOTIz\n"
    "MjIxNzE1WjAUMRIwEAYDVQQDDAlTTUlNRSByc2EwggEiMA0GCSqGSIb3DQEBAQUA\n"
    "A4IBDwAwggEKAoIBAQCTF3DR1lrRhjc9u1jEVzgYclC+L3X6x88IGgzCdKPaNwhL\n"
    "QlWsDXmluMlqa0Tvb4Ob392Ufxmkn1W30XhYTypLjGOL5bksoiGDiQZn1ovA/Gnd\n"
    "mCq1J47pSNhz6SL1/uOZvmj6vdpr0p26BtqGCr1hXowWKIvmJGdr5JV4fPgRXO/n\n"
    "FCqYvwzm0hxCCWF+cpACJgB/NkB54nSqeYdRhwJvU9D8glmTuwO4UY035FDYcYKa\n"
    "jiIMtnJnGlo/IJMEyI1+lQGWWFOSCPhld5B3etvb8Yz+LC51w4jlroXJw7q1HmTG\n"
    "i2IR4fugKC8lLugmbONeFXjeCawPRVhZPR2/1AHNAgMBAAGjcjBwMAkGA1UdEwQC\n"
    "MAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMEMB0GA1UdDgQW\n"
    "BBQTEOssjmFffw9DHdfYXG+4qmqEvDAfBgNVHSMEGDAWgBR1tdNQedtUtDillwMh\n"
    "WwDwHWigRTAKBggqhkjOPQQDAgNIADBFAiAJ6N2sNNdSNa+IDpskcT9WoVcNF5gK\n"
    "YOWbDzbJFIJTZQIhAOTlwtgT1PhcURW6WGxpnKHrkg8l+RbzadUEJJAksG/w\n"
    "-----END CERTIFICATE-----\n";

static const char RSA_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCTF3DR1lrRhjc9\n"
    "u1jEVzgYclC+L3X6x88IGgzCdKPaNwhLQlWsDXmluMlqa0Tvb4Ob392Ufxmkn1W3\n"
    "0XhYTypLjGOL5bksoiGDiQZn1ovA/GndmCq1J47pSNhz6SL1/uOZvmj6vdpr0p26\n"
    "BtqGCr1hXowWKIvmJGdr5JV4fPgRXO/nFCqYvwzm0hxCCWF+cpACJgB/NkB54nSq\n"
    "eYdRhwJvU9D8glmTuwO4UY035FDYcYKajiIMtnJnGlo/IJMEyI1+lQGWWFOSCPhl\n"
    "d5B3etvb8Yz+LC51w4jlroXJw7q1HmTGi2IR4fugKC8lLugmbONeFXjeCawPRVhZ\n"
    "PR2/1AHNAgMBAAECggEABvLN1BCcGrC/h4C3P6zFGOm+WBwJQG8G7Mfz2VqSncDV\n"
    "+SqP8U0NQl+TBQSk0+paXVcucip5s7w8W67sA42Kntk2n9aBMGAT7p3e+eT5lh5c\n"
    "zxu2MyrEUzXeb8W2iC6U+6xlUvViZ4+7/rX+X0px/TMIfnvgDyxu33rQkTAKG4iZ\n"
    "J4Lyon+aTmqTnZQetFk0eeQUxVnKg9RUSqWVgbPbZ9HncgXAtJ8BTXkEmkjqpjQ8\n"
    "4LWpP9pueGaDESPZy86UG18q4pUoozv/HFrEo7vGLjUUCXK5G1mL0GUKMIrhle1t\n"
    "GPSVrg+bKDRM9naGQkWGECar/Mu7K1PODe4Ck06PSwKBgQDDNwQhfPdhlvCP4xjt\n"
    "7rey1/Dpw8XUwjIbvwzbjQhJm001Ty3qP4p9uf9my1TcKHA5HdcNDssH40uEbMVY\n"
    "+3YVqkqviljVV8ifSJvdOsvaPX133bqtFBLeSnIlFrEhiLHSDdwdS5RbyLqu1r2X\n"
    "5O3X0aHUORAyTIL2EW9hLN94YwKBgQDA5GnboAw8P9+pDSwlkATA8W+aeKUyRWY7\n"
    "BVmOkAPAxLPa1WByihYE8OPtJPt4kGCOQ8nD2vF7y2Crh5yEB+sjMzyyXkmZIqxx\n"
    "7Hx9yT0skdae3H32VRNTreUAIJb3VxdXrIwW4ttz6mzVibuATI/HWRcPapxA+QOt\n"
    "bSIDi6R8DwKBgQCX22NOPa0e8FDgTXPmGw4xhIP3BQEO+aYLKXpyC+rHf5T3BEoe\n"
    "cCFmnlrMdx3jSV3LQKg6kyhjUXA8anS2PJ7mSZthpIhoJap+JfiBhyxu7+h7ZzPB\n"
    "Ud0/qL/UlCtkf7Z8RaXV8CZPo/185rWDxGU0vvFZaq5rwlMZ4gQ3nrWUKwKBgH5p\n"
    "s05x91LM8YFS1qnPVq40DFYJ1wm5HaR0fxrFGxCMWOqDiG/IO2IFlPpnkD6VMBJM\n"
    "LsCijjv5L2N6voJwxhMNkyu6SzWG2cjXmUa+Sc8ZzLPUAOEdJEtk3X1V3lo+w1d8\n"
    "B1tAVV4ENktDtpQAmQGmS0yZK8oQ5+4SZYY5UBTVAoGBAMB2u6z9vtsnzhjQkYzw\n"
    "1Cj9d5B6yU0PVlvMtx3gvN695KJirNu9J97uH/l0ChwRaQLKHDbHDxUesdNC+3OS\n"
    "XxACwAu74Hz+oNnN+vRC+dFoQv8F0VUCTkBALqPF5uOtbMHeo4Cd7INRu7Q0x8zY\n"
    "qRa6RR43B+gY9X3Ln41yewDZ\n"
    "-----END PRIVATE KEY-----\n";

static const char TSA_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDU7895fFTP6VGq\n"
    "Q1MsIXSlS8hELz9zSjM15f1UAQ5naCCL33GrrjiTJG1GtQpOj96QP2JYkV4PXwlW\n"
    "FQFQ9MZyDZ6+Lybg2snypYoTjs4umdvQHUZM7/Er54ofm0wmw0qRBX+poalMT2FD\n"
    "EqV8HBIFZ3DCmz5KdljuplOxJEPT+XuuPWWE67mouUlmSyzHFGo3WoX6kVfOPUNR\n"
    "+6IwUxdvqB8muj9KsnHOIw4haocKJ8ivEu+cah1WEELPrHYHk+6iAt/IqN/GtQtM\n"
    "026r5YUXKt3Kpc0qPJ547I6DRv20oH0ElUAst7Wh9J7ZkR4s9tQn3lMvYoA0n9oc\n"
    "0yqSKCVPAgMBAAECggEACI3G9IcNaSS4RnIElKXrZ6XPBQjY2wAaD9+N+Pfp5OGG\n"
    "nS0msHzZLPVY+8QosSs6XOpkQFE79BDJ8TlQH45rAl3ls0IgT7Fk92hgTuonrNuQ\n"
    "EaDQws/It7jKEFGkEifk25qFnFeFfi6aJkrzdt7cd8xwooCrVJZt0CMXrZVasYMm\n"
    "Cz8hEPulOCIdLpVoMexrPStN5bLJW4jRaflLMgW1fhyqS/OO6omf9eQmpf0dEsve\n"
    "N9oUjFH4mV6+yyixkC3FZMLTDsphwfpym1EMfz9PsDMfL66d3a6FUrJfqcWZyNkG\n"
    "DUHjoWwGR0wcIX5DGBoQPRsiIguWLSWzgAKQzLwdcQKBgQDq3rCaK4UgFiOosGPj\n"
    "nUgO/oUP48BEf2r7tUgu+0eKso0WSYv0QAX1ZDC4Ue+BjdhSogHaXdKlCj9C6xJZ\n"
    "3WQxqe1ELXv4EhOnKxTwmSktAhxWELFcpBDzhFHWSYHmLZhl6hFe4MMN3bGUNQRm\n"
    "FqaO2xYgnwzqPau4u1Q3Y45+YwKBgQDoF/oPuvXYzMx5CKEyigGH3Nti7sCSVjHO\n"
    "gQQcNjBag/pjG35FAOWt7G59iRoh0tO8/55drn8iqNdmyDFo5j+IV8/fQfa4vHRY\n"
    "OgXR3XeJdnojGi0062RbrxMyeW+xk5gct1YXTKMyj7bxNFyPiQJAUwBpSt4WxLmY\n"
    "Cp84ObnrJQKBgHndxHqqPDAS7Lu5korm8B2/mKFPBlNEXelu/Z5LCasAzE4VKUY5\n"
    "9h2Gt/Tbps9tHyJ5J0b7ybGS6JI7UNFKG5PdXNw0UY+9KW9i3kGc5w2Qe814ad7s\n"
    "zlLchG4QxBL/84Rl+E9nhi3qqxqAi+DAvfl/2jJg9J2SFEkNAjyfLq+LAoGBAIfD\n"
    "fsM02hq3seQa6DBoCf0vdCWrA3qWcQwa7AyUpjRMf2r56iLzI2dZpkhIqsCeUr17\n"
    "yWeDa1sa6OV2tXBnP0LCGxa9v1TQ6D2zszPQGNyQMWHXLhqGl24KO3CLGIsHizNB\n"
    "C1sVuWEaMCloN7y+qFJ4OwVchg1LhkUp8XkyS08BAoGBANuANVvDjIoUPUyy9MXv\n"
    "WXMQNdd8DlbmqEGJrWJNy2ZxhKKAe2CW2cjx9LWDNG624dVIUFC5AVYt0h7zCHxN\n"
    "8skO3SImYPg99TbinO1W35ORgoeXZf1mJblCH5VAvtlH3vUmT7Q6G4mpxs4VYane\n"
    "gG/IOR14psq0LoISUS7kO60w\n"
    "-----END PRIVATE KEY-----\n";

static const unsigned char REQ_DER[] = {
    0x30, 0x3f, 0x02, 0x01, 0x01, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xe2, 0xd0, 0xa0, 0xbb, 0x35, 0xce, 0xbb, 0x01,
    0x4a, 0x7f, 0xd7, 0x12, 0x18, 0x6a, 0xc2, 0x59, 0xab, 0xba, 0xd5, 0x03, 0xf6, 0xf8, 0xac, 0xa3,
    0xde, 0x33, 0x9e, 0xb6, 0xb1, 0x50, 0xce, 0x65, 0x06, 0x04, 0x2a, 0x03, 0x04, 0x01, 0x01, 0x01,
    0xff
};

static const unsigned char REQ_NOCERT_DER[] = {
    0x30, 0x36, 0x02, 0x01, 0x01, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xe2, 0xd0, 0xa0, 0xbb, 0x35, 0xce, 0xbb, 0x01,
    0x4a, 0x7f, 0xd7, 0x12, 0x18, 0x6a, 0xc2, 0x59, 0xab, 0xba, 0xd5, 0x03, 0xf6, 0xf8, 0xac, 0xa3,
    0xde, 0x33, 0x9e, 0xb6, 0xb1, 0x50, 0xce, 0x65
};

static const unsigned char RESP_DER[] = {
    0x30, 0x82, 0x07, 0x14, 0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x82, 0x07, 0x0b, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0, 0x82, 0x06, 0xfc, 0x30, 0x82, 0x06, 0xf8,
    0x02, 0x01, 0x03, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x02, 0x01, 0x05, 0x00, 0x30, 0x81, 0xa5, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x09, 0x10, 0x01, 0x04, 0xa0, 0x81, 0x95, 0x04, 0x81, 0x92, 0x30, 0x81, 0x8f, 0x02, 0x01, 0x01,
    0x06, 0x04, 0x2a, 0x03, 0x04, 0x01, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xe2, 0xd0, 0xa0, 0xbb, 0x35, 0xce, 0xbb,
    0x01, 0x4a, 0x7f, 0xd7, 0x12, 0x18, 0x6a, 0xc2, 0x59, 0xab, 0xba, 0xd5, 0x03, 0xf6, 0xf8, 0xac,
    0xa3, 0xde, 0x33, 0x9e, 0xb6, 0xb1, 0x50, 0xce, 0x65, 0x02, 0x01, 0x11, 0x18, 0x13, 0x32, 0x30,
    0x32, 0x36, 0x31, 0x30, 0x31, 0x38, 0x30, 0x32, 0x34, 0x36, 0x33, 0x31, 0x2e, 0x38, 0x32, 0x35,
    0x5a, 0x30, 0x0a, 0x02, 0x01, 0x01, 0x80, 0x02, 0x01, 0xf4, 0x81, 0x01, 0x64, 0x01, 0x01, 0xff,
    0xa0, 0x2a, 0xa4, 0x28, 0x30, 0x26, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x08, 0x54, 0x65, 0x73, 0x74, 0x20, 0x54, 0x53, 0x41, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x0c, 0x08, 0x72, 0x75, 0x73, 0x74, 0x79, 0x73, 0x73, 0x6c, 0xa0, 0x82, 0x04, 0x35,
    0x30, 0x82, 0x02, 0x99, 0x30, 0x82, 0x02, 0x3f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x00,
    0x88, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x27, 0x31,
    0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c,
    0x65, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x53, 0x4d, 0x49, 0x4d,
    0x45, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x30, 0x31, 0x38,
    0x30, 0x32, 0x34, 0x36, 0x33, 0x31, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x36, 0x30, 0x39, 0x32,
    0x34, 0x30, 0x32, 0x34, 0x36, 0x33, 0x31, 0x5a, 0x30, 0x26, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x08, 0x54, 0x65, 0x73, 0x74, 0x20, 0x54, 0x53, 0x41, 0x31, 0x11, 0x30,
    0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x72, 0x75, 0x73, 0x74, 0x79, 0x73, 0x73, 0x6c,
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
    0x00, 0xd4, 0xef, 0xcf, 0x79, 0x7c, 0x54, 0xcf, 0xe9, 0x51, 0xaa, 0x43, 0x53, 0x2c, 0x21, 0x74,
    0xa5, 0x4b, 0xc8, 0x44, 0x2f, 0x3f, 0x73, 0x4a, 0x33, 0x35, 0xe5, 0xfd, 0x54, 0x01, 0x0e, 0x67,
    0x68, 0x20, 0x8b, 0xdf, 0x71, 0xab, 0xae, 0x38, 0x93, 0x24, 0x6d, 0x46, 0xb5, 0x0a, 0x4e, 0x8f,
    0xde, 0x90, 0x3f, 0x62, 0x58, 0x91, 0x5e, 0x0f, 0x5f, 0x09, 0x56, 0x15, 0x01, 0x50, 0xf4, 0xc6,
    0x72, 0x0d, 0x9e, 0xbe, 0x2f, 0x26, 0xe0, 0xda, 0xc9, 0xf2, 0xa5, 0x8a, 0x13, 0x8e, 0xce, 0x2e,
    0x99, 0xdb, 0xd0, 0x1d, 0x46, 0x4c, 0xef, 0xf1, 0x2b, 0xe7, 0x8a, 0x1f, 0x9b, 0x4c, 0x26, 0xc3,
    0x4a, 0x91, 0x05, 0x7f, 0xa9, 0xa1, 0xa9, 0x4c, 0x4f, 0x61, 0x43, 0x12, 0xa5, 0x7c, 0x1c, 0x12,
    0x05, 0x67, 0x70, 0xc2, 0x9b, 0x3e, 0x4a, 0x76, 0x58, 0xee, 0xa6, 0x53, 0xb1, 0x24, 0x43, 0xd3,
    0xf9, 0x7b, 0xae, 0x3d, 0x65, 0x84, 0xeb, 0xb9, 0xa8, 0xb9, 0x49, 0x66, 0x4b, 0x2c, 0xc7, 0x14,
    0x6a, 0x37, 0x5a, 0x85, 0xfa, 0x91, 0x57, 0xce, 0x3d, 0x43, 0x51, 0xfb, 0xa2, 0x30, 0x53, 0x17,
    0x6f, 0xa8, 0x1f, 0x26, 0xba, 0x3f, 0x4a, 0xb2, 0x71, 0xce, 0x23, 0x0e, 0x21, 0x6a, 0x87, 0x0a,
    0x27, 0xc8, 0xaf, 0x12, 0xef, 0x9c, 0x6a, 0x1d, 0x56, 0x10, 0x42, 0xcf, 0xac, 0x76, 0x07, 0x93,
    0xee, 0xa2, 0x02, 0xdf, 0xc8, 0xa8, 0xdf, 0xc6, 0xb5, 0x0b, 0x4c, 0xd3, 0x6e, 0xab, 0xe5, 0x85,
    0x17, 0x2a, 0xdd, 0xca, 0xa5, 0xcd, 0x2a, 0x3c, 0x9e, 0x78, 0xec, 0x8e, 0x83, 0x46, 0xfd, 0xb4,
    0xa0, 0x7d, 0x04, 0x95, 0x40, 0x2c, 0xb7, 0xb5, 0xa1, 0xf4, 0x9e, 0xd9, 0x91, 0x1e, 0x2c, 0xf6,
    0xd4, 0x27, 0xde, 0x53, 0x2f, 0x62, 0x80, 0x34, 0x9f, 0xda, 0x1c, 0xd3, 0x2a, 0x92, 0x28, 0x25,
    0x4f, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x81, 0x8e, 0x30, 0x81, 0x8b, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,
    0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x16, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x01, 0x01,
    0xff, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08, 0x30,
    0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xaf, 0xf3, 0x6a, 0xa3, 0x18, 0x9f,
    0x62, 0x06, 0x65, 0x8a, 0x3b, 0xff, 0x17, 0xd5, 0x43, 0x7c, 0x46, 0x55, 0xe8, 0x2f, 0x30, 0x1f,
    0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x75, 0xb5, 0xd3, 0x50, 0x79,
    0xdb, 0x54, 0xb4, 0x38, 0xa5, 0x97, 0x03, 0x21, 0x5b, 0x00, 0xf0, 0x1d, 0x68, 0xa0, 0x45, 0x30,
    0x16, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0f, 0x30, 0x0d, 0x82, 0x0b, 0x74, 0x73, 0x61, 0x2e,
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x3d, 0xae, 0x73, 0xb7, 0xaa, 0xf2,
    0x3c, 0xe0, 0xd4, 0x91, 0xe7, 0x15, 0x10, 0x51, 0xe8, 0x81, 0xfa, 0xb3, 0x7f, 0x88, 0x67, 0x50,
    0xba, 0xbc, 0x23, 0x7a, 0x59, 0x80, 0xf6, 0x67, 0xc1, 0x29, 0x02, 0x21, 0x00, 0xed, 0xb2, 0x1b,
    0x10, 0x5f, 0xfa, 0x6a, 0x67, 0x9d, 0xf9, 0x31, 0xbd, 0xa0, 0xb9, 0x81, 0x5d, 0x9c, 0x98, 0x19,
    0x53, 0xcb, 0xdc, 0x07, 0xbd, 0xf9, 0x85, 0x4f, 0x76, 0xa2, 0x6a, 0x71, 0x50, 0x30, 0x82, 0x01,
    0x94, 0x30, 0x82, 0x01, 0x3a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x42, 0xcf, 0x19, 0x12,
    0xb3, 0x16, 0x3c, 0x87, 0xa7, 0x68, 0x3f, 0xee, 0x3b, 0x39, 0x70, 0xa3, 0x1c, 0xb0, 0x96, 0x79,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x27, 0x31, 0x10,
    0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x53, 0x4d, 0x49, 0x4d, 0x45,
    0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x30, 0x31, 0x37, 0x32,
    0x32, 0x31, 0x37, 0x31, 0x35, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x36, 0x30, 0x39, 0x32, 0x33,
    0x32, 0x32, 0x31, 0x37, 0x31, 0x35, 0x5a, 0x30, 0x27, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x0c, 0x07, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31, 0x13, 0x30, 0x11, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x53, 0x4d, 0x49, 0x4d, 0x45, 0x20, 0x52, 0x6f, 0x6f, 0x74,
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x1f, 0xc0, 0x2d, 0x35, 0x5c,
    0x38, 0xd5, 0x1f, 0x54, 0xd2, 0x56, 0xf8, 0x8f, 0x26, 0xfa, 0x91, 0x59, 0x66, 0xfd, 0x84, 0xd6,
    0x7b, 0x9e, 0x6a, 0x8b, 0x48, 0xc6, 0xdc, 0xae, 0x0a, 0xe5, 0x3b, 0xbe, 0x0b, 0x57, 0xf8, 0x1e,
    0x62, 0xa7, 0x1e, 0xea, 0x2e, 0xa6, 0xc2, 0xa5, 0x77, 0x3b, 0xb9, 0x3c, 0x39, 0xf9, 0x55, 0x14,
    0xd3, 0x7e, 0x4f, 0xdf, 0xae, 0xb9, 0x1e, 0x58, 0x65, 0x13, 0x4f, 0xa3, 0x42, 0x30, 0x40, 0x30,
    0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,
    0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06,
    0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x75, 0xb5, 0xd3, 0x50, 0x79,
    0xdb, 0x54, 0xb4, 0x38, 0xa5, 0x97, 0x03, 0x21, 0x5b, 0x00, 0xf0, 0x1d, 0x68, 0xa0, 0x45, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45,
    0x02, 0x21, 0x00, 0x99, 0xde, 0xd0, 0xd8, 0x7e, 0xa9, 0xa3, 0x8f, 0xc9, 0xf1, 0xc7, 0xf7, 0x5d,
    0x7b, 0x48, 0x7d, 0xff, 0x1e, 0x83, 0x6c, 0xba, 0x00, 0xad, 0x92, 0x37, 0x13, 0xb3, 0xe9, 0x0d,
    0x09, 0x1c, 0x99, 0x02, 0x20, 0x73, 0x21, 0x81, 0xae, 0x38, 0x27, 0x22, 0xe7, 0x6f, 0xca, 0x9a,
    0x24, 0xfb, 0x4d, 0x7a, 0xce, 0xa0, 0xba, 0x0f, 0x8d, 0x66, 0xa0, 0xf4, 0x58, 0xd0, 0x39, 0xf2,
    0xd6, 0x2a, 0x9e, 0x09, 0x90, 0x31, 0x82, 0x01, 0xff, 0x30, 0x82, 0x01, 0xfb, 0x02, 0x01, 0x01,
    0x30, 0x2d, 0x30, 0x27, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x45,
    0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x0a, 0x53, 0x4d, 0x49, 0x4d, 0x45, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x02, 0x02, 0x00, 0x88, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa0, 0x81,
    0xa4, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03, 0x31, 0x0d,
    0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04, 0x30, 0x1c, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05, 0x31, 0x0f, 0x17, 0x0d, 0x32, 0x36,
    0x31, 0x30, 0x31, 0x38, 0x30, 0x32, 0x34, 0x36, 0x33, 0x31, 0x5a, 0x30, 0x2f, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04, 0x31, 0x22, 0x04, 0x20, 0x21, 0xc6, 0xd1, 0xf9,
    0xdb, 0xa9, 0x04, 0x73, 0xd5, 0xb4, 0xb3, 0xe9, 0x98, 0x07, 0x7d, 0x08, 0x80, 0xb6, 0x2b, 0xec,
    0x50, 0xb3, 0x5b, 0x00, 0xc6, 0x87, 0x25, 0x01, 0x0b, 0xe8, 0xb9, 0xdd, 0x30, 0x37, 0x06, 0x0b,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f, 0x31, 0x28, 0x30, 0x26, 0x30,
    0x24, 0x30, 0x22, 0x04, 0x20, 0xef, 0xbd, 0x6d, 0xa8, 0xd7, 0xc9, 0x21, 0xbc, 0x60, 0x8e, 0xed,
    0xcf, 0x5f, 0x04, 0xb0, 0xf4, 0xb7, 0x70, 0x31, 0xe3, 0x42, 0xf4, 0xb2, 0x56, 0x93, 0x40, 0x3e,
    0x63, 0x16, 0x16, 0x2b, 0x50, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x01, 0x00, 0xb9, 0x15, 0x6c, 0xdb, 0xb4, 0xf2, 0xf1, 0x40,
    0x3a, 0xff, 0x5e, 0x24, 0xc1, 0x96, 0xb7, 0xf5, 0x29, 0xde, 0x01, 0x5c, 0xc7, 0xb6, 0x58, 0x3d,
    0x55, 0xff, 0xd0, 0x3b, 0x8e, 0xf0, 0xca, 0xf5, 0x7c, 0x71, 0x54, 0x72, 0xcd, 0x87, 0x77, 0x20,
    0x71, 0x42, 0x10, 0x74, 0xe6, 0x1d, 0x18, 0xf8, 0xdb, 0xfe, 0xce, 0x02, 0x41, 0x1b, 0x15, 0x9e,
    0x72, 0x49, 0x9e, 0x2d, 0x9d, 0x78, 0x5e, 0x39, 0x0a, 0x3e, 0x7a, 0x84, 0x7b, 0x41, 0x7c, 0x6d,
    0x6b, 0xdd, 0xf1, 0x41, 0x53, 0x9e, 0x84, 0xf3, 0x8a, 0xf7, 0xbc, 0xd7, 0x7a, 0x49, 0x13, 0xd7,
    0x04, 0xf7, 0xac, 0xc8, 0x46, 0xd6, 0xc0, 0x88, 0x36, 0x0b, 0xda, 0x10, 0x7e, 0xef, 0xff, 0x78,
    0x4f, 0xd9, 0xb0, 0x1e, 0x25, 0x31, 0xa3, 0x40, 0xef, 0x49, 0x54, 0xbe, 0x09, 0xb1, 0x2d, 0xc1,
    0x5a, 0xcc, 0xdc, 0x61, 0x37, 0x2c, 0x9d, 0x50, 0x44, 0x5b, 0x16, 0x82, 0xa6, 0x23, 0x3c, 0x2c,
    0xc8, 0xa1, 0xba, 0x86, 0x88, 0xf0, 0x55, 0x54, 0x46, 0x0e, 0xa6, 0x7f, 0xbf, 0xe7, 0x1d, 0x5a,
    0x34, 0xaa, 0xcf, 0x93, 0x81, 0x75, 0xfb, 0x08, 0x16, 0xc4, 0xc7, 0x1b, 0x7f, 0x92, 0x93, 0x3c,
    0x74, 0x11, 0x71, 0x4f, 0x0a, 0x7f, 0x33, 0xbe, 0x05, 0xdf, 0xc9, 0x4e, 0xb7, 0x1c, 0x72, 0x4b,
    0xdf, 0x09, 0xc4, 0x30, 0x1a, 0xd9, 0x33, 0x22, 0xba, 0x22, 0x0a, 0x02, 0xde, 0x47, 0x57, 0x62,
    0xea, 0x68, 0x9b, 0x3c, 0x5f, 0x0b, 0xe9, 0x73, 0xa1, 0x96, 0x36, 0xe8, 0x96, 0xa7, 0x36, 0x74,
    0xc6, 0x61, 0x87, 0xc6, 0x20, 0xc2, 0x39, 0xe1, 0xb0, 0x3c, 0xcd, 0xe8, 0x53, 0x5a, 0x72, 0xb4,
    0x5f, 0x87, 0x98, 0xeb, 0x13, 0x9d, 0xae, 0x15, 0xc7, 0xd4, 0xeb, 0x74, 0x86, 0x48, 0x93, 0xb5,
    0x2b, 0xf8, 0x13, 0xca, 0x89, 0x0d, 0x06, 0xc0
};

static const unsigned char TOKEN_DER[] = {
    0x30, 0x82, 0x07, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0,
    0x82, 0x06, 0xfc, 0x30, 0x82, 0x06, 0xf8, 0x02, 0x01, 0x03, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x30, 0x81, 0xa5, 0x06, 0x0b,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04, 0xa0, 0x81, 0x95, 0x04, 0x81,
    0x92, 0x30, 0x81, 0x8f, 0x02, 0x01, 0x01, 0x06, 0x04, 0x2a, 0x03, 0x04, 0x01, 0x30, 0x31, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    0xe2, 0xd0, 0xa0, 0xbb, 0x35, 0xce, 0xbb, 0x01, 0x4a, 0x7f, 0xd7, 0x12, 0x18, 0x6a, 0xc2, 0x59,
    0xab, 0xba, 0xd5, 0x03, 0xf6, 0xf8, 0xac, 0xa3, 0xde, 0x33, 0x9e, 0xb6, 0xb1, 0x50, 0xce, 0x65,
    0x02, 0x01, 0x11, 0x18, 0x13, 0x32, 0x30, 0x32, 0x36, 0x31, 0x30, 0x31, 0x38, 0x30, 0x32, 0x34,
    0x36, 0x33, 0x31, 0x2e, 0x38, 0x32, 0x35, 0x5a, 0x30, 0x0a, 0x02, 0x01, 0x01, 0x80, 0x02, 0x01,
    0xf4, 0x81, 0x01, 0x64, 0x01, 0x01, 0xff, 0xa0, 0x2a, 0xa4, 0x28, 0x30, 0x26, 0x31, 0x11, 0x30,
    0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x54, 0x65, 0x73, 0x74, 0x20, 0x54, 0x53, 0x41,
    0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x72, 0x75, 0x73, 0x74, 0x79,
    0x73, 0x73, 0x6c, 0xa0, 0x82, 0x04, 0x35, 0x30, 0x82, 0x02, 0x99, 0x30, 0x82, 0x02, 0x3f, 0xa0,
    0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x00, 0x88, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x04, 0x03, 0x02, 0x30, 0x27, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x07, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x0a, 0x53, 0x4d, 0x49, 0x4d, 0x45, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x20, 0x17,
    0x0d, 0x32, 0x36, 0x31, 0x30, 0x31, 0x38, 0x30, 0x32, 0x34, 0x36, 0x33, 0x31, 0x5a, 0x18, 0x0f,
    0x32, 0x31, 0x32, 0x36, 0x30, 0x39, 0x32, 0x34, 0x30, 0x32, 0x34, 0x36, 0x33, 0x31, 0x5a, 0x30,
    0x26, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x54, 0x65, 0x73, 0x74,
    0x20, 0x54, 0x53, 0x41, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x72,
    0x75, 0x73, 0x74, 0x79, 0x73, 0x73, 0x6c, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30,
    0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xd4, 0xef, 0xcf, 0x79, 0x7c, 0x54, 0xcf, 0xe9,
    0x51, 0xaa, 0x43, 0x53, 0x2c, 0x21, 0x74, 0xa5, 0x4b, 0xc8, 0x44, 0x2f, 0x3f, 0x73, 0x4a, 0x33,
    0x35, 0xe5, 0xfd, 0x54, 0x01, 0x0e, 0x67, 0x68, 0x20, 0x8b, 0xdf, 0x71, 0xab, 0xae, 0x38, 0x93,
    0x24, 0x6d, 0x46, 0xb5, 0x0a, 0x4e, 0x8f, 0xde, 0x90, 0x3f, 0x62, 0x58, 0x91, 0x5e, 0x0f, 0x5f,
    0x09, 0x56, 0x15, 0x01, 0x50, 0xf4, 0xc6, 0x72, 0x0d, 0x9e, 0xbe, 0x2f, 0x26, 0xe0, 0xda, 0xc9,
    0xf2, 0xa5, 0x8a, 0x13, 0x8e, 0xce, 0x2e, 0x99, 0xdb, 0xd0, 0x1d, 0x46, 0x4c, 0xef, 0xf1, 0x2b,
    0xe7, 0x8a, 0x1f, 0x9b, 0x4c, 0x26, 0xc3, 0x4a, 0x91, 0x05, 0x7f, 0xa9, 0xa1, 0xa9, 0x4c, 0x4f,
    0x61, 0x43, 0x12, 0xa5, 0x7c, 0x1c, 0x12, 0x05, 0x67, 0x70, 0xc2, 0x9b, 0x3e, 0x4a, 0x76, 0x58,
    0xee, 0xa6, 0x53, 0xb1, 0x24, 0x43, 0xd3, 0xf9, 0x7b, 0xae, 0x3d, 0x65, 0x84, 0xeb, 0xb9, 0xa8,
    0xb9, 0x49, 0x66, 0x4b, 0x2c, 0xc7, 0x14, 0x6a, 0x37, 0x5a, 0x85, 0xfa, 0x91, 0x57, 0xce, 0x3d,
    0x43, 0x51, 0xfb, 0xa2, 0x30, 0x53, 0x17, 0x6f, 0xa8, 0x1f, 0x26, 0xba, 0x3f, 0x4a, 0xb2, 0x71,
    0xce, 0x23, 0x0e, 0x21, 0x6a, 0x87, 0x0a, 0x27, 0xc8, 0xaf, 0x12, 0xef, 0x9c, 0x6a, 0x1d, 0x56,
    0x10, 0x42, 0xcf, 0xac, 0x76, 0x07, 0x93, 0xee, 0xa2, 0x02, 0xdf, 0xc8, 0xa8, 0xdf, 0xc6, 0xb5,
    0x0b, 0x4c, 0xd3, 0x6e, 0xab, 0xe5, 0x85, 0x17, 0x2a, 0xdd, 0xca, 0xa5, 0xcd, 0x2a, 0x3c, 0x9e,
    0x78, 0xec, 0x8e, 0x83, 0x46, 0xfd, 0xb4, 0xa0, 0x7d, 0x04, 0x95, 0x40, 0x2c, 0xb7, 0xb5, 0xa1,
    0xf4, 0x9e, 0xd9, 0x91, 0x1e, 0x2c, 0xf6, 0xd4, 0x27, 0xde, 0x53, 0x2f, 0x62, 0x80, 0x34, 0x9f,
    0xda, 0x1c, 0xd3, 0x2a, 0x92, 0x28, 0x25, 0x4f, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x81, 0x8e,
    0x30, 0x81, 0x8b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e,
    0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x16,
    0x06, 0x03, 0x55, 0x1d, 0x25, 0x01, 0x01, 0xff, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06,
    0x01, 0x05, 0x05, 0x07, 0x03, 0x08, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
    0x14, 0xaf, 0xf3, 0x6a, 0xa3, 0x18, 0x9f, 0x62, 0x06, 0x65, 0x8a, 0x3b, 0xff, 0x17, 0xd5, 0x43,
    0x7c, 0x46, 0x55, 0xe8, 0x2f, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
    0x80, 0x14, 0x75, 0xb5, 0xd3, 0x50, 0x79, 0xdb, 0x54, 0xb4, 0x38, 0xa5, 0x97, 0x03, 0x21, 0x5b,
    0x00, 0xf0, 0x1d, 0x68, 0xa0, 0x45, 0x30, 0x16, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0f, 0x30,
    0x0d, 0x82, 0x0b, 0x74, 0x73, 0x61, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02,
    0x20, 0x3d, 0xae, 0x73, 0xb7, 0xaa, 0xf2, 0x3c, 0xe0, 0xd4, 0x91, 0xe7, 0x15, 0x10, 0x51, 0xe8,
    0x81, 0xfa, 0xb3, 0x7f, 0x88, 0x67, 0x50, 0xba, 0xbc, 0x23, 0x7a, 0x59, 0x80, 0xf6, 0x67, 0xc1,
    0x29, 0x02, 0x21, 0x00, 0xed, 0xb2, 0x1b, 0x10, 0x5f, 0xfa, 0x6a, 0x67, 0x9d, 0xf9, 0x31, 0xbd,
    0xa0, 0xb9, 0x81, 0x5d, 0x9c, 0x98, 0x19, 0x53, 0xcb, 0xdc, 0x07, 0xbd, 0xf9, 0x85, 0x4f, 0x76,
    0xa2, 0x6a, 0x71, 0x50, 0x30, 0x82, 0x01, 0x94, 0x30, 0x82, 0x01, 0x3a, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x42, 0xcf, 0x19, 0x12, 0xb3, 0x16, 0x3c, 0x87, 0xa7, 0x68, 0x3f, 0xee, 0x3b,
    0x39, 0x70, 0xa3, 0x1c, 0xb0, 0x96, 0x79, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x30, 0x27, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07,
    0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x0a, 0x53, 0x4d, 0x49, 0x4d, 0x45, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x20, 0x17, 0x0d,
    0x32, 0x36, 0x31, 0x30, 0x31, 0x37, 0x32, 0x32, 0x31, 0x37, 0x31, 0x35, 0x5a, 0x18, 0x0f, 0x32,
    0x31, 0x32, 0x36, 0x30, 0x39, 0x32, 0x33, 0x32, 0x32, 0x31, 0x37, 0x31, 0x35, 0x5a, 0x30, 0x27,
    0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x45, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x53, 0x4d, 0x49,
    0x4d, 0x45, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
    0x00, 0x04, 0x1f, 0xc0, 0x2d, 0x35, 0x5c, 0x38, 0xd5, 0x1f, 0x54, 0xd2, 0x56, 0xf8, 0x8f, 0x26,
    0xfa, 0x91, 0x59, 0x66, 0xfd, 0x84, 0xd6, 0x7b, 0x9e, 0x6a, 0x8b, 0x48, 0xc6, 0xdc, 0xae, 0x0a,
    0xe5, 0x3b, 0xbe, 0x0b, 0x57, 0xf8, 0x1e, 0x62, 0xa7, 0x1e, 0xea, 0x2e, 0xa6, 0xc2, 0xa5, 0x77,
    0x3b, 0xb9, 0x3c, 0x39, 0xf9, 0x55, 0x14, 0xd3, 0x7e, 0x4f, 0xdf, 0xae, 0xb9, 0x1e, 0x58, 0x65,
    0x13, 0x4f, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
    0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,
    0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16,
    0x04, 0x14, 0x75, 0xb5, 0xd3, 0x50, 0x79, 0xdb, 0x54, 0xb4, 0x38, 0xa5, 0x97, 0x03, 0x21, 0x5b,
    0x00, 0xf0, 0x1d, 0x68, 0xa0, 0x45, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
    0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0x99, 0xde, 0xd0, 0xd8, 0x7e, 0xa9,
    0xa3, 0x8f, 0xc9, 0xf1, 0xc7, 0xf7, 0x5d, 0x7b, 0x48, 0x7d, 0xff, 0x1e, 0x83, 0x6c, 0xba, 0x00,
    0xad, 0x92, 0x37, 0x13, 0xb3, 0xe9, 0x0d, 0x09, 0x1c, 0x99, 0x02, 0x20, 0x73, 0x21, 0x81, 0xae,
    0x38, 0x27, 0x22, 0xe7, 0x6f, 0xca, 0x9a, 0x24, 0xfb, 0x4d, 0x7a, 0xce, 0xa0, 0xba, 0x0f, 0x8d,
    0x66, 0xa0, 0xf4, 0x58, 0xd0, 0x39, 0xf2, 0xd6, 0x2a, 0x9e, 0x09, 0x90, 0x31, 0x82, 0x01, 0xff,
    0x30, 0x82, 0x01, 0xfb, 0x02, 0x01, 0x01, 0x30, 0x2d, 0x30, 0x27, 0x31, 0x10, 0x30, 0x0e, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31, 0x13, 0x30,
    0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x53, 0x4d, 0x49, 0x4d, 0x45, 0x20, 0x52, 0x6f,
    0x6f, 0x74, 0x02, 0x02, 0x00, 0x88, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x01, 0x05, 0x00, 0xa0, 0x81, 0xa4, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x09, 0x03, 0x31, 0x0d, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x09, 0x10, 0x01, 0x04, 0x30, 0x1c, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09,
    0x05, 0x31, 0x0f, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x30, 0x31, 0x38, 0x30, 0x32, 0x34, 0x36, 0x33,
    0x31, 0x5a, 0x30, 0x2f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04, 0x31,
    0x22, 0x04, 0x20, 0x21, 0xc6, 0xd1, 0xf9, 0xdb, 0xa9, 0x04, 0x73, 0xd5, 0xb4, 0xb3, 0xe9, 0x98,
    0x07, 0x7d, 0x08, 0x80, 0xb6, 0x2b, 0xec, 0x50, 0xb3, 0x5b, 0x00, 0xc6, 0x87, 0x25, 0x01, 0x0b,
    0xe8, 0xb9, 0xdd, 0x30, 0x37, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10,
    0x02, 0x2f, 0x31, 0x28, 0x30, 0x26, 0x30, 0x24, 0x30, 0x22, 0x04, 0x20, 0xef, 0xbd, 0x6d, 0xa8,
    0xd7, 0xc9, 0x21, 0xbc, 0x60, 0x8e, 0xed, 0xcf, 0x5f, 0x04, 0xb0, 0xf4, 0xb7, 0x70, 0x31, 0xe3,
    0x42, 0xf4, 0xb2, 0x56, 0x93, 0x40, 0x3e, 0x63, 0x16, 0x16, 0x2b, 0x50, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x01, 0x00, 0xb9,
    0x15, 0x6c, 0xdb, 0xb4, 0xf2, 0xf1, 0x40, 0x3a, 0xff, 0x5e, 0x24, 0xc1, 0x96, 0xb7, 0xf5, 0x29,
    0xde, 0x01, 0x5c, 0xc7, 0xb6, 0x58, 0x3d, 0x55, 0xff, 0xd0, 0x3b, 0x8e, 0xf0, 0xca, 0xf5, 0x7c,
    0x71, 0x54, 0x72, 0xcd, 0x87, 0x77, 0x20, 0x71, 0x42, 0x10, 0x74, 0xe6, 0x1d, 0x18, 0xf8, 0xdb,
    0xfe, 0xce, 0x02, 0x41, 0x1b, 0x15, 0x9e, 0x72, 0x49, 0x9e, 0x2d, 0x9d, 0x78, 0x5e, 0x39, 0x0a,
    0x3e, 0x7a, 0x84, 0x7b, 0x41, 0x7c, 0x6d, 0x6b, 0xdd, 0xf1, 0x41, 0x53, 0x9e, 0x84, 0xf3, 0x8a,
    0xf7, 0xbc, 0xd7, 0x7a, 0x49, 0x13, 0xd7, 0x04, 0xf7, 0xac, 0xc8, 0x46, 0xd6, 0xc0, 0x88, 0x36,
    0x0b, 0xda, 0x10, 0x7e, 0xef, 0xff, 0x78, 0x4f, 0xd9, 0xb0, 0x1e, 0x25, 0x31, 0xa3, 0x40, 0xef,
    0x49, 0x54, 0xbe, 0x09, 0xb1, 0x2d, 0xc1, 0x5a, 0xcc, 0xdc, 0x61, 0x37, 0x2c, 0x9d, 0x50, 0x44,
    0x5b, 0x16, 0x82, 0xa6, 0x23, 0x3c, 0x2c, 0xc8, 0xa1, 0xba, 0x86, 0x88, 0xf0, 0x55, 0x54, 0x46,
    0x0e, 0xa6, 0x7f, 0xbf, 0xe7, 0x1d, 0x5a, 0x34, 0xaa, 0xcf, 0x93, 0x81, 0x75, 0xfb, 0x08, 0x16,
    0xc4, 0xc7, 0x1b, 0x7f, 0x92, 0x93, 0x3c, 0x74, 0x11, 0x71, 0x4f, 0x0a, 0x7f, 0x33, 0xbe, 0x05,
    0xdf, 0xc9, 0x4e, 0xb7, 0x1c, 0x72, 0x4b, 0xdf, 0x09, 0xc4, 0x30, 0x1a, 0xd9, 0x33, 0x22, 0xba,
    0x22, 0x0a, 0x02, 0xde, 0x47, 0x57, 0x62, 0xea, 0x68, 0x9b, 0x3c, 0x5f, 0x0b, 0xe9, 0x73, 0xa1,
    0x96, 0x36, 0xe8, 0x96, 0xa7, 0x36, 0x74, 0xc6, 0x61, 0x87, 0xc6, 0x20, 0xc2, 0x39, 0xe1, 0xb0,
    0x3c, 0xcd, 0xe8, 0x53, 0x5a, 0x72, 0xb4, 0x5f, 0x87, 0x98, 0xeb, 0x13, 0x9d, 0xae, 0x15, 0xc7,
    0xd4, 0xeb, 0x74, 0x86, 0x48, 0x93, 0xb5, 0x2b, 0xf8, 0x13, 0xca, 0x89, 0x0d, 0x06, 0xc0
};

static const char MSG[] = "hello, time stamps\n";

static BIO *mem(const char *s)
{
    return BIO_new_mem_buf(s, -1);
}

static BIO *mem_der(const unsigned char *d, size_t n)
{
    return BIO_new_mem_buf(d, (int)n);
}

static X509 *cert(const char *pem)
{
    BIO *b = mem(pem);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static EVP_PKEY *key(const char *pem)
{
    BIO *b = mem(pem);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);

    BIO_free(b);
    return k;
}

static X509_STORE *store_of(const char *pem)
{
    X509_STORE *s = X509_STORE_new();
    X509 *x = cert(pem);

    X509_STORE_add_cert(s, x);
    X509_free(x);
    return s;
}

static void hex(const char *label, const unsigned char *d, int n)
{
    int i;

    printf("  %s (%d):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 ? "\n    " : "", d[i]);
    printf("\n");
}

static char *write_file(const char *text, size_t len)
{
    static char names[8][64];
    static int k;
    char *name = names[k++ % 8];
    int fd;

    strcpy(name, "/tmp/rustyssl-ts-XXXXXX");
    fd = mkstemp(name);
    if (fd < 0)
        return NULL;
    if (write(fd, text, len) < 0)
        name[0] = '\0';
    close(fd);
    return name;
}

#define DER_SAME(type, obj, der, label)                                         \
    do {                                                                        \
        unsigned char *p_ = NULL;                                               \
        int n_ = i2d_##type(obj, &p_);                                          \
        check(n_ == (int)sizeof(der) && memcmp(p_, der, sizeof(der)) == 0, label); \
        OPENSSL_free(p_);                                                       \
    } while (0)

#define DER_PRINT(type, obj, label)                                             \
    do {                                                                        \
        unsigned char *p_ = NULL;                                               \
        int n_ = i2d_##type(obj, &p_);                                          \
        hex(label, p_, n_);                                                     \
        OPENSSL_free(p_);                                                       \
    } while (0)

/* The request, the reply, and the token the reference tool made. */
static void reference_objects(void)
{
    const unsigned char *p = REQ_DER;
    TS_REQ *req = d2i_TS_REQ(NULL, &p, sizeof(REQ_DER)), *req2;
    TS_RESP *resp, *resp2;
    TS_TST_INFO *tst, *tst2;
    TS_MSG_IMPRINT *mi;
    TS_STATUS_INFO *si;
    TS_ACCURACY *acc;
    PKCS7 *token;
    BIO *b;
    FILE *f;

    printf("# the reference's request\n");
    check(req != NULL && p == REQ_DER + sizeof(REQ_DER), "d2i_TS_REQ reads it all");
    TS_REQ_print_bio(out, req);
    DER_SAME(TS_REQ, req, REQ_DER, "i2d_TS_REQ gives it back");
    printf("  version %ld, cert_req %d, nonce %s, exts %d\n", TS_REQ_get_version(req),
           TS_REQ_get_cert_req(req), TS_REQ_get_nonce(req) == NULL ? "NULL" : "set",
           TS_REQ_get_ext_count(req));
    TS_OBJ_print_bio(out, TS_REQ_get_policy_id(req));
    mi = TS_REQ_get_msg_imprint(req);
    TS_X509_ALGOR_print_bio(out, TS_MSG_IMPRINT_get_algo(mi));
    hex("hash", ASN1_STRING_get0_data(TS_MSG_IMPRINT_get_msg(mi)),
        ASN1_STRING_length(TS_MSG_IMPRINT_get_msg(mi)));
    req2 = TS_REQ_dup(req);
    DER_SAME(TS_REQ, req2, REQ_DER, "TS_REQ_dup");
    TS_REQ_free(req2);
    b = BIO_new(BIO_s_mem());
    check(i2d_TS_REQ_bio(b, req) == 1, "i2d_TS_REQ_bio");
    req2 = d2i_TS_REQ_bio(b, NULL);
    DER_SAME(TS_REQ, req2, REQ_DER, "d2i_TS_REQ_bio");
    TS_REQ_free(req2);
    BIO_free(b);
    f = tmpfile();
    check(i2d_TS_REQ_fp(f, req) == 1, "i2d_TS_REQ_fp");
    rewind(f);
    req2 = d2i_TS_REQ_fp(f, NULL);
    DER_SAME(TS_REQ, req2, REQ_DER, "d2i_TS_REQ_fp");
    TS_REQ_free(req2);
    fclose(f);

    mi = TS_MSG_IMPRINT_dup(TS_REQ_get_msg_imprint(req));
    b = BIO_new(BIO_s_mem());
    check(i2d_TS_MSG_IMPRINT_bio(b, mi) == 1, "i2d_TS_MSG_IMPRINT_bio");
    TS_MSG_IMPRINT_free(mi);
    mi = d2i_TS_MSG_IMPRINT_bio(b, NULL);
    TS_MSG_IMPRINT_print_bio(out, mi);
    BIO_free(b);
    f = tmpfile();
    check(i2d_TS_MSG_IMPRINT_fp(f, mi) == 1, "i2d_TS_MSG_IMPRINT_fp");
    rewind(f);
    TS_MSG_IMPRINT_free(mi);
    mi = d2i_TS_MSG_IMPRINT_fp(f, NULL);
    check(mi != NULL, "d2i_TS_MSG_IMPRINT_fp");
    DER_PRINT(TS_MSG_IMPRINT, mi, "imprint");
    fclose(f);
    {
        unsigned char *q = NULL;
        int n = i2d_TS_MSG_IMPRINT(mi, &q);
        const unsigned char *r = q;
        TS_MSG_IMPRINT *mi2 = d2i_TS_MSG_IMPRINT(NULL, &r, n);

        check(mi2 != NULL && r == q + n, "d2i_TS_MSG_IMPRINT");
        TS_MSG_IMPRINT_free(mi2);
        OPENSSL_free(q);
    }
    TS_MSG_IMPRINT_free(mi);

    printf("# the reference's reply\n");
    p = RESP_DER;
    resp = d2i_TS_RESP(NULL, &p, sizeof(RESP_DER));
    check(resp != NULL && p == RESP_DER + sizeof(RESP_DER), "d2i_TS_RESP reads it all");
    TS_RESP_print_bio(out, resp);
    DER_SAME(TS_RESP, resp, RESP_DER, "i2d_TS_RESP gives it back");
    resp2 = TS_RESP_dup(resp);
    DER_SAME(TS_RESP, resp2, RESP_DER, "TS_RESP_dup");
    TS_RESP_free(resp2);
    b = BIO_new(BIO_s_mem());
    check(i2d_TS_RESP_bio(b, resp) == 1, "i2d_TS_RESP_bio");
    resp2 = d2i_TS_RESP_bio(b, NULL);
    DER_SAME(TS_RESP, resp2, RESP_DER, "d2i_TS_RESP_bio");
    TS_RESP_free(resp2);
    BIO_free(b);
    f = tmpfile();
    check(i2d_TS_RESP_fp(f, resp) == 1, "i2d_TS_RESP_fp");
    rewind(f);
    resp2 = d2i_TS_RESP_fp(f, NULL);
    DER_SAME(TS_RESP, resp2, RESP_DER, "d2i_TS_RESP_fp");
    TS_RESP_free(resp2);
    fclose(f);

    si = TS_RESP_get_status_info(resp);
    printf("  status %ld, text %s, failure info %s\n", ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(si)),
           TS_STATUS_INFO_get0_text(si) == NULL ? "NULL" : "set",
           TS_STATUS_INFO_get0_failure_info(si) == NULL ? "NULL" : "set");
    TS_STATUS_INFO_print_bio(out, si);
    tst = TS_RESP_get_tst_info(resp);
    TS_TST_INFO_print_bio(out, tst);
    printf("  version %ld, ordering %d, nonce %s, exts %d\n", TS_TST_INFO_get_version(tst),
           TS_TST_INFO_get_ordering(tst), TS_TST_INFO_get_nonce(tst) == NULL ? "NULL" : "set",
           TS_TST_INFO_get_ext_count(tst));
    TS_OBJ_print_bio(out, TS_TST_INFO_get_policy_id(tst));
    TS_MSG_IMPRINT_print_bio(out, TS_TST_INFO_get_msg_imprint(tst));
    printf("  serial ");
    TS_ASN1_INTEGER_print_bio(out, TS_TST_INFO_get_serial(tst));
    printf("\n  time ");
    ASN1_GENERALIZEDTIME_print(out, TS_TST_INFO_get_time(tst));
    printf("\n");
    acc = TS_TST_INFO_get_accuracy(tst);
    printf("  accuracy %ld %ld %ld\n", ASN1_INTEGER_get(TS_ACCURACY_get_seconds(acc)),
           ASN1_INTEGER_get(TS_ACCURACY_get_millis(acc)), ASN1_INTEGER_get(TS_ACCURACY_get_micros(acc)));
    GENERAL_NAME_print(out, TS_TST_INFO_get_tsa(tst));
    printf("\n");

    p = TOKEN_DER;
    token = d2i_PKCS7(NULL, &p, sizeof(TOKEN_DER));
    tst2 = PKCS7_to_TS_TST_INFO(token);
    {
        unsigned char *a = NULL, *c = NULL;
        int na = i2d_TS_TST_INFO(tst, &a), nc = i2d_TS_TST_INFO(tst2, &c);

        check(na > 0 && na == nc && memcmp(a, c, na) == 0, "PKCS7_to_TS_TST_INFO is the reply's TSTInfo");
        OPENSSL_free(a);
        OPENSSL_free(c);
    }
    check(TS_RESP_get_token(resp) != NULL && OBJ_obj2nid(TS_RESP_get_token(resp)->type) == NID_pkcs7_signed,
          "TS_RESP_get_token");
    TS_TST_INFO_free(tst2);
    b = BIO_new(BIO_s_mem());
    check(i2d_TS_TST_INFO_bio(b, tst) == 1, "i2d_TS_TST_INFO_bio");
    tst2 = d2i_TS_TST_INFO_bio(b, NULL);
    check(tst2 != NULL, "d2i_TS_TST_INFO_bio");
    TS_TST_INFO_free(tst2);
    BIO_free(b);
    f = tmpfile();
    check(i2d_TS_TST_INFO_fp(f, tst) == 1, "i2d_TS_TST_INFO_fp");
    rewind(f);
    tst2 = d2i_TS_TST_INFO_fp(f, NULL);
    check(tst2 != NULL, "d2i_TS_TST_INFO_fp");
    TS_TST_INFO_free(tst2);
    fclose(f);
    tst2 = TS_TST_INFO_dup(tst);
    check(tst2 != NULL, "TS_TST_INFO_dup");
    TS_TST_INFO_free(tst2);

    printf("# PKCS7_to_TS_TST_INFO of the wrong things\n");
    {
        PKCS7 *data = PKCS7_new();

        PKCS7_set_type(data, NID_pkcs7_data);
        check(PKCS7_to_TS_TST_INFO(data) == NULL, "of data");
        errors();
        PKCS7_free(data);
    }
    PKCS7_free(token);
    TS_RESP_free(resp);
    TS_REQ_free(req);
}

/* Verifying the reference's reply and token. */
static void verify_reference(void)
{
    const unsigned char *p = REQ_DER;
    TS_REQ *req = d2i_TS_REQ(NULL, &p, sizeof(REQ_DER)), *other;
    TS_RESP *resp;
    TS_VERIFY_CTX *ctx;
    PKCS7 *token;
    X509 *signer = NULL;
    ASN1_INTEGER *nonce;
    ASN1_OBJECT *policy;
    unsigned char *imprint;
    BIO *data;

    p = RESP_DER;
    resp = d2i_TS_RESP(NULL, &p, sizeof(RESP_DER));
    p = TOKEN_DER;
    token = d2i_PKCS7(NULL, &p, sizeof(TOKEN_DER));

    printf("# verifying against the request\n");
    ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL);
    check(ctx != NULL, "TS_REQ_to_TS_VERIFY_CTX");
    printf("  flags %x\n", TS_VERIFY_CTX_add_flags(ctx, TS_VFY_SIGNATURE));
    TS_VERIFY_CTX_set0_store(ctx, store_of(CA_PEM));
    check(TS_RESP_verify_response(ctx, resp) == 1, "TS_RESP_verify_response");
    errors();
    check(TS_RESP_verify_token(ctx, token) == 1, "TS_RESP_verify_token");
    errors();
    printf("  flags %x\n", TS_VERIFY_CTX_add_flags(ctx, TS_VFY_SIGNER));
    check(TS_RESP_verify_response(ctx, resp) == 1, "with the signer's name");
    errors();
    TS_VERIFY_CTX_free(ctx);

    printf("# the signature alone\n");
    {
        X509_STORE *s = store_of(CA_PEM), *e = X509_STORE_new();

        check(TS_RESP_verify_signature(token, NULL, s, &signer) == 1, "TS_RESP_verify_signature");
        X509_NAME_print_ex(out, X509_get_subject_name(signer), 0, XN_FLAG_ONELINE);
        printf("\n");
        X509_free(signer);
        check(TS_RESP_verify_signature(token, NULL, e, NULL) == 0, "with no trusted root");
        errors();
        check(TS_RESP_verify_signature(NULL, NULL, s, NULL) == 0, "of no token");
        errors();
        X509_STORE_free(s);
        X509_STORE_free(e);
    }

    printf("# a nonce asked for but not returned\n");
    other = TS_REQ_dup(req);
    nonce = ASN1_INTEGER_new();
    ASN1_INTEGER_set(nonce, 0x1234);
    TS_REQ_set_nonce(other, nonce);
    ctx = TS_REQ_to_TS_VERIFY_CTX(other, NULL);
    printf("  flags %x\n", TS_VERIFY_CTX_set_flags(ctx, TS_VFY_NONCE | TS_VFY_VERSION));
    check(TS_RESP_verify_response(ctx, resp) == 0, "refused");
    errors();

    printf("# another policy\n");
    policy = OBJ_txt2obj("1.2.3.4.5", 1);
    TS_REQ_set_policy_id(other, policy);
    check(TS_REQ_to_TS_VERIFY_CTX(other, ctx) == ctx, "into the same context");
    printf("  flags %x\n", TS_VERIFY_CTX_set_flags(ctx, TS_VFY_POLICY));
    check(TS_RESP_verify_response(ctx, resp) == 0, "refused");
    errors();

    printf("# another imprint\n");
    imprint = OPENSSL_malloc(32);
    memset(imprint, 0x5a, 32);
    TS_VERIFY_CTX_set0_imprint(ctx, imprint, 32);
    TS_VERIFY_CTX_set_flags(ctx, TS_VFY_IMPRINT);
    check(TS_RESP_verify_response(ctx, resp) == 0, "refused");
    errors();
    imprint = OPENSSL_malloc(31);
    memset(imprint, 0, 31);
    check(TS_VERIFY_CTX_set_imprint(ctx, imprint, 31) == imprint, "TS_VERIFY_CTX_set_imprint");
    check(TS_RESP_verify_response(ctx, resp) == 0, "refused, shorter");
    errors();
    TS_VERIFY_CTX_cleanup(ctx);
    TS_VERIFY_CTX_init(ctx);
    TS_VERIFY_CTX_free(ctx);

    printf("# the data\n");
    ctx = TS_VERIFY_CTX_new();
    TS_VERIFY_CTX_set_flags(ctx, TS_VFY_VERSION | TS_VFY_DATA | TS_VFY_SIGNATURE);
    data = mem(MSG);
    check(TS_VERIFY_CTX_set_data(ctx, data) == data, "TS_VERIFY_CTX_set_data");
    {
        X509_STORE *s = store_of(CA_PEM);

        check(TS_VERIFY_CTX_set_store(ctx, s) == s, "TS_VERIFY_CTX_set_store");
    }
    check(TS_VERIFY_CTX_set_certs(ctx, NULL) == NULL, "TS_VERIFY_CTX_set_certs");
    check(TS_RESP_verify_response(ctx, resp) == 1, "the message verifies");
    errors();
    TS_VERIFY_CTX_set0_data(ctx, mem("other data\n"));
    check(TS_RESP_verify_response(ctx, resp) == 0, "other data does not");
    errors();
    {
        STACK_OF(X509) *certs = sk_X509_new_null();

        sk_X509_push(certs, cert(TSA_PEM));
        TS_VERIFY_CTX_set0_certs(ctx, certs);
    }
    TS_VERIFY_CTX_set0_data(ctx, mem(MSG));
    check(TS_RESP_verify_token(ctx, token) == 1, "with untrusted certificates");
    errors();
    TS_VERIFY_CTX_free(ctx);

    ASN1_OBJECT_free(policy);
    ASN1_INTEGER_free(nonce);
    TS_REQ_free(other);
    PKCS7_free(token);
    TS_RESP_free(resp);
    TS_REQ_free(req);
}

/* A request, a TSTInfo, and their parts built field by field. */
static void build(void)
{
    TS_REQ *req = TS_REQ_new();
    TS_MSG_IMPRINT *mi = TS_MSG_IMPRINT_new();
    X509_ALGOR *alg = X509_ALGOR_new();
    unsigned char digest[32];
    ASN1_OBJECT *policy = OBJ_txt2obj("1.2.3.4.1", 1);
    ASN1_INTEGER *n = ASN1_INTEGER_new();
    X509_EXTENSION *ext, *got;
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    TS_TST_INFO *tst = TS_TST_INFO_new(), *tst2;
    TS_ACCURACY *acc = TS_ACCURACY_new(), *acc2;
    ASN1_GENERALIZEDTIME *t = ASN1_GENERALIZEDTIME_new();
    GENERAL_NAME *tsa;
    TS_STATUS_INFO *si, *si2;
    TS_RESP *resp;
    int crit = -1, idx = -1;
    void *d2i;

    printf("# a request\n");
    check(TS_REQ_set_version(req, 1) == 1, "TS_REQ_set_version");
    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha256), V_ASN1_NULL, NULL);
    check(TS_MSG_IMPRINT_set_algo(mi, alg) == 1, "TS_MSG_IMPRINT_set_algo");
    check(TS_MSG_IMPRINT_set_algo(mi, TS_MSG_IMPRINT_get_algo(mi)) == 1, "set to itself");
    EVP_Digest(MSG, strlen(MSG), digest, NULL, EVP_sha256(), NULL);
    check(TS_MSG_IMPRINT_set_msg(mi, digest, 32) == 1, "TS_MSG_IMPRINT_set_msg");
    check(TS_REQ_set_msg_imprint(req, mi) == 1, "TS_REQ_set_msg_imprint");
    check(TS_REQ_set_policy_id(req, policy) == 1, "TS_REQ_set_policy_id");
    ASN1_INTEGER_set(n, 0x1234567);
    check(TS_REQ_set_nonce(req, n) == 1, "TS_REQ_set_nonce");
    check(TS_REQ_set_cert_req(req, 5) == 1 && TS_REQ_get_cert_req(req) == 1, "TS_REQ_set_cert_req");
    ASN1_OCTET_STRING_set(os, (const unsigned char *)"\x04\x02\x01\x02", 4);
    ext = X509_EXTENSION_create_by_NID(NULL, NID_subject_key_identifier, 0, os);
    check(TS_REQ_add_ext(req, ext, -1) == 1, "TS_REQ_add_ext");
    X509_EXTENSION_set_critical(ext, 1);
    X509_EXTENSION_set_object(ext, OBJ_txt2obj("1.2.3.4.99", 1));
    check(TS_REQ_add_ext(req, ext, 0) == 1, "at the front");
    printf("  exts %d, by NID %d, by OBJ %d, critical %d %d\n", TS_REQ_get_ext_count(req),
           TS_REQ_get_ext_by_NID(req, NID_subject_key_identifier, -1),
           TS_REQ_get_ext_by_OBJ(req, X509_EXTENSION_get_object(ext), -1), TS_REQ_get_ext_by_critical(req, 1, -1),
           TS_REQ_get_ext_by_critical(req, 0, -1));
    check(sk_X509_EXTENSION_num(TS_REQ_get_exts(req)) == 2, "TS_REQ_get_exts");
    d2i = TS_REQ_get_ext_d2i(req, NID_subject_key_identifier, &crit, &idx);
    printf("  d2i %s, crit %d, idx %d\n", d2i == NULL ? "NULL" : "set", crit, idx);
    ASN1_OCTET_STRING_free(d2i);
    TS_REQ_print_bio(out, req);
    DER_PRINT(TS_REQ, req, "request");
    got = TS_REQ_delete_ext(req, 0);
    check(got != NULL && TS_REQ_get_ext_count(req) == 1, "TS_REQ_delete_ext");
    X509_EXTENSION_free(got);
    check(TS_REQ_get_ext(req, 0) != NULL && TS_REQ_get_ext(req, 1) == NULL, "TS_REQ_get_ext");
    TS_REQ_ext_free(req);
    check(TS_REQ_get_ext_count(req) == 0 && TS_REQ_get_exts(req) == NULL, "TS_REQ_ext_free");
    TS_REQ_ext_free(NULL);

    printf("# a TSTInfo\n");
    check(TS_TST_INFO_set_version(tst, 1) == 1, "TS_TST_INFO_set_version");
    check(TS_TST_INFO_set_policy_id(tst, policy) == 1, "TS_TST_INFO_set_policy_id");
    check(TS_TST_INFO_set_msg_imprint(tst, mi) == 1, "TS_TST_INFO_set_msg_imprint");
    ASN1_INTEGER_set(n, 77);
    check(TS_TST_INFO_set_serial(tst, n) == 1, "TS_TST_INFO_set_serial");
    ASN1_GENERALIZEDTIME_set_string(t, "20261017120000.25Z");
    check(TS_TST_INFO_set_time(tst, t) == 1, "TS_TST_INFO_set_time");
    ASN1_INTEGER_set(n, 2);
    check(TS_ACCURACY_set_seconds(acc, n) == 1, "TS_ACCURACY_set_seconds");
    check(TS_ACCURACY_set_millis(acc, n) == 1, "TS_ACCURACY_set_millis");
    check(TS_ACCURACY_set_micros(acc, n) == 1, "TS_ACCURACY_set_micros");
    check(TS_ACCURACY_set_micros(acc, NULL) == 1 && TS_ACCURACY_get_micros(acc) == NULL, "cleared");
    check(TS_TST_INFO_set_accuracy(tst, acc) == 1, "TS_TST_INFO_set_accuracy");
    check(TS_TST_INFO_set_ordering(tst, 1) == 1, "TS_TST_INFO_set_ordering");
    ASN1_INTEGER_set(n, -5);
    check(TS_TST_INFO_set_nonce(tst, n) == 1, "TS_TST_INFO_set_nonce");
    tsa = GENERAL_NAME_new();
    {
        ASN1_IA5STRING *dns = ASN1_IA5STRING_new();

        ASN1_STRING_set(dns, "tsa.example", -1);
        GENERAL_NAME_set0_value(tsa, GEN_DNS, dns);
    }
    check(TS_TST_INFO_set_tsa(tst, tsa) == 1, "TS_TST_INFO_set_tsa");
    X509_EXTENSION_set_critical(ext, 0);
    check(TS_TST_INFO_add_ext(tst, ext, -1) == 1, "TS_TST_INFO_add_ext");
    printf("  exts %d, by NID %d, by OBJ %d, critical %d\n", TS_TST_INFO_get_ext_count(tst),
           TS_TST_INFO_get_ext_by_NID(tst, NID_subject_key_identifier, -1),
           TS_TST_INFO_get_ext_by_OBJ(tst, X509_EXTENSION_get_object(ext), -1),
           TS_TST_INFO_get_ext_by_critical(tst, 0, -1));
    check(TS_TST_INFO_get_ext(tst, 0) != NULL && sk_X509_EXTENSION_num(TS_TST_INFO_get_exts(tst)) == 1,
          "TS_TST_INFO_get_ext");
    crit = idx = -1;
    printf("  d2i %s, crit %d\n",
           TS_TST_INFO_get_ext_d2i(tst, NID_subject_key_identifier, &crit, &idx) == NULL ? "NULL" : "set", crit);
    TS_TST_INFO_print_bio(out, tst);
    DER_PRINT(TS_TST_INFO, tst, "TSTInfo");
    {
        unsigned char *q = NULL;
        int len = i2d_TS_TST_INFO(tst, &q);
        const unsigned char *r = q;

        tst2 = d2i_TS_TST_INFO(NULL, &r, len);
        check(tst2 != NULL && r == q + len, "d2i_TS_TST_INFO");
        TS_TST_INFO_free(tst2);
        OPENSSL_free(q);
    }
    got = TS_TST_INFO_delete_ext(tst, 0);
    X509_EXTENSION_free(got);
    TS_TST_INFO_ext_free(tst);
    check(TS_TST_INFO_get_ext_count(tst) == 0, "TS_TST_INFO_ext_free");
    TS_TST_INFO_ext_free(NULL);

    printf("# an accuracy\n");
    DER_PRINT(TS_ACCURACY, acc, "accuracy");
    acc2 = TS_ACCURACY_dup(acc);
    {
        unsigned char *q = NULL;
        int len = i2d_TS_ACCURACY(acc2, &q);
        const unsigned char *r = q;
        TS_ACCURACY *acc3 = d2i_TS_ACCURACY(NULL, &r, len);

        check(acc3 != NULL && ASN1_INTEGER_get(TS_ACCURACY_get_millis(acc3)) == 2, "d2i_TS_ACCURACY");
        TS_ACCURACY_free(acc3);
        OPENSSL_free(q);
    }
    TS_ACCURACY_free(acc2);

    printf("# a status and a response\n");
    si = TS_STATUS_INFO_new();
    check(TS_STATUS_INFO_set_status(si, TS_STATUS_WAITING) == 1, "TS_STATUS_INFO_set_status");
    TS_STATUS_INFO_print_bio(out, si);
    DER_PRINT(TS_STATUS_INFO, si, "status");
    si2 = TS_STATUS_INFO_dup(si);
    {
        unsigned char *q = NULL;
        int len = i2d_TS_STATUS_INFO(si2, &q);
        const unsigned char *r = q;
        TS_STATUS_INFO *si3 = d2i_TS_STATUS_INFO(NULL, &r, len);

        check(si3 != NULL && ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(si3)) == 3, "d2i_TS_STATUS_INFO");
        TS_STATUS_INFO_free(si3);
        OPENSSL_free(q);
    }
    TS_STATUS_INFO_free(si2);
    resp = TS_RESP_new();
    check(TS_RESP_set_status_info(resp, si) == 1, "TS_RESP_set_status_info");
    TS_RESP_set_tst_info(resp, NULL, TS_TST_INFO_dup(tst));
    TS_RESP_print_bio(out, resp);
    TS_RESP_set_tst_info(resp, NULL, NULL);
    TS_RESP_print_bio(out, resp);
    DER_PRINT(TS_RESP, resp, "response");
    {
        unsigned char *q = NULL;
        int len = i2d_TS_RESP(resp, &q);
        const unsigned char *r = q;
        TS_RESP *resp2 = d2i_TS_RESP(NULL, &r, len);

        check(resp2 != NULL, "d2i_TS_RESP of a rejection");
        TS_RESP_free(resp2);
        OPENSSL_free(q);
    }
    printf("# a granted response with no token\n");
    TS_STATUS_INFO_set_status(si, TS_STATUS_GRANTED);
    TS_RESP_set_status_info(resp, si);
    {
        unsigned char *q = NULL;
        int len = i2d_TS_RESP(resp, &q);
        const unsigned char *r = q;

        check(d2i_TS_RESP(NULL, &r, len) == NULL, "refused");
        errors();
        OPENSSL_free(q);
    }
    TS_RESP_free(resp);
    TS_STATUS_INFO_free(si);

    GENERAL_NAME_free(tsa);
    ASN1_GENERALIZEDTIME_free(t);
    TS_ACCURACY_free(acc);
    TS_TST_INFO_free(tst);
    ASN1_OCTET_STRING_free(os);
    X509_EXTENSION_free(ext);
    ASN1_INTEGER_free(n);
    ASN1_OBJECT_free(policy);
    X509_ALGOR_free(alg);
    TS_MSG_IMPRINT_free(mi);
    TS_REQ_free(req);
}

/* The printers of ts_lib.c on their own. */
static void lib_print(void)
{
    ASN1_INTEGER *n = ASN1_INTEGER_new();
    ASN1_OBJECT *o = OBJ_txt2obj("1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20.21.22.23.24.25.26.27.28."
                                 "29.30.31.32.33.34.35.36.37.38.39.40.41.42.43.44.45.46.47.48.49.50",
                                 1);
    X509_ALGOR *alg = X509_ALGOR_new();
    STACK_OF(X509_EXTENSION) *exts = NULL;
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();

    printf("# the library's printers\n");
    ASN1_INTEGER_set(n, 0);
    printf("  %d\n", TS_ASN1_INTEGER_print_bio(out, n));
    ASN1_INTEGER_set(n, -255);
    printf("  %d\n", TS_ASN1_INTEGER_print_bio(out, n));
    ASN1_INTEGER_set_uint64(n, 0xffffffffffffffffULL);
    printf("  %d\n", TS_ASN1_INTEGER_print_bio(out, n));
    TS_OBJ_print_bio(out, OBJ_nid2obj(NID_sha256));
    TS_OBJ_print_bio(out, o);
    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha384), V_ASN1_UNDEF, NULL);
    printf("  %d\n", TS_X509_ALGOR_print_bio(out, alg));
    X509_ALGOR_set0(alg, OBJ_txt2obj("1.2.3.4", 1), V_ASN1_UNDEF, NULL);
    printf("  %d\n", TS_X509_ALGOR_print_bio(out, alg));
    bc->ca = 1;
    X509V3_add1_i2d(&exts, NID_basic_constraints, bc, 1, 0);
    ASN1_OCTET_STRING_set(os, (const unsigned char *)"\x01\x02\x03", 3);
    {
        ASN1_OBJECT *oid = OBJ_txt2obj("1.2.3.4.7", 1);
        X509_EXTENSION *ext = X509_EXTENSION_create_by_OBJ(NULL, oid, 0, os);

        X509v3_add_ext(&exts, ext, -1);
        X509_EXTENSION_free(ext);
        ASN1_OBJECT_free(oid);
    }
    printf("  %d\n", TS_ext_print_bio(out, exts));
    printf("  %d\n", TS_ext_print_bio(out, NULL));
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    BASIC_CONSTRAINTS_free(bc);
    ASN1_OCTET_STRING_free(os);
    X509_ALGOR_free(alg);
    ASN1_OBJECT_free(o);
    ASN1_INTEGER_free(n);
}

static int serial_calls;

static ASN1_INTEGER *serial_cb(TS_RESP_CTX *ctx, void *data)
{
    ASN1_INTEGER *s = ASN1_INTEGER_new();

    serial_calls++;
    printf("  serial callback: data %s, request %s, TSTInfo %s\n", (const char *)data,
           TS_RESP_CTX_get_request(ctx) != NULL ? "set" : "NULL",
           TS_RESP_CTX_get_tst_info(ctx) != NULL ? "set" : "NULL");
    ASN1_INTEGER_set(s, 0x1234 + serial_calls);
    return s;
}

static long fixed_usec = 123000;

static int time_cb(TS_RESP_CTX *ctx, void *data, long *sec, long *usec)
{
    (void)ctx;
    *sec = *(long *)data;
    *usec = fixed_usec;
    return 1;
}

static int time_fail_cb(TS_RESP_CTX *ctx, void *data, long *sec, long *usec)
{
    (void)data;
    (void)sec;
    (void)usec;
    TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION, "No clock here.");
    TS_RESP_CTX_add_failure_info(ctx, TS_INFO_TIME_NOT_AVAILABLE);
    return 0;
}

static int accept_cb(TS_RESP_CTX *ctx, X509_EXTENSION *ext, void *data)
{
    (void)data;
    printf("  extension callback: ");
    i2a_ASN1_OBJECT(out, X509_EXTENSION_get_object(ext));
    printf("\n");
    printf("  cond: %d\n", TS_RESP_CTX_set_status_info_cond(ctx, TS_STATUS_GRANTED_WITH_MODS, "Extension ignored."));
    printf("  cond again: %d\n", TS_RESP_CTX_set_status_info_cond(ctx, TS_STATUS_REJECTION, "Not seen."));
    return 1;
}

static long when = 1700000000;

/* A response to the DER request, shown, and verified against it. */
static TS_RESP *respond(TS_RESP_CTX *ctx, const unsigned char *der, size_t n, const char *label)
{
    BIO *b = mem_der(der, n);
    TS_RESP *resp = TS_RESP_create_response(ctx, b);

    printf("# %s\n", label);
    check(resp != NULL, label);
    errors();
    if (resp != NULL)
        TS_RESP_print_bio(out, resp);
    BIO_free(b);
    return resp;
}

static void verify_made(TS_RESP *resp, const unsigned char *der, size_t n, int extra)
{
    const unsigned char *p = der;
    TS_REQ *req = d2i_TS_REQ(NULL, &p, n);
    TS_VERIFY_CTX *v = TS_REQ_to_TS_VERIFY_CTX(req, NULL);

    TS_VERIFY_CTX_add_flags(v, TS_VFY_SIGNATURE | extra);
    TS_VERIFY_CTX_set0_store(v, store_of(CA_PEM));
    printf("  verify: %d\n", TS_RESP_verify_response(v, resp));
    errors();
    TS_VERIFY_CTX_free(v);
    TS_REQ_free(req);
}

static unsigned char *request_der(TS_REQ *req, int *n)
{
    unsigned char *p = NULL;

    *n = i2d_TS_REQ(req, &p);
    return p;
}

/* Responses made here. */
static void sign(void)
{
    TS_RESP_CTX *ctx = TS_RESP_CTX_new();
    X509 *tsa = cert(TSA_PEM), *ee = cert(RSA_PEM), *ca = cert(CA_PEM);
    EVP_PKEY *k = key(TSA_KEY_PEM), *eek = key(RSA_KEY_PEM);
    STACK_OF(X509) *chain = sk_X509_new_null();
    ASN1_OBJECT *def = OBJ_txt2obj("1.2.3.4.1", 1), *other = OBJ_txt2obj("1.2.3.4.5", 1);
    TS_RESP *resp;
    const unsigned char *p;
    TS_REQ *req;
    unsigned char *der;
    int n;

    printf("# setting up a TSA\n");
    check(TS_RESP_CTX_set_signer_cert(ctx, ee) == 0, "a signer with no time-stamping usage is refused");
    errors();
    check(TS_RESP_CTX_set_signer_cert(ctx, tsa) == 1, "TS_RESP_CTX_set_signer_cert");
    check(TS_RESP_CTX_set_signer_key(ctx, k) == 1, "TS_RESP_CTX_set_signer_key");
    sk_X509_push(chain, ca);
    check(TS_RESP_CTX_set_certs(ctx, chain) == 1, "TS_RESP_CTX_set_certs");
    check(TS_RESP_CTX_set_certs(ctx, NULL) == 1, "TS_RESP_CTX_set_certs, none");
    check(TS_RESP_CTX_set_certs(ctx, chain) == 1, "TS_RESP_CTX_set_certs, again");
    check(TS_RESP_CTX_set_def_policy(ctx, def) == 1, "TS_RESP_CTX_set_def_policy");
    check(TS_RESP_CTX_add_policy(ctx, other) == 1, "TS_RESP_CTX_add_policy");
    check(TS_RESP_CTX_add_md(ctx, EVP_sha512()) == 1 && TS_RESP_CTX_add_md(ctx, EVP_sha256()) == 1,
          "TS_RESP_CTX_add_md");
    check(TS_RESP_CTX_set_accuracy(ctx, 1, 500, 100) == 1, "TS_RESP_CTX_set_accuracy");
    check(TS_RESP_CTX_set_clock_precision_digits(ctx, 7) == 0, "7 digits are too many");
    check(TS_RESP_CTX_set_clock_precision_digits(ctx, 3) == 1, "TS_RESP_CTX_set_clock_precision_digits");
    TS_RESP_CTX_add_flags(ctx, TS_ORDERING | TS_TSA_NAME);
    TS_RESP_CTX_set_time_cb(ctx, time_cb, &when);
    TS_RESP_CTX_set_serial_cb(ctx, serial_cb, "data");
    check(TS_RESP_CTX_set_signer_digest(ctx, EVP_sha256()) == 1, "TS_RESP_CTX_set_signer_digest");
    check(TS_RESP_CTX_get_request(ctx) == NULL && TS_RESP_CTX_get_tst_info(ctx) == NULL, "nothing in progress");

    resp = respond(ctx, REQ_DER, sizeof(REQ_DER), "answering the reference's request");
    verify_made(resp, REQ_DER, sizeof(REQ_DER), TS_VFY_SIGNER);
    {
        PKCS7 *token = TS_RESP_get_token(resp);
        PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(token), 0);

        printf("  certs %d, signingCertificate %s, V2 %s\n", sk_X509_num(token->d.sign->cert),
               PKCS7_get_signed_attribute(si, NID_id_smime_aa_signingCertificate) ? "yes" : "no",
               PKCS7_get_signed_attribute(si, NID_id_smime_aa_signingCertificateV2) ? "yes" : "no");
    }
    TS_RESP_free(resp);

    printf("# with SHA-256 signing-certificate IDs and the chain's\n");
    check(TS_RESP_CTX_set_ess_cert_id_digest(ctx, EVP_sha256()) == 1, "TS_RESP_CTX_set_ess_cert_id_digest");
    TS_RESP_CTX_add_flags(ctx, TS_ESS_CERT_ID_CHAIN);
    fixed_usec = 120000;
    TS_RESP_CTX_set_clock_precision_digits(ctx, 6);
    resp = respond(ctx, REQ_NOCERT_DER, sizeof(REQ_NOCERT_DER), "a request for no certificates");
    {
        PKCS7 *token = TS_RESP_get_token(resp);
        PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(token), 0);
        STACK_OF(X509) *untrusted = sk_X509_new_null();
        X509_STORE *s = store_of(CA_PEM);
        X509 *signer = NULL;

        printf("  certs %d, signingCertificate %s, V2 %s\n", sk_X509_num(token->d.sign->cert),
               PKCS7_get_signed_attribute(si, NID_id_smime_aa_signingCertificate) ? "yes" : "no",
               PKCS7_get_signed_attribute(si, NID_id_smime_aa_signingCertificateV2) ? "yes" : "no");
        check(TS_RESP_verify_signature(token, NULL, s, NULL) == 0, "the signer is needed");
        errors();
        sk_X509_push(untrusted, tsa);
        check(TS_RESP_verify_signature(token, untrusted, s, &signer) == 1 && signer == tsa, "given it");
        errors();
        X509_free(signer);
        sk_X509_free(untrusted);
        X509_STORE_free(s);
    }
    TS_RESP_free(resp);

    printf("# no fraction\n");
    TS_RESP_CTX_set_clock_precision_digits(ctx, 0);
    resp = respond(ctx, REQ_DER, sizeof(REQ_DER), "0 digits");
    TS_RESP_free(resp);
    fixed_usec = 0;
    TS_RESP_CTX_set_clock_precision_digits(ctx, 6);
    resp = respond(ctx, REQ_DER, sizeof(REQ_DER), "6 digits of zero");
    TS_RESP_free(resp);

    printf("# rejections\n");
    resp = respond(ctx, (const unsigned char *)"\x30\x03\x02\x01\x01", 5, "a bad request");
    verify_made(resp, REQ_DER, sizeof(REQ_DER), 0);
    TS_RESP_free(resp);
    p = REQ_DER;
    req = d2i_TS_REQ(NULL, &p, sizeof(REQ_DER));
    TS_REQ_set_version(req, 2);
    der = request_der(req, &n);
    resp = respond(ctx, der, n, "version 2");
    TS_RESP_free(resp);
    OPENSSL_free(der);
    TS_REQ_set_version(req, 1);
    {
        ASN1_OBJECT *unknown = OBJ_txt2obj("1.2.3.4.9", 1);

        TS_REQ_set_policy_id(req, unknown);
        ASN1_OBJECT_free(unknown);
    }
    der = request_der(req, &n);
    resp = respond(ctx, der, n, "another policy");
    TS_RESP_free(resp);
    OPENSSL_free(der);
    TS_REQ_set_policy_id(req, other);
    der = request_der(req, &n);
    resp = respond(ctx, der, n, "the other accepted policy");
    TS_RESP_free(resp);
    OPENSSL_free(der);
    {
        TS_MSG_IMPRINT *mi = TS_REQ_get_msg_imprint(req);
        X509_ALGOR *alg = X509_ALGOR_new();
        unsigned char sha1[20] = { 0 };

        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha1), V_ASN1_NULL, NULL);
        TS_MSG_IMPRINT_set_algo(mi, alg);
        TS_MSG_IMPRINT_set_msg(mi, sha1, 20);
        der = request_der(req, &n);
        resp = respond(ctx, der, n, "SHA-1, not accepted");
        TS_RESP_free(resp);
        OPENSSL_free(der);
        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha512), V_ASN1_INTEGER, ASN1_INTEGER_new());
        TS_MSG_IMPRINT_set_algo(mi, alg);
        der = request_der(req, &n);
        resp = respond(ctx, der, n, "a digest with a parameter");
        TS_RESP_free(resp);
        OPENSSL_free(der);
        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha512), V_ASN1_NULL, NULL);
        TS_MSG_IMPRINT_set_algo(mi, alg);
        der = request_der(req, &n);
        resp = respond(ctx, der, n, "a digest of the wrong length");
        TS_RESP_free(resp);
        OPENSSL_free(der);
        X509_ALGOR_free(alg);
    }
    TS_REQ_free(req);

    printf("# extensions\n");
    p = REQ_DER;
    req = d2i_TS_REQ(NULL, &p, sizeof(REQ_DER));
    {
        ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
        X509_EXTENSION *ext;

        ASN1_OCTET_STRING_set(os, (const unsigned char *)"\x05\x00", 2);
        ext = X509_EXTENSION_create_by_OBJ(NULL, OBJ_txt2obj("1.2.3.4.42", 1), 0, os);
        TS_REQ_add_ext(req, ext, -1);
        X509_EXTENSION_free(ext);
        ASN1_OCTET_STRING_free(os);
    }
    der = request_der(req, &n);
    resp = respond(ctx, der, n, "refused by the default callback");
    TS_RESP_free(resp);
    TS_RESP_CTX_set_extension_cb(ctx, accept_cb, NULL);
    resp = respond(ctx, der, n, "accepted by ours");
    TS_RESP_free(resp);
    OPENSSL_free(der);
    TS_REQ_free(req);

    printf("# a failing clock\n");
    TS_RESP_CTX_set_time_cb(ctx, time_fail_cb, NULL);
    resp = respond(ctx, REQ_DER, sizeof(REQ_DER), "the time callback fails");
    TS_RESP_free(resp);

    printf("# the wrong key\n");
    TS_RESP_CTX_set_time_cb(ctx, time_cb, &when);
    TS_RESP_CTX_set_signer_key(ctx, eek);
    resp = respond(ctx, REQ_DER, sizeof(REQ_DER), "a key that is not the signer's");
    TS_RESP_free(resp);

    printf("# no default policy\n");
    TS_RESP_CTX_free(ctx);
    ctx = TS_RESP_CTX_new_ex(NULL, "provider=default");
    TS_RESP_CTX_set_signer_cert(ctx, tsa);
    TS_RESP_CTX_set_signer_key(ctx, k);
    TS_RESP_CTX_add_md(ctx, EVP_sha256());
    resp = respond(ctx, REQ_DER, sizeof(REQ_DER), "no default policy");
    TS_RESP_free(resp);

    printf("# the defaults: SHA-256, serial 1, the time now\n");
    TS_RESP_CTX_set_def_policy(ctx, def);
    {
        BIO *b = mem_der(REQ_DER, sizeof(REQ_DER));

        resp = TS_RESP_create_response(ctx, b);
        BIO_free(b);
    }
    TS_STATUS_INFO_print_bio(out, TS_RESP_get_status_info(resp));
    printf("  serial ");
    TS_ASN1_INTEGER_print_bio(out, TS_TST_INFO_get_serial(TS_RESP_get_tst_info(resp)));
    printf("\n");
    verify_made(resp, REQ_DER, sizeof(REQ_DER), 0);
    TS_RESP_free(resp);

    TS_RESP_CTX_free(ctx);
    TS_RESP_CTX_free(NULL);
    sk_X509_pop_free(chain, X509_free);
    ASN1_OBJECT_free(def);
    ASN1_OBJECT_free(other);
    EVP_PKEY_free(eek);
    EVP_PKEY_free(k);
    X509_free(ee);
    X509_free(tsa);
}

static ASN1_INTEGER *conf_serial_cb(TS_RESP_CTX *ctx, void *data)
{
    ASN1_INTEGER *s = ASN1_INTEGER_new();

    (void)ctx;
    printf("  configured serial callback: %s\n", data != NULL && *(const char *)data != '\0' ? "a file" : "none");
    ASN1_INTEGER_set(s, 99);
    return s;
}

static CONF *load_conf(const char *text)
{
    CONF *conf = NCONF_new(NULL);
    BIO *b = mem(text);
    long line = -1;

    if (NCONF_load_bio(conf, b, &line) <= 0)
        printf("  load failed at %ld\n", line);
    BIO_free(b);
    return conf;
}

/* A TSA set up from a configuration file. */
static void configure(void)
{
    char *tsa = write_file(TSA_PEM, strlen(TSA_PEM));
    char *tsa_key = write_file(TSA_KEY_PEM, strlen(TSA_KEY_PEM));
    char *both = write_file(CA_PEM_AND_RSA, strlen(CA_PEM_AND_RSA));
    char text[4096];
    CONF *conf, *bad;
    TS_RESP_CTX *ctx = TS_RESP_CTX_new();
    const char *section;
    X509 *x;
    STACK_OF(X509) *certs;
    EVP_PKEY *k;
    TS_RESP *resp;

    printf("# loading\n");
    x = TS_CONF_load_cert(tsa);
    check(x != NULL, "TS_CONF_load_cert");
    X509_free(x);
    certs = TS_CONF_load_certs(both);
    check(certs != NULL && sk_X509_num(certs) == 2, "TS_CONF_load_certs");
    sk_X509_pop_free(certs, X509_free);
    k = TS_CONF_load_key(tsa_key, NULL);
    check(k != NULL, "TS_CONF_load_key");
    EVP_PKEY_free(k);
    check(TS_CONF_load_cert("/nonexistent/tsa.pem") == NULL, "no such certificate file");
    errors();
    check(TS_CONF_load_certs("/nonexistent/certs.pem") == NULL, "no such certificates file");
    errors();
    check(TS_CONF_load_key("/nonexistent/tsa.key", "pass") == NULL, "no such key file");
    errors();
    check(TS_CONF_load_cert(tsa_key) == NULL, "a key is no certificate");
    errors();

    snprintf(text, sizeof(text),
             "[ tsa ]\n"
             "default_tsa = tsa_config1\n"
             "[ tsa_config1 ]\n"
             "serial = %s\n"
             "signer_cert = %s\n"
             "certs = %s\n"
             "signer_key = %s\n"
             "signer_digest = sha256\n"
             "default_policy = 1.2.3.4.1\n"
             "other_policies = 1.2.3.4.5, 1.2.3.4.6\n"
             "digests = sha1, sha256, sha384, sha512\n"
             "accuracy = secs:1, millisecs:500, microsecs:100\n"
             "clock_precision_digits = 3\n"
             "ordering = yes\n"
             "tsa_name = yes\n"
             "ess_cert_id_chain = no\n"
             "ess_cert_id_alg = sha1\n"
             "crypto_device = builtin\n",
             tsa, tsa, both, tsa_key);
    conf = load_conf(text);

    printf("# the configured TSA\n");
    section = TS_CONF_get_tsa_section(conf, NULL);
    printf("  section %s\n", section);
    check(strcmp(TS_CONF_get_tsa_section(conf, "other"), "other") == 0, "a given section");
    check(TS_CONF_set_serial(conf, section, conf_serial_cb, ctx) == 1, "TS_CONF_set_serial");
    check(TS_CONF_set_crypto_device(conf, section, NULL) == 1, "TS_CONF_set_crypto_device");
    check(TS_CONF_set_default_engine("builtin") == 1, "TS_CONF_set_default_engine builtin");
    check(TS_CONF_set_signer_cert(conf, section, NULL, ctx) == 1, "TS_CONF_set_signer_cert");
    check(TS_CONF_set_certs(conf, section, NULL, ctx) == 1, "TS_CONF_set_certs");
    check(TS_CONF_set_signer_key(conf, section, NULL, NULL, ctx) == 1, "TS_CONF_set_signer_key");
    check(TS_CONF_set_signer_digest(conf, section, NULL, ctx) == 1, "TS_CONF_set_signer_digest");
    check(TS_CONF_set_def_policy(conf, section, NULL, ctx) == 1, "TS_CONF_set_def_policy");
    check(TS_CONF_set_policies(conf, section, ctx) == 1, "TS_CONF_set_policies");
    check(TS_CONF_set_digests(conf, section, ctx) == 1, "TS_CONF_set_digests");
    check(TS_CONF_set_accuracy(conf, section, ctx) == 1, "TS_CONF_set_accuracy");
    check(TS_CONF_set_clock_precision_digits(conf, section, ctx) == 1, "TS_CONF_set_clock_precision_digits");
    check(TS_CONF_set_ordering(conf, section, ctx) == 1, "TS_CONF_set_ordering");
    check(TS_CONF_set_tsa_name(conf, section, ctx) == 1, "TS_CONF_set_tsa_name");
    check(TS_CONF_set_ess_cert_id_chain(conf, section, ctx) == 1, "TS_CONF_set_ess_cert_id_chain");
    check(TS_CONF_set_ess_cert_id_digest(conf, section, ctx) == 1, "TS_CONF_set_ess_cert_id_digest");
    errors();
    TS_RESP_CTX_set_time_cb(ctx, time_cb, &when);
    fixed_usec = 987654;
    resp = respond(ctx, REQ_DER, sizeof(REQ_DER), "answering with it");
    verify_made(resp, REQ_DER, sizeof(REQ_DER), TS_VFY_SIGNER);
    TS_RESP_free(resp);

    printf("# given values over the configuration's\n");
    check(TS_CONF_set_signer_cert(conf, section, tsa, ctx) == 1, "a given certificate");
    check(TS_CONF_set_certs(conf, section, tsa, ctx) == 1, "given certificates");
    check(TS_CONF_set_signer_key(conf, section, tsa_key, NULL, ctx) == 1, "a given key");
    check(TS_CONF_set_signer_digest(conf, section, "sha384", ctx) == 1, "a given digest");
    check(TS_CONF_set_def_policy(conf, section, "1.2.3.4.6", ctx) == 1, "a given policy");
    check(TS_CONF_set_crypto_device(conf, section, "builtin") == 1, "a given device");
    errors();

    printf("# an empty section\n");
    check(TS_CONF_get_tsa_section(load_conf("[ x ]\n"), NULL) == NULL, "no default TSA");
    errors();
    check(TS_CONF_set_serial(conf, "empty", conf_serial_cb, ctx) == 0, "no serial");
    errors();
    check(TS_CONF_set_signer_cert(conf, "empty", NULL, ctx) == 0, "no signer");
    errors();
    check(TS_CONF_set_certs(conf, "empty", NULL, ctx) == 1, "no certificates is fine");
    check(TS_CONF_set_signer_key(conf, "empty", NULL, NULL, ctx) == 0, "no key");
    errors();
    check(TS_CONF_set_signer_digest(conf, "empty", NULL, ctx) == 0, "no digest");
    errors();
    check(TS_CONF_set_def_policy(conf, "empty", NULL, ctx) == 0, "no default policy");
    errors();
    check(TS_CONF_set_policies(conf, "empty", ctx) == 1, "no other policies is fine");
    check(TS_CONF_set_digests(conf, "empty", ctx) == 0, "no digests");
    errors();
    check(TS_CONF_set_accuracy(conf, "empty", ctx) == 1, "no accuracy is fine");
    check(TS_CONF_set_clock_precision_digits(conf, "empty", ctx) == 1, "no digits is fine");
    check(TS_CONF_set_ordering(conf, "empty", ctx) == 1, "no ordering is fine");
    check(TS_CONF_set_ess_cert_id_digest(conf, "empty", ctx) == 1, "SHA-256 by default");
    check(TS_CONF_set_crypto_device(conf, "empty", NULL) == 1, "no device is fine");
    errors();

    printf("# bad values\n");
    bad = load_conf("[ bad ]\n"
                    "signer_digest = nosuch\n"
                    "default_policy = not an oid\n"
                    "other_policies = 1.2.3, bad policy\n"
                    "digests = sha256, nosuch\n"
                    "accuracy = secs:1, hours:2\n"
                    "clock_precision_digits = 9\n"
                    "ordering = maybe\n"
                    "tsa_name = YES\n"
                    "ess_cert_id_chain = 1\n"
                    "ess_cert_id_alg = nosuch\n"
                    "crypto_device = nosuch\n"
                    "[ bad2 ]\n"
                    "digests = ,\n"
                    "clock_precision_digits = -1\n"
                    "accuracy = secs, millisecs:x\n"
                    "[ bad3 ]\n"
                    "clock_precision_digits = lots\n");
    check(TS_CONF_set_signer_digest(bad, "bad", NULL, ctx) == 0, "signer_digest");
    errors();
    check(TS_CONF_set_def_policy(bad, "bad", NULL, ctx) == 0, "default_policy");
    errors();
    check(TS_CONF_set_policies(bad, "bad", ctx) == 0, "other_policies");
    errors();
    check(TS_CONF_set_digests(bad, "bad", ctx) == 0, "digests");
    errors();
    check(TS_CONF_set_accuracy(bad, "bad", ctx) == 0, "accuracy");
    errors();
    check(TS_CONF_set_clock_precision_digits(bad, "bad", ctx) == 0, "clock_precision_digits");
    errors();
    check(TS_CONF_set_ordering(bad, "bad", ctx) == 0, "ordering");
    errors();
    check(TS_CONF_set_tsa_name(bad, "bad", ctx) == 0, "tsa_name");
    errors();
    check(TS_CONF_set_ess_cert_id_chain(bad, "bad", ctx) == 0, "ess_cert_id_chain");
    errors();
    check(TS_CONF_set_ess_cert_id_digest(bad, "bad", ctx) == 0, "ess_cert_id_alg");
    errors();
    /* The engine's error entries name the engines directory, which differs between builds. */
    check(TS_CONF_set_crypto_device(bad, "bad", NULL) == 0, "crypto_device");
    printf("  errors: %s\n", ERR_peek_error() != 0 ? "some" : "none");
    ERR_clear_error();
    check(TS_CONF_set_default_engine("nosuch") == 0, "TS_CONF_set_default_engine nosuch");
    printf("  last error: %d/%d\n", ERR_GET_LIB(ERR_peek_last_error()), ERR_GET_REASON(ERR_peek_last_error()));
    ERR_clear_error();
    check(TS_CONF_set_digests(bad, "bad2", ctx) == 0, "no digest listed");
    errors();
    check(TS_CONF_set_clock_precision_digits(bad, "bad2", ctx) == 1, "a sign is no number, so 0 digits");
    errors();
    check(TS_CONF_set_accuracy(bad, "bad2", ctx) == 1, "accuracy with no or bad numbers");
    errors();
    check(TS_CONF_set_clock_precision_digits(bad, "bad3", ctx) == 1, "digits that are no number are 0");
    errors();

    NCONF_free(bad);
    NCONF_free(conf);
    TS_RESP_CTX_free(ctx);
    unlink(tsa);
    unlink(tsa_key);
    unlink(both);
}

int main(void)
{
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    setvbuf(stdout, NULL, _IONBF, 0);
    reference_objects();
    verify_reference();
    build();
    lib_print();
    sign();
    configure();
    BIO_free(out);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
