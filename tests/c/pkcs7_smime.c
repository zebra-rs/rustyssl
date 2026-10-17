/*
 * Conformance test for PKCS#7 signing, verifying, encrypting, and decrypting (PKCS7_sign(3),
 * PKCS7_sign_add_signer(3), PKCS7_final(3), PKCS7_verify(3), PKCS7_get0_signers,
 * PKCS7_encrypt(3), PKCS7_decrypt(3)), their data path (PKCS7_dataInit, PKCS7_dataDecode,
 * PKCS7_dataFinal, PKCS7_SIGNER_INFO_sign, PKCS7_dataVerify, PKCS7_signatureVerify), and
 * SMIME_crlf_copy and SMIME_text: objects the reference's tool wrote verified and decrypted,
 * objects made here round-tripped with each flag, and tampered, mismatched, and missing
 * inputs refused. Outputs that hold a signing time or an ECDSA signature are checked, not
 * printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The error queue, with each entry's data. */
static void errors(void)
{
    unsigned long e;
    const char *data;
    int flags;

    printf("  errors:");
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0')
            printf(" (%s)", data);
    }
    printf("\n");
}

/*
 * Made with the reference's openssl tool: an EC root; RSA and EC signers and an RSA recipient,
 * each for emailProtection; a message; smime -sign -nodetach (RSA, text), smime -sign -binary
 * (RSA, detached), smime -sign -nodetach -binary (EC), and smime -encrypt -aes-128-cbc (to the
 * recipient and the RSA signer, in that order).
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

static const char EC_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBnjCCAUOgAwIBAgIBZjAKBggqhkjOPQQDAjAnMRAwDgYDVQQKDAdFeGFtcGxl\n"
    "MRMwEQYDVQQDDApTTUlNRSBSb290MCAXDTI2MTAxNzIyMTcxNVoYDzIxMjYwOTIz\n"
    "MjIxNzE1WjATMREwDwYDVQQDDAhTTUlNRSBlYzBZMBMGByqGSM49AgEGCCqGSM49\n"
    "AwEHA0IABE+ed2YYrTPKzTSCIfsz5t548VhtIiTcxkrDi7n3iq20eXeG5NOkC0Yv\n"
    "sS1rZ/TNRNNq6rPCmC/bSC2CFtqfzm6jcjBwMAkGA1UdEwQCMAAwDgYDVR0PAQH/\n"
    "BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMEMB0GA1UdDgQWBBSqGg/MBRxHdgSm\n"
    "ueMVbCKkKfm/4jAfBgNVHSMEGDAWgBR1tdNQedtUtDillwMhWwDwHWigRTAKBggq\n"
    "hkjOPQQDAgNJADBGAiEA0bvNOSAuB7pUozWvrzw0azVBYOLKz7v6vtcTjpQiKjwC\n"
    "IQC7MYUejEbSuuJfSioTRaf7Q94Qcl9HUBtIQM+At5vMdw==\n"
    "-----END CERTIFICATE-----\n";

static const char RCPT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICaTCCAhCgAwIBAgIBZzAKBggqhkjOPQQDAjAnMRAwDgYDVQQKDAdFeGFtcGxl\n"
    "MRMwEQYDVQQDDApTTUlNRSBSb290MCAXDTI2MTAxNzIyMTcxNVoYDzIxMjYwOTIz\n"
    "MjIxNzE1WjAVMRMwEQYDVQQDDApTTUlNRSByY3B0MIIBIjANBgkqhkiG9w0BAQEF\n"
    "AAOCAQ8AMIIBCgKCAQEA18QxOUhaJRisASI6xBIN16PV9WkdrTbE/yz4ahtxgElk\n"
    "YK1mXdFD5QYRplsnHqPevW2cVVbS0+vtxMTxGy0znDNWX8WMzrgJjk1vniMuibwn\n"
    "4j8IRqptUSj2060QIB/5DIX0cHSz5xfvpv4D++K72tVvmL+KMSYSNdLxGMzPQ9Ci\n"
    "f8Fr/LEMOpibDj+kTPIk/n65w+W+Uno5NUqQ8uFsxgTbkuWh3lfXyRoIKT4rkGXg\n"
    "NL+myxIyTtT2wJRMOW4uGjKcfEH7ZteXkV23KMVBsZGZGRiEfaIHhnUGyWPFp5Ue\n"
    "a+YxR3MbbLd4OO4r8wS4l9ZNqE6lN/M7UimNxfz56wIDAQABo3IwcDAJBgNVHRME\n"
    "AjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDBDAdBgNVHQ4E\n"
    "FgQUUmeYW6EuzZLObWOj5T/p6KmKoPswHwYDVR0jBBgwFoAUdbXTUHnbVLQ4pZcD\n"
    "IVsA8B1ooEUwCgYIKoZIzj0EAwIDRwAwRAIgDRHniyVkaNrc4o4cD1JaVMtTO7qB\n"
    "FP3kjU4I72ipOKMCIFLvIE2lHC/XU7tOaJGloo9z/c4NP027HPqwm/Mnl8yh\n"
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

static const char EC_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLkdevDxeg4v1m2Y7\n"
    "/1HCYEAjUQZgcaW8rJrHXQlWf32hRANCAARPnndmGK0zys00giH7M+beePFYbSIk\n"
    "3MZKw4u594qttHl3huTTpAtGL7Eta2f0zUTTauqzwpgv20gtghban85u\n"
    "-----END PRIVATE KEY-----\n";

static const char RCPT_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDXxDE5SFolGKwB\n"
    "IjrEEg3Xo9X1aR2tNsT/LPhqG3GASWRgrWZd0UPlBhGmWyceo969bZxVVtLT6+3E\n"
    "xPEbLTOcM1ZfxYzOuAmOTW+eIy6JvCfiPwhGqm1RKPbTrRAgH/kMhfRwdLPnF++m\n"
    "/gP74rva1W+Yv4oxJhI10vEYzM9D0KJ/wWv8sQw6mJsOP6RM8iT+frnD5b5Sejk1\n"
    "SpDy4WzGBNuS5aHeV9fJGggpPiuQZeA0v6bLEjJO1PbAlEw5bi4aMpx8Qftm15eR\n"
    "XbcoxUGxkZkZGIR9ogeGdQbJY8WnlR5r5jFHcxtst3g47ivzBLiX1k2oTqU38ztS\n"
    "KY3F/PnrAgMBAAECggEAK76cGDgCBrlczhIJhgz+/3Q5AbthB+gtwmp0ptaPiWnX\n"
    "zv343hZ6RGmZlHewk7a3hwI9CtRChDK2Dwm6tD7S0t1ZqqsbpCGN1mr+sToCymv6\n"
    "ThVncSRGa4j5merhdRHmZVKXP2F5w+WHcfzYA+5xFanmKTrUIqjMUltFBDkp4F6B\n"
    "2Y75FCr0M9ror8Xpnoct87CSqfVojEDMxzKXDuWpxeQ+IVZmR9Awx3S8YTchoror\n"
    "AiBFivftXSRLMJq3h0LiKFhs0er5eyHOrlv5QeUcit17kh0Ll2fsuAmjLZMAiqmF\n"
    "1jofm0cV6CaLAehoUl5HfDUa5ThK3uysWIzfxqI4OQKBgQD223uMt2MxsNT2cX9/\n"
    "cQ8qHzCAVDCashQ25GziGBFOmp0N9x1+yyiEpzmaRd82JbbVs0WdNj7Uy9NgNZb+\n"
    "LFxJ2vV6O4InhCb1b4oxtpU1qcyoVk8V9TgrZZtdv1pw0x+F69iw6MIi+3d7H2+0\n"
    "oPBhoVSCsWYB8BQa5Bd83wCeVwKBgQDfwe2eAsZSofsLWY4ekcVC1j1vn8IJy8za\n"
    "/fjw2ps8hglz1SYIQFF5P8nQIZzT5RwY2p6X3Pio4frHyo2N0zj55g9kD+5KuNYr\n"
    "QHelAgIlCg/D0aE6MfPnuk39cZLWXjxwuAE2W5hh3dlerZJiOkXvh05ZHBwPP6JV\n"
    "kFyLuCXcjQKBgBL3G8/cyv8nUcU5RQ1ad0rKKKTDUxSfd9Qbyo24QaQjVsua36Y9\n"
    "H3jJjDBhC9wSG7DhXAjPARbCLhQnKdmPOOvnqZJhfgdhLMkQb7KQD3iW+gU41Eyg\n"
    "kVcsMDqMl/sxDSvxya0VxMyBO1W3PZLIBo/JoD+GN4sQkcrbGT7btyVzAoGBAL4E\n"
    "q2zfgFpWMqJt2BI/ypw64gt0SU0WZI6o1Yp8qw4X6dkTbuvc6xOjxxfYI52S2GyG\n"
    "492liwmodtbKPbHuaVlXNUTNfpi4JTCv26smbHnV9JNf56JLH41vmqGbnI4tkvhK\n"
    "WsU1vc+Gnf0YO9LtF80VQ8TK6U1NxecR5HXG2WhVAoGBAPUdVUJSI0SBc+GNKvpR\n"
    "tMgqkOnjEojDtk57rt2ADYxagm/t074fpzNFEhlAFA+zp7ffr7FuomkcXXn+bV41\n"
    "/SC97mpyitbJ+9MITor6YeEZsDKENWCtP5Qkct9evvolZ+dY1mA2a+j/3ZN5X3iu\n"
    "j0zTarrl0n21/ax9o4w5l4vO\n"
    "-----END PRIVATE KEY-----\n";

static const char REF_SIGNED[] =
    "-----BEGIN PKCS7-----\n"
    "MIIFEAYJKoZIhvcNAQcCoIIFATCCBP0CAQExDzANBglghkgBZQMEAgEFADA0Bgkq\n"
    "hkiG9w0BBwGgJwQlSGVsbG8sIFMvTUlNRS4NClNlY29uZCBsaW5lICANCg0KbGFz\n"
    "dKCCAm0wggJpMIICD6ADAgECAgFlMAoGCCqGSM49BAMCMCcxEDAOBgNVBAoMB0V4\n"
    "YW1wbGUxEzARBgNVBAMMClNNSU1FIFJvb3QwIBcNMjYxMDE3MjIxNzE1WhgPMjEy\n"
    "NjA5MjMyMjE3MTVaMBQxEjAQBgNVBAMMCVNNSU1FIHJzYTCCASIwDQYJKoZIhvcN\n"
    "AQEBBQADggEPADCCAQoCggEBAJMXcNHWWtGGNz27WMRXOBhyUL4vdfrHzwgaDMJ0\n"
    "o9o3CEtCVawNeaW4yWprRO9vg5vf3ZR/GaSfVbfReFhPKkuMY4vluSyiIYOJBmfW\n"
    "i8D8ad2YKrUnjulI2HPpIvX+45m+aPq92mvSnboG2oYKvWFejBYoi+YkZ2vklXh8\n"
    "+BFc7+cUKpi/DObSHEIJYX5ykAImAH82QHnidKp5h1GHAm9T0PyCWZO7A7hRjTfk\n"
    "UNhxgpqOIgy2cmcaWj8gkwTIjX6VAZZYU5II+GV3kHd629vxjP4sLnXDiOWuhcnD\n"
    "urUeZMaLYhHh+6AoLyUu6CZs414VeN4JrA9FWFk9Hb/UAc0CAwEAAaNyMHAwCQYD\n"
    "VR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwQwHQYD\n"
    "VR0OBBYEFBMQ6yyOYV9/D0Md19hcb7iqaoS8MB8GA1UdIwQYMBaAFHW101B521S0\n"
    "OKWXAyFbAPAdaKBFMAoGCCqGSM49BAMCA0gAMEUCIAno3aw011I1r4gOmyRxP1ah\n"
    "Vw0XmApg5ZsPNskUglNlAiEA5OXC2BPU+FxRFbpYbGmcoeuSDyX5FvNp1QQkkCSw\n"
    "b/AxggI+MIICOgIBATAsMCcxEDAOBgNVBAoMB0V4YW1wbGUxEzARBgNVBAMMClNN\n"
    "SU1FIFJvb3QCAWUwDQYJYIZIAWUDBAIBBQCggeQwGAYJKoZIhvcNAQkDMQsGCSqG\n"
    "SIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMDE3MjIxNzIzWjAvBgkqhkiG9w0B\n"
    "CQQxIgQgPnPqaFv9J7F1Oh4ddJCg0p2ZPvmplALyW0ZEDO48pZQweQYJKoZIhvcN\n"
    "AQkPMWwwajALBglghkgBZQMEASowCwYJYIZIAWUDBAEWMAsGCWCGSAFlAwQBAjAK\n"
    "BggqhkiG9w0DBzAOBggqhkiG9w0DAgICAIAwDQYIKoZIhvcNAwICAUAwBwYFKw4D\n"
    "AgcwDQYIKoZIhvcNAwICASgwDQYJKoZIhvcNAQEBBQAEggEATfKw9/1DzLmVFOA0\n"
    "otgHpTQAvxx4AgCoJH7C4jA8Fe341BCuX+lBBYIXputPO/QwDkT5L5oe2gCfRJA4\n"
    "9E4tNoZ3g+QO6nuQQnoKoOi0LbfGtZasSH6dCg7bQUdleWPNGI2TjK/5J7l+dv1y\n"
    "rQ0nBRaLxWp3+TxJqNt7f2iHzZR0OWj3M+yCEjWZ9dN1aHqxxdkqKNKOqLW1fHQE\n"
    "81c7LsQqN4uZX1tv6iiDN9my31q7tWxF7tKSBGm2sHMVsbIB7yPyrdWgVCkgh+TK\n"
    "JUX7G760M0YaiLdS+DodinpOYvXGWqvqyTzE1TK3mPE+rPXwQkVB5P0rTi4Gut3R\n"
    "0cGL1Q==\n"
    "-----END PKCS7-----\n";

static const char REF_DETACHED[] =
    "-----BEGIN PKCS7-----\n"
    "MIIE5wYJKoZIhvcNAQcCoIIE2DCCBNQCAQExDzANBglghkgBZQMEAgEFADALBgkq\n"
    "hkiG9w0BBwGgggJtMIICaTCCAg+gAwIBAgIBZTAKBggqhkjOPQQDAjAnMRAwDgYD\n"
    "VQQKDAdFeGFtcGxlMRMwEQYDVQQDDApTTUlNRSBSb290MCAXDTI2MTAxNzIyMTcx\n"
    "NVoYDzIxMjYwOTIzMjIxNzE1WjAUMRIwEAYDVQQDDAlTTUlNRSByc2EwggEiMA0G\n"
    "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCTF3DR1lrRhjc9u1jEVzgYclC+L3X6\n"
    "x88IGgzCdKPaNwhLQlWsDXmluMlqa0Tvb4Ob392Ufxmkn1W30XhYTypLjGOL5bks\n"
    "oiGDiQZn1ovA/GndmCq1J47pSNhz6SL1/uOZvmj6vdpr0p26BtqGCr1hXowWKIvm\n"
    "JGdr5JV4fPgRXO/nFCqYvwzm0hxCCWF+cpACJgB/NkB54nSqeYdRhwJvU9D8glmT\n"
    "uwO4UY035FDYcYKajiIMtnJnGlo/IJMEyI1+lQGWWFOSCPhld5B3etvb8Yz+LC51\n"
    "w4jlroXJw7q1HmTGi2IR4fugKC8lLugmbONeFXjeCawPRVhZPR2/1AHNAgMBAAGj\n"
    "cjBwMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUF\n"
    "BwMEMB0GA1UdDgQWBBQTEOssjmFffw9DHdfYXG+4qmqEvDAfBgNVHSMEGDAWgBR1\n"
    "tdNQedtUtDillwMhWwDwHWigRTAKBggqhkjOPQQDAgNIADBFAiAJ6N2sNNdSNa+I\n"
    "DpskcT9WoVcNF5gKYOWbDzbJFIJTZQIhAOTlwtgT1PhcURW6WGxpnKHrkg8l+Rbz\n"
    "adUEJJAksG/wMYICPjCCAjoCAQEwLDAnMRAwDgYDVQQKDAdFeGFtcGxlMRMwEQYD\n"
    "VQQDDApTTUlNRSBSb290AgFlMA0GCWCGSAFlAwQCAQUAoIHkMBgGCSqGSIb3DQEJ\n"
    "AzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MTAxNzIyMTcyM1owLwYJ\n"
    "KoZIhvcNAQkEMSIEIDVKMfxXK96uAutn+2U8yx/dsYCu/b4+3UEdMGAIAaAoMHkG\n"
    "CSqGSIb3DQEJDzFsMGowCwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQBFjALBglghkgB\n"
    "ZQMEAQIwCgYIKoZIhvcNAwcwDgYIKoZIhvcNAwICAgCAMA0GCCqGSIb3DQMCAgFA\n"
    "MAcGBSsOAwIHMA0GCCqGSIb3DQMCAgEoMA0GCSqGSIb3DQEBAQUABIIBAGj9Wv8M\n"
    "ubeElnkDG2nG9BaHqsXYlUTzK14+gaxZAXYOcZkPMWZHuWmBGoKu32A2gtnmbdZe\n"
    "Ymm689Vg5KwYigYgRzR3M4l6qvSnBsj7HoqNbIS3p+eO2GkFVM65kIg34T/aaTNN\n"
    "GA2ALydNi1AQ9aA7ycAiW6Q/wyoOgaTYDrLmreswfINJUTF0YUn4HDF8VLfDFCZB\n"
    "HeIj2gJxzYigAg8pnR6QrGHXoC6Z77aksm67eXpNUSRjW/ies/UhYFZgj40+PY54\n"
    "tBQfY5kxI3tpY9dNi2CSU6pH9dObUATJ0+BkZBmrZHdO/Iw6tbCCPv+6JcDanWpe\n"
    "cHJpGvP0MCOJt1I=\n"
    "-----END PKCS7-----\n";

static const char REF_EC[] =
    "-----BEGIN PKCS7-----\n"
    "MIIDhQYJKoZIhvcNAQcCoIIDdjCCA3ICAQExDzANBglghkgBZQMEAgEFADAyBgkq\n"
    "hkiG9w0BBwGgJQQjSGVsbG8sIFMvTUlNRS4KU2Vjb25kIGxpbmUgIA0KCmxhc3Sg\n"
    "ggGiMIIBnjCCAUOgAwIBAgIBZjAKBggqhkjOPQQDAjAnMRAwDgYDVQQKDAdFeGFt\n"
    "cGxlMRMwEQYDVQQDDApTTUlNRSBSb290MCAXDTI2MTAxNzIyMTcxNVoYDzIxMjYw\n"
    "OTIzMjIxNzE1WjATMREwDwYDVQQDDAhTTUlNRSBlYzBZMBMGByqGSM49AgEGCCqG\n"
    "SM49AwEHA0IABE+ed2YYrTPKzTSCIfsz5t548VhtIiTcxkrDi7n3iq20eXeG5NOk\n"
    "C0YvsS1rZ/TNRNNq6rPCmC/bSC2CFtqfzm6jcjBwMAkGA1UdEwQCMAAwDgYDVR0P\n"
    "AQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMEMB0GA1UdDgQWBBSqGg/MBRxH\n"
    "dgSmueMVbCKkKfm/4jAfBgNVHSMEGDAWgBR1tdNQedtUtDillwMhWwDwHWigRTAK\n"
    "BggqhkjOPQQDAgNJADBGAiEA0bvNOSAuB7pUozWvrzw0azVBYOLKz7v6vtcTjpQi\n"
    "KjwCIQC7MYUejEbSuuJfSioTRaf7Q94Qcl9HUBtIQM+At5vMdzGCAYAwggF8AgEB\n"
    "MCwwJzEQMA4GA1UECgwHRXhhbXBsZTETMBEGA1UEAwwKU01JTUUgUm9vdAIBZjAN\n"
    "BglghkgBZQMEAgEFAKCB5DAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqG\n"
    "SIb3DQEJBTEPFw0yNjEwMTcyMjE3MTVaMC8GCSqGSIb3DQEJBDEiBCA1SjH8Vyve\n"
    "rgLrZ/tlPMsf3bGArv2+Pt1BHTBgCAGgKDB5BgkqhkiG9w0BCQ8xbDBqMAsGCWCG\n"
    "SAFlAwQBKjALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMHMA4G\n"
    "CCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzANBggqhkiG9w0D\n"
    "AgIBKDAKBggqhkjOPQQDAgRHMEUCIGHhxi3gHTIAAYeH19S3Y0s1qiZJHwDu4fSI\n"
    "0TUA9VYrAiEA9R77mpMfEZa/34mVf0ApRe4TYbA7yzmTHDfYUKFdiV0=\n"
    "-----END PKCS7-----\n";

static const char REF_ENV[] =
    "-----BEGIN PKCS7-----\n"
    "MIIDCAYJKoZIhvcNAQcDoIIC+TCCAvUCAQAxggKQMIIBRAIBADAsMCcxEDAOBgNV\n"
    "BAoMB0V4YW1wbGUxEzARBgNVBAMMClNNSU1FIFJvb3QCAWUwDQYJKoZIhvcNAQEB\n"
    "BQAEggEAMPFT4m87AnnSImokqwVoqvUHsuW2DHiwtNNN215thoa/XHZpoe7kAD1i\n"
    "iKKQVIK87iTeMhNeBetMg4161jnHVtmpoNMkdcLIONQEWq8phAwbTg0CbfTL332R\n"
    "1ASnJtkmwpqJqOMHNFXVphvKzz2sw9zYv37mgidhFoI1gEoZkmGNpe6Du6bI5V6Q\n"
    "ovCT0r83RxA1jgab47P/STd4Q/gpAn2GYEJkrs4t8cGxanhtVVw/TKk+N3RXe0mT\n"
    "Sb9cH12h7EfAPNLloMh59nm9kXjGOZ04xmG8rvkWHykR09gT1/16GNwaVSChLn1N\n"
    "DXdUOYgZLCtIUfBq/tbiizh9tb4R6TCCAUQCAQAwLDAnMRAwDgYDVQQKDAdFeGFt\n"
    "cGxlMRMwEQYDVQQDDApTTUlNRSBSb290AgFnMA0GCSqGSIb3DQEBAQUABIIBAJbQ\n"
    "F/lrevqu4bVxOQo397Glo64nuYiBy2fEOESQhatztttncnC7lEdyEO80OrjFZ+Pc\n"
    "/IRXGbjaJzvgDQSvnHWEH08dYQLoPTVXILAGedEdBQ+jMdJ/fWgLp3DDydsQdu42\n"
    "QCk2Qw5N587/zO6f8gR725+lpU5kVbGcAfavjQ0DG+UV+CvYLk+2oxQ+FRdi7Rft\n"
    "P04aYT2Zi49Z7SvAlagw3I/MYBFc9YSzp6uyXypQ8qKoDjV3blu82Zut7zLtf2Jo\n"
    "PcONS/DVVv9+PI28Q/5m47BbPrzintXobt0h9YzSANw2jd1Zv1HFcPOHaS3E1nRk\n"
    "SteeLpDwmUfT7QGf6gkwXAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBAgQQ59/dKs6/\n"
    "zqA4BrWun7AHpIAwDFlXdXjOIXerxz5A0+2vG4DEYKufaTuLQw9TRiF8lKibiB/6\n"
    "OBqJuSxVs/ME3+LZ\n"
    "-----END PKCS7-----\n";
static BIO *mem(const char *s)
{
    return BIO_new_mem_buf(s, -1);
}

static BIO *bytes(const char *s, int n)
{
    return BIO_new_mem_buf(s, n);
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

static PKCS7 *p7_of(const char *pem)
{
    BIO *b = mem(pem);
    PKCS7 *p7 = PEM_read_bio_PKCS7(b, NULL, NULL, NULL);

    BIO_free(b);
    return p7;
}

/* A BIO's contents, escaped. */
static void show(const char *label, BIO *b)
{
    char *p;
    long n = BIO_get_mem_data(b, &p), i;

    printf("  %s (%ld): \"", label, n);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];

        if (c == '\r')
            printf("\\r");
        else if (c == '\n')
            printf("\\n");
        else if (c < 32 || c > 126)
            printf("\\x%02x", c);
        else
            putchar(c);
    }
    printf("\"\n");
}

static void hex(const char *label, const unsigned char *p, int n)
{
    int i;

    printf("  %s (%d):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 ? "\n    " : "", p[i]);
    printf("\n");
}

/* The SHA-256 of the object's DER. */
static void fingerprint(const char *label, PKCS7 *p7)
{
    unsigned char *d = NULL, md[32];
    unsigned int mdlen = 0;
    int n = i2d_PKCS7(p7, &d);

    EVP_Digest(d, n, md, &mdlen, EVP_sha256(), NULL);
    printf("  %s: DER %d,", label, n);
    hex("sha256", md, (int)mdlen);
    OPENSSL_free(d);
}

static const char *oid(const ASN1_OBJECT *o)
{
    static char bufs[4][80];
    static int k;
    char *buf = bufs[k++ % 4];

    if (o == NULL)
        return "(none)";
    OBJ_obj2txt(buf, 80, o, 0);
    return buf;
}

static void show_signers(PKCS7 *p7)
{
    STACK_OF(PKCS7_SIGNER_INFO) *sis = PKCS7_get_signer_info(p7);
    int i, j;

    printf("  signers %d, certs %d, detached %ld\n", sis == NULL ? -1 : sk_PKCS7_SIGNER_INFO_num(sis),
           PKCS7_type_is_signed(p7) ? sk_X509_num(p7->d.sign->cert) : -1, PKCS7_get_detached(p7));
    for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sis); i++) {
        PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sis, i);
        STACK_OF(X509_ALGOR) *caps = PKCS7_get_smimecap(si);

        printf("  %d: digest %s, attributes %d:", i, oid(si->digest_alg->algorithm), sk_X509_ATTRIBUTE_num(si->auth_attr));
        for (j = 0; j < sk_X509_ATTRIBUTE_num(si->auth_attr); j++)
            printf(" %s", oid(X509_ATTRIBUTE_get0_object(sk_X509_ATTRIBUTE_value(si->auth_attr, j))));
        printf("\n    capabilities:");
        for (j = 0; j < sk_X509_ALGOR_num(caps); j++) {
            X509_ALGOR *a = sk_X509_ALGOR_value(caps, j);

            printf(" %s", oid(a->algorithm));
            if (a->parameter != NULL && a->parameter->type == V_ASN1_INTEGER)
                printf("(%ld)", ASN1_INTEGER_get(a->parameter->value.integer));
        }
        /* An ECDSA signature's length varies. */
        if (si->enc_digest == NULL || si->enc_digest->length < 128)
            printf("\n    signature %s\n", si->enc_digest == NULL || si->enc_digest->length == 0 ? "none" : "short");
        else
            printf("\n    signature %d octets\n", si->enc_digest->length);
        sk_X509_ALGOR_pop_free(caps, X509_ALGOR_free);
    }
}

static X509_STORE *store_of(X509 *root)
{
    X509_STORE *st = X509_STORE_new();

    if (root != NULL)
        X509_STORE_add_cert(st, root);
    return st;
}

/* Verifies with `flags`, printing the result, the content, and the errors. */
static int verify(const char *label, PKCS7 *p7, STACK_OF(X509) *certs, X509_STORE *st, BIO *in, int flags)
{
    BIO *out = BIO_new(BIO_s_mem());
    int r = PKCS7_verify(p7, certs, st, in, out, flags);

    printf("# verify %s: %d\n", label, r);
    show("content", out);
    errors();
    BIO_free(out);
    return r;
}

/* Signs `msg` with `flags`, verifies it against the root, and returns the object. */
static PKCS7 *sign(const char *label, X509 *signer, EVP_PKEY *pkey, STACK_OF(X509) *certs, const char *msg, int flags,
                   X509_STORE *st, int print)
{
    BIO *in = mem(msg);
    PKCS7 *p7 = PKCS7_sign(signer, pkey, certs, in, flags);

    printf("# sign %s: %s\n", label, p7 == NULL ? "NULL" : "made");
    errors();
    if (p7 != NULL) {
        BIO *data = (flags & PKCS7_DETACHED) != 0 ? mem(msg) : NULL;
        STACK_OF(X509) *extra = NULL;

        show_signers(p7);
        if (print)
            fingerprint("encoding", p7);
        if ((flags & PKCS7_NOCERTS) != 0) {
            extra = sk_X509_new_null();
            sk_X509_push(extra, signer);
        }
        check(verify(label, p7, extra, st, data, flags & (PKCS7_TEXT | PKCS7_BINARY)) == 1, label);
        BIO_free(data);
        sk_X509_free(extra);
    } else {
        check(0, label);
    }
    BIO_free(in);
    return p7;
}

/* Decrypts with `flags`, printing the result, the content, and the errors. */
static int decrypt(const char *label, PKCS7 *p7, EVP_PKEY *pkey, X509 *x, int flags)
{
    BIO *out = BIO_new(BIO_s_mem());
    int r = PKCS7_decrypt(p7, pkey, x, out, flags);

    printf("# decrypt %s: %d\n", label, r);
    show("content", out);
    errors();
    BIO_free(out);
    return r;
}

static void crlf(const char *label, const char *in, int n, int flags)
{
    BIO *src = bytes(in, n), *out = BIO_new(BIO_s_mem());
    int r = SMIME_crlf_copy(src, out, flags);

    printf("# crlf_copy %s: %d\n", label, r);
    show("out", out);
    errors();
    BIO_free(src);
    BIO_free(out);
}

static void text(const char *label, const char *in)
{
    BIO *src = mem(in), *out = BIO_new(BIO_s_mem());
    int r = SMIME_text(src, out);

    printf("# text %s: %d\n", label, r);
    show("out", out);
    errors();
    BIO_free(src);
    BIO_free(out);
}

int main(void)
{
    X509 *root = cert(CA_PEM), *rsa = cert(RSA_PEM), *ec = cert(EC_PEM), *rcpt = cert(RCPT_PEM);
    EVP_PKEY *rsa_key = key(RSA_KEY_PEM), *ec_key = key(EC_KEY_PEM), *rcpt_key = key(RCPT_KEY_PEM);
    X509_STORE *st = store_of(root), *empty = store_of(NULL);
    static const char msg[] = "Hello, S/MIME.\nSecond line  \r\n\nlast";
    static const char lines[] = "one\ntwo  \r\n\n\nthree \r\r\n\n\n";
    PKCS7 *p7;

    check(root != NULL && rsa != NULL && ec != NULL && rcpt != NULL && rsa_key != NULL && ec_key != NULL
              && rcpt_key != NULL,
          "fixtures");

    /* SMIME_crlf_copy */
    crlf("text", lines, (int)strlen(lines), 0);
    crlf("binary", lines, (int)strlen(lines), PKCS7_BINARY);
    crlf("with a text header", lines, (int)strlen(lines), PKCS7_TEXT);
    crlf("ASCII CRLF", lines, (int)strlen(lines), SMIME_ASCIICRLF);
    crlf("CMS binary", lines, (int)strlen(lines), CMS_BINARY);
    crlf("CMS binary, CRLF", lines, (int)strlen(lines), CMS_BINARY | SMIME_CRLFEOL);
    crlf("an embedded NUL", "a\0b\nc", 5, 0);
    crlf("empty", "", 0, 0);
    {
        char longline[3000];

        memset(longline, 'x', sizeof(longline));
        longline[1500] = '\n';
        crlf("a long line", longline, (int)sizeof(longline), 0);
    }
    {
        BIO *b = mem("x");

        printf("# crlf_copy NULL: %d %d\n", SMIME_crlf_copy(NULL, b, 0), SMIME_crlf_copy(b, NULL, 0));
        errors();
        BIO_free(b);
    }
    check(1, "SMIME_crlf_copy");

    /* SMIME_text */
    text("plain", "Content-Type: text/plain\r\n\r\nbody\r\nmore");
    text("case and parameters", "MIME-Version: 1.0\r\ncontent-TYPE: Text/Plain; charset=\"us-ascii\"\r\n\r\nbody");
    text("continued", "Content-Type: text/plain;\r\n\tcharset=us-ascii\r\nX: y\r\n\r\nbody");
    text("quoted", "Content-Type: \"text/plain\"\r\n\r\nbody");
    text("a comment", "Content-Type: text/plain (plain text)\r\n\r\nbody");
    text("html", "Content-Type: text/html\r\n\r\n<p>");
    text("no type", "Subject: hi\r\n\r\nbody");
    text("no value", "Content-Type:\r\n\r\nbody");
    text("no blank line", "Content-Type: text/plain\r\n");
    text("LF only", "Content-Type: text/plain\n\nbody\n");
    text("empty", "");
    check(1, "SMIME_text");

    /* The reference's objects */
    p7 = p7_of(REF_SIGNED);
    show_signers(p7);
    check(verify("reference, attached", p7, NULL, st, NULL, 0) == 1, "verify the reference's attached signature");
    verify("reference, as text", p7, NULL, st, NULL, PKCS7_TEXT);
    check(verify("reference, untrusted", p7, NULL, empty, NULL, 0) == 0, "an untrusted signer is refused");
    check(verify("reference, not verified", p7, NULL, empty, NULL, PKCS7_NOVERIFY) == 1, "PKCS7_NOVERIFY");
    check(verify("reference, signatures not checked", p7, NULL, empty, NULL, PKCS7_NOVERIFY | PKCS7_NOSIGS) == 1,
          "PKCS7_NOSIGS");
    {
        BIO *in = mem(msg);

        check(verify("reference, dual content", p7, NULL, st, in, PKCS7_NO_DUAL_CONTENT) == 0, "PKCS7_NO_DUAL_CONTENT");
        BIO_free(in);
    }
    {
        STACK_OF(X509) *s = PKCS7_get0_signers(p7, NULL, 0), *mine = sk_X509_new_null();

        printf("# signers: %d, the RSA signer %d\n", sk_X509_num(s), X509_cmp(sk_X509_value(s, 0), rsa) == 0);
        sk_X509_free(s);
        s = PKCS7_get0_signers(p7, mine, PKCS7_NOINTERN);
        printf("  not internal: %s\n", s == NULL ? "NULL" : "found");
        errors();
        sk_X509_push(mine, rsa);
        s = PKCS7_get0_signers(p7, mine, PKCS7_NOINTERN);
        printf("  given: %d\n", sk_X509_num(s));
        sk_X509_free(s);
        sk_X509_free(mine);
        check(1, "PKCS7_get0_signers");
    }
    {
        /* The content's last octet changed. */
        ASN1_OCTET_STRING *os = p7->d.sign->contents->d.data;

        os->data[os->length - 1] ^= 1;
        check(verify("reference, tampered", p7, NULL, st, NULL, 0) == 0, "a tampered content is refused");
        os->data[os->length - 1] ^= 1;
    }
    {
        /* The data path by hand. */
        STACK_OF(PKCS7_SIGNER_INFO) *sis = PKCS7_get_signer_info(p7);
        PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sis, 0);
        BIO *bio = PKCS7_dataDecode(p7, NULL, NULL, NULL), *sink = BIO_new(BIO_s_mem());
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        char buf[256];
        int n;

        while ((n = BIO_read(bio, buf, sizeof(buf))) > 0)
            BIO_write(sink, buf, n);
        show("decoded", sink);
        printf("# dataVerify: %d\n", PKCS7_dataVerify(st, ctx, bio, p7, si));
        errors();
        printf("# dataVerify, untrusted: %d\n", PKCS7_dataVerify(empty, ctx, bio, p7, si));
        errors();
        printf("# signatureVerify: %d\n", PKCS7_signatureVerify(bio, p7, si, rsa));
        printf("# signatureVerify, the wrong signer: %d\n", PKCS7_signatureVerify(bio, p7, si, ec));
        errors();
        printf("# signatureVerify, no digest BIO: %d\n", PKCS7_signatureVerify(sink, p7, si, rsa));
        errors();
        X509_STORE_CTX_free(ctx);
        BIO_free_all(bio);
        BIO_free(sink);
        check(1, "PKCS7_dataDecode, PKCS7_dataVerify, PKCS7_signatureVerify");
    }
    PKCS7_free(p7);

    p7 = p7_of(REF_DETACHED);
    show_signers(p7);
    {
        BIO *in = mem(msg);

        check(verify("reference, detached", p7, NULL, st, in, PKCS7_BINARY) == 1, "verify the reference's detached signature");
        BIO_free(in);
        check(verify("reference, detached, no content", p7, NULL, st, NULL, 0) == 0, "a detached signature needs its content");
        in = mem("Hello, S/MIME!");
        check(verify("reference, detached, other content", p7, NULL, st, in, PKCS7_BINARY) == 0, "other content is refused");
        BIO_free(in);
    }
    PKCS7_free(p7);

    p7 = p7_of(REF_EC);
    show_signers(p7);
    check(verify("reference, EC", p7, NULL, st, NULL, PKCS7_BINARY) == 1, "verify the reference's EC signature");
    PKCS7_free(p7);

    p7 = p7_of(REF_ENV);
    printf("# recipients %d\n", sk_PKCS7_RECIP_INFO_num(p7->d.enveloped->recipientinfo));
    check(decrypt("reference, the recipient", p7, rcpt_key, rcpt, 0) == 1, "decrypt the reference's object");
    check(decrypt("reference, the RSA signer", p7, rsa_key, rsa, 0) == 1, "decrypt as the second recipient");
    check(decrypt("reference, the last recipient's key alone", p7, rsa_key, NULL, 0) == 1, "decrypt without a certificate");
    check(decrypt("reference, a key that doesn't match", p7, ec_key, rcpt, 0) == 0, "a mismatched key is refused");
    check(decrypt("reference, not a recipient", p7, ec_key, ec, 0) == 0, "a non-recipient is refused");
    check(decrypt("reference, as text", p7, rcpt_key, rcpt, PKCS7_TEXT) == 0, "text needs a text header");
    check(verify("reference, not signed", p7, NULL, st, NULL, 0) == 0, "PKCS7_verify needs SignedData");
    PKCS7_free(p7);

    /* Signing */
    p7 = sign("RSA", rsa, rsa_key, NULL, msg, 0, st, 0);
    if (p7 != NULL) {
        /* Signing again over the same attributes. */
        PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(p7), 0);

        printf("# SIGNER_INFO_sign: %d\n", PKCS7_SIGNER_INFO_sign(si));
        errors();
        check(verify("signed again", p7, NULL, st, NULL, 0) == 1, "PKCS7_SIGNER_INFO_sign");
        /* Another signer, reusing the first's digest. */
        si = PKCS7_sign_add_signer(p7, ec, ec_key, EVP_sha256(), PKCS7_REUSE_DIGEST);
        printf("# reuse digest: %s\n", si == NULL ? "NULL" : "added");
        errors();
        show_signers(p7);
        check(verify("two signers", p7, NULL, st, NULL, 0) == 1, "PKCS7_REUSE_DIGEST");
        si = PKCS7_sign_add_signer(p7, rsa, rsa_key, EVP_sha512(), PKCS7_REUSE_DIGEST);
        printf("# reuse a digest that isn't there: %s\n", si == NULL ? "NULL" : "added");
        errors();
        PKCS7_free(p7);
    }
    PKCS7_free(sign("RSA, no attributes", rsa, rsa_key, NULL, msg, PKCS7_NOATTR, st, 1));
    PKCS7_free(sign("RSA, no capabilities", rsa, rsa_key, NULL, msg, PKCS7_NOSMIMECAP, st, 0));
    PKCS7_free(sign("RSA, detached, binary", rsa, rsa_key, NULL, msg, PKCS7_DETACHED | PKCS7_BINARY | PKCS7_NOATTR, st, 1));
    PKCS7_free(sign("RSA, no certificates", rsa, rsa_key, NULL, msg, PKCS7_NOCERTS | PKCS7_NOATTR, st, 1));
    PKCS7_free(sign("RSA, text", rsa, rsa_key, NULL, msg, PKCS7_TEXT | PKCS7_NOATTR, st, 1));
    PKCS7_free(sign("EC", ec, ec_key, NULL, msg, PKCS7_BINARY, st, 0));
    {
        STACK_OF(X509) *chain = sk_X509_new_null();

        sk_X509_push(chain, root);
        sk_X509_push(chain, rcpt);
        PKCS7_free(sign("RSA, with certificates", rsa, rsa_key, chain, msg, PKCS7_NOATTR, st, 1));
        p7 = PKCS7_sign(NULL, NULL, chain, NULL, PKCS7_PARTIAL);
        printf("# certificates only:\n");
        show_signers(p7);
        fingerprint("encoding", p7);
        errors();
        PKCS7_free(p7);
        sk_X509_free(chain);
    }
    {
        /* Partial, then a signer with its own digest, then final. */
        BIO *in = mem(msg);
        PKCS7_SIGNER_INFO *si;

        p7 = PKCS7_sign(NULL, NULL, NULL, NULL, PKCS7_PARTIAL);
        si = PKCS7_sign_add_signer(p7, rsa, rsa_key, EVP_sha384(), PKCS7_NOATTR);
        printf("# partial: signer %s, final %d\n", si == NULL ? "NULL" : "added", PKCS7_final(p7, in, 0));
        errors();
        show_signers(p7);
        fingerprint("encoding", p7);
        check(verify("partial", p7, NULL, st, NULL, 0) == 1, "PKCS7_PARTIAL and PKCS7_final");
        PKCS7_free(p7);
        BIO_free(in);
        in = mem(msg);
        p7 = PKCS7_sign(rsa, rsa_key, NULL, NULL, PKCS7_STREAM | PKCS7_NOATTR);
        printf("# stream: final %d\n", PKCS7_final(p7, in, PKCS7_BINARY));
        fingerprint("encoding", p7);
        check(verify("stream", p7, NULL, st, NULL, PKCS7_BINARY) == 1, "PKCS7_STREAM and PKCS7_final");
        PKCS7_free(p7);
        BIO_free(in);
    }
    {
        BIO *in = mem(msg);

        p7 = PKCS7_sign(rsa, ec_key, NULL, in, 0);
        printf("# sign with a key that doesn't match: %s\n", p7 == NULL ? "NULL" : "made");
        errors();
        check(p7 == NULL, "a mismatched key is refused");
        BIO_free(in);
    }

    /* Encrypting */
    {
        const EVP_CIPHER *ciphers[] = {EVP_aes_128_cbc(), EVP_aes_256_cbc(), EVP_des_ede3_cbc()};
        STACK_OF(X509) *to = sk_X509_new_null();
        size_t i;

        sk_X509_push(to, rcpt);
        sk_X509_push(to, rsa);
        for (i = 0; i < sizeof(ciphers) / sizeof(ciphers[0]); i++) {
            BIO *in = mem(msg);
            PKCS7 *env = PKCS7_encrypt(to, in, ciphers[i], PKCS7_BINARY);
            X509_ALGOR *alg = env == NULL ? NULL : env->d.enveloped->enc_data->algorithm;

            printf("# encrypt %s: %s, algorithm %s, parameter %s, key %d octets\n", EVP_CIPHER_get0_name(ciphers[i]),
                   env == NULL ? "NULL" : "made", alg == NULL ? "-" : oid(alg->algorithm),
                   alg == NULL || alg->parameter == NULL ? "none" : "set",
                   env == NULL ? -1 : sk_PKCS7_RECIP_INFO_value(env->d.enveloped->recipientinfo, 0)->enc_key->length);
            errors();
            check(decrypt("made here", env, rcpt_key, rcpt, 0) == 1, "encrypt and decrypt");
            check(decrypt("made here, the last recipient's key alone", env, rsa_key, NULL, 0) == 1, "decrypt without a certificate");
            PKCS7_free(env);
            BIO_free(in);
        }
        {
            BIO *in = mem("Content-Type: text/plain\r\n\r\nthe body");
            PKCS7 *env = PKCS7_encrypt(to, in, EVP_aes_128_cbc(), PKCS7_TEXT);

            check(decrypt("text", env, rcpt_key, rcpt, PKCS7_TEXT) == 1, "decrypt as text");
            PKCS7_free(env);
            BIO_free(in);
            in = mem("a\nb\n");
            env = PKCS7_encrypt(to, in, EVP_aes_128_cbc(), PKCS7_STREAM);
            printf("# encrypt, stream: final %d\n", PKCS7_final(env, in, 0));
            errors();
            check(decrypt("stream", env, rcpt_key, rcpt, 0) == 1, "PKCS7_STREAM and PKCS7_final");
            PKCS7_free(env);
            BIO_free(in);
        }
        {
            BIO *in = mem(msg);
            PKCS7 *env = PKCS7_encrypt(to, in, NULL, 0);

            printf("# encrypt without a cipher: %s\n", env == NULL ? "NULL" : "made");
            errors();
            PKCS7_free(env);
            BIO_free(in);
        }
        sk_X509_free(to);
    }

    /* In a library context of their own */
    {
        OSSL_LIB_CTX *lc = OSSL_LIB_CTX_new();
        BIO *in = mem(msg);
        STACK_OF(X509) *to = sk_X509_new_null();
        PKCS7 *env;

        p7 = PKCS7_sign_ex(rsa, rsa_key, NULL, in, PKCS7_NOATTR, lc, "provider=default");
        printf("# sign_ex: %s\n", p7 == NULL ? "NULL" : "made");
        errors();
        fingerprint("encoding", p7);
        check(verify("sign_ex", p7, NULL, st, NULL, 0) == 1, "PKCS7_sign_ex");
        PKCS7_free(p7);
        BIO_free(in);
        in = mem(msg);
        sk_X509_push(to, rcpt);
        env = PKCS7_encrypt_ex(to, in, EVP_aes_128_cbc(), PKCS7_BINARY, lc, NULL);
        printf("# encrypt_ex: %s\n", env == NULL ? "NULL" : "made");
        errors();
        check(decrypt("encrypt_ex", env, rcpt_key, rcpt, 0) == 1, "PKCS7_encrypt_ex");
        PKCS7_free(env);
        BIO_free(in);
        sk_X509_free(to);
        OSSL_LIB_CTX_free(lc);
    }

    /* The data path by hand */
    {
        PKCS7 *d = PKCS7_new();
        BIO *b;

        PKCS7_set_type(d, NID_pkcs7_digest);
        PKCS7_set_digest(d, EVP_sha256());
        PKCS7_content_new(d, NID_pkcs7_data);
        b = PKCS7_dataInit(d, NULL);
        BIO_write(b, msg, (int)strlen(msg));
        printf("# DigestedData: final %d\n", PKCS7_dataFinal(d, b));
        errors();
        fingerprint("encoding", d);
        BIO_free_all(b);
        printf("# DigestedData, decode: %s\n", PKCS7_dataDecode(d, NULL, NULL, NULL) == NULL ? "NULL" : "made");
        errors();
        PKCS7_free(d);

        d = PKCS7_new();
        PKCS7_set_type(d, NID_pkcs7_data);
        b = PKCS7_dataInit(d, NULL);
        BIO_write(b, msg, (int)strlen(msg));
        printf("# Data: final %d\n", PKCS7_dataFinal(d, b));
        fingerprint("encoding", d);
        BIO_free_all(b);
        errors();
        PKCS7_free(d);

        d = PKCS7_new();
        PKCS7_set_type(d, NID_pkcs7_enveloped);
        printf("# EnvelopedData without a cipher: %s\n", PKCS7_dataInit(d, NULL) == NULL ? "NULL" : "made");
        errors();
        PKCS7_free(d);

        d = PKCS7_new();
        printf("# no content: init %s, decode %s, final %d\n", PKCS7_dataInit(d, NULL) == NULL ? "NULL" : "made",
               PKCS7_dataDecode(d, NULL, NULL, NULL) == NULL ? "NULL" : "made", PKCS7_dataFinal(d, NULL));
        errors();
        PKCS7_free(d);

        d = PKCS7_new();
        PKCS7_set_type(d, NID_pkcs7_encrypted);
        printf("# EncryptedData: init %s, decode %s\n", PKCS7_dataInit(d, NULL) == NULL ? "NULL" : "made",
               PKCS7_dataDecode(d, NULL, NULL, NULL) == NULL ? "NULL" : "made");
        errors();
        PKCS7_free(d);
        check(1, "PKCS7_dataInit and PKCS7_dataFinal");
    }

    /* NULL objects */
    printf("# NULL: init %s, decode %s, final %d, verify %d, signers %s, decrypt %d\n",
           PKCS7_dataInit(NULL, NULL) == NULL ? "NULL" : "made", PKCS7_dataDecode(NULL, NULL, NULL, NULL) == NULL ? "NULL" : "made",
           PKCS7_dataFinal(NULL, NULL), PKCS7_verify(NULL, NULL, NULL, NULL, NULL, 0),
           PKCS7_get0_signers(NULL, NULL, 0) == NULL ? "NULL" : "found", PKCS7_decrypt(NULL, NULL, NULL, NULL, 0));
    errors();
    check(1, "NULL objects");

    X509_STORE_free(st);
    X509_STORE_free(empty);
    X509_free(root);
    X509_free(rsa);
    X509_free(ec);
    X509_free(rcpt);
    EVP_PKEY_free(rsa_key);
    EVP_PKEY_free(ec_key);
    EVP_PKEY_free(rcpt_key);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
