/*
 * Conformance test for streaming and S/MIME (BIO_f_asn1(3), BIO_asn1_set_prefix(3),
 * BIO_new_NDEF(3), i2d_ASN1_bio_stream(3), PEM_write_bio_ASN1_stream(3), SMIME_write_ASN1(3),
 * SMIME_read_ASN1(3), and their PKCS#7 forms: PKCS7_stream, BIO_new_PKCS7(3),
 * i2d_PKCS7_bio_stream(3), PEM_write_bio_PKCS7_stream(3), SMIME_write_PKCS7(3),
 * SMIME_read_PKCS7(3)): the ASN.1 filter with prefix and suffix functions of its own; objects
 * streamed with indefinite lengths, short and long, as DER, PEM, and S/MIME, then read back
 * and verified or decrypted; the reference tool's S/MIME messages read; and malformed messages
 * refused. Random MIME boundaries are masked; outputs with an encrypted key are checked, not
 * printed.
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
#include <openssl/pkcs7.h>
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
            printf(" (%s)", data);
    }
    printf("\n");
}

/*
 * Made with the reference's openssl tool: an EC root; an RSA signer and an RSA recipient, each
 * for emailProtection; smime -sign (multipart/signed), smime -sign -nodetach (opaque), and
 * smime -encrypt -aes-128-cbc.
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

static const char REF_MULTI[] =
    "MIME-Version: 1.0\n"
    "Content-Type: multipart/signed; protocol=\"application/x-pkcs7-signature\"; micalg=\"sha-256\"; boundary=\"----DE64DCF074A707B4A6E1057AA5773F9B\"\n"
    "\n"
    "This is an S/MIME signed message\n"
    "\n"
    "------DE64DCF074A707B4A6E1057AA5773F9B\n"
    "Hello, S/MIME.\r\n"
    "Second line  \r\n"
    "\r\n"
    "last\n"
    "------DE64DCF074A707B4A6E1057AA5773F9B\n"
    "Content-Type: application/x-pkcs7-signature; name=\"smime.p7s\"\n"
    "Content-Transfer-Encoding: base64\n"
    "Content-Disposition: attachment; filename=\"smime.p7s\"\n"
    "\n"
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
    "AzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MTAxNzIyNTk0N1owLwYJ\n"
    "KoZIhvcNAQkEMSIEID5z6mhb/SexdToeHXSQoNKdmT75qZQC8ltGRAzuPKWUMHkG\n"
    "CSqGSIb3DQEJDzFsMGowCwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQBFjALBglghkgB\n"
    "ZQMEAQIwCgYIKoZIhvcNAwcwDgYIKoZIhvcNAwICAgCAMA0GCCqGSIb3DQMCAgFA\n"
    "MAcGBSsOAwIHMA0GCCqGSIb3DQMCAgEoMA0GCSqGSIb3DQEBAQUABIIBADoOOO9t\n"
    "xGxQ+6LXkWokULkgHgcHvw1BWKzgAEGmHLeCnGG51P0pSrFsLh5xY0Npn5gFJVrM\n"
    "RgxMfFmlW/WjvoZZ4Y5+IaeFazzS+nb9/ZxSAD8GHBvQTNN7/OWijW+o9cMx1keq\n"
    "jomXcFQppjx7Ciwv6ugJJWdwdzr+eDUMbFrgqlQ3eaEZeXEqZmiEe0lsKed4KGPi\n"
    "gR6V9lK+YJJvcckQJbAAQBr8eHE/ebHmivU/rA6KsOyLa/6J3g8vtReJDJ8dWXRN\n"
    "ozb9ORC5Ab7zfNpTDHtGeXbtNz2602JnwruQG+B2AnTW/PfSarXG7s+kETAj4P5Q\n"
    "pe+STAhx3NTMKdU=\n"
    "\n"
    "------DE64DCF074A707B4A6E1057AA5773F9B--\n"
    "\n";

static const char REF_OPAQUE[] =
    "MIME-Version: 1.0\n"
    "Content-Disposition: attachment; filename=\"smime.p7m\"\n"
    "Content-Type: application/x-pkcs7-mime; smime-type=signed-data; name=\"smime.p7m\"\n"
    "Content-Transfer-Encoding: base64\n"
    "\n"
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
    "SIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMDE3MjI1OTQ3WjAvBgkqhkiG9w0B\n"
    "CQQxIgQgPnPqaFv9J7F1Oh4ddJCg0p2ZPvmplALyW0ZEDO48pZQweQYJKoZIhvcN\n"
    "AQkPMWwwajALBglghkgBZQMEASowCwYJYIZIAWUDBAEWMAsGCWCGSAFlAwQBAjAK\n"
    "BggqhkiG9w0DBzAOBggqhkiG9w0DAgICAIAwDQYIKoZIhvcNAwICAUAwBwYFKw4D\n"
    "AgcwDQYIKoZIhvcNAwICASgwDQYJKoZIhvcNAQEBBQAEggEAOg44723EbFD7oteR\n"
    "aiRQuSAeBwe/DUFYrOAAQaYct4KcYbnU/SlKsWwuHnFjQ2mfmAUlWsxGDEx8WaVb\n"
    "9aO+hlnhjn4hp4VrPNL6dv39nFIAPwYcG9BM03v85aKNb6j1wzHWR6qOiZdwVCmm\n"
    "PHsKLC/q6AklZ3B3Ov54NQxsWuCqVDd5oRl5cSpmaIR7SWwp53goY+KBHpX2Ur5g\n"
    "km9xyRAlsABAGvx4cT95seaK9T+sDoqw7Itr/oneDy+1F4kMnx1ZdE2jNv05ELkB\n"
    "vvN82lMMe0Z5du03PbrTYmfCu5Ab4HYCdNb899Jqtcbuz6QRMCPg/lCl75JMCHHc\n"
    "1Mwp1Q==\n"
    "\n";

static const char REF_ENV[] =
    "MIME-Version: 1.0\n"
    "Content-Disposition: attachment; filename=\"smime.p7m\"\n"
    "Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\n"
    "Content-Transfer-Encoding: base64\n"
    "\n"
    "MIIBwAYJKoZIhvcNAQcDoIIBsTCCAa0CAQAxggFIMIIBRAIBADAsMCcxEDAOBgNV\n"
    "BAoMB0V4YW1wbGUxEzARBgNVBAMMClNNSU1FIFJvb3QCAWcwDQYJKoZIhvcNAQEB\n"
    "BQAEggEAEAttIz7roKuGijzB3qBLRJUm9dNrY1AhL+5JkkqRw+5B7+71ApOkWy/h\n"
    "5cgV4hkVXq1EhXdToQ4bA23Z9FCjG3xFSkELj/stVuOoaJ2SiGBWIGR0jkQ7a4Jz\n"
    "dXHl07O+VYcuei8lZLQaMQcLV53tpuof32r0Bu/ffca7aGDMjkytnl76vAJOcan5\n"
    "luiq/g6k0mlfiFnWNMXufdCYdOX5FbEE2E4v+twtSQVbqLQkF0Y4Y559wS4zpnYo\n"
    "Lb2D5yt+IzLc4CAI7Hfi4E+pJ2AaJbh5FvOcPcwbpdS5DFWrV8wUINx3UID8mrHb\n"
    "H1Xhjp89DGvef2eG7YB1MAZ6gaS+mDBcBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEC\n"
    "BBDLMOOJ7oGq0J/qL1M7o5pCgDDOJ7nIyDrjX/PKIYQdxqUPTOASveUcI8NGT2+H\n"
    "fpwMV/ghl/By3gUFrh3QwPUgdeo=\n"
    "\n";
static const char msg[] = "Hello, S/MIME.\nSecond line  \r\n\nlast";

static BIO *mem(const char *s)
{
    return BIO_new_mem_buf(s, -1);
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

static void hex(const char *label, const unsigned char *p, int n)
{
    int i;

    printf("  %s (%d):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 ? "\n    " : "", p[i]);
    printf("\n");
}

/* A memory BIO's length and SHA-256. */
static void digest(const char *label, BIO *b)
{
    char *p;
    long n = BIO_get_mem_data(b, &p);
    unsigned char md[32];
    unsigned int mdlen = 0;

    EVP_Digest(p, (size_t)n, md, &mdlen, EVP_sha256(), NULL);
    printf("  %s: %ld octets,", label, n);
    hex("sha256", md, (int)mdlen);
}

/* A memory BIO's text, with any MIME boundary (32 hex digits after "----") masked. */
static void text(const char *label, BIO *b)
{
    char *p, *copy, *q;
    long n = BIO_get_mem_data(b, &p);

    copy = malloc((size_t)n + 1);
    memcpy(copy, p, (size_t)n);
    copy[n] = '\0';
    for (q = strstr(copy, "----"); q != NULL; q = strstr(q + 1, "----")) {
        char *h = q + strspn(q, "-");

        if (strspn(h, "0123456789ABCDEF") == 32)
            memset(h, 'X', 32);
    }
    printf("  %s (%ld):\n%s<end>\n", label, n, copy);
    free(copy);
}

/* An ASN.1 filter's prefix and suffix functions, writing fixed octets. */
static unsigned char pre[] = "<prefix>";
static unsigned char suf[] = "<suffix>";
static int calls;

static int prefix_cb(BIO *b, unsigned char **pbuf, int *plen, void *parg)
{
    (void)b;
    calls++;
    printf("  prefix called, arg %s\n", *(void **)parg == NULL ? "NULL" : (char *)*(void **)parg);
    *pbuf = pre;
    *plen = (int)strlen((char *)pre);
    return 1;
}

static int suffix_cb(BIO *b, unsigned char **pbuf, int *plen, void *parg)
{
    (void)b;
    (void)parg;
    calls++;
    printf("  suffix called\n");
    *pbuf = suf;
    *plen = (int)strlen((char *)suf);
    return 1;
}

static int free_cb(BIO *b, unsigned char **pbuf, int *plen, void *parg)
{
    (void)b;
    (void)parg;
    calls++;
    printf("  free called, buffer %s\n", *pbuf == NULL ? "NULL" : (char *)*pbuf);
    *pbuf = NULL;
    *plen = 0;
    return 1;
}

static int failing_cb(BIO *b, unsigned char **pbuf, int *plen, void *parg)
{
    (void)b;
    (void)pbuf;
    (void)plen;
    (void)parg;
    return 0;
}

static void filter(const char *label, asn1_ps_func *p, asn1_ps_func *pf, asn1_ps_func *s, asn1_ps_func *sf,
                   const char *const *chunks)
{
    BIO *out = BIO_new(BIO_s_mem()), *f = BIO_new(BIO_f_asn1());
    asn1_ps_func *gp = NULL, *gpf = NULL;
    char *p0;
    long n;
    int i;

    printf("# filter %s\n", label);
    BIO_push(f, out);
    BIO_asn1_set_prefix(f, p, pf);
    BIO_asn1_set_suffix(f, s, sf);
    BIO_ctrl(f, BIO_C_SET_EX_ARG, 0, (void *)"the argument");
    BIO_asn1_get_prefix(f, &gp, &gpf);
    printf("  get prefix: %d %d\n", gp == p, gpf == pf);
    BIO_asn1_get_suffix(f, &gp, &gpf);
    printf("  get suffix: %d %d\n", gp == s, gpf == sf);
    for (i = 0; chunks[i] != NULL; i++)
        printf("  write %d: %d\n", i, BIO_write(f, chunks[i], (int)strlen(chunks[i])));
    printf("  puts: %d\n", BIO_puts(f, "!"));
    printf("  flush: %d\n", BIO_flush(f));
    printf("  write after: %d\n", BIO_write(f, "x", 1));
    n = BIO_get_mem_data(out, &p0);
    hex("out", (unsigned char *)p0, (int)n);
    BIO_pop(f);
    BIO_free(f);
    BIO_free(out);
    errors();
}

static PKCS7 *read_back(const char *label, BIO *b)
{
    PKCS7 *p7 = d2i_PKCS7_bio(b, NULL);

    printf("  %s: %s\n", label, p7 == NULL ? "NULL" : "read");
    return p7;
}

static int verify(const char *label, PKCS7 *p7, X509_STORE *st, BIO *in, int flags)
{
    BIO *out = BIO_new(BIO_s_mem());
    int r = PKCS7_verify(p7, NULL, st, in, out, flags);

    printf("# verify %s: %d\n", label, r);
    digest("content", out);
    errors();
    BIO_free(out);
    return r;
}

static int decrypt(const char *label, PKCS7 *p7, EVP_PKEY *pkey, X509 *x)
{
    BIO *out = BIO_new(BIO_s_mem());
    int r = PKCS7_decrypt(p7, pkey, x, out, 0);

    printf("# decrypt %s: %d\n", label, r);
    digest("content", out);
    errors();
    BIO_free(out);
    return r;
}

/* Reads an S/MIME message, printing the content part's and the object's state. */
static PKCS7 *smime_read(const char *label, const char *s, BIO **bcont)
{
    BIO *b = mem(s);
    PKCS7 *p7 = SMIME_read_PKCS7(b, bcont);

    printf("# read %s: %s, type %s, content %s\n", label, p7 == NULL ? "NULL" : "read",
           p7 == NULL ? "-" : OBJ_nid2sn(OBJ_obj2nid(p7->type)), bcont == NULL || *bcont == NULL ? "none" : "set");
    errors();
    BIO_free(b);
    return p7;
}

int main(void)
{
    X509 *root = cert(CA_PEM), *rsa = cert(RSA_PEM), *rcpt = cert(RCPT_PEM);
    EVP_PKEY *rsa_key = key(RSA_KEY_PEM), *rcpt_key = key(RCPT_KEY_PEM);
    X509_STORE *st = X509_STORE_new();
    char *big = malloc(10001);
    PKCS7 *p7;
    BIO *out, *in, *bcont;

    X509_STORE_add_cert(st, root);
    memset(big, 'a', 10000);
    for (int i = 0; i < 10000; i += 80)
        big[i] = '\n';
    big[10000] = '\0';
    check(root != NULL && rsa != NULL && rcpt != NULL && rsa_key != NULL && rcpt_key != NULL, "fixtures");

    /* The ASN.1 filter */
    {
        const char *const two[] = {"hello", "world, longer", NULL};
        const char *const none[] = {NULL};
        char longer[300];
        const char *const one_long[] = {longer, NULL};

        memset(longer, 'z', sizeof(longer) - 1);
        longer[sizeof(longer) - 1] = '\0';
        filter("with a prefix and a suffix", prefix_cb, free_cb, suffix_cb, free_cb, two);
        filter("plain", NULL, NULL, NULL, NULL, two);
        filter("nothing written", prefix_cb, free_cb, suffix_cb, free_cb, none);
        filter("a long write", NULL, NULL, suffix_cb, NULL, one_long);
        filter("a failing prefix", failing_cb, NULL, NULL, NULL, two);
        filter("a failing suffix", NULL, NULL, failing_cb, NULL, two);
        printf("# calls %d\n", calls);
        check(1, "BIO_f_asn1");
    }
    {
        BIO *b = BIO_new(BIO_s_mem());
        ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();

        printf("# NDEF of a primitive: %s\n",
               BIO_new_NDEF(b, (ASN1_VALUE *)os, ASN1_ITEM_rptr(ASN1_OCTET_STRING)) == NULL ? "NULL" : "made");
        errors();
        ASN1_OCTET_STRING_free(os);
        BIO_free(b);
        check(1, "BIO_new_NDEF refuses a type without streaming");
    }

    /* Streaming a signature */
    {
        const char *contents[] = {msg, big};
        int i;

        for (i = 0; i < 2; i++) {
            p7 = PKCS7_sign(rsa, rsa_key, NULL, NULL, PKCS7_STREAM | PKCS7_NOATTR);
            in = mem(contents[i]);
            out = BIO_new(BIO_s_mem());
            printf("# stream %d: %d\n", i, i2d_PKCS7_bio_stream(out, p7, in, PKCS7_STREAM));
            errors();
            digest("DER", out);
            {
                char *d;
                long n = BIO_get_mem_data(out, &d);

                hex("start", (unsigned char *)d, n > 48 ? 48 : (int)n);
            }
            PKCS7_free(p7);
            p7 = read_back("read back", out);
            check(verify("streamed", p7, st, NULL, 0) == 1, i == 0 ? "a short stream" : "a long stream");
            PKCS7_free(p7);
            BIO_free(in);
            BIO_free(out);
        }
    }
    {
        p7 = PKCS7_sign(rsa, rsa_key, NULL, NULL, PKCS7_STREAM | PKCS7_NOATTR);
        in = mem(msg);
        out = BIO_new(BIO_s_mem());
        printf("# PEM stream: %d\n", PEM_write_bio_PKCS7_stream(out, p7, in, PKCS7_STREAM));
        errors();
        text("PEM", out);
        PKCS7_free(p7);
        p7 = PEM_read_bio_PKCS7(out, NULL, NULL, NULL);
        check(p7 != NULL && verify("PEM", p7, st, NULL, 0) == 1, "PEM_write_bio_PKCS7_stream");
        PKCS7_free(p7);
        BIO_free(in);
        BIO_free(out);
    }
    {
        /* Not streamed: the stored content. */
        in = mem(msg);
        p7 = PKCS7_sign(rsa, rsa_key, NULL, in, PKCS7_NOATTR);
        out = BIO_new(BIO_s_mem());
        printf("# not streamed: %d\n", i2d_PKCS7_bio_stream(out, p7, NULL, 0));
        digest("DER", out);
        (void)BIO_reset(out);
        printf("# PEM, not streamed: %d\n", PEM_write_bio_ASN1_stream(out, (ASN1_VALUE *)p7, NULL, 0, "PKCS7", ASN1_ITEM_rptr(PKCS7)));
        digest("PEM", out);
        errors();
        PKCS7_free(p7);
        BIO_free(in);
        BIO_free(out);
        check(1, "i2d_ASN1_bio_stream without SMIME_STREAM");
    }
    {
        /* By hand: BIO_new_PKCS7, then BIO_write and BIO_flush. */
        BIO *b;

        p7 = PKCS7_sign(rsa, rsa_key, NULL, NULL, PKCS7_STREAM | PKCS7_NOATTR | PKCS7_BINARY);
        out = BIO_new(BIO_s_mem());
        b = BIO_new_PKCS7(out, p7);
        printf("# BIO_new_PKCS7: %s\n", b == NULL ? "NULL" : "made");
        BIO_write(b, "part one, ", 10);
        BIO_write(b, "part two", 8);
        printf("  flush: %d\n", BIO_flush(b));
        while (b != NULL && b != out) {
            BIO *next = BIO_pop(b);

            BIO_free(b);
            b = next;
        }
        errors();
        digest("DER", out);
        PKCS7_free(p7);
        p7 = read_back("read back", out);
        check(verify("by hand", p7, st, NULL, PKCS7_BINARY) == 1, "BIO_new_PKCS7");
        PKCS7_free(p7);
        BIO_free(out);
    }
    {
        /* Streaming an enveloped object. */
        STACK_OF(X509) *to = sk_X509_new_null();

        sk_X509_push(to, rcpt);
        p7 = PKCS7_encrypt(to, NULL, EVP_aes_128_cbc(), PKCS7_STREAM);
        in = mem(big);
        out = BIO_new(BIO_s_mem());
        printf("# stream enveloped: %d\n", i2d_PKCS7_bio_stream(out, p7, in, PKCS7_STREAM));
        errors();
        PKCS7_free(p7);
        p7 = read_back("read back", out);
        check(decrypt("streamed", p7, rcpt_key, rcpt) == 1, "a streamed enveloped object");
        PKCS7_free(p7);
        BIO_free(in);
        BIO_free(out);
        sk_X509_free(to);
    }
    {
        /* PKCS7_stream on each type */
        unsigned char **boundary = NULL;
        PKCS7 *d = PKCS7_new();

        PKCS7_set_type(d, NID_pkcs7_data);
        printf("# PKCS7_stream data: %d, boundary %s, NDEF %d\n", PKCS7_stream(&boundary, d),
               boundary == &d->d.data->data ? "the data" : "elsewhere", (d->d.data->flags & ASN1_STRING_FLAG_NDEF) != 0);
        PKCS7_free(d);
        d = PKCS7_new();
        PKCS7_set_type(d, NID_pkcs7_signed);
        printf("# PKCS7_stream signed without content: %d\n", PKCS7_stream(&boundary, d));
        errors();
        PKCS7_content_new(d, NID_pkcs7_digest);
        printf("# PKCS7_stream signed digest: %d\n", PKCS7_stream(&boundary, d));
        errors();
        PKCS7_free(d);
        d = PKCS7_new();
        PKCS7_set_type(d, NID_pkcs7_digest);
        printf("# PKCS7_stream digest: %d\n", PKCS7_stream(&boundary, d));
        errors();
        PKCS7_free(d);
        check(1, "PKCS7_stream");
    }

    /* S/MIME */
    {
        in = mem(msg);
        p7 = PKCS7_sign(rsa, rsa_key, NULL, in, PKCS7_NOATTR);
        out = BIO_new(BIO_s_mem());
        printf("# SMIME opaque: %d\n", SMIME_write_PKCS7(out, p7, NULL, 0));
        text("message", out);
        PKCS7_free(p7);
        p7 = SMIME_read_PKCS7(out, NULL);
        check(p7 != NULL && verify("opaque", p7, st, NULL, 0) == 1, "SMIME_write_PKCS7 and SMIME_read_PKCS7, opaque");
        PKCS7_free(p7);
        BIO_free(in);
        BIO_free(out);
    }
    {
        int flags[] = {PKCS7_DETACHED, PKCS7_DETACHED | SMIME_OLDMIME | SMIME_CRLFEOL, PKCS7_DETACHED | PKCS7_STREAM};
        int i;

        for (i = 0; i < 3; i++) {
            in = mem(msg);
            p7 = PKCS7_sign(rsa, rsa_key, NULL, in, flags[i] | PKCS7_NOATTR);
            BIO_free(in);
            in = mem(msg);
            out = BIO_new(BIO_s_mem());
            printf("# SMIME detached %d: %d\n", i, SMIME_write_PKCS7(out, p7, in, flags[i] | PKCS7_NOATTR));
            errors();
            text("message", out);
            PKCS7_free(p7);
            bcont = NULL;
            p7 = SMIME_read_PKCS7(out, &bcont);
            printf("  read %s, content %s\n", p7 == NULL ? "NULL" : "yes", bcont == NULL ? "none" : "set");
            errors();
            check(p7 != NULL && verify("detached", p7, st, bcont, 0) == 1, "SMIME multipart/signed");
            PKCS7_free(p7);
            BIO_free(bcont);
            BIO_free(in);
            BIO_free(out);
        }
    }
    {
        /* Certificates only, through the generic writer. */
        STACK_OF(X509) *chain = sk_X509_new_null();

        sk_X509_push(chain, root);
        p7 = PKCS7_sign(NULL, NULL, chain, NULL, PKCS7_PARTIAL);
        out = BIO_new(BIO_s_mem());
        printf("# SMIME certs-only: %d\n", SMIME_write_ASN1(out, (ASN1_VALUE *)p7, NULL, 0, NID_pkcs7_signed, NID_undef, NULL, ASN1_ITEM_rptr(PKCS7)));
        text("message", out);
        (void)BIO_reset(out);
        printf("# SMIME enveloped type: %d\n", SMIME_write_ASN1_ex(out, (ASN1_VALUE *)p7, NULL, SMIME_OLDMIME, NID_pkcs7_enveloped, NID_undef, NULL, ASN1_ITEM_rptr(PKCS7), NULL, NULL));
        text("message", out);
        PKCS7_free(p7);
        p7 = (PKCS7 *)SMIME_read_ASN1(out, NULL, ASN1_ITEM_rptr(PKCS7));
        printf("  read %s, certs %d\n", p7 == NULL ? "NULL" : "yes", p7 == NULL ? -1 : sk_X509_num(p7->d.sign->cert));
        errors();
        PKCS7_free(p7);
        BIO_free(out);
        sk_X509_free(chain);
        check(1, "SMIME_write_ASN1 and SMIME_read_ASN1");
    }
    {
        STACK_OF(X509) *to = sk_X509_new_null();

        sk_X509_push(to, rcpt);
        in = mem(msg);
        p7 = PKCS7_encrypt(to, in, EVP_aes_128_cbc(), PKCS7_STREAM);
        BIO_free(in);
        in = mem(msg);
        out = BIO_new(BIO_s_mem());
        printf("# SMIME enveloped, streamed: %d\n", SMIME_write_PKCS7(out, p7, in, PKCS7_STREAM));
        errors();
        PKCS7_free(p7);
        p7 = SMIME_read_PKCS7(out, NULL);
        check(p7 != NULL && decrypt("S/MIME", p7, rcpt_key, rcpt) == 1, "S/MIME enveloped");
        PKCS7_free(p7);
        BIO_free(in);
        BIO_free(out);
        sk_X509_free(to);
    }

    /* The reference's messages */
    bcont = NULL;
    p7 = smime_read("reference multipart", REF_MULTI, &bcont);
    check(p7 != NULL && verify("reference multipart", p7, st, bcont, 0) == 1, "the reference's multipart/signed");
    PKCS7_free(p7);
    BIO_free(bcont);
    p7 = smime_read("reference multipart, no content wanted", REF_MULTI, NULL);
    PKCS7_free(p7);
    p7 = smime_read("reference opaque", REF_OPAQUE, NULL);
    check(p7 != NULL && verify("reference opaque", p7, st, NULL, 0) == 1, "the reference's opaque signature");
    PKCS7_free(p7);
    p7 = smime_read("reference enveloped", REF_ENV, NULL);
    check(p7 != NULL && decrypt("reference", p7, rcpt_key, rcpt) == 1, "the reference's enveloped message");
    PKCS7_free(p7);

    /* In a library context, and the generic functions */
    {
        OSSL_LIB_CTX *lc = OSSL_LIB_CTX_new();
        PKCS7 *held = PKCS7_new_ex(lc, NULL), *got;
        BIO *b = mem(REF_OPAQUE);
        ASN1_VALUE *v;

        got = SMIME_read_PKCS7_ex(b, NULL, &held);
        printf("# read_ex into an object: %s, same %d\n", got == NULL ? "NULL" : "read", got == held);
        errors();
        check(got != NULL && verify("read_ex", got, st, NULL, 0) == 1, "SMIME_read_PKCS7_ex");
        BIO_free(b);
        b = mem(REF_MULTI);
        bcont = NULL;
        v = SMIME_read_ASN1_ex(b, 0, &bcont, ASN1_ITEM_rptr(PKCS7), NULL, lc, NULL);
        printf("# SMIME_read_ASN1_ex: %s, content %s\n", v == NULL ? "NULL" : "read", bcont == NULL ? "none" : "set");
        errors();
        BIO_free(b);
        out = BIO_new(BIO_s_mem());
        printf("# i2d_ASN1_bio_stream, stored: %d\n", i2d_ASN1_bio_stream(out, v, NULL, 0, ASN1_ITEM_rptr(PKCS7)));
        digest("DER", out);
        BIO_free(out);
        check(v != NULL && verify("read_ASN1_ex", (PKCS7 *)v, st, bcont, 0) == 1, "SMIME_read_ASN1_ex");
        PKCS7_free((PKCS7 *)v);
        BIO_free(bcont);
        PKCS7_free(got);
        OSSL_LIB_CTX_free(lc);
    }

    /* Malformed messages */
    {
        static const char *const bad[][2] = {
            {"no headers", "\n\nMIIB"},
            {"no content type", "Subject: x\n\nMIIB"},
            {"text", "Content-Type: text/plain\n\nhello"},
            {"no boundary", "Content-Type: multipart/signed\n\n"},
            {"one part", "Content-Type: multipart/signed; boundary=\"b\"\n\n--b\nhello\n--b--\n"},
            {"no closing boundary", "Content-Type: multipart/signed; boundary=\"b\"\n\n--b\nhello\n--b\nx\n"},
            {"three parts", "Content-Type: multipart/signed; boundary=\"b\"\n\n--b\na\n--b\nb\n--b\nc\n--b--\n"},
            {"no signature type", "Content-Type: multipart/signed; boundary=\"b\"\n\n--b\nhello\n--b\nX: y\n\nMIIB\n--b--\n"},
            {"a wrong signature type",
             "Content-Type: multipart/signed; boundary=\"b\"\n\n--b\nhello\n--b\nContent-Type: text/plain\n\nMIIB\n--b--\n"},
            {"a bad signature",
             "Content-Type: multipart/signed; boundary=\"b\"\n\n--b\nhello\n--b\nContent-Type: application/pkcs7-signature\n\n!!!!\n--b--\n"},
            {"bad base64", "Content-Type: application/pkcs7-mime\n\n!!!!\n"},
            {"empty", ""},
        };
        size_t i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            bcont = NULL;
            p7 = smime_read(bad[i][0], bad[i][1], &bcont);
            PKCS7_free(p7);
            BIO_free(bcont);
        }
        check(1, "malformed messages are refused");
    }

    X509_STORE_free(st);
    X509_free(root);
    X509_free(rsa);
    X509_free(rcpt);
    EVP_PKEY_free(rsa_key);
    EVP_PKEY_free(rcpt_key);
    free(big);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
