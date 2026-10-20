/*
 * Conformance test for CMS SignedData and ESS (CMS_sign(3), CMS_add1_signer(3),
 * CMS_SignerInfo_sign(3), CMS_verify(3), CMS_SignerInfo_verify, CMS_SignerInfo_verify_content,
 * CMS_get0_signers, CMS_set1_signers_certs, CMS_sign_receipt(3), CMS_verify_receipt(3),
 * CMS_add_standard_smimecap, CMS_final_digest, CMS_SignedData_verify, and ESS's
 * OSSL_ESS_signing_cert_new_init, OSSL_ESS_signing_cert_v2_new_init, and
 * OSSL_ESS_check_signing_certs): the reference tool's signatures (RSA, RSA-PSS, EC with CAdES,
 * Ed25519, by key identifier, detached) verified with each flag; signatures made here
 * round-tripped; receipts; tampered, untrusted, and mismatched inputs refused. Outputs with
 * a signing time or an ECDSA or PSS signature are checked, not printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/ess.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

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
 * Made with the reference's openssl tool: an EC root; RSA, EC, Ed25519, and RSA-PSS signers
 * and an RSA recipient, each for emailProtection; cms -sign -nodetach (RSA), -sign -binary
 * (RSA, detached), -sign -cades (EC), -sign -md sha512 (Ed25519), -sign (RSA-PSS key), -sign
 * -keyopt rsa_padding_mode:pss (RSA), and -sign -keyid (RSA).
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

static const char ED_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBbjCCARWgAwIBAgICAM8wCgYIKoZIzj0EAwIwJzEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTETMBEGA1UEAwwKU01JTUUgUm9vdDAgFw0yNjEwMTgwMDExMDlaGA8yMTI2MDky\n"
    "NDAwMTEwOVowEzERMA8GA1UEAwwIU01JTUUgZWQwKjAFBgMrZXADIQDNYaOTJ0e6\n"
    "ADMCqXOudbbz6U2f+G8rp6zdBJ25Wn2jrqNyMHAwCQYDVR0TBAIwADAOBgNVHQ8B\n"
    "Af8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwQwHQYDVR0OBBYEFG1pOkeVDJ9R\n"
    "xfKMDh429qiIjiYWMB8GA1UdIwQYMBaAFHW101B521S0OKWXAyFbAPAdaKBFMAoG\n"
    "CCqGSM49BAMCA0cAMEQCIF2WV45+mwK+DwJjgpJKzkwyWpyxJ3pgEzcjYaM6WKo5\n"
    "AiBBkzoTUbwSdiUQhKONAGzZD4/6QXXhzBEH9Y9XNR2amA==\n"
    "-----END CERTIFICATE-----\n";

static const char PSS_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICZzCCAg6gAwIBAgICANAwCgYIKoZIzj0EAwIwJzEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTETMBEGA1UEAwwKU01JTUUgUm9vdDAgFw0yNjEwMTgwMDExMDlaGA8yMTI2MDky\n"
    "NDAwMTEwOVowFDESMBAGA1UEAwwJU01JTUUgcHNzMIIBIDALBgkqhkiG9w0BAQoD\n"
    "ggEPADCCAQoCggEBAJ7lYbKSvecIAZ5nB17aVE4bBWxEiTvRYgLBJJ7Z7a3MgRzM\n"
    "lfLo2ZB3GH8Tp3WcSxPCwrjUQByZaQDPXbeYGFoN2R4ih01UmzxUmUwtFABIDJxG\n"
    "goaYrCFrXQnsdg4Z7x6X9ruH1GAkKpbVaow/U3SJHZ+C5d6Gq+6xbv8V/0zL65pX\n"
    "xvknapsJaszJbMIZwEjn7vmmcgIpKb3ekYu/at0JSSeOSA19LJY4GDfE9+54VbKf\n"
    "SwfhQb2ggvd0B9PHGk55VGY5Q09IGqIJj0qBT3p/PHa5n6Jp0LC68nHrKM6hiqqP\n"
    "6XqKQafvfWsVdLt/+G+2V9UlrZJmXXdbBacI//cCAwEAAaNyMHAwCQYDVR0TBAIw\n"
    "ADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwQwHQYDVR0OBBYE\n"
    "FMTfFOmZKwQmApR6o/OC3dTvIA0oMB8GA1UdIwQYMBaAFHW101B521S0OKWXAyFb\n"
    "APAdaKBFMAoGCCqGSM49BAMCA0cAMEQCIEASruKqZOG1OCLC/e6AEalvva304mV2\n"
    "gwcEE9X45xMnAiByH0JowVT+gU1nuv2K0et5cYGph/J8BjdzUSA/cyp3pw==\n"
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

static const char ED_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIF162xHXtCoLIEfb7ajZQDENRx8c5aU8qW55u5r8ejQe\n"
    "-----END PRIVATE KEY-----\n";

static const char PSS_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEuwIBADALBgkqhkiG9w0BAQoEggSnMIIEowIBAAKCAQEAnuVhspK95wgBnmcH\n"
    "XtpUThsFbESJO9FiAsEkntntrcyBHMyV8ujZkHcYfxOndZxLE8LCuNRAHJlpAM9d\n"
    "t5gYWg3ZHiKHTVSbPFSZTC0UAEgMnEaChpisIWtdCex2DhnvHpf2u4fUYCQqltVq\n"
    "jD9TdIkdn4Ll3oar7rFu/xX/TMvrmlfG+SdqmwlqzMlswhnASOfu+aZyAikpvd6R\n"
    "i79q3QlJJ45IDX0sljgYN8T37nhVsp9LB+FBvaCC93QH08caTnlUZjlDT0gaogmP\n"
    "SoFPen88drmfomnQsLrycesozqGKqo/peopBp+99axV0u3/4b7ZX1SWtkmZdd1sF\n"
    "pwj/9wIDAQABAoIBADts0hL06mzDA8f4BDunL6xeUrLhFun2Ls+U6Fs4abl8KDVb\n"
    "FiFYkDWFNPYhpZlIsJNdXXG+f5OylCCnbQdCrKjRUQgCJdP39m6jvQlOOpK4X276\n"
    "t8oawxVkj9EsTCKN9G3eq3oLHJQwMnVir4xwCogk151WWR3WA+srFLX1xhsz+a+a\n"
    "90CHwmqWCBAszOSf/y2E35sDyEYsHR4iZNTKwwjGJ/eX4pjz4lagpxPKS0xx7h6+\n"
    "tpzI/0k8xT67XDDfD2r/vcb0Sk6S5dWxgb8Ys5kH17etSPagosPcEt635NNkHRwd\n"
    "CGuiD8UlKtxs+wdnrHc7EdNqzMys2/y9TrySxHECgYEAzcYMGLabNyhIbxtFDD1h\n"
    "sq0Dv/c54uTpz2kfegaGCPdYn6Jym4usFjxOsu1F8SKddVzOcIY3nx+DyFjtjhNu\n"
    "WqXT9jB/GT5am6NjaaAYfcbfMWZjkfZicsZ/tdPfLMhI9EzBQATIVSvSmexkcdyQ\n"
    "cMCYRAB0OHh3uGXYnoPc9zUCgYEAxa4lDBRkcED4Opw4xFrjlrt0adXU3g5Otsj6\n"
    "+MeYGM9YyyI4FNyo7KEybZ8K1AGh56kNMF4Hgve6MEC5tS3raQzx5hafRDXuY9pp\n"
    "qD08kW17+vEzTr5VBOu6ByyGkYRct97nCMrbJL+Tb6V2wZu0xPbV9MNei4VpcmUT\n"
    "EVMpA/sCgYB2VUXvkFOCTLAa9NuoRkRAtC5L3qhzSqEKnbF0Qvwhe9yDMLAnsxKr\n"
    "VtMLIlfua7GRJGWzX/vsjfsC4+D4q0Py7RoPoaP1qF4C0tsAiwiKjCseBXuNHNtQ\n"
    "lcYrkkPtROBvXRRk9FsgX6skyUSaFfUaYicuM/Sh5OU0LZ18yufvYQKBgHUEmGOl\n"
    "MquMmiS/047QqsbQoqH/9amZWJk1MfPQ20VcgJiG4iHfWZPx/FMOAa/sY3YqCWen\n"
    "UdUCZlIoDoak7yTZh9yHabJMJpkvcronvdHsuKac351uaA+opw+WGPbNHsGtjqAS\n"
    "zVTcnx9JGJqVXJX39EGW4UHAMOKJ2Ja53p6/AoGBAJNY9rIIgyUZtGQGRyeY+UX/\n"
    "WWya7hh804Xs/r0DF2vHcvISNkfang8b8oHaCroYv5ZQe13WyE58r4jVfz/2vTfu\n"
    "AsUuwmn2SZMkMe4Pz+ZjPUcGITwSMwR7hVCNVxnd5Eapn4h5JBVGAiBZrwHcvswZ\n"
    "nUiY9qr/ycWV2rQdR85d\n"
    "-----END PRIVATE KEY-----\n";

static const char REF_SIGNED[] =
    "-----BEGIN CMS-----\n"
    "MIIFDAYJKoZIhvcNAQcCoIIE/TCCBPkCAQExDTALBglghkgBZQMEAgEwNAYJKoZI\n"
    "hvcNAQcBoCcEJUhlbGxvLCBTL01JTUUuDQpTZWNvbmQgbGluZSAgDQoNCmxhc3Sg\n"
    "ggJtMIICaTCCAg+gAwIBAgIBZTAKBggqhkjOPQQDAjAnMRAwDgYDVQQKDAdFeGFt\n"
    "cGxlMRMwEQYDVQQDDApTTUlNRSBSb290MCAXDTI2MTAxNzIyMTcxNVoYDzIxMjYw\n"
    "OTIzMjIxNzE1WjAUMRIwEAYDVQQDDAlTTUlNRSByc2EwggEiMA0GCSqGSIb3DQEB\n"
    "AQUAA4IBDwAwggEKAoIBAQCTF3DR1lrRhjc9u1jEVzgYclC+L3X6x88IGgzCdKPa\n"
    "NwhLQlWsDXmluMlqa0Tvb4Ob392Ufxmkn1W30XhYTypLjGOL5bksoiGDiQZn1ovA\n"
    "/GndmCq1J47pSNhz6SL1/uOZvmj6vdpr0p26BtqGCr1hXowWKIvmJGdr5JV4fPgR\n"
    "XO/nFCqYvwzm0hxCCWF+cpACJgB/NkB54nSqeYdRhwJvU9D8glmTuwO4UY035FDY\n"
    "cYKajiIMtnJnGlo/IJMEyI1+lQGWWFOSCPhld5B3etvb8Yz+LC51w4jlroXJw7q1\n"
    "HmTGi2IR4fugKC8lLugmbONeFXjeCawPRVhZPR2/1AHNAgMBAAGjcjBwMAkGA1Ud\n"
    "EwQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMEMB0GA1Ud\n"
    "DgQWBBQTEOssjmFffw9DHdfYXG+4qmqEvDAfBgNVHSMEGDAWgBR1tdNQedtUtDil\n"
    "lwMhWwDwHWigRTAKBggqhkjOPQQDAgNIADBFAiAJ6N2sNNdSNa+IDpskcT9WoVcN\n"
    "F5gKYOWbDzbJFIJTZQIhAOTlwtgT1PhcURW6WGxpnKHrkg8l+RbzadUEJJAksG/w\n"
    "MYICPDCCAjgCAQEwLDAnMRAwDgYDVQQKDAdFeGFtcGxlMRMwEQYDVQQDDApTTUlN\n"
    "RSBSb290AgFlMAsGCWCGSAFlAwQCAaCB5DAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN\n"
    "AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjEwMTgwMDExMDlaMC8GCSqGSIb3DQEJBDEi\n"
    "BCA+c+poW/0nsXU6Hh10kKDSnZk++amUAvJbRkQM7jyllDB5BgkqhkiG9w0BCQ8x\n"
    "bDBqMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqG\n"
    "SIb3DQMHMA4GCCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzAN\n"
    "BggqhkiG9w0DAgIBKDANBgkqhkiG9w0BAQEFAASCAQAOMIZnIQdf3nTJGeyEzzr4\n"
    "/9aznikMKHMItoooEuNCMmSZlJ5Ua8E2HnmWDabaTEsdoCVM/Oz3wZQdObdEDj/D\n"
    "dSVbtr0/25wAYEGVFU3PVxbKTCq6XpkkBbwCkOSB+TNIu7lFgORb+LqA5osVE2r+\n"
    "ZxPA1xiyWZth9VLCYK9g4q+9SNlSoBtlsVjrHjsOsIpJDNF+TNlKbMaGGh7pDgcd\n"
    "ndpJDeo2dQPnB6yQceAoSbXtNjYQTLj0lxpkZU7uMdvvgnmmeINTEtdJjZcWu1mT\n"
    "yMv2ZNWSe5AYRL8rAcHRcvGgv3SmtmXtcHtROtyy7rLdmZOcpn/1nKgjis+twzpt\n"
    "-----END CMS-----\n";

static const char REF_DETACHED[] =
    "-----BEGIN CMS-----\n"
    "MIIE4wYJKoZIhvcNAQcCoIIE1DCCBNACAQExDTALBglghkgBZQMEAgEwCwYJKoZI\n"
    "hvcNAQcBoIICbTCCAmkwggIPoAMCAQICAWUwCgYIKoZIzj0EAwIwJzEQMA4GA1UE\n"
    "CgwHRXhhbXBsZTETMBEGA1UEAwwKU01JTUUgUm9vdDAgFw0yNjEwMTcyMjE3MTVa\n"
    "GA8yMTI2MDkyMzIyMTcxNVowFDESMBAGA1UEAwwJU01JTUUgcnNhMIIBIjANBgkq\n"
    "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkxdw0dZa0YY3PbtYxFc4GHJQvi91+sfP\n"
    "CBoMwnSj2jcIS0JVrA15pbjJamtE72+Dm9/dlH8ZpJ9Vt9F4WE8qS4xji+W5LKIh\n"
    "g4kGZ9aLwPxp3ZgqtSeO6UjYc+ki9f7jmb5o+r3aa9Kdugbahgq9YV6MFiiL5iRn\n"
    "a+SVeHz4EVzv5xQqmL8M5tIcQglhfnKQAiYAfzZAeeJ0qnmHUYcCb1PQ/IJZk7sD\n"
    "uFGNN+RQ2HGCmo4iDLZyZxpaPyCTBMiNfpUBllhTkgj4ZXeQd3rb2/GM/iwudcOI\n"
    "5a6FycO6tR5kxotiEeH7oCgvJS7oJmzjXhV43gmsD0VYWT0dv9QBzQIDAQABo3Iw\n"
    "cDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcD\n"
    "BDAdBgNVHQ4EFgQUExDrLI5hX38PQx3X2FxvuKpqhLwwHwYDVR0jBBgwFoAUdbXT\n"
    "UHnbVLQ4pZcDIVsA8B1ooEUwCgYIKoZIzj0EAwIDSAAwRQIgCejdrDTXUjWviA6b\n"
    "JHE/VqFXDReYCmDlmw82yRSCU2UCIQDk5cLYE9T4XFEVulhsaZyh65IPJfkW82nV\n"
    "BCSQJLBv8DGCAjwwggI4AgEBMCwwJzEQMA4GA1UECgwHRXhhbXBsZTETMBEGA1UE\n"
    "AwwKU01JTUUgUm9vdAIBZTALBglghkgBZQMEAgGggeQwGAYJKoZIhvcNAQkDMQsG\n"
    "CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMDE4MDAxMTA5WjAvBgkqhkiG\n"
    "9w0BCQQxIgQgNUox/Fcr3q4C62f7ZTzLH92xgK79vj7dQR0wYAgBoCgweQYJKoZI\n"
    "hvcNAQkPMWwwajALBglghkgBZQMEASowCwYJYIZIAWUDBAEWMAsGCWCGSAFlAwQB\n"
    "AjAKBggqhkiG9w0DBzAOBggqhkiG9w0DAgICAIAwDQYIKoZIhvcNAwICAUAwBwYF\n"
    "Kw4DAgcwDQYIKoZIhvcNAwICASgwDQYJKoZIhvcNAQEBBQAEggEAfqDgVzgNFnqa\n"
    "cWQhRgq2WFraYPBmKebSzZZdAXdfSniVyhk58rd+IODRuKJ1ytKGX94JVs2tIVta\n"
    "rX4pCNdNaJ+CVMKb94wP6MwUQBLT8mMd0jHQtVdOJMA9I1mP70XYbsOW3pquA1c1\n"
    "WVu6VL6LRmvqF5BZJRFi58HB8M6UR31tDBXrG09C+JDulOgfgTMemxJYJTOqErxs\n"
    "3grc+WzwnYstsv1CHNj4F7Xl8gbY8dSwDUiODS30azIQ/9WNgESOZAIX3uO7SxGI\n"
    "kTWtlQ7pznMP6knYLwpvQNLig6sn1SJNmwCEMySUmsM7MKj3K7xPK0Dj/uuDwKoo\n"
    "pfHnwIvt9Q==\n"
    "-----END CMS-----\n";

static const char REF_CADES[] =
    "-----BEGIN CMS-----\n"
    "MIID8AYJKoZIhvcNAQcCoIID4TCCA90CAQExDTALBglghkgBZQMEAgEwNAYJKoZI\n"
    "hvcNAQcBoCcEJUhlbGxvLCBTL01JTUUuDQpTZWNvbmQgbGluZSAgDQoNCmxhc3Sg\n"
    "ggGiMIIBnjCCAUOgAwIBAgIBZjAKBggqhkjOPQQDAjAnMRAwDgYDVQQKDAdFeGFt\n"
    "cGxlMRMwEQYDVQQDDApTTUlNRSBSb290MCAXDTI2MTAxNzIyMTcxNVoYDzIxMjYw\n"
    "OTIzMjIxNzE1WjATMREwDwYDVQQDDAhTTUlNRSBlYzBZMBMGByqGSM49AgEGCCqG\n"
    "SM49AwEHA0IABE+ed2YYrTPKzTSCIfsz5t548VhtIiTcxkrDi7n3iq20eXeG5NOk\n"
    "C0YvsS1rZ/TNRNNq6rPCmC/bSC2CFtqfzm6jcjBwMAkGA1UdEwQCMAAwDgYDVR0P\n"
    "AQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMEMB0GA1UdDgQWBBSqGg/MBRxH\n"
    "dgSmueMVbCKkKfm/4jAfBgNVHSMEGDAWgBR1tdNQedtUtDillwMhWwDwHWigRTAK\n"
    "BggqhkjOPQQDAgNJADBGAiEA0bvNOSAuB7pUozWvrzw0azVBYOLKz7v6vtcTjpQi\n"
    "KjwCIQC7MYUejEbSuuJfSioTRaf7Q94Qcl9HUBtIQM+At5vMdzGCAeswggHnAgEB\n"
    "MCwwJzEQMA4GA1UECgwHRXhhbXBsZTETMBEGA1UEAwwKU01JTUUgUm9vdAIBZjAL\n"
    "BglghkgBZQMEAgGgggFPMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZI\n"
    "hvcNAQkFMQ8XDTI2MTAxODAwMTEwOVowLwYJKoZIhvcNAQkEMSIEID5z6mhb/Sex\n"
    "dToeHXSQoNKdmT75qZQC8ltGRAzuPKWUMGkGCyqGSIb3DQEJEAIvMVowWDBWMFQE\n"
    "ICQq+M8W/3R4dY24Pip98vDsxS+9sisie/SrxIxKFvYpMDAwK6QpMCcxEDAOBgNV\n"
    "BAoMB0V4YW1wbGUxEzARBgNVBAMMClNNSU1FIFJvb3QCAWYweQYJKoZIhvcNAQkP\n"
    "MWwwajALBglghkgBZQMEASowCwYJYIZIAWUDBAEWMAsGCWCGSAFlAwQBAjAKBggq\n"
    "hkiG9w0DBzAOBggqhkiG9w0DAgICAIAwDQYIKoZIhvcNAwICAUAwBwYFKw4DAgcw\n"
    "DQYIKoZIhvcNAwICASgwCgYIKoZIzj0EAwIESDBGAiEAkg8b685bJFqx7m4GnpQW\n"
    "x1fK3kUr+sTKIWaV97klPcwCIQDO3QDCz/fzug3KVc8RyyVna+JAKKN0gnFkkgrl\n"
    "VG9Feg==\n"
    "-----END CMS-----\n";

static const char REF_ED[] =
    "-----BEGIN CMS-----\n"
    "MIIDaQYJKoZIhvcNAQcCoIIDWjCCA1YCAQExDTALBglghkgBZQMEAgMwNAYJKoZI\n"
    "hvcNAQcBoCcEJUhlbGxvLCBTL01JTUUuDQpTZWNvbmQgbGluZSAgDQoNCmxhc3Sg\n"
    "ggFyMIIBbjCCARWgAwIBAgICAM8wCgYIKoZIzj0EAwIwJzEQMA4GA1UECgwHRXhh\n"
    "bXBsZTETMBEGA1UEAwwKU01JTUUgUm9vdDAgFw0yNjEwMTgwMDExMDlaGA8yMTI2\n"
    "MDkyNDAwMTEwOVowEzERMA8GA1UEAwwIU01JTUUgZWQwKjAFBgMrZXADIQDNYaOT\n"
    "J0e6ADMCqXOudbbz6U2f+G8rp6zdBJ25Wn2jrqNyMHAwCQYDVR0TBAIwADAOBgNV\n"
    "HQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwQwHQYDVR0OBBYEFG1pOkeV\n"
    "DJ9RxfKMDh429qiIjiYWMB8GA1UdIwQYMBaAFHW101B521S0OKWXAyFbAPAdaKBF\n"
    "MAoGCCqGSM49BAMCA0cAMEQCIF2WV45+mwK+DwJjgpJKzkwyWpyxJ3pgEzcjYaM6\n"
    "WKo5AiBBkzoTUbwSdiUQhKONAGzZD4/6QXXhzBEH9Y9XNR2amDGCAZQwggGQAgEB\n"
    "MC0wJzEQMA4GA1UECgwHRXhhbXBsZTETMBEGA1UEAwwKU01JTUUgUm9vdAICAM8w\n"
    "CwYJYIZIAWUDBAIDoIIBBDAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqG\n"
    "SIb3DQEJBTEPFw0yNjEwMTgwMDExMjBaME8GCSqGSIb3DQEJBDFCBEDVE/zTDhb2\n"
    "SeLUcyh5PFwgW268pWdjIp84265ngXDluqXfufy2LX2nMbfGafBjFXR+9uIR3s0g\n"
    "qbbIDmopzdAMMHkGCSqGSIb3DQEJDzFsMGowCwYJYIZIAWUDBAEqMAsGCWCGSAFl\n"
    "AwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwDgYIKoZIhvcNAwICAgCAMA0G\n"
    "CCqGSIb3DQMCAgFAMAcGBSsOAwIHMA0GCCqGSIb3DQMCAgEoMAUGAytlcARA4QhJ\n"
    "0WsfW6BfuvH/pXCn1uLVNrtUmfjVZ9D0mHNuMrWyph8F/lo3i+rQlfQNl7L9WlO5\n"
    "CDe+pJGZBr4FF4dNCQ==\n"
    "-----END CMS-----\n";

static const char REF_PSS[] =
    "-----BEGIN CMS-----\n"
    "MIIFCwYJKoZIhvcNAQcCoIIE/DCCBPgCAQExDTALBglghkgBZQMEAgEwNAYJKoZI\n"
    "hvcNAQcBoCcEJUhlbGxvLCBTL01JTUUuDQpTZWNvbmQgbGluZSAgDQoNCmxhc3Sg\n"
    "ggJrMIICZzCCAg6gAwIBAgICANAwCgYIKoZIzj0EAwIwJzEQMA4GA1UECgwHRXhh\n"
    "bXBsZTETMBEGA1UEAwwKU01JTUUgUm9vdDAgFw0yNjEwMTgwMDExMDlaGA8yMTI2\n"
    "MDkyNDAwMTEwOVowFDESMBAGA1UEAwwJU01JTUUgcHNzMIIBIDALBgkqhkiG9w0B\n"
    "AQoDggEPADCCAQoCggEBAJ7lYbKSvecIAZ5nB17aVE4bBWxEiTvRYgLBJJ7Z7a3M\n"
    "gRzMlfLo2ZB3GH8Tp3WcSxPCwrjUQByZaQDPXbeYGFoN2R4ih01UmzxUmUwtFABI\n"
    "DJxGgoaYrCFrXQnsdg4Z7x6X9ruH1GAkKpbVaow/U3SJHZ+C5d6Gq+6xbv8V/0zL\n"
    "65pXxvknapsJaszJbMIZwEjn7vmmcgIpKb3ekYu/at0JSSeOSA19LJY4GDfE9+54\n"
    "VbKfSwfhQb2ggvd0B9PHGk55VGY5Q09IGqIJj0qBT3p/PHa5n6Jp0LC68nHrKM6h\n"
    "iqqP6XqKQafvfWsVdLt/+G+2V9UlrZJmXXdbBacI//cCAwEAAaNyMHAwCQYDVR0T\n"
    "BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwQwHQYDVR0O\n"
    "BBYEFMTfFOmZKwQmApR6o/OC3dTvIA0oMB8GA1UdIwQYMBaAFHW101B521S0OKWX\n"
    "AyFbAPAdaKBFMAoGCCqGSM49BAMCA0cAMEQCIEASruKqZOG1OCLC/e6AEalvva30\n"
    "4mV2gwcEE9X45xMnAiByH0JowVT+gU1nuv2K0et5cYGph/J8BjdzUSA/cyp3pzGC\n"
    "Aj0wggI5AgEBMC0wJzEQMA4GA1UECgwHRXhhbXBsZTETMBEGA1UEAwwKU01JTUUg\n"
    "Um9vdAICANAwCwYJYIZIAWUDBAIBoIHkMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B\n"
    "BwEwHAYJKoZIhvcNAQkFMQ8XDTI2MTAxODAwMTEyMFowLwYJKoZIhvcNAQkEMSIE\n"
    "ID5z6mhb/SexdToeHXSQoNKdmT75qZQC8ltGRAzuPKWUMHkGCSqGSIb3DQEJDzFs\n"
    "MGowCwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZI\n"
    "hvcNAwcwDgYIKoZIhvcNAwICAgCAMA0GCCqGSIb3DQMCAgFAMAcGBSsOAwIHMA0G\n"
    "CCqGSIb3DQMCAgEoMA0GCSqGSIb3DQEBAQUABIIBAA9E1lTmwNafg54stF+dDLcA\n"
    "Pnsmmhxt1FhmA7zMRq5QG5sc8gfvi7hUBrqnkfxi9R5PbqZWfUFpV0IIKDuqmirH\n"
    "FXg1caME62mY2PVA9EhqwmjAoY1zZwJmMezWYZ/NBxqVEomSt88yxRwZREUVizxk\n"
    "8vNrmdiDZaRiW3dCwHX5nkmSc55+ljnIWKQlsj4ZbyA4LLmd/9MZ+fMX+MXFr4YS\n"
    "TSZzG5jb9bbeM0q9IDixacz8zdsy7BpjW31K9BpiQBPPXPWgI84mRKVjLGnQRfxW\n"
    "Ph7KAe5S4hgoqicSw4hB3tJregwbZ8ZkxecYhi7odZjevx4qq0sooOK4FEmfT4A=\n"
    "-----END CMS-----\n";

static const char REF_RSAPSS[] =
    "-----BEGIN CMS-----\n"
    "MIIFQAYJKoZIhvcNAQcCoIIFMTCCBS0CAQExDTALBglghkgBZQMEAgEwNAYJKoZI\n"
    "hvcNAQcBoCcEJUhlbGxvLCBTL01JTUUuDQpTZWNvbmQgbGluZSAgDQoNCmxhc3Sg\n"
    "ggJtMIICaTCCAg+gAwIBAgIBZTAKBggqhkjOPQQDAjAnMRAwDgYDVQQKDAdFeGFt\n"
    "cGxlMRMwEQYDVQQDDApTTUlNRSBSb290MCAXDTI2MTAxNzIyMTcxNVoYDzIxMjYw\n"
    "OTIzMjIxNzE1WjAUMRIwEAYDVQQDDAlTTUlNRSByc2EwggEiMA0GCSqGSIb3DQEB\n"
    "AQUAA4IBDwAwggEKAoIBAQCTF3DR1lrRhjc9u1jEVzgYclC+L3X6x88IGgzCdKPa\n"
    "NwhLQlWsDXmluMlqa0Tvb4Ob392Ufxmkn1W30XhYTypLjGOL5bksoiGDiQZn1ovA\n"
    "/GndmCq1J47pSNhz6SL1/uOZvmj6vdpr0p26BtqGCr1hXowWKIvmJGdr5JV4fPgR\n"
    "XO/nFCqYvwzm0hxCCWF+cpACJgB/NkB54nSqeYdRhwJvU9D8glmTuwO4UY035FDY\n"
    "cYKajiIMtnJnGlo/IJMEyI1+lQGWWFOSCPhld5B3etvb8Yz+LC51w4jlroXJw7q1\n"
    "HmTGi2IR4fugKC8lLugmbONeFXjeCawPRVhZPR2/1AHNAgMBAAGjcjBwMAkGA1Ud\n"
    "EwQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMEMB0GA1Ud\n"
    "DgQWBBQTEOssjmFffw9DHdfYXG+4qmqEvDAfBgNVHSMEGDAWgBR1tdNQedtUtDil\n"
    "lwMhWwDwHWigRTAKBggqhkjOPQQDAgNIADBFAiAJ6N2sNNdSNa+IDpskcT9WoVcN\n"
    "F5gKYOWbDzbJFIJTZQIhAOTlwtgT1PhcURW6WGxpnKHrkg8l+RbzadUEJJAksG/w\n"
    "MYICcDCCAmwCAQEwLDAnMRAwDgYDVQQKDAdFeGFtcGxlMRMwEQYDVQQDDApTTUlN\n"
    "RSBSb290AgFlMAsGCWCGSAFlAwQCAaCB5DAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN\n"
    "AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjEwMTgwMDExMjBaMC8GCSqGSIb3DQEJBDEi\n"
    "BCA+c+poW/0nsXU6Hh10kKDSnZk++amUAvJbRkQM7jyllDB5BgkqhkiG9w0BCQ8x\n"
    "bDBqMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqG\n"
    "SIb3DQMHMA4GCCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzAN\n"
    "BggqhkiG9w0DAgIBKDBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRww\n"
    "GgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAEggEAQKM+FUO7JYzxdDxW\n"
    "pISIxyrZGHflf8cniOCeXCbiH6hDDtKzTWsfLWy7GOs5lESiPEdD/Mx19siJVg4I\n"
    "BkYmIeyKzGsKSzU1h6LLJpjLukYR3oI/g786hcCvu4tlTeofCEM5LEmXN5D1AJwK\n"
    "6v8/PJFVw8JX9g1I6tp+M8xePhkODNCRYplEr2RRN3tURhhb/RDtY9UMXsSygrdG\n"
    "2Ru7X0vsM29jDO3ddLOqZetPNfgki6Ubt/gqw6goJIlYtaPhnMhE3UHBV+pQTOfG\n"
    "r/josin0idgp+yfDcKuxHMO32CWlmNDvdYVtND5d5NgCBT1MaDOISA/Z12sewbu7\n"
    "y5kXGg==\n"
    "-----END CMS-----\n";

static const char REF_KEYID[] =
    "-----BEGIN CMS-----\n"
    "MIIE9AYJKoZIhvcNAQcCoIIE5TCCBOECAQMxDTALBglghkgBZQMEAgEwNAYJKoZI\n"
    "hvcNAQcBoCcEJUhlbGxvLCBTL01JTUUuDQpTZWNvbmQgbGluZSAgDQoNCmxhc3Sg\n"
    "ggJtMIICaTCCAg+gAwIBAgIBZTAKBggqhkjOPQQDAjAnMRAwDgYDVQQKDAdFeGFt\n"
    "cGxlMRMwEQYDVQQDDApTTUlNRSBSb290MCAXDTI2MTAxNzIyMTcxNVoYDzIxMjYw\n"
    "OTIzMjIxNzE1WjAUMRIwEAYDVQQDDAlTTUlNRSByc2EwggEiMA0GCSqGSIb3DQEB\n"
    "AQUAA4IBDwAwggEKAoIBAQCTF3DR1lrRhjc9u1jEVzgYclC+L3X6x88IGgzCdKPa\n"
    "NwhLQlWsDXmluMlqa0Tvb4Ob392Ufxmkn1W30XhYTypLjGOL5bksoiGDiQZn1ovA\n"
    "/GndmCq1J47pSNhz6SL1/uOZvmj6vdpr0p26BtqGCr1hXowWKIvmJGdr5JV4fPgR\n"
    "XO/nFCqYvwzm0hxCCWF+cpACJgB/NkB54nSqeYdRhwJvU9D8glmTuwO4UY035FDY\n"
    "cYKajiIMtnJnGlo/IJMEyI1+lQGWWFOSCPhld5B3etvb8Yz+LC51w4jlroXJw7q1\n"
    "HmTGi2IR4fugKC8lLugmbONeFXjeCawPRVhZPR2/1AHNAgMBAAGjcjBwMAkGA1Ud\n"
    "EwQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMEMB0GA1Ud\n"
    "DgQWBBQTEOssjmFffw9DHdfYXG+4qmqEvDAfBgNVHSMEGDAWgBR1tdNQedtUtDil\n"
    "lwMhWwDwHWigRTAKBggqhkjOPQQDAgNIADBFAiAJ6N2sNNdSNa+IDpskcT9WoVcN\n"
    "F5gKYOWbDzbJFIJTZQIhAOTlwtgT1PhcURW6WGxpnKHrkg8l+RbzadUEJJAksG/w\n"
    "MYICJDCCAiACAQOAFBMQ6yyOYV9/D0Md19hcb7iqaoS8MAsGCWCGSAFlAwQCAaCB\n"
    "5DAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjEw\n"
    "MTgwMDExMjBaMC8GCSqGSIb3DQEJBDEiBCA+c+poW/0nsXU6Hh10kKDSnZk++amU\n"
    "AvJbRkQM7jyllDB5BgkqhkiG9w0BCQ8xbDBqMAsGCWCGSAFlAwQBKjALBglghkgB\n"
    "ZQMEARYwCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMHMA4GCCqGSIb3DQMCAgIAgDAN\n"
    "BggqhkiG9w0DAgIBQDAHBgUrDgMCBzANBggqhkiG9w0DAgIBKDANBgkqhkiG9w0B\n"
    "AQEFAASCAQBhQIAvGQHnFsy4SVG2s8h14z1QbC67rEtdjElT90kAwm0xsaaINv5b\n"
    "e9FdaZQZlLMMkju7v65o4YZwHs2Fs67ImHYjMfdpCYXV07CN7eeF+fPpwCiDbTpU\n"
    "1NKgn6UmodW+9qZ2RbACZpUyfMk7HQ39rSRLNJpXHUaDvkMtKs1SlpeDAF1B3iZ8\n"
    "wq1ESUEFzyuFaQIBMe7rTyAa6J9tzTucs0y11NOvehL+IgMcyuebWuuj1TpyEk88\n"
    "M18DsfDGNnOq+Vya5lUdF6S39gldmTuUpC9grphSuwSdBhLLFN7T1vGFbUH6zfPy\n"
    "q0vHx7vjzeQ1Og+5qTvj+Rm0rXpoC3RC\n"
    "-----END CMS-----\n";
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

static CMS_ContentInfo *load(const char *pem)
{
    BIO *b = mem(pem);
    CMS_ContentInfo *cms = PEM_read_bio_CMS(b, NULL, NULL, NULL);

    BIO_free(b);
    return cms;
}

static void hex(const char *label, const unsigned char *p, int n)
{
    int i;

    printf("  %s (%d):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 ? "\n    " : "", p[i]);
    printf("\n");
}

static void fingerprint(const char *label, CMS_ContentInfo *cms)
{
    unsigned char *d = NULL, md[32];
    unsigned int mdlen = 0;
    int n = i2d_CMS_ContentInfo(cms, &d);

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

static void show_signers(CMS_ContentInfo *cms)
{
    STACK_OF(CMS_SignerInfo) *sis = CMS_get0_SignerInfos(cms);
    int i, j;

    printf("  signers %d\n", sk_CMS_SignerInfo_num(sis));
    for (i = 0; i < sk_CMS_SignerInfo_num(sis); i++) {
        CMS_SignerInfo *si = sk_CMS_SignerInfo_value(sis, i);
        X509_ALGOR *dig, *sig;
        EVP_PKEY *pk;
        X509 *signer;
        ASN1_OCTET_STRING *keyid = NULL;
        X509_NAME *issuer = NULL;
        ASN1_INTEGER *sno = NULL;
        ASN1_OCTET_STRING *s = CMS_SignerInfo_get0_signature(si);

        CMS_SignerInfo_get0_algs(si, &pk, &signer, &dig, &sig);
        printf("  %d: digest %s, signature %s, key %s, signer %s\n", i, oid(dig->algorithm), oid(sig->algorithm),
               pk == NULL ? "none" : "set", signer == NULL ? "none" : "set");
        printf("    id %d:", CMS_SignerInfo_get0_signer_id(si, &keyid, &issuer, &sno));
        if (keyid != NULL)
            printf(" key id %d octets", ASN1_STRING_length(keyid));
        if (sno != NULL)
            printf(" serial %ld", ASN1_INTEGER_get(sno));
        printf("\n    signed attributes %d:", CMS_signed_get_attr_count(si));
        for (j = 0; j < CMS_signed_get_attr_count(si); j++)
            printf(" %s", oid(X509_ATTRIBUTE_get0_object(CMS_signed_get_attr(si, j))));
        printf("\n    signature %s\n", s == NULL ? "none" : ASN1_STRING_length(s) >= 256 ? "256+" : ASN1_STRING_length(s) > 0 ? "short" : "empty");
    }
}

static int verify(const char *label, CMS_ContentInfo *cms, STACK_OF(X509) *certs, X509_STORE *st, BIO *dcont, unsigned int flags)
{
    BIO *out = BIO_new(BIO_s_mem());
    int r = CMS_verify(cms, certs, st, dcont, out, flags);
    char *p;
    long n = BIO_get_mem_data(out, &p);

    printf("# verify %s: %d, content %ld octets\n", label, r, n);
    errors();
    BIO_free(out);
    return r;
}

int main(void)
{
    X509 *root = cert(CA_PEM), *rsa = cert(RSA_PEM), *ec = cert(EC_PEM), *ed = cert(ED_PEM), *pss = cert(PSS_PEM),
         *rcpt = cert(RCPT_PEM);
    EVP_PKEY *rsa_key = key(RSA_KEY_PEM), *ec_key = key(EC_KEY_PEM), *ed_key = key(ED_KEY_PEM), *pss_key = key(PSS_KEY_PEM);
    X509_STORE *st = X509_STORE_new(), *empty = X509_STORE_new();
    STACK_OF(X509) *chain = sk_X509_new_null();
    CMS_ContentInfo *cms;
    BIO *in;

    setvbuf(stdout, NULL, _IONBF, 0);
    X509_STORE_add_cert(st, root);
    sk_X509_push(chain, rsa);
    sk_X509_push(chain, root);
    check(root && rsa && ec && ed && pss && rcpt && rsa_key && ec_key && ed_key && pss_key, "fixtures");

    /* ESS */
    {
        ESS_SIGNING_CERT *sc = OSSL_ESS_signing_cert_new_init(rsa, NULL, 1), *sc2;
        ESS_SIGNING_CERT_V2 *v2 = OSSL_ESS_signing_cert_v2_new_init(EVP_sha256(), rsa, chain, 1), *v2b;
        ESS_SIGNING_CERT_V2 *v384 = OSSL_ESS_signing_cert_v2_new_init(EVP_sha384(), rsa, NULL, 0);
        STACK_OF(X509) *wrong = sk_X509_new_null(), *missing = sk_X509_new_null();
        unsigned char *d = NULL;
        const unsigned char *q;
        int n;

        n = i2d_ESS_SIGNING_CERT(sc, &d);
        hex("SigningCertificate", d, n);
        q = d;
        sc2 = d2i_ESS_SIGNING_CERT(NULL, &q, n);
        printf("  decoded %s, dup %s\n", sc2 == NULL ? "NULL" : "yes", ESS_SIGNING_CERT_dup(sc2) == NULL ? "NULL" : "made");
        OPENSSL_free(d);
        d = NULL;
        n = i2d_ESS_SIGNING_CERT_V2(v2, &d);
        hex("SigningCertificateV2 (SHA-256, with the root)", d, n);
        q = d;
        v2b = d2i_ESS_SIGNING_CERT_V2(NULL, &q, n);
        printf("  decoded %s\n", v2b == NULL ? "NULL" : "yes");
        OPENSSL_free(d);
        d = NULL;
        n = i2d_ESS_SIGNING_CERT_V2(v384, &d);
        hex("SigningCertificateV2 (SHA-384)", d, n);
        OPENSSL_free(d);
        sk_X509_push(wrong, root);
        sk_X509_push(wrong, rsa);
        sk_X509_push(missing, ec);
        printf("# check: %d %d %d\n", OSSL_ESS_check_signing_certs(sc, NULL, chain, 1),
               OSSL_ESS_check_signing_certs(NULL, v2, chain, 1), OSSL_ESS_check_signing_certs(sc, v384, chain, 0));
        errors();
        printf("# check, wrong order: %d\n", OSSL_ESS_check_signing_certs(sc, NULL, wrong, 1));
        errors();
        printf("# check, missing: %d\n", OSSL_ESS_check_signing_certs(NULL, v2, missing, 1));
        errors();
        printf("# check, none: %d %d\n", OSSL_ESS_check_signing_certs(NULL, NULL, chain, 1),
               OSSL_ESS_check_signing_certs(NULL, NULL, chain, 0));
        errors();
        {
            ESS_ISSUER_SERIAL *is = ESS_ISSUER_SERIAL_new(), *isd;
            ESS_CERT_ID *cid = ESS_CERT_ID_new(), *cidd;
            ESS_CERT_ID_V2 *cid2 = ESS_CERT_ID_V2_new(), *cid2d;
            unsigned char *e = NULL;

            n = i2d_ESS_ISSUER_SERIAL(is, &e);
            printf("# empty ESS_ISSUER_SERIAL: %d", n);
            OPENSSL_free(e);
            e = NULL;
            n = i2d_ESS_CERT_ID(cid, &e);
            printf(", ESS_CERT_ID: %d", n);
            q = e;
            cidd = d2i_ESS_CERT_ID(NULL, &q, n);
            OPENSSL_free(e);
            e = NULL;
            n = i2d_ESS_CERT_ID_V2(cid2, &e);
            printf(", ESS_CERT_ID_V2: %d", n);
            q = e;
            cid2d = d2i_ESS_CERT_ID_V2(NULL, &q, n);
            OPENSSL_free(e);
            isd = ESS_ISSUER_SERIAL_dup(is);
            printf(", dups %s %s %s\n", isd == NULL ? "NULL" : "made", ESS_CERT_ID_dup(cid) == NULL ? "NULL" : "made",
                   ESS_CERT_ID_V2_dup(cid2) == NULL ? "NULL" : "made");
            {
                const unsigned char *z = (const unsigned char *)"\x30\x00";

                printf("  d2i ISSUER_SERIAL of an empty SEQUENCE: %s\n", d2i_ESS_ISSUER_SERIAL(NULL, &z, 2) == NULL ? "NULL" : "made");
            }
            errors();
            ESS_ISSUER_SERIAL_free(is);
            ESS_ISSUER_SERIAL_free(isd);
            ESS_CERT_ID_free(cid);
            ESS_CERT_ID_free(cidd);
            ESS_CERT_ID_V2_free(cid2);
            ESS_CERT_ID_V2_free(cid2d);
        }
        {
            ESS_SIGNING_CERT *n1 = ESS_SIGNING_CERT_new();
            ESS_SIGNING_CERT_V2 *n2 = ESS_SIGNING_CERT_V2_new(), *d2 = ESS_SIGNING_CERT_V2_dup(v2);
            unsigned char *e = NULL;

            n = ASN1_item_i2d((ASN1_VALUE *)n1, &e, ASN1_ITEM_rptr(ESS_SIGNING_CERT));
            printf("# empty SigningCertificate via the item: %d", n);
            OPENSSL_free(e);
            e = NULL;
            n = ASN1_item_i2d((ASN1_VALUE *)n2, &e, ASN1_ITEM_rptr(ESS_SIGNING_CERT_V2));
            printf(", V2: %d, dup %s\n", n, d2 == NULL ? "NULL" : "made");
            OPENSSL_free(e);
            ESS_SIGNING_CERT_free(n1);
            ESS_SIGNING_CERT_V2_free(n2);
            ESS_SIGNING_CERT_V2_free(d2);
        }
        ESS_SIGNING_CERT_free(sc);
        ESS_SIGNING_CERT_free(sc2);
        ESS_SIGNING_CERT_V2_free(v2);
        ESS_SIGNING_CERT_V2_free(v2b);
        ESS_SIGNING_CERT_V2_free(v384);
        sk_X509_free(wrong);
        sk_X509_free(missing);
        check(1, "ESS");
    }

    /* The reference's signatures */
    {
        static const char *const pems[] = {REF_SIGNED, REF_CADES, REF_ED, REF_PSS, REF_RSAPSS, REF_KEYID};
        static const char *const names[] = {"RSA", "EC CAdES", "Ed25519", "RSA-PSS key", "RSA with PSS", "by key identifier"};
        static const int expect[] = {1, 1, 1, 0, 1, 1};
        size_t i;

        for (i = 0; i < 6; i++) {
            cms = load(pems[i]);
            printf("# reference %s\n", names[i]);
            show_signers(cms);
            check(verify(names[i], cms, NULL, st, NULL, 0) == expect[i], names[i]);
            CMS_ContentInfo_free(cms);
        }
        cms = load(REF_CADES);
        check(verify("CAdES, checked", cms, NULL, st, NULL, CMS_CADES) == 1, "CMS_CADES");
        CMS_ContentInfo_free(cms);
        cms = load(REF_SIGNED);
        check(verify("CAdES required, absent", cms, NULL, st, NULL, CMS_CADES) == 0, "CAdES needs its attribute");
        check(verify("untrusted", cms, NULL, empty, NULL, 0) == 0, "an untrusted signer is refused");
        verify("not verified", cms, NULL, empty, NULL, CMS_NO_SIGNER_CERT_VERIFY);
        verify("attributes not verified", cms, NULL, empty, NULL, CMS_NOVERIFY | CMS_NO_ATTR_VERIFY);
        verify("content not verified", cms, NULL, empty, NULL, CMS_NOVERIFY | CMS_NO_CONTENT_VERIFY);
        {
            STACK_OF(X509) *signers;
            STACK_OF(X509) *mine = sk_X509_new_null();
            CMS_SignerInfo *si = sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), 0);

            printf("# before: signers %d\n", sk_X509_num(CMS_get0_signers(cms)));
            printf("  set1_signers_certs: %d\n", CMS_set1_signers_certs(cms, NULL, 0));
            signers = CMS_get0_signers(cms);
            printf("  after: signers %d, the RSA signer %d\n", sk_X509_num(signers), X509_cmp(sk_X509_value(signers, 0), rsa) == 0);
            sk_X509_free(signers);
            printf("  cert_cmp: %d %d\n", CMS_SignerInfo_cert_cmp(si, rsa), CMS_SignerInfo_cert_cmp(si, ec) == 0);
            CMS_SignerInfo_set1_signer_cert(si, NULL);
            printf("  cleared, NOINTERN: %d\n", CMS_set1_signers_certs(cms, mine, CMS_NOINTERN));
            sk_X509_push(mine, rsa);
            printf("  given: %d\n", CMS_set1_signers_certs(cms, mine, CMS_NOINTERN));
            sk_X509_free(mine);
            printf("  pkey ctx %s, md ctx %s\n", CMS_SignerInfo_get0_pkey_ctx(si) == NULL ? "NULL" : "set",
                   CMS_SignerInfo_get0_md_ctx(si) == NULL ? "NULL" : "set");
            printf("# SignerInfo_verify: %d\n", CMS_SignerInfo_verify(si));
            {
                BIO *chainb = CMS_dataInit(cms, NULL), *sink = BIO_new(BIO_s_mem());
                char buf[256];
                int k;

                while ((k = BIO_read(chainb, buf, sizeof(buf))) > 0)
                    BIO_write(sink, buf, k);
                printf("  verify_content: %d\n", CMS_SignerInfo_verify_content(si, chainb));
                BIO_free_all(chainb);
                BIO_free(sink);
            }
            errors();
            check(1, "signer functions");
        }
        {
            ASN1_OCTET_STRING **pos = CMS_get0_content(cms);

            (*pos)->data[0] ^= 1;
            check(verify("tampered", cms, NULL, st, NULL, 0) == 0, "a tampered content is refused");
            (*pos)->data[0] ^= 1;
        }
        CMS_ContentInfo_free(cms);

        cms = load(REF_DETACHED);
        in = mem(msg);
        check(verify("detached", cms, NULL, st, in, CMS_BINARY) == 1, "a detached signature");
        BIO_free(in);
        in = mem(msg);
        verify("detached, as text", cms, NULL, st, in, 0);
        BIO_free(in);
        verify("detached, no content", cms, NULL, st, NULL, 0);
        in = mem("other");
        check(verify("detached, other content", cms, NULL, st, in, CMS_BINARY) == 0, "other content is refused");
        BIO_free(in);
        CMS_ContentInfo_free(cms);
    }

    /* Signing */
    {
        static const unsigned int flags[] = {CMS_NOATTR, CMS_NOATTR | CMS_DETACHED | CMS_BINARY, CMS_NOATTR | CMS_NOCERTS,
                                             CMS_NOATTR | CMS_USE_KEYID, CMS_NOATTR | CMS_ASCIICRLF, CMS_NOATTR | CMS_TEXT};
        static const char *const names[] = {"no attributes", "detached", "no certificates", "by key identifier", "ASCII CRLF",
                                            "text"};
        size_t i;

        for (i = 0; i < 6; i++) {
            STACK_OF(X509) *certs = NULL;
            BIO *dcont = NULL;

            in = mem(msg);
            cms = CMS_sign(rsa, rsa_key, NULL, in, flags[i]);
            printf("# sign %s: %s\n", names[i], cms == NULL ? "NULL" : "made");
            errors();
            show_signers(cms);
            fingerprint("encoding", cms);
            if (flags[i] & CMS_NOCERTS) {
                certs = sk_X509_new_null();
                sk_X509_push(certs, rsa);
            }
            if (flags[i] & CMS_DETACHED)
                dcont = mem(msg);
            check(verify(names[i], cms, certs, st, dcont, flags[i] & (CMS_BINARY | CMS_TEXT)) == 1, names[i]);
            sk_X509_free(certs);
            BIO_free(dcont);
            CMS_ContentInfo_free(cms);
            BIO_free(in);
        }
    }
    {
        static const unsigned int flags[] = {0, CMS_NOSMIMECAP, CMS_NO_SIGNING_TIME, CMS_CADES};
        static const char *const names[] = {"with attributes", "no capabilities", "no signing time", "CAdES"};
        size_t i;

        for (i = 0; i < 4; i++) {
            in = mem(msg);
            cms = CMS_sign(rsa, rsa_key, chain, in, flags[i]);
            printf("# sign %s: %s\n", names[i], cms == NULL ? "NULL" : "made");
            errors();
            show_signers(cms);
            if (flags[i] == CMS_NO_SIGNING_TIME)
                fingerprint("encoding", cms);
            check(verify(names[i], cms, NULL, st, NULL, flags[i] & CMS_CADES) == 1, names[i]);
            CMS_ContentInfo_free(cms);
            BIO_free(in);
        }
    }
    {
        X509 *certs[3];
        EVP_PKEY *keys[3];
        static const char *const names[] = {"EC", "Ed25519", "RSA-PSS key"};
        size_t i;

        certs[0] = ec, certs[1] = ed, certs[2] = pss;
        keys[0] = ec_key, keys[1] = ed_key, keys[2] = pss_key;

        for (i = 0; i < 3; i++) {
            in = mem(msg);
            cms = CMS_sign(NULL, NULL, NULL, NULL, CMS_PARTIAL);
            printf("# add1_signer %s: %s\n", names[i],
                   CMS_add1_signer(cms, certs[i], keys[i], i == 1 ? EVP_sha512() : NULL, 0) == NULL ? "NULL" : "added");
            printf("  final %d\n", CMS_final(cms, in, NULL, 0));
            errors();
            show_signers(cms);
            verify(names[i], cms, NULL, st, NULL, 0);
            CMS_ContentInfo_free(cms);
            BIO_free(in);
        }
        in = mem(msg);
        cms = CMS_sign(NULL, NULL, NULL, NULL, CMS_PARTIAL);
        printf("# add1_signer Ed25519, default digest: %s\n", CMS_add1_signer(cms, ed, ed_key, NULL, 0) == NULL ? "NULL" : "added");
        errors();
        CMS_ContentInfo_free(cms);
        BIO_free(in);
    }
    {
        /* A second signer reusing the first's digest; then RSA-PSS by key parameter. */
        CMS_SignerInfo *si;
        EVP_PKEY_CTX *pctx;

        in = mem(msg);
        cms = CMS_sign(rsa, rsa_key, NULL, in, 0);
        si = CMS_add1_signer(cms, ec, ec_key, EVP_sha256(), CMS_REUSE_DIGEST);
        printf("# reuse digest: %s\n", si == NULL ? "NULL" : "added");
        errors();
        show_signers(cms);
        check(verify("two signers", cms, NULL, st, NULL, 0) == 1, "CMS_REUSE_DIGEST");
        si = CMS_add1_signer(cms, rsa, rsa_key, EVP_sha512(), CMS_REUSE_DIGEST);
        printf("# reuse a digest that isn't there: %s\n", si == NULL ? "NULL" : "added");
        errors();
        CMS_ContentInfo_free(cms);
        BIO_free(in);

        in = mem(msg);
        cms = CMS_sign(NULL, NULL, NULL, NULL, CMS_PARTIAL);
        si = CMS_add1_signer(cms, rsa, rsa_key, EVP_sha256(), CMS_KEY_PARAM);
        pctx = CMS_SignerInfo_get0_pkey_ctx(si);
        printf("# key param: %s, ctx %s, PSS %d\n", si == NULL ? "NULL" : "added", pctx == NULL ? "NULL" : "set",
               EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING));
        printf("  final %d\n", CMS_final(cms, in, NULL, 0));
        errors();
        show_signers(cms);
        check(verify("PSS by key parameter", cms, NULL, st, NULL, 0) == 1, "CMS_KEY_PARAM");
        CMS_ContentInfo_free(cms);
        BIO_free(in);

        in = mem(msg);
        cms = CMS_sign(NULL, NULL, NULL, NULL, CMS_PARTIAL);
        si = CMS_add1_signer(cms, rsa, rsa_key, EVP_sha256(), CMS_KEY_PARAM | CMS_NOATTR);
        printf("# key param, no attributes: %s, final %d\n", si == NULL ? "NULL" : "added", CMS_final(cms, in, NULL, 0));
        errors();
        fingerprint("encoding", cms);
        check(verify("key param, no attributes", cms, NULL, st, NULL, 0) == 1, "CMS_KEY_PARAM and CMS_NOATTR");
        CMS_ContentInfo_free(cms);
        BIO_free(in);
    }
    {
        /* A precomputed digest. */
        unsigned char md[32];
        unsigned int mdlen;
        CMS_ContentInfo *cms2;

        EVP_Digest(msg, strlen(msg), md, &mdlen, EVP_sha256(), NULL);
        cms = CMS_sign(rsa, rsa_key, NULL, NULL, CMS_PARTIAL | CMS_DETACHED | CMS_BINARY | CMS_NO_SIGNING_TIME);
        printf("# final_digest: %d\n", CMS_final_digest(cms, md, mdlen, NULL, 0));
        errors();
        fingerprint("encoding", cms);
        in = mem(msg);
        check(verify("final_digest", cms, NULL, st, in, CMS_BINARY) == 1, "CMS_final_digest");
        BIO_free(in);
        CMS_ContentInfo_free(cms);
        cms2 = CMS_sign(rsa, rsa_key, NULL, NULL, CMS_PARTIAL | CMS_DETACHED | CMS_NOATTR);
        printf("# final_digest without attributes: %d\n", CMS_final_digest(cms2, md, mdlen, NULL, 0));
        errors();
        CMS_ContentInfo_free(cms2);
    }
    {
        BIO *out;

        in = mem(msg);
        cms = CMS_sign(rsa, rsa_key, NULL, NULL, CMS_STREAM | CMS_NOATTR);
        out = BIO_new(BIO_s_mem());
        printf("# stream: %d\n", i2d_CMS_bio_stream(out, cms, in, CMS_STREAM));
        CMS_ContentInfo_free(cms);
        cms = d2i_CMS_bio(out, NULL);
        fingerprint("read back", cms);
        check(verify("streamed", cms, NULL, st, NULL, 0) == 1, "a streamed signature");
        CMS_ContentInfo_free(cms);
        BIO_free(out);
        BIO_free(in);
    }
    {
        in = mem(msg);
        cms = CMS_sign(rsa, ec_key, NULL, in, 0);
        printf("# sign with a key that doesn't match: %s\n", cms == NULL ? "NULL" : "made");
        errors();
        BIO_free(in);
        cms = CMS_ContentInfo_new();
        printf("# SignedData_init: %d %d\n", CMS_SignedData_init(cms), CMS_SignedData_init(cms));
        CMS_ContentInfo_free(cms);
        cms = CMS_data_create(NULL, CMS_STREAM);
        printf("  on Data: %d, add1_signer %s\n", CMS_SignedData_init(cms),
               CMS_add1_signer(cms, rsa, rsa_key, NULL, 0) == NULL ? "NULL" : "added");
        errors();
        CMS_ContentInfo_free(cms);
        check(1, "refused signing");
    }

    /* In a library context */
    {
        OSSL_LIB_CTX *lc = OSSL_LIB_CTX_new();

        in = mem(msg);
        cms = CMS_sign_ex(rsa, rsa_key, NULL, in, CMS_NOATTR, lc, "provider=default");
        printf("# sign_ex: %s\n", cms == NULL ? "NULL" : "made");
        fingerprint("encoding", cms);
        check(verify("sign_ex", cms, NULL, st, NULL, 0) == 1, "CMS_sign_ex");
        CMS_ContentInfo_free(cms);
        BIO_free(in);
        OSSL_LIB_CTX_free(lc);
    }

    /* Receipts */
    {
        CMS_ContentInfo *rcms;
        CMS_SignerInfo *si;
        CMS_ReceiptRequest *rr;
        unsigned char *id = OPENSSL_malloc(8);
        STACK_OF(GENERAL_NAMES) *to = sk_GENERAL_NAMES_new_null();
        GENERAL_NAMES *gns = GENERAL_NAMES_new();
        GENERAL_NAME *gn = GENERAL_NAME_new();

        memcpy(id, "receipt!", 8);
        gn->type = GEN_EMAIL;
        gn->d.rfc822Name = ASN1_IA5STRING_new();
        ASN1_STRING_set(gn->d.rfc822Name, "a@example.com", -1);
        sk_GENERAL_NAME_push(gns, gn);
        sk_GENERAL_NAMES_push(to, gns);
        in = mem(msg);
        cms = CMS_sign(NULL, NULL, NULL, NULL, CMS_PARTIAL);
        si = CMS_add1_signer(cms, rsa, rsa_key, NULL, 0);
        rr = CMS_ReceiptRequest_create0(id, 8, 0, NULL, to);
        printf("# receipt request: add1 %d, final %d\n", CMS_add1_ReceiptRequest(si, rr), CMS_final(cms, in, NULL, 0));
        CMS_ReceiptRequest_free(rr);
        errors();
        rcms = CMS_sign_receipt(si, ec, ec_key, NULL, 0);
        printf("# sign_receipt: %s\n", rcms == NULL ? "NULL" : "made");
        errors();
        show_signers(rcms);
        printf("  eContentType %s\n", oid(CMS_get0_eContentType(rcms)));
        check(CMS_verify_receipt(rcms, cms, NULL, st, 0) == 1, "CMS_sign_receipt and CMS_verify_receipt");
        errors();
        {
            /* A receipt for another request. */
            CMS_ContentInfo *other;
            BIO *in2 = mem(msg);

            other = CMS_sign(rsa, rsa_key, NULL, in2, 0);
            printf("# verify_receipt against another message: %d\n", CMS_verify_receipt(rcms, other, NULL, st, 0));
            errors();
            si = sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(other), 0);
            printf("# sign_receipt without a request: %s\n", CMS_sign_receipt(si, ec, ec_key, NULL, 0) == NULL ? "NULL" : "made");
            errors();
            CMS_ContentInfo_free(other);
            BIO_free(in2);
        }
        CMS_ContentInfo_free(rcms);
        CMS_ContentInfo_free(cms);
        BIO_free(in);
    }

    /*
     * A receipt in a library context, while nothing can be fetched in the default one (as the
     * openssl tool's OPENSSL_TEST_LIBCTX mode has it): the msgSigDigest's digest comes from the
     * signer's context.
     */
    {
        OSSL_LIB_CTX *lc = OSSL_LIB_CTX_new();
        BIO *b = mem(RSA_KEY_PEM);
        EVP_PKEY *k = PEM_read_bio_PrivateKey_ex(b, NULL, NULL, NULL, lc, NULL);
        BIO *b2 = mem(EC_KEY_PEM);
        EVP_PKEY *k2 = PEM_read_bio_PrivateKey_ex(b2, NULL, NULL, NULL, lc, NULL);
        CMS_ContentInfo *rcms;
        CMS_SignerInfo *si;
        CMS_ReceiptRequest *rr;
        STACK_OF(GENERAL_NAMES) *to = sk_GENERAL_NAMES_new_null();
        GENERAL_NAMES *gns = GENERAL_NAMES_new();
        GENERAL_NAME *gn = GENERAL_NAME_new();

        gn->type = GEN_EMAIL;
        gn->d.rfc822Name = ASN1_IA5STRING_new();
        ASN1_STRING_set(gn->d.rfc822Name, "a@example.com", -1);
        sk_GENERAL_NAME_push(gns, gn);
        sk_GENERAL_NAMES_push(to, gns);
        BIO_free(b);
        BIO_free(b2);
        in = mem(msg);
        check(EVP_set_default_properties(NULL, "provider=none-at-all") == 1, "no fetches in the default context");
        cms = CMS_sign_ex(NULL, NULL, NULL, NULL, CMS_PARTIAL, lc, NULL);
        si = CMS_add1_signer(cms, rsa, k, NULL, 0);
        rr = CMS_ReceiptRequest_create0_ex(NULL, -1, 1, NULL, to, lc);
        printf("# receipt request in a context: add1 %d, final %d\n", CMS_add1_ReceiptRequest(si, rr), CMS_final(cms, in, NULL, 0));
        CMS_ReceiptRequest_free(rr);
        errors();
        rcms = si == NULL ? NULL : CMS_sign_receipt(si, ec, k2, NULL, 0);
        printf("# sign_receipt in a context: %s\n", rcms == NULL ? "NULL" : "made");
        errors();
        EVP_set_default_properties(NULL, "");
        check(rcms != NULL && CMS_verify_receipt(rcms, cms, NULL, st, 0) == 1, "a receipt signed in a library context");
        errors();
        CMS_ContentInfo_free(rcms);
        CMS_ContentInfo_free(cms);
        BIO_free(in);
        EVP_PKEY_free(k);
        EVP_PKEY_free(k2);
        OSSL_LIB_CTX_free(lc);
    }

    /* S/MIME, capabilities, and the SignedData functions */
    {
        BIO *out = BIO_new(BIO_s_mem()), *bcont = NULL;
        CMS_ContentInfo *back;
        STACK_OF(X509_ALGOR) *caps = NULL;
        int i;
        char *p, *q2;
        long n;

        in = mem(msg);
        cms = CMS_sign(rsa, rsa_key, NULL, in, CMS_DETACHED | CMS_NOATTR);
        BIO_free(in);
        in = mem(msg);
        printf("# SMIME_write_CMS detached: %d\n", SMIME_write_CMS(out, cms, in, CMS_DETACHED));
        n = BIO_get_mem_data(out, &p);
        q2 = strstr(p, "micalg=");
        printf("  %.*s\n", q2 == NULL ? 0 : 17, q2 == NULL ? "" : q2);
        printf("  %ld octets\n", n);
        back = SMIME_read_CMS(out, &bcont);
        check(back != NULL && verify("S/MIME multipart", back, NULL, st, bcont, 0) == 1, "S/MIME multipart/signed");
        CMS_ContentInfo_free(back);
        BIO_free(bcont);
        BIO_free(in);
        BIO_free(out);
        CMS_ContentInfo_free(cms);

        printf("# standard capabilities: %d\n", CMS_add_standard_smimecap(&caps));
        printf("  simple: %d %d\n", CMS_add_simple_smimecap(&caps, NID_aes_128_gcm, 0), CMS_add_simple_smimecap(&caps, NID_rc2_cbc, 40));
        for (i = 0; i < sk_X509_ALGOR_num(caps); i++) {
            X509_ALGOR *a = sk_X509_ALGOR_value(caps, i);

            printf("  %s", oid(a->algorithm));
            if (a->parameter != NULL && a->parameter->type == V_ASN1_INTEGER)
                printf("(%ld)", ASN1_INTEGER_get(a->parameter->value.integer));
        }
        printf("\n");
        in = mem(msg);
        cms = CMS_sign(NULL, NULL, NULL, NULL, CMS_PARTIAL);
        {
            CMS_SignerInfo *si = CMS_add1_signer(cms, rsa, rsa_key, NULL, CMS_NOSMIMECAP);

            printf("  add_smimecap: %d\n", CMS_add_smimecap(si, caps));
            printf("  final %d, signed attributes %d\n", CMS_final(cms, in, NULL, 0), CMS_signed_get_attr_count(si));
            printf("  SignerInfo_sign again: %d\n", CMS_SignerInfo_sign(si));
        }
        check(verify("with capabilities added", cms, NULL, st, NULL, 0) == 1, "CMS_add_smimecap");
        sk_X509_ALGOR_pop_free(caps, X509_ALGOR_free);
        CMS_ContentInfo_free(cms);
        BIO_free(in);

        {
            CMS_SignedData *sd = CMS_SignedData_new();
            BIO *r = CMS_SignedData_verify(sd, NULL, NULL, st, NULL, NULL, 0, NULL, NULL);

            printf("# SignedData_verify of an empty one: %s\n", r == NULL ? "NULL" : "made");
            errors();
            printf("  of NULL: %s\n", CMS_SignedData_verify(NULL, NULL, NULL, st, NULL, NULL, 0, NULL, NULL) == NULL ? "NULL" : "made");
            errors();
            CMS_SignedData_free(sd);
        }
        check(1, "S/MIME, capabilities, and SignedData");
    }

    X509_STORE_free(st);
    X509_STORE_free(empty);
    sk_X509_free(chain);
    X509_free(root);
    X509_free(rsa);
    X509_free(ec);
    X509_free(ed);
    X509_free(pss);
    X509_free(rcpt);
    EVP_PKEY_free(rsa_key);
    EVP_PKEY_free(ec_key);
    EVP_PKEY_free(ed_key);
    EVP_PKEY_free(pss_key);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
