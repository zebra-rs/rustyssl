/*
 * Conformance test for CMS EnvelopedData and AuthEnvelopedData (CMS_encrypt(3),
 * CMS_decrypt(3), CMS_add1_recipient(3), CMS_add0_recipient_key(3), CMS_get0_RecipientInfos(3)
 * and the CMS_RecipientInfo_* functions, CMS_EnvelopedData_create(3),
 * CMS_AuthEnvelopedData_create(3), and CMS_EnvelopedData_decrypt): the reference tool's
 * envelopes (RSA key transport with PKCS#1 v1.5 and OAEP, by key identifier; ECDH with AES
 * and triple DES; X9.42 DH; KEK; password; AES-GCM; several recipients) decrypted every way
 * the API offers; recipients inspected; envelopes made here round-tripped; wrong keys, ids,
 * passwords, and tags refused. Envelopes made here are random, so only their structure is
 * printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
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

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

/*
 * Made with the reference's openssl tool: an EC root; RSA, EC (P-256), and X9.42 DH (RFC 5114
 * 2048-bit group, -force_pubkey) recipients; cms -encrypt -binary with -aes-128-cbc (RSA),
 * -aes-256-cbc -keyid (RSA), -keyopt rsa_padding_mode:oaep, rsa_oaep_md:sha256 and
 * rsa_oaep_label:6162 (RSA), -aes-128-cbc (EC), -aes-256-cbc (DH), -des-ede3-cbc (EC),
 * -secretkey 000102...0F -secretkeyid 0A0B0C, -pwri_password hunter2, -aes-256-gcm (RSA and
 * EC), and -aes-128-cbc (EC and RSA).
 */
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

static const char DH_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEUjCCA/egAwIBAgIBBzAKBggqhkjOPQQDAjAnMRAwDgYDVQQKDAdFeGFtcGxl\n"
    "MRMwEQYDVQQDDApTTUlNRSBSb290MB4XDTI2MTAxODAwNTU0N1oXDTM2MTAxNTAw\n"
    "NTU0N1owDTELMAkGA1UEAwwCZGgwggNDMIICNgYHKoZIzj4CATCCAikCggEBAK0Q\n"
    "fh6RI6nQ1mD6p5VZxR+iDWTlaDuf0bVLFZe2HQp15voUHflaVtuvmjxAe6HfFes9\n"
    "aIownBgOHea4WhJ0oKZtP4FSrWrCEpA3ye3v2k342R6P71W3OUt61bfQtsEiB8n5\n"
    "jRHtNNv2xroLLIu8J75qAOCgucSXCLO/ijFwkYg2gShhMLyJhdsWAucUQV2TMCeC\n"
    "c8feMe/ccxD3Eh/VoHQVmH2a3ApIbc35OsxEMoOHMV114ZjGQaSAzYahueWH6L5g\n"
    "5pzJKLK5xSFy5BMELpsj8QsOFueXY8m1Pc9LqAop4/tzwWuOdbl+82Pi/6Mfcc+d\n"
    "5ThOcbgcCsTf/gwQ5k8CggEBAKxAMu9PLZrjnfMLXI/9rFBs3r57iZmMr3SGagjP\n"
    "5P/jpoJKThC5pvDdkh8BpwxK+qtznXcAwp9SxX2xfGIKhlK+XpABqNZq18F2aRAZ\n"
    "mQJK9NAnJ1rBNIu4p2LQUhvJiuJHFQQi6h7UCZOdVNp0YM219sayUHF8vvGA6zQR\n"
    "jpjRGVKaRdb4NFZuMCXjFqMw77t3qG8MGrFbBRrj1CjI+Ky3CoE3FQuO6xDhg+3R\n"
    "mWPd2eJj5HcFie9qoh5/Xy/zgbU5zONAnRPNVmr7tI1sAZGB4bz+lLMCae3+cv6b\n"
    "aqS9e1oPHHHP/0wZxBjh9uwBeYG8CH8qcGWzhLiQ0xkfK/oCHQCAHA00xY2T/plx\n"
    "dxAfgFNaRzjOvL84mpmzY3HrA4IBBQACggEAbn+cT3A9B6NoTm6Z2Igo3WasTGP4\n"
    "j487j5c8rmNEdOa3bvGOXsSm2v2NME1bztykRIJs3ZfaJW2KPFpykz/V1olr6Fu7\n"
    "hhjMt6uyqZDSWddrfsb9CnDkpq9kwzBQ3CLmzu4/OZcSlKMd7Ux4eyEH/qoB8IOK\n"
    "gCEi5H0BZrHb/dVbDlFemGo0fQF+rOrIR7HesEfHMSqm58fjpeuKkiMIhmalKvB4\n"
    "8+NuYvjOvGTnaiJikRatWRjpjHK1qSMsHsGhqftjk/0kJWtRwdnQWGdfrJUlAk8/\n"
    "R3PkhaZEnsxHf264R85Aq3Rg648VyRRFWAkvyFVTJGDF4qFOC1zQ77CrvKNCMEAw\n"
    "HQYDVR0OBBYEFHES4gW0utcs3l8m8JyGBWiqV10cMB8GA1UdIwQYMBaAFHW101B5\n"
    "21S0OKWXAyFbAPAdaKBFMAoGCCqGSM49BAMCA0kAMEYCIQCmVEMXCr9ju1glBTVA\n"
    "4j9A5XHxWfK7AzBYO744J39IIgIhAOURhjLm72MqSfGxiY7vVooFzDogCzSxZA4R\n"
    "b9BZADry\n"
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

static const char DH_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICXQIBADCCAjYGByqGSM4+AgEwggIpAoIBAQCtEH4ekSOp0NZg+qeVWcUfog1k\n"
    "5Wg7n9G1SxWXth0Kdeb6FB35Wlbbr5o8QHuh3xXrPWiKMJwYDh3muFoSdKCmbT+B\n"
    "Uq1qwhKQN8nt79pN+Nkej+9VtzlLetW30LbBIgfJ+Y0R7TTb9sa6CyyLvCe+agDg\n"
    "oLnElwizv4oxcJGINoEoYTC8iYXbFgLnFEFdkzAngnPH3jHv3HMQ9xIf1aB0FZh9\n"
    "mtwKSG3N+TrMRDKDhzFddeGYxkGkgM2Gobnlh+i+YOacySiyucUhcuQTBC6bI/EL\n"
    "Dhbnl2PJtT3PS6gKKeP7c8FrjnW5fvNj4v+jH3HPneU4TnG4HArE3/4MEOZPAoIB\n"
    "AQCsQDLvTy2a453zC1yP/axQbN6+e4mZjK90hmoIz+T/46aCSk4Quabw3ZIfAacM\n"
    "Svqrc513AMKfUsV9sXxiCoZSvl6QAajWatfBdmkQGZkCSvTQJydawTSLuKdi0FIb\n"
    "yYriRxUEIuoe1AmTnVTadGDNtfbGslBxfL7xgOs0EY6Y0RlSmkXW+DRWbjAl4xaj\n"
    "MO+7d6hvDBqxWwUa49QoyPistwqBNxULjusQ4YPt0Zlj3dniY+R3BYnvaqIef18v\n"
    "84G1OczjQJ0TzVZq+7SNbAGRgeG8/pSzAmnt/nL+m2qkvXtaDxxxz/9MGcQY4fbs\n"
    "AXmBvAh/KnBls4S4kNMZHyv6Ah0AgBwNNMWNk/6ZcXcQH4BTWkc4zry/OJqZs2Nx\n"
    "6wQeAhxrExSm661eE2Aw6Xl9KdkZGpB2fq0rKMIjMP5A\n"
    "-----END PRIVATE KEY-----\n";

static const char REF_RSA[] =
    "-----BEGIN CMS-----\n"
    "MIIBwAYJKoZIhvcNAQcDoIIBsTCCAa0CAQAxggFIMIIBRAIBADAsMCcxEDAOBgNV\n"
    "BAoMB0V4YW1wbGUxEzARBgNVBAMMClNNSU1FIFJvb3QCAWUwDQYJKoZIhvcNAQEB\n"
    "BQAEggEAABzy/Hy2QLwmT6B7OwiPyPxE2Cil3UKys95+mocMk3/7q3ipdBX9NvoN\n"
    "zf4Btpk2tCYxHtnfePtTajn359I2Fnafej6/4dxmm/Xg43qimd20s4UavFhrvrYe\n"
    "bCy9CqvRUZatS5tkE1xehV2rW4DRqJ2hGlesW2/WzM37MuL6LnZoudV6Aw7qnTM4\n"
    "3743vwjKqPuoK/KrmR147lSsKIUyPRhXau6czFXskB6M6WzDruSJKVSEjtbnDw5A\n"
    "MtkemmHGW6gEGSAXsbp2otBAgDRlsfx4ZhlBbEAIj/6k6Rq8+LUk0/E3xdCPGjq5\n"
    "jjTSDt8p587W2CQXep5FOb3zd3s++DBcBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEC\n"
    "BBBxUGnNH5mBTkgtxchSDmcFgDCrLUc3hSq955chk5mrTR01V9Iw0INh2zMYbZds\n"
    "wCilAf6BAtUmuULVNY/auJhgp1I=\n"
    "-----END CMS-----\n";

static const char REF_KEYID[] =
    "-----BEGIN CMS-----\n"
    "MIIBqAYJKoZIhvcNAQcDoIIBmTCCAZUCAQIxggEwMIIBLAIBAoAUExDrLI5hX38P\n"
    "Qx3X2FxvuKpqhLwwDQYJKoZIhvcNAQEBBQAEggEAgYO0HQxPJMQHccwYvwkOfOaL\n"
    "yRPDXMr/PrgE89svJWKC/ApiSdwT36eVZJZe45l6zr5ICWxkU1Pr/pcs8gYGoccC\n"
    "xilf5QSZEkQoqlMwQ6Su0zXnKoO9OqcZkwYyjXBUK875TQt5IZAJdB6It8oqa4ux\n"
    "P1BVv7ddXLiRgzSj723aeVZKBHLxyguGTnlGTOf5kCLsSoNXbhvaVSV7/CEg1Sdc\n"
    "r1hqDS9FnBSqzxtiAAwKW4IViH9Ou8bw5F6t+/95h8Vpd/tgQn+BU7HR4Gp3mc0T\n"
    "pm6eIfBYHEf9Fki3SZIJReR59YUA5gtf09ZA+BEWEF+xYz5s5Ca67zLm3t2zwTBc\n"
    "BgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBBtK/eQ+CgZON6Ejpck8hMwgDAPjnQa\n"
    "87DfaNOsg0Te32eP9VPWlSOkZRsGwu+ospKFPHiI1oFyLKyqF+MTAMv29PU=\n"
    "-----END CMS-----\n";

static const char REF_OAEP[] =
    "-----BEGIN CMS-----\n"
    "MIIB/gYJKoZIhvcNAQcDoIIB7zCCAesCAQAxggGGMIIBggIBADAsMCcxEDAOBgNV\n"
    "BAoMB0V4YW1wbGUxEzARBgNVBAMMClNNSU1FIFJvb3QCAWUwSwYJKoZIhvcNAQEH\n"
    "MD6gDTALBglghkgBZQMEAgGhGjAYBgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIBohEw\n"
    "DwYJKoZIhvcNAQEJBAJhYgSCAQBplsbLvpQAecKjNJvySXsSJZI37GzouwVtF1p6\n"
    "JeIoqQ7ZY82cFH0dVH+O958YXA6Aju9zdflOQAHKv0v89QT4U8eD5HcIQTQ4hdy2\n"
    "4hVcoSUOS6IRreWVhpFRy8pNT4sJBv3rWygvUANoAi0PMaUeo7YNYQpX/RwYoZpT\n"
    "TAJ1ZyEAokPYjtKtF20nrnFtbNu10Osd24bar3NNxfzyKW1NIVl83MxF7NeWzIkk\n"
    "Q5j+1iXVL6Am60qLshe3J+DbbqyC4XEJpMzX93+bvgg5SWFXg48XgCnnn59CQN3E\n"
    "YxT3lwe+/hj92H8aqglyA//DQKQGbf7n6Ytmnx6IOvQkSJODMFwGCSqGSIb3DQEH\n"
    "ATAdBglghkgBZQMEAQIEEAZwqoMy3sWvRhVEjJj/mzuAMKb55jubGo2MU/z19tT3\n"
    "h2KtSxYSVJPiBNR3JG7cdqxQaPDVWBupru1+BxV7DUvCIA==\n"
    "-----END CMS-----\n";

static const char REF_EC[] =
    "-----BEGIN CMS-----\n"
    "MIIBNgYJKoZIhvcNAQcDoIIBJzCCASMCAQIxgb+hgbwCAQOgUaFPMAkGByqGSM49\n"
    "AgEDQgAE5ddaqA2Eq+R5tSJ15mQA/b6lFgohTJHJhS4v4OdleDqjuzEhSiG+BBR9\n"
    "FWBAMOOqubLISbSDCx7EtO6FPBqPojAYBgkrgQUQhkg/AAIwCwYJYIZIAWUDBAEF\n"
    "MEowSDAsMCcxEDAOBgNVBAoMB0V4YW1wbGUxEzARBgNVBAMMClNNSU1FIFJvb3QC\n"
    "AWYEGF64DmQp6bKtYz+hEgikQPByeRo+ocqNFDBcBgkqhkiG9w0BBwEwHQYJYIZI\n"
    "AWUDBAECBBBaK+VchGrbmRVJIg3aGn+YgDBRmHJrK+ZqnZV6mOs8HG0/AB0cmTou\n"
    "mX1WyVoxI+cMg+W4XyFXxJuvy8PYdm5DrIc=\n"
    "-----END CMS-----\n";

static const char REF_EC3DES[] =
    "-----BEGIN CMS-----\n"
    "MIIBOQYJKoZIhvcNAQcDoIIBKjCCASYCAQIxgdOhgdACAQOgUaFPMAkGByqGSM49\n"
    "AgEDQgAEO8LrBrwh9oG4J9uw6FVbchrmwI0zuXFvMn/0V6z/Caybm3c9C73UnBpy\n"
    "Ffm12U6Gui6NW+PxGm3/cmVD9+WxzDAcBgkrgQUQhkg/AAIwDwYLKoZIhvcNAQkQ\n"
    "AwYFADBaMFgwLDAnMRAwDgYDVQQKDAdFeGFtcGxlMRMwEQYDVQQDDApTTUlNRSBS\n"
    "b290AgFmBCi6/NSWQloVuV8b06aS3nJ4Af4kDuGebqkP2r7xwH3+5P4pXg3h/uhL\n"
    "MEsGCSqGSIb3DQEHATAUBggqhkiG9w0DBwQIr9o+ZnCrg86AKFEzcLGrXHh6lpr5\n"
    "8octF3RApD1VaGBugJBtmvTcN/QWK3Vcq7gFVr0=\n"
    "-----END CMS-----\n";

static const char REF_DH[] =
    "-----BEGIN CMS-----\n"
    "MIICFAYJKoZIhvcNAQcDoIICBTCCAgECAQIxggGcoYIBmAIBA6CCARmhggEVMAkG\n"
    "ByqGSM4+AgEDggEGAAKCAQEAipxE6NTQIsXedLRm2z9MCgQK3aD2sgGXVwlDeuPo\n"
    "AUju1V0sdXLqKIP6E3e5yuwEslXkdlubWoFpMB2K5xB2Y1rtcwZEHPWwz7o+WTfe\n"
    "AEoi0DKZWOsjIfG5uAR7sjdyqt0AxsrgwaSLya4pWaE01yA7ZIxKp3lgW0FjZ5Ym\n"
    "vL9Fd7g8UuC6IoAZZBHdBn4Nnyl7eGiKgsYVRYyKvFJe03rERnzdSvqPIm5rg/Lq\n"
    "UvpKp1LdtycLXoicJyGVkklke7TlZu779K4C6vWU52EolFuTlSKNZHoeHDeTeTGL\n"
    "T2dDaw1Fmw1993joheMU3/ELH2P6j4CpVathNQBeFjqGTTAaBgsqhkiG9w0BCRAD\n"
    "BTALBglghkgBZQMEAS0wWjBYMCwwJzEQMA4GA1UECgwHRXhhbXBsZTETMBEGA1UE\n"
    "AwwKU01JTUUgUm9vdAIBBwQolHtORY4risbZixDJhxN06e/euViRVUal8HQIehHS\n"
    "+yKUaLEjzJOKLTBcBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBAqv6RK6uQcsFej\n"
    "Ix44q6E7gDBgcnLnaUemMR1pNuNxHVqUFg3ZuhVb2ruXYwyi81WRxouHxf/8/Z6l\n"
    "tJD+X8bj0iU=\n"
    "-----END CMS-----\n";

static const char REF_KEK[] =
    "-----BEGIN CMS-----\n"
    "MIGnBgkqhkiG9w0BBwOggZkwgZYCAQIxM6IxAgEEMAUEAwoLDDALBglghkgBZQME\n"
    "AQUEGFWe0bQq8e7Cz2G59+9kgBxabw+GOJ7TSDBcBgkqhkiG9w0BBwEwHQYJYIZI\n"
    "AWUDBAECBBDt0qqjnnjqnzwHPUbUDikCgDBH9mNv1HbD0I3dHHnJKPNf7lIy2oXb\n"
    "gJ3rTQ8wG+Q7N5mn7Q8cBmktX8mRKTPP2ts=\n"
    "-----END CMS-----\n";

static const char REF_PWRI[] =
    "-----BEGIN CMS-----\n"
    "MIHuBgkqhkiG9w0BBwOggeAwgd0CAQMxeqN4AgEAoCMGCSqGSIb3DQEFDDAWBBB2\n"
    "9Fl37okwv4DlG6SCZkFsAgIIADAsBgsqhkiG9w0BCRADCTAdBglghkgBZQMEAQIE\n"
    "EAyN0JNgTj1QmV3dxjtY0IwEIEzxbOW5uBpjNpyb5KZAqIxSoGCIo5lDkPRh44Mv\n"
    "/GJ4MFwGCSqGSIb3DQEHATAdBglghkgBZQMEAQIEEEfqe3Qf8jBe5Q8VhLwsiBCA\n"
    "MOtjNAR/uV+ALQuiTubhQQZqz4MH11/nbdAlzhIytivB1kHGQhfWfrV25luxpjsj\n"
    "sA==\n"
    "-----END CMS-----\n";

static const char REF_GCM[] =
    "-----BEGIN CMS-----\n"
    "MIIClwYLKoZIhvcNAQkQARegggKGMIICggIBADGCAhcwggFEAgEAMCwwJzEQMA4G\n"
    "A1UECgwHRXhhbXBsZTETMBEGA1UEAwwKU01JTUUgUm9vdAIBZTANBgkqhkiG9w0B\n"
    "AQEFAASCAQB6Zq5suUx/oyz8y8fPssVh2KainhpOJCoH4wu7U8GWnPIhryvnhfpB\n"
    "t2VtGFp5kW7b6XWrrepLZbaAfI41nS8frXTfF/VzJ9X8QdzyxWWVRYjcj8jqSZqa\n"
    "/SJtwmBqsG5fReVQJVmF9J5L8LvPPTWCQ/h6lTlyRvCp3SwVK0fTFt76nyVsH4wO\n"
    "4RFqjA9uZ/R0h4mN03hchRyqXNnYxaehYY79I9uKJMMATKMqYXXS/CzW1LK/uvOt\n"
    "hkSkdHe7iEkZ5ldwnAr+NrHXQKfjAKOqUOjL5pSoD1VWdNYl26kBDo7BU92NQM7b\n"
    "YImTGChf2H/lLSajSjQrHifP6nIuu+LSoYHMAgEDoFGhTzAJBgcqhkjOPQIBA0IA\n"
    "BFZqV0sZX24rxCcQiE+U+PvWoqQlpcU1u7EhjDBwd4Y0/qnljkVayuckVDS43tpH\n"
    "WzLU9OLh0p8t59wId4s8WF8wGAYJK4EFEIZIPwACMAsGCWCGSAFlAwQBLTBaMFgw\n"
    "LDAnMRAwDgYDVQQKDAdFeGFtcGxlMRMwEQYDVQQDDApTTUlNRSBSb290AgFmBChL\n"
    "nJTxcU9Lwxg1GOQ5zqWRM6ccbqAhtOeiFXq6HN9yYQcsqpP4IJc4MFAGCSqGSIb3\n"
    "DQEHATAeBglghkgBZQMEAS4wEQQMSIHWxMKBq7KNgaiQAgEQgCPSz4eJse4rCqM7\n"
    "45XAzDlt26DteUMOdJNzC3J+b4RlCLah0AQQoRWT+t2KW8PB8h9gHxzQqA==\n"
    "-----END CMS-----\n";

static const char REF_MULTI[] =
    "-----BEGIN CMS-----\n"
    "MIICfwYJKoZIhvcNAQcDoIICcDCCAmwCAQIxggIHMIIBRAIBADAsMCcxEDAOBgNV\n"
    "BAoMB0V4YW1wbGUxEzARBgNVBAMMClNNSU1FIFJvb3QCAWUwDQYJKoZIhvcNAQEB\n"
    "BQAEggEAQ8XSUO7O9FZDlacWgdmp/+fLp08sqpDT+7Ob1jhWiq53ZGtRmuC17nE/\n"
    "GwGuUNxU77ULvL14XCcIMCGX4ojDhBRQOwlUOMubKllLkkQtUpqsRApGsAQ7Fbuj\n"
    "oHjrGMPZjKX7MxCto1uZfelLQGie0hHD7znOSGRer75Q1EzzO/CrOGY2g8fUAYdb\n"
    "cVhLPv/2p9rtydlLLecdHwtP+KGbVjngGj7br1P/mT6VkSo2GX/pqauQlvdwCd/X\n"
    "aMTpEx3KsiTGJlfO/UfMsC6wJdr2+CbqPY6FdcmiqzCp3/sQw1zi9Y9nBgo7JsJT\n"
    "lz1BKsZ6R/g1VkOG2O3gjtpsBvQP76GBvAIBA6BRoU8wCQYHKoZIzj0CAQNCAARK\n"
    "IUu+0ajO2FrQaWP+PyJ628VkLE3+iTqgnBjHFF1zpbGWzPDQxCTHOxux2ZEO0Qcw\n"
    "2VGnrmGQnkU7r+USg8aJMBgGCSuBBRCGSD8AAjALBglghkgBZQMEAQUwSjBIMCww\n"
    "JzEQMA4GA1UECgwHRXhhbXBsZTETMBEGA1UEAwwKU01JTUUgUm9vdAIBZgQYxjxa\n"
    "SJ440P1ZCQPZRmKZOwtyj10BMTy/MFwGCSqGSIb3DQEHATAdBglghkgBZQMEAQIE\n"
    "EDQ1NA5TAK36Q7aKeS5hvruAMNjTvQpKkgwoSTT/s0+AY3n7sYvQL3386atpWgPN\n"
    "NByOp9gg+bmPSVZjgxA/VYYdEg==\n"
    "-----END CMS-----\n";
static const char msg[] = "Hello, S/MIME.\nSecond line  \r\n\nlast";
static const unsigned char kek[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
static const unsigned char kekid[3] = { 10, 11, 12 };

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

/* A copy through DER, so that each decryption starts afresh. */
static CMS_ContentInfo *redo(CMS_ContentInfo *cms)
{
    unsigned char *d = NULL;
    const unsigned char *p;
    int n = i2d_CMS_ContentInfo(cms, &d);
    CMS_ContentInfo *out;

    p = d;
    out = n > 0 ? d2i_CMS_ContentInfo(NULL, &p, n) : NULL;
    OPENSSL_free(d);
    return out;
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

/* Whether the BIO holds the message. */
static int is_msg(BIO *out)
{
    char *p = NULL;
    long n = BIO_get_mem_data(out, &p);

    return n == (long)strlen(msg) && memcmp(p, msg, (size_t)n) == 0;
}

/* Decrypts with CMS_decrypt into a memory BIO; whether that gave the message. */
static int decrypts(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *x, unsigned int flags)
{
    BIO *out = BIO_new(BIO_s_mem());
    int r = CMS_decrypt(cms, pk, x, NULL, out, flags);
    int ok = r == 1 && is_msg(out);

    printf("  CMS_decrypt %d, message %s\n", r, is_msg(out) ? "yes" : "no");
    BIO_free(out);
    return ok;
}

/* The data path alone, after a key was set: whether it gave the message. */
static int data_path(CMS_ContentInfo *cms)
{
    return decrypts(cms, NULL, NULL, 0);
}

static void show(CMS_ContentInfo *cms)
{
    STACK_OF(CMS_RecipientInfo) *ris = CMS_get0_RecipientInfos(cms);
    int i, j;

    printf("  type %s, recipients %d\n", oid(CMS_get0_type(cms)), sk_CMS_RecipientInfo_num(ris));
    for (i = 0; i < sk_CMS_RecipientInfo_num(ris); i++) {
        CMS_RecipientInfo *ri = sk_CMS_RecipientInfo_value(ris, i);
        int t = CMS_RecipientInfo_type(ri);

        printf("  %d: type %d, pkey ctx %s\n", i, t, CMS_RecipientInfo_get0_pkey_ctx(ri) ? "set" : "none");
        if (t == CMS_RECIPINFO_TRANS) {
            EVP_PKEY *pk = NULL;
            X509 *rc = NULL;
            X509_ALGOR *alg = NULL;
            ASN1_OCTET_STRING *keyid = NULL;
            X509_NAME *issuer = NULL;
            ASN1_INTEGER *sno = NULL;

            CMS_RecipientInfo_ktri_get0_algs(ri, &pk, &rc, &alg);
            printf("    key transport %s, key %s, cert %s\n", oid(alg->algorithm), pk ? "set" : "none", rc ? "set" : "none");
            printf("    id %d:", CMS_RecipientInfo_ktri_get0_signer_id(ri, &keyid, &issuer, &sno));
            if (keyid != NULL)
                printf(" key id %d octets", ASN1_STRING_length(keyid));
            if (sno != NULL)
                printf(" serial %ld", ASN1_INTEGER_get(sno));
            printf("\n");
        } else if (t == CMS_RECIPINFO_AGREE) {
            X509_ALGOR *alg = NULL, *pubalg = NULL;
            ASN1_OCTET_STRING *ukm = NULL, *keyid = NULL;
            ASN1_BIT_STRING *pub = NULL;
            X509_NAME *issuer = NULL;
            ASN1_INTEGER *sno = NULL;
            STACK_OF(CMS_RecipientEncryptedKey) *reks = CMS_RecipientInfo_kari_get0_reks(ri);

            CMS_RecipientInfo_kari_get0_alg(ri, &alg, &ukm);
            printf("    key agreement %s, ukm %s, ctx %s\n", oid(alg->algorithm), ukm ? "set" : "none",
                   CMS_RecipientInfo_kari_get0_ctx(ri) ? "set" : "none");
            printf("    originator %d:", CMS_RecipientInfo_kari_get0_orig_id(ri, &pubalg, &pub, &keyid, &issuer, &sno));
            if (pubalg != NULL)
                printf(" %s", oid(pubalg->algorithm));
            if (pub != NULL)
                printf(" public key %s", ASN1_STRING_length(pub) > 0 ? "set" : "empty");
            if (keyid != NULL)
                printf(" key id");
            if (sno != NULL)
                printf(" serial %ld", ASN1_INTEGER_get(sno));
            printf("\n    encrypted keys %d:", sk_CMS_RecipientEncryptedKey_num(reks));
            for (j = 0; j < sk_CMS_RecipientEncryptedKey_num(reks); j++) {
                CMS_RecipientEncryptedKey *rek = sk_CMS_RecipientEncryptedKey_value(reks, j);
                ASN1_OCTET_STRING *rkid = NULL;
                ASN1_GENERALIZEDTIME *tm = NULL;
                CMS_OtherKeyAttribute *other = NULL;

                issuer = NULL;
                sno = NULL;
                printf(" id %d", CMS_RecipientEncryptedKey_get0_id(rek, &rkid, &tm, &other, &issuer, &sno));
                if (rkid != NULL)
                    printf(" key id %d octets", ASN1_STRING_length(rkid));
                if (sno != NULL)
                    printf(" serial %ld", ASN1_INTEGER_get(sno));
            }
            printf("\n");
        } else if (t == CMS_RECIPINFO_KEK) {
            X509_ALGOR *alg = NULL;
            ASN1_OCTET_STRING *id = NULL;
            ASN1_GENERALIZEDTIME *date = NULL;
            ASN1_OBJECT *otherid = NULL;
            ASN1_TYPE *othertype = NULL;

            printf("    kek %d:", CMS_RecipientInfo_kekri_get0_id(ri, &alg, &id, &date, &otherid, &othertype));
            printf(" %s, id %d octets, date %s, other %s/%s\n", oid(alg->algorithm), ASN1_STRING_length(id),
                   date ? "set" : "none", otherid ? oid(otherid) : "none", othertype ? "set" : "none");
        }
    }
}

static int sign_of(int r)
{
    return r < 0 ? -1 : r > 0 ? 1 : 0;
}

/* The EnvelopedData inside a ContentInfo's DER: SEQUENCE { OID, [0] { EnvelopedData } }. */
static CMS_EnvelopedData *inner_env(CMS_ContentInfo *cms)
{
    unsigned char *d = NULL;
    const unsigned char *p, *end;
    long len;
    int tag, xclass, n = i2d_CMS_ContentInfo(cms, &d);
    CMS_EnvelopedData *env = NULL;

    p = d;
    end = d + n;
    if (n > 0 && ASN1_get_object(&p, &len, &tag, &xclass, n) == V_ASN1_CONSTRUCTED) {
        ASN1_OBJECT *o = d2i_ASN1_OBJECT(NULL, &p, end - p);

        ASN1_OBJECT_free(o);
        if (ASN1_get_object(&p, &len, &tag, &xclass, end - p) == V_ASN1_CONSTRUCTED)
            env = (CMS_EnvelopedData *)ASN1_item_d2i(NULL, &p, len, ASN1_ITEM_rptr(CMS_EnvelopedData));
    }
    OPENSSL_free(d);
    return env;
}

int main(void)
{
    X509 *rsa = cert(RSA_PEM), *ec = cert(EC_PEM), *dh = cert(DH_PEM);
    EVP_PKEY *rsa_key = key(RSA_KEY_PEM), *ec_key = key(EC_KEY_PEM), *dh_key = key(DH_KEY_PEM);
    STACK_OF(X509) *certs = sk_X509_new_null();
    CMS_ContentInfo *cms, *c2;
    STACK_OF(CMS_RecipientInfo) *ris;
    CMS_RecipientInfo *ri;
    BIO *in, *out;
    int r;

    setvbuf(stdout, NULL, _IONBF, 0);
    check(rsa && ec && dh && rsa_key && ec_key && dh_key, "fixtures");

    /* The reference's envelopes, by key and certificate, and by key alone. */
    cms = load(REF_RSA);
    show(cms);
    check(decrypts(cms, rsa_key, rsa, 0), "RSA, with its certificate");
    CMS_ContentInfo_free(cms);
    cms = load(REF_RSA);
    check(decrypts(cms, rsa_key, NULL, 0), "RSA, without a certificate");
    CMS_ContentInfo_free(cms);
    cms = load(REF_KEYID);
    show(cms);
    check(decrypts(cms, rsa_key, rsa, 0), "RSA by key identifier");
    CMS_ContentInfo_free(cms);
    cms = load(REF_OAEP);
    show(cms);
    check(decrypts(cms, rsa_key, rsa, CMS_DEBUG_DECRYPT), "RSA-OAEP with SHA-256 and a label");
    CMS_ContentInfo_free(cms);
    cms = load(REF_EC);
    show(cms);
    check(decrypts(cms, ec_key, ec, 0), "ECDH with AES key wrap");
    CMS_ContentInfo_free(cms);
    cms = load(REF_EC);
    check(decrypts(cms, ec_key, NULL, 0), "ECDH without a certificate");
    CMS_ContentInfo_free(cms);
    cms = load(REF_EC3DES);
    show(cms);
    check(decrypts(cms, ec_key, ec, 0), "ECDH with triple DES key wrap");
    CMS_ContentInfo_free(cms);
    cms = load(REF_DH);
    show(cms);
    check(decrypts(cms, dh_key, dh, 0), "X9.42 DH");
    CMS_ContentInfo_free(cms);
    cms = load(REF_GCM);
    show(cms);
    check(decrypts(cms, ec_key, ec, 0), "AES-GCM AuthEnvelopedData, by ECDH");
    CMS_ContentInfo_free(cms);
    cms = load(REF_GCM);
    check(decrypts(cms, rsa_key, rsa, 0), "AES-GCM AuthEnvelopedData, by RSA");
    CMS_ContentInfo_free(cms);
    cms = load(REF_MULTI);
    show(cms);
    check(decrypts(cms, rsa_key, rsa, 0), "two recipients, the first");
    CMS_ContentInfo_free(cms);
    cms = load(REF_MULTI);
    check(decrypts(cms, ec_key, NULL, 0), "two recipients, the second, without a certificate");
    CMS_ContentInfo_free(cms);

    /* Wrong keys and certificates. */
    cms = load(REF_RSA);
    r = decrypts(cms, rsa_key, ec, CMS_DEBUG_DECRYPT);
    errors();
    check(!r, "the wrong certificate finds no recipient");
    CMS_ContentInfo_free(cms);
    cms = load(REF_EC);
    r = decrypts(cms, rsa_key, NULL, 0);
    errors();
    check(!r, "an RSA key for an ECDH recipient");
    CMS_ContentInfo_free(cms);
    cms = load(REF_EC);
    r = decrypts(cms, dh_key, NULL, 0);
    errors();
    check(!r, "a DH key for an ECDH recipient");
    CMS_ContentInfo_free(cms);
    in = mem(msg);
    cms = CMS_data_create(in, CMS_BINARY);
    BIO_free(in);
    r = decrypts(cms, rsa_key, rsa, 0);
    errors();
    check(!r, "Data is not enveloped");
    printf("  recipient infos %s\n", CMS_get0_RecipientInfos(cms) == NULL ? "none" : "set");
    errors();
    CMS_ContentInfo_free(cms);

    /* KEK. */
    cms = load(REF_KEK);
    show(cms);
    ri = sk_CMS_RecipientInfo_value(CMS_get0_RecipientInfos(cms), 0);
    printf("  id cmp: same %d, other %d, shorter %d\n", CMS_RecipientInfo_kekri_id_cmp(ri, kekid, 3),
           sign_of(CMS_RecipientInfo_kekri_id_cmp(ri, kek, 3)), sign_of(CMS_RecipientInfo_kekri_id_cmp(ri, kekid, 2)));
    r = CMS_decrypt_set1_key(cms, (unsigned char *)kek, 16, kekid, 3);
    printf("  CMS_decrypt_set1_key %d\n", r);
    check(r == 1 && data_path(cms), "KEK by its id");
    CMS_ContentInfo_free(cms);
    cms = load(REF_KEK);
    r = CMS_decrypt_set1_key(cms, (unsigned char *)kek, 16, NULL, 0);
    check(r == 1 && data_path(cms), "KEK without an id");
    CMS_ContentInfo_free(cms);
    cms = load(REF_KEK);
    r = CMS_decrypt_set1_key(cms, (unsigned char *)kek, 16, kek, 3);
    printf("  CMS_decrypt_set1_key %d\n", r);
    errors();
    check(r == 0, "KEK with the wrong id");
    r = CMS_decrypt_set1_key(cms, (unsigned char *)kek, 24, NULL, 0);
    printf("  CMS_decrypt_set1_key %d\n", r);
    errors();
    check(r == 0, "KEK of the wrong length");
    ri = sk_CMS_RecipientInfo_value(CMS_get0_RecipientInfos(cms), 0);
    check(CMS_RecipientInfo_set0_key(ri, (unsigned char *)kek, 16) == 1 && CMS_RecipientInfo_decrypt(cms, ri) == 1,
          "CMS_RecipientInfo_set0_key and _decrypt");
    CMS_RecipientInfo_set0_key(ri, NULL, 0);
    check(data_path(cms), "then the data path");
    printf("  on a KEK recipient: ktri_get0_algs %d, ktri_cert_cmp %d, kari_get0_alg %d, kari_orig_id_cmp %d,"
           " set0_pkey %d, set0_password %d\n",
           CMS_RecipientInfo_ktri_get0_algs(ri, NULL, NULL, NULL), CMS_RecipientInfo_ktri_cert_cmp(ri, rsa),
           CMS_RecipientInfo_kari_get0_alg(ri, NULL, NULL), CMS_RecipientInfo_kari_orig_id_cmp(ri, ec),
           CMS_RecipientInfo_set0_pkey(ri, NULL), CMS_RecipientInfo_set0_password(ri, NULL, 0));
    errors();
    CMS_ContentInfo_free(cms);

    /* Passwords. */
    cms = load(REF_PWRI);
    show(cms);
    r = CMS_decrypt_set1_password(cms, (unsigned char *)"hunter2", -1);
    printf("  CMS_decrypt_set1_password %d\n", r);
    check(r == 1 && data_path(cms), "a password");
    CMS_ContentInfo_free(cms);
    cms = load(REF_PWRI);
    r = CMS_decrypt_set1_password(cms, (unsigned char *)"hunter3", 7);
    printf("  CMS_decrypt_set1_password %d\n", r);
    errors();
    check(r == 0, "the wrong password");
    ri = sk_CMS_RecipientInfo_value(CMS_get0_RecipientInfos(cms), 0);
    check(CMS_RecipientInfo_set0_password(ri, (unsigned char *)"hunter2", 7) == 1
          && CMS_RecipientInfo_decrypt(cms, ri) == 1, "CMS_RecipientInfo_set0_password and _decrypt");
    CMS_RecipientInfo_set0_password(ri, NULL, 0);
    check(data_path(cms), "then the data path");
    printf("  on a password recipient: set0_key %d, kekri_id_cmp %d, kekri_get0_id %d\n",
           CMS_RecipientInfo_set0_key(ri, NULL, 0), CMS_RecipientInfo_kekri_id_cmp(ri, kekid, 3),
           CMS_RecipientInfo_kekri_get0_id(ri, NULL, NULL, NULL, NULL, NULL));
    errors();
    CMS_ContentInfo_free(cms);
    cms = load(REF_RSA);
    printf("  CMS_decrypt_set1_password on RSA %d, CMS_decrypt_set1_key %d\n",
           CMS_decrypt_set1_password(cms, (unsigned char *)"x", 1), CMS_decrypt_set1_key(cms, (unsigned char *)kek, 16, NULL, 0));
    errors();
    CMS_ContentInfo_free(cms);

    /* Recipients by hand: key transport. */
    cms = load(REF_MULTI);
    ris = CMS_get0_RecipientInfos(cms);
    ri = sk_CMS_RecipientInfo_value(ris, 0);
    printf("  ktri_cert_cmp: rsa %d, ec %d\n", CMS_RecipientInfo_ktri_cert_cmp(ri, rsa), CMS_RecipientInfo_ktri_cert_cmp(ri, ec) != 0);
    EVP_PKEY_up_ref(rsa_key);
    check(CMS_RecipientInfo_set0_pkey(ri, rsa_key) == 1 && CMS_RecipientInfo_decrypt(cms, ri) == 1,
          "CMS_RecipientInfo_set0_pkey and _decrypt");
    CMS_RecipientInfo_set0_pkey(ri, NULL);
    printf("  again without a key %d\n", CMS_RecipientInfo_decrypt(cms, ri));
    errors();
    check(data_path(cms), "then the data path");
    printf("  on a key-transport recipient: kari_get0_reks %s, kari_get0_ctx %s, kari_orig_id_cmp %d, kekri_id_cmp %d\n",
           CMS_RecipientInfo_kari_get0_reks(ri) ? "set" : "none", CMS_RecipientInfo_kari_get0_ctx(ri) ? "set" : "none",
           CMS_RecipientInfo_kari_orig_id_cmp(ri, ec), CMS_RecipientInfo_kekri_id_cmp(ri, kekid, 3));
    errors();
    CMS_ContentInfo_free(cms);

    /* Key agreement. */
    cms = load(REF_MULTI);
    ris = CMS_get0_RecipientInfos(cms);
    ri = sk_CMS_RecipientInfo_value(ris, 1);
    {
        STACK_OF(CMS_RecipientEncryptedKey) *reks = CMS_RecipientInfo_kari_get0_reks(ri);
        CMS_RecipientEncryptedKey *rek = sk_CMS_RecipientEncryptedKey_value(reks, 0);

        printf("  rek cert_cmp: ec %d, rsa %d; orig_id_cmp %d\n", CMS_RecipientEncryptedKey_cert_cmp(rek, ec),
               CMS_RecipientEncryptedKey_cert_cmp(rek, rsa) != 0, CMS_RecipientInfo_kari_orig_id_cmp(ri, ec));
        check(CMS_RecipientInfo_kari_set0_pkey(ri, ec_key) == 1 && CMS_RecipientInfo_kari_decrypt(cms, ri, rek) == 1,
              "CMS_RecipientInfo_kari_set0_pkey and _kari_decrypt");
        CMS_RecipientInfo_kari_set0_pkey(ri, NULL);
        check(data_path(cms), "then the data path");
        printf("  decrypt on a key-agreement recipient %d\n", CMS_RecipientInfo_decrypt(cms, ri));
        errors();
        r = CMS_RecipientInfo_kari_set0_pkey_and_peer(ri, ec_key, ec);
        printf("  set0_pkey_and_peer %d, then kari_decrypt with the wrong peer %d\n", r,
               CMS_RecipientInfo_kari_decrypt(cms, ri, rek));
        ERR_clear_error();
        CMS_RecipientInfo_kari_set0_pkey(ri, NULL);
    }
    CMS_ContentInfo_free(cms);
    cms = load(REF_EC);
    r = CMS_decrypt_set1_pkey_and_peer(cms, ec_key, ec, NULL);
    check(r == 1 && data_path(cms), "CMS_decrypt_set1_pkey_and_peer");
    CMS_ContentInfo_free(cms);
    cms = load(REF_EC);
    r = CMS_decrypt_set1_pkey(cms, ec_key, rsa);
    printf("  CMS_decrypt_set1_pkey with another's certificate %d\n", r);
    errors();
    check(r == 0, "the certificate names no encrypted key");
    CMS_ContentInfo_free(cms);
    cms = load(REF_EC);
    check(CMS_decrypt(cms, NULL, NULL, NULL, NULL, 0) == 1, "CMS_decrypt with nothing to do");
    CMS_ContentInfo_free(cms);

    /* Re-encrypting a content key. */
    cms = load(REF_RSA);
    ri = sk_CMS_RecipientInfo_value(CMS_get0_RecipientInfos(cms), 0);
    r = CMS_decrypt_set1_pkey(cms, rsa_key, rsa);
    printf("  set1_pkey %d, encrypt without a key %d\n", r, CMS_RecipientInfo_encrypt(cms, ri));
    ERR_clear_error();
    CMS_RecipientInfo_set0_pkey(ri, X509_get_pubkey(rsa));
    check(CMS_RecipientInfo_encrypt(cms, ri) == 1, "CMS_RecipientInfo_encrypt");
    EVP_PKEY_up_ref(rsa_key);
    CMS_RecipientInfo_set0_pkey(ri, rsa_key);
    check(CMS_RecipientInfo_decrypt(cms, ri) == 1, "the re-encrypted key decrypts");
    CMS_RecipientInfo_set0_pkey(ri, NULL);
    check(data_path(cms), "then the data path");
    CMS_ContentInfo_free(cms);

    /* CMS_EnvelopedData_decrypt. */
    cms = load(REF_RSA);
    {
        CMS_EnvelopedData *env = inner_env(cms);

        out = CMS_EnvelopedData_decrypt(env, NULL, rsa_key, rsa, NULL, 0, NULL, NULL);
        check(out != NULL && is_msg(out), "CMS_EnvelopedData_decrypt with a key");
        BIO_free(out);
        ASN1_item_free((ASN1_VALUE *)env, ASN1_ITEM_rptr(CMS_EnvelopedData));
    }
    CMS_ContentInfo_free(cms);
    cms = load(REF_PWRI);
    {
        CMS_EnvelopedData *env = inner_env(cms);
        ASN1_OCTET_STRING *secret = ASN1_OCTET_STRING_new();

        ASN1_OCTET_STRING_set(secret, (const unsigned char *)"hunter2", 7);
        out = CMS_EnvelopedData_decrypt(env, NULL, NULL, NULL, secret, 0, NULL, NULL);
        check(out != NULL && is_msg(out), "CMS_EnvelopedData_decrypt with a password");
        BIO_free(out);
        ASN1_item_free((ASN1_VALUE *)env, ASN1_ITEM_rptr(CMS_EnvelopedData));
        ASN1_OCTET_STRING_free(secret);
    }
    CMS_ContentInfo_free(cms);
    out = CMS_EnvelopedData_decrypt(NULL, NULL, rsa_key, rsa, NULL, 0, NULL, NULL);
    printf("  NULL EnvelopedData %s\n", out ? "set" : "none");
    errors();

    /* A tampered tag. */
    cms = load(REF_GCM);
    {
        unsigned char *d = NULL;
        const unsigned char *p;
        int n = i2d_CMS_ContentInfo(cms, &d);

        d[n - 1] ^= 1;
        p = d;
        c2 = d2i_CMS_ContentInfo(NULL, &p, n);
        OPENSSL_free(d);
    }
    r = decrypts(c2, ec_key, ec, 0);
    ERR_clear_error();
    check(!r, "AES-GCM with a tampered tag");
    CMS_ContentInfo_free(c2);
    CMS_ContentInfo_free(cms);

    /* Made here: CMS_encrypt for each kind of key. */
    sk_X509_push(certs, rsa);
    in = mem(msg);
    cms = CMS_encrypt(certs, in, EVP_aes_128_cbc(), CMS_BINARY);
    BIO_free(in);
    show(cms);
    c2 = redo(cms);
    check(decrypts(c2, rsa_key, rsa, 0), "CMS_encrypt to RSA, round trip");
    CMS_ContentInfo_free(c2);
    CMS_ContentInfo_free(cms);
    in = mem(msg);
    cms = CMS_encrypt(certs, in, EVP_aes_256_cbc(), CMS_BINARY | CMS_USE_KEYID);
    BIO_free(in);
    show(cms);
    c2 = redo(cms);
    check(decrypts(c2, rsa_key, NULL, 0), "by key identifier, round trip");
    CMS_ContentInfo_free(c2);
    CMS_ContentInfo_free(cms);
    sk_X509_pop(certs);
    sk_X509_push(certs, ec);
    sk_X509_push(certs, dh);
    in = mem(msg);
    cms = CMS_encrypt_ex(certs, in, EVP_aes_192_cbc(), CMS_BINARY, NULL, NULL);
    BIO_free(in);
    show(cms);
    c2 = redo(cms);
    check(decrypts(c2, ec_key, ec, 0), "CMS_encrypt_ex to ECDH and DH, by ECDH");
    CMS_ContentInfo_free(c2);
    c2 = redo(cms);
    check(decrypts(c2, dh_key, dh, 0), "by DH");
    CMS_ContentInfo_free(c2);
    CMS_ContentInfo_free(cms);
    in = mem(msg);
    cms = CMS_encrypt(certs, in, EVP_des_ede3_cbc(), CMS_BINARY);
    BIO_free(in);
    c2 = redo(cms);
    show(c2);
    check(decrypts(c2, ec_key, NULL, 0), "triple DES to ECDH, round trip");
    CMS_ContentInfo_free(c2);
    CMS_ContentInfo_free(cms);
    sk_X509_push(certs, rsa);
    in = mem(msg);
    cms = CMS_encrypt(certs, in, EVP_aes_256_gcm(), CMS_BINARY);
    BIO_free(in);
    show(cms);
    c2 = redo(cms);
    check(decrypts(c2, rsa_key, rsa, 0), "AES-GCM to three, by RSA");
    CMS_ContentInfo_free(c2);
    c2 = redo(cms);
    check(decrypts(c2, dh_key, dh, 0), "by DH");
    CMS_ContentInfo_free(c2);
    CMS_ContentInfo_free(cms);

    /* RSA-OAEP from the recipient's key context. */
    cms = CMS_EnvelopedData_create(EVP_aes_128_cbc());
    CMS_set_detached(cms, 0);
    ri = CMS_add1_recipient_cert(cms, rsa, CMS_KEY_PARAM);
    check(ri != NULL && CMS_RecipientInfo_get0_pkey_ctx(ri) != NULL, "CMS_KEY_PARAM keeps a key context");
    EVP_PKEY_CTX_set_rsa_padding(CMS_RecipientInfo_get0_pkey_ctx(ri), RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(CMS_RecipientInfo_get0_pkey_ctx(ri), EVP_sha256());
    EVP_PKEY_CTX_set0_rsa_oaep_label(CMS_RecipientInfo_get0_pkey_ctx(ri), OPENSSL_memdup("ab", 2), 2);
    in = mem(msg);
    check(CMS_final(cms, in, NULL, CMS_BINARY) == 1, "CMS_final with OAEP");
    BIO_free(in);
    show(cms);
    c2 = redo(cms);
    check(decrypts(c2, rsa_key, rsa, CMS_DEBUG_DECRYPT), "OAEP, round trip");
    CMS_ContentInfo_free(c2);
    CMS_ContentInfo_free(cms);

    /* KEK and password recipients made here. */
    cms = CMS_EnvelopedData_create_ex(EVP_aes_256_cbc(), NULL, NULL);
    printf("  detached by default %d\n", CMS_is_detached(cms));
    CMS_set_detached(cms, 0);
    {
        ASN1_OBJECT *other = OBJ_nid2obj(NID_pkcs7_data);
        unsigned char *k = OPENSSL_memdup(kek, 16);

        ri = CMS_add0_recipient_key(cms, NID_undef, k, 16, OPENSSL_memdup(kekid, 3), 3, NULL, other, NULL);
        check(ri != NULL, "CMS_add0_recipient_key");
        ri = CMS_add0_recipient_password(cms, 1000, -1, -1, (unsigned char *)OPENSSL_strdup("hunter2"), -1, NULL);
        check(ri != NULL, "CMS_add0_recipient_password");
        k = OPENSSL_memdup(kek, 16);
        printf("  aes192-wrap with 16 octets %s\n", CMS_add0_recipient_key(cms, NID_id_aes192_wrap, k, 16, NULL, 0, NULL, NULL, NULL) ? "set" : "none");
        printf("  20 octets %s\n", CMS_add0_recipient_key(cms, NID_undef, k, 20, NULL, 0, NULL, NULL, NULL) ? "set" : "none");
        printf("  SHA-1 %s\n", CMS_add0_recipient_key(cms, NID_sha1, k, 16, NULL, 0, NULL, NULL, NULL) ? "set" : "none");
        printf("  another wrap %s\n", CMS_add0_recipient_password(cms, 1, NID_aes_128_cbc, -1, NULL, 0, NULL) ? "set" : "none");
        errors();
        OPENSSL_free(k);
    }
    in = mem(msg);
    check(CMS_final(cms, in, NULL, CMS_BINARY) == 1, "CMS_final with KEK and password recipients");
    BIO_free(in);
    show(cms);
    c2 = redo(cms);
    check(CMS_decrypt_set1_key(c2, (unsigned char *)kek, 16, kekid, 3) == 1 && data_path(c2), "the KEK, round trip");
    CMS_ContentInfo_free(c2);
    c2 = redo(cms);
    check(CMS_decrypt_set1_password(c2, (unsigned char *)"hunter2", 7) == 1 && data_path(c2), "the password, round trip");
    CMS_ContentInfo_free(c2);
    CMS_ContentInfo_free(cms);
    in = mem(msg);
    cms = CMS_data_create(in, CMS_BINARY);
    BIO_free(in);
    printf("  a password recipient for Data %s\n",
           CMS_add0_recipient_password(cms, 1, -1, -1, NULL, 0, EVP_aes_128_cbc()) ? "set" : "none");
    printf("  a KEK recipient for Data %s\n", CMS_add0_recipient_key(cms, NID_undef, NULL, 16, NULL, 0, NULL, NULL, NULL) ? "set" : "none");
    printf("  a certificate recipient for Data %s\n", CMS_add1_recipient_cert(cms, rsa, 0) ? "set" : "none");
    errors();
    CMS_ContentInfo_free(cms);

    /* AuthEnvelopedData made here, and its limits. */
    cms = CMS_AuthEnvelopedData_create_ex(EVP_aes_128_gcm(), NULL, NULL);
    CMS_set_detached(cms, 0);
    check(CMS_add1_recipient(cms, ec, NULL, NULL, CMS_USE_KEYID) != NULL, "CMS_add1_recipient, by key identifier");
    in = mem(msg);
    check(CMS_final(cms, in, NULL, CMS_BINARY) == 1, "CMS_final of AuthEnvelopedData");
    BIO_free(in);
    show(cms);
    c2 = redo(cms);
    check(decrypts(c2, ec_key, ec, 0), "AuthEnvelopedData, round trip");
    CMS_ContentInfo_free(c2);
    CMS_ContentInfo_free(cms);
    /* Streamed: the tag, known only once the content is through, goes into the MAC. */
    {
        STACK_OF(X509) *one = sk_X509_new_null();

        sk_X509_push(one, ec);
        cms = CMS_encrypt(one, NULL, EVP_aes_128_gcm(), CMS_STREAM | CMS_BINARY);
        sk_X509_free(one);
    }
    in = mem(msg);
    out = BIO_new(BIO_s_mem());
    r = PEM_write_bio_CMS_stream(out, cms, in, CMS_STREAM | CMS_BINARY);
    errors();
    check(r == 1, "PEM_write_bio_CMS_stream of AuthEnvelopedData");
    BIO_free(in);
    CMS_ContentInfo_free(cms);
    cms = PEM_read_bio_CMS(out, NULL, NULL, NULL);
    BIO_free(out);
    check(cms != NULL && decrypts(cms, ec_key, ec, 0), "streamed AuthEnvelopedData, round trip");
    CMS_ContentInfo_free(cms);
    cms = CMS_AuthEnvelopedData_create(EVP_aes_128_cbc());
    check(CMS_add1_recipient_cert(cms, rsa, 0) != NULL, "AuthEnvelopedData with CBC takes a recipient");
    in = mem(msg);
    r = CMS_final(cms, in, NULL, CMS_BINARY);
    BIO_free(in);
    errors();
    check(r == 0, "but not CBC");
    CMS_ContentInfo_free(cms);
    cms = CMS_EnvelopedData_create(EVP_aes_128_gcm());
    check(CMS_add1_recipient_cert(cms, rsa, 0) != NULL, "EnvelopedData with GCM takes a recipient");
    in = mem(msg);
    r = CMS_final(cms, in, NULL, CMS_BINARY);
    BIO_free(in);
    ERR_clear_error();
    printf("  CMS_final %d\n", r);
    CMS_ContentInfo_free(cms);

    /* An originator's static key, which OpenSSL can't use. */
    cms = CMS_EnvelopedData_create(EVP_aes_128_cbc());
    ri = CMS_add1_recipient(cms, ec, ec_key, ec, 0);
    check(ri != NULL, "CMS_add1_recipient with the originator's key");
    show(cms);
    in = mem(msg);
    r = CMS_final(cms, in, NULL, CMS_BINARY);
    BIO_free(in);
    errors();
    check(r == 0, "static key agreement is refused");
    printf("  originator by key identifier %s\n", CMS_add1_recipient(cms, ec, ec_key, ec, CMS_USE_ORIGINATOR_KEYID) ? "set" : "none");
    printf("  a key without a certificate %s\n", CMS_add1_recipient(cms, ec, ec_key, NULL, 0) ? "set" : "none");
    errors();
    show(cms);
    CMS_ContentInfo_free(cms);

    /* Streaming: the content written later. */
    sk_X509_free(certs);
    certs = sk_X509_new_null();
    sk_X509_push(certs, rsa);
    cms = CMS_encrypt(certs, NULL, EVP_aes_128_cbc(), CMS_BINARY | CMS_PARTIAL);
    check(cms != NULL, "CMS_encrypt with CMS_PARTIAL");
    in = mem(msg);
    check(CMS_final(cms, in, NULL, CMS_BINARY) == 1, "then CMS_final");
    BIO_free(in);
    c2 = redo(cms);
    check(decrypts(c2, rsa_key, rsa, 0), "round trip");
    CMS_ContentInfo_free(c2);
    CMS_ContentInfo_free(cms);
    cms = CMS_encrypt(certs, NULL, NULL, CMS_BINARY | CMS_PARTIAL);
    printf("  no cipher %s\n", cms ? "set" : "none");
    errors();
    CMS_ContentInfo_free(cms);

    sk_X509_free(certs);
    X509_free(rsa);
    X509_free(ec);
    X509_free(dh);
    EVP_PKEY_free(rsa_key);
    EVP_PKEY_free(ec_key);
    EVP_PKEY_free(dh_key);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
