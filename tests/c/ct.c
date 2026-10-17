/*
 * Conformance test for certificate transparency (ct(7), SCT_new(3), o2i_SCT_LIST(3),
 * SCT_validate(3), SCT_print(3), CTLOG_STORE_new(3), CT_POLICY_EVAL_CTX_new(3)): SCT lists
 * embedded in certificates, decoded, encoded, printed (with the logs' names), and validated
 * (valid, without an issuer, against an unknown log, in the future, with a bad signature);
 * SCTs built with the setters and from base64; malformed encodings; logs from base64 and log
 * stores loaded from configuration files (good, missing, without enabled logs, with a bad
 * log, from $CTLOG_FILE); the policy evaluation context; and the X.509 extensions.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ct.h>
#include <openssl/err.h>
#include <openssl/pem.h>
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

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

/*
 * Upstream's test material (test/certs/embeddedSCTs*.pem, test/ct/log_list.cnf, OpenSSL's,
 * Apache-2.0): certificates with one and three embedded SCTs, their issuers, and the logs.
 */
static const char EMBEDDEDSCTS1_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIID+TCCAuGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJHQjEk\n"
    "MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX\n"
    "YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAgFw0yMDAxMjUxMTUwMTNaGA8yMTIwMDEy\n"
    "NjExNTAxM1owGTEXMBUGA1UEAwwOc2VydmVyLmV4YW1wbGUwggEiMA0GCSqGSIb3\n"
    "DQEBAQUAA4IBDwAwggEKAoIBAQC4iOkDj+IKkMDaaPLAjnMbogFfps1xFBgOwHsK\n"
    "/RWic1e0kHBfEwQ0/iNWm8SZaknmIwGScYdX5dYGSeBhqlzMixjgsafpoxTrJIAE\n"
    "FVCk05BJF9PjzEYY9H2bM4Eb/KmWakU5WrWP5vrmWyS8BcphosWkWfehj+kFJ1wI\n"
    "0E/wvKlVcAlvcioRewEv8SuAcb1uAhE/xXEEBqvILPvuQvMBeR8cvYt9IYh8043I\n"
    "QoHfEj3hLgt6i45KhYvVWQR8mzzu8bgbnGhfDco4fKK55BRSUye7yn4HHTE9Uo8S\n"
    "wuN7dH2TSsZrlxrt1cCf1TKkoqnbnHg1emeMZfm3FURh82+pAgMBAAGjggEMMIIB\n"
    "CDAdBgNVHQ4EFgQUtMa8XD5ylrF9AqCdnPEhXa63H2owHwYDVR0jBBgwFoAUX52I\n"
    "Dchz5lTU+A3Y5rDBJLRHw1UwCQYDVR0TBAIwADATBgNVHSUEDDAKBggrBgEFBQcD\n"
    "ATCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN8cLsEVAJRSR6lhaDJd3Fx5Wej3xtOI\n"
    "/AAuC70/dNdkAAABb15m6AAAAAQDAEcwRQIgVVLvhQAex2omlFnb+MczYTjvUETM\n"
    "SW6EeAIxPuicWWcCIQCYJYPr1uLeBMcq2RJCtoWgs/F0BsfUFnhJk/lav8NoNDAZ\n"
    "BgNVHREEEjAQgg5zZXJ2ZXIuZXhhbXBsZTANBgkqhkiG9w0BAQsFAAOCAQEATRog\n"
    "ZfvqRl9hMgYODL8VVRJNgqQqKVLCGME4ksBudWKPO0ulfD+de81WCFEHINBu2sPa\n"
    "NSs3YHv/5eaw0tJAd4lPGGhGCl/qEIqQxN6wKcenIWu2M4QzsH6V4D7IuR+OUZCC\n"
    "vNN//NpdIH1KbNGViQCw7o5ClL1+ow0MT+PuzGCI7LkdHTJzyoftzGSHqF/DzDDd\n"
    "uO4ez6fQR4aj/CvQ6UZAy8ihYc2B+dz6NR/nGdCkIs7eEWISOxCgmH8NAJLgPOaU\n"
    "Odw3qk4hXEyTiPkMsSjl9QSfQi5s6d9rbEuQ22ow6H092n7Du15AZS4kKlHxDa5s\n"
    "G8vj2f3xch0fyx+c+w==\n"
    "-----END CERTIFICATE-----\n";

static const char EMBEDDEDSCTS1_ISSUER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIID1zCCAr+gAwIBAgIBADANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJHQjEk\n"
    "MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX\n"
    "YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAgFw0yMjA2MDExMDM4MDJaGA8yMTIyMDUw\n"
    "ODEwMzgwMlowVTELMAkGA1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRy\n"
    "YW5zcGFyZW5jeSBDQTEOMAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW4w\n"
    "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBySP0M2GKef2BSK8HlM05\n"
    "by+yfwqflReazxXdOVhDH0jfuZaRps4HmZ5nrbbWKzWgA0mRCT0xm/cmVqn/w/dW\n"
    "3jICayVyVu5Pug6hl2lfzHnKgQMvc+hI0BEuPbk+9ZHsOO13072lO5lxQRt3mC4l\n"
    "13Dk+PccDRDtr7m0c5JYbrenekVk43K2JzAFVZ+8GQwdtaQDyDoQO8BsqbPbqvkV\n"
    "CV+w7D/RToI/SgkqSEkdJyEVgbwiyN+RXctc1sLBXif284LHhxk1TOeNoXS5Sw6P\n"
    "SSa8/RumtVIRcwgbGK2Xhn+9Su5ZpHeY3b8539OeJzHIyiEAqp54bXpArZni5d7z\n"
    "AgMBAAGjga8wgawwHQYDVR0OBBYEFF+diA3Ic+ZU1PgN2OawwSS0R8NVMH0GA1Ud\n"
    "IwR2MHSAFF+diA3Ic+ZU1PgN2OawwSS0R8NVoVmkVzBVMQswCQYDVQQGEwJHQjEk\n"
    "MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX\n"
    "YWxlczEQMA4GA1UEBxMHRXJ3IFdlboIBADAMBgNVHRMEBTADAQH/MA0GCSqGSIb3\n"
    "DQEBCwUAA4IBAQAx4nGkweUG9fE1IpAsRSNoW+OzxWmzhLXHWFslPHe8P7OODW+y\n"
    "t5nUWdAwPej7vGo/y2nF9Y2WbRKwJrAcNFn6rLnrA5nuzH+mOJt5EckajWWU2MqF\n"
    "9nLfQiNsds85//r3ENQ3wfh6hZojvh98o+5mC5AV8JzORyj5NxzDXp5zdf8dt00s\n"
    "D612d/RTFMPPzVK5vYBOoCusafV5qI/c4DYi02B00xtkUj3lFZc5afGpWIbJIarc\n"
    "ESlqR3J66UetqbK4bP/nwQlW3PgZCpJXSHVPuwK3V+4ZTSVd5+FbYVp1DXp/qbq8\n"
    "P6RD7n+MnBgdEH0AFtgQ28effUXaSWDTXxze\n"
    "-----END CERTIFICATE-----\n";

static const char EMBEDDEDSCTS3_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIHvzCCBqegAwIBAgIRANSYNM/GMmLagfa+3OOk63swDQYJKoZIhvcNAQELBQAw\n"
    "gZIxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO\n"
    "BgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMTgwNgYD\n"
    "VQQDEy9DT01PRE8gUlNBIEV4dGVuZGVkIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZl\n"
    "ciBDQTAeFw0xNTEyMDEwMDAwMDBaFw0xODAyMjUyMzU5NTlaMIIBMzEQMA4GA1UE\n"
    "BRMHMzgzMDEzODETMBEGCysGAQQBgjc8AgEDEwJVUzEZMBcGCysGAQQBgjc8AgEC\n"
    "EwhEZWxhd2FyZTEdMBsGA1UEDxMUUHJpdmF0ZSBPcmdhbml6YXRpb24xCzAJBgNV\n"
    "BAYTAlVTMQ4wDAYDVQQREwUwNzAxMzELMAkGA1UECBMCTkoxEDAOBgNVBAcTB0Ns\n"
    "aWZ0b24xEjAQBgNVBAkTCVN1aXRlIDEwMDEXMBUGA1UECRMOMTI1NSBCcm9hZCBT\n"
    "dC4xGjAYBgNVBAoTEUNvbW9kbyBHcm91cCBJbmMuMRYwFAYDVQQLEw1DT01PRE8g\n"
    "RVYgU1NMMRowGAYDVQQLExFDT01PRE8gRVYgU0dDIFNTTDEXMBUGA1UEAxMOd3d3\n"
    "LmNvbW9kby5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5S2RD\n"
    "XGjch2spb10rLVCA4TgeB/TiNLHPczeKMJzIY9qKUGQfcYCTwfWe2E1xBer/i0OX\n"
    "IUca+/Br3HTK2qkNoc/nuFkJJ3ej17A9Kv1EYhsN+2gHobKEy+sMTJyGmFVo98nu\n"
    "V9mmiEWM7Bi0Y6YRVYCOey4K2yUwSK1MOgc10RzbwDsk+P2mvTzvPi8QZzd4I36/\n"
    "xlFFhk39VKY94PorJCzF/6qifmNnIjxMkrmSKJKKQaZu8vgbshqlj3+TkeCtIjdR\n"
    "77OcZuROMFdnKsp8JKAq9bzXmDkwlDmUzxAzgYmAvqCwQvNWtJrm0SeiEkNsoK5F\n"
    "xadrfw6OO7BCGXiNAgMBAAGjggNqMIIDZjAfBgNVHSMEGDAWgBQ52v/KKBSKqHQT\n"
    "CLnkDqnS+n6daTAdBgNVHQ4EFgQURD5zMOsLG6ennQ/aeZZNGofpnSEwDgYDVR0P\n"
    "AQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwNAYDVR0lBC0wKwYIKwYBBQUHAwEGCCsG\n"
    "AQUFBwMCBgorBgEEAYI3CgMDBglghkgBhvhCBAEwRgYDVR0gBD8wPTA7BgwrBgEE\n"
    "AbIxAQIBBQEwKzApBggrBgEFBQcCARYdaHR0cHM6Ly9zZWN1cmUuY29tb2RvLmNv\n"
    "bS9DUFMwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5jb21vZG9jYS5jb20v\n"
    "Q09NT0RPUlNBRXh0ZW5kZWRWYWxpZGF0aW9uU2VjdXJlU2VydmVyQ0EuY3JsMIGH\n"
    "BggrBgEFBQcBAQR7MHkwUQYIKwYBBQUHMAKGRWh0dHA6Ly9jcnQuY29tb2RvY2Eu\n"
    "Y29tL0NPTU9ET1JTQUV4dGVuZGVkVmFsaWRhdGlvblNlY3VyZVNlcnZlckNBLmNy\n"
    "dDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMCUGA1UdEQQe\n"
    "MByCDnd3dy5jb21vZG8uY29tggpjb21vZG8uY29tMIIBfQYKKwYBBAHWeQIEAgSC\n"
    "AW0EggFpAWcAdQBo9pj4H2SCvjqM7rkoHUz8cVFdZ5PURNEKZ6y7T0/7xAAAAVFd\n"
    "vZuJAAAEAwBGMEQCIFgtCr54QYrnialeZiHFahZ53zOFitPzHXGvdTD7zE5FAiBB\n"
    "nIm4gBmHRmwcOpULvvSYddTKSZf9JS7jeLU2MCAmTQB2AFYUBpov18Ls0/XhvUSy\n"
    "PsdGdrm8mRFcwO+UmFXWidDdAAABUV29mSgAAAQDAEcwRQIgeWjpcDhaY/OmsZcO\n"
    "ftDFcRt2BssJY0ge4SDzp+8qTnQCIQCOt7vthV2FG1RePMXs8hOcCdEKAcJZX3wx\n"
    "GaGd4RfHHwB2AKS5CZC0GFgUh7sTosxncAo8NZgE+RvfuON3zQ7IDdwQAAABUV29\n"
    "m5wAAAQDAEcwRQIgKwZCD9lxvSFCpfnFVYPSneWhjbY9pnOJQjKckQ87anQCIQCG\n"
    "7hD5EOZ7F2XZLTdTSjvwrgPkIXY376+0RC4r9VzGkTANBgkqhkiG9w0BAQsFAAOC\n"
    "AQEAHVZgKwtIKcxJg6k5THIICJ63vZyaPJN21HVYPAN/heDUcbYzOqP0F+v+ahj5\n"
    "yNiRhSji/xxcOf5bWT158dHQoMtC1Ld1dI3lttVAvDTgXOApbmc8N0Xpjvapag3r\n"
    "b0IYW5SJio0qn1VxgeSsf0UCBTyw0N8lgbaIr3FHw2SP2rUS8PUixFRK52MYnyEp\n"
    "6Imz730Adl0RgUvp7mzRcWVDK4i6sPRqV6my68XsyaBcQr2qKALQK0Js+mE/0850\n"
    "47USqZ1XjbUke47OPxdlF85uUtIUSGquHTWnxrqy7FLMPIu9HL8XGo3vVlTYCCsb\n"
    "d6V/RWexyzZiHDGA1ToA0Y16Aw==\n"
    "-----END CERTIFICATE-----\n";

static const char EMBEDDEDSCTS3_ISSUER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIGDjCCA/agAwIBAgIQBqdDgNTr/tQ1taP34Wq92DANBgkqhkiG9w0BAQwFADCB\n"
    "hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\n"
    "A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV\n"
    "BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTIwMjEy\n"
    "MDAwMDAwWhcNMjcwMjExMjM1OTU5WjCBkjELMAkGA1UEBhMCR0IxGzAZBgNVBAgT\n"
    "EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR\n"
    "Q09NT0RPIENBIExpbWl0ZWQxODA2BgNVBAMTL0NPTU9ETyBSU0EgRXh0ZW5kZWQg\n"
    "VmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENBMIIBIjANBgkqhkiG9w0BAQEFAAOC\n"
    "AQ8AMIIBCgKCAQEAlVbeVLTf1QJJe9FbXKKyHo+cK2JMK40SKPMalaPGEP0p3uGf\n"
    "CzhAk9HvbpUQ/OGQF3cs7nU+e2PsYZJuTzurgElr3wDqAwB/L3XVKC/sVmePgIOj\n"
    "vdwDmZOLlJFWW6G4ajo/Br0OksxgnP214J9mMF/b5pTwlWqvyIqvgNnmiDkBfBzA\n"
    "xSr3e5Wg8narbZtyOTDr0VdVAZ1YEZ18bYSPSeidCfw8/QpKdhQhXBZzQCMZdMO6\n"
    "WAqmli7eNuWf0MLw4eDBYuPCGEUZUaoXHugjddTI0JYT/8ck0YwLJ66eetw6YWNg\n"
    "iJctXQUL5Tvrrs46R3N2qPos3cCHF+msMJn4HwIDAQABo4IBaTCCAWUwHwYDVR0j\n"
    "BBgwFoAUu69+Aj36pvE8hI6t7jiY7NkyMtQwHQYDVR0OBBYEFDna/8ooFIqodBMI\n"
    "ueQOqdL6fp1pMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMD4G\n"
    "A1UdIAQ3MDUwMwYEVR0gADArMCkGCCsGAQUFBwIBFh1odHRwczovL3NlY3VyZS5j\n"
    "b21vZG8uY29tL0NQUzBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9k\n"
    "b2NhLmNvbS9DT01PRE9SU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDBxBggr\n"
    "BgEFBQcBAQRlMGMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29t\n"
    "L0NPTU9ET1JTQUFkZFRydXN0Q0EuY3J0MCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz\n"
    "cC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQEMBQADggIBAERCnUFRK0iIXZebeV4R\n"
    "AUpSGXtBLMeJPNBy3IX6WK/VJeQT+FhlZ58N/1eLqYVeyqZLsKeyLeCMIs37/3mk\n"
    "jCuN/gI9JN6pXV/kD0fQ22YlPodHDK4ixVAihNftSlka9pOlk7DgG4HyVsTIEFPk\n"
    "1Hax0VtpS3ey4E/EhOfUoFDuPPpE/NBXueEoU/1Tzdy5H3pAvTA/2GzS8+cHnx8i\n"
    "teoiccsq8FZ8/qyo0QYPFBRSTP5kKwxpKrgNUG4+BAe/eiCL+O5lCeHHSQgyPQ0o\n"
    "fkkdt0rvAucNgBfIXOBhYsvss2B5JdoaZXOcOBCgJjqwyBZ9kzEi7nQLiMBciUEA\n"
    "KKlHMd99SUWa9eanRRrSjhMQ34Ovmw2tfn6dNVA0BM7pINae253UqNpktNEvWS5e\n"
    "ojZh1CSggjMziqHRbO9haKPl0latxf1eYusVqHQSTC8xjOnB3xBLAer2VBvNfzu9\n"
    "XJ/B288ByvK6YBIhMe2pZLiySVgXbVrXzYxtvp5/4gJYp9vDLVj2dAZqmvZh+fYA\n"
    "tmnYOosxWd2R5nwnI4fdAw+PKowegwFOAWEMUnNt/AiiuSpm5HZNMaBWm9lTjaK2\n"
    "jwLI5jqmBNFI+8NKAnb9L9K8E7bobTQk+p0pisehKxTxlgBzuRPpwLk6R1YCcYAn\n"
    "pLwltum95OmYdBbxN4SBB7SC\n"
    "-----END CERTIFICATE-----\n";

static const char LOG_LIST_CNF[] =
    "enabled_logs=test,pilot,aviator,rocketeer,digicert,certly,izempe,symantec,venafi\n"
    "\n"
    "# Comment out the next line to ignore configuration errors\n"
    "config_diagnostics = 1\n"
    "\n"
    "[test]\n"
    "description = https://github.com/google/certificate-transparency/tree/99218b6445906a81f219d84e9c6d2683e13e4e58/test/testdata\n"
    "key = MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmXg8sUUzwBYaWrRb+V0IopzQ6o3UyEJ04r5ZrRXGdpYM8K+hB0pXrGRLI0eeWz+3skXrS0IO83AhA3GpRL6s6w==\n"
    "\n"
    "[pilot]\n"
    "description = Google Pilot Log\n"
    "key = MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==\n"
    "\n"
    "[aviator]\n"
    "description = Google Aviator log\n"
    "key = MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==\n"
    "\n"
    "[rocketeer]\n"
    "description = Google Rocketeer log\n"
    "key = MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==\n"
    "\n"
    "[digicert]\n"
    "description = DigiCert Log Server\n"
    "key = MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==\n"
    "\n"
    "[certly]\n"
    "description = Certly.IO log\n"
    "key = MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==\n"
    "\n"
    "[izempe]\n"
    "description = Izempe log\n"
    "key = MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ2Q5DC3cUBj4IQCiDu0s6j51up+TZAkAEcQRF6tczw90rLWXkJMAW7jr9yc92bIKgV8vDXU4lDeZHvYHduDuvg==\n"
    "\n"
    "[symantec]\n"
    "description = Symantec log\n"
    "key = MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg==\n"
    "\n"
    "[venafi]\n"
    "description = Venafi log\n"
    "key = MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWtgnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauCFx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5wQIDAQAB\n";
static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s (%zu):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 ? "\n    " : "", p[i]);
    printf("\n");
}

static BIO *out;

static void flush_out(void)
{
    char *text;
    long len = BIO_get_mem_data(out, &text);

    printf("%.*s\n", (int)len, text);
    (void)BIO_reset(out);
}

static void show_sct(SCT *sct)
{
    unsigned char *p;
    size_t n;

    printf("  version %d, entry %d, source %d, timestamp %llu, nid %d, status %d (%s)\n", SCT_get_version(sct),
           SCT_get_log_entry_type(sct), SCT_get_source(sct), (unsigned long long)SCT_get_timestamp(sct),
           SCT_get_signature_nid(sct), SCT_get_validation_status(sct), SCT_validation_status_string(sct));
    n = SCT_get0_log_id(sct, &p);
    hex("log id", p, n);
    n = SCT_get0_extensions(sct, &p);
    printf("  extensions %zu %s\n", n, p == NULL ? "NULL" : "set");
    n = SCT_get0_signature(sct, &p);
    hex("signature", p, n);
}

static char *write_file(const char *text)
{
    static char names[8][64];
    static int k;
    char *name = names[k++ % 8];
    int fd;

    strcpy(name, "/tmp/rustyssl-ct-XXXXXX");
    fd = mkstemp(name);
    if (fd < 0)
        return NULL;
    if (write(fd, text, strlen(text)) < 0)
        name[0] = '\0';
    close(fd);
    return name;
}

static void validate(const char *label, STACK_OF(SCT) *scts, X509 *cert, X509 *issuer, CTLOG_STORE *store,
                     uint64_t when)
{
    CT_POLICY_EVAL_CTX *ctx = CT_POLICY_EVAL_CTX_new();
    int i, r;

    if (cert != NULL)
        CT_POLICY_EVAL_CTX_set1_cert(ctx, cert);
    if (issuer != NULL)
        CT_POLICY_EVAL_CTX_set1_issuer(ctx, issuer);
    CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ctx, store);
    CT_POLICY_EVAL_CTX_set_time(ctx, when);
    r = SCT_LIST_validate(scts, ctx);
    printf("# validate: %s: %d\n", label, r);
    for (i = 0; i < sk_SCT_num(scts); i++)
        printf("  %d: %s\n", i, SCT_validation_status_string(sk_SCT_value(scts, i)));
    printf("  cert %d, issuer %d, store %d, time %llu\n", CT_POLICY_EVAL_CTX_get0_cert(ctx) == cert,
           CT_POLICY_EVAL_CTX_get0_issuer(ctx) == issuer, CT_POLICY_EVAL_CTX_get0_log_store(ctx) == store,
           (unsigned long long)CT_POLICY_EVAL_CTX_get_time(ctx));
    errors();
    check(1, label);
    CT_POLICY_EVAL_CTX_free(ctx);
}

static void parse(const char *label, const unsigned char *p, size_t n)
{
    const unsigned char *q = p;
    STACK_OF(SCT) *l = o2i_SCT_LIST(NULL, &q, n);

    printf("# o2i_SCT_LIST: %s: %s, %d SCTs, consumed %d\n", label, l == NULL ? "NULL" : "list", sk_SCT_num(l),
           (int)(q - p));
    errors();
    SCT_LIST_free(l);
    q = p;
    {
        SCT *s = o2i_SCT(NULL, &q, n);

        printf("  o2i_SCT: %s, consumed %d\n", s == NULL ? "NULL" : "SCT", (int)(q - p));
        errors();
        SCT_free(s);
    }
    check(1, label);
}

int main(void)
{
    X509 *cert1 = read_cert(EMBEDDEDSCTS1_PEM), *issuer1 = read_cert(EMBEDDEDSCTS1_ISSUER_PEM);
    X509 *cert3 = read_cert(EMBEDDEDSCTS3_PEM), *issuer3 = read_cert(EMBEDDEDSCTS3_ISSUER_PEM);
    STACK_OF(SCT) *scts1, *scts3, *again;
    CTLOG_STORE *store = CTLOG_STORE_new(), *empty = CTLOG_STORE_new();
    char *list = write_file(LOG_LIST_CNF);
    unsigned char *der = NULL, *tls = NULL, buf[2048], *p;
    const unsigned char *q;
    int n, crit, idx;
    uint64_t when = 1700000000000ULL;

    out = BIO_new(BIO_s_mem());
    printf("# load the logs: %d\n", CTLOG_STORE_load_file(store, list));
    errors();
    check(1, "load the logs");

    scts1 = X509_get_ext_d2i(cert1, NID_ct_precert_scts, &crit, NULL);
    scts3 = X509_get_ext_d2i(cert3, NID_ct_precert_scts, &crit, NULL);
    printf("# embedded SCTs: %d and %d, critical %d\n", sk_SCT_num(scts1), sk_SCT_num(scts3), crit);
    show_sct(sk_SCT_value(scts1, 0));
    SCT_LIST_print(scts3, out, 2, "\n--\n", store);
    flush_out();
    SCT_LIST_print(scts1, out, 0, NULL, NULL);
    flush_out();
    check(1, "embedded SCTs");

    printf("# the certificate printed\n");
    X509_print_ex(out, cert3, XN_FLAG_COMPAT, X509_FLAG_NO_PUBKEY | X509_FLAG_NO_SIGDUMP);
    flush_out();
    check(1, "the certificate printed");

    validate("one SCT", scts1, cert1, issuer1, store, when);
    validate("three SCTs", scts3, cert3, issuer3, store, when);
    validate("no issuer", scts1, cert1, NULL, store, when);
    validate("unknown log", scts1, cert1, issuer1, empty, when);
    validate("in the future", scts1, cert1, issuer1, store, 1365094800000ULL);
    validate("wrong issuer", scts1, cert1, issuer3, store, when);
    validate("as an X.509 entry", scts1, cert1, issuer1, store, when);
    SCT_set_source(sk_SCT_value(scts1, 0), SCT_SOURCE_TLS_EXTENSION);
    validate("X.509 entry type", scts1, cert1, issuer1, store, when);
    SCT_set_source(sk_SCT_value(scts1, 0), SCT_SOURCE_X509V3_EXTENSION);
    {
        unsigned char *sig;
        size_t siglen = SCT_get0_signature(sk_SCT_value(scts3, 1), &sig);

        sig[siglen - 1] ^= 1;
        validate("bad signature", scts3, cert3, issuer3, store, when);
        sig[siglen - 1] ^= 1;
    }
    validate("NULL list", NULL, cert1, issuer1, store, when);

    printf("# encodings\n");
    n = i2o_SCT_LIST(scts3, &tls);
    hex("i2o_SCT_LIST", tls, n);
    printf("  length only %d\n", i2o_SCT_LIST(scts3, NULL));
    q = tls;
    again = o2i_SCT_LIST(NULL, &q, n);
    printf("  again: %d SCTs, consumed %d\n", sk_SCT_num(again), (int)(q - tls));
    p = buf;
    printf("  into a buffer: %d, advanced %d\n", i2o_SCT_LIST(again, &p), (int)(p - buf));
    printf("  same %d\n", memcmp(buf, tls, n) == 0);
    q = tls;
    printf("  into the list again: %s, %d SCTs\n", o2i_SCT_LIST(&again, &q, n) == again ? "same" : "other",
           sk_SCT_num(again));
    n = i2d_SCT_LIST(scts1, &der);
    hex("i2d_SCT_LIST", der, n);
    idx = X509_get_ext_by_NID(cert1, NID_ct_precert_scts, -1);
    {
        ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(X509_get_ext(cert1, idx));

        printf("  the extension's value %d\n",
               ASN1_STRING_length(data) == n && memcmp(ASN1_STRING_get0_data(data), der, n) == 0);
    }
    q = der;
    {
        STACK_OF(SCT) *d = d2i_SCT_LIST(NULL, &q, n);

        printf("  d2i: %d SCTs, consumed %d\n", sk_SCT_num(d), (int)(q - der));
        SCT_LIST_free(d);
    }
    n = i2o_SCT(sk_SCT_value(scts1, 0), NULL);
    p = NULL;
    printf("  i2o_SCT %d %d\n", n, i2o_SCT(sk_SCT_value(scts1, 0), &p));
    hex("SCT", p, n);
    {
        SCT *s;

        q = p;
        s = o2i_SCT(NULL, &q, n);
        show_sct(s);
        SCT_free(s);
    }
    OPENSSL_free(p);
    OPENSSL_free(tls);
    OPENSSL_free(der);
    SCT_LIST_free(again);
    errors();
    check(1, "encodings");

    printf("# malformed\n");
    {
        unsigned char m[256];

        memset(m, 0, sizeof(m));
        parse("empty", m, 0);
        parse("one octet", m, 1);
        m[1] = 1;
        parse("list of one octet", m, 3);
        m[1] = 2;
        parse("an empty SCT", m, 4);
        m[1] = 3;
        m[3] = 1;
        parse("an SCT of one octet", m, 5);
        m[1] = 4;
        parse("list length too long", m, 5);
        m[0] = 0;
        m[1] = 45;
        m[2] = 0;
        m[3] = 43;
        parse("a version 1 SCT without a signature", m, 47);
        m[3] = 47;
        m[1] = 49;
        m[2 + 2 + 43] = 4;
        m[2 + 2 + 44] = 3;
        m[2 + 2 + 45] = 0;
        m[2 + 2 + 46] = 9;
        parse("a signature running past its SCT", m, 51);
        m[2 + 2 + 46] = 0;
        m[2 + 2 + 44] = 2;
        parse("an unknown signature algorithm", m, 51);
        m[2 + 2] = 7;
        parse("version 8", m, 51);
        m[2 + 2] = 0;
        m[2 + 2 + 41] = 0;
        m[2 + 2 + 42] = 200;
        parse("extensions running past their SCT", m, 51);
        der = (unsigned char *)"\x04\x03\x00\x01\x00";
        q = der;
        printf("  d2i of a bad list: %s\n", d2i_SCT_LIST(NULL, &q, 5) == NULL ? "NULL" : "list");
        errors();
        q = der;
        printf("  d2i of no DER: %s\n", d2i_SCT_LIST(NULL, &q, 2) == NULL ? "NULL" : "list");
        errors();
    }
    check(1, "malformed");

    printf("# built\n");
    {
        SCT *s = SCT_new();
        unsigned char id[32], *ext = OPENSSL_malloc(3), *sig = OPENSSL_malloc(4);
        STACK_OF(SCT) *one = sk_SCT_new_null();

        memset(id, 0xab, sizeof(id));
        show_sct(s);
        p = NULL;
        printf("  incomplete: %d\n", i2o_SCT(s, &p));
        errors();
        printf("  version 2: %d, version 1: %d\n", SCT_set_version(s, 1), SCT_set_version(s, SCT_VERSION_V1));
        printf("  short id: %d, %d\n", SCT_set1_log_id(s, id, 31), SCT_set0_log_id(s, id, 33));
        printf("  id: %d\n", SCT_set1_log_id(s, id, sizeof(id)));
        printf("  entry types: %d %d %d\n", SCT_set_log_entry_type(s, CT_LOG_ENTRY_TYPE_NOT_SET),
               SCT_set_log_entry_type(s, 7), SCT_set_log_entry_type(s, CT_LOG_ENTRY_TYPE_X509));
        printf("  nids: %d %d %d\n", SCT_set_signature_nid(s, NID_sha1WithRSAEncryption),
               SCT_set_signature_nid(s, NID_sha256WithRSAEncryption), SCT_get_signature_nid(s));
        errors();
        printf("  no signature: %d\n", i2o_SCT(s, NULL));
        memcpy(ext, "\x01\x02\x03", 3);
        memcpy(sig, "\x0a\x0b\x0c\x0d", 4);
        SCT_set0_extensions(s, ext, 3);
        SCT_set0_signature(s, sig, 4);
        SCT_set_timestamp(s, 1234567890123ULL);
        printf("  sources: %d %d\n", SCT_set_source(s, SCT_SOURCE_UNKNOWN), SCT_get_log_entry_type(s));
        printf("  sources: %d %d\n", SCT_set_source(s, SCT_SOURCE_OCSP_STAPLED_RESPONSE), SCT_get_log_entry_type(s));
        show_sct(s);
        p = NULL;
        n = i2o_SCT(s, &p);
        hex("i2o_SCT", p, n);
        OPENSSL_free(p);
        printf("  extensions copied: %d, cleared: %d, signature cleared: %d\n", SCT_set1_extensions(s, id, 2),
               SCT_set1_extensions(s, NULL, 0), SCT_set1_signature(s, id, 0));
        show_sct(s);
        SCT_set1_signature(s, id, 5);
        SCT_set_signature_nid(s, NID_ecdsa_with_SHA256);
        sk_SCT_push(one, s);
        SCT_print(s, out, 4, NULL);
        flush_out();
        p = NULL;
        n = i2d_SCT_LIST(one, &p);
        hex("i2d_SCT_LIST", p, n);
        OPENSSL_free(p);
        SCT_set_timestamp(s, 0xffffffffffffffffULL);
        SCT_print(s, out, 0, store);
        flush_out();
        SCT_set_timestamp(s, 253402300799999ULL);
        SCT_print(s, out, 0, store);
        flush_out();
        SCT_LIST_free(one);
    }
    check(1, "built");

    printf("# from base64\n");
    {
        SCT *s = SCT_new_from_base64(SCT_VERSION_V1, "3xwuwRUAlFJHqWFoMl3cXHlZ6PfG04j8AC4LvT9012Q=",
                                     CT_LOG_ENTRY_TYPE_X509, 1, "",
                                     "BAMARzBAMiBIL2dRrzXbplQ2vh/WZA89v5pBQpSVkkUwKI+j5"
                                     "eI+BgIhAOTtwNs6xXKx4vXoq2poBlOYfc9BAn3+/6EFUZ2J7b8I");

        show_sct(s);
        SCT_print(s, out, 0, store);
        flush_out();
        SCT_free(s);
        errors();
        s = SCT_new_from_base64(1, "AAAA", CT_LOG_ENTRY_TYPE_X509, 1, "", "");
        printf("  version 2: %s\n", s == NULL ? "NULL" : "SCT");
        errors();
        s = SCT_new_from_base64(0, "!!!!", CT_LOG_ENTRY_TYPE_X509, 1, "", "");
        printf("  bad log id: %s\n", s == NULL ? "NULL" : "SCT");
        errors();
        s = SCT_new_from_base64(0, "AAAA", CT_LOG_ENTRY_TYPE_X509, 1, "", "");
        printf("  short log id: %s\n", s == NULL ? "NULL" : "SCT");
        errors();
        s = SCT_new_from_base64(0, "3xwuwRUAlFJHqWFoMl3cXHlZ6PfG04j8AC4LvT9012Q=", CT_LOG_ENTRY_TYPE_X509, 1, "AQID",
                                "BAMAAA==");
        printf("  empty signature: %s\n", s == NULL ? "NULL" : "SCT");
        errors();
        s = SCT_new_from_base64(0, "3xwuwRUAlFJHqWFoMl3cXHlZ6PfG04j8AC4LvT9012Q=", 5, 1, "", "BAMAAQE=");
        printf("  bad entry type: %s\n", s == NULL ? "NULL" : "SCT");
        errors();
    }
    check(1, "from base64");

    printf("# logs\n");
    {
        CTLOG *log = NULL;
        const uint8_t *id;
        size_t idlen;

        printf("  from base64: %d\n",
               CTLOG_new_from_base64(&log, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmXg8sUUzwBYaWrRb+V0IopzQ6o3UyEJ04r5ZrRXGdpYM8K+hB0pXrGRLI0eeWz+3skXrS0IO83AhA3GpRL6s6w==",
                                     "my log"));
        CTLOG_get0_log_id(log, &id, &idlen);
        hex("log id", id, idlen);
        printf("  name %s, key %s\n", CTLOG_get0_name(log), CTLOG_get0_public_key(log) == NULL ? "NULL" : "set");
        printf("  found by id: %s\n", CTLOG_get0_name(CTLOG_STORE_get0_log_by_id(store, id, idlen)));
        printf("  found by a prefix: %s\n", CTLOG_get0_name(CTLOG_STORE_get0_log_by_id(store, id, 4)));
        printf("  found by nothing: %s\n", CTLOG_get0_name(CTLOG_STORE_get0_log_by_id(store, id, 0)));
        printf("  not found: %s\n", CTLOG_STORE_get0_log_by_id(empty, id, idlen) == NULL ? "NULL" : "log");
        CTLOG_free(log);
        log = NULL;
        printf("  not base64: %d\n", CTLOG_new_from_base64(&log, "\01\02\03\04", "x"));
        errors();
        printf("  padding: %d\n", CTLOG_new_from_base64(&log, "====", "x"));
        errors();
        printf("  not a key: %d\n", CTLOG_new_from_base64(&log, "AAAA", "x"));
        errors();
        printf("  no output: %d\n", CTLOG_new_from_base64(NULL, "AAAA", "x"));
        errors();
        {
            EVP_PKEY *k = X509_get_pubkey(issuer1);

            log = CTLOG_new(k, "issuer's key");
            CTLOG_get0_log_id(log, &id, &idlen);
            hex("issuer key id", id, idlen);
            CTLOG_free(log);
        }
    }
    check(1, "logs");

    printf("# log files\n");
    {
        CTLOG_STORE *s = CTLOG_STORE_new();
        char *bad = write_file("enabled_logs = a, b\n[a]\ndescription = A\nkey = MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmXg8sUUzwBYaWrRb+V0IopzQ6o3UyEJ04r5ZrRXGdpYM8K+hB0pXrGRLI0eeWz+3skXrS0IO83AhA3GpRL6s6w==\n[b]\ndescription = B\n");
        char *none = write_file("[a]\ndescription = A\n");
        char *nodesc = write_file("enabled_logs = a\n[a]\nkey = AAAA\n");
        char *empty_list = write_file("enabled_logs =\n");

        printf("  missing file: %d\n", CTLOG_STORE_load_file(s, "/nonexistent/ct_log_list.cnf"));
        errors();
        printf("  a log without a key: %d\n", CTLOG_STORE_load_file(s, bad));
        errors();
        printf("  no enabled logs: %d\n", CTLOG_STORE_load_file(s, none));
        errors();
        printf("  a log without a description: %d\n", CTLOG_STORE_load_file(s, nodesc));
        errors();
        printf("  an empty list: %d\n", CTLOG_STORE_load_file(s, empty_list));
        errors();
        setenv("CTLOG_FILE", list, 1);
        printf("  $CTLOG_FILE: %d\n", CTLOG_STORE_load_default_file(s));
        errors();
        setenv("CTLOG_FILE", "/nonexistent/ct_log_list.cnf", 1);
        printf("  a missing $CTLOG_FILE: %d\n", CTLOG_STORE_load_default_file(s));
        errors();
        CTLOG_STORE_free(s);
        unlink(bad);
        unlink(none);
        unlink(nodesc);
        unlink(empty_list);
    }
    check(1, "log files");

    printf("# the policy context\n");
    {
        CT_POLICY_EVAL_CTX *ctx = CT_POLICY_EVAL_CTX_new();
        uint64_t t = CT_POLICY_EVAL_CTX_get_time(ctx);

        printf("  default time after 2026: %d, cert %s, issuer %s, store %s\n", t > 1767225600000ULL,
               CT_POLICY_EVAL_CTX_get0_cert(ctx) == NULL ? "NULL" : "set",
               CT_POLICY_EVAL_CTX_get0_issuer(ctx) == NULL ? "NULL" : "set",
               CT_POLICY_EVAL_CTX_get0_log_store(ctx) == NULL ? "NULL" : "set");
        CT_POLICY_EVAL_CTX_free(ctx);
        CT_POLICY_EVAL_CTX_free(NULL);
    }
    check(1, "the policy context");

    printf("# extensions\n");
    {
        X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, NULL, NID_ct_precert_poison, "NULL");

        printf("  poison: %s, critical %d\n", ex == NULL ? "NULL" : "made", X509_EXTENSION_get_critical(ex));
        X509V3_EXT_print(out, ex, 0, 4);
        flush_out();
        hex("poison value", ASN1_STRING_get0_data(X509_EXTENSION_get_data(ex)),
            ASN1_STRING_length(X509_EXTENSION_get_data(ex)));
        X509_EXTENSION_free(ex);
        ex = X509V3_EXT_i2d(NID_ct_precert_scts, 0, scts1);
        printf("  SCTs: %s\n", ex == NULL ? "NULL" : "made");
        X509V3_EXT_print(out, ex, 0, 2);
        flush_out();
        X509_EXTENSION_free(ex);
        ex = X509V3_EXT_i2d(NID_ct_cert_scts, 0, scts1);
        {
            STACK_OF(SCT) *o = X509V3_EXT_d2i(ex);

            printf("  OCSP SCTs: %d, source %d, entry %d\n", sk_SCT_num(o), SCT_get_source(sk_SCT_value(o, 0)),
                   SCT_get_log_entry_type(sk_SCT_value(o, 0)));
            SCT_LIST_free(o);
        }
        X509_EXTENSION_free(ex);
        errors();
    }
    check(1, "extensions");

    printf("# library contexts\n");
    {
        CTLOG_STORE *s = CTLOG_STORE_new_ex(NULL, "provider=default");
        CT_POLICY_EVAL_CTX *ctx = CT_POLICY_EVAL_CTX_new_ex(NULL, "provider=default");
        CTLOG *log = NULL;
        EVP_PKEY *k = X509_get_pubkey(issuer1);
        CTLOG *log2 = CTLOG_new_ex(k, "with properties", NULL, "provider=default");
        SCT *one = sk_SCT_value(scts1, 0);

        printf("  load: %d\n", CTLOG_STORE_load_file(s, list));
        printf("  from base64: %d\n",
               CTLOG_new_from_base64_ex(&log, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmXg8sUUzwBYaWrRb+V0IopzQ6o3UyEJ04r5ZrRXGdpYM8K+hB0pXrGRLI0eeWz+3skXrS0IO83AhA3GpRL6s6w==",
                                        "with properties", NULL, "provider=default"));
        printf("  names: %s, %s\n", CTLOG_get0_name(log), CTLOG_get0_name(log2));
        CT_POLICY_EVAL_CTX_set1_cert(ctx, cert1);
        CT_POLICY_EVAL_CTX_set1_issuer(ctx, issuer1);
        CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ctx, s);
        CT_POLICY_EVAL_CTX_set_time(ctx, when);
        printf("  SCT_validate: %d (%s)\n", SCT_validate(one, ctx), SCT_validation_status_string(one));
        SCT_set_version(one, SCT_VERSION_V1);
        CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ctx, empty);
        printf("  SCT_validate, no log: %d (%s)\n", SCT_validate(one, ctx), SCT_validation_status_string(one));
        errors();
        CTLOG_free(log);
        CTLOG_free(log2);
        CT_POLICY_EVAL_CTX_free(ctx);
        CTLOG_STORE_free(s);
    }
    check(1, "library contexts");

    SCT_LIST_free(scts1);
    SCT_LIST_free(scts3);
    SCT_free(NULL);
    SCT_LIST_free(NULL);
    CTLOG_free(NULL);
    CTLOG_STORE_free(NULL);
    CTLOG_STORE_free(store);
    CTLOG_STORE_free(empty);
    X509_free(cert1);
    X509_free(issuer1);
    X509_free(cert3);
    X509_free(issuer3);
    BIO_free(out);
    unlink(list);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
