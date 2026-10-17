/*
 * Conformance test for printing certificates, CRLs, requests, and attribute certificates:
 * X509_print(3), X509_print_ex (name and certificate flags), X509_print_fp,
 * X509_print_ex_fp, X509_signature_print, X509_aux_print, X509_ocspid_print,
 * X509_STORE_CTX_print_verify_cb, X509_CRL_print, X509_CRL_print_ex, X509_CRL_print_fp,
 * X509_REQ_print, X509_REQ_print_ex, X509_REQ_print_fp, X509_ACERT_print, and
 * X509_ACERT_print_ex, on EC, RSA, RSA-PSS, DSA, and Ed25519 certificates, a version 1
 * certificate, negative and long serial numbers, a trusted certificate's auxiliary data,
 * CRLs with and without entries, a request with attributes and requested extensions, and
 * upstream's attribute certificates. The output must be byte-identical.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_acert.h>
#include <openssl/x509_vfy.h>
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
        if ((flags & ERR_TXT_STRING) != 0 && *data != '\0')
            printf("\n  data:\n%s\n", data);
    }
    printf("\n");
}

/*
 * The material, made with the reference's openssl tool: an EC root; end-entity certificates
 * for EC, RSA (a 128-bit serial number), RSA-PSS (serial -5), DSA, and Ed25519 keys with
 * common extensions and an unknown one; a self-signed certificate signed with RSA-PSS; a
 * version 1 certificate; a trusted certificate with uses and an alias; CRLs without and with
 * entries; requests with and without attributes; and upstream's test attribute certificates
 * (test/certs/acert*.pem, OpenSSL's, Apache-2.0).
 */
static const char ROOT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBiTCCAS+gAwIBAgIBATAKBggqhkjOPQQDAjA0MQswCQYDVQQGEwJKUDEQMA4G\n"
    "A1UECgwHRXhhbXBsZTETMBEGA1UEAwwKUHJpbnQgUm9vdDAeFw0yNjEwMTcxOTU5\n"
    "MThaFw00NTEyMTYxOTU5MThaMDQxCzAJBgNVBAYTAkpQMRAwDgYDVQQKDAdFeGFt\n"
    "cGxlMRMwEQYDVQQDDApQcmludCBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"
    "QgAEozrn42QodXhVujnXGnwsoBZ+DVJtL6uK82G4iiRU3+GA+ofmnKdHBgWcqbYM\n"
    "PbPQx0OGK/Azqt27y38n87FxuaMyMDAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E\n"
    "FgQUYoYQTzTLLNBUTfUjg+Jb5FTca1YwCgYIKoZIzj0EAwIDSAAwRQIhAKpM/IAF\n"
    "Zg9aUBF8izXb4vF5rwr0TPlgOc26gEQ6ayvZAiBvOonM0L4da/PaiiM0xkaBJaWp\n"
    "T++QphxXT7jSR/Gqyw==\n"
    "-----END CERTIFICATE-----\n";

static const char EEC_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICZTCCAgugAwIBAgIBAjAKBggqhkjOPQQDAjA0MQswCQYDVQQGEwJKUDEQMA4G\n"
    "A1UECgwHRXhhbXBsZTETMBEGA1UEAwwKUHJpbnQgUm9vdDAeFw0yNjAxMDEwMDAw\n"
    "MDBaFw00NjAxMDEwMDAwMDBaMHMxCzAJBgNVBAYTAkpQMQ4wDAYDVQQIDAVUb2t5\n"
    "bzEWMBQGA1UECgwNRXhhbXBsZSwgSW5jLjEeMAsGA1UECwwEVW5pdDAPBgNVBAMM\n"
    "CFByaW50IEVDMRwwGgYJKoZIhvcNAQkBFg1hQGV4YW1wbGUuY29tMFkwEwYHKoZI\n"
    "zj0CAQYIKoZIzj0DAQcDQgAEozrn42QodXhVujnXGnwsoBZ+DVJtL6uK82G4iiRU\n"
    "3+GA+ofmnKdHBgWcqbYMPbPQx0OGK/Azqt27y38n87FxuaOBzjCByzAJBgNVHRME\n"
    "AjAAMAsGA1UdDwQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\n"
    "LwYDVR0RBCgwJoIPd3d3LmV4YW1wbGUuY29thwTAAAIBgQ1hQGV4YW1wbGUuY29t\n"
    "MB0GA1UdDgQWBBRihhBPNMss0FRN9SOD4lvkVNxrVjAfBgNVHSMEGDAWgBRihhBP\n"
    "NMss0FRN9SOD4lvkVNxrVjAQBgNVHSAECTAHMAUGAyoDBDAPBgMqAwUECAwGY3Vz\n"
    "dG9tMAoGCCqGSM49BAMCA0gAMEUCIA5z1j5HqDY/9g2gAblgUkw8yrDT59nYari7\n"
    "FxzO6RH8AiEAz5Zu+cX8Xmb/OW3KHKZkYwqreWLAFwGs7PnkdFZgyiA=\n"
    "-----END CERTIFICATE-----\n";

static const char ERSA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICXTCCAgKgAwIBAgIQASNFZ4mrze8BI0VniavN7zAKBggqhkjOPQQDAjA0MQsw\n"
    "CQYDVQQGEwJKUDEQMA4GA1UECgwHRXhhbXBsZTETMBEGA1UEAwwKUHJpbnQgUm9v\n"
    "dDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBQxEjAQBgNVBAMMCVBy\n"
    "aW50IFJTQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzFFiVD7CYZcdVOjW\n"
    "3ap1zM5TLBPHzR0YY4qmH1urSFVKJBTkXI8UO3a8tK0F7meJIOHcqMxjk85R3zPu\n"
    "4VBsibjQCvZ16OD74xIj3DJyThBPcM0eXVnSt2mVbIj1e3sG99LVaEiqWtN/FWV2\n"
    "3e5BkV0L1WzImUzj2KRY7LEzvG8CAwEAAaOBzjCByzAJBgNVHRMEAjAAMAsGA1Ud\n"
    "DwQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwLwYDVR0RBCgw\n"
    "JoIPd3d3LmV4YW1wbGUuY29thwTAAAIBgQ1hQGV4YW1wbGUuY29tMB0GA1UdDgQW\n"
    "BBRbIG0xuVl6YC4mF6/UOn6VAMZu7DAfBgNVHSMEGDAWgBRihhBPNMss0FRN9SOD\n"
    "4lvkVNxrVjAQBgNVHSAECTAHMAUGAyoDBDAPBgMqAwUECAwGY3VzdG9tMAoGCCqG\n"
    "SM49BAMCA0kAMEYCIQCn8OzKEQYSwTSjtnEsYTIWGDseJKC7uilBsxMqbT2a0gIh\n"
    "AIrsDe1twI3o+48zxsytYK6XcjXFqHcoShO0fRUezxIV\n"
    "-----END CERTIFICATE-----\n";

static const char EPSS_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICTDCCAfGgAwIBAgIB+zAKBggqhkjOPQQDAjA0MQswCQYDVQQGEwJKUDEQMA4G\n"
    "A1UECgwHRXhhbXBsZTETMBEGA1UEAwwKUHJpbnQgUm9vdDAeFw0yNjAxMDEwMDAw\n"
    "MDBaFw00NjAxMDEwMDAwMDBaMBQxEjAQBgNVBAMMCVByaW50IFBTUzCBnTALBgkq\n"
    "hkiG9w0BAQoDgY0AMIGJAoGBAMIVd0tSty8E55QV186wIk0IJNU5NseNZ0TEu2VV\n"
    "ebr5v8AsO3tu34Kr1LHI0grzpf9/xK986Bg06/ILZinGt5EcUsCQ4yQiCRMRJ04p\n"
    "bgfW0UBpHpol8NUfUT/iB7zd96qMk6AJOiu9TEsmnpyN8j90jAyT76sY6TGfOA2z\n"
    "4m8JAgMBAAGjgc4wgcswCQYDVR0TBAIwADALBgNVHQ8EBAMCB4AwHQYDVR0lBBYw\n"
    "FAYIKwYBBQUHAwEGCCsGAQUFBwMCMC8GA1UdEQQoMCaCD3d3dy5leGFtcGxlLmNv\n"
    "bYcEwAACAYENYUBleGFtcGxlLmNvbTAdBgNVHQ4EFgQUmGf7UNY22+R4brlw9TcB\n"
    "K70Z6AQwHwYDVR0jBBgwFoAUYoYQTzTLLNBUTfUjg+Jb5FTca1YwEAYDVR0gBAkw\n"
    "BzAFBgMqAwQwDwYDKgMFBAgMBmN1c3RvbTAKBggqhkjOPQQDAgNJADBGAiEAhEiK\n"
    "whr60BIV0A4L5/PtIpCv3IobTZ919qGmhERb46ACIQCQblq5l1VANp5/WMi2uF1Z\n"
    "XvXIBfi6MwGMfWXZJbxshg==\n"
    "-----END CERTIFICATE-----\n";

static const char EDSA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDbTCCAxOgAwIBAgIBBDAKBggqhkjOPQQDAjA0MQswCQYDVQQGEwJKUDEQMA4G\n"
    "A1UECgwHRXhhbXBsZTETMBEGA1UEAwwKUHJpbnQgUm9vdDAeFw0yNjAxMDEwMDAw\n"
    "MDBaFw00NjAxMDEwMDAwMDBaMBQxEjAQBgNVBAMMCVByaW50IERTQTCCAb4wggEz\n"
    "BgcqhkjOOAQBMIIBJgKBgQCDCdyKvidfhbPdaFOhviv4W73mDOTLxSz+R6zvsT/L\n"
    "+Ur9AIM4WLOCmEI9CWAnzm4v6cjf2dc7qOXl2tIiT9/AZyfpcC/yvvcjRj8sOCqc\n"
    "xPXauMc6tcqsiRWKla+yuI7HFQhZbOttijvwFXOZTHmmo2Uq+iRn9iQ9thjTjXQ7\n"
    "1wIdAMlO4gomm0Oc+HbVvw1KhEPKMo7ZAGvsbLscZSECgYA2Dsvtg8U8Qqj9H+tZ\n"
    "OVorfNb8xS/V0fskERyCXe7038XpfvZQzsgtG3u7yDZRGY0OZgHnW1dFh332RGbw\n"
    "vckugM5ieNotckmSbwgYMeddMN5eeX7O3ZhOXFKlLWglkzkJDmPpLXIW8ZSxDXGg\n"
    "2HIhMNKpznCVX+yyY+t6I3KUSgOBhAACgYBLwwdid3a3JI8s+r7AhpP7eUS5+utp\n"
    "CfZX3MhF3f/Toqqpl+FgBvjqda6dAvhgnaESRJrDsvWUsTib7ip7XMcD5GSJXBTP\n"
    "V+Uh3ABQhSbrcnQShFnKqJJE6OjF0YYmYEBshMkSwk0aauzVM9SzyYX55mQR9MK4\n"
    "vhz6CqYMceKJdaOBzjCByzAJBgNVHRMEAjAAMAsGA1UdDwQEAwIHgDAdBgNVHSUE\n"
    "FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwLwYDVR0RBCgwJoIPd3d3LmV4YW1wbGUu\n"
    "Y29thwTAAAIBgQ1hQGV4YW1wbGUuY29tMB0GA1UdDgQWBBRbPcUN7h9/x9TIwabX\n"
    "qK4vihxZuDAfBgNVHSMEGDAWgBRihhBPNMss0FRN9SOD4lvkVNxrVjAQBgNVHSAE\n"
    "CTAHMAUGAyoDBDAPBgMqAwUECAwGY3VzdG9tMAoGCCqGSM49BAMCA0gAMEUCIQDO\n"
    "82vrv9JRg6lty9e8UxJY9tBaf5+lLn/MXFjTB+1JnwIgXsq7e5vZuXA7AnGqWaFF\n"
    "RKMp8P4OqZfXVfuftpwSkvA=\n"
    "-----END CERTIFICATE-----\n";

static const char EED_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIB2zCCAYGgAwIBAgIBBTAKBggqhkjOPQQDAjA0MQswCQYDVQQGEwJKUDEQMA4G\n"
    "A1UECgwHRXhhbXBsZTETMBEGA1UEAwwKUHJpbnQgUm9vdDAeFw0yNjAxMDEwMDAw\n"
    "MDBaFw00NjAxMDEwMDAwMDBaMBgxFjAUBgNVBAMMDVByaW50IEVkMjU1MTkwKjAF\n"
    "BgMrZXADIQBfbHby27cV4cEWY7KrGT/baEgXxmMl1+FX5WXQ4/8ua6OBzjCByzAJ\n"
    "BgNVHRMEAjAAMAsGA1UdDwQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB\n"
    "BQUHAwIwLwYDVR0RBCgwJoIPd3d3LmV4YW1wbGUuY29thwTAAAIBgQ1hQGV4YW1w\n"
    "bGUuY29tMB0GA1UdDgQWBBRxNPW9J72+KbE7bAMAFnuEGqdGfjAfBgNVHSMEGDAW\n"
    "gBRihhBPNMss0FRN9SOD4lvkVNxrVjAQBgNVHSAECTAHMAUGAyoDBDAPBgMqAwUE\n"
    "CAwGY3VzdG9tMAoGCCqGSM49BAMCA0gAMEUCIQCcKBVuMxhBt/gnoymB30EwnJZh\n"
    "RWOlCm+wJSpcxZ1F8gIgaBi4NcPIl+s1yLiPt0H4shlR02ojL3nyDwUNtCiu8zo=\n"
    "-----END CERTIFICATE-----\n";

static const char SPSS_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICMzCCAW2gAwIBAgIBBjA8BgkqhkiG9w0BAQowL6APMA0GCWCGSAFlAwQCAQUA\n"
    "oRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAMB8xHTAbBgNVBAMMFFByaW50\n"
    "IFJTQS1QU1MgU2lnbmVkMB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFow\n"
    "HzEdMBsGA1UEAwwUUHJpbnQgUlNBLVBTUyBTaWduZWQwgZ8wDQYJKoZIhvcNAQEB\n"
    "BQADgY0AMIGJAoGBAMxRYlQ+wmGXHVTo1t2qdczOUywTx80dGGOKph9bq0hVSiQU\n"
    "5FyPFDt2vLStBe5niSDh3KjMY5POUd8z7uFQbIm40Ar2dejg++MSI9wyck4QT3DN\n"
    "Hl1Z0rdplWyI9Xt7BvfS1WhIqlrTfxVldt3uQZFdC9VsyJlM49ikWOyxM7xvAgMB\n"
    "AAGjITAfMB0GA1UdDgQWBBRbIG0xuVl6YC4mF6/UOn6VAMZu7DA8BgkqhkiG9w0B\n"
    "AQowL6APMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQC\n"
    "AQUAA4GBAAhlCPF42ekADGPFSmWZ/BT45NWPG7EI5yK98UkCIUBAf84UkuoqBzKJ\n"
    "jd2IMXuVCLufpeqgm+kOlDxhe/TdSVSLIBRIf94hdJ2rI0YFjQ1cZb3o+cH1Yws0\n"
    "4uRDrTcumGiOLywpGUxT1BUmGgpAV+htEmoY5TsUMPKfnMmp0Nsd\n"
    "-----END CERTIFICATE-----\n";

static const char V1_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIByzCCAXGgAwIBAgIBADAKBggqhkjOPQQDAjA0MQswCQYDVQQGEwJKUDEQMA4G\n"
    "A1UECgwHRXhhbXBsZTETMBEGA1UEAwwKUHJpbnQgUm9vdDAeFw0yNjAxMDEwMDAw\n"
    "MDBaFw00NjAxMDEwMDAwMDBaMB8xHTAbBgNVBAMMFFByaW50IFJTQS1QU1MgU2ln\n"
    "bmVkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMUWJUPsJhlx1U6NbdqnXM\n"
    "zlMsE8fNHRhjiqYfW6tIVUokFORcjxQ7dry0rQXuZ4kg4dyozGOTzlHfM+7hUGyJ\n"
    "uNAK9nXo4PvjEiPcMnJOEE9wzR5dWdK3aZVsiPV7ewb30tVoSKpa038VZXbd7kGR\n"
    "XQvVbMiZTOPYpFjssTO8bwIDAQABo0IwQDAdBgNVHQ4EFgQUWyBtMblZemAuJhev\n"
    "1Dp+lQDGbuwwHwYDVR0jBBgwFoAUYoYQTzTLLNBUTfUjg+Jb5FTca1YwCgYIKoZI\n"
    "zj0EAwIDSAAwRQIhAIcMTq2+M3FSGiEppzDFU1/iRy5A+yawz0A1QPfJzJ85AiAX\n"
    "AGiZ5gR4bsEpgWRCkGmpQRVcw+rNd84uIxkdKHd25Q==\n"
    "-----END CERTIFICATE-----\n";

static const char TRUSTED_PEM[] =
    "-----BEGIN TRUSTED CERTIFICATE-----\n"
    "MIICZTCCAgugAwIBAgIBAjAKBggqhkjOPQQDAjA0MQswCQYDVQQGEwJKUDEQMA4G\n"
    "A1UECgwHRXhhbXBsZTETMBEGA1UEAwwKUHJpbnQgUm9vdDAeFw0yNjAxMDEwMDAw\n"
    "MDBaFw00NjAxMDEwMDAwMDBaMHMxCzAJBgNVBAYTAkpQMQ4wDAYDVQQIDAVUb2t5\n"
    "bzEWMBQGA1UECgwNRXhhbXBsZSwgSW5jLjEeMAsGA1UECwwEVW5pdDAPBgNVBAMM\n"
    "CFByaW50IEVDMRwwGgYJKoZIhvcNAQkBFg1hQGV4YW1wbGUuY29tMFkwEwYHKoZI\n"
    "zj0CAQYIKoZIzj0DAQcDQgAEozrn42QodXhVujnXGnwsoBZ+DVJtL6uK82G4iiRU\n"
    "3+GA+ofmnKdHBgWcqbYMPbPQx0OGK/Azqt27y38n87FxuaOBzjCByzAJBgNVHRME\n"
    "AjAAMAsGA1UdDwQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\n"
    "LwYDVR0RBCgwJoIPd3d3LmV4YW1wbGUuY29thwTAAAIBgQ1hQGV4YW1wbGUuY29t\n"
    "MB0GA1UdDgQWBBRihhBPNMss0FRN9SOD4lvkVNxrVjAfBgNVHSMEGDAWgBRihhBP\n"
    "NMss0FRN9SOD4lvkVNxrVjAQBgNVHSAECTAHMAUGAyoDBDAPBgMqAwUECAwGY3Vz\n"
    "dG9tMAoGCCqGSM49BAMCA0gAMEUCIA5z1j5HqDY/9g2gAblgUkw8yrDT59nYari7\n"
    "FxzO6RH8AiEAz5Zu+cX8Xmb/OW3KHKZkYwqreWLAFwGs7PnkdFZgyiAwJzAPBggr\n"
    "BgEFBQcDAQYDKgNjoAoGCCsGAQUFBwMEDAhNeSBBbGlhcw==\n"
    "-----END TRUSTED CERTIFICATE-----\n";

static const char EMPTY_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIHMMHMCAQEwCgYIKoZIzj0EAwIwNDELMAkGA1UEBhMCSlAxEDAOBgNVBAoMB0V4\n"
    "YW1wbGUxEzARBgNVBAMMClByaW50IFJvb3QXDTI2MTAwMTAwMDAwMFoXDTI2MTEw\n"
    "MTAwMDAwMFqgDjAMMAoGA1UdFAQDAgEBMAoGCCqGSM49BAMCA0kAMEYCIQC5ob8/\n"
    "wxaEGqs2qyDSd5N4kisMdrgjFNVLn/u8aTVZpwIhAJxSzuvwOchtr/p5lGRygwQs\n"
    "jGF9OnHW3q0jj0arZiQX\n"
    "-----END X509 CRL-----\n";

static const char FULL_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBQzCB6QIBATAKBggqhkjOPQQDAjA0MQswCQYDVQQGEwJKUDEQMA4GA1UECgwH\n"
    "RXhhbXBsZTETMBEGA1UEAwwKUHJpbnQgUm9vdBcNMjYxMDAxMDAwMDAwWhcNMjYx\n"
    "MTAxMDAwMDAwWjBTMCACAQQXDTI2MTAxNzE5NTkxOFowDDAKBgNVHRUEAwoBBDAv\n"
    "AhABI0VniavN7wEjRWeJq83vFw0yNjEwMTcxOTU5MThaMAwwCgYDVR0VBAMKAQGg\n"
    "LzAtMB8GA1UdIwQYMBaAFGKGEE80yyzQVE31I4PiW+RU3GtWMAoGA1UdFAQDAgEC\n"
    "MAoGCCqGSM49BAMCA0kAMEYCIQDay5A8PEmkp+0HUgpZVuKVmysuci4RPx1HE5/Q\n"
    "LrDejQIhAIJyFFWbqntHWzzF9+HhG4WXg+m5FDiHsFvdUlFNxGKE\n"
    "-----END X509 CRL-----\n";

static const char REQ_CSR[] =
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIIB7jCCAVcCAQAwNzELMAkGA1UEBhMCSlAxEDAOBgNVBAoMB0V4YW1wbGUxFjAU\n"
    "BgNVBAMMDVByaW50IFJlcXVlc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n"
    "AMxRYlQ+wmGXHVTo1t2qdczOUywTx80dGGOKph9bq0hVSiQU5FyPFDt2vLStBe5n\n"
    "iSDh3KjMY5POUd8z7uFQbIm40Ar2dejg++MSI9wyck4QT3DNHl1Z0rdplWyI9Xt7\n"
    "BvfS1WhIqlrTfxVldt3uQZFdC9VsyJlM49ikWOyxM7xvAgMBAAGgdzAVBgkqhkiG\n"
    "9w0BCQcxCAwGc2VjcmV0MCMGCSqGSIb3DQEJAjEWDBRFeGFtcGxlIFVuc3RydWN0\n"
    "dXJlZDA5BgkqhkiG9w0BCQ4xLDAqMBoGA1UdEQQTMBGCD3JlcS5leGFtcGxlLmNv\n"
    "bTAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4GBAGZxLIOr3wdzOkCvn8cV\n"
    "8kXfyDqwnxfC5+ieHc5/WqnMHyhruvmQeWixyCso6V9I7G74s4dkMSu335HoFTSw\n"
    "bDLhG3K1G1yOJC/mmTJBwjdbMOgWg5BxuqTMSSM8Y2CBaDmWmLIZlXtoXdySk2oN\n"
    "zTkkK4iJQw8XYJUoPgx2Ww9I\n"
    "-----END CERTIFICATE REQUEST-----\n";

static const char BARE_CSR[] =
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIHRMHkCAQAwFzEVMBMGA1UEAwwMQmFyZSBSZXF1ZXN0MFkwEwYHKoZIzj0CAQYI\n"
    "KoZIzj0DAQcDQgAEozrn42QodXhVujnXGnwsoBZ+DVJtL6uK82G4iiRU3+GA+ofm\n"
    "nKdHBgWcqbYMPbPQx0OGK/Azqt27y38n87FxuaAAMAoGCCqGSM49BAMCA0gAMEUC\n"
    "ID8ylcq7lxYcQIbCT2UkN1wQVJySv5NKqAcZ6kt0Tuk3AiEAi7rBKUrsR+LjSK5T\n"
    "lxhV+4Yp08PEry907a3JGyKRiaU=\n"
    "-----END CERTIFICATE REQUEST-----\n";

static const char ACERT_PEM[] =
    "-----BEGIN ATTRIBUTE CERTIFICATE-----\n"
    "MIID4zCCAssCAQEwOaA3MB+kHTAbMRkwFwYDVQQDDBBUUE0gTWFudWZhY3R1cmVyAhRADHoGLYO7i9GfV2Yz2rrlRFDPSqA6MDikNjA0MQswCQYDVQQGEwJVUzEUMBIGA1UECgwLZXhhbXBsZS5jb20xDzANBgNVBAsMBlBDVGVzdDANBgkqhkiG9w0BAQsFAAIBATAiGA8yMDE4MDEwMTA1MDAwMFoYDzIwMjgwMTAxMDUwMDAwWjCB7TALBgVngQUCEzECMAAwHAYFZ4EFAhExEzARMAkCAQECAQMCARYEBAAAAAEwEgYFZ4EFAhkxCTAHBgVngQUIAjCBlQYHZ4EFBQEHAjGBiTCBhqBkMC8wDgYGZ4EFEgMBBAQAAgABDBJYWVogQ29tcHV0aW5nIEluYy4MATGABkFCQzEyMzAxMA4GBmeBBRIDAQQEAAcAAgwNTm90IFNwZWNpZmllZAwDSEQxgAgxMjM0QUJDRIMB/6IeMBwMCHVuYW1lIC1yDBA2LjUuMC0xNS1nZW5lcmljMBQGBWeBBQIXMQswCQIBAQIBAQIBETCCAScwbwYDVR0jBGgwZoAUl46DRCrPD3GZndkBbbNDngf6ZHChOKQ2MDQxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtleGFtcGxlLmNvbTEPMA0GA1UECwwGUENUZXN0ghRmuv6Ey2JadCAOFysMNOn9CiH45zBBBgNVHSAEOjA4MDYGAioDMDAwLgYIKwYBBQUHAgIwIgwgVENHIFRydXN0ZWQgUGxhdGZvcm0gRW5kb3JzZW1lbnQwcQYDVR0RBGowaKRmMGQxEzARBgZngQUFAQQMB01vZGVsIEExHjAcBgZngQUFAQEMElhZWiBDb21wdXRpbmcgSW5jLjEZMBcGBmeBBQUBBQwNTm90IFNwZWNpZmllZDESMBAGBmeBBQUBBgwGQUJDMTIzMA0GCSqGSIb3DQEBCwUAA4IBAQBKj3TsMcVSu8zFLPwMX5f8SHelruSr0Oi4QCNLwAylo9Oi3loIaIwCRf95+z4SUJjGhyuBBooWP6Io0uWJ43tI7IFHdZ5vMtRIdemD3te+2iYH7OHMzMucsQ3L63n+XHHxhNrMgBOGI9+7Q4Rnvnm7OFFVqSKt5rX0sZFrR12XVD67CA3VC+khyXy1cV/3v95DwWFSHOG2VkiKjDdO2B4WRrK0Cy2J7ZFo0TYtaLNEONABL5nfa9MIXUAgo4hDwhxNSXfirJPgVt8HQNaoQPepHDiZbmRZc38Q1LAUpTxMYDePH0pQDkmI9Tdk+4/CMYhU0CIq6jzRHrOaUwfgNGp9\n"
    "-----END ATTRIBUTE CERTIFICATE-----\n";

static const char ACERT_IETF_PEM[] =
    "-----BEGIN ATTRIBUTE CERTIFICATE-----\n"
    "MIICPTCCASUCAQEwN6AWMBGkDzANMQswCQYDVQQDDAJDQQIBAqEdpBswGTEXMBUG\n"
    "A1UEAwwOc2VydmVyLmV4YW1wbGWgLTArpCkwJzElMCMGA1UEAwwcQXR0cmlidXRl\n"
    "IENlcnRpZmljYXRlIElzc3VlcjANBgkqhkiG9w0BAQsFAAIUA7WQWQKiqrVAIUS4\n"
    "LE/ZgBtfV8IwIhgPMjAyMTA2MTUxMjM1MDBaGA8yMDMxMDYxMzEyMzUwMFowQTAj\n"
    "BggrBgEFBQcKBDEXMBWgCYYHVGVzdHZhbDAIDAZncm91cDEwGgYDVQRIMRMwEaEP\n"
    "gw1hZG1pbmlzdHJhdG9yMCwwHwYDVR0jBBgwFoAUYm7JaGdsZLtTgt0tqoCK2MrI\n"
    "i10wCQYDVR04BAIFADANBgkqhkiG9w0BAQsFAAOCAQEARYpFEjordN68NXSLmDae\n"
    "uruxhw+Zsr9Grom4mqYy/2lAuu58os4xA4Cez9OdkfCZmU9baDBVfMWys7GlCJdg\n"
    "wn5uO5Kk2eiEWsujO/EV4c5eyXSrsUghQZQKfIVsgeut+7WfmDy/+j8ibbxJxJp/\n"
    "KMIoDjBAaMDhhxaCYclm8dJRT9DPba/bCNjuPGeTXslDQSXIfzFDgQkRZ0+Z7s9i\n"
    "enYBmnH4rvW+SX8v5MzfGOu8VtHAKKBEcCbs2qGwYBEUUsCA/LYKSnOwn655wsd9\n"
    "k6KifIGOCVS4ZbK9pDyYcH/6/OmD1eSUwDZsd8CrJYDC31gAu7xqhOsBzR9DL3oD\n"
    "4Q==\n"
    "-----END ATTRIBUTE CERTIFICATE-----\n";

static const char ACERT_BC1_PEM[] =
    "-----BEGIN ATTRIBUTE CERTIFICATE-----\n"
    "MIIHQDCCBqkCAQEwgZChgY2kgYowgYcxHDAaBgkqhkiG9w0BCQEWDW1sb3JjaEB2\n"
    "dC5lZHUxHjAcBgNVBAMTFU1hcmt1cyBMb3JjaCAobWxvcmNoKTEbMBkGA1UECxMS\n"
    "VmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAyMQswCQYDVQQKEwJ2\n"
    "dDELMAkGA1UEBhMCVVMwgYmkgYYwgYMxGzAZBgkqhkiG9w0BCQEWDHNzaGFoQHZ0\n"
    "LmVkdTEbMBkGA1UEAxMSU3VtaXQgU2hhaCAoc3NoYWgpMRswGQYDVQQLExJWaXJn\n"
    "aW5pYSBUZWNoIFVzZXIxEDAOBgNVBAsTB0NsYXNzIDExCzAJBgNVBAoTAnZ0MQsw\n"
    "CQYDVQQGEwJVUzANBgkqhkiG9w0BAQQFAAIBBTAiGA8yMDAzMDcxODE2MDgwMloY\n"
    "DzIwMDMwNzI1MTYwODAyWjCCBU0wggVJBgorBgEEAbRoCAEBMYIFORaCBTU8UnVs\n"
    "ZSBSdWxlSWQ9IkZpbGUtUHJpdmlsZWdlLVJ1bGUiIEVmZmVjdD0iUGVybWl0Ij4K\n"
    "IDxUYXJnZXQ+CiAgPFN1YmplY3RzPgogICA8U3ViamVjdD4KICAgIDxTdWJqZWN0\n"
    "TWF0Y2ggTWF0Y2hJZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5j\n"
    "dGlvbjpzdHJpbmctZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlw\n"
    "ZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjc3RyaW5nIj4KICAg\n"
    "ICAgIENOPU1hcmt1cyBMb3JjaDwvQXR0cmlidXRlVmFsdWU+CiAgICAgPFN1Ympl\n"
    "Y3RBdHRyaWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFt\n"
    "ZXM6dGM6eGFjbWw6MS4wOnN1YmplY3Q6c3ViamVjdC1pZCIgRGF0YVR5cGU9Imh0\n"
    "dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hI3N0cmluZyIgLz4gCiAgICA8\n"
    "L1N1YmplY3RNYXRjaD4KICAgPC9TdWJqZWN0PgogIDwvU3ViamVjdHM+CiAgPFJl\n"
    "c291cmNlcz4KICAgPFJlc291cmNlPgogICAgPFJlc291cmNlTWF0Y2ggTWF0Y2hJ\n"
    "ZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5jdGlvbjpzdHJpbmct\n"
    "ZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlwZT0iaHR0cDovL3d3\n"
    "dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIj4KICAgICAgaHR0cDovL3p1\n"
    "bmkuY3MudnQuZWR1PC9BdHRyaWJ1dGVWYWx1ZT4KICAgICA8UmVzb3VyY2VBdHRy\n"
    "aWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6\n"
    "eGFjbWw6MS4wOnJlc291cmNlOnJlc291cmNlLWlkIiBEYXRhVHlwZT0iaHR0cDov\n"
    "L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIiAvPiAKICAgIDwvUmVz\n"
    "b3VyY2VNYXRjaD4KICAgPC9SZXNvdXJjZT4KICA8L1Jlc291cmNlcz4KICA8QWN0\n"
    "aW9ucz4KICAgPEFjdGlvbj4KICAgIDxBY3Rpb25NYXRjaCBNYXRjaElkPSJ1cm46\n"
    "b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmZ1bmN0aW9uOnN0cmluZy1lcXVhbCI+\n"
    "CiAgICAgPEF0dHJpYnV0ZVZhbHVlIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9y\n"
    "Zy8yMDAxL1hNTFNjaGVtYSNzdHJpbmciPgpEZWxlZ2F0ZSBBY2Nlc3MgICAgIDwv\n"
    "QXR0cmlidXRlVmFsdWU+CgkgIDxBY3Rpb25BdHRyaWJ1dGVEZXNpZ25hdG9yIEF0\n"
    "dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmFjdGlvbjph\n"
    "Y3Rpb24taWQiIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj\n"
    "aGVtYSNzdHJpbmciIC8+IAogICAgPC9BY3Rpb25NYXRjaD4KICAgPC9BY3Rpb24+\n"
    "CiAgPC9BY3Rpb25zPgogPC9UYXJnZXQ+CjwvUnVsZT4KMA0GCSqGSIb3DQEBBAUA\n"
    "A4GBAGiJSM48XsY90HlYxGmGVSmNR6ZW2As+bot3KAfiCIkUIOAqhcphBS23egTr\n"
    "6asYwy151HshbPNYz+Cgeqs45KkVzh7bL/0e1r8sDVIaaGIkjHK3CqBABnfSayr3\n"
    "Rd1yBoDdEv8Qb+3eEPH6ab9021AsLEnJ6LWTmybbOpMNZ3tv\n"
    "-----END ATTRIBUTE CERTIFICATE-----\n";
static BIO *mem(const char *pem)
{
    return BIO_new_mem_buf(pem, -1);
}

static X509 *read_cert(const char *pem)
{
    BIO *b = mem(pem);
    X509 *x = PEM_read_bio_X509_AUX(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static void show(const char *label, BIO *b, int ret)
{
    char *text;
    long len = BIO_get_mem_data(b, &text);

    printf("# %s: %d\n%.*s", label, ret, (int)len, text);
    if (len > 0 && text[len - 1] != '\n')
        printf("\n");
    (void)BIO_reset(b);
    errors();
    check(1, label);
}

static void print_cert(BIO *b, const char *label, X509 *x)
{
    char buf[128];

    snprintf(buf, sizeof(buf), "X509_print %s", label);
    show(buf, b, X509_print(b, x));
}

int main(void)
{
    BIO *b = BIO_new(BIO_s_mem()), *in;
    X509 *root = read_cert(ROOT_PEM), *eec = read_cert(EEC_PEM), *ersa = read_cert(ERSA_PEM);
    X509 *epss = read_cert(EPSS_PEM), *edsa = read_cert(EDSA_PEM), *eed = read_cert(EED_PEM);
    X509 *spss = read_cert(SPSS_PEM), *v1 = read_cert(V1_PEM), *trusted = read_cert(TRUSTED_PEM);
    X509_CRL *empty, *full;
    X509_REQ *req, *bare;
    X509_ACERT *acert, *acert_ietf, *acert_bc1;
    const X509_ALGOR *alg;
    const ASN1_BIT_STRING *sig;

    in = mem(EMPTY_CRL);
    empty = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    BIO_free(in);
    in = mem(FULL_CRL);
    full = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    BIO_free(in);
    in = mem(REQ_CSR);
    req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
    BIO_free(in);
    in = mem(BARE_CSR);
    bare = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
    BIO_free(in);
    in = mem(ACERT_PEM);
    acert = PEM_read_bio_X509_ACERT(in, NULL, NULL, NULL);
    BIO_free(in);
    in = mem(ACERT_IETF_PEM);
    acert_ietf = PEM_read_bio_X509_ACERT(in, NULL, NULL, NULL);
    BIO_free(in);
    in = mem(ACERT_BC1_PEM);
    acert_bc1 = PEM_read_bio_X509_ACERT(in, NULL, NULL, NULL);
    BIO_free(in);

    print_cert(b, "root", root);
    print_cert(b, "EC", eec);
    print_cert(b, "RSA", ersa);
    print_cert(b, "RSA-PSS key", epss);
    print_cert(b, "DSA", edsa);
    print_cert(b, "Ed25519", eed);
    print_cert(b, "RSA-PSS signed", spss);
    print_cert(b, "version 1", v1);
    print_cert(b, "trusted", trusted);

    show("oneline names", b, X509_print_ex(b, eec, XN_FLAG_ONELINE, X509_FLAG_COMPAT));
    show("multiline names", b, X509_print_ex(b, eec, XN_FLAG_MULTILINE, X509_FLAG_COMPAT));
    show("RFC 2253 names", b, X509_print_ex(b, eec, XN_FLAG_RFC2253, X509_FLAG_COMPAT));
    show("no header, key, or signature", b,
         X509_print_ex(b, eec, XN_FLAG_COMPAT, X509_FLAG_NO_HEADER | X509_FLAG_NO_PUBKEY | X509_FLAG_NO_SIGDUMP));
    show("no extensions or aux", b, X509_print_ex(b, trusted, XN_FLAG_COMPAT, X509_FLAG_NO_EXTENSIONS | X509_FLAG_NO_AUX));
    show("subject only", b, X509_print_ex(b, eec, XN_FLAG_ONELINE, ~X509_FLAG_NO_SUBJECT));
    show("key identifiers only", b, X509_print_ex(b, eec, XN_FLAG_COMPAT, X509_FLAG_EXTENSIONS_ONLY_KID));
    show("extensions, unknown ones in hex", b,
         X509_print_ex(b, eec, XN_FLAG_COMPAT, ~X509_FLAG_NO_EXTENSIONS | X509V3_EXT_DUMP_UNKNOWN));
    show("extensions, unknown ones parsed", b,
         X509_print_ex(b, eec, XN_FLAG_COMPAT, ~X509_FLAG_NO_EXTENSIONS | X509V3_EXT_PARSE_UNKNOWN));

    X509_get0_signature(&sig, &alg, ersa);
    show("signature algorithm", b, X509_signature_print(b, alg, NULL));
    show("RSA signature", b, X509_signature_print(b, alg, sig));
    X509_get0_signature(&sig, &alg, spss);
    show("RSA-PSS signature", b, X509_signature_print(b, alg, sig));
    X509_get0_signature(&sig, &alg, eec);
    show("ECDSA signature", b, X509_signature_print(b, alg, sig));

    show("aux, indented", b, X509_aux_print(b, trusted, 4));
    X509_keyid_set1(trusted, (const unsigned char *)"\x01\x02\xab", 3);
    show("aux with a key identifier", b, X509_aux_print(b, trusted, 0));
    show("aux of an untrusted certificate", b, X509_aux_print(b, eec, 0));
    show("OCSP identifiers", b, X509_ocspid_print(b, eec));
    show("OCSP identifiers, NULL", b, X509_ocspid_print(b, NULL));

    show("CRL without entries", b, X509_CRL_print(b, empty));
    show("CRL with entries", b, X509_CRL_print(b, full));
    show("CRL, oneline issuer", b, X509_CRL_print_ex(b, full, XN_FLAG_ONELINE));

    show("request", b, X509_REQ_print(b, req));
    show("bare request", b, X509_REQ_print(b, bare));
    show("request, multiline, no attributes", b,
         X509_REQ_print_ex(b, req, XN_FLAG_MULTILINE, X509_FLAG_NO_ATTRIBUTES));
    show("request, no extensions or key", b,
         X509_REQ_print_ex(b, req, XN_FLAG_COMPAT, X509_FLAG_NO_EXTENSIONS | X509_FLAG_NO_PUBKEY));

    show("attribute certificate", b, X509_ACERT_print(b, acert));
    show("IETF attribute certificate", b, X509_ACERT_print(b, acert_ietf));
    show("attribute certificate with a base certificate", b, X509_ACERT_print(b, acert_bc1));
    show("attribute certificate, multiline", b,
         X509_ACERT_print_ex(b, acert, XN_FLAG_MULTILINE, X509_FLAG_NO_SIGDUMP | X509_FLAG_NO_EXTENSIONS));

    printf("# to a FILE\n");
    fflush(stdout);
    printf("  X509_print_fp %d\n", X509_print_fp(stdout, v1));
    fflush(stdout);
    printf("  X509_print_ex_fp %d\n", X509_print_ex_fp(stdout, eec, XN_FLAG_ONELINE, ~X509_FLAG_NO_SUBJECT));
    fflush(stdout);
    printf("  X509_CRL_print_fp %d\n", X509_CRL_print_fp(stdout, empty));
    fflush(stdout);
    printf("  X509_REQ_print_fp %d\n", X509_REQ_print_fp(stdout, bare));
    fflush(stdout);
    errors();
    check(1, "to a FILE");

    printf("# X509_STORE_CTX_print_verify_cb\n");
    {
        X509_STORE *store = X509_STORE_new(), *empty_store = X509_STORE_new();
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        STACK_OF(X509) *untrusted = sk_X509_new_null();

        X509_STORE_add_cert(store, root);
        X509_STORE_CTX_init(ctx, store, eec, NULL);
        X509_STORE_CTX_set_verify_cb(ctx, X509_STORE_CTX_print_verify_cb);
        X509_VERIFY_PARAM_set1_host(X509_STORE_CTX_get0_param(ctx), "wrong.example", 0);
        X509_VERIFY_PARAM_add1_host(X509_STORE_CTX_get0_param(ctx), "other.example", 0);
        printf("  hostname: %d\n", X509_verify_cert(ctx));
        errors();
        X509_STORE_CTX_free(ctx);

        ctx = X509_STORE_CTX_new();
        sk_X509_push(untrusted, ersa);
        sk_X509_push(untrusted, v1);
        X509_STORE_CTX_init(ctx, empty_store, eec, untrusted);
        X509_STORE_CTX_set_verify_cb(ctx, X509_STORE_CTX_print_verify_cb);
        printf("  no issuer: %d\n", X509_verify_cert(ctx));
        errors();
        X509_STORE_CTX_free(ctx);

        ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, ersa, untrusted);
        X509_STORE_CTX_set_verify_cb(ctx, X509_STORE_CTX_print_verify_cb);
        X509_VERIFY_PARAM_set1_email(X509_STORE_CTX_get0_param(ctx), "b@example.com", 0);
        printf("  email: %d\n", X509_verify_cert(ctx));
        errors();
        X509_STORE_CTX_free(ctx);

        ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, edsa, untrusted);
        X509_STORE_CTX_set_verify_cb(ctx, X509_STORE_CTX_print_verify_cb);
        X509_VERIFY_PARAM_set1_ip_asc(X509_STORE_CTX_get0_param(ctx), "192.0.2.9");
        printf("  IP: %d\n", X509_verify_cert(ctx));
        errors();
        X509_STORE_CTX_free(ctx);

        ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, root, NULL);
        printf("  ok: %d, NULL: %d\n", X509_STORE_CTX_print_verify_cb(1, ctx), X509_STORE_CTX_print_verify_cb(0, NULL));
        errors();
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        X509_STORE_free(empty_store);
        sk_X509_free(untrusted);
    }
    check(1, "X509_STORE_CTX_print_verify_cb");

    X509_free(root);
    X509_free(eec);
    X509_free(ersa);
    X509_free(epss);
    X509_free(edsa);
    X509_free(eed);
    X509_free(spss);
    X509_free(v1);
    X509_free(trusted);
    X509_CRL_free(empty);
    X509_CRL_free(full);
    X509_REQ_free(req);
    X509_REQ_free(bare);
    X509_ACERT_free(acert);
    X509_ACERT_free(acert_ietf);
    X509_ACERT_free(acert_bc1);
    BIO_free(b);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
