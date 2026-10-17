/*
 * Conformance test for the PKCS#7 structures (PKCS7_new(3), d2i_PKCS7(3), PKCS7_set_type,
 * PKCS7_add_signature(3), PKCS7_add_recipient, PKCS7_get_signer_info, the attribute functions,
 * and their DER, PEM, BIO, and FILE forms): objects the reference's tool wrote (signed with
 * attributes, detached, certificates and CRLs only, enveloped) decoded, printed, read, and
 * encoded again; and every content type built field by field, with signers for RSA, EC, DSA,
 * RSA-PSS, and Ed25519 keys, recipients, certificates, CRLs, attributes, and capabilities.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

/*
 * Made with the reference's openssl tool: a root, EC, RSA, DSA, RSA-PSS, and Ed25519
 * certificates and keys, a CRL, and PKCS#7 objects: smime -sign (EC, attached), smime -sign
 * (RSA, detached, with the root), crl2pkcs7, and smime -encrypt (AES-256, to the RSA
 * certificate).
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

static const char EC_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvK30d565umx2MuWB\n"
    "8GZVrPCqSOcu6ewC6O01Gm0aW4ChRANCAASjOufjZCh1eFW6OdcafCygFn4NUm0v\n"
    "q4rzYbiKJFTf4YD6h+acp0cGBZyptgw9s9DHQ4Yr8DOq3bvLfyfzsXG5\n"
    "-----END PRIVATE KEY-----\n";

static const char RSA_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMxRYlQ+wmGXHVTo\n"
    "1t2qdczOUywTx80dGGOKph9bq0hVSiQU5FyPFDt2vLStBe5niSDh3KjMY5POUd8z\n"
    "7uFQbIm40Ar2dejg++MSI9wyck4QT3DNHl1Z0rdplWyI9Xt7BvfS1WhIqlrTfxVl\n"
    "dt3uQZFdC9VsyJlM49ikWOyxM7xvAgMBAAECgYAPZQptopTu2X4CSdD2vsNFfT5T\n"
    "EeJ6F/kgdu/xaOzM9HAzq8dRGg7CND4ftvG9dtukOKBxr4TJPEB6+uTC4VZsH6Co\n"
    "QvXcFPl8kugbW0FUExxrANmo8X3kqyP1WWOAf2mFfmDKbwkjtGnNBAMM/LMFDZtn\n"
    "YFE9R/SdVgScQ4ZvkQJBAOrelrrDYSuY2DQaGjgERFAexGIrTf0813n5xgvhcyxn\n"
    "09yWPWQE2L7nC+a2A6CVCAOWSPL608ymV9rnrO14WvUCQQDesyUJgdj0cz2nJzDZ\n"
    "8NIMei5FLGit1OhH6m0Un2RVJyEQXF1lp1YJhnCsD3+XZOcMgC1pFBdZxzwCrf6K\n"
    "C+NTAkANgdmXSg83i6W7cVjaqdwn420V3Dmy+6HEwQmTu1Z9UkdL41QKgYDZkb4M\n"
    "eaFBxfBdDHKLjsNJfLOGwlYenhJVAkB17wTEHiFYgta5eEWkhKWXufRa6YOd2swP\n"
    "mZOegjJN7eTSlzdWp+EmNi3g0GxPLj41HoPty5f6EUo0WRQc4uLFAkB8E0uH7x/H\n"
    "u7XkIF8U1hhpTvZ406TPdVgXwPS6dCEcL3HEcvWJ77fnvV7hbPoQga3wzUqn0S6Y\n"
    "zcTQYnIh0rlk\n"
    "-----END PRIVATE KEY-----\n";

static const char DSA_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIBWwIBADCCATMGByqGSM44BAEwggEmAoGBAIMJ3Iq+J1+Fs91oU6G+K/hbveYM\n"
    "5MvFLP5HrO+xP8v5Sv0AgzhYs4KYQj0JYCfObi/pyN/Z1zuo5eXa0iJP38BnJ+lw\n"
    "L/K+9yNGPyw4KpzE9dq4xzq1yqyJFYqVr7K4jscVCFls622KO/AVc5lMeaajZSr6\n"
    "JGf2JD22GNONdDvXAh0AyU7iCiabQ5z4dtW/DUqEQ8oyjtkAa+xsuxxlIQKBgDYO\n"
    "y+2DxTxCqP0f61k5Wit81vzFL9XR+yQRHIJd7vTfxel+9lDOyC0be7vINlEZjQ5m\n"
    "AedbV0WHffZEZvC9yS6AzmJ42i1ySZJvCBgx510w3l55fs7dmE5cUqUtaCWTOQkO\n"
    "Y+ktchbxlLENcaDYciEw0qnOcJVf7LJj63ojcpRKBB8CHQCM2xggWPXoGhtFqIiR\n"
    "iBGltgM+DGWOJGizLSQG\n"
    "-----END PRIVATE KEY-----\n";

static const char PSS_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICdwIBADALBgkqhkiG9w0BAQoEggJjMIICXwIBAAKBgQDCFXdLUrcvBOeUFdfO\n"
    "sCJNCCTVOTbHjWdExLtlVXm6+b/ALDt7bt+Cq9SxyNIK86X/f8SvfOgYNOvyC2Yp\n"
    "xreRHFLAkOMkIgkTESdOKW4H1tFAaR6aJfDVH1E/4ge83feqjJOgCTorvUxLJp6c\n"
    "jfI/dIwMk++rGOkxnzgNs+JvCQIDAQABAoGBAKkqkq9ZqodWLA98Nn1WMp+YAJrF\n"
    "YsTusFtVas15gkAB3iu/oh0FV9YKtbo8gy++jSq1EBextI8c2adAXkz9gxN3aSjv\n"
    "sY3hLRkAkRqwvVInchTT55yKdRvAXVaMdi5Ab9bWbZ4eG/EGdPENjhxHGZZj5Frn\n"
    "ctae8s0ZKHlPO9cBAkEA8wAxK/qccWwxiIr9YGHbynQEBk2zoDjbUSOHiHXIwwA/\n"
    "sQPIpyO3k81vi8tHKam5fkdUMUKtjmz8dyL6rO3h6QJBAMx3X+PsI70qb0X6dDno\n"
    "E/zkj0yig61C0WgQ32qgzoQIHU2Y+OkxZXKFzU1KE+EfRdi/40eBVdHTQLJfJLZz\n"
    "0CECQQCa4GJ2r1IKkHS5nCyFw5k8Xdk600dLNTHDcyus87UzY/M0NT8sF/2nPGZ9\n"
    "6N/AVCafr4KfqunHPvtiS28NzMgRAkEAsmpcR0OQMAnuTQ7uCnWDs4IxtPp+klqi\n"
    "5f8LJT0q17VI9KROVxXeYx90dUP1stSaGzfd+FBYdZ60brFtFLRcYQJBAIPA2mLj\n"
    "PAQp9iEe/to0MMYJeoryBKUYZKYGvU+NpkVc/QxizpAJ7dAevaxMrGtQtqXq2TKX\n"
    "zNVr27QyIzBnZyM=\n"
    "-----END PRIVATE KEY-----\n";

static const char ED_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIBLKXy/D7+VRDnKSj111DpShkFRRTjAbXbnZQCJsevaR\n"
    "-----END PRIVATE KEY-----\n";

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

static const char SIGNED_PEM[] =
    "-----BEGIN PKCS7-----\n"
    "MIIERgYJKoZIhvcNAQcCoIIENzCCBDMCAQExDzANBglghkgBZQMEAgEFADAfBgkq\n"
    "hkiG9w0BBwGgEgQQSGVsbG8sIFBLQ1MjNy4NCqCCAmkwggJlMIICC6ADAgECAgEC\n"
    "MAoGCCqGSM49BAMCMDQxCzAJBgNVBAYTAkpQMRAwDgYDVQQKDAdFeGFtcGxlMRMw\n"
    "EQYDVQQDDApQcmludCBSb290MB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAw\n"
    "MFowczELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMRYwFAYDVQQKDA1FeGFt\n"
    "cGxlLCBJbmMuMR4wCwYDVQQLDARVbml0MA8GA1UEAwwIUHJpbnQgRUMxHDAaBgkq\n"
    "hkiG9w0BCQEWDWFAZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n"
    "AASjOufjZCh1eFW6OdcafCygFn4NUm0vq4rzYbiKJFTf4YD6h+acp0cGBZyptgw9\n"
    "s9DHQ4Yr8DOq3bvLfyfzsXG5o4HOMIHLMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgeA\n"
    "MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAvBgNVHREEKDAmgg93d3cu\n"
    "ZXhhbXBsZS5jb22HBMAAAgGBDWFAZXhhbXBsZS5jb20wHQYDVR0OBBYEFGKGEE80\n"
    "yyzQVE31I4PiW+RU3GtWMB8GA1UdIwQYMBaAFGKGEE80yyzQVE31I4PiW+RU3GtW\n"
    "MBAGA1UdIAQJMAcwBQYDKgMEMA8GAyoDBQQIDAZjdXN0b20wCgYIKoZIzj0EAwID\n"
    "SAAwRQIgDnPWPkeoNj/2DaABuWBSTDzKsNPn2dhquLsXHM7pEfwCIQDPlm75xfxe\n"
    "Zv85bcocpmRjCqt5YsAXAazs+eR0VmDKIDGCAY0wggGJAgEBMDkwNDELMAkGA1UE\n"
    "BhMCSlAxEDAOBgNVBAoMB0V4YW1wbGUxEzARBgNVBAMMClByaW50IFJvb3QCAQIw\n"
    "DQYJYIZIAWUDBAIBBQCggeQwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkq\n"
    "hkiG9w0BCQUxDxcNMjYxMDE3MjE0MzI0WjAvBgkqhkiG9w0BCQQxIgQgHOVrOce8\n"
    "IsUi2vgeYq0Ql8mbFD5z8RFhCUnc4yAaHNwweQYJKoZIhvcNAQkPMWwwajALBglg\n"
    "hkgBZQMEASowCwYJYIZIAWUDBAEWMAsGCWCGSAFlAwQBAjAKBggqhkiG9w0DBzAO\n"
    "BggqhkiG9w0DAgICAIAwDQYIKoZIhvcNAwICAUAwBwYFKw4DAgcwDQYIKoZIhvcN\n"
    "AwICASgwCgYIKoZIzj0EAwIERzBFAiB9oXFB/9tW0w1qgJn7ge9Uj+zy0bSzRthK\n"
    "lfUgPm6BwwIhANj8N7tLrVNNdzlZXQPtrVuNa0pWTTjIL4W4UWWs/wkO\n"
    "-----END PKCS7-----\n";

static const char DETACHED_PEM[] =
    "-----BEGIN PKCS7-----\n"
    "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\n"
    "LPoUH3/X9A==\n"
    "-----END PKCS7-----\n";

static const char CERTS_PEM[] =
    "-----BEGIN PKCS7-----\n"
    "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\n"
    "-----END PKCS7-----\n";

static const char ENV_PEM[] =
    "-----BEGIN PKCS7-----\n"
    "MIIBSQYJKoZIhvcNAQcDoIIBOjCCATYCAQAxgeIwgd8CAQAwSDA0MQswCQYDVQQG\n"
    "EwJKUDEQMA4GA1UECgwHRXhhbXBsZTETMBEGA1UEAwwKUHJpbnQgUm9vdAIQASNF\n"
    "Z4mrze8BI0VniavN7zANBgkqhkiG9w0BAQEFAASBgIaxYDeWrGOIstJ8aYGKSe6K\n"
    "6D8gf/wmMBfFc9Dw5ItxfuuuHW0ZpSsovDDvtv2iHx6zyitOZd2/GVD5OkGdfHJQ\n"
    "bl6MWj60IK1iN38AvyOpPZ9b0zSBb2j8zKZcLJH7T3A4mxn21VKRPqOuiYnw+/sM\n"
    "jwa8IUmdDwzP7wBGq+4iMEwGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEKGfJIqE\n"
    "/7x3FSiuRlA+ydGAIEd6PPSvEQtJ8QNRw/k/xpCy90EZitGguxl0AqIWvISS\n"
    "-----END PKCS7-----\n";
static BIO *mem(const char *pem)
{
    return BIO_new_mem_buf(pem, -1);
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

static void der(const char *label, PKCS7 *p7)
{
    unsigned char *d = NULL;
    int n = i2d_PKCS7(p7, &d);

    hex(label, d, n);
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
    int i;

    printf("  signers %d\n", sis == NULL ? -1 : sk_PKCS7_SIGNER_INFO_num(sis));
    for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sis); i++) {
        PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sis, i);
        X509_ALGOR *dig, *sig;
        EVP_PKEY *pk;
        X509 *x = PKCS7_cert_from_signer_info(p7, si);
        ASN1_TYPE *t;
        STACK_OF(X509_ALGOR) *caps;
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int mdlen = 0;

        PKCS7_SIGNER_INFO_get0_algs(si, &pk, &dig, &sig);
        printf("  %d: digest %s, signature %s, key %s, cert %s\n", i, oid(dig->algorithm), oid(sig->algorithm),
               pk == NULL ? "none" : "set", x == NULL ? "not found" : "found");
        t = PKCS7_get_signed_attribute(si, NID_pkcs9_contentType);
        printf("    contentType %s\n", t == NULL ? "none" : oid(t->value.object));
        t = PKCS7_get_signed_attribute(si, NID_pkcs9_signingTime);
        printf("    signingTime %s\n", t == NULL ? "none" : (const char *)t->value.utctime->data);
        printf("    messageDigest %s\n", PKCS7_digest_from_attributes(si->auth_attr) == NULL ? "none" : "set");
        printf("    unsigned %s\n", PKCS7_get_attribute(si, NID_pkcs9_contentType) == NULL ? "none" : "set");
        caps = PKCS7_get_smimecap(si);
        printf("    capabilities %d\n", caps == NULL ? -1 : sk_X509_ALGOR_num(caps));
        sk_X509_ALGOR_pop_free(caps, X509_ALGOR_free);
        PKCS7_ISSUER_AND_SERIAL_digest(si->issuer_and_serial, EVP_sha256(), md, &mdlen);
        hex("issuer and serial digest", md, (int)mdlen);
    }
}

static PKCS7 *load(const char *label, const char *pem)
{
    BIO *b = mem(pem), *out = BIO_new(BIO_s_mem());
    PKCS7 *p7 = PEM_read_bio_PKCS7(b, NULL, NULL, NULL), *again;
    unsigned char *d = NULL;
    const unsigned char *q;
    int n;
    char *text;
    long len;

    BIO_free(b);
    printf("# %s: %s, type %s, other %d, detached %ld\n", label, p7 == NULL ? "NULL" : "read", oid(p7->type),
           PKCS7_type_is_other(p7), PKCS7_ctrl(p7, PKCS7_OP_GET_DETACHED_SIGNATURE, 0, NULL));
    n = i2d_PKCS7(p7, &d);
    q = d;
    again = d2i_PKCS7(NULL, &q, n);
    printf("  DER %d, decoded again %s, consumed %d\n", n, again == NULL ? "NULL" : "yes", (int)(q - d));
    {
        unsigned char *d2 = NULL;
        int n2 = i2d_PKCS7(again, &d2);

        printf("  same encoding %d\n", n2 == n && memcmp(d, d2, n) == 0);
        OPENSSL_free(d2);
    }
    {
        PKCS7 *dup = PKCS7_dup(p7);
        unsigned char *d3 = NULL;
        int n3 = i2d_PKCS7(dup, &d3);

        printf("  dup same %d\n", n3 == n && memcmp(d, d3, n) == 0);
        OPENSSL_free(d3);
        PKCS7_free(dup);
    }
    PKCS7_print_ctx(out, p7, 2, NULL);
    len = BIO_get_mem_data(out, &text);
    printf("%.*s", (int)len, text);
    (void)BIO_reset(out);
    PEM_write_bio_PKCS7(out, p7);
    len = BIO_get_mem_data(out, &text);
    printf("  PEM again same %d\n", strncmp(text, pem, len) == 0);
    (void)BIO_reset(out);
    i2d_PKCS7_bio(out, p7);
    {
        PKCS7 *viabio = d2i_PKCS7_bio(out, NULL);

        printf("  via a BIO %s\n", viabio == NULL ? "NULL" : "yes");
        PKCS7_free(viabio);
    }
    {
        unsigned char *nd = NULL;
        int nn = i2d_PKCS7_NDEF(p7, &nd);

        hex("NDEF", nd, nn > 64 ? 64 : nn);
        OPENSSL_free(nd);
    }
    show_signers(p7);
    printf("  octet string %s\n", PKCS7_get_octet_string(p7) == NULL ? "none" : "set");
    if (PKCS7_type_is_signed(p7))
        printf("  certs %d, crls %d, content type %s\n", sk_X509_num(p7->d.sign->cert), sk_X509_CRL_num(p7->d.sign->crl),
               oid(p7->d.sign->contents->type));
    printf("  issuer and serial 0: %s\n", PKCS7_get_issuer_and_serial(p7, 0) == NULL ? "NULL" : "set");
    OPENSSL_free(d);
    PKCS7_free(again);
    BIO_free(out);
    errors();
    check(p7 != NULL, label);
    return p7;
}

int main(void)
{
    X509 *root = cert(ROOT_PEM), *eec = cert(EEC_PEM), *ersa = cert(ERSA_PEM), *edsa = cert(EDSA_PEM);
    X509 *epss = cert(EPSS_PEM), *eed = cert(EED_PEM);
    EVP_PKEY *kec = key(EC_KEY_PEM), *krsa = key(RSA_KEY_PEM), *kdsa = key(DSA_KEY_PEM), *kpss = key(PSS_KEY_PEM), *ked = key(ED_KEY_PEM);
    X509_CRL *crl;
    PKCS7 *p7;
    BIO *b;
    static const int types[] = { NID_pkcs7_data, NID_pkcs7_signed, NID_pkcs7_enveloped, NID_pkcs7_signedAndEnveloped,
                                 NID_pkcs7_digest, NID_pkcs7_encrypted, NID_commonName };
    size_t i;

    b = mem(FULL_CRL);
    crl = PEM_read_bio_X509_CRL(b, NULL, NULL, NULL);
    BIO_free(b);

    PKCS7_free(load("signed", SIGNED_PEM));
    PKCS7_free(load("detached", DETACHED_PEM));
    PKCS7_free(load("certificates only", CERTS_PEM));
    PKCS7_free(load("enveloped", ENV_PEM));

    printf("# empty types\n");
    for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        p7 = PKCS7_new();
        printf("  %d: set %d, other %d\n", types[i], PKCS7_set_type(p7, types[i]), PKCS7_type_is_other(p7));
        der("DER", p7);
        {
            PKCS7 *inner = PKCS7_new();

            PKCS7_set_type(inner, NID_pkcs7_data);
            printf("  content_new data %d, set_content %d\n", PKCS7_content_new(p7, NID_pkcs7_data),
                   PKCS7_set_content(p7, inner));
            if (!PKCS7_type_is_signed(p7) && !PKCS7_type_is_digest(p7))
                PKCS7_free(inner);
        }
        printf("  ctrl get %ld, set %ld, unknown %ld\n", PKCS7_ctrl(p7, PKCS7_OP_GET_DETACHED_SIGNATURE, 0, NULL),
               PKCS7_ctrl(p7, PKCS7_OP_SET_DETACHED_SIGNATURE, 1, NULL), PKCS7_ctrl(p7, 99, 0, NULL));
        printf("  certificate %d, crl %d, cipher %d, digest %d, recipient %s\n", PKCS7_add_certificate(p7, root),
               PKCS7_add_crl(p7, crl), PKCS7_set_cipher(p7, EVP_aes_128_cbc()), PKCS7_set_digest(p7, EVP_sha256()),
               PKCS7_add_recipient(p7, ersa) == NULL ? "NULL" : "added");
        printf("  signature %s\n", PKCS7_add_signature(p7, eec, kec, EVP_sha256()) == NULL ? "NULL" : "added");
        der("filled", p7);
        errors();
        PKCS7_free(p7);
    }
    check(1, "empty types");

    printf("# signed, built\n");
    p7 = PKCS7_new_ex(NULL, "provider=default");
    PKCS7_set_type(p7, NID_pkcs7_signed);
    PKCS7_content_new(p7, NID_pkcs7_data);
    ASN1_OCTET_STRING_set(p7->d.sign->contents->d.data, (const unsigned char *)"content", 7);
    {
        PKCS7_SIGNER_INFO *si;
        STACK_OF(X509_ALGOR) *caps = sk_X509_ALGOR_new_null();
        ASN1_TIME *t = ASN1_TIME_set(NULL, 1800000000);
        ASN1_OCTET_STRING *os;

        printf("  RSA %s\n", (si = PKCS7_add_signature(p7, ersa, krsa, EVP_sha256())) == NULL ? "NULL" : "added");
        printf("  content type %d, again %d\n", PKCS7_add_attrib_content_type(si, NULL),
               PKCS7_add_attrib_content_type(si, NULL));
        printf("  signing time %d\n", PKCS7_add0_attrib_signing_time(si, t));
        printf("  digest %d\n", PKCS7_add1_attrib_digest(si, (const unsigned char *)"0123456789abcdef", 16));
        printf("  digest again %d\n", PKCS7_add1_attrib_digest(si, (const unsigned char *)"fedcba9876543210", 16));
        PKCS7_simple_smimecap(caps, NID_aes_256_cbc, 0);
        PKCS7_simple_smimecap(caps, NID_rc2_cbc, 128);
        printf("  capabilities %d, empty %d\n", PKCS7_add_attrib_smimecap(si, caps), PKCS7_add_attrib_smimecap(si, NULL));
        sk_X509_ALGOR_pop_free(caps, X509_ALGOR_free);
        os = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(os, (const unsigned char *)"x", 1);
        printf("  unsigned %d\n", PKCS7_add_attribute(si, NID_pkcs9_unstructuredName, V_ASN1_OCTET_STRING, os));
        {
            STACK_OF(X509_ATTRIBUTE) *sa = sk_X509_ATTRIBUTE_deep_copy(si->auth_attr, X509_ATTRIBUTE_dup, X509_ATTRIBUTE_free);
            STACK_OF(X509_ATTRIBUTE) *ua = sk_X509_ATTRIBUTE_deep_copy(si->unauth_attr, X509_ATTRIBUTE_dup, X509_ATTRIBUTE_free);

            printf("  set attributes %d %d\n", PKCS7_set_signed_attributes(si, sa), PKCS7_set_attributes(si, ua));
            sk_X509_ATTRIBUTE_pop_free(sa, X509_ATTRIBUTE_free);
            sk_X509_ATTRIBUTE_pop_free(ua, X509_ATTRIBUTE_free);
        }
        printf("  EC %s\n", PKCS7_add_signature(p7, eec, kec, EVP_sha384()) == NULL ? "NULL" : "added");
        printf("  DSA %s\n", PKCS7_add_signature(p7, edsa, kdsa, NULL) == NULL ? "NULL" : "added");
        printf("  RSA-PSS %s\n", PKCS7_add_signature(p7, epss, kpss, EVP_sha256()) == NULL ? "NULL" : "added");
        errors();
        printf("  Ed25519 %s\n", PKCS7_add_signature(p7, eed, ked, EVP_sha512()) == NULL ? "NULL" : "added");
        errors();
        printf("  certificates %d %d %d, crl %d\n", PKCS7_add_certificate(p7, ersa), PKCS7_add_certificate(p7, eec),
               PKCS7_add_certificate(p7, ersa), PKCS7_add_crl(p7, crl));
    }
    show_signers(p7);
    der("signed", p7);
    printf("  detached set %ld, get %ld\n", PKCS7_ctrl(p7, PKCS7_OP_SET_DETACHED_SIGNATURE, 1, NULL),
           PKCS7_ctrl(p7, PKCS7_OP_GET_DETACHED_SIGNATURE, 0, NULL));
    der("detached", p7);
    {
        PKCS7 *ctx = PKCS7_new_ex(NULL, "provider=default");
        unsigned char *d = NULL;
        const unsigned char *q;
        int n = i2d_PKCS7(p7, &d);

        q = d;
        printf("  decoded into an object with a context %s\n", d2i_PKCS7(&ctx, &q, n) == ctx ? "same" : "other");
        show_signers(ctx);
        OPENSSL_free(d);
        PKCS7_free(ctx);
    }
    PKCS7_free(p7);
    errors();
    check(1, "signed, built");

    printf("# enveloped, built\n");
    p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_enveloped);
    printf("  RSA %s\n", PKCS7_add_recipient(p7, ersa) == NULL ? "NULL" : "added");
    printf("  RSA-PSS %s\n", PKCS7_add_recipient(p7, epss) == NULL ? "NULL" : "added");
    errors();
    printf("  EC %s\n", PKCS7_add_recipient(p7, eec) == NULL ? "NULL" : "added");
    errors();
    printf("  cipher %d\n", PKCS7_set_cipher(p7, EVP_aes_256_cbc()));
    {
        PKCS7_RECIP_INFO *ri = PKCS7_RECIP_INFO_new();
        X509_ALGOR *alg;

        printf("  set %d\n", PKCS7_RECIP_INFO_set(ri, ersa));
        PKCS7_RECIP_INFO_get0_alg(ri, &alg);
        printf("  algorithm %s\n", oid(alg->algorithm));
        printf("  added %d\n", PKCS7_add_recipient_info(p7, ri));
    }
    der("enveloped", p7);
    PKCS7_free(p7);
    errors();
    check(1, "enveloped, built");

    printf("# other types\n");
    p7 = PKCS7_new();
    {
        ASN1_TYPE *t = ASN1_TYPE_new();
        ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();

        ASN1_OCTET_STRING_set(os, (const unsigned char *)"other", 5);
        ASN1_TYPE_set(t, V_ASN1_OCTET_STRING, os);
        printf("  set0 %d, other %d, octet string %s\n", PKCS7_set0_type_other(p7, NID_commonName, t),
               PKCS7_type_is_other(p7), PKCS7_get_octet_string(p7) == NULL ? "none" : "set");
    }
    der("other", p7);
    PKCS7_free(p7);
    check(1, "other types");

    printf("# the structures alone\n");
    {
        PKCS7_ISSUER_AND_SERIAL *ias = PKCS7_ISSUER_AND_SERIAL_new();
        PKCS7_SIGNER_INFO *si = PKCS7_SIGNER_INFO_new();
        unsigned char *d = NULL;
        int n;

        X509_NAME_set(&ias->issuer, X509_get_subject_name(root));
        ASN1_INTEGER_set(ias->serial, 7);
        n = i2d_PKCS7_ISSUER_AND_SERIAL(ias, &d);
        hex("issuer and serial", d, n);
        OPENSSL_free(d);
        d = NULL;
        PKCS7_SIGNER_INFO_set(si, ersa, krsa, EVP_sha1());
        n = i2d_PKCS7_SIGNER_INFO(si, &d);
        hex("signer info", d, n);
        {
            const unsigned char *q = d;
            PKCS7_SIGNER_INFO *again = d2i_PKCS7_SIGNER_INFO(NULL, &q, n);

            printf("  decoded %s\n", again == NULL ? "NULL" : "yes");
            PKCS7_SIGNER_INFO_free(again);
        }
        OPENSSL_free(d);
        PKCS7_SIGNER_INFO_free(si);
        PKCS7_ISSUER_AND_SERIAL_free(ias);
    }
    {
#define ROUND(T)                                                                          \
    do {                                                                                  \
        T *v = T##_new();                                                                 \
        unsigned char *d = NULL;                                                          \
        const unsigned char *q;                                                           \
        int n = i2d_##T(v, &d), n2;                                                       \
        T *w;                                                                             \
        q = d;                                                                            \
        w = d2i_##T(NULL, &q, n);                                                         \
        n2 = ASN1_item_i2d((ASN1_VALUE *)w, NULL, ASN1_ITEM_rptr(T));                     \
        printf("  %s: %d octets, decoded %s, item %d\n", #T, n, w == NULL ? "NULL" : "yes", n2); \
        if (n > 0)                                                                        \
            hex(#T, d, n);                                                                \
        OPENSSL_free(d);                                                                  \
        T##_free(w);                                                                      \
        T##_free(v);                                                                      \
    } while (0)
        ROUND(PKCS7_SIGNED);
        ROUND(PKCS7_SIGNER_INFO);
        ROUND(PKCS7_ISSUER_AND_SERIAL);
        ROUND(PKCS7_ENVELOPE);
        ROUND(PKCS7_RECIP_INFO);
        ROUND(PKCS7_ENC_CONTENT);
        ROUND(PKCS7_SIGN_ENVELOPE);
        ROUND(PKCS7_ENCRYPT);
        ROUND(PKCS7_DIGEST);
        ROUND(PKCS7);
        errors();
    }
    {
        PKCS7 *s = PKCS7_new();
        PKCS7_SIGNER_INFO *si = PKCS7_SIGNER_INFO_new();
        ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
        STACK_OF(X509_ATTRIBUTE) *attrs;
        unsigned char *d = NULL;
        int n;

        PKCS7_set_type(s, NID_pkcs7_signed);
        PKCS7_SIGNER_INFO_set(si, eec, kec, EVP_sha256());
        ASN1_OCTET_STRING_set(os, (const unsigned char *)"ab", 2);
        printf("  add_signed_attribute %d, add_signer %d\n",
               PKCS7_add_signed_attribute(si, NID_pkcs9_messageDigest, V_ASN1_OCTET_STRING, os), PKCS7_add_signer(s, si));
        attrs = si->auth_attr;
        n = ASN1_item_i2d((ASN1_VALUE *)attrs, &d, ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
        hex("attributes to sign", d, n);
        OPENSSL_free(d);
        d = NULL;
        n = ASN1_item_i2d((ASN1_VALUE *)attrs, &d, ASN1_ITEM_rptr(PKCS7_ATTR_VERIFY));
        hex("attributes to verify", d, n);
        OPENSSL_free(d);
        {
            FILE *f = tmpfile();
            PKCS7 *r;

            printf("  i2d_PKCS7_fp %d, PEM_write_PKCS7 %d\n", i2d_PKCS7_fp(f, s), PEM_write_PKCS7(f, s));
            rewind(f);
            r = d2i_PKCS7_fp(f, NULL);
            printf("  d2i_PKCS7_fp %s\n", r == NULL ? "NULL" : "read");
            PKCS7_free(r);
            r = PEM_read_PKCS7(f, NULL, NULL, NULL);
            printf("  PEM_read_PKCS7 %s\n", r == NULL ? "NULL" : "read");
            PKCS7_free(r);
            fclose(f);
        }
        PKCS7_free(s);
    }
    PKCS7_free(NULL);
    printf("  NULL signer info: %s\n", PKCS7_get_signer_info(NULL) == NULL ? "NULL" : "set");
    errors();
    check(1, "the structures alone");

    X509_free(root);
    X509_free(eec);
    X509_free(ersa);
    X509_free(edsa);
    X509_free(epss);
    X509_free(eed);
    EVP_PKEY_free(kec);
    EVP_PKEY_free(krsa);
    EVP_PKEY_free(kdsa);
    EVP_PKEY_free(kpss);
    EVP_PKEY_free(ked);
    X509_CRL_free(crl);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
