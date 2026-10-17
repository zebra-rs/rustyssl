/*
 * Conformance test for verification (X509_verify_cert(3), X509_STORE_CTX_verify,
 * X509_build_chain, and the verification callback), in TAP format: chains built from the store
 * and untrusted certificates (complete, missing an issuer, self-signed, partial, trusted first
 * or last), validity times, purposes, host names, email and IP addresses, name constraints
 * (permitted and excluded), path lengths, a non-CA issuer, security levels, strict checks,
 * and a callback that sees, and may accept, each failure.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/http.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
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

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static const char ROOT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBWTCB/6ADAgECAgEBMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCVRlc3QgUm9v\n"
    "dDAeFw0yNjEwMTcxODQzMDFaFw00NjEwMTIxODQzMDFaMBQxEjAQBgNVBAMMCVRl\n"
    "c3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCOQKxyM4V3UGsTn7hIB\n"
    "2RN95FW86pJk/3LZsUao6N1uG5lfZwRpZCyIQwz2YhOD2JWb6eJ1Z/zJKbt9Ve+p\n"
    "kgSjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQW\n"
    "BBRB9ZdzNyU66j9lh2x/YaHkSXrgGTAKBggqhkjOPQQDAgNJADBGAiEA207RdWcA\n"
    "uzkiwH/9ZZoXDJBLVelrNUvQORJdi2bfiiECIQCpsvpuO3GR+FedkBKdzOa39A07\n"
    "0lHS61fyeJIfzvfMxg==\n"
    "-----END CERTIFICATE-----\n";

static const char INTER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBgjCCASigAwIBAgIBAjAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlUZXN0IFJv\n"
    "b3QwHhcNMjYxMDE3MTg0MzAxWhcNNDUxMjE2MTg0MzAxWjAcMRowGAYDVQQDDBFU\n"
    "ZXN0IEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLIbzSSw\n"
    "I2RRwytQ8tlnZgW/ivPMHE0Lz/Pc8zRV3ckPhVuVQJgdyD/741NPfCt0CSoU6bgR\n"
    "B9+etndJBg8r1UyjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEG\n"
    "MB0GA1UdDgQWBBRHbAq5cXeEzVM8N8wQCgxvOA9VVDAfBgNVHSMEGDAWgBRB9Zdz\n"
    "NyU66j9lh2x/YaHkSXrgGTAKBggqhkjOPQQDAgNIADBFAiAO5q2lg8jGRq71d8kC\n"
    "nWHt+5kF2OmKJIKKy5ivtmxJugIhAPa/9g13ATWcw/qn9kj2B9JKfr7U7rKsY2TW\n"
    "szNMU7pj\n"
    "-----END CERTIFICATE-----\n";

static const char LEAF_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBtjCCAVugAwIBAgIBAzAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFUZXN0IElu\n"
    "dGVybWVkaWF0ZTAeFw0yNjEwMTcxODQzMDFaFw0zNjEwMTQxODQzMDFaMBoxGDAW\n"
    "BgNVBAMMD3d3dy5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\n"
    "BLWw7F4cajN8onZfQtLn609kyc3gAqghW9ZiakhECOBlMAktSMLz1X+378uvVuky\n"
    "spdIO/2KJytrU6hdTwfunCujgY8wgYwwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMC\n"
    "B4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwGgYDVR0RBBMwEYIPd3d3LmV4YW1wbGUu\n"
    "Y29tMB0GA1UdDgQWBBQLxjyHNUkjtousHItTw5HSIb8tbzAfBgNVHSMEGDAWgBRH\n"
    "bAq5cXeEzVM8N8wQCgxvOA9VVDAKBggqhkjOPQQDAgNJADBGAiEA3JLpIX9FiCzZ\n"
    "Un8T3sWRCWPCL1kt3DLbansWyuGjNh0CIQDlg6VYZMurr+OfmChcQq6JdVt28Tk4\n"
    "dVR8Koo+LaYPVw==\n"
    "-----END CERTIFICATE-----\n";

static const char SHORTLIVED_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBtzCCAV2gAwIBAgIBBDAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFUZXN0IElu\n"
    "dGVybWVkaWF0ZTAeFw0yNjEwMTcxODQzMDFaFw0yNjEwMTgxODQzMDFaMBwxGjAY\n"
    "BgNVBAMMEXNob3J0LmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"
    "QgAEtbDsXhxqM3yidl9C0ufrT2TJzeACqCFb1mJqSEQI4GUwCS1IwvPVf7fvy69W\n"
    "6TKyl0g7/YonK2tTqF1PB+6cK6OBjzCBjDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQE\n"
    "AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAaBgNVHREEEzARgg93d3cuZXhhbXBs\n"
    "ZS5jb20wHQYDVR0OBBYEFAvGPIc1SSO2i6wci1PDkdIhvy1vMB8GA1UdIwQYMBaA\n"
    "FEdsCrlxd4TNUzw3zBAKDG84D1VUMAoGCCqGSM49BAMCA0gAMEUCIFnt+NZRi2LP\n"
    "RQssdMqr+53PFNhhzOpE0U+848WX4gwGAiEAnlsW3ilxpyluy/Plco6NTDB3A+Lb\n"
    "XubqHkecFHW3mwY=\n"
    "-----END CERTIFICATE-----\n";

static const char NC_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBtjCCAVygAwIBAgIBBTAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlUZXN0IFJv\n"
    "b3QwHhcNMjYxMDE3MTg0MzAxWhcNNDUxMjE2MTg0MzAxWjAZMRcwFQYDVQQDDA5D\n"
    "b25zdHJhaW5lZCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGkhmY1XLVz8\n"
    "b96q6DYoX9oFPBlwu6+iOjr48M33ql+WKLyz86yWUz/HsO7wsGr1dsOG5/VPybPH\n"
    "Mel4iEwmNlWjgZkwgZYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\n"
    "HQYDVR0OBBYEFLNS/i3f3BVoRkKDZQTxPpIyj2HMMB8GA1UdIwQYMBaAFEH1l3M3\n"
    "JTrqP2WHbH9hoeRJeuAZMDMGA1UdHgEB/wQpMCegEDAOggwuZXhhbXBsZS5jb22h\n"
    "EzARgg9iYWQuZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDSAAwRQIhANLG03eQVIg3\n"
    "EJ1RDcGD+DPMZZWPhqaHTtf96ORdsq2QAiBm8Wnaq5qXEI2jmKvFCyZw9WTCoCLY\n"
    "JBMXm2Nu+DMRvA==\n"
    "-----END CERTIFICATE-----\n";

static const char OUT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBpzCCAUygAwIBAgIBBjAKBggqhkjOPQQDAjAZMRcwFQYDVQQDDA5Db25zdHJh\n"
    "aW5lZCBDQTAeFw0yNjEwMTcxODQzMDFaFw0zNjEwMTQxODQzMDFaMA4xDDAKBgNV\n"
    "BAMMA291dDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLWw7F4cajN8onZfQtLn\n"
    "609kyc3gAqghW9ZiakhECOBlMAktSMLz1X+378uvVukyspdIO/2KJytrU6hdTwfu\n"
    "nCujgY8wgYwwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYI\n"
    "KwYBBQUHAwEwGgYDVR0RBBMwEYIPd3d3LmV4YW1wbGUub3JnMB8GA1UdIwQYMBaA\n"
    "FLNS/i3f3BVoRkKDZQTxPpIyj2HMMB0GA1UdDgQWBBQLxjyHNUkjtousHItTw5HS\n"
    "Ib8tbzAKBggqhkjOPQQDAgNJADBGAiEAwtBpbtxwokiyX15lu96aikFD04vlmvJ2\n"
    "U8FXv0ppi4oCIQDRkEBXfYgDqwit+rOscAQ54G2neUTOzz3GNiZQ1vRNiA==\n"
    "-----END CERTIFICATE-----\n";

static const char BAD_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBpzCCAUygAwIBAgIBBzAKBggqhkjOPQQDAjAZMRcwFQYDVQQDDA5Db25zdHJh\n"
    "aW5lZCBDQTAeFw0yNjEwMTcxODQzMDFaFw0zNjEwMTQxODQzMDFaMA4xDDAKBgNV\n"
    "BAMMA2JhZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLWw7F4cajN8onZfQtLn\n"
    "609kyc3gAqghW9ZiakhECOBlMAktSMLz1X+378uvVukyspdIO/2KJytrU6hdTwfu\n"
    "nCujgY8wgYwwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYI\n"
    "KwYBBQUHAwEwGgYDVR0RBBMwEYIPYmFkLmV4YW1wbGUuY29tMB8GA1UdIwQYMBaA\n"
    "FLNS/i3f3BVoRkKDZQTxPpIyj2HMMB0GA1UdDgQWBBQLxjyHNUkjtousHItTw5HS\n"
    "Ib8tbzAKBggqhkjOPQQDAgNJADBGAiEA0d70gfb9U443ge6iLpO4mFRNwfZILK9s\n"
    "HEXUZj6Kvn4CIQDifyZjl/QK0OIzJJEV8gMFkWAylK4mYPI5dd8QnJQKKQ==\n"
    "-----END CERTIFICATE-----\n";

static const char NCOK_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBpDCCAUugAwIBAgIBCDAKBggqhkjOPQQDAjAZMRcwFQYDVQQDDA5Db25zdHJh\n"
    "aW5lZCBDQTAeFw0yNjEwMTcxODQzMDFaFw0zNjEwMTQxODQzMDFaMA0xCzAJBgNV\n"
    "BAMMAm9rMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtbDsXhxqM3yidl9C0ufr\n"
    "T2TJzeACqCFb1mJqSEQI4GUwCS1IwvPVf7fvy69W6TKyl0g7/YonK2tTqF1PB+6c\n"
    "K6OBjzCBjDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr\n"
    "BgEFBQcDATAaBgNVHREEEzARgg93d3cuZXhhbXBsZS5jb20wHQYDVR0OBBYEFAvG\n"
    "PIc1SSO2i6wci1PDkdIhvy1vMB8GA1UdIwQYMBaAFLNS/i3f3BVoRkKDZQTxPpIy\n"
    "j2HMMAoGCCqGSM49BAMCA0cAMEQCICp3p/PoD87EG3GElvLu9E41OtnfjhFZQBgX\n"
    "KEtHMAFpAiAkt+lKAzA1NIe8Iy+VoctIjYMI3O4WrxxMKKllwBotZw==\n"
    "-----END CERTIFICATE-----\n";

static const char ROOT0_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBZTCCAQqgAwIBAgIBCTAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1Sb290IFBh\n"
    "dGhMZW4wMB4XDTI2MTAxNzE4NDMwMloXDTQ2MTAxMjE4NDMwMlowGDEWMBQGA1UE\n"
    "AwwNUm9vdCBQYXRoTGVuMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLeGI0SD\n"
    "Gm1RsLgfTION/i6IUR7xVLFXAZPZCGKrcOWes9QHqNDHRQu9mPECn0zzkxEbyTwi\n"
    "Iqi9ms//pPI3O9CjRTBDMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD\n"
    "AgEGMB0GA1UdDgQWBBTzRKCaef3o7qsgptr40LZS9dVpUzAKBggqhkjOPQQDAgNJ\n"
    "ADBGAiEA8xY3H3JJ6D7ZjwRb4rWvIneG7GRN+LOfRl7ghEc9erICIQDEpkG8VV/c\n"
    "XafcVAdrVXYXW07aC78+RlG/o3/91shN2Q==\n"
    "-----END CERTIFICATE-----\n";

static const char SUB0_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBhDCCASqgAwIBAgIBCjAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1Sb290IFBh\n"
    "dGhMZW4wMB4XDTI2MTAxNzE4NDMwMloXDTQ1MTIxNjE4NDMwMlowGjEYMBYGA1UE\n"
    "AwwPU3ViIE9mIFBhdGhMZW4wMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEshvN\n"
    "JLAjZFHDK1Dy2WdmBb+K88wcTQvP89zzNFXdyQ+FW5VAmB3IP/vjU098K3QJKhTp\n"
    "uBEH3562d0kGDyvVTKNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n"
    "AQYwHQYDVR0OBBYEFEdsCrlxd4TNUzw3zBAKDG84D1VUMB8GA1UdIwQYMBaAFPNE\n"
    "oJp5/ejuqyCm2vjQtlL11WlTMAoGCCqGSM49BAMCA0gAMEUCIQClFnJemfGOkkhq\n"
    "SLWTy8KNnh3UgKIbqPAblTkA1WcUbwIgDziFZ0/PLhq6BylqPRfdxgATaAme+yX4\n"
    "OAzuTAiqeiE=\n"
    "-----END CERTIFICATE-----\n";

static const char DEEP_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBtTCCAVqgAwIBAgIBCzAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9TdWIgT2Yg\n"
    "UGF0aExlbjAwHhcNMjYxMDE3MTg0MzExWhcNMzYxMDE0MTg0MzExWjAbMRkwFwYD\n"
    "VQQDDBBkZWVwLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
    "tbDsXhxqM3yidl9C0ufrT2TJzeACqCFb1mJqSEQI4GUwCS1IwvPVf7fvy69W6TKy\n"
    "l0g7/YonK2tTqF1PB+6cK6OBjzCBjDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIH\n"
    "gDATBgNVHSUEDDAKBggrBgEFBQcDATAaBgNVHREEEzARgg93d3cuZXhhbXBsZS5j\n"
    "b20wHQYDVR0OBBYEFAvGPIc1SSO2i6wci1PDkdIhvy1vMB8GA1UdIwQYMBaAFEds\n"
    "Crlxd4TNUzw3zBAKDG84D1VUMAoGCCqGSM49BAMCA0kAMEYCIQDxBJoq9m+gTuCo\n"
    "d/Kl37zyd6dztou+rFT+DYqYTNeFwQIhAKuJew7QZguQQF2wRnx2aOojwBtYwVNc\n"
    "ER4KEt1Gs5DO\n"
    "-----END CERTIFICATE-----\n";

static const char NOCA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBdDCCARmgAwIBAgIBDDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlUZXN0IFJv\n"
    "b3QwHhcNMjYxMDE3MTg0MzAyWhcNNDUxMjE2MTg0MzAyWjATMREwDwYDVQQDDAhO\n"
    "b3QgQSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIXMDwpFSHBKUx32Q+yx\n"
    "qYjppH4tAWejeb31R/EUSbn3b3qeBxhQ9pQTKHc313XQ3mZTXqmyZlSXEZhqvTrD\n"
    "Uk6jXTBbMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgKEMB0GA1UdDgQWBBT/FXdY\n"
    "s8QxfQ20Qirhx87x2OVQuTAfBgNVHSMEGDAWgBRB9ZdzNyU66j9lh2x/YaHkSXrg\n"
    "GTAKBggqhkjOPQQDAgNJADBGAiEA5xPC5/jshHDI+h7YbrnUTJeo5q+n3dgjxlIO\n"
    "kteXcqwCIQDRvjO59sSTfUTVK7Q12YCCAYMO0tU+ibifbzFWlaoyog==\n"
    "-----END CERTIFICATE-----\n";

static const char UNDERNOCA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBrTCCAVSgAwIBAgIBDTAKBggqhkjOPQQDAjATMREwDwYDVQQDDAhOb3QgQSBD\n"
    "QTAeFw0yNjEwMTcxODQzMDJaFw0zNjEwMTQxODQzMDJaMBwxGjAYBgNVBAMMEXVu\n"
    "ZGVyLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtbDsXhxq\n"
    "M3yidl9C0ufrT2TJzeACqCFb1mJqSEQI4GUwCS1IwvPVf7fvy69W6TKyl0g7/Yon\n"
    "K2tTqF1PB+6cK6OBjzCBjDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNV\n"
    "HSUEDDAKBggrBgEFBQcDATAaBgNVHREEEzARgg93d3cuZXhhbXBsZS5jb20wHQYD\n"
    "VR0OBBYEFAvGPIc1SSO2i6wci1PDkdIhvy1vMB8GA1UdIwQYMBaAFP8Vd1izxDF9\n"
    "DbRCKuHHzvHY5VC5MAoGCCqGSM49BAMCA0cAMEQCIHGSVcoPjGXLaqVsM6pDpXI6\n"
    "cLS4kCyNsBh+RIdqtK+xAiBViDivEx2A4hlCX0GCjl/mPcXpSgwVEDfN7Z8LqqYU\n"
    "tQ==\n"
    "-----END CERTIFICATE-----\n";

static const char WEAK_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIB/jCCAaOgAwIBAgIBDjAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFUZXN0IElu\n"
    "dGVybWVkaWF0ZTAeFw0yNjEwMTcxODQzMDJaFw0zNjEwMTQxODQzMDJaMBsxGTAX\n"
    "BgNVBAMMEHdlYWsuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ\n"
    "AoGBAKdmQ+W18f+s0uK5ei7oI9a+42j6rXuJp9VrcXsLfZ/SPjMeGDaKrAbU8XvT\n"
    "EvOWDc6btVUuCVS8wXHRp6Nn1X5Xth127kMKtc5vpN3Uu0fLyQ4zomUnSVO/VY9O\n"
    "GtI5iKtT7Xqus623rzTH0UhNrJKklkUjoIg0F0xOniIgPSn9AgMBAAGjgY8wgYww\n"
    "CQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEw\n"
    "GgYDVR0RBBMwEYIPd3d3LmV4YW1wbGUuY29tMB0GA1UdDgQWBBTOV+xHl+8c0Ovt\n"
    "R9kmkEHx6qrM7DAfBgNVHSMEGDAWgBRHbAq5cXeEzVM8N8wQCgxvOA9VVDAKBggq\n"
    "hkjOPQQDAgNJADBGAiEAoIccwbc4E+IlIypd5B46zH5Es5wY5s4S/8958Yn/BA8C\n"
    "IQCkLoUukSZwdPnTbKvU/CRBgRx35GrSYsSjF+9THuqAkg==\n"
    "-----END CERTIFICATE-----\n";

static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

/* 2027-06-01, within the certificates' validity but past the short-lived one's. */
static const time_t WHEN = 1811808000;

static int accept_errors;

static const char *subject(X509 *x)
{
    static char buf[128];

    if (x == NULL)
        return "(none)";
    X509_NAME_oneline(X509_get_subject_name(x), buf, sizeof(buf));
    return buf;
}

static int trace_cb(int ok, X509_STORE_CTX *ctx)
{
    printf("    cb: ok %d, error %d, depth %d, cert %s\n", ok, X509_STORE_CTX_get_error(ctx),
           X509_STORE_CTX_get_error_depth(ctx), subject(X509_STORE_CTX_get_current_cert(ctx)));
    return ok || accept_errors;
}

struct run {
    const char *label;
    X509 *leaf;
    X509 *untrusted[3];
    X509 *trusted[3];
    unsigned long flags;
    int purpose, depth, level, accept;
    const char *host, *email, *ip;
    time_t when;
};

static void verify(const struct run *r)
{
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    STACK_OF(X509) *untrusted = sk_X509_new_null(), *chain;
    X509_VERIFY_PARAM *vpm;
    int i, ret;

    for (i = 0; i < 3 && r->trusted[i] != NULL; i++)
        X509_STORE_add_cert(store, r->trusted[i]);
    for (i = 0; i < 3 && r->untrusted[i] != NULL; i++)
        sk_X509_push(untrusted, r->untrusted[i]);
    X509_STORE_CTX_init(ctx, store, r->leaf, untrusted);
    X509_STORE_CTX_set_verify_cb(ctx, trace_cb);
    vpm = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set_time(vpm, r->when != 0 ? r->when : WHEN);
    if (r->flags != 0)
        X509_VERIFY_PARAM_set_flags(vpm, r->flags);
    if (strncmp(r->label, "trusted last", 12) == 0)
        X509_VERIFY_PARAM_clear_flags(vpm, X509_V_FLAG_TRUSTED_FIRST);
    if (r->purpose != 0)
        X509_STORE_CTX_set_purpose(ctx, r->purpose);
    if (r->depth != 0)
        X509_VERIFY_PARAM_set_depth(vpm, r->depth);
    if (r->level != 0)
        X509_VERIFY_PARAM_set_auth_level(vpm, r->level);
    if (r->host != NULL)
        X509_VERIFY_PARAM_set1_host(vpm, r->host, 0);
    if (r->email != NULL)
        X509_VERIFY_PARAM_set1_email(vpm, r->email, 0);
    if (r->ip != NULL)
        X509_VERIFY_PARAM_set1_ip_asc(vpm, r->ip);
    accept_errors = r->accept;
    printf("# %s\n", r->label);
    ret = X509_verify_cert(ctx);
    printf("  result %d, error %d (%s), depth %d, num_untrusted %d\n", ret, X509_STORE_CTX_get_error(ctx),
           X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)), X509_STORE_CTX_get_error_depth(ctx),
           X509_STORE_CTX_get_num_untrusted(ctx));
    chain = X509_STORE_CTX_get0_chain(ctx);
    printf("  chain:");
    for (i = 0; i < sk_X509_num(chain); i++)
        printf(" [%s]", subject(sk_X509_value(chain, i)));
    printf("\n");
    if (r->host != NULL)
        printf("  peername %s\n", X509_VERIFY_PARAM_get0_peername(vpm) == NULL ? "(none)" : X509_VERIFY_PARAM_get0_peername(vpm));
    errors();
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
}

static void show_url(const char *url, int with_query)
{
    char *scheme, *user, *host, *port, *path, *query = NULL, *frag;
    int num, r = OSSL_parse_url(url, &scheme, &user, &host, &port, &num, &path, with_query ? &query : NULL, &frag);

    if (r == 0) {
        printf("  [%s]: fails\n", url);
        errors();
        return;
    }
    printf("  [%s]: scheme [%s] user [%s] host [%s] port [%s] %d path [%s] query [%s] frag [%s]\n", url, scheme, user,
           host, port, num, path, query == NULL ? "(not asked)" : query, frag);
    OPENSSL_free(scheme);
    OPENSSL_free(user);
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);
    OPENSSL_free(query);
    OPENSSL_free(frag);
}

int main(void)
{
    X509 *root = read_cert(ROOT_PEM), *inter = read_cert(INTER_PEM), *leaf = read_cert(LEAF_PEM);
    X509 *shortlived = read_cert(SHORTLIVED_PEM), *nc = read_cert(NC_PEM), *out = read_cert(OUT_PEM);
    X509 *bad = read_cert(BAD_PEM), *ncok = read_cert(NCOK_PEM), *root0 = read_cert(ROOT0_PEM);
    X509 *sub0 = read_cert(SUB0_PEM), *deep = read_cert(DEEP_PEM), *noca = read_cert(NOCA_PEM);
    X509 *undernoca = read_cert(UNDERNOCA_PEM), *weak = read_cert(WEAK_PEM);
    const struct run runs[] = {
        { "complete", leaf, { inter }, { root }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "trusted last", leaf, { inter, root }, { root }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "intermediate trusted too", leaf, { inter }, { root, inter }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "missing intermediate", leaf, { NULL }, { root }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "no trust", leaf, { inter, root }, { NULL }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "self-signed leaf", root, { NULL }, { NULL }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "trusted self-signed leaf", root, { NULL }, { root }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "partial chain", leaf, { NULL }, { inter }, X509_V_FLAG_PARTIAL_CHAIN, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "partial chain, leaf trusted", leaf, { NULL }, { leaf }, X509_V_FLAG_PARTIAL_CHAIN, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "without partial chains", leaf, { NULL }, { inter }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "expired", shortlived, { inter }, { root }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "expired, accepted", shortlived, { inter }, { root }, 0, 0, 0, 0, 1, NULL, NULL, NULL, 0 },
        { "not yet valid", leaf, { inter }, { root }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 1000 },
        { "no time check", leaf, { inter }, { root }, X509_V_FLAG_NO_CHECK_TIME, 0, 0, 0, 0, NULL, NULL, NULL, 1000 },
        { "server purpose", leaf, { inter }, { root }, 0, X509_PURPOSE_SSL_SERVER, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "client purpose", leaf, { inter }, { root }, 0, X509_PURPOSE_SSL_CLIENT, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "S/MIME purpose, accepted", leaf, { inter }, { root }, 0, X509_PURPOSE_SMIME_SIGN, 0, 0, 1, NULL, NULL, NULL, 0 },
        { "host", leaf, { inter }, { root }, 0, 0, 0, 0, 0, "www.example.com", NULL, NULL, 0 },
        { "wrong host", leaf, { inter }, { root }, 0, 0, 0, 0, 0, "www.example.net", NULL, NULL, 0 },
        { "wrong email", leaf, { inter }, { root }, 0, 0, 0, 0, 0, NULL, "a@example.com", NULL, 0 },
        { "wrong IP", leaf, { inter }, { root }, 0, 0, 0, 0, 0, NULL, NULL, "192.0.2.1", 0 },
        { "name constraints, permitted", ncok, { nc }, { root }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "name constraints, not permitted", out, { nc }, { root }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "name constraints, excluded", bad, { nc }, { root }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "name constraints, both accepted", bad, { nc }, { root }, 0, 0, 0, 0, 1, NULL, NULL, NULL, 0 },
        { "path length", deep, { sub0 }, { root0 }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "issuer not a CA", undernoca, { noca }, { root }, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "depth 0", leaf, { inter }, { root }, 0, 0, -1, 0, 0, NULL, NULL, NULL, 0 },
        { "depth 1", leaf, { inter }, { root }, 0, 0, 1, 0, 0, NULL, NULL, NULL, 0 },
        { "weak key at level 2", weak, { inter }, { root }, 0, 0, 0, 2, 0, NULL, NULL, NULL, 0 },
        { "level 1", weak, { inter }, { root }, 0, 0, 0, 1, 0, NULL, NULL, NULL, 0 },
        { "strict", leaf, { inter }, { root }, X509_V_FLAG_X509_STRICT, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
        { "self-signature checked", leaf, { inter }, { root }, X509_V_FLAG_CHECK_SS_SIGNATURE, 0, 0, 0, 0, NULL, NULL, NULL, 0 },
    };
    size_t i;

    for (i = 0; i < sizeof(runs) / sizeof(runs[0]); i++) {
        struct run r = runs[i];

        verify(&r);
    }

    printf("# no certificate\n");
    {
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();

        X509_STORE_CTX_init(ctx, NULL, NULL, NULL);
        printf("  result %d, error %d\n", X509_verify_cert(ctx), X509_STORE_CTX_get_error(ctx));
        errors();
        printf("  again: %d\n", X509_verify_cert(ctx));
        X509_STORE_CTX_free(ctx);
        printf("  NULL: %d\n", X509_verify_cert(NULL));
        errors();
    }
    printf("# X509_STORE_CTX_verify\n");
    {
        X509_STORE *store = X509_STORE_new();
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        STACK_OF(X509) *untrusted = sk_X509_new_null();

        X509_STORE_add_cert(store, root);
        sk_X509_push(untrusted, leaf);
        sk_X509_push(untrusted, inter);
        X509_STORE_CTX_init(ctx, store, NULL, untrusted);
        X509_VERIFY_PARAM_set_time(X509_STORE_CTX_get0_param(ctx), WHEN);
        printf("  result %d, chain %d\n", X509_STORE_CTX_verify(ctx), sk_X509_num(X509_STORE_CTX_get0_chain(ctx)));
        X509_STORE_CTX_free(ctx);
        printf("  NULL: %d\n", X509_STORE_CTX_verify(NULL));
        errors();
        X509_STORE_free(store);
        sk_X509_free(untrusted);
    }
    printf("# X509_build_chain\n");
    {
        X509_STORE *store = X509_STORE_new();
        STACK_OF(X509) *certs = sk_X509_new_null(), *built;
        int j;

        X509_STORE_add_cert(store, root);
        sk_X509_push(certs, inter);
        built = X509_build_chain(leaf, certs, store, 0, NULL, NULL);
        printf("  with a store, no self-signed: %d:", sk_X509_num(built));
        for (j = 0; j < sk_X509_num(built); j++)
            printf(" [%s]", subject(sk_X509_value(built, j)));
        printf("\n");
        OSSL_STACK_OF_X509_free(built);
        built = X509_build_chain(leaf, certs, store, 1, NULL, NULL);
        printf("  with self-signed: %d\n", sk_X509_num(built));
        OSSL_STACK_OF_X509_free(built);
        sk_X509_push(certs, root);
        built = X509_build_chain(leaf, certs, NULL, 1, NULL, NULL);
        printf("  trusted list: %d\n", sk_X509_num(built));
        OSSL_STACK_OF_X509_free(built);
        built = X509_build_chain(shortlived, NULL, store, 0, NULL, NULL);
        printf("  incomplete: %s\n", built == NULL ? "none" : "some");
        OSSL_STACK_OF_X509_free(built);
        printf("  NULL: %s\n", X509_build_chain(NULL, NULL, NULL, 0, NULL, NULL) == NULL ? "none" : "some");
        errors();
        X509_STORE_free(store);
        sk_X509_free(certs);
    }
    printf("# NAME_CONSTRAINTS_check\n");
    {
        NAME_CONSTRAINTS *ncs = X509_get_ext_d2i(nc, NID_name_constraints, NULL, NULL);
        X509 *cnonly = X509_new();
        X509_NAME *n = X509_NAME_new();

        printf("  ok %d, out %d, bad %d, CN of out %d\n", NAME_CONSTRAINTS_check(ncok, ncs), NAME_CONSTRAINTS_check(out, ncs),
               NAME_CONSTRAINTS_check(bad, ncs), NAME_CONSTRAINTS_check_CN(out, ncs));
        X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"host.example.org", -1, -1, 0);
        X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"Not A Host", -1, -1, 0);
        X509_set_subject_name(cnonly, n);
        printf("  CN outside %d\n", NAME_CONSTRAINTS_check_CN(cnonly, ncs));
        X509_NAME_free(n);
        n = X509_NAME_new();
        X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"a.bad.example.com", -1, -1, 0);
        X509_set_subject_name(cnonly, n);
        printf("  CN excluded %d, all %d\n", NAME_CONSTRAINTS_check_CN(cnonly, ncs), NAME_CONSTRAINTS_check(cnonly, ncs));
        X509_NAME_free(n);
        X509_free(cnonly);
        NAME_CONSTRAINTS_free(ncs);
        errors();
    }
    printf("# OSSL_parse_url\n");
    {
        static const char *const urls[] = {
            "https://user@example.com:8443/a/b?q=1#frag", "http://[::1]:80/x", "example.com/path",
            "ldap://host", "http://h:99999/", "http://h:80x", "http://[::1/", "mailto:a@b", "http://h/?a#b",
            "file:///etc/x", "http://h: 80/", "http://h:-1/",
        };
        size_t j;

        for (j = 0; j < sizeof(urls) / sizeof(urls[0]); j++) {
            show_url(urls[j], 1);
            show_url(urls[j], 0);
        }
        printf("  NULL: %d\n", OSSL_parse_url(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL));
        errors();
    }
    check(1, "done");
    X509_free(root);
    X509_free(inter);
    X509_free(leaf);
    X509_free(shortlived);
    X509_free(nc);
    X509_free(out);
    X509_free(bad);
    X509_free(ncok);
    X509_free(root0);
    X509_free(sub0);
    X509_free(deep);
    X509_free(noca);
    X509_free(undernoca);
    X509_free(weak);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
