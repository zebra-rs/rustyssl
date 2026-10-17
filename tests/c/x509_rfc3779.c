/*
 * Conformance test for RFC 3779 path validation (X509v3_addr_validate_path(3),
 * X509v3_asid_validate_path, X509v3_addr_validate_resource_set,
 * X509v3_asid_validate_resource_set) and its part in X509_verify_cert: address blocks and AS
 * identifiers nested within their issuers', inheritance, issuers without resources, resources
 * outside the issuer's, a family the issuer lacks, and a trust anchor that inherits, with a
 * callback that sees, and may accept, each failure.
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

/*
 * The PKI, made with the reference's openssl tool: a root with 10.0.0.0/8, 2001:db8::/32,
 * AS 64496-64511, and RDI 1-10, and a root that inherits; CAs with 10.1.0.0/16 and AS 64500
 * (inheriting RDIs), inheriting everything, without resources, and with resources outside the
 * root's; and leaves with 10.1.2.0/24 and AS 64500, inheriting, with 2001:db8:1::/48, with
 * the root's own resources, with RDI 5, and without resources.
 */
static const char ROOT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBwDCCAWagAwIBAgIBATAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1SZXNvdXJj\n"
    "ZSBSb290MB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowGDEWMBQGA1UE\n"
    "AwwNUmVzb3VyY2UgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIvAttzZ\n"
    "RtSoSNNlUyoL6XwSlHV6TdtpuyxMOHnuQqW/QSl93DGtNafyHzg8Fy4W1LfNHOqg\n"
    "IeiAcBFqXyvAzOKjgaAwgZ0wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n"
    "AQYwLAYIKwYBBQUHAQcBAf8EHTAbMAoEAgABMAQDAgAKMA0EAgACMAcDBQAgAQ24\n"
    "MC0GCCsGAQUFBwEIAQH/BB4wHKAOMAwwCgIDAPvwAgMA+/+hCjAIMAYCAQECAQow\n"
    "HQYDVR0OBBYEFGvGmDZNsu90BnrIObYEJEO5gNW7MAoGCCqGSM49BAMCA0gAMEUC\n"
    "IQD/fNNfOZFAjGx35+vAgFFiR7RLc68m93geDxWU7nwhagIgECoMqGOX6QecSvj1\n"
    "8yBd9xDFYydfOjEAdG92ppzWdFY=\n"
    "-----END CERTIFICATE-----\n";

static const char ROOTINH_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBljCCAT2gAwIBAgIBAjAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9Jbmhlcml0\n"
    "aW5nIFJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAaMRgwFgYD\n"
    "VQQDDA9Jbmhlcml0aW5nIFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASL\n"
    "wLbc2UbUqEjTZVMqC+l8EpR1ek3babssTDh57kKlv0EpfdwxrTWn8h84PBcuFtS3\n"
    "zRzqoCHogHARal8rwMzio3QwcjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE\n"
    "AwIBBjAZBggrBgEFBQcBBwEB/wQKMAgwBgQCAAEFADAVBggrBgEFBQcBCAEB/wQG\n"
    "MASgAgUAMB0GA1UdDgQWBBRrxpg2TbLvdAZ6yDm2BCRDuYDVuzAKBggqhkjOPQQD\n"
    "AgNHADBEAiA/9tlMXM0ExurDk8NCkYBS0gMJt5Ru99zLiF4hfd+oHgIgPpYJctO6\n"
    "iGBmiu201YUWhlC/cApR4Vexjwsyjx4x17I=\n"
    "-----END CERTIFICATE-----\n";

static const char IOK_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBozCCAUigAwIBAgIBAzAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1SZXNvdXJj\n"
    "ZSBSb290MB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowFzEVMBMGA1UE\n"
    "AwwMUmVzb3VyY2VzIE9LMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi8C23NlG\n"
    "1KhI02VTKgvpfBKUdXpN22m7LEw4ee5Cpb9BKX3cMa01p/IfODwXLhbUt80c6qAh\n"
    "6IBwEWpfK8DM4qOBgzCBgDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB\n"
    "BjAeBggrBgEFBQcBBwEB/wQPMA0wCwQCAAEwBQMDAAoBMB4GCCsGAQUFBwEIAQH/\n"
    "BA8wDaAHMAUCAwD79KECBQAwHQYDVR0OBBYEFGvGmDZNsu90BnrIObYEJEO5gNW7\n"
    "MAoGCCqGSM49BAMCA0kAMEYCIQCaR2e0kBybhjaELxygIDcGa8dY4e/NPaSH9Abi\n"
    "KVuneQIhAMXYVlysrMtcBYewGKm5DgT01PnorfzWSI1odlUYNpch\n"
    "-----END CERTIFICATE-----\n";

static const char IINH_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBpTCCAUygAwIBAgIBBDAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1SZXNvdXJj\n"
    "ZSBSb290MB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowHjEcMBoGA1UE\n"
    "AwwTUmVzb3VyY2VzIEluaGVyaXRlZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\n"
    "BIvAttzZRtSoSNNlUyoL6XwSlHV6TdtpuyxMOHnuQqW/QSl93DGtNafyHzg8Fy4W\n"
    "1LfNHOqgIeiAcBFqXyvAzOKjgYAwfjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB\n"
    "/wQEAwIBBjAhBggrBgEFBQcBBwEB/wQSMBAwBgQCAAEFADAGBAIAAgUAMBkGCCsG\n"
    "AQUFBwEIAQH/BAowCKACBQChAgUAMB0GA1UdDgQWBBRrxpg2TbLvdAZ6yDm2BCRD\n"
    "uYDVuzAKBggqhkjOPQQDAgNHADBEAiBVzCFj5wcCVKrjLh6jedvkOXSvPP3fVTqk\n"
    "m8c0coQgoQIgAbYhbkujqIbOICNLPjnbgAtgJihZt8FXWrI+sct7IkM=\n"
    "-----END CERTIFICATE-----\n";

static const char INONE_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBYDCCAQagAwIBAgIBBTAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1SZXNvdXJj\n"
    "ZSBSb290MB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowFzEVMBMGA1UE\n"
    "AwwMTm8gUmVzb3VyY2VzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi8C23NlG\n"
    "1KhI02VTKgvpfBKUdXpN22m7LEw4ee5Cpb9BKX3cMa01p/IfODwXLhbUt80c6qAh\n"
    "6IBwEWpfK8DM4qNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\n"
    "HQYDVR0OBBYEFGvGmDZNsu90BnrIObYEJEO5gNW7MAoGCCqGSM49BAMCA0gAMEUC\n"
    "IQD9T0/MPSQpp0q+PW6tBdIP5LZfdA2OnYs5hnQBqORgNgIgS9Ay+4ZdJ6XQf38t\n"
    "0Dm6FuSKu3gzsDYTrdKdTojy7yc=\n"
    "-----END CERTIFICATE-----\n";

static const char IOUT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBoDCCAUegAwIBAgIBBjAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1SZXNvdXJj\n"
    "ZSBSb290MB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowHDEaMBgGA1UE\n"
    "AwwRUmVzb3VyY2VzIE91dHNpZGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASL\n"
    "wLbc2UbUqEjTZVMqC+l8EpR1ek3babssTDh57kKlv0EpfdwxrTWn8h84PBcuFtS3\n"
    "zRzqoCHogHARal8rwMzio34wfDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE\n"
    "AwIBBjAeBggrBgEFBQcBBwEB/wQPMA0wCwQCAAEwBQMDAMCoMBoGCCsGAQUFBwEI\n"
    "AQH/BAswCaAHMAUCAwD96DAdBgNVHQ4EFgQUa8aYNk2y73QGesg5tgQkQ7mA1bsw\n"
    "CgYIKoZIzj0EAwIDRwAwRAIgW2beLJ90VuPkHzo22bzDaAnZ5ClW5gAWU180rplU\n"
    "rr4CIBa+w4z553HABe54na5tv8DVwu5/36tXQEt5g7LIiZOx\n"
    "-----END CERTIFICATE-----\n";

static const char IOKR_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBrTCCAVOgAwIBAgIBBzAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9Jbmhlcml0\n"
    "aW5nIFJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAgMR4wHAYD\n"
    "VQQDDBVVbmRlciBJbmhlcml0aW5nIFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\n"
    "BwNCAASLwLbc2UbUqEjTZVMqC+l8EpR1ek3babssTDh57kKlv0EpfdwxrTWn8h84\n"
    "PBcuFtS3zRzqoCHogHARal8rwMzio4GDMIGAMA8GA1UdEwEB/wQFMAMBAf8wDgYD\n"
    "VR0PAQH/BAQDAgEGMB4GCCsGAQUFBwEHAQH/BA8wDTALBAIAATAFAwMACgEwHgYI\n"
    "KwYBBQUHAQgBAf8EDzANoAcwBQIDAPv0oQIFADAdBgNVHQ4EFgQUa8aYNk2y73QG\n"
    "esg5tgQkQ7mA1bswCgYIKoZIzj0EAwIDSAAwRQIhAN2MSVmwvyqobcBzRL/dLrGV\n"
    "mfOkyYiPGfYSUhACHjFsAiAFMuJk34+jXu5ObqYllMlbHDDTuIrbGJICHFkWF8mO\n"
    "xg==\n"
    "-----END CERTIFICATE-----\n";

static const char LOK_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBdzCCARygAwIBAgIBCDAKBggqhkjOPQQDAjAXMRUwEwYDVQQDDAxSZXNvdXJj\n"
    "ZXMgT0swHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjASMRAwDgYDVQQD\n"
    "DAdMZWFmIE9LMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi8C23NlG1KhI02VT\n"
    "KgvpfBKUdXpN22m7LEw4ee5Cpb9BKX3cMa01p/IfODwXLhbUt80c6qAh6IBwEWpf\n"
    "K8DM4qNeMFwwHwYIKwYBBQUHAQcBAf8EEDAOMAwEAgABMAYDBAAKAQIwGgYIKwYB\n"
    "BQUHAQgBAf8ECzAJoAcwBQIDAPv0MB0GA1UdDgQWBBRrxpg2TbLvdAZ6yDm2BCRD\n"
    "uYDVuzAKBggqhkjOPQQDAgNJADBGAiEAsFmdto1aTILSQ1ps6wk+uomHaYmIGsw0\n"
    "p7gv35zcBiUCIQC9flG3V8xC8BzAP1JvGtm4IAyJ8kTUp8H5CZJf0jm5gA==\n"
    "-----END CERTIFICATE-----\n";

static const char LINH_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBcjCCARegAwIBAgIBCTAKBggqhkjOPQQDAjAXMRUwEwYDVQQDDAxSZXNvdXJj\n"
    "ZXMgT0swHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAYMRYwFAYDVQQD\n"
    "DA1MZWFmIEluaGVyaXRzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi8C23NlG\n"
    "1KhI02VTKgvpfBKUdXpN22m7LEw4ee5Cpb9BKX3cMa01p/IfODwXLhbUt80c6qAh\n"
    "6IBwEWpfK8DM4qNTMFEwGQYIKwYBBQUHAQcBAf8ECjAIMAYEAgABBQAwFQYIKwYB\n"
    "BQUHAQgBAf8EBjAEoAIFADAdBgNVHQ4EFgQUa8aYNk2y73QGesg5tgQkQ7mA1bsw\n"
    "CgYIKoZIzj0EAwIDSQAwRgIhAPAUMBXZnEdrU0z/hICHVMVEXGSYgq9ipQT4Pdez\n"
    "miy8AiEA/y2o6vNQZ8CP6w4LYpCdvXnLra51jD7IgATd7m2Ttf8=\n"
    "-----END CERTIFICATE-----\n";

static const char LV6_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBXzCCAQWgAwIBAgIBCjAKBggqhkjOPQQDAjAXMRUwEwYDVQQDDAxSZXNvdXJj\n"
    "ZXMgT0swHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAUMRIwEAYDVQQD\n"
    "DAlMZWFmIElQdjYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASLwLbc2UbUqEjT\n"
    "ZVMqC+l8EpR1ek3babssTDh57kKlv0EpfdwxrTWn8h84PBcuFtS3zRzqoCHogHAR\n"
    "al8rwMzio0UwQzAiBggrBgEFBQcBBwEB/wQTMBEwDwQCAAIwCQMHACABDbgAATAd\n"
    "BgNVHQ4EFgQUa8aYNk2y73QGesg5tgQkQ7mA1bswCgYIKoZIzj0EAwIDSAAwRQIg\n"
    "UgyK5oFzqErnnjVn1T859ZQ78XmjjieP6StXaUydaqICIQDW3Y6lZHfgXJ1Bh4M3\n"
    "l302cYcGYUiWEbuxq+/4VF0TIg==\n"
    "-----END CERTIFICATE-----\n";

static const char LWIDE_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBgTCCASegAwIBAgIBCzAKBggqhkjOPQQDAjAXMRUwEwYDVQQDDAxSZXNvdXJj\n"
    "ZXMgT0swHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAYMRYwFAYDVQQD\n"
    "DA1MZWFmIFRvbyBXaWRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi8C23NlG\n"
    "1KhI02VTKgvpfBKUdXpN22m7LEw4ee5Cpb9BKX3cMa01p/IfODwXLhbUt80c6qAh\n"
    "6IBwEWpfK8DM4qNjMGEwHQYIKwYBBQUHAQcBAf8EDjAMMAoEAgABMAQDAgAKMCEG\n"
    "CCsGAQUFBwEIAQH/BBIwEKAOMAwwCgIDAPvwAgMA+/8wHQYDVR0OBBYEFGvGmDZN\n"
    "su90BnrIObYEJEO5gNW7MAoGCCqGSM49BAMCA0gAMEUCIBsfgbAkdPhYmYWC6dCT\n"
    "Z/yxmvv7cQMw7UHsJe3GA21iAiEAjgqg9a1+oOnKOLpwjao4VmVP1OEAF0lu3z/Y\n"
    "k57AYnU=\n"
    "-----END CERTIFICATE-----\n";

static const char LRDI_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBUzCB+qADAgECAgEMMAoGCCqGSM49BAMCMBcxFTATBgNVBAMMDFJlc291cmNl\n"
    "cyBPSzAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBMxETAPBgNVBAMM\n"
    "CExlYWYgUkRJMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi8C23NlG1KhI02VT\n"
    "KgvpfBKUdXpN22m7LEw4ee5Cpb9BKX3cMa01p/IfODwXLhbUt80c6qAh6IBwEWpf\n"
    "K8DM4qM7MDkwGAYIKwYBBQUHAQgBAf8ECTAHoQUwAwIBBTAdBgNVHQ4EFgQUa8aY\n"
    "Nk2y73QGesg5tgQkQ7mA1bswCgYIKoZIzj0EAwIDSAAwRQIgGbwF7Ex+CqbMZnLy\n"
    "AEEomN8ulu2xquiBpgQEaE8LN6ACIQDVR4IrtPoMrCxDs/aRR6IYH1TujQldBD9s\n"
    "0YuofH7QXA==\n"
    "-----END CERTIFICATE-----\n";

static const char LPLAIN_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBRzCB7aADAgECAgENMAoGCCqGSM49BAMCMBcxFTATBgNVBAMMDFJlc291cmNl\n"
    "cyBPSzAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBUxEzARBgNVBAMM\n"
    "CkxlYWYgUGxhaW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASLwLbc2UbUqEjT\n"
    "ZVMqC+l8EpR1ek3babssTDh57kKlv0EpfdwxrTWn8h84PBcuFtS3zRzqoCHogHAR\n"
    "al8rwMzioywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRrxpg2TbLvdAZ6yDm2BCRD\n"
    "uYDVuzAKBggqhkjOPQQDAgNJADBGAiEAgAx1220ulbuHFh1AaULngeAWHBJXlumd\n"
    "+uY/jh1ZeJYCIQD66UQ+PcsnZzxrcSMMMeyD0yX1hpjoAor5qvtcgqbT7w==\n"
    "-----END CERTIFICATE-----\n";

static const char LOK2_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBjjCCATOgAwIBAgIBDjAKBggqhkjOPQQDAjAeMRwwGgYDVQQDDBNSZXNvdXJj\n"
    "ZXMgSW5oZXJpdGVkMB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowIjEg\n"
    "MB4GA1UEAwwXTGVhZiBPSyBVbmRlciBJbmhlcml0ZWQwWTATBgcqhkjOPQIBBggq\n"
    "hkjOPQMBBwNCAASLwLbc2UbUqEjTZVMqC+l8EpR1ek3babssTDh57kKlv0Epfdwx\n"
    "rTWn8h84PBcuFtS3zRzqoCHogHARal8rwMzio14wXDAfBggrBgEFBQcBBwEB/wQQ\n"
    "MA4wDAQCAAEwBgMEAAoBAjAaBggrBgEFBQcBCAEB/wQLMAmgBzAFAgMA+/QwHQYD\n"
    "VR0OBBYEFGvGmDZNsu90BnrIObYEJEO5gNW7MAoGCCqGSM49BAMCA0kAMEYCIQC5\n"
    "7edkGAZzXj214H9nFZurWpIaY+k3t49dJ+aGgXgejAIhALA6DIo4Dx302XqS0Qbh\n"
    "nGPp52gksBuD5W8N0BKN4R3i\n"
    "-----END CERTIFICATE-----\n";

static const char LOK3_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBgDCCASegAwIBAgIBDzAKBggqhkjOPQQDAjAXMRUwEwYDVQQDDAxObyBSZXNv\n"
    "dXJjZXMwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAdMRswGQYDVQQD\n"
    "DBJMZWFmIE9LIFVuZGVyIE5vbmUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASL\n"
    "wLbc2UbUqEjTZVMqC+l8EpR1ek3babssTDh57kKlv0EpfdwxrTWn8h84PBcuFtS3\n"
    "zRzqoCHogHARal8rwMzio14wXDAfBggrBgEFBQcBBwEB/wQQMA4wDAQCAAEwBgME\n"
    "AAoBAjAaBggrBgEFBQcBCAEB/wQLMAmgBzAFAgMA+/QwHQYDVR0OBBYEFGvGmDZN\n"
    "su90BnrIObYEJEO5gNW7MAoGCCqGSM49BAMCA0cAMEQCICvgpk+/hT5AJ179BMB/\n"
    "THAE2yUSB7Fqu2DokO3h5t89AiAad+6aUSkpQCuhu9iCl/0laplaHBjgOER+7FCG\n"
    "oDvkMg==\n"
    "-----END CERTIFICATE-----\n";

static const char LOK4_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBiTCCAS+gAwIBAgIBEDAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFSZXNvdXJj\n"
    "ZXMgT3V0c2lkZTAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMCAxHjAc\n"
    "BgNVBAMMFUxlYWYgT0sgVW5kZXIgT3V0c2lkZTBZMBMGByqGSM49AgEGCCqGSM49\n"
    "AwEHA0IABIvAttzZRtSoSNNlUyoL6XwSlHV6TdtpuyxMOHnuQqW/QSl93DGtNafy\n"
    "Hzg8Fy4W1LfNHOqgIeiAcBFqXyvAzOKjXjBcMB8GCCsGAQUFBwEHAQH/BBAwDjAM\n"
    "BAIAATAGAwQACgECMBoGCCsGAQUFBwEIAQH/BAswCaAHMAUCAwD79DAdBgNVHQ4E\n"
    "FgQUa8aYNk2y73QGesg5tgQkQ7mA1bswCgYIKoZIzj0EAwIDSAAwRQIgQyp3JFAC\n"
    "s0g29t1SMiU8QZaDv2iEpq4X/mSyLqc4NOACIQC59fQ08VlW6iBOwC6IwCABmEnk\n"
    "56vENu/NLteC//0I9Q==\n"
    "-----END CERTIFICATE-----\n";

static const char LOK5_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBlTCCATugAwIBAgIBETAKBggqhkjOPQQDAjAgMR4wHAYDVQQDDBVVbmRlciBJ\n"
    "bmhlcml0aW5nIFJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAo\n"
    "MSYwJAYDVQQDDB1MZWFmIE9LIFVuZGVyIEluaGVyaXRpbmcgUm9vdDBZMBMGByqG\n"
    "SM49AgEGCCqGSM49AwEHA0IABIvAttzZRtSoSNNlUyoL6XwSlHV6TdtpuyxMOHnu\n"
    "QqW/QSl93DGtNafyHzg8Fy4W1LfNHOqgIeiAcBFqXyvAzOKjXjBcMB8GCCsGAQUF\n"
    "BwEHAQH/BBAwDjAMBAIAATAGAwQACgECMBoGCCsGAQUFBwEIAQH/BAswCaAHMAUC\n"
    "AwD79DAdBgNVHQ4EFgQUa8aYNk2y73QGesg5tgQkQ7mA1bswCgYIKoZIzj0EAwID\n"
    "SAAwRQIhAIEh4xJmk2Htmtt6UnTdW3GItgBDEysKxQ9xQAEnwlwQAiB/r55gE9dk\n"
    "MZiP2rPrpzajoHQRS/tSk2mgWWOTsCP/UQ==\n"
    "-----END CERTIFICATE-----\n";
static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    X509_check_purpose(x, -1, 0);
    return x;
}

/* 2027-06-01, within the certificates' validity. */
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

static void verify(const char *label, X509 *leaf, X509 *inter, X509 *root, int accept)
{
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    STACK_OF(X509) *untrusted = sk_X509_new_null();
    int ret;

    X509_STORE_add_cert(store, root);
    if (inter != NULL)
        sk_X509_push(untrusted, inter);
    X509_STORE_CTX_init(ctx, store, leaf, untrusted);
    X509_STORE_CTX_set_verify_cb(ctx, trace_cb);
    X509_VERIFY_PARAM_set_time(X509_STORE_CTX_get0_param(ctx), WHEN);
    accept_errors = accept;
    printf("# %s\n", label);
    ret = X509_verify_cert(ctx);
    printf("  result %d, error %d (%s), depth %d, cert %s\n", ret, X509_STORE_CTX_get_error(ctx),
           X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)), X509_STORE_CTX_get_error_depth(ctx),
           subject(X509_STORE_CTX_get_current_cert(ctx)));
    if (sk_X509_num(X509_STORE_CTX_get0_chain(ctx)) > 0) {
        accept_errors = 1;
        X509_STORE_CTX_set_error(ctx, X509_V_OK);
        printf("  again: asid %d, addr %d, error %d\n", X509v3_asid_validate_path(ctx),
               X509v3_addr_validate_path(ctx), X509_STORE_CTX_get_error(ctx));
    }
    errors();
    check(1, label);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
}

static void resources(const char *label, X509 *of, X509 *a, X509 *b)
{
    STACK_OF(X509) *chain = sk_X509_new_null();
    IPAddrBlocks *addr = X509_get_ext_d2i(of, NID_sbgp_ipAddrBlock, NULL, NULL);
    ASIdentifiers *asid = X509_get_ext_d2i(of, NID_sbgp_autonomousSysNum, NULL, NULL);

    if (a != NULL)
        sk_X509_push(chain, a);
    if (b != NULL)
        sk_X509_push(chain, b);
    printf("# resource sets: %s\n", label);
    printf("  addr %d %d, asid %d %d\n", X509v3_addr_validate_resource_set(chain, addr, 0),
           X509v3_addr_validate_resource_set(chain, addr, 1), X509v3_asid_validate_resource_set(chain, asid, 0),
           X509v3_asid_validate_resource_set(chain, asid, 1));
    errors();
    check(1, label);
    sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
    ASIdentifiers_free(asid);
    sk_X509_free(chain);
}

int main(void)
{
    X509 *root = read_cert(ROOT_PEM), *rootinh = read_cert(ROOTINH_PEM), *iok = read_cert(IOK_PEM);
    X509 *iinh = read_cert(IINH_PEM), *inone = read_cert(INONE_PEM), *iout = read_cert(IOUT_PEM);
    X509 *iokr = read_cert(IOKR_PEM), *lok = read_cert(LOK_PEM), *linh = read_cert(LINH_PEM);
    X509 *lv6 = read_cert(LV6_PEM), *lwide = read_cert(LWIDE_PEM), *lrdi = read_cert(LRDI_PEM);
    X509 *lplain = read_cert(LPLAIN_PEM), *lok2 = read_cert(LOK2_PEM), *lok3 = read_cert(LOK3_PEM);
    X509 *lok4 = read_cert(LOK4_PEM), *lok5 = read_cert(LOK5_PEM);

    verify("nested", lok, iok, root, 0);
    verify("leaf inherits", linh, iok, root, 0);
    verify("CA inherits", lok2, iinh, root, 0);
    verify("CA without resources", lok3, inone, root, 0);
    verify("CA without resources, accepted", lok3, inone, root, 1);
    verify("CA outside the root's", lok4, iout, root, 0);
    verify("CA outside the root's, accepted", lok4, iout, root, 1);
    verify("leaf wider than its CA", lwide, iok, root, 0);
    verify("leaf wider than its CA, accepted", lwide, iok, root, 1);
    verify("family the CA lacks", lv6, iok, root, 0);
    verify("RDI inherited through the CA", lrdi, iok, root, 0);
    verify("leaf without resources", lplain, iok, root, 0);
    verify("root inherits", lok5, iokr, rootinh, 0);
    verify("root inherits, accepted", lok5, iokr, rootinh, 1);
    verify("root alone", root, NULL, root, 0);

    resources("leaf under its chain", lok, iok, root);
    resources("inheriting leaf", linh, iok, root);
    resources("wide leaf", lwide, iok, root);
    resources("IPv6 leaf", lv6, iok, root);
    resources("under the root only", lwide, root, NULL);
    resources("under an inheriting CA", lok, iinh, root);
    resources("under a CA without resources", lok, inone, root);
    resources("no chain", lok, NULL, NULL);
    resources("no resources", lplain, iok, root);
    printf("# NULL chains\n");
    printf("  addr %d, asid %d\n", X509v3_addr_validate_resource_set(NULL, NULL, 0),
           X509v3_asid_validate_resource_set(NULL, NULL, 0));
    check(1, "NULL chains");
    printf("# no chain in the context\n");
    {
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();

        X509_STORE_CTX_init(ctx, NULL, lok, NULL);
        printf("  asid %d, error %d\n", X509v3_asid_validate_path(ctx), X509_STORE_CTX_get_error(ctx));
        X509_STORE_CTX_set_error(ctx, X509_V_OK);
        printf("  addr %d, error %d\n", X509v3_addr_validate_path(ctx), X509_STORE_CTX_get_error(ctx));
        X509_STORE_CTX_free(ctx);
    }
    check(1, "no chain in the context");

    X509_free(root);
    X509_free(rootinh);
    X509_free(iok);
    X509_free(iinh);
    X509_free(inone);
    X509_free(iout);
    X509_free(iokr);
    X509_free(lok);
    X509_free(linh);
    X509_free(lv6);
    X509_free(lwide);
    X509_free(lrdi);
    X509_free(lplain);
    X509_free(lok2);
    X509_free(lok3);
    X509_free(lok4);
    X509_free(lok5);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
