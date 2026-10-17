/*
 * Conformance test for the policy tree (X509_policy_check(3), the X509_policy_tree_*,
 * _level_*, and _node_* getters, X509_POLICY_NODE_print) and policy checking in
 * X509_verify_cert (X509_V_FLAG_POLICY_CHECK, _EXPLICIT_POLICY, _INHIBIT_ANY, _INHIBIT_MAP,
 * _NOTIFY_POLICY, the user's acceptable policies): policies matched down the chain, anyPolicy,
 * qualifiers, mappings, policy constraints, inhibitAnyPolicy, duplicate (invalid) policies,
 * and a chain of mappings whose tree outgrows OpenSSL's 1,000-node bound (CVE-2023-0464).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>
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
 * The PKI, made with the reference's openssl tool (policies under 1.3.6.1.4.1.55555.1): a
 * root; CAs with policies 1 and 2, with anyPolicy (and a CPS), mapping 1 to 3, requiring an
 * explicit policy, inhibiting anyPolicy, and inhibiting mapping after mapping 1 to 3; three
 * "bomb" CAs with policies 1 to 10 each mapped to all ten; and leaves with policy 1 (critical,
 * with a CPS and a user notice), 3, none, anyPolicy, 1 twice, and 1 and 2.
 */
static const char ROOT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBXDCCAQOgAwIBAgIBATAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtQb2xpY3kg\n"
    "Um9vdDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBYxFDASBgNVBAMM\n"
    "C1BvbGljeSBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPl7vlrPAYcFN\n"
    "WmgwuNsX1N+/WG016hopSFbNs7Q4HRtSYfjmoPEFUJwd5UJvh9rY9UVtKL9zMXLD\n"
    "MFiBYffqOKNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYD\n"
    "VR0OBBYEFNztpRcHS5eiQoa2K0JrGpc5ANblMAoGCCqGSM49BAMCA0cAMEQCIFef\n"
    "8cY8gFSCzU90hgu00d+DN9DVbORP/aHnWlxjATprAiAeRDOKfI/s+fSpVspLyELw\n"
    "aN55BLWWcbOyUHTrrik+9Q==\n"
    "-----END CERTIFICATE-----\n";

static const char IP12_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBiDCCAS+gAwIBAgIBAjAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtQb2xpY3kg\n"
    "Um9vdDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBsxGTAXBgNVBAMM\n"
    "EFBvbGljaWVzIDEgYW5kIDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ+Xu+W\n"
    "s8BhwU1aaDC42xfU379YbTXqGilIVs2ztDgdG1Jh+Oag8QVQnB3lQm+H2tj1RW0o\n"
    "v3MxcsMwWIFh9+o4o2kwZzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB\n"
    "BjAlBgNVHSAEHjAcMAwGCisGAQQBg7IDAQEwDAYKKwYBBAGDsgMBAjAdBgNVHQ4E\n"
    "FgQU3O2lFwdLl6JChrYrQmsalzkA1uUwCgYIKoZIzj0EAwIDRwAwRAIgW/26m0/g\n"
    "FWh320vqFcYTWcoflAD5dkH6UvSsYezvY9ACIDgI63CBPCPiyQmHnk2N8/l9h2/j\n"
    "OteXnrR40VphmpqS\n"
    "-----END CERTIFICATE-----\n";

static const char IANY_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBlDCCATugAwIBAgIBAzAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtQb2xpY3kg\n"
    "Um9vdDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBUxEzARBgNVBAMM\n"
    "CkFueSBQb2xpY3kwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ+Xu+Ws8BhwU1a\n"
    "aDC42xfU379YbTXqGilIVs2ztDgdG1Jh+Oag8QVQnB3lQm+H2tj1RW0ov3MxcsMw\n"
    "WIFh9+o4o3sweTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjA3BgNV\n"
    "HSAEMDAuMCwGBFUdIAAwJDAiBggrBgEFBQcCARYWaHR0cDovL2Nwcy5leGFtcGxl\n"
    "L2FueTAdBgNVHQ4EFgQU3O2lFwdLl6JChrYrQmsalzkA1uUwCgYIKoZIzj0EAwID\n"
    "RwAwRAIgQqRUZi79W6gNq+2tsC5DS9z9fhaDaC6ntoj5+q0lmswCID7uhPCJ4CSh\n"
    "C9oW+rKs/pHIQPSAaJDOykvrTHBF9/js\n"
    "-----END CERTIFICATE-----\n";

static const char IMAP_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBnjCCAUWgAwIBAgIBBDAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtQb2xpY3kg\n"
    "Um9vdDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBkxFzAVBgNVBAMM\n"
    "Dk1hcHBpbmcgMSB0byAzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPl7vlrPA\n"
    "YcFNWmgwuNsX1N+/WG016hopSFbNs7Q4HRtSYfjmoPEFUJwd5UJvh9rY9UVtKL9z\n"
    "MXLDMFiBYffqOKOBgDB+MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEG\n"
    "MBcGA1UdIAQQMA4wDAYKKwYBBAGDsgMBATAjBgNVHSEEHDAaMBgGCisGAQQBg7ID\n"
    "AQEGCisGAQQBg7IDAQMwHQYDVR0OBBYEFNztpRcHS5eiQoa2K0JrGpc5ANblMAoG\n"
    "CCqGSM49BAMCA0cAMEQCIAJqLDBn5oWuF79SAUhq+mIKEjb+bD5IxlUCDvooW4dQ\n"
    "AiBh9JYv/S67FnMxUzBwtpxXWE/QNtnBz9zTgBMYERbigA==\n"
    "-----END CERTIFICATE-----\n";

static const char IREQ_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBiTCCATCgAwIBAgIBBTAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtQb2xpY3kg\n"
    "Um9vdDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBwxGjAYBgNVBAMM\n"
    "EUV4cGxpY2l0IFJlcXVpcmVkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPl7v\n"
    "lrPAYcFNWmgwuNsX1N+/WG016hopSFbNs7Q4HRtSYfjmoPEFUJwd5UJvh9rY9UVt\n"
    "KL9zMXLDMFiBYffqOKNpMGcwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n"
    "AQYwFwYDVR0gBBAwDjAMBgorBgEEAYOyAwEBMAwGA1UdJAQFMAOAAQAwHQYDVR0O\n"
    "BBYEFNztpRcHS5eiQoa2K0JrGpc5ANblMAoGCCqGSM49BAMCA0cAMEQCICoR/etT\n"
    "4izev1cuzLpzU1aM2r652M09E/x4UOMB8ZIgAiAWPXJF3OyVBmqUTnHeyMPRlUWP\n"
    "skV4ud3nrAxUJeQwLg==\n"
    "-----END CERTIFICATE-----\n";

static const char IINH_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBfjCCASSgAwIBAgIBBjAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtQb2xpY3kg\n"
    "Um9vdDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBgxFjAUBgNVBAMM\n"
    "DUFueSBJbmhpYml0ZWQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ+Xu+Ws8Bh\n"
    "wU1aaDC42xfU379YbTXqGilIVs2ztDgdG1Jh+Oag8QVQnB3lQm+H2tj1RW0ov3Mx\n"
    "csMwWIFh9+o4o2EwXzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAR\n"
    "BgNVHSAECjAIMAYGBFUdIAAwCgYDVR02BAMCAQAwHQYDVR0OBBYEFNztpRcHS5ei\n"
    "Qoa2K0JrGpc5ANblMAoGCCqGSM49BAMCA0gAMEUCIQDB+2jTAZ1d2XMId7425tch\n"
    "KZAJUp9Xg0LBD+9DwnwY/wIgcNQWkW/T3+WoiDXDBPEi5MJnjt+pCMJHWqgq7HJW\n"
    "v9w=\n"
    "-----END CERTIFICATE-----\n";

static const char INOMAP_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBsDCCAVegAwIBAgIBBzAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtQb2xpY3kg\n"
    "Um9vdDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBwxGjAYBgNVBAMM\n"
    "EU1hcHBpbmcgSW5oaWJpdGVkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPl7v\n"
    "lrPAYcFNWmgwuNsX1N+/WG016hopSFbNs7Q4HRtSYfjmoPEFUJwd5UJvh9rY9UVt\n"
    "KL9zMXLDMFiBYffqOKOBjzCBjDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE\n"
    "AwIBBjAXBgNVHSAEEDAOMAwGCisGAQQBg7IDAQEwIwYDVR0hBBwwGjAYBgorBgEE\n"
    "AYOyAwEBBgorBgEEAYOyAwEDMAwGA1UdJAQFMAOBAQAwHQYDVR0OBBYEFNztpRcH\n"
    "S5eiQoa2K0JrGpc5ANblMAoGCCqGSM49BAMCA0cAMEQCIBsk4grkQx1BBirXOnaf\n"
    "McOcfhiIPqQrpvT1xZIHcCe4AiB05CyNpsAuK3XVpNtAXLcr844BbWq0aS4/QAyR\n"
    "xk2zgw==\n"
    "-----END CERTIFICATE-----\n";

static const char B1_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIMLjCCC9WgAwIBAgIBCDAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtQb2xpY3kg\n"
    "Um9vdDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBExDzANBgNVBAMM\n"
    "BkJvbWIgMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD5e75azwGHBTVpoMLjb\n"
    "F9Tfv1htNeoaKUhWzbO0OB0bUmH45qDxBVCcHeVCb4fa2PVFbSi/czFywzBYgWH3\n"
    "6jijggsXMIILEzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjCBlwYD\n"
    "VR0gBIGPMIGMMAwGCisGAQQBg7IDAQEwDAYKKwYBBAGDsgMBAjAMBgorBgEEAYOy\n"
    "AwEDMAwGCisGAQQBg7IDAQQwDAYKKwYBBAGDsgMBBTAMBgorBgEEAYOyAwEGMAwG\n"
    "CisGAQQBg7IDAQcwDAYKKwYBBAGDsgMBCDAMBgorBgEEAYOyAwEJMAwGCisGAQQB\n"
    "g7IDAQowggo1BgNVHSEEggosMIIKKDAYBgorBgEEAYOyAwEBBgorBgEEAYOyAwEB\n"
    "MBgGCisGAQQBg7IDAQEGCisGAQQBg7IDAQIwGAYKKwYBBAGDsgMBAQYKKwYBBAGD\n"
    "sgMBAzAYBgorBgEEAYOyAwEBBgorBgEEAYOyAwEEMBgGCisGAQQBg7IDAQEGCisG\n"
    "AQQBg7IDAQUwGAYKKwYBBAGDsgMBAQYKKwYBBAGDsgMBBjAYBgorBgEEAYOyAwEB\n"
    "BgorBgEEAYOyAwEHMBgGCisGAQQBg7IDAQEGCisGAQQBg7IDAQgwGAYKKwYBBAGD\n"
    "sgMBAQYKKwYBBAGDsgMBCTAYBgorBgEEAYOyAwEBBgorBgEEAYOyAwEKMBgGCisG\n"
    "AQQBg7IDAQIGCisGAQQBg7IDAQEwGAYKKwYBBAGDsgMBAgYKKwYBBAGDsgMBAjAY\n"
    "BgorBgEEAYOyAwECBgorBgEEAYOyAwEDMBgGCisGAQQBg7IDAQIGCisGAQQBg7ID\n"
    "AQQwGAYKKwYBBAGDsgMBAgYKKwYBBAGDsgMBBTAYBgorBgEEAYOyAwECBgorBgEE\n"
    "AYOyAwEGMBgGCisGAQQBg7IDAQIGCisGAQQBg7IDAQcwGAYKKwYBBAGDsgMBAgYK\n"
    "KwYBBAGDsgMBCDAYBgorBgEEAYOyAwECBgorBgEEAYOyAwEJMBgGCisGAQQBg7ID\n"
    "AQIGCisGAQQBg7IDAQowGAYKKwYBBAGDsgMBAwYKKwYBBAGDsgMBATAYBgorBgEE\n"
    "AYOyAwEDBgorBgEEAYOyAwECMBgGCisGAQQBg7IDAQMGCisGAQQBg7IDAQMwGAYK\n"
    "KwYBBAGDsgMBAwYKKwYBBAGDsgMBBDAYBgorBgEEAYOyAwEDBgorBgEEAYOyAwEF\n"
    "MBgGCisGAQQBg7IDAQMGCisGAQQBg7IDAQYwGAYKKwYBBAGDsgMBAwYKKwYBBAGD\n"
    "sgMBBzAYBgorBgEEAYOyAwEDBgorBgEEAYOyAwEIMBgGCisGAQQBg7IDAQMGCisG\n"
    "AQQBg7IDAQkwGAYKKwYBBAGDsgMBAwYKKwYBBAGDsgMBCjAYBgorBgEEAYOyAwEE\n"
    "BgorBgEEAYOyAwEBMBgGCisGAQQBg7IDAQQGCisGAQQBg7IDAQIwGAYKKwYBBAGD\n"
    "sgMBBAYKKwYBBAGDsgMBAzAYBgorBgEEAYOyAwEEBgorBgEEAYOyAwEEMBgGCisG\n"
    "AQQBg7IDAQQGCisGAQQBg7IDAQUwGAYKKwYBBAGDsgMBBAYKKwYBBAGDsgMBBjAY\n"
    "BgorBgEEAYOyAwEEBgorBgEEAYOyAwEHMBgGCisGAQQBg7IDAQQGCisGAQQBg7ID\n"
    "AQgwGAYKKwYBBAGDsgMBBAYKKwYBBAGDsgMBCTAYBgorBgEEAYOyAwEEBgorBgEE\n"
    "AYOyAwEKMBgGCisGAQQBg7IDAQUGCisGAQQBg7IDAQEwGAYKKwYBBAGDsgMBBQYK\n"
    "KwYBBAGDsgMBAjAYBgorBgEEAYOyAwEFBgorBgEEAYOyAwEDMBgGCisGAQQBg7ID\n"
    "AQUGCisGAQQBg7IDAQQwGAYKKwYBBAGDsgMBBQYKKwYBBAGDsgMBBTAYBgorBgEE\n"
    "AYOyAwEFBgorBgEEAYOyAwEGMBgGCisGAQQBg7IDAQUGCisGAQQBg7IDAQcwGAYK\n"
    "KwYBBAGDsgMBBQYKKwYBBAGDsgMBCDAYBgorBgEEAYOyAwEFBgorBgEEAYOyAwEJ\n"
    "MBgGCisGAQQBg7IDAQUGCisGAQQBg7IDAQowGAYKKwYBBAGDsgMBBgYKKwYBBAGD\n"
    "sgMBATAYBgorBgEEAYOyAwEGBgorBgEEAYOyAwECMBgGCisGAQQBg7IDAQYGCisG\n"
    "AQQBg7IDAQMwGAYKKwYBBAGDsgMBBgYKKwYBBAGDsgMBBDAYBgorBgEEAYOyAwEG\n"
    "BgorBgEEAYOyAwEFMBgGCisGAQQBg7IDAQYGCisGAQQBg7IDAQYwGAYKKwYBBAGD\n"
    "sgMBBgYKKwYBBAGDsgMBBzAYBgorBgEEAYOyAwEGBgorBgEEAYOyAwEIMBgGCisG\n"
    "AQQBg7IDAQYGCisGAQQBg7IDAQkwGAYKKwYBBAGDsgMBBgYKKwYBBAGDsgMBCjAY\n"
    "BgorBgEEAYOyAwEHBgorBgEEAYOyAwEBMBgGCisGAQQBg7IDAQcGCisGAQQBg7ID\n"
    "AQIwGAYKKwYBBAGDsgMBBwYKKwYBBAGDsgMBAzAYBgorBgEEAYOyAwEHBgorBgEE\n"
    "AYOyAwEEMBgGCisGAQQBg7IDAQcGCisGAQQBg7IDAQUwGAYKKwYBBAGDsgMBBwYK\n"
    "KwYBBAGDsgMBBjAYBgorBgEEAYOyAwEHBgorBgEEAYOyAwEHMBgGCisGAQQBg7ID\n"
    "AQcGCisGAQQBg7IDAQgwGAYKKwYBBAGDsgMBBwYKKwYBBAGDsgMBCTAYBgorBgEE\n"
    "AYOyAwEHBgorBgEEAYOyAwEKMBgGCisGAQQBg7IDAQgGCisGAQQBg7IDAQEwGAYK\n"
    "KwYBBAGDsgMBCAYKKwYBBAGDsgMBAjAYBgorBgEEAYOyAwEIBgorBgEEAYOyAwED\n"
    "MBgGCisGAQQBg7IDAQgGCisGAQQBg7IDAQQwGAYKKwYBBAGDsgMBCAYKKwYBBAGD\n"
    "sgMBBTAYBgorBgEEAYOyAwEIBgorBgEEAYOyAwEGMBgGCisGAQQBg7IDAQgGCisG\n"
    "AQQBg7IDAQcwGAYKKwYBBAGDsgMBCAYKKwYBBAGDsgMBCDAYBgorBgEEAYOyAwEI\n"
    "BgorBgEEAYOyAwEJMBgGCisGAQQBg7IDAQgGCisGAQQBg7IDAQowGAYKKwYBBAGD\n"
    "sgMBCQYKKwYBBAGDsgMBATAYBgorBgEEAYOyAwEJBgorBgEEAYOyAwECMBgGCisG\n"
    "AQQBg7IDAQkGCisGAQQBg7IDAQMwGAYKKwYBBAGDsgMBCQYKKwYBBAGDsgMBBDAY\n"
    "BgorBgEEAYOyAwEJBgorBgEEAYOyAwEFMBgGCisGAQQBg7IDAQkGCisGAQQBg7ID\n"
    "AQYwGAYKKwYBBAGDsgMBCQYKKwYBBAGDsgMBBzAYBgorBgEEAYOyAwEJBgorBgEE\n"
    "AYOyAwEIMBgGCisGAQQBg7IDAQkGCisGAQQBg7IDAQkwGAYKKwYBBAGDsgMBCQYK\n"
    "KwYBBAGDsgMBCjAYBgorBgEEAYOyAwEKBgorBgEEAYOyAwEBMBgGCisGAQQBg7ID\n"
    "AQoGCisGAQQBg7IDAQIwGAYKKwYBBAGDsgMBCgYKKwYBBAGDsgMBAzAYBgorBgEE\n"
    "AYOyAwEKBgorBgEEAYOyAwEEMBgGCisGAQQBg7IDAQoGCisGAQQBg7IDAQUwGAYK\n"
    "KwYBBAGDsgMBCgYKKwYBBAGDsgMBBjAYBgorBgEEAYOyAwEKBgorBgEEAYOyAwEH\n"
    "MBgGCisGAQQBg7IDAQoGCisGAQQBg7IDAQgwGAYKKwYBBAGDsgMBCgYKKwYBBAGD\n"
    "sgMBCTAYBgorBgEEAYOyAwEKBgorBgEEAYOyAwEKMB0GA1UdDgQWBBTc7aUXB0uX\n"
    "okKGtitCaxqXOQDW5TAKBggqhkjOPQQDAgNHADBEAiBCvaVZnbVpkemz3HuA03ZB\n"
    "876VZfecJ8QxbmN0qFM+6wIgSd2GDIFUzj7ZA31DF1egCs9IPwBXD28TMqASF8dd\n"
    "JWc=\n"
    "-----END CERTIFICATE-----\n";

static const char B2_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIMKjCCC9CgAwIBAgIBCTAKBggqhkjOPQQDAjARMQ8wDQYDVQQDDAZCb21iIDEw\n"
    "HhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjARMQ8wDQYDVQQDDAZCb21i\n"
    "IDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ+Xu+Ws8BhwU1aaDC42xfU379Y\n"
    "bTXqGilIVs2ztDgdG1Jh+Oag8QVQnB3lQm+H2tj1RW0ov3MxcsMwWIFh9+o4o4IL\n"
    "FzCCCxMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwgZcGA1UdIASB\n"
    "jzCBjDAMBgorBgEEAYOyAwEBMAwGCisGAQQBg7IDAQIwDAYKKwYBBAGDsgMBAzAM\n"
    "BgorBgEEAYOyAwEEMAwGCisGAQQBg7IDAQUwDAYKKwYBBAGDsgMBBjAMBgorBgEE\n"
    "AYOyAwEHMAwGCisGAQQBg7IDAQgwDAYKKwYBBAGDsgMBCTAMBgorBgEEAYOyAwEK\n"
    "MIIKNQYDVR0hBIIKLDCCCigwGAYKKwYBBAGDsgMBAQYKKwYBBAGDsgMBATAYBgor\n"
    "BgEEAYOyAwEBBgorBgEEAYOyAwECMBgGCisGAQQBg7IDAQEGCisGAQQBg7IDAQMw\n"
    "GAYKKwYBBAGDsgMBAQYKKwYBBAGDsgMBBDAYBgorBgEEAYOyAwEBBgorBgEEAYOy\n"
    "AwEFMBgGCisGAQQBg7IDAQEGCisGAQQBg7IDAQYwGAYKKwYBBAGDsgMBAQYKKwYB\n"
    "BAGDsgMBBzAYBgorBgEEAYOyAwEBBgorBgEEAYOyAwEIMBgGCisGAQQBg7IDAQEG\n"
    "CisGAQQBg7IDAQkwGAYKKwYBBAGDsgMBAQYKKwYBBAGDsgMBCjAYBgorBgEEAYOy\n"
    "AwECBgorBgEEAYOyAwEBMBgGCisGAQQBg7IDAQIGCisGAQQBg7IDAQIwGAYKKwYB\n"
    "BAGDsgMBAgYKKwYBBAGDsgMBAzAYBgorBgEEAYOyAwECBgorBgEEAYOyAwEEMBgG\n"
    "CisGAQQBg7IDAQIGCisGAQQBg7IDAQUwGAYKKwYBBAGDsgMBAgYKKwYBBAGDsgMB\n"
    "BjAYBgorBgEEAYOyAwECBgorBgEEAYOyAwEHMBgGCisGAQQBg7IDAQIGCisGAQQB\n"
    "g7IDAQgwGAYKKwYBBAGDsgMBAgYKKwYBBAGDsgMBCTAYBgorBgEEAYOyAwECBgor\n"
    "BgEEAYOyAwEKMBgGCisGAQQBg7IDAQMGCisGAQQBg7IDAQEwGAYKKwYBBAGDsgMB\n"
    "AwYKKwYBBAGDsgMBAjAYBgorBgEEAYOyAwEDBgorBgEEAYOyAwEDMBgGCisGAQQB\n"
    "g7IDAQMGCisGAQQBg7IDAQQwGAYKKwYBBAGDsgMBAwYKKwYBBAGDsgMBBTAYBgor\n"
    "BgEEAYOyAwEDBgorBgEEAYOyAwEGMBgGCisGAQQBg7IDAQMGCisGAQQBg7IDAQcw\n"
    "GAYKKwYBBAGDsgMBAwYKKwYBBAGDsgMBCDAYBgorBgEEAYOyAwEDBgorBgEEAYOy\n"
    "AwEJMBgGCisGAQQBg7IDAQMGCisGAQQBg7IDAQowGAYKKwYBBAGDsgMBBAYKKwYB\n"
    "BAGDsgMBATAYBgorBgEEAYOyAwEEBgorBgEEAYOyAwECMBgGCisGAQQBg7IDAQQG\n"
    "CisGAQQBg7IDAQMwGAYKKwYBBAGDsgMBBAYKKwYBBAGDsgMBBDAYBgorBgEEAYOy\n"
    "AwEEBgorBgEEAYOyAwEFMBgGCisGAQQBg7IDAQQGCisGAQQBg7IDAQYwGAYKKwYB\n"
    "BAGDsgMBBAYKKwYBBAGDsgMBBzAYBgorBgEEAYOyAwEEBgorBgEEAYOyAwEIMBgG\n"
    "CisGAQQBg7IDAQQGCisGAQQBg7IDAQkwGAYKKwYBBAGDsgMBBAYKKwYBBAGDsgMB\n"
    "CjAYBgorBgEEAYOyAwEFBgorBgEEAYOyAwEBMBgGCisGAQQBg7IDAQUGCisGAQQB\n"
    "g7IDAQIwGAYKKwYBBAGDsgMBBQYKKwYBBAGDsgMBAzAYBgorBgEEAYOyAwEFBgor\n"
    "BgEEAYOyAwEEMBgGCisGAQQBg7IDAQUGCisGAQQBg7IDAQUwGAYKKwYBBAGDsgMB\n"
    "BQYKKwYBBAGDsgMBBjAYBgorBgEEAYOyAwEFBgorBgEEAYOyAwEHMBgGCisGAQQB\n"
    "g7IDAQUGCisGAQQBg7IDAQgwGAYKKwYBBAGDsgMBBQYKKwYBBAGDsgMBCTAYBgor\n"
    "BgEEAYOyAwEFBgorBgEEAYOyAwEKMBgGCisGAQQBg7IDAQYGCisGAQQBg7IDAQEw\n"
    "GAYKKwYBBAGDsgMBBgYKKwYBBAGDsgMBAjAYBgorBgEEAYOyAwEGBgorBgEEAYOy\n"
    "AwEDMBgGCisGAQQBg7IDAQYGCisGAQQBg7IDAQQwGAYKKwYBBAGDsgMBBgYKKwYB\n"
    "BAGDsgMBBTAYBgorBgEEAYOyAwEGBgorBgEEAYOyAwEGMBgGCisGAQQBg7IDAQYG\n"
    "CisGAQQBg7IDAQcwGAYKKwYBBAGDsgMBBgYKKwYBBAGDsgMBCDAYBgorBgEEAYOy\n"
    "AwEGBgorBgEEAYOyAwEJMBgGCisGAQQBg7IDAQYGCisGAQQBg7IDAQowGAYKKwYB\n"
    "BAGDsgMBBwYKKwYBBAGDsgMBATAYBgorBgEEAYOyAwEHBgorBgEEAYOyAwECMBgG\n"
    "CisGAQQBg7IDAQcGCisGAQQBg7IDAQMwGAYKKwYBBAGDsgMBBwYKKwYBBAGDsgMB\n"
    "BDAYBgorBgEEAYOyAwEHBgorBgEEAYOyAwEFMBgGCisGAQQBg7IDAQcGCisGAQQB\n"
    "g7IDAQYwGAYKKwYBBAGDsgMBBwYKKwYBBAGDsgMBBzAYBgorBgEEAYOyAwEHBgor\n"
    "BgEEAYOyAwEIMBgGCisGAQQBg7IDAQcGCisGAQQBg7IDAQkwGAYKKwYBBAGDsgMB\n"
    "BwYKKwYBBAGDsgMBCjAYBgorBgEEAYOyAwEIBgorBgEEAYOyAwEBMBgGCisGAQQB\n"
    "g7IDAQgGCisGAQQBg7IDAQIwGAYKKwYBBAGDsgMBCAYKKwYBBAGDsgMBAzAYBgor\n"
    "BgEEAYOyAwEIBgorBgEEAYOyAwEEMBgGCisGAQQBg7IDAQgGCisGAQQBg7IDAQUw\n"
    "GAYKKwYBBAGDsgMBCAYKKwYBBAGDsgMBBjAYBgorBgEEAYOyAwEIBgorBgEEAYOy\n"
    "AwEHMBgGCisGAQQBg7IDAQgGCisGAQQBg7IDAQgwGAYKKwYBBAGDsgMBCAYKKwYB\n"
    "BAGDsgMBCTAYBgorBgEEAYOyAwEIBgorBgEEAYOyAwEKMBgGCisGAQQBg7IDAQkG\n"
    "CisGAQQBg7IDAQEwGAYKKwYBBAGDsgMBCQYKKwYBBAGDsgMBAjAYBgorBgEEAYOy\n"
    "AwEJBgorBgEEAYOyAwEDMBgGCisGAQQBg7IDAQkGCisGAQQBg7IDAQQwGAYKKwYB\n"
    "BAGDsgMBCQYKKwYBBAGDsgMBBTAYBgorBgEEAYOyAwEJBgorBgEEAYOyAwEGMBgG\n"
    "CisGAQQBg7IDAQkGCisGAQQBg7IDAQcwGAYKKwYBBAGDsgMBCQYKKwYBBAGDsgMB\n"
    "CDAYBgorBgEEAYOyAwEJBgorBgEEAYOyAwEJMBgGCisGAQQBg7IDAQkGCisGAQQB\n"
    "g7IDAQowGAYKKwYBBAGDsgMBCgYKKwYBBAGDsgMBATAYBgorBgEEAYOyAwEKBgor\n"
    "BgEEAYOyAwECMBgGCisGAQQBg7IDAQoGCisGAQQBg7IDAQMwGAYKKwYBBAGDsgMB\n"
    "CgYKKwYBBAGDsgMBBDAYBgorBgEEAYOyAwEKBgorBgEEAYOyAwEFMBgGCisGAQQB\n"
    "g7IDAQoGCisGAQQBg7IDAQYwGAYKKwYBBAGDsgMBCgYKKwYBBAGDsgMBBzAYBgor\n"
    "BgEEAYOyAwEKBgorBgEEAYOyAwEIMBgGCisGAQQBg7IDAQoGCisGAQQBg7IDAQkw\n"
    "GAYKKwYBBAGDsgMBCgYKKwYBBAGDsgMBCjAdBgNVHQ4EFgQU3O2lFwdLl6JChrYr\n"
    "QmsalzkA1uUwCgYIKoZIzj0EAwIDSAAwRQIgMyecf95fOW/C+3yzNeT5UdvVVAgM\n"
    "jUtZ+mc1t6iBKa0CIQDtsRHCgig/hplJDnCpSNadTqYWAc+357jGtBXcfL7rNg==\n"
    "-----END CERTIFICATE-----\n";

static const char B3_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIMKjCCC9CgAwIBAgIBCjAKBggqhkjOPQQDAjARMQ8wDQYDVQQDDAZCb21iIDIw\n"
    "HhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjARMQ8wDQYDVQQDDAZCb21i\n"
    "IDMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ+Xu+Ws8BhwU1aaDC42xfU379Y\n"
    "bTXqGilIVs2ztDgdG1Jh+Oag8QVQnB3lQm+H2tj1RW0ov3MxcsMwWIFh9+o4o4IL\n"
    "FzCCCxMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwgZcGA1UdIASB\n"
    "jzCBjDAMBgorBgEEAYOyAwEBMAwGCisGAQQBg7IDAQIwDAYKKwYBBAGDsgMBAzAM\n"
    "BgorBgEEAYOyAwEEMAwGCisGAQQBg7IDAQUwDAYKKwYBBAGDsgMBBjAMBgorBgEE\n"
    "AYOyAwEHMAwGCisGAQQBg7IDAQgwDAYKKwYBBAGDsgMBCTAMBgorBgEEAYOyAwEK\n"
    "MIIKNQYDVR0hBIIKLDCCCigwGAYKKwYBBAGDsgMBAQYKKwYBBAGDsgMBATAYBgor\n"
    "BgEEAYOyAwEBBgorBgEEAYOyAwECMBgGCisGAQQBg7IDAQEGCisGAQQBg7IDAQMw\n"
    "GAYKKwYBBAGDsgMBAQYKKwYBBAGDsgMBBDAYBgorBgEEAYOyAwEBBgorBgEEAYOy\n"
    "AwEFMBgGCisGAQQBg7IDAQEGCisGAQQBg7IDAQYwGAYKKwYBBAGDsgMBAQYKKwYB\n"
    "BAGDsgMBBzAYBgorBgEEAYOyAwEBBgorBgEEAYOyAwEIMBgGCisGAQQBg7IDAQEG\n"
    "CisGAQQBg7IDAQkwGAYKKwYBBAGDsgMBAQYKKwYBBAGDsgMBCjAYBgorBgEEAYOy\n"
    "AwECBgorBgEEAYOyAwEBMBgGCisGAQQBg7IDAQIGCisGAQQBg7IDAQIwGAYKKwYB\n"
    "BAGDsgMBAgYKKwYBBAGDsgMBAzAYBgorBgEEAYOyAwECBgorBgEEAYOyAwEEMBgG\n"
    "CisGAQQBg7IDAQIGCisGAQQBg7IDAQUwGAYKKwYBBAGDsgMBAgYKKwYBBAGDsgMB\n"
    "BjAYBgorBgEEAYOyAwECBgorBgEEAYOyAwEHMBgGCisGAQQBg7IDAQIGCisGAQQB\n"
    "g7IDAQgwGAYKKwYBBAGDsgMBAgYKKwYBBAGDsgMBCTAYBgorBgEEAYOyAwECBgor\n"
    "BgEEAYOyAwEKMBgGCisGAQQBg7IDAQMGCisGAQQBg7IDAQEwGAYKKwYBBAGDsgMB\n"
    "AwYKKwYBBAGDsgMBAjAYBgorBgEEAYOyAwEDBgorBgEEAYOyAwEDMBgGCisGAQQB\n"
    "g7IDAQMGCisGAQQBg7IDAQQwGAYKKwYBBAGDsgMBAwYKKwYBBAGDsgMBBTAYBgor\n"
    "BgEEAYOyAwEDBgorBgEEAYOyAwEGMBgGCisGAQQBg7IDAQMGCisGAQQBg7IDAQcw\n"
    "GAYKKwYBBAGDsgMBAwYKKwYBBAGDsgMBCDAYBgorBgEEAYOyAwEDBgorBgEEAYOy\n"
    "AwEJMBgGCisGAQQBg7IDAQMGCisGAQQBg7IDAQowGAYKKwYBBAGDsgMBBAYKKwYB\n"
    "BAGDsgMBATAYBgorBgEEAYOyAwEEBgorBgEEAYOyAwECMBgGCisGAQQBg7IDAQQG\n"
    "CisGAQQBg7IDAQMwGAYKKwYBBAGDsgMBBAYKKwYBBAGDsgMBBDAYBgorBgEEAYOy\n"
    "AwEEBgorBgEEAYOyAwEFMBgGCisGAQQBg7IDAQQGCisGAQQBg7IDAQYwGAYKKwYB\n"
    "BAGDsgMBBAYKKwYBBAGDsgMBBzAYBgorBgEEAYOyAwEEBgorBgEEAYOyAwEIMBgG\n"
    "CisGAQQBg7IDAQQGCisGAQQBg7IDAQkwGAYKKwYBBAGDsgMBBAYKKwYBBAGDsgMB\n"
    "CjAYBgorBgEEAYOyAwEFBgorBgEEAYOyAwEBMBgGCisGAQQBg7IDAQUGCisGAQQB\n"
    "g7IDAQIwGAYKKwYBBAGDsgMBBQYKKwYBBAGDsgMBAzAYBgorBgEEAYOyAwEFBgor\n"
    "BgEEAYOyAwEEMBgGCisGAQQBg7IDAQUGCisGAQQBg7IDAQUwGAYKKwYBBAGDsgMB\n"
    "BQYKKwYBBAGDsgMBBjAYBgorBgEEAYOyAwEFBgorBgEEAYOyAwEHMBgGCisGAQQB\n"
    "g7IDAQUGCisGAQQBg7IDAQgwGAYKKwYBBAGDsgMBBQYKKwYBBAGDsgMBCTAYBgor\n"
    "BgEEAYOyAwEFBgorBgEEAYOyAwEKMBgGCisGAQQBg7IDAQYGCisGAQQBg7IDAQEw\n"
    "GAYKKwYBBAGDsgMBBgYKKwYBBAGDsgMBAjAYBgorBgEEAYOyAwEGBgorBgEEAYOy\n"
    "AwEDMBgGCisGAQQBg7IDAQYGCisGAQQBg7IDAQQwGAYKKwYBBAGDsgMBBgYKKwYB\n"
    "BAGDsgMBBTAYBgorBgEEAYOyAwEGBgorBgEEAYOyAwEGMBgGCisGAQQBg7IDAQYG\n"
    "CisGAQQBg7IDAQcwGAYKKwYBBAGDsgMBBgYKKwYBBAGDsgMBCDAYBgorBgEEAYOy\n"
    "AwEGBgorBgEEAYOyAwEJMBgGCisGAQQBg7IDAQYGCisGAQQBg7IDAQowGAYKKwYB\n"
    "BAGDsgMBBwYKKwYBBAGDsgMBATAYBgorBgEEAYOyAwEHBgorBgEEAYOyAwECMBgG\n"
    "CisGAQQBg7IDAQcGCisGAQQBg7IDAQMwGAYKKwYBBAGDsgMBBwYKKwYBBAGDsgMB\n"
    "BDAYBgorBgEEAYOyAwEHBgorBgEEAYOyAwEFMBgGCisGAQQBg7IDAQcGCisGAQQB\n"
    "g7IDAQYwGAYKKwYBBAGDsgMBBwYKKwYBBAGDsgMBBzAYBgorBgEEAYOyAwEHBgor\n"
    "BgEEAYOyAwEIMBgGCisGAQQBg7IDAQcGCisGAQQBg7IDAQkwGAYKKwYBBAGDsgMB\n"
    "BwYKKwYBBAGDsgMBCjAYBgorBgEEAYOyAwEIBgorBgEEAYOyAwEBMBgGCisGAQQB\n"
    "g7IDAQgGCisGAQQBg7IDAQIwGAYKKwYBBAGDsgMBCAYKKwYBBAGDsgMBAzAYBgor\n"
    "BgEEAYOyAwEIBgorBgEEAYOyAwEEMBgGCisGAQQBg7IDAQgGCisGAQQBg7IDAQUw\n"
    "GAYKKwYBBAGDsgMBCAYKKwYBBAGDsgMBBjAYBgorBgEEAYOyAwEIBgorBgEEAYOy\n"
    "AwEHMBgGCisGAQQBg7IDAQgGCisGAQQBg7IDAQgwGAYKKwYBBAGDsgMBCAYKKwYB\n"
    "BAGDsgMBCTAYBgorBgEEAYOyAwEIBgorBgEEAYOyAwEKMBgGCisGAQQBg7IDAQkG\n"
    "CisGAQQBg7IDAQEwGAYKKwYBBAGDsgMBCQYKKwYBBAGDsgMBAjAYBgorBgEEAYOy\n"
    "AwEJBgorBgEEAYOyAwEDMBgGCisGAQQBg7IDAQkGCisGAQQBg7IDAQQwGAYKKwYB\n"
    "BAGDsgMBCQYKKwYBBAGDsgMBBTAYBgorBgEEAYOyAwEJBgorBgEEAYOyAwEGMBgG\n"
    "CisGAQQBg7IDAQkGCisGAQQBg7IDAQcwGAYKKwYBBAGDsgMBCQYKKwYBBAGDsgMB\n"
    "CDAYBgorBgEEAYOyAwEJBgorBgEEAYOyAwEJMBgGCisGAQQBg7IDAQkGCisGAQQB\n"
    "g7IDAQowGAYKKwYBBAGDsgMBCgYKKwYBBAGDsgMBATAYBgorBgEEAYOyAwEKBgor\n"
    "BgEEAYOyAwECMBgGCisGAQQBg7IDAQoGCisGAQQBg7IDAQMwGAYKKwYBBAGDsgMB\n"
    "CgYKKwYBBAGDsgMBBDAYBgorBgEEAYOyAwEKBgorBgEEAYOyAwEFMBgGCisGAQQB\n"
    "g7IDAQoGCisGAQQBg7IDAQYwGAYKKwYBBAGDsgMBCgYKKwYBBAGDsgMBBzAYBgor\n"
    "BgEEAYOyAwEKBgorBgEEAYOyAwEIMBgGCisGAQQBg7IDAQoGCisGAQQBg7IDAQkw\n"
    "GAYKKwYBBAGDsgMBCgYKKwYBBAGDsgMBCjAdBgNVHQ4EFgQU3O2lFwdLl6JChrYr\n"
    "QmsalzkA1uUwCgYIKoZIzj0EAwIDSAAwRQIgCVDuvdUORV13SBRfdN/PYzlhHUkN\n"
    "1/oEvEJFeSJc7tQCIQDp9S8EFLlzZzsoZvpqsM7G9tCv0bswrxOuIccJAm6KZg==\n"
    "-----END CERTIFICATE-----\n";

static const char L1_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBljCCATygAwIBAgIBCzAKBggqhkjOPQQDAjAbMRkwFwYDVQQDDBBQb2xpY2ll\n"
    "cyAxIGFuZCAyMB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowETEPMA0G\n"
    "A1UEAwwGTGVhZiAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPl7vlrPAYcFN\n"
    "WmgwuNsX1N+/WG016hopSFbNs7Q4HRtSYfjmoPEFUJwd5UJvh9rY9UVtKL9zMXLD\n"
    "MFiBYffqOKN7MHkwWAYDVR0gAQH/BE4wTDBKBgorBgEEAYOyAwEBMDwwIAYIKwYB\n"
    "BQUHAgEWFGh0dHA6Ly9jcHMuZXhhbXBsZS8xMBgGCCsGAQUFBwICMAwaClBvbGlj\n"
    "eSBvbmUwHQYDVR0OBBYEFNztpRcHS5eiQoa2K0JrGpc5ANblMAoGCCqGSM49BAMC\n"
    "A0gAMEUCIHyuAIvpTxqXYPn61W+x1lYfaUMoXFnR222e5sFWpdd9AiEA5zmqdzXn\n"
    "QWRE2B0xd8TeJoMcpz9jONYKuQWiRFwLT3E=\n"
    "-----END CERTIFICATE-----\n";

static const char L3_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBVDCB+6ADAgECAgEMMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMMEFBvbGljaWVz\n"
    "IDEgYW5kIDIwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjARMQ8wDQYD\n"
    "VQQDDAZMZWFmIDMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ+Xu+Ws8BhwU1a\n"
    "aDC42xfU379YbTXqGilIVs2ztDgdG1Jh+Oag8QVQnB3lQm+H2tj1RW0ov3MxcsMw\n"
    "WIFh9+o4ozowODAXBgNVHSAEEDAOMAwGCisGAQQBg7IDAQMwHQYDVR0OBBYEFNzt\n"
    "pRcHS5eiQoa2K0JrGpc5ANblMAoGCCqGSM49BAMCA0gAMEUCIQDd1Ns1ahHtZwDH\n"
    "Y23lEShzEhWTb3PTJ0FBjgENvxxA7QIgAdlTGqGoFsE+IZE+xF7Cglp7SHPX9xXW\n"
    "IcfYpxp4eWY=\n"
    "-----END CERTIFICATE-----\n";

static const char LNONE_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBSjCB8KADAgECAgENMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMMEFBvbGljaWVz\n"
    "IDEgYW5kIDIwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAUMRIwEAYD\n"
    "VQQDDAlMZWFmIE5vbmUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ+Xu+Ws8Bh\n"
    "wU1aaDC42xfU379YbTXqGilIVs2ztDgdG1Jh+Oag8QVQnB3lQm+H2tj1RW0ov3Mx\n"
    "csMwWIFh9+o4oywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBTc7aUXB0uXokKGtitC\n"
    "axqXOQDW5TAKBggqhkjOPQQDAgNJADBGAiEAkLYu3mDpsQUWyFe8PI8UQVyFbvcl\n"
    "No62Lnsbe8GE9FECIQDUb7G/aJewtpTT0GVHiJoetzF68NMA98+QH4FFr/zm8w==\n"
    "-----END CERTIFICATE-----\n";

static const char LANY_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBUDCB96ADAgECAgEOMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMMEFBvbGljaWVz\n"
    "IDEgYW5kIDIwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjATMREwDwYD\n"
    "VQQDDAhMZWFmIEFueTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD5e75azwGHB\n"
    "TVpoMLjbF9Tfv1htNeoaKUhWzbO0OB0bUmH45qDxBVCcHeVCb4fa2PVFbSi/czFy\n"
    "wzBYgWH36jijNDAyMBEGA1UdIAQKMAgwBgYEVR0gADAdBgNVHQ4EFgQU3O2lFwdL\n"
    "l6JChrYrQmsalzkA1uUwCgYIKoZIzj0EAwIDSAAwRQIhAK74I8pVv+WngFTcJZHR\n"
    "hHQgMlrKAh9l2HGxwDxKBo41AiBrlWwMXKLN+hMCY2HegmROjxfnGlKNOBw8rY0N\n"
    "ec2mxw==\n"
    "-----END CERTIFICATE-----\n";

static const char LDUP_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBZTCCAQugAwIBAgIBDzAKBggqhkjOPQQDAjAbMRkwFwYDVQQDDBBQb2xpY2ll\n"
    "cyAxIGFuZCAyMB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowEzERMA8G\n"
    "A1UEAwwITGVhZiBEdXAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ+Xu+Ws8Bh\n"
    "wU1aaDC42xfU379YbTXqGilIVs2ztDgdG1Jh+Oag8QVQnB3lQm+H2tj1RW0ov3Mx\n"
    "csMwWIFh9+o4o0gwRjAlBgNVHSAEHjAcMAwGCisGAQQBg7IDAQEwDAYKKwYBBAGD\n"
    "sgMBATAdBgNVHQ4EFgQU3O2lFwdLl6JChrYrQmsalzkA1uUwCgYIKoZIzj0EAwID\n"
    "SAAwRQIgJhHSQXp6P19AEt91w1PxcNJMSCw22Z0FSmwa63nADOwCIQCrYYTlff7m\n"
    "DhhJLFp+8Sd0/ucZ37eEXO1iNVYuyaUMpA==\n"
    "-----END CERTIFICATE-----\n";

static const char L1A_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBZjCCAQ2gAwIBAgIBEDAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApBbnkgUG9s\n"
    "aWN5MB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowGzEZMBcGA1UEAwwQ\n"
    "TGVhZiAxIFVuZGVyIEFueTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD5e75az\n"
    "wGHBTVpoMLjbF9Tfv1htNeoaKUhWzbO0OB0bUmH45qDxBVCcHeVCb4fa2PVFbSi/\n"
    "czFywzBYgWH36jijSDBGMCUGA1UdIAQeMBwwDAYKKwYBBAGDsgMBATAMBgorBgEE\n"
    "AYOyAwECMB0GA1UdDgQWBBTc7aUXB0uXokKGtitCaxqXOQDW5TAKBggqhkjOPQQD\n"
    "AgNHADBEAiAiVqRiD4Pr3tAJzmN0KDaS0R0QHze1qa2cXPOQI9yEawIgfyKOIEkk\n"
    "5lEhfZpAM+yxSBqyQHUvi5xOueEOL5MXicU=\n"
    "-----END CERTIFICATE-----\n";

static const char L3M_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBWTCCAQCgAwIBAgIBETAKBggqhkjOPQQDAjAZMRcwFQYDVQQDDA5NYXBwaW5n\n"
    "IDEgdG8gMzAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBgxFjAUBgNV\n"
    "BAMMDUxlYWYgMyBNYXBwZWQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ+Xu+W\n"
    "s8BhwU1aaDC42xfU379YbTXqGilIVs2ztDgdG1Jh+Oag8QVQnB3lQm+H2tj1RW0o\n"
    "v3MxcsMwWIFh9+o4ozowODAXBgNVHSAEEDAOMAwGCisGAQQBg7IDAQMwHQYDVR0O\n"
    "BBYEFNztpRcHS5eiQoa2K0JrGpc5ANblMAoGCCqGSM49BAMCA0cAMEQCIBsoIdmJ\n"
    "VKj0eQz3hLUpv0EBmqfDlL+hzKZFV56nvO1oAiBSifDJGGu2JMZcx5s8VMS5N56O\n"
    "QK4eYAy0aqumwPOfHQ==\n"
    "-----END CERTIFICATE-----\n";

static const char L3N_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBYTCCAQegAwIBAgIBEjAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFNYXBwaW5n\n"
    "IEluaGliaXRlZDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBwxGjAY\n"
    "BgNVBAMMEUxlYWYgMyBOb3QgTWFwcGVkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"
    "QgAEPl7vlrPAYcFNWmgwuNsX1N+/WG016hopSFbNs7Q4HRtSYfjmoPEFUJwd5UJv\n"
    "h9rY9UVtKL9zMXLDMFiBYffqOKM6MDgwFwYDVR0gBBAwDjAMBgorBgEEAYOyAwED\n"
    "MB0GA1UdDgQWBBTc7aUXB0uXokKGtitCaxqXOQDW5TAKBggqhkjOPQQDAgNIADBF\n"
    "AiEAlJYjq7H0ZHvyYVDxqMH6Wc/VnWblA6ufnn3uTPco59UCIHbE97h9mt6BnpqF\n"
    "8I/TP9SZksLyUf+v+SToJPAHHV2C\n"
    "-----END CERTIFICATE-----\n";

static const char LREQ_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBVDCB+qADAgECAgETMAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEUV4cGxpY2l0\n"
    "IFJlcXVpcmVkMB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowHTEbMBkG\n"
    "A1UEAwwSTGVhZiBOb25lIFJlcXVpcmVkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"
    "QgAEPl7vlrPAYcFNWmgwuNsX1N+/WG016hopSFbNs7Q4HRtSYfjmoPEFUJwd5UJv\n"
    "h9rY9UVtKL9zMXLDMFiBYffqOKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQU3O2l\n"
    "FwdLl6JChrYrQmsalzkA1uUwCgYIKoZIzj0EAwIDSQAwRgIhAOjws9lMl7fU48Db\n"
    "dUQN8k5LZ9yqxhXbPOJbsXCiu2tCAiEAvDS8Ep/qge+0q+A1xgyQW0MdRmgASAYR\n"
    "6uuIQwSvShw=\n"
    "-----END CERTIFICATE-----\n";

static const char L1R_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBoTCCAUagAwIBAgIBFDAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFFeHBsaWNp\n"
    "dCBSZXF1aXJlZDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBoxGDAW\n"
    "BgNVBAMMD0xlYWYgMSBSZXF1aXJlZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\n"
    "BD5e75azwGHBTVpoMLjbF9Tfv1htNeoaKUhWzbO0OB0bUmH45qDxBVCcHeVCb4fa\n"
    "2PVFbSi/czFywzBYgWH36jijezB5MFgGA1UdIAEB/wROMEwwSgYKKwYBBAGDsgMB\n"
    "ATA8MCAGCCsGAQUFBwIBFhRodHRwOi8vY3BzLmV4YW1wbGUvMTAYBggrBgEFBQcC\n"
    "AjAMGgpQb2xpY3kgb25lMB0GA1UdDgQWBBTc7aUXB0uXokKGtitCaxqXOQDW5TAK\n"
    "BggqhkjOPQQDAgNJADBGAiEA6yskwWQA2PbHeiFRPiu2dl7wx68hDwMajINN1BCs\n"
    "Y9kCIQCCvLw0WPgjjBM70xvd4QJDl+Fpw3/BdNAuVZ18S/0mnw==\n"
    "-----END CERTIFICATE-----\n";

static const char LANYI_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBVzCB/qADAgECAgEVMAoGCCqGSM49BAMCMBgxFjAUBgNVBAMMDUFueSBJbmhp\n"
    "Yml0ZWQwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAdMRswGQYDVQQD\n"
    "DBJMZWFmIEFueSBJbmhpYml0ZWQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ+\n"
    "Xu+Ws8BhwU1aaDC42xfU379YbTXqGilIVs2ztDgdG1Jh+Oag8QVQnB3lQm+H2tj1\n"
    "RW0ov3MxcsMwWIFh9+o4ozQwMjARBgNVHSAECjAIMAYGBFUdIAAwHQYDVR0OBBYE\n"
    "FNztpRcHS5eiQoa2K0JrGpc5ANblMAoGCCqGSM49BAMCA0gAMEUCIDMMZl4D4h78\n"
    "vtR+J/HEu8l/cUgpuqt7efFvfSy/AM+PAiEAjGedhSa1KEOcPX3+H9Fqtjd46Nzp\n"
    "GcW/bl3IYrRjv/A=\n"
    "-----END CERTIFICATE-----\n";

static const char LBOMB_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBjzCCATWgAwIBAgIBFjAKBggqhkjOPQQDAjARMQ8wDQYDVQQDDAZCb21iIDMw\n"
    "HhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlMZWFm\n"
    "IEJvbWIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ+Xu+Ws8BhwU1aaDC42xfU\n"
    "379YbTXqGilIVs2ztDgdG1Jh+Oag8QVQnB3lQm+H2tj1RW0ov3MxcsMwWIFh9+o4\n"
    "o3sweTBYBgNVHSABAf8ETjBMMEoGCisGAQQBg7IDAQEwPDAgBggrBgEFBQcCARYU\n"
    "aHR0cDovL2Nwcy5leGFtcGxlLzEwGAYIKwYBBQUHAgIwDBoKUG9saWN5IG9uZTAd\n"
    "BgNVHQ4EFgQU3O2lFwdLl6JChrYrQmsalzkA1uUwCgYIKoZIzj0EAwIDSAAwRQIg\n"
    "FkhMgtb9B0LuM1+86qkfAp/gk/zJy8uJJeH3Z4+5xjoCIQDZYRA9u3E16TfmtmnZ\n"
    "85mez46wZ+4zr+okKvEO6zbLeA==\n"
    "-----END CERTIFICATE-----\n";
static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
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

static const char *oid(const ASN1_OBJECT *o)
{
    static char buf[80];

    if (o == NULL)
        return "(none)";
    OBJ_obj2txt(buf, sizeof(buf), o, 0);
    return buf;
}

static void print_nodes(const char *what, STACK_OF(X509_POLICY_NODE) *nodes)
{
    int i;

    if (nodes == NULL) {
        printf("  %s: NULL\n", what);
        return;
    }
    printf("  %s (%d):", what, sk_X509_POLICY_NODE_num(nodes));
    for (i = 0; i < sk_X509_POLICY_NODE_num(nodes); i++) {
        const X509_POLICY_NODE *node = sk_X509_POLICY_NODE_value(nodes, i);

        printf(" %s", oid(X509_policy_node_get0_policy(node)));
        printf(" <- %s;", oid(X509_policy_node_get0_policy(X509_policy_node_get0_parent(node))));
    }
    printf("\n");
}

static void print_tree(const X509_POLICY_TREE *tree, int explicit_policy)
{
    BIO *b = BIO_new(BIO_s_mem());
    int i, j;

    printf("  explicit %d, tree %s\n", explicit_policy, tree == NULL ? "NULL" : "set");
    if (tree == NULL) {
        BIO_free(b);
        return;
    }
    printf("  levels %d\n", X509_policy_tree_level_count(tree));
    for (i = 0; i <= X509_policy_tree_level_count(tree); i++) {
        X509_POLICY_LEVEL *level = X509_policy_tree_get0_level(tree, i);

        if (level == NULL) {
            printf("  level %d: NULL\n", i);
            continue;
        }
        printf("  level %d: %d nodes\n", i, X509_policy_level_node_count(level));
        for (j = 0; j <= X509_policy_level_node_count(level); j++) {
            X509_POLICY_NODE *node = X509_policy_level_get0_node(level, j);
            STACK_OF(POLICYQUALINFO) *quals = X509_policy_node_get0_qualifiers(node);
            char *text;
            long len;

            if (node == NULL) {
                printf("    node %d: NULL\n", j);
                continue;
            }
            printf("    node %d: %s, parent %s, %d qualifiers\n", j, oid(X509_policy_node_get0_policy(node)),
                   oid(X509_policy_node_get0_policy(X509_policy_node_get0_parent(node))),
                   quals == NULL ? -1 : sk_POLICYQUALINFO_num(quals));
            X509_POLICY_NODE_print(b, node, 6);
            len = BIO_get_mem_data(b, &text);
            printf("%.*s", (int)len, text);
            (void)BIO_reset(b);
        }
    }
    print_nodes("authority", X509_policy_tree_get0_policies(tree));
    print_nodes("user", X509_policy_tree_get0_user_policies(tree));
    BIO_free(b);
}

static int trace_cb(int ok, X509_STORE_CTX *ctx)
{
    printf("    cb: ok %d, error %d, depth %d, cert %s\n", ok, X509_STORE_CTX_get_error(ctx),
           X509_STORE_CTX_get_error_depth(ctx), subject(X509_STORE_CTX_get_current_cert(ctx)));
    if (ok == 2)
        print_tree(X509_STORE_CTX_get0_policy_tree(ctx), X509_STORE_CTX_get_explicit_policy(ctx));
    return ok || accept_errors;
}

struct run {
    const char *label;
    X509 *leaf;
    X509 *untrusted[3];
    unsigned long flags;
    const char *policies[2];
    int accept;
};

static void verify(X509 *root, const struct run *r)
{
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    STACK_OF(X509) *untrusted = sk_X509_new_null();
    X509_VERIFY_PARAM *vpm;
    int i, ret;

    X509_STORE_add_cert(store, root);
    for (i = 0; i < 3 && r->untrusted[i] != NULL; i++)
        sk_X509_push(untrusted, r->untrusted[i]);
    X509_STORE_CTX_init(ctx, store, r->leaf, untrusted);
    X509_STORE_CTX_set_verify_cb(ctx, trace_cb);
    vpm = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set_time(vpm, WHEN);
    X509_VERIFY_PARAM_set_flags(vpm, r->flags);
    for (i = 0; i < 2 && r->policies[i] != NULL; i++)
        X509_VERIFY_PARAM_add0_policy(vpm, OBJ_txt2obj(r->policies[i], 0));
    accept_errors = r->accept;
    printf("# %s\n", r->label);
    ret = X509_verify_cert(ctx);
    printf("  result %d, error %d (%s), depth %d, cert %s\n", ret, X509_STORE_CTX_get_error(ctx),
           X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)), X509_STORE_CTX_get_error_depth(ctx),
           subject(X509_STORE_CTX_get_current_cert(ctx)));
    print_tree(X509_STORE_CTX_get0_policy_tree(ctx), X509_STORE_CTX_get_explicit_policy(ctx));
    errors();
    check(1, r->label);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
}

static void direct(const char *label, X509 *a, X509 *b, X509 *c, X509 *d, unsigned int flags, const char *policy)
{
    STACK_OF(X509) *certs = sk_X509_new_null();
    STACK_OF(ASN1_OBJECT) *oids = sk_ASN1_OBJECT_new_null();
    X509_POLICY_TREE *tree = (X509_POLICY_TREE *)1;
    int explicit_policy = 7, ret;

    if (a != NULL)
        sk_X509_push(certs, a);
    if (b != NULL)
        sk_X509_push(certs, b);
    if (c != NULL)
        sk_X509_push(certs, c);
    if (d != NULL)
        sk_X509_push(certs, d);
    if (policy != NULL)
        sk_ASN1_OBJECT_push(oids, OBJ_txt2obj(policy, 0));
    printf("# X509_policy_check: %s\n", label);
    ret = X509_policy_check(&tree, &explicit_policy, certs, oids, flags);
    printf("  ret %d\n", ret);
    print_tree(tree, explicit_policy);
    errors();
    check(1, label);
    X509_policy_tree_free(tree);
    sk_X509_free(certs);
    sk_ASN1_OBJECT_pop_free(oids, ASN1_OBJECT_free);
}

#define P "1.3.6.1.4.1.55555.1."
#define CHECK X509_V_FLAG_POLICY_CHECK
#define EXPLICIT (X509_V_FLAG_POLICY_CHECK | X509_V_FLAG_EXPLICIT_POLICY)

int main(void)
{
    X509 *root = read_cert(ROOT_PEM), *ip12 = read_cert(IP12_PEM), *iany = read_cert(IANY_PEM);
    X509 *imap = read_cert(IMAP_PEM), *ireq = read_cert(IREQ_PEM), *iinh = read_cert(IINH_PEM);
    X509 *inomap = read_cert(INOMAP_PEM), *b1 = read_cert(B1_PEM), *b2 = read_cert(B2_PEM);
    X509 *b3 = read_cert(B3_PEM), *l1 = read_cert(L1_PEM), *l3 = read_cert(L3_PEM);
    X509 *lnone = read_cert(LNONE_PEM), *lany = read_cert(LANY_PEM), *ldup = read_cert(LDUP_PEM);
    X509 *l1a = read_cert(L1A_PEM), *l3m = read_cert(L3M_PEM), *l3n = read_cert(L3N_PEM);
    X509 *lreq = read_cert(LREQ_PEM), *l1r = read_cert(L1R_PEM), *lanyi = read_cert(LANYI_PEM);
    X509 *lbomb = read_cert(LBOMB_PEM);
    const struct run runs[] = {
        { "policy 1 under 1 and 2", l1, { ip12 }, CHECK, { NULL }, 0 },
        { "policy 1, explicit", l1, { ip12 }, EXPLICIT, { NULL }, 0 },
        { "policy 3 under 1 and 2", l3, { ip12 }, CHECK, { NULL }, 0 },
        { "policy 3, explicit", l3, { ip12 }, EXPLICIT, { NULL }, 0 },
        { "policy 3, explicit, accepted", l3, { ip12 }, EXPLICIT, { NULL }, 1 },
        { "no policies, explicit", lnone, { ip12 }, EXPLICIT, { NULL }, 0 },
        { "anyPolicy leaf", lany, { ip12 }, EXPLICIT, { NULL }, 0 },
        { "anyPolicy leaf, anyPolicy inhibited", lany, { ip12 }, EXPLICIT | X509_V_FLAG_INHIBIT_ANY, { NULL }, 0 },
        { "duplicate policies", ldup, { ip12 }, CHECK, { NULL }, 0 },
        { "duplicate policies, accepted", ldup, { ip12 }, CHECK, { NULL }, 1 },
        { "duplicate policies, unchecked", ldup, { ip12 }, 0, { NULL }, 0 },
        { "under anyPolicy", l1a, { iany }, EXPLICIT, { NULL }, 0 },
        { "under anyPolicy, inhibited", l1a, { iany }, EXPLICIT | X509_V_FLAG_INHIBIT_ANY, { NULL }, 0 },
        { "user policy 1", l1, { ip12 }, EXPLICIT, { P "1" }, 0 },
        { "user policy 2", l1, { ip12 }, EXPLICIT, { P "2" }, 0 },
        { "user policies 2 and 1", l1, { ip12 }, EXPLICIT, { P "2", P "1" }, 0 },
        { "user anyPolicy", l1, { ip12 }, EXPLICIT, { "2.5.29.32.0" }, 0 },
        { "user policy 5 under anyPolicy", l1a, { iany }, EXPLICIT, { P "5" }, 0 },
        { "user policy 2 under anyPolicy", l1a, { iany }, CHECK, { P "2" }, 0 },
        { "mapped", l3m, { imap }, EXPLICIT, { NULL }, 0 },
        { "mapped, user policy 3", l3m, { imap }, EXPLICIT, { P "3" }, 0 },
        { "mapped, user policy 1", l3m, { imap }, EXPLICIT, { P "1" }, 0 },
        { "mapping inhibited", l3m, { imap }, EXPLICIT | X509_V_FLAG_INHIBIT_MAP, { NULL }, 0 },
        { "mapping, then inhibited", l3n, { inomap }, EXPLICIT, { NULL }, 0 },
        { "explicit policy required by the CA", lreq, { ireq }, CHECK, { NULL }, 0 },
        { "explicit policy required by the CA, policy 1", l1r, { ireq }, CHECK, { NULL }, 0 },
        { "anyPolicy inhibited by the CA", lanyi, { iinh }, CHECK, { NULL }, 0 },
        { "anyPolicy inhibited by the CA, explicit", lanyi, { iinh }, EXPLICIT, { NULL }, 0 },
        { "notify", l1, { ip12 }, CHECK | X509_V_FLAG_NOTIFY_POLICY, { NULL }, 0 },
        { "too many nodes", lbomb, { b3, b2, b1 }, CHECK, { NULL }, 0 },
        { "too many nodes, unchecked", lbomb, { b3, b2, b1 }, 0, { NULL }, 0 },
        { "two of the bomb's CAs", b3, { b2, b1 }, EXPLICIT, { P "7" }, 0 },
    };
    size_t i;

    for (i = 0; i < sizeof(runs) / sizeof(runs[0]); i++)
        verify(root, &runs[i]);

    direct("policy 1", l1, ip12, root, NULL, 0, NULL);
    direct("policy 1, user policy 1", l1, ip12, root, NULL, X509_V_FLAG_EXPLICIT_POLICY, P "1");
    direct("policy 3, explicit", l3, ip12, root, NULL, X509_V_FLAG_EXPLICIT_POLICY, NULL);
    direct("the anchor alone", root, NULL, NULL, NULL, 0, NULL);
    direct("the anchor alone, explicit", root, NULL, NULL, NULL, X509_V_FLAG_EXPLICIT_POLICY, NULL);
    direct("no certificates", NULL, NULL, NULL, NULL, 0, NULL);
    direct("duplicates", ldup, ip12, root, NULL, 0, NULL);
    direct("too many nodes", lbomb, b3, b2, b1, 0, NULL);
    direct("mapped, anyPolicy", l3m, imap, root, NULL, X509_V_FLAG_EXPLICIT_POLICY, "2.5.29.32.0");
    direct("under anyPolicy, user policy 9", l1a, iany, root, NULL, 0, P "9");

    printf("# NULL\n");
    printf("  levels %d, level %p, policies %p, user %p\n", X509_policy_tree_level_count(NULL),
           (void *)X509_policy_tree_get0_level(NULL, 0), (void *)X509_policy_tree_get0_policies(NULL),
           (void *)X509_policy_tree_get0_user_policies(NULL));
    printf("  nodes %d, node %p, policy %p, qualifiers %p, parent %p\n", X509_policy_level_node_count(NULL),
           (void *)X509_policy_level_get0_node(NULL, 0), (void *)X509_policy_node_get0_policy(NULL),
           (void *)X509_policy_node_get0_qualifiers(NULL), (void *)X509_policy_node_get0_parent(NULL));
    X509_policy_tree_free(NULL);
    check(1, "NULL");

    X509_free(root);
    X509_free(ip12);
    X509_free(iany);
    X509_free(imap);
    X509_free(ireq);
    X509_free(iinh);
    X509_free(inomap);
    X509_free(b1);
    X509_free(b2);
    X509_free(b3);
    X509_free(l1);
    X509_free(l3);
    X509_free(lnone);
    X509_free(lany);
    X509_free(ldup);
    X509_free(l1a);
    X509_free(l3m);
    X509_free(l3n);
    X509_free(lreq);
    X509_free(l1r);
    X509_free(lanyi);
    X509_free(lbomb);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
