/*
 * Conformance test for revocation checking in X509_verify_cert(3): X509_V_FLAG_CRL_CHECK and
 * X509_V_FLAG_CRL_CHECK_ALL against CRLs from the context and from the store, revoked and
 * unrevoked certificates, missing CRLs, CRL validity times, bad signatures, unhandled critical
 * extensions, delta CRLs (X509_V_FLAG_USE_DELTAS, removeFromCRL), issuing distribution
 * points (scope, only CA certificates, only some reasons), a CRL issuer without cRLSign, an
 * indirect CRL (X509_V_FLAG_EXTENDED_CRL_SUPPORT, the CRL issuer's own path), and a custom
 * get_crl, with a callback that sees, and may accept, each failure.
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
 * The PKI, made with the reference's openssl tool: a root, an intermediate, an intermediate
 * without cRLSign, and a CRL signer under the root; leaves under the intermediates (serials
 * 0x10 to 0x13, the first with a distribution point and a freshest CRL, the third with an
 * indirect distribution point naming the CRL signer); and CRLs current from 2026-10-01 to
 * 2026-11-01 unless named otherwise, the intermediate's revoking 0x10, its delta CRL
 * removing 0x10 and revoking 0x11.
 */
static const char ROOT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBWDCB/6ADAgECAgEBMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCVRlc3QgUm9v\n"
    "dDAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBQxEjAQBgNVBAMMCVRl\n"
    "c3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFco+CU/Tbj0VjvImgy8\n"
    "Ta3RogPsza83gouaAh9fgcDXOSrXzdFBgwJgR1Qjiti3gNtbXiaxyr8HaMO+RHXa\n"
    "cmqjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQW\n"
    "BBR9KHmNUy8d9PZiGqndbTK4cBkDDDAKBggqhkjOPQQDAgNIADBFAiA+G6y/Gi+F\n"
    "K5vqQyh92cGrB6rs7SmBJC2244zRMwNIRwIhAOC3s0FT2XVUfWkojsvCUVLCU7Zl\n"
    "9aKjeG3tebaQSnBq\n"
    "-----END CERTIFICATE-----\n";

static const char INTER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBgTCCASigAwIBAgIBAjAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlUZXN0IFJv\n"
    "b3QwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAcMRowGAYDVQQDDBFU\n"
    "ZXN0IEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFifAfwb\n"
    "WVExdAtdveFldk+LzkeU1kZgw0+dfRPkjM5meqvFOl3rJwFVPYnoQiC6jGZjqNMT\n"
    "6pXyu92MLPuVzkijYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEG\n"
    "MB0GA1UdDgQWBBQ233y0jeSWG0YmAKKOUGc/3KxNxDAfBgNVHSMEGDAWgBR9KHmN\n"
    "Uy8d9PZiGqndbTK4cBkDDDAKBggqhkjOPQQDAgNHADBEAiARIO1575mk0hi9yMaD\n"
    "0qvv+Vxlo/NZ4TuHh9dZfN0L5gIgfpn6ejUPwOKFC+1e+aHF5royubf2RaB2c3F5\n"
    "CNn2W1o=\n"
    "-----END CERTIFICATE-----\n";

static const char INTERX_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBgTCCASegAwIBAgIBAzAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlUZXN0IFJv\n"
    "b3QwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAbMRkwFwYDVQQDDBBU\n"
    "ZXN0IE5vIENSTCBTaWduMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa0g8UUMy\n"
    "IgtwAEmL7TGdXHZSCJam+jl8T2YoKENT2pkpy15EigCUhEtljRB+ggtvov4DfnUv\n"
    "jBWpIyza38zACKNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQw\n"
    "HQYDVR0OBBYEFPRWOeCcgpNsKpDc+yNk+yJmPfL0MB8GA1UdIwQYMBaAFH0oeY1T\n"
    "Lx309mIaqd1tMrhwGQMMMAoGCCqGSM49BAMCA0gAMEUCIQDjH1VxOwSjMBpFWGWp\n"
    "YAzr5vdTRUSZ6LaZ1s98HpiQzAIgCUqYqZvNuozChfOTidY5LRG4bdvY5TvKwRtO\n"
    "WHnn2f8=\n"
    "-----END CERTIFICATE-----\n";

static const char SIGNER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBbzCCARWgAwIBAgIBBDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlUZXN0IFJv\n"
    "b3QwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAaMRgwFgYDVQQDDA9U\n"
    "ZXN0IENSTCBTaWduZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQW1ZI7U/jB\n"
    "Zhv/kNZBVwTy1zvcngVjC99qqysADR8q9TMLKmtJt0BipajYMZkmkF/p5cLO9wrk\n"
    "rySqmZW+Yd6ho1IwUDAOBgNVHQ8BAf8EBAMCAQIwHQYDVR0OBBYEFEhJfFqHASrS\n"
    "9bcLbNpQvr+73sVXMB8GA1UdIwQYMBaAFH0oeY1TLx309mIaqd1tMrhwGQMMMAoG\n"
    "CCqGSM49BAMCA0gAMEUCIClrVh2QGMpKZB+KGnoTfxRFJox58e53L4AB3kKkpKxH\n"
    "AiEA/YAtjiT3UWSidx2itE7t9Uv39VK9ghLsniMnIYXD/70=\n"
    "-----END CERTIFICATE-----\n";

static const char LEAF_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBzTCCAXKgAwIBAgIBEDAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFUZXN0IElu\n"
    "dGVybWVkaWF0ZTAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBQxEjAQ\n"
    "BgNVBAMMCVRlc3QgTGVhZjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFporWAT\n"
    "7hh1LhAYTmogUEN5yIt9lRqRyqfD8V+qk0PK1iRrQzwmBzIPXOZFoMNbwNlkLnwM\n"
    "ELWAp1emj3BmY26jgawwgakwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBQ233y0jeSW\n"
    "G0YmAKKOUGc/3KxNxDAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8vY3JsLmV4YW1w\n"
    "bGUvaW50ZXIuY3JsMC0GA1UdLgQmMCQwIqAgoB6GHGh0dHA6Ly9jcmwuZXhhbXBs\n"
    "ZS9kZWx0YS5jcmwwHQYDVR0OBBYEFBp5eBwPIq97BLCMLAsvtO9H6rKVMAoGCCqG\n"
    "SM49BAMCA0kAMEYCIQD7FGUXA9kjna9yxxyg32ZYTd1sJXmq6JMJAvuEa/yvhgIh\n"
    "AK5f3PbGRzSrk8MWVQ/17z7Tlwm79KyKzJvV9dLNqOYY\n"
    "-----END CERTIFICATE-----\n";

static const char LEAF2_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBbTCCARSgAwIBAgIBETAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFUZXN0IElu\n"
    "dGVybWVkaWF0ZTAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMBYxFDAS\n"
    "BgNVBAMMC1Rlc3QgTGVhZiAyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJP5o\n"
    "eHHQcHWhlUWi1KbWR+lfroqjZjfMcnkYJHyNEwcd7UtNUYL+Uh+xB+IyLWvRsAGC\n"
    "aTQe9lah9dHmKgHxMqNNMEswCQYDVR0TBAIwADAfBgNVHSMEGDAWgBQ233y0jeSW\n"
    "G0YmAKKOUGc/3KxNxDAdBgNVHQ4EFgQU3gxRKL+YivZa3o8NmxViIMmSyl0wCgYI\n"
    "KoZIzj0EAwIDRwAwRAIgZq48DBxCADI7YZZ08JzYDWfl6OS0Yb854GL2im8Asj0C\n"
    "IHOAD/yiuYhXwNb+hNtoyVZbCTFl7dLccTR91nXUw0Sk\n"
    "-----END CERTIFICATE-----\n";

static const char LEAFI_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIByjCCAW+gAwIBAgIBEjAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFUZXN0IElu\n"
    "dGVybWVkaWF0ZTAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMDAwMDBaMB0xGzAZ\n"
    "BgNVBAMMElRlc3QgSW5kaXJlY3QgTGVhZjBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"
    "A0IABPXeRgOsi04bO6L3dTiKZlCjVWkekYZhlGUGBjcPH08LV80044HIw/Ls1c6y\n"
    "GTH0MbjrA6AvwJhS/eSuQCB6oWCjgaAwgZ0wCQYDVR0TBAIwADAfBgNVHSMEGDAW\n"
    "gBQ233y0jeSWG0YmAKKOUGc/3KxNxDBQBgNVHR8ESTBHMEWgI6Ahhh9odHRwOi8v\n"
    "Y3JsLmV4YW1wbGUvaW5kaXJlY3QuY3Jsoh6kHDAaMRgwFgYDVQQDDA9UZXN0IENS\n"
    "TCBTaWduZXIwHQYDVR0OBBYEFCNxlkSLvFN5klTdUrbZFZGf2L6gMAoGCCqGSM49\n"
    "BAMCA0kAMEYCIQCJtsz9PoefCx9jU62rpGAB5e2dVNmCO3C3kLKVvq5sMAIhAJxI\n"
    "8xenoDVqCyYnhaHoJwnklgIrpxXBZpVkF0iOA7YG\n"
    "-----END CERTIFICATE-----\n";

static const char LEAFX_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBbjCCAROgAwIBAgIBEzAKBggqhkjOPQQDAjAbMRkwFwYDVQQDDBBUZXN0IE5v\n"
    "IENSTCBTaWduMB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAwMFowFjEUMBIG\n"
    "A1UEAwwLVGVzdCBMZWFmIFgwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQG9BFD\n"
    "A7cgf2Z5HYmLLTUacwo0MOCabdz40usek9LnDFYtfq5Rv//e2/EnC/yir1auR5aC\n"
    "QGi8tuaLrAUjJBKbo00wSzAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFPRWOeCcgpNs\n"
    "KpDc+yNk+yJmPfL0MB0GA1UdDgQWBBQs7/aBp8FsOKTYi229u85u883YpjAKBggq\n"
    "hkjOPQQDAgNJADBGAiEAtuDeaBQ4GAOMPhJdHxbCWb/eVT2cQCAlMyrM9eeBJIUC\n"
    "IQC5XZlSd7qz88cmSutUFn47IpZDi6vZUpRBxHQ272z4Hg==\n"
    "-----END CERTIFICATE-----\n";

static const char ROOT_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIHLMHQCAQEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBSb290Fw0yNjEw\n"
    "MDEwMDAwMDBaFw0yNjExMDEwMDAwMDBaoC8wLTAfBgNVHSMEGDAWgBR9KHmNUy8d\n"
    "9PZiGqndbTK4cBkDDDAKBgNVHRQEAwIBATAKBggqhkjOPQQDAgNHADBEAiAuDMWV\n"
    "BLFyS4mSI3jVu8Qi9EfVHk+vte+TWunqZTsCVQIgFokOpK9uJFS8cOep0kN6IiEO\n"
    "1wFUktplddHEKG7QhZ8=\n"
    "-----END X509 CRL-----\n";

static const char INTER_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIH4MIGgAgEBMAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEVRlc3QgSW50ZXJtZWRp\n"
    "YXRlFw0yNjEwMDEwMDAwMDBaFw0yNjExMDEwMDAwMDBaMCIwIAIBEBcNMjYxMDE3\n"
    "MTkxNjU1WjAMMAoGA1UdFQQDCgEBoC8wLTAfBgNVHSMEGDAWgBQ233y0jeSWG0Ym\n"
    "AKKOUGc/3KxNxDAKBgNVHRQEAwIBAjAKBggqhkjOPQQDAgNHADBEAiBDGOQSecAD\n"
    "JyXAGvnUwe5SyePl+12Wpno5gaDoFdzeGwIgJtEsUo5oEnRH9MLiity7nQcU6oun\n"
    "2FI37XzBKSYO2Ns=\n"
    "-----END X509 CRL-----\n";

static const char INTER_EXPIRED_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIH5MIGgAgEBMAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEVRlc3QgSW50ZXJtZWRp\n"
    "YXRlFw0yNjA5MDEwMDAwMDBaFw0yNjEwMTAwMDAwMDBaMCIwIAIBEBcNMjYxMDE3\n"
    "MTkxNjU1WjAMMAoGA1UdFQQDCgEBoC8wLTAfBgNVHSMEGDAWgBQ233y0jeSWG0Ym\n"
    "AKKOUGc/3KxNxDAKBgNVHRQEAwIBAzAKBggqhkjOPQQDAgNIADBFAiEAgDue44Ho\n"
    "hFOTZNJ/nRMmMRFTqEf2dUV7KMZjxdUH8dMCICIAf9Vn0UDj4TWzKP4eWS58EqFE\n"
    "4r//bxWqGDmvVt7C\n"
    "-----END X509 CRL-----\n";

static const char INTER_FUTURE_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIH6MIGgAgEBMAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEVRlc3QgSW50ZXJtZWRp\n"
    "YXRlFw0yNjEwMjAwMDAwMDBaFw0yNjExMjAwMDAwMDBaMCIwIAIBEBcNMjYxMDE3\n"
    "MTkxNjU1WjAMMAoGA1UdFQQDCgEBoC8wLTAfBgNVHSMEGDAWgBQ233y0jeSWG0Ym\n"
    "AKKOUGc/3KxNxDAKBgNVHRQEAwIBBDAKBggqhkjOPQQDAgNJADBGAiEA1s6LACf8\n"
    "8pPCwi7BsdvJfVCIrHMr3oDJwWyvjSyk6N0CIQDlGsDfN/7XxUFfp/cHbCq0M4Ji\n"
    "CiFPp6EY6+lIis3J/Q==\n"
    "-----END X509 CRL-----\n";

static const char INTER_BADSIG_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIH4MIGgAgEBMAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEVRlc3QgSW50ZXJtZWRp\n"
    "YXRlFw0yNjEwMDEwMDAwMDBaFw0yNjExMDEwMDAwMDBaMCIwIAIBEBcNMjYxMDE3\n"
    "MTkxNjU1WjAMMAoGA1UdFQQDCgEBoC8wLTAfBgNVHSMEGDAWgBQ233y0jeSWG0Ym\n"
    "AKKOUGc/3KxNxDAKBgNVHRQEAwIBAjAKBggqhkjOPQQDAgNHADBEAiBDGOQSecAD\n"
    "JyXAGvnUwe5SyePl+12Wpno5gaDoFdzeGwIgJtEsUo5oEnRH9MLiity7nQcU6oun\n"
    "2FI37XzBKSYO2No=\n"
    "-----END X509 CRL-----\n";

static const char INTER_CRIT_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBCDCBrgIBATAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFUZXN0IEludGVybWVk\n"
    "aWF0ZRcNMjYxMDAxMDAwMDAwWhcNMjYxMTAxMDAwMDAwWjAiMCACARAXDTI2MTAx\n"
    "NzE5MTY1NVowDDAKBgNVHRUEAwoBAaA9MDswHwYDVR0jBBgwFoAUNt98tI3klhtG\n"
    "JgCijlBnP9ysTcQwDAYDKgMEAQH/BAIFADAKBgNVHRQEAwIBBTAKBggqhkjOPQQD\n"
    "AgNJADBGAiEAnLWrFzVeoMclEoC4+KZNu8WMBM6L9X2TMM2Mk13dERUCIQDv3gHk\n"
    "xEBlxLiXJy2vRs8CjpoJ5umVCRDDe3S2Ct1EaA==\n"
    "-----END X509 CRL-----\n";

static const char INTER_DELTA_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBKjCB0QIBATAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFUZXN0IEludGVybWVk\n"
    "aWF0ZRcNMjYxMDAxMDAwMDAwWhcNMjYxMTAxMDAwMDAwWjBEMCACARAXDTI2MTAx\n"
    "NzE5MTY1NVowDDAKBgNVHRUEAwoBCDAgAgERFw0yNjEwMTcxOTE2NTVaMAwwCgYD\n"
    "VR0VBAMKAQGgPjA8MB8GA1UdIwQYMBaAFDbffLSN5JYbRiYAoo5QZz/crE3EMA0G\n"
    "A1UdGwEB/wQDAgEBMAoGA1UdFAQDAgEDMAoGCCqGSM49BAMCA0gAMEUCIQCVQh0h\n"
    "nWEPvNqWvC7qLFk6Pv6kNuS/owUvsr/gSBDcHgIgUhRaoTELHFs4SdyyeMH9yED6\n"
    "BzONjrGWiahbd9ZTZK4=\n"
    "-----END X509 CRL-----\n";

static const char INTER_IDPCA_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBCjCBsQIBATAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFUZXN0IEludGVybWVk\n"
    "aWF0ZRcNMjYxMDAxMDAwMDAwWhcNMjYxMTAxMDAwMDAwWjAiMCACARAXDTI2MTAx\n"
    "NzE5MTY1NVowDDAKBgNVHRUEAwoBAaBAMD4wHwYDVR0jBBgwFoAUNt98tI3klhtG\n"
    "JgCijlBnP9ysTcQwDwYDVR0cAQH/BAUwA4IB/zAKBgNVHRQEAwIBBjAKBggqhkjO\n"
    "PQQDAgNIADBFAiA66u4vTfvx9xWfDHOV+0O/6XcalDFtGC+XetA+ycTgFAIhALVk\n"
    "Q7AeCrXPqIoWn9lEHLmejBdSM+QdxINadMbs8xzf\n"
    "-----END X509 CRL-----\n";

static const char INTER_IDPREASONS_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBDDCBsgIBATAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFUZXN0IEludGVybWVk\n"
    "aWF0ZRcNMjYxMDAxMDAwMDAwWhcNMjYxMTAxMDAwMDAwWjAiMCACARAXDTI2MTAx\n"
    "NzE5MTY1NVowDDAKBgNVHRUEAwoBAaBBMD8wHwYDVR0jBBgwFoAUNt98tI3klhtG\n"
    "JgCijlBnP9ysTcQwEAYDVR0cAQH/BAYwBIMCBkAwCgYDVR0UBAMCAQcwCgYIKoZI\n"
    "zj0EAwIDSQAwRgIhAJHNYpBd9xzpWUuq6bXnlBgs75YglxmzyYcMWT624XNnAiEA\n"
    "yR+b/VQFQJv1LMJxLMaBWviICBwU7M2zydV0sM8UoAU=\n"
    "-----END X509 CRL-----\n";

static const char INTER_IDPMATCH_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBKjCB0AIBATAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFUZXN0IEludGVybWVk\n"
    "aWF0ZRcNMjYxMDAxMDAwMDAwWhcNMjYxMTAxMDAwMDAwWjAiMCACARAXDTI2MTAx\n"
    "NzE5MTY1NVowDDAKBgNVHRUEAwoBAaBfMF0wHwYDVR0jBBgwFoAUNt98tI3klhtG\n"
    "JgCijlBnP9ysTcQwLgYDVR0cAQH/BCQwIqAgoB6GHGh0dHA6Ly9jcmwuZXhhbXBs\n"
    "ZS9pbnRlci5jcmwwCgYDVR0UBAMCAQgwCgYIKoZIzj0EAwIDSQAwRgIhAI2Q/P9a\n"
    "zl4gsfujuDaA3xSLJXqbfXyF5xHZePPqE1OSAiEAtLJhk6CKZz071Z2XpJQDn9zU\n"
    "jKNJemaVdWb5OcRq1MU=\n"
    "-----END X509 CRL-----\n";

static const char INTER_IDPOTHER_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBKDCB0AIBATAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFUZXN0IEludGVybWVk\n"
    "aWF0ZRcNMjYxMDAxMDAwMDAwWhcNMjYxMTAxMDAwMDAwWjAiMCACARAXDTI2MTAx\n"
    "NzE5MTY1NVowDDAKBgNVHRUEAwoBAaBfMF0wHwYDVR0jBBgwFoAUNt98tI3klhtG\n"
    "JgCijlBnP9ysTcQwLgYDVR0cAQH/BCQwIqAgoB6GHGh0dHA6Ly9jcmwuZXhhbXBs\n"
    "ZS9vdGhlci5jcmwwCgYDVR0UBAMCAQkwCgYIKoZIzj0EAwIDRwAwRAIgPBlW0inB\n"
    "kGKI5nG4SBOIyFaCGUlBifeqFDJclaanwUoCIHbEjqCJc1lTr4TNe8X+TQhdc/uX\n"
    "QpU2swUW9WM2eq3A\n"
    "-----END X509 CRL-----\n";

static const char INTERX_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIHTMHsCAQEwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQVGVzdCBObyBDUkwgU2ln\n"
    "bhcNMjYxMDAxMDAwMDAwWhcNMjYxMTAxMDAwMDAwWqAvMC0wHwYDVR0jBBgwFoAU\n"
    "9FY54JyCk2wqkNz7I2T7ImY98vQwCgYDVR0UBAMCAQEwCgYIKoZIzj0EAwIDSAAw\n"
    "RQIgUNlC3q7SjeoZNPFtQ0x5ps74QqFzLOrtPqNBgdbXIDoCIQCfuOwwtDTebaEF\n"
    "qflnCGu76n/JuWzu2qwNrdO9HDdSnQ==\n"
    "-----END X509 CRL-----\n";

static const char INDIRECT_CRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIHkMIGLAgEBMAoGCCqGSM49BAMCMBoxGDAWBgNVBAMMD1Rlc3QgQ1JMIFNpZ25l\n"
    "chcNMjYxMDAxMDAwMDAwWhcNMjYxMTAxMDAwMDAwWqBAMD4wHwYDVR0jBBgwFoAU\n"
    "SEl8WocBKtL1twts2lC+v7vexVcwDwYDVR0cAQH/BAUwA4QB/zAKBgNVHRQEAwIB\n"
    "ATAKBggqhkjOPQQDAgNIADBFAiA38fFkRvHpAeQ5n99138XdcVAUs3pOUuhq+LI+\n"
    "E9kM+QIhALfX41M1Ct2SE3IfylOLf1vmI1f4s0fzpb18jLbNi2GB\n"
    "-----END X509 CRL-----\n";
static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static X509_CRL *read_crl(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509_CRL *x = PEM_read_bio_X509_CRL(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

/* 2026-10-15, within the current CRLs' times. */
static const time_t WHEN = 1792022400;

static int accept_errors;
static X509_CRL *custom_crl;

static const char *name(const X509_NAME *nm)
{
    static char buf[128];

    if (nm == NULL)
        return "(none)";
    X509_NAME_oneline(nm, buf, sizeof(buf));
    return buf;
}

static int trace_cb(int ok, X509_STORE_CTX *ctx)
{
    X509 *x = X509_STORE_CTX_get_current_cert(ctx);
    X509_CRL *crl = X509_STORE_CTX_get0_current_crl(ctx);

    printf("    cb: ok %d, error %d, depth %d, cert %s", ok, X509_STORE_CTX_get_error(ctx),
           X509_STORE_CTX_get_error_depth(ctx), x == NULL ? "(none)" : name(X509_get_subject_name(x)));
    printf(", crl %s\n", crl == NULL ? "(none)" : name(X509_CRL_get_issuer(crl)));
    return ok || accept_errors;
}

static int get_crl(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x)
{
    printf("    get_crl: %s\n", name(X509_get_subject_name(x)));
    (void)ctx;
    if (custom_crl == NULL)
        return 0;
    X509_CRL_up_ref(custom_crl);
    *crl = custom_crl;
    return 1;
}

struct run {
    const char *label;
    X509 *leaf;
    X509 *untrusted[3];
    X509 *trusted[3];
    X509_CRL *crls[3];
    X509_CRL *store_crls[3];
    unsigned long flags;
    int accept;
    X509_CRL *custom;
    time_t when;
};

static void verify(const struct run *r)
{
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    STACK_OF(X509) *untrusted = sk_X509_new_null(), *chain;
    STACK_OF(X509_CRL) *crls = sk_X509_CRL_new_null();
    X509_VERIFY_PARAM *vpm;
    int i, ret;

    for (i = 0; i < 3 && r->trusted[i] != NULL; i++)
        X509_STORE_add_cert(store, r->trusted[i]);
    for (i = 0; i < 3 && r->store_crls[i] != NULL; i++)
        X509_STORE_add_crl(store, r->store_crls[i]);
    for (i = 0; i < 3 && r->untrusted[i] != NULL; i++)
        sk_X509_push(untrusted, r->untrusted[i]);
    for (i = 0; i < 3 && r->crls[i] != NULL; i++)
        sk_X509_CRL_push(crls, r->crls[i]);
    custom_crl = r->custom;
    if (r->custom != NULL || strstr(r->label, "get_crl") != NULL)
        X509_STORE_set_get_crl(store, get_crl);
    X509_STORE_CTX_init(ctx, store, r->leaf, untrusted);
    X509_STORE_CTX_set0_crls(ctx, crls);
    X509_STORE_CTX_set_verify_cb(ctx, trace_cb);
    vpm = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set_time(vpm, r->when != 0 ? r->when : WHEN);
    if (r->flags != 0)
        X509_VERIFY_PARAM_set_flags(vpm, r->flags);
    accept_errors = r->accept;
    printf("# %s\n", r->label);
    ret = X509_verify_cert(ctx);
    printf("  result %d, error %d (%s), depth %d\n", ret, X509_STORE_CTX_get_error(ctx),
           X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)), X509_STORE_CTX_get_error_depth(ctx));
    chain = X509_STORE_CTX_get0_chain(ctx);
    printf("  chain:");
    for (i = 0; i < sk_X509_num(chain); i++)
        printf(" [%s]", name(X509_get_subject_name(sk_X509_value(chain, i))));
    printf("\n  current crl %s\n", X509_STORE_CTX_get0_current_crl(ctx) == NULL ? "(none)" : "set");
    errors();
    check(1, r->label);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    sk_X509_CRL_free(crls);
}

#define CHECK X509_V_FLAG_CRL_CHECK
#define ALL (X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL)
#define EXT (X509_V_FLAG_CRL_CHECK | X509_V_FLAG_EXTENDED_CRL_SUPPORT)

int main(void)
{
    X509 *root = read_cert(ROOT_PEM), *inter = read_cert(INTER_PEM), *interx = read_cert(INTERX_PEM);
    X509 *signer = read_cert(SIGNER_PEM), *leaf = read_cert(LEAF_PEM), *leaf2 = read_cert(LEAF2_PEM);
    X509 *leafi = read_cert(LEAFI_PEM), *leafx = read_cert(LEAFX_PEM);
    X509_CRL *root_crl = read_crl(ROOT_CRL), *inter_crl = read_crl(INTER_CRL);
    X509_CRL *expired = read_crl(INTER_EXPIRED_CRL), *future = read_crl(INTER_FUTURE_CRL);
    X509_CRL *badsig = read_crl(INTER_BADSIG_CRL), *crit = read_crl(INTER_CRIT_CRL);
    X509_CRL *delta = read_crl(INTER_DELTA_CRL), *idpca = read_crl(INTER_IDPCA_CRL);
    X509_CRL *idpreasons = read_crl(INTER_IDPREASONS_CRL), *idpmatch = read_crl(INTER_IDPMATCH_CRL);
    X509_CRL *idpother = read_crl(INTER_IDPOTHER_CRL), *interx_crl = read_crl(INTERX_CRL);
    X509_CRL *indirect = read_crl(INDIRECT_CRL);
    const struct run runs[] = {
        { "no CRL check", leaf, { inter }, { root }, { NULL }, { NULL }, 0, 0, NULL, 0 },
        { "revoked", leaf, { inter }, { root }, { inter_crl }, { NULL }, CHECK, 0, NULL, 0 },
        { "revoked, accepted", leaf, { inter }, { root }, { inter_crl }, { NULL }, CHECK, 1, NULL, 0 },
        { "not revoked", leaf2, { inter }, { root }, { inter_crl }, { NULL }, CHECK, 0, NULL, 0 },
        { "no CRL", leaf2, { inter }, { root }, { NULL }, { NULL }, CHECK, 0, NULL, 0 },
        { "no CRL, accepted", leaf2, { inter }, { root }, { NULL }, { NULL }, CHECK, 1, NULL, 0 },
        { "CRL in the store, not revoked", leaf2, { inter }, { root }, { NULL }, { inter_crl }, CHECK, 0, NULL, 0 },
        { "CRL in the store, revoked", leaf, { inter }, { root }, { NULL }, { inter_crl }, CHECK, 0, NULL, 0 },
        { "the whole chain", leaf2, { inter }, { root }, { inter_crl, root_crl }, { NULL }, ALL, 0, NULL, 0 },
        { "the whole chain, no root CRL", leaf2, { inter }, { root }, { inter_crl }, { NULL }, ALL, 0, NULL, 0 },
        { "the whole chain, revoked", leaf, { inter }, { root }, { root_crl }, { inter_crl }, ALL, 1, NULL, 0 },
        { "expired CRL", leaf2, { inter }, { root }, { expired }, { NULL }, CHECK, 0, NULL, 0 },
        { "expired CRL, accepted", leaf2, { inter }, { root }, { expired }, { NULL }, CHECK, 1, NULL, 0 },
        { "CRL not yet valid", leaf2, { inter }, { root }, { future }, { NULL }, CHECK, 0, NULL, 0 },
        { "expired CRL, no time check", leaf2, { inter }, { root }, { expired }, { NULL }, CHECK | X509_V_FLAG_NO_CHECK_TIME, 0, NULL, 0 },
        { "expired and current CRLs", leaf2, { inter }, { root }, { expired, inter_crl }, { NULL }, CHECK, 0, NULL, 0 },
        { "newer of two CRLs", leaf2, { inter }, { root }, { inter_crl, future }, { NULL }, CHECK, 0, NULL, 1792800000 },
        { "bad CRL signature", leaf2, { inter }, { root }, { badsig }, { NULL }, CHECK, 0, NULL, 0 },
        { "critical CRL extension", leaf2, { inter }, { root }, { crit }, { NULL }, CHECK, 0, NULL, 0 },
        { "critical CRL extension, ignored", leaf2, { inter }, { root }, { crit }, { NULL }, CHECK | X509_V_FLAG_IGNORE_CRITICAL, 0, NULL, 0 },
        { "delta CRL, unused", leaf, { inter }, { root }, { inter_crl, delta }, { NULL }, CHECK, 0, NULL, 0 },
        { "delta CRL, removed", leaf, { inter }, { root }, { inter_crl, delta }, { NULL }, CHECK | X509_V_FLAG_USE_DELTAS, 0, NULL, 0 },
        { "delta CRL, no freshest CRL", leaf2, { inter }, { root }, { inter_crl, delta }, { NULL }, CHECK | X509_V_FLAG_USE_DELTAS, 0, NULL, 0 },
        { "delta CRL alone", leaf, { inter }, { root }, { delta }, { NULL }, CHECK | X509_V_FLAG_USE_DELTAS, 0, NULL, 0 },
        { "only CA certificates", leaf2, { inter }, { root }, { idpca }, { NULL }, CHECK, 0, NULL, 0 },
        { "distribution point matches", leaf, { inter }, { root }, { idpmatch }, { NULL }, CHECK, 0, NULL, 0 },
        { "no distribution point", leaf2, { inter }, { root }, { idpmatch }, { NULL }, CHECK, 0, NULL, 0 },
        { "distribution point differs, accepted", leaf, { inter }, { root }, { idpother }, { NULL }, CHECK, 1, NULL, 0 },
        { "only some reasons", leaf2, { inter }, { root }, { idpreasons }, { NULL }, CHECK, 0, NULL, 0 },
        { "only some reasons, extended", leaf2, { inter }, { root }, { idpreasons }, { NULL }, EXT, 0, NULL, 0 },
        { "only some reasons and all", leaf2, { inter }, { root }, { idpreasons, inter_crl }, { NULL }, EXT, 0, NULL, 0 },
        { "issuer without cRLSign", leafx, { interx }, { root }, { interx_crl }, { NULL }, CHECK, 0, NULL, 0 },
        { "indirect CRL", leafi, { inter, signer }, { root }, { indirect }, { NULL }, CHECK, 0, NULL, 0 },
        { "indirect CRL, extended", leafi, { inter, signer }, { root }, { indirect }, { NULL }, EXT, 0, NULL, 0 },
        { "indirect CRL, extended, no signer", leafi, { inter }, { root }, { indirect }, { NULL }, EXT, 0, NULL, 0 },
        { "indirect CRL, extended, all", leafi, { inter, signer }, { root }, { indirect, root_crl }, { inter_crl }, EXT | X509_V_FLAG_CRL_CHECK_ALL, 0, NULL, 0 },
        { "custom get_crl, revoked", leaf, { inter }, { root }, { NULL }, { NULL }, CHECK, 0, inter_crl, 0 },
        { "custom get_crl, other issuer", leaf, { inter }, { root }, { NULL }, { NULL }, CHECK, 1, root_crl, 0 },
        { "custom get_crl, none", leaf, { inter }, { root }, { NULL }, { NULL }, CHECK, 0, NULL, 0 },
    };
    size_t i;

    for (i = 0; i < sizeof(runs) / sizeof(runs[0]); i++)
        verify(&runs[i]);

    X509_free(root);
    X509_free(inter);
    X509_free(interx);
    X509_free(signer);
    X509_free(leaf);
    X509_free(leaf2);
    X509_free(leafi);
    X509_free(leafx);
    X509_CRL_free(root_crl);
    X509_CRL_free(inter_crl);
    X509_CRL_free(expired);
    X509_CRL_free(future);
    X509_CRL_free(badsig);
    X509_CRL_free(crit);
    X509_CRL_free(delta);
    X509_CRL_free(idpca);
    X509_CRL_free(idpreasons);
    X509_CRL_free(idpmatch);
    X509_CRL_free(idpother);
    X509_CRL_free(interx_crl);
    X509_CRL_free(indirect);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
