/*
 * Conformance test for PEM bundles (PEM_X509_INFO_read_bio_ex(3), PEM_X509_INFO_write_bio,
 * X509_INFO_new, X509_PKEY_new), in TAP format: a bundle of certificates, CRLs, and private keys
 * (traditional RSA and EC, PKCS#8, PEM-encrypted, and encrypted PKCS#8) with an unknown block,
 * read into entries (a new one for each repeated kind; encrypted keys kept encrypted), into a
 * given list and a new one, from a BIO and a FILE; a trusted certificate; a broken bundle; and
 * entries written back.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
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
            printf(" [%s]", data);
    }
    printf("\n");
}

static const char BUNDLE[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBvjCCAWSgAwIBAgIBBzAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowETEPMA0GA1UEAwwG\n"
    "c2VydmVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEJmU/wZeX86icApfkgw1\n"
    "Vpwhan4WCwtpPNtvP4/ErxhATPYxrjMQqlv00olStwd324fXxDMKZEuBAO3ucJmK\n"
    "lqOBqDCBpTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggr\n"
    "BgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFCQZP0LkcWQzli7s4uZl9Y/W6N11\n"
    "MB8GA1UdIwQYMBaAFDSWzDx07E/3WRiFfN2ccfeakuE1MBYGA1UdEQQPMA2CC3d3\n"
    "dy5leGFtcGxlMBEGCWCGSAGG+EIBAQQEAwIGwDAKBggqhkjOPQQDAgNIADBFAiEA\n"
    "xpq7e4/INYzqjxGr0AfLJor5LyrRKl9ea0cR7htWCh4CIECo8YuCNq4t5xl6eRH1\n"
    "xspB6WRZ5yKS6EC7pnA7E+4o\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIICXAIBAAKBgQC00e780dx/VI4WzJJtcf+nECCHtEHtsQ6TjZIna3esmUjdYlJr\n"
    "hZJRsfOma2569HBZsMqF+I9p14sSfY3ssDbTShhYz8zY/ZinB6w7dZJovtncaXts\n"
    "9WAJhj2u95bvIYT9HrxwxRtF5N3V4X/vSPHWkJq23q7BrdW0e8Lo8EdtdQIDAQAB\n"
    "AoGAKlwX6aBcUHQFiW/JSdxv8LpFdKUU4NMewBBlUdjKQ2PxfvN+rXOwMHVIyA7Y\n"
    "5fMHsutItpPhPQFisiU5r14kqXt6mgRY8lccJEnhrnFnF1s/OmcVWAi/bXgJH4/E\n"
    "MIdRxLtGLvY4il7LZHce6doXoxpL+PZYnQdFAl+pto6TXmECQQDw1UV2r3KvCpQi\n"
    "IxdRMN4WUp6FHgZzQ7VfASheXKHdpQo26W/MrpNPazRB14PmaKNZ04XNky84HjNp\n"
    "FqyKxcZJAkEAwDUgq/QE8eNW4JE5CJfA8a9qeU25gt62tQZGQSAErG8lhyX0TtKA\n"
    "NIp4oTgNU0VVIWrHUDXPqAW+7FqYVWZ9zQJAaCo2o0D7f445yBIZcbqLNGiDu9vi\n"
    "ulQczHy5syaptC5AHsQU4RjZCk66CYhnum6jyKReiS4SDFmzrs5pzpQAUQJAA/cU\n"
    "nXeDQpo2CJv2WT8IM/Qydh4sXY7KpiFjAaTvc783PvqBd77P9kWFB45od/dOMkpJ\n"
    "olX52rWDosybp+ddYQJBAJhETB1QlhaHJBgrF5pvOEUYF3LeG79yYVJbQZfc39dA\n"
    "TWLReg8NaDSQj5kDrfuVeM1AWdmpgwBnX0QXB6m1zn0=\n"
    "-----END RSA PRIVATE KEY-----\n"
    "-----BEGIN UNKNOWN THING-----\n"
    "AAAA\n"
    "-----END UNKNOWN THING-----\n"
    "-----BEGIN X509 CRL-----\n"
    "MIIBIzCBygIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3NlIENBFw0y\n"
    "NjEwMTcxNTE1MTFaFw0yNjExMTYxNTE1MTFaMCIwIAIBBxcNMjYxMDE3MTUxNTEx\n"
    "WjAMMAoGA1UdFQQDCgEBoGAwXjAfBgNVHSMEGDAWgBQ0lsw8dOxP91kYhXzdnHH3\n"
    "mpLhNTAvBgNVHRwBAf8EJTAjoB2gG4YZaHR0cDovL2NybC5leGFtcGxlL2NhLmNy\n"
    "bIMCA0gwCgYDVR0UBAMCAREwCgYIKoZIzj0EAwIDSAAwRQIhAI76kr7OV6FMMqpS\n"
    "XIEpew38/kE+CMxyGYwejjVbjhyIAiBH9j8oiP2i3450dKVi0Mivw73uIdPqOT4M\n"
    "1teqCGXpXA==\n"
    "-----END X509 CRL-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBXzCCAQSgAwIBAgIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowFTETMBEGA1UEAwwK\n"
    "UHVycG9zZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBWjWIRih6WIPZH9\n"
    "yyM92OMGrP0IA1y4D9r8UFgmiVhQ2yk9byExM1oXjHDR9dt6q1lEA9jpqNZ3bnJc\n"
    "62luj0mjRTBDMBIGA1UdEwEB/wQIMAYBAf8CAQIwDgYDVR0PAQH/BAQDAgEGMB0G\n"
    "A1UdDgQWBBQ0lsw8dOxP91kYhXzdnHH3mpLhNTAKBggqhkjOPQQDAgNJADBGAiEA\n"
    "kj2rk1mD4ySwCZoobiJ9MdfoCxdvK6omAzn5TXDujQ8CIQD+Ns1YYa12PfODJ3Fy\n"
    "twUt2FgdVL8c5pnN7he1zcvVCQ==\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIEXyhsOYGXj+W51si2OB5nllDmT6VWUeoPtTQebkP+XboAoGCCqGSM49\n"
    "AwEHoUQDQgAEFaNYhGKHpYg9kf3LIz3Y4was/QgDXLgP2vxQWCaJWFDbKT1vITEz\n"
    "WheMcNH123qrWUQD2Omo1nduclzraW6PSQ==\n"
    "-----END EC PRIVATE KEY-----\n"
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALTR7vzR3H9UjhbM\n"
    "km1x/6cQIIe0Qe2xDpONkidrd6yZSN1iUmuFklGx86Zrbnr0cFmwyoX4j2nXixJ9\n"
    "jeywNtNKGFjPzNj9mKcHrDt1kmi+2dxpe2z1YAmGPa73lu8hhP0evHDFG0Xk3dXh\n"
    "f+9I8daQmrbersGt1bR7wujwR211AgMBAAECgYAqXBfpoFxQdAWJb8lJ3G/wukV0\n"
    "pRTg0x7AEGVR2MpDY/F+836tc7AwdUjIDtjl8wey60i2k+E9AWKyJTmvXiSpe3qa\n"
    "BFjyVxwkSeGucWcXWz86ZxVYCL9teAkfj8Qwh1HEu0Yu9jiKXstkdx7p2hejGkv4\n"
    "9lidB0UCX6m2jpNeYQJBAPDVRXavcq8KlCIjF1Ew3hZSnoUeBnNDtV8BKF5cod2l\n"
    "Cjbpb8yuk09rNEHXg+Zoo1nThc2TLzgeM2kWrIrFxkkCQQDANSCr9ATx41bgkTkI\n"
    "l8Dxr2p5TbmC3ra1BkZBIASsbyWHJfRO0oA0inihOA1TRVUhasdQNc+oBb7sWphV\n"
    "Zn3NAkBoKjajQPt/jjnIEhlxuos0aIO72+K6VBzMfLmzJqm0LkAexBThGNkKTroJ\n"
    "iGe6bqPIpF6JLhIMWbOuzmnOlABRAkAD9xSdd4NCmjYIm/ZZPwgz9DJ2Hixdjsqm\n"
    "IWMBpO9zvzc++oF3vs/2RYUHjmh3904ySkmiVfnatYOizJun511hAkEAmERMHVCW\n"
    "FockGCsXmm84RRgXct4bv3JhUltBl9zf10BNYtF6Dw1oNJCPmQOt+5V4zUBZ2amD\n"
    "AGdfRBcHqbXOfQ==\n"
    "-----END PRIVATE KEY-----\n"
    "-----BEGIN X509 CRL-----\n"
    "MIH+MIGmAgEBMAoGCCqGSM49BAMCMBUxEzARBgNVBAMMClB1cnBvc2UgQ0EXDTI2\n"
    "MTAxNzE1MTUxMVoXDTI2MTExNjE1MTUxMVqgYDBeMB8GA1UdIwQYMBaAFDSWzDx0\n"
    "7E/3WRiFfN2ccfeakuE1MC8GA1UdHAEB/wQlMCOgHaAbhhlodHRwOi8vY3JsLmV4\n"
    "YW1wbGUvY2EuY3JsgwIDSDAKBgNVHRQEAwIBEDAKBggqhkjOPQQDAgNHADBEAiA4\n"
    "6lXGdquAsE3ImzQrs5zgAcqjcMl76gREvVZJBZrFxwIgHdUgSR2hJL8mKUlTBA75\n"
    "lcKyjjBI/UsLKszeaJxU73A=\n"
    "-----END X509 CRL-----\n"
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "Proc-Type: 4,ENCRYPTED\n"
    "DEK-Info: AES-128-CBC,52D97D66FE7ECBB3DADDC060D946B7C7\n"
    "\n"
    "exN88Q0MJtQk5S6Dpmgqxq1bBY9bH+epajxdxAKPNDL4tCNfl4pQW1GLYXlHlV2m\n"
    "/IpD68VUwjsr+oa5CnDkZ+u2x/ydmDyxklz3j3oX4eDhvS7AIc94X08HXCy1Dal5\n"
    "iFPdiTeAgW8MosciYb1bIUqBUO5LUwdMKuMj6Lv5KguXI/pzzPaItvb+DEYgrhBr\n"
    "j5gF/Jf21+9j9OKD04LG6HFjH6HQ/s/pEA51VZ4vSq/wFUjeIH04FkNPt4Jit3VQ\n"
    "bYhN3XWp2Gw6YbAVCgMJTqCFNNF1Cn7rIqyeHIf3pi6b5g7e3UZl2qsdDYf+AckL\n"
    "kpa2PKlW8JXNhXSvgFAfe4H21sBt1bOo4dA3mK00hjS4LSPpZm2yOPkQ3m56t1iY\n"
    "VZtBtgqz2G6WPHrPtWhIRUJ7M0Z5AtN/3ZRyGuX1WvUDlrncR/ug1OnKuNSBdciZ\n"
    "do9E1joQkcwJ3D/nr83/fiQkxfm4NFIrb/4B0h/1yLsvL6P/Z88fRoc60EWIBPdJ\n"
    "YDR5wM6CW+7ILSnLUhyjGYkouiyrROtnG+GfQe8t2G8m1tigx0k6aMGaJhLEBChX\n"
    "1oV+1CG66+NyhrYJIA1kOq6BBaeEQtCv0LQ6F9Wcsvjb/pEsFePMKyKcpagyiLkF\n"
    "8Uxt3KSWFwrpq9sePyegdh7RzbF1h6q5mx+adFkSmkBWrtCpcqcJSUaVHw7mjYMH\n"
    "VBKqYgChtQFIGqoOUnwNTcoQ22Vx70h3fD88sXogVRBbtSfX3PobMOiWaVaagf1w\n"
    "Fu3tB64rCbAJjqrqi/mLVUnmRK+13uhjpOFaa5GEwAnwGqxwOjbQ363rXdZMiOkT\n"
    "-----END RSA PRIVATE KEY-----\n"
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    "MIIC5TBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQ2gCpdW3/8HtclTYs\n"
    "xSvstAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEAQIEEGDTsScdw6D4EBAs\n"
    "hRurLNcEggKA5IcI/cO/RquEjON3eyQAWKhB5ekL7OV7HxyCOd87s5tGLJADxDCr\n"
    "zM3jOuYd0p100qNB+P3z6LEYsRoHyoIeLBkyudewbPnjzCruymV7Wn30W/ur6WgP\n"
    "66lOBrz1b6A2ggfIA3x9E4OAISsHLRmRZMbUovK/WR5gdSlQpzoh6iuWgHtDm3WI\n"
    "9j/aUrWmXDVgF/EW50V/vpPzTCnzYUylG7mo3xKKiFoNSy9VJXXG3O/guxSnW3gf\n"
    "dylEopL+E9HpM+fgboLskIJ8UkRVOiDp3p6ATNs8Jczn9w8pVDHlbIceKwXLcRxB\n"
    "hCm1O24ooVpHuk2gVMpF9m8nZjzmCNxhna/z/OLWsnqUu4TBiPZYygQEDocoiyZS\n"
    "bQFSCwyDCyTkUH7j08DTHyvedXNOmmk1ePuNF2juzkSjtngDsJT4rAPFs+sCiKCj\n"
    "vj+8UP3W6j9N0ITjySidJ372P2SMQOHy7VTnQHoTGBYLpZIMRtpwPaPKZdXa05oc\n"
    "xcjcOD5jkDEQ5go+pU5+bFnXf6nSjfExlUZUoRM5nFaEyeAis8UWnm4JmNPknFE4\n"
    "UV/20/f42bNMT2WIYO4KO6FibJx8DKGKzqMn7ZEWXdk4biFkv22Tk7CCBa46uzLi\n"
    "3u2yWb0PjHABdqrj07h3vN6X06fhEyqUoxxM/V2zK+dLfjErmALfJC4uJH3zlzK8\n"
    "/HVsTgxWgGIuBoOHms2lE7ZDzJkQFGYG13l35rAS+vfyXYOlhbSOdbtgbpxqE5hf\n"
    "l593WP+wvZ6tASIT5DMslqCjlIXZ93ssWQGJeGBog8k29M3x5AD/5z8N4qahaWYp\n"
    "Vqj6jvuNUrf1cXv76bhZQl2ytGmhLVlvrQ==\n"
    "-----END ENCRYPTED PRIVATE KEY-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBvjCCAWSgAwIBAgIBBzAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowETEPMA0GA1UEAwwG\n"
    "c2VydmVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEJmU/wZeX86icApfkgw1\n"
    "Vpwhan4WCwtpPNtvP4/ErxhATPYxrjMQqlv00olStwd324fXxDMKZEuBAO3ucJmK\n"
    "lqOBqDCBpTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggr\n"
    "BgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFCQZP0LkcWQzli7s4uZl9Y/W6N11\n"
    "MB8GA1UdIwQYMBaAFDSWzDx07E/3WRiFfN2ccfeakuE1MBYGA1UdEQQPMA2CC3d3\n"
    "dy5leGFtcGxlMBEGCWCGSAGG+EIBAQQEAwIGwDAKBggqhkjOPQQDAgNIADBFAiEA\n"
    "xpq7e4/INYzqjxGr0AfLJor5LyrRKl9ea0cR7htWCh4CIECo8YuCNq4t5xl6eRH1\n"
    "xspB6WRZ5yKS6EC7pnA7E+4o\n"
    "-----END CERTIFICATE-----\n";

static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBXzCCAQSgAwIBAgIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowFTETMBEGA1UEAwwK\n"
    "UHVycG9zZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBWjWIRih6WIPZH9\n"
    "yyM92OMGrP0IA1y4D9r8UFgmiVhQ2yk9byExM1oXjHDR9dt6q1lEA9jpqNZ3bnJc\n"
    "62luj0mjRTBDMBIGA1UdEwEB/wQIMAYBAf8CAQIwDgYDVR0PAQH/BAQDAgEGMB0G\n"
    "A1UdDgQWBBQ0lsw8dOxP91kYhXzdnHH3mpLhNTAKBggqhkjOPQQDAgNJADBGAiEA\n"
    "kj2rk1mD4ySwCZoobiJ9MdfoCxdvK6omAzn5TXDujQ8CIQD+Ns1YYa12PfODJ3Fy\n"
    "twUt2FgdVL8c5pnN7he1zcvVCQ==\n"
    "-----END CERTIFICATE-----\n";

static void show(const char *label, STACK_OF(X509_INFO) *sk)
{
    int i;

    printf("# %s: %d entries\n", label, sk_X509_INFO_num(sk));
    for (i = 0; i < sk_X509_INFO_num(sk); i++) {
        X509_INFO *xi = sk_X509_INFO_value(sk, i);
        char name[128] = "";

        if (xi->x509 != NULL)
            X509_NAME_oneline(X509_get_subject_name(xi->x509), name, sizeof(name));
        printf("  %d: cert %s, crl %s, key %s, enc %d (%s), trusted %d\n", i, xi->x509 != NULL ? name : "-",
               xi->crl == NULL ? "-" : X509_CRL_get0_nextUpdate(xi->crl) != NULL ? "yes" : "?",
               xi->x_pkey == NULL ? "-" : xi->x_pkey->dec_pkey == NULL ? "none"
                                         : EVP_PKEY_get0_type_name(xi->x_pkey->dec_pkey),
               xi->enc_len, xi->enc_cipher.cipher == NULL ? "-" : EVP_CIPHER_get0_name(xi->enc_cipher.cipher),
               xi->x509 != NULL && X509_trusted(xi->x509));
    }
}

static void write_entry(const char *label, X509_INFO *xi, const EVP_CIPHER *enc)
{
    BIO *mem = BIO_new(BIO_s_mem());
    char *data;
    long n;
    int r = PEM_X509_INFO_write_bio(mem, xi, (EVP_CIPHER *)enc, (const unsigned char *)"pw", 2, NULL, NULL);
    const char *p;
    int blocks = 0;

    n = BIO_get_mem_data(mem, &data);
    for (p = data; p < data + n && (p = strstr(p, "-----BEGIN ")) != NULL && p < data + n; p++) {
        const char *e = strchr(p + 11, '-');

        printf("    block %.*s\n", (int)(e - p - 11), p + 11);
        blocks++;
        if (strncmp(p + 11, "RSA PRIVATE KEY", 15) == 0 && strstr(p, "ENCRYPTED") != NULL && enc == NULL)
            printf("      kept encrypted\n");
    }
    printf("  %s: %d, %d blocks\n", label, r, blocks);
    errors();
    BIO_free(mem);
}

int main(void)
{
    BIO *b = BIO_new_mem_buf(BUNDLE, -1);
    STACK_OF(X509_INFO) *sk = PEM_X509_INFO_read_bio_ex(b, NULL, NULL, NULL, NULL, NULL), *given;
    X509_INFO *xi;
    int i;

    BIO_free(b);
    check(sk != NULL, "read the bundle");
    show("the bundle", sk);
    errors();

    /* Into a given list, with one already there. */
    given = sk_X509_INFO_new_null();
    sk_X509_INFO_push(given, X509_INFO_new());
    b = BIO_new_mem_buf(CA_PEM, -1);
    check(PEM_X509_INFO_read_bio(b, given, NULL, NULL) == given, "into a given list");
    BIO_free(b);
    show("given", given);

    /* A trusted certificate. */
    {
        X509 *x;
        BIO *mem = BIO_new(BIO_s_mem());
        STACK_OF(X509_INFO) *t;

        b = BIO_new_mem_buf(CA_PEM, -1);
        x = PEM_read_bio_X509(b, NULL, NULL, NULL);
        BIO_free(b);
        X509_add1_trust_object(x, OBJ_nid2obj(NID_server_auth));
        PEM_write_bio_X509_AUX(mem, x);
        t = PEM_X509_INFO_read_bio(mem, NULL, NULL, NULL);
        show("trusted", t);
        sk_X509_INFO_pop_free(t, X509_INFO_free);
        X509_free(x);
        BIO_free(mem);
    }

    /* From a FILE. */
    {
        FILE *fp = tmpfile();

        if (fp != NULL) {
            STACK_OF(X509_INFO) *f;

            fputs(BUNDLE, fp);
            rewind(fp);
            f = PEM_X509_INFO_read(fp, NULL, NULL, NULL);
            printf("# from a FILE: %d entries\n", sk_X509_INFO_num(f));
            sk_X509_INFO_pop_free(f, X509_INFO_free);
            rewind(fp);
            f = PEM_X509_INFO_read_ex(fp, NULL, NULL, NULL, NULL, NULL);
            printf("  again: %d entries\n", sk_X509_INFO_num(f));
            sk_X509_INFO_pop_free(f, X509_INFO_free);
            fclose(fp);
        }
    }

    /* A broken block: a certificate that doesn't decode, into a given list. */
    {
        static const char BROKEN[] = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n";
        int before = sk_X509_INFO_num(given);

        b = BIO_new_mem_buf(BROKEN, -1);
        check(PEM_X509_INFO_read_bio(b, given, NULL, NULL) == NULL, "a broken certificate fails");
        errors();
        BIO_free(b);
        printf("  given list kept: %d -> %d\n", before, sk_X509_INFO_num(given));
        b = BIO_new_mem_buf("-----BEGIN CERTIFICATE-----\nMAA", -1);
        check(PEM_X509_INFO_read_bio(b, NULL, NULL, NULL) == NULL, "a cut block fails");
        errors();
        BIO_free(b);
        b = BIO_new_mem_buf("nothing here", -1);
        sk = (sk_X509_INFO_pop_free(sk, X509_INFO_free), PEM_X509_INFO_read_bio(b, NULL, NULL, NULL));
        printf("  no PEM: %d entries\n", sk == NULL ? -1 : sk_X509_INFO_num(sk));
        errors();
        BIO_free(b);
        sk_X509_INFO_pop_free(sk, X509_INFO_free);
    }

    /* Writing. */
    b = BIO_new_mem_buf(BUNDLE, -1);
    sk = PEM_X509_INFO_read_bio(b, NULL, NULL, NULL);
    BIO_free(b);
    printf("# writing\n");
    for (i = 0; i < sk_X509_INFO_num(sk); i++) {
        char label[32];

        xi = sk_X509_INFO_value(sk, i);
        snprintf(label, sizeof(label), "entry %d", i);
        write_entry(label, xi, NULL);
        /* OpenSSL reads through the missing cipher of an encrypted PKCS#8 entry. */
        if ((xi->enc_data != NULL && xi->enc_cipher.cipher != NULL) || (xi->x_pkey != NULL && xi->enc_data == NULL)) {
            snprintf(label, sizeof(label), "entry %d, AES", i);
            write_entry(label, xi, EVP_aes_128_cbc());
        }
    }
    write_entry("empty", (xi = X509_INFO_new()), NULL);
    X509_INFO_free(xi);
    xi = X509_INFO_new();
    xi->x_pkey = X509_PKEY_new();
    check(xi->x_pkey != NULL && xi->x_pkey->enc_algor != NULL && xi->x_pkey->enc_pkey != NULL, "X509_PKEY_new");
    X509_INFO_free(xi);
    X509_INFO_free(NULL);
    X509_PKEY_free(NULL);

    sk_X509_INFO_pop_free(sk, X509_INFO_free);
    /* The failed read freed the given list's entries (it keeps the pointers): only the list is left. */
    sk_X509_INFO_free(given);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
