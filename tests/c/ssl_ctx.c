/*
 * Conformance test for libssl's objects before any handshake (SSL_CTX_new(3), SSL_new(3),
 * SSL_CTX_set_options(3), SSL_CTX_ctrl(3), SSL_CTX_use_certificate(3), SSL_set_bio(3),
 * SSL_CTX_set_security_level(3), SSL_load_client_CA_file(3)): every method's versions and roles,
 * the context's defaults and what a connection inherits, options and modes, the ctrl commands
 * that need no connection, version bounds, certificates and keys (files, DER, chains, the
 * security level's key check, a mismatched key), client CA lists, verification locations,
 * application data, BIO ownership, file descriptors, switching contexts, hosts and the server
 * name, the stored callbacks, and NULL and bad arguments.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
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

/* The test's scratch directory, which differs per run. */
static char dir[64];

static void errors(void)
{
    unsigned long e;
    const char *data, *at;
    int flags;

    printf("  errors:");
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((flags & ERR_TXT_STRING) == 0 || data == NULL || *data == '\0')
            continue;
        /* The scratch directory prints as DIR. */
        if ((at = strstr(data, dir)) != NULL)
            printf(" [%.*sDIR%s]", (int)(at - data), data, at + strlen(dir));
        else
            printf(" [%s]", data);
    }
    printf("\n");
}

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

static const char RESP_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICgDCCAiagAwIBAgICAMgwCgYIKoZIzj0EAwIwJzEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTETMBEGA1UEAwwKU01JTUUgUm9vdDAeFw0yNjEwMTgwMjAxMjFaFw0zNjEwMTUw\n"
    "MjAxMjFaMBkxFzAVBgNVBAMMDk9DU1AgcmVzcG9uZGVyMIIBIjANBgkqhkiG9w0B\n"
    "AQEFAAOCAQ8AMIIBCgKCAQEA3HCIIiJdIC4WPiFIfG9O9v8sU4avr8jbqZHk3WDb\n"
    "uchCk7WV0W6dyTT8b09NCG72+sLyZ9+SB9sMo8Y0bXVqSSsUsHmccKNef7BWjel/\n"
    "Ixffx3hoa95KWwD5i09xP8rOS3nvKQgFhhOHIzSrkcoelmjdshfqAavgSZ8AiHHb\n"
    "XCeeCR/BIGGTW9upVz00HMp1+OMjYaWuHhZjiE0H0tyqW9N7F+qSZUUdF04kOz8p\n"
    "dhHw62pPZY+LTbGlRLY8lOHkOCyhGFP2sw181yJ8nJepkWwoU/nadHM/IeOxfhK/\n"
    "9MXVLo0M8NfBSeQFbyzBzeGlu74aVAD7ZfBPJrIGpfKpmQIDAQABo4GEMIGBMAkG\n"
    "A1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMJMA8G\n"
    "CSsGAQUFBzABBQQCBQAwHQYDVR0OBBYEFOtte27fJFSMNXDOGt5fGtSvDMpzMB8G\n"
    "A1UdIwQYMBaAFHW101B521S0OKWXAyFbAPAdaKBFMAoGCCqGSM49BAMCA0gAMEUC\n"
    "IQDqiUQ6WbknYC0kqcQEKxcodQH6FD3ERSY48C1Hupq4nAIgBKZ6kl+kzNc0/GsE\n"
    "N3T1gsXvAErpJllMJa/euPYvqso=\n"
    "-----END CERTIFICATE-----\n";

static const char ED_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBCDCBu6ADAgECAhQ4pdT3bTgoTWI2cRS401uMRc+y6TAFBgMrZXAwEjEQMA4G\n"
    "A1UEAwwHZWQyNTUxOTAgFw0yNjEwMTgwNzQxMzRaGA8yMTI2MDkyNDA3NDEzNFow\n"
    "EjEQMA4GA1UEAwwHZWQyNTUxOTAqMAUGAytlcAMhANKoopwtNLseI8s7r5edlwoz\n"
    "Z6eTkcqrtTDHGpWhJJU9oyEwHzAdBgNVHQ4EFgQUcik+yiRWQHlmX1FQ9l8u9HrH\n"
    "vZYwBQYDK2VwA0EAktPDFffeEm7aUkGLHb0nO+Gp8c2sUWlJJVYFkDvqdXJHn2AC\n"
    "9nhKLMq4ZPBxu2Fh6U8Q06wGJoqUfzliDcChAw==\n"
    "-----END CERTIFICATE-----\n";

static const char WEAK_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIByjCCATOgAwIBAgIUeMEiHBFJqRDA1McsTmq1kRk5sHkwDQYJKoZIhvcNAQEL\n"
    "BQAwDzENMAsGA1UEAwwEd2VhazAgFw0yNjEwMTgwNzQxMzRaGA8yMTI2MDkyNDA3\n"
    "NDEzNFowDzENMAsGA1UEAwwEd2VhazCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC\n"
    "gYEAmF6Ld4J/HHj+wg/GCL8q91qIB8YZhj2Q6dmr2laKI83VR1uATYF75ipCnsp1\n"
    "1+mm9y1JWqeOt+9h7pTzCuxsnAI9iOJISo0PKeXaEMmBptPdcCk9e02rbeECUObC\n"
    "L8V7oY+v40mYdBpRNmxhdzG2/ESAid3rJwXmR+rzfFvTWgsCAwEAAaMhMB8wHQYD\n"
    "VR0OBBYEFKHMgTargEQLlYNu6xhlP4K8YiveMA0GCSqGSIb3DQEBCwUAA4GBAEqw\n"
    "IZdf9vBXH5RHPlwJu+nGf9KyIt7qey4ShatT/eVR8000dsl3OcodGoouUcVTtGbT\n"
    "tJQwC27i+U/zeCtIDWsd3kn7S7B1y+ajJVYJDIFMC/omTpg5PxiBtZZ/5PJyczjE\n"
    "v9V/TVN3FVa9rDJ6xgYQ//aSl0LnlccBGLtPZMlk\n"
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
    "MC4CAQAwBQYDK2VwBCIEIMeFDJvoAEY7DXOd1H+D0IlD9f9f8qzrSWCcCP4SuoH5\n"
    "-----END PRIVATE KEY-----\n";

static const char WEAK_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAJhei3eCfxx4/sIP\n"
    "xgi/KvdaiAfGGYY9kOnZq9pWiiPN1UdbgE2Be+YqQp7KddfppvctSVqnjrfvYe6U\n"
    "8wrsbJwCPYjiSEqNDynl2hDJgabT3XApPXtNq23hAlDmwi/Fe6GPr+NJmHQaUTZs\n"
    "YXcxtvxEgInd6ycF5kfq83xb01oLAgMBAAECgYA9H2AvNugq0dbQnmdAxv9Dbsu2\n"
    "4p8GnNfvF2S7F5AewMlX8LrNXK4JLNbAwFL5pD9YVJBij2jPHHZasOG2dhUy+bQU\n"
    "SKk5cYmR2i4IL8AaF2/3azMfm+MnJMv8e9LEXHcy3hq221/sQ3BRTRHqKlcpWs+O\n"
    "AYdMGcCLu70ey4YOoQJBAMeT0umNuYO18kWDXetG9AUnr7jaqVQU30Inxpmm4MsG\n"
    "509a0MU4S5+G+FF1XQ7LrGV6WQnXduOAF045EmddsKkCQQDDchcRMbvL4BGYCxzB\n"
    "mR1/GGJ61r9dzKsX9U5W2fy+FmWPmZiGN9kk9SiSWeP+QRBTAkmrB7vjGU6o1Ve9\n"
    "TEGTAkAC7GdqhGjzRPcHjaUSjTeF2873JjzUvnmGvo5qMceZMcCxqOLmAK0a6R86\n"
    "Ej4KuXENC33CZyWWr4mn264pVXYBAkAKGQjsEH+9ZtRB4MEZl4mYmW/tHM9CT2K/\n"
    "mCL2BckzIQEaTDs/I/+KE0iHVzGaX04ym7mmpn2knBgeTPd9hkUVAkA2DZWMRvQN\n"
    "+fvv8L/9tFTDfQ3KSYyLB+AoGhuX6B+cRRKQOw24DGaF/DDCD2nU6zZIHi9NxSlu\n"
    "cynDI8xFjQkf\n"
    "-----END PRIVATE KEY-----\n";

static const char RSA_ENC_KEY_PEM[] =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    "MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQ3Fmltj6hqO/iKuN5\n"
    "TeP82gICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEAQIEEIJNb/8I7NyoW0gJ\n"
    "PG5HeUIEggTQavAS5fat2ZwqyvOhsQUussHed5HzP7NffGLQSngzgW9Xlc1VQ3/l\n"
    "U4t7yS4VHFvU+NxKZ05fg6/qq7D/25tEGyc5EJXuRIB8nCDaDfuMrAVjAX6f/6Ha\n"
    "2UbHqontdbWKtk1DUn2wpVeEfy7H8DBsvGaRo32WZQjk0aBPUvK6TwRpfA+4apjr\n"
    "YHllWjy19j6kE/d86L+7MSrKWft4E/46C9mn5GfV+xlW432y+M70ivq38u0rFUCi\n"
    "qlfPJe6//q17uV4dj7WWC9fBan8bg/T0AIwKfuWci7uMJDYhqABcI0mMIe6Fw9hN\n"
    "KEzd0oheAOevH/caFkNbY9vKO4zwirdvKoi1ZiK+htGKyr5nHhsrKmwjaJ2weUpl\n"
    "f1AhjSfvkFHtEe9Q9513NfyK5pallVRyvoLiOfBEd35nhSOK9qI99Pe5sFpzeQH6\n"
    "btiyz0bYnlnwVyQu0EH0hQFnQfjvbknmphZ0/Kvb1Usj3z63YpDZvDY1BVa1Buf2\n"
    "nBVmvzvoAkR2BQOMEehiufa6TQUzlEQzE+8YqI/b7lJcP6JQHik59mnq8HBUu7cx\n"
    "mmpv+P0mOhcn04segKeQi4eivihk0OJYwRIEabHq+c23RipjM+jyugAg1p3+Iufq\n"
    "pP4H9E8YTzgJWYa5fM+g/hsC7SP+LDaVXgejasLIlm7ykcKaKzWadfnpEblAYo3z\n"
    "4YYyrZmQSyDgCfvKjFKjKLjA4AJ2/nBsEVet3VU4s/IeQ4v+TUe+VTGyqhGB7ayy\n"
    "tZbJCArzSO1pUi9nIdVOkobh+0dVySSeUAUiM9QY1r/piHi8YcqAfG7EbkSVL96a\n"
    "OUYyO0neyKmaYGSJ9BDErRGAXrbTpwfIq2CWL2ZleIVYBLDywH8lz5INmBnmhpH/\n"
    "mK4eZrpUXm3qVsYzrZkPQsWxvD/p6h9rcCXru6o7A37xV6fi9w/njBOSvM95OXnO\n"
    "7BNcwTQlfcWOkPao0nMLIJF5JONQSdQKVcT1IBbQjGNWuwP4zFYLr3HDBgBoowEv\n"
    "7nCIG/IvASQZFv7GgGiyyAaxcNl6kaiDMVXQcXQBDju6Mm6qZoIe2a1DrgWPpmy6\n"
    "Ltwr66Ve+2byuNPziUqUFl+IL2fKxaX6oQsbjiLD3dfSYJl2i+iSBAoT8WW1xM7J\n"
    "4RO4qT/JCdDKkYezXu5jXY0L774ipPIkLuZNZzZB0bbGInf6uDUPliEwawBA2kJE\n"
    "xv2NWLiRu7KNAApyw3fXa6DX36JSqRmaNU8IOkW3OjxaPSkWFzv6OcHSLaF45W9C\n"
    "APB+I3ze2kAbui6GQWyMrNFELbRhvziemk6omY7bxkw3kT4giyAis3f0oTXcC301\n"
    "o92LBfGM/lE0HULuJUpkIuWWIX1hkyoWlaV8sH5+ozY1+yMwcGr2ZzDk24z5j4fG\n"
    "Fp+KdNKrvkOJjUuhmuSuF5cMd02yGdAcBsyzqGBtiJzo2l+1hz7ITF0l+yjeg5wM\n"
    "TqYTKfqIO9chxfOHELo/KG4nT3m9r9tT3N2BAJKwBFk3WNU+euVkheemuex7k6DF\n"
    "SIdWWE+RRawkuGRlTBw/EmVBSec0UoJhwnePqBrJccOPaz5zJpsVmBVyceJDAstK\n"
    "1MCwxI++4rqZk4g5EyCW7qZr06pW4/8ZGIWP1mOYGNP0vtt5PKmCX80=\n"
    "-----END ENCRYPTED PRIVATE KEY-----\n";


static const char *path_of(const char *name)
{
    static char paths[16][128];
    static int k;
    char *p = paths[k++ % 16];

    snprintf(p, 128, "%s/%s", dir, name);
    return p;
}

static void write_file(const char *name, const void *data, size_t len)
{
    FILE *f = fopen(path_of(name), "wb");

    if (f != NULL) {
        fwrite(data, 1, len, f);
        fclose(f);
    }
}

static X509 *cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static EVP_PKEY *key(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);

    BIO_free(b);
    return k;
}

static void name_of(const char *label, const X509 *x)
{
    printf("  %s: ", label);
    if (x == NULL)
        printf("(none)");
    else
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(x), 0, XN_FLAG_ONELINE);
    printf("\n");
}

static void names(const char *label, const STACK_OF(X509_NAME) *sk)
{
    int i;

    printf("  %s (%d):", label, sk == NULL ? -1 : sk_X509_NAME_num(sk));
    for (i = 0; i < sk_X509_NAME_num(sk); i++) {
        char buf[128];

        X509_NAME_oneline(sk_X509_NAME_value(sk, i), buf, sizeof(buf));
        printf(" %s", buf);
    }
    printf("\n");
}

/* Methods */

struct meth {
    const char *name;
    const SSL_METHOD *(*fn)(void);
};

static void methods(void)
{
    static const struct meth all[] = {
        { "TLS_method", TLS_method },
        { "TLS_client_method", TLS_client_method },
        { "TLS_server_method", TLS_server_method },
        { "TLSv1_method", TLSv1_method },
        { "TLSv1_client_method", TLSv1_client_method },
        { "TLSv1_server_method", TLSv1_server_method },
        { "TLSv1_1_method", TLSv1_1_method },
        { "TLSv1_1_client_method", TLSv1_1_client_method },
        { "TLSv1_1_server_method", TLSv1_1_server_method },
        { "TLSv1_2_method", TLSv1_2_method },
        { "TLSv1_2_client_method", TLSv1_2_client_method },
        { "TLSv1_2_server_method", TLSv1_2_server_method },
        { "DTLS_method", DTLS_method },
        { "DTLS_client_method", DTLS_client_method },
        { "DTLS_server_method", DTLS_server_method },
        { "DTLSv1_method", DTLSv1_method },
        { "DTLSv1_client_method", DTLSv1_client_method },
        { "DTLSv1_server_method", DTLSv1_server_method },
        { "DTLSv1_2_method", DTLSv1_2_method },
        { "DTLSv1_2_client_method", DTLSv1_2_client_method },
        { "DTLSv1_2_server_method", DTLSv1_2_server_method },
    };
    size_t i;

    printf("# methods\n");
    for (i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        const SSL_METHOD *m = all[i].fn();
        SSL_CTX *ctx = SSL_CTX_new(m);
        SSL *s = ctx == NULL ? NULL : SSL_new(ctx);

        if (s == NULL) {
            printf("  %s: no object\n", all[i].name);
            errors();
            SSL_CTX_free(ctx);
            continue;
        }
        printf("  %s: same %d, version %#x (%s), client %#x, server %d, dtls %d, tls %d, quic %d, timeout %ld, state %d\n",
               all[i].name, SSL_CTX_get_ssl_method(ctx) == m && SSL_get_ssl_method(s) == m && all[i].fn() == m,
               (unsigned)SSL_version(s), SSL_get_version(s), (unsigned)SSL_client_version(s), SSL_is_server(s),
               SSL_is_dtls(s), SSL_is_tls(s), SSL_is_quic(s), SSL_get_default_timeout(s), (int)SSL_get_state(s));
        SSL_set_connect_state(s);
        printf("    connecting: server %d, version %s; ", SSL_is_server(s), SSL_get_version(s));
        SSL_set_accept_state(s);
        printf("accepting: server %d; clear %d, version %#x\n", SSL_is_server(s), SSL_clear(s),
               (unsigned)SSL_version(s));
        SSL_free(s);
        SSL_CTX_free(ctx);
    }
    {
        SSL_CTX *ctx = SSL_CTX_new(TLS_method());
        SSL *s = SSL_new(ctx);

        check(SSL_set_ssl_method(s, TLSv1_2_method()) == 1 && SSL_get_ssl_method(s) == TLSv1_2_method(),
              "SSL_set_ssl_method");
        printf("  after: version %#x\n", (unsigned)SSL_version(s));
        check(SSL_clear(s) == 1 && SSL_get_ssl_method(s) == TLS_method(), "SSL_clear reverts the method");
        check(SSL_set_ssl_method(s, TLS_client_method()) == 1, "a method of the same version");
        SSL_free(s);
        SSL_CTX_free(ctx);
    }
    check(SSL_CTX_new(NULL) == NULL, "no method");
    errors();
    check(SSL_new(NULL) == NULL, "no context");
    errors();
}

/* Defaults and inheritance */

static void defaults(SSL_CTX *ctx)
{
    printf("  options %#llx, mode %#lx, verify %d/%d, quiet %d, level %d, timeout %ld, cert list %ld\n",
           (unsigned long long)SSL_CTX_get_options(ctx), SSL_CTX_get_mode(ctx), SSL_CTX_get_verify_mode(ctx),
           SSL_CTX_get_verify_depth(ctx), SSL_CTX_get_quiet_shutdown(ctx), SSL_CTX_get_security_level(ctx),
           SSL_CTX_get_timeout(ctx), SSL_CTX_get_max_cert_list(ctx));
    printf("  cache mode %#lx, size %ld, tickets %zu, early %u/%u, read ahead %ld, versions %ld-%ld\n",
           SSL_CTX_get_session_cache_mode(ctx), SSL_CTX_sess_get_cache_size(ctx), SSL_CTX_get_num_tickets(ctx),
           (unsigned)SSL_CTX_get_max_early_data(ctx), (unsigned)SSL_CTX_get_recv_max_early_data(ctx),
           SSL_CTX_get_read_ahead(ctx), SSL_CTX_get_min_proto_version(ctx), SSL_CTX_get_max_proto_version(ctx));
    printf("  store %d, param %d, cert %d, key %d, security cb %d, ex %d, verify cb %d, passwd cb %d, info cb %d, keylog %d\n",
           SSL_CTX_get_cert_store(ctx) != NULL, SSL_CTX_get0_param(ctx) != NULL, SSL_CTX_get0_certificate(ctx) != NULL,
           SSL_CTX_get0_privatekey(ctx) != NULL, SSL_CTX_get_security_callback(ctx) != NULL,
           SSL_CTX_get0_security_ex_data(ctx) != NULL, SSL_CTX_get_verify_callback(ctx) != NULL,
           SSL_CTX_get_default_passwd_cb(ctx) != NULL, SSL_CTX_get_info_callback(ctx) != NULL,
           SSL_CTX_get_keylog_callback(ctx) != NULL);
    printf("  CA lists %d/%d, status type %ld\n", sk_X509_NAME_num(SSL_CTX_get0_CA_list(ctx)),
           sk_X509_NAME_num(SSL_CTX_get_client_CA_list(ctx)), SSL_CTX_get_tlsext_status_type(ctx));
}

static int verify_cb(int ok, X509_STORE_CTX *x)
{
    (void)x;
    return ok;
}

static void info_cb(const SSL *s, int where, int ret)
{
    (void)s;
    (void)where;
    (void)ret;
}

static void keylog_cb(const SSL *s, const char *line)
{
    (void)s;
    (void)line;
}

static int passwd_cb(char *buf, int size, int rwflag, void *u)
{
    const char *pw = "secret";

    printf("  passwd callback: size %d, rwflag %d, userdata %s\n", size, rwflag, u == NULL ? "(none)" : (char *)u);
    if (size < 7)
        return 0;
    memcpy(buf, pw, 6);
    return 6;
}

static int security_seen = 0;

static int security_cb(const SSL *s, const SSL_CTX *ctx, int op, int bits, int nid, void *other, void *ex)
{
    security_seen++;
    printf("  security callback: ssl %d, ctx %d, op %#x, bits %d, nid %d, other %d, ex %s\n", s != NULL,
           ctx != NULL, (unsigned)op, bits, nid, other != NULL, ex == NULL ? "(none)" : (char *)ex);
    return bits >= 112 || op == SSL_SECOP_TMP_DH;
}

static void contexts(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method()), *lib = SSL_CTX_new_ex(NULL, "provider=default", TLS_server_method());
    SSL *s;
    unsigned char sid[33];

    printf("# defaults\n");
    defaults(ctx);
    check(lib != NULL, "SSL_CTX_new_ex with properties");
    defaults(lib);
    SSL_CTX_free(lib);

    printf("# options and modes\n");
    printf("  set %#llx\n", (unsigned long long)SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3 | SSL_OP_PREFER_NO_DHE_KEX));
    printf("  clear %#llx\n", (unsigned long long)SSL_CTX_clear_options(ctx, SSL_OP_NO_COMPRESSION));
    printf("  mode %#lx, cleared %#lx\n", SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ENABLE_PARTIAL_WRITE),
           SSL_CTX_clear_mode(ctx, SSL_MODE_AUTO_RETRY));

    printf("# connection inherits\n");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
    SSL_CTX_set_verify_depth(ctx, 5);
    SSL_CTX_set_quiet_shutdown(ctx, 1);
    SSL_CTX_set_security_level(ctx, 1);
    SSL_CTX_set_num_tickets(ctx, 4);
    SSL_CTX_set_max_early_data(ctx, 1000);
    SSL_CTX_set_recv_max_early_data(ctx, 2000);
    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_max_cert_list(ctx, 4096);
    memset(sid, 'a', sizeof(sid));
    check(SSL_CTX_set_session_id_context(ctx, sid, 32) == 1, "SSL_CTX_set_session_id_context");
    check(SSL_CTX_set_session_id_context(ctx, sid, 33) == 0, "a context too long");
    errors();
    SSL_CTX_set_info_callback(ctx, info_cb);
    SSL_CTX_set_keylog_callback(ctx, keylog_cb);
    SSL_CTX_set_default_passwd_cb(ctx, passwd_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, "ctx");
    printf("  ctx userdata %s\n", (char *)SSL_CTX_get_default_passwd_cb_userdata(ctx));
    check(SSL_CTX_set_timeout(ctx, 300) == 7200 && SSL_CTX_get_timeout(ctx) == 300, "SSL_CTX_set_timeout");
    check(SSL_CTX_set_timeout(ctx, 7200) == 300, "the old timeout back");
    defaults(ctx);
    s = SSL_new(ctx);
    printf("  ssl options %#llx, mode %#lx, verify %d/%d, quiet %d, level %d, tickets %zu, early %u/%u, read ahead %d, cert list %ld\n",
           (unsigned long long)SSL_get_options(s), SSL_get_mode(s), SSL_get_verify_mode(s), SSL_get_verify_depth(s),
           SSL_get_quiet_shutdown(s), SSL_get_security_level(s), SSL_get_num_tickets(s),
           (unsigned)SSL_get_max_early_data(s), (unsigned)SSL_get_recv_max_early_data(s), SSL_get_read_ahead(s),
           SSL_get_max_cert_list(s));
    printf("  ssl verify cb %d, info cb %d, passwd cb %d, userdata %s, security cb %d\n",
           SSL_get_verify_callback(s) == verify_cb, SSL_get_info_callback(s) == info_cb,
           SSL_get_default_passwd_cb(s) == passwd_cb, (char *)SSL_get_default_passwd_cb_userdata(s),
           SSL_get_security_callback(s) == SSL_CTX_get_security_callback(ctx));
    SSL_set_options(s, SSL_OP_NO_TICKET);
    SSL_clear_options(s, SSL_OP_NO_TLSv1_3);
    SSL_set_mode(s, SSL_MODE_AUTO_RETRY);
    SSL_clear_mode(s, SSL_MODE_RELEASE_BUFFERS);
    SSL_set_verify(s, SSL_VERIFY_NONE, NULL);
    SSL_set_verify_depth(s, 9);
    SSL_set_quiet_shutdown(s, 0);
    SSL_set_security_level(s, 3);
    SSL_set_num_tickets(s, 7);
    SSL_set_max_early_data(s, 11);
    SSL_set_recv_max_early_data(s, 12);
    SSL_set_read_ahead(s, 0);
    SSL_set_info_callback(s, NULL);
    SSL_set_default_passwd_cb(s, NULL);
    SSL_set_default_passwd_cb_userdata(s, "ssl");
    printf("  changed: options %#llx, mode %#lx, verify %d/%d (callback kept %d), quiet %d, level %d, tickets %zu, early %u/%u, read ahead %d, info cb %d, userdata %s\n",
           (unsigned long long)SSL_get_options(s), SSL_get_mode(s), SSL_get_verify_mode(s), SSL_get_verify_depth(s),
           SSL_get_verify_callback(s) == verify_cb, SSL_get_quiet_shutdown(s), SSL_get_security_level(s),
           SSL_get_num_tickets(s), (unsigned)SSL_get_max_early_data(s), (unsigned)SSL_get_recv_max_early_data(s),
           SSL_get_read_ahead(s), SSL_get_info_callback(s) != NULL, (char *)SSL_get_default_passwd_cb_userdata(s));
    defaults(ctx);
    check(SSL_set_session_id_context(s, sid, 4) == 1, "SSL_set_session_id_context");
    check(SSL_set_session_id_context(s, sid, 40) == 0, "too long for the connection");
    errors();
    printf("  ssl state %d, in init %d, before %d, finished %d, want %d, shutdown %d, verify result %ld, reused %d\n",
           (int)SSL_get_state(s), SSL_in_init(s), SSL_in_before(s), SSL_is_init_finished(s), SSL_want(s),
           SSL_get_shutdown(s), SSL_get_verify_result(s), SSL_session_reused(s));
    SSL_set_shutdown(s, SSL_SENT_SHUTDOWN);
    SSL_set_verify_result(s, X509_V_ERR_CERT_HAS_EXPIRED);
    printf("  shutdown %d, verify result %ld\n", SSL_get_shutdown(s), SSL_get_verify_result(s));
    check(SSL_clear(s) == 1 && SSL_get_shutdown(s) == 0, "SSL_clear resets the shutdown");
    printf("  verify result after clear %ld\n", SSL_get_verify_result(s));
    check(SSL_up_ref(s) == 1, "SSL_up_ref");
    SSL_free(s);
    check(SSL_get_SSL_CTX(s) == ctx, "SSL_get_SSL_CTX");
    SSL_free(s);
    check(SSL_CTX_up_ref(ctx) == 1, "SSL_CTX_up_ref");
    SSL_CTX_free(ctx);
    SSL_CTX_free(ctx);
}

/* ctrl */

static void controls(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *s;
    unsigned char keys[80];
    long n;

    printf("# ctrl\n");
    printf("  read ahead %ld -> %ld, cert list %ld -> %ld -> %ld\n", SSL_CTX_ctrl(ctx, SSL_CTRL_SET_READ_AHEAD, 1, NULL),
           SSL_CTX_ctrl(ctx, SSL_CTRL_GET_READ_AHEAD, 0, NULL), SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_CERT_LIST, 100, NULL),
           SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_CERT_LIST, -1, NULL), SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MAX_CERT_LIST, 0, NULL));
    printf("  cache size %ld -> %ld, negative %ld; mode %ld -> %ld\n", SSL_CTX_sess_set_cache_size(ctx, 10),
           SSL_CTX_sess_get_cache_size(ctx), SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_SIZE, -1, NULL),
           SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH), SSL_CTX_get_session_cache_mode(ctx));
    printf("  stats %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld\n", SSL_CTX_sess_number(ctx),
           SSL_CTX_sess_connect(ctx), SSL_CTX_sess_connect_good(ctx), SSL_CTX_sess_connect_renegotiate(ctx),
           SSL_CTX_sess_accept(ctx), SSL_CTX_sess_accept_good(ctx), SSL_CTX_sess_accept_renegotiate(ctx),
           SSL_CTX_sess_hits(ctx), SSL_CTX_sess_cb_hits(ctx), SSL_CTX_sess_misses(ctx), SSL_CTX_sess_timeouts(ctx),
           SSL_CTX_sess_cache_full(ctx));
    printf("  fragment: 511 %ld, 512 %ld, 16385 %ld, split 0 %ld, split 513 %ld, split 400 %ld\n",
           SSL_CTX_set_max_send_fragment(ctx, 511), SSL_CTX_set_max_send_fragment(ctx, 512),
           SSL_CTX_set_max_send_fragment(ctx, 16385), SSL_CTX_set_split_send_fragment(ctx, 0),
           SSL_CTX_set_split_send_fragment(ctx, 513), SSL_CTX_set_split_send_fragment(ctx, 400));
    printf("  pipelines: 0 %ld, 1 %ld, 32 %ld, 33 %ld\n", SSL_CTX_set_max_pipelines(ctx, 0),
           SSL_CTX_set_max_pipelines(ctx, 1), SSL_CTX_set_max_pipelines(ctx, 32), SSL_CTX_set_max_pipelines(ctx, 33));
    printf("  cert flags %ld -> %ld\n", SSL_CTX_ctrl(ctx, SSL_CTRL_CERT_FLAGS, 0x30000, NULL),
           SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_CERT_FLAGS, 0x10000, NULL));
    printf("  dh auto %ld, status type %ld -> %ld\n", SSL_CTX_set_dh_auto(ctx, 1),
           SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp), SSL_CTX_get_tlsext_status_type(ctx));
    printf("  status arg %ld, servername arg %ld\n", SSL_CTX_set_tlsext_status_arg(ctx, keys),
           SSL_CTX_set_tlsext_servername_arg(ctx, keys));
    {
        void *arg = NULL;
        int (*cb)(SSL *, void *) = NULL;

        printf("  get status arg %ld (%d), get status cb %ld (%d)\n", SSL_CTX_get_tlsext_status_arg(ctx, &arg),
               arg == keys, SSL_CTX_get_tlsext_status_cb(ctx, &cb), cb == NULL);
    }
    n = SSL_CTX_get_tlsext_ticket_keys(ctx, NULL, 0);
    printf("  ticket keys length %ld, wrong length %ld\n", n, SSL_CTX_get_tlsext_ticket_keys(ctx, keys, 79));
    errors();
    memset(keys, 7, sizeof(keys));
    check(SSL_CTX_set_tlsext_ticket_keys(ctx, keys, 80) == 1, "set ticket keys");
    memset(keys, 0, sizeof(keys));
    check(SSL_CTX_get_tlsext_ticket_keys(ctx, keys, 80) == 1 && keys[0] == 7 && keys[79] == 7, "get them back");
    printf("  msg callback arg %ld, unknown %ld, callback unknown %ld\n",
           SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MSG_CALLBACK_ARG, 0, keys), SSL_CTX_ctrl(ctx, 9999, 1, NULL),
           SSL_CTX_callback_ctrl(ctx, 9999, NULL));
    printf("  NULL context: %ld\n", SSL_CTX_ctrl(NULL, SSL_CTRL_GET_READ_AHEAD, 0, NULL));
    check(SSL_CTX_set_tlsext_servername_callback(ctx, NULL) == 1, "the servername callback");
    check(SSL_CTX_set_tlsext_status_cb(ctx, NULL) == 1, "the status callback");
    check(SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB, NULL) == 1, "not-resumable callback");
    printf("  srp username %d, password %d, strength %d, arg %d\n", SSL_CTX_set_srp_username(ctx, "user"),
           SSL_CTX_set_srp_password(ctx, "pass"), SSL_CTX_set_srp_strength(ctx, 1024), SSL_CTX_set_srp_cb_arg(ctx, keys));
    check(SSL_CTX_set_srp_username(ctx, "") == 0, "an empty srp username");
    errors();

    s = SSL_new(ctx);
    printf("  ssl: read ahead %ld, mode %ld, cert list %ld -> %ld, renegotiations %ld %ld %ld, flags %ld, ri %ld\n",
           SSL_ctrl(s, SSL_CTRL_GET_READ_AHEAD, 0, NULL), SSL_ctrl(s, SSL_CTRL_MODE, 0, NULL),
           SSL_ctrl(s, SSL_CTRL_SET_MAX_CERT_LIST, 50, NULL), SSL_get_max_cert_list(s), SSL_num_renegotiations(s),
           SSL_clear_num_renegotiations(s), SSL_total_renegotiations(s), SSL_ctrl(s, SSL_CTRL_GET_FLAGS, 0, NULL),
           SSL_get_secure_renegotiation_support(s));
    printf("  ssl fragment 512 %ld, split 600 %ld, pipelines 2 %ld, raw cipher list len %ld\n",
           SSL_set_max_send_fragment(s, 512), SSL_set_split_send_fragment(s, 600), SSL_set_max_pipelines(s, 2),
           SSL_ctrl(s, SSL_CTRL_GET_RAW_CIPHERLIST, 0, NULL));
    printf("  ssl status type %ld -> %ld, dh auto %ld, debug arg %ld, unknown %ld, callback unknown %ld\n",
           SSL_set_tlsext_status_type(s, TLSEXT_STATUSTYPE_ocsp), SSL_get_tlsext_status_type(s),
           SSL_set_dh_auto(s, 1), SSL_set_tlsext_debug_arg(s, keys), SSL_ctrl(s, 9999, 0, NULL),
           SSL_callback_ctrl(s, 9999, NULL));
    {
        unsigned char *resp = NULL;

        printf("  ocsp response %ld (%d)\n", SSL_get_tlsext_status_ocsp_resp(s, &resp), resp == NULL);
        resp = OPENSSL_malloc(3);
        memcpy(resp, "abc", 3);
        check(SSL_set_tlsext_status_ocsp_resp(s, resp, 3) == 1, "set the OCSP response");
        resp = NULL;
        printf("  ocsp response %ld (%.3s)\n", SSL_get_tlsext_status_ocsp_resp(s, &resp), resp);
    }
    check(SSL_callback_ctrl(s, SSL_CTRL_SET_TLSEXT_DEBUG_CB, NULL) == 1, "the debug callback");
    check(SSL_set_retry_verify(s) == 1 && SSL_want(s) == SSL_RETRY_VERIFY, "retry verify");
    SSL_free(s);
    SSL_CTX_free(ctx);
}

/* Versions */

static void versions(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method()), *dtls = SSL_CTX_new(DTLS_method()), *fixed = SSL_CTX_new(TLSv1_2_method());
    SSL *s;
    static const int vals[] = { 0, SSL3_VERSION, TLS1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION, 0x305, 0x200,
                                DTLS1_VERSION, DTLS1_2_VERSION, DTLS1_BAD_VER, 0xfefc };
    size_t i;

    printf("# version bounds\n");
    for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        int a = SSL_CTX_set_min_proto_version(ctx, vals[i]);
        long ga = SSL_CTX_get_min_proto_version(ctx);
        int b = SSL_CTX_set_max_proto_version(ctx, vals[i]);
        long gb = SSL_CTX_get_max_proto_version(ctx);
        int c = SSL_CTX_set_min_proto_version(dtls, vals[i]);
        long gc = SSL_CTX_get_min_proto_version(dtls);
        int d = SSL_CTX_set_max_proto_version(fixed, vals[i]);
        long gd = SSL_CTX_get_max_proto_version(fixed);

        printf("  %#x: tls min %d (%#lx) max %d (%#lx), dtls min %d (%#lx), fixed max %d (%#lx)\n", (unsigned)vals[i],
               a, (unsigned long)ga, b, (unsigned long)gb, c, (unsigned long)gc, d, (unsigned long)gd);
        SSL_CTX_set_min_proto_version(ctx, 0);
        SSL_CTX_set_max_proto_version(ctx, 0);
        SSL_CTX_set_min_proto_version(dtls, 0);
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    printf("  mixed: %d\n", (int)SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION));
    s = SSL_new(ctx);
    printf("  ssl inherits %#lx-%#lx\n", (unsigned long)SSL_get_min_proto_version(s),
           (unsigned long)SSL_get_max_proto_version(s));
    printf("  ssl set %d %d -> %#lx-%#lx\n", (int)SSL_set_min_proto_version(s, TLS1_VERSION),
           (int)SSL_set_max_proto_version(s, TLS1_3_VERSION), (unsigned long)SSL_get_min_proto_version(s),
           (unsigned long)SSL_get_max_proto_version(s));
    SSL_free(s);
    s = SSL_new(fixed);
    printf("  fixed method's connection %#lx-%#lx\n", (unsigned long)SSL_get_min_proto_version(s),
           (unsigned long)SSL_get_max_proto_version(s));
    SSL_free(s);
    SSL_CTX_free(ctx);
    SSL_CTX_free(dtls);
    SSL_CTX_free(fixed);
}

/* Certificates and keys */

static void keys_and_certs(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL *s;
    X509 *rsa = cert(RSA_PEM), *ec = cert(EC_PEM), *ca = cert(CA_PEM), *ed = cert(ED_PEM), *weak = cert(WEAK_PEM);
    EVP_PKEY *rsak = key(RSA_KEY_PEM), *eck = key(EC_KEY_PEM), *edk = key(ED_KEY_PEM), *weakk = key(WEAK_KEY_PEM);
    STACK_OF(X509) *chain = NULL;
    unsigned char *der = NULL;
    int n;

    printf("# certificates and keys\n");
    SSL_CTX_set_default_passwd_cb(ctx, passwd_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, "keys");
    check(SSL_CTX_check_private_key(ctx) == 0, "nothing to check");
    errors();
    check(SSL_CTX_use_certificate_file(ctx, path_of("rsa.pem"), SSL_FILETYPE_PEM) == 1, "SSL_CTX_use_certificate_file");
    name_of("certificate", SSL_CTX_get0_certificate(ctx));
    check(SSL_CTX_check_private_key(ctx) == 0, "no key yet");
    errors();
    check(SSL_CTX_use_PrivateKey_file(ctx, path_of("ec.key"), SSL_FILETYPE_PEM) == 1, "an EC key goes in its own slot");
    printf("  current is EC: %d, cert %d\n", EVP_PKEY_is_a(SSL_CTX_get0_privatekey(ctx), "EC"),
           SSL_CTX_get0_certificate(ctx) != NULL);
    check(SSL_CTX_check_private_key(ctx) == 0, "the EC slot has no certificate");
    errors();
    check(SSL_CTX_use_PrivateKey_file(ctx, path_of("rsa_enc.key"), SSL_FILETYPE_PEM) == 1, "an encrypted key");
    check(SSL_CTX_check_private_key(ctx) == 1, "SSL_CTX_check_private_key");
    check(SSL_CTX_use_PrivateKey(ctx, weakk) == 0, "a mismatched key");
    errors();
    check(SSL_CTX_use_certificate_file(ctx, path_of("rsa.pem"), 99) == 0, "a bad file type");
    errors();
    check(SSL_CTX_use_certificate_file(ctx, path_of("missing.pem"), SSL_FILETYPE_PEM) == 0, "a missing file");
    errors();
    check(SSL_CTX_use_certificate_file(ctx, path_of("rsa.key"), SSL_FILETYPE_PEM) == 0, "not a certificate");
    errors();
    check(SSL_CTX_use_PrivateKey_file(ctx, path_of("rsa.pem"), SSL_FILETYPE_PEM) == 0, "not a key");
    errors();
    n = i2d_X509(ec, &der);
    check(SSL_CTX_use_certificate_ASN1(ctx, n, der) == 1, "SSL_CTX_use_certificate_ASN1");
    OPENSSL_free(der);
    der = NULL;
    check(SSL_CTX_check_private_key(ctx) == 1, "the EC slot is complete");
    n = i2d_PrivateKey(rsak, &der);
    check(SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx, der, n) == 1, "SSL_CTX_use_PrivateKey_ASN1");
    check(SSL_CTX_use_RSAPrivateKey_ASN1(ctx, der, n) == 1, "SSL_CTX_use_RSAPrivateKey_ASN1");
    check(SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx, der, 5) == 0, "a truncated key");
    errors();
    OPENSSL_free(der);
    der = NULL;
    check(SSL_CTX_use_RSAPrivateKey(ctx, (RSA *)EVP_PKEY_get0_RSA(rsak)) == 1, "SSL_CTX_use_RSAPrivateKey");
    check(SSL_CTX_use_RSAPrivateKey_file(ctx, path_of("rsa.key"), SSL_FILETYPE_PEM) == 1, "SSL_CTX_use_RSAPrivateKey_file");
    check(SSL_CTX_use_RSAPrivateKey_file(ctx, path_of("ec.key"), SSL_FILETYPE_PEM) == 0, "an EC key isn't RSA");
    errors();

    printf("# the security level\n");
    check(SSL_CTX_use_certificate(ctx, weak) == 0, "a 1024-bit key at level 2");
    errors();
    SSL_CTX_set_security_level(ctx, 0);
    check(SSL_CTX_use_certificate(ctx, weak) == 1, "accepted at level 0");
    printf("  the RSA slot's key was dropped: %d\n", SSL_CTX_check_private_key(ctx));
    errors();
    SSL_CTX_set_security_level(ctx, 2);
    SSL_CTX_set_security_callback(ctx, security_cb);
    SSL_CTX_set0_security_ex_data(ctx, "ex");
    check(SSL_CTX_get_security_callback(ctx) == security_cb && strcmp(SSL_CTX_get0_security_ex_data(ctx), "ex") == 0,
          "the security callback");
    check(SSL_CTX_use_certificate(ctx, rsa) == 1, "a 2048-bit key through the callback");
    check(SSL_CTX_use_certificate(ctx, weak) == 0, "refused by the callback");
    errors();
    check(SSL_CTX_add1_chain_cert(ctx, weak) == 0, "a weak CA");
    errors();
    check(SSL_CTX_set0_tmp_dh_pkey(ctx, EVP_PKEY_dup(rsak)) == 1, "SSL_CTX_set0_tmp_dh_pkey");
    printf("  callback calls %d\n", security_seen);
    s = SSL_new(ctx);
    check(SSL_get_security_callback(s) == security_cb && strcmp(SSL_get0_security_ex_data(s), "ex") == 0,
          "a connection inherits the security callback");
    SSL_set0_security_ex_data(s, "ssl ex");
    SSL_set_security_callback(s, NULL);
    check(SSL_get_security_callback(s) == NULL && strcmp(SSL_get0_security_ex_data(s), "ssl ex") == 0,
          "SSL_set_security_callback and SSL_set0_security_ex_data");
    check(SSL_CTX_get_security_callback(ctx) == security_cb && strcmp(SSL_CTX_get0_security_ex_data(ctx), "ex") == 0,
          "the context keeps its own");
    SSL_free(s);
    SSL_CTX_free(ctx);

    ctx = SSL_CTX_new(TLS_server_method());
    printf("# chains\n");
    check(SSL_CTX_use_certificate_chain_file(ctx, path_of("chain.pem")) == 1, "SSL_CTX_use_certificate_chain_file");
    check(SSL_CTX_get0_chain_certs(ctx, &chain) == 1 && sk_X509_num(chain) == 2, "two chain certificates");
    name_of("chain 0", sk_X509_value(chain, 0));
    check(SSL_CTX_use_PrivateKey(ctx, rsak) == 1, "its key");
    check(SSL_CTX_add1_chain_cert(ctx, ca) == 1 && SSL_CTX_add0_chain_cert(ctx, X509_dup(ca)) == 1, "add chain certificates");
    SSL_CTX_get0_chain_certs(ctx, &chain);
    printf("  chain now %d\n", sk_X509_num(chain));
    {
        STACK_OF(X509) *sk = sk_X509_new_null(), *extra = NULL;

        sk_X509_push(sk, X509_dup(ca));
        check(SSL_CTX_set1_chain(ctx, sk) == 1, "SSL_CTX_set1_chain");
        SSL_CTX_get0_chain_certs(ctx, &chain);
        printf("  chain now %d\n", sk_X509_num(chain));
        check(SSL_CTX_set0_chain(ctx, sk) == 1, "SSL_CTX_set0_chain");
        check(SSL_CTX_clear_chain_certs(ctx) == 1, "SSL_CTX_clear_chain_certs");
        SSL_CTX_get0_chain_certs(ctx, &chain);
        printf("  chain cleared %d\n", chain == NULL);
        check(SSL_CTX_add_extra_chain_cert(ctx, X509_dup(ca)) == 1, "an extra chain certificate");
        SSL_CTX_get_extra_chain_certs(ctx, &extra);
        printf("  extra %d\n", sk_X509_num(extra));
        SSL_CTX_get_extra_chain_certs_only(ctx, &extra);
        printf("  extra only %d\n", sk_X509_num(extra));
        check(SSL_CTX_clear_extra_chain_certs(ctx) == 1, "cleared");
        SSL_CTX_get_extra_chain_certs(ctx, &extra);
        printf("  extra falls back to the chain: %d\n", extra == NULL);
    }
    check(SSL_CTX_use_cert_and_key(ctx, ed, edk, NULL, 1) == 1, "SSL_CTX_use_cert_and_key");
    check(SSL_CTX_use_cert_and_key(ctx, rsa, eck, NULL, 1) == 0, "a mismatched pair");
    errors();
    check(SSL_CTX_use_cert_and_key(ctx, rsa, rsak, NULL, 0) == 0, "no override");
    errors();
    {
        STACK_OF(X509) *sk = sk_X509_new_null();

        sk_X509_push(sk, ca);
        check(SSL_CTX_use_cert_and_key(ctx, rsa, rsak, sk, 1) == 1, "with a chain");
        sk_X509_free(sk);
    }
    printf("  current %s\n", EVP_PKEY_get0_type_name(SSL_CTX_get0_privatekey(ctx)));
    check(SSL_CTX_select_current_cert(ctx, ed) == 1, "SSL_CTX_select_current_cert");
    printf("  current %s\n", EVP_PKEY_get0_type_name(SSL_CTX_get0_privatekey(ctx)));
    check(SSL_CTX_select_current_cert(ctx, ec) == 0, "no such certificate");
    check(SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST) == 1, "the first");
    printf("  first %s\n", EVP_PKEY_get0_type_name(SSL_CTX_get0_privatekey(ctx)));
    check(SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_NEXT) == 1, "the next");
    printf("  next %s\n", EVP_PKEY_get0_type_name(SSL_CTX_get0_privatekey(ctx)));
    check(SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_NEXT) == 0, "no more");
    check(SSL_CTX_set_current_cert(ctx, 99) == 0, "a bad operation");

    printf("# per connection\n");
    s = SSL_new(ctx);
    check(SSL_get_certificate(s) == SSL_CTX_get0_certificate(ctx) && SSL_get_privatekey(s) == SSL_CTX_get0_privatekey(ctx),
          "the connection shares the certificates");
    check(SSL_use_certificate(s, ec) == 1 && SSL_use_PrivateKey(s, eck) == 1 && SSL_check_private_key(s) == 1,
          "SSL_use_certificate and SSL_use_PrivateKey");
    printf("  ssl %s, ctx %s\n", EVP_PKEY_get0_type_name(SSL_get_privatekey(s)),
           EVP_PKEY_get0_type_name(SSL_CTX_get0_privatekey(ctx)));
    check(SSL_use_certificate_file(s, path_of("rsa.der"), SSL_FILETYPE_ASN1) == 1, "SSL_use_certificate_file (DER)");
    check(SSL_use_PrivateKey_file(s, path_of("rsa.key.der"), SSL_FILETYPE_ASN1) == 1, "SSL_use_PrivateKey_file (DER)");
    check(SSL_use_RSAPrivateKey_file(s, path_of("rsa.key"), SSL_FILETYPE_PEM) == 1, "SSL_use_RSAPrivateKey_file");
    n = i2d_X509(rsa, &der);
    check(SSL_use_certificate_ASN1(s, der, n) == 1, "SSL_use_certificate_ASN1");
    OPENSSL_free(der);
    der = NULL;
    n = i2d_PrivateKey(rsak, &der);
    check(SSL_use_PrivateKey_ASN1(EVP_PKEY_RSA, s, der, n) == 1 && SSL_use_RSAPrivateKey_ASN1(s, der, n) == 1,
          "SSL_use_PrivateKey_ASN1");
    OPENSSL_free(der);
    der = NULL;
    check(SSL_use_RSAPrivateKey(s, (RSA *)EVP_PKEY_get0_RSA(rsak)) == 1, "SSL_use_RSAPrivateKey");
    check(SSL_use_certificate_chain_file(s, path_of("chain.pem")) == 1, "SSL_use_certificate_chain_file");
    check(SSL_get0_chain_certs(s, &chain) == 1 && sk_X509_num(chain) == 2, "the connection's chain");
    check(SSL_add1_chain_cert(s, ca) == 1 && SSL_add0_chain_cert(s, X509_dup(ca)) == 1, "SSL_add1_chain_cert");
    check(SSL_clear_chain_certs(s) == 1, "SSL_clear_chain_certs");
    check(SSL_use_cert_and_key(s, ed, edk, NULL, 1) == 1, "SSL_use_cert_and_key");
    check(SSL_select_current_cert(s, ed) == 1 && SSL_set_current_cert(s, SSL_CERT_SET_FIRST) == 1, "select");
    printf("  server cert set %ld\n", SSL_ctrl(s, SSL_CTRL_SET_CURRENT_CERT, SSL_CERT_SET_SERVER, NULL));
    check(SSL_use_certificate(s, NULL) == 0, "NULL certificate");
    errors();
    check(SSL_use_PrivateKey(s, NULL) == 0, "NULL key");
    errors();
    check(SSL_set0_tmp_dh_pkey(s, EVP_PKEY_dup(rsak)) == 1, "SSL_set0_tmp_dh_pkey");
    SSL_certs_clear(s);
    check(SSL_get_certificate(s) == NULL && SSL_get_privatekey(s) == NULL, "SSL_certs_clear");
    check(SSL_check_private_key(s) == 0, "nothing after the clear");
    errors();
    check(SSL_CTX_get0_certificate(ctx) != NULL, "the context keeps its own");
    SSL_set_default_passwd_cb(s, passwd_cb);
    SSL_set_default_passwd_cb_userdata(s, "connection");
    check(SSL_use_PrivateKey_file(s, path_of("rsa_enc.key"), SSL_FILETYPE_PEM) == 1, "the connection's passwd callback");
    SSL_free(s);
    SSL_CTX_free(ctx);
    X509_free(rsa);
    X509_free(ec);
    X509_free(ca);
    X509_free(ed);
    X509_free(weak);
    EVP_PKEY_free(rsak);
    EVP_PKEY_free(eck);
    EVP_PKEY_free(edk);
    EVP_PKEY_free(weakk);
}

/* Client CA lists */

static void ca_lists(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *s;
    X509 *ca = cert(CA_PEM), *rsa = cert(RSA_PEM);
    STACK_OF(X509_NAME) *sk, *dup;

    printf("# CA lists\n");
    check(SSL_CTX_add_client_CA(ctx, ca) == 1 && SSL_CTX_add_client_CA(ctx, rsa) == 1, "SSL_CTX_add_client_CA");
    check(SSL_CTX_add_client_CA(ctx, NULL) == 0, "NULL certificate");
    names("client CAs", SSL_CTX_get_client_CA_list(ctx));
    check(SSL_CTX_add1_to_CA_list(ctx, ca) == 1, "SSL_CTX_add1_to_CA_list");
    names("CAs", SSL_CTX_get0_CA_list(ctx));
    sk = SSL_load_client_CA_file(path_of("chain.pem"));
    names("from the file", sk);
    dup = SSL_dup_CA_list(sk);
    names("copy", dup);
    sk_X509_NAME_pop_free(dup, X509_NAME_free);
    check(SSL_add_file_cert_subjects_to_stack(sk, path_of("dup.pem")) == 1, "SSL_add_file_cert_subjects_to_stack");
    names("added", sk);
    check(SSL_add_dir_cert_subjects_to_stack(sk, path_of("cadir")) == 1, "SSL_add_dir_cert_subjects_to_stack");
    names("from the directory", sk);
    check(SSL_add_store_cert_subjects_to_stack(sk, path_of("cadir")) == 1, "SSL_add_store_cert_subjects_to_stack");
    names("from the store", sk);
    SSL_CTX_set_client_CA_list(ctx, sk);
    names("set", SSL_CTX_get_client_CA_list(ctx));
    check(SSL_load_client_CA_file(path_of("missing.pem")) == NULL, "a missing file");
    errors();
    check(SSL_load_client_CA_file(path_of("rsa.key")) == NULL, "no certificates");
    errors();
    sk = SSL_load_client_CA_file_ex(path_of("chain.pem"), NULL, "provider=default");
    names("SSL_load_client_CA_file_ex", sk);
    SSL_CTX_set0_CA_list(ctx, sk);
    names("set0", SSL_CTX_get0_CA_list(ctx));

    s = SSL_new(ctx);
    names("client's client CAs (the peer's)", SSL_get_client_CA_list(s));
    SSL_set_accept_state(s);
    names("server's client CAs", SSL_get_client_CA_list(s));
    names("server's CAs", SSL_get0_CA_list(s));
    names("peer's CAs", SSL_get0_peer_CA_list(s));
    check(SSL_add_client_CA(s, rsa) == 1, "SSL_add_client_CA");
    names("its own", SSL_get_client_CA_list(s));
    check(SSL_add1_to_CA_list(s, rsa) == 1, "SSL_add1_to_CA_list");
    names("its own CAs", SSL_get0_CA_list(s));
    SSL_set_client_CA_list(s, NULL);
    names("set to none", SSL_get_client_CA_list(s));
    SSL_set0_CA_list(s, NULL);
    names("CAs to none", SSL_get0_CA_list(s));
    SSL_free(s);
    SSL_CTX_free(ctx);
    X509_free(ca);
    X509_free(rsa);
}

/* Verification locations and parameters */

static void verification(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    X509_STORE *st = X509_STORE_new();
    SSL *s;

    printf("# verification\n");
    check(SSL_CTX_load_verify_locations(ctx, NULL, NULL) == 0, "nothing to load");
    check(SSL_CTX_load_verify_locations(ctx, path_of("ca.pem"), NULL) == 1, "SSL_CTX_load_verify_locations");
    check(SSL_CTX_load_verify_file(ctx, path_of("missing.pem")) == 0, "a missing file");
    errors();
    check(SSL_CTX_load_verify_dir(ctx, path_of("cadir")) == 1, "SSL_CTX_load_verify_dir");
    check(SSL_CTX_load_verify_store(ctx, path_of("ca.pem")) == 1, "SSL_CTX_load_verify_store");
    check(SSL_CTX_load_verify_locations(ctx, path_of("ca.pem"), path_of("cadir")) == 1, "both");
    printf("  objects %d\n", sk_X509_OBJECT_num(X509_STORE_get0_objects(SSL_CTX_get_cert_store(ctx))));
    check(SSL_CTX_set_default_verify_paths(ctx) == 1 && SSL_CTX_set_default_verify_dir(ctx) == 1
              && SSL_CTX_set_default_verify_file(ctx) == 1 && SSL_CTX_set_default_verify_store(ctx) == 1,
          "the default paths");
    errors();
    SSL_CTX_set_cert_store(ctx, st);
    check(SSL_CTX_get_cert_store(ctx) == st, "SSL_CTX_set_cert_store");
    X509_STORE_up_ref(st);
    SSL_CTX_set1_cert_store(ctx, st);
    check(SSL_CTX_get_cert_store(ctx) == st, "SSL_CTX_set1_cert_store");
    X509_STORE_free(st);
    {
        X509_VERIFY_PARAM *p = X509_VERIFY_PARAM_new();
        X509_STORE *got = NULL;

        X509_VERIFY_PARAM_set_depth(p, 3);
        check(SSL_CTX_set1_param(ctx, p) == 1 && SSL_CTX_get_verify_depth(ctx) == 3, "SSL_CTX_set1_param");
        check(SSL_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER) == 1 && SSL_CTX_set_trust(ctx, X509_TRUST_SSL_SERVER) == 1,
              "purpose and trust");
        check(SSL_CTX_set_purpose(ctx, 999) == 0, "a bad purpose");
        errors();
        check(SSL_CTX_set1_verify_cert_store(ctx, st) == 1 && SSL_CTX_get0_verify_cert_store(ctx, &got) == 1 && got == st,
              "the verify store");
        check(SSL_CTX_set0_chain_cert_store(ctx, NULL) == 1 && SSL_CTX_get0_chain_cert_store(ctx, &got) == 1 && got == NULL,
              "the chain store");
        s = SSL_new(ctx);
        printf("  ssl depth %d, purpose %d\n", SSL_get_verify_depth(s), X509_VERIFY_PARAM_get_purpose(SSL_get0_param(s)));
        check(SSL_set1_param(s, p) == 1 && SSL_set_purpose(s, X509_PURPOSE_SSL_CLIENT) == 1
                  && SSL_set_trust(s, X509_TRUST_SSL_CLIENT) == 1,
              "SSL_set1_param");
        got = NULL;
        check(SSL_get0_verify_cert_store(s, &got) == 1 && got == st, "the connection's verify store");
        check(SSL_set1_chain_cert_store(s, st) == 1 && SSL_get0_chain_cert_store(s, &got) == 1 && got == st,
              "the connection's chain store");
        check(SSL_set0_verify_cert_store(s, NULL) == 1, "cleared");
        printf("  ssl purpose %d, ctx purpose %d\n", X509_VERIFY_PARAM_get_purpose(SSL_get0_param(s)),
               X509_VERIFY_PARAM_get_purpose(SSL_CTX_get0_param(ctx)));
        SSL_free(s);
        X509_VERIFY_PARAM_free(p);
    }
    printf("  store index %d\n", SSL_get_ex_data_X509_STORE_CTX_idx() >= 0);
    SSL_CTX_free(ctx);
}

/* Application data */

static void application_data(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *s = SSL_new(ctx);
    int ci = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL), si = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    printf("# application data\n");
    check(SSL_CTX_set_ex_data(ctx, ci, "context") == 1 && strcmp(SSL_CTX_get_ex_data(ctx, ci), "context") == 0,
          "SSL_CTX_set_ex_data");
    check(SSL_set_ex_data(s, si, "connection") == 1 && strcmp(SSL_get_ex_data(s, si), "connection") == 0,
          "SSL_set_ex_data");
    check(SSL_get_ex_data(s, si + 50) == NULL, "an unset index");
    SSL_set_app_data(s, "app");
    check(strcmp(SSL_get_app_data(s), "app") == 0, "SSL_get_app_data");
    SSL_free(s);
    SSL_CTX_free(ctx);
}

/* BIOs and file descriptors */

static long free_cb(BIO *b, int oper, const char *argp, size_t len, int argi, long argl, int ret, size_t *processed)
{
    (void)argp;
    (void)len;
    (void)argi;
    (void)argl;
    (void)processed;
    if (oper == BIO_CB_FREE)
        printf("    freed %s\n", (const char *)BIO_get_callback_arg(b));
    return ret;
}

static BIO *named(const char *name)
{
    BIO *b = BIO_new(BIO_s_mem());

    BIO_set_callback_ex(b, free_cb);
    BIO_set_callback_arg(b, (char *)name);
    return b;
}

static void bios(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *s = SSL_new(ctx);
    BIO *a = named("a"), *b = named("b"), *c = named("c"), *d = named("d");
    int fds[2];

    printf("# BIOs\n");
    check(SSL_get_rbio(s) == NULL && SSL_get_wbio(s) == NULL && SSL_get_fd(s) == -1, "none at first");
    printf("  one BIO for both\n");
    SSL_set_bio(s, a, a);
    check(SSL_get_rbio(s) == a && SSL_get_wbio(s) == a, "set");
    printf("  the same again (nothing)\n");
    SSL_set_bio(s, a, a);
    printf("  only the write side\n");
    SSL_set_bio(s, a, b);
    printf("  only the read side, which was shared\n");
    SSL_set_bio(s, c, b);
    printf("  only the read side, separate\n");
    SSL_set_bio(s, d, b);
    printf("  set0_rbio\n");
    SSL_set0_rbio(s, NULL);
    printf("  set0_wbio\n");
    SSL_set0_wbio(s, NULL);
    check(SSL_get_rbio(s) == NULL && SSL_get_wbio(s) == NULL, "both gone");
    if (pipe(fds) == 0) {
        check(SSL_set_fd(s, fds[0]) == 1 && SSL_get_fd(s) == fds[0] && SSL_get_rfd(s) == fds[0] && SSL_get_wfd(s) == fds[0],
              "SSL_set_fd");
        check(SSL_get_rbio(s) == SSL_get_wbio(s), "one socket BIO");
        check(SSL_set_wfd(s, fds[1]) == 1 && SSL_get_wfd(s) == fds[1] && SSL_get_rfd(s) == fds[0], "SSL_set_wfd");
        check(SSL_set_rfd(s, fds[1]) == 1 && SSL_get_rbio(s) == SSL_get_wbio(s), "SSL_set_rfd reuses the write BIO");
        check(SSL_set_rfd(s, fds[0]) == 1 && SSL_get_rfd(s) == fds[0], "a new read BIO");
        close(fds[0]);
        close(fds[1]);
    }
    printf("  freeing the connection\n");
    SSL_set_bio(s, named("e"), named("f"));
    SSL_free(s);
    SSL_CTX_free(ctx);
}

/* Contexts switched and hosts */

static void switching(void)
{
    SSL_CTX *one = SSL_CTX_new(TLS_method()), *two = SSL_CTX_new(TLS_method());
    SSL *s;
    X509 *rsa = cert(RSA_PEM), *ec = cert(EC_PEM);
    EVP_PKEY *rsak = key(RSA_KEY_PEM), *eck = key(EC_KEY_PEM);
    char *ip;

    printf("# switching contexts\n");
    SSL_CTX_use_certificate(one, rsa);
    SSL_CTX_use_PrivateKey(one, rsak);
    SSL_CTX_use_certificate(two, ec);
    SSL_CTX_use_PrivateKey(two, eck);
    SSL_CTX_set_session_id_context(one, (const unsigned char *)"one", 3);
    SSL_CTX_set_session_id_context(two, (const unsigned char *)"two", 3);
    SSL_CTX_set_options(two, SSL_OP_NO_TICKET);
    s = SSL_new(one);
    check(SSL_set_SSL_CTX(s, two) == two && SSL_get_SSL_CTX(s) == two, "SSL_set_SSL_CTX");
    printf("  key %s, options kept %d\n", EVP_PKEY_get0_type_name(SSL_get_privatekey(s)),
           (SSL_get_options(s) & SSL_OP_NO_TICKET) == 0);
    check(SSL_set_SSL_CTX(s, two) == two, "the same context");
    check(SSL_set_SSL_CTX(s, NULL) == one, "back to the session context");
    printf("  key %s\n", EVP_PKEY_get0_type_name(SSL_get_privatekey(s)));
    SSL_free(s);

    printf("# hosts and server names\n");
    s = SSL_new(one);
    check(SSL_set1_host(s, "www.example.com") == 1 && SSL_add1_host(s, "example.org") == 1, "SSL_set1_host");
    printf("  host %s\n", X509_VERIFY_PARAM_get0_host(SSL_get0_param(s), 0));
    check(SSL_set1_host(s, "192.0.2.1") == 1, "an IP address");
    ip = X509_VERIFY_PARAM_get1_ip_asc(SSL_get0_param(s));
    printf("  ip %s, host %s\n", ip, X509_VERIFY_PARAM_get0_host(SSL_get0_param(s), 0) == NULL ? "(none)" : "set");
    OPENSSL_free(ip);
    check(SSL_add1_host(s, "192.0.2.2") == 0, "a second IP address");
    errors();
    check(SSL_set1_host(s, NULL) == 1, "cleared");
    SSL_set_hostflags(s, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    printf("  hostflags %u, peername %s\n", X509_VERIFY_PARAM_get_hostflags(SSL_get0_param(s)),
           SSL_get0_peername(s) == NULL ? "(none)" : SSL_get0_peername(s));
    printf("  server name %s, type %d\n", SSL_get_servername(s, TLSEXT_NAMETYPE_host_name) == NULL ? "(none)" : "set",
           SSL_get_servername_type(s));
    check(SSL_set_tlsext_host_name(s, "sni.example") == 1, "SSL_set_tlsext_host_name");
    printf("  server name %s, type %d, other type %s\n", SSL_get_servername(s, TLSEXT_NAMETYPE_host_name),
           SSL_get_servername_type(s), SSL_get_servername(s, 1) == NULL ? "(none)" : "set");
    check(SSL_set_tlsext_host_name(s, "") == 0, "an empty name");
    errors();
    {
        char longname[300];

        memset(longname, 'a', sizeof(longname) - 1);
        longname[sizeof(longname) - 1] = '\0';
        check(SSL_set_tlsext_host_name(s, longname) == 0, "a name too long");
        errors();
    }
    check(SSL_ctrl(s, SSL_CTRL_SET_TLSEXT_HOSTNAME, 1, "x") == 0, "a bad name type");
    errors();
    check(SSL_set_tlsext_host_name(s, NULL) == 1 && SSL_get_servername(s, TLSEXT_NAMETYPE_host_name) == NULL,
          "cleared");
    SSL_set_tlsext_host_name(s, "server.example");
    SSL_set_accept_state(s);
    printf("  as a server: %s\n", SSL_get_servername(s, TLSEXT_NAMETYPE_host_name) == NULL ? "(none)" : "set");
    SSL_free(s);
    SSL_CTX_free(one);
    SSL_CTX_free(two);
    X509_free(rsa);
    X509_free(ec);
    EVP_PKEY_free(rsak);
    EVP_PKEY_free(eck);
}

/* Callbacks stored and other setters */

static int i_cb(void) { return 1; }

static void callbacks(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *s = SSL_new(ctx);
    static const unsigned char alpn[] = { 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    static const unsigned char badalpn[] = { 2, 'h', '2', 0 };

    printf("# callbacks and other settings\n");
    (void)i_cb;
    SSL_CTX_set_msg_callback(ctx, NULL);
    SSL_set_msg_callback(s, NULL);
    SSL_CTX_set_cert_verify_callback(ctx, NULL, NULL);
    SSL_CTX_set_cert_cb(ctx, NULL, NULL);
    SSL_set_cert_cb(s, NULL, NULL);
    SSL_CTX_set_client_cert_cb(ctx, NULL);
    check(SSL_CTX_get_client_cert_cb(ctx) == NULL, "SSL_CTX_get_client_cert_cb");
    SSL_CTX_set_psk_client_callback(ctx, NULL);
    SSL_CTX_set_psk_server_callback(ctx, NULL);
    SSL_CTX_set_psk_find_session_callback(ctx, NULL);
    SSL_CTX_set_psk_use_session_callback(ctx, NULL);
    SSL_set_psk_client_callback(s, NULL);
    SSL_set_psk_server_callback(s, NULL);
    SSL_set_psk_find_session_callback(s, NULL);
    SSL_set_psk_use_session_callback(s, NULL);
    check(SSL_CTX_use_psk_identity_hint(ctx, "hint") == 1 && SSL_use_psk_identity_hint(s, "hint") == 1,
          "the PSK identity hint");
    {
        char longhint[300];

        memset(longhint, 'h', sizeof(longhint) - 1);
        longhint[sizeof(longhint) - 1] = '\0';
        check(SSL_CTX_use_psk_identity_hint(ctx, longhint) == 0, "a hint too long");
        errors();
    }
    SSL_CTX_set_client_hello_cb(ctx, NULL, NULL);
    SSL_CTX_set_alpn_select_cb(ctx, NULL, NULL);
    SSL_CTX_set_next_proto_select_cb(ctx, NULL, NULL);
    SSL_CTX_set_next_protos_advertised_cb(ctx, NULL, NULL);
    printf("  alpn: ok %d, bad %d, short %d, clear %d; ssl ok %d, bad %d, clear %d\n",
           SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn)), SSL_CTX_set_alpn_protos(ctx, badalpn, sizeof(badalpn)),
           SSL_CTX_set_alpn_protos(ctx, alpn, 1), SSL_CTX_set_alpn_protos(ctx, NULL, 0),
           SSL_set_alpn_protos(s, alpn, sizeof(alpn)), SSL_set_alpn_protos(s, alpn, 5), SSL_set_alpn_protos(s, NULL, 0));
    printf("  max fragment length: ctx 9 %d, 2 %d; ssl 0 %d, 4 %d\n", SSL_CTX_set_tlsext_max_fragment_length(ctx, 9),
           SSL_CTX_set_tlsext_max_fragment_length(ctx, TLSEXT_max_fragment_length_1024),
           SSL_set_tlsext_max_fragment_length(s, TLSEXT_max_fragment_length_DISABLED),
           SSL_set_tlsext_max_fragment_length(s, TLSEXT_max_fragment_length_4096));
    errors();
    check(SSL_CTX_set_session_ticket_cb(ctx, NULL, NULL, NULL) == 1, "SSL_CTX_set_session_ticket_cb");
    check(SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, NULL) == 1, "SSL_CTX_set_tlsext_ticket_key_evp_cb");
    SSL_CTX_sess_set_new_cb(ctx, NULL);
    SSL_CTX_sess_set_remove_cb(ctx, NULL);
    SSL_CTX_sess_set_get_cb(ctx, NULL);
    check(SSL_CTX_sess_get_new_cb(ctx) == NULL && SSL_CTX_sess_get_remove_cb(ctx) == NULL
              && SSL_CTX_sess_get_get_cb(ctx) == NULL,
          "the session callbacks");
    SSL_CTX_set_cookie_generate_cb(ctx, NULL);
    SSL_CTX_set_cookie_verify_cb(ctx, NULL);
    SSL_CTX_set_stateless_cookie_generate_cb(ctx, NULL);
    SSL_CTX_set_stateless_cookie_verify_cb(ctx, NULL);
    check(SSL_CTX_set_generate_session_id(ctx, NULL) == 1 && SSL_set_generate_session_id(s, NULL) == 1,
          "the session ID generators");
    SSL_CTX_set_not_resumable_session_callback(ctx, NULL);
    SSL_set_not_resumable_session_callback(s, NULL);
    SSL_CTX_set_allow_early_data_cb(ctx, NULL, NULL);
    SSL_set_allow_early_data_cb(s, NULL, NULL);
    SSL_CTX_set_record_padding_callback(ctx, NULL);
    SSL_CTX_set_record_padding_callback_arg(ctx, "pad");
    check(strcmp(SSL_CTX_get_record_padding_callback_arg(ctx), "pad") == 0, "the padding argument");
    check(SSL_set_record_padding_callback(s, NULL) == 1, "SSL_set_record_padding_callback");
    SSL_set_record_padding_callback_arg(s, "ssl pad");
    check(strcmp(SSL_get_record_padding_callback_arg(s), "ssl pad") == 0, "the connection's padding argument");
    printf("  block padding: ctx 1 %d, 16 %d, 16385 %d, ex %d; ssl 0 %d, 99999 %d, ex %d\n",
           SSL_CTX_set_block_padding(ctx, 1), SSL_CTX_set_block_padding(ctx, 16),
           SSL_CTX_set_block_padding(ctx, 16385), SSL_CTX_set_block_padding_ex(ctx, 32, 1),
           SSL_set_block_padding(s, 0), SSL_set_block_padding(s, 99999), SSL_set_block_padding_ex(s, 8, 64));
    SSL_CTX_set_default_read_buffer_len(ctx, 4096);
    SSL_set_default_read_buffer_len(s, 8192);
    SSL_CTX_set_tmp_dh_callback(ctx, NULL);
    SSL_set_tmp_dh_callback(s, NULL);
    check(SSL_CTX_set_async_callback(ctx, NULL) == 1 && SSL_CTX_set_async_callback_arg(ctx, NULL) == 1
              && SSL_set_async_callback(s, NULL) == 1 && SSL_set_async_callback_arg(s, NULL) == 1,
          "the async callbacks");
    SSL_CTX_set_post_handshake_auth(ctx, 1);
    SSL_set_post_handshake_auth(s, 1);
    SSL_CTX_set_srp_username_callback(ctx, NULL);
    SSL_CTX_set_srp_verify_param_callback(ctx, NULL);
    SSL_CTX_set_srp_client_pwd_callback(ctx, NULL);
    SSL_set_debug(s, 1);
    printf("  client random %zu, server random %zu, finished %zu, peer finished %zu\n",
           SSL_get_client_random(s, NULL, 0), SSL_get_server_random(s, NULL, 0), SSL_get_finished(s, NULL, 0),
           SSL_get_peer_finished(s, NULL, 0));
    {
        unsigned char r[40];

        memset(r, 0xaa, sizeof(r));
        printf("  client random copied %zu (%02x)\n", SSL_get_client_random(s, r, sizeof(r)), r[0]);
    }
    SSL_free(s);
    SSL_CTX_free(ctx);
}

/* NULL arguments */

static void nulls(void)
{
    printf("# NULL arguments\n");
    SSL_free(NULL);
    SSL_CTX_free(NULL);
    check(SSL_get_rbio(NULL) == NULL && SSL_get_wbio(NULL) == NULL, "the BIOs");
    check(SSL_get_options(NULL) == 0 && SSL_set_options(NULL, 1) == 0 && SSL_clear_options(NULL, 1) == 0,
          "the options");
    check(SSL_get_verify_result(NULL) == 0 && SSL_get_verify_mode(NULL) == 0 && SSL_get_verify_depth(NULL) == 0,
          "verification");
    check(SSL_is_server(NULL) == 0, "the role");
    check(SSL_check_private_key(NULL) == 0, "SSL_check_private_key");
    errors();
    check(SSL_CTX_check_private_key(NULL) == 0, "SSL_CTX_check_private_key");
    errors();
    check(SSL_get_certificate(NULL) == NULL && SSL_get_privatekey(NULL) == NULL, "the certificate");
    check(SSL_get0_param(NULL) == NULL && SSL_get0_peername(NULL) == NULL, "the parameters");
    check(SSL_get_servername(NULL, 0) == NULL && SSL_want(NULL) == SSL_NOTHING, "the server name");
    check(SSL_get_ex_data_X509_STORE_CTX_idx() == SSL_get_ex_data_X509_STORE_CTX_idx(), "the index is fixed");
}

int main(void)
{
    char cmd[160];

    setvbuf(stdout, NULL, _IONBF, 0);
    snprintf(dir, sizeof(dir), "/tmp/rustyssl-ssl-ctx-%ld", (long)getpid());
    if (mkdir(dir, 0700) != 0)
        return 1;
    write_file("rsa.pem", RSA_PEM, strlen(RSA_PEM));
    write_file("rsa.key", RSA_KEY_PEM, strlen(RSA_KEY_PEM));
    write_file("rsa_enc.key", RSA_ENC_KEY_PEM, strlen(RSA_ENC_KEY_PEM));
    write_file("ec.key", EC_KEY_PEM, strlen(EC_KEY_PEM));
    write_file("ca.pem", CA_PEM, strlen(CA_PEM));
    {
        char buf[8192];

        snprintf(buf, sizeof(buf), "%s%s%s", RSA_PEM, CA_PEM, EC_PEM);
        write_file("chain.pem", buf, strlen(buf));
        snprintf(buf, sizeof(buf), "%s%s", CA_PEM, RESP_PEM);
        write_file("dup.pem", buf, strlen(buf));
    }
    {
        X509 *x = cert(RSA_PEM);
        EVP_PKEY *k = key(RSA_KEY_PEM);
        unsigned char *der = NULL;
        int n = i2d_X509(x, &der);

        write_file("rsa.der", der, (size_t)n);
        OPENSSL_free(der);
        der = NULL;
        n = i2d_PrivateKey(k, &der);
        write_file("rsa.key.der", der, (size_t)n);
        OPENSSL_free(der);
        X509_free(x);
        EVP_PKEY_free(k);
    }
    mkdir(path_of("cadir"), 0700);
    write_file("cadir/a.pem", CA_PEM, strlen(CA_PEM));
    write_file("cadir/b.pem", WEAK_PEM, strlen(WEAK_PEM));
    mkdir(path_of("cadir/sub"), 0700);

    methods();
    contexts();
    controls();
    versions();
    keys_and_certs();
    ca_lists();
    verification();
    application_data();
    bios();
    switching();
    callbacks();
    nulls();

    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0)
        printf("# not cleaned\n");
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
