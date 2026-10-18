/*
 * Conformance test for SSL_CONF (SSL_CONF_cmd(3), SSL_CONF_CTX_new(3),
 * SSL_CONF_CTX_set_flags(3), SSL_CONF_CTX_set1_prefix(3), SSL_CONF_CTX_set_ssl_ctx(3),
 * SSL_CONF_cmd_argv(3)) and the configuration's ssl_conf module (SSL_CTX_config(3),
 * config(5)): file commands on a context, every kind of value, the flags that allow them, the
 * prefix, the command line's switches and argument lists, commands on a connection and on no
 * object, the private key found in a certificate's file, named sets from a configuration file,
 * and the system default applied by SSL_CTX_new, with and without configuration diagnostics.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
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

/* The test's scratch directory, which differs per run. */
static char dir[64];

/* The errors recorded, with their data (the scratch directory printed as DIR). */
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


static const char DH_PEM[] =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz\n"
    "+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a\n"
    "87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7\n"
    "YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi\n"
    "7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD\n"
    "ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==\n"
    "-----END DH PARAMETERS-----\n";

static const char *path_of(const char *name)
{
    static char buf[4][256];
    static int next = 0;
    char *p = buf[next++ % 4];

    snprintf(p, 256, "%s/%s", dir, name);
    return p;
}

static void write_file(const char *name, const char *data)
{
    FILE *f = fopen(path_of(name), "wb");

    if (f == NULL || fwrite(data, 1, strlen(data), f) != strlen(data)) {
        printf("Bail out! write %s\n", name);
        exit(1);
    }
    fclose(f);
}

/* The context's settings that the commands change. */
static void settings(const char *label, SSL_CTX *ctx)
{
    printf("  %s: options %llx verify %d min %lx max %lx tickets %zu\n", label,
           (unsigned long long)SSL_CTX_get_options(ctx), SSL_CTX_get_verify_mode(ctx),
           (long)SSL_CTX_get_min_proto_version(ctx), (long)SSL_CTX_get_max_proto_version(ctx),
           SSL_CTX_get_num_tickets(ctx));
}

static void ssl_settings(const char *label, SSL *s)
{
    printf("  %s: options %llx verify %d min %lx max %lx tickets %zu\n", label,
           (unsigned long long)SSL_get_options(s), SSL_get_verify_mode(s),
           (long)SSL_get_min_proto_version(s), (long)SSL_get_max_proto_version(s),
           SSL_get_num_tickets(s));
}

/* One command, its result, and the errors it recorded. */
static int cmd(SSL_CONF_CTX *cctx, const char *name, const char *value)
{
    int r = SSL_CONF_cmd(cctx, name, value);
    const char *at = value == NULL ? NULL : strstr(value, dir);

    if (at != NULL)
        printf("  %s = %.*sDIR%s -> %d\n", name, (int)(at - value), value, at + strlen(dir), r);
    else
        printf("  %s = %s -> %d\n", name == NULL ? "(null)" : name, value == NULL ? "(null)" : value, r);
    errors();
    return r;
}

static void file_commands(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
    unsigned int flags;
    const STACK_OF(X509_NAME) *names;
    char buf[300];

    printf("# file commands on a context\n");
    check(cctx != NULL, "SSL_CONF_CTX_new");
    flags = SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_CLIENT | SSL_CONF_FLAG_SERVER);
    printf("  flags %x\n", flags);
    flags = SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE | SSL_CONF_FLAG_SHOW_ERRORS);
    printf("  flags %x\n", flags);
    printf("  cleared %x\n", SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_CLIENT));
    printf("  set %x\n", SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT));
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    settings("start", ctx);

    check(cmd(cctx, "Options", "-SessionTicket,ServerPreference,-Compression") == 2, "Options");
    settings("options", ctx);
    check(cmd(cctx, "options", "+Bugs,-EncryptThenMac,PrioritizeChaCha,StrictCertCheck") == 2, "names in any case");
    settings("options", ctx);
    check(cmd(cctx, "Options", "Nonsense") == 0, "an unknown option");
    check(cmd(cctx, "Options", "SessionTicket,,Bugs") == 0, "an empty option");
    check(cmd(cctx, "Protocol", "-ALL,TLSv1.2,TLSv1.3") == 2, "Protocol");
    settings("protocol", ctx);
    check(cmd(cctx, "Protocol", "ALL") == 2, "Protocol ALL");
    check(cmd(cctx, "MinProtocol", "TLSv1.2") == 2, "MinProtocol");
    check(cmd(cctx, "MaxProtocol", "TLSv1.3") == 2, "MaxProtocol");
    check(cmd(cctx, "MaxProtocol", "tlsv1.3") == 0, "versions are case-sensitive");
    check(cmd(cctx, "MinProtocol", "DTLSv1.2") == 2, "a DTLS version on TLS");
    check(cmd(cctx, "MinProtocol", "None") == 2, "None");
    settings("versions", ctx);
    check(cmd(cctx, "VerifyMode", "Peer,Request") == 2, "VerifyMode");
    settings("verify", ctx);
    check(cmd(cctx, "VerifyMode", "Require,Once,RequestPostHandshake") == 2, "VerifyMode server settings");
    settings("verify", ctx);
    check(cmd(cctx, "VerifyMode", "-Peer") == 2, "a verify mode cleared");
    settings("verify", ctx);

    check(cmd(cctx, "CipherString", "HIGH:!aNULL") == 2, "CipherString");
    check(cmd(cctx, "CipherString", "NOTHING") == 0, "a cipher string matching nothing");
    check(cmd(cctx, "Ciphersuites", "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256") == 2, "Ciphersuites");
    check(cmd(cctx, "Groups", "X25519:P-256") == 2, "Groups");
    check(cmd(cctx, "Groups", "X25519:nonsense") == 0, "an unknown group");
    check(cmd(cctx, "Curves", "?nonsense:secp384r1") == 2, "Curves");
    check(cmd(cctx, "ECDHParameters", "automatic") == 2, "ECDHParameters automatic");
    check(cmd(cctx, "ECDHParameters", "+Automatic") == 2, "ECDHParameters +automatic");
    check(cmd(cctx, "ECDHParameters", "auto") == 0, "auto is for the command line");
    check(cmd(cctx, "ECDHParameters", "P-384") == 2, "ECDHParameters P-384");
    check(cmd(cctx, "ECDHParameters", "P-256:P-384") == 0, "one group only");
    check(cmd(cctx, "SignatureAlgorithms", "RSA+SHA256:ecdsa_secp256r1_sha256:ed25519") == 2, "SignatureAlgorithms");
    check(cmd(cctx, "SignatureAlgorithms", "nonsense") == 0, "an unknown signature algorithm");
    check(cmd(cctx, "ClientSignatureAlgorithms", "RSA-PSS+SHA384") == 2, "ClientSignatureAlgorithms");
    check(cmd(cctx, "RecordPadding", "512") == 2, "RecordPadding");
    check(cmd(cctx, "RecordPadding", "512,256") == 2, "RecordPadding with handshake padding");
    check(cmd(cctx, "RecordPadding", "512,") == 0, "a missing second number");
    check(cmd(cctx, "RecordPadding", "x") == 0, "not a number");
    check(cmd(cctx, "RecordPadding", "0x10") == 2, "hexadecimal");
    check(cmd(cctx, "NumTickets", "5") == 2, "NumTickets");
    check(cmd(cctx, "NumTickets", "-1") == 0, "a negative count");
    check(cmd(cctx, "NumTickets", " 3junk") == 2, "atoi's parse");
    settings("tickets", ctx);

    check(cmd(cctx, "Certificate", path_of("rsa.pem")) == 2, "Certificate");
    check(cmd(cctx, "PrivateKey", path_of("rsa.key")) == 2, "PrivateKey");
    check(SSL_CTX_check_private_key(ctx) == 1, "the key matches");
    check(cmd(cctx, "Certificate", path_of("missing.pem")) == 0, "a missing certificate");
    check(cmd(cctx, "ChainCAFile", path_of("ca.pem")) == 2, "ChainCAFile");
    check(cmd(cctx, "VerifyCAFile", path_of("ca.pem")) == 2, "VerifyCAFile");
    check(cmd(cctx, "VerifyCAPath", path_of("cadir")) == 2, "VerifyCAPath");
    check(cmd(cctx, "ChainCAPath", path_of("cadir")) == 2, "ChainCAPath");
    check(cmd(cctx, "VerifyCAFile", path_of("missing.pem")) == 0, "a missing CA file");
    check(cmd(cctx, "RequestCAFile", path_of("ca.pem")) == 2, "RequestCAFile");
    check(cmd(cctx, "ClientCAFile", path_of("chain.pem")) == 2, "ClientCAFile");
    check(cmd(cctx, "RequestCAPath", path_of("cadir")) == 2, "RequestCAPath");
    check(cmd(cctx, "DHParameters", path_of("dh.pem")) == 2, "DHParameters");
    check(cmd(cctx, "DHParameters", path_of("rsa.pem")) == 0, "not DH parameters");
    check(cmd(cctx, "DHParameters", path_of("missing.pem")) == 0, "a missing DH file");

    check(cmd(cctx, "Nonsense", "1") == -2, "an unknown command");
    check(cmd(cctx, "Groups", NULL) == -3, "a missing value");
    check(cmd(cctx, NULL, "1") == 0, "a NULL command");
    check(cmd(cctx, "no_ticket", NULL) == -2, "a switch isn't a file command");
    check(cmd(cctx, "groups", "X448") == 2, "file names are case-insensitive");

    check(SSL_CONF_CTX_finish(cctx) == 1, "SSL_CONF_CTX_finish");
    names = SSL_CTX_get0_CA_list(ctx);
    printf("  CA names: %d\n", names == NULL ? -1 : sk_X509_NAME_num(names));
    if (names != NULL && sk_X509_NAME_num(names) > 0)
        printf("  first: %s\n", X509_NAME_oneline(sk_X509_NAME_value(names, 0), buf, sizeof(buf)));

    printf("# value types\n");
    printf("  Groups %d Certificate %d VerifyCAPath %d VerifyCAStore %d Nonsense %d no_ticket %d\n",
           SSL_CONF_cmd_value_type(cctx, "Groups"), SSL_CONF_cmd_value_type(cctx, "Certificate"),
           SSL_CONF_cmd_value_type(cctx, "VerifyCAPath"), SSL_CONF_cmd_value_type(cctx, "VerifyCAStore"),
           SSL_CONF_cmd_value_type(cctx, "Nonsense"), SSL_CONF_cmd_value_type(cctx, "no_ticket"));

    printf("# without the certificate flag\n");
    SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);
    check(cmd(cctx, "Certificate", path_of("rsa.pem")) == -2, "Certificate needs the flag");
    check(cmd(cctx, "PrivateKey", path_of("rsa.key")) == -2, "so does PrivateKey");
    printf("  Certificate %d\n", SSL_CONF_cmd_value_type(cctx, "Certificate"));

    printf("# client only\n");
    SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_SERVER);
    check(cmd(cctx, "NumTickets", "1") == -2, "NumTickets is for servers");
    check(cmd(cctx, "ECDHParameters", "P-256") == -2, "so is ECDHParameters");
    check(cmd(cctx, "Options", "ServerPreference") == 0, "a server option on a client");
    check(cmd(cctx, "VerifyMode", "Require") == 0, "a server verify mode on a client");

    printf("# a prefix\n");
    check(SSL_CONF_CTX_set1_prefix(cctx, "TLS_") == 1, "SSL_CONF_CTX_set1_prefix");
    check(cmd(cctx, "tls_MinProtocol", "TLSv1.3") == 2, "the prefix in any case");
    check(cmd(cctx, "MinProtocol", "TLSv1.3") == -2, "no prefix");
    check(cmd(cctx, "TLS_", "TLSv1.3") == -2, "the prefix alone");
    printf("  tls_Groups %d\n", SSL_CONF_cmd_value_type(cctx, "tls_Groups"));
    check(SSL_CONF_CTX_set1_prefix(cctx, NULL) == 1, "no prefix again");
    settings("end", ctx);

    SSL_CONF_CTX_free(cctx);
    SSL_CTX_free(ctx);
}

static void argv_commands(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
    char *args[] = { "-no_ticket", "-groups", "X25519", "-serverpref", "-sigalgs", "nonsense",
                     "-cipher", "HIGH", "-unknown", "-num_tickets", "-min_protocol", NULL };
    char **argv = args;
    int argc = 11, r, i;

    printf("# command line\n");
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CMDLINE | SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_SHOW_ERRORS);
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    for (i = 0; i < 8 && argc > 0; i++) {
        const char *at = argv[0];

        r = SSL_CONF_cmd_argv(cctx, &argc, &argv);
        printf("  %s -> %d (argc %d)\n", at, r, argc);
        errors();
        if (r <= 0) {
            argv++;
            argc--;
        }
    }
    settings("argv", ctx);
    argc = 0;
    check(SSL_CONF_cmd_argv(cctx, &argc, &argv) == 0, "no arguments");
    check(cmd(cctx, "-named_curve", "auto") == 2, "auto on the command line");
    check(cmd(cctx, "-named_curve", "automatic") == 0, "automatic isn't");
    check(cmd(cctx, "-strict", NULL) == 1, "a certificate flag switch");
    check(cmd(cctx, "-no_tls1_3", NULL) == 1, "a protocol switch");
    check(cmd(cctx, "-comp", NULL) == 1, "an inverted switch");
    check(cmd(cctx, "-legacy_server_connect", NULL) == -2, "a client switch on a server");
    check(cmd(cctx, "Groups", "X25519") == -2, "file names on the command line");
    check(cmd(cctx, "-", NULL) == -2, "a dash alone");
    check(cmd(cctx, "no_ticket", NULL) == -2, "no dash");
    printf("  -groups %d -no_ticket %d -Groups %d\n", SSL_CONF_cmd_value_type(cctx, "-groups"),
           SSL_CONF_cmd_value_type(cctx, "-no_ticket"), SSL_CONF_cmd_value_type(cctx, "-Groups"));
    settings("switches", ctx);
    {
        char *one[] = { "-no_ems", NULL };
        char **v = one;

        check(SSL_CONF_cmd_argv(cctx, NULL, &v) == 1 && v == one + 1, "no count");
    }
    SSL_CONF_CTX_free(cctx);
    SSL_CTX_free(ctx);
}

static void on_connection(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *s = SSL_new(ctx);
    SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();

    printf("# commands on a connection\n");
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_CLIENT | SSL_CONF_FLAG_CERTIFICATE
                                     | SSL_CONF_FLAG_REQUIRE_PRIVATE | SSL_CONF_FLAG_SHOW_ERRORS);
    SSL_CONF_CTX_set_ssl(cctx, s);
    check(cmd(cctx, "Options", "-SessionTicket") == 2, "Options");
    check(cmd(cctx, "MaxProtocol", "TLSv1.2") == 2, "MaxProtocol");
    check(cmd(cctx, "Groups", "P-256") == 2, "Groups");
    check(cmd(cctx, "SignatureAlgorithms", "ECDSA+SHA256") == 2, "SignatureAlgorithms");
    check(cmd(cctx, "CipherString", "ECDHE") == 2, "CipherString");
    check(cmd(cctx, "VerifyMode", "Peer") == 2, "VerifyMode");
    check(cmd(cctx, "Certificate", path_of("rsa_and_key.pem")) == 2, "a certificate with its key");
    check(SSL_check_private_key(s) == 0, "no key yet");
    errors();
    check(SSL_CONF_CTX_finish(cctx) == 1, "finish loads the key");
    check(SSL_check_private_key(s) == 1, "the key from the certificate's file");
    ssl_settings("ssl", s);
    settings("its context", ctx);

    printf("# no object\n");
    SSL_CONF_CTX_set_ssl(cctx, NULL);
    check(cmd(cctx, "SignatureAlgorithms", "RSA+SHA256") == 2, "a syntax check");
    check(cmd(cctx, "SignatureAlgorithms", "RSA+SHA1234") == 0, "a bad one");
    check(cmd(cctx, "Groups", "X25519") == 0, "groups aren't checked without a context");
    check(cmd(cctx, "Options", "SessionTicket") == 2, "options");
    check(cmd(cctx, "MinProtocol", "TLSv1.2") == 0, "no object for the version");
    check(cmd(cctx, "CipherString", "NOTHING") == 2, "nothing to set");
    check(cmd(cctx, "NumTickets", "1") == -2, "a server command");
    check(cmd(cctx, "Certificate", path_of("rsa.pem")) == 2, "nothing to load into");
    check(cmd(cctx, "RequestCAFile", path_of("ca.pem")) == 2, "names to drop");
    check(SSL_CONF_CTX_finish(cctx) == 1, "finish");
    SSL_CONF_CTX_free(cctx);
    SSL_free(s);
    SSL_CTX_free(ctx);
}

static void configured(void)
{
    char conf[2048];
    SSL_CTX *ctx;
    SSL *s;

    printf("# SSL_CTX_config\n");
    snprintf(conf, sizeof(conf),
             "openssl_conf = init\n"
             "[init]\n"
             "ssl_conf = ssl_sect\n"
             "[ssl_sect]\n"
             "system_default = sys_sect\n"
             "server = server_sect\n"
             "bad = bad_sect\n"
             "[sys_sect]\n"
             "MinProtocol = TLSv1.2\n"
             "Groups = nonsense\n"
             "Options = -SessionTicket\n"
             "[server_sect]\n"
             "Options = ServerPreference\n"
             "MaxProtocol = TLSv1.2\n"
             "Certificate = %s\n"
             "PrivateKey = %s\n"
             "[bad_sect]\n"
             "Groups = X25519\n"
             "Nonsense = 1\n"
             "MaxProtocol = TLSv1.3\n",
             path_of("rsa.pem"), path_of("rsa.key"));
    write_file("ssl.cnf", conf);
    check(CONF_modules_load_file(path_of("ssl.cnf"), NULL, 0) == 1, "the configuration");
    errors();
    ctx = SSL_CTX_new(TLS_server_method());
    check(ctx != NULL, "a context with a failing system default");
    errors();
    settings("system default", ctx);
    check(SSL_CTX_config(ctx, "server") == 1, "SSL_CTX_config");
    errors();
    settings("server", ctx);
    check(SSL_CTX_check_private_key(ctx) == 1, "its key");
    check(SSL_CTX_config(ctx, "bad") == 0, "a failing set");
    errors();
    settings("bad", ctx);
    check(SSL_CTX_config(ctx, "missing") == 0, "a missing set");
    errors();
    check(SSL_CTX_config(ctx, NULL) == 0, "no name");
    errors();
    s = SSL_new(ctx);
    check(SSL_config(s, "server") == 1, "SSL_config");
    errors();
    ssl_settings("ssl", s);
    SSL_free(s);
    SSL_CTX_free(ctx);
    CONF_modules_unload(0);

    snprintf(conf, sizeof(conf),
             "config_diagnostics = 1\n"
             "openssl_conf = init\n"
             "[init]\n"
             "ssl_conf = ssl_sect\n"
             "[ssl_sect]\n"
             "system_default = sys_sect\n"
             "[sys_sect]\n"
             "Groups = nonsense\n");
    write_file("diag.cnf", conf);
    check(CONF_modules_load_file(path_of("diag.cnf"), NULL, 0) == 1, "a configuration with diagnostics");
    errors();
    ctx = SSL_CTX_new(TLS_server_method());
    check(ctx == NULL, "the system default's failure counts");
    errors();
    SSL_CTX_free(ctx);
    CONF_modules_unload(0);
    ctx = SSL_CTX_new(TLS_server_method());
    check(ctx != NULL, "no system default after unloading");
    errors();
    SSL_CTX_free(ctx);
}

int main(void)
{
    char cmdline[300], buf[16384];

    setvbuf(stdout, NULL, _IONBF, 0);
    snprintf(dir, sizeof(dir), "/tmp/rustyssl-ssl-conf-%ld", (long)getpid());
    if (mkdir(dir, 0700) != 0)
        return 1;
    write_file("rsa.pem", RSA_PEM);
    write_file("rsa.key", RSA_KEY_PEM);
    write_file("ca.pem", CA_PEM);
    write_file("dh.pem", DH_PEM);
    snprintf(buf, sizeof(buf), "%s%s", CA_PEM, RSA_PEM);
    write_file("chain.pem", buf);
    snprintf(buf, sizeof(buf), "%s%s", RSA_PEM, RSA_KEY_PEM);
    write_file("rsa_and_key.pem", buf);
    mkdir(path_of("cadir"), 0700);
    write_file("cadir/a.pem", CA_PEM);

    file_commands();
    argv_commands();
    on_connection();
    configured();

    snprintf(cmdline, sizeof(cmdline), "rm -rf %s", dir);
    if (system(cmdline) != 0)
        printf("# not cleaned\n");
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
