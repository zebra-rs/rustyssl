/*
 * Conformance test for libssl's strings (SSL_state_string(3), SSL_state_string_long(3),
 * SSL_rstate_string(3), SSL_rstate_string_long(3), SSL_get_version(3),
 * SSL_CIPHER_get_name(3), SSL_CIPHER_standard_name(3), OPENSSL_cipher_name(3),
 * SSL_CIPHER_get_version(3), ERR_reason_error_string(3)): the handshake state at every
 * info-callback point of many handshakes (TLS 1.0 to 1.3, client authentication, every key
 * exchange, OCSP stapling, HelloRetryRequest, resumption by ticket and by session ID,
 * renegotiation, KeyUpdate, post-handshake authentication, a failure), the record layer's read
 * state between a record's header and its body, the version and suite names after each
 * handshake and for every suite, and the reason string of every SSL_R_* code.
 *
 * The client and server talk through memory BIOs. Only deterministic output is printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
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

/* Prints and clears the error queue. */
static void errors(const char *who)
{
    unsigned long e;
    char buf[256];

    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
        printf("  %s: %s\n", who, buf);
    }
}

static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBmzCCAUCgAwIBAgIUHfTNPsE5lGD3nT8fR1Nd24C0BsgwCgYIKoZIzj0EAwIw\n"
    "KjEQMA4GA1UECgwHRXhhbXBsZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDAgFw0y\n"
    "NjEwMTgwOTMyNDZaGA8yMTI2MDkyNDA5MzI0NlowKjEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"
    "A0IABLfBhwdOVIbIOwWlwBUmASMV1CS8SOnPi/viY8J5Ml2EwP5wOJe2mtSxgMlo\n"
    "COh/RepmP8BAKwLO40zMoIv99xOjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P\n"
    "AQH/BAQDAgEGMB0GA1UdDgQWBBQ6zTauzjp1rC8vPBSILXAK3pm9PjAKBggqhkjO\n"
    "PQQDAgNJADBGAiEA8n+eFk52ddsEdBxGgskm6aD0for7v4Ys0o0bN2t9wq8CIQDY\n"
    "V8DuzBptykbkta8E/bbLFVRo0LjIzjF/bGH+iqEMeA==\n"
    "-----END CERTIFICATE-----\n";

static const char SERVER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBxDCCAWqgAwIBAgICA+kwCgYIKoZIzj0EAwIwKjEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDAgFw0yNjEwMTgwOTMyNDZaGA8yMTI2\n"
    "MDkyNDA5MzI0NlowGTEXMBUGA1UEAwwOc2VydmVyLmV4YW1wbGUwWTATBgcqhkjO\n"
    "PQIBBggqhkjOPQMBBwNCAARQwBruuNdz4xCD1gvolSn84T4lhmxXimDiZyo55Kdd\n"
    "rfRyA09qPpfiXyudWm0VDT2tdis7qXDPv2njo4sH3xHko4GOMIGLMAkGA1UdEwQC\n"
    "MAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBkGA1UdEQQS\n"
    "MBCCDnNlcnZlci5leGFtcGxlMB0GA1UdDgQWBBTJhnvwTSY1MKJTWPQEV8hTOvQj\n"
    "CzAfBgNVHSMEGDAWgBQ6zTauzjp1rC8vPBSILXAK3pm9PjAKBggqhkjOPQQDAgNI\n"
    "ADBFAiA9HtDZKkG58jRwUNQ4CbP61ozryZRRkz7W3RF94vEpSQIhAKwrnOIS/FEg\n"
    "N7iBJyOB+Buj5UbPic6SYxuj11J3f/PG\n"
    "-----END CERTIFICATE-----\n";

static const char SERVER_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvhwC7sEHpNUtRIwR\n"
    "1HpSoTfsfnL+ayakODf8YQkvzpKhRANCAARQwBruuNdz4xCD1gvolSn84T4lhmxX\n"
    "imDiZyo55KddrfRyA09qPpfiXyudWm0VDT2tdis7qXDPv2njo4sH3xHk\n"
    "-----END PRIVATE KEY-----\n";

/* An RSA server certificate, for the RSA key exchanges (its chain isn't verified). */
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

static const char *where_name(int where)
{
    if (where & SSL_CB_ALERT)
        return (where & SSL_CB_READ) ? "read alert" : "write alert";
    if ((where & SSL_CB_HANDSHAKE_START) != 0)
        return "handshake start";
    if ((where & SSL_CB_HANDSHAKE_DONE) != 0)
        return "handshake done";
    if ((where & SSL_CB_EXIT) != 0)
        return "exit";
    if ((where & SSL_CB_LOOP) != 0)
        return "loop";
    return "other";
}

/* Every info-callback point, with the state's names and the read state. */
static void info_cb(const SSL *x, int where, int ret)
{
    if (where & SSL_CB_ALERT) {
        printf("    %s %s: %s %s\n", SSL_is_server(x) ? "server" : "client", where_name(where),
               SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
        return;
    }
    printf("    %s %s: %s [%s] %s/%s%s\n", SSL_is_server(x) ? "server" : "client",
           where_name(where), SSL_state_string_long(x), SSL_state_string(x),
           SSL_rstate_string(x), SSL_rstate_string_long(x),
           SSL_in_init((SSL *)x) ? "" : " (not in init)");
}

static int accept_any(int ok, X509_STORE_CTX *ctx)
{
    (void)ok;
    (void)ctx;
    return 1;
}

static int status_cb(SSL *x, void *arg)
{
    unsigned char *resp;

    (void)arg;
    if (!SSL_is_server(x))
        return 1;
    /* Any octets: the client keeps them without parsing. */
    resp = OPENSSL_malloc(3);
    if (resp == NULL)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    memcpy(resp, "\x30\x01\x00", 3);
    SSL_set_tlsext_status_ocsp_resp(x, resp, 3);
    return SSL_TLSEXT_ERR_OK;
}

static int use_pem(SSL_CTX *ctx, const char *crt, const char *k_pem)
{
    X509 *x = cert(crt);
    EVP_PKEY *k = key(k_pem);
    int ok = x != NULL && k != NULL && SSL_CTX_use_certificate(ctx, x) == 1
             && SSL_CTX_use_PrivateKey(ctx, k) == 1;

    X509_free(x);
    EVP_PKEY_free(k);
    return ok;
}

static int use_pki(SSL_CTX *ctx)
{
    return use_pem(ctx, SERVER_PEM, SERVER_KEY_PEM);
}

/* The RSA certificate instead, unverified. */
static void use_rsa(SSL_CTX *c, SSL_CTX *s)
{
    if (!use_pem(s, RSA_PEM, RSA_KEY_PEM)) {
        printf("Bail out! RSA certificate\n");
        exit(1);
    }
    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);
}

/* A pair of contexts for versions [min, max], with the info callback. */
static void contexts(SSL_CTX **c, SSL_CTX **s, int min, int max)
{
    X509 *ca = cert(CA_PEM);

    *c = SSL_CTX_new(TLS_client_method());
    *s = SSL_CTX_new(TLS_server_method());
    if (*c == NULL || *s == NULL || ca == NULL || !use_pki(*s)) {
        printf("Bail out! contexts\n");
        exit(1);
    }
    X509_STORE_add_cert(SSL_CTX_get_cert_store(*c), ca);
    X509_free(ca);
    SSL_CTX_set_verify(*c, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_min_proto_version(*c, min);
    SSL_CTX_set_max_proto_version(*c, max);
    SSL_CTX_set_min_proto_version(*s, min);
    SSL_CTX_set_max_proto_version(*s, max);
    SSL_CTX_set_info_callback(*c, info_cb);
    SSL_CTX_set_info_callback(*s, info_cb);
}

struct link {
    SSL *c, *s;
    BIO *c_in, *c_out, *s_in, *s_out;
};

static BIO *mem(void)
{
    BIO *b = BIO_new(BIO_s_mem());

    BIO_set_mem_eof_return(b, -1);
    return b;
}

static void link_up(struct link *l, SSL_CTX *cctx, SSL_CTX *sctx)
{
    memset(l, 0, sizeof(*l));
    l->c = SSL_new(cctx);
    l->s = SSL_new(sctx);
    l->c_in = mem();
    l->c_out = mem();
    l->s_in = mem();
    l->s_out = mem();
    SSL_set_bio(l->c, l->c_in, l->c_out);
    SSL_set_bio(l->s, l->s_in, l->s_out);
    SSL_set_connect_state(l->c);
    SSL_set_accept_state(l->s);
}

static int relay(struct link *l, int dir)
{
    BIO *from = dir == 0 ? l->c_out : l->s_out, *to = dir == 0 ? l->s_in : l->c_in;
    unsigned char buf[65536];
    int len = BIO_read(from, buf, sizeof(buf));

    if (len <= 0)
        return 0;
    BIO_write(to, buf, len);
    return 1;
}

/* One end's step: the handshake while in it, otherwise a read. -1 when it failed. */
static int step(SSL *x, const char *who)
{
    unsigned char buf[256];
    int r, e;

    if (SSL_in_init(x))
        r = SSL_do_handshake(x);
    else
        r = SSL_read(x, buf, sizeof(buf));
    if (r > 0)
        return 1;
    e = SSL_get_error(x, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
        return 0;
    printf("  %s: stopped, SSL_get_error %d\n", who, e);
    errors(who);
    return -1;
}

/* Steps both ends and relays until nothing moves; 1 when both are out of the handshake. */
static int pump(struct link *l)
{
    int round, idle = 0, cstop = 0, sstop = 0;

    for (round = 0; round < 64 && idle < 2; round++) {
        int moved;

        if (!cstop && step(l->c, "client") < 0)
            cstop = 1;
        moved = relay(l, 0);
        if (!sstop && step(l->s, "server") < 0)
            sstop = 1;
        moved |= relay(l, 1);
        idle = moved ? 0 : idle + 1;
    }
    return !cstop && !sstop && !SSL_in_init(l->c) && !SSL_in_init(l->s);
}

/* The negotiated version and suite, by every name. */
static void names(struct link *l)
{
    const SSL_CIPHER *ci = SSL_get_current_cipher(l->c);
    SSL_SESSION *sess = SSL_get_session(l->c);
    char buf[256];

    if (ci == NULL) {
        printf("  no suite\n");
        return;
    }
    printf("  version %s (client %04x, server %04x, server's client version %04x, session %04x)\n",
           SSL_get_version(l->c), (unsigned)SSL_version(l->c), (unsigned)SSL_version(l->s),
           (unsigned)SSL_client_version(l->s),
           sess != NULL ? (unsigned)SSL_SESSION_get_protocol_version(sess) : 0u);
    /* A resumed TLS 1.2 handshake reports the original's group (the session's). */
    printf("  group %s / %s\n", OBJ_nid2sn(SSL_get_negotiated_group(l->c)),
           OBJ_nid2sn(SSL_get_negotiated_group(l->s)));
    /* The server's view of the ClientHello's suites, after the handshake. */
    printf("  client's suites %d, shared %s\n", sk_SSL_CIPHER_num(SSL_get_client_ciphers(l->s)),
           SSL_get_shared_ciphers(l->s, buf, sizeof(buf)) != NULL ? buf : "(none)");
    printf("  states: %s / %s, read %s / %s\n", SSL_state_string_long(l->c),
           SSL_state_string_long(l->s), SSL_rstate_string_long(l->c), SSL_rstate_string_long(l->s));
    printf("  suite %s (%s, %s) %s\n", SSL_CIPHER_get_name(ci), SSL_CIPHER_standard_name(ci),
           OPENSSL_cipher_name(SSL_CIPHER_standard_name(ci)), SSL_CIPHER_get_version(ci));
    printf("  %s", SSL_CIPHER_description(ci, buf, sizeof(buf)));
}

static void link_down(struct link *l)
{
    SSL_set_shutdown(l->c, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_set_shutdown(l->s, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_free(l->c);
    SSL_free(l->s);
}

/* A handshake between the contexts, resuming `resume` if set; returns the client's session. */
static SSL_SESSION *connect_once(const char *name, SSL_CTX *c, SSL_CTX *s, SSL_SESSION *resume)
{
    struct link l;
    SSL_SESSION *sess;

    link_up(&l, c, s);
    if (resume != NULL)
        SSL_set_session(l.c, resume);
    check(pump(&l), name);
    if (resume != NULL)
        check(SSL_session_reused(l.c), "resumed");
    names(&l);
    sess = SSL_get1_session(l.c);
    link_down(&l);
    return sess;
}

/* A handshake between the contexts (which it frees). */
static void handshake(const char *name, SSL_CTX *c, SSL_CTX *s)
{
    printf("# %s\n", name);
    SSL_SESSION_free(connect_once(name, c, s, NULL));
    SSL_CTX_free(c);
    SSL_CTX_free(s);
}

/* A handshake, then another resuming its session, between the contexts (which it frees). */
static void resumption(const char *name, SSL_CTX *c, SSL_CTX *s)
{
    SSL_SESSION *sess;

    printf("# %s\n", name);
    sess = connect_once("the full handshake", c, s, NULL);
    SSL_SESSION_free(connect_once(name, c, s, sess));
    SSL_SESSION_free(sess);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
}

static void test_handshakes(void)
{
    SSL_CTX *c, *s;

    contexts(&c, &s, TLS1_VERSION, TLS1_VERSION);
    SSL_CTX_set_cipher_list(c, "DEFAULT:@SECLEVEL=0");
    SSL_CTX_set_cipher_list(s, "DEFAULT:@SECLEVEL=0");
    handshake("TLS 1.0", c, s);

    contexts(&c, &s, TLS1_1_VERSION, TLS1_1_VERSION);
    SSL_CTX_set_cipher_list(c, "DEFAULT:@SECLEVEL=0");
    SSL_CTX_set_cipher_list(s, "DEFAULT:@SECLEVEL=0");
    handshake("TLS 1.1", c, s);

    contexts(&c, &s, TLS1_2_VERSION, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(c, "ECDHE-ECDSA-AES128-GCM-SHA256");
    SSL_CTX_set_verify(s, SSL_VERIFY_PEER, accept_any);
    use_pki(c);
    handshake("TLS 1.2, ECDHE, client authentication", c, s);

    contexts(&c, &s, TLS1_2_VERSION, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(c, "DHE-RSA-AES256-GCM-SHA384");
    SSL_CTX_set_dh_auto(s, 1);
    use_rsa(c, s);
    handshake("TLS 1.2, finite-field DHE", c, s);

    contexts(&c, &s, TLS1_2_VERSION, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(c, "AES128-SHA");
    SSL_CTX_set_cipher_list(s, "AES128-SHA");
    use_rsa(c, s);
    handshake("TLS 1.2, RSA key transport, CBC", c, s);

    contexts(&c, &s, TLS1_2_VERSION, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(c, "ECDHE-RSA-CHACHA20-POLY1305");
    use_rsa(c, s);
    SSL_CTX_set_tlsext_status_cb(c, status_cb);
    SSL_CTX_set_tlsext_status_cb(s, status_cb);
    SSL_CTX_set_tlsext_status_type(c, TLSEXT_STATUSTYPE_ocsp);
    handshake("TLS 1.2, OCSP stapling", c, s);

    contexts(&c, &s, TLS1_2_VERSION, TLS1_2_VERSION);
    resumption("TLS 1.2 resumed by ticket", c, s);

    contexts(&c, &s, TLS1_2_VERSION, TLS1_2_VERSION);
    SSL_CTX_set_options(s, SSL_OP_NO_TICKET);
    resumption("TLS 1.2 resumed by session ID", c, s);

    contexts(&c, &s, TLS1_3_VERSION, TLS1_3_VERSION);
    SSL_CTX_set_verify(s, SSL_VERIFY_PEER, accept_any);
    use_pki(c);
    handshake("TLS 1.3, client authentication", c, s);

    contexts(&c, &s, TLS1_3_VERSION, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(c, "TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set1_groups_list(s, "P-256");
    SSL_CTX_set1_groups_list(c, "X25519:P-256");
    handshake("TLS 1.3, HelloRetryRequest", c, s);

    contexts(&c, &s, TLS1_3_VERSION, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(c, "TLS_AES_128_GCM_SHA256");
    SSL_CTX_set_tlsext_status_cb(c, status_cb);
    SSL_CTX_set_tlsext_status_cb(s, status_cb);
    SSL_CTX_set_tlsext_status_type(c, TLSEXT_STATUSTYPE_ocsp);
    resumption("TLS 1.3 resumed, OCSP stapling", c, s);

    contexts(&c, &s, TLS1_3_VERSION, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(c, "TLS_AES_128_GCM_SHA256");
    SSL_CTX_set_ciphersuites(s, "TLS_AES_256_GCM_SHA384");
    {
        struct link l;

        printf("# a failure\n");
        link_up(&l, c, s);
        check(!pump(&l), "no shared cipher");
        printf("  states: %s [%s] / %s [%s]\n", SSL_state_string_long(l.c),
               SSL_state_string(l.c), SSL_state_string_long(l.s), SSL_state_string(l.s));
        SSL_free(l.c);
        SSL_free(l.s);
        SSL_CTX_free(c);
        SSL_CTX_free(s);
    }
}

/* Sends application data both ways (the post-handshake messages travel with it). */
static void exchange(struct link *l)
{
    check(SSL_write(l->c, "ping", 4) == 4, "client writes");
    check(SSL_write(l->s, "pong", 4) == 4, "server writes");
    pump(l);
}

static void test_post_handshake(void)
{
    SSL_CTX *c, *s;
    struct link l;

    /* No application data in flight: OpenSSL takes it during a renegotiation only in SSL_read. */
    contexts(&c, &s, TLS1_2_VERSION, TLS1_2_VERSION);
    SSL_CTX_set_options(s, SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
    SSL_CTX_set_cipher_list(c, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");
    printf("# TLS 1.2 renegotiation\n");
    link_up(&l, c, s);
    check(pump(&l), "the first handshake");
    printf("  suite %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(l.c)));
    /* The renegotiation offers the cipher list set since. */
    check(SSL_set_cipher_list(l.c, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"),
          "a new cipher list");
    check(SSL_renegotiate(l.c) == 1, "SSL_renegotiate");
    check(pump(&l), "the renegotiation");
    check(SSL_num_renegotiations(l.c) == 1, "renegotiated");
    printf("  suite %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(l.c)));
    exchange(&l);
    printf("# a HelloRequest\n");
    check(SSL_renegotiate(l.s) == 1, "the server's SSL_renegotiate");
    check(pump(&l), "the server's renegotiation");
    check(SSL_num_renegotiations(l.s) == 1, "renegotiated again");
    exchange(&l);
    names(&l);
    SSL_free(l.c);
    SSL_free(l.s);
    SSL_CTX_free(c);
    SSL_CTX_free(s);

    contexts(&c, &s, TLS1_3_VERSION, TLS1_3_VERSION);
    use_pki(c);
    SSL_CTX_set_post_handshake_auth(c, 1);
    SSL_CTX_set_verify(s, SSL_VERIFY_PEER | SSL_VERIFY_POST_HANDSHAKE, accept_any);
    printf("# TLS 1.3 KeyUpdate and post-handshake authentication\n");
    link_up(&l, c, s);
    check(pump(&l), "the handshake");
    exchange(&l);
    check(SSL_key_update(l.c, SSL_KEY_UPDATE_REQUESTED) == 1, "SSL_key_update");
    exchange(&l);
    check(SSL_verify_client_post_handshake(l.s) == 1, "SSL_verify_client_post_handshake");
    exchange(&l);
    exchange(&l);
    names(&l);
    SSL_free(l.c);
    SSL_free(l.s);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
}

/* The read state between a record's header and its body. */
static void test_read_state(void)
{
    SSL_CTX *c, *s;
    struct link l;
    unsigned char buf[4096];
    int len;

    printf("# the read state\n");
    contexts(&c, &s, TLS1_2_VERSION, TLS1_3_VERSION);
    SSL_CTX_set_info_callback(c, NULL);
    SSL_CTX_set_info_callback(s, NULL);
    link_up(&l, c, s);
    printf("  new: %s %s / %s %s\n", SSL_rstate_string(l.c), SSL_rstate_string_long(l.c),
           SSL_rstate_string(l.s), SSL_rstate_string_long(l.s));
    check(SSL_do_handshake(l.c) == -1, "the ClientHello");
    len = BIO_read(l.c_out, buf, sizeof(buf));
    check(len > 10, "a ClientHello record");
    BIO_write(l.s_in, buf, 3);
    check(SSL_do_handshake(l.s) == -1, "part of the header");
    printf("  three octets: %s %s\n", SSL_rstate_string(l.s), SSL_rstate_string_long(l.s));
    BIO_write(l.s_in, buf + 3, 4);
    check(SSL_do_handshake(l.s) == -1, "the header and two octets");
    printf("  seven octets: %s %s\n", SSL_rstate_string(l.s), SSL_rstate_string_long(l.s));
    BIO_write(l.s_in, buf + 7, len - 7);
    check(SSL_do_handshake(l.s) == -1, "the whole record");
    printf("  the record: %s %s\n", SSL_rstate_string(l.s), SSL_rstate_string_long(l.s));
    errors("server");
    SSL_free(l.c);
    SSL_free(l.s);

    /* A header that fails its checks. */
    link_up(&l, c, s);
    BIO_write(l.s_in, "\x16\x03\x01\x7f\xff", 5);
    check(SSL_do_handshake(l.s) == -1, "a record too long");
    printf("  after a bad header: %s %s\n", SSL_rstate_string(l.s), SSL_rstate_string_long(l.s));
    errors("server");
    SSL_free(l.c);
    SSL_free(l.s);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    printf("  NULL: %s\n", SSL_rstate_string(NULL) == NULL ? "NULL" : "not NULL");
}

/* Versions before any handshake, per method. */
static void test_versions(void)
{
    const SSL_METHOD *methods[] = {
        TLS_method(), TLS_client_method(), TLS_server_method(), TLSv1_2_method(),
        TLSv1_1_method(), TLSv1_method(),
    };
    const char *labels[] = {
        "TLS_method", "TLS_client_method", "TLS_server_method", "TLSv1_2_method",
        "TLSv1_1_method", "TLSv1_method",
    };
    size_t i;

    printf("# versions before a handshake\n");
    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        SSL_CTX *ctx = SSL_CTX_new(methods[i]);
        SSL *x = SSL_new(ctx);

        printf("  %s: %s %04x, %s [%s]\n", labels[i], SSL_get_version(x), (unsigned)SSL_version(x),
               SSL_state_string_long(x), SSL_state_string(x));
        SSL_free(x);
        SSL_CTX_free(ctx);
    }
}

/* Every suite's names and version. */
static void test_suite_names(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    STACK_OF(SSL_CIPHER) *sk;
    int i;

    printf("# suite names\n");
    SSL_CTX_set_security_level(ctx, 0);
    check(SSL_CTX_set_cipher_list(ctx, "ALL:COMPLEMENTOFALL") == 1, "every suite");
    sk = SSL_CTX_get_ciphers(ctx);
    for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        const SSL_CIPHER *ci = sk_SSL_CIPHER_value(sk, i);
        const char *std = SSL_CIPHER_standard_name(ci);

        printf("  %08lx %s %s %s %s\n", (unsigned long)SSL_CIPHER_get_id(ci),
               SSL_CIPHER_get_name(ci), std, OPENSSL_cipher_name(std), SSL_CIPHER_get_version(ci));
    }
    printf("  unknown: %s; NULL: %s %s\n", OPENSSL_cipher_name("TLS_NO_SUCH_SUITE"),
           SSL_CIPHER_get_name(NULL), SSL_CIPHER_get_version(NULL));
    SSL_CTX_free(ctx);
}

/* Every SSL_R_* reason's string (and the library's name). */
static void test_reasons(void)
{
    int r, n = 0;

    printf("# reason strings\n");
    printf("  library: %s\n", ERR_lib_error_string(ERR_PACK(ERR_LIB_SSL, 0, 0)));
    for (r = 1; r < 4096; r++) {
        const char *s = ERR_reason_error_string(ERR_PACK(ERR_LIB_SSL, 0, r));

        if (s != NULL) {
            printf("  %d: %s\n", r, s);
            n++;
        }
    }
    printf("  %d reasons\n", n);
    check(n > 300, "the reasons have strings");
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    test_versions();
    test_handshakes();
    test_post_handshake();
    test_read_state();
    test_suite_names();
    test_reasons();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
