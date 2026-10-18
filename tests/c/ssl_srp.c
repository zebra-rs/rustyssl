/*
 * Conformance test for SRP over TLS 1.2 (SSL_CTX_set_srp_password(3) and friends): the
 * connection's SRP state (SSL_SRP_CTX_init, SSL_SRP_CTX_free, SSL_CTX_SRP_CTX_init,
 * SSL_CTX_SRP_CTX_free, SSL_get_srp_g, SSL_get_srp_N, SSL_get_srp_username,
 * SSL_get_srp_userinfo), the server's parameters (SSL_set_srp_server_param,
 * SSL_set_srp_server_param_pw, SSL_srp_server_param_with_username), the client's A
 * (SRP_Calc_A_param), and handshakes over a BIO pair: SRP and SRP-RSA suites, a wrong
 * password, a username callback that retries or refuses, a client without a login, the
 * client's parameter checks (its callback, the strength, an unknown group) and its password
 * callback.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/srp.h>
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

/* Prints and clears the error queue: library/reason. */
static void errors(const char *who)
{
    unsigned long e;

    printf("  %s errors:", who);
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

/* A self-signed RSA certificate for a new 2048-bit key. */
static X509 *rsa_cert(EVP_PKEY **pk)
{
    X509 *x = X509_new();
    X509_NAME *n = X509_NAME_new();

    *pk = EVP_RSA_gen(2048);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"srp", -1, -1, 0);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 9);
    X509_set_version(x, X509_VERSION_3);
    X509_set_subject_name(x, n);
    X509_set_issuer_name(x, n);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, *pk);
    X509_sign(x, *pk, EVP_sha256());
    X509_NAME_free(n);
    return x;
}

/* A number's size, or -1 for none. */
static int bits(const BIGNUM *bn)
{
    return bn == NULL ? -1 : BN_num_bits(bn);
}

static const char *str(const char *s)
{
    return s == NULL ? "(null)" : s;
}

/* What the username callback does: 0 sets the user's parameters, -1 retries once, else fails. */
static int username_mode, username_calls, verify_ret = 1, verify_calls, pwd_calls, pwd_null;
static const char *server_password = "password";

static int username_cb(SSL *s, int *ad, void *arg)
{
    (void)arg;
    username_calls++;
    printf("  username callback #%d: \"%s\", ad %d\n", username_calls,
           str(SSL_get_srp_username(s)), *ad);
    if (username_mode == -1 && username_calls == 1)
        return -1;
    if (username_mode == 1) {
        *ad = SSL_AD_UNKNOWN_PSK_IDENTITY;
        return SSL3_AL_FATAL;
    }
    if (username_mode == 2) {
        *ad = SSL_AD_ACCESS_DENIED;
        return SSL3_AL_FATAL;
    }
    if (username_mode == 3) {
        /* A known group's N with another generator. */
        const SRP_gN *gn = SRP_get_default_gN("1024");
        BIGNUM *g = BN_new(), *salt = NULL, *v = NULL;
        int r;

        BN_set_word(g, 5);
        SRP_create_verifier_BN(SSL_get_srp_username(s), server_password, &salt, &v, gn->N, g);
        r = SSL_set_srp_server_param(s, gn->N, g, salt, v, "info");
        BN_free(g);
        BN_free(salt);
        BN_clear_free(v);
        return r > 0 ? SSL_ERROR_NONE : SSL3_AL_FATAL;
    }
    if (SSL_set_srp_server_param_pw(s, SSL_get_srp_username(s), server_password, "1024") != 1)
        return SSL3_AL_FATAL;
    return SSL_ERROR_NONE;
}

static int verify_cb(SSL *s, void *arg)
{
    (void)arg;
    verify_calls++;
    printf("  verify callback #%d: N %d bits, g %d bits\n", verify_calls, bits(SSL_get_srp_N(s)),
           bits(SSL_get_srp_g(s)));
    return verify_ret;
}

static char *pwd_cb(SSL *s, void *arg)
{
    (void)s;
    pwd_calls++;
    printf("  password callback #%d, arg %s\n", pwd_calls, arg == NULL ? "NULL" : (char *)arg);
    return pwd_null ? NULL : OPENSSL_strdup("password");
}

/*
 * A TLS 1.2 handshake over a BIO pair: 0, or the SSL_get_error that stopped one end (whose
 * errors are printed). SSL_ERROR_WANT_X509_LOOKUP is retried.
 */
static int handshake(SSL_CTX *cctx, SSL_CTX *sctx, SSL **pc, SSL **ps)
{
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    BIO *a = NULL, *b = NULL;
    int cdone = 0, sdone = 0, round;

    BIO_new_bio_pair(&a, 0, &b, 0);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    *pc = c;
    *ps = s;
    for (round = 0; round < 64 && (!cdone || !sdone); round++) {
        int i;

        for (i = 0; i < 2; i++) {
            SSL *x = i == 0 ? c : s;
            int *done = i == 0 ? &cdone : &sdone, r, e;

            if (*done)
                continue;
            r = SSL_do_handshake(x);
            if (r == 1) {
                *done = 1;
                continue;
            }
            e = SSL_get_error(x, r);
            if (e == SSL_ERROR_WANT_X509_LOOKUP)
                printf("  %s: want x509 lookup\n", i == 0 ? "client" : "server");
            else if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                printf("  %s stopped: %d\n", i == 0 ? "client" : "server", e);
                errors(i == 0 ? "client" : "server");
                /* The other end reads the alert. */
                x = i == 0 ? s : c;
                r = SSL_do_handshake(x);
                printf("  %s then: %d\n", i == 0 ? "server" : "client", SSL_get_error(x, r));
                errors(i == 0 ? "server" : "client");
                return e;
            }
        }
    }
    return cdone && sdone ? 0 : -1;
}

/* The contexts for a handshake: the client with `user` and `pass` (either may be NULL). */
static void contexts(SSL_CTX **cctx, SSL_CTX **sctx, const char *ciphers, const char *user,
                     const char *pass, X509 *x, EVP_PKEY *pk)
{
    *cctx = SSL_CTX_new(TLS_client_method());
    *sctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_max_proto_version(*cctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(*sctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(*cctx, ciphers);
    SSL_CTX_set_cipher_list(*sctx, ciphers);
    SSL_CTX_use_certificate(*sctx, x);
    SSL_CTX_use_PrivateKey(*sctx, pk);
    SSL_CTX_set_srp_username_callback(*sctx, username_cb);
    if (user != NULL)
        SSL_CTX_set_srp_username(*cctx, (char *)user);
    if (pass != NULL)
        SSL_CTX_set_srp_password(*cctx, (char *)pass);
}

/* The SRP username line of the session's SSL_SESSION_print, and its DER's (i2d's). */
static void session_srp(const char *who, SSL *x)
{
    SSL_SESSION *sess = SSL_get_session(x), *back;
    BIO *b = BIO_new(BIO_s_mem());
    char line[256], *p;
    unsigned char *der = NULL;
    const unsigned char *q;
    int len;

    printf("  %s's session:", who);
    if (sess == NULL || b == NULL || SSL_SESSION_print(b, sess) != 1) {
        printf(" none\n");
        BIO_free(b);
        return;
    }
    while (BIO_gets(b, line, sizeof(line)) > 0)
        if ((p = strstr(line, "SRP username:")) != NULL)
            printf(" %s", p);
    len = i2d_SSL_SESSION(sess, &der);
    q = der;
    back = len > 0 ? d2i_SSL_SESSION(NULL, &q, len) : NULL;
    BIO_free(b);
    b = BIO_new(BIO_s_mem());
    if (back != NULL && b != NULL && SSL_SESSION_print(b, back) == 1) {
        while (BIO_gets(b, line, sizeof(line)) > 0)
            if ((p = strstr(line, "SRP username:")) != NULL)
                printf("  decoded: %s", p);
    }
    SSL_SESSION_free(back);
    OPENSSL_free(der);
    BIO_free(b);
}

/* A handshake between the contexts (which it frees); 0, or the error that stopped it. */
static int run(const char *name, SSL_CTX *cctx, SSL_CTX *sctx)
{
    SSL *c, *s;
    int r;

    printf("# %s\n", name);
    username_calls = verify_calls = pwd_calls = 0;
    r = handshake(cctx, sctx, &c, &s);
    if (r == 0) {
        printf("  suite %s, server's username \"%s\", userinfo \"%s\"\n",
               SSL_CIPHER_get_name(SSL_get_current_cipher(c)), str(SSL_get_srp_username(s)),
               str(SSL_get_srp_userinfo(s)));
        printf("  client N %d g %d bits, server N %d g %d bits\n", bits(SSL_get_srp_N(c)),
               bits(SSL_get_srp_g(c)), bits(SSL_get_srp_N(s)), bits(SSL_get_srp_g(s)));
        session_srp("client", c);
        session_srp("server", s);
    }
    printf("  username callbacks %d, verify callbacks %d, password callbacks %d\n",
           username_calls, verify_calls, pwd_calls);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return r;
}

static void test_null(void)
{
    int ad = 0;

    printf("# NULL connections and contexts\n");
    check(SSL_get_srp_g(NULL) == NULL && SSL_get_srp_N(NULL) == NULL, "no numbers");
    check(SSL_get_srp_username(NULL) == NULL && SSL_get_srp_userinfo(NULL) == NULL, "no strings");
    check(SSL_SRP_CTX_init(NULL) == 0 && SSL_SRP_CTX_free(NULL) == 0, "connection init and free");
    check(SSL_CTX_SRP_CTX_init(NULL) == 0 && SSL_CTX_SRP_CTX_free(NULL) == 0,
          "context init and free");
    check(SRP_Calc_A_param(NULL) == 0, "no A");
    check(SSL_set_srp_server_param(NULL, NULL, NULL, NULL, NULL, NULL) == -1, "no parameters");
    check(SSL_set_srp_server_param_pw(NULL, "u", "p", NULL) == -1, "no parameters from a password");
    check(SSL_srp_server_param_with_username(NULL, &ad) == SSL3_AL_FATAL && ad == 0,
          "no username parameters");
    errors("NULL");
}

static void test_state(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *s;
    const SRP_gN *gn = SRP_get_default_gN("1024");
    BIGNUM *salt = NULL, *v = NULL;
    int ad = 0;

    printf("# a connection's SRP state\n");
    SSL_CTX_set_srp_username(ctx, "user");
    SSL_CTX_set_srp_password(ctx, "pass");
    s = SSL_new(ctx);
    printf("  username \"%s\", userinfo \"%s\", N %d, g %d\n", str(SSL_get_srp_username(s)),
           str(SSL_get_srp_userinfo(s)), bits(SSL_get_srp_N(s)), bits(SSL_get_srp_g(s)));
    check(SRP_Calc_A_param(s) == 0, "no A without N and g");
    errors("A");
    check(SSL_srp_server_param_with_username(s, &ad) == SSL3_AL_FATAL, "no parameters");
    printf("  ad %d\n", ad);
    check(SSL_set_srp_server_param(s, gn->N, NULL, NULL, NULL, NULL) == -1, "N alone");
    printf("  N %d, g %d\n", bits(SSL_get_srp_N(s)), bits(SSL_get_srp_g(s)));
    SRP_create_verifier_BN("user", "pass", &salt, &v, gn->N, gn->g);
    check(SSL_set_srp_server_param(s, NULL, gn->g, salt, v, "the info") == 1, "the rest");
    printf("  userinfo \"%s\", g %d\n", str(SSL_get_srp_userinfo(s)), bits(SSL_get_srp_g(s)));
    check(SSL_srp_server_param_with_username(s, &ad) == SSL_ERROR_NONE, "B made");
    printf("  ad %d\n", ad);
    check(SRP_Calc_A_param(s) == 1, "A made");
    check(SSL_set_srp_server_param_pw(s, "user", "pass", "999") == -1, "an unknown group");
    check(SSL_set_srp_server_param_pw(s, "user", "pass", "1536") == 1, "the 1536-bit group");
    printf("  N %d, g %d\n", bits(SSL_get_srp_N(s)), bits(SSL_get_srp_g(s)));
    check(SSL_set_srp_server_param_pw(s, "user", "pass", NULL) == 1, "the default group");
    printf("  N %d, g %d\n", bits(SSL_get_srp_N(s)), bits(SSL_get_srp_g(s)));
    check(SSL_SRP_CTX_free(s) == 1, "the connection's state freed");
    printf("  username \"%s\", userinfo \"%s\", N %d\n", str(SSL_get_srp_username(s)),
           str(SSL_get_srp_userinfo(s)), bits(SSL_get_srp_N(s)));
    check(SSL_SRP_CTX_init(s) == 1, "the connection's state again");
    printf("  username \"%s\", N %d\n", str(SSL_get_srp_username(s)), bits(SSL_get_srp_N(s)));
    check(SSL_CTX_SRP_CTX_free(ctx) == 1, "the context's state freed");
    SSL_SRP_CTX_init(s);
    printf("  username \"%s\", userinfo \"%s\"\n", str(SSL_get_srp_username(s)),
           str(SSL_get_srp_userinfo(s)));
    check(SSL_CTX_SRP_CTX_init(ctx) == 1, "the context's state again");
    errors("state");
    BN_free(salt);
    BN_clear_free(v);
    SSL_free(s);
    SSL_CTX_free(ctx);
}

static void test_handshakes(void)
{
    SSL_CTX *c, *s;
    EVP_PKEY *pk = NULL;
    X509 *x = rsa_cert(&pk);

    username_mode = 0;
    contexts(&c, &s, "SRP-AES-128-CBC-SHA", "user", "password", x, pk);
    check(run("SRP", c, s) == 0, "SRP");

    contexts(&c, &s, "SRP-RSA-AES-128-CBC-SHA", "user", "password", x, pk);
    check(run("SRP with an RSA signature", c, s) == 0, "SRP-RSA");

    contexts(&c, &s, "SRP-AES-256-CBC-SHA", "user", "badpass", x, pk);
    check(run("a wrong password", c, s) == SSL_ERROR_SSL, "a wrong password");

    username_mode = -1;
    contexts(&c, &s, "SRP-AES-128-CBC-SHA", "user", "password", x, pk);
    check(run("the username callback retries", c, s) == 0, "a retry");

    username_mode = 1;
    contexts(&c, &s, "SRP-AES-128-CBC-SHA", "user", "password", x, pk);
    check(run("an unknown user", c, s) == SSL_ERROR_SSL, "an unknown user");

    username_mode = 2;
    contexts(&c, &s, "SRP-AES-128-CBC-SHA", "user", "password", x, pk);
    check(run("the username callback refuses", c, s) == SSL_ERROR_SSL, "a refusal");

    username_mode = 0;
    contexts(&c, &s, "SRP-AES-128-CBC-SHA", NULL, "password", x, pk);
    SSL_CTX_set_srp_cb_arg(c, NULL);
    check(run("a client without a login", c, s) == SSL_ERROR_SSL, "no login");

    contexts(&c, &s, "SRP-AES-128-CBC-SHA", NULL, "password", x, pk);
    check(run("SRP not enabled on the client", c, s) == SSL_ERROR_SSL, "not enabled");

    contexts(&c, &s, "SRP-AES-128-CBC-SHA", "user", "password", x, pk);
    SSL_CTX_set_srp_verify_param_callback(c, verify_cb);
    verify_ret = 1;
    check(run("the client's parameter callback accepts", c, s) == 0, "the callback accepts");

    contexts(&c, &s, "SRP-AES-128-CBC-SHA", "user", "password", x, pk);
    SSL_CTX_set_srp_verify_param_callback(c, verify_cb);
    verify_ret = 0;
    check(run("the client's parameter callback refuses", c, s) == SSL_ERROR_SSL,
          "the callback refuses");

    contexts(&c, &s, "SRP-AES-128-CBC-SHA", "user", "password", x, pk);
    SSL_CTX_set_srp_strength(c, 2048);
    check(run("a group below the client's strength", c, s) == SSL_ERROR_SSL, "too weak");

    username_mode = 3;
    contexts(&c, &s, "SRP-AES-128-CBC-SHA", "user", "password", x, pk);
    check(run("an unknown group", c, s) == SSL_ERROR_SSL, "an unknown group");

    username_mode = 0;
    contexts(&c, &s, "SRP-AES-128-CBC-SHA", "user", NULL, x, pk);
    SSL_CTX_set_srp_client_pwd_callback(c, pwd_cb);
    SSL_CTX_set_srp_cb_arg(c, "the arg");
    pwd_null = 0;
    check(run("the client's password callback", c, s) == 0, "a password from the callback");

    contexts(&c, &s, "SRP-AES-128-CBC-SHA", "user", NULL, x, pk);
    SSL_CTX_set_srp_client_pwd_callback(c, pwd_cb);
    pwd_null = 1;
    check(run("the client's password callback gives none", c, s) == SSL_ERROR_SSL,
          "no password from the callback");

    contexts(&c, &s, "SRP-AES-128-CBC-SHA", "user", NULL, x, pk);
    check(run("a client without a password", c, s) == SSL_ERROR_SSL, "no password");

    X509_free(x);
    EVP_PKEY_free(pk);
}

int main(void)
{
    test_null();
    test_state();
    test_handshakes();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
