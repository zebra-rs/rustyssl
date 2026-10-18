/*
 * The BoGo shim: BoringSSL's TLS test runner (ssl/test/runner) driving the OpenSSL API, for
 * `cargo xtask test-bogo`. It is built once against the vendored 3.5 headers and runs on the
 * reference libraries and on rustyssl's, by pointing the dynamic loader at each.
 *
 * The runner starts one shim process per test, with `-port`, `-shim-id` and the flags that
 * configure the test (`ssl/test/test_config.cc` in BoringSSL lists them all). For each
 * connection (the first, then `-resume-count` resumptions) the shim connects to the runner
 * over TCP, sends its ID as a little-endian 64-bit integer, and runs the TLS connection as a
 * client or a server: the handshake, checks of what was negotiated, then an echo loop that
 * writes back each byte it reads XORed with 0xff, until the runner closes. It exits 0 when
 * everything went as configured, 1 otherwise (after printing the error queue to stderr), and
 * 89 for a flag it doesn't implement, which the runner reports as unimplemented.
 *
 * A flag may carry a prefix: `-on-initial-`, `-on-resume-` or `-on-retry-` applies it to that
 * connection only, `-on-shim-` to the shim (there is no separate handshaker here), and
 * `-on-handshaker-` flags are ignored. Implemented are the flags OpenSSL's API can express;
 * BoringSSL-only features (ECH, ALPS, Channel ID, delegated credentials, PAKEs, the
 * asynchronous private-key and ticket hooks, compliance policies, QUIC) and DTLS (Phase 8.1)
 * exit 89.
 *
 * Behavior the runner assumes of BoringSSL is set up where OpenSSL differs: TLS 1.0 and 1.1
 * stay enabled (security level 0), the cipher list is `ALL`, a client refuses renegotiation
 * unless a `-renegotiate-*` flag allows it, verification goes through a callback that accepts
 * any chain (unless `-verify-fail`), and an unclean EOF ends the echo loop like a clean one.
 *
 * With BOGO_SHIM_LOG set to a directory, the shim also writes there, per process, the first
 * error-queue entry of each failed connection, in a file named by a hash of its arguments
 * (paths reduced to their file names, the port and ID left out), so the harness can compare
 * the two libraries' failures test by test.
 */

#define _POSIX_C_SOURCE 200809L

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define EXIT_UNIMPLEMENTED 89

/* A byte string: base64 flags decode into one, string flags copy into one. */
struct bytes {
    unsigned char *data;
    size_t len;
    int set;
};

#define MAX_INTS 64

/* The X.509 credentials (-new-x509-credential), each its own certificate slot in OpenSSL. */
#define MAX_CREDS 8

struct ints {
    int v[MAX_INTS];
    size_t n;
};

/* One connection's configuration (the initial one, the resumptions', the 0-RTT retry's). */
struct config {
    int port, ipv6, is_server, resume_count, is_handshaker_supported;
    unsigned long long shim_id;
    struct bytes cert_file, key_file, ocsp_response, session_id_context;
    int min_version, max_version, expect_version;
    int no_tls13, no_tls12, no_tls11, no_tls1, no_ticket, no_legacy_server_connect;
    struct bytes cipher, tls13_ciphers;
    struct ints curves, verify_prefs;
    int expect_curve_id, expect_cipher;
    int verify_peer, require_any_client_certificate, verify_fail, expect_verify_result;
    int shim_writes_first, repeat_shim_initial_write, shim_shuts_down, check_close_notify;
    struct bytes shim_initial_write;
    int write_different_record_sizes, read_size, peek_then_read, async;
    struct bytes host_name, expect_server_name;
    int expect_no_server_name;
    struct bytes advertise_alpn, expect_alpn, select_alpn, expect_advertised_alpn;
    int decline_alpn, reject_alpn, select_empty_alpn;
    struct bytes advertise_npn, select_next_proto, expect_next_proto;
    int expect_no_next_proto, advertise_empty_npn, select_empty_next_proto;
    int expect_session_miss, expect_extended_master_secret;
    int expect_secure_renegotiation, expect_no_secure_renegotiation;
    int export_keying_material, use_export_context, tls_unique;
    struct bytes export_label, export_context;
    int renegotiate_freely, renegotiate_once, expect_total_renegotiations;
    struct bytes psk, psk_identity;
    int enable_ocsp_stapling;
    struct bytes expect_ocsp_response;
    int max_send_fragment, max_cert_list, partial_write;
    int fallback_scsv, server_preference, key_update, key_update_before_read;
    int implicit_handshake, handshake_twice, no_op_extra_handshake;
    struct bytes expect_peer_cert_file;
    int expect_no_peer_cert, fail_cert_callback, use_early_callback, fail_early_callback;
    int expect_no_session, expect_session_id, expect_no_session_id;
    int max_version_set;
    struct bytes trust_cert;
    int use_custom_verify_callback, use_ocsp_callback, set_ocsp_in_callback;
    int decline_ocsp_callback, fail_ocsp_callback;
    int expect_peer_signature_algorithm;
    struct ints signing_prefs;
    int expect_hrr, expect_no_hrr, use_old_client_cert_callback;
    int use_ticket_callback, renew_ticket, skip_ticket;
    int dtls, mtu;
    /* -cert-file and -key-file after a -new-x509-credential set the newest credential's. */
    struct bytes cred_cert[MAX_CREDS], cred_key[MAX_CREDS];
    int ncreds, in_cred;
    int expect_selected_credential, expect_selected_credential_set;
};

enum kind { BOOL, INT, STR, B64, INTS, UNSUPPORTED };

struct flag {
    const char *name;
    enum kind kind;
    size_t offset;
    int has_param; /* for UNSUPPORTED only: not needed, the shim exits at once */
};

#define F(name, kind, field) {name, kind, offsetof(struct config, field), 0}

static const struct flag FLAGS[] = {
    F("-port", INT, port),
    F("-ipv6", BOOL, ipv6),
    F("-server", BOOL, is_server),
    F("-resume-count", INT, resume_count),
    F("-is-handshaker-supported", BOOL, is_handshaker_supported),
    F("-cert-file", STR, cert_file),
    F("-key-file", STR, key_file),
    F("-ocsp-response", B64, ocsp_response),
    F("-session-id-context", B64, session_id_context),
    F("-min-version", INT, min_version),
    F("-max-version", INT, max_version),
    F("-expect-version", INT, expect_version),
    F("-no-tls13", BOOL, no_tls13),
    F("-no-tls12", BOOL, no_tls12),
    F("-no-tls11", BOOL, no_tls11),
    F("-no-tls1", BOOL, no_tls1),
    F("-no-ticket", BOOL, no_ticket),
    F("-no-legacy-server-connect", BOOL, no_legacy_server_connect),
    F("-cipher", STR, cipher),
    F("-tls13-ciphers", STR, tls13_ciphers),
    F("-curves", INTS, curves),
    F("-verify-prefs", INTS, verify_prefs),
    F("-expect-curve-id", INT, expect_curve_id),
    F("-expect-cipher", INT, expect_cipher),
    F("-verify-peer", BOOL, verify_peer),
    F("-require-any-client-certificate", BOOL, require_any_client_certificate),
    F("-verify-fail", BOOL, verify_fail),
    F("-expect-verify-result", BOOL, expect_verify_result),
    F("-shim-writes-first", BOOL, shim_writes_first),
    F("-shim-initial-write", STR, shim_initial_write),
    F("-repeat-shim-initial-write", INT, repeat_shim_initial_write),
    F("-shim-shuts-down", BOOL, shim_shuts_down),
    F("-check-close-notify", BOOL, check_close_notify),
    F("-write-different-record-sizes", BOOL, write_different_record_sizes),
    F("-read-size", INT, read_size),
    F("-peek-then-read", BOOL, peek_then_read),
    F("-async", BOOL, async),
    F("-host-name", STR, host_name),
    F("-expect-server-name", STR, expect_server_name),
    F("-expect-no-server-name", BOOL, expect_no_server_name),
    F("-advertise-alpn", STR, advertise_alpn),
    F("-expect-alpn", STR, expect_alpn),
    F("-select-alpn", STR, select_alpn),
    F("-expect-advertised-alpn", STR, expect_advertised_alpn),
    F("-decline-alpn", BOOL, decline_alpn),
    F("-reject-alpn", BOOL, reject_alpn),
    F("-select-empty-alpn", BOOL, select_empty_alpn),
    F("-advertise-npn", STR, advertise_npn),
    F("-select-next-proto", STR, select_next_proto),
    F("-expect-next-proto", STR, expect_next_proto),
    F("-expect-no-next-proto", BOOL, expect_no_next_proto),
    F("-advertise-empty-npn", BOOL, advertise_empty_npn),
    F("-select-empty-next-proto", BOOL, select_empty_next_proto),
    F("-expect-session-miss", BOOL, expect_session_miss),
    F("-expect-extended-master-secret", BOOL, expect_extended_master_secret),
    F("-expect-secure-renegotiation", BOOL, expect_secure_renegotiation),
    F("-expect-no-secure-renegotiation", BOOL, expect_no_secure_renegotiation),
    F("-export-keying-material", INT, export_keying_material),
    F("-export-label", STR, export_label),
    F("-export-context", STR, export_context),
    F("-use-export-context", BOOL, use_export_context),
    F("-tls-unique", BOOL, tls_unique),
    F("-renegotiate-freely", BOOL, renegotiate_freely),
    F("-renegotiate-once", BOOL, renegotiate_once),
    F("-expect-total-renegotiations", INT, expect_total_renegotiations),
    F("-psk", STR, psk),
    F("-psk-identity", STR, psk_identity),
    F("-enable-ocsp-stapling", BOOL, enable_ocsp_stapling),
    F("-expect-ocsp-response", B64, expect_ocsp_response),
    F("-max-send-fragment", INT, max_send_fragment),
    F("-dtls", BOOL, dtls),
    F("-mtu", INT, mtu),
    F("-max-cert-list", INT, max_cert_list),
    F("-partial-write", BOOL, partial_write),
    F("-fallback-scsv", BOOL, fallback_scsv),
    F("-server-preference", BOOL, server_preference),
    F("-key-update", BOOL, key_update),
    F("-key-update-before-read", BOOL, key_update_before_read),
    F("-implicit-handshake", BOOL, implicit_handshake),
    F("-handshake-twice", BOOL, handshake_twice),
    F("-no-op-extra-handshake", BOOL, no_op_extra_handshake),
    F("-expect-peer-cert-file", STR, expect_peer_cert_file),
    F("-expect-selected-credential", INT, expect_selected_credential),
    F("-expect-no-peer-cert", BOOL, expect_no_peer_cert),
    F("-fail-cert-callback", BOOL, fail_cert_callback),
    F("-use-early-callback", BOOL, use_early_callback),
    F("-fail-early-callback", BOOL, fail_early_callback),
    F("-expect-no-session", BOOL, expect_no_session),
    F("-expect-session-id", BOOL, expect_session_id),
    F("-expect-no-session-id", BOOL, expect_no_session_id),
    /* The runner's root, for a shim that verifies; this one's callback accepts any chain, as
       BoringSSL's does. */
    F("-trust-cert", STR, trust_cert),
    F("-use-custom-verify-callback", BOOL, use_custom_verify_callback),
    F("-use-ocsp-callback", BOOL, use_ocsp_callback),
    F("-set-ocsp-in-callback", BOOL, set_ocsp_in_callback),
    F("-decline-ocsp-callback", BOOL, decline_ocsp_callback),
    F("-fail-ocsp-callback", BOOL, fail_ocsp_callback),
    F("-expect-peer-signature-algorithm", INT, expect_peer_signature_algorithm),
    F("-signing-prefs", INTS, signing_prefs),
    F("-expect-hrr", BOOL, expect_hrr),
    F("-expect-no-hrr", BOOL, expect_no_hrr),
    F("-use-old-client-cert-callback", BOOL, use_old_client_cert_callback),
    F("-use-ticket-callback", BOOL, use_ticket_callback),
    F("-renew-ticket", BOOL, renew_ticket),
    F("-skip-ticket", BOOL, skip_ticket),
};

/* Flags that take a parameter (needed only to skip a `-on-handshaker-` one's value). */
static const char *const PARAM_FLAGS_IGNORED[] = {"-handshaker-path", "-write-settings", NULL};

static void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);

    if (p == NULL) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    return p;
}

static void set_bytes(struct bytes *b, const unsigned char *data, size_t len)
{
    free(b->data);
    b->data = xmalloc(len + 1);
    memcpy(b->data, data, len);
    b->data[len] = 0;
    b->len = len;
    b->set = 1;
}

/* Standard base64, padding required, as the runner writes it. */
static int decode_base64(struct bytes *out, const char *in)
{
    size_t len = strlen(in), pad = 0;
    unsigned char *buf;
    int n;

    if (len % 4 != 0)
        return 0;
    if (len == 0) {
        set_bytes(out, (const unsigned char *)"", 0);
        return 1;
    }
    if (in[len - 1] == '=')
        pad++;
    if (len > 1 && in[len - 2] == '=')
        pad++;
    buf = xmalloc(len / 4 * 3 + 1);
    n = EVP_DecodeBlock(buf, (const unsigned char *)in, (int)len);
    if (n < 0 || (size_t)n < pad) {
        free(buf);
        return 0;
    }
    set_bytes(out, buf, (size_t)n - pad);
    free(buf);
    return 1;
}

static int set_flag(struct config *c, const struct flag *f, const char *param)
{
    char *base = (char *)c + f->offset;
    char *end;
    long v;

    switch (f->kind) {
    case BOOL:
        *(int *)base = 1;
        return 1;
    case INT:
        errno = 0;
        v = strtol(param, &end, 10);
        if (errno != 0 || *end != 0 || v < -2147483647L || v > 2147483647L)
            return 0;
        *(int *)base = (int)v;
        if (f->offset == offsetof(struct config, max_version))
            c->max_version_set = 1;
        if (f->offset == offsetof(struct config, expect_selected_credential))
            c->expect_selected_credential_set = 1;
        return 1;
    case STR:
        set_bytes((struct bytes *)base, (const unsigned char *)param, strlen(param));
        return 1;
    case B64:
        return decode_base64((struct bytes *)base, param);
    case INTS: {
        struct ints *is = (struct ints *)base;

        errno = 0;
        v = strtol(param, &end, 10);
        if (errno != 0 || *end != 0 || is->n >= MAX_INTS)
            return 0;
        is->v[is->n++] = (int)v;
        return 1;
    }
    case UNSUPPORTED:
        break;
    }
    return 0;
}

/* Exits 89 for something the shim doesn't implement, noting it under BOGO_SHIM_LOG. */
static void unimplemented(const char *what)
{
    const char *dir = getenv("BOGO_SHIM_LOG");
    char path[4096];
    FILE *f;

    fprintf(stderr, "Unimplemented: %s\n", what);
    if (dir != NULL) {
        snprintf(path, sizeof(path), "%s/unimplemented", dir);
        if ((f = fopen(path, "a")) != NULL) {
            fprintf(f, "%s\n", what);
            fclose(f);
        }
    }
    exit(EXIT_UNIMPLEMENTED);
}

static int remove_prefix(const char **name, const char *prefix)
{
    size_t n = strlen(prefix);

    if (strncmp(*name, prefix, n) == 0 && (*name)[n] == '-') {
        *name += n;
        return 1;
    }
    return 0;
}

static const struct flag *find_flag(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof(FLAGS) / sizeof(FLAGS[0]); i++)
        if (strcmp(FLAGS[i].name, name) == 0)
            return &FLAGS[i];
    return NULL;
}

/* The flags a credential may carry besides its files: none has a per-certificate equivalent in
 * OpenSSL's API, so they are unimplemented on a credential. */
static const char *const CREDENTIAL_ONLY_FLAGS[] = {
    "-signing-prefs", "-delegated-credential", "-ocsp-response", "-signed-cert-timestamps",
    "-must-match-issuer", "-pake-context", "-pake-client-id", "-pake-server-id",
    "-pake-password", "-wrong-pake-role", "-psk-importer-key", "-psk-importer-identity", NULL,
};

static void new_credential(struct config *c)
{
    if (c->ncreds >= MAX_CREDS)
        unimplemented("more credentials");
    c->ncreds++;
    c->in_cred = 1;
}

static void credential_file(struct config *c, int key, const char *param)
{
    struct bytes *b = key ? &c->cred_key[c->ncreds - 1] : &c->cred_cert[c->ncreds - 1];

    set_bytes(b, (const unsigned char *)param, strlen(param));
}

/*
 * BoringSSL's stateful credential flags: -new-x509-credential starts a credential, and the
 * -cert-file and -key-file after it are the credential's. Other kinds of credential (delegated,
 * SPAKE2+, PSK, raw public key) are unimplemented. Whether the flag was one of these.
 */
static int credential_flag(int argc, char **argv, int *i, const char *name, int skip,
                           struct config *only, struct config *initial, struct config *resume,
                           struct config *retry)
{
    struct config *targets[3] = { initial, resume, retry };
    const struct config *probe = only != NULL ? only : initial;
    const char *const *p;
    int key, t;

    if (strcmp(name, "-new-x509-credential") == 0) {
        if (skip)
            return 1;
        for (t = 0; t < 3; t++)
            if (only == NULL || only == targets[t])
                new_credential(targets[t]);
        return 1;
    }
    if (strncmp(name, "-new-", 5) == 0 && strlen(name) > 16
        && strcmp(name + strlen(name) - 11, "-credential") == 0)
        unimplemented(name);
    if (!probe->in_cred)
        return 0;
    for (p = CREDENTIAL_ONLY_FLAGS; *p != NULL; p++)
        if (strcmp(*p, name) == 0) {
            static char what[128];

            snprintf(what, sizeof(what), "%s on a credential", name);
            unimplemented(what);
        }
    key = strcmp(name, "-key-file") == 0;
    if (!key && strcmp(name, "-cert-file") != 0)
        return 0;
    if (++*i >= argc) {
        fprintf(stderr, "Missing parameter for %s\n", name);
        exit(1);
    }
    if (skip)
        return 1;
    for (t = 0; t < 3; t++)
        if (only == NULL || only == targets[t])
            credential_file(targets[t], key, argv[*i]);
    return 1;
}

/* Parses the arguments into the three configurations; exits 89 on an unimplemented flag. */
static void parse(int argc, char **argv, struct config *initial, struct config *resume,
                  struct config *retry)
{
    int i;

    for (i = 1; i < argc; i++) {
        const char *name = argv[i];
        struct config *only = NULL;
        const struct flag *f;
        const char *param = NULL;
        int skip = 0;

        if (remove_prefix(&name, "-on-shim")) {
            /* The shim's own flags: there is no separate handshaker. */
        } else if (remove_prefix(&name, "-on-handshaker")) {
            skip = 1;
        }
        if (remove_prefix(&name, "-on-initial"))
            only = initial;
        else if (remove_prefix(&name, "-on-resume"))
            only = resume;
        else if (remove_prefix(&name, "-on-retry"))
            only = retry;

        if (strcmp(name, "-shim-id") == 0) {
            if (++i >= argc)
                exit(1);
            initial->shim_id = resume->shim_id = retry->shim_id = strtoull(argv[i], NULL, 10);
            continue;
        }
        if (credential_flag(argc, argv, &i, name, skip, only, initial, resume, retry))
            continue;
        f = find_flag(name);
        if (f == NULL) {
            const char *const *p;

            for (p = PARAM_FLAGS_IGNORED; skip && *p != NULL; p++)
                if (strcmp(*p, name) == 0) {
                    i++;
                    break;
                }
            if (skip)
                continue;
            unimplemented(name);
        }
        if (f->kind != BOOL) {
            if (++i >= argc) {
                fprintf(stderr, "Missing parameter for %s\n", name);
                exit(1);
            }
            param = argv[i];
        }
        if (skip)
            continue;
        if (only != NULL) {
            if (!set_flag(only, f, param))
                goto bad;
        } else if (!set_flag(initial, f, param) || !set_flag(resume, f, param)
                   || !set_flag(retry, f, param)) {
            goto bad;
        }
        continue;
    bad:
        fprintf(stderr, "Invalid parameter for %s: %s\n", name, param ? param : "(none)");
        exit(1);
    }
}

/* What the shim knows of each connection, through the SSL's ex_data. */
struct state {
    const struct config *config;
    int handshake_done, got_new_session, early_callback_called, cert_verified;
    SSL_SESSION *new_session;
    BIO *async_bio;
    int renegotiations, saw_hrr, ticket_decrypt_done;
};

static int g_state_index = -1;

static struct state *get_state(const SSL *ssl)
{
    return SSL_get_ex_data(ssl, g_state_index);
}

/* ---- The asynchronous BIO: a filter that lets through only what the shim allows. ---- */

struct async_quota {
    size_t read, write;
    /* Over DTLS's packets, a quota counts whole datagrams. */
    int datagram;
};

static int async_write(BIO *b, const char *in, int inl)
{
    struct async_quota *q = BIO_get_data(b);
    BIO *next = BIO_next(b);
    int ret;

    BIO_clear_retry_flags(b);
    if (q == NULL || next == NULL)
        return 0;
    if (q->write == 0) {
        BIO_set_retry_write(b);
        errno = EAGAIN;
        return -1;
    }
    if (!q->datagram && (size_t)inl > q->write)
        inl = (int)q->write;
    ret = BIO_write(next, in, inl);
    if (ret <= 0)
        BIO_copy_next_retry(b);
    else
        q->write -= q->datagram ? 1 : (size_t)ret;
    return ret;
}

static int async_read(BIO *b, char *out, int outl)
{
    struct async_quota *q = BIO_get_data(b);
    BIO *next = BIO_next(b);
    int ret;

    BIO_clear_retry_flags(b);
    if (q == NULL || next == NULL)
        return 0;
    if (q->read == 0) {
        BIO_set_retry_read(b);
        errno = EAGAIN;
        return -1;
    }
    if (!q->datagram && (size_t)outl > q->read)
        outl = (int)q->read;
    ret = BIO_read(next, out, outl);
    if (ret <= 0)
        BIO_copy_next_retry(b);
    else
        q->read -= q->datagram ? 1 : (size_t)ret;
    return ret;
}

static long async_ctrl(BIO *b, int cmd, long larg, void *parg)
{
    BIO *next = BIO_next(b);

    return next == NULL ? 0 : BIO_ctrl(next, cmd, larg, parg);
}

static int async_create(BIO *b)
{
    struct async_quota *q = calloc(1, sizeof(*q));

    if (q == NULL)
        return 0;
    BIO_set_data(b, q);
    BIO_set_init(b, 1);
    return 1;
}

static int async_destroy(BIO *b)
{
    free(BIO_get_data(b));
    BIO_set_data(b, NULL);
    return 1;
}

static BIO *async_bio_new(void)
{
    static BIO_METHOD *method;

    if (method == NULL) {
        method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_FILTER, "async bio");
        if (method == NULL || !BIO_meth_set_write(method, async_write)
            || !BIO_meth_set_read(method, async_read) || !BIO_meth_set_ctrl(method, async_ctrl)
            || !BIO_meth_set_create(method, async_create)
            || !BIO_meth_set_destroy(method, async_destroy))
            return NULL;
    }
    return BIO_new(method);
}

/*
 * The packeted BIO: DTLS's datagrams over the runner's TCP connection. Each datagram goes as
 * 'P', a 32-bit big-endian length and the bytes; the runner also sends 'M' (a new MTU) and
 * the clock opcodes 'T' (a timeout passed), 'E' (the next timeout expected) and 'U' (a new
 * initial timeout). BoringSSL's shim drives a simulated clock with those; OpenSSL's DTLS
 * timers run on the real clock, so a test that sends one is unimplemented here.
 */
struct packeted {
    SSL *ssl;
};

static int read_full(BIO *b, unsigned char *out, size_t len)
{
    while (len > 0) {
        int n = BIO_read(b, out, len > INT32_MAX ? INT32_MAX : (int)len);

        if (n <= 0)
            return n;
        out += n;
        len -= (size_t)n;
    }
    return 1;
}

static int packeted_write(BIO *b, const char *in, int inl)
{
    BIO *next = BIO_next(b);
    unsigned char header[5];
    int n;

    BIO_clear_retry_flags(b);
    if (next == NULL || inl < 0)
        return -1;
    header[0] = 'P';
    header[1] = (unsigned char)((unsigned)inl >> 24);
    header[2] = (unsigned char)((unsigned)inl >> 16);
    header[3] = (unsigned char)((unsigned)inl >> 8);
    header[4] = (unsigned char)inl;
    if (BIO_write(next, header, 5) != 5)
        return -1;
    for (n = 0; n < inl;) {
        int w = BIO_write(next, in + n, inl - n);

        if (w <= 0)
            return -1;
        n += w;
    }
    return inl;
}

static int packeted_read(BIO *b, char *out, int outl)
{
    struct packeted *d = BIO_get_data(b);
    BIO *next = BIO_next(b);
    unsigned char op, len[4], *buf;
    uint32_t n;
    int r;

    BIO_clear_retry_flags(b);
    if (next == NULL || d == NULL)
        return -1;
    for (;;) {
        if ((r = read_full(next, &op, 1)) <= 0)
            return r;
        switch (op) {
        case 'P':
            if ((r = read_full(next, len, 4)) <= 0)
                return r;
            n = (uint32_t)len[0] << 24 | (uint32_t)len[1] << 16 | (uint32_t)len[2] << 8 | len[3];
            buf = xmalloc(n);
            if (read_full(next, buf, n) <= 0) {
                fprintf(stderr, "Packeted BIO was truncated\n");
                free(buf);
                return -1;
            }
            if ((uint32_t)outl > n)
                outl = (int)n;
            memcpy(out, buf, (size_t)outl);
            free(buf);
            return outl;
        case 'M':
            if ((r = read_full(next, len, 4)) <= 0)
                return r;
            n = (uint32_t)len[0] << 24 | (uint32_t)len[1] << 16 | (uint32_t)len[2] << 8 | len[3];
            if (d->ssl == NULL || !SSL_set_mtu(d->ssl, (long)n)) {
                fprintf(stderr, "SSL_set_mtu(%u) failed\n", (unsigned)n);
                return -1;
            }
            continue;
        case 'T':
        case 'E':
        case 'U':
            unimplemented("DTLS's simulated clock");
            return -1;
        default:
            fprintf(stderr, "Unknown opcode, %u\n", op);
            return -1;
        }
    }
}

static long packeted_ctrl(BIO *b, int cmd, long larg, void *parg)
{
    BIO *next = BIO_next(b);

    switch (cmd) {
    /* What a UDP socket would say, with BoringSSL's default MTU when none is set. */
    case BIO_CTRL_DGRAM_QUERY_MTU:
        return 1472;
    case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
        return 0;
    case BIO_CTRL_DGRAM_SET_MTU:
        return larg;
    case BIO_CTRL_FLUSH:
        return 1;
    default:
        if (cmd >= BIO_CTRL_DGRAM_CONNECT && cmd <= BIO_CTRL_DGRAM_SET_PEEK_MODE)
            return 0;
        return next == NULL ? 0 : BIO_ctrl(next, cmd, larg, parg);
    }
}

static int packeted_create(BIO *b)
{
    struct packeted *d = calloc(1, sizeof(*d));

    if (d == NULL)
        return 0;
    BIO_set_data(b, d);
    BIO_set_init(b, 1);
    return 1;
}

static BIO *packeted_bio_new(void)
{
    static BIO_METHOD *method;

    if (method == NULL) {
        method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_FILTER, "packeted bio");
        if (method == NULL || !BIO_meth_set_write(method, packeted_write)
            || !BIO_meth_set_read(method, packeted_read)
            || !BIO_meth_set_ctrl(method, packeted_ctrl)
            || !BIO_meth_set_create(method, packeted_create)
            || !BIO_meth_set_destroy(method, async_destroy))
            return NULL;
    }
    return BIO_new(method);
}

/* After a failed call: lets one more byte through where the library is waiting. */
static int retry_async(SSL *ssl, int ret)
{
    struct state *st = get_state(ssl);
    struct async_quota *q;

    if (ret >= 0 || !st->config->async)
        return 0;
    q = BIO_get_data(st->async_bio);
    switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_WANT_READ:
        q->read++;
        return 1;
    case SSL_ERROR_WANT_WRITE:
        q->write++;
        return 1;
    default:
        return 0;
    }
}

/* ---- Callbacks ---- */

static int verify_callback(X509_STORE_CTX *store, void *arg)
{
    SSL *ssl = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
    struct state *st = get_state(ssl);

    (void)arg;
    st->cert_verified = 1;
    if (st->config->verify_fail) {
        X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }
    return 1;
}

static int new_session_callback(SSL *ssl, SSL_SESSION *session)
{
    struct state *st = get_state(ssl);

    st->got_new_session = 1;
    if (SSL_is_server(ssl))
        return 0;
    SSL_SESSION_free(st->new_session);
    st->new_session = session;
    return 1;
}

static void info_callback(const SSL *ssl, int where, int ret)
{
    struct state *st = get_state(ssl);

    (void)ret;
    if (st == NULL)
        return;
    if (where & SSL_CB_HANDSHAKE_START && st->handshake_done)
        st->renegotiations++;
    if (where & SSL_CB_HANDSHAKE_DONE) {
        st->handshake_done = 1;
        /* A second renegotiation is refused after the first. */
        if (st->config->renegotiate_once && st->renegotiations >= 1)
            SSL_set_options((SSL *)ssl, SSL_OP_NO_RENEGOTIATION);
    }
}

static int client_hello_callback(SSL *ssl, int *alert, void *arg)
{
    struct state *st = get_state(ssl);

    (void)alert;
    (void)arg;
    st->early_callback_called = 1;
    if (st->config->fail_early_callback)
        return SSL_CLIENT_HELLO_ERROR;
    return SSL_CLIENT_HELLO_SUCCESS;
}

static int cert_callback(SSL *ssl, void *arg)
{
    (void)arg;
    return get_state(ssl)->config->fail_cert_callback ? 0 : 1;
}

static int alpn_select_callback(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen, void *arg)
{
    const struct config *c = get_state(ssl)->config;

    (void)arg;
    if (c->decline_alpn)
        return SSL_TLSEXT_ERR_NOACK;
    if (c->reject_alpn)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    if (c->expect_advertised_alpn.set
        && (c->expect_advertised_alpn.len != inlen
            || memcmp(c->expect_advertised_alpn.data, in, inlen) != 0)) {
        fprintf(stderr, "bad ALPN select callback inputs.\n");
        exit(1);
    }
    if (!c->select_alpn.set && !c->select_empty_alpn)
        return SSL_TLSEXT_ERR_NOACK;
    *out = c->select_alpn.set ? c->select_alpn.data : (const unsigned char *)"";
    *outlen = (unsigned char)(c->select_alpn.set ? c->select_alpn.len : 0);
    return SSL_TLSEXT_ERR_OK;
}

static int npn_advertise_callback(SSL *ssl, const unsigned char **out, unsigned int *outlen,
                                  void *arg)
{
    const struct config *c = get_state(ssl)->config;

    (void)arg;
    if (!c->advertise_npn.set && !c->advertise_empty_npn)
        return SSL_TLSEXT_ERR_NOACK;
    *out = c->advertise_npn.set ? c->advertise_npn.data : (const unsigned char *)"";
    *outlen = (unsigned int)(c->advertise_npn.set ? c->advertise_npn.len : 0);
    return SSL_TLSEXT_ERR_OK;
}

static int npn_select_callback(SSL *ssl, unsigned char **out, unsigned char *outlen,
                               const unsigned char *in, unsigned int inlen, void *arg)
{
    const struct config *c = get_state(ssl)->config;

    (void)in;
    (void)inlen;
    (void)arg;
    if (!c->select_next_proto.set && !c->select_empty_next_proto)
        return SSL_TLSEXT_ERR_NOACK;
    *out = c->select_next_proto.set ? c->select_next_proto.data : (unsigned char *)"";
    *outlen = (unsigned char)(c->select_next_proto.set ? c->select_next_proto.len : 0);
    return SSL_TLSEXT_ERR_OK;
}

static int status_callback(SSL *ssl, void *arg)
{
    const struct config *c = get_state(ssl)->config;
    unsigned char *copy;

    (void)arg;
    if (!SSL_is_server(ssl))
        return 1;
    if (c->fail_ocsp_callback)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    if (c->decline_ocsp_callback || !c->ocsp_response.set)
        return SSL_TLSEXT_ERR_NOACK;
    copy = OPENSSL_malloc(c->ocsp_response.len ? c->ocsp_response.len : 1);
    if (copy == NULL)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    memcpy(copy, c->ocsp_response.data, c->ocsp_response.len);
    if (!SSL_set_tlsext_status_ocsp_resp(ssl, copy, (long)c->ocsp_response.len)) {
        OPENSSL_free(copy);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    return SSL_TLSEXT_ERR_OK;
}

static unsigned int psk_client_callback(SSL *ssl, const char *hint, char *identity,
                                        unsigned int max_identity_len, unsigned char *psk,
                                        unsigned int max_psk_len)
{
    const struct config *c = get_state(ssl)->config;

    (void)hint;
    if (c->psk_identity.len + 1 > max_identity_len || c->psk.len > max_psk_len)
        return 0;
    memcpy(identity, c->psk_identity.set ? (char *)c->psk_identity.data : "",
           c->psk_identity.len + 1);
    memcpy(psk, c->psk.data, c->psk.len);
    return (unsigned int)c->psk.len;
}

static unsigned int psk_server_callback(SSL *ssl, const char *identity, unsigned char *psk,
                                        unsigned int max_psk_len)
{
    const struct config *c = get_state(ssl)->config;
    const char *want = c->psk_identity.set ? (const char *)c->psk_identity.data : "";

    if (strcmp(identity, want) != 0) {
        fprintf(stderr, "Client PSK identity did not match.\n");
        return 0;
    }
    if (c->psk.len > max_psk_len)
        return 0;
    memcpy(psk, c->psk.data, c->psk.len);
    return (unsigned int)c->psk.len;
}

/* TLS 1.3's HelloRetryRequest: a ServerHello with this random (RFC 8446, section 4.1.3). */
static const unsigned char HRR_RANDOM[32] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

static void msg_callback(int write_p, int version, int content_type, const void *buf, size_t len,
                         SSL *ssl, void *arg)
{
    const unsigned char *b = buf;
    struct state *st = get_state(ssl);

    (void)write_p;
    (void)version;
    (void)arg;
    if (st != NULL && content_type == SSL3_RT_HANDSHAKE && len >= 38 && b[0] == 2
        && memcmp(b + 6, HRR_RANDOM, sizeof(HRR_RANDOM)) == 0)
        st->saw_hrr = 1;
}

/* The client certificate from the files, through the callback older applications use. */
static int client_cert_callback(SSL *ssl, X509 **x509, EVP_PKEY **pkey)
{
    const struct config *c = get_state(ssl)->config;
    BIO *in;

    if (!c->cert_file.set || !c->key_file.set)
        return 0;
    in = BIO_new_file((char *)c->cert_file.data, "r");
    *x509 = in != NULL ? PEM_read_bio_X509(in, NULL, NULL, NULL) : NULL;
    BIO_free(in);
    in = BIO_new_file((char *)c->key_file.data, "r");
    *pkey = in != NULL ? PEM_read_bio_PrivateKey(in, NULL, NULL, NULL) : NULL;
    BIO_free(in);
    if (*x509 == NULL || *pkey == NULL) {
        X509_free(*x509);
        EVP_PKEY_free(*pkey);
        *x509 = NULL;
        *pkey = NULL;
        return -1;
    }
    return 1;
}

/* Tickets under the all-zero key, as BoringSSL's shim makes them with this callback. */
static int ticket_key_callback(SSL *ssl, unsigned char key_name[16], unsigned char *iv,
                               EVP_CIPHER_CTX *cctx, EVP_MAC_CTX *hctx, int enc)
{
    static const unsigned char zeros[16] = {0};
    struct state *st = get_state(ssl);
    const struct config *c = st->config;
    OSSL_PARAM params[3];

    if (!enc) {
        if (st->ticket_decrypt_done) {
            fprintf(stderr, "TicketKeyCallback called after completion.\n");
            return -1;
        }
        st->ticket_decrypt_done = 1;
    }
    if (enc) {
        if (c->skip_ticket)
            return 0;
        memcpy(key_name, zeros, 16);
        if (RAND_bytes(iv, 16) != 1)
            return -1;
    } else if (memcmp(key_name, zeros, 16) != 0) {
        return 0;
    }
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void *)zeros, 16);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA256", 0);
    params[2] = OSSL_PARAM_construct_end();
    if (!EVP_MAC_CTX_set_params(hctx, params)
        || !EVP_CipherInit_ex(cctx, EVP_aes_128_cbc(), NULL, zeros, iv, enc))
        return -1;
    return !enc && c->renew_ticket ? 2 : 1;
}

/* ---- Groups and signature algorithms by codepoint ---- */

struct named {
    int id;
    const char *name;
};

static const struct named GROUPS[] = {
    {23, "P-256"}, {24, "P-384"}, {25, "P-521"}, {29, "X25519"}, {30, "X448"},
    {256, "ffdhe2048"}, {257, "ffdhe3072"}, {258, "ffdhe4096"}, {259, "ffdhe6144"},
    {260, "ffdhe8192"}, {0x0200, "MLKEM512"}, {0x0201, "MLKEM768"}, {0x0202, "MLKEM1024"},
    {0x11eb, "SecP256r1MLKEM768"}, {0x11ec, "X25519MLKEM768"},
    {0x11ed, "SecP384r1MLKEM1024"}, {0, NULL},
};

static const struct named SIGALGS[] = {
    {0x0201, "rsa_pkcs1_sha1"}, {0x0203, "ecdsa_sha1"}, {0x0401, "rsa_pkcs1_sha256"},
    {0x0501, "rsa_pkcs1_sha384"}, {0x0601, "rsa_pkcs1_sha512"},
    {0x0403, "ecdsa_secp256r1_sha256"}, {0x0503, "ecdsa_secp384r1_sha384"},
    {0x0603, "ecdsa_secp521r1_sha512"}, {0x0804, "rsa_pss_rsae_sha256"},
    {0x0805, "rsa_pss_rsae_sha384"}, {0x0806, "rsa_pss_rsae_sha512"}, {0x0807, "ed25519"},
    {0x0808, "ed448"}, {0x0809, "rsa_pss_pss_sha256"}, {0x080a, "rsa_pss_pss_sha384"},
    {0x080b, "rsa_pss_pss_sha512"}, {0x0904, "mldsa44"}, {0x0905, "mldsa65"},
    {0x0906, "mldsa87"}, {0, NULL},
};

static const char *name_of(const struct named *table, int id)
{
    for (; table->name != NULL; table++)
        if (table->id == id)
            return table->name;
    return NULL;
}

/* "a:b:c" from the codepoints, or NULL (and the shim exits 89) for one OpenSSL can't name. */
static char *list_of(const struct named *table, const struct ints *ids)
{
    size_t i, len = 1;
    char *out;

    for (i = 0; i < ids->n; i++) {
        const char *n = name_of(table, ids->v[i]);

        if (n == NULL) {
            char what[64];

            snprintf(what, sizeof(what), "codepoint %d", ids->v[i]);
            unimplemented(what);
        }
        len += strlen(n) + 1;
    }
    out = xmalloc(len);
    out[0] = 0;
    for (i = 0; i < ids->n; i++) {
        if (i > 0)
            strcat(out, ":");
        strcat(out, name_of(table, ids->v[i]));
    }
    return out;
}

/* The negotiated group's codepoint. */
static int group_id(SSL *ssl)
{
    int nid = SSL_get_negotiated_group(ssl);
    const char *name;
    const struct named *g;

    if (nid & TLSEXT_nid_unknown)
        return nid & 0xffff;
    name = SSL_group_to_name(ssl, nid);
    if (name == NULL)
        return 0;
    for (g = GROUPS; g->name != NULL; g++)
        if (OPENSSL_strcasecmp(g->name, name) == 0)
            return g->id;
    if (OPENSSL_strcasecmp(name, "secp256r1") == 0 || OPENSSL_strcasecmp(name, "prime256v1") == 0)
        return 23;
    if (OPENSSL_strcasecmp(name, "secp384r1") == 0)
        return 24;
    if (OPENSSL_strcasecmp(name, "secp521r1") == 0)
        return 25;
    return 0;
}

/* ---- Connection setup ---- */

static SSL_CTX *new_ctx(int dtls)
{
    SSL_CTX *ctx = SSL_CTX_new(dtls ? DTLS_method() : TLS_method());

    if (ctx == NULL)
        return NULL;
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
    SSL_CTX_sess_set_new_cb(ctx, new_session_callback);
    SSL_CTX_set_info_callback(ctx, info_callback);
    SSL_CTX_set_cert_verify_callback(ctx, verify_callback, NULL);
    SSL_CTX_set_client_hello_cb(ctx, client_hello_callback, NULL);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_callback, NULL);
    SSL_CTX_set_next_protos_advertised_cb(ctx, npn_advertise_callback, NULL);
    SSL_CTX_set_tlsext_status_cb(ctx, status_callback);
    return ctx;
}

static int load_credential(SSL *ssl, const struct config *c)
{
    int i;

    if (c->cert_file.set && SSL_use_certificate_chain_file(ssl, (char *)c->cert_file.data) != 1)
        return 0;
    if (c->key_file.set
        && SSL_use_PrivateKey_file(ssl, (char *)c->key_file.data, SSL_FILETYPE_PEM) != 1)
        return 0;
    for (i = 0; i < c->ncreds; i++) {
        if (!c->cred_cert[i].set || !c->cred_key[i].set)
            unimplemented("a credential without a certificate and key");
        if (SSL_use_certificate_chain_file(ssl, (char *)c->cred_cert[i].data) != 1
            || SSL_use_PrivateKey_file(ssl, (char *)c->cred_key[i].data, SSL_FILETYPE_PEM) != 1)
            return 0;
    }
    return 1;
}

/*
 * The credential this end used (-expect-selected-credential): the index of the credential whose
 * certificate is the one SSL_get_certificate reports, else -1 (the legacy one, or none).
 */
static int selected_credential(SSL *ssl, const struct config *c)
{
    X509 *used = SSL_get_certificate(ssl);
    int i;

    if (used == NULL)
        return -1;
    for (i = 0; i < c->ncreds; i++) {
        BIO *in = BIO_new_file((char *)c->cred_cert[i].data, "r");
        X509 *x = in != NULL ? PEM_read_bio_X509(in, NULL, NULL, NULL) : NULL;
        int same = x != NULL && X509_cmp(x, used) == 0;

        X509_free(x);
        BIO_free(in);
        if (same)
            return i;
    }
    return -1;
}

static SSL *new_ssl(SSL_CTX *ctx, const struct config *c, struct state *st, SSL_SESSION *session)
{
    SSL *ssl = SSL_new(ctx);
    char cipher_list[1024];
    int mode = SSL_VERIFY_NONE;

    if (ssl == NULL || !SSL_set_ex_data(ssl, g_state_index, st))
        return NULL;
    if (c->is_server)
        SSL_set_accept_state(ssl);
    else
        SSL_set_connect_state(ssl);

    /* The runner expects every cipher and TLS 1.0 and 1.1, as BoringSSL's shim offers. */
    snprintf(cipher_list, sizeof(cipher_list), "%s:@SECLEVEL=0",
             c->cipher.set ? (char *)c->cipher.data : "ALL");
    if (!SSL_set_cipher_list(ssl, cipher_list))
        return NULL;
    if (c->cipher.set)
        SSL_set_options(ssl, SSL_OP_CIPHER_SERVER_PREFERENCE);
    if (c->tls13_ciphers.set && !SSL_set_ciphersuites(ssl, (char *)c->tls13_ciphers.data))
        return NULL;
    if (!SSL_set_min_proto_version(ssl, c->dtls ? DTLS1_VERSION : TLS1_VERSION))
        return NULL;
    if (c->mtu != 0) {
        SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
        if (!SSL_set_mtu(ssl, c->mtu))
            return NULL;
    }
    if (c->min_version != 0 && !SSL_set_min_proto_version(ssl, c->min_version))
        return NULL;
    if (c->max_version_set && !SSL_set_max_proto_version(ssl, c->max_version))
        return NULL;
    if (c->no_tls13)
        SSL_set_options(ssl, SSL_OP_NO_TLSv1_3);
    if (c->no_tls12)
        SSL_set_options(ssl, SSL_OP_NO_TLSv1_2);
    if (c->no_tls11)
        SSL_set_options(ssl, SSL_OP_NO_TLSv1_1);
    if (c->no_tls1)
        SSL_set_options(ssl, SSL_OP_NO_TLSv1);
    if (c->no_ticket)
        SSL_set_options(ssl, SSL_OP_NO_TICKET);
    if (c->server_preference)
        SSL_set_options(ssl, SSL_OP_CIPHER_SERVER_PREFERENCE);
    /* BoringSSL connects to servers without renegotiation_info unless told not to. */
    if (c->no_legacy_server_connect)
        SSL_clear_options(ssl, SSL_OP_LEGACY_SERVER_CONNECT);
    else
        SSL_set_options(ssl, SSL_OP_LEGACY_SERVER_CONNECT);
    /* A BoringSSL client refuses renegotiation by default. */
    if (!c->is_server && !c->renegotiate_freely && !c->renegotiate_once)
        SSL_set_options(ssl, SSL_OP_NO_RENEGOTIATION);
    SSL_set_options(ssl, SSL_OP_IGNORE_UNEXPECTED_EOF);
    if (c->fallback_scsv)
        SSL_set_mode(ssl, SSL_MODE_SEND_FALLBACK_SCSV);
    if (c->partial_write)
        SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    if (!c->check_close_notify)
        SSL_set_quiet_shutdown(ssl, 1);
    if (c->curves.n > 0) {
        char *list = list_of(GROUPS, &c->curves);
        int ok = SSL_set1_groups_list(ssl, list);

        free(list);
        if (!ok)
            return NULL;
    }
    /*
     * What this end accepts from the peer and what it signs with: a client's signature_algorithms
     * and a server's choice come from the sigalgs list, a server's CertificateRequest and a
     * client's choice from the client sigalgs list.
     */
    if (c->verify_prefs.n > 0) {
        char *list = list_of(SIGALGS, &c->verify_prefs);
        int ok = c->is_server ? SSL_set1_client_sigalgs_list(ssl, list)
                              : SSL_set1_sigalgs_list(ssl, list);

        free(list);
        if (!ok)
            return NULL;
    }
    if (c->signing_prefs.n > 0) {
        char *list = list_of(SIGALGS, &c->signing_prefs);
        int ok = c->is_server ? SSL_set1_sigalgs_list(ssl, list)
                              : SSL_set1_client_sigalgs_list(ssl, list);

        free(list);
        if (!ok)
            return NULL;
    }
    SSL_set_msg_callback(ssl, msg_callback);
    if (c->require_any_client_certificate)
        mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    if (c->verify_peer)
        mode = SSL_VERIFY_PEER;
    SSL_set_verify(ssl, mode, NULL);
    if (c->host_name.set && !SSL_set_tlsext_host_name(ssl, (char *)c->host_name.data))
        return NULL;
    if (c->advertise_alpn.set
        && SSL_set_alpn_protos(ssl, c->advertise_alpn.data, (unsigned int)c->advertise_alpn.len)
               != 0)
        return NULL;
    if (c->psk.set) {
        SSL_set_psk_client_callback(ssl, psk_client_callback);
        SSL_set_psk_server_callback(ssl, psk_server_callback);
    }
    if (c->enable_ocsp_stapling && !SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp))
        return NULL;
    if (c->max_send_fragment != 0 && !SSL_set_max_send_fragment(ssl, c->max_send_fragment))
        return NULL;
    if (c->max_cert_list != 0)
        SSL_set_max_cert_list(ssl, c->max_cert_list);
    if (c->session_id_context.set
        && !SSL_set_session_id_context(ssl, c->session_id_context.data,
                                       (unsigned int)c->session_id_context.len))
        return NULL;
    /* A client offers NPN only with a select callback, which only the context holds. */
    SSL_CTX_set_next_proto_select_cb(
        ctx, c->select_next_proto.set || c->select_empty_next_proto ? npn_select_callback : NULL,
        NULL);
    SSL_CTX_set_client_cert_cb(ctx, c->use_old_client_cert_callback ? client_cert_callback : NULL);
    if (SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, c->use_ticket_callback ? ticket_key_callback
                                                                         : NULL)
        != 1)
        return NULL;
    SSL_set_cert_cb(ssl, cert_callback, NULL);
    if (!c->use_old_client_cert_callback && !load_credential(ssl, c))
        return NULL;
    if (session != NULL && !SSL_set_session(ssl, session))
        return NULL;
    return ssl;
}

static int connect_to_runner(const struct config *c)
{
    int fd, one = 1;
    unsigned char id[8];
    size_t i;

    fd = socket(c->ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (c->ipv6) {
        struct sockaddr_in6 sin6;

        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons((uint16_t)c->port);
        inet_pton(AF_INET6, "::1", &sin6.sin6_addr);
        if (connect(fd, (struct sockaddr *)&sin6, sizeof(sin6)) != 0) {
            perror("connect");
            close(fd);
            return -1;
        }
    } else {
        struct sockaddr_in sin;

        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons((uint16_t)c->port);
        inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);
        if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
            perror("connect");
            close(fd);
            return -1;
        }
    }
    for (i = 0; i < 8; i++)
        id[i] = (unsigned char)(c->shim_id >> (8 * i));
    if (write(fd, id, sizeof(id)) != (ssize_t)sizeof(id)) {
        perror("write");
        close(fd);
        return -1;
    }
    return fd;
}

/* ---- I/O ---- */

static int do_read(SSL *ssl, unsigned char *out, size_t max)
{
    const struct config *c = get_state(ssl)->config;
    int ret;

    do {
        if (c->peek_then_read) {
            unsigned char *peeked = xmalloc(max);
            int n;

            do {
                ret = SSL_peek(ssl, out, (int)max);
            } while (retry_async(ssl, ret));
            if (ret <= 0) {
                free(peeked);
                return ret;
            }
            /* A second peek returns the same; then the read consumes it. */
            do {
                n = SSL_peek(ssl, peeked, ret);
            } while (retry_async(ssl, n));
            if (n != ret || memcmp(peeked, out, (size_t)ret) != 0) {
                fprintf(stderr, "First and second SSL_peek did not match.\n");
                free(peeked);
                return -1;
            }
            do {
                n = SSL_read(ssl, peeked, ret);
            } while (retry_async(ssl, n));
            if (n != ret || memcmp(peeked, out, (size_t)ret) != 0) {
                fprintf(stderr, "SSL_peek and SSL_read did not match.\n");
                free(peeked);
                return -1;
            }
            free(peeked);
            return ret;
        }
        ret = SSL_read(ssl, out, (int)max);
    } while (retry_async(ssl, ret));
    return ret;
}

static int write_all(SSL *ssl, const void *in, size_t len)
{
    const unsigned char *p = in;
    int ret;

    if (len == 0) {
        do {
            ret = SSL_write(ssl, p, 0);
        } while (retry_async(ssl, ret));
        return ret;
    }
    while (len > 0) {
        do {
            ret = SSL_write(ssl, p, (int)len);
        } while (retry_async(ssl, ret));
        if (ret <= 0)
            return ret;
        p += ret;
        len -= (size_t)ret;
    }
    return 1;
}

static int do_shutdown(SSL *ssl)
{
    int ret;

    do {
        ret = SSL_shutdown(ssl);
    } while (retry_async(ssl, ret));
    return ret;
}

/* ---- Checks after the handshake ---- */

static int same_bytes(const struct bytes *want, const unsigned char *got, size_t len)
{
    size_t wlen = want->set ? want->len : 0;

    return wlen == len && (len == 0 || memcmp(want->data, got, len) == 0);
}

static int check_peer_cert(SSL *ssl, const struct config *c)
{
    STACK_OF(X509) *want = sk_X509_new_null(), *got;
    X509 *x, *leaf;
    BIO *in;
    int i, ok = 0;

    in = BIO_new_file((char *)c->expect_peer_cert_file.data, "r");
    if (in == NULL || want == NULL)
        goto end;
    while ((x = PEM_read_bio_X509(in, NULL, NULL, NULL)) != NULL)
        sk_X509_push(want, x);
    ERR_clear_error();
    if (sk_X509_num(want) == 0)
        goto end;
    /* Clients report the chain with the leaf, servers without. */
    if (c->is_server)
        X509_free(sk_X509_shift(want));
    leaf = SSL_get1_peer_certificate(ssl);
    if (leaf == NULL) {
        fprintf(stderr, "No peer certificate.\n");
        goto end;
    }
    X509_free(leaf);
    got = SSL_get_peer_cert_chain(ssl);
    if (sk_X509_num(got) != sk_X509_num(want)) {
        fprintf(stderr, "Received a chain of length %d instead of %d.\n", sk_X509_num(got),
                sk_X509_num(want));
        goto end;
    }
    for (i = 0; i < sk_X509_num(got); i++)
        if (X509_cmp(sk_X509_value(got, i), sk_X509_value(want, i)) != 0) {
            fprintf(stderr, "Chain certificate %d did not match.\n", i + 1);
            goto end;
        }
    ok = 1;
end:
    BIO_free(in);
    sk_X509_pop_free(want, X509_free);
    return ok;
}

static int check_handshake(SSL *ssl, int is_resume)
{
    struct state *st = get_state(ssl);
    const struct config *c = st->config;
    const unsigned char *p;
    unsigned int plen;

    if (c->expect_ocsp_response.set) {
        unsigned char *resp = NULL;
        long n = SSL_get_tlsext_status_ocsp_resp(ssl, &resp);

        if (n < 0 || !same_bytes(&c->expect_ocsp_response, resp, (size_t)n)) {
            fprintf(stderr, "OCSP response mismatch\n");
            return 0;
        }
    }
    if (c->expect_verify_result) {
        long want = c->verify_fail ? X509_V_ERR_APPLICATION_VERIFICATION : X509_V_OK;

        if (SSL_get_verify_result(ssl) != want) {
            fprintf(stderr, "Wrong certificate verification result\n");
            return 0;
        }
    }
    if (c->expect_peer_cert_file.set && !check_peer_cert(ssl, c))
        return 0;
    if (c->expect_selected_credential_set) {
        int used = selected_credential(ssl, c);

        if (used != c->expect_selected_credential) {
            fprintf(stderr, "Credential %d was used, wanted %d\n", used,
                    c->expect_selected_credential);
            return 0;
        }
    }
    if (c->expect_no_peer_cert) {
        X509 *peer = SSL_get1_peer_certificate(ssl);

        if (peer != NULL) {
            X509_free(peer);
            fprintf(stderr, "Received peer certificate when none was expected.\n");
            return 0;
        }
    }
    if (SSL_get_current_cipher(ssl) == NULL) {
        fprintf(stderr, "null cipher after handshake\n");
        return 0;
    }
    if (c->expect_version != 0 && SSL_version(ssl) != c->expect_version) {
        fprintf(stderr, "want version %04x, got %04x\n", (unsigned)c->expect_version,
                (unsigned)SSL_version(ssl));
        return 0;
    }
    if (!!SSL_session_reused(ssl) != (is_resume && !c->expect_session_miss)) {
        fprintf(stderr, "session unexpectedly was%s reused\n",
                SSL_session_reused(ssl) ? "" : " not");
        return 0;
    }
    if (!st->handshake_done) {
        fprintf(stderr, "handshake was not completed\n");
        return 0;
    }
    if (!c->is_server) {
        int expect_new = !c->expect_no_session && !SSL_session_reused(ssl)
                         && SSL_version(ssl) < TLS1_3_VERSION;

        if (expect_new != st->got_new_session) {
            fprintf(stderr, "new session was%s cached, but we expected the opposite\n",
                    st->got_new_session ? "" : " not");
            return 0;
        }
    }
    if (!is_resume) {
        if (c->expect_session_id && !st->got_new_session) {
            fprintf(stderr, "session was not cached on the server.\n");
            return 0;
        }
        if (c->expect_no_session_id && st->got_new_session) {
            fprintf(stderr, "session was unexpectedly cached on the server.\n");
            return 0;
        }
    }
    if (c->is_server && !st->early_callback_called) {
        fprintf(stderr, "early callback not called\n");
        return 0;
    }
    if (c->expect_server_name.set) {
        const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

        if (name == NULL || strcmp(name, (char *)c->expect_server_name.data) != 0) {
            fprintf(stderr, "servername mismatch (got %s; want %s)\n", name ? name : "(null)",
                    (char *)c->expect_server_name.data);
            return 0;
        }
    }
    if (c->expect_no_server_name && SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name) != NULL) {
        fprintf(stderr, "Unexpected server name.\n");
        return 0;
    }
    if (c->expect_next_proto.set || c->expect_no_next_proto) {
        SSL_get0_next_proto_negotiated(ssl, &p, &plen);
        if (!same_bytes(&c->expect_next_proto, p, plen)) {
            fprintf(stderr, "negotiated next proto mismatch\n");
            return 0;
        }
    }
    SSL_get0_alpn_selected(ssl, &p, &plen);
    if (!same_bytes(c->is_server ? &c->select_alpn : &c->expect_alpn, p, plen)) {
        fprintf(stderr, "negotiated alpn proto mismatch\n");
        return 0;
    }
    if (c->expect_extended_master_secret && !SSL_get_extms_support(ssl)) {
        fprintf(stderr, "No EMS for connection when expected\n");
        return 0;
    }
    if (c->expect_secure_renegotiation && !SSL_get_secure_renegotiation_support(ssl)) {
        fprintf(stderr, "No secure renegotiation for connection when expected\n");
        return 0;
    }
    if (c->expect_no_secure_renegotiation && SSL_get_secure_renegotiation_support(ssl)) {
        fprintf(stderr, "Secure renegotiation unexpectedly negotiated for connection\n");
        return 0;
    }
    if (c->expect_curve_id != 0 && group_id(ssl) != c->expect_curve_id) {
        fprintf(stderr, "curve_id was %04x, wanted %04x\n", (unsigned)group_id(ssl),
                (unsigned)c->expect_curve_id);
        return 0;
    }
    if (c->expect_peer_signature_algorithm != 0) {
        const char *name = NULL;
        const struct named *a;
        int id = 0;

        if (SSL_get0_peer_signature_name(ssl, &name) && name != NULL)
            for (a = SIGALGS; a->name != NULL; a++)
                if (strcmp(a->name, name) == 0)
                    id = a->id;
        if (id != c->expect_peer_signature_algorithm) {
            fprintf(stderr, "Peer signature algorithm was %04x, wanted %04x.\n", (unsigned)id,
                    (unsigned)c->expect_peer_signature_algorithm);
            return 0;
        }
    }
    if (c->expect_hrr && !st->saw_hrr) {
        fprintf(stderr, "No HRR was sent or received.\n");
        return 0;
    }
    if (c->expect_no_hrr && st->saw_hrr) {
        fprintf(stderr, "HRR was sent or received.\n");
        return 0;
    }
    if (c->expect_cipher != 0
        && SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(ssl)) != c->expect_cipher) {
        fprintf(stderr, "Cipher ID was %04x, wanted %04x\n",
                SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(ssl)),
                (unsigned)c->expect_cipher);
        return 0;
    }
    return 1;
}

/* tls-unique (RFC 5929): the first Finished message of the latest handshake. */
static int tls_unique(SSL *ssl, unsigned char *out, size_t max)
{
    int ours_first = SSL_session_reused(ssl) ? SSL_is_server(ssl) : !SSL_is_server(ssl);

    return (int)(ours_first ? SSL_get_finished(ssl, out, max)
                            : SSL_get_peer_finished(ssl, out, max));
}

static int do_exchange(SSL **out_session_owner, SSL *ssl, int is_resume)
{
    struct state *st = get_state(ssl);
    const struct config *c = st->config;
    int ret;

    (void)out_session_owner;
    if (!c->implicit_handshake) {
        do {
            ret = SSL_do_handshake(ssl);
        } while (retry_async(ssl, ret));
        if (ret != 1 || !check_handshake(ssl, is_resume))
            return 0;
        if (c->handshake_twice) {
            do {
                ret = SSL_do_handshake(ssl);
            } while (retry_async(ssl, ret));
            if (ret != 1)
                return 0;
        }
        if (c->no_op_extra_handshake && SSL_do_handshake(ssl) != 1) {
            fprintf(stderr, "Extra SSL_do_handshake was not a no-op.\n");
            return 0;
        }
        st->got_new_session = 0;
    }

    if (c->export_keying_material > 0) {
        size_t n = (size_t)c->export_keying_material;
        unsigned char *out = xmalloc(n);
        int ok = SSL_export_keying_material(
            ssl, out, n, c->export_label.set ? (char *)c->export_label.data : "",
            c->export_label.len, c->export_context.data, c->export_context.len,
            c->use_export_context);

        if (!ok) {
            fprintf(stderr, "failed to export keying material\n");
            free(out);
            return 0;
        }
        ret = write_all(ssl, out, n);
        free(out);
        if (ret <= 0)
            return 0;
    }
    if (c->tls_unique) {
        unsigned char buf[64];

        if (tls_unique(ssl, buf, sizeof(buf)) != 12) {
            fprintf(stderr, "expected 12 bytes of tls-unique\n");
            return 0;
        }
        if (write_all(ssl, buf, 12) <= 0)
            return 0;
    }

    if (c->write_different_record_sizes) {
        static const size_t sizes[] = {0, 1, 255, 256, 257, 16383, 16384, 16385, 32767, 32768,
                                       32769};
        unsigned char *buf = xmalloc(32769);
        size_t i;

        memset(buf, 0x42, 32769);
        for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
            if (write_all(ssl, buf, sizes[i]) < 0) {
                free(buf);
                return 0;
            }
        free(buf);
    } else {
        if (c->shim_writes_first) {
            const char *msg = c->shim_initial_write.set ? (char *)c->shim_initial_write.data
                                                        : "hello";
            size_t len = c->shim_initial_write.set ? c->shim_initial_write.len : 5;
            int i, n = c->repeat_shim_initial_write > 0 ? c->repeat_shim_initial_write : 1;

            for (i = 0; i < n; i++)
                if (write_all(ssl, msg, len) <= 0)
                    return 0;
        }
        if (!c->shim_shuts_down) {
            /* TLS reads 512 octets at a time, so records span reads; DTLS a whole one. */
            size_t size = c->read_size > 0 ? (size_t)c->read_size : c->dtls ? 16384 : 512;
            unsigned char *buf = xmalloc(size);

            for (;;) {
                int n, err, i;

                if (c->key_update_before_read && !SSL_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED)) {
                    fprintf(stderr, "SSL_key_update failed.\n");
                    free(buf);
                    return 0;
                }
                n = do_read(ssl, buf, size);
                err = SSL_get_error(ssl, n);
                if (getenv("BOGO_SHIM_DEBUG") != NULL)
                    fprintf(stderr, "read %d (error %d): %02x %02x\n", n, err,
                            n > 0 ? buf[0] : 0, n > 1 ? buf[1] : 0);
                if (err == SSL_ERROR_ZERO_RETURN || (n == 0 && err == SSL_ERROR_SYSCALL))
                    break;
                if (err != SSL_ERROR_NONE || n <= 0) {
                    free(buf);
                    return 0;
                }
                if (!st->handshake_done) {
                    fprintf(stderr, "handshake was not completed after SSL_read\n");
                    free(buf);
                    return 0;
                }
                if (c->key_update && !SSL_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED)) {
                    fprintf(stderr, "SSL_key_update failed.\n");
                    free(buf);
                    return 0;
                }
                for (i = 0; i < n; i++)
                    buf[i] ^= 0xff;
                if (write_all(ssl, buf, (size_t)n) <= 0) {
                    free(buf);
                    return 0;
                }
            }
            free(buf);
        }
    }

    if (!c->is_server && SSL_version(ssl) < TLS1_3_VERSION && !c->implicit_handshake
        && st->got_new_session) {
        fprintf(stderr, "new session was established after the handshake\n");
        return 0;
    }
    if (!c->is_server && SSL_version(ssl) >= TLS1_3_VERSION) {
        int expect_new = !c->expect_no_session && !c->shim_shuts_down;

        if (expect_new != st->got_new_session) {
            fprintf(stderr, "new session was%s cached, but we expected the opposite\n",
                    st->got_new_session ? "" : " not");
            return 0;
        }
    }

    ret = do_shutdown(ssl);
    if (c->shim_shuts_down && c->check_close_notify) {
        if (ret != 0) {
            fprintf(stderr, "Unexpected SSL_shutdown result: %d != 0\n", ret);
            return 0;
        }
        ret = do_shutdown(ssl);
    }
    if (ret != 1) {
        fprintf(stderr, "Unexpected SSL_shutdown result: %d != 1\n", ret);
        return 0;
    }
    if (SSL_total_renegotiations(ssl) != c->expect_total_renegotiations) {
        fprintf(stderr, "Expected %d renegotiations, got %ld\n", c->expect_total_renegotiations,
                SSL_total_renegotiations(ssl));
        return 0;
    }
    return 1;
}

/* ---- The failure log (BOGO_SHIM_LOG) ---- */

static char g_log_path[4096];
static char g_log_args[8192];

static void log_init(int argc, char **argv)
{
    const char *dir = getenv("BOGO_SHIM_LOG");
    unsigned long long h = 1469598103934665603ULL;
    int i;

    if (dir == NULL)
        return;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i], *slash = strrchr(a, '/');

        if ((strcmp(a, "-port") == 0 || strcmp(a, "-shim-id") == 0) && i + 1 < argc) {
            i++;
            continue;
        }
        if (slash != NULL)
            a = slash + 1;
        if (strlen(g_log_args) + strlen(a) + 2 < sizeof(g_log_args)) {
            strcat(g_log_args, " ");
            strcat(g_log_args, a);
        }
        for (; *a; a++)
            h = (h ^ (unsigned char)*a) * 1099511628211ULL;
        h = (h ^ 0xff) * 1099511628211ULL;
    }
    snprintf(g_log_path, sizeof(g_log_path), "%s/%016llx", dir, h);
}

/* The first queued error's library and reason, for the comparison. */
static void log_failure(int conn)
{
    unsigned long e = ERR_peek_error();
    FILE *f;
    const char *reason;

    if (g_log_path[0] == 0 || (f = fopen(g_log_path, "a")) == NULL)
        return;
    reason = ERR_reason_error_string(e);
    if (ftell(f) == 0)
        fprintf(f, "args:%s\n", g_log_args);
    fprintf(f, "connection %d: %d:%d %s\n", conn, ERR_GET_LIB(e), ERR_GET_REASON(e),
            reason != NULL ? reason : "-");
    fclose(f);
}

int main(int argc, char **argv)
{
    static struct config initial, resume, retry;
    SSL_CTX *ctx;
    SSL_SESSION *session = NULL;
    int i;

    signal(SIGPIPE, SIG_IGN);
    parse(argc, argv, &initial, &resume, &retry);
    if (initial.is_handshaker_supported) {
        printf("No\n");
        return 0;
    }
    log_init(argc, argv);
    g_state_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    ctx = new_ctx(initial.dtls);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    for (i = 0; i <= initial.resume_count; i++) {
        int is_resume = i > 0, fd, ok;
        const struct config *c = is_resume ? &resume : &initial;
        struct state st;
        SSL *ssl;
        BIO *bio;

        if (is_resume && !c->is_server && session == NULL) {
            fprintf(stderr, "No session to offer.\n");
            return 1;
        }
        memset(&st, 0, sizeof(st));
        st.config = c;
        ssl = new_ssl(ctx, c, &st, session);
        SSL_SESSION_free(session);
        session = NULL;
        if (ssl == NULL) {
            fprintf(stderr, "Connection %d failed.\n", i + 1);
            log_failure(i + 1);
            ERR_print_errors_fp(stderr);
            return 1;
        }
        fd = connect_to_runner(c);
        if (fd < 0)
            return 1;
        bio = BIO_new_socket(fd, BIO_NOCLOSE);
        if (c->dtls) {
            BIO *packeted = packeted_bio_new();
            struct packeted *d;

            if (packeted == NULL)
                return 1;
            d = BIO_get_data(packeted);
            d->ssl = ssl;
            BIO_push(packeted, bio);
            bio = packeted;
        }
        if (c->async) {
            BIO *async = async_bio_new();
            struct async_quota *q;

            if (async == NULL)
                return 1;
            q = BIO_get_data(async);
            q->datagram = c->dtls;
            BIO_push(async, bio);
            st.async_bio = async;
            bio = async;
        }
        SSL_set_bio(ssl, bio, bio);

        ok = do_exchange(NULL, ssl, is_resume);
        if (!ok) {
            int err = SSL_get_error(ssl, -1);

            if (err != SSL_ERROR_NONE)
                fprintf(stderr, "SSL error: %d\n", err);
            fprintf(stderr, "Connection %d failed.\n", i + 1);
            log_failure(i + 1);
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(fd);
            return 1;
        }
        session = st.new_session;
        st.new_session = NULL;
        SSL_free(ssl);
        shutdown(fd, SHUT_WR);
        {
            char drain[256];

            while (read(fd, drain, sizeof(drain)) > 0)
                ;
        }
        close(fd);
    }
    SSL_SESSION_free(session);
    SSL_CTX_free(ctx);
    return 0;
}
