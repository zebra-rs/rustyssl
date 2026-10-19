/*
 * Conformance test for the ENGINE API (engine.h, ENGINE_add(3)), in TAP format: the engine
 * list, the built-in engines, engines an application makes, control commands, the method
 * tables and defaults, key loaders, and the dynamic engine's commands.
 *
 * The engines directory is pointed at one that doesn't exist, so no engine module is found on
 * either library; source locations and dlopen's messages in the errors aren't printed.
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The queued errors: library, function and reason, and the data of ENGINE's own. */
static void errors(const char *who)
{
    unsigned long e;
    const char *file, *func, *data;
    int line, flags;

    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        int engine = ERR_GET_LIB(e) == ERR_LIB_ENGINE;

        printf("  %s: lib %d %s: %s%s%s\n", who, ERR_GET_LIB(e), func,
               ERR_reason_error_string(e), engine && (flags & ERR_TXT_STRING) ? " / " : "",
               engine && (flags & ERR_TXT_STRING) ? data : "");
    }
}

static void list(const char *what)
{
    ENGINE *e;

    printf("  %s:", what);
    for (e = ENGINE_get_first(); e != NULL; e = ENGINE_get_next(e))
        printf(" %s", ENGINE_get_id(e));
    printf("\n");
}

static int destroyed, inits, finishes, ctrls, init_result = 1;
static long last_i;

static int app_destroy(ENGINE *e)
{
    (void)e;
    destroyed++;
    return 1;
}

static int app_init(ENGINE *e)
{
    (void)e;
    inits++;
    return init_result;
}

static int app_finish(ENGINE *e)
{
    (void)e;
    finishes++;
    return 1;
}

#define CMD_COUNT (ENGINE_CMD_BASE)
#define CMD_NAME (ENGINE_CMD_BASE + 1)
#define CMD_GO (ENGINE_CMD_BASE + 2)
#define CMD_RAW (ENGINE_CMD_BASE + 3)

static const ENGINE_CMD_DEFN app_cmds[] = {
    { CMD_COUNT, "COUNT", "A number", ENGINE_CMD_FLAG_NUMERIC },
    { CMD_NAME, "NAME", NULL, ENGINE_CMD_FLAG_STRING },
    { CMD_GO, "GO", "No input", ENGINE_CMD_FLAG_NO_INPUT },
    { CMD_RAW, "RAW", "Internal", ENGINE_CMD_FLAG_INTERNAL },
    { 0, NULL, NULL, 0 }
};

static int app_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    (void)e;
    (void)f;
    ctrls++;
    last_i = i;
    if (cmd == CMD_NAME)
        printf("  ctrl NAME %s\n", (const char *)p);
    else
        printf("  ctrl %d %ld %s\n", cmd, i, p == NULL ? "NULL" : "p");
    return cmd == CMD_GO ? 1 : (cmd == CMD_COUNT ? (int)(i > 0) : 1);
}

static int digest_nids[] = { NID_sha256, NID_sha1 };

static int app_digests(ENGINE *e, const EVP_MD **md, const int **nids, int nid)
{
    (void)e;
    if (md == NULL) {
        *nids = digest_nids;
        return 2;
    }
    if (nid == NID_sha256) {
        *md = EVP_sha256();
        return 1;
    }
    if (nid == NID_sha1) {
        *md = EVP_sha1();
        return 1;
    }
    *md = NULL;
    return 0;
}

static int cipher_nids[] = { NID_aes_128_cbc };

static int app_ciphers(ENGINE *e, const EVP_CIPHER **c, const int **nids, int nid)
{
    (void)e;
    if (c == NULL) {
        *nids = cipher_nids;
        return 1;
    }
    *c = nid == NID_aes_128_cbc ? EVP_aes_128_cbc() : NULL;
    return *c != NULL;
}

#define TEST_PKEY_NID NID_hmac
static int pkey_nids[] = { TEST_PKEY_NID };
static int pkey_meth_calls;

static int app_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **m, const int **nids, int nid)
{
    static EVP_PKEY_METHOD *meth;

    (void)e;
    if (m == NULL) {
        *nids = pkey_nids;
        return 1;
    }
    if (nid != TEST_PKEY_NID) {
        *m = NULL;
        return 0;
    }
    pkey_meth_calls++;
    /* A fresh one each time it's asked for: the engine frees what it hands out at the end. */
    meth = EVP_PKEY_meth_new(TEST_PKEY_NID, 0);
    *m = meth;
    return meth != NULL;
}

static int asn1_nids[] = { NID_hmac };

static int app_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **m, const int **nids, int nid)
{
    static EVP_PKEY_ASN1_METHOD *ameth;

    (void)e;
    if (m == NULL) {
        *nids = asn1_nids;
        return 1;
    }
    if (nid != NID_hmac) {
        *m = NULL;
        return 0;
    }
    if (ameth == NULL)
        ameth = EVP_PKEY_asn1_new(NID_hmac, 0, "RUSTYSSL-TEST", "a test method");
    *m = ameth;
    return ameth != NULL;
}

static int loads;

static EVP_PKEY *app_load_key(ENGINE *e, const char *id, UI_METHOD *ui, void *cb)
{
    (void)e;
    (void)ui;
    (void)cb;
    loads++;
    printf("  load %s\n", id);
    return strcmp(id, "good") == 0 ? EVP_PKEY_new() : NULL;
}

static int app_client_cert(ENGINE *e, SSL *s, STACK_OF(X509_NAME) *ca, X509 **cert,
                           EVP_PKEY **key, STACK_OF(X509) **other, UI_METHOD *ui, void *cb)
{
    (void)e;
    (void)s;
    (void)ca;
    (void)cert;
    (void)key;
    (void)other;
    (void)ui;
    (void)cb;
    loads++;
    return 7;
}

static ENGINE *app_engine(const char *id)
{
    ENGINE *e = ENGINE_new();

    ENGINE_set_id(e, id);
    ENGINE_set_name(e, "rustyssl test engine");
    return e;
}

static void test_builtins(void)
{
    ENGINE *d1, *d2;

    list("at first");
    ENGINE_load_builtin_engines();
    list("built in");
    d1 = ENGINE_by_id("dynamic");
    d2 = ENGINE_by_id("dynamic");
    check(d1 != NULL && d2 != NULL && d1 != d2, "ENGINE_by_id(\"dynamic\") gives a copy each time");
    printf("  %s / %s / flags %d\n", ENGINE_get_id(d1), ENGINE_get_name(d1), ENGINE_get_flags(d1));
    check(ENGINE_init(d1) == 0, "the dynamic engine itself can't be initialized");
    errors("init dynamic");
    ENGINE_free(d1);
    ENGINE_free(d2);
    check(ENGINE_by_id("rustyssl-nosuch") == NULL, "a missing engine isn't found");
    errors("nosuch");
    check(ENGINE_by_id(NULL) == NULL, "ENGINE_by_id(NULL)");
    errors("NULL id");
}

static void test_dynamic_commands(void)
{
    ENGINE *d = ENGINE_by_id("dynamic");
    const ENGINE_CMD_DEFN *defn;
    int cmd;
    char buf[256];

    for (defn = ENGINE_get_cmd_defns(d); defn->cmd_num != 0; defn++)
        printf("  defn %u %s flags %u: %s\n", defn->cmd_num, defn->cmd_name, defn->cmd_flags,
               defn->cmd_desc);
    check(ENGINE_ctrl(d, ENGINE_CTRL_HAS_CTRL_FUNCTION, 0, NULL, NULL) == 1, "has a control function");
    for (cmd = ENGINE_ctrl(d, ENGINE_CTRL_GET_FIRST_CMD_TYPE, 0, NULL, NULL); cmd > 0;
         cmd = ENGINE_ctrl(d, ENGINE_CTRL_GET_NEXT_CMD_TYPE, cmd, NULL, NULL)) {
        int len = ENGINE_ctrl(d, ENGINE_CTRL_GET_NAME_LEN_FROM_CMD, cmd, NULL, NULL);
        int dlen = ENGINE_ctrl(d, ENGINE_CTRL_GET_DESC_LEN_FROM_CMD, cmd, NULL, NULL);

        ENGINE_ctrl(d, ENGINE_CTRL_GET_NAME_FROM_CMD, cmd, buf, NULL);
        printf("  cmd %d %s (%d) desc %d flags %d executable %d\n", cmd, buf, len, dlen,
               ENGINE_ctrl(d, ENGINE_CTRL_GET_CMD_FLAGS, cmd, NULL, NULL),
               ENGINE_cmd_is_executable(d, cmd));
        ENGINE_ctrl(d, ENGINE_CTRL_GET_DESC_FROM_CMD, cmd, buf, NULL);
        printf("    %s\n", buf);
    }
    check(ENGINE_ctrl(d, ENGINE_CTRL_GET_CMD_FROM_NAME, 0, (void *)"LOAD", NULL) == ENGINE_CMD_BASE + 6,
          "LOAD's number");
    check(ENGINE_ctrl(d, ENGINE_CTRL_GET_CMD_FROM_NAME, 0, (void *)"NOPE", NULL) == -1, "an unknown name");
    errors("unknown name");
    check(ENGINE_ctrl(d, ENGINE_CTRL_GET_CMD_FLAGS, 999, NULL, NULL) == -1, "an unknown number");
    errors("unknown number");
    check(ENGINE_ctrl_cmd_string(d, "LIST_ADD", "x", 0) == 0, "LIST_ADD x");
    errors("LIST_ADD x");
    check(ENGINE_ctrl_cmd_string(d, "LIST_ADD", "5", 0) == 0, "LIST_ADD 5");
    errors("LIST_ADD 5");
    check(ENGINE_ctrl_cmd_string(d, "LIST_ADD", NULL, 0) == 0, "LIST_ADD with no input");
    errors("LIST_ADD NULL");
    check(ENGINE_ctrl_cmd_string(d, "LOAD", "x", 0) == 0, "LOAD with input");
    errors("LOAD x");
    check(ENGINE_ctrl_cmd_string(d, "DIR_ADD", "", 0) == 0, "an empty DIR_ADD");
    errors("DIR_ADD");
    check(ENGINE_ctrl_cmd_string(d, "NOPE", "1", 1) == 1, "an optional command that's missing");
    check(ENGINE_ctrl_cmd_string(d, "NOPE", "1", 0) == 0, "a command that's missing");
    errors("NOPE");
    check(ENGINE_ctrl_cmd(d, "NOPE", 0, NULL, NULL, 0) == 0, "ENGINE_ctrl_cmd of a command that's missing");
    errors("ctrl_cmd NOPE");
    check(ENGINE_ctrl_cmd(d, "NO_VCHECK", 1, NULL, NULL, 0) == 1, "ENGINE_ctrl_cmd NO_VCHECK");
    check(ENGINE_ctrl_cmd_string(d, "LOAD", NULL, 0) == 0, "LOAD with nothing to load");
    errors("LOAD nothing");
    check(ENGINE_ctrl_cmd_string(d, "ID", "x", 0) == 0, "after that, the engine counts as loaded");
    errors("after LOAD nothing");
    ENGINE_free(d);
    d = ENGINE_by_id("dynamic");
    check(ENGINE_ctrl_cmd_string(d, "SO_PATH", "/nonexistent/rustyssl-engine.so", 0) == 1
          && ENGINE_ctrl_cmd_string(d, "LOAD", NULL, 0) == 0, "LOAD of a library that isn't there");
    errors("LOAD missing");
    check(ENGINE_ctrl_cmd_string(d, "SO_PATH", "rustyssl-bare", 0) == 1
          && ENGINE_ctrl_cmd_string(d, "LOAD", NULL, 0) == 0, "LOAD of a bare name (lib<name>, then nothing)");
    errors("LOAD bare");
    ENGINE_free(d);
    d = ENGINE_by_id("dynamic");
    check(ENGINE_ctrl_cmd_string(d, "ID", "rustyssl-x", 0) == 1
          && ENGINE_ctrl_cmd_string(d, "DIR_LOAD", "2", 0) == 1
          && ENGINE_ctrl_cmd_string(d, "DIR_ADD", "/nonexistent/a", 0) == 1
          && ENGINE_ctrl_cmd_string(d, "DIR_ADD", "/nonexistent/b/", 0) == 1
          && ENGINE_ctrl_cmd_string(d, "LOAD", NULL, 0) == 0, "LOAD from directories");
    errors("LOAD dirs");
    check(ENGINE_ctrl(d, 12345, 0, NULL, NULL) == 0, "a command the dynamic engine doesn't have");
    errors("12345");
    ENGINE_free(d);
}

static void test_app_engine(void)
{
    ENGINE *e = ENGINE_new(), *f, *g, *it;
    int destroyed0 = destroyed;

    check(e != NULL, "ENGINE_new");
    check(ENGINE_add(e) == 0, "an engine with no id isn't listed");
    errors("add without id");
    check(ENGINE_set_id(e, NULL) == 0 && ENGINE_set_name(e, NULL) == 0, "NULL id and name");
    errors("NULL id/name");
    check(ENGINE_set_id(e, "rustyssl-a") == 1 && ENGINE_set_name(e, "first") == 1, "id and name");
    check(ENGINE_set_destroy_function(e, app_destroy) == 1 && ENGINE_set_init_function(e, app_init) == 1
          && ENGINE_set_finish_function(e, app_finish) == 1 && ENGINE_set_ctrl_function(e, app_ctrl) == 1
          && ENGINE_set_flags(e, 0) == 1 && ENGINE_set_cmd_defns(e, app_cmds) == 1, "functions set");
    check(ENGINE_get_destroy_function(e) == app_destroy && ENGINE_get_init_function(e) == app_init
          && ENGINE_get_finish_function(e) == app_finish && ENGINE_get_ctrl_function(e) == app_ctrl
          && ENGINE_get_flags(e) == 0 && ENGINE_get_cmd_defns(e) == app_cmds, "functions read back");
    check(strcmp(ENGINE_get_id(e), "rustyssl-a") == 0 && strcmp(ENGINE_get_name(e), "first") == 0,
          "id and name read back");
    check(ENGINE_add(e) == 1, "listed");
    f = app_engine("rustyssl-b");
    g = app_engine("rustyssl-a");
    check(ENGINE_add(f) == 1, "a second listed");
    check(ENGINE_add(g) == 0, "a conflicting id isn't listed");
    errors("conflict");
    ENGINE_free(g);
    list("listed");
    it = ENGINE_get_last();
    printf("  last %s", ENGINE_get_id(it));
    it = ENGINE_get_prev(it);
    printf(", before it %s\n", ENGINE_get_id(it));
    ENGINE_free(it);
    check(ENGINE_get_next(NULL) == NULL && ENGINE_get_prev(NULL) == NULL, "neighbours of NULL");
    errors("NULL neighbours");
    it = ENGINE_by_id("rustyssl-a");
    check(it == e, "found by id (the listed engine itself)");
    ENGINE_free(it);

    /* Control commands. */
    check(ENGINE_ctrl(e, ENGINE_CTRL_GET_FIRST_CMD_TYPE, 0, NULL, NULL) == CMD_COUNT, "first command");
    check(ENGINE_ctrl_cmd_string(e, "COUNT", "3", 0) == 1 && last_i == 3, "a numeric command");
    check(ENGINE_ctrl_cmd_string(e, "COUNT", " -2", 0) == 0 && last_i == -2, "a negative number");
    check(ENGINE_ctrl_cmd_string(e, "NAME", "hello", 0) == 1, "a string command");
    check(ENGINE_ctrl_cmd_string(e, "GO", NULL, 0) == 1, "a command with no input");
    check(ENGINE_ctrl_cmd_string(e, "RAW", "x", 0) == 0, "an internal command isn't executable");
    errors("RAW");
    check(ENGINE_cmd_is_executable(e, CMD_RAW) == 0 && ENGINE_cmd_is_executable(e, CMD_GO) == 1,
          "ENGINE_cmd_is_executable");
    check(ENGINE_ctrl_cmd(e, "COUNT", 9, NULL, NULL, 0) == 1 && last_i == 9, "ENGINE_ctrl_cmd");
    check(ENGINE_ctrl(e, 99999, 5, NULL, NULL) == 1, "an engine's own command goes to its function");
    ENGINE_set_flags(e, ENGINE_FLAGS_MANUAL_CMD_CTRL);
    check(ENGINE_ctrl(e, ENGINE_CTRL_GET_FIRST_CMD_TYPE, 0, NULL, NULL) == 1,
          "with ENGINE_FLAGS_MANUAL_CMD_CTRL, the engine answers itself");
    ENGINE_set_flags(e, 0);
    printf("  %d control calls\n", ctrls);

    /* Initialization. */
    check(ENGINE_init(e) == 1 && inits == 1, "ENGINE_init runs init");
    check(ENGINE_init(e) == 1 && inits == 1, "a second ENGINE_init doesn't");
    check(ENGINE_finish(e) == 1 && finishes == 0, "ENGINE_finish of one of two");
    check(ENGINE_finish(e) == 1 && finishes == 1, "the last ENGINE_finish runs finish");
    init_result = 0;
    check(ENGINE_init(e) == 0 && inits == 2, "a failing init");
    errors("failed init");
    init_result = 1;
    check(ENGINE_init(NULL) == 0 && ENGINE_finish(NULL) == 1 && ENGINE_free(NULL) == 1
          && ENGINE_up_ref(NULL) == 0 && ENGINE_add(NULL) == 0 && ENGINE_remove(NULL) == 0,
          "NULL engines");
    errors("NULL engines");

    /* References. */
    check(ENGINE_up_ref(f) == 1 && ENGINE_free(f) == 1 && destroyed == destroyed0, "up_ref and free");
    ENGINE_set_destroy_function(f, app_destroy);
    check(ENGINE_remove(f) == 1 && destroyed == destroyed0, "removed, but still ours");
    check(ENGINE_remove(f) == 0, "not listed any more");
    errors("remove twice");
    ENGINE_free(f);
    check(destroyed == destroyed0 + 1, "destroyed at the last reference");
    list("after remove");

    /* By-id copies. */
    g = app_engine("rustyssl-copied");
    ENGINE_set_flags(g, ENGINE_FLAGS_BY_ID_COPY);
    ENGINE_add(g);
    it = ENGINE_by_id("rustyssl-copied");
    check(it != NULL && it != g && strcmp(ENGINE_get_name(it), "rustyssl test engine") == 0,
          "a BY_ID_COPY engine is copied");
    ENGINE_free(it);
    ENGINE_remove(g);
    ENGINE_free(g);

    ENGINE_free(e);
}

static void test_tables(void)
{
    ENGINE *e = app_engine("rustyssl-methods"), *d, *pe = NULL;
    const RSA_METHOD *rsa = RSA_get_default_method();
    const DSA_METHOD *dsa = DSA_get_default_method();
    const DH_METHOD *dh = DH_get_default_method();
    const EC_KEY_METHOD *ec = EC_KEY_get_default_method();
    const EVP_PKEY_ASN1_METHOD *am;
    int i0 = inits, f0 = finishes;

    check(ENGINE_get_default_RSA() == NULL && ENGINE_get_default_DSA() == NULL
          && ENGINE_get_default_DH() == NULL && ENGINE_get_default_EC() == NULL
          && ENGINE_get_default_RAND() == NULL, "no defaults at first");
    check(ENGINE_get_digest_engine(NID_sha256) == NULL && ENGINE_get_cipher_engine(NID_aes_128_cbc) == NULL
          && ENGINE_get_pkey_meth_engine(TEST_PKEY_NID) == NULL
          && ENGINE_get_pkey_asn1_meth_engine(NID_hmac) == NULL, "no engines for NIDs at first");
    ENGINE_set_init_function(e, app_init);
    ENGINE_set_finish_function(e, app_finish);
    check(ENGINE_register_RSA(e) == 1 && ENGINE_set_default_RSA(e) == 1 && inits == i0,
          "an engine without an RSA method registers nothing");
    check(ENGINE_set_RSA(e, rsa) == 1 && ENGINE_set_DSA(e, dsa) == 1 && ENGINE_set_DH(e, dh) == 1
          && ENGINE_set_EC(e, ec) == 1 && ENGINE_set_RAND(e, RAND_OpenSSL()) == 1, "methods set");
    check(ENGINE_get_RSA(e) == rsa && ENGINE_get_DSA(e) == dsa && ENGINE_get_DH(e) == dh
          && ENGINE_get_EC(e) == ec && ENGINE_get_RAND(e) == RAND_OpenSSL(), "methods read back");
    check(ENGINE_set_digests(e, app_digests) == 1 && ENGINE_set_ciphers(e, app_ciphers) == 1
          && ENGINE_set_pkey_meths(e, app_pkey_meths) == 1 && ENGINE_set_pkey_asn1_meths(e, app_asn1_meths) == 1,
          "callbacks set");
    check(ENGINE_get_digests(e) == app_digests && ENGINE_get_ciphers(e) == app_ciphers
          && ENGINE_get_pkey_meths(e) == app_pkey_meths && ENGINE_get_pkey_asn1_meths(e) == app_asn1_meths,
          "callbacks read back");
    check(ENGINE_get_digest(e, NID_sha256) == EVP_sha256() && ENGINE_get_cipher(e, NID_aes_128_cbc) == EVP_aes_128_cbc(),
          "the engine's digest and cipher");
    check(ENGINE_get_digest(e, NID_md5) == NULL && ENGINE_get_cipher(e, NID_des_cbc) == NULL,
          "ones it doesn't have");
    errors("unimplemented");
    check(ENGINE_get_pkey_meth(e, TEST_PKEY_NID) != NULL && ENGINE_get_pkey_meth(e, NID_rsa) == NULL,
          "the engine's public-key method");
    errors("unimplemented pkey");
    am = ENGINE_get_pkey_asn1_meth(e, NID_hmac);
    check(am != NULL && ENGINE_get_pkey_asn1_meth(e, NID_rsa) == NULL, "the engine's ASN.1 method");
    errors("unimplemented asn1");
    check(ENGINE_get_pkey_asn1_meth_str(e, "rustyssl-test", -1) == am
          && ENGINE_get_pkey_asn1_meth_str(e, "RUSTYSSL-TESTX", 13) == am
          && ENGINE_get_pkey_asn1_meth_str(e, "RUSTYSSL", -1) == NULL, "ASN.1 methods by PEM name");

    /* Registration: lookups initialize. */
    check(ENGINE_register_RSA(e) == 1 && inits == i0, "ENGINE_register_RSA doesn't initialize");
    d = ENGINE_get_default_RSA();
    check(d == e && inits == i0 + 1, "a lookup initializes the registered engine");
    ENGINE_finish(d);
    ENGINE_set_table_flags(ENGINE_TABLE_FLAG_NOINIT);
    check(ENGINE_get_table_flags() == ENGINE_TABLE_FLAG_NOINIT, "ENGINE_TABLE_FLAG_NOINIT");
    check(ENGINE_register_DSA(e) == 1 && ENGINE_get_default_DSA() == e, "an initialized engine is used");
    ENGINE_finish(e);
    ENGINE_set_table_flags(0);
    check(ENGINE_set_default_DH(e) == 1 && ENGINE_set_default_EC(e) == 1 && ENGINE_set_default_DSA(e) == 1,
          "set_default_DH, _EC and _DSA");
    d = ENGINE_get_default_DH();
    check(d == e, "the default DH engine");
    ENGINE_finish(d);
    d = ENGINE_get_default_EC();
    check(d == e, "the default EC engine");
    ENGINE_finish(d);
    check(ENGINE_set_default_digests(e) == 1 && ENGINE_set_default_ciphers(e) == 1
          && ENGINE_set_default_pkey_meths(e) == 1 && ENGINE_set_default_pkey_asn1_meths(e) == 1,
          "set_default for the NID tables");
    d = ENGINE_get_digest_engine(NID_sha1);
    check(d == e, "the digest engine for SHA-1");
    ENGINE_finish(d);
    check(ENGINE_get_digest_engine(NID_md5) == NULL, "none for MD5");
    d = ENGINE_get_cipher_engine(NID_aes_128_cbc);
    check(d == e, "the cipher engine");
    ENGINE_finish(d);
    d = ENGINE_get_pkey_meth_engine(TEST_PKEY_NID);
    check(d == e, "the public-key method engine");
    ENGINE_finish(d);
    d = ENGINE_get_pkey_asn1_meth_engine(NID_hmac);
    check(d == e, "the ASN.1 method engine");
    ENGINE_finish(d);
    check(ENGINE_pkey_asn1_find_str(&pe, "RUSTYSSL-TEST", 13) == am && pe == e,
          "ENGINE_pkey_asn1_find_str");
    ENGINE_free(pe);
    check(ENGINE_pkey_asn1_find_str(&pe, "nope", 4) == NULL && pe == NULL, "a name nobody has");
    check(ENGINE_register_digests(e) == 1 && ENGINE_register_ciphers(e) == 1
          && ENGINE_register_pkey_meths(e) == 1 && ENGINE_register_pkey_asn1_meths(e) == 1
          && ENGINE_register_DH(e) == 1 && ENGINE_register_EC(e) == 1 && ENGINE_register_RAND(e) == 1,
          "registering again");
    check(ENGINE_set_default_RAND(e) == 1, "set_default_RAND");
    d = ENGINE_get_default_RAND();
    check(d == e, "the default RAND engine");
    ENGINE_finish(d);
    ENGINE_unregister_RAND(e);
    check(ENGINE_get_default_RAND() == NULL, "RAND unregistered");

    /* The flags forms. */
    check(ENGINE_set_default(e, ENGINE_METHOD_RSA | ENGINE_METHOD_DSA) == 1, "ENGINE_set_default");
    check(ENGINE_set_default_string(e, "RSA,DIGESTS") == 1, "ENGINE_set_default_string");
    check(ENGINE_set_default_string(e, "ALL") == 1, "ENGINE_set_default_string ALL");
    ENGINE_unregister_RAND(e);
    check(ENGINE_set_default_string(e, "RSA,BOGUS") == 0, "an unknown name");
    errors("BOGUS");
    check(ENGINE_register_complete(e) == 1, "ENGINE_register_complete");
    ENGINE_unregister_RAND(e);

    /* Unregistering finishes the defaults. */
    ENGINE_unregister_RSA(e);
    ENGINE_unregister_DSA(e);
    ENGINE_unregister_DH(e);
    ENGINE_unregister_EC(e);
    ENGINE_unregister_digests(e);
    ENGINE_unregister_ciphers(e);
    ENGINE_unregister_pkey_meths(e);
    ENGINE_unregister_pkey_asn1_meths(e);
    check(ENGINE_get_default_RSA() == NULL && ENGINE_get_digest_engine(NID_sha256) == NULL
          && ENGINE_get_pkey_asn1_meth_engine(NID_hmac) == NULL, "unregistered");
    printf("  init %d finish %d\n", inits - i0, finishes - f0);

    /* The register_all forms go over the listed engines. */
    ENGINE_add(e);
    ENGINE_register_all_RSA();
    ENGINE_register_all_DSA();
    ENGINE_register_all_DH();
    ENGINE_register_all_EC();
    ENGINE_register_all_RAND();
    ENGINE_register_all_digests();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_pkey_meths();
    ENGINE_register_all_pkey_asn1_meths();
    check(ENGINE_register_all_complete() == 1, "ENGINE_register_all_complete");
    d = ENGINE_get_default_DSA();
    check(d == e, "registered from the list");
    ENGINE_finish(d);
    ENGINE_unregister_RSA(e);
    ENGINE_unregister_DSA(e);
    ENGINE_unregister_DH(e);
    ENGINE_unregister_EC(e);
    ENGINE_unregister_RAND(e);
    ENGINE_unregister_digests(e);
    ENGINE_unregister_ciphers(e);
    ENGINE_unregister_pkey_meths(e);
    ENGINE_unregister_pkey_asn1_meths(e);
    ENGINE_remove(e);
    printf("  public-key method asked for %s\n", pkey_meth_calls > 0 ? "yes" : "no");
    ENGINE_free(e);
}

static void test_loaders(void)
{
    ENGINE *e = app_engine("rustyssl-loader");
    EVP_PKEY *k;
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;

    check(ENGINE_load_private_key(e, "good", NULL, NULL) == NULL, "not initialized");
    errors("uninitialized");
    ENGINE_init(e);
    check(ENGINE_load_private_key(e, "good", NULL, NULL) == NULL
          && ENGINE_load_public_key(e, "good", NULL, NULL) == NULL
          && ENGINE_load_ssl_client_cert(e, NULL, NULL, &cert, &key, NULL, NULL, NULL) == 0,
          "no loaders");
    errors("no loaders");
    check(ENGINE_set_load_privkey_function(e, app_load_key) == 1
          && ENGINE_set_load_pubkey_function(e, app_load_key) == 1
          && ENGINE_set_load_ssl_client_cert_function(e, app_client_cert) == 1, "loaders set");
    check(ENGINE_get_load_privkey_function(e) == app_load_key && ENGINE_get_load_pubkey_function(e) == app_load_key
          && ENGINE_get_ssl_client_cert_function(e) == app_client_cert, "loaders read back");
    k = ENGINE_load_private_key(e, "good", NULL, NULL);
    check(k != NULL, "a private key");
    EVP_PKEY_free(k);
    check(ENGINE_load_private_key(e, "bad", NULL, NULL) == NULL, "a private key that fails");
    errors("bad private");
    k = ENGINE_load_public_key(e, "good", NULL, NULL);
    check(k != NULL, "a public key");
    EVP_PKEY_free(k);
    check(ENGINE_load_public_key(e, "bad", NULL, NULL) == NULL, "a public key that fails");
    errors("bad public");
    check(ENGINE_load_ssl_client_cert(e, NULL, NULL, &cert, &key, NULL, NULL, NULL) == 7,
          "the client certificate loader's result");
    check(ENGINE_load_private_key(NULL, "x", NULL, NULL) == NULL, "NULL engine");
    errors("NULL loader");
    printf("  %d loads\n", loads);
    ENGINE_finish(e);
    ENGINE_free(e);
}

static void test_ex_data(void)
{
    ENGINE *e = app_engine("rustyssl-ex");
    int idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    static int marker;

    printf("  ex index %d\n", idx);
    check(ENGINE_set_ex_data(e, idx, &marker) == 1 && ENGINE_get_ex_data(e, idx) == &marker,
          "ex_data");
    check(ENGINE_get_static_state() != NULL && ENGINE_get_static_state() == ENGINE_get_static_state(),
          "ENGINE_get_static_state");
    ENGINE_free(e);
}

/* Keys made with an engine take its method and keep it initialized until they're freed. */
static int key_inits;

static int rsa_init(RSA *r)
{
    (void)r;
    key_inits++;
    return 1;
}

static int ec_init(EC_KEY *k)
{
    (void)k;
    key_inits++;
    return 1;
}

static void test_keys(void)
{
    ENGINE *e = app_engine("rustyssl-keys"), *bare = app_engine("rustyssl-bare");
    RSA_METHOD *rm = RSA_meth_dup(RSA_PKCS1_OpenSSL());
    DSA_METHOD *dm = DSA_meth_dup(DSA_OpenSSL());
    DH_METHOD *hm = DH_meth_dup(DH_OpenSSL());
    EC_KEY_METHOD *em = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    RSA *r, *r2;
    DSA *d;
    DH *h;
    EC_KEY *k, *k2;

    RSA_meth_set1_name(rm, "engine RSA");
    RSA_meth_set_init(rm, rsa_init);
    EC_KEY_METHOD_set_init(em, ec_init, NULL, NULL, NULL, NULL, NULL);
    check(ENGINE_set_RSA(e, rm) == 1 && ENGINE_set_DSA(e, dm) == 1 && ENGINE_set_DH(e, hm) == 1
              && ENGINE_set_EC(e, em) == 1 && ENGINE_set_init_function(e, app_init) == 1
              && ENGINE_set_finish_function(e, app_finish) == 1,
          "an engine with key methods");
    inits = finishes = key_inits = 0;

    r = RSA_new_method(e);
    check(r != NULL && RSA_get_method(r) == rm && RSA_get0_engine(r) == e, "RSA_new_method");
    printf("  RSA: engine inits %d, key inits %d\n", inits, key_inits);
    d = DSA_new_method(e);
    check(d != NULL && DSA_get_method(d) == dm && DSA_get0_engine(d) == e, "DSA_new_method");
    h = DH_new_method(e);
    check(h != NULL && DH_get0_engine(h) == e, "DH_new_method");
    k = EC_KEY_new_method(e);
    check(k != NULL && EC_KEY_get_method(k) == em && EC_KEY_get0_engine(k) == e,
          "EC_KEY_new_method");
    printf("  four keys: engine inits %d, finishes %d, key inits %d\n", inits, finishes,
           key_inits);
    DSA_free(d);
    DH_free(h);
    printf("  two freed: finishes %d\n", finishes);

    check(RSA_set_method(r, RSA_PKCS1_OpenSSL()) == 1 && RSA_get0_engine(r) == NULL,
          "RSA_set_method lets the engine go");
    printf("  after RSA_set_method: finishes %d\n", finishes);
    RSA_free(r);

    /* A copy takes the source's engine. */
    k2 = EC_KEY_new();
    check(k2 != NULL && EC_KEY_copy(k2, k) == k2 && EC_KEY_get0_engine(k2) == e
              && EC_KEY_get_method(k2) == em,
          "EC_KEY_copy takes the engine");
    printf("  after the copy: inits %d, key inits %d\n", inits, key_inits);
    EC_KEY_free(k2);
    EC_KEY_free(k);
    printf("  all freed: finishes %d\n", finishes);

    /* The default RSA engine is the one RSA_new uses. */
    check(ENGINE_set_default_RSA(e) == 1, "ENGINE_set_default_RSA");
    r = RSA_new();
    check(r != NULL && RSA_get0_engine(r) == e && RSA_get_method(r) == rm,
          "RSA_new takes the default engine");
    r2 = RSA_new_method(NULL);
    check(r2 != NULL && RSA_get0_engine(r2) == e, "RSA_new_method(NULL) too");
    RSA_free(r);
    RSA_free(r2);
    ENGINE_unregister_RSA(e);
    r = RSA_new();
    check(r != NULL && RSA_get0_engine(r) == NULL, "unregistered, no engine");
    RSA_free(r);

    /* An engine without the method, and one whose init fails. */
    ERR_clear_error();
    check(RSA_new_method(bare) == NULL, "an engine without an RSA method");
    errors("RSA_new_method(bare)");
    check(EC_KEY_new_method(bare) == NULL, "an engine without an EC_KEY method");
    errors("EC_KEY_new_method(bare)");
    init_result = 0;
    check(DH_new_method(e) == NULL, "an engine that doesn't initialize");
    errors("DH_new_method");
    init_result = 1;
    printf("  at the end: inits %d, finishes %d\n", inits, finishes);

    ENGINE_free(bare);
    ENGINE_free(e);
    RSA_meth_free(rm);
    DSA_meth_free(dm);
    DH_meth_free(hm);
    EC_KEY_METHOD_free(em);
}

/*
 * EVP through an engine: a digest (SHA-256's own functions, counted), a cipher (a toy: XOR
 * with the key's first octet, under AES-128-CBC's NID), and a key method whose keygen is
 * counted.
 */
static int md_inits, cipher_inits, cipher_calls, keygens;
static EVP_MD *evp_md;
static EVP_CIPHER *evp_cipher;
static EVP_PKEY_METHOD *evp_pmeth;
static int (*sha256_init)(EVP_MD_CTX *ctx);

static int counted_init(EVP_MD_CTX *ctx)
{
    md_inits++;
    return sha256_init(ctx);
}

static int xor_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv,
                    int enc)
{
    (void)iv;
    (void)enc;
    cipher_inits++;
    if (key != NULL)
        *(unsigned char *)EVP_CIPHER_CTX_get_cipher_data(ctx) = key[0];
    return 1;
}

static int xor_do(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    unsigned char k = *(unsigned char *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    size_t i;

    cipher_calls++;
    for (i = 0; i < inl; i++)
        out[i] = in[i] ^ k;
    return 1;
}

static int evp_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    (void)ctx;
    (void)pkey;
    keygens++;
    return 1;
}

static int evp_digests(ENGINE *e, const EVP_MD **md, const int **nids, int nid)
{
    static const int n[] = { NID_sha256 };

    (void)e;
    if (md == NULL) {
        *nids = n;
        return 1;
    }
    *md = nid == NID_sha256 ? evp_md : NULL;
    return *md != NULL;
}

static int evp_ciphers(ENGINE *e, const EVP_CIPHER **c, const int **nids, int nid)
{
    static const int n[] = { NID_aes_128_cbc };

    (void)e;
    if (c == NULL) {
        *nids = n;
        return 1;
    }
    *c = nid == NID_aes_128_cbc ? evp_cipher : NULL;
    return *c != NULL;
}

static int evp_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **m, const int **nids, int nid)
{
    static const int n[] = { NID_hmac };

    (void)e;
    if (m == NULL) {
        *nids = n;
        return 1;
    }
    *m = nid == NID_hmac ? evp_pmeth : NULL;
    return *m != NULL;
}

static void hex(const char *what, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s:", what);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void test_mac(const char *name, const char *which, const char *alg, const char *engine)
{
    EVP_MAC *m = EVP_MAC_fetch(NULL, name, NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(m), *dup;
    unsigned char key[16] = { 0x5a }, iv[12] = { 0 }, out[64];
    size_t n = 0;
    int before = md_inits, calls = cipher_calls, ok;
    OSSL_PARAM params[4], *q = params;

    *q++ = OSSL_PARAM_construct_utf8_string(which, (char *)alg, 0);
    *q++ = OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_ENGINE, (char *)engine, 0);
    if (strcmp(name, "GMAC") == 0)
        *q++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV, iv, sizeof(iv));
    *q = OSSL_PARAM_construct_end();
    ERR_clear_error();
    ok = EVP_MAC_init(ctx, key, sizeof(key), params);
    printf("  %s(%s) with engine %s: init %d", name, alg, engine, ok);
    if (ok == 1) {
        ok = EVP_MAC_update(ctx, (const unsigned char *)"abc", 3);
        dup = EVP_MAC_CTX_dup(ctx);
        printf(", dup %s", dup != NULL ? "made" : "not made");
        if (dup != NULL) {
            ok = ok && EVP_MAC_final(dup, out, &n, sizeof(out));
            EVP_MAC_CTX_free(dup);
        }
        printf(", update+final %d", ok);
    }
    printf(", digest inits %d, cipher calls %d\n", md_inits - before, cipher_calls - calls);
    if (n > 0)
        hex("the MAC", out, n);
    errors(name);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(m);
}

static void test_evp(void)
{
    ENGINE *e = app_engine("rustyssl-evp"), *bare = app_engine("rustyssl-evp-bare");
    EVP_MD_CTX *md = EVP_MD_CTX_new(), *md2 = EVP_MD_CTX_new();
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    EVP_PKEY_CTX *p, *p2;
    EVP_PKEY *k = NULL, *hk;
    unsigned char out[64], key[16] = { 0x5a }, iv[16] = { 0 };
    unsigned int n = 0;
    int len = 0, fin = 0;

    /* The static digest's table has no state size (an engine sets it, as dasync does). */
    evp_md = EVP_MD_meth_dup(EVP_sha256());
    sha256_init = EVP_MD_meth_get_init(EVP_sha256());
    EVP_MD_meth_set_init(evp_md, counted_init);
    EVP_MD_meth_set_app_datasize(evp_md, sizeof(SHA256_CTX));
    evp_cipher = EVP_CIPHER_meth_new(NID_aes_128_cbc, 16, 16);
    EVP_CIPHER_meth_set_iv_length(evp_cipher, 16);
    EVP_CIPHER_meth_set_flags(evp_cipher, EVP_CIPH_CBC_MODE);
    EVP_CIPHER_meth_set_init(evp_cipher, xor_init);
    EVP_CIPHER_meth_set_do_cipher(evp_cipher, xor_do);
    EVP_CIPHER_meth_set_impl_ctx_size(evp_cipher, 1);
    evp_pmeth = EVP_PKEY_meth_new(NID_hmac, 0);
    EVP_PKEY_meth_set_keygen(evp_pmeth, NULL, evp_keygen);
    check(ENGINE_set_digests(e, evp_digests) == 1 && ENGINE_set_ciphers(e, evp_ciphers) == 1
              && ENGINE_set_pkey_meths(e, evp_pkey_meths) == 1
              && ENGINE_set_init_function(e, app_init) == 1
              && ENGINE_set_finish_function(e, app_finish) == 1,
          "an engine with a digest, a cipher and a key method");
    inits = finishes = 0;

    /* A digest through the engine given, then through the default digest engine. */
    check(EVP_DigestInit_ex(md, EVP_sha256(), e) == 1 && EVP_DigestUpdate(md, "abc", 3) == 1
              && EVP_DigestFinal_ex(md, out, &n) == 1,
          "EVP_DigestInit_ex with the engine");
    hex("SHA-256(abc) through the engine", out, n);
    printf("  digest inits %d, engine inits %d\n", md_inits, inits);
    check(EVP_DigestInit_ex(md, NULL, NULL) == 1 && EVP_DigestFinal_ex(md, out, &n) == 1,
          "a re-init keeps the engine's digest");
    printf("  digest inits %d, engine inits %d, finishes %d\n", md_inits, inits, finishes);
    check(EVP_MD_CTX_copy_ex(md2, md) == 1, "EVP_MD_CTX_copy_ex of an engine's context");
    printf("  after the copy: engine inits %d\n", inits);
    EVP_MD_CTX_reset(md2);
    EVP_MD_CTX_reset(md);
    printf("  reset: finishes %d\n", finishes);
    check(ENGINE_set_default_digests(e) == 1, "ENGINE_set_default_digests");
    check(EVP_Digest("abc", 3, out, &n, EVP_sha256(), NULL) == 1, "EVP_Digest takes the default");
    printf("  digest inits %d\n", md_inits);
    ENGINE_unregister_digests(e);
    check(EVP_Digest("abc", 3, out, &n, EVP_sha256(), NULL) == 1, "and not once unregistered");
    printf("  digest inits %d\n", md_inits);
    ERR_clear_error();
    check(EVP_DigestInit_ex(md, EVP_sha256(), bare) == 0, "an engine without the digest");
    errors("EVP_DigestInit_ex(bare)");
    EVP_MD_CTX_reset(md);

    /* A cipher through the engine. */
    check(EVP_EncryptInit_ex(c, EVP_aes_128_cbc(), e, key, iv) == 1
              && EVP_EncryptUpdate(c, out, &len, (const unsigned char *)"0123456789abcdefXY", 18) == 1
              && EVP_EncryptFinal_ex(c, out + len, &fin) == 1,
          "EVP_EncryptInit_ex with the engine");
    hex("the engine's ciphertext", out, (size_t)(len + fin));
    printf("  cipher inits %d, calls %d, cipher %s\n", cipher_inits, cipher_calls,
           EVP_CIPHER_CTX_get0_cipher(c) == evp_cipher ? "the engine's" : "another");
    EVP_CIPHER_CTX_reset(c);
    ERR_clear_error();
    check(EVP_EncryptInit_ex(c, EVP_aes_128_cbc(), bare, key, iv) == 0,
          "an engine without the cipher");
    errors("EVP_EncryptInit_ex(bare)");
    EVP_CIPHER_CTX_reset(c);

    /* A key context through the engine's method. */
    p = EVP_PKEY_CTX_new_id(NID_hmac, e);
    check(p != NULL && EVP_PKEY_keygen_init(p) == 1 && EVP_PKEY_keygen(p, &k) == 1,
          "EVP_PKEY_CTX_new_id with the engine");
    printf("  keygens %d, engine inits %d\n", keygens, inits);
    p2 = EVP_PKEY_CTX_dup(p);
    printf("  dup %s, engine inits %d\n", p2 != NULL ? "made" : "not made", inits);
    EVP_PKEY_CTX_free(p2);
    EVP_PKEY_CTX_free(p);
    EVP_PKEY_free(k);
    k = NULL;
    printf("  freed: finishes %d\n", finishes);

    /* A key whose contexts use the engine (EVP_PKEY_set1_engine). */
    hk = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 16);
    check(hk != NULL && EVP_PKEY_set1_engine(hk, e) == 1, "EVP_PKEY_set1_engine");
    /* The HMAC key is a provided one: its context doesn't reach the engine's keygen. */
    ERR_clear_error();
    p = EVP_PKEY_CTX_new(hk, NULL);
    printf("  a context for the key: %s", p != NULL ? "made" : "not made");
    if (p != NULL)
        printf(", keygen_init %d", EVP_PKEY_keygen_init(p));
    printf(", keygens %d\n", keygens);
    errors("EVP_PKEY_CTX_new(hk)");
    EVP_PKEY_CTX_free(p);
    EVP_PKEY_free(k);
    ERR_clear_error();
    check(EVP_PKEY_set1_engine(hk, bare) == 0, "an engine without the key method");
    errors("EVP_PKEY_set1_engine(bare)");
    EVP_PKEY_free(hk);
    printf("  at the end: inits %d, finishes %d\n", inits, finishes);

    /* The MACs' engine parameter (provider_util.c's load_common). */
    check(ENGINE_add(e) == 1, "the engine listed for the MACs");
    test_mac("HMAC", OSSL_MAC_PARAM_DIGEST, "SHA256", "rustyssl-evp");
    test_mac("CMAC", OSSL_MAC_PARAM_CIPHER, "AES-128-CBC", "rustyssl-evp");
    test_mac("GMAC", OSSL_MAC_PARAM_CIPHER, "AES-128-GCM", "rustyssl-evp");
    test_mac("HMAC", OSSL_MAC_PARAM_DIGEST, "SHA256", "rustyssl-no-such-engine");
    ENGINE_remove(e);
    printf("  after the MACs: inits %d, finishes %d\n", inits, finishes);

    EVP_MD_CTX_free(md);
    EVP_MD_CTX_free(md2);
    EVP_CIPHER_CTX_free(c);
    ENGINE_free(bare);
    ENGINE_free(e);
    EVP_MD_meth_free(evp_md);
    EVP_CIPHER_meth_free(evp_cipher);
    EVP_PKEY_meth_free(evp_pmeth);
}

int main(void)
{
    setenv("OPENSSL_ENGINES", "/nonexistent/rustyssl-engines", 1);
    test_builtins();
    test_dynamic_commands();
    test_app_engine();
    test_tables();
    test_loaders();
    test_ex_data();
    test_keys();
    test_evp();
    list("at the end");
    printf("1..%d\n", number);
    return failures != 0;
}
