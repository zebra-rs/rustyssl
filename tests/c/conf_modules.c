/*
 * Conformance test for the configuration modules (CONF_modules_load_file(3), config(5)), in
 * TAP format, each configuration loaded into a new library context:
 *   - CONF_modules_load_file_ex and CONF_modules_load: the openssl_conf section, an
 *     application's section, CONF_MFLAGS_DEFAULT_SECTION, _IGNORE_ERRORS, _SILENT, _NO_DSO,
 *     _IGNORE_MISSING_FILE, _IGNORE_RETURN_CODES, config_diagnostics, and a missing file;
 *   - the built-in modules: providers (activation, soft_load, identity, parameters, an
 *     unknown provider, a bad directive), alg_section (default_properties, fips_mode, an
 *     unknown option), ssl_conf, random, oid_section, engines, and an unknown module;
 *   - a module of the test's own (CONF_module_add): its init and finish, the CONF_imodule_*
 *     accessors, names with suffixes, and a failing init; CONF_modules_finish and
 *     CONF_modules_unload; and OSSL_LIB_CTX_load_config;
 *   - the helpers the modules use: X509V3_parse_list, X509V3_add_value, X509V3_conf_free,
 *     X509V3_get_value_bool, and ASN1_str2mask.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). The DSO
 * library's error data names the platform's loader messages, so it isn't printed.
 */
#define _POSIX_C_SOURCE 200809L
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>

/* libcrypto's accessors of the ssl_conf module's sets (internal/sslconf.h, exported for libssl). */
typedef struct ssl_conf_cmd_st SSL_CONF_CMD;
const SSL_CONF_CMD *conf_ssl_get(size_t idx, const char **name, size_t *cnt);
int conf_ssl_name_find(const char *name, size_t *idx);
void conf_ssl_get_cmd(const SSL_CONF_CMD *cmd, size_t idx, char **cmdstr, char **arg);

static int failures = 0;
static int number = 0;
static char path[128];

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* Prints and clears the error queue: library, reason, and data (but the DSO library's). */
static void errors(const char *what)
{
    unsigned long e;
    const char *data;
    int flags;

    printf("# errors %s:", what);
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0'
            && ERR_GET_LIB(e) != ERR_LIB_DSO)
            printf(" [%s]", data);
    }
    printf("\n");
}

static void write_conf(const char *text)
{
    FILE *f = fopen(path, "w");

    fputs(text, f);
    fclose(f);
}

/* Loads `text` into a new library context: the result, the providers, the properties. */
static int run(const char *what, const char *text, const char *appname, unsigned long flags)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    char *props;
    int r;

    write_conf(text);
    r = CONF_modules_load_file_ex(ctx, path, appname, flags);
    props = EVP_get1_default_properties(ctx);
    printf("# %s: %d; default %d legacy %d base %d null %d; properties \"%s\"\n", what, r,
        OSSL_PROVIDER_available(ctx, "default"), OSSL_PROVIDER_available(ctx, "legacy"),
        OSSL_PROVIDER_available(ctx, "base"), OSSL_PROVIDER_available(ctx, "null"),
        props != NULL ? props : "(null)");
    OPENSSL_free(props);
    errors(what);
    OSSL_LIB_CTX_free(ctx);
    return r;
}

static int my_init(CONF_IMODULE *md, const CONF *cnf)
{
    const char *value = CONF_imodule_get_value(md);

    /* The flags start uninitialized in OpenSSL (its instance comes from OPENSSL_malloc). */
    printf("# my_init: name %s, value %s, data %s, module data %s, conf %s\n",
        CONF_imodule_get_name(md), value, CONF_imodule_get_usr_data(md) == NULL ? "none" : "set",
        CONF_module_get_usr_data(CONF_imodule_get_module(md)) == NULL ? "none" : "set",
        cnf != NULL ? "given" : "none");
    CONF_imodule_set_usr_data(md, (void *)md);
    CONF_imodule_set_flags(md, 7);
    CONF_module_set_usr_data(CONF_imodule_get_module(md), (void *)"module");
    if (strcmp(value, "fail") == 0)
        return 0;
    if (strcmp(value, "negative") == 0)
        return -5;
    return 1;
}

static void my_finish(CONF_IMODULE *md)
{
    printf("# my_finish: name %s, data %s, flags %lu\n", CONF_imodule_get_name(md),
        CONF_imodule_get_usr_data(md) == md ? "its own" : "other", CONF_imodule_get_flags(md));
}

/* The ssl_conf sets `names` name, as libssl's SSL_CTX_config reads them. */
static void ssl_sets(const char *const *names)
{
    for (; *names != NULL; names++) {
        size_t idx = 99, cnt = 99, i;
        const char *name = NULL;
        const SSL_CONF_CMD *cmds;

        if (!conf_ssl_name_find(*names, &idx)) {
            printf("# ssl set %s: not found\n", *names);
            continue;
        }
        cmds = conf_ssl_get(idx, &name, &cnt);
        printf("# ssl set %s: index %zu, name %s, %zu commands:", *names, idx, name, cnt);
        for (i = 0; i < cnt; i++) {
            char *cmd = NULL, *arg = NULL;

            conf_ssl_get_cmd(cmds, i, &cmd, &arg);
            printf(" %s=%s", cmd, arg);
        }
        printf("\n");
    }
}

static void test_flags(void)
{
    static const char failing[] = "openssl_conf = init\n[init]\nmine = negative\n";
    char missing[160];

    run("no openssl_conf", "a = 1\n", NULL, 0);
    run("missing section", "openssl_conf = init\n", NULL, 0);
    run("missing section, silent", "openssl_conf = init\n", NULL, CONF_MFLAGS_SILENT);
    run("appname", "app = mysect\nopenssl_conf = init\n[mysect]\nmine = app\n[init]\nmine = d\n",
        "app", 0);
    run("appname without its section", "openssl_conf = init\n[init]\nmine = d\n", "nosuch", 0);
    run("appname, default section", "openssl_conf = init\n[init]\nmine = d\n", "nosuch",
        CONF_MFLAGS_DEFAULT_SECTION);
    run("failing module", failing, NULL, 0);
    run("failing module, ignored",
        "openssl_conf = init\n[init]\nmine = negative\nproviders = p\n[p]\nnull = l\n"
        "[l]\nactivate = 1\n",
        NULL, CONF_MFLAGS_IGNORE_ERRORS);
    run("failing module, silent", failing, NULL, CONF_MFLAGS_SILENT);
    run("failing module, return codes ignored", failing, NULL, CONF_MFLAGS_IGNORE_RETURN_CODES);
    run("diagnostics", "config_diagnostics = 1\nopenssl_conf = init\n[init]\nmine = negative\n",
        NULL, CONF_MFLAGS_IGNORE_RETURN_CODES | CONF_MFLAGS_IGNORE_ERRORS);
    run("diagnostics off", "config_diagnostics = 0\nopenssl_conf = init\n[init]\nmine = negative\n",
        NULL, CONF_MFLAGS_IGNORE_RETURN_CODES);
    run("bad syntax", "openssl_conf = init\n[init\n", NULL, 0);

    snprintf(missing, sizeof(missing), "%s.missing", path);
    printf("# missing file: %d\n", CONF_modules_load_file_ex(NULL, missing, NULL, 0));
    ERR_clear_error();
    printf("# missing file, ignored: %d\n",
        CONF_modules_load_file_ex(NULL, missing, NULL, CONF_MFLAGS_IGNORE_MISSING_FILE));
    errors("missing files");
    printf("# CONF_modules_load NULL: %d\n", CONF_modules_load(NULL, NULL, 0));
    check(1, "the flags");
}

static void test_modules(void)
{
    run("unknown module", "openssl_conf = init\n[init]\nfoo = bar\n", NULL, 0);
    run("unknown module, no DSO", "openssl_conf = init\n[init]\nfoo = bar\n", NULL,
        CONF_MFLAGS_NO_DSO);
    run("unknown module with a path", "openssl_conf = init\n[init]\nfoo = f\n[f]\npath = /nonexistent/foo\n",
        NULL, 0);
    run("my module", "openssl_conf = init\n[init]\nmine = one\nmine.2 = two\nmine.x = fail\n", NULL,
        0);
    run("module prefix", "openssl_conf = init\n[init]\nmi = short\n", NULL, CONF_MFLAGS_NO_DSO);

    run("providers",
        "openssl_conf = init\n[init]\nproviders = p\nalg_section = a\n[p]\nnull = l\n"
        "default = d\n[l]\nactivate = 1\n[d]\nactivate = yes\n[a]\n"
        "default_properties = provider=null\n",
        NULL, 0);
    run("an unknown provider", "openssl_conf = init\n[init]\nproviders = p\n[p]\nnope = n\n"
        "[n]\nactivate = 1\n", NULL, 0);
    run("an unknown provider, soft", "openssl_conf = init\n[init]\nproviders = p\n[p]\nnope = n\n"
        "[n]\nactivate = 1\nsoft_load = 1\n", NULL, 0);
    run("provider parameters", "openssl_conf = init\n[init]\nproviders = p\n[p]\ndefault = d\n"
        "[d]\nactivate = 1\nfoo = bar\nsub = s\n[s]\nx = 1\n", NULL, 0);
    run("a bad activate", "openssl_conf = init\n[init]\nproviders = p\n[p]\ndefault = d\n"
        "[d]\nactivate = maybe\n", NULL, 0);
    run("identity", "openssl_conf = init\n[init]\nproviders = p\n[p]\nmyname = d\n[d]\n"
        "identity = null\nactivate = 1\n", NULL, 0);
    run("a missing provider section", "openssl_conf = init\n[init]\nproviders = p\n[p]\n"
        "default = nosuch\n", NULL, 0);
    run("a missing providers section", "openssl_conf = init\n[init]\nproviders = nosuch\n", NULL,
        0);
    run("not activated", "openssl_conf = init\n[init]\nproviders = p\n[p]\nnull = l\n[l]\n"
        "activate = 0\n", NULL, 0);
    run("dotted names", "openssl_conf = init\n[init]\nproviders = p\n[p]\nx.base = b\n[b]\n"
        "x.activate = 1\n", NULL, 0);

    run("alg_section: unknown", "openssl_conf = init\n[init]\nalg_section = a\n[a]\nfoo = bar\n",
        NULL, 0);
    run("alg_section: fips_mode", "openssl_conf = init\n[init]\nalg_section = a\n[a]\n"
        "fips_mode = yes\n", NULL, 0);
    run("alg_section: bad fips_mode", "openssl_conf = init\n[init]\nalg_section = a\n[a]\n"
        "fips_mode = sometimes\n", NULL, 0);
    run("alg_section: missing", "openssl_conf = init\n[init]\nalg_section = nosuch\n", NULL, 0);

    run("ssl_conf: missing", "openssl_conf = init\n[init]\nssl_conf = nosuch\n", NULL, 0);
    run("ssl_conf: empty", "openssl_conf = init\n[init]\nssl_conf = s\n[s]\n", NULL, 0);
    run("ssl_conf: empty commands", "openssl_conf = init\n[init]\nssl_conf = s\n[s]\nsys = t\n"
        "[t]\n", NULL, 0);
    run("ssl_conf", "openssl_conf = init\n[init]\nssl_conf = s\n[s]\nsystem_default = t\n[t]\n"
        "CipherString = DEFAULT\n.MinProtocol = TLSv1.2\n", NULL, 0);
    {
        static const char *const one[] = { "system_default", "other", "", NULL };

        ssl_sets(one);
        check(conf_ssl_name_find(NULL, NULL) == 0, "conf_ssl_name_find of NULL");
    }
    run("ssl_conf: two sets", "openssl_conf = init\n[init]\nssl_conf = s\n[s]\nfirst = a\n"
        "x.second = b\n[a]\nOptions = -SessionTicket\n[b]\nCiphersuites = TLS_AES_128_GCM_SHA256\n"
        "y.z.Groups = X25519\n", NULL, 0);
    {
        static const char *const two[] = { "first", "x.second", "second", "system_default", NULL };

        ssl_sets(two);
    }

    run("random: unknown", "openssl_conf = init\n[init]\nrandom = r\n[r]\nfoo = bar\n", NULL, 0);
    run("random", "openssl_conf = init\n[init]\nrandom = r\n[r]\nrandom = CTR-DRBG\n"
        "cipher = AES-128-CTR\nproperties = provider=default\nseed = SEED-SRC\n", NULL, 0);
    run("random: missing", "openssl_conf = init\n[init]\nrandom = nosuch\n", NULL, 0);

    run("oid_section", "openssl_conf = init\n[init]\noid_section = o\n[o]\n"
        "rustysslTestOid = 1.2.3.4.5.6.7\nrustysslOther = Rustyssl Other Name, 1.2.3.4.5.6.8\n",
        NULL, 0);
    printf("# the new objects: %d %s, %d %s\n", OBJ_sn2nid("rustysslTestOid"),
        OBJ_nid2ln(OBJ_sn2nid("rustysslTestOid")), OBJ_sn2nid("rustysslOther"),
        OBJ_nid2ln(OBJ_sn2nid("rustysslOther")));
    run("oid_section: bad", "openssl_conf = init\n[init]\noid_section = o\n[o]\nbad = xx\n", NULL,
        0);
    run("stbl_section", "openssl_conf = init\n[init]\nstbl_section = t\n[t]\n"
        "rustysslTestOid = min:1, max:8, flags:nomask\n", NULL, 0);
    run("stbl_section: bad", "openssl_conf = init\n[init]\nstbl_section = t\n[t]\n"
        "rustysslTestOid = size:1\n", NULL, 0);

    run("engines: no commands", "openssl_conf = init\n[init]\nengines = e\n[e]\nfoo = f\n[f]\n"
        "engine_id = foo\n", NULL, 0);
    run("engines: soft", "openssl_conf = init\n[init]\nengines = e\n[e]\nfoo = f\n[f]\n"
        "soft_load = 1\nx = y\n", NULL, 0);
    run("engines: a command", "openssl_conf = init\n[init]\nengines = e\n[e]\nfoo = f\n[f]\n"
        "engine_id = foo\ninit = 0\n", NULL, 0);
    run("engines: missing", "openssl_conf = init\n[init]\nengines = nosuch\n", NULL, 0);
    run("engines: missing engine section", "openssl_conf = init\n[init]\nengines = e\n[e]\n"
        "foo = nosuch\n", NULL, 0);
    check(1, "the modules");
}

static void test_load_config(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    char *props;

    write_conf("openssl_conf = init\n[init]\nproviders = p\nalg_section = a\n[p]\nbase = b\n"
               "[b]\nactivate = 1\n[a]\ndefault_properties = ?provider=base\n");
    printf("# OSSL_LIB_CTX_load_config: %d\n", OSSL_LIB_CTX_load_config(ctx, path));
    props = EVP_get1_default_properties(ctx);
    printf("# base %d default %d properties \"%s\"\n", OSSL_PROVIDER_available(ctx, "base"),
        OSSL_PROVIDER_available(ctx, "default"), props);
    OPENSSL_free(props);
    write_conf("openssl_conf = init\n[init]\nmine = negative\n");
    printf("# OSSL_LIB_CTX_load_config, failing: %d\n", OSSL_LIB_CTX_load_config(ctx, path));
    errors("OSSL_LIB_CTX_load_config");
    OSSL_LIB_CTX_free(ctx);
    check(1, "OSSL_LIB_CTX_load_config");
}

static void test_conf_object(void)
{
    CONF *conf = NCONF_new_ex(NULL, NULL);
    BIO *b = BIO_new_mem_buf("myapp = s\n[s]\nmine = from CONF_modules_load\n", -1);

    NCONF_load_bio(conf, b, NULL);
    printf("# CONF_modules_load: %d\n", CONF_modules_load(conf, "myapp", 0));
    printf("# CONF_modules_load, no section: %d\n", CONF_modules_load(conf, "nosuch", 0));
    errors("CONF_modules_load");
    BIO_free(b);
    NCONF_free(conf);
    check(1, "CONF_modules_load on a configuration");
}

static void print_list(const char *what, STACK_OF(CONF_VALUE) *sk)
{
    int i;

    printf("# %s:", what);
    if (sk == NULL) {
        printf(" NULL\n");
        return;
    }
    for (i = 0; i < sk_CONF_VALUE_num(sk); i++) {
        CONF_VALUE *v = sk_CONF_VALUE_value(sk, i);

        printf(" [%s|%s]", v->name != NULL ? v->name : "(null)",
            v->value != NULL ? v->value : "(null)");
    }
    printf("\n");
}

static void test_helpers(void)
{
    static const char *lists[] = {
        "min:1, max:8, mask:utf8only", " a , bc ,d", "x: 8 ,y", "name:", " ,a", "a\nb, c",
        "k:v:w", "", "   ", "one", "a:1,", ",",
    };
    static const char *bools[] = { "TRUE", "y", "yes", "NO", "n", "false", "maybe", "Yes", "" };
    static const char *masks[] = {
        "UTF8|BMP", "DIR", " PRINTABLE | IA5 ", "utf8string", "foo", "", "UTF8|", "EXP",
        "T61|UNIV|NUMERIC", "BOOLEAN", "SEQ", "dir",
    };
    STACK_OF(CONF_VALUE) *sk = NULL;
    size_t i;

    for (i = 0; i < sizeof(lists) / sizeof(lists[0]); i++) {
        char label[64];

        sk = X509V3_parse_list(lists[i]);
        snprintf(label, sizeof(label), "parse_list \"%s\"", lists[i]);
        print_list(label, sk);
        sk_CONF_VALUE_pop_free(sk, X509V3_conf_free);
        errors("parse_list");
    }
    sk = NULL;
    printf("# add_value: %d %d %d\n", X509V3_add_value("n1", "v1", &sk),
        X509V3_add_value("n2", NULL, &sk), X509V3_add_value(NULL, "v3", &sk));
    print_list("added", sk);
    sk_CONF_VALUE_pop_free(sk, X509V3_conf_free);
    X509V3_conf_free(NULL);

    for (i = 0; i < sizeof(bools) / sizeof(bools[0]); i++) {
        CONF_VALUE v;
        int b = -1, r;

        v.section = NULL;
        v.name = "flag";
        v.value = (char *)bools[i];
        r = X509V3_get_value_bool(&v, &b);
        printf("# bool \"%s\": %d %d\n", bools[i], r, b);
        errors("bool");
    }
    for (i = 0; i < sizeof(masks) / sizeof(masks[0]); i++) {
        unsigned long m = 99;
        int r = ASN1_str2mask(masks[i], &m);

        printf("# mask \"%s\": %d %lx\n", masks[i], r, m);
        errors("mask");
    }
    write_conf("openssl_conf = init\n[init]\nmine = global\n");
    printf("# CONF_modules_load_file: %d\n", CONF_modules_load_file(path, NULL, 0));
    errors("CONF_modules_load_file");
    check(1, "the helpers");
}

int main(void)
{
    snprintf(path, sizeof(path), "/tmp/rustyssl-conf-modules-%ld.cnf", (long)getpid());
    setvbuf(stdout, NULL, _IOLBF, 0);

    check(CONF_module_add("mine", my_init, my_finish) == 1, "CONF_module_add");
    OPENSSL_load_builtin_modules();
    ASN1_add_oid_module();
    ASN1_add_stable_module();
    EVP_add_alg_module();
    ENGINE_add_conf_module();
    test_flags();
    test_modules();
    test_load_config();
    test_conf_object();
    test_helpers();

    printf("# CONF_modules_finish:\n");
    CONF_modules_finish();
    run("my module after finish", "openssl_conf = init\n[init]\nmine = again\n", NULL, 0);
    printf("# CONF_modules_unload(0):\n");
    CONF_modules_unload(0);
    run("my module after unload(0)", "openssl_conf = init\n[init]\nmine = again\n", NULL, 0);
    printf("# CONF_modules_unload(1):\n");
    CONF_modules_unload(1);
    run("my module after unload(1)", "openssl_conf = init\n[init]\nmine = again\n", NULL,
        CONF_MFLAGS_NO_DSO);
    run("providers after unload(1)", "openssl_conf = init\n[init]\nproviders = p\n[p]\n"
        "null = l\n[l]\nactivate = 1\n", NULL, CONF_MFLAGS_NO_DSO);
    check(CONF_module_add("mine", my_init, my_finish) == 1, "CONF_module_add again");
    run("my module added again", "openssl_conf = init\n[init]\nmine = back\n", NULL, 0);

    unlink(path);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
