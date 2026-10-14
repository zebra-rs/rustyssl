/*
 * Conformance test for OPENSSL_INIT_LOAD_CONFIG with a configuration file
 * (OPENSSL_init_crypto(3), config(5)), in TAP format: the file named in the settings (with
 * an application's section) activates the null and default providers and sets the default
 * properties for the default library context; a later load, OPENSSL_config, and
 * OPENSSL_INIT_LOAD_CONFIG with another file change nothing (the configuration is decided
 * once); and OPENSSL_cleanup at exit finishes the module the test added.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int my_init(CONF_IMODULE *md, const CONF *cnf)
{
    (void)cnf;
    printf("# my_init: %s = %s\n", CONF_imodule_get_name(md), CONF_imodule_get_value(md));
    return 1;
}

static void my_finish(CONF_IMODULE *md)
{
    printf("# my_finish: %s\n", CONF_imodule_get_name(md));
}

static void state(const char *what)
{
    char *props = EVP_get1_default_properties(NULL);
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA256", NULL);

    printf("# %s: default %d null %d base %d; properties \"%s\"; SHA256 %s\n", what,
        OSSL_PROVIDER_available(NULL, "default"), OSSL_PROVIDER_available(NULL, "null"),
        OSSL_PROVIDER_available(NULL, "base"), props != NULL ? props : "(null)",
        md != NULL ? "fetched" : "not fetched");
    EVP_MD_free(md);
    OPENSSL_free(props);
    ERR_clear_error();
}

int main(void)
{
    char path[128], other[128];
    FILE *f;
    OPENSSL_INIT_SETTINGS *s = OPENSSL_INIT_new();

    setvbuf(stdout, NULL, _IOLBF, 0);
    snprintf(path, sizeof(path), "/tmp/rustyssl-init-config-%ld.cnf", (long)getpid());
    snprintf(other, sizeof(other), "/tmp/rustyssl-init-config-%ld-other.cnf", (long)getpid());
    f = fopen(path, "w");
    fputs("openssl_conf = wrong\n"
          "myapp = app\n"
          "[wrong]\nmine = from openssl_conf\n"
          "[app]\nmine = from myapp\nproviders = p\nalg_section = a\n"
          "[p]\nnull = l\ndefault = d\n[l]\nactivate = 1\n[d]\nactivate = 1\n"
          "[a]\ndefault_properties = ?provider=default\n",
        f);
    fclose(f);
    f = fopen(other, "w");
    fputs("openssl_conf = o\n[o]\nmine = from the other file\nproviders = p\n[p]\nbase = b\n"
          "[b]\nactivate = 1\n",
        f);
    fclose(f);

    check(CONF_module_add("mine", my_init, my_finish) == 1, "CONF_module_add");
    OPENSSL_INIT_set_config_filename(s, path);
    OPENSSL_INIT_set_config_appname(s, "myapp");
    check(OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, s) == 1,
        "OPENSSL_INIT_LOAD_CONFIG with the settings' file and application");
    state("after loading");

    OPENSSL_INIT_set_config_filename(s, other);
    OPENSSL_INIT_set_config_appname(s, NULL);
    check(OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, s) == 1,
        "OPENSSL_INIT_LOAD_CONFIG again: decided once");
    OPENSSL_config("myapp");
    setenv("OPENSSL_CONF", other, 1);
    check(OSSL_PROVIDER_available(NULL, "base") == 0, "the other file wasn't loaded");
    state("after the later loads");

    check(OSSL_LIB_CTX_load_config(NULL, other) == 1, "OSSL_LIB_CTX_load_config of the default");
    state("after OSSL_LIB_CTX_load_config");

    OPENSSL_INIT_free(s);
    unlink(path);
    unlink(other);
    printf("1..%d\n", number);
    return failures != 0;
}
