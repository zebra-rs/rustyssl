/*
 * Conformance test for libcrypto's shared-object API (internal/dso.h: DSO_new, DSO_load,
 * DSO_bind_func, the name translation, DSO_pathbyaddr, ...), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both (TEST_PLAN.md, layer L4). The header isn't installed, so its
 * declarations are repeated here. The loader's messages name the paths it searched, which
 * differ between the two runs, so errors print only their library and reason, and paths only
 * their last component.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

typedef void (*DSO_FUNC_TYPE)(void);
typedef struct dso_st DSO;
typedef struct dso_meth_st DSO_METHOD;
#define DSO_CTRL_GET_FLAGS 1
#define DSO_CTRL_SET_FLAGS 2
#define DSO_CTRL_OR_FLAGS 3
#define DSO_FLAG_NO_NAME_TRANSLATION 0x01
#define DSO_FLAG_NAME_TRANSLATION_EXT_ONLY 0x02
#define DSO_FLAG_NO_UNLOAD_ON_FREE 0x04
DSO *DSO_new(void);
int DSO_free(DSO *dso);
int DSO_flags(DSO *dso);
int DSO_up_ref(DSO *dso);
long DSO_ctrl(DSO *dso, int cmd, long larg, void *parg);
const char *DSO_get_filename(DSO *dso);
int DSO_set_filename(DSO *dso, const char *filename);
char *DSO_convert_filename(DSO *dso, const char *filename);
char *DSO_merge(DSO *dso, const char *filespec1, const char *filespec2);
DSO *DSO_load(DSO *dso, const char *filename, DSO_METHOD *meth, int flags);
DSO_FUNC_TYPE DSO_bind_func(DSO *dso, const char *symname);
DSO_METHOD *DSO_METHOD_openssl(void);
int DSO_pathbyaddr(void *addr, char *path, int sz);
DSO *DSO_dsobyaddr(void *addr, int flags);
void *DSO_global_lookup(const char *name);

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void errors(const char *what)
{
    unsigned long e;

    printf("  %s:", what);
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static void show(const char *what, char *s)
{
    printf("  %s: %s\n", what, s != NULL ? s : "(null)");
    OPENSSL_free(s);
}

static const char *base(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash != NULL ? slash + 1 : path;
}

static void test_names(void)
{
    DSO *d = DSO_new();

    check(d != NULL && DSO_flags(d) == 0, "DSO_new: no flags");
    show("convert foo", DSO_convert_filename(d, "foo"));
    show("convert dir/foo", DSO_convert_filename(d, "dir/foo"));
    show("convert /abs/foo.so", DSO_convert_filename(d, "/abs/foo.so"));
    show("convert (none)", DSO_convert_filename(d, NULL));
    errors("without a name");
    check(DSO_ctrl(d, DSO_CTRL_SET_FLAGS, DSO_FLAG_NAME_TRANSLATION_EXT_ONLY, NULL) == 0
          && DSO_ctrl(d, DSO_CTRL_GET_FLAGS, 0, NULL) == DSO_FLAG_NAME_TRANSLATION_EXT_ONLY,
          "DSO_CTRL_SET_FLAGS and _GET_FLAGS");
    show("convert foo, extension only", DSO_convert_filename(d, "foo"));
    check(DSO_ctrl(d, DSO_CTRL_OR_FLAGS, DSO_FLAG_NO_NAME_TRANSLATION, NULL) == 0
          && DSO_flags(d) == (DSO_FLAG_NAME_TRANSLATION_EXT_ONLY | DSO_FLAG_NO_NAME_TRANSLATION),
          "DSO_CTRL_OR_FLAGS");
    show("convert foo, no translation", DSO_convert_filename(d, "foo"));
    show("merge, no translation", DSO_merge(d, "foo", "/usr/lib"));
    errors("merging without translation");
    DSO_ctrl(d, DSO_CTRL_SET_FLAGS, 0, NULL);
    show("merge foo /usr/lib", DSO_merge(d, "foo", "/usr/lib"));
    show("merge foo /usr/lib/", DSO_merge(d, "foo", "/usr/lib/"));
    show("merge foo /usr/lib//", DSO_merge(d, "foo", "/usr/lib//"));
    show("merge /abs/foo /usr/lib", DSO_merge(d, "/abs/foo", "/usr/lib"));
    show("merge foo (none)", DSO_merge(d, "foo", NULL));
    show("merge foo (empty)", DSO_merge(d, "foo", ""));
    show("merge (none) /usr/lib", DSO_merge(d, NULL, "/usr/lib"));
    errors("merging without a name");
    check(DSO_ctrl(d, 99, 0, NULL) == -1, "an unknown control: -1");
    errors("unknown control");

    check(DSO_get_filename(d) == NULL, "no file name at first");
    check(DSO_set_filename(d, "first") == 1 && DSO_set_filename(d, "second") == 1
          && strcmp(DSO_get_filename(d), "second") == 0, "DSO_set_filename, twice");
    show("convert the DSO's name", DSO_convert_filename(d, NULL));
    check(DSO_set_filename(d, NULL) == 0, "DSO_set_filename(NULL)");
    errors("a NULL file name");
    check(DSO_load(d, NULL, NULL, 0) == NULL, "DSO_load of a DSO that has a name");
    errors("loading a named DSO");
    check(DSO_up_ref(d) == 1 && DSO_free(d) == 1 && DSO_free(d) == 1, "DSO_up_ref and two frees");

    check(DSO_free(NULL) == 1 && DSO_flags(NULL) == 0, "DSO_free and DSO_flags of NULL");
    check(DSO_up_ref(NULL) == 0 && DSO_ctrl(NULL, DSO_CTRL_GET_FLAGS, 0, NULL) == -1
          && DSO_get_filename(NULL) == NULL && DSO_convert_filename(NULL, "x") == NULL
          && DSO_bind_func(NULL, "x") == NULL, "the others of NULL");
    errors("NULL DSOs");
    check(DSO_METHOD_openssl() != NULL && DSO_METHOD_openssl() == DSO_METHOD_openssl(),
          "DSO_METHOD_openssl");
}

static void test_loading(void)
{
    char path[1024];
    int len;
    DSO *d;
    DSO_FUNC_TYPE f;

    check(DSO_load(NULL, "rustyssl_no_such_library", NULL, 0) == NULL, "loading a missing library");
    errors("a missing library");

    d = DSO_new();
    check(DSO_bind_func(d, "OPENSSL_version_major") == NULL, "binding before loading");
    errors("nothing loaded");
    DSO_free(d);

    len = DSO_pathbyaddr(NULL, NULL, 0);
    check(len > 1, "DSO_pathbyaddr's size for this library");
    check(DSO_pathbyaddr(NULL, path, sizeof(path)) == len && strlen(path) == (size_t)len - 1,
          "DSO_pathbyaddr: the path and its NUL");
    printf("  this library: %s\n", base(path));
    check(DSO_pathbyaddr(NULL, path, 4) == 4 && strlen(path) == 3, "truncated to the room");
    check(DSO_pathbyaddr((void *)OPENSSL_version_major, path, sizeof(path)) == len,
          "an address in libcrypto names it too");

    d = DSO_dsobyaddr((void *)OPENSSL_version_major, 0);
    check(d != NULL, "DSO_dsobyaddr loads libcrypto");
    printf("  its name: %s, flags %d\n", base(DSO_get_filename(d)), DSO_flags(d));
    f = DSO_bind_func(d, "OPENSSL_version_major");
    check(f != NULL && ((unsigned int (*)(void))f)() == OPENSSL_version_major(),
          "DSO_bind_func, and the function works");
    check(DSO_bind_func(d, "rustyssl_no_such_symbol") == NULL, "a missing symbol");
    errors("a missing symbol");
    check(DSO_bind_func(d, NULL) == NULL, "a NULL symbol name");
    errors("a NULL name");
    check(DSO_set_filename(d, "other") == 0, "renaming a loaded DSO");
    errors("renaming");
    check(DSO_load(d, "other", NULL, 0) == NULL, "loading it again");
    errors("loading again");
    check(DSO_free(d) == 1, "DSO_free unloads it");
    check(OPENSSL_version_major() == 3, "libcrypto is still loaded");

    d = DSO_dsobyaddr(NULL, DSO_FLAG_NO_UNLOAD_ON_FREE);
    check(d != NULL && DSO_flags(d) == DSO_FLAG_NO_UNLOAD_ON_FREE, "DSO_dsobyaddr with flags");
    DSO_free(d);

    check(DSO_global_lookup("OPENSSL_version_major") == (void *)OPENSSL_version_major,
          "DSO_global_lookup finds a libcrypto function");
    check(DSO_global_lookup("rustyssl_no_such_symbol") == NULL, "and not a missing one");
    errors("global lookups");
}

int main(void)
{
    test_names();
    test_loading();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
