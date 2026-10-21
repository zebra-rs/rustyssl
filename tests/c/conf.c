/*
 * Conformance test for the configuration-file library (NCONF_new(3), CONF_modules_load(3)'s
 * file format, config(5)), in TAP format:
 *   - the grammar: the default section, section headers, names, values, comments, both
 *     quotes, escapes, continued and long lines, a byte order mark, CR LF, a NUL in a line,
 *     variable references ($name, ${name}, $(name), section::name, ENV::name), assignments to
 *     other sections, repeated names, the .pragma directives (dollarid, abspath, includedir,
 *     and unknown ones), and .include of files and directories (missing ones, relative ones,
 *     OPENSSL_CONF_INCLUDE), and the errors with their line numbers;
 *   - the lookups: NCONF_get_string (the group, the default section, ENV, no configuration),
 *     NCONF_get_number_e, NCONF_get_section, NCONF_get_section_names, and NCONF_dump_bio, in
 *     the hash table's order;
 *   - loading from a file, a FILE, and a BIO; the WIN32 method; a method of the test's own
 *     (dispatched through its function pointers); the classic CONF_* functions over a hash
 *     table; CONF_parse_list; and CONF_get1_default_config_file.
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
#include <openssl/conf.h>
#include <openssl/conf_api.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/safestack.h>

static int failures = 0;
static int number = 0;
static char dir[128];

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* Prints `s` with the test's directory (which names the process) as TMP. */
static void print_masked(const char *s)
{
    size_t n = strlen(dir);
    const char *p;

    while (n > 0 && (p = strstr(s, dir)) != NULL) {
        printf("%.*sTMP", (int)(p - s), s);
        s = p + n;
    }
    printf("%s", s);
}

/*
 * Prints and clears the error queue: library, reason, function, and data of each entry.
 */
static void errors(const char *what)
{
    unsigned long e;
    const char *func, *data;
    int flags;

    printf("# errors %s:", what);
    while ((e = ERR_get_error_all(NULL, NULL, &func, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if (func != NULL && *func != '\0')
            printf(" %s", func);
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0') {
            printf(" [");
            print_masked(data);
            printf("]");
        }
    }
    printf("\n");
}

static void print_value(const char *label, const char *v)
{
    printf("# %s: ", label);
    if (v == NULL) {
        printf("NULL\n");
        return;
    }
    printf("\"");
    for (; *v != '\0'; v++) {
        if (*v == '\\' || *v == '"')
            printf("\\%c", *v);
        else if ((unsigned char)*v < 0x20 || (unsigned char)*v >= 0x7f)
            printf("\\x%02x", (unsigned char)*v);
        else
            putchar(*v);
    }
    printf("\"\n");
}

/* Prints a section's values in order. */
static void print_section(const CONF *conf, const char *name)
{
    STACK_OF(CONF_VALUE) *sk = NCONF_get_section(conf, name);
    int i;

    printf("# [%s]:", name);
    if (sk == NULL) {
        printf(" none\n");
        ERR_clear_error();
        return;
    }
    printf(" %d\n", sk_CONF_VALUE_num(sk));
    for (i = 0; i < sk_CONF_VALUE_num(sk); i++) {
        CONF_VALUE *v = sk_CONF_VALUE_value(sk, i);
        char label[300];

        snprintf(label, sizeof(label), "  %s %s", v->section, v->name);
        print_value(label, v->value);
    }
}

/* Prints what a BIO holds, masked. */
static void print_bio(BIO *b)
{
    char *p;
    long n = BIO_get_mem_data(b, &p);
    char *s = malloc((size_t)n + 1);

    memcpy(s, p, (size_t)n);
    s[n] = '\0';
    print_masked(s);
    free(s);
}

static void dump(const CONF *conf)
{
    BIO *b = BIO_new(BIO_s_mem());

    printf("# dump %d:\n", NCONF_dump_bio(conf, b));
    print_bio(b);
    BIO_free(b);
}

/* Loads `text` (of `len` octets) into a new default configuration: the result and line. */
static CONF *load_text(const char *what, const char *text, size_t len, int *ret)
{
    CONF *conf = NCONF_new(NULL);
    BIO *b = BIO_new_mem_buf(text, (int)len);
    long eline = -7;

    *ret = NCONF_load_bio(conf, b, &eline);
    printf("# %s: load %d, line %ld\n", what, *ret, eline);
    errors(what);
    BIO_free(b);
    return conf;
}

static CONF *load(const char *what, const char *text, int *ret)
{
    return load_text(what, text, strlen(text), ret);
}

static void write_file(const char *name, const char *text)
{
    char path[256];
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s", dir, name);
    f = fopen(path, "w");
    fputs(text, f);
    fclose(f);
}

static void test_grammar(void)
{
    static const char text[] =
        "# a comment\n"
        "top = level   # trailing comment\n"
        "  spaced\t=  \t value with  spaces  \t\n"
        "[ first ]\n"
        "a = 1\n"
        "b = 'single # not a comment' and \"double \"\"quoted\"\" # kept\"\n"
        "c = esc\\\\aped\\n\\t\\r\\b\\x\\#hash\n"
        "d = $a-${a}-$(a)-$first::a-${first::a}-$(top)\n"
        "e = continued \\\n"
        "   line\n"
        "f = ends in \\\\\n"
        "g = 2\n"
        "a = 3\n"
        "other::x = in another\n"
        "[a b]\n"
        "name.with.dots = ok\n"
        "Mixed_Case-1 = punctuation;!.,_\n"
        "[empty]\n"
        "[first]\n"
        "h = back $a\n"
        "[ENV]\n"
        "home = $ENV::RUSTYSSL_CONF_TEST\n"
        "via = $RUSTYSSL_CONF_TEST\n";
    CONF *conf;
    int ret;
    long n = -1;
    STACK_OF(OPENSSL_CSTRING) *names;
    int i;

    conf = load("grammar", text, &ret);
    check(ret == 1, "the grammar loads");
    print_section(conf, "default");
    print_section(conf, "first");
    print_section(conf, "other");
    print_section(conf, "a b");
    print_section(conf, "empty");
    print_section(conf, "ENV");
    print_section(conf, "missing");
    names = NCONF_get_section_names(conf);
    printf("# section names:");
    for (i = 0; i < sk_OPENSSL_CSTRING_num(names); i++)
        printf(" [%s]", sk_OPENSSL_CSTRING_value(names, i));
    printf("\n");
    sk_OPENSSL_CSTRING_free(names);
    dump(conf);

    print_value("first a", NCONF_get_string(conf, "first", "a"));
    print_value("first top (default)", NCONF_get_string(conf, "first", "top"));
    print_value("NULL top", NCONF_get_string(conf, NULL, "top"));
    print_value("missing top", NCONF_get_string(conf, "missing", "top"));
    print_value("ENV variable", NCONF_get_string(conf, "ENV", "RUSTYSSL_CONF_TEST"));
    print_value("ENV home (file)", NCONF_get_string(conf, "ENV", "home"));
    print_value("first nothing", NCONF_get_string(conf, "first", "nothing"));
    errors("lookups");
    print_value("NULL nothing", NCONF_get_string(conf, NULL, "nothing"));
    errors("lookup without a group");
    print_value("no conf, environment", NCONF_get_string(NULL, "any", "RUSTYSSL_CONF_TEST"));
    print_value("no conf, none", NCONF_get_string(NULL, "any", "RUSTYSSL_CONF_NONE"));
    errors("lookups without a configuration");

    check(NCONF_get_number_e(conf, "first", "a", &n) == 1 && n == 3, "a number");
    n = -1;
    printf("# g: %d %ld\n", NCONF_get_number_e(conf, "first", "g", &n), n);
    n = -1;
    printf("# top (not a number): %d %ld\n", NCONF_get_number_e(conf, NULL, "top", &n), n);
    printf("# missing: %d\n", NCONF_get_number_e(conf, NULL, "missing", &n));
    printf("# no result: %d\n", NCONF_get_number_e(conf, NULL, "top", NULL));
    errors("numbers");
    printf("# get_section NULL: %p %p\n", (void *)NCONF_get_section(NULL, "first"),
        (void *)NCONF_get_section(conf, NULL));
    errors("sections of nothing");
    check(NCONF_get0_libctx(conf) == NULL, "no library context");
    NCONF_free(conf);
}

static void test_numbers(void)
{
    static const char text[] =
        "big = 9223372036854775807\n"
        "over = 9223372036854775808\n"
        "digits = 0012abc\n"
        "empty =\n";
    CONF *conf;
    int ret;
    long n;

    conf = load("numbers", text, &ret);
    n = -1;
    printf("# big: %d %ld\n", NCONF_get_number_e(conf, NULL, "big", &n), n);
    n = -1;
    printf("# over: %d %ld\n", NCONF_get_number_e(conf, NULL, "over", &n), n);
    n = -1;
    printf("# digits: %d %ld\n", NCONF_get_number_e(conf, NULL, "digits", &n), n);
    n = -1;
    printf("# empty: %d %ld\n", NCONF_get_number_e(conf, NULL, "empty", &n), n);
    errors("number limits");
    NCONF_free(conf);
}

static void test_errors(void)
{
    static const struct {
        const char *what, *text;
    } cases[] = {
        { "missing equal sign", "a = 1\nb 2\n" },
        { "missing close bracket", "a = 1\n\n[sect\n" },
        { "variable with no value", "a = $nothing\n" },
        { "variable in another section", "[s]\nv = 1\n[t]\na = $s::w\n" },
        { "no close brace", "a = 1\nb = ${a\n" },
        { "no close parenthesis", "a = 1\nb = $(a}\n" },
        { "dollar alone", "a = $\n" },
        { "trailing dollar", "a = 1\nb = $a$\n" },
        { "invalid pragma", ".pragma dollarid\n" },
        { "invalid pragma value", ".pragma dollarid:maybe\n" },
        { "pragma without a keyword", ".pragma :on\n" },
        { "name only", "justaname\n" },
        { "equal sign only", "= value\n" },
        { "brackets", "[]\n" },
        { "bracket with words", "[ a b c\n" },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int ret;
        CONF *conf = load(cases[i].what, cases[i].text, &ret);

        dump(conf);
        NCONF_free(conf);
    }
    check(1, "the errors");
}

static void test_pragmas(void)
{
    static const char text[] =
        "a = 1\n"
        ".pragma dollarid:on\n"
        "cost$ = 5\n"
        "plain = $a$b\n"
        "braced = ${a}x\n"
        "ref = ${cost$}\n"
        ".pragma = dollarid : off\n"
        "after = $a\n"
        ".pragma unknown:whatever\n"
        ".pragma abspath:true\n"
        ".pragma abspath:false\n"
        ".include_not = value\n";
    CONF *conf;
    int ret;

    conf = load("pragmas", text, &ret);
    check(ret == 1, "the pragmas");
    print_section(conf, "default");
    NCONF_free(conf);
}

static void test_lines(void)
{
    char *text;
    CONF *conf;
    int ret;
    size_t n, i;
    static const char bom[] = "\xEF\xBB\xBF" "a = after bom\r\nb = crlf\r\n";
    static const char nul[] = "a = before\0after\nb = next\n";
    static const char unterminated[] = "a = 'open quote\nb = \"open dquote\nc = end\\";

    /* Lines longer than OpenSSL's 512-octet buffer, and one ending just at it. */
    text = malloc(4096);
    n = 0;
    n += (size_t)sprintf(text + n, "long = ");
    for (i = 0; i < 1100; i++)
        text[n++] = (char)('a' + i % 26);
    n += (size_t)sprintf(text + n, "\nedge = ");
    for (i = 0; i < 511 - 7 - 1; i++)
        text[n++] = 'x';
    n += (size_t)sprintf(text + n, "\nshort = s\nedge2 = ");
    for (i = 0; i < 511 - 8; i++)
        text[n++] = 'y';
    n += (size_t)sprintf(text + n, "\\\n  more\nlast = z");
    conf = load_text("long lines", text, n, &ret);
    check(ret == 1, "long lines");
    print_section(conf, "default");
    NCONF_free(conf);
    free(text);

    conf = load_text("byte order mark", bom, sizeof(bom) - 1, &ret);
    print_section(conf, "default");
    NCONF_free(conf);
    conf = load_text("NUL in a line", nul, sizeof(nul) - 1, &ret);
    print_section(conf, "default");
    NCONF_free(conf);
    conf = load_text("unterminated", unterminated, sizeof(unterminated) - 1, &ret);
    print_section(conf, "default");
    NCONF_free(conf);
    conf = load_text("empty", "", 0, &ret);
    print_section(conf, "default");
    dump(conf);
    NCONF_free(conf);
    check(1, "the line handling");
}

static void test_includes(void)
{
    char path[256], text[1024];
    CONF *conf;
    int ret;

    snprintf(path, sizeof(path), "[one]\nx = from one\n.include %s/sub/\n", dir);
    write_file("one.cnf", path);
    snprintf(path, sizeof(path), "%s/sub", dir);
    mkdir(path, 0700);
    write_file("sub/a.cnf", "[suba]\ny = a\n");
    write_file("sub/b.conf", "[subb]\ny = b\n");
    write_file("sub/c.txt", "[subc]\ny = c\n");
    write_file("sub/D.CNF", "[subd]\ny = d\n");
    write_file("rel.cnf", "[rel]\nz = relative\n");
    write_file("nested.cnf", ".include sub\n");

    snprintf(text, sizeof(text),
        "a = before\n"
        ".include %s/one.cnf\n"
        "[back]\n"
        "b = after\n"
        ".include = %s/missing.cnf\n"
        ".pragma includedir:%s\n"
        ".include rel.cnf\n"
        "[back]\n"
        "c = end\n",
        dir, dir, dir);
    conf = load("includes", text, &ret);
    check(ret == 1, "includes");
    print_section(conf, "default");
    print_section(conf, "one");
    print_section(conf, "suba");
    print_section(conf, "subb");
    print_section(conf, "subc");
    print_section(conf, "subd");
    print_section(conf, "rel");
    print_section(conf, "back");
    NCONF_free(conf);

    /* A directory included from a file of a directory. */
    snprintf(path, sizeof(path), "%s/dir2", dir);
    mkdir(path, 0700);
    write_file("dir2/n.cnf", ".include ..\n[n]\nv = 1\n");
    snprintf(text, sizeof(text), ".include %s/dir2\n[after]\nw = 2\n", dir);
    conf = load("a directory from a directory", text, &ret);
    print_section(conf, "n");
    print_section(conf, "after");
    NCONF_free(conf);

    /* abspath refuses relative includes. */
    conf = load("abspath", ".pragma abspath:on\n.include rel.cnf\n", &ret);
    NCONF_free(conf);

    /* OPENSSL_CONF_INCLUDE prefixes relative includes, over includedir. */
    setenv("OPENSSL_CONF_INCLUDE", dir, 1);
    conf = load("OPENSSL_CONF_INCLUDE", ".pragma includedir:/nonexistent\n.include rel.cnf\n",
        &ret);
    print_section(conf, "rel");
    NCONF_free(conf);
    unsetenv("OPENSSL_CONF_INCLUDE");

    /* A variable in the include's name. */
    snprintf(text, sizeof(text), "d = %s\n.include $d/rel.cnf\n", dir);
    conf = load("variable include", text, &ret);
    print_section(conf, "rel");
    NCONF_free(conf);
}

static void test_files(void)
{
    char path[256];
    CONF *conf;
    long eline = -7;
    FILE *f;
    LHASH_OF(CONF_VALUE) *lh;
    BIO *b;

    write_file("file.cnf", "k = from a file\n[s]\nn = 42\nbad line\n");
    write_file("good.cnf", "k = good\n[s]\nn = 42\n");
    snprintf(path, sizeof(path), "%s/good.cnf", dir);

    conf = NCONF_new(NCONF_default());
    printf("# NCONF_load: %d\n", NCONF_load(conf, path, &eline));
    print_value("k", NCONF_get_string(conf, NULL, "k"));
    /*
     * OpenSSL's NCONF_free_data leaves the freed table in the configuration, which any later
     * use (NCONF_free too) reads again: the configuration is left as it is (DEVIATIONS.md).
     */
    NCONF_free_data(conf);
    conf = NCONF_new(NCONF_default());
    snprintf(path, sizeof(path), "%s/file.cnf", dir);
    eline = -7;
    printf("# NCONF_load bad: %d line %ld\n", NCONF_load(conf, path, &eline), eline);
    errors("a bad file");
    snprintf(path, sizeof(path), "%s/none.cnf", dir);
    eline = -7;
    printf("# NCONF_load missing: %d line %ld\n", NCONF_load(conf, path, &eline), eline);
    errors("a missing file");
    printf("# NCONF_load NULL conf: %d\n", NCONF_load(NULL, path, NULL));
    printf("# NCONF_load_bio NULL conf: %d\n", NCONF_load_bio(NULL, NULL, NULL));
    printf("# NCONF_dump_bio NULL conf: %d\n", NCONF_dump_bio(NULL, NULL));
    errors("no configuration");
    NCONF_free(conf);
    NCONF_free(NULL);
    NCONF_free_data(NULL);

    snprintf(path, sizeof(path), "%s/good.cnf", dir);
    f = fopen(path, "r");
    conf = NCONF_new_ex(OSSL_LIB_CTX_get0_global_default(), NULL);
    printf("# NCONF_load_fp: %d\n", NCONF_load_fp(conf, f, NULL));
    fclose(f);
    print_section(conf, "s");
    check(NCONF_get0_libctx(conf) == OSSL_LIB_CTX_get0_global_default(), "the library context");
    NCONF_free(conf);

    /* The classic functions, over a hash table. */
    eline = -7;
    lh = CONF_load(NULL, path, &eline);
    printf("# CONF_load: %s line %ld\n", lh != NULL ? "table" : "NULL", eline);
    print_value("CONF_get_string", CONF_get_string(lh, "s", "n"));
    print_value("CONF_get_string default", CONF_get_string(lh, "s", "k"));
    print_value("CONF_get_string none", CONF_get_string(lh, "s", "none"));
    printf("# CONF_get_number: %ld %ld\n", CONF_get_number(lh, "s", "n"),
        CONF_get_number(lh, "s", "none"));
    printf("# CONF_get_section: %d\n", sk_CONF_VALUE_num(CONF_get_section(lh, "s")));
    b = BIO_new(BIO_s_mem());
    printf("# CONF_dump_bio: %d\n", CONF_dump_bio(lh, b));
    print_bio(b);
    BIO_free(b);
    printf("# CONF_dump_fp:\n");
    fflush(stdout);
    printf("# -> %d\n", CONF_dump_fp(lh, stdout));
    {
        CONF ctmp;

        CONF_set_nconf(&ctmp, lh);
        print_value("through CONF_set_nconf", NCONF_get_string(&ctmp, "s", "n"));
        printf("# NCONF_dump_fp:\n");
        fflush(stdout);
        printf("# -> %d\n", NCONF_dump_fp(&ctmp, stdout));
    }
    b = BIO_new_mem_buf("extra = more\n", -1);
    lh = CONF_load_bio(lh, b, &eline);
    BIO_free(b);
    print_value("after CONF_load_bio", CONF_get_string(lh, NULL, "extra"));
    print_value("kept", CONF_get_string(lh, NULL, "k"));
    errors("the classic functions");
    print_value("CONF_get_string NULL", CONF_get_string(NULL, "any", "RUSTYSSL_CONF_TEST"));
    printf("# CONF_get_number NULL: %ld\n", CONF_get_number(NULL, "any", "RUSTYSSL_CONF_NUM"));
    printf("# CONF_get_section NULL: %p\n", (void *)CONF_get_section(NULL, "s"));
    errors("the classic functions without a table");
    CONF_free(lh);
    CONF_free(NULL);

    snprintf(path, sizeof(path), "%s/none.cnf", dir);
    eline = -7;
    printf("# CONF_load missing: %s line %ld\n",
        CONF_load(NULL, path, &eline) != NULL ? "table" : "NULL", eline);
    errors("CONF_load of a missing file");
    snprintf(path, sizeof(path), "%s/file.cnf", dir);
    f = fopen(path, "r");
    eline = -7;
    lh = CONF_load_fp(NULL, f, &eline);
    fclose(f);
    printf("# CONF_load_fp bad: %s line %ld\n", lh != NULL ? "table" : "NULL", eline);
    errors("CONF_load_fp of a bad file");
    check(1, "loading files");
}

static void test_win32(void)
{
    static const char text[] =
        "a = 1 ; comment\n"
        "b = back\\slash # not a comment\n"
        "c = 'quoted ; still'\n"
        "d = \"dq\"\"x\"\n"
        "e = $a\n";
    CONF *conf = NCONF_new(NCONF_WIN32());
    BIO *b = BIO_new_mem_buf(text, -1);
    long eline = -7;

    printf("# WIN32 load: %d line %ld\n", NCONF_load_bio(conf, b, &eline), eline);
    errors("WIN32");
    print_section(conf, "default");
    BIO_free(b);
    NCONF_free(conf);
    check(1, "the WIN32 method");
}

/* A method of the test's own: the default one with its own init and dump. */
static CONF_METHOD custom;
static int custom_dumps = 0;

static int custom_init(CONF *conf)
{
    int ret = NCONF_default()->init(conf);

    conf->meth = &custom;
    printf("# custom init: %d\n", ret);
    return ret;
}

static int custom_dump(const CONF *conf, BIO *out)
{
    custom_dumps++;
    return BIO_puts(out, "custom dump\n") > 0 && conf != NULL;
}

static void test_methods(void)
{
    CONF *conf;
    BIO *b;
    LHASH_OF(CONF_VALUE) *lh;
    long eline;

    /* The default create runs the method's init, whose memset leaves the default method. */
    custom = *NCONF_default();
    custom.dump = custom_dump;
    conf = NCONF_new(&custom);
    printf("# custom (default init): name %s, meth is default %d\n", conf->meth->name,
        conf->meth == NCONF_default());
    b = BIO_new(BIO_s_mem());
    printf("# dump %d, custom dumps %d\n", NCONF_dump_bio(conf, b), custom_dumps);
    BIO_free(b);
    NCONF_free(conf);

    custom.init = custom_init;
    conf = NCONF_new(&custom);
    printf("# custom (own init): meth is custom %d\n", conf->meth == &custom);
    b = BIO_new(BIO_s_mem());
    printf("# dump %d, custom dumps %d\n", NCONF_dump_bio(conf, b), custom_dumps);
    print_bio(b);
    BIO_free(b);
    printf("# is_number of 7: %d, to_int of 7: %d\n", conf->meth->is_number(conf, '7'),
        conf->meth->to_int(conf, '7'));
    NCONF_free(conf);

    /* CONF_set_default_method sets the classic functions' method. */
    CONF_set_default_method(&custom);
    b = BIO_new_mem_buf("x = 1\n", -1);
    eline = 0;
    lh = CONF_load_bio(NULL, b, &eline);
    BIO_free(b);
    b = BIO_new(BIO_s_mem());
    printf("# CONF_dump_bio with the custom method: %d, custom dumps %d\n",
        CONF_dump_bio(lh, b), custom_dumps);
    print_bio(b);
    BIO_free(b);
    CONF_set_default_method(NCONF_default());
    CONF_free(lh);
    check(custom_dumps == 2, "the methods' functions");
}

static int list_cb(const char *elem, int len, void *arg)
{
    int *count = arg;

    printf(" <%.*s>", len, elem != NULL ? elem : "(null)");
    (*count)++;
    if (len == 4 && elem != NULL && strncmp(elem, "stop", 4) == 0)
        return 0;
    if (len == 4 && elem != NULL && strncmp(elem, "fail", 4) == 0)
        return -1;
    return 1;
}

static void test_parse_list(void)
{
    static const struct {
        const char *list;
        int sep, nospc;
    } cases[] = {
        { "a,b,c", ',', 0 },
        { " a , b ,c ", ',', 0 },
        { " a , b ,c ", ',', 1 },
        { "a,,b", ',', 0 },
        { ",", ',', 1 },
        { "", ',', 0 },
        { "one:two stop:three", ':', 0 },
        { "x;fail;y", ';', 0 },
        { "   ", ',', 1 },
        { "a\tb", '\t', 1 },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int count = 0, ret;

        printf("# parse_list \"%s\" '%c' %d:", cases[i].list,
            cases[i].sep == '\t' ? 'T' : cases[i].sep, cases[i].nospc);
        ret = CONF_parse_list(cases[i].list, cases[i].sep, cases[i].nospc, list_cb, &count);
        printf(" -> %d (%d)\n", ret, count);
    }
    printf("# parse_list NULL: %d\n", CONF_parse_list(NULL, ',', 0, list_cb, NULL));
    errors("parse_list");
    check(1, "CONF_parse_list");
}

int main(void)
{
    char *file;
    char cmd[300];

    setvbuf(stdout, NULL, _IOLBF, 0);
    snprintf(dir, sizeof(dir), "/tmp/rustyssl-conf-%ld", (long)getpid());
    mkdir(dir, 0700);
    setenv("RUSTYSSL_CONF_TEST", "from the environment", 1);
    setenv("RUSTYSSL_CONF_NUM", "77", 1);

    test_grammar();
    test_numbers();
    test_errors();
    test_pragmas();
    test_lines();
    test_includes();
    test_files();
    test_win32();
    test_methods();
    test_parse_list();

    file = CONF_get1_default_config_file();
    print_value("default config file", file);
    OPENSSL_free(file);
    check(file != NULL, "CONF_get1_default_config_file");

    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0)
        printf("# could not remove the test's directory\n");
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
