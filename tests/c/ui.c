/*
 * Conformance test for the UI (UI_new(3), UI_create_method(3), UI_UTIL_read_pw(3),
 * EVP_read_pw_string(3)) and the passphrases asked through it, in TAP format: a scripted method
 * that logs each call and answers from a list; every kind of string, added and duplicated, and
 * their errors; UI_process's results, failures at each stage, and cancellation; results too
 * short and too long (and redoable); booleans; the error queue shown through the writer; user
 * data plain and duplicated; application data; prompts constructed by default and by a method;
 * the default method; the password utilities; UI_UTIL_wrap_read_pem_callback and
 * PEM_def_callback; and an encoder asking a pem_password_cb or a UI method for a passphrase.
 *
 * Nothing here reads the terminal (UI_OpenSSL's console comes with step 6.2): the default
 * method is the scripted one whenever a default UI is made.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ui.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void errors(void)
{
    unsigned long e;
    const char *data;
    int flags;

    printf("  errors:");
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

/* The script: what the opener, flusher, and closer return, and the reader's answers. */
static int open_ret = 1, flush_ret = 1, close_ret = 1, write_ret = 1;
static const char *answers[8];
static int answer_ret[8];
static int next_answer = 0;

static const char *str(const char *s)
{
    return s == NULL ? "(null)" : s;
}

static int s_open(UI *ui)
{
    (void)ui;
    printf("  open\n");
    return open_ret;
}

static int s_write(UI *ui, UI_STRING *uis)
{
    (void)ui;
    printf("  write type %d flags %d out [%s] action [%s] test [%s] min %d max %d\n",
           (int)UI_get_string_type(uis), UI_get_input_flags(uis), str(UI_get0_output_string(uis)),
           str(UI_get0_action_string(uis)), str(UI_get0_test_string(uis)),
           UI_get_result_minsize(uis), UI_get_result_maxsize(uis));
    return write_ret;
}

static int s_flush(UI *ui)
{
    (void)ui;
    printf("  flush\n");
    return flush_ret;
}

static int s_read(UI *ui, UI_STRING *uis)
{
    int i = next_answer++, r;

    if (UI_get_string_type(uis) == UIT_INFO || UI_get_string_type(uis) == UIT_ERROR)
        return 1;
    if (i >= 8 || answers[i] == NULL) {
        printf("  read %d: no answer\n", i);
        return 1;
    }
    if (answer_ret[i] != 1) {
        printf("  read %d: returns %d\n", i, answer_ret[i]);
        return answer_ret[i];
    }
    /* The second answer of each run through UI_set_result_ex, the others UI_set_result. */
    r = i == 1 ? UI_set_result_ex(ui, uis, answers[i], (int)strlen(answers[i]))
               : UI_set_result(ui, uis, answers[i]);
    printf("  read %d [%s]: set %d, result [%s] length %d\n", i, answers[i], r,
           str(UI_get0_result_string(uis)), UI_get_result_string_length(uis));
    return r >= 0 ? 1 : 0;
}

static int s_close(UI *ui)
{
    (void)ui;
    printf("  close\n");
    return close_ret;
}

static void *s_dup(UI *ui, void *data)
{
    (void)ui;
    printf("  dup [%s]\n", str(data));
    return OPENSSL_strdup(data);
}

static void s_destroy(UI *ui, void *data)
{
    (void)ui;
    printf("  destroy [%s]\n", str(data));
    OPENSSL_free(data);
}

static char *s_prompt(UI *ui, const char *desc, const char *name)
{
    char buf[200];

    (void)ui;
    snprintf(buf, sizeof(buf), "<%s|%s>", str(desc), str(name));
    return OPENSSL_strdup(buf);
}

static UI_METHOD *scripted(int with_prompt)
{
    UI_METHOD *m = UI_create_method("scripted");

    UI_method_set_opener(m, s_open);
    UI_method_set_writer(m, s_write);
    UI_method_set_flusher(m, s_flush);
    UI_method_set_reader(m, s_read);
    UI_method_set_closer(m, s_close);
    if (with_prompt)
        UI_method_set_prompt_constructor(m, s_prompt);
    return m;
}

static void script(const char *a0, const char *a1, const char *a2)
{
    int i;

    for (i = 0; i < 8; i++) {
        answers[i] = NULL;
        answer_ret[i] = 1;
    }
    answers[0] = a0;
    answers[1] = a1;
    answers[2] = a2;
    next_answer = 0;
    open_ret = flush_ret = close_ret = write_ret = 1;
}

static void test_strings(UI_METHOD *m)
{
    UI *ui = UI_new_method(m);
    char a[20] = "", b[20] = "", c[4] = "x";
    int r;

    check(ui != NULL, "a UI with the scripted method");
    check(UI_get_method(ui) == m, "UI_get_method");
    check(UI_set_method(ui, UI_null()) == UI_null() && UI_get_method(ui) == UI_null(), "UI_set_method");
    UI_set_method(ui, m);
    printf("  input %d\n", UI_add_input_string(ui, "Name:", UI_INPUT_FLAG_ECHO, a, 2, 10));
    printf("  verify %d\n", UI_dup_verify_string(ui, "Again:", 0, b, 2, 10, a));
    printf("  boolean %d\n", UI_dup_input_boolean(ui, "Sure?", "proceed", "yY", "nN", 0, c));
    printf("  info %d\n", UI_add_info_string(ui, "some info"));
    printf("  error %d\n", UI_dup_error_string(ui, "an error"));
    printf("  dup input %d\n", UI_dup_input_string(ui, "Copied:", 0, b, 0, 5));
    printf("  dup info %d\n", UI_dup_info_string(ui, "more info"));
    printf("  add error %d\n", UI_add_error_string(ui, "plain error"));
    printf("  verify (plain) %d\n", UI_add_verify_string(ui, "Plain again:", 0, b, 0, 10, a));
    printf("  boolean (plain) %d\n", UI_add_input_boolean(ui, "Plain?", NULL, "a", "b", 0, c));
    ERR_clear_error();

    /* The errors of adding. */
    printf("  no prompt %d\n", UI_add_input_string(ui, NULL, 0, a, 0, 5));
    errors();
    printf("  no result buffer %d\n", UI_add_input_string(ui, "x", 0, NULL, 0, 5));
    errors();
    printf("  no ok characters %d\n", UI_add_input_boolean(ui, "x", NULL, NULL, "n", 0, c));
    errors();
    printf("  common characters %d\n", UI_add_input_boolean(ui, "x", NULL, "yn", "n", 0, c));
    errors();
    printf("  dup without a prompt %d\n", UI_dup_input_string(ui, NULL, 0, a, 0, 5));
    errors();
    UI_free(ui);

    /* A whole run. */
    ui = UI_new_method(m);
    script("alice", "alice", "yes");
    UI_add_input_string(ui, "Name:", 0, a, 2, 10);
    UI_add_verify_string(ui, "Again:", 0, b, 2, 10, a);
    UI_add_input_boolean(ui, "Sure?", "go on", "yY", "nN", 0, c);
    UI_add_info_string(ui, "info");
    r = UI_process(ui);
    printf("  process %d: a [%s] b [%s] c [%c]\n", r, a, b, c[0]);
    printf("  result 0 [%s] length %d; result 1 [%s] length %d\n", str(UI_get0_result(ui, 0)),
           UI_get_result_length(ui, 0), str(UI_get0_result(ui, 1)), UI_get_result_length(ui, 1));
    printf("  result 2 [%s] length %d; result 3 [%s] length %d\n", str(UI_get0_result(ui, 2)),
           UI_get_result_length(ui, 2), str(UI_get0_result(ui, 3)), UI_get_result_length(ui, 3));
    ERR_clear_error();
    printf("  result -1 [%s]\n", str(UI_get0_result(ui, -1)));
    errors();
    printf("  result 9 [%s]\n", str(UI_get0_result(ui, 9)));
    errors();
    printf("  length -1 %d, length 9 %d\n", UI_get_result_length(ui, -1), UI_get_result_length(ui, 9));
    errors();
    printf("  redoable %d\n", UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, NULL, NULL));
    UI_free(ui);

    /* Too short, too long, and a cancelling boolean. */
    ui = UI_new_method(m);
    script("a", "abcdefghijklmnop", "no");
    UI_add_input_string(ui, "Short:", 0, a, 2, 10);
    r = UI_process(ui);
    printf("  too short: process %d, redoable %d\n", r, UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, NULL, NULL));
    errors();
    UI_free(ui);
    ui = UI_new_method(m);
    script("abcdefghijklmnop", NULL, NULL);
    UI_add_input_string(ui, "Long:", 0, a, 2, 10);
    r = UI_process(ui);
    printf("  too long: process %d, redoable %d\n", r, UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, NULL, NULL));
    errors();
    UI_free(ui);
    ui = UI_new_method(m);
    script("maybe no", NULL, NULL);
    c[0] = 'x';
    UI_add_input_boolean(ui, "Sure?", NULL, "yY", "nN", 0, c);
    r = UI_process(ui);
    printf("  boolean: process %d, answer %d\n", r, c[0]);
    UI_free(ui);
}

static void test_failures(UI_METHOD *m)
{
    static const char *const stages[] = { "opener", "writer", "flusher 0", "flusher -1",
                                          "reader 0", "reader -1", "reader -2", "closer" };
    size_t i;
    char a[20];

    for (i = 0; i < sizeof(stages) / sizeof(stages[0]); i++) {
        UI *ui = UI_new_method(m);
        int r;

        script("value", NULL, NULL);
        switch (i) {
        case 0:
            open_ret = 0;
            break;
        case 1:
            write_ret = 0;
            break;
        case 2:
            flush_ret = 0;
            break;
        case 3:
            flush_ret = -1;
            break;
        case 4:
            answer_ret[0] = 0;
            break;
        case 5:
            answer_ret[0] = -1;
            break;
        case 6:
            answer_ret[0] = -2;
            break;
        default:
            close_ret = 0;
            break;
        }
        UI_add_input_string(ui, "Prompt:", 0, a, 0, 10);
        r = UI_process(ui);
        printf("  %s fails: process %d\n", stages[i], r);
        errors();
        UI_free(ui);
    }
    {
        /* A method without a reader cancels. */
        UI_METHOD *noread = UI_create_method("no reader");
        UI *ui = UI_new_method(noread);

        UI_add_input_string(ui, "Prompt:", 0, a, 0, 10);
        printf("  no reader: process %d\n", UI_process(ui));
        errors();
        UI_free(ui);
        UI_destroy_method(noread);
    }
}

static void test_print_errors(UI_METHOD *m)
{
    UI *ui = UI_new_method(m);
    char a[20];

    script("x", NULL, NULL);
    UI_add_input_string(ui, "Prompt:", 0, a, 0, 10);
    printf("  print errors was %d\n", UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, NULL, NULL));
    printf("  print errors now %d\n", UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, NULL, NULL));
    ERR_raise_data(ERR_LIB_UI, UI_R_INDEX_TOO_LARGE, "a queued error");
    printf("  process %d\n", UI_process(ui));
    printf("  unknown control %d\n", UI_ctrl(ui, 99, 0, NULL, NULL));
    errors();
    printf("  control of no UI %d\n", UI_ctrl(NULL, UI_CTRL_IS_REDOABLE, 0, NULL, NULL));
    errors();
    UI_free(ui);
}

static void test_user_data(UI_METHOD *m)
{
    UI *ui = UI_new_method(m);
    char *p;
    int idx;

    printf("  add user data: old %p\n", UI_add_user_data(ui, "first"));
    printf("  user data [%s]\n", str(UI_get0_user_data(ui)));
    printf("  dup without a duplicator %d\n", UI_dup_user_data(ui, "x"));
    errors();
    UI_method_set_data_duplicator(m, s_dup, s_destroy);
    printf("  dup user data %d\n", UI_dup_user_data(ui, "second"));
    printf("  user data [%s]\n", str(UI_get0_user_data(ui)));
    printf("  add over the duplicate: old %p\n", UI_add_user_data(ui, "third"));
    printf("  user data [%s]\n", str(UI_get0_user_data(ui)));
    printf("  dup again %d\n", UI_dup_user_data(ui, "fourth"));
    UI_free(ui);
    UI_method_set_data_duplicator(m, NULL, NULL);

    ui = UI_new_method(m);
    idx = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI, 0, NULL, NULL, NULL, NULL);
    printf("  set ex data %d\n", UI_set_ex_data(ui, idx, "app data"));
    printf("  ex data [%s]\n", str(UI_get_ex_data(ui, idx)));

    p = UI_construct_prompt(ui, "pass phrase", "the key");
    printf("  prompt [%s]\n", str(p));
    OPENSSL_free(p);
    p = UI_construct_prompt(ui, "pass phrase", NULL);
    printf("  prompt [%s]\n", str(p));
    OPENSSL_free(p);
    p = UI_construct_prompt(ui, NULL, "x");
    printf("  prompt [%s]\n", str(p));
    OPENSSL_free(p);
    UI_free(ui);
    p = UI_construct_prompt(NULL, "thing", "obj");
    printf("  prompt without a UI [%s]\n", str(p));
    OPENSSL_free(p);
}

static int pem_calls = 0;

static int pem_cb(char *buf, int size, int rwflag, void *u)
{
    pem_calls++;
    printf("  pem callback: size %d rwflag %d u [%s]\n", size, rwflag, str(u));
    if (size < 6)
        return -1;
    memcpy(buf, "secret", 6);
    return 6;
}

static void test_utilities(UI_METHOD *m, UI_METHOD *mp)
{
    char buf[100], buff[100];
    UI_METHOD *w;
    UI *ui;
    int r;

    UI_set_default_method(m);
    check(UI_get_default_method() == m, "the default method set");
    ui = UI_new();
    check(UI_get_method(ui) == m, "a new UI takes it");
    UI_free(ui);

    script("pw1", "pw1", NULL);
    memset(buf, 0, sizeof(buf));
    r = UI_UTIL_read_pw(buf, buff, 20, "Password:", 1);
    printf("  UI_UTIL_read_pw %d [%s]\n", r, buf);
    script("pw2", NULL, NULL);
    r = UI_UTIL_read_pw_string(buf, 20, "Password:", 0);
    printf("  UI_UTIL_read_pw_string %d [%s]\n", r, buf);
    printf("  UI_UTIL_read_pw with no room %d\n", UI_UTIL_read_pw(buf, buff, 0, "x", 0));

    EVP_set_pw_prompt("Default prompt:");
    printf("  EVP_get_pw_prompt [%s]\n", str(EVP_get_pw_prompt()));
    script("pw3", "pw3", NULL);
    r = EVP_read_pw_string(buf, 20, NULL, 1);
    printf("  EVP_read_pw_string %d [%s]\n", r, buf);
    script("ab", NULL, NULL);
    r = EVP_read_pw_string_min(buf, 4, 20, "Min 4:", 0);
    printf("  EVP_read_pw_string_min too short %d\n", r);
    errors();
    EVP_set_pw_prompt(NULL);
    printf("  EVP_get_pw_prompt cleared [%s]\n", str(EVP_get_pw_prompt()));

    /* PEM_def_callback: userdata as the password, else asked through the default UI. */
    r = PEM_def_callback(buf, 3, 0, "longpass");
    printf("  PEM_def_callback with userdata %d [%.*s]\n", r, r > 0 ? r : 0, buf);
    script("typed", "typed", NULL);
    memset(buf, 0, sizeof(buf));
    r = PEM_def_callback(buf, 20, 1, NULL);
    printf("  PEM_def_callback asked %d [%s]\n", r, buf);
    script("ab", "ab", NULL);
    r = PEM_def_callback(buf, 20, 1, NULL);
    printf("  PEM_def_callback too short %d\n", r);
    errors();

    /* The PEM callback wrapper. */
    w = UI_UTIL_wrap_read_pem_callback(pem_cb, 1);
    check(w != NULL, "UI_UTIL_wrap_read_pem_callback");
    ui = UI_new_method(w);
    UI_add_user_data(ui, "cbarg");
    memset(buf, 0, sizeof(buf));
    UI_add_input_string(ui, "Wrapped:", 0, buf, 0, 50);
    UI_add_verify_string(ui, "Wrapped again:", 0, buff, 0, 50, buf);
    r = UI_process(ui);
    printf("  wrapped: process %d [%s] calls %d\n", r, buf, pem_calls);
    UI_free(ui);
    UI_destroy_method(w);
    w = UI_UTIL_wrap_read_pem_callback(NULL, 0);
    ui = UI_new_method(w);
    UI_add_user_data(ui, "from-userdata");
    memset(buf, 0, sizeof(buf));
    UI_add_input_string(ui, "Default:", 0, buf, 0, 50);
    r = UI_process(ui);
    printf("  wrapped default callback: process %d [%s]\n", r, buf);
    UI_free(ui);
    UI_destroy_method(w);
    (void)mp;
}

/* An encoder encrypting a traditional PEM with a passphrase from a pem_password_cb or a UI. */
static void test_encoder(UI_METHOD *mp)
{
    static const char key_pem[] =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMkNIRFUM9yc+f3f\n"
        "4X382GadKojwXpFJiCmuj4GKt16Woi9E5VKTo5rCpZSaj9ZJwz72plEZJP7+hNBX\n"
        "asXyH83dfoKA44g2oIM7kpvAAuj441wdJENZfgRZACjqtl7oAvaswEz1NnvJAhuO\n"
        "GDbqlvdoIcghZI5EK9nyuqWt1w79AgMBAAECgYBgpLYDjXVMlAy7k7XiCPvA/8Wl\n"
        "g94BetZAKxACljqk9kXJ8RVHB386clyDvXRs7pIzHv89tpeJF7GiMJM7ybKtObJf\n"
        "IRBSwRckuVHdlxI4YzTK+xBNGzkjzvj5BpvDtCSsFlfqFM/Uxt/NJzhLOuvpYcwc\n"
        "dypwHmyAEdLyu/HrAQJBAOMaAMxmHnW66UcW86yOTWFMqo2d7JFnuMzDsdcGIA8O\n"
        "onvxVjPs8cWlRd2pc+pBxKi5XaKHAxcl1zjH1mVQYsECQQDiooTpTnxXyQG7J+zA\n"
        "SQgERnZF4fwpdiKn4iJbP+PVrS6ZQ0ND+UN893fY+H9Q+/plEJX13c0nWKqceX0t\n"
        "TEc9AkANlzbJBKt5/C+Ns4/tma6DziS+yN6pbP2gM23nIlS00fljVXQFM37chyGB\n"
        "PGzVbg4o0r8JxO6oaflRSpRIB+GBAkANUhgVznMohbwAUBxuQNyjw7B38wxrM3Je\n"
        "A8CZNGwjxwYSJA30FNaOpcz5h8GT9PuGrS7jQKIqSd/dSpa87trRAkBkyCVNVUoP\n"
        "mf0C/4pEuFF9WmDZ+IBGooNI3YCkePXHU+bcZsXI76kPdHJgtcE0yixVgDlwqBuw\n"
        "v3PX/DuH/TDr\n"
        "-----END PRIVATE KEY-----\n";
    BIO *in = BIO_new_mem_buf(key_pem, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    int how;

    BIO_free(in);
    check(k != NULL, "the RSA key");
    if (k == NULL) {
        errors();
        return;
    }
    for (how = 0; how < 2; how++) {
        OSSL_ENCODER_CTX *ctx = OSSL_ENCODER_CTX_new_for_pkey(k, EVP_PKEY_KEYPAIR, "PEM",
                                                              "type-specific", NULL);
        unsigned char *data = NULL;
        size_t len = 0;
        EVP_PKEY *back = NULL;
        BIO *b;
        char what[100];

        OSSL_ENCODER_CTX_set_cipher(ctx, "AES-128-CBC", NULL);
        pem_calls = 0;
        script("secret", "secret", NULL);
        if (how == 0)
            check(OSSL_ENCODER_CTX_set_pem_password_cb(ctx, pem_cb, "enc"), "set_pem_password_cb");
        else
            check(OSSL_ENCODER_CTX_set_passphrase_ui(ctx, mp, NULL), "set_passphrase_ui");
        snprintf(what, sizeof(what), "%s: encoded", how == 0 ? "pem callback" : "UI method");
        check(OSSL_ENCODER_to_data(ctx, &data, &len), what);
        printf("  callback calls %d, answers read %d, encrypted %s\n", pem_calls, next_answer,
               data != NULL && strstr((char *)data, "ENCRYPTED") != NULL ? "yes" : "no");
        OSSL_ENCODER_CTX_free(ctx);
        b = BIO_new_mem_buf(data, (int)len);
        pem_calls = 0;
        back = PEM_read_bio_PrivateKey(b, NULL, pem_cb, "dec");
        snprintf(what, sizeof(what), "%s: decrypts with a pem callback (%d calls)",
                 how == 0 ? "pem callback" : "UI method", pem_calls);
        check(back != NULL && EVP_PKEY_eq(back, k) == 1, what);
        EVP_PKEY_free(back);
        BIO_free(b);
        OPENSSL_free(data);
        ERR_clear_error();
    }
    EVP_PKEY_free(k);
}

int main(void)
{
    UI_METHOD *m = scripted(0), *mp = scripted(1);

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    check(m != NULL && mp != NULL, "the scripted methods");
    test_strings(m);
    test_failures(m);
    test_print_errors(m);
    test_user_data(mp);
    test_utilities(m, mp);
    test_encoder(mp);
    UI_set_default_method(NULL);
    UI_destroy_method(m);
    UI_destroy_method(mp);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
