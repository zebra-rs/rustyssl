/*
 * Conformance test for the decoder framework (OSSL_DECODER(3), OSSL_DECODER_CTX(3),
 * OSSL_DECODER_from_bio(3)) with the default provider's structural decoders, in TAP format:
 * fetching decoders and their names, properties, and parameter lists, and the fetch errors;
 * listing them; contexts given decoders one by one and by add_extra's chains; decoding PEM
 * (plain, a traditional DEK-Info encryption with a passphrase given each way, a certificate,
 * an unknown type) and DER (SubjectPublicKeyInfo, EncryptedPrivateKeyInfo without a
 * passphrase) into a construct callback that prints what each level passes on; the input type,
 * structure, and selection; from_data's remaining input; from_fp; the cleanup; and the errors.
 *
 * The key decoders come with step 4.7b2, and decrypting PKCS#8 with step 4.7d, so the walks here
 * stop at DER.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
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

static void print_name(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static void names(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    if (p == NULL)
        printf(" (none)");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u", p->key, p->data_type);
    printf("\n");
}

static const char PUB_PEM[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOpHMxf8yxrjnTSjEJmHUQro48fyPbAc\n"
    "CvBdS86HOFf0x+A2kzEu6WrGG18fYQIwUKc3FewoBVqmG1aa4SgHwssCAwEAAQ==\n"
    "-----END PUBLIC KEY-----\n";

static const char TRAD_PEM[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBPAIBAAJBAOpHMxf8yxrjnTSjEJmHUQro48fyPbAcCvBdS86HOFf0x+A2kzEu\n"
    "6WrGG18fYQIwUKc3FewoBVqmG1aa4SgHwssCAwEAAQJBAKp1S5O0dwMFgah+zOEo\n"
    "N6s8cB9W/dNZVAw3laSbdj9nkh8E+lMUAn6Rr8i05PLBZ2pJc7ME2LU7E7DrAI5P\n"
    "9iECIQD/1lbUEyRqwWWWMOrTyDOcu/8urENxUjJyz/t5ZVOodwIhAOptWYW8k4Q1\n"
    "sRoovz937dSl3zO9blyH/cHYNkzYf2FNAiEA8DrxD3TmFkSBwpUufC0aocs6JDZn\n"
    "oepAKuU3StelxaMCIHoffxyBcaPVSK6k/YR12KsHwjA1BfIkUhiSpy7/NdSdAiEA\n"
    "wdTMyx/hLA6cfKgNG88uTaUDdb7/wWeqKTbsYH5Qrek=\n"
    "-----END RSA PRIVATE KEY-----\n";

static const char ENC_TRAD_PEM[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "Proc-Type: 4,ENCRYPTED\n"
    "DEK-Info: AES-128-CBC,CE867A7B54987C4DBF4038675F1C3376\n"
    "\n"
    "1TR66nptKUJxi67wmHCuLuBRtdutaWHnWmyWe+b9gh77UNJ2SdbsF1wcMYHNejVw\n"
    "w1P34XGL2Omxn7aQuoubKp0H4wJLCNm4GzulJqRlmNpyzG+ECYHVlNCFnDyCuaik\n"
    "EULXHWs6TbRtL6p8KRkhHMq93OggKj5/0/1WBuipRxs8To01c8vmSIWu1le439XQ\n"
    "pC4R2zGRYUjujWJpXLSk0Pl/EWRFnLhEQtjYEanXjwuZG9xRqN+C4LQpLil28jy+\n"
    "bCCWq6CVMDpB4fOQotvrq8gt2XYFaFAYg3NOAf3pe17JRer1XUVJRR4wB1RehNRh\n"
    "p7ME5wHXWXs3D5k8WLDB4VZZ0c3xOjaneti27MlgEbvT/0Wn9ewb0k84wvrPNGOF\n"
    "7h+bBW03cxpblE8j8akC7UR5Dcq4ClhaIGyLTc3oB+DTotnf0gxh67Lwhl4BEyET\n"
    "-----END RSA PRIVATE KEY-----\n";

static const char ENC_P8_PEM[] =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    "MIIBxTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQNO4DBgtRaOFemoDh\n"
    "sphL5wICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEECfRrLF3LRmKI30k\n"
    "IgR6UCYEggFgGic+z6lAyMkS9tVABnJme6/Ia0AvWjXQoypCLCxA2KvR8L4MSwSX\n"
    "zhO6SlC5CZqY64NWIlUsLQNjJCD7OR//V92sHs/wbhENBjfOvfxyT7JPwMelFpsk\n"
    "O8g2YiSLURdnDdYyle4DF4M11diqAHZ0sb2TWYALDF3yCIkshTJAVEMvpR57gnGF\n"
    "PeyWEWv2FSSfnyiZ1fUeIG44Jm3K+0I7QT4237gcBywt6A+bKjreBuEf2EUbtYgQ\n"
    "YhJjDLmnYid41a1jF0hmebMFzLFn0592ASN5oLm6qM6bwrimL8iXybdwl2tIMAr6\n"
    "1/zWpU+Rq1x8DxA2UoJaS1nI4fmaBofQawGhFN8+nHPXVW2MiyqAgZWRyCAv8AUC\n"
    "5zNoUXcP3fxAjL/S8TPsP7IU4Gr2wiaK/xLks6rrVnnBgGucIRhLnL4xLBEF1IO2\n"
    "gQfXkrdKmpo3dW1Ivcyqculm8ruZYeEBrw==\n"
    "-----END ENCRYPTED PRIVATE KEY-----\n";

/* What the construct callback saw, and what it answers. */
static int construct_calls = 0;
static int construct_answer = 1;

static int construct(OSSL_DECODER_INSTANCE *inst, const OSSL_PARAM *params, void *data)
{
    const OSSL_PARAM *p;
    int was_set = -1;
    const char *structure = OSSL_DECODER_INSTANCE_get_input_structure(inst, &was_set);

    construct_calls++;
    printf("  construct (%s) by %s input %s structure %s ctx %s\n", (const char *)data,
           OSSL_DECODER_get0_name(OSSL_DECODER_INSTANCE_get_decoder(inst)),
           OSSL_DECODER_INSTANCE_get_input_type(inst), structure != NULL ? structure : "(none)",
           OSSL_DECODER_INSTANCE_get_decoder_ctx(inst) != NULL ? "set" : "NULL");
    for (p = params; p != NULL && p->key != NULL; p++) {
        if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            printf("    %s: %s\n", p->key, (const char *)p->data);
        } else if (p->data_type == OSSL_PARAM_OCTET_STRING) {
            const unsigned char *d = p->data;
            size_t i;

            printf("    %s (%zu):", p->key, p->data_size);
            for (i = 0; i < p->data_size && i < 12; i++)
                printf("%02x", d[i]);
            printf("\n");
        } else if (p->data_type == OSSL_PARAM_INTEGER) {
            printf("    %s: %d\n", p->key, *(const int *)p->data);
        }
    }
    return construct_answer;
}

static int cleanups = 0;

static void cleanup(void *data)
{
    cleanups++;
    printf("  cleanup (%s)\n", (const char *)data);
}

static int pass_calls = 0;

static int pass_cb(char *pass, size_t pass_size, size_t *pass_len, const OSSL_PARAM params[],
                   void *arg)
{
    const char *pw = arg;

    pass_calls++;
    (void)params;
    if (pw == NULL)
        return 0;
    *pass_len = strlen(pw) < pass_size ? strlen(pw) : pass_size;
    memcpy(pass, pw, *pass_len);
    return 1;
}

/* A context with the named decoder (fetched with the properties) and the constructor. */
static OSSL_DECODER_CTX *ctx_with(const char *props, const char *label)
{
    OSSL_DECODER_CTX *c = OSSL_DECODER_CTX_new();
    OSSL_DECODER *d = OSSL_DECODER_fetch(NULL, "DER", props);

    printf("  add %s: %d\n", props, OSSL_DECODER_CTX_add_decoder(c, d));
    OSSL_DECODER_free(d);
    OSSL_DECODER_CTX_set_construct(c, construct);
    OSSL_DECODER_CTX_set_construct_data(c, (void *)label);
    return c;
}

static void decode_text(const char *what, OSSL_DECODER_CTX *c, const char *text)
{
    BIO *b = BIO_new_mem_buf(text, -1);
    int r;

    construct_calls = 0;
    r = OSSL_DECODER_from_bio(c, b);
    printf("  %s: %d constructs %d\n", what, r, construct_calls);
    errors();
    BIO_free(b);
}

static int count_der = 0;

static void count_decoder(OSSL_DECODER *d, void *arg)
{
    (void)arg;
    if (OSSL_DECODER_is_a(d, "DER")) {
        count_der++;
        printf("  listed DER: %s\n", OSSL_DECODER_get0_properties(d));
    }
}

static void test_fetch(void)
{
    OSSL_DECODER *d = OSSL_DECODER_fetch(NULL, "DER", "input=pem");
    OSSL_PARAM none[] = { OSSL_PARAM_END };

    check(d != NULL, "fetch DER input=pem");
    printf("  name %s description %s provider %s\n", OSSL_DECODER_get0_name(d),
           OSSL_DECODER_get0_description(d) == NULL ? "(none)" : "?",
           OSSL_PROVIDER_get0_name(OSSL_DECODER_get0_provider(d)));
    printf("  properties %s\n", OSSL_DECODER_get0_properties(d));
    printf("  names:");
    printf(" (%d)\n", OSSL_DECODER_names_do_all(d, print_name, NULL));
    printf("  is_a DER %d der %d PEM %d\n", OSSL_DECODER_is_a(d, "DER"), OSSL_DECODER_is_a(d, "der"),
           OSSL_DECODER_is_a(d, "PEM"));
    names("gettable", OSSL_DECODER_gettable_params(d));
    names("settable", OSSL_DECODER_settable_ctx_params(d));
    printf("  get_params %d\n", OSSL_DECODER_get_params(d, none));
    printf("  up_ref %d\n", OSSL_DECODER_up_ref(d));
    OSSL_DECODER_free(d);
    OSSL_DECODER_free(d);
    OSSL_DECODER_free(NULL);
    d = OSSL_DECODER_fetch(NULL, "DER", "structure=SubjectPublicKeyInfo");
    check(d != NULL, "fetch DER structure=SubjectPublicKeyInfo");
    printf("  properties %s\n", OSSL_DECODER_get0_properties(d));
    names("settable", OSSL_DECODER_settable_ctx_params(d));
    OSSL_DECODER_free(d);
    printf("  NoSuchDecoder: %s\n", OSSL_DECODER_fetch(NULL, "NoSuchDecoder", NULL) == NULL ? "NULL" : "?");
    errors();
    printf("  DER provider=nope: %s\n", OSSL_DECODER_fetch(NULL, "DER", "provider=nope") == NULL ? "NULL" : "?");
    errors();
    printf("  getters of NULL: provider %s properties %s\n",
           OSSL_DECODER_get0_provider(NULL) == NULL ? "NULL" : "?",
           OSSL_DECODER_get0_properties(NULL) == NULL ? "NULL" : "?");
    printf("  names_do_all NULL %d gettable %s get_params %d settable %s\n",
           OSSL_DECODER_names_do_all(NULL, print_name, NULL),
           OSSL_DECODER_gettable_params(NULL) == NULL ? "NULL" : "?",
           OSSL_DECODER_get_params(NULL, none),
           OSSL_DECODER_settable_ctx_params(NULL) == NULL ? "NULL" : "?");
    errors();
    OSSL_DECODER_do_all_provided(NULL, count_decoder, NULL);
    check(count_der == 3, "three DER decoders listed");
}

static void test_ctx(void)
{
    OSSL_DECODER_CTX *c = OSSL_DECODER_CTX_new(), *e;
    OSSL_PARAM params[2];
    BIO *b;

    check(c != NULL, "OSSL_DECODER_CTX_new");
    printf("  decoders %d, of NULL %d\n", OSSL_DECODER_CTX_get_num_decoders(c),
           OSSL_DECODER_CTX_get_num_decoders(NULL));
    printf("  getters: construct %s data %s cleanup %s\n",
           OSSL_DECODER_CTX_get_construct(c) == NULL ? "NULL" : "?",
           OSSL_DECODER_CTX_get_construct_data(c) == NULL ? "NULL" : "?",
           OSSL_DECODER_CTX_get_cleanup(c) == NULL ? "NULL" : "?");
    decode_text("no decoders", c, PUB_PEM);
    printf("  from_bio NULL bio %d\n", OSSL_DECODER_from_bio(c, NULL));
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DECODER_PARAM_PROPERTIES, "", 0);
    params[1] = OSSL_PARAM_construct_end();
    printf("  set_params without decoders %d\n", OSSL_DECODER_CTX_set_params(c, params));
    printf("  add_extra without decoders %d\n", OSSL_DECODER_CTX_add_extra(c, NULL, NULL));
    printf("  setters on NULL: %d %d %d %d %d %d %d %d\n", OSSL_DECODER_CTX_set_selection(NULL, 0),
           OSSL_DECODER_CTX_set_input_type(NULL, "PEM"), OSSL_DECODER_CTX_set_input_structure(NULL, "x"),
           OSSL_DECODER_CTX_set_construct(NULL, construct), OSSL_DECODER_CTX_set_construct_data(NULL, NULL),
           OSSL_DECODER_CTX_set_cleanup(NULL, cleanup), OSSL_DECODER_CTX_set_params(NULL, params),
           OSSL_DECODER_CTX_add_extra(NULL, NULL, NULL));
    printf("  add_decoder NULL %d\n", OSSL_DECODER_CTX_add_decoder(c, NULL));
    errors();
    OSSL_DECODER_CTX_free(c);
    OSSL_DECODER_CTX_free(NULL);

    /* PEM to DER, with what each PEM type holds. */
    c = ctx_with("input=pem", "pem2der");
    OSSL_DECODER_CTX_set_cleanup(c, cleanup);
    printf("  construct %s cleanup %s data %s\n",
           OSSL_DECODER_CTX_get_construct(c) == construct ? "set" : "?",
           OSSL_DECODER_CTX_get_cleanup(c) == cleanup ? "set" : "?",
           (const char *)OSSL_DECODER_CTX_get_construct_data(c));
    printf("  set_params %d\n", OSSL_DECODER_CTX_set_params(c, params));
    decode_text("public key", c, PUB_PEM);
    decode_text("traditional RSA", c, TRAD_PEM);
    decode_text("encrypted traditional, no passphrase", c, ENC_TRAD_PEM);
    printf("  set_passphrase %d\n", OSSL_DECODER_CTX_set_passphrase(c, (const unsigned char *)"secret", 6));
    decode_text("encrypted traditional, explicit passphrase", c, ENC_TRAD_PEM);
    printf("  wrong passphrase %d\n", OSSL_DECODER_CTX_set_passphrase(c, (const unsigned char *)"wrong", 5));
    decode_text("encrypted traditional, wrong passphrase", c, ENC_TRAD_PEM);
    pass_calls = 0;
    printf("  set_passphrase_cb %d\n", OSSL_DECODER_CTX_set_passphrase_cb(c, pass_cb, "secret"));
    decode_text("encrypted traditional, callback", c, ENC_TRAD_PEM);
    printf("  callback calls %d\n", pass_calls);
    OSSL_DECODER_CTX_set_passphrase_cb(c, pass_cb, NULL);
    decode_text("encrypted traditional, refusing callback", c, ENC_TRAD_PEM);
    printf("  NULL passphrase %d, NULL cb %d\n", OSSL_DECODER_CTX_set_passphrase(c, NULL, 0),
           OSSL_DECODER_CTX_set_passphrase_cb(c, NULL, NULL));
    errors();
    /* Set only: asking them needs a UI. */
    printf("  pem cb %d NULL %d ui %d NULL %d\n", OSSL_DECODER_CTX_set_pem_password_cb(c, PEM_def_callback, NULL),
           OSSL_DECODER_CTX_set_pem_password_cb(c, NULL, NULL),
           OSSL_DECODER_CTX_set_passphrase_ui(c, UI_OpenSSL(), NULL),
           OSSL_DECODER_CTX_set_passphrase_ui(c, NULL, NULL));
    errors();
    OSSL_DECODER_CTX_set_passphrase_cb(c, pass_cb, NULL);
    decode_text("encrypted PKCS#8", c, ENC_P8_PEM);
    decode_text("a certificate", c,
                "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n");
    decode_text("an unknown type", c, "-----BEGIN FOO-----\nMAMCAQA=\n-----END FOO-----\n");
    decode_text("not PEM", c, "hello");
    construct_answer = 0;
    decode_text("a refusing constructor", c, PUB_PEM);
    construct_answer = 1;
    printf("  input type DER %d\n", OSSL_DECODER_CTX_set_input_type(c, "DER"));
    decode_text("input type DER", c, PUB_PEM);
    printf("  input type pem %d\n", OSSL_DECODER_CTX_set_input_type(c, "pem"));
    decode_text("input type pem", c, PUB_PEM);
    printf("  structure SubjectPublicKeyInfo %d\n",
           OSSL_DECODER_CTX_set_input_structure(c, "SubjectPublicKeyInfo"));
    decode_text("both set", c, TRAD_PEM);
    OSSL_DECODER_CTX_set_input_type(c, NULL);
    OSSL_DECODER_CTX_set_input_structure(c, NULL);
    printf("  selection public %d\n", OSSL_DECODER_CTX_set_selection(c, EVP_PKEY_PUBLIC_KEY));
    decode_text("public key, public selection", c, PUB_PEM);
    printf("  selection private %d\n", OSSL_DECODER_CTX_set_selection(c, EVP_PKEY_KEYPAIR));
    OSSL_DECODER_CTX_set_passphrase_cb(c, pass_cb, NULL);
    decode_text("encrypted PKCS#8, private selection", c, ENC_P8_PEM);
    {
        size_t len = strlen(PUB_PEM) * 2;
        char *two = malloc(len + 1);
        const unsigned char *p = (const unsigned char *)two;
        size_t left = len;
        int r;

        OSSL_DECODER_CTX_set_selection(c, 0);
        strcpy(two, PUB_PEM);
        strcat(two, PUB_PEM);
        construct_calls = 0;
        r = OSSL_DECODER_from_data(c, &p, &left);
        printf("  from_data %d left %zu moved %ld\n", r, left, (long)(p - (const unsigned char *)two));
        errors();
        p = NULL;
        printf("  from_data NULL %d\n", OSSL_DECODER_from_data(c, &p, &left));
        errors();
        free(two);
    }
    {
        FILE *fp = tmpfile();

        if (fp != NULL) {
            fputs(PUB_PEM, fp);
            rewind(fp);
            construct_calls = 0;
            printf("  from_fp %d constructs %d\n", OSSL_DECODER_from_fp(c, fp), construct_calls);
            errors();
            fclose(fp);
        }
    }
    OSSL_DECODER_CTX_free(c);
    printf("  cleanups %d\n", cleanups);

    /* SubjectPublicKeyInfo DER to its key type's, from the PEM's DER. */
    c = ctx_with("structure=SubjectPublicKeyInfo", "spki2typespki");
    b = BIO_new(BIO_s_mem());
    {
        BIO *in = BIO_new_mem_buf(PUB_PEM, -1);
        char *name = NULL, *header = NULL;
        unsigned char *der = NULL;
        long derlen = 0;

        PEM_read_bio(in, &name, &header, &der, &derlen);
        BIO_write(b, der, (int)derlen);
        construct_calls = 0;
        printf("  spki from_bio %d constructs %d\n", OSSL_DECODER_from_bio(c, b), construct_calls);
        errors();
        BIO_free(b);
        b = BIO_new_mem_buf(der, 10);
        printf("  spki of 10 octets %d\n", OSSL_DECODER_from_bio(c, b));
        errors();
        BIO_free(b);
        BIO_free(in);
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(der);
    }
    /* add_extra's chains from the SPKI decoder: the other DER decoders. */
    printf("  add_extra %d decoders %d\n", OSSL_DECODER_CTX_add_extra(c, NULL, NULL),
           OSSL_DECODER_CTX_get_num_decoders(c));
    decode_text("public key through the chain", c, PUB_PEM);
    printf("  add_extra again %d decoders %d\n", OSSL_DECODER_CTX_add_extra(c, NULL, "provider=default"),
           OSSL_DECODER_CTX_get_num_decoders(c));
    OSSL_DECODER_CTX_free(c);

    /* EncryptedPrivateKeyInfo DER without a passphrase. */
    e = ctx_with("structure=EncryptedPrivateKeyInfo", "epki2pki");
    {
        BIO *in = BIO_new_mem_buf(ENC_P8_PEM, -1);
        char *name = NULL, *header = NULL;
        unsigned char *der = NULL;
        long derlen = 0;

        PEM_read_bio(in, &name, &header, &der, &derlen);
        b = BIO_new_mem_buf(der, (int)derlen);
        OSSL_DECODER_CTX_set_passphrase_cb(e, pass_cb, NULL);
        construct_calls = 0;
        printf("  epki from_bio %d constructs %d\n", OSSL_DECODER_from_bio(e, b), construct_calls);
        errors();
        BIO_free(b);
        BIO_free(in);
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(der);
    }
    decode_text("epki of PEM text", e, PUB_PEM);
    OSSL_DECODER_CTX_free(e);
    printf("  export NULL %d\n", OSSL_DECODER_export(NULL, NULL, 0, NULL, NULL));
    printf("  instance getters of NULL: %s %s %s %s\n",
           OSSL_DECODER_INSTANCE_get_decoder(NULL) == NULL ? "NULL" : "?",
           OSSL_DECODER_INSTANCE_get_decoder_ctx(NULL) == NULL ? "NULL" : "?",
           OSSL_DECODER_INSTANCE_get_input_type(NULL) == NULL ? "NULL" : "?",
           OSSL_DECODER_INSTANCE_get_input_structure(NULL, NULL) == NULL ? "NULL" : "?");
    errors();
}

int main(void)
{
    test_fetch();
    test_ctx();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
