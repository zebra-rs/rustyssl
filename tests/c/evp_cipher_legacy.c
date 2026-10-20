/*
 * Conformance test for the static ciphers' own C functions (EVP_CIPHER_meth_get_init(3),
 * EVP_CIPHER_impl_ctx_size), in TAP format: copies of the static ciphers (EVP_CIPHER_meth_dup)
 * running them through EVP in every mode, and a cipher of the test's own that runs
 * EVP_aes_128_cbc()'s functions on state it keeps, as the dasync engine does, copied octet for
 * octet with the context.
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void hex(const char *what, const unsigned char *p, int n)
{
    int i;

    printf("  %s:", what);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static const unsigned char key[32] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
};
static const unsigned char iv[16] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
};
static const char plain[] = "The static cipher's own functions, run on the context's state.";

/* Encrypts the text in two updates (13 octets, then the rest) with `c`; returns the length. */
static int crypt(const EVP_CIPHER *c, int enc, const unsigned char *in, int inl, unsigned char *out,
                 int bits)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int l1 = 0, l2 = 0, l3 = 0, first = inl < 13 ? inl : 13;

    if (bits)
        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS);
    if (!EVP_CipherInit_ex(ctx, c, NULL, key, iv, enc)
        || !EVP_CipherUpdate(ctx, out, &l1, in, first)
        || !EVP_CipherUpdate(ctx, out + l1, &l2, in + first, inl - first)
        || !EVP_CipherFinal_ex(ctx, out + l1 + l2, &l3)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return l1 + l2 + l3;
}

/* A copy of the static cipher `name`, through EVP both ways. */
static void one(const char *name, int bits)
{
    const EVP_CIPHER *st = EVP_get_cipherbyname(name);
    EVP_CIPHER *c = st != NULL ? EVP_CIPHER_meth_dup(st) : NULL;
    unsigned char out[160], back[160];
    int inl = (int)sizeof(plain) - 1, n, m;
    char what[96];

    if (c == NULL) {
        printf("  %s: none\n", name);
        check(0, name);
        return;
    }
    printf("# %s: size %d, init %d, do %d, cleanup %d, ctrl %d, asn1 %d/%d\n", name,
           EVP_CIPHER_impl_ctx_size(st), EVP_CIPHER_meth_get_init(st) != NULL,
           EVP_CIPHER_meth_get_do_cipher(st) != NULL, EVP_CIPHER_meth_get_cleanup(st) != NULL,
           EVP_CIPHER_meth_get_ctrl(st) != NULL, EVP_CIPHER_meth_get_set_asn1_params(st) != NULL,
           EVP_CIPHER_meth_get_get_asn1_params(st) != NULL);
    n = crypt(c, 1, (const unsigned char *)plain, inl, out, bits);
    snprintf(what, sizeof(what), "%s encrypts", name);
    check(n > 0, what);
    if (n > 0)
        hex("ciphertext", out, n);
    m = n > 0 ? crypt(c, 0, out, n, back, bits) : -1;
    snprintf(what, sizeof(what), "%s decrypts it back", name);
    check(m == inl && memcmp(back, plain, (size_t)inl) == 0, what);
    EVP_CIPHER_meth_free(c);
    ERR_clear_error();
}

/*
 * The dasync way: a cipher of the test's own whose state is a pointer to state of the static
 * cipher's size, which its functions run on with the context's cipher data swapped for it.
 */
struct inner {
    void *data;
};

static const EVP_CIPHER *wrapped;

static int wrap_init(EVP_CIPHER_CTX *ctx, const unsigned char *k, const unsigned char *v, int enc)
{
    struct inner *in = EVP_CIPHER_CTX_get_cipher_data(ctx);
    int ret;

    if (in->data == NULL && EVP_CIPHER_impl_ctx_size(wrapped) != 0) {
        in->data = calloc(1, (size_t)EVP_CIPHER_impl_ctx_size(wrapped));
        if (in->data == NULL)
            return 0;
    }
    EVP_CIPHER_CTX_set_cipher_data(ctx, in->data);
    ret = EVP_CIPHER_meth_get_init(wrapped)(ctx, k, v, enc);
    EVP_CIPHER_CTX_set_cipher_data(ctx, in);
    return ret;
}

static int wrap_do(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    struct inner *s = EVP_CIPHER_CTX_get_cipher_data(ctx);
    int ret;

    EVP_CIPHER_CTX_set_cipher_data(ctx, s->data);
    ret = EVP_CIPHER_meth_get_do_cipher(wrapped)(ctx, out, in, inl);
    EVP_CIPHER_CTX_set_cipher_data(ctx, s);
    return ret;
}

static int wrap_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    struct inner *s = EVP_CIPHER_CTX_get_cipher_data(ctx);

    (void)arg;
    if (type == EVP_CTRL_COPY) {
        /* The copy's state: a copy, octet for octet, of the original's. */
        EVP_CIPHER_CTX *to = ptr;
        struct inner *t = EVP_CIPHER_CTX_get_cipher_data(to);
        size_t sz = (size_t)EVP_CIPHER_impl_ctx_size(wrapped);

        t->data = malloc(sz);
        if (t->data == NULL)
            return 0;
        memcpy(t->data, s->data, sz);
        return 1;
    }
    return type == EVP_CTRL_INIT ? 1 : -1;
}

static int wrap_cleanup(EVP_CIPHER_CTX *ctx)
{
    struct inner *s = EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (s != NULL)
        free(s->data);
    return 1;
}

static void test_wrapped(void)
{
    EVP_CIPHER *c = EVP_CIPHER_meth_new(NID_aes_128_cbc, 16, 16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(), *copy = EVP_CIPHER_CTX_new();
    unsigned char a[160], b[160], ref[160];
    int la = 0, lb = 0, l = 0, lr;

    wrapped = EVP_aes_128_cbc();
    check(c != NULL && EVP_CIPHER_meth_set_iv_length(c, 16)
              && EVP_CIPHER_meth_set_flags(c, EVP_CIPH_CBC_MODE | EVP_CIPH_CUSTOM_COPY)
              && EVP_CIPHER_meth_set_init(c, wrap_init)
              && EVP_CIPHER_meth_set_do_cipher(c, wrap_do)
              && EVP_CIPHER_meth_set_ctrl(c, wrap_ctrl)
              && EVP_CIPHER_meth_set_cleanup(c, wrap_cleanup)
              && EVP_CIPHER_meth_set_impl_ctx_size(c, sizeof(struct inner)),
          "a cipher over EVP_aes_128_cbc()'s functions");
    /* The reference ciphertext, from the provider's AES-128-CBC. */
    lr = crypt(EVP_aes_128_cbc(), 1, (const unsigned char *)plain, (int)sizeof(plain) - 1, ref, 0);
    check(EVP_EncryptInit_ex(ctx, c, NULL, key, iv)
              && EVP_EncryptUpdate(ctx, a, &la, (const unsigned char *)plain, 20),
          "encrypting the first part");
    check(EVP_CIPHER_CTX_copy(copy, ctx), "EVP_CIPHER_CTX_copy copies the state octet for octet");
    check(EVP_EncryptUpdate(ctx, a + la, &l, (const unsigned char *)plain + 20,
                            (int)sizeof(plain) - 1 - 20),
          "the original goes on");
    la += l;
    check(EVP_EncryptFinal_ex(ctx, a + la, &l), "and finishes");
    la += l;
    memcpy(b, a, 16);
    lb = 16;
    check(EVP_EncryptUpdate(copy, b + lb, &l, (const unsigned char *)plain + 20,
                            (int)sizeof(plain) - 1 - 20),
          "the copy goes on from the same point");
    lb += l;
    check(EVP_EncryptFinal_ex(copy, b + lb, &l), "and finishes");
    lb += l;
    hex("wrapped", a, la);
    check(la == lr && memcmp(a, ref, (size_t)la) == 0, "the same ciphertext as AES-128-CBC's");
    check(lb == la && memcmp(a, b, (size_t)la) == 0, "the copy's is the same");
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_CTX_free(copy);
    EVP_CIPHER_meth_free(c);
}

/*
 * A cipher over EVP_aes_128_gcm()'s own functions and state size, as the ossltest engine makes
 * its AES-128-GCM: the context's state is the static cipher's.
 */
static int gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *k, const unsigned char *v, int enc)
{
    return EVP_CIPHER_meth_get_init(EVP_aes_128_gcm())(ctx, k, v, enc);
}

static int gcm_do(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    return EVP_CIPHER_meth_get_do_cipher(EVP_aes_128_gcm())(ctx, out, in, inl);
}

static int gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    return EVP_CIPHER_meth_get_ctrl(EVP_aes_128_gcm())(ctx, type, arg, ptr);
}

static int gcm_cleanup(EVP_CIPHER_CTX *ctx)
{
    return EVP_CIPHER_meth_get_cleanup(EVP_aes_128_gcm())(ctx);
}

/* Encrypts `plain` with AAD under `c`; the ciphertext's length, the tag in `tag`. */
static int gcm_seal(const EVP_CIPHER *c, unsigned char *out, unsigned char tag[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    static const unsigned char aad[] = "header";
    int l = 0, n = 0, ok;

    ok = EVP_EncryptInit_ex(ctx, c, NULL, NULL, NULL)
         && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) > 0
         && EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)
         && EVP_EncryptUpdate(ctx, NULL, &l, aad, (int)sizeof(aad) - 1)
         && EVP_EncryptUpdate(ctx, out, &l, (const unsigned char *)plain, (int)sizeof(plain) - 1)
         && EVP_EncryptFinal_ex(ctx, out + l, &n)
         && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) > 0;
    EVP_CIPHER_CTX_free(ctx);
    return ok ? l + n : -1;
}

/* Decrypts `in` with `tag`: whether the tag held, and the plaintext in `out`. */
static int gcm_open(const EVP_CIPHER *c, const unsigned char *in, int inl, unsigned char tag[16],
                    unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    static const unsigned char aad[] = "header";
    int l = 0, n = 0, ok;

    ok = EVP_DecryptInit_ex(ctx, c, NULL, NULL, NULL)
         && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) > 0
         && EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)
         && EVP_DecryptUpdate(ctx, NULL, &l, aad, (int)sizeof(aad) - 1)
         && EVP_DecryptUpdate(ctx, out, &l, in, inl)
         && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) > 0
         && EVP_DecryptFinal_ex(ctx, out + l, &n) > 0;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* A TLS 1.2 record (explicit IV, payload, tag) sealed and opened in place. */
static void gcm_tls_record(const EVP_CIPHER *c)
{
    EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new(), *d = EVP_CIPHER_CTX_new();
    unsigned char hdr[13] = { 0, 0, 0, 0, 0, 0, 0, 1, 23, 3, 3, 0, 0 };
    unsigned char rec[8 + 32 + 16];
    int pad, n, m;

    memcpy(rec + 8, plain, 32);
    hdr[11] = (unsigned char)((8 + 32 + 16) >> 8);
    hdr[12] = (unsigned char)((8 + 32 + 16) & 0xff);
    check(EVP_CipherInit_ex(e, c, NULL, key, NULL, 1)
              && EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_GCM_SET_IV_FIXED, 4, (void *)iv) > 0,
          "TLS: a sealing context with a fixed IV field");
    /* The header gives the record's length with the explicit IV and the tag; seal wants the
       payload's, which the ctrl corrects and returns the tag length for. */
    hdr[11] = 0;
    hdr[12] = 8 + 32;
    pad = EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_AEAD_TLS1_AAD, 13, hdr);
    printf("# TLS AAD returns %d\n", pad);
    n = EVP_Cipher(e, rec, rec, (unsigned int)sizeof(rec));
    printf("# sealed %d\n", n);
    check(EVP_CipherInit_ex(d, c, NULL, key, NULL, 0)
              && EVP_CIPHER_CTX_ctrl(d, EVP_CTRL_GCM_SET_IV_FIXED, 4, (void *)iv) > 0,
          "TLS: an opening context with the same fixed field");
    hdr[11] = 0;
    hdr[12] = 8 + 32 + 16;
    pad = EVP_CIPHER_CTX_ctrl(d, EVP_CTRL_AEAD_TLS1_AAD, 13, hdr);
    m = EVP_Cipher(d, rec, rec, (unsigned int)sizeof(rec));
    printf("# opened %d (pad %d)\n", m, pad);
    check(m == 32 && memcmp(rec + 8, plain, 32) == 0, "TLS: the record opens to its payload");
    rec[20] ^= 1;
    hdr[11] = 0;
    hdr[12] = 8 + 32 + 16;
    EVP_CIPHER_CTX_ctrl(d, EVP_CTRL_AEAD_TLS1_AAD, 13, hdr);
    check(EVP_Cipher(d, rec, rec, (unsigned int)sizeof(rec)) == -1,
          "TLS: a changed record doesn't open");
    EVP_CIPHER_CTX_free(e);
    EVP_CIPHER_CTX_free(d);
}

static void test_wrapped_gcm(void)
{
    EVP_CIPHER *c = EVP_CIPHER_meth_new(NID_aes_128_gcm, 1, 16);
    unsigned char ref[128], out[128], back[128], tag[16], reftag[16];
    int lr, l;

    printf("# AES-128-GCM over EVP_aes_128_gcm()'s functions, state size %d\n",
           EVP_CIPHER_impl_ctx_size(EVP_aes_128_gcm()) > 0);
    check(c != NULL && EVP_CIPHER_meth_set_iv_length(c, 12)
              && EVP_CIPHER_meth_set_flags(c, EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV
                                                  | EVP_CIPH_FLAG_CUSTOM_CIPHER
                                                  | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT
                                                  | EVP_CIPH_FLAG_AEAD_CIPHER
                                                  | EVP_CIPH_CUSTOM_IV_LENGTH)
              && EVP_CIPHER_meth_set_init(c, gcm_init)
              && EVP_CIPHER_meth_set_do_cipher(c, gcm_do)
              && EVP_CIPHER_meth_set_ctrl(c, gcm_ctrl)
              && EVP_CIPHER_meth_set_cleanup(c, gcm_cleanup)
              && EVP_CIPHER_meth_set_impl_ctx_size(c, EVP_CIPHER_impl_ctx_size(EVP_aes_128_gcm())),
          "a cipher over EVP_aes_128_gcm()'s functions");
    lr = gcm_seal(EVP_aes_128_gcm(), ref, reftag);
    l = gcm_seal(c, out, tag);
    hex("gcm", out, l > 0 ? l : 0);
    hex("tag", tag, 16);
    check(l == lr && memcmp(out, ref, (size_t)l) == 0 && memcmp(tag, reftag, 16) == 0,
          "the same ciphertext and tag as AES-128-GCM's");
    check(gcm_open(c, out, l, tag, back) && memcmp(back, plain, sizeof(plain) - 1) == 0,
          "it opens with the tag");
    tag[0] ^= 1;
    check(!gcm_open(c, out, l, tag, back), "and not with another");
    ERR_clear_error();
    gcm_tls_record(c);
    ERR_clear_error();
    EVP_CIPHER_meth_free(c);
}

int main(void)
{
    static const char *const names[] = {
        "aes-128-ecb", "aes-192-cbc", "aes-256-cfb", "aes-128-cfb8", "aes-256-cfb1",
        "aes-128-ofb", "aes-256-ctr", "camellia-128-cbc", "camellia-256-ctr", "camellia-192-cfb8",
        "seed-cbc", "seed-ofb", "bf-cbc", "bf-cfb", "cast5-ecb", "cast5-ofb", "idea-cbc", "idea-cfb",
        "rc2-cbc", "rc2-40-cbc", "rc2-ofb", "des-cbc", "des-cfb8", "des-cfb1", "des-ede-cbc",
        "des-ede3-cbc", "des-ede3-cfb1", "des-ede3-ofb", "desx-cbc", "rc4", "rc4-40",
    };
    size_t i;

    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL);
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        one(names[i], 0);
    printf("# 1-bit CFB counted in bits\n");
    one("aes-128-cfb1", 1);
    one("des-ede3-cfb1", 1);
    printf("# the NULL cipher: init %d, do %d\n", EVP_CIPHER_meth_get_init(EVP_enc_null()) != NULL,
           EVP_CIPHER_meth_get_do_cipher(EVP_enc_null()) != NULL);
    test_wrapped();
    test_wrapped_gcm();
    printf("1..%d\n", number);
    return failures != 0;
}
