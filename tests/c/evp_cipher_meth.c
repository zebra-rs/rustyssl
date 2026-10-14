/*
 * Conformance test for application-defined ciphers (EVP_CIPHER_meth_new(3)), in TAP format:
 *   - EVP_CIPHER_meth_new, the setters (each sets once), the getters, EVP_CIPHER_meth_dup and
 *     EVP_CIPHER_meth_free, EVP_CIPHER_impl_ctx_size, and the EVP_CIPHER getters on it;
 *   - ciphering with it: every call of its functions is logged, so the order and count of
 *     init, do_cipher (with its lengths), cleanup, ctrl, and the ASN.1 parameter functions
 *     are compared, through EVP_CipherInit_ex (the IV kept by mode, EVP_CTRL_INIT,
 *     EVP_CIPH_ALWAYS_CALL_INIT, a second init without a key), updates in pieces of every size
 *     around the block, the finals (padding, no padding, bad padding), EVP_Cipher, a stream
 *     cipher, one that does its own buffering (EVP_CIPH_FLAG_CUSTOM_CIPHER), EVP_CIPHER_CTX_ctrl,
 *     EVP_CIPHER_CTX_set_key_length, EVP_CIPHER_CTX_rand_key, a custom IV length,
 *     EVP_CIPHER_CTX_copy (with EVP_CIPH_CUSTOM_COPY), EVP_CIPHER_CTX_reset, and
 *     EVP_CIPHER_param_to_asn1 and EVP_CIPHER_asn1_to_param.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("# %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* Prints and clears the error queue: library and reason of each entry. */
static void errors(const char *what)
{
    unsigned long e;

    printf("# errors after %s:", what);
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

/*
 * The test's cipher: a byte-wise XOR with the key, chained through the context's IV as CBC
 * is (so its IV handling shows), over blocks of 8. Its state is the key, in the context's
 * cipher data.
 */
struct toy {
    unsigned char key[16];
    int keylen;
    int copies;
    size_t pos;
};

static int toy_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    struct toy *t = EVP_CIPHER_CTX_get_cipher_data(ctx);

    printf("# toy init key %s iv %s enc %d (data %s, iv len %d, key len %d)\n", key == NULL ? "NULL" : "set",
        iv == NULL ? "NULL" : "set", enc, t == NULL ? "NULL" : "set", EVP_CIPHER_CTX_get_iv_length(ctx),
        EVP_CIPHER_CTX_get_key_length(ctx));
    if (t != NULL && key != NULL) {
        t->keylen = EVP_CIPHER_CTX_get_key_length(ctx);
        memcpy(t->key, key, (size_t)t->keylen);
    }
    /* The modes OpenSSL doesn't keep the IV for (stream, CTR) get it here. */
    if (iv != NULL)
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, 8);
    if (t != NULL)
        t->pos = 0;
    return 1;
}

static int toy_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    struct toy *t = EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    int enc = EVP_CIPHER_CTX_is_encrypting(ctx);
    size_t i;

    int custom = (EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ctx)) & EVP_CIPH_FLAG_CUSTOM_CIPHER) != 0;

    printf("# toy cipher %zu%s\n", inl, in == NULL ? " (NULL in)" : "");
    if (in == NULL)
        return 0;
    for (i = 0; i < inl; i++) {
        size_t at = t->pos + i;
        unsigned char c = in[i], k = t->key[at % (size_t)t->keylen];
        unsigned char *v = &iv[at % 8];

        out[i] = (unsigned char)(c ^ k ^ *v);
        *v = enc ? out[i] : c;
    }
    t->pos += inl;
    /* A cipher that does its own buffering returns what it wrote. */
    return custom ? (int)inl : 1;
}

static int toy_cleanup(EVP_CIPHER_CTX *ctx)
{
    printf("# toy cleanup (data %s)\n", EVP_CIPHER_CTX_get_cipher_data(ctx) == NULL ? "NULL" : "set");
    return 1;
}

static int toy_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    struct toy *t = EVP_CIPHER_CTX_get_cipher_data(ctx);

    printf("# toy ctrl %#x %d %s\n", type, arg, ptr == NULL ? "NULL" : "set");
    switch (type) {
    case EVP_CTRL_INIT:
        return 1;
    case EVP_CTRL_COPY: {
        EVP_CIPHER_CTX *out = ptr;
        struct toy *o = EVP_CIPHER_CTX_get_cipher_data(out);

        printf("# toy copy: data %s, same %d\n", o == NULL ? "NULL" : "set", o != NULL && memcmp(o, t, sizeof(*t)) == 0);
        if (o != NULL)
            o->copies = t->copies + 1;
        return 1;
    }
    case EVP_CTRL_SET_KEY_LENGTH:
        return arg >= 4 && arg <= 16;
    case EVP_CTRL_RAND_KEY:
        memset(ptr, 0x5a, (size_t)EVP_CIPHER_CTX_get_key_length(ctx));
        return 1;
    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = 8;
        return 1;
    case 0x7000:
        return 42;
    default:
        return -1;
    }
}

static int toy_set_asn1(EVP_CIPHER_CTX *ctx, ASN1_TYPE *type)
{
    (void)ctx;
    printf("# toy set_asn1_parameters (type %s)\n", type == NULL ? "NULL" : "set");
    return ASN1_TYPE_set_octetstring(type, (unsigned char *)"toy!", 4);
}

static int toy_get_asn1(EVP_CIPHER_CTX *ctx, ASN1_TYPE *type)
{
    unsigned char buf[8];
    int n = ASN1_TYPE_get_octetstring(type, buf, sizeof(buf));

    (void)ctx;
    printf("# toy get_asn1_parameters: %d\n", n);
    return n == 4;
}

static EVP_CIPHER *make_toy(int block, unsigned long flags)
{
    EVP_CIPHER *c = EVP_CIPHER_meth_new(NID_undef, block, 8);

    check(c != NULL && EVP_CIPHER_meth_set_iv_length(c, 8) == 1 && EVP_CIPHER_meth_set_flags(c, flags) == 1
            && EVP_CIPHER_meth_set_impl_ctx_size(c, sizeof(struct toy)) == 1
            && EVP_CIPHER_meth_set_init(c, toy_init) == 1 && EVP_CIPHER_meth_set_do_cipher(c, toy_cipher) == 1
            && EVP_CIPHER_meth_set_cleanup(c, toy_cleanup) == 1 && EVP_CIPHER_meth_set_ctrl(c, toy_ctrl) == 1
            && EVP_CIPHER_meth_set_set_asn1_params(c, toy_set_asn1) == 1
            && EVP_CIPHER_meth_set_get_asn1_params(c, toy_get_asn1) == 1,
        "the setters");
    return c;
}

static const unsigned char key[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static const unsigned char iv[16] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
    0xac, 0xad, 0xae, 0xaf };
static unsigned char data[64];

static void setters_and_getters(void)
{
    EVP_CIPHER *c = make_toy(8, EVP_CIPH_CBC_MODE), *dup;

    printf("# again: iv %d flags %d size %d init %d cipher %d cleanup %d ctrl %d set %d get %d\n",
        EVP_CIPHER_meth_set_iv_length(c, 4), EVP_CIPHER_meth_set_flags(c, 2),
        EVP_CIPHER_meth_set_impl_ctx_size(c, 4), EVP_CIPHER_meth_set_init(c, toy_init),
        EVP_CIPHER_meth_set_do_cipher(c, toy_cipher), EVP_CIPHER_meth_set_cleanup(c, toy_cleanup),
        EVP_CIPHER_meth_set_ctrl(c, toy_ctrl), EVP_CIPHER_meth_set_set_asn1_params(c, toy_set_asn1),
        EVP_CIPHER_meth_set_get_asn1_params(c, toy_get_asn1));
    check(EVP_CIPHER_meth_get_init(c) == toy_init && EVP_CIPHER_meth_get_do_cipher(c) == toy_cipher
            && EVP_CIPHER_meth_get_cleanup(c) == toy_cleanup && EVP_CIPHER_meth_get_ctrl(c) == toy_ctrl
            && EVP_CIPHER_meth_get_set_asn1_params(c) == toy_set_asn1
            && EVP_CIPHER_meth_get_get_asn1_params(c) == toy_get_asn1
            && EVP_CIPHER_impl_ctx_size(c) == (int)sizeof(struct toy),
        "the getters");
    printf("# EVP_CIPHER: nid %d block %d key %d iv %d flags %lx mode %x name %s, provider %s, up_ref %d\n",
        EVP_CIPHER_get_nid(c), EVP_CIPHER_get_block_size(c), EVP_CIPHER_get_key_length(c),
        EVP_CIPHER_get_iv_length(c), EVP_CIPHER_get_flags(c), (unsigned)EVP_CIPHER_get_mode(c),
        EVP_CIPHER_get0_name(c) == NULL ? "NULL" : EVP_CIPHER_get0_name(c),
        EVP_CIPHER_get0_provider(c) == NULL ? "NULL" : "set", EVP_CIPHER_up_ref(c));
    EVP_CIPHER_free(c);
    dup = EVP_CIPHER_meth_dup(c);
    check(dup != NULL && dup != c && EVP_CIPHER_meth_get_do_cipher(dup) == toy_cipher
            && EVP_CIPHER_impl_ctx_size(dup) == (int)sizeof(struct toy) && EVP_CIPHER_get_iv_length(dup) == 8,
        "EVP_CIPHER_meth_dup");
    EVP_CIPHER_meth_free(dup);
    {
        EVP_CIPHER *fetched = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);

        printf("# dup of a fetched cipher: %s; its init %s, ctx size %d\n",
            EVP_CIPHER_meth_dup(fetched) == NULL ? "NULL" : "a copy",
            EVP_CIPHER_meth_get_init(fetched) == NULL ? "NULL" : "set", EVP_CIPHER_impl_ctx_size(fetched));
        EVP_CIPHER_meth_free(fetched);
        printf("# still usable: block %d\n", EVP_CIPHER_get_block_size(fetched));
        EVP_CIPHER_free(fetched);
    }
    EVP_CIPHER_meth_free(NULL);
    EVP_CIPHER_meth_free(c);
    errors("the setters and getters");
}

/* Encrypts `len` octets in the pieces `pieces`, then decrypts the result in other pieces. */
static void round_trip(const char *what, EVP_CIPHER *c, int len, int pad)
{
    static const int pieces[] = { 3, 8, 13, 0, 5, 1, 64 };
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char ct[128], pt[128];
    int n = 0, m, total = 0, ptotal = 0, i, r;
    size_t p;

    printf("# -- %s, %d octets\n", what, len);
    r = EVP_EncryptInit_ex(ctx, c, NULL, key, iv);
    printf("# init %d; iv %s, oiv %s\n", r,
        memcmp(EVP_CIPHER_CTX_iv(ctx), iv, 8) == 0 ? "set" : "not set",
        memcmp(EVP_CIPHER_CTX_original_iv(ctx), iv, 8) == 0 ? "set" : "not set");
    EVP_CIPHER_CTX_set_padding(ctx, pad);
    for (i = 0, p = 0; i < len; p++) {
        int k = pieces[p % 7] < len - i ? pieces[p % 7] : len - i;

        r = EVP_EncryptUpdate(ctx, ct + total, &n, data + i, k);
        printf("# update %d: %d, out %d\n", k, r, n);
        total += n;
        i += k;
    }
    r = EVP_EncryptFinal_ex(ctx, ct + total, &n);
    printf("# final: %d, out %d\n", r, n);
    total += r ? n : 0;
    hex("ciphertext", ct, (size_t)total);
    errors("encrypting");

    r = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, pad);
    printf("# decrypt init %d\n", r);
    for (i = 0, p = 3; i < total; p++) {
        int k = pieces[p % 7] < total - i ? pieces[p % 7] : total - i;

        r = EVP_DecryptUpdate(ctx, pt + ptotal, &m, ct + i, k);
        printf("# update %d: %d, out %d\n", k, r, m);
        ptotal += m;
        i += k;
    }
    r = EVP_DecryptFinal_ex(ctx, pt + ptotal, &m);
    printf("# final: %d, out %d\n", r, m);
    ptotal += r ? m : 0;
    check(ptotal == len && memcmp(pt, data, (size_t)len) == 0, what);
    errors("decrypting");

    /* Bad padding: the last octet changed. */
    if (pad && total > 0) {
        ct[total - 1] ^= 0x40;
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
        r = EVP_DecryptUpdate(ctx, pt, &m, ct, total);
        printf("# bad padding: update %d out %d", r, m);
        r = EVP_DecryptFinal_ex(ctx, pt + m, &m);
        printf(", final %d\n", r);
        errors("bad padding");
    }
    EVP_CIPHER_CTX_free(ctx);
}

static void ciphering(void)
{
    EVP_CIPHER *cbc = make_toy(8, EVP_CIPH_CBC_MODE | EVP_CIPH_CTRL_INIT);
    EVP_CIPHER *stream = make_toy(1, EVP_CIPH_STREAM_CIPHER);
    EVP_CIPHER *custom = make_toy(8, EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_CUSTOM_CIPHER);
    EVP_CIPHER *ctr = make_toy(1, EVP_CIPH_CTR_MODE | EVP_CIPH_ALWAYS_CALL_INIT);

    round_trip("block cipher with padding", cbc, 21, 1);
    round_trip("block cipher with padding, whole blocks", cbc, 16, 1);
    round_trip("block cipher with padding, nothing", cbc, 0, 1);
    round_trip("block cipher without padding", cbc, 24, 0);
    round_trip("stream cipher", stream, 21, 1);
    round_trip("custom cipher", custom, 21, 1);
    round_trip("CTR mode, always init", ctr, 10, 1);
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        unsigned char out[64];
        int r, n;

        printf("# -- no padding with a partial block\n");
        EVP_EncryptInit_ex(ctx, cbc, NULL, key, iv);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        EVP_EncryptUpdate(ctx, out, &n, data, 5);
        r = EVP_EncryptFinal_ex(ctx, out, &n);
        printf("# final %d\n", r);
        errors("no padding with a partial block");

        printf("# -- EVP_Cipher\n");
        EVP_EncryptInit_ex(ctx, cbc, NULL, key, iv);
        r = EVP_Cipher(ctx, out, data, 16);
        printf("# EVP_Cipher %d\n", r);
        hex("EVP_Cipher", out, 16);
        EVP_EncryptInit_ex(ctx, custom, NULL, key, iv);
        r = EVP_Cipher(ctx, out, data, 16);
        printf("# EVP_Cipher (custom) %d\n", r);

        printf("# -- a second init without a key, and with only an IV\n");
        r = EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL);
        printf("# init with nothing %d\n", r);
        r = EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv + 8);
        printf("# init with an IV %d, iv %s\n", r, memcmp(EVP_CIPHER_CTX_iv(ctx), iv + 8, 8) == 0 ? "new" : "old");
        EVP_CIPHER_CTX_free(ctx);
    }
    EVP_CIPHER_meth_free(cbc);
    EVP_CIPHER_meth_free(stream);
    EVP_CIPHER_meth_free(custom);
    EVP_CIPHER_meth_free(ctr);
    errors("ciphering");
}

static void controls(void)
{
    EVP_CIPHER *c = make_toy(8, EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_RAND_KEY
        | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(), *copy = EVP_CIPHER_CTX_new();
    unsigned char k[16], out[32], out2[32];
    ASN1_TYPE *type = ASN1_TYPE_new();
    int r, n, n2;

    printf("# -- controls\n");
    EVP_EncryptInit_ex(ctx, c, NULL, key, iv);
    printf("# iv length %d, key length %d\n", EVP_CIPHER_CTX_get_iv_length(ctx), EVP_CIPHER_CTX_get_key_length(ctx));
    r = EVP_CIPHER_CTX_ctrl(ctx, 0x7000, 3, NULL);
    printf("# ctrl 0x7000: %d\n", r);
    r = EVP_CIPHER_CTX_ctrl(ctx, 0x7001, 0, NULL);
    printf("# ctrl 0x7001: %d\n", r);
    errors("ctrl");
    r = EVP_CIPHER_CTX_set_key_length(ctx, 12);
    printf("# set_key_length 12: %d, now %d\n", r, EVP_CIPHER_CTX_get_key_length(ctx));
    r = EVP_CIPHER_CTX_set_key_length(ctx, 2);
    printf("# set_key_length 2: %d, now %d\n", r, EVP_CIPHER_CTX_get_key_length(ctx));
    errors("set_key_length");
    r = EVP_CIPHER_CTX_rand_key(ctx, k);
    printf("# rand_key %d\n", r);
    hex("random key", k, (size_t)EVP_CIPHER_CTX_get_key_length(ctx));

    printf("# -- copy\n");
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &n, data, 11);
    r = EVP_CIPHER_CTX_copy(copy, ctx);
    printf("# copy %d, data %s\n", r, EVP_CIPHER_CTX_get_cipher_data(copy) == EVP_CIPHER_CTX_get_cipher_data(ctx) ? "shared" : "own");
    EVP_EncryptUpdate(ctx, out + n, &n2, data + 11, 9);
    n += n2;
    EVP_EncryptFinal_ex(ctx, out + n, &n2);
    n += n2;
    EVP_EncryptUpdate(copy, out2, &n2, data, 0);
    {
        int m = 0, m2;

        EVP_EncryptUpdate(copy, out2 + 8, &m, data + 11, 9);
        EVP_EncryptFinal_ex(copy, out2 + 8 + m, &m2);
        check(m + m2 + 8 == n && memcmp(out + 8, out2 + 8, (size_t)(n - 8)) == 0, "the copy ciphers on from the same state");
    }

    printf("# -- ASN.1 parameters\n");
    r = EVP_CIPHER_param_to_asn1(ctx, type);
    printf("# param_to_asn1 %d\n", r);
    r = EVP_CIPHER_asn1_to_param(ctx, type);
    printf("# asn1_to_param %d\n", r);
    errors("the ASN.1 parameters");

    printf("# -- reset and free\n");
    r = EVP_CIPHER_CTX_reset(ctx);
    printf("# reset %d, cipher %s\n", r, EVP_CIPHER_CTX_get0_cipher(ctx) == NULL ? "NULL" : "set");
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_CTX_free(copy);
    ASN1_TYPE_free(type);
    EVP_CIPHER_meth_free(c);
    errors("the controls");
}

int main(void)
{
    size_t i;

    setvbuf(stdout, NULL, _IONBF, 0);
    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7 + 3);
    setters_and_getters();
    ciphering();
    controls();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
