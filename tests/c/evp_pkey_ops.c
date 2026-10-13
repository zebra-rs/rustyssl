/*
 * Conformance test for the key operations a provider offers (EVP_ASYM_CIPHER(3), EVP_KEM(3),
 * EVP_KEYEXCH(3), EVP_PKEY_encrypt(3), EVP_PKEY_encapsulate(3), EVP_PKEY_derive(3), and the
 * ctrl translations of EVP_PKEY_CTX_ctrl(3) and the typed setters of RSA, DH, DSA, and EC), in
 * TAP format, with a provider of its own registered by OSSL_PROVIDER_add_builtin. "pktest"
 * offers a key type under the names TOY, RSA, RSA-PSS, DH, DHX, DSA, EC, and SM2 (its keys
 * are a few octets), an asymmetric cipher, a KEM, a key exchange, and a signature that XOR
 * with the key, and algorithms whose functions don't make a whole (which can't be fetched).
 * Every operation logs the parameters it's given and gives back the ones it was given, so the
 * output shows what each ctrl, ctrl string, and typed setter turns into.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

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
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void list(const char *label, const OSSL_PARAM *p)
{
    int n = 0;

    for (; p != NULL && p->key != NULL; p++)
        n++;
    printf("  %s: %d\n", label, n);
}

static const char *str(const char *s)
{
    return s == NULL ? "(null)" : s;
}

static void name_cb(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

/* The provider ---------------------------------------------------------------------------- */

/* A parameter as the provider was given it. */
typedef struct {
    char key[48];
    unsigned int type;
    unsigned char val[64];
    size_t len;
    int null;
} ITEM;

typedef struct {
    ITEM items[24];
    int n;
} STORE;

typedef struct {
    unsigned char k[32];
    size_t len;
} TOYKEY;

/* The context of every operation. */
typedef struct {
    TOYKEY *key, *other;
    STORE st;
} OPCTX;

static int provctx_token;

/* strnlen, which C99 doesn't have. */
static size_t text_len(const char *s, size_t max)
{
    size_t n = 0;

    while (n < max && s[n] != '\0')
        n++;
    return n;
}

static void log_params(const char *who, const OSSL_PARAM *p)
{
    for (; p != NULL && p->key != NULL; p++) {
        printf("    > %s %s", who, p->key);
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: {
            int64_t v = 0;

            OSSL_PARAM_get_int64(p, &v);
            printf(" int/%zu=%lld\n", p->data_size, (long long)v);
            break;
        }
        case OSSL_PARAM_UNSIGNED_INTEGER: {
            uint64_t v = 0;

            if (p->data_size <= sizeof(v) && OSSL_PARAM_get_uint64(p, &v))
                printf(" uint/%zu=%llu\n", p->data_size, (unsigned long long)v);
            else
                hex("uint", p->data, p->data_size);
            break;
        }
        case OSSL_PARAM_UTF8_STRING:
            if (p->data == NULL)
                printf(" utf8=(null)/%zu\n", p->data_size);
            else
                printf(" utf8=%.*s\n", (int)text_len(p->data, p->data_size), (const char *)p->data);
            break;
        case OSSL_PARAM_OCTET_STRING:
            printf(" octets");
            if (p->data == NULL)
                printf("=(null)/%zu\n", p->data_size);
            else
                hex("", p->data, p->data_size);
            break;
        default:
            printf(" type %u\n", p->data_type);
        }
    }
}

static void store_set(STORE *s, const OSSL_PARAM *p)
{
    for (; p != NULL && p->key != NULL; p++) {
        ITEM *it = NULL;
        int i;

        for (i = 0; i < s->n; i++)
            if (strcmp(s->items[i].key, p->key) == 0)
                it = &s->items[i];
        if (it == NULL) {
            if (s->n == 24)
                continue;
            it = &s->items[s->n++];
        }
        memset(it, 0, sizeof(*it));
        snprintf(it->key, sizeof(it->key), "%s", p->key);
        it->type = p->data_type;
        it->null = p->data == NULL;
        if (p->data != NULL) {
            it->len = p->data_size < sizeof(it->val) ? p->data_size : sizeof(it->val);
            if (p->data_type == OSSL_PARAM_UTF8_STRING)
                it->len = text_len(p->data, it->len);
            memcpy(it->val, p->data, it->len);
        }
    }
}

static const char *const pad_names[] = { "?", "pkcs1", "?", "none", "oaep", "x931", "pss" };

/* Gives back what was set, in the type asked for. */
static int store_get(STORE *s, OSSL_PARAM *p, const TOYKEY *key)
{
    for (; p != NULL && p->key != NULL; p++) {
        ITEM *it = NULL;
        int i;

        if (strcmp(p->key, OSSL_SIGNATURE_PARAM_ALGORITHM_ID) == 0 && key != NULL) {
            /* sha256WithRSAEncryption */
            static const unsigned char aid[] = {
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00
            };

            if (!OSSL_PARAM_set_octet_string(p, aid, sizeof(aid)))
                return 0;
            continue;
        }
        for (i = 0; i < s->n; i++)
            if (strcmp(s->items[i].key, p->key) == 0)
                it = &s->items[i];
        if (it == NULL)
            continue;
        if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            char buf[64];

            if (it->type == OSSL_PARAM_INTEGER) {
                int v = 0;
                OSSL_PARAM q = OSSL_PARAM_construct_int("x", &v);

                memcpy(&v, it->val, it->len < sizeof(v) ? it->len : sizeof(v));
                (void)q;
                if (strcmp(it->key, OSSL_PKEY_PARAM_PAD_MODE) == 0 && v >= 0 && v <= 6)
                    snprintf(buf, sizeof(buf), "%s", pad_names[v]);
                else
                    snprintf(buf, sizeof(buf), "%d", v);
            } else {
                snprintf(buf, sizeof(buf), "%.*s", (int)it->len, (const char *)it->val);
            }
            if (!OSSL_PARAM_set_utf8_string(p, buf))
                return 0;
        } else if (p->data_type == OSSL_PARAM_OCTET_STRING) {
            if (!OSSL_PARAM_set_octet_string(p, it->val, it->len))
                return 0;
        } else if (p->data_type == OSSL_PARAM_OCTET_PTR) {
            if (!OSSL_PARAM_set_octet_ptr(p, it->val, it->len))
                return 0;
        } else if (p->data_type == OSSL_PARAM_INTEGER
                   || p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
            OSSL_PARAM q = { "x", it->type, it->val, it->len, 0 };
            int64_t v = 0;

            if (it->type == OSSL_PARAM_UTF8_STRING) {
                char buf[64];

                snprintf(buf, sizeof(buf), "%.*s", (int)it->len, (const char *)it->val);
                v = atoi(buf);
            } else if (!OSSL_PARAM_get_int64(&q, &v)) {
                return 0;
            }
            if (!OSSL_PARAM_set_int64(p, v))
                return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM echo_params[] = {
    OSSL_PARAM_uint(OSSL_EXCHANGE_PARAM_PAD, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ALG_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MGF1_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, NULL, 0),
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DIST_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, NULL, 0),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_PBITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_QBITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_GENERATOR, NULL),
    OSSL_PARAM_uint(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_CIPHER, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ALGORITHM_ID_PARAMS, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *echo_list(void *ctx, void *provctx)
{
    (void)ctx;
    (void)provctx;
    return echo_params;
}

/* Key management. */

static void *km_new(void *provctx)
{
    (void)provctx;
    return OPENSSL_zalloc(sizeof(TOYKEY));
}

static void km_free(void *key)
{
    OPENSSL_free(key);
}

static int km_has(const void *key, int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return ((const TOYKEY *)key)->len > 0;
    return 1;
}

static int km_import(void *key, int selection, const OSSL_PARAM params[])
{
    TOYKEY *k = key;
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    void *buf = k->k;

    (void)selection;
    if (p == NULL)
        return 1;
    return OSSL_PARAM_get_octet_string(p, &buf, sizeof(k->k), &k->len);
}

static const OSSL_PARAM key_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *km_types(int selection)
{
    (void)selection;
    return key_types;
}

static int km_export(void *key, int selection, OSSL_CALLBACK *cb, void *cbarg)
{
    TOYKEY *k = key;
    OSSL_PARAM params[2];

    (void)selection;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, k->k, k->len);
    params[1] = OSSL_PARAM_construct_end();
    return cb(params, cbarg);
}

static int km_get_params(void *key, OSSL_PARAM params[])
{
    TOYKEY *k = key;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, (int)k->len * 8))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, (int)k->len * 4))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, (int)k->len))
        return 0;
    return 1;
}

static const OSSL_PARAM key_gettable[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *km_gettable(void *provctx)
{
    (void)provctx;
    return key_gettable;
}

static int gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    log_params("gen", params);
    store_set(genctx, params);
    return 1;
}

static void *gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    STORE *s = OPENSSL_zalloc(sizeof(*s));

    (void)provctx;
    printf("    > gen init %d\n", selection);
    if (s != NULL)
        gen_set_params(s, params);
    return s;
}

static int gen_get_params(void *genctx, OSSL_PARAM params[])
{
    return store_get(genctx, params, NULL);
}

static void *gen_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    TOYKEY *k = OPENSSL_zalloc(sizeof(*k));

    (void)genctx;
    (void)cb;
    (void)cbarg;
    if (k != NULL) {
        memcpy(k->k, "0123456789abcdef", 16);
        k->len = 16;
    }
    return k;
}

static void gen_cleanup(void *genctx)
{
    OPENSSL_free(genctx);
}

static const OSSL_DISPATCH keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))km_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))km_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))km_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))km_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))km_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))km_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))km_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))km_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))km_gettable },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))echo_list },
    { OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS, (void (*)(void))gen_get_params },
    { OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS, (void (*)(void))echo_list },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))gen_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))gen_cleanup },
    OSSL_DISPATCH_END
};

/* The operations' common functions. */

static void *op_newctx(void *provctx)
{
    (void)provctx;
    return OPENSSL_zalloc(sizeof(OPCTX));
}

static void *op_newctx_q(void *provctx, const char *propq)
{
    (void)propq;
    return op_newctx(provctx);
}

static void op_freectx(void *ctx)
{
    OPENSSL_free(ctx);
}

static void *op_dupctx(void *ctx)
{
    return OPENSSL_memdup(ctx, sizeof(OPCTX));
}

static int op_set_params(void *ctx, const OSSL_PARAM params[])
{
    log_params("op", params);
    store_set(&((OPCTX *)ctx)->st, params);
    return 1;
}

static int op_get_params(void *ctx, OSSL_PARAM params[])
{
    OPCTX *c = ctx;

    return store_get(&c->st, params, c->key);
}

static int op_init(void *ctx, void *key, const OSSL_PARAM params[])
{
    OPCTX *c = ctx;

    c->key = key;
    c->other = NULL;
    return op_set_params(ctx, params);
}

static int op_init2(void *ctx, void *key, void *other, const OSSL_PARAM params[])
{
    OPCTX *c = ctx;

    c->key = key;
    c->other = other;
    printf("    > auth key %zu\n", c->other->len);
    return op_set_params(ctx, params);
}

/* Out = in XOR the key (and the other key). */
static void toy_xor(const OPCTX *c, unsigned char *out, const unsigned char *in, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        out[i] = in[i] ^ c->key->k[i % c->key->len];
        if (c->other != NULL && c->other->len > 0)
            out[i] ^= c->other->k[i % c->other->len];
    }
}

static int cipher_crypt(void *ctx, unsigned char *out, size_t *outlen, size_t outsize,
                        const unsigned char *in, size_t inlen)
{
    OPCTX *c = ctx;

    if (c->key == NULL || c->key->len == 0)
        return 0;
    if (out == NULL) {
        *outlen = inlen;
        return 1;
    }
    if (outsize < inlen)
        return 0;
    toy_xor(c, out, in, inlen);
    *outlen = inlen;
    return 1;
}

static const OSSL_DISPATCH cipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))op_newctx },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))op_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))cipher_crypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))op_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))cipher_crypt },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))op_freectx },
    { OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))op_dupctx },
    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, (void (*)(void))op_get_params },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))echo_list },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))op_set_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))echo_list },
    OSSL_DISPATCH_END
};

/* An asymmetric cipher that can't decrypt (it has the init but not the function). */
static const OSSL_DISPATCH bad_cipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))op_newctx },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))op_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))cipher_crypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))op_init },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))op_freectx },
    OSSL_DISPATCH_END
};

static int kem_encapsulate(void *ctx, unsigned char *out, size_t *outlen,
                           unsigned char *secret, size_t *secretlen)
{
    OPCTX *c = ctx;

    if (out == NULL) {
        *outlen = 4;
        if (secretlen != NULL)
            *secretlen = 4;
        return 1;
    }
    memcpy(secret, "SECR", 4);
    toy_xor(c, out, secret, 4);
    *outlen = 4;
    *secretlen = 4;
    return 1;
}

static int kem_decapsulate(void *ctx, unsigned char *out, size_t *outlen,
                           const unsigned char *in, size_t inlen)
{
    OPCTX *c = ctx;

    if (out == NULL) {
        *outlen = 4;
        return 1;
    }
    if (inlen != 4 || *outlen < 4)
        return 0;
    toy_xor(c, out, in, 4);
    *outlen = 4;
    return 1;
}

static const OSSL_DISPATCH kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))op_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))op_init },
    { OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT, (void (*)(void))op_init2 },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))op_init },
    { OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT, (void (*)(void))op_init2 },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))kem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))op_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))op_dupctx },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))op_get_params },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void))echo_list },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))op_set_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void))echo_list },
    OSSL_DISPATCH_END
};

/* A KEM that can encapsulate but not decapsulate. */
static const OSSL_DISPATCH bad_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))op_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))op_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))op_init },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))op_freectx },
    OSSL_DISPATCH_END
};

static int exch_set_peer(void *ctx, void *peer)
{
    ((OPCTX *)ctx)->other = peer;
    printf("    > peer %zu\n", ((TOYKEY *)peer)->len);
    return 1;
}

static int exch_derive(void *ctx, unsigned char *secret, size_t *secretlen, size_t outlen)
{
    OPCTX *c = ctx;
    size_t i;

    if (c->key == NULL)
        return 0;
    if (secret == NULL) {
        *secretlen = c->key->len;
        return 1;
    }
    if (c->other == NULL || outlen < c->key->len)
        return 0;
    for (i = 0; i < c->key->len; i++)
        secret[i] = c->key->k[i] ^ c->other->k[i % c->other->len] ^ 0x5a;
    *secretlen = c->key->len;
    return 1;
}

static const OSSL_DISPATCH exch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))op_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))op_init },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))exch_set_peer },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))exch_derive },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))op_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))op_dupctx },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))op_get_params },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))echo_list },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))op_set_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))echo_list },
    OSSL_DISPATCH_END
};

/* An exchange without a derive function. */
static const OSSL_DISPATCH bad_exch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))op_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))op_init },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))op_freectx },
    OSSL_DISPATCH_END
};

static int sig_sign(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize,
                    const unsigned char *tbs, size_t tbslen)
{
    return cipher_crypt(ctx, sig, siglen, sigsize, tbs, tbslen);
}

static int sig_verify(void *ctx, const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen)
{
    unsigned char buf[256];

    if (siglen != tbslen || siglen > sizeof(buf))
        return 0;
    toy_xor(ctx, buf, tbs, tbslen);
    return memcmp(buf, sig, siglen) == 0;
}

static const OSSL_DISPATCH sig_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))op_newctx_q },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))op_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))op_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))sig_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))op_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))op_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))op_get_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))echo_list },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))op_set_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))echo_list },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM keymgmts[] = {
    { "TOY", "provider=pktest", keymgmt_functions, "toy keys" },
    { "RSA:rsaEncryption", "provider=pktest", keymgmt_functions, "toy RSA keys" },
    { "RSA-PSS", "provider=pktest", keymgmt_functions, NULL },
    { "DH", "provider=pktest", keymgmt_functions, NULL },
    { "DHX", "provider=pktest", keymgmt_functions, NULL },
    { "DSA", "provider=pktest", keymgmt_functions, NULL },
    { "EC", "provider=pktest", keymgmt_functions, NULL },
    { "SM2", "provider=pktest", keymgmt_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM ciphers[] = {
    { "TOY", "provider=pktest", cipher_functions, "toy cipher" },
    { "RSA:rsaEncryption", "provider=pktest", cipher_functions, NULL },
    { "BAD-CIPHER", "provider=pktest", bad_cipher_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM kems[] = {
    { "TOY", "provider=pktest", kem_functions, "toy KEM" },
    { "BAD-KEM", "provider=pktest", bad_kem_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM exchanges[] = {
    { "TOY", "provider=pktest", exch_functions, "toy exchange" },
    { "DH", "provider=pktest", exch_functions, NULL },
    { "DHX", "provider=pktest", exch_functions, NULL },
    { "EC", "provider=pktest", exch_functions, NULL },
    { "SM2", "provider=pktest", exch_functions, NULL },
    { "BAD-EXCH", "provider=pktest", bad_exch_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM signatures[] = {
    { "TOY", "provider=pktest", sig_functions, "toy signature" },
    { "RSA:rsaEncryption", "provider=pktest", sig_functions, NULL },
    { "RSA-PSS", "provider=pktest", sig_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return keymgmts;
    case OSSL_OP_ASYM_CIPHER:
        return ciphers;
    case OSSL_OP_KEM:
        return kems;
    case OSSL_OP_KEYEXCH:
        return exchanges;
    case OSSL_OP_SIGNATURE:
        return signatures;
    }
    return NULL;
}

static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))query },
    OSSL_DISPATCH_END
};

static int provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                         const OSSL_DISPATCH **out, void **provctx)
{
    (void)handle;
    (void)in;
    *out = provider_functions;
    *provctx = &provctx_token;
    return 1;
}

/* The tests ------------------------------------------------------------------------------- */

static OSSL_LIB_CTX *lib;

static void cipher_cb(EVP_ASYM_CIPHER *m, void *arg)
{
    (void)arg;
    printf(" %s", EVP_ASYM_CIPHER_get0_name(m));
}

static void kem_cb(EVP_KEM *m, void *arg)
{
    (void)arg;
    printf(" %s", EVP_KEM_get0_name(m));
}

static void exch_cb(EVP_KEYEXCH *m, void *arg)
{
    (void)arg;
    printf(" %s", EVP_KEYEXCH_get0_name(m));
}

static void test_methods(void)
{
    EVP_ASYM_CIPHER *ac = EVP_ASYM_CIPHER_fetch(lib, "toy", NULL);
    EVP_KEM *kem = EVP_KEM_fetch(lib, "TOY", NULL);
    EVP_KEYEXCH *ex = EVP_KEYEXCH_fetch(lib, "DHX", NULL);
    int r;

    check(ac != NULL && kem != NULL && ex != NULL, "fetch the toy operations");
    printf("  cipher %s desc %s prov %s is_a %d %d\n", EVP_ASYM_CIPHER_get0_name(ac),
           str(EVP_ASYM_CIPHER_get0_description(ac)),
           OSSL_PROVIDER_get0_name(EVP_ASYM_CIPHER_get0_provider(ac)),
           EVP_ASYM_CIPHER_is_a(ac, "toy"), EVP_ASYM_CIPHER_is_a(ac, "RSA"));
    printf("  names:");
    r = EVP_ASYM_CIPHER_names_do_all(ac, name_cb, NULL);
    printf(" (%d)\n", r);
    list("gettable", EVP_ASYM_CIPHER_gettable_ctx_params(ac));
    list("settable", EVP_ASYM_CIPHER_settable_ctx_params(ac));
    printf("  up_ref %d\n", EVP_ASYM_CIPHER_up_ref(ac));
    EVP_ASYM_CIPHER_free(ac);

    printf("  kem %s desc %s prov %s is_a %d %d\n", EVP_KEM_get0_name(kem),
           str(EVP_KEM_get0_description(kem)),
           OSSL_PROVIDER_get0_name(EVP_KEM_get0_provider(kem)), EVP_KEM_is_a(kem, "toy"),
           EVP_KEM_is_a(kem, "RSA"));
    printf("  names:");
    r = EVP_KEM_names_do_all(kem, name_cb, NULL);
    printf(" (%d)\n", r);
    list("gettable", EVP_KEM_gettable_ctx_params(kem));
    list("settable", EVP_KEM_settable_ctx_params(kem));
    printf("  up_ref %d\n", EVP_KEM_up_ref(kem));
    EVP_KEM_free(kem);

    printf("  exch %s desc %s prov %s\n", EVP_KEYEXCH_get0_name(ex),
           str(EVP_KEYEXCH_get0_description(ex)),
           OSSL_PROVIDER_get0_name(EVP_KEYEXCH_get0_provider(ex)));
    printf("  names:");
    r = EVP_KEYEXCH_names_do_all(ex, name_cb, NULL);
    printf(" (%d)\n", r);

    printf("  do_all:");
    EVP_ASYM_CIPHER_do_all_provided(lib, cipher_cb, NULL);
    EVP_KEM_do_all_provided(lib, kem_cb, NULL);
    EVP_KEYEXCH_do_all_provided(lib, exch_cb, NULL);
    printf("\n");
    errors();

    check(EVP_ASYM_CIPHER_fetch(lib, "BAD-CIPHER", NULL) == NULL, "a cipher without decrypt");
    errors();
    check(EVP_KEM_fetch(lib, "BAD-KEM", NULL) == NULL, "a KEM without decapsulate");
    errors();
    check(EVP_KEYEXCH_fetch(lib, "BAD-EXCH", NULL) == NULL, "an exchange without derive");
    errors();

    EVP_ASYM_CIPHER_free(ac);
    EVP_KEM_free(kem);
    EVP_KEYEXCH_free(ex);
}

/* A key of the toy provider's type `name`, generated with a context it prints. */
static EVP_PKEY *toy_key(const char *name)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(lib, name, NULL);
    EVP_PKEY *k = NULL;

    if (c == NULL || EVP_PKEY_keygen_init(c) != 1 || EVP_PKEY_keygen(c, &k) != 1)
        printf("  no %s key\n", name);
    EVP_PKEY_CTX_free(c);
    return k;
}

static EVP_PKEY *toy_key_from(const char *name, const char *octets)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(lib, name, NULL);
    EVP_PKEY *k = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)octets,
                                                  strlen(octets));
    params[1] = OSSL_PARAM_construct_end();
    if (c == NULL || EVP_PKEY_fromdata_init(c) != 1
        || EVP_PKEY_fromdata(c, &k, EVP_PKEY_KEYPAIR, params) != 1)
        printf("  no %s key from data\n", name);
    EVP_PKEY_CTX_free(c);
    return k;
}

static void test_cipher(void)
{
    EVP_PKEY *k = toy_key("TOY");
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(lib, k, NULL), *d;
    unsigned char ct[32] = { 0 }, pt[32] = { 0 };
    int r;
    size_t ctlen = sizeof(ct), ptlen = sizeof(pt), n = 0;
    OSSL_PARAM params[2];
    unsigned int pad = 3;

    printf("  key id %d type %s bits %d size %d\n", EVP_PKEY_get_id(k),
           str(EVP_PKEY_get0_type_name(k)), EVP_PKEY_get_bits(k), EVP_PKEY_get_size(k));
    params[0] = OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &pad);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_PKEY_encrypt_init_ex(c, params) == 1, "encrypt init");
    printf("  op %d prov %s\n", EVP_PKEY_CTX_get_operation(c),
           OSSL_PROVIDER_get0_name(EVP_PKEY_CTX_get0_provider(c)));
    list("ctx settable", EVP_PKEY_CTX_settable_params(c));
    list("ctx gettable", EVP_PKEY_CTX_gettable_params(c));
    pad = 0;
    printf("  get_params %d pad %u\n", EVP_PKEY_CTX_get_params(c, params), pad);
    r = EVP_PKEY_encrypt(c, NULL, &n, (const unsigned char *)"hello", 5);
    printf("  size %d %zu\n", r, n);
    r = EVP_PKEY_encrypt(c, ct, &ctlen, (const unsigned char *)"hello", 5);
    printf("  encrypt %d %zu", r, ctlen);
    hex("", ct, ctlen);
    n = 2;
    printf("  too small %d\n", EVP_PKEY_encrypt(c, ct, &n, (const unsigned char *)"hello", 5));
    errors();
    d = EVP_PKEY_CTX_dup(c);
    check(d != NULL, "dup an encryption");
    check(EVP_PKEY_decrypt_init(c) == 1, "decrypt init");
    r = EVP_PKEY_decrypt(c, pt, &ptlen, ct, ctlen);
    printf("  decrypt %d %zu %.*s\n", r, ptlen, (int)ptlen, pt);
    printf("  encrypt while decrypting %d\n", EVP_PKEY_encrypt(c, ct, &ctlen, pt, 1));
    errors();
    ctlen = sizeof(ct);
    r = EVP_PKEY_encrypt(d, ct, &ctlen, (const unsigned char *)"hi", 2);
    printf("  dup encrypt %d %zu\n", r, ctlen);
    printf("  rsa setters on toy: label %d oaep %d padding %d\n",
           EVP_PKEY_CTX_set0_rsa_oaep_label(d, NULL, 0), EVP_PKEY_CTX_set_rsa_oaep_md(d, EVP_sha1()),
           EVP_PKEY_CTX_set_rsa_padding(d, RSA_PKCS1_PADDING));
    errors();
    EVP_PKEY_CTX_free(d);
    printf("  old %d %d\n", EVP_PKEY_encrypt_old(ct, pt, 4, k), EVP_PKEY_decrypt_old(ct, pt, 4, k));
    errors();
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(k);
}

static void test_kem(void)
{
    EVP_PKEY *k = toy_key_from("TOY", "kemkey"), *a = toy_key_from("TOY", "AUTH");
    EVP_PKEY *blank = EVP_PKEY_new();
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(lib, k, NULL), *d;
    unsigned char out[16] = { 0 }, sec[16] = { 0 }, got[16] = { 0 };
    int r;
    size_t outlen = 0, seclen = 0, gotlen = sizeof(got);

    check(EVP_PKEY_encapsulate_init(c, NULL) == 1, "encapsulate init");
    printf("  op %d prov %s kem_op %d\n", EVP_PKEY_CTX_get_operation(c),
           OSSL_PROVIDER_get0_name(EVP_PKEY_CTX_get0_provider(c)),
           EVP_PKEY_CTX_set_kem_op(c, "TOYOP"));
    list("ctx settable", EVP_PKEY_CTX_settable_params(c));
    list("ctx gettable", EVP_PKEY_CTX_gettable_params(c));
    r = EVP_PKEY_encapsulate(c, NULL, &outlen, NULL, &seclen);
    printf("  sizes %d %zu %zu\n", r, outlen, seclen);
    printf("  out without secret %d\n", EVP_PKEY_encapsulate(c, out, &outlen, NULL, &seclen));
    outlen = sizeof(out);
    seclen = sizeof(sec);
    r = EVP_PKEY_encapsulate(c, out, &outlen, sec, &seclen);
    printf("  encapsulate %d %zu %zu", r, outlen, seclen);
    hex("", out, outlen);
    d = EVP_PKEY_CTX_dup(c);
    check(d != NULL, "dup an encapsulation");
    EVP_PKEY_CTX_free(d);
    check(EVP_PKEY_decapsulate_init(c, NULL) == 1, "decapsulate init");
    r = EVP_PKEY_decapsulate(c, got, &gotlen, out, outlen);
    printf("  decapsulate %d %zu %.*s\n", r, gotlen, (int)gotlen, got);
    gotlen = 0;
    r = EVP_PKEY_decapsulate(c, NULL, &gotlen, out, outlen);
    printf("  size %d %zu\n", r, gotlen);
    printf("  encapsulate while decapsulating %d\n",
           EVP_PKEY_encapsulate(c, out, &outlen, sec, &seclen));
    errors();
    check(EVP_PKEY_auth_encapsulate_init(c, a, NULL) == 1, "auth encapsulate init");
    outlen = sizeof(out);
    seclen = sizeof(sec);
    r = EVP_PKEY_encapsulate(c, out, &outlen, sec, &seclen);
    printf("  auth encapsulate %d", r);
    hex("", out, outlen);
    check(EVP_PKEY_auth_decapsulate_init(c, a, NULL) == 1, "auth decapsulate init");
    gotlen = sizeof(got);
    r = EVP_PKEY_decapsulate(c, got, &gotlen, out, outlen);
    printf("  auth decapsulate %d %.*s\n", r, (int)gotlen, got);
    printf("  auth of another type %d op %d\n", EVP_PKEY_auth_encapsulate_init(c, blank, NULL),
           EVP_PKEY_CTX_get_operation(c));
    errors();
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(blank);
    EVP_PKEY_free(a);
    EVP_PKEY_free(k);
}

/* Prints a getter's result and the errors. */
#define SHOW(label, expr) do {                     \
        printf("  %s %d\n", label, (int)(expr));   \
        errors();                                  \
    } while (0)

static void test_exchange(void)
{
    EVP_PKEY *k = toy_key_from("DH", "alice"), *p = toy_key_from("DH", "bob");
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(lib, k, NULL), *d;
    unsigned char out[32] = { 0 }, *ukm = OPENSSL_malloc(3), *got = NULL;
    int r;
    size_t outlen = 0;
    const EVP_MD *md = NULL;
    ASN1_OBJECT *oid = NULL;
    int len = 0;
    char txt[64];

    memcpy(ukm, "ukm", 3);
    check(EVP_PKEY_derive_init(c) == 1, "derive init");
    printf("  op %d prov %s\n", EVP_PKEY_CTX_get_operation(c),
           OSSL_PROVIDER_get0_name(EVP_PKEY_CTX_get0_provider(c)));
    SHOW("derive without a peer", EVP_PKEY_derive(c, out, &outlen));
    SHOW("set_peer", EVP_PKEY_derive_set_peer(c, p));
    printf("  peer %d\n", EVP_PKEY_CTX_get0_peerkey(c) == p);
    r = EVP_PKEY_derive(c, NULL, &outlen);
    printf("  size %d %zu\n", r, outlen);
    outlen = sizeof(out);
    r = EVP_PKEY_derive(c, out, &outlen);
    printf("  derive %d", r);
    hex("", out, outlen);
    SHOW("set_peer_ex no check", EVP_PKEY_derive_set_peer_ex(c, k, 0));
    d = EVP_PKEY_CTX_dup(c);
    printf("  dup %d peer %d\n", d != NULL, EVP_PKEY_CTX_get0_peerkey(d) != NULL);
    EVP_PKEY_CTX_free(d);

    SHOW("dh pad", EVP_PKEY_CTX_set_dh_pad(c, 1));
    SHOW("dh kdf type", EVP_PKEY_CTX_set_dh_kdf_type(c, EVP_PKEY_DH_KDF_X9_42));
    SHOW("dh kdf type get", EVP_PKEY_CTX_get_dh_kdf_type(c));
    SHOW("dh kdf type bad", EVP_PKEY_CTX_set_dh_kdf_type(c, 7));
    SHOW("dh kdf md", EVP_PKEY_CTX_set_dh_kdf_md(c, EVP_sha256()));
    SHOW("dh kdf md get", EVP_PKEY_CTX_get_dh_kdf_md(c, &md));
    printf("  md %s\n", md == NULL ? "NULL" : EVP_MD_get0_name(md));
    SHOW("dh kdf outlen", EVP_PKEY_CTX_set_dh_kdf_outlen(c, 24));
    SHOW("dh kdf outlen get", EVP_PKEY_CTX_get_dh_kdf_outlen(c, &len));
    printf("  outlen %d\n", len);
    SHOW("dh kdf ukm", EVP_PKEY_CTX_set0_dh_kdf_ukm(c, ukm, 3));
    SHOW("dh kdf ukm get", EVP_PKEY_CTX_get0_dh_kdf_ukm(c, &got));
    if (got != NULL)
        printf("  ukm %.3s\n", got);
    SHOW("dh kdf oid", EVP_PKEY_CTX_set0_dh_kdf_oid(c, OBJ_nid2obj(NID_id_smime_alg_CMS3DESwrap)));
    SHOW("dh kdf oid get", EVP_PKEY_CTX_get0_dh_kdf_oid(c, &oid));
    OBJ_obj2txt(txt, sizeof(txt), oid, 0);
    printf("  oid %s\n", txt);
    ASN1_OBJECT_free(oid);
    SHOW("ecdh cofactor", EVP_PKEY_CTX_set_ecdh_cofactor_mode(c, 1));
    SHOW("ecdh cofactor get", EVP_PKEY_CTX_get_ecdh_cofactor_mode(c));
    SHOW("ecdh cofactor ctrl", EVP_PKEY_CTX_ctrl(c, EVP_PKEY_EC, EVP_PKEY_OP_DERIVE,
                                                 EVP_PKEY_CTRL_EC_ECDH_COFACTOR, -1, NULL));
    SHOW("ecdh cofactor ctrl get", EVP_PKEY_CTX_ctrl(c, EVP_PKEY_EC, EVP_PKEY_OP_DERIVE,
                                                     EVP_PKEY_CTRL_EC_ECDH_COFACTOR, -2, NULL));
    SHOW("ecdh cofactor ctrl bad", EVP_PKEY_CTX_ctrl(c, EVP_PKEY_EC, EVP_PKEY_OP_DERIVE,
                                                     EVP_PKEY_CTRL_EC_ECDH_COFACTOR, 3, NULL));
    SHOW("ecdh kdf type", EVP_PKEY_CTX_set_ecdh_kdf_type(c, EVP_PKEY_ECDH_KDF_X9_63));
    SHOW("ecdh kdf type get", EVP_PKEY_CTX_get_ecdh_kdf_type(c));
    SHOW("ecdh kdf type none", EVP_PKEY_CTX_set_ecdh_kdf_type(c, EVP_PKEY_ECDH_KDF_NONE));
    SHOW("ecdh kdf type get", EVP_PKEY_CTX_get_ecdh_kdf_type(c));
    SHOW("ecdh kdf md", EVP_PKEY_CTX_set_ecdh_kdf_md(c, EVP_sha384()));
    SHOW("ecdh kdf md get", EVP_PKEY_CTX_get_ecdh_kdf_md(c, &md));
    printf("  md %s\n", md == NULL ? "NULL" : EVP_MD_get0_name(md));
    SHOW("ecdh kdf outlen", EVP_PKEY_CTX_set_ecdh_kdf_outlen(c, 12));
    SHOW("ecdh kdf outlen get", EVP_PKEY_CTX_get_ecdh_kdf_outlen(c, &len));
    printf("  outlen %d\n", len);
    ukm = OPENSSL_malloc(2);
    memcpy(ukm, "ec", 2);
    SHOW("ecdh kdf ukm", EVP_PKEY_CTX_set0_ecdh_kdf_ukm(c, ukm, 2));
    SHOW("ecdh kdf ukm get", EVP_PKEY_CTX_get0_ecdh_kdf_ukm(c, &got));
    SHOW("ctrl_str dh_pad", EVP_PKEY_CTX_ctrl_str(c, "dh_pad", "0"));
    SHOW("ctrl_str ecdh_cofactor_mode", EVP_PKEY_CTX_ctrl_str(c, "ecdh_cofactor_mode", "0"));
    SHOW("ctrl_str ecdh_kdf_md", EVP_PKEY_CTX_ctrl_str(c, "ecdh_kdf_md", "SHA1"));
    SHOW("ctrl_str pad", EVP_PKEY_CTX_ctrl_str(c, "pad", "1"));
    SHOW("ctrl_str kdf-ukm", EVP_PKEY_CTX_ctrl_str(c, "hexkdf-ukm", "0102"));
    SHOW("set1_id on derive", EVP_PKEY_CTX_set1_id(c, "x", 1));
    SHOW("get1_id on derive", EVP_PKEY_CTX_get1_id(c, txt));
    outlen = sizeof(out);
    r = EVP_PKEY_derive(c, out, &outlen);
    printf("  derive %d %zu\n", r, outlen);
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new_from_pkey(lib, k, NULL);
    check(EVP_PKEY_derive_init_ex(c, NULL) == 1, "derive init again");
    {
        EVP_PKEY *blank = EVP_PKEY_new();

        SHOW("set_peer of another type", EVP_PKEY_derive_set_peer(c, blank));
        EVP_PKEY_free(blank);
    }
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(p);
    EVP_PKEY_free(k);
}

static void test_signature(void)
{
    EVP_PKEY *k = toy_key("TOY");
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(lib, k, NULL);
    unsigned char sig[32] = { 0 }, id[16] = { 0 };
    int r;
    size_t siglen = sizeof(sig), idlen = 0;
    X509_ALGOR *alg = NULL, *alg2 = X509_ALGOR_new();
    const EVP_MD *md = NULL;
    char txt[64];

    SHOW("set1_id before init", EVP_PKEY_CTX_set1_id(c, "id!", 3));
    check(EVP_PKEY_sign_init(c) == 1, "sign init uses the ID");
    SHOW("get1_id", EVP_PKEY_CTX_get1_id(c, id));
    printf("  id %.3s\n", *(const char **)id);
    SHOW("get1_id_len", EVP_PKEY_CTX_get1_id_len(c, &idlen));
    printf("  idlen %zu\n", idlen);
    SHOW("ctrl_str distid", EVP_PKEY_CTX_ctrl_str(c, "distid", "abc"));
    SHOW("ctrl_str hexdistid", EVP_PKEY_CTX_ctrl_str(c, "hexdistid", "616263"));
    SHOW("ctrl_str digestsize", EVP_PKEY_CTX_ctrl_str(c, "digestsize", "12"));
    SHOW("signature md", EVP_PKEY_CTX_set_signature_md(c, EVP_sha512()));
    SHOW("signature md get", EVP_PKEY_CTX_get_signature_md(c, &md));
    printf("  md %s\n", md == NULL ? "NULL" : EVP_MD_get0_name(md));
    SHOW("ctrl get md", EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_GET_MD, 0,
                                          (void *)&md));
    printf("  md %s\n", md == NULL ? "NULL" : EVP_MD_get0_name(md));
    SHOW("get_algor", EVP_PKEY_CTX_get_algor(c, &alg));
    if (alg != NULL) {
        OBJ_obj2txt(txt, sizeof(txt), alg->algorithm, 0);
        printf("  algor %s\n", txt);
    }
    SHOW("set_algor_params", EVP_PKEY_CTX_set_algor_params(c, alg));
    SHOW("get_algor_params", EVP_PKEY_CTX_get_algor_params(c, alg2));
    printf("  params %d\n", alg2->parameter == NULL ? -1 : alg2->parameter->type);
    r = EVP_PKEY_sign(c, sig, &siglen, (const unsigned char *)"data", 4);
    printf("  sign %d %zu\n", r, siglen);
    check(EVP_PKEY_verify_init(c) == 1, "verify init");
    printf("  verify %d\n", EVP_PKEY_verify(c, sig, siglen, (const unsigned char *)"data", 4));
    X509_ALGOR_free(alg);
    X509_ALGOR_free(alg2);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(k);
}

static void test_rsa(void)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(lib, "RSA", NULL), *c;
    EVP_PKEY *k = NULL;
    BIGNUM *e = BN_new(), *e2 = BN_new();
    const EVP_MD *md = NULL;
    unsigned char *label = OPENSSL_malloc(5), *got = NULL, ct[16] = { 0 };
    int r;
    size_t ctlen = sizeof(ct);
    char name[64];
    int pad = 0, saltlen = 0;

    BN_set_word(e, 65537);
    BN_set_word(e2, 0x10001000100ULL);
    memcpy(label, "label", 5);
    check(EVP_PKEY_keygen_init(g) == 1, "RSA keygen init");
    SHOW("keygen bits", EVP_PKEY_CTX_set_rsa_keygen_bits(g, 2048));
    SHOW("keygen primes", EVP_PKEY_CTX_set_rsa_keygen_primes(g, 3));
    SHOW("keygen pubexp", EVP_PKEY_CTX_set_rsa_keygen_pubexp(g, e));
    SHOW("keygen set1 pubexp", EVP_PKEY_CTX_set1_rsa_keygen_pubexp(g, e2));
    SHOW("pss keygen md", EVP_PKEY_CTX_set_rsa_pss_keygen_md(g, EVP_sha256()));
    SHOW("pss keygen md name", EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(g, "SHA256", NULL));
    SHOW("pss keygen saltlen", EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(g, 20));
    SHOW("ctrl_str rsa_keygen_bits", EVP_PKEY_CTX_ctrl_str(g, "rsa_keygen_bits", "3072"));
    SHOW("ctrl_str rsa_keygen_pubexp", EVP_PKEY_CTX_ctrl_str(g, "rsa_keygen_pubexp", "3"));
    SHOW("ctrl_str rsa_keygen_primes", EVP_PKEY_CTX_ctrl_str(g, "rsa_keygen_primes", "2"));
    SHOW("group", EVP_PKEY_CTX_set_group_name(g, "rsa-group"));
    SHOW("group get", EVP_PKEY_CTX_get_group_name(g, name, sizeof(name)));
    printf("  group %s\n", name);
    SHOW("keygen", EVP_PKEY_keygen(g, &k));
    printf("  key id %d type %s\n", EVP_PKEY_get_id(k), str(EVP_PKEY_get0_type_name(k)));
    EVP_PKEY_CTX_free(g);
    BN_free(e2);

    c = EVP_PKEY_CTX_new_from_pkey(lib, k, NULL);
    check(EVP_PKEY_encrypt_init(c) == 1, "RSA encrypt init");
    SHOW("padding", EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING));
    SHOW("padding get", EVP_PKEY_CTX_get_rsa_padding(c, &pad));
    printf("  pad %d\n", pad);
    /* Reading back a mode without a name crashes the reference (docs/DEVIATIONS.md). */
    SHOW("padding with tls", EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_WITH_TLS_PADDING));
    SHOW("oaep md", EVP_PKEY_CTX_set_rsa_oaep_md(c, EVP_sha256()));
    SHOW("oaep md get", EVP_PKEY_CTX_get_rsa_oaep_md(c, &md));
    printf("  md %s\n", md == NULL ? "NULL" : EVP_MD_get0_name(md));
    SHOW("oaep md name", EVP_PKEY_CTX_set_rsa_oaep_md_name(c, "SHA1", "fips=no"));
    SHOW("oaep md name get", EVP_PKEY_CTX_get_rsa_oaep_md_name(c, name, sizeof(name)));
    printf("  name %s\n", name);
    SHOW("mgf1 md", EVP_PKEY_CTX_set_rsa_mgf1_md(c, EVP_sha384()));
    SHOW("mgf1 md get", EVP_PKEY_CTX_get_rsa_mgf1_md(c, &md));
    printf("  md %s\n", md == NULL ? "NULL" : EVP_MD_get0_name(md));
    SHOW("mgf1 md name", EVP_PKEY_CTX_set_rsa_mgf1_md_name(c, "SHA224", "x=1"));
    SHOW("mgf1 md name get", EVP_PKEY_CTX_get_rsa_mgf1_md_name(c, name, sizeof(name)));
    printf("  name %s\n", name);
    SHOW("label", EVP_PKEY_CTX_set0_rsa_oaep_label(c, label, 5));
    SHOW("label get", EVP_PKEY_CTX_get0_rsa_oaep_label(c, &got));
    if (got != NULL)
        printf("  label %.5s\n", got);
    SHOW("label NULL", EVP_PKEY_CTX_set0_rsa_oaep_label(c, NULL, 0));
    SHOW("implicit rejection", EVP_PKEY_CTX_ctrl(c, EVP_PKEY_RSA, -1,
                                                 EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION, 0, NULL));
    SHOW("ctrl_str rsa_padding_mode", EVP_PKEY_CTX_ctrl_str(c, "rsa_padding_mode", "oaep"));
    SHOW("ctrl_str rsa_oaep_md", EVP_PKEY_CTX_ctrl_str(c, "rsa_oaep_md", "SHA256"));
    SHOW("ctrl_str rsa_mgf1_md", EVP_PKEY_CTX_ctrl_str(c, "rsa_mgf1_md", "SHA1"));
    SHOW("ctrl_str rsa_oaep_label", EVP_PKEY_CTX_ctrl_str(c, "rsa_oaep_label", "6c6162"));
    SHOW("ctrl_str rsa_pkcs1_implicit_rejection",
         EVP_PKEY_CTX_ctrl_str(c, "rsa_pkcs1_implicit_rejection", "1"));
    SHOW("ctrl_str digest", EVP_PKEY_CTX_ctrl_str(c, "digest", "SHA512"));
    SHOW("pss saltlen while encrypting", EVP_PKEY_CTX_set_rsa_pss_saltlen(c, 20));
    r = EVP_PKEY_encrypt(c, ct, &ctlen, (const unsigned char *)"rsa", 3);
    printf("  encrypt %d %zu\n", r, ctlen);

    check(EVP_PKEY_sign_init(c) == 1, "RSA sign init");
    SHOW("padding pss", EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_PSS_PADDING));
    SHOW("padding get", EVP_PKEY_CTX_get_rsa_padding(c, &pad));
    printf("  pad %d\n", pad);
    SHOW("saltlen digest", EVP_PKEY_CTX_set_rsa_pss_saltlen(c, RSA_PSS_SALTLEN_DIGEST));
    SHOW("saltlen get", EVP_PKEY_CTX_get_rsa_pss_saltlen(c, &saltlen));
    printf("  saltlen %d\n", saltlen);
    SHOW("saltlen 20", EVP_PKEY_CTX_set_rsa_pss_saltlen(c, 20));
    SHOW("saltlen get", EVP_PKEY_CTX_get_rsa_pss_saltlen(c, &saltlen));
    printf("  saltlen %d\n", saltlen);
    SHOW("ctrl_str rsa_pss_saltlen", EVP_PKEY_CTX_ctrl_str(c, "rsa_pss_saltlen", "max"));
    SHOW("saltlen get", EVP_PKEY_CTX_get_rsa_pss_saltlen(c, &saltlen));
    printf("  saltlen %d\n", saltlen);
    SHOW("mgf1", EVP_PKEY_CTX_set_rsa_mgf1_md(c, EVP_sha256()));
    SHOW("oaep md while signing", EVP_PKEY_CTX_set_rsa_oaep_md(c, EVP_sha256()));
    SHOW("label while signing", EVP_PKEY_CTX_get0_rsa_oaep_label(c, &got));
    SHOW("ctrl_str digestsize", EVP_PKEY_CTX_ctrl_str(c, "digestsize", "16"));
    EVP_PKEY_CTX_free(c);

    g = EVP_PKEY_CTX_new_from_name(lib, "RSA-PSS", NULL);
    check(EVP_PKEY_keygen_init(g) == 1, "RSA-PSS keygen init");
    SHOW("pss keygen md", EVP_PKEY_CTX_set_rsa_pss_keygen_md(g, EVP_sha256()));
    SHOW("pss keygen md name", EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(g, "SHA384", "p=1"));
    SHOW("pss keygen mgf1", EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(g, EVP_sha1()));
    SHOW("pss keygen mgf1 name", EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(g, "SHA512"));
    SHOW("pss keygen saltlen", EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(g, 32));
    SHOW("keygen bits", EVP_PKEY_CTX_set_rsa_keygen_bits(g, 1024));
    SHOW("ctrl_str rsa_pss_keygen_md", EVP_PKEY_CTX_ctrl_str(g, "rsa_pss_keygen_md", "SHA256"));
    SHOW("ctrl_str rsa_pss_keygen_saltlen",
         EVP_PKEY_CTX_ctrl_str(g, "rsa_pss_keygen_saltlen", "16"));
    EVP_PKEY_CTX_free(g);
    EVP_PKEY_free(k);
}

static void test_ffc_ec(void)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(lib, "DH", NULL);

    check(EVP_PKEY_paramgen_init(g) == 1, "DH paramgen init");
    SHOW("prime len", EVP_PKEY_CTX_set_dh_paramgen_prime_len(g, 2048));
    SHOW("subprime len", EVP_PKEY_CTX_set_dh_paramgen_subprime_len(g, 256));
    SHOW("generator", EVP_PKEY_CTX_set_dh_paramgen_generator(g, 5));
    SHOW("type", EVP_PKEY_CTX_set_dh_paramgen_type(g, DH_PARAMGEN_TYPE_FIPS_186_4));
    SHOW("gindex", EVP_PKEY_CTX_set_dh_paramgen_gindex(g, 2));
    SHOW("seed", EVP_PKEY_CTX_set_dh_paramgen_seed(g, (const unsigned char *)"seed", 4));
    SHOW("nid", EVP_PKEY_CTX_set_dh_nid(g, NID_ffdhe3072));
    SHOW("nid modp", EVP_PKEY_CTX_set_dh_nid(g, NID_modp_1536));
    SHOW("nid bad", EVP_PKEY_CTX_set_dh_nid(g, NID_sha256));
    SHOW("rfc5114", EVP_PKEY_CTX_set_dh_rfc5114(g, 2));
    SHOW("rfc5114 bad", EVP_PKEY_CTX_set_dhx_rfc5114(g, 4));
    SHOW("ctrl_str dh_paramgen_prime_len", EVP_PKEY_CTX_ctrl_str(g, "dh_paramgen_prime_len", "1024"));
    SHOW("ctrl_str dh_paramgen_generator", EVP_PKEY_CTX_ctrl_str(g, "dh_paramgen_generator", "2"));
    SHOW("ctrl_str dh_paramgen_type", EVP_PKEY_CTX_ctrl_str(g, "dh_paramgen_type", "1"));
    SHOW("ctrl_str dh_paramgen_type bad", EVP_PKEY_CTX_ctrl_str(g, "dh_paramgen_type", "9"));
    SHOW("ctrl_str dh_rfc5114", EVP_PKEY_CTX_ctrl_str(g, "dh_rfc5114", "3"));
    SHOW("ctrl_str dh_rfc5114 bad", EVP_PKEY_CTX_ctrl_str(g, "dh_rfc5114", "0"));
    SHOW("ctrl_str dh_param", EVP_PKEY_CTX_ctrl_str(g, "dh_param", "ffdhe4096"));
    SHOW("ctrl_str dh_paramgen_subprime_len",
         EVP_PKEY_CTX_ctrl_str(g, "dh_paramgen_subprime_len", "224"));
    EVP_PKEY_CTX_free(g);

    g = EVP_PKEY_CTX_new_from_name(lib, "DHX", NULL);
    check(EVP_PKEY_paramgen_init(g) == 1, "DHX paramgen init");
    SHOW("type", EVP_PKEY_CTX_set_dh_paramgen_type(g, DH_PARAMGEN_TYPE_FIPS_186_2));
    SHOW("rfc5114", EVP_PKEY_CTX_set_dhx_rfc5114(g, 1));
    SHOW("nid", EVP_PKEY_CTX_set_dh_nid(g, NID_ffdhe2048));
    SHOW("ctrl_str dh_paramgen_subprime_len",
         EVP_PKEY_CTX_ctrl_str(g, "dh_paramgen_subprime_len", "224"));
    SHOW("ctrl_str dh_param", EVP_PKEY_CTX_ctrl_str(g, "dh_param", "ffdhe2048"));
    SHOW("ctrl_str dh_paramgen_type", EVP_PKEY_CTX_ctrl_str(g, "dh_paramgen_type", "2"));
    EVP_PKEY_CTX_free(g);

    g = EVP_PKEY_CTX_new_from_name(lib, "DSA", NULL);
    check(EVP_PKEY_paramgen_init(g) == 1, "DSA paramgen init");
    SHOW("bits", EVP_PKEY_CTX_set_dsa_paramgen_bits(g, 2048));
    SHOW("q bits", EVP_PKEY_CTX_set_dsa_paramgen_q_bits(g, 256));
    SHOW("md", EVP_PKEY_CTX_set_dsa_paramgen_md(g, EVP_sha256()));
    SHOW("md props", EVP_PKEY_CTX_set_dsa_paramgen_md_props(g, "SHA384", NULL));
    SHOW("gindex", EVP_PKEY_CTX_set_dsa_paramgen_gindex(g, 3));
    SHOW("seed", EVP_PKEY_CTX_set_dsa_paramgen_seed(g, (const unsigned char *)"dsa", 3));
    SHOW("type", EVP_PKEY_CTX_set_dsa_paramgen_type(g, "fips186_2"));
    SHOW("ctrl_str dsa_paramgen_bits", EVP_PKEY_CTX_ctrl_str(g, "dsa_paramgen_bits", "1024"));
    SHOW("ctrl_str dsa_paramgen_q_bits", EVP_PKEY_CTX_ctrl_str(g, "dsa_paramgen_q_bits", "160"));
    SHOW("ctrl_str dsa_paramgen_md", EVP_PKEY_CTX_ctrl_str(g, "dsa_paramgen_md", "SHA1"));
    EVP_PKEY_CTX_free(g);

    g = EVP_PKEY_CTX_new_from_name(lib, "EC", NULL);
    check(EVP_PKEY_keygen_init(g) == 1, "EC keygen init");
    SHOW("curve", EVP_PKEY_CTX_set_ec_paramgen_curve_nid(g, NID_X9_62_prime256v1));
    SHOW("curve sm2", EVP_PKEY_CTX_set_ec_paramgen_curve_nid(g, NID_sm2));
    SHOW("enc named", EVP_PKEY_CTX_set_ec_param_enc(g, OPENSSL_EC_NAMED_CURVE));
    SHOW("enc explicit", EVP_PKEY_CTX_set_ec_param_enc(g, OPENSSL_EC_EXPLICIT_CURVE));
    SHOW("enc bad", EVP_PKEY_CTX_set_ec_param_enc(g, 7));
    SHOW("ctrl_str ec_paramgen_curve", EVP_PKEY_CTX_ctrl_str(g, "ec_paramgen_curve", "P-384"));
    SHOW("ctrl_str ec_param_enc", EVP_PKEY_CTX_ctrl_str(g, "ec_param_enc", "named_curve"));
    SHOW("ctrl_str group", EVP_PKEY_CTX_ctrl_str(g, "group", "P-521"));
    SHOW("ctrl_str unknown", EVP_PKEY_CTX_ctrl_str(g, "ecdh_kdf_md", "SHA1"));
    EVP_PKEY_CTX_free(g);

    g = EVP_PKEY_CTX_new_from_name(lib, "SM2", NULL);
    check(EVP_PKEY_paramgen_init(g) == 1, "SM2 paramgen init");
    SHOW("curve", EVP_PKEY_CTX_set_ec_paramgen_curve_nid(g, NID_sm2));
    SHOW("enc", EVP_PKEY_CTX_set_ec_param_enc(g, OPENSSL_EC_NAMED_CURVE));
    SHOW("ctrl_str ec_paramgen_curve", EVP_PKEY_CTX_ctrl_str(g, "ec_paramgen_curve", "SM2"));
    EVP_PKEY_CTX_free(g);

    {
        EVP_PKEY *a = toy_key_from("EC", "ecalice");
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(lib, a, NULL);

        check(EVP_PKEY_derive_init(c) == 1, "EC derive init");
        SHOW("ctrl_str ecdh_cofactor_mode", EVP_PKEY_CTX_ctrl_str(c, "ecdh_cofactor_mode", "1"));
        SHOW("ctrl_str ecdh_kdf_md", EVP_PKEY_CTX_ctrl_str(c, "ecdh_kdf_md", "SHA256"));
        SHOW("ctrl_str dh_pad", EVP_PKEY_CTX_ctrl_str(c, "dh_pad", "1"));
        SHOW("kdf type ctrl", EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE,
                                                EVP_PKEY_CTRL_EC_KDF_TYPE,
                                                EVP_PKEY_ECDH_KDF_X9_63, NULL));
        EVP_PKEY_CTX_free(c);
        EVP_PKEY_free(a);
    }
}

int main(void)
{
    OSSL_PROVIDER *prov;

    setvbuf(stdout, NULL, _IOLBF, 0);
    lib = OSSL_LIB_CTX_new();
    check(OSSL_PROVIDER_add_builtin(lib, "pktest", provider_init) == 1, "add_builtin");
    prov = OSSL_PROVIDER_load(lib, "pktest");
    check(prov != NULL, "load");
    test_methods();
    test_cipher();
    test_kem();
    test_exchange();
    test_signature();
    test_rsa();
    test_ffc_ec();
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(lib);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
