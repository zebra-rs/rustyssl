/*
 * Conformance test for encrypted PEM (PEM_read_bio(3)'s PEM_get_EVP_CIPHER_INFO and
 * PEM_do_header, PEM_ASN1_write_bio, EVP_BytesToKey(3), PEM_def_callback), in TAP format:
 * Proc-Type/DEK-Info headers read (and every way one can be wrong), bodies decrypted under a
 * password from the callback or the caller's data (and wrong ones), values written as PEM
 * plain and encrypted (then read back), the key derivation's vectors, and the errors.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

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

static void hex(const char *label, const unsigned char *p, long n)
{
    long i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void header(const char *h)
{
    EVP_CIPHER_INFO info;
    char *copy = h == NULL ? NULL : OPENSSL_strdup(h);
    int r;

    memset(&info, 0x55, sizeof(info));
    r = PEM_get_EVP_CIPHER_INFO(copy, &info);
    printf("  [%s]: %d %s", h == NULL ? "NULL" : h, r,
           info.cipher == NULL ? "-" : EVP_CIPHER_get0_name(info.cipher));
    hex("iv", info.iv, sizeof(info.iv));
    errors();
    if (copy != NULL)
        check(strcmp(copy, h) == 0, "the header is as it was");
    OPENSSL_free(copy);
}

static void headers(void)
{
    static const char *const texts[] = {
        NULL,
        "",
        "\n",
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,000102030405060708090A0B0C0D0E0F\n",
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: aes-256-cbc,f0e0d0c0b0a090807060504030201000\n",
        "Proc-Type:4,ENCRYPTED\nDEK-Info:DES-EDE3-CBC,0123456789ABCDEF\n",
        "Proc-Type: \t4, \tENCRYPTED \t\r\nDEK-Info: \tDES-CBC \t,0123456789abcdefXYZ\n",
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-ECB\n",
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-ECB,00\n",
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC\n",
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0001\n",
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,000102030405060708090a0b0c0d0eZZ\n",
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: NO-SUCH-CIPHER,00\n",
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC 000102030405060708090A0B0C0D0E0F\n",
        "Proc-Type: 4,ENCRYPTED\nDek-Info: AES-128-CBC,00\n",
        "Proc-Type: 4,ENCRYPTED",
        "Proc-Type: 4,ENCRYPTED x\nDEK-Info: AES-128-CBC,00\n",
        "Proc-Type: 4,ENCRYPTEDX\n",
        "Proc-Type: 4,MIC-ONLY\n",
        "Proc-Type: 5,ENCRYPTED\n",
        "Proc-Type: 4 ENCRYPTED\n",
        "Content-Domain: RFC822\n",
        "proc-type: 4,ENCRYPTED\n",
        NULL
    };
    int i;

    header(NULL);
    for (i = 1; texts[i] != NULL || i == 0; i++)
        header(texts[i]);
}

static void bytes_to_key(void)
{
    static const unsigned char salt[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    const EVP_CIPHER *ciphers[] = { EVP_aes_256_cbc(), EVP_aes_128_cbc(), EVP_des_ede3_cbc(),
                                    EVP_aes_128_ecb() };
    const EVP_MD *mds[] = { EVP_md5(), EVP_sha256(), EVP_sha1() };
    unsigned char key[64], iv[16];
    int c, m, r;

    for (c = 0; c < 4; c++)
        for (m = 0; m < 3; m++) {
            memset(key, 0xee, sizeof(key));
            memset(iv, 0xee, sizeof(iv));
            r = EVP_BytesToKey(ciphers[c], mds[m], m == 1 ? NULL : salt,
                               (const unsigned char *)"password", 8, m + 1, key, iv);
            printf("  %s %s: %d\n", EVP_CIPHER_get0_name(ciphers[c]), EVP_MD_get0_name(mds[m]), r);
            hex("key", key, EVP_CIPHER_get_key_length(ciphers[c]));
            hex("iv", iv, EVP_CIPHER_get_iv_length(ciphers[c]));
        }
    check(EVP_BytesToKey(EVP_aes_192_cbc(), EVP_md5(), salt, NULL, 0, 1, key, iv) == 24,
          "no data: only the key's length");
    memset(key, 0xee, sizeof(key));
    check(EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt, (const unsigned char *)"", 0, 0,
                         key, NULL) == 16,
          "an empty password, no IV, a count of 0");
    hex("key", key, 16);
    check(EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha512(), NULL, (const unsigned char *)"pw", 2, 1,
                         NULL, iv) == 16,
          "only the IV");
    hex("iv", iv, 16);
    check(EVP_BytesToKey(EVP_aes_128_cbc(), NULL, salt, (const unsigned char *)"pw", 2, 1, key,
                         iv) == 0,
          "no digest");
    errors();
}

static int calls;

static int cb(char *buf, int size, int rwflag, void *u)
{
    const char *pw = u;

    calls++;
    printf("  callback size %d rwflag %d\n", size, rwflag);
    if (pw == NULL)
        return -1;
    if (strcmp(pw, "empty") == 0)
        return 0;
    strcpy(buf, pw);
    return (int)strlen(pw);
}

/* A known encrypted body: "secret data!" (and 19 more) under AES-128-CBC, password "pw". */
static long known(unsigned char *out, EVP_CIPHER_INFO *info)
{
    static const unsigned char iv[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                          0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    unsigned char key[16];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, m = 0;

    info->cipher = EVP_aes_128_cbc();
    memcpy(info->iv, iv, 16);
    EVP_BytesToKey(info->cipher, EVP_md5(), iv, (const unsigned char *)"pw", 2, 1, key, NULL);
    EVP_EncryptInit_ex(ctx, info->cipher, NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &n, (const unsigned char *)"secret data! and some more.", 28);
    EVP_EncryptFinal_ex(ctx, out + n, &m);
    EVP_CIPHER_CTX_free(ctx);
    return n + m;
}

static void decrypt(const char *what, pem_password_cb *callback, void *u)
{
    EVP_CIPHER_INFO info;
    unsigned char data[64];
    long len = known(data, &info);
    int r = PEM_do_header(&info, data, &len, callback, u);

    printf("  %s: %d %ld\n", what, r, len);
    if (r)
        printf("  plaintext: %.*s\n", (int)len, data);
    errors();
}

static void do_header(void)
{
    EVP_CIPHER_INFO none;
    unsigned char data[8] = "abcdefg";
    long len = 7;

    calls = 0;
    decrypt("the caller's data", NULL, "pw");
    decrypt("the callback", cb, "pw");
    decrypt("the wrong password", cb, "pw!");
    decrypt("the callback fails", cb, NULL);
    decrypt("an empty password", cb, "empty");
    decrypt("a longer one, cut", NULL, "pwXX");
    printf("  calls %d\n", calls);
    none.cipher = NULL;
    check(PEM_do_header(&none, data, &len, cb, NULL) == 1 && len == 7, "no cipher: nothing");
    check(calls == 4, "the callback only where given, and not for no cipher");
}

static int ctx_i2d(const void *x, unsigned char **out, void *vctx)
{
    printf("  ctx i2d %s\n", (const char *)vctx);
    return i2d_ASN1_OCTET_STRING(x, out);
}

static int failing_i2d(const void *x, unsigned char **out)
{
    (void)x, (void)out;
    return 0;
}

/* Reads the PEM from `b` back, decrypting with `pw`. */
static void read_back(BIO *b, const char *pw, int expect)
{
    char *name = NULL, *hdr = NULL;
    unsigned char *data = NULL;
    long len = 0;
    EVP_CIPHER_INFO info;
    int r;

    r = PEM_read_bio(b, &name, &hdr, &data, &len);
    check(r == expect, expect ? "read back" : "nothing to read back");
    if (r != 1) {
        errors();
        return;
    }
    printf("  name %s, encrypted %d, %ld octets\n", name, hdr[0] != '\0', len);
    if (hdr[0] != '\0')
        printf("  Proc-Type line ok %d, DEK-Info %.*s\n",
               strncmp(hdr, "Proc-Type: 4,ENCRYPTED\nDEK-Info: ", 33) == 0,
               (int)strcspn(hdr + 33, ","), hdr + 33);
    r = PEM_get_EVP_CIPHER_INFO(hdr, &info) && PEM_do_header(&info, data, &len, NULL, (void *)pw);
    printf("  decrypted %d:", r);
    hex("", data, r ? len : 0);
    errors();
    OPENSSL_free(name);
    OPENSSL_free(hdr);
    OPENSSL_free(data);
}

static void writing(void)
{
    ASN1_OCTET_STRING *o = ASN1_OCTET_STRING_new();
    BIO *b = BIO_new(BIO_s_mem());
    FILE *fp = tmpfile();
    char text[400];
    long n;

    ASN1_OCTET_STRING_set(o, (const unsigned char *)"some key material", 17);

    check(PEM_ASN1_write_bio((i2d_of_void *)i2d_ASN1_OCTET_STRING, "TEST DATA", b, o, NULL, NULL,
                             0, NULL, NULL),
          "plain");
    n = BIO_read(b, text, sizeof(text) - 1);
    text[n > 0 ? n : 0] = '\0';
    printf("%s", text);

    check(PEM_ASN1_write_bio((i2d_of_void *)i2d_ASN1_OCTET_STRING, "TEST DATA", b, o,
                             EVP_aes_256_cbc(), (const unsigned char *)"secret", 6, NULL, NULL),
          "AES-256-CBC under kstr");
    read_back(b, "secret", 1);
    calls = 0;
    check(PEM_ASN1_write_bio((i2d_of_void *)i2d_ASN1_OCTET_STRING, "TEST DATA", b, o,
                             EVP_des_ede3_cbc(), NULL, 0, cb, "from the callback"),
          "DES-EDE3-CBC under the callback's password");
    check(calls == 1, "one call");
    read_back(b, "from the callback", 1);
    check(PEM_ASN1_write_bio((i2d_of_void *)i2d_ASN1_OCTET_STRING, "TEST DATA", b, o,
                             EVP_aes_128_cbc(), NULL, 0, NULL, "the caller's data"),
          "AES-128-CBC under the caller's data");
    read_back(b, "the caller's data", 1);
    check(PEM_ASN1_write_bio_ctx(ctx_i2d, "vctx", "TEST DATA", b, o, EVP_aria_128_cbc(),
                                 (const unsigned char *)"k", 1, NULL, NULL),
          "with a context");
    read_back(b, "k", 1);
    read_back(b, "nothing left", 0);

    /* What fails. */
    check(!PEM_ASN1_write_bio((i2d_of_void *)i2d_ASN1_OCTET_STRING, "TEST DATA", b, o,
                              EVP_aes_128_ecb(), (const unsigned char *)"k", 1, NULL, NULL),
          "a cipher without an IV");
    errors();
    check(!PEM_ASN1_write_bio((i2d_of_void *)i2d_ASN1_OCTET_STRING, "TEST DATA", b, o,
                              EVP_aes_128_cbc(), NULL, 0, cb, NULL),
          "the callback fails");
    errors();
    check(!PEM_ASN1_write_bio((i2d_of_void *)i2d_ASN1_OCTET_STRING, "TEST DATA", b, o,
                              EVP_aes_128_cbc(), NULL, 0, cb, "empty"),
          "an empty password");
    errors();
    check(!PEM_ASN1_write_bio(NULL, "TEST DATA", b, o, NULL, NULL, 0, NULL, NULL), "no i2d");
    errors();
    check(!PEM_ASN1_write_bio(failing_i2d, "TEST DATA", b, o, NULL, NULL, 0, NULL, NULL),
          "nothing to encode");
    errors();
    check(BIO_pending(b) == 0, "nothing written");

    /* To a FILE. */
    check(PEM_ASN1_write((i2d_of_void *)i2d_ASN1_OCTET_STRING, "TEST DATA", fp, o, NULL, NULL,
                         0, NULL, NULL),
          "to a FILE");
    rewind(fp);
    n = (long)fread(text, 1, sizeof(text) - 1, fp);
    text[n > 0 ? n : 0] = '\0';
    printf("%s", text);
    fclose(fp);
    BIO_free(b);
    ASN1_OCTET_STRING_free(o);
}

static void def_callback(void)
{
    char buf[16];

    memset(buf, 'x', sizeof(buf));
    check(PEM_def_callback(buf, sizeof(buf), 0, "password") == 8 && memcmp(buf, "passwordx", 9) == 0,
          "the caller's data");
    memset(buf, 'x', sizeof(buf));
    check(PEM_def_callback(buf, 4, 1, "password") == 4 && memcmp(buf, "passx", 5) == 0,
          "cut to the room");
    check(PEM_def_callback(buf, 0, 1, "password") == 0, "no room");
}

int main(void)
{
    headers();
    bytes_to_key();
    do_header();
    writing();
    def_callback();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
