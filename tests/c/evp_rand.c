/*
 * Conformance test for EVP_RAND(3) and the default provider's random generators
 * (EVP_RAND-CTR-DRBG(7), EVP_RAND-HASH-DRBG(7), EVP_RAND-HMAC-DRBG(7), EVP_RAND-SEED-SRC(7),
 * EVP_RAND-TEST-RAND(7)), in TAP format: the methods and their parameter lists, known answers
 * from the reference's evprand.txt (a cross-section, driven as its evp_test does: each DRBG
 * under a TEST-RAND parent that gives it entropy and nonces), the DRBG state machine, limits,
 * reseeding, and parameter errors, TEST-RAND's and SEED-SRC's behavior, chains of DRBGs, and
 * the NULL arguments the reference takes. Output that is random (from the operating system, or
 * from a DRBG seeded by another, whose address is mixed in) is checked, not printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The queue, oldest first, with each entry's data. */
static void errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf("  errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && data[0] != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

/* The queue's codes only (a failed fetch's data has the name's number, which differs). */
static void codes(void)
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

static size_t unhex(const char *s, unsigned char *out)
{
    size_t n = 0;
    unsigned int b;

    while (s != NULL && s[0] != '\0' && s[1] != '\0' && sscanf(s, "%2x", &b) == 1) {
        out[n++] = (unsigned char)b;
        s += 2;
    }
    return n;
}

static void list(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    if (p == NULL)
        printf(" NULL");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u/%zu", p->key, p->data_type, p->data_size);
    printf("\n");
}

static void name_cb(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static EVP_RAND_CTX *rand_ctx(const char *name, EVP_RAND_CTX *parent)
{
    EVP_RAND *rand = EVP_RAND_fetch(NULL, name, NULL);
    EVP_RAND_CTX *ctx = EVP_RAND_CTX_new(rand, parent);

    EVP_RAND_free(rand);
    return ctx;
}

/* A TEST-RAND of strength 256 (or none for 0) with the entropy and nonce given (hex). */
static EVP_RAND_CTX *test_rand(unsigned int strength, const char *entropy, const char *nonce)
{
    EVP_RAND_CTX *t = rand_ctx("TEST-RAND", NULL);
    unsigned char e[256], n[256];
    OSSL_PARAM params[4], *p = params;

    *p++ = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    if (entropy != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, e, unhex(entropy, e));
    if (nonce != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE, n, unhex(nonce, n));
    *p = OSSL_PARAM_construct_end();
    EVP_RAND_CTX_set_params(t, params);
    return t;
}

static int set_test_entropy(EVP_RAND_CTX *t, const char *entropy)
{
    unsigned char e[256];
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, e, unhex(entropy, e));
    params[1] = OSSL_PARAM_construct_end();
    return EVP_RAND_CTX_set_params(t, params);
}

/* ---------------------------------------------------------------------------------------- */

struct kat {
    const char *rand, *cipher, *digest;
    int use_df, pr, bits;
    const char *entropy, *nonce, *pers, *reseed_entropy, *reseed_addin, *pr_entropy_a, *addin_a,
        *pr_entropy_b, *addin_b, *output;
};

static const struct kat kats[] = {
    { "CTR-DRBG", "AES-192-CTR", NULL, 1, 1, 256,
      "22ed7a66c9e9f494c8d2b8f81d0d49bcdd0c03863ff5979212211efe3e945758b6228cdd9e9eec5f7984aef7212699f3",
      "5bf245b95f8e1377d5a17eb331aabcd9",
      NULL,
      NULL,
      NULL,
      "c0535acd3d715a0b1453ab3447d53d9131c939aee1d9ca24a75b285cf58d79403a4111e2f3dee011154d31d646d93001",
      NULL,
      "9fbc48890273fcafca1904b6486d1877cad91eb601e979259506f93ba462ac17d8676c570b2231d4d98ec617c4826573",
      NULL,
      "19ced57563d065b606da27dd5e8de83b93bb7c8f8b02d0288f475550c3f44b77",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 1, 0, 512,
      "890eb067acf7382eff80b0c73bc872c6",
      "aad471ef3ef1d203",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "a5514ed7095f64f3d0d3a5760394ab42062f373a25072a6ea6bcfd8489e94af6cf18659fea22ed1ca0a9e33f718b115ee536b12809c31b72b08ddd8be1910fa3",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 1, 0, 512,
      "b408cefb5bc7157d3f26cb95a8b1d7ac",
      "026c768fd577b92a",
      NULL,
      NULL,
      NULL,
      NULL,
      "5737ef81dee365b6dadb3feebf5d1084",
      NULL,
      "3368a516b3431a3daaa60dc8743c8297",
      "4e909ebb24147a0004063a5e47ee044fead610d62324bd0f963f756fb91361e8b87e3a76a398143fe88130fe1b547b661a6480c711b739f18a9df3ae51d41bc9",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 1, 0, 512,
      "e10bc28a0bfddfe93e7f5186e0ca0b3b",
      "9ff477c18673840d",
      "c980dedf9882ed4464a674967868f143",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "35b00df6269b6641fd4ccb354d56d851de7a77527e034d60c9e1a9e1525a30ed361fded89d3dccb978d4e7a9e100ebf63062735b52831c6f0a1d3e1bdc5ebc72",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 1, 0, 512,
      "cae48dd80d298103ef1ec0bf1bb96270",
      "d827f91613e0b47f",
      "cc928f3d2df31a29f4e444f3df08be21",
      NULL,
      NULL,
      NULL,
      "7eaa1bbec79393a7f4a8227b691ecb68",
      NULL,
      "6869c6c7b9e6653b3977f0789e94478a",
      "920132cd284695b868b5bc4b703afea4d996624a8f57e9fbf5e793b509cb15b4beaf702dac28712d249ae75090a91fd35775294bf24ddebfd24e45d13f4a1748",
    },
    { "CTR-DRBG", "AES-192-CTR", NULL, 1, 0, 512,
      "c35c2fa2a89d52a11fa32aa96c95b8f1c9a8f9cb245a8b40",
      "f3a6e5a7fbd9d3c68e277ba9ac9bbb00",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "8c2e72abfd9bb8284db79e17a43a3146cd7694e35249fc3383914a7117f41368e6d4f148ff49bf29076b5015c59f457945662e3d3503843f4aa5a3df9a9df10d",
    },
    { "CTR-DRBG", "AES-192-CTR", NULL, 1, 0, 512,
      "eb4553f7141bc10882f0a3741780a42df8bc38a7121d3b7e",
      "6f347f9c1de84fd5341625ae8d6bf50c",
      "5e2e73b86ca2f3150d53d23d590acbeedaaf91638bdc3f9d588e945af4bb6ea2",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "a1deb9a5aad608a587d61ce5e0d7c7dd449b8c87898354ad1add6e05853873d279ebe4132fc236a42d8ff0dc3ace95d2cdf9d0b057117cb119ee7550ce03085c",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 1, 0, 512,
      "36401940fa8b1fba91a1661f211d78a0b9389a74e5bccfece8d766af1a6d3b14",
      "496f25b0f1301b4f501be30380a137eb",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "5862eb38bd558dd978a696e6df164782ddd887e7e9a6c9f3f1fbafb78941b535a64912dfd224c6dc7454e5250b3d97165e16260c2faf1cc7735cb75fb4f07e1d",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 1, 0, 512,
      "8148d65d86513ce7d38923ec2f26b9e7c677dcc8997e325b7372619e753ed944",
      "41c71a24d17d974190982bb7515ce7f5",
      NULL,
      NULL,
      NULL,
      NULL,
      "55b446046c2d14bdd0cdba4b71873fd4762650695a11507949462da8d964ab6a",
      NULL,
      "91468f1a097d99ee339462ca916cb4a10f63d53850a4f17f598eac490299b02e",
      "54603d1a506132bbfa05b153a04f22a1d516cc46323cef15111af221f030f38d6841d4670518b4914a4631af682e7421dffaac986a38e94d92bfa758e2eb101f",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 1, 0, 512,
      "5416e77b5e1d872d4ff91973b1be66bc07f4a99e30db7d0006da006fcfb082db",
      "7a811ce62b9fd34af186b2b3e50eaf5d",
      "71ee0c7699ac0e805632f2058de38bf872b8340f89998f7a8a2ad4ac045ae6ef",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "68f5859cf76f94c445d9fcd34fc17ac224c3d7d7c2fc38faaf3c24be6cd3cd93b7f9d8a6146f5ac83ac1d7b1b2b7e7ecbc1a2e38760ef86a577d402d85990d9b",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 1, 0, 512,
      "87b56e964eba227154724bb9484b812d3e2c0c43b3d17f6098d9526e16e6d0ef",
      "9bea6a7ff2358df142e6c23e2157fb83",
      "9860b432edd58d1ccbfeecbce99ffaee7d935a614860d4e965bd67041403096b",
      NULL,
      NULL,
      NULL,
      "99a5cc87924e8ea65a596f81fd17d63f5b4542fe6e8e1511b5d35c835dfadb0b",
      NULL,
      "9a8dec54734a34582a2332f3452e82313524c3e0dfb485faeac6ca5fc0ff504d",
      "dbc6a2330b19b5cddd8cd6392ec1fb508678c805e87d1aca07ac265007632503044a00610c79d98375afa7ab4cca1a90989cbfe7c674af5d823ced11c47e9af6",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 0, 0, 512,
      "ce50f33da5d4c1d3d4004eb35244b7f2cd7f2e5076fbf6780a7ff634b249a5fc",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "6545c0529d372443b392ceb3ae3a99a30f963eaf313280f1d1a1e87f9db373d361e75d18018266499cccd64d9bbb8de0185f213383080faddec46bae1f784e5a",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 0, 0, 512,
      "6bd4f2ae649fc99350951ff0c5d460c1a9214154e7384975ee54b34b7cae0704",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "ecd4893b979ac92db1894ae3724518a2f78cf2dbe2f6bbc6fda596df87c7a4ae",
      NULL,
      "b23e9188687c88768b26738862c4791fa52f92502e1f94bf66af017c4228a0dc",
      "5b2bf7a5c60d8ab6591110cbd61cd387b02de19784f496d1a109123d8b3562a5de2dd6d5d1aef957a6c4f371cecd93c15799d82e34d6a0dba7e915a27d8e65f3",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 0, 0, 512,
      "cee23de86a69c7ef57f6e1e12bd16e35e51624226fa19597bf93ec476a44b0f2",
      NULL,
      "a2ef16f226ea324f23abd59d5e3c660561c25e73638fe21c87566e86a9e04c3e",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "2a76d71b329f449c98dc08fff1d205a2fbd9e4ade120c7611c225c984eac8531288dd3049f3dc3bb3671501ab8fbf9ad49c86cce307653bd8caf29cb0cf07764",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 0, 0, 512,
      "50b96542a1f2b8b05074051fe8fb0e45adbbd5560e3594e12d485fe1bfcb741f",
      NULL,
      "820c3030f97b3ead81a93b88b871937278fd3d711d2085d9280cba394673b17e",
      NULL,
      NULL,
      NULL,
      "1f1632058806d6d8e231288f3b15a3c324e90ccef4891bd595f09c3e80e27469",
      NULL,
      "5cadc8bfd86d2a5d44f921f64c7d153001b9bdd7caa6618639b948ebfad5cb8a",
      "02b76a66f103e98d450e25e09c35337747d987471d2b3d81e03be24c7e985417a32acd72bc0a6eddd9871410dacb921c659249b4e2b368c4ac8580fb5db559bc",
    },
    { "CTR-DRBG", "AES-192-CTR", NULL, 0, 0, 512,
      "f1ef7eb311c850e189be229df7e6d68f1795aa8e21d93504e75abe78f041395873540386812a9a2a",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "6bb0aa5b4b97ee83765736ad0e9068dfef0ccfc93b71c1d3425302ef7ba4635ffc09981d262177e208a7ec90a557b6d76112d56c40893892c3034835036d7a69",
    },
    { "CTR-DRBG", "AES-192-CTR", NULL, 0, 0, 512,
      "d76697495add9baac8cfdf90e0a6f3381a52b2889f840a24cfc9606f97c49446202e70583fde09dc",
      NULL,
      "d64e546523fb082b5e87bbe6b66a8e6a7940bb06ed17fe833c4e9bbb211396c227f83671c924240e",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "5693f68ec7a8d2631dee9d371503e05cbd5fb872506f040050b1d441a94bd74ec06f24c1cc4363ece1d8b2295e74389b6dd8b1e5438bceab2f2bc2af5a9d8da8",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 0, 0, 512,
      "df5d73faa468649edda33b5cca79b0b05600419ccb7a879ddfec9db32ee494e5531b51de16a30f769262474c73bec010",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "d1c07cd95af8a7f11012c84ce48bb8cb87189e99d40fccb1771c619bdf82ab2280b1dc2f2581f39164f7ac0c510494b3a43c41b7db17514c87b107ae793e01c5",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 0, 0, 512,
      "f45e9d040c1456f1c7f26e7f146469fbe3973007fe037239ad57623046e7ec52221b22eec208b22ac4cf4ca8d6253874",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "28819bc79b92fc8790ebdc99812cdcea5c96e6feab32801ec1851b9f46e80eb6800028e61fbccb6ccbe42b06bf5a0864",
      NULL,
      "418ca848027e1b3c84d66717e6f31bf89684d5db94cd2d579233f716ac70ab66cc7b01a6f9ab8c7665fcc37dba4af1ad",
      "4f11406bd303c104243441a8f828bf0293cb20ac39392061429c3f56c1f426239f8f0c687b69897a2c7c8c2b4fb520b62741ffdd29f038b7c82a9d00a890a3ed",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 0, 0, 512,
      "22a89ee0e37b54ea636863d9fed10821f1952a428488d528eceb9d2ec69d573ec6216216fb3e8f72a148a5ada9d620b1",
      NULL,
      "953c10badcbcd45fb4e5475826477fc137ac96a49ad5005fb14bdaf6468ae7f46c5d0de22d304afc67989615adc2e983",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "f7fab6a6fcf445f0a0434b2aa0c610bdef5489ecd95414634623add18a9f888bca6be151312d1b9e8f83bd0acad6234d3bccc11b63a40d6fbff448f67db0b91f",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 0, 0, 512,
      "0dd4d80062ecc0f359efbe7723020be9b88b550fe74088094069e74428395856f63eed4f5b0e7d1e006f0eaff74f638c",
      NULL,
      "d2aa2ccd4bc6537e51f6550ab6d6294547bef3e971a7f128e4436f957de9982c93ee22110b0e40ab33a7d3dfa22f599d",
      NULL,
      NULL,
      NULL,
      "0b081bab6c74d86b4a010e2ded99d14e0c9838f7c3d69afd64f1b66377d95cdcb7f6ec5358e3516034c3339ced7e1638",
      NULL,
      "ca818f938ae0c7f4f507e4cfec10e7baf51fe34b89a502f754d2d2be7395120fe1fb013c67ac2500b3d17b735da09a6e",
      "6808268b13e236f642c06deba2494496e7003c937ebf6f7cb7c92104ea090f18484aa075560d7844a06eb559948c93b26ae40f2db98ecb53ad593eb4c78f82b1",
    },
    { "HASH-DRBG", NULL, "SHA-1", 0, 0, 640,
      "136cf1c174e5a09f66b962d994396525",
      "fff1c6645f19231f",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "0e28130fa5ca11edd3293ca26fdb8ae1810611f78715082ed3841e7486f16677b28e33ffe0b93d98ba57ba358c1343ab2a26b4eb7940f5bc639384641ee80a25140331076268bd1ce702ad534dda0ed8",
    },
    { "HASH-DRBG", NULL, "SHA-1", 0, 0, 640,
      "c3ef82ce241f02e4298b118ca4f16225",
      "15e32abbae6b7433",
      NULL,
      NULL,
      NULL,
      NULL,
      "2b790052f09b364d4a8267a0a7de63b8",
      NULL,
      "2ee0819a671d07b5085cc46aa0e61b56",
      "5825fa1d1dc33c64cdc8690682eff06039e79508c3af48e880f8227d5f9aaa14b3bc76baee477ebbb5c45547134179223257525e8f3afefb78b59da032f1006d74c9831375a677eab3239c94ebe3f7fa",
    },
    { "HASH-DRBG", NULL, "SHA-1", 0, 0, 640,
      "f7e316b13117dcc18c4407b6a5cdc5d8",
      "b80ddee75cf39a48",
      "816cb137ef64f9df71a3b3a0b3aaf9b1",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "be888585d95d95269f002abd8b1e33b2cb667a96d3be6d20d784b1bbc6639347837d01d4b95eed8137cf29fe724cfedf8b23f9258480be350c3407973c59a9d7f3a6585b3c0e36a36c6234d68852acaf",
    },
    { "HASH-DRBG", NULL, "SHA-1", 0, 0, 640,
      "6466e1799a68012379631b3aae41f59b",
      "6b0c61269f67c576",
      "cc936b87c8c8c1ab85dde0ad2e9242b4",
      NULL,
      NULL,
      NULL,
      "d1033ac553ef08f22fd38f12b49b45bc",
      NULL,
      "f004ba01f51455430d84362e376eb775",
      "5d675d1e92490952703c194194e1b061b6ec4e219dc2e1edaa891ef2d1b7ed050a06342d3c095011eb339f198519779b01ab1a580bd2e34d6cf4e47c1befe0c7dc37b4aafb31128fa396267f3732095a",
    },
    { "HASH-DRBG", NULL, "SHA-256", 0, 0, 1024,
      "a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb",
      "8581f9317517276e06e9607ddbcbcc2e",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "d3e160c35b99f340b2628264d1751060e0045da383ff57a57d73a673d2b8d80daaf6a6c35a91bb4579d73fd0c8fed111b0391306828adfed528f018121b3febdc343e797b87dbb63db1333ded9d1ece177cfa6b71fe8ab1da46624ed6415e51ccde2c7ca86e283990eeaeb91120415528b2295910281b02dd431f4c9f70427df",
    },
    { "HASH-DRBG", NULL, "SHA-256", 0, 0, 1024,
      "9b6d88373841458da926cc51f83922d363f0f80f90a2f5505c04033824ef7385",
      "82b21ff47bb5e1b33288b22f3856886b",
      NULL,
      NULL,
      NULL,
      NULL,
      "45d21d94ae1ea460857b50b5b240d943d42160e4c12377e0f817b79e92530bc1",
      NULL,
      "ea432e31cc94c20d66fb13d1ef42a5f62b024134fc635aa1279a6179204731ca",
      "3d23d0fc03936766a1e1330393e8ff6211149f3d0758db038da1c833ca8e5265c2a9ff6c8e0836904c5fcd3e61b1c77d613dc6bdaf6437573a618e3e75e455338a7f9a41300da8fd2da408cf095ff7eae1686d60ce9c2f547d0515da91600201c8374b7af8a5f49a6381aaca394c65d451341a0ae1546cd57e0d9167a6b5397d",
    },
    { "HASH-DRBG", NULL, "SHA-256", 0, 0, 1024,
      "dfeabab904bfe93a37bb5b1ea4a696f881ab5ab4be87ffbf2d4e8cdfaabb37fd",
      "a2d458b475053a0346b57fc518849ba1",
      "d15d5d9a4a3a41877b4ea98dbda5079ee393f6ab24105dbd70f5bf145772b15c",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "86d8c63ed4a8a19f3429b4dd57ede5ca573e861712e631400645ceee763c37cf950bdcc4d9c886ead3f0f1bf46a63bf22bd2eb39b2dac61d2e8c8f29e26045b3db56b2265adc8152d4f736c09ee90364a1e265eb5e77b0c5988c8fa52717fd33b6da760e78f2a7c27065227c47ac2134b95b7dadbf96e4ea2dad78ef200e174b",
    },
    { "HASH-DRBG", NULL, "SHA-256", 0, 0, 1024,
      "68c43a008fe46a823d260a9d7fa388fb9e401f0197e7e758a744b4babb3f4651",
      "eb6825777856331884aaf3751b3e4006",
      "23ce0d32cbf2d26467f0d62acff1a3acbaa6d2746dc3ee7aa9d32c880788afc8",
      NULL,
      NULL,
      NULL,
      "a31b9f13b58d4fa2f8d8ac42b62a207ff647339a146bd8b268b33d4aff57adbd",
      NULL,
      "d34fc6504eca4b568193c75357b0d3821a48c77ff80d6dbd21c6cf045ff489cf",
      "abb4ecbacd4e8fa943c7221aed433861c3b203232657ec4c417d021f905d911db1058ff1e11e272232482ec96bae7cb4efc135502dbe41724077077f6de79b713670c385d04644e1281c3e582e0016255abbe5f8c06d0de57160559f0c08f7fb5be3563c649966190f8d3261364447537de2c7371c6e8c308933d27145bf90ab",
    },
    { "HASH-DRBG", NULL, "SHA-512/256", 0, 0, 1024,
      "44ce0a55dd28a430bc87627f2a06a391269c4294f10d65cc674b47a12cc9d6f6",
      "c289eaa7eb8c0ec54d1a1d380f16def5",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "c294640085507dee07b3a9e14c89a9d246370314b88ad7f22f5143132f953bbef8aeeef29dac7907c5f6da5f79f5e0cf89e9d63adc9f4eea7bef098d68389e681e9ff31dff03b26d6183bbcabad590cbdece476dc0cab3e6fcf85ac7c12149640e272cf85571aa2c638165df5553519116393a3c0ee3aed718d42380201d2c35",
    },
    { "HASH-DRBG", NULL, "SHA-512/256", 0, 0, 1024,
      "7350612ad286d0ffd637cfdf7c86402e51ceafce1f246f79c24db94b4ba92360",
      "0e35c59815abc8c8662e27c87a3f6a87",
      NULL,
      NULL,
      NULL,
      NULL,
      "86a2a7faa08f5cbb52143a34ee3e66a6fb234e11ead462b94b264f25af6fcfd3",
      NULL,
      "4d748d317c3734890b77946f3dce111e7378203100de5f36e4d65cc4a85a2635",
      "9b43ff0c4fc6e82cfbd9920839a7a4f5cb0d584419621eff4fdbc64b09a29ef225c1df78b981d415782dcf03a47274a3efb35ada443a024a524634ab831f206a53c1c0c0c8c9f46d409a0b0daa62364636dbe27ee2ba8cb4cbc4b5f82f64c40dd7fce1616b0c91eea1eea657e855e6042470d5fe35bdd02133c3edf1c73d6234",
    },
    { "HASH-DRBG", NULL, "SHA-512/256", 0, 0, 1024,
      "e724ab61bd5e236354310c8e3b1c1cef587eacc99ea3411cd61e1e033c834e5d",
      "2951ffc5d08e47040572ff1ba43493c0",
      "59bfffefbc2c23df1f33f6b6dd852039daa82ef64d219ba4ff2ab243652eb9a2",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "d640ceacaf7a7fea51dcb22704cc6d93d042e4fc667189e891ce5a221b7911041240498c11a51ccfae98dbce4e7b0ee1b63db44b04f8349631dd935dd18b205a7197e4de79086902a2a85594213a95cf37cff5068b51f23bb6e99c2853ce57869d1032071459471d8a2103a620a76826749bed5428eb197176202e9bcfbb3ca2",
    },
    { "HASH-DRBG", NULL, "SHA-512/256", 0, 0, 1024,
      "f0bc27b45894b8dd8df1ede041521947680238ac91235d513dffc8edc208433d",
      "e395bf2eb1247d7a8f1bf0eb93999563",
      "30fafec33e0a81f029f5d2a49c3f2c9b64ebe5d864cf59d3a0a3f7ed23b9f6be",
      NULL,
      NULL,
      NULL,
      "a7ea8a0ce5b21697a01fb74f99823c7bea304c800b6c10053d3e7b8f63f59e10",
      NULL,
      "c8c491bd3580973fe6b7369ebb9eafbeb48cc1ad2d468c3f93672f51c12e3bd1",
      "d00e5bcbb7c9032c88564ac84b7453b07da60b189b768a24c4cf0160d6227f79f69bc62e5a7bcf551c386d3423a9cc77fd229a2b5f14d39af6dc965b77262f9d03e181552a5e2011aa7447a5e7aea97c9c56ef5b40fc4000d06a36672818e3e0ea894840ec066d1c38a1e32e2667bfe16147094f37f57da718432641f74fea56",
    },
    { "HMAC-DRBG", NULL, "SHA-1", 0, 0, 640,
      "e91b63309e93d1d08e30e8d556906875",
      "f59747c468b0d0da",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "b7928f9503a417110788f9d0c2585f8aee6fb73b220a626b3ab9825b7a9facc79723d7e1ba9255e40e65c249b6082a7bc5e3f129d3d8f69b04ed1183419d6c4f2a13b304d2c5743f41c8b0ee73225347",
    },
    { "HMAC-DRBG", NULL, "SHA-1", 0, 0, 640,
      "32c1ca125223de8de569697f92a37c67",
      "72d4cc4f0544d409",
      NULL,
      NULL,
      NULL,
      NULL,
      "9e98cc8e0f8eb84d1911c1775a5703bb",
      NULL,
      "593aa3a300e5c907a011dd5a3dcd77e2",
      "942909a9d380aa5d4e3af69093a8fa513ee545b9bf9e1b81c5f30966db3e5cb52f8b1b6fe440d592e5fe4a972c36aa498035e2442f82910c5cd095c7f4b4c7e7555c4669cca481cdfbfda167b5d6f8d5",
    },
    { "HMAC-DRBG", NULL, "SHA-1", 0, 0, 640,
      "49058e6773ed2b7ab309c0949fdf9c9e",
      "a457cb8ec0e7fd01",
      "dc477641d89c7fc4a30f1430197dd159",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "4e891f4e281100453b70788929ec743a3c5edd9b81dc798bc93771368c39b612037b6f42f60c5d8924b646848151b0c295be491d4a28d1927deed523fd04d3d2dda95ed42166312e5c3392d22893b0dc",
    },
    { "HMAC-DRBG", NULL, "SHA-1", 0, 0, 640,
      "c27f80b1d085dd15cb163f0336d07745",
      "7ecb3f32a90242f7",
      "4deb622a31b4c530348b5f08008fb7ee",
      NULL,
      NULL,
      NULL,
      "5a84f94804e2d04ead773d2a324b34d6",
      NULL,
      "226d9f4d720f580c2be44d4eaf2ec8db",
      "6db76a0a003a64dec6801dd3271fae8a43aa8ce2e0d205e3830e267072abe28d2a6f707494d15638559fa4282843760daa90eec5d2865ea11e836e60345160d5112445ab1754b578b55471a1d9caf275",
    },
    { "HMAC-DRBG", NULL, "SHA-256", 0, 0, 1024,
      "ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488",
      "659ba96c601dc69fc902940805ec0ca8",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc107694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8",
    },
    { "HMAC-DRBG", NULL, "SHA-256", 0, 0, 1024,
      "d3cc4d1acf3dde0c4bd2290d262337042dc632948223d3a2eaab87da44295fbd",
      "0109b0e729f457328aa18569a9224921",
      NULL,
      NULL,
      NULL,
      NULL,
      "3c311848183c9a212a26f27f8c6647e40375e466a0857cc39c4e47575d53f1f6",
      NULL,
      "fcb9abd19ccfbccef88c9c39bfb3dd7b1c12266c9808992e305bc3cff566e4e4",
      "9c7b758b212cd0fcecd5daa489821712e3cdea4467b560ef5ddc24ab47749a1f1ffdbbb118f4e62fcfca3371b8fbfc5b0646b83e06bfbbab5fac30ea09ea2bc76f1ea568c9be0444b2cc90517b20ca825f2d0eccd88e7175538b85d90ab390183ca6395535d34473af6b5a5b88f5a59ee7561573337ea819da0dcc3573a22974",
    },
    { "HMAC-DRBG", NULL, "SHA-256", 0, 0, 1024,
      "5cacc68165a2e2ee20812f35ec73a79dbf30fd475476ac0c44fc6174cdac2b55",
      "6f885496c1e63af620becd9e71ecb824",
      "e72dd8590d4ed5295515c35ed6199e9d211b8f069b3058caa6670b96ef1208d0",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "f1012cf543f94533df27fedfbf58e5b79a3dc517a9c402bdbfc9a0c0f721f9d53faf4aafdc4b8f7a1b580fcaa52338d4bd95f58966a243cdcd3f446ed4bc546d9f607b190dd69954450d16cd0e2d6437067d8b44d19a6af7a7cfa8794e5fbd728e8fb2f2e8db5dd4ff1aa275f35886098e80ff844886060da8b1e7137846b23b",
    },
    { "HMAC-DRBG", NULL, "SHA-256", 0, 0, 1024,
      "5d3286bc53a258a53ba781e2c4dcd79a790e43bbe0e89fb3eed39086be34174b",
      "c5422294b7318952ace7055ab7570abf",
      "2dba094d008e150d51c4135bb2f03dcde9cbf3468a12908a1b025c120c985b9d",
      NULL,
      NULL,
      NULL,
      "793a7ef8f6f0482beac542bb785c10f8b7b406a4de92667ab168ecc2cf7573c6",
      NULL,
      "2238cdb4e23d629fe0c2a83dd8d5144ce1a6229ef41dabe2a99ff722e510b530",
      "d04678198ae7e1aeb435b45291458ffde0891560748b43330eaf866b5a6385e74c6fa5a5a44bdb284d436e98d244018d6acedcdfa2e9f499d8089e4db86ae89a6ab2d19cb705e2f048f97fb597f04106a1fa6a1416ad3d859118e079a0c319eb95686f4cbcce3b5101c7a0b010ef029c4ef6d06cdfac97efb9773891688c37cf",
    },
    { "HMAC-DRBG", NULL, "SHA-512/256", 0, 0, 1024,
      "5b3f146867c87388fe04fc3d24f35626faf66baf9d8c5d0facb2aaee8bb4e466",
      "175857ea77de3cf4113001a1aad3dc23",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "5a78701c0446bf9cc04f34719e6b4a269367e250b5747b241c5ac3b70e946b918f4d9f700c9a975eb0b5ab4f72a479c8ff6098e346e9fe4b5926a41982fe1b80bd49961ef154851b49c6abe7454b0b9ee27a32c460768008922daadc9e06553cfdda852dca6565b18f5ea9a98b96dc411b2a949c61b2114dbb657948e4f76b42",
    },
    { "HMAC-DRBG", NULL, "SHA-512/256", 0, 0, 1024,
      "cdd5df69d5f412f28cbc4e7d1a3ec0aa8a9c39099d744356700dee9e12adba1e",
      "4064a9c86f77daeca18694ef44db43f5",
      NULL,
      NULL,
      NULL,
      NULL,
      "eaebfc8c4fa7314df29b550b7300e65631320bed97076ed77962f200af98bd3f",
      NULL,
      "92e763bbb3e5128ee56d67e211a459251f7d1468a6810bcfb3d2d595387b2b62",
      "6ab56be520083baac951a1b8518ccfd5aa01f0297e0260441ce1cb5498f890f01a40150896b91c227787ae8766bed29151411bc3016f1c21a783e2a32f3332495d9172aca0a443bb6e4c11ca18b1e92eb77758996b96a5e68a6d5be355921ba1993fcd2f091d5abbe1c308c5ab60dffbd1166872a905e4d415fa4077fca8cc47",
    },
    { "HMAC-DRBG", NULL, "SHA-512/256", 0, 0, 1024,
      "dd8dfec2a638c28cc592fe8251d3194fbb6e61aa616ea5e97d0f7fbdcb86373c",
      "b1374a4e92d9727022a751b8bcc161c9",
      "e08910e9bdcf94a44129e70ac8d51bae004460be9209fbc4fea6e58677c0ba0c",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "6042b14ef02ce94944d88222ab63fe31cc33f9d263507897b0c62290b0927618735364adb6c79384a40b5856f3cc97d7612ba3775844c64339922bf56e66a29666f1c2b2fb190605e90eb758c07628364ca08a11277b8d21476526201af6270ada6434ac9979b5f824387ff370c7e4b3357b589bfb4a85b4beeb005f933650dc",
    },
    { "HMAC-DRBG", NULL, "SHA-512/256", 0, 0, 1024,
      "21e70d349eab293c4f5837c3df990834507b951a8d4666570e8c7985483c391f",
      "37ed12bd119a1266d5783e1c7668f787",
      "178e4aecd4411836d2d941af0995d91f540d10204f21372ad92c5b33e0302f0b",
      NULL,
      NULL,
      NULL,
      "6e675921863c9c468cddf377318e2a5449eebf8b23e5ff18f1c7c1c72f4c1965",
      NULL,
      "122f0a17b7bde2e486f7c0f0d1d8e323bd7f2bc3e73d8213950f66e3d4e4c4be",
      "30446c874ffa0c9c031ebec131cc3927720f5eeb2d89c24a71010b93645cdb820599e91cf29bbaf7253b1f53304c28e7eaf44198ea135029455aa7fef794a275421c2f8be689af46d924e88faced5299b1e861e9c69340de5bd88d1ed912c9c54909c4d0d1bbbdf7a43d02a35ff8527042efc9102539ed3b669121bd35a0f014",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 1, 1, 512,
      "5d4041942bcf68864a4997d8171f1f9f",
      "d4f1f4ae08bcb3e1",
      NULL,
      NULL,
      NULL,
      "ef55a769b7eaf03fe082029bb32a2b9d",
      NULL,
      "8239e865c0a42e14b964b9c09de85a20",
      NULL,
      "4155320287eedcf7d484c2c2a1e2eb64b9c9ce77c87202a1ae1616c7a5cfd1c687c7a0bfcc85bda48fdd4629fd330c22d0a76076f88fc7cd04037ee06b7af602",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 1, 1, 512,
      "8e83e0eb37ea3e535e176e77bdb15390",
      "fcdcc13c9a882294",
      NULL,
      NULL,
      NULL,
      "6a85e737c8f10431984fc87367d108f8",
      "a2d938cf8b29675b65626fe8ebb30176",
      "d7a468e21274c3d9f1b705bcd4ba0458",
      "59631e818a14a8bba1b84125d07fcc43",
      "78d6a670ffd182f5a2887f6d3d8c39b1a8cb2c91ab147ebc95459f24b820ac2123db72d7128d4895f3190c43c61945fc8bac4029730003455e12ff0cc1024182",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 1, 1, 512,
      "04d949a6dce86ebbf108772b9e08ca92",
      "6516da99a259f3e8",
      "bfa49a8f7bd8b17a9dfa45ed2152b3ad",
      NULL,
      NULL,
      "387e3f6b51707b20ec53d066c30fe3b0",
      NULL,
      "e086a6aa5f722fadf7ef06b8d69c9de8",
      NULL,
      "c90aaf85897144664f250b2bded8faff525a1b325e417a101fef1e6223e92030c90dad69b49c5bf48742d5ae5e5e43ccd9fd0b934ae3d40637360f3f72820ccf",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 1, 1, 512,
      "92898f31fa1cff6d182f260643dff818",
      "c2a4d972c3b9b697",
      "ea65ee60264e7eb60e8268c4373c5c0b",
      NULL,
      NULL,
      "20728a06f86f8dd441e272b7c42ce810",
      "1a40fae3cc6c7ca0f8daba59236dad1d",
      "3db0f094f305503317863e2208f7a501",
      "9f72766cc746e5ed2e532012bc59318c",
      "5a3539870f4d22a40924ee71c96fac720ad6f08882d0832873ec3f93d8ab4523f07eac45145e939fb1d676433db6e80888f6da89087742fe1af43fc423c51f68",
    },
    { "CTR-DRBG", "AES-192-CTR", NULL, 1, 1, 512,
      "8577cbf8bdaa31a1ae5e32ea09d0bef710ea7437e67b6825",
      "3f9bdeb56b6e5d0fba56494001fe307e",
      "4b5cd497a417a2987dedf236eaffd2c315a65b761b2b68c3f4b19e4093b4c8c2",
      NULL,
      NULL,
      "31d4baaf6c27d967e8efc85479db4d012855ca680f875980",
      NULL,
      "3774912d4c79faa6d3c980a10dff18ecf6a068e683e19b1f",
      NULL,
      "a391525b20340e0f0fccf03760bb5095c27a130c6a3e134c2c10d59efec1a4a6cb753f0722a53b716985712db292b8eb8b039c11d27c1ffc709ca99f81b796c5",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 1, 1, 512,
      "16a1f035388cd8d956026e3b0117cb524dd3eb563f9a7720bb7dcb0fc6fbe743",
      "a2d015f22d854e29de278d910c573de5",
      NULL,
      NULL,
      NULL,
      "cf140bcd4d7130e7e3ea14046c56442b57c43b34ad219553e7105c18f6e561af",
      NULL,
      "e27c9f0be60d82d6cc474efb7fc737b16a6895d9a3a45b971d19b743c1a4ac8f",
      NULL,
      "b4e8395bcb7503410a94633f70e9904a5b30e62c35bc6dd2a03496c4a49932e184fbffdbcf1de1c72c50d36dc2ae8f04f40f96aae159c3fb816ca16df99b6c3e",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 1, 1, 512,
      "a31337e0cbf2ee3e8d1d39324c978e714b5acc678920d5839fe95477ca3b8741",
      "a7f8b770a506acfc79b2c431660d310f",
      NULL,
      NULL,
      NULL,
      "c2e44d8b2c97f4c14e39c8137cc62818f1a223dde1dfe9def8672c2a6fab8c04",
      "5494597f0e8644d6028495c6599911cf30fc96a1b92a3a5dc862fecfc353c43d",
      "923405e7878b3e203cb531f688c10725d7a55edacc2b9f195f7137080b278ea1",
      "e7635b6f9e63c08942c4b5c86b5e60bbe3e89ea3809fb3939985c93eedd17f8d",
      "5dbd55ed2f6d6c1749096b40f6a97d9cf42c0841b27ce0efd7433110d8118955c8cefeb9db8e1c7961eb3f517f2047d27281261760a5e2b24535bb6f565bb971",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 1, 1, 512,
      "ca58fdf2b977cb49d4e05be23950d98a6ab3c52fdf74d5858fd1ba64547bdb1e",
      "c5ea24c0fa0c90150920924232364545",
      "5a7095e98140523391537e75d6199d1ead0dc6a7de6c1fe0ea1833a87e0620e9",
      NULL,
      NULL,
      "7d20766bcfa215c82f9fbc883f80d12cb716d1809ee1c9b3881b2145efa17fce",
      NULL,
      "c89235552ad91d8e1238ac014e3818769cf2b6d413b62c77c0e7e60c474495be",
      NULL,
      "ce2fdbb6d9b7398504c5c042c231c61d9b5a59f87e0dcc627b65115510eb9e3da4fb1c6a18c074dbdde702236321d039f9a7c452843b4940722bb06c9cdbc343",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 1, 1, 512,
      "534346a3e0baa65d7a51871b6d633a6f1efa9ff55dfde3212c95029adf2387d9",
      "0cbe99821509975d824fd826c47d2abc",
      "020d7340569e68d992e6e8ddfbead9f993c74d971e4339fe91074f87e9d7d777",
      NULL,
      NULL,
      "286091709d2e91bfef6654b8449d5e5564b6c2fe1f3e4e6e59fe776461bfb0dc",
      "f41040eff2a7010287c2a76d7867a66e61299be1e1247a6b22a64b829ada8624",
      "e68e127b2e5b9d6539c26f7e78bec13314e37febdb7105d1d65f0bde23c87d38",
      "94efe68e2185646a17bb8a83268142a7b7a02786c1ee90ab8f7399ccf543de26",
      "da6389d151e3b2b332fbcc02b2cc5af4f69835e9fbbe19130f91cbf30a3c24580ebfb4311b3487e9d6a61de9dc2842c107152158b0e75a932c38e5b8ddff10e6",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 0, 1, 512,
      "f1893be2bc86c80d6422f3d586c0a8ce9bad6486f23123f02ba01403384b83fe",
      NULL,
      NULL,
      NULL,
      NULL,
      "79dde8e1502818df744e1afe8e5ecb3b8d19365182c7957260d1794e54912620",
      NULL,
      "cf684fd0eebba77901efcbe3cc5297ba9f04367fd54fe6af9463ad2ebcfedbf4",
      NULL,
      "fdb97f0eb27279b8d885f2462e8968dc4c9266f81167359d89df4c327642eae1b3131f90d64c1b5a0e71950284fc3fd026201094e8ab3f3760184d7184c90a34",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 0, 1, 512,
      "4d85ec7a58763c383548e70758c6db91f99b1466baa7d4f20ba1f8a44ec4d1f3",
      NULL,
      NULL,
      NULL,
      NULL,
      "3a9e8e7aebfed99f34b16294c1da973bd706afba105d78cb132e4d3aee221cc1",
      "dd4f1c82473fe4cc56128152001547ff7234eadea5e94f0d64b0c08d24788570",
      "e37f193e5f1356368aec70a0de2c330c3cf9af26c6aee46b9f114f6276ed38b4",
      "e90046b7fcd9d86434c312b959795fbfbe666dda2b16a7b14cb0cc1d84895273",
      "173a535a1ce52e3ca2b68fb2c24880a4dc2837174ce3df1c1f445f43013384a0570ec8d5197b2d00fef3cb3556086bd82fb6075562f3adae4dca39008bcd7397",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 0, 1, 512,
      "528ccd2d6c143800a34ad33e7f153cfaceaa2411abbaf4bfcfe9796898d0ece6",
      NULL,
      "07ca7a007b53f014d7f10461d6c97b5c8b0c502d3461d583f99efec69f121cd2",
      NULL,
      NULL,
      "478fd1eaa7ed293294d370979b0f0f1948d5a3161b12eeebf2cf6bd1bf059adf",
      NULL,
      "036bf1173977b323f60c6f0f603d9c50835b2afca8347dfb24e8f66604444951",
      NULL,
      "bba1ef50b4bad288897f02ac2706ee1e01488dcbe9b3d8a637921f5e788faed3b23db63d590ceaa7607a2179192bea9aeaa85d048e7e108fee666dc646af5f0e",
    },
    { "CTR-DRBG", "AES-128-CTR", NULL, 0, 1, 512,
      "f623911bb7efe5f6c4e969799724b317d6aa2107a356ab6a05143eee99e675b3",
      NULL,
      "19733edbc20bedc0bc269c4837a1a471377cfeb6cd60039e4944b31af73bc4c0",
      NULL,
      NULL,
      "60a809d63f6d5efeb4335b819e1d0a06b7be668765ca72f5404992a0e90b7a70",
      "0591feffa77de223d6fb1a91579f766c4c09f3e9540d14fd2ee98894f7a80053",
      "530e7a6dfa6339aaa6661bc4fb13ff1f351c79e9d3415e2d0d570b8f9907c8b4",
      "c5f7b282a516a2f831d668ca4448662c92907cbbfa9b90c3745ea2e79b28ec6d",
      "e108b1bd65928d8097190c106321e9fcb3b930ef3b74421ed8e70802d3f06ebe7338948cbf08ab91cdf71dd398ddc4752b6d3dbc265fe836588783fbddd509fb",
    },
    { "CTR-DRBG", "AES-192-CTR", NULL, 0, 1, 512,
      "eddb79f0fb5a5dd6b5e46112a7d705270ceecefdcc2e8db2721c42f3e6358683610d40d0f67092cc",
      NULL,
      NULL,
      NULL,
      NULL,
      "7e963554e90e20a6d851ba8678552d3cc4e8ad738dba17fde8b3c51f65f2c05b6b3825d8c4fa8e9c",
      NULL,
      "42ca453ebdc7e392156718a856d4fdedf324aab01156431e49edcb44d916906d789fc2e0d8d52797",
      NULL,
      "e198bfc6cc3a026a143d3560b70b69832a4d0864ac2b97134bb64876de80b085f05483e82ad4b50defd37f77be7e1a0310b71ff7df6e7fe0c22dc5a77806e094",
    },
    { "CTR-DRBG", "AES-192-CTR", NULL, 0, 1, 512,
      "6e7c6d3224b574f9d197037a7770db1f005dfc82d6fd19399d73614bb398fa0e259848ded31f19e4",
      NULL,
      "d0a67c39d4ee83208d40debebf38332b0c09b6683a5070dfd91bdfb0aa7c60af4dc36b18926189c6",
      NULL,
      NULL,
      "b481b84b2ab1c542e5828b3db7067729516bb2eaf6f93f65538102935cd4fd2d3675bab00980a217",
      NULL,
      "9ad8c9710fbecb0ca91f0c1f07cbea29efa6753a2f39b57c9d10dc13eb2d8c39846712167b13c42e",
      NULL,
      "ce788ccd16c5c21f91d26556b7fcb0aa644a0d2692ab3cd9e8a50860d402e6b9b8c824fe38c4c150a2ce97b939b6b633cd48991e152b8134462ea3f039b11c0b",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 0, 1, 512,
      "faf346c9c8afbc5ab6e33ce492247fac6db9a7ba4297557f587a42563ddf56c90e41c6afb56233815b74e091bac7d8e5",
      NULL,
      NULL,
      NULL,
      NULL,
      "dfc111252d7146922713720ae1e348a07ae403b5238fefb4e8592f6f6cc4a61c94828db84c6faecd1502261008011f2c",
      NULL,
      "4528bac5b99c772347d44f4ece79bc811ca8ebea9483fa5f5040c02f77069dad1aec7adaa8a9a6a9ddabab045d328a90",
      NULL,
      "bc013dc891db12c34ad11944805bf13dfd67ff2c23176d83f5b396b69e400042252e11816c3095421137181a5d0ee37c83a339c58d080946ca90aa437d50d9cf",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 0, 1, 512,
      "c519cd4f839c9a5e936485242c4da847f47af5b544acd12b49036453655de3ed57b2ae015822a60edcfb859b00bbef2e",
      NULL,
      NULL,
      NULL,
      NULL,
      "0415f8fd00d4d2454706142083346304d8051b8259d08de493d991d366a42fd452d6533346896d323ba1066a485ef105",
      "7e95d809c11a7a975230da9599d0073136bd057a1a6990f980894c01912bc39b8dac94c083933d39278f65542dd8dd4e",
      "9a146501a4dc9349b0392897263cfa414b6fc7e59d7093ab66bd265b7e41b5c2766f56d97b7d22d02220cbc389b34a6f",
      "188357a4c4dbdd05cb6bc5d9160d5d951cef6ed9ab6c622b5a9cda2c761d9278235fbe9d6312b9d892a59abb7f3f4865",
      "cb79c79dd19a72b303a2568266abf23ad6e341cfcfee8a768af64584e4e471dedc0d832a04e8dcf4b896ad9bf4a4a2495cc6f3efd22a68938424717dd75e83b0",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 0, 1, 512,
      "c8f0c7b9bdf7e7d524c998aedeabb3b7dd4fa8f95c51b582010a5e09d0b4b1ad510302422df738fbef002a051543b4cc",
      NULL,
      "3b8f2ed03e4c4a857ebaf4730124ae5b3ffa67e294381fe085e1d5b25bb79c228f39b9912d8bf9e84cdb43fcefb552e0",
      NULL,
      NULL,
      "c1a7b160c8e33a01fbd49743dc1161539390d9ba6b876fe63b58e8fd605b98617322578b17aca9db71e858b154f97910",
      NULL,
      "d98b25eda41d15eacdecba586609d8c743704fa099ac37f9185bcb19652723d1648431a73c4399773c85caf12fcdd842",
      NULL,
      "338da59350a72bba94b217b99ff813fafa85f31fa7e991d4350d6fce39471aa249c6a9e7d189649ea6770a15be302b943ad403728b7387f5984c9bfb82597771",
    },
    { "CTR-DRBG", "AES-256-CTR", NULL, 0, 1, 512,
      "c54805274bde00aa5289e0513579019707666d2fa7a1c8908865891c87c0c652335a4d3cc415bc30742b164647f8820f",
      NULL,
      "d63fb5afa2101fa4b8a6c3b89d9c250ac728fc1ddad0e7585b5d54728ed20c2f940e89155596e3b963635b6d6088164b",
      NULL,
      NULL,
      "b2ad31d1f20dcf30dd526ec9156c07f270216bdb59197325bab180675929888ab699c54fb21819b7d921d6346bff2f7f",
      "744bfae3c23a5cc9a3b373b6c50795068d35eb8a339746ac810d16f864e880061082edf9d2687c211960aa83400f85f9",
      "eca449048d26fd38f8ca435237dce66eadec7069ee5dd0b70084b819a711c0820a7556bbd0ae20f06e5169278b593b71",
      "ad55c682962aa4fe9ebc227c9402e79b0aa7874844d33eaee7e2d15baf81d9d33936e4d93f28ad109657b512aee115a5",
      "f08fdfc1775b6feb5a4177110bf29d7c3ab715dfdc4b27200359288c0624bd5c1028acc9914d88a82b09f5eaafdc3bca8547b98481df39b86504314221cbdc3c",
    },
    { "HASH-DRBG", NULL, "SHA-1", 0, 1, 640,
      "212956390783381dbfc6362dd0da9a09",
      "5280987fc5e27a49",
      NULL,
      NULL,
      NULL,
      "2edb396eeb8960f77943c2a59075a786",
      NULL,
      "30b565b63a5012676940d3ef17d9e996",
      NULL,
      "ca50ec95c7c38a58129fd37523d1f2598ce6de98a6f107724c5546beadaa5bafbf1e62d274843f1107c345b1288163f1dd24afb27a63d39ee2aa770dfca668eb134abe080578b2f8d1a3a899f5a00af7",
    },
    { "HASH-DRBG", NULL, "SHA-1", 0, 1, 640,
      "fec1235d115354e198b340fcf18bf911",
      "937c5499ffe04d10",
      NULL,
      NULL,
      NULL,
      "3e33f5bf1c0495746048194eb198e1c6",
      "fe52ccba22469414564ed59ec87d26d3",
      "44e1caa5ed987020f851417c3eaf4a65",
      "61bb236cae59ccfadbc1b8558913ade2",
      "55ae31bddc4a74013e5c420b16f94f4e7683b4f4203cdd641d6e5a0f2216f35faeaab405d71e76eb920c7be3d8736d70d015e942b1fdc73730c5cf8ac4bc6ddd20e65ef2e4bedf5a60e9e755ace29fd7",
    },
    { "HASH-DRBG", NULL, "SHA-1", 0, 1, 640,
      "4652da57429a76d6fe9e0e1fbb2f3ccd",
      "5044e6ab2b552066",
      "96f187867c057ae982e03a056bbf0f48",
      NULL,
      NULL,
      "ca890d8453821c32c4ede3d3902b1306",
      NULL,
      "099a2a45526029fcdd2da74f638500a9",
      NULL,
      "684cc1695b5a4b5d50d74290528ad55622598618eb8edaf141e41a8906f3bf940173383688a861ddcc564ede0efc3eeb3b01897f738523a5fac99852c435bfed58eb4a6fd7d0d5669a6aafbdc8d4fff9",
    },
    { "HASH-DRBG", NULL, "SHA-1", 0, 1, 640,
      "8b769915917bbf4e4b48f26639306152",
      "17ea14e8ad5446aa",
      "9994ed56b1355a6d603e366a8f9c04a9",
      NULL,
      NULL,
      "36391d0d897510aa844c9920488d49f2",
      "1b8c8b88d7ce96eb7abd03b5551ce99d",
      "74c7b54e9fdc824fc8e0463673ef92bc",
      "fab6fc0acb22983865c3836253718f31",
      "1f07772a46662b3750e39b3191fa74c8354f9d7eaea56ba0d29272d071ef6da2411cd05b64762e27a736b088d92dad4f222efa3e3ca2bee0d5f1401d7ef53e3842132181511a5159bc8ea3a6db1215ab",
    },
    { "HASH-DRBG", NULL, "SHA-256", 0, 1, 1024,
      "4a4e743f877ea6e94e545a56ccb5a1f99efc7eb1e8191929152a56d41dc92425",
      "33b7ab9356acf7da03d3d6773b61f8d9",
      NULL,
      NULL,
      NULL,
      "2e148f9269d00a162e897a91f3aca46fed1e2adbab4f848218f288650dab8b1e",
      NULL,
      "2566475353ec8ced47d03b76fca779d0668c95136cf7866259d9e3b7e0d1f74f",
      NULL,
      "924b74d6ba3d56dffc0de00711e3010ccbdb730718743f0cc0631931434b0ffc4ad6d5ef96fd81f16e51a10206f674987d1b52f0cf15d294c98bc4a877f4716c0ff2c2484d3f057eafd09154874aa2a213a2641da1a3d7be6988616b6bb483cd9213ed750858ce85811b8f708dcfd607b383eda845c87f60084db7a0500643b1",
    },
    { "HASH-DRBG", NULL, "SHA-256", 0, 1, 1024,
      "e6cb69220ef01bb23f8879a508be049ec7e8dacb898e2ddb75cef6bcc5a84a3f",
      "4429e3d890f2b6ef9a36f21286e9c885",
      NULL,
      NULL,
      NULL,
      "aaecb8f54221c7176e2dd941625bf84eb79e9c53c8d1a5569a33dcb4c198e627",
      "46f518eabcf170eae6ab571432269e874dff27a66f2c2f792a695b4f68678e3c",
      "c72ef4489b151dbd6e8214887d3ddc48043e21a4ede40fe6f1ecbcd5f5641be5",
      "0aabce2b5bafc3314db0605d85b80edf9561a0e2e8d4e408d53f551cea6a558b",
      "8a5b386266528ee2d5e197f636748ea878508a1a0b805473f44cc60f8bddfc57387dc958ac51b3fabf077b8939d21c9424a663c5b0873c7977ca2ce447699a9e39e1ba5e51c6619127e9f18bb6abc2d1831d95bf34f4f81da6c79eda485944b4f7043e4639f6bc8855c1c017cbed40e3bca2eac4c45ebfc69f7a8189e76f51c7",
    },
    { "HASH-DRBG", NULL, "SHA-256", 0, 1, 1024,
      "5314e6405ceb2b26b4034502aea394850570650ab622c41090d0c15414a5a7e0",
      "1ac01cf36c44bf789e53a0d6456d12ce",
      "8f09e95ad10aa3c2d3f8468e70ecfa373a3461de7a5002bd837d35a607dcfc30",
      NULL,
      NULL,
      "7dac9bba1000dde15e3d9099e1d7824b54d8e6241be478435aad647539c72d58",
      NULL,
      "722ed3424e3b586ddea0d37b6318ecd549667086b5e63e35ff85a734c4666b31",
      NULL,
      "c90b12cba054c272e05686ce79b48fbab4059db8311f9b39ad7e5e4f72b586354cceeb3adec29508396aeeb66cba471f208f28f49306c9501e1fcf221b1a05ded54a64cef14b617f9fb476a370984308f62ab586b11b58b5a95aadca1de8c92c1ed9ae5894fe7ed4ccd9887d666382cbcf7535c78e5cecbb0b1b97b43f59b97d",
    },
    { "HASH-DRBG", NULL, "SHA-256", 0, 1, 1024,
      "29e1a42709b7e84dbe50788fbad8cb609c127eec3262636a513fd9059fb8bae4",
      "f3a521f28dffbd97574c405b69b636ad",
      "c99a1147d8db401f4fcf763867296758e26404a30a4a9fa496a717f21f5d749b",
      NULL,
      NULL,
      "d5266c01e10d72dd7e8a3bf717cccb8f643ca233314e3e74f106f46b090e5c73",
      "17254ea392aead0dc94992d867813497d3fd6dc7669667150afe6c28a2b89946",
      "c7e5f03d26bdf9553338e64ba64ce5b5751b04f9c69992221495f2227b9799d0",
      "157dde59ceb2c662c8665fbe623ec75873fd0c5ccce79a9f5b7098ec8ed77b67",
      "e304de9ffd885cf917ead78f05939b8cf54709fc2d0c799a98b543486337204477b1060bceae2a22f7ff42b6cb4b4bc0610ae2b67558a7c54b65e45bb9f1a86981b74705b48cdbf7d8decf87868267bd948e9394aa4357f8dbbf30612a0eb5b131884c220e442d36778e8d74091d8a27c070fe690469e07f3aabeef7c629bfab",
    },
    { "HASH-DRBG", NULL, "SHA-512/256", 0, 1, 1024,
      "2ba723efc4a13a52e8fe06537482d78758af2300c411f9083817bccc49056e85",
      "84e7909dcb143410a34285170553649a",
      NULL,
      NULL,
      NULL,
      "5cb0008d9a4cd9ba6dacd5e272c350e9098d5b87019d8889a3c3b99c5db8e731",
      NULL,
      "8d2a6d181c802711fc1ba84a95ac35cf5ce0d1a850c729ab317427ff44693437",
      NULL,
      "ed34cd3977ac1ac646d9e03b2e0ed8d301ae602a6361d88c7107d480662af4c3c35398eb2c2cccefc6ef0058f4dab5d204ade3fe40a77bde57a656bb8bbce862622db5fb561e134bfd114094677ec73778e61fab315089919cc663bce70044f1e835abd513a3e0ff964544fa541d88bedf638bffcd3608971849fc83a0d9707b",
    },
    { "HASH-DRBG", NULL, "SHA-512/256", 0, 1, 1024,
      "c4bef9b07a7142187727217a1a0aac46d458a7228e3a1efe81dde68effcefa73",
      "5c6da6d6372ef2333b1c297a3d64ad6b",
      NULL,
      NULL,
      NULL,
      "9b1cae17a33aa16f937d3be7e6282fed3279c69eb630bd217fd2ae471b2cf938",
      "eb3dea2791961932bd49d1d60c8d48437051f133390aaf7c766512f4de1ae773",
      "65d0c91d6818b9380354ae651fbc8a18ea3c4e1b92808d79fbab9c7fd2982850",
      "82b127e81a85faa555f9773af25fdf51ff02acf4e3f0c9e73677e6c02f24b5ed",
      "de85330a80b2fe63067478d72f8027de01bf494823785f751a593f2c18ce4bc6722e32d779ae5f5581f85bb671c011b537f46becb79678cf7e7b075bf1140a83218de5a63df3fce2d0265b2fcfca6904492e70ffd826543cde6cf3c95558cd9cea6c9a88340f46b306668160d5a2e0c8fde5ba28943c3fc0f5bc8030c138afcf",
    },
    { "HASH-DRBG", NULL, "SHA-512/256", 0, 1, 1024,
      "3cc10ddb2c937d4c1acd2d79bb4c64ecee66be277404fc168706c2216eb819b0",
      "15ea3424a8caffe35f93dcebc51a03c6",
      "8d883b1989724ca9c10a5db8044289443a6d9bd78bd3ddb85326ed491d7c0eda",
      NULL,
      NULL,
      "8666e3aecef949ef639b3ebe5771bc389dc2833fab5d8cbff4b9ae6360144dfa",
      NULL,
      "9ce5c40bfa3efa3f5735f0999343c675922daab5c60f61bf4e349fd84f119aac",
      NULL,
      "3d7475e1045ff4279f29d4cfe5d5de72e098564783ac79f6769008dd13cef8a87d325363389557cd37adae75f377d4bd1e3847f97993e460439d298f4e32a656b8c7d8b04ac7d0a890eb8b9f208fc7dedaff0597215ef6459fd0be80e702868287c398a56550e213aea063665d7c632787368540f94c832223123e6b7e4e4957",
    },
    { "HASH-DRBG", NULL, "SHA-512/256", 0, 1, 1024,
      "1b9375777a03adbb7fe60a2f3a5aeb41e7297d5d1f6d384bfe826f0375ab1fc3",
      "44ae3d66a65c8c9ff927e06768f53287",
      "b2429a36cb2cdb6f0b2f331859eac7e9fc2eea4261f6caccfd74e72b875f2464",
      NULL,
      NULL,
      "e8898a7c1e79ea36a942a9b81bbe2799ee403aba4a813e03311b70dbb99f86ee",
      "28d011978b56e937594120afe6a8c1ddc28489c32a2bf99c1036111c33851cd9",
      "e366eab19612a73dc20f96bf0c96092b254b84d4a24785093d5a1da10973249a",
      "86f269148bb96d7e074c86a739f6bc79903b8117fb5b9010e86ac6d8aac29bbf",
      "d5582ccaa9e460ff28aeb514d89f48009b45f56b670be3bd04f0bdf1f2239f9c56a2879ecc162b5c2b2ebeed1eca20908f228a7e75edf72230a890e514505295423fa7bb75c550ebfcf024e259a233520738931872d434590054941ff0b51e9dfc04b8172f54da213b75612bd84cd166cc5d7277ca79fff686117f7bcf40718b",
    },
    { "HMAC-DRBG", NULL, "SHA-1", 0, 1, 640,
      "a0c9ab58f1e2e5a4de3ebd4ff73e9c5b",
      "64efd8ca028cf811",
      NULL,
      NULL,
      NULL,
      "48a584fe69ab5aee42aa4d42176099d4",
      NULL,
      "5e1397dc404d86a37bf55954756951e4",
      NULL,
      "9a00a2d00ed59bfe31ecb1399b608148d1969d250d3c1e94101098129325cab8fccc2d54731970c0107aa4892519955e4bc6001d7f4e6a2bf8a301ab46055c09a67188f1a740eef3e15c029b44af0344",
    },
    { "HMAC-DRBG", NULL, "SHA-1", 0, 1, 640,
      "d92b39ff610db66427613c111c002b75",
      "329734372847a88f",
      NULL,
      NULL,
      NULL,
      "53c1d289b30d3584d34efb884ce6d1d7",
      "9980d97c65cc8b3c61b390e48abc6523",
      "174a3c20508ca0171ed9610622d454fd",
      "76213356e359e94984cfa7db15220518",
      "e0b298f7cd1112527a506201e38f7e60d762f591603db72aca3a2cd1b9d115c3ddbc7dcb7643f2f40f53e96e6ca1590ca27abb77a6234754ff1edef86f75fd5f298872ad1544fb88a62936e238f22aef",
    },
    { "HMAC-DRBG", NULL, "SHA-1", 0, 1, 640,
      "db8128c27eaf3a39d5019785aa35b20c",
      "3977437fd75e8032",
      "4f8060506daf40819c7c58630151edc7",
      NULL,
      NULL,
      "ed340ddbe1b29eb9bedb3048a3fdd06a",
      NULL,
      "a957c5cff00eb87549c307400d4059d0",
      NULL,
      "4ac933b7de803c266461493a19dbb00e9db25ee768165781fc9a70c67c4e8a92db36471e3cb1714fbb65e17d74770061b0abae52be34a604d87e56a4ae1e90c6533cc764aa7419b5439e3efa193934bb",
    },
    { "HMAC-DRBG", NULL, "SHA-1", 0, 1, 640,
      "680face90d7bca21d4a0edb7799ee5d8",
      "b7be9eeddd0e3b4b",
      "f58c40ae70f7a55648a931a0a9313dd7",
      NULL,
      NULL,
      "7cafe231630aa95a742c4e5f5f22c6a4",
      "dc3663f062789cd15cbb20c3c18cd9d7",
      "1c0d7792898827948a589f822d1af7a6",
      "fe85b0ab14c696e69c24e7b5a137120c",
      "68004b3a28f7f01cf9e9b5712079ef80871b08b9a91bcd2b9f094da48480b34cafd5596b0c0a48e148dabc6f77b8ffaf187028e104137a4feb1c72b0c44fe8b1afaba5bcfd8667f2f55b4606632e3cbc",
    },
    { "HMAC-DRBG", NULL, "SHA-256", 0, 1, 1024,
      "9969e54b4703ff31785b879a7e5c0eae0d3e309559e9fe96b0676d49d591ea4d",
      "07d20d46d064757d3023cac2376127ab",
      NULL,
      NULL,
      NULL,
      "c60f2999100f738c10f74792676a3fc4a262d13721798046e29a295181569f54",
      NULL,
      "c11d4524c9071bd3096015fcf7bc24a607f22fa065c937658a2a77a8699089f4",
      NULL,
      "abc015856094803a938dffd20da94843870ef935b82cfec17706b8f551b8385044235dd44b599f94b39be78dd476e0cf11309c995a7334e0a78b37bc9586235086fa3b637ba91cf8fb65efa22a589c137531aa7b2d4e2607aac27292b01c698e6e01ae679eb87c01a89c7422d4372d6d754ababb4bf896fcb1cd09d692d0283f",
    },
    { "HMAC-DRBG", NULL, "SHA-256", 0, 1, 1024,
      "2cad88b2b6a06e703de46185ccb2ddcf5e0ee030995ebdf95cc4fbc38441f17f",
      "32310770e04172c0cf91f6590cce44a4",
      NULL,
      NULL,
      NULL,
      "448bfbc5ce9e3b9da3e9642daecd994dfe373e75253e8eb585141224eca7ad7b",
      "ef6da5e6530e0d621749ab192e06327e995c3ac0c3963ab8c8cd2df2839ab5df",
      "afb57f69799c0b892b3015990e133698d543aa87829ace868e4a5e9525d62357",
      "44278b31ed853f0a510bd14650ac4b4971d8b426799a43511d016be68dedbb8d",
      "4c7dfbe509dc5a3ac26998723c6a44cad20b197fc86117c778d1568ab828923862885e97198f77a1cb45113f5d78726a0f120aec94afc45f57c8dcc1cb092b343480012858ef5bc559f57023442209326ec4a54d91ca3a77dfdf9e75f117cef50e6fd2dc9af6ddce8e6515b4a97357a97b6cd274f68a042fa41bbd7b7261b034",
    },
    { "HMAC-DRBG", NULL, "SHA-256", 0, 1, 1024,
      "f7b90c797a4a376cdd9f5c435f5985e77f36ec1df1145a12072cbb2a0da378fc",
      "d95202986d45896e9f4a65f2f353fa35",
      "61535c5c045e784267fd0d85f2861778fa53c8e8586af67cf5c9f21a28ebb656",
      NULL,
      NULL,
      "130ab64f41a5d49d6a241e0260b4bb8a46a16c6ac9e234c84b5b26cdb518d459",
      NULL,
      "f7670e817ac061ac60439be60982492000dc5da8bc6636bdac8b1cab03198dfd",
      NULL,
      "8df4e349f9ea43cc509ecb2b1124358cda2de1f5cc9315edca63610a413478d68b8bb49c2814c82ce571f6e0a6780fa21c4b570610ee0c04d3edb92124f580f962d741330200c19885ca716502223247b728d66fbbeb7c6cc25cfe9866b1450b346227c7663074c8b15d189f1c6edba172a53c733d67c1c69bd7aca7e62013cd",
    },
    { "HMAC-DRBG", NULL, "SHA-256", 0, 1, 1024,
      "4294671d493dc085b5184607d7de2ff2b6aceb734a1b026f6cfee7c5a90f03da",
      "d071544e599235d5eb38b64b551d2a6e",
      "63bc769ae1d95a98bde870e4db7776297041d37c8a5c688d4e024b78d83f4d78",
      NULL,
      NULL,
      "db9b4790b62336fbb9a684b82947065393eeef8f57bd2477141ad17e776dac34",
      "28848becd3f47696f124f4b14853a456156f69be583a7d4682cff8d44b39e1d3",
      "4a9abe80f6f522f29878bedf8245b27940a76471006fb4a4110beb4decb6c341",
      "8bfce0b7132661c3cd78175d83926f643e36f7608eec2c5dac3ddcbacc8c2182",
      "e580dc969194b2b18a97478aef9d1a72390aff14562747bf080d741527a6655ce7fc135325b457483a9f9c70f91165a811cf4524b50d51199a0df3bd60d12abac27d0bf6618e6b114e05420352e23f3603dfe8a225dc19b3d1fff1dc245dc6b1df24c741744bec3f9437dbbf222df84881a457a589e7815ef132f686b760f012",
    },
    { "HMAC-DRBG", NULL, "SHA-512/256", 0, 1, 1024,
      "bceb3e2b96e3cfebfdc65baf3ad3d33183f2fc5f634212c9951afb098fb6491b",
      "f195010065dc299f08aaf22d25cabf39",
      NULL,
      NULL,
      NULL,
      "f89d46b0587c441238131c569f0b3441ede3ff8f36e1e656e976d8c79e231888",
      NULL,
      "89d638eaa7c29052b73afbcb1228e2747850da2e87c5440ee7ef35ced9d0d835",
      NULL,
      "f3538461534087d3ef13c3ace2fdaddaf73352b52f8ca22a6d8eca9bbd0aa4c5cd522f063e5e54d40adf10d4442a6afd9ece7322248c156dcf0b4d8421581ad9189a08e246b1ed592f4bc668c68dbf6a9537e273c1503141b44f30e00137ceb6fa4d81ca20b9a3608895ce088d9a8ca2b2842f1996ae9227f8c4edc58f97897b",
    },
    { "HMAC-DRBG", NULL, "SHA-512/256", 0, 1, 1024,
      "9537d18c1ee448757e29db5344903a58e73e7558f3511c2dbdcf9433bbad6263",
      "a185925d718f156dde2d557c78a55507",
      NULL,
      NULL,
      NULL,
      "86b1bc17ed6e9e213524614b2850052b4c6f7ebe30159cc4b81aa193a255b9b2",
      "5ac15db7605e7a2346520ff5627962f970ede8efa3fa7639884d56ad4db2ce29",
      "7bfb4bb691e61bb93becf00265c867723a7603decfa49d3d2e23fadcb2c98721",
      "90fe8db2d13c3ed7fe0a6e1ccf0fceefb032ddc9174fd294e206a0a12412f5db",
      "3855acee3404e56549edee4be084cd58372a7d82e1e116341090b4c32e77aa417a35b861a735aabf242e8acf2ffdf67c4ee06b1048afaf933497df9c3ea1aab2f789a3a8e8e54e743f4f1a62bfe4060a6ac0f9a9fcae95c751b77b31aec22c59eccac42cd2153145d57fbd7d2bf88fba8da32b575bc66803043a7a309d7c8f48",
    },
    { "HMAC-DRBG", NULL, "SHA-512/256", 0, 1, 1024,
      "850f9e31805c8a62d7fb6fe416d99d7018fdbc03418cc288f57d228e52a07d2c",
      "61140916e1351220e703d7089f1389bb",
      "569fc1a13483136e350e865d6b291d70eb8895d42fe6b4af564b7aae8628ef08",
      NULL,
      NULL,
      "e9484250991414673395a9c700177e51252d4316fd79e25613b6a681fecce48c",
      NULL,
      "e7255e59bab76bb37c21f997f49eaa9d400644b5b52a33eb521d623300125e00",
      NULL,
      "1b95d3b9bf38758830deb226be160c715a6e8980a13db56c35a7d8367ff1d7120e538fa109725231d33196a0c856468bb8c03f350a322b0664a65df284f247c5640f03056b9dc25a7636e4354fd16418211a7e1de623e5452faca17236469cff90428bd39a994aab4d09b68864e3fd001ae6057635b2c9b0a91acdc3598e9457",
    },
    { "HMAC-DRBG", NULL, "SHA-512/256", 0, 1, 1024,
      "8fba04662d11203823179e5e92daa25e58a3d179c014dfe23033dd5d45b03116",
      "1f41802eafe1023796b4d0ea8ee1624a",
      "0de0ace1f5fdb878b6407ecb9bbd85ba2bcac4dda8d9bb4705275ee74a0972d2",
      NULL,
      NULL,
      "ee46249955835a0a4979cf320e12d8ca3b092ce7262b6517a67aca1a95c52c99",
      "bd2c057997cfb7437daf88c72ab1913aa7dde606ec1e1c66d465353d3eb7ae93",
      "7a6988c887886d5bd54f5170c63a94416b9e1e1b07c566e713f97ae9149f92cb",
      "6bcbed4ac1cc5009268e18b5500ea82f821c5debcd35a3672daf594db0a840e4",
      "5eb5f2aa880ef9c00193fa27a093dd4683547111f05f92ef090dafec280b8cc10d873748c1d303ef3eefbb8d54601649a91aa8f100770d1ca37a53b42409d0151c4f8b45c2f402ab9d7e8b705278927b0ff01079fbdf3b2d1fc25e0c43685e965cedb3994d8b14ed7e4b6a2be89ea81888742351608163375ed89477c61a2e3d",
    },
    { "HASH-DRBG", NULL, "SHA2-224", 0, 0, 16,
      "c3ef82ce241f02e4298b118ca4f1622515e32abbae6b7433",
      "15e32abbae6b7433",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "5af6",
    },
    { "HMAC-DRBG", NULL, "SHA2-384", 0, 0, 16,
      "32c1ca125223de8de569697f92a37c6732c1ca125223de8de569697f92a37c67",
      "15e32abbae6b7433",
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      "ee9f",
    },
};

/* evp_test's rand_test_run for one case. */
static int run_kat(const struct kat *k)
{
    unsigned char ent[512], non[512], pers[512], buf[512], addin[512], want[512], got[512];
    unsigned int strength = 256;
    EVP_RAND_CTX *parent, *ctx = NULL;
    OSSL_PARAM params[5], *p;
    size_t got_len = (size_t)k->bits / 8, n;
    int use_df = k->use_df, ok = 0;

    parent = rand_ctx("TEST-RAND", NULL);
    params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_RAND_CTX_set_params(parent, params) || (ctx = rand_ctx(k->rand, parent)) == NULL)
        goto end;
    p = params;
    *p++ = OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_USE_DF, &use_df);
    if (k->cipher != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, (char *)k->cipher, 0);
    if (k->digest != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, (char *)k->digest, 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC, "HMAC", 0);
    *p = OSSL_PARAM_construct_end();
    if (!EVP_RAND_CTX_set_params(ctx, params))
        goto end;
    strength = EVP_RAND_get_strength(ctx);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, ent, unhex(k->entropy, ent));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE, non, unhex(k->nonce, non));
    params[2] = OSSL_PARAM_construct_end();
    if (!EVP_RAND_instantiate(parent, strength, 0, NULL, 0, params))
        goto end;
    n = unhex(k->pers, pers);
    if (!EVP_RAND_instantiate(ctx, strength, k->pr, pers, n, NULL))
        goto end;
    if (k->reseed_entropy != NULL) {
        if (!set_test_entropy(parent, k->reseed_entropy))
            goto end;
        n = unhex(k->reseed_addin, addin);
        if (!EVP_RAND_reseed(ctx, k->pr, NULL, 0, k->reseed_addin != NULL ? addin : NULL, n))
            goto end;
    }
    if (k->pr_entropy_a != NULL && !set_test_entropy(parent, k->pr_entropy_a))
        goto end;
    n = unhex(k->addin_a, addin);
    if (!EVP_RAND_generate(ctx, got, got_len, strength, k->pr, k->addin_a != NULL ? addin : NULL, n))
        goto end;
    if (k->pr_entropy_b != NULL && !set_test_entropy(parent, k->pr_entropy_b))
        goto end;
    n = unhex(k->addin_b, buf);
    if (!EVP_RAND_generate(ctx, got, got_len, strength, k->pr, k->addin_b != NULL ? buf : NULL, n))
        goto end;
    ok = unhex(k->output, want) == got_len && memcmp(got, want, got_len) == 0
         && EVP_RAND_uninstantiate(ctx) == 1 && EVP_RAND_uninstantiate(parent) == 1
         && EVP_RAND_verify_zeroization(ctx) == 1
         && EVP_RAND_get_state(ctx) == EVP_RAND_STATE_UNINITIALISED;
end:
    if (!ok)
        errors();
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_CTX_free(parent);
    return ok;
}

static void known_answers(void)
{
    size_t i;
    char what[128];

    for (i = 0; i < sizeof(kats) / sizeof(kats[0]); i++) {
        const struct kat *k = &kats[i];

        snprintf(what, sizeof(what), "%s %s df=%d pr=%d%s%s%s", k->rand,
                 k->cipher != NULL ? k->cipher : k->digest, k->use_df, k->pr,
                 k->pers != NULL ? " pers" : "", k->addin_a != NULL ? " addin" : "",
                 k->reseed_entropy != NULL ? " reseed" : "");
        check(run_kat(k), what);
    }
}

/* ---------------------------------------------------------------------------------------- */

static void count_cb(EVP_RAND *rand, void *arg)
{
    static const char *names[] = { "CTR-DRBG", "HASH-DRBG", "HMAC-DRBG", "SEED-SRC", "TEST-RAND" };
    size_t i;

    for (i = 0; i < 5; i++)
        if (EVP_RAND_is_a(rand, names[i]))
            ((int *)arg)[i]++;
}

static void methods(void)
{
    int counts[5] = { 0 };

    static const char *names[] = { "CTR-DRBG", "HASH-DRBG", "HMAC-DRBG", "SEED-SRC", "TEST-RAND",
                                   "ctr-drbg", NULL };
    const char **n;
    EVP_RAND *rand;

    for (n = names; *n != NULL; n++) {
        EVP_RAND_CTX *ctx;

        rand = EVP_RAND_fetch(NULL, *n, NULL);
        check(rand != NULL, *n);
        if (rand == NULL)
            continue;
        printf("  %s:", EVP_RAND_get0_name(rand));
        EVP_RAND_names_do_all(rand, name_cb, NULL);
        printf(" provider %s is_a %d/%d description %s\n",
               OSSL_PROVIDER_get0_name(EVP_RAND_get0_provider(rand)), EVP_RAND_is_a(rand, *n),
               EVP_RAND_is_a(rand, "SHA256"),
               EVP_RAND_get0_description(rand) != NULL ? EVP_RAND_get0_description(rand) : "(none)");
        list("gettable", EVP_RAND_gettable_params(rand));
        list("gettable ctx", EVP_RAND_gettable_ctx_params(rand));
        list("settable ctx", EVP_RAND_settable_ctx_params(rand));
        ctx = EVP_RAND_CTX_new(rand, NULL);
        check(ctx != NULL && EVP_RAND_CTX_get0_rand(ctx) == rand, "a context");
        printf("  state %d strength %u\n", EVP_RAND_get_state(ctx), EVP_RAND_get_strength(ctx));
        list("ctx gettable", EVP_RAND_CTX_gettable_params(ctx));
        list("ctx settable", EVP_RAND_CTX_settable_params(ctx));
        printf("  get_params %d locking %d up_ref %d\n", EVP_RAND_get_params(rand, NULL),
               EVP_RAND_enable_locking(ctx), EVP_RAND_CTX_up_ref(ctx));
        EVP_RAND_CTX_free(ctx);
        EVP_RAND_CTX_free(ctx);
        EVP_RAND_free(rand);
        errors();
    }
    EVP_RAND_do_all_provided(NULL, count_cb, counts);
    check(counts[0] == 1 && counts[1] == 1 && counts[2] == 1 && counts[3] == 1 && counts[4] == 1,
          "each provided once");
    rand = EVP_RAND_fetch(NULL, "NO-SUCH-RAND", NULL);
    check(rand == NULL, "an unknown name");
    codes();
    rand = EVP_RAND_fetch(NULL, "SEED-SRC", "provider=base");
    check(rand == NULL, "the base provider isn't loaded");
    codes();
    {
        OSSL_PROVIDER *base = OSSL_PROVIDER_load(NULL, "base");

        rand = EVP_RAND_fetch(NULL, "SEED-SRC", "provider=base");
        check(rand != NULL, "the base provider's seed source");
        printf("  provider %s\n", OSSL_PROVIDER_get0_name(EVP_RAND_get0_provider(rand)));
        EVP_RAND_free(rand);
        OSSL_PROVIDER_unload(base);
    }
}

static void nulls(void)
{
    unsigned char out[8];

    check(EVP_RAND_up_ref(NULL) == 1, "up_ref of NULL");
    EVP_RAND_free(NULL);
    EVP_RAND_CTX_free(NULL);
    check(EVP_RAND_is_a(NULL, "CTR-DRBG") == 0, "is_a of NULL");
    check(EVP_RAND_CTX_new(NULL, NULL) == NULL, "a context of NULL");
    errors();
    check(EVP_RAND_nonce(NULL, out, 8) == 0, "a nonce of NULL");
    errors();
}

/* ---------------------------------------------------------------------------------------- */

static void test_rand_itself(void)
{
    EVP_RAND_CTX *t = test_rand(128, "000102030405060708090a0b0c0d0e0f1011", "a0a1a2a3");
    unsigned char out[64];
    unsigned int gen = 1, max_request = 0, strength = 0;
    size_t max = 3;
    int state = -1;
    OSSL_PARAM params[5];

    check(EVP_RAND_generate(t, out, 4, 0, 0, NULL, 0) == 1, "TEST-RAND generates before instantiating");
    hex("first", out, 4);
    check(EVP_RAND_generate(t, out, 4, 129, 0, NULL, 0) == 0, "not above its strength");
    errors();
    check(EVP_RAND_instantiate(t, 129, 0, NULL, 0, NULL) == 0, "nor instantiates above it");
    errors();
    check(EVP_RAND_instantiate(t, 128, 0, NULL, 0, NULL) == 1, "instantiated, the entropy from its start");
    check(EVP_RAND_generate(t, out, 18, 0, 0, NULL, 0) == 1, "all of the entropy");
    hex("all", out, 18);
    check(EVP_RAND_generate(t, out, 1, 0, 0, NULL, 0) == 0, "then none is left");
    errors();
    check(EVP_RAND_nonce(t, out, 2) == 1, "a nonce (the start of it)");
    hex("nonce", out, 2);
    check(EVP_RAND_nonce(t, out, 8) == 1, "a longer one");
    hex("nonce", out, 8);
    params[0] = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_REQUEST, &max);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_RAND_CTX_set_params(t, params) == 1 && set_test_entropy(t, "1112131415161718191a"),
          "a request limit of 3");
    check(EVP_RAND_generate(t, out, 10, 0, 0, NULL, 0) == 1, "chunks of it");
    hex("chunked", out, 10);
    params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_GENERATE, &gen);
    check(EVP_RAND_CTX_set_params(t, params) == 1, "generating mode");
    check(EVP_RAND_generate(t, out, 16, 0, 0, NULL, 0) == 1, "xorshift");
    hex("xorshift", out, 16);
    check(EVP_RAND_instantiate(t, 0, 0, NULL, 0, NULL) == 1
          && EVP_RAND_generate(t, out, 8, 0, 0, NULL, 0) == 1, "restarted");
    hex("restarted", out, 8);
    check(EVP_RAND_nonce(t, out, 5) == 1, "a generated nonce");
    hex("nonce", out, 5);
    params[0] = OSSL_PARAM_construct_int(OSSL_RAND_PARAM_STATE, &state);
    params[1] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    params[2] = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_REQUEST, &max);
    params[3] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_GENERATE, &max_request);
    params[4] = OSSL_PARAM_construct_end();
    check(EVP_RAND_CTX_get_params(t, params) == 1, "its parameters");
    printf("  state %d strength %u max %zu generate %u\n", state, strength, max, max_request);
    check(EVP_RAND_uninstantiate(t) == 1 && EVP_RAND_get_state(t) == EVP_RAND_STATE_UNINITIALISED
          && EVP_RAND_verify_zeroization(t) == 1 && EVP_RAND_reseed(t, 1, NULL, 0, NULL, 0) == 1,
          "uninstantiated");
    check(EVP_RAND_get_strength(t) == 128, "its strength");
    EVP_RAND_CTX_free(t);
    t = test_rand(0, NULL, NULL);
    check(EVP_RAND_nonce(t, out, 4) == 0, "no nonce without one");
    errors();
    EVP_RAND_CTX_free(t);
}

/* ---------------------------------------------------------------------------------------- */

static int set_str(EVP_RAND_CTX *ctx, const char *key, const char *value)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string(key, (char *)value, 0);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_RAND_CTX_set_params(ctx, params);
}

static int set_int(EVP_RAND_CTX *ctx, const char *key, int value)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_int(key, &value);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_RAND_CTX_set_params(ctx, params);
}

static int set_uint(EVP_RAND_CTX *ctx, const char *key, unsigned int value)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_uint(key, &value);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_RAND_CTX_set_params(ctx, params);
}

/* A DRBG's parameters, but its reseed time. */
static void drbg_params(EVP_RAND_CTX *ctx)
{
    int state = -9, use_df = -9;
    unsigned int strength = 9, counter = 9, requests = 9;
    size_t max_request = 9, min_e = 9, max_e = 9, min_n = 9, max_n = 9, max_p = 9, max_a = 9;
    uint64_t interval = 9;
    char cipher[32] = "-", digest[32] = "-", mac[32] = "-";
    OSSL_PARAM params[16];
    int r;

    params[0] = OSSL_PARAM_construct_int(OSSL_RAND_PARAM_STATE, &state);
    params[1] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    params[2] = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_REQUEST, &max_request);
    params[3] = OSSL_PARAM_construct_size_t(OSSL_DRBG_PARAM_MIN_ENTROPYLEN, &min_e);
    params[4] = OSSL_PARAM_construct_size_t(OSSL_DRBG_PARAM_MAX_ENTROPYLEN, &max_e);
    params[5] = OSSL_PARAM_construct_size_t(OSSL_DRBG_PARAM_MIN_NONCELEN, &min_n);
    params[6] = OSSL_PARAM_construct_size_t(OSSL_DRBG_PARAM_MAX_NONCELEN, &max_n);
    params[7] = OSSL_PARAM_construct_size_t(OSSL_DRBG_PARAM_MAX_PERSLEN, &max_p);
    params[8] = OSSL_PARAM_construct_size_t(OSSL_DRBG_PARAM_MAX_ADINLEN, &max_a);
    params[9] = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_COUNTER, &counter);
    params[10] = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS, &requests);
    params[11] = OSSL_PARAM_construct_uint64(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, &interval);
    params[12] = OSSL_PARAM_construct_end();
    r = EVP_RAND_CTX_get_params(ctx, params);
    printf("  params %d: state %d strength %u max %zu entropy %zu-%zu nonce %zu-%zu pers %zu adin %zu"
           " counter %u requests %u interval %llu\n", r, state, strength, max_request, min_e, max_e,
           min_n, max_n, max_p, max_a, counter, requests, (unsigned long long)interval);
    params[0] = OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_USE_DF, &use_df);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_RAND_CTX_get_params(ctx, params);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, cipher, sizeof(cipher));
    printf("  use_df %d/%d", r, use_df);
    r = EVP_RAND_CTX_get_params(ctx, params);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, digest, sizeof(digest));
    printf(" cipher %d/%s", r, cipher);
    r = EVP_RAND_CTX_get_params(ctx, params);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC, mac, sizeof(mac));
    printf(" digest %d/%s", r, digest);
    r = EVP_RAND_CTX_get_params(ctx, params);
    printf(" mac %d/%s\n", r, mac);
    params[0] = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_REQUEST, &max_request);
    params[1] = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_COUNTER, &counter);
    params[2] = OSSL_PARAM_construct_end();
    r = EVP_RAND_CTX_get_params(ctx, params);
    printf("  quick %d: max %zu counter %u\n", r, max_request, counter);
    errors();
}

/* Each DRBG fresh, then set up, through its parameters. */
static void drbg_setup(void)
{
    static const char *names[] = { "CTR-DRBG", "HASH-DRBG", "HMAC-DRBG", NULL };
    const char **n;
    EVP_RAND_CTX *ctx;

    for (n = names; *n != NULL; n++) {
        ctx = rand_ctx(*n, NULL);
        printf("  %s, fresh\n", *n);
        drbg_params(ctx);
        EVP_RAND_CTX_free(ctx);
    }
    ctx = rand_ctx("CTR-DRBG", NULL);
    check(set_int(ctx, OSSL_DRBG_PARAM_USE_DF, 0) == 0, "CTR-DRBG: no derivation function without a cipher");
    errors();
    check(set_str(ctx, OSSL_DRBG_PARAM_CIPHER, "AES-128-CBC") == 0, "a CBC cipher");
    errors();
    check(set_str(ctx, OSSL_DRBG_PARAM_CIPHER, "TR") == 0, "a short name");
    errors();
    check(set_str(ctx, OSSL_DRBG_PARAM_CIPHER, "NOPE-CTR") == 0, "an unknown cipher");
    codes();
    check(set_str(ctx, OSSL_DRBG_PARAM_CIPHER, "aes-128-ctr") == 1, "AES-128-CTR (by any case)");
    drbg_params(ctx);
    check(set_int(ctx, OSSL_DRBG_PARAM_USE_DF, 0) == 1, "without the derivation function");
    drbg_params(ctx);
    check(set_str(ctx, OSSL_DRBG_PARAM_CIPHER, "ARIA-256-CTR") == 1, "ARIA-256-CTR");
    drbg_params(ctx);
    check(set_str(ctx, OSSL_DRBG_PARAM_PROPERTIES, "provider=nonesuch") == 1, "properties alone");
    {
        OSSL_PARAM params[3];

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_PROPERTIES, "provider=nonesuch", 0);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, "AES-256-CTR", 0);
        params[2] = OSSL_PARAM_construct_end();
        check(EVP_RAND_CTX_set_params(ctx, params) == 0, "a cipher no provider matches");
        codes();
        params[0] = OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_PROPERTIES, (int *)"x");
        params[1] = OSSL_PARAM_construct_end();
        check(EVP_RAND_CTX_set_params(ctx, params) == 0, "properties not a string");
        errors();
    }
    drbg_params(ctx);
    EVP_RAND_CTX_free(ctx);

    ctx = rand_ctx("HASH-DRBG", NULL);
    check(set_str(ctx, OSSL_DRBG_PARAM_DIGEST, "SHAKE256") == 0, "HASH-DRBG: an XOF");
    errors();
    drbg_params(ctx);
    check(set_str(ctx, OSSL_DRBG_PARAM_DIGEST, "nonesuch") == 0, "an unknown digest");
    codes();
    check(set_str(ctx, OSSL_DRBG_PARAM_DIGEST, "SHA2-224") == 1, "SHA2-224");
    drbg_params(ctx);
    check(set_str(ctx, OSSL_DRBG_PARAM_DIGEST, "SHA512") == 1, "SHA-512");
    drbg_params(ctx);
    check(set_str(ctx, OSSL_DRBG_PARAM_DIGEST, "NULL") == 0, "a digest of no size");
    errors();
    drbg_params(ctx);
    EVP_RAND_CTX_free(ctx);

    ctx = rand_ctx("HMAC-DRBG", NULL);
    check(set_str(ctx, OSSL_DRBG_PARAM_MAC, "HMAC") == 1, "HMAC-DRBG: a MAC without a digest");
    errors();
    drbg_params(ctx);
    check(set_str(ctx, OSSL_DRBG_PARAM_DIGEST, "SHA1") == 1, "SHA-1");
    drbg_params(ctx);
    {
        OSSL_PARAM params[3];

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, "SHA256", 0);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC, "nonesuch", 0);
        params[2] = OSSL_PARAM_construct_end();
        check(EVP_RAND_CTX_set_params(ctx, params) == 0, "an unknown MAC");
        codes();
        drbg_params(ctx);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC, "KMAC128", 0);
        check(EVP_RAND_CTX_set_params(ctx, params) == 1, "KMAC128 as the MAC");
        drbg_params(ctx);
    }
    check(set_str(ctx, OSSL_DRBG_PARAM_DIGEST, "SHAKE128") == 0, "an XOF");
    errors();
    check(set_uint(ctx, OSSL_DRBG_PARAM_RESEED_REQUESTS, 7) == 0,
          "the refused XOF stays, and refuses later parameters");
    errors();
    drbg_params(ctx);
    EVP_RAND_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

#define E32 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define E48 E32 "202122232425262728292a2b2c2d2e2f"

static void drbg_states(void)
{
    EVP_RAND_CTX *t = test_rand(256, E48, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    EVP_RAND_CTX *ctx = rand_ctx("CTR-DRBG", t);
    unsigned char out[200], pers[100];
    unsigned int reseed;

    memset(pers, 0x5a, sizeof(pers));
    check(ctx != NULL, "CTR-DRBG under TEST-RAND");
    check(set_str(ctx, OSSL_DRBG_PARAM_CIPHER, "AES-256-CTR") == 1, "AES-256-CTR");
    printf("  state %d\n", EVP_RAND_get_state(ctx));
    check(EVP_RAND_generate(ctx, out, 16, 0, 0, NULL, 0) == 1,
          "generating instantiates it");
    hex("restart", out, 16);
    errors();
    check(EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL) == 1,
          "instantiating it again succeeds, with an error");
    errors();
    check(EVP_RAND_generate(ctx, out, 16, 257, 0, NULL, 0) == 0, "above its strength");
    errors();
    check(EVP_RAND_uninstantiate(ctx) == 1, "uninstantiated");
    check(EVP_RAND_verify_zeroization(ctx) == 1, "its secrets zeroed");
    check(EVP_RAND_instantiate(ctx, 256, 0, pers, 33, NULL) == 1, "with a personalization string");
    check(EVP_RAND_generate(ctx, out, 100, 256, 0, pers, 50) == 1, "with additional input");
    hex("adin", out, 100);
    check(EVP_RAND_verify_zeroization(ctx) == 0, "secrets in use");
    check(EVP_RAND_reseed(ctx, 0, (unsigned char *)"short", 5, NULL, 0) == 0,
          "too little entropy given to reseed");
    errors();
    printf("  state %d\n", EVP_RAND_get_state(ctx));
    check(EVP_RAND_generate(ctx, out, 16, 0, 0, NULL, 0) == 1, "restarts after the error");
    hex("again", out, 16);
    check(EVP_RAND_reseed(ctx, 0, pers, 40, (unsigned char *)"adin", 4) == 1,
          "reseeded with entropy given, then the parent's");
    check(EVP_RAND_generate(ctx, out, 16, 0, 1, NULL, 0) == 1, "with prediction resistance");
    hex("pr", out, 16);
    check(set_int(ctx, OSSL_DRBG_PARAM_USE_DF, 0) == 1, "without the derivation function");
    drbg_params(ctx);
    check(EVP_RAND_uninstantiate(ctx) == 1
          && EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL) == 1, "instantiated again");
    check(EVP_RAND_generate(ctx, out, 16, 0, 0, pers, 49) == 0, "additional input longer than the seed");
    errors();
    check(EVP_RAND_generate(ctx, out, 16, 0, 0, pers, 48) == 1, "as long as the seed");
    hex("no df", out, 16);
    check(EVP_RAND_uninstantiate(ctx) == 1 && EVP_RAND_instantiate(ctx, 0, 0, pers, 49, NULL) == 0,
          "a personalization string longer than the seed");
    errors();
    check(set_test_entropy(t, E32) && EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL) == 0,
          "too little entropy from the parent");
    errors();
    check(set_test_entropy(t, E48) && set_uint(ctx, OSSL_DRBG_PARAM_RESEED_REQUESTS, 2) == 1
          && EVP_RAND_generate(ctx, out, 8, 0, 0, NULL, 0) == 1, "reseed every 2 requests");
    {
        OSSL_PARAM params[2];

        params[0] = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_COUNTER, &reseed);
        params[1] = OSSL_PARAM_construct_end();
        EVP_RAND_CTX_get_params(ctx, params);
        printf("  reseeds %u", reseed);
        EVP_RAND_generate(ctx, out, 8, 0, 0, NULL, 0);
        EVP_RAND_generate(ctx, out, 8, 0, 0, NULL, 0);
        EVP_RAND_generate(ctx, out, 8, 0, 0, NULL, 0);
        EVP_RAND_CTX_get_params(ctx, params);
        printf(" then %u\n", reseed);
    }
    hex("after reseeds", out, 8);
    check(EVP_RAND_nonce(ctx, out, 20) == 1, "a nonce from a DRBG is output");
    hex("nonce", out, 20);
    check(EVP_RAND_enable_locking(ctx) == 1, "locking");
    errors();
    EVP_RAND_CTX_free(ctx);

    ctx = rand_ctx("HASH-DRBG", t);
    check(set_str(ctx, OSSL_DRBG_PARAM_DIGEST, "SHA256") == 1, "HASH-DRBG under TEST-RAND");
    check(EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL) == 1, "instantiated");
    check(EVP_RAND_generate(ctx, out, 200, 0, 0, NULL, 0) == 1, "200 octets");
    hex("hash", out, 200);
    EVP_RAND_CTX_free(ctx);
    ctx = rand_ctx("HMAC-DRBG", t);
    check(set_str(ctx, OSSL_DRBG_PARAM_DIGEST, "SHA512") == 1, "HMAC-DRBG under TEST-RAND");
    check(EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL) == 1, "instantiated");
    check(EVP_RAND_generate(ctx, out, 150, 0, 0, NULL, 0) == 1, "150 octets");
    hex("hmac", out, 150);
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_CTX_free(t);

    t = test_rand(128, E48, NULL);
    ctx = rand_ctx("HASH-DRBG", t);
    check(set_str(ctx, OSSL_DRBG_PARAM_DIGEST, "SHA256") == 1
          && EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL) == 0, "a parent too weak");
    errors();
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_CTX_free(t);
    t = test_rand(256, E48, NULL);
    ctx = rand_ctx("HASH-DRBG", t);
    check(set_str(ctx, OSSL_DRBG_PARAM_DIGEST, "SHA256") == 1
          && EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL) == 0, "a parent with no nonce");
    errors();
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_CTX_free(t);
}

/* A chain: SEED-SRC (or the operating system), a DRBG, and DRBGs under it. Random output. */
static void chains(void)
{
    EVP_RAND_CTX *seed = rand_ctx("SEED-SRC", NULL), *primary, *child, *bad, *none;
    unsigned char out[300], again[300];
    unsigned int strength = 256;

    check(EVP_RAND_generate(seed, out, 32, 256, 0, NULL, 0) == 0, "SEED-SRC: not instantiated");
    errors();
    check(EVP_RAND_instantiate(seed, 256, 0, NULL, 0, NULL) == 1, "instantiated");
    check(EVP_RAND_generate(seed, out, 32, 256, 0, NULL, 0) == 1, "32 octets at 256 bits");
    check(EVP_RAND_generate(seed, out, 300, 128, 0, (unsigned char *)"adin", 4) == 1,
          "300 octets, in chunks");
    check(EVP_RAND_generate(seed, out, 16, 256, 0, NULL, 0) == 0, "too short for 256 bits");
    errors();
    printf("  strength %u\n", EVP_RAND_get_strength(seed));
    check(EVP_RAND_reseed(seed, 0, NULL, 0, NULL, 0) == 1 && EVP_RAND_enable_locking(seed) == 1,
          "reseeds and locks");
    bad = rand_ctx("SEED-SRC", seed);
    check(bad == NULL, "a seed source has no parent");
    errors();

    primary = rand_ctx("CTR-DRBG", seed);
    check(primary != NULL && set_str(primary, OSSL_DRBG_PARAM_CIPHER, "AES-256-CTR") == 1
          && EVP_RAND_instantiate(primary, 256, 0, NULL, 0, NULL) == 1, "a primary DRBG over it");
    child = rand_ctx("HASH-DRBG", primary);
    check(child != NULL && set_str(child, OSSL_DRBG_PARAM_DIGEST, "SHA256") == 1
          && EVP_RAND_instantiate(child, 256, 1, NULL, 0, NULL) == 1, "a child DRBG over that");
    check(EVP_RAND_generate(child, out, 300, 256, 0, NULL, 0) == 1
          && EVP_RAND_generate(child, again, 300, 256, 1, NULL, 0) == 1
          && memcmp(out, again, 300) != 0, "which generates");
    check(EVP_RAND_reseed(primary, 0, NULL, 0, NULL, 0) == 1
          && EVP_RAND_generate(child, out, 10, 0, 0, NULL, 0) == 1, "and reseeds after its parent");
    errors();
    EVP_RAND_CTX_free(child);

    none = rand_ctx("HMAC-DRBG", NULL);
    check(none != NULL && set_str(none, OSSL_DRBG_PARAM_DIGEST, "SHA384") == 1
          && EVP_RAND_instantiate(none, 192, 0, (unsigned char *)"me", 2, NULL) == 1
          && EVP_RAND_generate(none, out, 64, 192, 1, NULL, 0) == 1,
          "a DRBG without a parent seeds itself");
    check(EVP_RAND_nonce(none, out, 16) == 1, "a nonce");
    EVP_RAND_CTX_free(none);

    child = rand_ctx("CTR-DRBG", seed);
    {
        OSSL_PARAM params[2];

        params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
        params[1] = OSSL_PARAM_construct_end();
        check(EVP_RAND_CTX_get_params(seed, params) == 1, "its strength");
        printf("  seed strength %u\n", strength);
    }
    EVP_RAND_CTX_free(child);
    EVP_RAND_CTX_free(primary);
    EVP_RAND_CTX_free(seed);
    errors();
}

int main(void)
{
    methods();
    nulls();
    known_answers();
    test_rand_itself();
    drbg_setup();
    drbg_states();
    chains();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
