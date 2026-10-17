/*
 * Conformance test for RSA through EVP (EVP_PKEY-RSA(7), EVP_SIGNATURE-RSA(7),
 * EVP_ASYM_CIPHER-RSA(7), provider-keymgmt(7)), in TAP format: RSA and RSA-PSS keys made from
 * data and their parameters; decryption with PKCS #1 v1.5 (with and without implicit
 * rejection), OAEP, no padding, and the TLS premaster mode, encryption round trips, and the
 * errors; signatures over digests and messages with PKCS #1 v1.5, PSS (salt lengths, MGF1
 * digests, a restricted RSA-PSS key's limits), X9.31, and no padding, verification and
 * recovery, the composite algorithms (RSA-SHA256 and the others) over messages and digests,
 * the algorithm identifiers the contexts report, and copies of a context mid-message.
 *
 * The key and the implicit-rejection vectors are OpenSSL's (test/recipes/30-test_evp_data/
 * evppkey_rsa_common.txt, RSA-2048-2). PSS signatures are random, so only their lengths and
 * verification are printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rsaerr.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The error queue, emptied: each entry's library, reason, and text. */
/*
 * Whether errors() prints RSA's two PKCS#1 type 1 padding-check reasons as one: recovering a
 * PSS signature with PKCS#1 padding fails one way or the other depending on whether the random
 * salt makes the recovered value's first octet zero (1 time in 256, on either library).
 */
static int merge_padding_reasons = 0;

static void errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf("  errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        if (merge_padding_reasons && ERR_GET_LIB(code) == ERR_LIB_RSA
            && (ERR_GET_REASON(code) == RSA_R_INVALID_PADDING
                || ERR_GET_REASON(code) == RSA_R_BLOCK_TYPE_IS_NOT_01)) {
            printf(" %d/padding", ERR_LIB_RSA);
            continue;
        }
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && *data != '\0')
            printf(" (%s)", data);
    }
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s(%zu):", label, n);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static const char *str(const char *s)
{
    return s == NULL ? "-" : s;
}

static const char KEY_N[] =
    "c8cc839714098da56caa23640f93dc8997c16372968fc1b0c6df5113c1c94e8b"
    "21e48ad2297e65419011b4e6d8f5e73b1b78b257400321d1ef6b602d4ec8ce8d"
    "141c94905eb4ad306639a49206534b6e7f2607423e97dffd133c88d721399def"
    "bc7e96ccdcbd7f3aae1fe892712bfb4929817d511666440a1facb7a208f5ea16"
    "5910add8a3f2d497202360ccb632024f0d07169c1918f316f794b143aef54ec8"
    "7522a4c02978f9689980bffbf649c307e81819bff88409638d48bd94be152b59"
    "ff649fa0bd629d0ffa1813c3abf4b56bd3c2ea5465dffa14589292a9d8a24ad2"
    "6be7ee0510741b6382d43c83d5bfa40a46613d062be445517dbcaf0cb4e1a769";
static const char KEY_E[] =
    "10001";
static const char KEY_D[] =
    "1455010e0f2d587663a666a6ff1ccdbbf0edd8100646d02a023922908992c4ad"
    "39e5565929726ef6508c3a71158ef0b6ff751d39d07580bb2d2f063210442d06"
    "03ff50dbbd7b35fe2c9bb19a47a1af85a4c24901e02ca8b58b7919b20edf32aa"
    "cfbf51adb4bc4b61b9b7e968caa4d570f70ef18d8063228893e47d439efca793"
    "259bcf2cd108a3d8688cdf078e7ac799969f2339d2c1f522b969684629a933ba"
    "aec2681625eab84f4e56f4447e9d88fb9a199cf71023e0e257b14441b33c84d3"
    "bc67ca8031d2612618103a7a0a40844262f75d8890cd616e51f9035488fd6e09"
    "9de8ff6d65a4ff118254807c9f58d2fbba8ba151dc8c68be349c977a204e04c1";
static const char KEY_P[] =
    "f8f5ad6ba828931bea459b8a3f6dc041d23482409c2571e963f31f748602a256"
    "371b3883ed459ecf970526459edd16e05522f5a45d94751b2ec2daf272c7f881"
    "6a52c00d18080171634da899d7973222f51b937630548696a9f7d8c24a59497c"
    "1efcd455cfb97ee86d2b6d34972b332fda303f04999b4eb6b5cc0bb33e7761dd";
static const char KEY_Q[] =
    "ce7a2e3b49a90b96330a12dc682bdfbdfbae8dd6dc03b6147aefbd575743f0f6"
    "da4d86235061b71afd9cad2d34025e56ac86b0f7743eb35e1acbca2378954244"
    "65b706ed22175e5718c8c70b6703ea8f6b510f945be48e5a36bb3c3c91732b58"
    "9dfc05d72d80903194452bda21348647ec72943f11a846e62faebe8eb536b0fd";
static const char KEY_DMP1[] =
    "76fe15f18ae239cdf1df6b445ca4bc6bb968d788c21933a4f5dcd280033d6712"
    "062cc08a6df204c1fbd0be46307443e6dd4a6456375429d4e038ca256faf1c9b"
    "de91c6b17b76f81995f91c48cbbebc7bf0e3494c08359e4e8cd6a587d7b96d62"
    "21fd7e0fb5c5575f082ee57769798071b2bbb4a32238151b47314bb654790311";
static const char KEY_DMQ1[] =
    "998848b055499a1009cbc7d294b36b1ffdf2020e6e7364053e94de1a000dc934"
    "0587f7e27276f68cdf608d753b63377b03b6f4084d2c027c4b38960a6233ba9e"
    "d9738b76f10ea75be456078bf701f67cc6b3f3fdc186e64336c76b372e80910e"
    "c80b0adcc23d02fb9ae10486a28248075b4ea7e56ddfcf3882e451561471a291";
static const char KEY_IQMP[] =
    "643bf746429f7d83667a0653021347efbfc05e6351f821a9debb60e0eccde500"
    "5ad9e9ec31e558f7e92c29328e74569d7cef7c74cabc2b355ed401a1a0914b4e"
    "3cbb06484e58196051169ed14caa2efa6ea044e054d26144cc1629c55010558a"
    "04e133f44b7c244dac25bf913c57b890ee49f548259cd63404fef6859dcf975a";
static const char CT_OAEP[] =
    "c16673fbc9f7ab41095341896d66a03d6ff0b350e56d286833a2dde565388d94"
    "f7e0ca4ed9470b5d5d6474e3e8a0edb59687fbda4f0acc991cd7b8506c9e5fa6"
    "9ae6b23437a40807098aba76ea44f4d426bc9392f38f6748a2e46f2a8648adc6"
    "192a668b97a6019ee3b5762545915fb2bd4f7e52f286aa7f25646f1bafe303c0"
    "c09836b2f87dc557f2dbb1a1fa9bfbb9ecd2719ee1b06eda1779763882ddd8cf"
    "8c68660c53e393322d78f8a75370e8308736792de9dcbcd1cc40411561e32b61"
    "8d10ee1c95606ab6ca5a242a7fca1cb77561435f291217d2c548e13b71ab3ab7"
    "ec227af16bea2c4fc97ac2bda291e5653671e427085136c094e623c52716861e";
/* The Bleichenbacher implicit-rejection vectors (ciphertext, the plaintext decryption
 * gives: the message, or the synthetic one for a bad padding). */
static const char *const IMPLICIT[][2] = {
    {
        "8bfe264e85d3bdeaa6b8851b8e3b956ee3d226fd3f69063a86880173a273d9f2"
        "83b2eebdd1ed35f7e02d91c571981b6737d5320bd8396b0f3ad5b019daec1b0a"
        "ab3cbbc026395f4fd14f13673f2dfc81f9b660ec26ac381e6db3299b4e460b43"
        "fab9955df2b3cfaa20e900e19c856238fd371899c2bf2ce8c868b76754e5db3b"
        "036533fd603746be13c10d4e3e6022ebc905d20c2a7f32b215a4cd53b3f44ca1"
        "c327d2c2b651145821c08396c89071f665349c25e44d2733cd9305985ceef643"
        "0c3cf57af5fa224089221218fa34737c79c446d28a94c41c96e4e92ac53fbcf3"
        "84dea8419ea089f8784445a492c812eb0d409467f75afd7d4d1078886205a066",
        "6c6f72656d20697073756d20646f6c6f722073697420616d6574"},
    {
        "20aaa8adbbc593a924ba1c5c7990b5c2242ae4b99d0fe636a19a4cf754edbcee"
        "774e472fe028160ed42634f8864900cb514006da642cae6ae8c7d087caebcfa6"
        "dad1551301e130344989a1d462d4164505f6393933450c67bc6d39d8f5160907"
        "cabc251b737925a1cf21e5c6aa5781b7769f6a2a583d97cce008c0f8b6add5f0"
        "b2bd80bee60237aa39bb20719fe75749f4bc4e42466ef5a861ae3a92395c7d85"
        "8d430bfe38040f445ea93fa2958b503539800ffa5ce5f8cf51fa8171a91f36cb"
        "4f4575e8de6b4d3f096ee140b938fd2f50ee13f0d050222e2a72b0a3069ff3a6"
        "738e82c87090caa5aed4fcbe882c49646aa250b98f12f83c8d528113614a29e7",
        ""},
    {
        "48cceab10f39a4db32f60074feea473cbcdb7accf92e150417f76b44756b190e"
        "843e79ec12aa85083a21f5437e7bad0a60482e601198f9d86923239c8786ee72"
        "8285afd0937f7dde12717f28389843d7375912b07b991f4fdb0190fced8ba665"
        "314367e8c5f9d2981d0f5128feeb46cb50fc237e64438a86df198dd0209364ae"
        "3a842d77532b66b7ef263b83b1541ed671b120dfd660462e2107a4ee7b964e73"
        "4a7bd68d90dda61770658a3c242948532da32648687e0318286473f675b412d6"
        "468f013f14d760a358dfcad3cda2afeec5e268a37d250c37f722f468a70dfd92"
        "d7294c3c1ee1e7f8843b7d16f9f37ef35748c3ae93aa155cdcdfeb4e78567303",
        "22d850137b9eebe092b24f602dc5bb7918c16bd89ddbf20467b119d205f9c2e4bd7d2592cf1e532106e0f33557565923c73a02d4f09c0c22bea89148183e60317f7028b3aa1f261f91c979393101d7e15f4067e63979b32751658ef769610fe97cf9cef3278b3117d384051c3b1d82c251c2305418c8f6840530e631aad63e70e20e025bcd8efb54c92ec6d3b106a2f8e64eeff7d38495b0fc50c97138af4b1c0a67a1c4e27b077b8439332edfa8608dfeae653cd6a628ac550395f7e74390e42c11682234870925eeaa1fa71b76cf1f2ee3bda69f6717033ff8b7c95c9799e7a3bea5e7e4a1c359772fb6b1c6e6c516661dfe30c3"},
    {
        "1439e08c3f84c1a7fec74ce07614b20e01f6fa4e8c2a6cffdc3520d8889e5d9a"
        "950c6425798f85d4be38d300ea5695f13ecd4cb389d1ff5b82484b494d6280ab"
        "7fa78e645933981cb934cce8bfcd114cc0e6811eefa47aae20af638a1cd163d2"
        "d3366186d0a07df0c81f6c9f3171cf3561472e98a6006bf75ddb457bed036dcc"
        "e199369de7d94ef2c68e8467ee0604eea2b3009479162a7891ba5c40cab17f49"
        "e1c438cb6eaea4f76ce23cce0e483ff0e96fa790ea15be67671814342d0a23f4"
        "a20262b6182e72f3a67cd289711503c85516a9ed225422f98b116f1ab080a80a"
        "bd6f0216df88d8cfd67c139243be8dd78502a7aaf6bc99d7da71bcdf627e7354",
        "0f9b"},
    {
        "1690ebcceece2ce024f382e467cf8510e74514120937978576caf684d4a02ad5"
        "69e8d76cbe365a060e00779de2f0865ccf0d923de3b4783a4e2c74f422e2f326"
        "086c390b658ba47f31ab013aa80f468c71256e5fa5679b24e83cd82c3d1e05e3"
        "98208155de2212993cd2b8bab6987cf4cc1293f19909219439d74127545e9ed8"
        "a706961b8ee2119f6bfacafbef91b75a789ba65b8b833bc6149cf49b5c4d2c63"
        "59f62808659ba6541e1cd24bf7f7410486b5103f6c0ea29334ea6f4975b17387"
        "474fe920710ea61568d7b7c0a7916acf21665ad5a31c4eabcde44f8fb6120d84"
        "57afa1f3c85d517cda364af620113ae5a3c52a048821731922737307f77a1081",
        "4f02"},
    {
        "6213634593332c485cef783ea2846e3d6e8b0e005cd8293eaebbaa5079712fd6"
        "81579bdfbbda138ae4d9d952917a03c92398ec0cb2bb0c6b5a8d55061fed0d0d"
        "8d72473563152648cfe640b335dc95331c21cb133a91790fa93ae44497c12870"
        "8970d2beeb77e8721b061b1c44034143734a77be8220877415a6dba073c38716"
        "05380542a9f25252a4babe8331cdd53cf828423f3cc70b560624d0581fb126b2"
        "ed4f4ed358f0eb8065cf176399ac1a846a31055f9ae8c9c24a1ba050bc208421"
        "25bc1753158f8065f3adb9cc16bfdf83816bdf38b624f12022c5a6fbfe29bc91"
        "542be8c0208a770bcd677dc597f5557dc2ce28a11bf3e3857f158717a33f6592",
        "6c6f72656d20697073756d"},
    {
        "00a2e8f114ea8d05d12dc843e3cc3b2edc8229ff2a028bda29ba9d55e3cd0291"
        "1902fef1f42a075bf05e8016e8567213d6f260fa49e360779dd81aeea3e04c2c"
        "b567e0d72b98bf754014561b7511e083d20e0bfb9cd23f8a0d3c88900c49d2fc"
        "d5843ff0765607b2026f28202a87aa94678aed22a0c20724541394cd8f44e373"
        "eba1d2bae98f516c1e2ba3d86852d064f856b1daf24795e767a2b90396e50743"
        "e3150664afab131fe40ea405dcf572dd1079af1d3f0392ccadcca0a12740dbb2"
        "13b925ca2a06b1bc1383e83a658c82ba2e7427342379084d5f66b544579f0766"
        "4cb26edd4f10fd913fdbc0de05ef887d4d1ec1ac95652397ea7fd4e4759fda8b",
        "6c6f72656d20697073756d"},
    {
        "a2e8f114ea8d05d12dc843e3cc3b2edc8229ff2a028bda29ba9d55e3cd029119"
        "02fef1f42a075bf05e8016e8567213d6f260fa49e360779dd81aeea3e04c2cb5"
        "67e0d72b98bf754014561b7511e083d20e0bfb9cd23f8a0d3c88900c49d2fcd5"
        "843ff0765607b2026f28202a87aa94678aed22a0c20724541394cd8f44e373eb"
        "a1d2bae98f516c1e2ba3d86852d064f856b1daf24795e767a2b90396e50743e3"
        "150664afab131fe40ea405dcf572dd1079af1d3f0392ccadcca0a12740dbb213"
        "b925ca2a06b1bc1383e83a658c82ba2e7427342379084d5f66b544579f07664c"
        "b26edd4f10fd913fdbc0de05ef887d4d1ec1ac95652397ea7fd4e4759fda8b",
        "6c6f72656d20697073756d"},
    {
        "00001f71879b426127f7dead621f7380a7098cf7d22173aa27991b143c46d533"
        "83c209bd0c9c00d84078037e715f6b98c65005a77120070522ede51d472c87ef"
        "94b94ead4c5428ee108a345561658301911ec5a8f7dd43ed4a3957fd29fb02a3"
        "529bf63f8040d3953490939bd8f78b2a3404b6fb5ff70a4bfdaac5c541d6bcce"
        "49c9778cc390be24cbef1d1eca7e870457241d3ff72ca44f9f56bdf31a890fa5"
        "eb3a9107b603ccc9d06a5dd911a664c82b6abd4fe036f8db8d5a070c2d86386a"
        "e18d97adc1847640c211d91ff5c3387574a26f8ef27ca7f48d2dd1f0c7f14b81"
        "cc9d33ee6853031d3ecf10a914ffd90947909c8011fd30249219348ebff76bfc",
        "6c6f72656d20697073756d"},
    {
        "1f71879b426127f7dead621f7380a7098cf7d22173aa27991b143c46d53383c2"
        "09bd0c9c00d84078037e715f6b98c65005a77120070522ede51d472c87ef94b9"
        "4ead4c5428ee108a345561658301911ec5a8f7dd43ed4a3957fd29fb02a3529b"
        "f63f8040d3953490939bd8f78b2a3404b6fb5ff70a4bfdaac5c541d6bcce49c9"
        "778cc390be24cbef1d1eca7e870457241d3ff72ca44f9f56bdf31a890fa5eb3a"
        "9107b603ccc9d06a5dd911a664c82b6abd4fe036f8db8d5a070c2d86386ae18d"
        "97adc1847640c211d91ff5c3387574a26f8ef27ca7f48d2dd1f0c7f14b81cc9d"
        "33ee6853031d3ecf10a914ffd90947909c8011fd30249219348ebff76bfc",
        "6c6f72656d20697073756d"},
    {
        "b5e49308f6e9590014ffaffc5b8560755739dd501f1d4e9227a7d291408cf4b7"
        "53f292322ff8bead613bf2caa181b221bc38caf6392deafb28eb21ad60930841"
        "ed02fd6225cc9c463409adbe7d8f32440212fbe3881c51375bb09565efb22e62"
        "b071472fb38676e5b4e23a0617db5d14d93519ac0007a30a9c822eb31c38b57f"
        "cb1be29608fcf1ca2abdcaf5d5752bbc2b5ac7dba5afcff4a5641da360dd01f7"
        "112539b1ed46cdb550a3b1006559b9fe1891030ec80f0727c42401ddd6cbb5e3"
        "c80f312df6ec89394c5a7118f573105e7ab00fe57833c126141b50a935224842"
        "addfb479f75160659ba28877b512bb9a93084ad8bec540f92640f63a11a010e0",
        "6c6f72656d20697073756d"},
    {
        "1ea0b50ca65203d0a09280d39704b24fe6e47800189db5033f202761a78bafb2"
        "70c5e25abd1f7ecc6e7abc4f26d1b0cd9b8c648d529416ee64ccbdd7aa72a771"
        "d0353262b543f0e436076f40a1095f5c7dfd10dcf0059ccb30e92dfa5e015661"
        "8215f1c3ff3aa997a9d999e506924f5289e3ac72e5e2086cc7b499d71583ed56"
        "1028671155db4005bee01800a7cdbdae781dd32199b8914b5d4011dd6ff11cd2"
        "6d46aad54934d293b0bc403dd211bf13b5a5c6836a5e769930f437ffd8634fb7"
        "371776f4bc88fa6c271d8aa6013df89ae6470154497c4ac861be2a1c65ebffec"
        "139bf7aaba3a81c7c5cdd84da9af5d3edfb957848074686b5837ecbcb6a41c50",
        "6c6f72656d20697073756d"},
    {
        "5f02f4b1f46935c742ebe62b6f05aa0a3286aab91a49b34780adde6410ab46f7"
        "386e05748331864ac98e1da63686e4babe3a19ed40a7f5ceefb89179596aab07"
        "ab1015e03b8f825084dab028b6731288f2e511a4b314b6ea3997d2e8fe2825ce"
        "f8897cbbdfb6c939d441d6e04948414bb69e682927ef8576c9a7090d4aad0e74"
        "c520d6d5ce63a154720f00b76de8cc550b1aa14f016d63a7b6d6eaa1f7dbe9e5"
        "0200d3159b3d099c900116bf4eba3b94204f18b1317b07529751abf64a26b0a0"
        "bf1c8ce757333b3d673211b67cc0653f2fe2620d57c8b6ee574a0323a167eab1"
        "106d9bc7fd90d415be5f1e9891a0e6c709f4fc0404e8226f8477b4e939b36eb2",
        "af9ac70191c92413cb9f2d"},
    {
        "9b2ec9c0c917c98f1ad3d0119aec6be51ae3106e9af1914d48600ab6a2c0c0c8"
        "ae02a2dc3039906ff3aac904af32ec798fd65f3ad1afa2e69400e7c1de81f572"
        "8f3b3291f38263bc7a90a0563e43ce7a0d4ee9c0d8a716621ca5d3d081188769"
        "ce1b131af7d35b13dea99153579c86db31fe07d5a2c14d621b77854e48a8df41"
        "b5798563af489a291e417b6a334c63222627376118c02c53b6e86310f728734f"
        "fc86ef9d7c8bf56c0c841b24b82b59f51aee4526ba1c4268506d301e4ebc498c"
        "6aebb6fd5258c876bf900bac8ca4d309dd522f6a6343599a8bc3760f422c10c7"
        "2d0ad527ce4af1874124ace3d99bb74db8d69d2528db22c3a37644640f95c05f",
        "a1f8c9255c35cfba403ccc"},
    {
        "782c2b59a21a511243820acedd567c136f6d3090c115232a82a5efb0b178285f"
        "55b5ec2d2bac96bf00d6592ea7cdc3341610c8fb07e527e5e2d20cfaf2c7f23e"
        "375431f45e998929a02f25fd95354c33838090bca838502259e92d86d568bc2c"
        "db132fab2a399593ca60a015dc2bb1afcd64fef8a3834e17e5358d822980dc44"
        "6e845b3ab4702b1ee41fe5db716d92348d5091c15d35a110555a35deb4650a5a"
        "1d2c98025d42d4544f8b32aa6a5e02dc02deaed9a7313b73b49b0d4772a3768b"
        "0ea0db5846ace6569cae677bf67fb0acf3c255dc01ec8400c963b6e49b106772"
        "8b4e563d7e1e1515664347b92ee64db7efb5452357a02fff7fcb7437abc2e579",
        "e6d700309ca0ed62452254"},
    {
        "0096136621faf36d5290b16bd26295de27f895d1faa51c800dafce73d001d607"
        "96cd4e2ac3fa2162131d859cd9da5a0c8a42281d9a63e5f353971b72e36b5722"
        "e4ac444d77f892a5443deb3dca49fa732fe855727196e23c26eeac55eeced826"
        "7a209ebc0f92f4656d64a6c13f7f7ce544ebeb0f668fe3a6c0f189e4bcd5ea12"
        "b73cf63e0c8350ee130dd62f01e5c97a1e13f52fde96a9a1bc9936ce734fdd61"
        "f27b18216f1d6de87f49cf4f2ea821fb8efd1f92cdad529baf7e31aff9bff407"
        "4f2cad2b4243dd15a711adcf7de900851fbd6bcb53dac399d7c880531d06f25f"
        "7002e1aaf1722765865d2c2b902c7736acd27bc6cbd3e38b560e2eecf7d4b576",
        "ba27b1842e7c21c0e7ef6a"},
    {
        "96136621faf36d5290b16bd26295de27f895d1faa51c800dafce73d001d60796"
        "cd4e2ac3fa2162131d859cd9da5a0c8a42281d9a63e5f353971b72e36b5722e4"
        "ac444d77f892a5443deb3dca49fa732fe855727196e23c26eeac55eeced8267a"
        "209ebc0f92f4656d64a6c13f7f7ce544ebeb0f668fe3a6c0f189e4bcd5ea12b7"
        "3cf63e0c8350ee130dd62f01e5c97a1e13f52fde96a9a1bc9936ce734fdd61f2"
        "7b18216f1d6de87f49cf4f2ea821fb8efd1f92cdad529baf7e31aff9bff4074f"
        "2cad2b4243dd15a711adcf7de900851fbd6bcb53dac399d7c880531d06f25f70"
        "02e1aaf1722765865d2c2b902c7736acd27bc6cbd3e38b560e2eecf7d4b576",
        "ba27b1842e7c21c0e7ef6a"},
    {
        "0000587cccc6b264bdfe0dc2149a988047fa921801f3502ea64624c510c6033d"
        "2f427e3f136c26e88ea9f6519e86a542cec96aad1e5e9013c3cc203b6de15a69"
        "183050813af5c9ad79703136d4b92f50ce171eefc6aa7988ecf02f319ffc5eaf"
        "d6ee7a137f8fce64b255bb1b8dd19cfe767d64fdb468b9b2e9e7a0c24dae0323"
        "9c8c714d3f40b7ee9c4e59ac15b17e4d328f1100756bce17133e8e7493b54e50"
        "06c3cbcdacd134130c5132a1edebdbd01a0c41452d16ed7a0788003c34730d08"
        "08e7e14c797a21f2b45a8aa1644357fd5e988f99b017d9df37563a354c788dc0"
        "e2f9466045622fa3f3e17db63414d27761f57392623a2bef6467501c63e8d645",
        "d5cf555b1d6151029a429a"},
    {
        "587cccc6b264bdfe0dc2149a988047fa921801f3502ea64624c510c6033d2f42"
        "7e3f136c26e88ea9f6519e86a542cec96aad1e5e9013c3cc203b6de15a691830"
        "50813af5c9ad79703136d4b92f50ce171eefc6aa7988ecf02f319ffc5eafd6ee"
        "7a137f8fce64b255bb1b8dd19cfe767d64fdb468b9b2e9e7a0c24dae03239c8c"
        "714d3f40b7ee9c4e59ac15b17e4d328f1100756bce17133e8e7493b54e5006c3"
        "cbcdacd134130c5132a1edebdbd01a0c41452d16ed7a0788003c34730d0808e7"
        "e14c797a21f2b45a8aa1644357fd5e988f99b017d9df37563a354c788dc0e2f9"
        "466045622fa3f3e17db63414d27761f57392623a2bef6467501c63e8d645",
        "d5cf555b1d6151029a429a"},
    {
        "1786550ce8d8433052e01ecba8b76d3019f1355b212ac9d0f5191b023325a7e7"
        "714b7802f8e9a17c4cb3cd3a84041891471b10ca1fcfb5d041d34c82e6d0011c"
        "f4dc76b90e9c2e0743590579d55bcd7857057152c4a8040361343d1d22ba677d"
        "62b011407c652e234b1d663af25e2386251d7409190f19fc8ec3f9374fdf1254"
        "633874ce2ec2bff40ad0cb473f9761ec7b68da45a4bd5e33f5d7dac9b9a20821"
        "df9406b653f78a95a6c0ea0a4d57f867e4db22c17bf9a12c150f809a7b72b6db"
        "86c22a8732241ebf3c6a4f2cf82671d917aba8bc61052b40ccddd743a94ea9b5"
        "38175106201971cca9d136d25081739aaf6cd18b2aecf9ad320ea3f89502f955",
        "3d4a054d9358209e9cbbb9"},
    {
        "179598823812d2c58a7eb50521150a48bcca8b4eb53414018b6bca19f4801456"
        "c5e36a940037ac516b0d6412ba44ec6b4f268a55ef1c5ffbf18a2f4e3522bb7b"
        "6ed89774b79bffa22f7d3102165565642de0d43a955e96a1f2e80e5430671d72"
        "66eb4f905dc8ff5e106dc5588e5b0289e49a4913940e392a97062616d2bda381"
        "55471b7d360cfb94681c702f60ed2d4de614ea72bf1c53160e63179f6c5b897b"
        "59492bee219108309f0b7b8cb2b136c346a5e98b8b4b8415fb1d713bae067911"
        "e3057f1c335b4b7e39101eafd5d28f0189037e4334f4fdb9038427b1d119a670"
        "2aa8233319cc97d496cc289ae8c956ddc84042659a2d43d6aa22f12b81ab884e",
        "1f037dd717b07d3e7f7359"},
    {
        "a7a340675a82c30e22219a55bc07cdf36d47d01834c1834f917f18b517419ce9"
        "de2a96460e745024436470ed85e94297b283537d52189c406a3f533cb405cc6a"
        "9dba46b482ce98b6e3dd52d8fce2237425617e38c11fbc46b61897ef200d01e4"
        "f25f5f6c4c5b38cd0de38ba11908b86595a8036a08a42a3d05b79600a97ac18b"
        "a368a08d6cf6ccb624f6e8002afc75599fba4de3d4f3ba7d208391ebe8d21f82"
        "82b18e2c10869eb2702e68f9176b42b0ddc9d763f0c86ba0ff92c957aaeab76d"
        "9ab8da52ea297ec11d92d770146faa1b300e0f91ef969b53e7d2907ffc984e9a"
        "9c9d11fb7d6cba91972059b46506b035efec6575c46d7114a6b935864858445f",
        "63cb0bf65fc8255dd29e17"},
    {
        "3d1b97e7aa34eaf1f4fc171ceb11dcfffd9a46a5b6961205b10b302818c1fcc9"
        "f4ec78bf18ea0cee7e9fa5b16fb4c611463b368b3312ac11cf9c06b7cf72b54e"
        "284848a508d3f02328c62c2999d0fb60929f81783c7a256891bc2ff4d91df2af"
        "96a24fc5701a1823af939ce6dbdc510608e3d41eec172ad2d51b9fc61b4217c9"
        "23cadcf5bac321355ef8be5e5f090cdc2bd0c697d9058247db3ad613fdce87d2"
        "955a6d1c948a5160f93da21f731d74137f5d1f53a1923adb513d2e6e1589d44c"
        "c079f4c6ddd471d38ac82d20d8b1d21f8d65f3b6907086809f4123e08d86fb38"
        "729585de026a485d8f0e703fd4772f6668febf67df947b82195fa3867e3a3065",
        "6f09a0b62699337c497b0b"},
};

static BIGNUM *bn(const char *h)
{
    BIGNUM *b = NULL;

    BN_hex2bn(&b, h);
    return b;
}

/*
 * The key as `type` ("RSA" or "RSA-PSS"); with `saltlen` > 0, an RSA-PSS key restricted to
 * SHA256, MGF1 with SHA384, and that minimum salt length.
 */
static EVP_PKEY *make_key(const char *type, int saltlen)
{
    const char *names[] = {
        "n", "e", "d", "rsa-factor1", "rsa-factor2", "rsa-exponent1", "rsa-exponent2",
        "rsa-coefficient1"
    };
    const char *values[] = { KEY_N, KEY_E, KEY_D, KEY_P, KEY_Q, KEY_DMP1, KEY_DMQ1, KEY_IQMP };
    BIGNUM *nums[8];
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params;
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    size_t i;

    for (i = 0; i < 8; i++) {
        nums[i] = bn(values[i]);
        OSSL_PARAM_BLD_push_BN(bld, names[i], nums[i]);
    }
    if (saltlen > 0) {
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_RSA_DIGEST, "SHA256", 0);
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, "SHA384", 0);
        OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, saltlen);
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    check(EVP_PKEY_fromdata_init(ctx) == 1
          && EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) == 1,
          "key from data");
    errors();
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    for (i = 0; i < 8; i++)
        BN_free(nums[i]);
    return pkey;
}

static void test_keymgmt(EVP_PKEY *k)
{
    BIGNUM *n = bn(KEY_N), *got = NULL;
    char digest[50] = "";
    EVP_PKEY *dup;
    OSSL_PARAM *out = NULL, *p;

    printf("# key management\n");
    check(EVP_PKEY_get_bits(k) == 2048 && EVP_PKEY_get_security_bits(k) == 112
          && EVP_PKEY_get_size(k) == 256, "bits, security bits, and size");
    check(EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_RSA_N, &got) == 1 && BN_cmp(got, n) == 0,
          "the modulus");
    check(EVP_PKEY_get_default_digest_name(k, digest, sizeof(digest)) == 1, "default digest");
    printf("  %s\n", digest);
    dup = EVP_PKEY_dup(k);
    check(dup != NULL && EVP_PKEY_eq(k, dup) == 1, "a duplicate is equal");
    check(EVP_PKEY_todata(k, EVP_PKEY_KEYPAIR, &out) == 1, "to data");
    for (p = out; p != NULL && p->key != NULL; p++)
        printf("  %s %zu\n", p->key, p->data_size);
    check(EVP_PKEY_is_a(k, "RSA") && EVP_PKEY_get_id(k) == EVP_PKEY_RSA, "is RSA");
    errors();
    OSSL_PARAM_free(out);
    EVP_PKEY_free(dup);
    BN_free(got);
    BN_free(n);
}

/*
 * `hexct` decrypted with `pad` (default PKCS #1 v1.5); `want` is the plaintext, "*" for any,
 * or NULL for a failure.
 */
static void decrypt(EVP_PKEY *k, const char *pad, const char *hexct, int implicit,
                    const char *want, const char *what)
{
    long n, wn = 0;
    unsigned char *in = OPENSSL_hexstr2buf(hexct, &n), out[512];
    int any = want != NULL && strcmp(want, "*") == 0;
    unsigned char *w = want != NULL && *want != '\0' && !any ? OPENSSL_hexstr2buf(want, &wn) : NULL;
    size_t outlen = sizeof(out);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(k, NULL);
    int r;

    EVP_PKEY_decrypt_init(c);
    if (pad != NULL)
        EVP_PKEY_CTX_ctrl_str(c, "rsa_padding_mode", pad);
    if (!implicit)
        EVP_PKEY_CTX_ctrl_str(c, "rsa_pkcs1_implicit_rejection", "0");
    r = EVP_PKEY_decrypt(c, out, &outlen, in, (size_t)n);
    if (any)
        check(r == 1, what);
    else if (want != NULL)
        check(r == 1 && outlen == (size_t)wn && (wn == 0 || memcmp(out, w, (size_t)wn) == 0),
              what);
    else
        check(r <= 0, what);
    if (r == 1)
        hex("plaintext", out, outlen);
    errors();
    EVP_PKEY_CTX_free(c);
    OPENSSL_free(in);
    OPENSSL_free(w);
}

static void test_cipher(EVP_PKEY *k)
{
    const char *pads[] = { "pkcs1", "oaep" };
    unsigned char big[300] = { 0 }, out[256];
    size_t i, ol = sizeof(out), need = 0;
    EVP_PKEY_CTX *c;
    OSSL_PARAM p[3];
    int pad = 7;
    unsigned int ver = 0x0303;
    long n;
    unsigned char *in;

    printf("# asymmetric cipher\n");
    for (i = 0; i < sizeof(IMPLICIT) / sizeof(IMPLICIT[0]); i++)
        decrypt(k, NULL, IMPLICIT[i][0], 1, IMPLICIT[i][1], "decrypt, implicit rejection");
    decrypt(k, NULL, IMPLICIT[1][0], 0, NULL, "a bad padding without implicit rejection");
    decrypt(k, "oaep", CT_OAEP, 1, "616263", "decrypt OAEP");
    decrypt(k, "oaep", IMPLICIT[0][0], 1, NULL, "a bad OAEP padding");
    decrypt(k, "none", IMPLICIT[0][0], 1, "*", "decrypt without padding");

    for (i = 0; i < 2; i++) {
        unsigned char ct[256], pt[256];
        size_t ctlen = sizeof(ct), ptlen = sizeof(pt);
        int r1, r2;

        c = EVP_PKEY_CTX_new(k, NULL);
        EVP_PKEY_encrypt_init(c);
        EVP_PKEY_CTX_ctrl_str(c, "rsa_padding_mode", pads[i]);
        r1 = EVP_PKEY_encrypt(c, ct, &ctlen, (const unsigned char *)"hello", 5);
        EVP_PKEY_CTX_free(c);
        c = EVP_PKEY_CTX_new(k, NULL);
        EVP_PKEY_decrypt_init(c);
        EVP_PKEY_CTX_ctrl_str(c, "rsa_padding_mode", pads[i]);
        r2 = EVP_PKEY_decrypt(c, pt, &ptlen, ct, ctlen);
        printf("  %s\n", pads[i]);
        check(r1 == 1 && ctlen == 256 && r2 == 1 && ptlen == 5 && memcmp(pt, "hello", 5) == 0,
              "encryption round trip");
        errors();
        EVP_PKEY_CTX_free(c);
    }

    c = EVP_PKEY_CTX_new(k, NULL);
    EVP_PKEY_encrypt_init(c);
    check(EVP_PKEY_encrypt(c, out, &ol, big, 250) <= 0, "too long to encrypt");
    errors();
    EVP_PKEY_CTX_ctrl_str(c, "rsa_padding_mode", "none");
    check(EVP_PKEY_encrypt(c, out, &ol, big, 10) <= 0, "too short for no padding");
    errors();
    ol = 10;
    check(EVP_PKEY_encrypt(c, out, &ol, big, 256) == 0, "an output buffer too small");
    errors();
    check(EVP_PKEY_encrypt(c, NULL, &need, big, 256) == 1 && need == 256, "the size query");
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new(k, NULL);
    EVP_PKEY_decrypt_init(c);
    p[0] = OSSL_PARAM_construct_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, &pad);
    p[1] = OSSL_PARAM_construct_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, &ver);
    p[2] = OSSL_PARAM_construct_end();
    check(EVP_PKEY_CTX_set_params(c, p) == 1, "the TLS premaster mode");
    in = OPENSSL_hexstr2buf(IMPLICIT[0][0], &n);
    ol = sizeof(out);
    check(EVP_PKEY_decrypt(c, out, &ol, in, (size_t)n) == 1 && ol == 48,
          "a bad premaster gives a random one");
    errors();
    OPENSSL_free(in);
    EVP_PKEY_CTX_free(c);
}

static const unsigned char msg[] = "the quick brown fox";

/* The context's algorithm identifier, pad mode, digests, and salt length. */
static void ctx_params(EVP_PKEY_CTX *c)
{
    unsigned char buf[200];
    char pad[30] = "", md[30] = "", mgf[30] = "", sl[30] = "";
    OSSL_PARAM p[5], q[2];
    int r;

    p[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, buf, sizeof(buf));
    p[1] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, pad, sizeof(pad));
    p[2] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, md, sizeof(md));
    p[3] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, mgf, sizeof(mgf));
    p[4] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_get_params(c, p);
    printf("  params %d pad=%s md=%s mgf1=%s\n", r, pad, md, mgf);
    if (r == 1)
        hex("algorithm-id", buf, p[0].return_size);
    errors();
    q[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, sl, sizeof(sl));
    q[1] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_get_params(c, q);
    printf("  saltlen %d %s\n", r, sl);
    errors();
}

static void set_rsa(EVP_PKEY_CTX *c, const char *pad, const char *saltlen, const char *mgf1)
{
    if (pad != NULL)
        printf("  pad mode %d\n", EVP_PKEY_CTX_ctrl_str(c, "rsa_padding_mode", pad));
    if (saltlen != NULL)
        printf("  salt length %d\n", EVP_PKEY_CTX_ctrl_str(c, "rsa_pss_saltlen", saltlen));
    if (mgf1 != NULL)
        printf("  mgf1 digest %d\n", EVP_PKEY_CTX_ctrl_str(c, "rsa_mgf1_md", mgf1));
    errors();
}

/* A message signed and verified with the digest `md`; `ok` is whether signing works. */
static void digest_sign(EVP_PKEY *k, const char *md, const char *pad, const char *saltlen,
                        const char *mgf1, int ok)
{
    unsigned char sig[512];
    size_t sl = sizeof(sig);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    int random = (pad != NULL && strcmp(pad, "pss") == 0) || EVP_PKEY_is_a(k, "RSA-PSS");
    int r;

    printf("# digest sign %s pad %s salt %s mgf1 %s\n", str(md), str(pad), str(saltlen),
           str(mgf1));
    r = EVP_DigestSignInit_ex(m, &pc, md, NULL, NULL, k, NULL) == 1;
    if (r) {
        set_rsa(pc, pad, saltlen, mgf1);
        r = EVP_DigestSign(m, sig, &sl, msg, sizeof(msg) - 1) == 1;
    }
    check(r == ok, ok ? "signs" : "doesn't sign");
    errors();
    if (r && !random)
        hex("signature", sig, sl);
    else if (r)
        printf("  length %zu\n", sl);
    if (pc != NULL)
        ctx_params(pc);
    EVP_MD_CTX_free(m);
    if (!r)
        return;

    m = EVP_MD_CTX_new();
    pc = NULL;
    EVP_DigestVerifyInit_ex(m, &pc, md, NULL, NULL, k, NULL);
    set_rsa(pc, pad, saltlen, mgf1);
    check(EVP_DigestVerify(m, sig, sl, msg, sizeof(msg) - 1) == 1, "verifies");
    errors();
    sig[5] ^= 1;
    check(EVP_DigestVerify(m, sig, sl, msg, sizeof(msg) - 1) <= 0, "a changed signature fails");
    /* A changed PSS signature's first error depends on the random signature. */
    if (random)
        ERR_clear_error();
    errors();
    EVP_MD_CTX_free(m);
}

/*
 * The digest-sized `tbs` signed with EVP_PKEY_sign (with the composite algorithm `alg` or the
 * key's), verified, and recovered; `ok` is whether signing works.
 */
static void pkey_sign(EVP_PKEY *k, const char *alg, const EVP_MD *md, const char *pad,
                      size_t tbslen, int ok)
{
    unsigned char tbs[64], sig[512], rec[512];
    size_t i, sl = sizeof(sig), rl = sizeof(rec), q = 0;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(k, NULL);
    EVP_SIGNATURE *s = alg != NULL ? EVP_SIGNATURE_fetch(NULL, alg, NULL) : NULL;
    int random = (pad != NULL && strcmp(pad, "pss") == 0) || EVP_PKEY_is_a(k, "RSA-PSS");
    int r;

    for (i = 0; i < sizeof(tbs); i++)
        tbs[i] = (unsigned char)(i * 7);
    printf("# sign %s digest %s pad %s length %zu\n", str(alg),
           md != NULL ? EVP_MD_get0_name(md) : "-", str(pad), tbslen);
    r = alg != NULL ? EVP_PKEY_sign_init_ex2(c, s, NULL) : EVP_PKEY_sign_init(c);
    check(r == 1, "sign init");
    set_rsa(c, pad, NULL, NULL);
    if (md != NULL)
        printf("  digest %d\n", EVP_PKEY_CTX_set_signature_md(c, md));
    errors();
    check(EVP_PKEY_sign(c, NULL, &q, tbs, tbslen) == 1 && q == 256, "the size query");
    r = EVP_PKEY_sign(c, sig, &sl, tbs, tbslen) == 1;
    check(r == ok, ok ? "signs" : "doesn't sign");
    errors();
    if (r && !random)
        hex("signature", sig, sl);
    ctx_params(c);
    EVP_PKEY_CTX_free(c);
    if (r) {
        c = EVP_PKEY_CTX_new(k, NULL);
        if (alg != NULL)
            EVP_PKEY_verify_init_ex2(c, s, NULL);
        else
            EVP_PKEY_verify_init(c);
        set_rsa(c, pad, NULL, NULL);
        if (md != NULL)
            EVP_PKEY_CTX_set_signature_md(c, md);
        check(EVP_PKEY_verify(c, sig, sl, tbs, tbslen) == 1, "verifies");
        check(EVP_PKEY_verify(c, sig, sl, tbs, tbslen - 1) <= 0, "a shorter input fails");
        errors();
        EVP_PKEY_CTX_free(c);

        c = EVP_PKEY_CTX_new(k, NULL);
        r = alg != NULL ? EVP_PKEY_verify_recover_init_ex2(c, s, NULL)
                        : EVP_PKEY_verify_recover_init(c);
        printf("  recover init %d\n", r);
        set_rsa(c, pad, NULL, NULL);
        if (md != NULL)
            EVP_PKEY_CTX_set_signature_md(c, md);
        r = EVP_PKEY_verify_recover(c, rec, &rl, sig, sl);
        printf("  recover %d\n", r);
        if (r == 1)
            hex("recovered", rec, rl);
        merge_padding_reasons = random;
        errors();
        merge_padding_reasons = 0;
        rl = 3;
        printf("  recover into 3 octets %d\n", EVP_PKEY_verify_recover(c, rec, &rl, sig, sl));
        errors();
        EVP_PKEY_CTX_free(c);
    }
    EVP_SIGNATURE_free(s);
}

/* A message signed and verified with the composite algorithm `alg`, in pieces and at once. */
static void message_sign(EVP_PKEY *k, const char *alg, size_t mdlen, int ok)
{
    unsigned char sig[512], digest[64] = { 1 };
    size_t sl = sizeof(sig);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(k, NULL);
    EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, alg, NULL);
    int r;

    printf("# message sign %s\n", alg);
    r = EVP_PKEY_sign_message_init(c, s, NULL) == 1;
    check(r == ok, ok ? "sign message init" : "no sign message init");
    errors();
    if (!r) {
        EVP_PKEY_CTX_free(c);
        EVP_SIGNATURE_free(s);
        return;
    }
    check(EVP_PKEY_sign_message_update(c, msg, 5) == 1
          && EVP_PKEY_sign_message_update(c, msg + 5, sizeof(msg) - 6) == 1
          && EVP_PKEY_sign_message_final(c, sig, &sl) == 1, "signs in pieces");
    hex("signature", sig, sl);
    errors();
    check(EVP_PKEY_sign_message_final(c, sig, &sl) <= 0, "no second final");
    errors();
    ctx_params(c);
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new(k, NULL);
    check(EVP_PKEY_verify_message_init(c, s, NULL) == 1
          && EVP_PKEY_CTX_set_signature(c, sig, sl) == 1
          && EVP_PKEY_verify_message_update(c, msg, sizeof(msg) - 1) == 1
          && EVP_PKEY_verify_message_final(c) == 1, "verifies in pieces");
    errors();
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new(k, NULL);
    check(EVP_PKEY_verify_message_init(c, s, NULL) == 1
          && EVP_PKEY_verify(c, sig, sl, msg, sizeof(msg) - 1) == 1, "verifies at once");
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new(k, NULL);
    EVP_PKEY_verify_message_init(c, s, NULL);
    check(EVP_PKEY_verify(c, sig, sl, msg, sizeof(msg) - 2) <= 0, "another message fails");
    errors();
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new(k, NULL);
    EVP_PKEY_sign_init_ex2(c, s, NULL);
    sl = sizeof(sig);
    r = EVP_PKEY_sign(c, sig, &sl, digest, mdlen);
    check(r == 1, "signs a digest");
    hex("signature", sig, sl);
    errors();
    EVP_PKEY_CTX_free(c);
    EVP_SIGNATURE_free(s);
}

static void names(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s", p->key);
    printf("\n");
}

static void test_signatures(EVP_PKEY *k)
{
    const char *mds[] = {
        "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA512-224", "SHA512-256", "SHA3-224",
        "SHA3-256", "SHA3-384", "SHA3-512", "MD5", "MD5-SHA1", "SM3"
    };
    const struct {
        const char *name;
        size_t mdlen;
    } algs[] = {
        { "RSA-SHA1", 20 }, { "RSA-SHA256", 32 }, { "RSA-SHA512", 64 }, { "RSA-SHA3-256", 32 },
        { "RSA-RIPEMD160", 20 }, { "RSA-SM3", 32 }, { "RSA-SHA2-512/224", 28 },
        { "sha384WithRSAEncryption", 48 }
    };
    EVP_MD_CTX *m, *m2;
    EVP_SIGNATURE *s;
    unsigned char a[256], b[256];
    size_t i, al = sizeof(a), bl = sizeof(b);

    for (i = 0; i < sizeof(mds) / sizeof(mds[0]); i++)
        digest_sign(k, mds[i], NULL, NULL, NULL, 1);
    digest_sign(k, "SHAKE128", NULL, NULL, NULL, 0);
    digest_sign(k, "BLAKE2b512", NULL, NULL, NULL, 0);
    digest_sign(k, NULL, NULL, NULL, NULL, 1);
    digest_sign(k, "SHA256", "pss", NULL, NULL, 1);
    digest_sign(k, "SHA256", "pss", "digest", "SHA1", 1);
    digest_sign(k, "SHA256", "pss", "max", NULL, 1);
    digest_sign(k, "SHA256", "pss", "20", "SHA512", 1);
    digest_sign(k, "SHA512", "pss", "auto", NULL, 1);
    digest_sign(k, "SHA256", "pss", "-5", NULL, 1);
    digest_sign(k, "SHA256", "pss", "1000", NULL, 0);
    digest_sign(k, "SHA256", "x931", NULL, NULL, 1);
    digest_sign(k, "SHA1", "x931", NULL, NULL, 1);
    digest_sign(k, "SHA256", "none", NULL, NULL, 0);
    digest_sign(k, "SHA256", "oaep", NULL, NULL, 1);
    digest_sign(k, "SHA256", "pkcs1", "20", NULL, 1);
    digest_sign(k, "SHA256", "pkcs1", NULL, "SHA1", 1);

    pkey_sign(k, NULL, NULL, NULL, 20, 1);
    pkey_sign(k, NULL, EVP_sha256(), NULL, 32, 1);
    pkey_sign(k, NULL, EVP_sha256(), NULL, 20, 0);
    pkey_sign(k, NULL, EVP_sha1(), NULL, 20, 1);
    pkey_sign(k, NULL, EVP_md5_sha1(), NULL, 36, 1);
    pkey_sign(k, NULL, EVP_sha256(), "pss", 32, 1);
    pkey_sign(k, NULL, EVP_sha256(), "x931", 32, 1);
    pkey_sign(k, NULL, NULL, "none", 64, 0);
    pkey_sign(k, NULL, NULL, "x931", 32, 1);
    pkey_sign(k, "RSA-SHA256", NULL, NULL, 32, 1);
    pkey_sign(k, "RSA-SHA1", NULL, NULL, 20, 1);
    pkey_sign(k, "RSA-SHA256", NULL, "pss", 32, 1);

    for (i = 0; i < sizeof(algs) / sizeof(algs[0]); i++)
        message_sign(k, algs[i].name, algs[i].mdlen, 1);

    printf("# a copy mid-message\n");
    m = EVP_MD_CTX_new();
    EVP_DigestSignInit_ex(m, NULL, "SHA256", NULL, NULL, k, NULL);
    EVP_DigestSignUpdate(m, msg, 4);
    m2 = EVP_MD_CTX_dup(m);
    EVP_DigestSignUpdate(m, msg + 4, sizeof(msg) - 5);
    EVP_DigestSignUpdate(m2, msg + 4, sizeof(msg) - 5);
    check(EVP_DigestSignFinal(m, a, &al) == 1 && EVP_DigestSignFinal(m2, b, &bl) == 1
          && al == bl && memcmp(a, b, al) == 0, "a copy signs the same");
    al = sizeof(a);
    check(EVP_DigestSignFinal(m, a, &al) == 1, "a final leaves the context usable");
    errors();
    EVP_MD_CTX_free(m);
    EVP_MD_CTX_free(m2);

    printf("# parameter lists\n");
    s = EVP_SIGNATURE_fetch(NULL, "RSA", NULL);
    check(s != NULL, "fetch RSA");
    names("settable", EVP_SIGNATURE_settable_ctx_params(s));
    names("gettable", EVP_SIGNATURE_gettable_ctx_params(s));
    EVP_SIGNATURE_free(s);
    s = EVP_SIGNATURE_fetch(NULL, "RSA-SHA256", NULL);
    check(s != NULL, "fetch RSA-SHA256");
    names("settable", EVP_SIGNATURE_settable_ctx_params(s));
    EVP_SIGNATURE_free(s);
}

static void test_pss_keys(void)
{
    EVP_PKEY *pk, *rk;

    printf("# RSA-PSS keys\n");
    pk = make_key("RSA-PSS", 0);
    digest_sign(pk, "SHA256", NULL, NULL, NULL, 1);
    digest_sign(pk, "SHA256", "pkcs1", NULL, NULL, 1);
    pkey_sign(pk, NULL, EVP_sha256(), NULL, 32, 1);

    printf("# a restricted RSA-PSS key\n");
    rk = make_key("RSA-PSS", 30);
    digest_sign(rk, "SHA256", NULL, NULL, NULL, 1);
    digest_sign(rk, "SHA1", NULL, NULL, NULL, 0);
    digest_sign(rk, "SHA256", NULL, "20", NULL, 1);
    digest_sign(rk, "SHA256", NULL, "40", NULL, 1);
    digest_sign(rk, "SHA256", NULL, "digest", NULL, 1);
    digest_sign(rk, "SHA256", NULL, NULL, "SHA384", 1);
    digest_sign(rk, "SHA256", NULL, NULL, "SHA256", 1);
    digest_sign(rk, NULL, NULL, NULL, NULL, 1);
    pkey_sign(rk, NULL, NULL, NULL, 32, 1);
    message_sign(rk, "RSA-SHA256", 32, 0);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(rk);
}

int main(void)
{
    EVP_PKEY *k = make_key("RSA", 0);

    test_keymgmt(k);
    test_cipher(k);
    test_signatures(k);
    test_pss_keys();
    EVP_PKEY_free(k);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
