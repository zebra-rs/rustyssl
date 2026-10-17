/*
 * Conformance test for decoding post-quantum keys (d2i_AutoPrivateKey(3), d2i_PrivateKey,
 * d2i_PUBKEY, EVP_PKCS82PKEY(3)) through the default provider's ML-KEM, ML-DSA, and SLH-DSA
 * decoders, in TAP format: each parameter set's PrivateKeyInfo and SubjectPublicKeyInfo,
 * compared and used (signed and verified, or encapsulated to and decapsulated); ML-KEM-512's
 * and ML-DSA-44's private-key formats (seed and expanded key, seed only, expanded key only,
 * the key pair, the bare seed and key); the providers' input formats and seed preference set
 * by configuration; keys whose seed and expanded key disagree; and malformed encodings, with
 * their errors.
 *
 * The fixtures were made with the reference's openssl genpkey and pkey (with its
 * output_formats parameters), and are kept here in base64.
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
#include <openssl/provider.h>
#include <openssl/x509.h>

static const char ml_kem_512_spki[] =
    "MIIDMjALBglghkgBZQMEBAEDggMhAN1xBtuGmK+jPiFHpXGUAM5rp0gwvC0rgCCSmxlMl1maMeiQVjDor2Yhhuh8LtT0T6rS"
    "Jb8mNnpiH/nwhJBUshTRJiqJOKnQb3ElCrvgnE/bnP36QMMRgAOwQE93dfbcTBrhRQW7gzKId7TlYybDvEI0JnQLkDkgG9aF"
    "GmrZdT4gdNlHywhnaWKhyvzwtV75apwxYc0bhfvLeLZXDpHgP5G5E2j4BukbkONje7apAqwrQnHLryxXxVv5FQtRB5nsog6y"
    "NySXWTGUBi9wl9L8xwMKwfWsClf3lgUpMUprHObTnYlRMB8Xq7rTvyl5p+J8RFbSl6szBOnQlcuVxnocsFTxRp9Uwd02LyOM"
    "JbsFx1j4CQxmoo13JnMiDXEZEi58bYNWPuRSS0zMYtqGFYVCzNq0x+GJSsQFDlUhaQHIvfBHRjQsMZMsQk47ky0zv7nIqbex"
    "nZe7lNXBV/f2WScBhSUinJnnDgbFYnZWPYibR0dQqzo7aMvCorCcjrxpWma4dvHEF98Cx/r8pGwkvmtyes4Rup9KeULUkPHM"
    "z9b5URz3MaQhPC70gnbbJmhkyTl1KNnMm83azhi7PuzLgogjUtVAMEWBd0z5p6pxhQjXLq6qplYZsdwEe6oCezGmRY4HmFoT"
    "T6zpvky8z0nBVCCbsrkVnunKnI9FLd85F+sMxYoBJ97Tl60pkilyuoTknBZiMGMzjf5YH8egrpcxNw3ac6Gpw7RZnIriGGlR"
    "jyqrVyHoD7ccD8HTWDp8zYl5dfLIy/fVmh1VNXNgd6eTl1vWbUF0AkWhfWx0Tq36vr28KK+bzkqypWMTL5C8z7uxD3OhIAuS"
    "qoFqDYraBZLJb1JaBntpryEqvSCXmC/LT5lEnvxIT+BzKnBTVctqumvsX/oHMx3xhPZ7Af5RJDTSLGJiFPbSmiNUbCTksi+E"
    "yo6cFN0Qg7hbXnLqmRNUiJaEqal5rKQHMTGRUi8osfMAKexosxIkSDY6SnXrWrDHfdEGUweKQLowZwj2kCCidkMXoGTcBkll"
    "M8O70woDroLFsDv50PseaEoR0YgIGNqQUKL0ZOCF";
#define ml_kem_512_spki_len 822

static const char ml_kem_512_p8[] =
    "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"
    "Rsc=";
#define ml_kem_512_p8_len 1730

static const char ml_kem_768_spki[] =
    "MIIEsjALBglghkgBZQMEBAIDggShAHxUw4fGOI9CeeRCHmScs8OgWNeaTfeVgn+kvA/CMSrmAVs4CKURSrYFXok7CKBMMi+l"
    "Bzdxw+rTsnu5PEwyeKfyidunuqoCzRxSDwKUXZQJp+OQwFsUl3cTGVXRsrHjMe/VQn+pb7hzq5DXyEswHVmmcAvTSnwhg32Y"
    "BjHbrbwUPdL6qHRQQ77mk8BEgKAYSlg6gacpPZsSzQDyWLzwkYkmVjYFVz1wdIPIONqxI/DMqoAxGsjGKQJ7HRUIL1hZxgk5"
    "GXgwF9JnvhhlveLGqyZFnb0WDYYYTnLjBp5gfzdlan57lAUXGZCxA7HcC9BoukgjafHiv8L8jMVXwrkrlLL8etEitC3Mjc2G"
    "YkuMiTwFRxcFsAEAIpXqdID1qzyxj2BcWrjaAOEgHAt7F9hAorRXyuoqmW8FNgcXoXtGT1pQUvgGkXFymJqyqO4bUTQaKI14"
    "tH+JN5BlrgQTEqmRylFbXNfbepScCbyknZZTfeIH0OQJiiiwdd9XZN65zXXRxyasN6TAnEuzqYGpFt80MwAcQdDwY8cCFy0s"
    "XmB0XGGBKsvoFI4ZMDriRXWoHi9XJe16OWOynDXyjAg0L3hBTtDMDVn2dplJxEPZoXjRfQicvrppCPODoC8beZHczxQBYZyi"
    "qxhVUCNoLQurg9iwy0IARQJXD7kRREJlO+qHlbM8l+R8d1qSN5Y5FljrWcvBtu3Kxw/DNbFlK+V5FJNha8DyOO5GrE/mLfbD"
    "otKnHWWaBHvFMDQ7MTh1yCWic2R3FQssSCxFFVMTgXP1v1xskP1JRrn5ABV8ZF1bevZDCMIUkTbrb+H3Lgcwe7VGGI2jxY8a"
    "hLMKckF4RlQkErE2ktewhgJWO/goagrsSUB6jUh1HrGsKmRcmdVBHTsonoZJSK0VdcPpUiZbXZ07aU+yfyDEFuWRXPwMDCKE"
    "R0bUHAIRXF5RiL7MLU6kOzZFlt+RjyGmI9ewsIFpX+sqJACLKTSxVxA3ww9VZe2QvVYMsqMUhsSSWfTpr5JUqb2mpBzIxjdz"
    "IWMivYmwB4QHMUfSNlnmpGVoX9uJqPEwnyf3ymdXV7Q6TP4YfSkEtNkMlGQDNzV8eOJkl6z3kV08bDc7dCpmLoNXO/ojus2o"
    "eXGkXH3hIAWFjERALYlnCBwbIjjEDaO2BRx4RWbGYiscxOtAmhYhCgtbImSII4YMKPO6M1CReQ9RHA+isze5wKlqKb98DS1r"
    "OvQXr8B5YNxKGoZXHpY5q+ikt9kofigDhfzntJAQavmTG0jyGJrzLFAcsQqRsnuCyhMxayNRHrtXwsl1d697isgzPYAAPeni"
    "i2xyFh5Uqalra/ORaXhqVDZ0dlv1S0tQdImRYDqcdIQMiSMxij5StQCyMo4CU/kDf+TkCui7jIX8dx31nyPiuSyojW0hHN4M"
    "qtuwvwgYCmEKIfKlvxb3N8TWhS+qZk95RFDIFeZ7usIxCXZZbAhKSAO7eiCMZiJXzMLaJsdGAg0ynnbWZQEFB93lVNPbmwp1"
    "jQjiEi7DxZVmpn9iQ/lcLN27wwPIjpoIk96+p3wuzximQTU0lKd1paJk3rcb37EU9MWoiE8G";
#define ml_kem_768_spki_len 1206

static const char ml_kem_768_p8[] =
    "MFQCAQAwCwYJYIZIAWUDBAQCBEKAQPbD99RqW2WImImyQBS+u2Xof8DlZMhnKwuBAy1u8c5iTCMA+qqx2w1XQ4UFi3IkfZ8J"
    "ovJeJGC6/hwG4Sp5BtU=";
#define ml_kem_768_p8_len 86

static const char ml_kem_1024_spki[] =
    "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"
    "cp990gIW";
#define ml_kem_1024_spki_len 1590

static const char ml_kem_1024_p8[] =
    "MFQCAQAwCwYJYIZIAWUDBAQDBEKAQIMdF3NcXr+6V1I1qt/99M+twQZFRAT/Icp2HES7rjnCVgCPyoUwA7xO9meqyh0Wy0vC"
    "CsmwRN0t+jKB1Z0mTCs=";
#define ml_kem_1024_p8_len 86

static const char ml_dsa_44_spki[] =
    "MIIFMjALBglghkgBZQMEAxEDggUhAI3iKN2E/ogWlG5R586EQin1sLsCmTsH9FYbvEJj4VPOzM+zJ9EGGUKqmmLthhyuHHRQ"
    "lLfirOdP/dB3Zbj2dTTHxXZ89WkuVreMHj0nvZ1D4f59T2j8M9e1HtfLfxj+s4emBoD0eRv3/FLMnc5wUk+IpfvVDGxxGvbO"
    "z2aSa+6TQmu669iAViIxNZz56B05ucbHFydj3B3Rd8FUfqNYFKSIL+TJA1wsuGdeyMbjmod1ikJX9zFEfbTxF9FcUI7c9H1M"
    "cMvLNIwxwKxj7+9MMMUWCy5JovKcV4WY3Lro8vN4IpeSfpUle5fWNhtRxdpuGeBQEUqlVyNd/grlDYnkknXkvoc7aUtn0J6o"
    "G0EMh2nJ4QpqPXprEU3q093yd5o1HhYou8OZ7HB773jFaE8oxmOHh02uZDsRXBmR03gaPjJYrs8XXD5h1AFHm5tbgHW0sWNt"
    "56F33QND+WeqZaQ8O7+DqWayCB9sQz0rJyyyokCkd7OS+UyZFUKU1SktgY+hhVO5kCgbfCuZqoWi2ZmjQRSwjJG+cBoPrTLD"
    "dJyq6QUI5ft8Obf6n6RozvWJH3ig318Niw1mT5b5k/Oac5wv8QtOYIsep36ZT/+w0Lz1yxQI+j1vMmh7zSOF2Q/8nfOFKFAg"
    "GwV7PdbTlvVYXrkwidbWOdT8ccQgPKSj5EahBLhOfnGqZafhVYTwceW4d/CKb3cR3Si+jkRSBXgQeePqIqBROfx7Z8TVx/0m"
    "m4mse9zOhGL69caXGFpK7meD2E/uRhDigUjlO0VAcDWQgVaU2uUM6F29VEDZOa0mgSxKoAxOW7dB64NNzz+fJi6q0X0x9vHJ"
    "ENUS5xtwV2E5oUPtbLLOYyTbTeRb4y4sROP1EgYlQ6tvAgERS7kpPsMBtuRHblOAikM2jmjjALMsUMTphkeSP5v+T+9NHClj"
    "fw0BexHUhvIG0OQDuKKo5RNk5+3y/lnNEaRK2BsuUNG0+KjmI1yHK3is3665VMvGApQ2xK/iVE5BiD7AbbL0k4uoEnguAImA"
    "9uiywxHkN3ZDgPexkexKnGqC2GrwQccpgPcclCGr0egx9GFhnEx15/CK7c9yeB+zBr/QL+SglLNymTI1c9rmHH9wYzimPdqJ"
    "gefcHHbs+/rQQa5u0hTH/bFrOTUbaujPb0VFh/g4vWmMjUR47G5f1N2AEV3WY7xBeY5NqKt1NeYdAXFajPLrzAP7viFp3YLR"
    "ByF5j6Q753SRXCX1vrjtTanT4CTw1Qc9q01w/oJ2/8FsAt5xwY/6I+LSWGhqqt6ch3y3ubjwvsfgduQtStZMWzWtOaDAlEuk"
    "H1yAsfaoVffxXBaE/ugurlDq7Rm/xQ8/Xsh18JINHGQEUWnoUz3LLYq/tvhuwE8COendPlQUQd8XGHhdEHNghkyYF6tbCh6p"
    "IUdu2kXgC5FKSAxegrttd3NfTsa13zukL/I8yoR8OdaaiVsS5e+qcGNuERUIh6lPwfx9JXI+nABfhA2gJ66fylysI3orN8T0"
    "aRsfzIrumXihoYHGkHBmrzLUWExxMN93GuBmfiYSzvNWXcZ3AQdccWOKdbvMKPnk8UkumOh4XPgx/a47Ve4yRgxNOzb3GrP+"
    "91Nu9ShQJBTzXo0fpCstdZpaXSCH93KkNuE9ax3hzT+fn4DnQ1Qxo/ztSSdGO4QOLSBeIK8cBQRUfaZ4by3L83rz9AqXkND2"
    "skdNtTCKcB8f/0i2+nKw0Fs57mKQFjHGsbk4/FGbq9NtmpBSU0o=";
#define ml_dsa_44_spki_len 1334

static const char ml_dsa_44_p8[] =
    "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";
#define ml_dsa_44_p8_len 2626

static const char ml_dsa_65_spki[] =
    "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";
#define ml_dsa_65_spki_len 1974

static const char ml_dsa_65_p8[] =
    "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIEOuA4x5E4aGTqzsCL/zKx4EMscYmv3vCfKvOj0wN7VZ";
#define ml_dsa_65_p8_len 54

static const char ml_dsa_87_spki[] =
    "MIIKMjALBglghkgBZQMEAxMDggohALluC9ryVQX1+VFJe8jN1+8fa3YpFq6Kb3cfe8P5ERdP/NzKwqQkIFs0YLh/CrP6KvzX"
    "7WRz/Ewg08RMCVEeTj9YREsnjFK0XOgQxkm5pMqf7Fs2nTZMScvHys4q4xeLaeGK0fUsHh7zfW3PC6cYQ1A6bL13QIASFrbY"
    "SQBM4bu/R6HXpXirtDlt9YnABn4PkQmSQKLNxoAeGj+GxOr5Ky8sPN6wKJ9lbsAVF8a95gNwB1IO9PPzxyBXJch4bKasQEDo"
    "4ibh2woGsIgMj08WVdxdCu2JSNWxuRrMp3wYX5xVu0lAlR1HatrSsprZkNEByvxv2g2eCm1sRzUZ1sBKEwP1G6rU1PeceAja"
    "j0vgLc0g7veNoix11PCjipf+ZMNIyaAErVQUicWT9D5EUsGvhSg7qfsRjUR/iKRUIS77sC7b0kQWn11kbbDFyktopYv8GIzA"
    "VDZ9ED1zR5xo3qXutkIE2ga/1+DJk3ccM3C/byy/+U+cGy3c6wVyNZZxN6gzLTKc+zBGr45Ougv3Uk51s37/GP/CS6M8CYkF"
    "slMkYYj4hvEzh9nx7CceZvORYfdIhjv4VDHODQoL4MSduSvLM65vFCIhd6baF065f0iNsk7gDynK1Z3IFb9nu7MOkUwZaIA3"
    "tNwkrgKya2d+k6j2In59XHTXWBXjjJluxbAE/wEiyNh+LXNXLMW+IXqQVVLjuJwsTsV+BOvRRlF+Xls2BHUcriXUbkcb8Ciu"
    "x+EBdcqQnTOxmLzYaqLQ2yLyNoBawKvu1ScvySDup/D8lUOGJo3l6HPEX0+My3dBjYfLmSXb8qRB/AG2F8XQ7DO7u9uX+tFp"
    "VfASIdOTf/7tYKWdMU3ewmXmAmambmvvcVq4cZtyeCqtdydRqq8F4tZuYPxCcHw4ekxFsm1SCfY22gY3W8l1+axVMbYhYLgE"
    "2cnyeKTpfJkGthootlAkFA7B8SpVEo1meu1DpoOrO7lPkkoYGhMvIZN+MPWDZPm7CXJnLglHgO+UZn/21YL7R9q4fPg4KR0/"
    "jJcoXdnXwbhh6h98s6kxexsK2QTC9xgoXvVnEiFvPfY17VMZfUimbsrvwt8WByuRvuv7JMqtu3j3Ce+/HKCqbygvLDAfkufE"
    "80XRtXzWcAaSdTI6gk6vUlMEOG2ZGIYg1/fDgl16UT1m3MCAb/AK8ro0ZfBeB28agm7/tmaxn2T6t6B6RPBmtkoY2zwHSHf1"
    "uOqsAHntqRrMw9NwrLiELD4ExuX8AV4wwl28RRAADBWHbiSdfbJMkGIoRBER+vZ+GGCkcc3n91YtgPmycj0UyGAtBc1K2y2n"
    "sOsAkkhctHWVLsdXmp29QzjaottWXW8YqrP78g1m8cSY8YZ1PayyNHicOV79UolBXxBLQ8pPmKfHBtDTaWxdz/bF/CY41yJq"
    "Ue40EtdSkOK9uxoGVJoI2Nyc5oFbEr4WKnhtx3yw/WB6bZtPNCrNSPqCA5mbg4nSvLvvYIJ5RcYMUS7Q+dl0evCsQNVGsCEg"
    "1UUW1pDUMcMCrBuJf/LRKD2hZUOrmvzRtQdUUxzDNvEzFIW9/BjyEMkgNewe1nwE5xKYnD9TILznO6/NkdOgZa49aN3YWub0"
    "GJilM7nS/mBZyQocLoGK6ArT3cvWdkViEHnG9QAyi7Y3q5iXUUr5w2+3hJJtZsN7F+7C6LDXo3Ww2uXU80oLubayR3a9Ercq"
    "kkd6uYkTFSrc4QyQHytXkrXf2o3XhIfzgqWJNx2cp5amNYjHYCa7ICJ9nHL1qnnw2cZqaMlJuWMcmc934VhCLN1PxMmhfEiN"
    "/OWNBFRpxLY86VIPppYjZaX86VNQ85EE5IuYMweG524XrEYvqo/ooUNU7b1zK0Wv/Y26LJEhkTOTWszXgvHjvQ+GLRcXxqbR"
    "Q2P5QyseU+l9+ZZ6X/j9fjRfi/0qhjfVlrQVOOHXuRJVf2meqxD/oZYAlgL92Uww5UADKTbcVyiQXRxNMminAVUlqzC6zC/K"
    "fSvQd7txawQC6/xbtwy0Yq6Zy5SF9I2FMekZxohYRZgB3nuE7A+7YAd9pRfMBwpc0kDMvNx4Kxv2tcpvk4uK2T14CXs8x9lx"
    "GrgDqGf7QsaZQMwTrQeobGPFmGKY2hZcFgfFcN+1XlZAIUZaYnxiGMdUoHoJf/p3z6jBFjJTGxDRKzyOA16lU+qulSd+OHF9"
    "FKQGV6wCTSN6eo74Sue+blvtDMBKr8MrybrtOxjXb6d/HDOPjGdm3XtJ5bebVqGgPnU+OoGvXfQqy0AB78SS86PkhjuAPZyx"
    "fFFOMDtN3a37aZ3EUUF1yh6cShAbb39KKyuuVXwPSS/9q70J+mpFrVnDiMBO7zcy7+DRhYtStWiz0ZPDvWbuUVhfz7PJ3XFA"
    "645VdcPmyXmnA8QkfaCnLyriwWA3VXa+1wznToRmClmTu9XQMo2AEs9M/oJEhy/3qEbLOo/wv/HgENgdkp8MxbmlXotebcup"
    "mLB1tQcCdIBkt6SHBjFsAzeiYYFUYJpbim+iZqt93ntLLPR/weF7aJmT7wQUh1jhr3El8bomn5VbxakG2NQY9VkDZYQXEqnF"
    "0jnL6BRqj8nDIPboU99PRU3hJ+cL8pmGTETnvi4OVe4p+tnOubEOm2DIOzBPSZ0lPXCYHIt0AC3YYuRyn/zUGPpAewDX1xuU"
    "vjQRBm13peBzo2yOrHU9ILkGiHzaQjlyMcdo9CpUOKSUikAAdxyExseKGVLB8VpHjX1pD2w0kQ2UKEtseDLOCyaD9cUS26uI"
    "3rFwXHTRzTE3l5XHpsyyrCO2uEgILqvE9v24lvXtOMnW3xls2xiaIlm0z3o5AyhjKNECZN+x8PCc8PtRIUygLqBumssz3KL+"
    "7DMXcDMAh9zIGPTo5E5OXU+4BfQXp3IDXLnzdhAfn+Fxiy2ZU3XYwNnnB+ek2SU+3Tnf9AZT3tTuJGXVyiZRi4IEKs8Qjib5"
    "8IKvqFvOSvik/kBdXihqHmNhneI+QYgADJtfupilyrAmHpvwQX7N2SjjNtAWLJRl7kjX9X9s9VcBWc0kQge/7KBFHCKqeVY4"
    "dl9IPjP0tFBdcbrL0V6Hr+Hz9KlLHy/Tq60rv/cEekHLfGbf7tz0BosM+JP0QCcfG3abiOv9X5WxxFNUaZ2ENG/Kncgjxwb9"
    "BjwojDiszji/8oz9UKeVnsm5JEWoA40L/Tu7WbqCJk4/j1nwX4y/DaLZWHG+6QgNr+mNVKS8r+2GW4Pq8SJAqEvABoi21PBk"
    "MuDIg47jLCgnWpkttQBnZdP01pUCHpN+qPRjDGGxBcGXbE4PNRR422P9AA+m8qIaDZPRZBzS6cVcpWOEnQUeDrqiC7aCLteX"
    "34wzhXLxo3QDayDNkX3n7HxUee6B+LM1O86+hTy359cV0XLl5J5a+NLKvKN0cN+eZsJnG1ON1bZLgOobKkW7VjcBwog/uOi1"
    "vfA/xx2H+3/tmBOVKGGpLphbFMfxiw==";
#define ml_dsa_87_spki_len 2614

static const char ml_dsa_87_p8[] =
    "MDQCAQAwCwYJYIZIAWUDBAMTBCKAICgIC8AESgQSj/2dlDd8GVx1GVTy5BwwldfK8CEAIY0X";
#define ml_dsa_87_p8_len 54

static const char slh_dsa_sha2_128s_spki[] =
    "MDAwCwYJYIZIAWUDBAMUAyEA1Ma69VsPYbTIheTg2jrrJOl6zE0b+mXbLmd5/YNpOqo=";
#define slh_dsa_sha2_128s_spki_len 50

static const char slh_dsa_sha2_128s_p8[] =
    "MFICAQAwCwYJYIZIAWUDBAMUBEB48mcf+8Hal1v4Ju+yHFJGCiZ8v4MR7zYF9ZkEFDvXQNTGuvVbD2G0yIXk4No66yTpesxN"
    "G/pl2y5nef2DaTqq";
#define slh_dsa_sha2_128s_p8_len 84

static const char slh_dsa_sha2_128f_spki[] =
    "MDAwCwYJYIZIAWUDBAMVAyEAzqcub6EHzodCdQJ/a7uvAWUwcyTdXRLYE0ASb7Yx6fo=";
#define slh_dsa_sha2_128f_spki_len 50

static const char slh_dsa_sha2_128f_p8[] =
    "MFICAQAwCwYJYIZIAWUDBAMVBECFNEh4a3YJypsaIh6iaM9Q/CScwUWn23DPPQXu+efRR86nLm+hB86HQnUCf2u7rwFlMHMk"
    "3V0S2BNAEm+2Men6";
#define slh_dsa_sha2_128f_p8_len 84

static const char slh_dsa_sha2_192s_spki[] =
    "MEAwCwYJYIZIAWUDBAMWAzEAcuJIqZI9JfXdX9jwgHjx3abs/zNefk5F3i5Snn9qh3VuGqSFJZt2mziqEJI+IcjA";
#define slh_dsa_sha2_192s_spki_len 66

static const char slh_dsa_sha2_192s_p8[] =
    "MHICAQAwCwYJYIZIAWUDBAMWBGDZNASqUTR6cSXATaD8VE4zV/c5g87ImJHGEbr+cJmtSy9gPH0Hll41gWBq7EckF9Ry4kip"
    "kj0l9d1f2PCAePHdpuz/M15+TkXeLlKef2qHdW4apIUlm3abOKoQkj4hyMA=";
#define slh_dsa_sha2_192s_p8_len 116

static const char slh_dsa_sha2_192f_spki[] =
    "MEAwCwYJYIZIAWUDBAMXAzEA7Kf2WQOSXWNu/Yln2MB9iFIUTtWqmvRogs/C2enIXyeBnhfuWFMhp6W7aCaDyhFT";
#define slh_dsa_sha2_192f_spki_len 66

static const char slh_dsa_sha2_192f_p8[] =
    "MHICAQAwCwYJYIZIAWUDBAMXBGA7hI2q2c57PZ2kC4kOEAaeDbO+CM6Iq+sq7BOVFk5FVSOkBAsMwy1tAxvL1Dv21izsp/ZZ"
    "A5JdY279iWfYwH2IUhRO1aqa9GiCz8LZ6chfJ4GeF+5YUyGnpbtoJoPKEVM=";
#define slh_dsa_sha2_192f_p8_len 116

static const char slh_dsa_sha2_256s_spki[] =
    "MFAwCwYJYIZIAWUDBAMYA0EAL766QyFQw1tohTduiw6PaGniGV7nekMYzjdaCB1gAlTvcZoUPUVAkaMWrXxa003I1dgeme3s"
    "twpaaiG+pZH7oQ==";
#define slh_dsa_sha2_256s_spki_len 82

static const char slh_dsa_sha2_256s_p8[] =
    "MIGTAgEAMAsGCWCGSAFlAwQDGASBgJze+bXx1H2VpY5HMLhqTIRV4l9k/K5WP+hOrU+z9Bth6niRdb+Hh2NqyaNrI2kdwGUE"
    "aYE/4A7AWbGVpq0sfr0vvrpDIVDDW2iFN26LDo9oaeIZXud6QxjON1oIHWACVO9xmhQ9RUCRoxatfFrTTcjV2B6Z7ey3Clpq"
    "Ib6lkfuh";
#define slh_dsa_sha2_256s_p8_len 150

static const char slh_dsa_sha2_256f_spki[] =
    "MFAwCwYJYIZIAWUDBAMZA0EA3JGNZ75s0rgl2hQd5i8D54eSDGgYspDMTWWb8NhhCu4ZcvSqftKABdivMKfV+R4IiyzouKEw"
    "rj/2168DP4Ne5g==";
#define slh_dsa_sha2_256f_spki_len 82

static const char slh_dsa_sha2_256f_p8[] =
    "MIGTAgEAMAsGCWCGSAFlAwQDGQSBgDOVT5ied+W/F3kGhzkJFQI0aY1jemEHtaYvYfVNjgZPDFbXsjMFpK+Y/4rFbSfbNCCx"
    "MveiZBLMUJB4mR5GGHLckY1nvmzSuCXaFB3mLwPnh5IMaBiykMxNZZvw2GEK7hly9Kp+0oAF2K8wp9X5HgiLLOi4oTCuP/bX"
    "rwM/g17m";
#define slh_dsa_sha2_256f_p8_len 150

static const char slh_dsa_shake_128s_spki[] =
    "MDAwCwYJYIZIAWUDBAMaAyEAoDfCbGmHBWIwg4lwZDlmqxmLUWAbCwTQjsvzCZb+Tew=";
#define slh_dsa_shake_128s_spki_len 50

static const char slh_dsa_shake_128s_p8[] =
    "MFICAQAwCwYJYIZIAWUDBAMaBEDsnKEr6Gvk+zsfmE5zprsA4lgdO8I+gCK1z0VcrHrvvaA3wmxphwViMIOJcGQ5ZqsZi1Fg"
    "GwsE0I7L8wmW/k3s";
#define slh_dsa_shake_128s_p8_len 84

static const char slh_dsa_shake_128f_spki[] =
    "MDAwCwYJYIZIAWUDBAMbAyEASDsWq1wHFSjX/MoEQoqmC0+OSgtAoXt6nOVnXxFIpEs=";
#define slh_dsa_shake_128f_spki_len 50

static const char slh_dsa_shake_128f_p8[] =
    "MFICAQAwCwYJYIZIAWUDBAMbBEC8su6uysCgnYT768LozHpPc3LzO8vk4fo4sNplhq+erEg7FqtcBxUo1/zKBEKKpgtPjkoL"
    "QKF7epzlZ18RSKRL";
#define slh_dsa_shake_128f_p8_len 84

static const char slh_dsa_shake_192s_spki[] =
    "MEAwCwYJYIZIAWUDBAMcAzEAQmrPFEKzBweB6szLenkxr9XRcGxF4ccyKbtaR4kJHknfQ8dlm3zGdjoJSLtjfhp3";
#define slh_dsa_shake_192s_spki_len 66

static const char slh_dsa_shake_192s_p8[] =
    "MHICAQAwCwYJYIZIAWUDBAMcBGCoavSBfswJnDwswDj61wpf4eVfgReri2Q/JPAbPH+eoprk3kobdKx5OsABIhOljb5Cas8U"
    "QrMHB4HqzMt6eTGv1dFwbEXhxzIpu1pHiQkeSd9Dx2WbfMZ2OglIu2N+Gnc=";
#define slh_dsa_shake_192s_p8_len 116

static const char slh_dsa_shake_192f_spki[] =
    "MEAwCwYJYIZIAWUDBAMdAzEA5ZwQa3zc9T40VHFpHu/EV05QLi/y9Mx+6VFcTCLpvAlw8tWcWaIolvRQOuw2cYb3";
#define slh_dsa_shake_192f_spki_len 66

static const char slh_dsa_shake_192f_p8[] =
    "MHICAQAwCwYJYIZIAWUDBAMdBGBlsDkoQVMIHC5xPSFA5rJ7H0mTlWlKn7g2Nll70cXNusqXXzv9VxwfO+yxT07N9ELlnBBr"
    "fNz1PjRUcWke78RXTlAuL/L0zH7pUVxMIum8CXDy1ZxZoiiW9FA67DZxhvc=";
#define slh_dsa_shake_192f_p8_len 116

static const char slh_dsa_shake_256s_spki[] =
    "MFAwCwYJYIZIAWUDBAMeA0EAYrU+w9ey/9FkGtUUsr3YySVi8/A4q2cPkYNw39QwbCSVWpGgT+rPe9FN9Q70tRlzgU1fqcNk"
    "/1eAmalAsLvbHQ==";
#define slh_dsa_shake_256s_spki_len 82

static const char slh_dsa_shake_256s_p8[] =
    "MIGTAgEAMAsGCWCGSAFlAwQDHgSBgNHY5XJyu4IQrCfbC77gZAPrFdWRVBarnTW5h0j2Q6zsbYAel3lJ6GhjBEsOlv8VC0gM"
    "7+qvrOJfpd4UvNYcisJitT7D17L/0WQa1RSyvdjJJWLz8DirZw+Rg3Df1DBsJJVakaBP6s970U31DvS1GXOBTV+pw2T/V4CZ"
    "qUCwu9sd";
#define slh_dsa_shake_256s_p8_len 150

static const char slh_dsa_shake_256f_spki[] =
    "MFAwCwYJYIZIAWUDBAMfA0EAIwtSn6tjqf9MoIWayB0R5ruQ7b45FvIZf4KRI/AbyBoT/HIIo/y6y8nYweCh2xn5AFtA0UUN"
    "RUv4SUZvWYECSA==";
#define slh_dsa_shake_256f_spki_len 82

static const char slh_dsa_shake_256f_p8[] =
    "MIGTAgEAMAsGCWCGSAFlAwQDHwSBgNv6FzfcPHuZQT5fs8voXvfU6sKYvT9wKvqSjanAwZbrpoAZRE/s8V51kRlysFq4ecpP"
    "xLaEuo7HfmPHjiChA2wjC1Kfq2Op/0yghZrIHRHmu5DtvjkW8hl/gpEj8BvIGhP8cgij/LrLydjB4KHbGfkAW0DRRQ1FS/hJ"
    "Rm9ZgQJI";
#define slh_dsa_shake_256f_p8_len 150

static const char ml_kem_512_seed_only[] =
    "MFQCAQAwCwYJYIZIAWUDBAQBBEKAQKc7qEkk5AZIFhW3+PL00W9gsGG9bovIlAE+P1VGelpcST41xhObuLNBmcFj379MQ/ak"
    "ZL9QeyRhK+hKBqTGRsc=";
#define ml_kem_512_seed_only_len 86

static const char ml_kem_512_priv_only[] =
    "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"
    "pMZGxw==";
#define ml_kem_512_priv_only_len 1660

static const char ml_kem_512_oqskeypair[] =
    "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"
    "0YgIGNqQUKL0ZOCF";
#define ml_kem_512_oqskeypair_len 2460

static const char ml_kem_512_bare_seed[] =
    "MFICAQAwCwYJYIZIAWUDBAQBBECnO6hJJOQGSBYVt/jy9NFvYLBhvW6LyJQBPj9VRnpaXEk+NcYTm7izQZnBY9+/TEP2pGS/"
    "UHskYSvoSgakxkbH";
#define ml_kem_512_bare_seed_len 84

static const char ml_kem_512_bare_priv[] =
    "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";
#define ml_kem_512_bare_priv_len 1656

static const char ml_dsa_44_seed_only[] =
    "MDQCAQAwCwYJYIZIAWUDBAMRBCKAIDQyuIo63Kf70TyE71Xyg9BQcJ0asbz4n7fvl7QljkAY";
#define ml_dsa_44_seed_only_len 54

static const char ml_dsa_44_priv_only[] =
    "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";
#define ml_dsa_44_priv_only_len 2588

static const char ml_dsa_44_oqskeypair[] =
    "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"
    "OPxRm6vTbZqQUlNK";
#define ml_dsa_44_oqskeypair_len 3900

static const char ml_dsa_44_bare_seed[] =
    "MDICAQAwCwYJYIZIAWUDBAMRBCA0MriKOtyn+9E8hO9V8oPQUHCdGrG8+J+375e0JY5AGA==";
#define ml_dsa_44_bare_seed_len 52

static const char ml_dsa_44_bare_priv[] =
    "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";
#define ml_dsa_44_bare_priv_len 2584

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

/* The fixture's octets (freed by the caller). */
static unsigned char *der_of(const char *b64, int len)
{
    unsigned char *out = malloc(strlen(b64));

    if (out != NULL && EVP_DecodeBlock(out, (const unsigned char *)b64, (int)strlen(b64)) < len) {
        free(out);
        out = NULL;
    }
    return out;
}

static void describe(const char *label, EVP_PKEY *pk)
{
    unsigned char buf[8192];
    size_t len = 0;

    printf("  %s:", label);
    if (pk == NULL) {
        printf(" NULL\n");
        return;
    }
    printf(" %s bits %d sec %d size %d", EVP_PKEY_get0_type_name(pk), EVP_PKEY_get_bits(pk),
           EVP_PKEY_get_security_bits(pk), EVP_PKEY_get_size(pk));
    if (EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY, buf, sizeof(buf), &len))
        printf(" pub %02x%02x%02x%02x(%zu)", buf[0], buf[1], buf[2], buf[3], len);
    printf(" priv %d",
           EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PRIV_KEY, buf, sizeof(buf), &len));
    printf(" seed %d\n",
           EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_ML_DSA_SEED, buf, sizeof(buf),
                                           &len)
           || EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_ML_KEM_SEED, buf, sizeof(buf),
                                              &len));
    ERR_clear_error();
}

/* The private key works with the public one: a signature verifies, or a secret decapsulates. */
static void use(EVP_PKEY *priv, EVP_PKEY *pub)
{
    static const unsigned char msg[] = "the message";
    unsigned char sig[50000], ct[2000], s1[64], s2[64];
    size_t siglen = sizeof(sig), ctlen = sizeof(ct), l1 = sizeof(s1), l2 = sizeof(s2);
    int ok;

    if (EVP_PKEY_is_a(priv, "ML-KEM-512") || EVP_PKEY_is_a(priv, "ML-KEM-768")
        || EVP_PKEY_is_a(priv, "ML-KEM-1024")) {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL);

        ok = EVP_PKEY_encapsulate_init(c, NULL) == 1
             && EVP_PKEY_encapsulate(c, ct, &ctlen, s1, &l1) == 1;
        EVP_PKEY_CTX_free(c);
        c = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL);
        ok = ok && EVP_PKEY_decapsulate_init(c, NULL) == 1
             && EVP_PKEY_decapsulate(c, s2, &l2, ct, ctlen) == 1 && l1 == l2
             && memcmp(s1, s2, l1) == 0;
        EVP_PKEY_CTX_free(c);
        printf("  encapsulate/decapsulate %d\n", ok);
    } else {
        EVP_MD_CTX *m = EVP_MD_CTX_new();

        ok = EVP_DigestSignInit_ex(m, NULL, NULL, NULL, NULL, priv, NULL) == 1
             && EVP_DigestSign(m, sig, &siglen, msg, sizeof(msg)) == 1;
        EVP_MD_CTX_free(m);
        m = EVP_MD_CTX_new();
        ok = ok && EVP_DigestVerifyInit_ex(m, NULL, NULL, NULL, NULL, pub, NULL) == 1
             && EVP_DigestVerify(m, sig, siglen, msg, sizeof(msg)) == 1;
        EVP_MD_CTX_free(m);
        printf("  sign/verify %d\n", ok);
    }
    ERR_clear_error();
}

struct fixture {
    const char *name;
    int sign; /* use it: SLH-DSA's small variants are slow to sign with */
    const char *p8;
    int p8len;
    const char *spki;
    int spkilen;
};

#define FX(n, s) { #n, s, n##_p8, n##_p8_len, n##_spki, n##_spki_len }

static const struct fixture fixtures[] = {
    FX(ml_kem_512, 1), FX(ml_kem_768, 1), FX(ml_kem_1024, 1),
    FX(ml_dsa_44, 1), FX(ml_dsa_65, 1), FX(ml_dsa_87, 1),
    FX(slh_dsa_sha2_128s, 0), FX(slh_dsa_sha2_128f, 1), FX(slh_dsa_sha2_192s, 0),
    FX(slh_dsa_sha2_192f, 0), FX(slh_dsa_sha2_256s, 0), FX(slh_dsa_sha2_256f, 0),
    FX(slh_dsa_shake_128s, 0), FX(slh_dsa_shake_128f, 1), FX(slh_dsa_shake_192s, 0),
    FX(slh_dsa_shake_192f, 0), FX(slh_dsa_shake_256s, 0), FX(slh_dsa_shake_256f, 0),
};

static void one_fixture(const struct fixture *f)
{
    unsigned char *p8 = der_of(f->p8, f->p8len), *spki = der_of(f->spki, f->spkilen);
    const unsigned char *p;
    EVP_PKEY *k, *pub, *k2;
    PKCS8_PRIV_KEY_INFO *inf;
    char what[128];

    printf("# %s\n", f->name);
    p = p8;
    k = d2i_AutoPrivateKey(NULL, &p, f->p8len);
    snprintf(what, sizeof(what), "%s: d2i_AutoPrivateKey", f->name);
    check(k != NULL && p == p8 + f->p8len, what);
    describe("priv", k);
    errors();
    p = spki;
    pub = d2i_PUBKEY(NULL, &p, f->spkilen);
    snprintf(what, sizeof(what), "%s: d2i_PUBKEY", f->name);
    check(pub != NULL && p == spki + f->spkilen, what);
    describe("pub", pub);
    printf("  eq %d\n", EVP_PKEY_eq(k, pub));
    errors();
    if (f->sign && k != NULL && pub != NULL)
        use(k, pub);
    p = p8;
    inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, f->p8len);
    k2 = EVP_PKCS82PKEY(inf);
    snprintf(what, sizeof(what), "%s: EVP_PKCS82PKEY", f->name);
    check(k2 != NULL && EVP_PKEY_eq(k2, pub) == 1, what);
    PKCS8_PRIV_KEY_INFO_free(inf);
    EVP_PKEY_free(k2);
    p = p8;
    k2 = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, f->p8len);
    check(k2 == NULL, "not as RSA");
    errors();
    EVP_PKEY_free(k);
    EVP_PKEY_free(pub);
    free(p8);
    free(spki);
}

struct format {
    const char *name;
    const char *b64;
    int len;
};

#define FMT(t, f) { #f, t##_##f, t##_##f##_len }

static const struct format kem_formats[] = {
    { "seed_priv", ml_kem_512_p8, ml_kem_512_p8_len },
    FMT(ml_kem_512, seed_only), FMT(ml_kem_512, priv_only), FMT(ml_kem_512, oqskeypair),
    FMT(ml_kem_512, bare_seed), FMT(ml_kem_512, bare_priv),
};

static const struct format dsa_formats[] = {
    { "seed_priv", ml_dsa_44_p8, ml_dsa_44_p8_len },
    FMT(ml_dsa_44, seed_only), FMT(ml_dsa_44, priv_only), FMT(ml_dsa_44, oqskeypair),
    FMT(ml_dsa_44, bare_seed), FMT(ml_dsa_44, bare_priv),
};

/* Each private-key format of a type in a library context, compared with the public key. */
static void formats(OSSL_LIB_CTX *libctx, const char *label, const struct format *fmts,
                    const char *spki_b64, int spkilen)
{
    unsigned char *spki = der_of(spki_b64, spkilen), *der;
    const unsigned char *p = spki;
    EVP_PKEY *pub = d2i_PUBKEY(NULL, &p, spkilen), *k;
    size_t i;

    printf("# %s formats\n", label);
    for (i = 0; i < 6; i++) {
        der = der_of(fmts[i].b64, fmts[i].len);
        p = der;
        k = d2i_AutoPrivateKey_ex(NULL, &p, fmts[i].len, libctx, NULL);
        printf("  %s: %s eq %d\n", fmts[i].name, k != NULL ? "decoded" : "refused",
               k != NULL ? EVP_PKEY_eq(k, pub) : -9);
        describe(fmts[i].name, k);
        errors();
        EVP_PKEY_free(k);
        free(der);
    }
    EVP_PKEY_free(pub);
    free(spki);
}

/* A library context whose default provider has the configuration parameters given. */
static OSSL_LIB_CTX *configured(const char *const *params, OSSL_PROVIDER **prov)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    size_t i;

    *prov = OSSL_PROVIDER_load(libctx, "default");
    for (i = 0; params[i] != NULL; i += 2)
        OSSL_PROVIDER_add_conf_parameter(*prov, params[i], params[i + 1]);
    return libctx;
}

static void configurations(void)
{
    static const char *const restricted[] = {
        "ml-kem.input_formats", "bare-seed, priv-only", "ml-dsa.input_formats", "OQS seed-o",
        NULL
    };
    static const char *const none[] = {
        "ml-kem.input_formats", "nothing", "ml-dsa.input_formats", ", ,", NULL
    };
    static const char *const no_seed[] = {
        "ml-kem.prefer_seed", "no", "ml-dsa.prefer_seed", "no", "ml-kem.retain_seed", "no",
        "ml-dsa.retain_seed", "no", NULL
    };
    OSSL_PROVIDER *prov;
    OSSL_LIB_CTX *libctx;

    printf("# configured input formats\n");
    libctx = configured(restricted, &prov);
    formats(libctx, "ML-KEM-512 (bare-seed, priv-only)", kem_formats, ml_kem_512_spki,
            ml_kem_512_spki_len);
    formats(libctx, "ML-DSA-44 (OQS seed-o)", dsa_formats, ml_dsa_44_spki, ml_dsa_44_spki_len);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
    libctx = configured(none, &prov);
    formats(libctx, "ML-KEM-512 (none)", kem_formats, ml_kem_512_spki, ml_kem_512_spki_len);
    formats(libctx, "ML-DSA-44 (none)", dsa_formats, ml_dsa_44_spki, ml_dsa_44_spki_len);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
    libctx = configured(no_seed, &prov);
    formats(libctx, "ML-KEM-512 (no seed)", kem_formats, ml_kem_512_spki, ml_kem_512_spki_len);
    formats(libctx, "ML-DSA-44 (no seed)", dsa_formats, ml_dsa_44_spki, ml_dsa_44_spki_len);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
}

/* The fixture with the octet at `at` changed (bit flips), decoded automatically. */
static void changed(const char *label, const char *b64, int len, int at, unsigned char x,
                    OSSL_LIB_CTX *libctx)
{
    unsigned char *der = der_of(b64, len);
    const unsigned char *p = der;
    EVP_PKEY *k;

    der[at < 0 ? len + at : at] ^= x;
    k = d2i_AutoPrivateKey_ex(NULL, &p, len, libctx, NULL);
    printf("  %s: %s\n", label, k != NULL ? "decoded" : "refused");
    errors();
    EVP_PKEY_free(k);
    free(der);
}

static void disagreements(void)
{
    static const char *const no_seed[] = {
        "ml-kem.prefer_seed", "no", "ml-dsa.prefer_seed", "no", NULL
    };
    OSSL_PROVIDER *prov;
    OSSL_LIB_CTX *libctx = configured(no_seed, &prov);

    printf("# seeds and keys that disagree\n");
    /* ML-KEM-512's seed-priv: the seed at 6 (z its last 32), dk at 74 (z its last 32). */
    changed("ML-KEM z", ml_kem_512_p8, ml_kem_512_p8_len, -1, 1, NULL);
    changed("ML-KEM dk", ml_kem_512_p8, ml_kem_512_p8_len, 80, 1, NULL);
    changed("ML-KEM seed d", ml_kem_512_p8, ml_kem_512_p8_len, 7, 1, NULL);
    changed("ML-KEM dk, no seed preferred", ml_kem_512_p8, ml_kem_512_p8_len, 80, 1, libctx);
    changed("ML-KEM dk's ek, no seed preferred", ml_kem_512_p8, ml_kem_512_p8_len, 74 + 768 + 5,
            1, libctx);
    changed("ML-KEM dk's hash, no seed preferred", ml_kem_512_p8, ml_kem_512_p8_len,
            74 + 1632 - 40, 1, libctx);
    changed("ML-KEM priv-only dk's s", ml_kem_512_priv_only, ml_kem_512_priv_only_len, 30, 0x55,
            NULL);
    /* ML-DSA-44's seed-priv: the seed at 6, sk at 42. */
    changed("ML-DSA sk", ml_dsa_44_p8, ml_dsa_44_p8_len, 60, 1, NULL);
    changed("ML-DSA seed", ml_dsa_44_p8, ml_dsa_44_p8_len, 7, 1, NULL);
    changed("ML-DSA sk, no seed preferred", ml_dsa_44_p8, ml_dsa_44_p8_len, 100, 1, libctx);
    changed("ML-DSA sk's tr, no seed preferred", ml_dsa_44_p8, ml_dsa_44_p8_len, 42 + 70, 1,
            libctx);
    changed("ML-DSA priv-only sk", ml_dsa_44_priv_only, ml_dsa_44_priv_only_len, 200, 0x10,
            NULL);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
}

static void malformed(void)
{
    unsigned char *der, *spki, buf[200];
    const unsigned char *p;
    EVP_PKEY *k;
    int n;

    printf("# malformed encodings\n");
    /* ML-KEM-512's seed-only PrivateKeyInfo with a NULL parameter. */
    der = der_of(ml_kem_512_seed_only, ml_kem_512_seed_only_len);
    n = ml_kem_512_seed_only_len;
    buf[0] = 0x30;
    buf[1] = (unsigned char)(der[1] + 2);
    memcpy(buf + 2, der + 2, 3);
    buf[5] = 0x30;
    buf[6] = 0x0d;
    memcpy(buf + 7, der + 7, 11);
    buf[18] = 0x05;
    buf[19] = 0x00;
    memcpy(buf + 20, der + 18, (size_t)(n - 18));
    p = buf;
    k = d2i_AutoPrivateKey(NULL, &p, n + 2);
    check(k == NULL, "ML-KEM with parameters");
    errors();
    free(der);
    /* The same for SLH-DSA-SHA2-128f. */
    der = der_of(slh_dsa_sha2_128f_p8, slh_dsa_sha2_128f_p8_len);
    n = slh_dsa_sha2_128f_p8_len;
    buf[0] = 0x30;
    buf[1] = (unsigned char)(der[1] + 2);
    memcpy(buf + 2, der + 2, 3);
    buf[5] = 0x30;
    buf[6] = 0x0d;
    memcpy(buf + 7, der + 7, 11);
    buf[18] = 0x05;
    buf[19] = 0x00;
    memcpy(buf + 20, der + 18, (size_t)(n - 18));
    p = buf;
    k = d2i_AutoPrivateKey(NULL, &p, n + 2);
    check(k == NULL, "SLH-DSA with parameters");
    errors();
    free(der);
    /* SLH-DSA-SHA2-128f's SubjectPublicKeyInfo: unused bits, a short key, another OID. */
    spki = der_of(slh_dsa_sha2_128f_spki, slh_dsa_sha2_128f_spki_len);
    spki[17] = 1;
    p = spki;
    k = d2i_PUBKEY(NULL, &p, slh_dsa_sha2_128f_spki_len);
    check(k == NULL, "SLH-DSA unused bits");
    errors();
    spki[17] = 0;
    spki[16] ^= 1;
    p = spki;
    k = d2i_PUBKEY(NULL, &p, slh_dsa_sha2_128f_spki_len);
    check(k == NULL, "SLH-DSA another OID");
    errors();
    spki[16] ^= 1;
    p = spki;
    k = d2i_PUBKEY(NULL, &p, slh_dsa_sha2_128f_spki_len - 1);
    check(k == NULL, "SLH-DSA truncated");
    errors();
    free(spki);
    /* ML-KEM-512's and ML-DSA-44's: the BIT STRING header changed, then truncated. */
    spki = der_of(ml_kem_512_spki, ml_kem_512_spki_len);
    spki[21] = 1;
    p = spki;
    k = d2i_PUBKEY(NULL, &p, ml_kem_512_spki_len);
    check(k == NULL, "ML-KEM unused bits");
    errors();
    spki[21] = 0;
    p = spki;
    k = d2i_PUBKEY(NULL, &p, ml_kem_512_spki_len - 1);
    check(k == NULL, "ML-KEM truncated");
    errors();
    free(spki);
    spki = der_of(ml_dsa_44_spki, ml_dsa_44_spki_len);
    spki[16] ^= 3;
    p = spki;
    k = d2i_PUBKEY(NULL, &p, ml_dsa_44_spki_len);
    check(k == NULL, "ML-DSA another variant's OID");
    errors();
    free(spki);
    /* ML-DSA-44's bare seed, one short. */
    der = der_of(ml_dsa_44_bare_seed, ml_dsa_44_bare_seed_len);
    der[1] = (unsigned char)(der[1] - 1);
    der[ml_dsa_44_bare_seed_len - 33] = 0x1f;
    p = der;
    k = d2i_AutoPrivateKey(NULL, &p, ml_dsa_44_bare_seed_len - 1);
    check(k == NULL, "ML-DSA a seed one short");
    errors();
    free(der);
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++)
        one_fixture(&fixtures[i]);
    formats(NULL, "ML-KEM-512", kem_formats, ml_kem_512_spki, ml_kem_512_spki_len);
    formats(NULL, "ML-DSA-44", dsa_formats, ml_dsa_44_spki, ml_dsa_44_spki_len);
    configurations();
    disagreements();
    malformed();
    printf("1..%d\n", number);
    return failures != 0;
}
