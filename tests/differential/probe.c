/*
 * Differential probe (TEST_PLAN.md, layer L5). Reads one command per line on stdin, runs it
 * against whichever libcrypto the dynamic loader picked, and prints a deterministic line per
 * command. `cargo xtask test-differential` runs the same input against the reference and
 * rustyssl and compares the output.
 *
 * Commands for BUF_MEM (one buffer at a time):
 *   new <flags>        BUF_MEM_new_ex(flags), replacing any current buffer
 *   grow <len>         BUF_MEM_grow
 *   grow_clean <len>   BUF_MEM_grow_clean
 *   fill <byte>        set every byte below `length` to <byte>
 *   dump               print `length` bytes of data in hex
 *   free               BUF_MEM_free
 *   reverse <hex>      BUF_reverse, copying and in place
 *
 * Commands for the error queue:
 *   errstr <code> <len>        ERR_error_string_n into a buffer of <len> bytes
 *   raise <lib> <reason>       ERR_raise
 *   data <word>                ERR_add_error_data with one string
 *   txt <sep> <len> <every>    ERR_add_error_txt with <len> bytes of text and the separator
 *                              (- for none) after every <every> bytes
 *   mark, pop, poptomark, clearmark, count, clear
 *                              ERR_set_mark, ERR_pop, ERR_pop_to_mark, ERR_clear_last_mark,
 *                              ERR_count_to_mark, ERR_clear_error
 *   get, peek, last            ERR_get_error_all, ERR_peek_error_all, ERR_peek_last_error_all
 *   save, savemark, restore    OSSL_ERR_STATE_save, _save_to_mark, _restore with one saved state
 *   state                      the thread's ERR_STATE, slot by slot (data as length and hash)
 *
 * Commands for a stack of pointers into a pool of 64 ints (pool[i] = i * 7 % 10, so values
 * repeat; elements print as pool indexes, so the order of equal values shows):
 *   sknew <cmp>                OPENSSL_sk_new: 0 no comparator, 1 by value, 2 reversed
 *   skcmp <cmp>                OPENSSL_sk_set_cmp_func
 *   skpush <i>, skunshift <i>, skinsert <i> <loc>, skset <loc> <i>, skdelptr <i>
 *   skdelete <loc>, skshift, skpop, skzero, sksort, skdup, skreserve <n>
 *   skfind <value>, skfindex <value>, skfindall <value>   (with the comparisons made)
 *   skdump                     the elements and the sorted flag
 *
 * Commands for a hash table of items keyed by number (pool indexes again):
 *   lhnew <hash>               lh_ITEM_new: 0 the key itself, 1 a multiplicative hash
 *   lhinsert <i>, lhdelete <i>, lhget <i>, lhdown <n>, lhdump (the doall order)
 *
 * Commands for a BIO (`_` in a word stands for a newline):
 *   bionew <kind>              0 memory, 1 secure memory, 2 read-only over a fixed text,
 *                              3 memory behind a null filter, 4 behind a buffer, 5 behind a
 *                              line buffer, 6 a read buffer over the fixed text, 7 memory
 *                              behind a prefix filter ("> ", indented 2), 8 one end of a BIO
 *                              pair (buffers of 16 and 32 bytes), 9 a datagram memory BIO,
 *                              10 one end of a datagram pair (default buffers)
 *   biopeer                    switch to the pair's other end
 *   biowrite <word>, bioputs <word>, bioread <n>, biogets <n>, bioline <n>
 *   bionread <n>, bionwrite <word>   BIO_nread and BIO_nwrite (what was read, or copied in)
 *   bioctrl <name> <n>         reset, eof, pending, wpending, seek, tell, eofret, setclose,
 *                              getclose, flush, info, shutdown, guarantee, request, lines,
 *                              bufsize, wbufsize, notrunc, mtu
 *   biomem                     BIO_get_mem_ptr: the buffer's length and a hash of its data
 *   biostate                   retry flags, bytes read and written
 *
 * Commands for OpenSSL's printf (`_` in a format stands for a space). Each argument is typed:
 * i:<int>, j:<64-bit int>, d:<double>, or s:<word> (s:- is a null string); at most three:
 *   printf <n> <format> <arg>...   BIO_snprintf into a buffer of <n> bytes (at most 100),
 *                                  printing the return and the first <n> + 1 bytes
 *   bioprintf <format> <arg>...    BIO_printf to a memory BIO, printing the return and what
 *                                  it wrote
 *
 * Commands for addresses (`_` in a spec stands for nothing, so `_` alone is the empty spec):
 *   hostserv <spec> <prio>     BIO_parse_hostserv with priority 0 (host) or 1 (service):
 *                              the result, host, and service, or the error's reason
 *   addr <family> <hex> <port> BIO_ADDR_rawmake (4 for AF_INET, 6 for AF_INET6, u for
 *                              AF_UNIX with the hex as the path), then the family, raw port,
 *                              raw address, and numeric host and service strings
 *
 * Other helpers:
 *   hexdecode <text> <sep>     OPENSSL_hexstr2buf_ex with the separator's code
 *   strtoul <text> <base>      OPENSSL_strtoul, with and without an end pointer
 *   tracecat <name> <num>      OSSL_trace_get_category_num and OSSL_trace_get_category_name
 *
 * Commands for objects (`-` for empty hex):
 *   objtxt <hex> <no_name>     OBJ_txt2obj of the text in hex: its NID, OBJ_obj2txt with names
 *                              and without, and a2d_ASN1_OBJECT of the text; or the error
 *   objder <hex>               an object with those content octets: OBJ_obj2nid, OBJ_obj2txt
 *                              with names and without, and i2a_ASN1_OBJECT
 *   objname <name>             OBJ_sn2nid, OBJ_ln2nid, and OBJ_txt2nid
 *
 * Commands for ASN.1 headers:
 *   asnhdr <hex> <delta>       ASN1_get_object on the octets with omax their count plus delta
 *                              (never more than the octets, past the header): the result, the
 *                              outputs (preset to -7), the octets used, and the errors
 *   asnput <cons> <len> <tag> <class>   ASN1_put_object and ASN1_object_size
 *   d2iobj <hex>               d2i_ASN1_OBJECT: the NID and text, the octets used, the errors,
 *                              and i2d_ASN1_OBJECT of the result
 *
 * Commands for INTEGER and ENUMERATED:
 *   asnint <type> <hex>        a string of that type and octets: the int64, uint64, long, and
 *                              ENUMERATED getters, i2a_ASN1_INTEGER, and the errors
 *   asnset <value>             ASN1_INTEGER_set_int64 and the octets stored
 *   a2iint <size> <hex>        a2i_ASN1_INTEGER on the text (in hex) with a buffer of <size>
 *   a2istr <size> <hex>        the same with a2i_ASN1_STRING, then i2a_ASN1_STRING of the result
 *                              (at most 300)
 *   asnbit <hex> <n> <value> <flags-hex>   a BIT STRING of those octets: ASN1_BIT_STRING_set_bit
 *                              of bit <n>, the octets after, get_bit around <n>, and
 *                              ASN1_BIT_STRING_check against the flags
 *
 * Commands for character strings:
 *   asntext <type> <flags> <hex>   a string of that type: ASN1_STRING_print_ex with <flags> (to a
 *                              BIO and counted), ASN1_STRING_to_UTF8, and the errors
 *   asnmb <inform> <mask> <min> <max> <hex>   ASN1_mbstring_ncopy: the type, the octets, the
 *                              errors
 *
 * Commands for times:
 *   asntime <type> <flags> <hex>   a string of that type, flags, and octets: the checks,
 *                              ASN1_TIME_to_tm, both printouts, ASN1_TIME_normalize, and the
 *                              difference from a fixed time
 *   asntimet <time> <days> <secs>  ASN1_TIME_adj, ASN1_UTCTIME_adj, ASN1_GENERALIZEDTIME_adj,
 *                              and OPENSSL_gmtime_adj of OPENSSL_gmtime
 *
 * Commands for the template engine:
 *   asnany <type>:<hex> ...    up to 8 ASN1_TYPEs (type -2 is a negative INTEGER, 1 a BOOLEAN
 *                              from the first octet, 6 an OBJECT from its content octets, `-`
 *                              for none): i2d_ASN1_TYPE of each, then i2d_ASN1_SEQUENCE_ANY and
 *                              i2d_ASN1_SET_ANY of them all
 *   asnd2i <item> <hex>        ASN1_item_d2i of the octets with item <item> (0 ANY, 1 SEQUENCE_ANY,
 *                              2 SET_ANY, 3 OCTET_STRING, 4 INTEGER, 5 BIT_STRING, 6 BMPSTRING,
 *                              7 TIME, 8 DIRECTORYSTRING, 9 INT64, 10 UINT32, 11 the probe's
 *                              PROBEREC, 12 ASN1_SEQUENCE, 13 UTF8STRING, 14 RSAPublicKey,
 *                              15 RSAPrivateKey, 16 RSA_PSS_PARAMS, 17 RSA_OAEP_PARAMS,
 *                              18 BIGNUM): how much was read
 *                              and the re-encoding and ASN1_item_print listing, or the errors with
 *                              their data
 *   asnbio <hex>               ASN1_item_d2i_bio (as ANY) from a memory BIO over the octets until
 *                              a read fails: each element's re-encoding, then the errors
 *   asnparse <indent> <dump> <hex>   ASN1_parse_dump of the octets (dump -2: ASN1_parse) to a
 *                              memory BIO: the return, the listing (escaped), and the errors
 *   asns2i <text>              s2i_ASN1_INTEGER of the text (`-` for none, `_` for a space), then
 *                              i2s_ASN1_INTEGER and the octets of what it made, and the errors
 *   b64enc <chunk> <hex>       EVP_EncodeUpdate of the octets in chunks, then EVP_EncodeFinal, and
 *                              EVP_EncodeBlock of them all: each step's return and output
 *   b64dec <chunk> <hex>       EVP_DecodeUpdate of the text (in hex) in chunks, then
 *                              EVP_DecodeFinal, and EVP_DecodeBlock of it all
 *   b64bio <enc> <nonl> <chunk> <hex>   through BIO_f_base64 (BIO_FLAGS_BASE64_NO_NL if <nonl>):
 *                              writes the octets in chunks and flushes (enc 1), or reads the
 *                              text in chunks (enc 0); the results and the output
 *   pemread <flags> <hex>      PEM_read_bio_ex of the text (in hex) with <flags> until it fails:
 *                              each block's name, header, and data, then the errors
 *   paramset <fn> <type> <size> <null> <value>   OSSL_PARAM_set_<fn> (int32, uint32, int64,
 *                              uint64, double, int, uint, long, ulong, size_t, time_t) of the
 *                              value into a parameter of the type and size (data NULL if
 *                              <null>): the return, return_size, the data, and the errors;
 *                              cases where OpenSSL touches memory out of bounds print "skip"
 *   paramget <type> <hex>      every typed getter on a parameter of the type over the octets
 *                              (`-` for none): each return and value, and the errors
 *   paramstr <op> <size> <max> <hex>   op 0: OSSL_PARAM_get_utf8_string of <size> of the octets
 *                              into a buffer of <max>; 1: get_octet_string likewise; 2 and 3:
 *                              set_utf8_string (the octets up to a NUL) and set_octet_string
 *                              into a parameter of <size> octets (<max> 0: data NULL)
 *   parammerge <keys> <keys>   OSSL_PARAM_merge of two arrays of the comma-separated keys (`-`
 *                              for none): the merged keys and which array each came from
 *   tracestr <text> <full> <hex>   OSSL_trace_string to a memory BIO (`-` for no data), printing
 *                              the return and what it wrote; never full and masked past
 *                              OSSL_TRACE_STRING_MAX, where OpenSSL overflows its buffer
 *
 * Commands for library contexts, in four slots (a context is named by its slot, g for the
 * global default, `-` for NULL):
 *   ctxnew <slot>              OSSL_LIB_CTX_new into an empty slot
 *   ctxfree <slot>             OSSL_LIB_CTX_free; the slot stays filled if it was the default
 *   ctxfreeglobal              OSSL_LIB_CTX_free of the global default, while it's the default
 *   ctxdefault <name>          OSSL_LIB_CTX_set0_default: the previous default's name
 *   ctxmax <name> <n>          OSSL_set_max_threads, then OSSL_get_max_threads of every context
 *   ctxdiag <name> <n>         OSSL_LIB_CTX_set_conf_diagnostics, then every context's flag
 *   ctxexidx <class>           CRYPTO_get_ex_new_index in the class: the index
 *
 * Commands for default properties, in one library context of the probe's (`-` for an empty
 * query; a query is in hex):
 *   propnew                    a new context, so names are numbered afresh
 *   propset <hex>              EVP_set_default_properties (propset with no argument: NULL):
 *                              the return, the errors with their data, whether FIPS is
 *                              required, and EVP_get1_default_properties
 *   propfips <enable>          EVP_default_properties_enable_fips, then as propset
 *
 * Commands for providers, in one library context of the probe's, with eight slots for the
 * providers loaded (names: default, base, null, and ones no module exists for):
 *   pnew                       a new context
 *   pload <slot> <name>        OSSL_PROVIDER_load into an empty slot: loaded or NULL, and the
 *                              errors (codes; the data of CRYPTO's)
 *   ptry <slot> <name> <keep>  OSSL_PROVIDER_try_load, keeping the fallback if <keep>
 *   punload <slot>             OSSL_PROVIDER_unload, emptying the slot
 *   pavail <name>              OSSL_PROVIDER_available
 *   pall                       OSSL_PROVIDER_do_all: the names, in order; then which slots hold
 *                              the same provider as another, and the error libraries taken
 *   pparams <slot>             the provider's name, version, and status parameters
 * Each frees the thread's error state afterwards (OPENSSL_thread_stop), so no error slot keeps
 * a buffer sized by a module lookup's message, which differs between the libraries.
 *
 * Commands for fetching, from two providers of the probe's own ("fp" and "fq", registered with
 * OSSL_PROVIDER_add_builtin) whose digests ALG-1 to ALG-4 have several implementations with
 * different properties, each described by its own text (a query is in hex; numbers in error
 * data print as #, as the libraries number names differently until step 3.3):
 *   fnew                       a new context with both providers loaded
 *   ffetch <name> <hex>        EVP_MD_fetch (`-` for no query): the implementation chosen, and
 *                              the errors
 *   fdefault <hex>             EVP_set_default_properties (`-` for NULL)
 *   fall                       EVP_MD_do_all_provided: the implementations, in order
 *   fload <p|q>, funload <p|q> load or unload one of the providers
 * Each frees the thread's error state afterwards, as the provider commands do.
 *
 * Commands for digesting with the default provider's digests, on two contexts (each line
 * prints the result and the errors as library/reason; outputs are at most 256 octets of a
 * fixed pattern, taken from a rolling offset):
 *   dctx <0|1>                 work on context 0 or 1
 *   dinit <name|->             EVP_DigestInit_ex with the digest fetched by name (`-`: NULL)
 *   dinitp <name> <key> <n>    EVP_DigestInit_ex2 with a size_t parameter (xoflen or size)
 *   dset <key> <n>             EVP_MD_CTX_set_params with a size_t parameter
 *   dupdate <n>                EVP_DigestUpdate of <n> octets
 *   dfinal, dxof <n>, dsqueeze <n>   EVP_DigestFinal_ex, EVP_DigestFinalXOF, EVP_DigestSqueeze
 *   dsize, dflags              EVP_MD_CTX_get_size_ex; the flags
 *   dcopy, dreset              EVP_MD_CTX_copy_ex onto the other context; EVP_MD_CTX_reset
 *   dname <name>               EVP_get_digestbyname: the digest's name, NID, and signature NID
 *   dnid <nid>                 EVP_get_digestbynid likewise
 *
 * Commands for encrypting and decrypting with the default provider's ciphers, on two contexts
 * (each line prints the result, lengths, output, and the errors as library/reason; inputs are a
 * fixed pattern from a rolling offset, keys and IVs another):
 *   cctx <0|1>                 work on context 0 or 1
 *   cinit <name|-> <enc> <k> <i>   EVP_CipherInit_ex with the cipher fetched by name (`-`: NULL),
 *                              direction <enc> (1, 0, -1), and a key and IV if <k> and <i> are 1
 *                              (skipped when ECB or CBC turns around without a key; data
 *                              operations are skipped after an init failed turning it around)
 *   cinitp <name> <key> <n>    EVP_CipherInit_ex2 to encrypt with a key, an IV, and a size_t or
 *                              uint parameter (keylen, ivlen, padding, num, use-bits)
 *   cupdate <n>, cfinal        EVP_CipherUpdate of <n> octets; EVP_CipherFinal_ex
 *   ccipher <n>                EVP_Cipher of <n> octets (the stream ciphers' only for a length
 *                              that isn't whole blocks; see docs/DEVIATIONS.md)
 *   cpad <0|1>, ckeylen <n>, cnum <n>   EVP_CIPHER_CTX_set_padding, _set_key_length, _set_num
 *   cflags <set|clear> <hex>   EVP_CIPHER_CTX_set_flags or _clear_flags
 *   cstate                     the lengths, num, IVs, flags, and direction
 *   cctrl <type> <arg>         EVP_CIPHER_CTX_ctrl with a 64-octet buffer
 *   ccopy, creset              EVP_CIPHER_CTX_copy onto the other context; EVP_CIPHER_CTX_reset
 *   cname <name>, cnid <nid>   EVP_get_cipherbyname, _bynid: the name, NID, and type
 *   caad <n>, cmsglen <n>      EVP_CipherUpdate of <n> octets of AAD (no output); of no input
 *                              and no output (CCM's message length); skipped for ciphers that
 *                              take neither
 *   ctagget <n>, ctagset <n>, ctaglen <n>   the AEAD tag: got into the probe's tag buffer, set
 *                              from it, or its length set (no data)
 *
 * Commands for big numbers, in four registers (0-3) that start at zero; each line prints the
 * result, the registers it wrote (as BN_bn2hex), and the errors as library/reason:
 *   bnset <r> <hex>            BN_hex2bn of the hex (with an optional -) into register <r>
 *   bntext <r> <kind> <text>   BN_dec2bn, BN_hex2bn, or BN_asc2bn (dec, hex, asc): the count
 *   bnop <op> <r> <a> <b>      r = a op b: add, sub, uadd, usub, mul, sqr (of a), nnmod, exp
 *                              (exp skipped when the result would pass 65536 bits, mul and
 *                              sqr past 200000), cmp (prints BN_cmp and BN_ucmp), copy (of a),
 *                              swap (a and b)
 *   bndiv <q|-> <rem|-> <a> <b>   BN_div (skipped if q and rem are one register)
 *   bnshift <op> <r> <a> <n>   lshift, rshift (n at most 100000, a left shift's result at
 *                              most 300000 bits), lshift1, rshift1
 *   bnword <op> <r> <w>        add, sub, mul, div, mod with a word (decimal)
 *   bnbit <op> <r> <n>         set, clear, isset, mask
 *   bnflag <r>                 BN_set_flags(BN_FLG_CONSTTIME)
 *   bnshow <r>                 hex, decimal, bits, bytes, the predicates, the word, BN_print
 *   bnto <r> <kind> <len>      BN_bn2bin, BN_bn2binpad, BN_bn2lebinpad, BN_bn2nativepad,
 *                              BN_signed_bn2bin, _bn2lebin, _bn2native, BN_bn2mpi (bin, binpad,
 *                              lebin, native, sbin, slebin, snative, mpi) into <len> octets
 *   bnfrom <r> <kind> <hex|->  BN_bin2bn, BN_lebin2bn, BN_native2bn, the signed forms (bin,
 *                              lebin, native, sbin, slebin, snative), or BN_mpi2bn (mpi)
 *   bnrand <r> <bits> <top> <bottom> <kind>   BN_rand, BN_priv_rand, BN_bntest_rand (0-2):
 *                              the number only from a deterministic generator (another's is
 *                              checked, then zeroed)
 *   bnrange <r> <range> <kind> BN_rand_range or BN_priv_rand_range (0, 1) below register
 *                              <range>, likewise
 *   bnasn1 <r>                 BN_to_ASN1_INTEGER, back with ASN1_INTEGER_to_BN, and
 *                              ASN1_bn_print (newlines as |)
 *   bnparam <r> <u|s> <size>   OSSL_PARAM_set_BN into <size> octets, then OSSL_PARAM_get_BN
 *   bnmod <op> <r> <a> <b> <m> r = a op b mod m: add, sub, mul, sqr (of a), lshift1 (of a),
 *                              addq, subq, lshift1q (the quick forms)
 *   bnmshift <q|n> <r> <a> <n> <m>   BN_mod_lshift_quick (not into m) or BN_mod_lshift by <n>
 *   bnexp <kind> <r> <a> <p> <m>   BN_mod_exp, _mont, _mont_consttime, _recp, _simple, or
 *                              _mont_word (exp, mont, ct, recp, simple, word; the word is a's;
 *                              skipped past 2048-bit exponents or moduli)
 *   bnexp2 <r> <a1> <p1> <a2> <p2> <m>   BN_mod_exp2_mont (registers by index mod 4)
 *   bninv <r|-> <a> <n>, bngcd <r> <a> <b>, bnkron <a> <b>, bncoprime <a> <b>
 *                              (bninv skipped into the modulus)
 *   bnsqrt <r|-> <a> <p>       BN_mod_sqrt (skipped past 512-bit moduli, and into an operand)
 *   bnmont <op> <r> <a> <b> <m>   with a context set to m: mul, to (of a), from (of a)
 *                              (skipped when the set fails)
 *   bnrecp <op> <r> <a> <b> <m>   with a context set to m: div (rem into a's register's
 *                              neighbour), mul, recip (BN_reciprocal of m by b's bits)
 *   bnnist <bits> <r> <a>      BN_nist_mod_<bits>, and BN_nist_mod_func's answer for a
 *   bnprime <n> <r>            the RFC prime n (0-7), into the register
 *   bnisprime <r> <kind> <checks>   BN_check_prime, BN_is_prime_ex, BN_is_prime_fasttest_ex
 *                              (check, ex, fast) of the register (skipped past 1024 bits)
 *   bngen <r> <bits> <safe> <add> <rem>   BN_generate_prime_ex2 (add and rem as decimal
 *                              words, 0 for none; at most 160 bits, 64 for a safe prime): the
 *                              prime only from deterministic generators, else its length
 *   bngf2m <op> <r> <a> <b> <field>   over field 0 (x^163+x^7+x^6+x^3+1), 1 (x^233+x^74+1),
 *                              2 (x^4+x+1), 3 (x^10+x^3+1), 4 (x^8+x^4+x^3+x^2+x^6+x+1: seven
 *                              terms), 5 (an even one): mod, add, mul, sqr, inv, div, exp, sqrt,
 *                              solve, and the array forms modarr, mularr, sqrarr, invarr,
 *                              divarr, exparr, sqrtarr, solvearr (results that depend on random
 *                              numbers printed only from a deterministic generator)
 *
 *   ecgrp <sn>                 the curve's group becomes the EC commands' (two point registers)
 *   ecpt <r> <hex>             EC_POINT_oct2point into register r
 *   eccomp <r> <x> <bit>       EC_POINT_set_compressed_coordinates
 *   ecmul <r> <k|-> <reg|-> <k2|->   EC_POINT_mul: each point printed affine, in its three
 *                              encodings, and (for the generic prime method with a known
 *                              generator) in its Jacobian coordinates; with a point off
 *                              the curve on a specialized method, only "offcurve"
 *   ecadd <r> <a> <b>          EC_POINT_add of registers
 *   ecpk <hex>                 d2i_ECPKParameters: what it consumes, and the group's state,
 *                              encoding, check, and print
 *   eckey <hex>                d2i_ECPrivateKey: what it consumes, and the key's state,
 *                              encoding, check, and print
 *   ecgen <curve>              EC_KEY_generate_key: the private and public keys
 *   ecsign <curve> <priv> <digest>        ECDSA_sign's DER (its nonce from the generator)
 *   ecsetup <curve> <priv>     ECDSA_sign_setup's kinv and r
 *   ecverify <curve> <priv> <digest> <sig>  ECDSA_verify of any octets
 *   ecdh <curve> <priv> <peer's priv> <0|1>  ECDH_compute_key, with the cofactor for 1
 *   eckm <sel> <group|-> <priv|-> <pub|-> <k=v,...|->  EVP_PKEY_fromdata of an EC key (the
 *                              selection in hex; the other parameters' values are strings,
 *                              or ints with a leading #): the key's export, checks, parameters
 *                              set back, and comparison with its copy
 *   ecdhkem <group> <ikm>      an EC key generated from DHKEM input key material
 *   sm2km <sel> <group|-> <priv|-> <pub|-> <k=v,...|->  as eckm, with the SM2 key manager
 *   ecxkm <type> <sel> <priv|-> <pub|-> <ikm|->  an ECX key (X25519, ED25519, ...) from data,
 *                              its export, raw keys, and checks; with ikm, one generated from
 *                              DHKEM input key material instead
 *   mlkemkm <alg> <sel> <seed|-> <privfrom|-> <pubfrom|-> <edits|->  an ML-KEM key from data:
 *                              the seed given, and the private and public keys of the keys
 *                              generated from the 64-octet seeds given, edited (comma-separated
 *                              p@N^XX or q@N^XX to xor octet N of the private or public key,
 *                              p@N=XX to set it, p#N to make it N octets); the key's parts (as
 *                              SHA-256 prefixes), checks, sizes, and export
 *   mldsakm <alg> <sel> <seed|-> <privfrom|-> <pubfrom|-> <edits|->  as mlkemkm, for ML-DSA
 *                              (whose seeds are 32 octets)
 *   slhdsakm <alg> <sel> - <privfrom|-> <pubfrom|-> <edits|->  as mlkemkm, for SLH-DSA (whose
 *                              keys come from seeds of 3n octets, SK.seed || SK.prf || PK.seed)
 *   mlkem <alg> <keyseed> <ikme|-> <edits|-> <croom> <sroom>  the ML-KEM KEM with the key
 *                              generated from the 64-octet seed: an encapsulation (with the
 *                              ikmE given, else random) into rooms of croom and sroom octets,
 *                              then the decapsulation of its ciphertext edited (comma-separated
 *                              c@N^XX to xor octet N, c#N to make it N octets)
 *   mldsa <alg> <keyseed> <msg|-> <ctx|-|e> <opts|-> <room> <edits|->  an ML-DSA signature with
 *                              the key generated from the 32-octet seed, of the message (with
 *                              the context string, e for an empty one), the options (comma-
 *                              separated det=N, enc=N, mu=N, ent=HEX for the parameters; pub to
 *                              verify with the public key alone), into room octets (0 for a size
 *                              query), then its verification edited (s@N^XX to xor octet N of
 *                              the signature, s#N to make it N octets, m@N^XX for the message)
 *   slhdsa <alg> <keyseed> <msg|-> <ctx|-|e> <opts|-> <room> <edits|->  as mldsa, for SLH-DSA
 *                              (keys from 3n octets of seeds; no mu, test entropy of n octets)
 *   mlx <alg> <keyseed> <ctseed> <delta>  a hybrid ML-KEM key: ML-KEM's from the 64-octet seed,
 *                              X25519's or X448's from it too (a NIST curve's random); the
 *                              private key (X25519 and X448) and public key imported, the
 *                              decapsulation of a ciphertext streamed from ctseed (of the right
 *                              length plus delta), and an encapsulation to the public key
 *   dhcheck <p|-> <q|-> <g|-> <pub|-> <edit|->  DH's checks (DH_check, DH_check_params, and
 *                              DH_check_pub_key, with their _ex forms) of numbers in hex or a
 *                              named group's (ffdhe2048:p, dh_2048_256:q, ...), one of them
 *                              added to by the edit (p3 adds 3 to p, y1 to the public key)
 *   dhder <p|x> <hex>          d2i_DHparams (p) or d2i_DHxparams (x) of the octets: the result,
 *                              the octets consumed, and the parameters' sizes, encoding,
 *                              checks, and printed text (as a SHA-256 prefix)
 *   dhkey <DH|DHX> <p|-> <q|-> <g|-> <pub|gx|-> <priv|-> <length|-> <edit|->  a DH or DHX
 *                              key from data through its key manager (numbers as for dhcheck;
 *                              gx for g^priv mod p; the edit also takes xN for the private
 *                              key), then its sizes, every validation, its encoded public key,
 *                              that set on a copy, and a comparison with the copy
 *   dhexch <p|l> <group> <priv> <peer's priv> <edit|-> <pad> <kdf|-> <room>  the DH exchange
 *                              of two keys of a named group made from their private keys (the
 *                              peer's public key changed by the edit: yN adds N, y=1 sets 1, y=p
 *                              sets p - 1), through the provider (p) or, with an application's
 *                              DH_METHOD, the legacy method (l); padded or not; through X9.42's
 *                              KDF given as digest:outlen:cekalg:ukm-hex; into room octets
 *   dsaverify <dgst|-> <sig|-> <key>  DSA_verify (and d2i_DSA_SIG and DSA_do_verify of what
 *                              decodes) of a signature in hex over a digest in hex with RFC
 *                              6979's DSA-1024 key (key: k, or nopub, small, q+2, or even for a
 *                              key changed so; OpenSSL crashes without the public key)
 *   dsader <k|p|u> <hex>       d2i_DSAPrivateKey (k), d2i_DSAparams (p), or d2i_DSAPublicKey (u)
 *                              of the octets: the result, the octets consumed, the numbers, and
 *                              whether each encoding of the key re-encodes them
 *   x25519x <priv> <peer's pub> <room>  the X25519 exchange into room octets (prefilled 0x77)
 *   x448x <priv> <peer's pub> <room>  the same with X448
 *   ed25519 <alg|-> <instance|-> <ctx|-> <priv> <msg|-> <sig|->  Ed25519 signatures through
 *                              an algorithm (- for EVP_DigestSign) with the instance and context
 *                              string given: with no signature, the message signed and
 *                              verified; with one, verified
 *   ed448 <alg|-> <instance|-> <ctx|-> <priv> <msg|-> <sig|->  the same with Ed448 (ED448,
 *                              ED448ph)
 *   sm2enc <priv> <md|-> <msg> <ct|-> <room>  the SM2 asymmetric cipher: with no ciphertext,
 *                              the message's size, encryption, and decryption again; with one,
 *                              its message's size and its decryption into room octets
 *   sm2sig <priv> <id|-> <md|-> <msg> <sig|->  the SM2 signature provider: with no signature,
 *                              the message signed through a digest context (with the ID) and,
 *                              as a number, by EVP_PKEY_sign, each verified; with one, it's
 *                              verified both ways
 *   ecdhx <curve> <priv> <peer's priv> <mode> <md|-> <outlen> <ukm|-> <room>  the ECDH
 *                              provider: the shared secret into a buffer of room octets, with
 *                              the cofactor mode (-1 the key's, or anything set), and X9.63's
 *                              KDF for a digest (its output length and keying material)
 *   ecsig <curve> <priv> <md|-> <nonce-type> <alg|-> <msg> <sig|->  the ECDSA provider: with
 *                              no signature, the message signed through a digest context,
 *                              as a digest (EVP_PKEY_sign with the digest set), and with the
 *                              composite algorithm, each verified; with one, it's verified
 *                              each way
 *
 *   # ...              comment, echoed
 */
#define _POSIX_C_SOURCE 200809L
/* ERR_get_state is deprecated. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/aes.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/blowfish.h>
#include <openssl/bn.h>
#include <openssl/cast.h>
#include <openssl/conf.h>
#include <openssl/buffer.h>
#include <openssl/camellia.h>
#include <openssl/crypto.h>
#include <openssl/des.h>
#include <openssl/ec.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/idea.h>
#include <openssl/kdf.h>
#include <openssl/lhash.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/mdc2.h>
#include <openssl/modes.h>
#include <openssl/objects.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/rc2.h>
#include <openssl/rc4.h>
#include <openssl/ripemd.h>
#include <openssl/rsa.h>
#include <openssl/seed.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <ctype.h>
#include <openssl/pem.h>
#include <openssl/stack.h>
#include <openssl/thread.h>
#include <openssl/trace.h>
#include <openssl/whrlpool.h>
#include <openssl/x509v3.h>

static BUF_MEM *buffer = NULL;

static void print_state(const char *command, size_t result)
{
    printf("%s %zu length=%zu max=%zu\n", command, result, buffer->length, buffer->max);
}

static int parse_hex(const char *hex, unsigned char *out, size_t *len)
{
    size_t n = strlen(hex);

    if (n % 2 != 0 || n / 2 > 256)
        return 0;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned int byte;

        if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
            return 0;
        out[i] = (unsigned char)byte;
    }
    *len = n / 2;
    return 1;
}

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

static void print_escaped(const char *label, int ret, const char *data, size_t len)
{
    printf("%s %d \"", label, ret);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];

        if (c >= ' ' && c <= '~' && c != '\\' && c != '"')
            putchar(c);
        else
            printf("\\x%02x", c);
    }
    printf("\"\n");
}

/* FNV-1a, to compare long data without printing it. */
static unsigned long hash(const char *text)
{
    unsigned long h = 2166136261UL;

    for (; *text != '\0'; text++)
        h = ((h ^ (unsigned char)*text) * 16777619UL) & 0xffffffffUL;
    return h;
}

static const char *or_dash(const char *text)
{
    return text == NULL || text[0] == '\0' ? "-" : text;
}

static void print_error(const char *command, unsigned long code, const char *file, int line,
                        const char *func, const char *data, int flags)
{
    printf("%s %lx", command, code);
    if (code != 0)
        printf(" %s:%d:%s data=%zu:%lx flags=%d", or_dash(file), line, or_dash(func), strlen(data),
               hash(data), flags);
    printf("\n");
}

static void print_err_state(void)
{
    ERR_STATE *es = ERR_get_state();

    if (es == NULL) {
        printf("state none\n");
        return;
    }
    printf("state top=%d bottom=%d\n", es->top, es->bottom);
    for (int i = 0; i < ERR_NUM_ERRORS; i++) {
        const char *data = es->err_data[i];
        int text = data != NULL && (es->err_data_flags[i] & ERR_TXT_STRING) != 0;

        printf("  %d: %lx marks=%d flags=%d %s:%d:%s data=%d:%zu", i, es->err_buffer[i],
               es->err_marks[i], es->err_flags[i], or_dash(es->err_file[i]), es->err_line[i],
               or_dash(es->err_func[i]), es->err_data_flags[i], es->err_data_size[i]);
        if (text)
            printf(":%zu:%lx", strlen(data), hash(data));
        printf("\n");
    }
}

/* Builds the text for `txt`: letters, with the separator after every `every` of them. */
static char *make_text(const char *separator, size_t len, size_t every)
{
    size_t sep = strlen(separator), used = 0;
    char *text = malloc(len + (every == 0 ? 0 : len / every * sep) + 1);

    if (text == NULL)
        return NULL;
    for (size_t i = 0; i < len; i++) {
        text[used++] = (char)('a' + i % 26);
        if (every != 0 && (i + 1) % every == 0) {
            memcpy(text + used, separator, sep);
            used += sep;
        }
    }
    text[used] = '\0';
    return text;
}

/* The pool stacks and hash tables point into. */
static int pool[64];
static int comparisons;

static int pool_index(const void *p)
{
    return p == NULL ? -1 : (int)((const int *)p - pool);
}

static int by_value(const void *a, const void *b)
{
    const int *x = *(const int *const *)a, *y = *(const int *const *)b;

    comparisons++;
    return *x < *y ? -1 : *x > *y;
}

static int by_value_reversed(const void *a, const void *b)
{
    return -by_value(a, b);
}

static OPENSSL_sk_compfunc comparator(int which)
{
    return which == 1 ? by_value : which == 2 ? by_value_reversed : NULL;
}

static void print_stack(const char *label, const OPENSSL_STACK *st)
{
    printf("%s num=%d sorted=%d:", label, OPENSSL_sk_num(st), OPENSSL_sk_is_sorted(st));
    for (int i = 0; i < OPENSSL_sk_num(st); i++)
        printf(" %d", pool_index(OPENSSL_sk_value(st, i)));
    printf("\n");
}

/* Runs a stack command; returns 0 if `command` isn't one. */
static int stack_command(const char *command, const char *line)
{
    static OPENSSL_STACK *st = NULL;
    int a = 0, b = 0, n;

    n = sscanf(line, "%*s %d %d", &a, &b);
    if (a < 0 || a >= 64)
        a = 0;
    if (strcmp(command, "sknew") == 0) {
        OPENSSL_sk_free(st);
        st = OPENSSL_sk_new(comparator(a));
        printf("sknew\n");
        return 1;
    }
    if (strncmp(command, "sk", 2) != 0)
        return 0;
    if (st == NULL) {
        printf("error no stack\n");
    } else if (strcmp(command, "skcmp") == 0) {
        OPENSSL_sk_compfunc old = OPENSSL_sk_set_cmp_func(st, comparator(a));
        printf("skcmp old=%d sorted=%d\n", old == by_value ? 1 : old == by_value_reversed ? 2 : 0,
               OPENSSL_sk_is_sorted(st));
    } else if (strcmp(command, "skpush") == 0) {
        printf("skpush %d\n", OPENSSL_sk_push(st, &pool[a]));
    } else if (strcmp(command, "skunshift") == 0) {
        printf("skunshift %d\n", OPENSSL_sk_unshift(st, &pool[a]));
    } else if (strcmp(command, "skinsert") == 0) {
        printf("skinsert %d\n", OPENSSL_sk_insert(st, &pool[a], b));
    } else if (strcmp(command, "skset") == 0) {
        sscanf(line, "%*s %d %d", &a, &b);
        if (b < 0 || b >= 64)
            b = 0;
        printf("skset %d\n", pool_index(OPENSSL_sk_set(st, a, &pool[b])));
        ERR_clear_error();
    } else if (strcmp(command, "skdelptr") == 0) {
        printf("skdelptr %d\n", pool_index(OPENSSL_sk_delete_ptr(st, &pool[a])));
    } else if (strcmp(command, "skdelete") == 0) {
        sscanf(line, "%*s %d", &a);
        printf("skdelete %d\n", pool_index(OPENSSL_sk_delete(st, a)));
    } else if (strcmp(command, "skshift") == 0) {
        printf("skshift %d\n", pool_index(OPENSSL_sk_shift(st)));
    } else if (strcmp(command, "skpop") == 0) {
        printf("skpop %d\n", pool_index(OPENSSL_sk_pop(st)));
    } else if (strcmp(command, "skzero") == 0) {
        OPENSSL_sk_zero(st);
        printf("skzero\n");
    } else if (strcmp(command, "sksort") == 0) {
        comparisons = 0;
        OPENSSL_sk_sort(st);
        print_stack("sksort", st);
    } else if (strcmp(command, "skdup") == 0) {
        OPENSSL_STACK *copy = OPENSSL_sk_dup(st);

        print_stack("skdup", copy);
        OPENSSL_sk_free(st);
        st = copy;
    } else if (strcmp(command, "skreserve") == 0) {
        sscanf(line, "%*s %d", &a);
        printf("skreserve %d\n", OPENSSL_sk_reserve(st, a));
        ERR_clear_error();
    } else if (strcmp(command, "skfind") == 0 || strcmp(command, "skfindex") == 0
               || strcmp(command, "skfindall") == 0) {
        int key, *k = &key, count = 5, at;

        sscanf(line, "%*s %d", &key);
        comparisons = 0;
        if (strcmp(command, "skfind") == 0)
            at = OPENSSL_sk_find(st, k);
        else if (strcmp(command, "skfindex") == 0)
            at = OPENSSL_sk_find_ex(st, k);
        else
            at = OPENSSL_sk_find_all(st, k, &count);
        printf("%s %d count=%d comparisons=%d\n", command, at, count, comparisons);
    } else if (strcmp(command, "skdump") == 0) {
        print_stack("skdump", st);
    } else {
        printf("error unknown command %s\n", command);
    }
    (void)n;
    return 1;
}

/* Hash table items: pool entries, keyed by their index. */
typedef struct {
    int key;
} ITEM;

DEFINE_LHASH_OF_EX(ITEM);

static ITEM items[64];

static unsigned long hash_key(const ITEM *item)
{
    return (unsigned long)item->key;
}

static unsigned long hash_mixed(const ITEM *item)
{
    return ((unsigned long)item->key * 2654435761UL) & 0xffffffffUL;
}

static int same_key(const ITEM *a, const ITEM *b)
{
    return a->key != b->key;
}

static void print_item(ITEM *item)
{
    printf(" %d", (int)(item - items));
}

/* Runs a hash table command; returns 0 if `command` isn't one. */
static int lhash_command(const char *command, const char *line)
{
    static LHASH_OF(ITEM) *lh = NULL;
    static ITEM copies[64];
    int a = 0;

    sscanf(line, "%*s %d", &a);
    if (strcmp(command, "lhnew") == 0) {
        lh_ITEM_free(lh);
        for (int i = 0; i < 64; i++)
            items[i].key = copies[i].key = i;
        lh = lh_ITEM_new(a == 1 ? hash_mixed : hash_key, same_key);
        printf("lhnew\n");
        return 1;
    }
    if (strncmp(command, "lh", 2) != 0)
        return 0;
    if (a < 0 || a >= 64)
        a = 0;
    if (lh == NULL) {
        printf("error no table\n");
    } else if (strcmp(command, "lhinsert") == 0) {
        ITEM *old = lh_ITEM_insert(lh, &items[a]);

        printf("lhinsert %d items=%lu\n", old == NULL ? -1 : (int)(old - items),
               lh_ITEM_num_items(lh));
    } else if (strcmp(command, "lhdelete") == 0) {
        ITEM *old = lh_ITEM_delete(lh, &copies[a]);

        printf("lhdelete %d items=%lu\n", old == NULL ? -1 : (int)(old - items),
               lh_ITEM_num_items(lh));
    } else if (strcmp(command, "lhget") == 0) {
        ITEM *found = lh_ITEM_retrieve(lh, &copies[a]);

        printf("lhget %d\n", found == NULL ? -1 : (int)(found - items));
    } else if (strcmp(command, "lhdown") == 0) {
        sscanf(line, "%*s %d", &a);
        lh_ITEM_set_down_load(lh, (unsigned long)a);
        printf("lhdown %lu\n", lh_ITEM_get_down_load(lh));
    } else if (strcmp(command, "lhdump") == 0) {
        printf("lhdump");
        lh_ITEM_doall(lh, print_item);
        printf("\n");
    } else {
        printf("error unknown command %s\n", command);
    }
    return 1;
}

static void print_bytes(const char *label, int ret, const char *data, int len)
{
    printf("%s %d \"", label, ret);
    for (int i = 0; i < len; i++)
        printf(data[i] == '\n' ? "\\n" : "%c", data[i]);
    printf("\"\n");
}

/* Runs a memory BIO command; returns 0 if `command` isn't one. */
static int bio_command(const char *command, const char *line)
{
    static const char fixed[] = "line one\nline two\nthird line, no newline";
    static BIO *bio = NULL, *peer = NULL;
    char word[200] = "", name[32] = "";
    char buf[300];
    int n = 0;

    if (strncmp(command, "bio", 3) != 0)
        return 0;
    sscanf(line, "%*s %199s", word);
    for (char *p = word; *p != '\0'; p++)
        if (*p == '_')
            *p = '\n';
    if (strcmp(word, "-") == 0)
        word[0] = '\0';
    n = atoi(word);
    if (n < 0 || n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    if (strcmp(command, "bionew") == 0) {
        BIO_free_all(bio);
        BIO_free(peer);
        peer = NULL;
        switch (n) {
        case 1:
            bio = BIO_new(BIO_s_secmem());
            break;
        case 2:
            bio = BIO_new_mem_buf(fixed, -1);
            break;
        case 3:
            bio = BIO_push(BIO_new(BIO_f_null()), BIO_new(BIO_s_mem()));
            break;
        case 4:
            bio = BIO_push(BIO_new(BIO_f_buffer()), BIO_new(BIO_s_mem()));
            break;
        case 5:
            bio = BIO_push(BIO_new(BIO_f_linebuffer()), BIO_new(BIO_s_mem()));
            break;
        case 6:
            bio = BIO_push(BIO_new(BIO_f_readbuffer()), BIO_new_mem_buf(fixed, -1));
            break;
        case 7:
            bio = BIO_push(BIO_new(BIO_f_prefix()), BIO_new(BIO_s_mem()));
            (void)BIO_set_prefix(bio, "> ");
            (void)BIO_set_indent(bio, 2);
            break;
        case 8:
            if (!BIO_new_bio_pair(&bio, 16, &peer, 32))
                bio = peer = NULL;
            break;
        case 9:
            bio = BIO_new(BIO_s_dgram_mem());
            break;
        case 10:
            if (!BIO_new_bio_dgram_pair(&bio, 0, &peer, 0))
                bio = peer = NULL;
            break;
        default:
            bio = BIO_new(BIO_s_mem());
        }
        printf("bionew %d\n", bio != NULL);
    } else if (bio == NULL) {
        printf("error no bio\n");
    } else if (strcmp(command, "biopeer") == 0) {
        if (peer != NULL) {
            BIO *other = bio;

            bio = peer;
            peer = other;
        }
        printf("biopeer %d\n", peer != NULL);
    } else if (strcmp(command, "bionread") == 0) {
        char *p = NULL;
        int ret = BIO_nread(bio, &p, n);

        print_bytes("bionread", ret, p, ret > 0 && p != NULL ? ret : 0);
    } else if (strcmp(command, "bionwrite") == 0) {
        char *p = NULL;
        int room = BIO_nwrite0(bio, &p), len = (int)strlen(word), ret;

        if (room > 0 && p != NULL)
            memcpy(p, word, (size_t)(len < room ? len : room));
        ret = BIO_nwrite(bio, &p, len);
        printf("bionwrite %d %d\n", room, ret);
    } else if (strcmp(command, "biowrite") == 0) {
        printf("biowrite %d\n", BIO_write(bio, word, (int)strlen(word)));
    } else if (strcmp(command, "bioputs") == 0) {
        printf("bioputs %d\n", BIO_puts(bio, word));
    } else if (strcmp(command, "bioread") == 0) {
        int ret;

        /* A positive EOF return reads "bytes" that were never written: show the fill. */
        memset(buf, '#', sizeof(buf));
        ret = BIO_read(bio, buf, n);

        print_bytes("bioread", ret, buf, ret > 0 ? ret : 0);
    } else if (strcmp(command, "biogets") == 0 || strcmp(command, "bioline") == 0) {
        int ret;

        memset(buf, '#', sizeof(buf));
        ret = strcmp(command, "biogets") == 0 ? BIO_gets(bio, buf, n) : BIO_get_line(bio, buf, n);
        print_bytes(command, ret, buf, ret > 0 ? ret : 0);
    } else if (strcmp(command, "bioctrl") == 0) {
        long arg = 0, ret = -99;
        char *data = NULL;

        sscanf(line, "%*s %31s %ld", name, &arg);
        if (strcmp(name, "reset") == 0)
            ret = BIO_reset(bio);
        else if (strcmp(name, "eof") == 0)
            ret = BIO_eof(bio);
        else if (strcmp(name, "pending") == 0)
            ret = BIO_pending(bio);
        else if (strcmp(name, "wpending") == 0)
            ret = BIO_wpending(bio);
        else if (strcmp(name, "seek") == 0)
            ret = BIO_seek(bio, arg);
        else if (strcmp(name, "tell") == 0)
            ret = BIO_tell(bio);
        else if (strcmp(name, "eofret") == 0)
            ret = BIO_set_mem_eof_return(bio, arg);
        else if (strcmp(name, "setclose") == 0)
            ret = BIO_set_close(bio, arg);
        else if (strcmp(name, "getclose") == 0)
            ret = BIO_get_close(bio);
        else if (strcmp(name, "flush") == 0)
            ret = BIO_flush(bio);
        else if (strcmp(name, "shutdown") == 0)
            ret = BIO_shutdown_wr(bio);
        else if (strcmp(name, "guarantee") == 0)
            ret = (long)BIO_ctrl_get_write_guarantee(bio);
        else if (strcmp(name, "request") == 0)
            ret = (long)BIO_ctrl_get_read_request(bio);
        else if (strcmp(name, "lines") == 0)
            ret = BIO_get_buffer_num_lines(bio);
        else if (strcmp(name, "bufsize") == 0)
            ret = BIO_set_buffer_size(bio, arg);
        else if (strcmp(name, "wbufsize") == 0)
            ret = BIO_set_write_buf_size(bio, arg);
        else if (strcmp(name, "notrunc") == 0)
            ret = BIO_dgram_set_no_trunc(bio, (int)arg);
        else if (strcmp(name, "mtu") == 0)
            ret = BIO_dgram_set_mtu(bio, arg) + 1000 * BIO_dgram_get_mtu(bio);
        else if (strcmp(name, "info") == 0) {
            ret = BIO_get_mem_data(bio, &data);
            if (ret > 0 && data != NULL) {
                print_bytes("bioctrl info", (int)ret, data, (int)ret);
                ERR_clear_error();
                return 1;
            }
        }
        printf("bioctrl %s %ld\n", name, ret);
    } else if (strcmp(command, "biomem") == 0) {
        BUF_MEM *bm = NULL;
        BIO *mem = BIO_find_type(bio, BIO_TYPE_MEM);

        if (mem != NULL && BIO_get_mem_ptr(mem, &bm) > 0 && bm != NULL) {
            char *copy = OPENSSL_strndup(bm->data == NULL ? "" : bm->data, bm->length);

            printf("biomem %zu %lx\n", bm->length, copy == NULL ? 0UL : hash(copy));
            OPENSSL_free(copy);
        } else {
            printf("biomem none\n");
        }
    } else if (strcmp(command, "biostate") == 0) {
        printf("biostate retry=%d read=%d write=%d in=%llu out=%llu\n", BIO_should_retry(bio) != 0,
               BIO_should_read(bio) != 0, BIO_should_write(bio) != 0,
               (unsigned long long)BIO_number_read(bio), (unsigned long long)BIO_number_written(bio));
    } else {
        printf("error unknown command %s\n", command);
    }
    ERR_clear_error();
    return 1;
}

/* Runs a string helper command; returns 0 if `command` isn't one. */
static int string_command(const char *command, const char *line)
{
    char text[200] = "";
    int other = 0;

    sscanf(line, "%*s %199s %d", text, &other);
    if (strcmp(text, "-") == 0)
        text[0] = '\0';
    if (strcmp(command, "hexdecode") == 0) {
        unsigned char buf[100];
        size_t len = 0;
        int ok = OPENSSL_hexstr2buf_ex(buf, sizeof(buf), &len, text, (char)other);

        printf("hexdecode %d", ok);
        if (ok) {
            printf(" len=%zu ", len);
            for (size_t i = 0; i < len; i++)
                printf("%02x", buf[i]);
        } else {
            printf(" reason=%d", ERR_GET_REASON(ERR_get_error()));
        }
        printf("\n");
        ERR_clear_error();
    } else if (strcmp(command, "tracecat") == 0) {
        const char *name = OSSL_trace_get_category_name(other);

        printf("tracecat %d %s\n", OSSL_trace_get_category_num(text), name == NULL ? "(null)" : name);
    } else if (strcmp(command, "tracestr") == 0) {
        unsigned char data[256];
        char hex[600] = "-";
        size_t len = 0;
        BIO *mem = BIO_new(BIO_s_mem());
        char *out;
        long n;
        int text_mode = 0, full = 0, ret;

        sscanf(line, "%*s %d %d %599s", &text_mode, &full, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("tracestr bad hex\n");
            BIO_free(mem);
            return 1;
        }
        if (full && !text_mode && len > OSSL_TRACE_STRING_MAX)
            full = 0;
        ret = OSSL_trace_string(mem, text_mode, full, data, len);
        n = BIO_get_mem_data(mem, &out);
        print_escaped("tracestr", ret, out, (size_t)n);
        BIO_free(mem);
    } else if (strcmp(command, "strtoul") == 0) {
        unsigned long value = 0;
        char *end = NULL;
        int with, without, saved;

        with = OPENSSL_strtoul(text, &end, other, &value);
        saved = errno;
        printf("strtoul %d %lu end=%d errno=%d", with, value, (int)(end - text), saved);
        without = OPENSSL_strtoul(text, NULL, other, &value);
        printf(" without=%d\n", without);
    } else {
        return 0;
    }
    return 1;
}

/* Prints OBJ_obj2txt of `o` with names and without, as `label`. */
static void print_obj_texts(const ASN1_OBJECT *o)
{
    char buf[700];
    int n;

    n = OBJ_obj2txt(buf, sizeof(buf), o, 0);
    printf(" txt=%d:%s", n, buf);
    n = OBJ_obj2txt(buf, sizeof(buf), o, 1);
    printf(" num=%d:%s", n, buf);
}

static void print_obj_error(void)
{
    unsigned long code = ERR_peek_last_error();

    printf(" err=%d/%d\n", ERR_GET_LIB(code), ERR_GET_REASON(code));
    ERR_clear_error();
}

/* Runs an object command; returns 0 if `command` isn't one. */
static int obj_command(const char *command, const char *line)
{
    char hex[600] = "-", text[300];
    unsigned char data[300];
    size_t len = 0;
    int other = 0;

    sscanf(line, "%*s %599s %d", hex, &other);
    if (strcmp(command, "objname") == 0) {
        printf("objname %d %d %d", OBJ_sn2nid(hex), OBJ_ln2nid(hex), OBJ_txt2nid(hex));
        print_obj_error();
        return 1;
    }
    if (strcmp(command, "objtxt") != 0 && strcmp(command, "objder") != 0)
        return 0;
    if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
        printf("%s bad hex\n", command);
        return 1;
    }
    if (strcmp(command, "objtxt") == 0) {
        ASN1_OBJECT *o;
        unsigned char out[300];
        int n;

        memcpy(text, data, len);
        text[len] = '\0';
        o = OBJ_txt2obj(text, other);
        printf("objtxt nid=%d", OBJ_obj2nid(o));
        if (o != NULL)
            print_obj_texts(o);
        ASN1_OBJECT_free(o);
        print_obj_error();
        n = a2d_ASN1_OBJECT(out, sizeof(out), text, -1);
        printf("a2d %d ", n);
        for (int i = 0; i < n; i++)
            printf("%02x", out[i]);
        printf(" measured=%d", a2d_ASN1_OBJECT(NULL, 0, text, -1));
        print_obj_error();
    } else {
        ASN1_OBJECT *o = ASN1_OBJECT_create(0, data, (int)len, NULL, NULL);
        BIO *mem = BIO_new(BIO_s_mem());
        char *out;
        long n;
        int ret;

        printf("objder nid=%d", OBJ_obj2nid(o));
        print_obj_texts(o);
        ret = i2a_ASN1_OBJECT(mem, o);
        n = BIO_get_mem_data(mem, &out);
        printf(" i2a=%d:", ret);
        for (long i = 0; i < n; i++)
            putchar(out[i] == '\n' ? '|' : out[i]);
        BIO_free(mem);
        ASN1_OBJECT_free(o);
        print_obj_error();
    }
    return 1;
}

static void print_asn_errors(void)
{
    unsigned long code;

    printf(" err=");
    while ((code = ERR_get_error()) != 0)
        printf("%d/%d,", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

/* Runs an ASN.1 header command; returns 0 if `command` isn't one. */
static int asn_command(const char *command, const char *line)
{
    char hex[600] = "-";
    unsigned char data[300];
    size_t len = 0;

    if (strcmp(command, "asnput") == 0) {
        unsigned char buf[32], *p = buf;
        int cons = 0, length = 0, tag = 0, xclass = 0;

        sscanf(line, "%*s %d %d %d %d", &cons, &length, &tag, &xclass);
        ASN1_put_object(&p, cons, length, tag, xclass);
        printf("asnput size=%d", ASN1_object_size(cons, length, tag));
        print_hex("", buf, (size_t)(p - buf));
        return 1;
    }
    if (strcmp(command, "asnhdr") != 0 && strcmp(command, "d2iobj") != 0)
        return 0;
    int delta = 0;

    sscanf(line, "%*s %599s %d", hex, &delta);
    if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
        printf("%s bad hex\n", command);
        return 1;
    }
    if (strcmp(command, "asnhdr") == 0) {
        const unsigned char *p = data;
        long length = -7, omax = (long)len + delta;
        int tag = -7, xclass = -7, ret;

        /* More than the octets is fine only when the header ends within them. */
        if (delta > 0) {
            long probe_len = -7;
            int probe_tag, probe_class;
            const unsigned char *q = data;

            if (len == 0 || ASN1_get_object(&q, &probe_len, &probe_tag, &probe_class, (long)len) & 0x80)
                omax = (long)len;
            ERR_clear_error();
        }
        ret = ASN1_get_object(&p, &length, &tag, &xclass, omax);
        printf("asnhdr ret=%#x tag=%d class=%d length=%ld used=%d", ret, tag, xclass, length, (int)(p - data));
        print_asn_errors();
    } else {
        const unsigned char *p = data;
        ASN1_OBJECT *o = d2i_ASN1_OBJECT(NULL, &p, (long)len);
        unsigned char out[300], *q = out;
        char text[700] = "";
        int n = 0;

        if (o != NULL) {
            OBJ_obj2txt(text, sizeof(text), o, 1);
            n = i2d_ASN1_OBJECT(o, &q);
        }
        printf("d2iobj %s nid=%d text=%s used=%d", o == NULL ? "NULL" : "ok", OBJ_obj2nid(o), text, (int)(p - data));
        print_hex(" i2d", out, n > 0 ? (size_t)n : 0);
        if (o != NULL && o != OBJ_nid2obj(OBJ_obj2nid(o)))
            ASN1_OBJECT_free(o);
        printf("d2iobj");
        print_asn_errors();
    }
    return 1;
}

/* Runs an INTEGER command; returns 0 if `command` isn't one. */
static int int_command(const char *command, const char *line)
{
    char hex[700] = "-";
    unsigned char data[300];
    size_t len = 0;
    int number = 0;

    if (strcmp(command, "asnset") == 0) {
        long long value = 0;
        ASN1_INTEGER *a = ASN1_INTEGER_new();

        sscanf(line, "%*s %lld", &value);
        printf("asnset %d type=%d", ASN1_INTEGER_set_int64(a, (int64_t)value), a->type);
        print_hex("", a->data, (size_t)a->length);
        ASN1_INTEGER_free(a);
        return 1;
    }
    if (strcmp(command, "asnint") != 0 && strcmp(command, "a2iint") != 0 && strcmp(command, "a2istr") != 0)
        return 0;
    sscanf(line, "%*s %d %699s", &number, hex);
    if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
        printf("%s bad hex\n", command);
        return 1;
    }
    if (strcmp(command, "asnint") == 0) {
        ASN1_STRING *s = ASN1_STRING_type_new(number);
        BIO *mem = BIO_new(BIO_s_mem());
        int64_t v = -7;
        uint64_t u = 7;
        char *out;
        long n;
        int r1, r2;

        ASN1_STRING_set(s, data, (int)len);
        r1 = ASN1_INTEGER_get_int64(&v, s);
        r2 = ASN1_INTEGER_get_uint64(&u, s);
        printf("asnint %d:%lld %d:%llu %ld %ld i2a=%d:", r1, (long long)v, r2, (unsigned long long)u,
               ASN1_INTEGER_get(s), ASN1_ENUMERATED_get(s), i2a_ASN1_INTEGER(mem, s));
        n = BIO_get_mem_data(mem, &out);
        fwrite(out, 1, (size_t)n, stdout);
        print_asn_errors();
        BIO_free(mem);
        ASN1_STRING_free(s);
    } else {
        BIO *in = BIO_new(BIO_s_mem());
        ASN1_INTEGER *a = ASN1_INTEGER_new();
        char buf[300];
        int r;

        if (number < 0 || number > 300)
            number = 300;
        BIO_write(in, data, (int)len);
        memset(buf, 'x', sizeof(buf));
        r = strcmp(command, "a2istr") == 0 ? a2i_ASN1_STRING(in, a, buf, number) : a2i_ASN1_INTEGER(in, a, buf, number);
        printf("%s %d type=%d", command, r, a->type);
        print_hex("", a->data, (size_t)a->length);
        print_escaped(" buf", 0, buf, number > 0 ? (size_t)number : 0);
        if (r == 1 && strcmp(command, "a2istr") == 0) {
            BIO *mem = BIO_new(BIO_s_mem());
            char *out;
            long n;

            r = i2a_ASN1_STRING(mem, a, V_ASN1_OCTET_STRING);
            n = BIO_get_mem_data(mem, &out);
            print_escaped(" i2a", r, out, (size_t)n);
            BIO_free(mem);
        }
        printf("%s", command);
        print_asn_errors();
        ASN1_INTEGER_free(a);
        BIO_free(in);
    }
    return 1;
}

/* Runs a BIT STRING command; returns 0 if `command` isn't one. */
static int bit_command(const char *command, const char *line)
{
    char hex[600] = "-", flags_hex[600] = "-";
    unsigned char data[300], flags[300];
    size_t len = 0, flags_len = 0;
    int n = 0, value = 0, r;
    ASN1_BIT_STRING *s;

    if (strcmp(command, "asnbit") != 0)
        return 0;
    sscanf(line, "%*s %599s %d %d %599s", hex, &n, &value, flags_hex);
    if ((strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len))
        || (strcmp(flags_hex, "-") != 0 && !parse_hex(flags_hex, flags, &flags_len))) {
        printf("asnbit bad hex\n");
        return 1;
    }
    s = ASN1_BIT_STRING_new();
    if (len > 0)
        ASN1_BIT_STRING_set(s, data, (int)len);
    s->flags = ASN1_STRING_FLAG_BITS_LEFT | 5;
    r = ASN1_BIT_STRING_set_bit(s, n, value);
    printf("asnbit %d flags=%#lx get=%d,%d,%d check=%d", r, s->flags, ASN1_BIT_STRING_get_bit(s, n - 1),
           ASN1_BIT_STRING_get_bit(s, n), ASN1_BIT_STRING_get_bit(s, n + 1),
           ASN1_BIT_STRING_check(s, flags, (int)flags_len));
    print_hex("", s->data, (size_t)s->length);
    ASN1_BIT_STRING_free(s);
    return 1;
}

/* Runs a character-string command; returns 0 if `command` isn't one. */
static int text_command(const char *command, const char *line)
{
    char hex[700] = "-";
    unsigned char data[300];
    size_t len = 0;

    if (strcmp(command, "asntext") == 0) {
        int type = 0;
        unsigned long flags = 0;
        ASN1_STRING *s;
        BIO *mem = BIO_new(BIO_s_mem());
        unsigned char *utf8 = NULL;
        char *out;
        long n;
        int r, counted;

        sscanf(line, "%*s %d %lx %699s", &type, &flags, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("asntext bad hex\n");
            BIO_free(mem);
            return 1;
        }
        s = ASN1_STRING_type_new(type);
        ASN1_STRING_set(s, data, (int)len);
        r = ASN1_STRING_print_ex(mem, s, flags);
        counted = ASN1_STRING_print_ex(NULL, s, flags);
        n = BIO_get_mem_data(mem, &out);
        print_escaped("asntext", r, out, n > 0 ? (size_t)n : 0);
        printf("asntext counted=%d", counted);
        r = ASN1_STRING_to_UTF8(&utf8, s);
        print_escaped(" utf8", r, (const char *)utf8, r > 0 ? (size_t)r : 0);
        printf("asntext");
        print_asn_errors();
        OPENSSL_free(utf8);
        ASN1_STRING_free(s);
        BIO_free(mem);
        return 1;
    }
    if (strcmp(command, "asnmb") == 0) {
        int inform = 0, r;
        unsigned long mask = 0;
        long min = 0, max = 0;
        ASN1_STRING *out = NULL;

        sscanf(line, "%*s %x %lx %ld %ld %699s", &inform, &mask, &min, &max, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("asnmb bad hex\n");
            return 1;
        }
        r = ASN1_mbstring_ncopy(&out, data, (int)len, inform, mask, min, max);
        printf("asnmb %d", r);
        if (out != NULL) {
            printf(" type=%d", out->type);
            print_hex("", out->data, (size_t)out->length);
        } else {
            printf("\n");
        }
        printf("asnmb");
        print_asn_errors();
        ASN1_STRING_free(out);
        return 1;
    }
    return 0;
}

/* Encodes `der` as a new buffer, printing its length and octets after `label`. */
static void print_i2d(const char *label, int len, unsigned char *der)
{
    printf(" %s=%d", label, len);
    if (len > 0) {
        printf(":");
        for (int i = 0; i < len; i++)
            printf("%02x", der[i]);
    }
    OPENSSL_free(der);
}

/* An application type for asnd2i: most kinds of field, a CHOICE, ANY DEFINED BY, and itself. */
typedef struct {
    int type;
    union {
        ASN1_INTEGER *num;
        ASN1_UTF8STRING *str;
    } d;
} PROBEPICK;

ASN1_CHOICE(PROBEPICK) = {
    ASN1_SIMPLE(PROBEPICK, d.num, ASN1_INTEGER),
    ASN1_EXP(PROBEPICK, d.str, ASN1_UTF8STRING, 3)
} ASN1_CHOICE_END(PROBEPICK)

typedef struct PROBEREC_st PROBEREC;
struct PROBEREC_st {
    ASN1_OBJECT *type;
    void *value;
    ASN1_OCTET_STRING *opt;
    ASN1_IA5STRING *imp;
    ASN1_BOOLEAN flag;
    STACK_OF(ASN1_TYPE) *set;
    PROBEPICK *pick;
    int64_t i64;
    PROBEREC *inner;
};
DECLARE_ASN1_ITEM(PROBEREC)

ASN1_ADB_TEMPLATE(PROBEREC_default) = ASN1_SIMPLE(PROBEREC, value, ASN1_ANY);

ASN1_ADB(PROBEREC) = {
    ADB_ENTRY(NID_sha256, ASN1_SIMPLE(PROBEREC, value, ASN1_INTEGER)),
    ADB_ENTRY(NID_sha1, ASN1_OPT(PROBEREC, value, ASN1_UTF8STRING))
} ASN1_ADB_END(PROBEREC, 0, type, 0, &PROBEREC_default_tt, NULL);

ASN1_SEQUENCE(PROBEREC) = {
    ASN1_SIMPLE(PROBEREC, type, ASN1_OBJECT),
    ASN1_ADB_OBJECT(PROBEREC),
    ASN1_EXP_OPT(PROBEREC, opt, ASN1_OCTET_STRING, 0),
    ASN1_IMP_OPT(PROBEREC, imp, ASN1_IA5STRING, 1),
    ASN1_OPT(PROBEREC, flag, ASN1_FBOOLEAN),
    ASN1_SET_OF_OPT(PROBEREC, set, ASN1_ANY),
    ASN1_OPT(PROBEREC, pick, PROBEPICK),
    ASN1_IMP_EX(PROBEREC, i64, INT64, 4, ASN1_TFLG_OPTIONAL | ASN1_TFLG_EMBED),
    ASN1_EXP_OPT(PROBEREC, inner, PROBEREC, 2)
} ASN1_SEQUENCE_END(PROBEREC)

static const ASN1_ITEM *probe_item(int n)
{
    switch (n) {
    case 0: return ASN1_ITEM_rptr(ASN1_ANY);
    case 1: return ASN1_ITEM_rptr(ASN1_SEQUENCE_ANY);
    case 2: return ASN1_ITEM_rptr(ASN1_SET_ANY);
    case 3: return ASN1_ITEM_rptr(ASN1_OCTET_STRING);
    case 4: return ASN1_ITEM_rptr(ASN1_INTEGER);
    case 5: return ASN1_ITEM_rptr(ASN1_BIT_STRING);
    case 6: return ASN1_ITEM_rptr(ASN1_BMPSTRING);
    case 7: return ASN1_ITEM_rptr(ASN1_TIME);
    case 8: return ASN1_ITEM_rptr(DIRECTORYSTRING);
    case 9: return ASN1_ITEM_rptr(INT64);
    case 10: return ASN1_ITEM_rptr(UINT32);
    case 11: return ASN1_ITEM_rptr(PROBEREC);
    case 12: return ASN1_ITEM_rptr(ASN1_SEQUENCE);
    case 14: return ASN1_ITEM_rptr(RSAPublicKey);
    case 15: return ASN1_ITEM_rptr(RSAPrivateKey);
    case 16: return ASN1_ITEM_rptr(RSA_PSS_PARAMS);
    case 17: return ASN1_ITEM_rptr(RSA_OAEP_PARAMS);
    case 18: return ASN1_ITEM_rptr(BIGNUM);
    default: return ASN1_ITEM_rptr(ASN1_UTF8STRING);
    }
}

static void print_out(const unsigned char *p, int n);

/* Runs a template engine command; returns 0 if `command` isn't one. */
static int template_command(const char *command, const char *line)
{
    if (strcmp(command, "pemread") == 0) {
        char hex[700] = "-";
        unsigned char data[300];
        size_t len = 0;
        unsigned int flags = 0;
        BIO *in;
        char *name, *header;
        unsigned char *body;
        long blen;
        int r;
        unsigned long code;

        sscanf(line, "%*s %u %699s", &flags, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("pemread bad hex\n");
            return 1;
        }
        flags &= ~(unsigned int)PEM_FLAG_SECURE;
        in = BIO_new_mem_buf(data, (int)len);
        while ((r = PEM_read_bio_ex(in, &name, &header, &body, &blen, flags)) == 1) {
            print_escaped("pemread name", 1, name, strlen(name));
            print_escaped("pemread header", 1, header, strlen(header));
            print_escaped("pemread data", (int)blen, (char *)body, (size_t)blen);
            {
                /* The header as encryption, and the body decrypted under "pw". */
                EVP_CIPHER_INFO info;
                unsigned long e;
                int ok = PEM_get_EVP_CIPHER_INFO(header, &info);

                printf("pemread cipher %d %s", ok,
                       info.cipher == NULL ? "-" : EVP_CIPHER_get0_name(info.cipher));
                print_out(info.iv, sizeof(info.iv));
                if (ok && info.cipher != NULL) {
                    ok = PEM_do_header(&info, body, &blen, NULL, "pw");
                    printf(" decrypt %d", ok);
                    if (ok)
                        print_out(body, (int)blen);
                }
                while ((e = ERR_get_error()) != 0)
                    printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
                printf("\n");
            }
            OPENSSL_free(name);
            OPENSSL_free(header);
            OPENSSL_free(body);
        }
        printf("pemread %d left %d", r, (int)BIO_pending(in));
        while ((code = ERR_get_error()) != 0)
            printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        printf("\n");
        BIO_free(in);
        return 1;
    }
    if (strcmp(command, "b64bio") == 0) {
        char hex[700] = "-";
        unsigned char data[300], out[1200];
        size_t len = 0;
        int enc = 0, nonl = 0, chunk = 1, r, total = 0;
        BIO *mem, *b64 = BIO_new(BIO_f_base64());
        char *text;
        long n;

        sscanf(line, "%*s %d %d %d %699s", &enc, &nonl, &chunk, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("b64bio bad hex\n");
            BIO_free(b64);
            return 1;
        }
        if (chunk < 1)
            chunk = 1;
        if (nonl)
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        printf("b64bio");
        if (enc) {
            size_t i;

            mem = BIO_new(BIO_s_mem());
            BIO_push(b64, mem);
            for (i = 0; i < len; i += (size_t)chunk)
                printf(" %d", BIO_write(b64, data + i, len - i < (size_t)chunk ? (int)(len - i) : chunk));
            printf(" wpending %ld flush %d", (long)BIO_wpending(b64), BIO_flush(b64));
            n = BIO_get_mem_data(mem, &text);
            print_escaped(" out", 0, text, (size_t)n);
        } else {
            mem = BIO_new_mem_buf(data, (int)len);
            BIO_push(b64, mem);
            while ((r = BIO_read(b64, out + total, chunk)) > 0 && total < 900)
                total += r;
            printf(" last %d eof %d", r, (int)BIO_eof(b64));
            print_hex("", out, (size_t)total);
        }
        BIO_free_all(b64);
        ERR_clear_error();
        return 1;
    }
    if (strcmp(command, "b64enc") == 0 || strcmp(command, "b64dec") == 0) {
        char hex[700] = "-";
        unsigned char data[300], out[1200];
        size_t len = 0, i;
        int chunk = 1, outl, r;
        int enc = strcmp(command, "b64enc") == 0;
        EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();

        sscanf(line, "%*s %d %699s", &chunk, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("%s bad hex\n", command);
            EVP_ENCODE_CTX_free(ctx);
            return 1;
        }
        if (chunk < 1)
            chunk = 1;
        printf("%s", command);
        if (enc)
            EVP_EncodeInit(ctx);
        else
            EVP_DecodeInit(ctx);
        for (i = 0; i < len || i == 0; i += (size_t)chunk) {
            int n = len - i < (size_t)chunk ? (int)(len - i) : chunk;

            memset(out, 0xee, sizeof(out));
            r = enc ? EVP_EncodeUpdate(ctx, out, &outl, data + i, n) : EVP_DecodeUpdate(ctx, out, &outl, data + i, n);
            printf(" [%d %d num=%d", r, outl, EVP_ENCODE_CTX_num(ctx));
            print_hex("", out, (size_t)(outl > 0 ? outl + 1 : 0));
            printf("]");
            if (len == 0 || (!enc && r < 0))
                break;
        }
        memset(out, 0xee, sizeof(out));
        if (enc) {
            EVP_EncodeFinal(ctx, out, &outl);
            r = 1;
        } else {
            r = EVP_DecodeFinal(ctx, out, &outl);
        }
        printf(" final %d %d", r, outl);
        print_hex("", out, (size_t)(outl > 0 ? outl + 1 : 0));
        memset(out, 0xee, sizeof(out));
        r = enc ? EVP_EncodeBlock(out, data, (int)len) : EVP_DecodeBlock(out, data, (int)len);
        printf(" block %d", r);
        print_hex("", out, (size_t)(r > 0 ? r + 1 : 0));
        printf("\n");
        EVP_ENCODE_CTX_free(ctx);
        return 1;
    }
    if (strcmp(command, "asns2i") == 0) {
        char text[300] = "";
        ASN1_INTEGER *a;
        char *s;
        unsigned long code;
        int i;

        sscanf(line, "%*s %299s", text);
        if (strcmp(text, "-") == 0)
            text[0] = '\0';
        for (i = 0; text[i] != '\0'; i++)
            if (text[i] == '_')
                text[i] = ' ';
        a = s2i_ASN1_INTEGER(NULL, text);
        if (a != NULL) {
            s = i2s_ASN1_INTEGER(NULL, a);
            printf("asns2i %s type=%d", s != NULL ? s : "NULL", a->type);
            print_hex("", a->data, (size_t)a->length);
            OPENSSL_free(s);
            ASN1_INTEGER_free(a);
        } else {
            printf("asns2i NULL\n");
        }
        printf("asns2i errors:");
        while ((code = ERR_get_error()) != 0)
            printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        printf("\n");
        return 1;
    }
    if (strcmp(command, "asnparse") == 0) {
        char hex[700] = "-";
        unsigned char data[300];
        size_t len = 0;
        int indent = 0, dump = 0, r;
        BIO *mem = BIO_new(BIO_s_mem());
        char *out;
        long outlen;
        unsigned long code;

        sscanf(line, "%*s %d %d %699s", &indent, &dump, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("asnparse bad hex\n");
            BIO_free(mem);
            return 1;
        }
        r = dump < -1 ? ASN1_parse(mem, data, (long)len, indent) : ASN1_parse_dump(mem, data, (long)len, indent, dump);
        outlen = BIO_get_mem_data(mem, &out);
        print_escaped("asnparse", r, out, (size_t)outlen);
        printf("asnparse errors:");
        while ((code = ERR_get_error()) != 0)
            printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        printf("\n");
        BIO_free(mem);
        return 1;
    }
    if (strcmp(command, "asnbio") == 0) {
        char hex[700] = "-";
        unsigned char data[300], *der;
        size_t len = 0;
        int i, dlen;
        BIO *b;
        ASN1_VALUE *v;
        unsigned long code;
        const char *edata;
        int eflags;

        sscanf(line, "%*s %699s", hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("asnbio bad hex\n");
            return 1;
        }
        b = BIO_new_mem_buf(data, (int)len);
        printf("asnbio");
        while ((v = ASN1_item_d2i_bio(ASN1_ITEM_rptr(ASN1_ANY), b, NULL)) != NULL) {
            der = NULL;
            dlen = ASN1_item_i2d(v, &der, ASN1_ITEM_rptr(ASN1_ANY));
            printf(" %d:", dlen);
            for (i = 0; i < dlen; i++)
                printf("%02x", der[i]);
            OPENSSL_free(der);
            ASN1_item_free(v, ASN1_ITEM_rptr(ASN1_ANY));
        }
        printf(" left=%d", (int)BIO_pending(b));
        while ((code = ERR_get_error_all(NULL, NULL, NULL, &edata, &eflags)) != 0) {
            printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
            if ((eflags & ERR_TXT_STRING) != 0 && edata[0] != '\0')
                printf("[%s]", edata);
        }
        printf("\n");
        BIO_free(b);
        return 1;
    }
    if (strcmp(command, "asnd2i") == 0) {
        char hex[700] = "-";
        unsigned char data[300], *der = NULL;
        const unsigned char *q = data;
        size_t len = 0;
        int n = 0, i;
        const ASN1_ITEM *it;
        ASN1_VALUE *v;
        unsigned long code;
        const char *edata;
        int eflags;

        sscanf(line, "%*s %d %699s", &n, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("asnd2i bad hex\n");
            return 1;
        }
        it = probe_item(n);
        v = ASN1_item_d2i(NULL, &q, (long)len, it);
        if (v != NULL) {
            int dlen = ASN1_item_i2d(v, &der, it);

            BIO *mem = BIO_new(BIO_s_mem());
            char *text;
            long tlen;
            int r;

            printf("asnd2i ok used=%ld der=%d:", (long)(q - data), dlen);
            for (i = 0; i < dlen; i++)
                printf("%02x", der[i]);
            OPENSSL_free(der);
            r = ASN1_item_print(mem, v, 2, it, NULL);
            tlen = BIO_get_mem_data(mem, &text);
            print_escaped(" print", r, text, (size_t)tlen);
            BIO_free(mem);
            ASN1_item_free(v, it);
        } else {
            printf("asnd2i fail used=%ld", (long)(q - data));
        }
        while ((code = ERR_get_error_all(NULL, NULL, NULL, &edata, &eflags)) != 0) {
            printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
            if ((eflags & ERR_TXT_STRING) != 0 && edata[0] != '\0')
                printf("[%s]", edata);
        }
        printf("\n");
        return 1;
    }
    if (strcmp(command, "asnany") == 0) {
        STACK_OF(ASN1_TYPE) *sk = sk_ASN1_TYPE_new_null();
        const char *p = line + strlen(command);
        char item[600];
        int n, offset;
        unsigned char *der;

        printf("asnany");
        while (sk_ASN1_TYPE_num(sk) < 8 && sscanf(p, " %599s%n", item, &offset) == 1) {
            unsigned char data[300];
            size_t len = 0;
            int type = 0;
            char *colon = strchr(item, ':');
            ASN1_TYPE *t = ASN1_TYPE_new();

            p += offset;
            if (colon == NULL || sscanf(item, "%d", &type) != 1
                || (strcmp(colon + 1, "-") != 0 && !parse_hex(colon + 1, data, &len))) {
                printf(" bad");
                ASN1_TYPE_free(t);
                continue;
            }
            if (type == V_ASN1_BOOLEAN) {
                ASN1_TYPE_set(t, type, len > 0 && data[0] != 0 ? (void *)1 : NULL);
            } else if (type == V_ASN1_NULL) {
                ASN1_TYPE_set(t, type, NULL);
            } else if (type == V_ASN1_OBJECT) {
                unsigned char object[310];
                const unsigned char *q = object;
                ASN1_OBJECT *o;

                object[0] = V_ASN1_OBJECT;
                object[1] = (unsigned char)len;
                memcpy(object + 2, data, len);
                o = len < 128 ? d2i_ASN1_OBJECT(NULL, &q, (long)len + 2) : NULL;
                if (o == NULL) {
                    printf(" noobj");
                    ASN1_TYPE_free(t);
                    ERR_clear_error();
                    continue;
                }
                ASN1_TYPE_set(t, type, o);
            } else {
                ASN1_STRING *str = ASN1_STRING_type_new(type == -2 ? V_ASN1_NEG_INTEGER : type);

                ASN1_STRING_set(str, data, (int)len);
                ASN1_TYPE_set(t, type == -2 ? V_ASN1_INTEGER : type, str);
            }
            der = NULL;
            n = i2d_ASN1_TYPE(t, &der);
            print_i2d("e", n, der);
            sk_ASN1_TYPE_push(sk, t);
        }
        der = NULL;
        n = i2d_ASN1_SEQUENCE_ANY(sk, &der);
        print_i2d("seq", n, der);
        der = NULL;
        n = i2d_ASN1_SET_ANY(sk, &der);
        print_i2d("set", n, der);
        printf(" measured=%d,%d\n", i2d_ASN1_SEQUENCE_ANY(sk, NULL), i2d_ASN1_SET_ANY(sk, NULL));
        sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
        ERR_clear_error();
        return 1;
    }
    return 0;
}

/* Runs a time command; returns 0 if `command` isn't one. */
static int time_command(const char *command, const char *line)
{
    if (strcmp(command, "asntime") == 0) {
        char hex[700] = "-";
        unsigned char data[300];
        size_t len = 0;
        int type = 0, day = 7, sec = 7, r;
        long flags = 0;
        ASN1_STRING *s, *n, *fixed = ASN1_STRING_new();
        BIO *mem = BIO_new(BIO_s_mem());
        struct tm tm;
        char *out;
        long outlen;

        sscanf(line, "%*s %d %lx %699s", &type, &flags, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("asntime bad hex\n");
            BIO_free(mem);
            ASN1_STRING_free(fixed);
            return 1;
        }
        s = ASN1_STRING_type_new(type);
        ASN1_STRING_set(s, data, (int)len);
        s->flags = flags;
        memset(&tm, 0, sizeof(tm));
        r = ASN1_TIME_to_tm(s, &tm);
        printf("asntime check=%d,%d,%d tm=%d %d-%d-%d %d:%d:%d %d %d", ASN1_TIME_check(s), ASN1_UTCTIME_check(s),
               ASN1_GENERALIZEDTIME_check(s), r, tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
               tm.tm_wday, tm.tm_yday);
        r = ASN1_TIME_print(mem, s);
        BIO_puts(mem, "|");
        r = r * 10 + ASN1_TIME_print_ex(mem, s, ASN1_DTFLGS_ISO8601);
        outlen = BIO_get_mem_data(mem, &out);
        print_escaped(" print", r, out, (size_t)outlen);
        ASN1_TIME_set_string(fixed, "20240229123456Z");
        r = ASN1_TIME_diff(&day, &sec, fixed, s);
        printf("asntime diff=%d %d %d cmp=%d", r, day, sec, ASN1_TIME_compare(s, fixed));
        n = ASN1_STRING_dup(s);
        r = ASN1_TIME_normalize(n);
        printf(" normalize=%d type=%d", r, n->type);
        print_hex("", n->data, n->length > 0 ? (size_t)n->length : 0);
        ASN1_STRING_free(n);
        ASN1_STRING_free(s);
        ASN1_STRING_free(fixed);
        BIO_free(mem);
        ERR_clear_error();
        return 1;
    }
    if (strcmp(command, "asntimet") == 0) {
        long long when = 0;
        int days = 0;
        long secs = 0;
        time_t t;
        ASN1_STRING *a, *u, *g;
        struct tm tm;

        sscanf(line, "%*s %lld %d %ld", &when, &days, &secs);
        t = (time_t)when;
        a = ASN1_TIME_adj(NULL, t, days, secs);
        u = ASN1_UTCTIME_adj(NULL, t, days, secs);
        g = ASN1_GENERALIZEDTIME_adj(NULL, t, days, secs);
        printf("asntimet %s %s %s", a ? (a->length > 0 ? (char *)a->data : "-1") : "NULL",
               u ? (char *)u->data : "NULL", g ? (g->length > 0 ? (char *)g->data : "-1") : "NULL");
        memset(&tm, 0, sizeof(tm));
        if (OPENSSL_gmtime(&t, &tm) != NULL) {
            int r = OPENSSL_gmtime_adj(&tm, days, secs);

            printf(" gmtime_adj=%d %d-%d-%d %d:%d:%d", r, tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min,
                   tm.tm_sec);
        }
        printf("\n");
        ASN1_STRING_free(a);
        ASN1_STRING_free(u);
        ASN1_STRING_free(g);
        ERR_clear_error();
        return 1;
    }
    return 0;
}

/* Runs an error-queue command; returns 0 if `command` isn't one. */
static void print_octets(const unsigned char *data, size_t len)
{
    printf(" ");
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
}

static void print_param_errors(void)
{
    unsigned long code;

    printf(" errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void print_return_size(size_t n)
{
    if (n == OSSL_PARAM_UNMODIFIED)
        printf(" return unmodified");
    else
        printf(" return %zu", n);
}

static int params_command(const char *command, const char *line)
{
    if (strcmp(command, "paramset") == 0) {
        char fn[16] = "", value[64] = "0";
        unsigned int type = 0;
        size_t size = 0;
        int null = 0, r = 0;
        unsigned char data[40];
        OSSL_PARAM p = { "p", 0, NULL, 0, 12345 };
        long long sv;
        unsigned long long uv;
        double dv;

        sscanf(line, "%*s %15s %u %zu %d %63s", fn, &type, &size, &null, value);
        sv = strtoll(value, NULL, 0);
        uv = strtoull(value, NULL, 0);
        dv = strtod(value, NULL);
        if (size > 32)
            size = 32;
        memset(data, 0xaa, sizeof(data));
        p.data_type = type;
        p.data_size = size;
        p.data = null ? NULL : data;
        printf("paramset %s %u %zu %d %s:", fn, type, size, null, value);
        /* OpenSSL reads before a value narrowed to nothing, and writes a real through NULL. */
        if ((type == OSSL_PARAM_INTEGER && size == 0 && !null)
            || (type == OSSL_PARAM_REAL && size == 8 && null
                && (strcmp(fn, "uint64") == 0 || strcmp(fn, "ulong") == 0 || strcmp(fn, "size_t") == 0))
            || (strcmp(fn, "double") == 0 && (dv == 9223372036854775808.0 || dv == -9223372036854775808.0
                                              || dv == 18446744073709551616.0))) {
            printf(" skip\n");
            return 1;
        }
        if (strcmp(fn, "int32") == 0)
            r = OSSL_PARAM_set_int32(&p, (int32_t)sv);
        else if (strcmp(fn, "uint32") == 0)
            r = OSSL_PARAM_set_uint32(&p, (uint32_t)uv);
        else if (strcmp(fn, "int64") == 0)
            r = OSSL_PARAM_set_int64(&p, (int64_t)sv);
        else if (strcmp(fn, "uint64") == 0)
            r = OSSL_PARAM_set_uint64(&p, (uint64_t)uv);
        else if (strcmp(fn, "double") == 0)
            r = OSSL_PARAM_set_double(&p, dv);
        else if (strcmp(fn, "int") == 0)
            r = OSSL_PARAM_set_int(&p, (int)sv);
        else if (strcmp(fn, "uint") == 0)
            r = OSSL_PARAM_set_uint(&p, (unsigned int)uv);
        else if (strcmp(fn, "long") == 0)
            r = OSSL_PARAM_set_long(&p, (long)sv);
        else if (strcmp(fn, "ulong") == 0)
            r = OSSL_PARAM_set_ulong(&p, (unsigned long)uv);
        else if (strcmp(fn, "size_t") == 0)
            r = OSSL_PARAM_set_size_t(&p, (size_t)uv);
        else if (strcmp(fn, "time_t") == 0)
            r = OSSL_PARAM_set_time_t(&p, (time_t)sv);
        printf(" %d", r);
        print_return_size(p.return_size);
        if (!null)
            print_octets(data, size);
        print_param_errors();
        return 1;
    }
    if (strcmp(command, "paramget") == 0) {
        char hex[700] = "-";
        unsigned char data[300];
        size_t len = 0;
        unsigned int type = 0;
        OSSL_PARAM p = { "p", 0, NULL, 0, 0 };
        int32_t i32;
        uint32_t u32;
        int64_t i64;
        uint64_t u64;
        double d;
        int r;

        sscanf(line, "%*s %u %699s", &type, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("paramget bad hex\n");
            return 1;
        }
        printf("paramget %u %s:", type, hex);
        if (type == OSSL_PARAM_INTEGER && len == 0) {
            printf(" skip\n");
            return 1;
        }
        p.data_type = type;
        p.data = data;
        p.data_size = len;
        r = OSSL_PARAM_get_int32(&p, &i32);
        printf(" int32 %d %d", r, r ? i32 : 0);
        r = OSSL_PARAM_get_uint32(&p, &u32);
        printf(" uint32 %d %u", r, r ? u32 : 0);
        r = OSSL_PARAM_get_int64(&p, &i64);
        printf(" int64 %d %lld", r, r ? (long long)i64 : 0);
        r = OSSL_PARAM_get_uint64(&p, &u64);
        printf(" uint64 %d %llu", r, r ? (unsigned long long)u64 : 0);
        r = OSSL_PARAM_get_double(&p, &d);
        printf(" double %d %.17g", r, r ? d : 0);
        print_param_errors();
        return 1;
    }
    if (strcmp(command, "paramstr") == 0) {
        char hex[700] = "-";
        unsigned char data[300], out[300];
        size_t len = 0, size = 0, max = 0, used = 99;
        int op = 0, r;
        OSSL_PARAM p = { "p", 0, NULL, 0, 12345 };
        void *buf = out;

        sscanf(line, "%*s %d %zu %zu %699s", &op, &size, &max, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("paramstr bad hex\n");
            return 1;
        }
        if (max > sizeof(out))
            max = sizeof(out);
        if (size > sizeof(out))
            size = sizeof(out);
        memset(out, 0xaa, sizeof(out));
        printf("paramstr %d %zu %zu %s:", op, size, max, hex);
        if (op == 0 || op == 1) {
            if (size > len)
                size = len;
            p.data_type = op == 0 ? OSSL_PARAM_UTF8_STRING : OSSL_PARAM_OCTET_STRING;
            p.data = data;
            p.data_size = size;
            if (op == 0)
                r = OSSL_PARAM_get_utf8_string(&p, (char **)&buf, max);
            else
                r = OSSL_PARAM_get_octet_string(&p, &buf, max, &used);
            printf(" %d used %zu", r, used);
            print_octets(out, max + 1 < sizeof(out) ? max + 1 : max);
        } else {
            data[len < sizeof(data) ? len : sizeof(data) - 1] = '\0';
            p.data_type = op == 2 ? OSSL_PARAM_UTF8_STRING : OSSL_PARAM_OCTET_STRING;
            p.data = max == 0 ? NULL : out;
            p.data_size = size;
            if (op == 2)
                r = OSSL_PARAM_set_utf8_string(&p, (const char *)data);
            else
                r = OSSL_PARAM_set_octet_string(&p, data, len);
            printf(" %d", r);
            print_return_size(p.return_size);
            print_octets(out, size + 1 < sizeof(out) ? size + 1 : size);
        }
        print_param_errors();
        return 1;
    }
    if (strcmp(command, "parammerge") == 0) {
        char lists[2][300] = { "-", "-" };
        OSSL_PARAM arrays[2][40];
        int values[2][40];
        OSSL_PARAM *m, *q;
        int a;

        sscanf(line, "%*s %299s %299s", lists[0], lists[1]);
        printf("parammerge %s %s:", lists[0], lists[1]);
        for (a = 0; a < 2; a++) {
            int n = 0;
            char *key = strcmp(lists[a], "-") == 0 ? NULL : strtok(lists[a], ",");

            for (; key != NULL && n < 39; key = strtok(NULL, ",")) {
                values[a][n] = a * 100 + n;
                arrays[a][n] = OSSL_PARAM_construct_int(key, &values[a][n]);
                n++;
            }
            arrays[a][n] = OSSL_PARAM_construct_end();
        }
        m = OSSL_PARAM_merge(arrays[0], arrays[1]);
        if (m == NULL)
            printf(" NULL");
        for (q = m; q != NULL && q->key != NULL; q++)
            printf(" %s=%d", q->key, *(int *)q->data);
        OSSL_PARAM_free(m);
        print_param_errors();
        return 1;
    }
    return 0;
}

static OSSL_LIB_CTX *ctx_slots[4];

static OSSL_LIB_CTX *ctx_named(const char *name, int *ok)
{
    *ok = 1;
    if (strcmp(name, "-") == 0)
        return NULL;
    if (strcmp(name, "g") == 0)
        return OSSL_LIB_CTX_get0_global_default();
    if (name[0] >= '0' && name[0] <= '3' && name[1] == '\0' && ctx_slots[name[0] - '0'] != NULL)
        return ctx_slots[name[0] - '0'];
    *ok = 0;
    return NULL;
}

static void print_ctx_name(OSSL_LIB_CTX *ctx)
{
    int i;

    if (ctx == NULL) {
        printf(" NULL");
        return;
    }
    if (ctx == OSSL_LIB_CTX_get0_global_default()) {
        printf(" g");
        return;
    }
    for (i = 0; i < 4; i++)
        if (ctx == ctx_slots[i]) {
            printf(" %d", i);
            return;
        }
    printf(" other");
}

static int ctx_command(const char *command, const char *line)
{
    char name[16] = "-";
    long long n = 0;
    int slot = -1, ok, i;
    OSSL_LIB_CTX *ctx;

    if (strncmp(command, "ctx", 3) != 0)
        return 0;
    sscanf(line, "%*s %15s %lld", name, &n);
    if (name[0] >= '0' && name[0] <= '3' && name[1] == '\0')
        slot = name[0] - '0';
    printf("%s %s:", command, name);
    if (strcmp(command, "ctxnew") == 0) {
        if (slot < 0 || ctx_slots[slot] != NULL)
            printf(" busy");
        else
            printf(" %s", (ctx_slots[slot] = OSSL_LIB_CTX_new()) != NULL ? "made" : "NULL");
    } else if (strcmp(command, "ctxfree") == 0) {
        if (slot < 0 || ctx_slots[slot] == NULL) {
            printf(" empty");
        } else {
            int is_default = OSSL_LIB_CTX_set0_default(NULL) == ctx_slots[slot];

            OSSL_LIB_CTX_free(ctx_slots[slot]);
            if (is_default) {
                printf(" default, kept");
            } else {
                ctx_slots[slot] = NULL;
                printf(" freed");
            }
        }
    } else if (strcmp(command, "ctxfreeglobal") == 0) {
        if (OSSL_LIB_CTX_set0_default(NULL) == OSSL_LIB_CTX_get0_global_default()) {
            OSSL_LIB_CTX_free(OSSL_LIB_CTX_get0_global_default());
            printf(" kept %llu", (unsigned long long)OSSL_get_max_threads(NULL));
        } else {
            printf(" skip");
        }
    } else if (strcmp(command, "ctxdefault") == 0) {
        ctx = ctx_named(name, &ok);
        if (ok)
            print_ctx_name(OSSL_LIB_CTX_set0_default(ctx));
        else
            printf(" empty");
        printf(" now");
        print_ctx_name(OSSL_LIB_CTX_set0_default(NULL));
    } else if (strcmp(command, "ctxmax") == 0 || strcmp(command, "ctxdiag") == 0) {
        int max = strcmp(command, "ctxmax") == 0;

        ctx = ctx_named(name, &ok);
        if (!ok) {
            printf(" empty\n");
            return 1;
        }
        if (max)
            printf(" %d", OSSL_set_max_threads(ctx, (uint64_t)n));
        else
            OSSL_LIB_CTX_set_conf_diagnostics(ctx, (int)n);
        for (i = -1; i < 4; i++) {
            OSSL_LIB_CTX *c = i < 0 ? OSSL_LIB_CTX_get0_global_default() : ctx_slots[i];

            if (c == NULL)
                continue;
            if (max)
                printf(" %llu", (unsigned long long)OSSL_get_max_threads(c));
            else
                printf(" %d", OSSL_LIB_CTX_get_conf_diagnostics(c));
        }
        if (max)
            printf(" default %llu", (unsigned long long)OSSL_get_max_threads(NULL));
        else
            printf(" default %d", OSSL_LIB_CTX_get_conf_diagnostics(NULL));
    } else if (strcmp(command, "ctxexidx") == 0) {
        printf(" %d", CRYPTO_get_ex_new_index(atoi(name), 0, NULL, NULL, NULL, NULL));
    } else {
        printf(" unknown");
    }
    printf("\n");
    ERR_clear_error();
    return 1;
}

static OSSL_LIB_CTX *prop_ctx;

/* Prints text quoted on the same line, bytes outside printable ASCII escaped. */
static void print_quoted(const char *text)
{
    printf(" \"");
    for (; *text != '\0'; text++) {
        unsigned char c = (unsigned char)*text;

        if (c >= ' ' && c <= '~' && c != '\\' && c != '"')
            putchar(c);
        else
            printf("\\x%02x", c);
    }
    printf("\"");
}

static void print_prop_state(int r)
{
    unsigned long code;
    const char *data;
    int flags;
    char *text;

    printf(" %d errors:", r);
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && data[0] != '\0')
            print_quoted(data);
    }
    text = EVP_get1_default_properties(prop_ctx);
    printf(" fips %d now", EVP_default_properties_is_fips_enabled(prop_ctx));
    if (text == NULL)
        printf(" NULL");
    else
        print_quoted(text);
    printf("\n");
    OPENSSL_free(text);
}

static int prop_command(const char *command, const char *line)
{
    if (strcmp(command, "propnew") == 0) {
        OSSL_LIB_CTX_free(prop_ctx);
        prop_ctx = OSSL_LIB_CTX_new();
        printf("propnew\n");
        return 1;
    }
    if (prop_ctx == NULL)
        prop_ctx = OSSL_LIB_CTX_new();
    if (strcmp(command, "propset") == 0) {
        char hex[700] = "";
        unsigned char q[300];
        size_t len = 0;

        sscanf(line, "%*s %699s", hex);
        if (hex[0] != '\0' && strcmp(hex, "-") != 0 && !parse_hex(hex, q, &len)) {
            printf("propset bad hex\n");
            return 1;
        }
        q[len] = '\0';
        printf("propset %s:", hex[0] == '\0' ? "NULL" : hex);
        print_prop_state(EVP_set_default_properties(prop_ctx, hex[0] == '\0' ? NULL : (const char *)q));
        return 1;
    }
    if (strcmp(command, "propfips") == 0) {
        int enable = 0;

        sscanf(line, "%*s %d", &enable);
        printf("propfips %d:", enable);
        print_prop_state(EVP_default_properties_enable_fips(prop_ctx, enable));
        return 1;
    }
    return 0;
}

static OSSL_LIB_CTX *prov_ctx;
static OSSL_PROVIDER *prov_slots[8];
static int prov_library_base = -1;

static void print_prov_errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf(" errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if (ERR_GET_LIB(code) == ERR_LIB_CRYPTO && (flags & ERR_TXT_STRING) != 0 && data[0] != '\0')
            print_quoted(data);
    }
    printf("\n");
}

static int print_prov_name(OSSL_PROVIDER *prov, void *arg)
{
    (void)arg;
    printf(" %s", OSSL_PROVIDER_get0_name(prov));
    return 1;
}

static int prov_command(const char *command, const char *line)
{
    char name[64] = "";
    int slot = -1, keep = 0;

    if (command[0] != 'p' || (strcmp(command, "pnew") != 0 && strcmp(command, "pload") != 0
                              && strcmp(command, "ptry") != 0 && strcmp(command, "punload") != 0
                              && strcmp(command, "pavail") != 0 && strcmp(command, "pall") != 0
                              && strcmp(command, "pparams") != 0))
        return 0;
    if (prov_library_base < 0)
        prov_library_base = ERR_get_next_error_library();
    if (strcmp(command, "pnew") == 0 || prov_ctx == NULL) {
        int i;

        for (i = 0; i < 8; i++) {
            OSSL_PROVIDER_unload(prov_slots[i]);
            prov_slots[i] = NULL;
        }
        OSSL_LIB_CTX_free(prov_ctx);
        prov_ctx = OSSL_LIB_CTX_new();
        if (strcmp(command, "pnew") == 0) {
            printf("pnew\n");
            return 1;
        }
    }
    printf("%s", line);
    if (strcmp(command, "pload") == 0 || strcmp(command, "ptry") == 0) {
        sscanf(line, "%*s %d %63s %d", &slot, name, &keep);
        if (slot < 0 || slot > 7 || prov_slots[slot] != NULL) {
            printf(": busy\n");
            return 1;
        }
        prov_slots[slot] = strcmp(command, "pload") == 0 ? OSSL_PROVIDER_load(prov_ctx, name)
                                                         : OSSL_PROVIDER_try_load(prov_ctx, name, keep);
        printf(": %s", prov_slots[slot] == NULL ? "NULL" : "loaded");
    } else if (strcmp(command, "punload") == 0) {
        sscanf(line, "%*s %d", &slot);
        if (slot < 0 || slot > 7 || prov_slots[slot] == NULL) {
            printf(": empty\n");
            return 1;
        }
        printf(": %d", OSSL_PROVIDER_unload(prov_slots[slot]));
        prov_slots[slot] = NULL;
    } else if (strcmp(command, "pavail") == 0) {
        sscanf(line, "%*s %63s", name);
        printf(": %d", OSSL_PROVIDER_available(prov_ctx, name));
    } else if (strcmp(command, "pall") == 0) {
        int i, j, r;

        printf(":");
        r = OSSL_PROVIDER_do_all(prov_ctx, print_prov_name, NULL);
        printf(" (%d) same:", r);
        for (i = 0; i < 8; i++)
            for (j = i + 1; j < 8; j++)
                if (prov_slots[i] != NULL && prov_slots[i] == prov_slots[j])
                    printf(" %d=%d", i, j);
        printf(" libraries %d", ERR_get_next_error_library() - prov_library_base);
    } else {
        const char *pname = NULL, *version = NULL;
        int status = -1;
        OSSL_PARAM params[4];

        sscanf(line, "%*s %d", &slot);
        if (slot < 0 || slot > 7 || prov_slots[slot] == NULL) {
            printf(": empty\n");
            return 1;
        }
        params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, (char **)&pname, 0);
        params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, (char **)&version, 0);
        params[2] = OSSL_PARAM_construct_int(OSSL_PROV_PARAM_STATUS, &status);
        params[3] = OSSL_PARAM_construct_end();
        printf(": %s %d", OSSL_PROVIDER_get0_name(prov_slots[slot]), OSSL_PROVIDER_get_params(prov_slots[slot], params));
        printf(" \"%s\" \"%s\" %d self-test %d", pname, version, status, OSSL_PROVIDER_self_test(prov_slots[slot]));
    }
    print_prov_errors();
    /*
     * A failed module lookup's data holds the module directory and the system loader's message,
     * which differ between the libraries; drop the error state so no slot keeps a buffer sized
     * by it (the err commands print the sizes).
     */
    OPENSSL_thread_stop();
    return 1;
}

static void *f_newctx(void *provctx) { return provctx; }
static void f_freectx(void *ctx) { (void)ctx; }
static int f_init(void *ctx, const OSSL_PARAM params[]) { (void)ctx, (void)params; return 1; }
static int f_update(void *ctx, const unsigned char *in, size_t inl) { (void)ctx, (void)in, (void)inl; return 1; }
static int f_final(void *ctx, unsigned char *out, size_t *outl, size_t outsz)
{
    (void)ctx, (void)out, (void)outsz;
    *outl = 0;
    return 1;
}
static int f_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);

    return p == NULL || OSSL_PARAM_set_size_t(p, 20);
}

static const OSSL_DISPATCH f_digest[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))f_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))f_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))f_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))f_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))f_freectx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))f_get_params },
    OSSL_DISPATCH_END
};
static const OSSL_ALGORITHM fp_digests[] = {
    { "ALG-1:A1", "provider=fp,x.n=1,x.s=a,fips=yes", f_digest, "p1a" },
    { "ALG-1", "provider=fp,x.n=2,x.s=b", f_digest, "p1b" },
    { "ALG-1", "provider=fp,x.n=3,fips=no,x.flag", f_digest, "p1c" },
    { "ALG-2:A2", "provider=fp,x.n=1", f_digest, "p2a" },
    { "ALG-2", "provider=fp,x.s='Q',x.n=-1", f_digest, "p2b" },
    { "ALG-3", "provider=fp", f_digest, "p3" },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM fq_digests[] = {
    { "ALG-1", "provider=fq,x.n=1", f_digest, "q1" },
    { "ALG-4:A4", "provider=fq,fips=yes,x.s=a", f_digest, "q4" },
    { "ALG-2", "provider=fq,x.flag=no", f_digest, "q2" },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM *fp_query(void *provctx, int op, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    return op == OSSL_OP_DIGEST ? fp_digests : NULL;
}
static const OSSL_ALGORITHM *fq_query(void *provctx, int op, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    return op == OSSL_OP_DIGEST ? fq_digests : NULL;
}
static const OSSL_DISPATCH fp_dispatch[] = { { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fp_query },
                                             OSSL_DISPATCH_END };
static const OSSL_DISPATCH fq_dispatch[] = { { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fq_query },
                                             OSSL_DISPATCH_END };
static int fp_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    (void)in;
    *out = fp_dispatch;
    *provctx = (void *)handle;
    return 1;
}
static int fq_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    (void)in;
    *out = fq_dispatch;
    *provctx = (void *)handle;
    return 1;
}

static OSSL_LIB_CTX *fetch_ctx;
static OSSL_PROVIDER *fetch_provs[2];

static void print_fetch_errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf(" errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && data[0] != '\0') {
            printf(" \"");
            for (; *data != '\0'; data++) {
                unsigned char c = (unsigned char)*data;

                if (isdigit(c)) {
                    putchar('#');
                    while (isdigit((unsigned char)data[1]))
                        data++;
                } else if (c >= ' ' && c <= '~' && c != '\\' && c != '"') {
                    putchar(c);
                } else {
                    printf("\\x%02x", c);
                }
            }
            printf("\"");
        }
    }
    printf("\n");
}

static void print_impl(EVP_MD *md, void *arg)
{
    (void)arg;
    printf(" %s", EVP_MD_get0_description(md));
}

static int fetch_command(const char *command, const char *line)
{
    char a[64] = "", hex[700] = "-";
    unsigned char q[300];
    size_t len = 0;
    int which;

    if (strcmp(command, "fnew") != 0 && strcmp(command, "ffetch") != 0 && strcmp(command, "fdefault") != 0
        && strcmp(command, "fall") != 0 && strcmp(command, "fload") != 0 && strcmp(command, "funload") != 0)
        return 0;
    if (strcmp(command, "fnew") == 0 || fetch_ctx == NULL) {
        OSSL_PROVIDER_unload(fetch_provs[0]);
        OSSL_PROVIDER_unload(fetch_provs[1]);
        OSSL_LIB_CTX_free(fetch_ctx);
        fetch_ctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER_add_builtin(fetch_ctx, "fp", fp_init);
        OSSL_PROVIDER_add_builtin(fetch_ctx, "fq", fq_init);
        fetch_provs[0] = OSSL_PROVIDER_load(fetch_ctx, "fp");
        fetch_provs[1] = OSSL_PROVIDER_load(fetch_ctx, "fq");
        if (strcmp(command, "fnew") == 0) {
            printf("fnew\n");
            return 1;
        }
    }
    printf("%s", line);
    if (strcmp(command, "ffetch") == 0) {
        EVP_MD *md;

        sscanf(line, "%*s %63s %699s", a, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, q, &len)) {
            printf(": bad hex\n");
            return 1;
        }
        q[len] = '\0';
        md = EVP_MD_fetch(fetch_ctx, a, strcmp(hex, "-") == 0 ? NULL : (const char *)q);
        printf(": %s", md == NULL ? "NULL" : EVP_MD_get0_description(md));
        EVP_MD_free(md);
    } else if (strcmp(command, "fdefault") == 0) {
        sscanf(line, "%*s %699s", hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, q, &len)) {
            printf(": bad hex\n");
            return 1;
        }
        q[len] = '\0';
        printf(": %d", EVP_set_default_properties(fetch_ctx, strcmp(hex, "-") == 0 ? NULL : (const char *)q));
    } else if (strcmp(command, "fall") == 0) {
        printf(":");
        EVP_MD_do_all_provided(fetch_ctx, print_impl, NULL);
    } else {
        sscanf(line, "%*s %63s", a);
        which = a[0] == 'q';
        if (strcmp(command, "fload") == 0) {
            if (fetch_provs[which] == NULL)
                fetch_provs[which] = OSSL_PROVIDER_load(fetch_ctx, which ? "fq" : "fp");
            printf(": %s", fetch_provs[which] != NULL ? "loaded" : "NULL");
        } else {
            printf(": %d", fetch_provs[which] == NULL ? -1 : OSSL_PROVIDER_unload(fetch_provs[which]));
            fetch_provs[which] = NULL;
        }
    }
    print_fetch_errors();
    /* The data's name numbers differ between the libraries: drop the buffers they sized. */
    OPENSSL_thread_stop();
    return 1;
}

static EVP_MD_CTX *digest_ctx[2];
static int digest_current;
static size_t digest_offset;
static unsigned char digest_data[2048];

static void print_digest_errors(void)
{
    unsigned long code;

    printf(" errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static int digest_command(const char *command, const char *line)
{
    EVP_MD_CTX *ctx;
    char a[64] = "", key[32] = "";
    unsigned char out[300];
    unsigned long n = 0;
    size_t sz;
    int r = 0;

    if (command[0] != 'd' || (strcmp(command, "dctx") != 0 && strcmp(command, "dinit") != 0
            && strcmp(command, "dinitp") != 0 && strcmp(command, "dset") != 0
            && strcmp(command, "dupdate") != 0 && strcmp(command, "dfinal") != 0
            && strcmp(command, "dxof") != 0 && strcmp(command, "dsqueeze") != 0
            && strcmp(command, "dsize") != 0 && strcmp(command, "dflags") != 0
            && strcmp(command, "dcopy") != 0 && strcmp(command, "dreset") != 0
            && strcmp(command, "dname") != 0 && strcmp(command, "dnid") != 0))
        return 0;
    if (digest_ctx[0] == NULL) {
        size_t i;

        for (i = 0; i < sizeof(digest_data); i++)
            digest_data[i] = (unsigned char)(i * 7 + 3);
        digest_ctx[0] = EVP_MD_CTX_new();
        digest_ctx[1] = EVP_MD_CTX_new();
    }
    ctx = digest_ctx[digest_current];
    printf("%s:", line);
    memset(out, 0xee, sizeof(out));
    if (strcmp(command, "dctx") == 0) {
        sscanf(line, "%*s %lu", &n);
        digest_current = n != 0;
        printf("\n");
        return 1;
    } else if (strcmp(command, "dinit") == 0 || strcmp(command, "dinitp") == 0) {
        EVP_MD *md = NULL;
        OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

        sscanf(line, "%*s %63s %31s %lu", a, key, &n);
        sz = n;
        if (strcmp(a, "-") != 0 && (md = EVP_MD_fetch(NULL, a, NULL)) == NULL) {
            printf(" fetch failed");
            print_digest_errors();
            return 1;
        }
        if (strcmp(command, "dinitp") == 0) {
            params[0] = OSSL_PARAM_construct_size_t(key, &sz);
            r = EVP_DigestInit_ex2(ctx, md, params);
        } else {
            r = EVP_DigestInit_ex(ctx, md, NULL);
        }
        EVP_MD_free(md);
        printf(" %d", r);
    } else if (strcmp(command, "dset") == 0) {
        OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

        sscanf(line, "%*s %31s %lu", key, &n);
        sz = n;
        params[0] = OSSL_PARAM_construct_size_t(key, &sz);
        printf(" %d", EVP_MD_CTX_set_params(ctx, params));
    } else if (strcmp(command, "dupdate") == 0) {
        sscanf(line, "%*s %lu", &n);
        if (n > 1024)
            n = 1024;
        printf(" %d", EVP_DigestUpdate(ctx, digest_data + digest_offset, n));
        digest_offset = (digest_offset + n * 3 + 1) % 1024;
    } else if (strcmp(command, "dfinal") == 0) {
        unsigned int len = 0;

        if (EVP_MD_CTX_get_size_ex(ctx) > 256) {
            printf(" too long\n");
            return 1;
        }
        r = EVP_DigestFinal_ex(ctx, out, &len);
        printf(" %d %u ", r, len);
        for (sz = 0; sz < (r ? len : 0) && sz < 256; sz++)
            printf("%02x", out[sz]);
    } else if (strcmp(command, "dxof") == 0 || strcmp(command, "dsqueeze") == 0) {
        sscanf(line, "%*s %lu", &n);
        if (n > 256)
            n = 256;
        r = command[1] == 'x' ? EVP_DigestFinalXOF(ctx, out, n) : EVP_DigestSqueeze(ctx, out, n);
        printf(" %d ", r);
        for (sz = 0; sz < (r ? n : 0); sz++)
            printf("%02x", out[sz]);
    } else if (strcmp(command, "dsize") == 0) {
        printf(" %d", EVP_MD_CTX_get_size_ex(ctx));
    } else if (strcmp(command, "dflags") == 0) {
        printf(" %x", EVP_MD_CTX_test_flags(ctx, 0xffffff));
    } else if (strcmp(command, "dname") == 0 || strcmp(command, "dnid") == 0) {
        const EVP_MD *md;

        sscanf(line, "%*s %63s", a);
        md = command[1] == 'n' && command[2] == 'a' ? EVP_get_digestbyname(a)
                                                     : EVP_get_digestbynid(atoi(a));
        if (md == NULL)
            printf(" NULL");
        else
            printf(" %s %d %d", EVP_MD_get0_name(md), EVP_MD_get_type(md), EVP_MD_get_pkey_type(md));
    } else if (strcmp(command, "dcopy") == 0) {
        printf(" %d", EVP_MD_CTX_copy_ex(digest_ctx[!digest_current], ctx));
    } else {
        printf(" %d", EVP_MD_CTX_reset(ctx));
    }
    print_digest_errors();
    return 1;
}

static EVP_CIPHER_CTX *cipher_ctx[2];
static int cipher_current;
/* Whether each context's cipher has had a key, and an init that succeeded, since it was set. */
static int cipher_keyed[2], cipher_ready[2];
/*
 * Whether each context was turned around by an init that failed before setting its key: ECB
 * and CBC then run the old direction's key schedule the platform's way in OpenSSL
 * (docs/DEVIATIONS.md), so data operations are skipped until a key is set.
 */
static int cipher_turned[2];
/*
 * Whether each context is GCM given a key without an IV: what it then does with data is the
 * platform's in OpenSSL (docs/DEVIATIONS.md), so its data operations are skipped.
 */
static int cipher_gcm_noiv[2];
static size_t cipher_offset;
static unsigned char cipher_data[2048], cipher_key[64], cipher_iv[16], cipher_tag[16];

static void print_out(const unsigned char *p, int n)
{
    int i;

    printf(" ");
    for (i = 0; i < n && i < 1100; i++)
        printf("%02x", p[i]);
}

/* Whether GCM made its IV up at random (its output then differs from run to run). */
/* Whether the context's cipher is `name` (or has it as a name). */
static int cipher_is(EVP_CIPHER_CTX *ctx, const char *name)
{
    const EVP_CIPHER *c = EVP_CIPHER_CTX_get0_cipher(ctx);

    return c != NULL && EVP_CIPHER_is_a(c, name);
}

/* Whether the context's cipher is one of the AES key wraps. */
static int aes_wrap(EVP_CIPHER_CTX *ctx)
{
    const EVP_CIPHER *c = EVP_CIPHER_CTX_get0_cipher(ctx);

    return c != NULL && EVP_CIPHER_get_mode(c) == EVP_CIPH_WRAP_MODE
           && !cipher_is(ctx, "DES3-WRAP");
}

/* Whether the context's cipher is SIV or GCM-SIV. */
static int siv(EVP_CIPHER_CTX *ctx)
{
    const EVP_CIPHER *c = EVP_CIPHER_CTX_get0_cipher(ctx);

    return c != NULL && (EVP_CIPHER_get_mode(c) == EVP_CIPH_SIV_MODE
                         || EVP_CIPHER_get_mode(c) == EVP_CIPH_GCM_SIV_MODE);
}

/*
 * Whether the context is GCM-SIV with no init that succeeded: OpenSSL then uses a cipher
 * context it hasn't made for a message or final (docs/DEVIATIONS.md).
 */
static int gcm_siv_unready(EVP_CIPHER_CTX *ctx)
{
    const EVP_CIPHER *c = EVP_CIPHER_CTX_get0_cipher(ctx);

    return c != NULL && EVP_CIPHER_get_mode(c) == EVP_CIPH_GCM_SIV_MODE
           && !cipher_ready[cipher_current];
}

/* Whether the context's output is random: GCM's generated IV, triple DES's key wrap. */
static int random_iv(EVP_CIPHER_CTX *ctx)
{
    unsigned int gen = 0;
    OSSL_PARAM params[2];

    if (cipher_is(ctx, "DES3-WRAP") && EVP_CIPHER_CTX_is_encrypting(ctx))
        return 1;
    if (EVP_CIPHER_CTX_get0_cipher(ctx) == NULL
        || EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(ctx)) != EVP_CIPH_GCM_MODE)
        return 0;
    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_AEAD_IV_GENERATED, &gen);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_CIPHER_CTX_get_params(ctx, params) == 1 && gen != 0;
}

static int cipher_command(const char *command, const char *line)
{
    static const char *const commands[] = { "cctx", "cinit", "cinitp", "cupdate", "cfinal",
                                            "ccipher", "cpad", "ckeylen", "cnum", "cflags",
                                            "cstate", "cctrl", "ccopy", "creset", "cname",
                                            "cnid", "caad", "cmsglen", "ctagget", "ctagset",
                                            "ctaglen", "cparam", "ctlsaad", "casn1", NULL };
    const char *const *c;
    EVP_CIPHER_CTX *ctx;
    char a[64] = "", key[32] = "";
    unsigned char out[1100];
    long n = 0, m = 0, k = 0;
    int r = 0, outl = -7;

    for (c = commands; *c != NULL && strcmp(*c, command) != 0; c++)
        ;
    if (*c == NULL)
        return 0;
    if (cipher_ctx[0] == NULL) {
        size_t i;

        for (i = 0; i < sizeof(cipher_data); i++)
            cipher_data[i] = (unsigned char)(i * 13 + 1);
        for (i = 0; i < sizeof(cipher_key); i++)
            cipher_key[i] = (unsigned char)(i * 5 + 7);
        for (i = 0; i < sizeof(cipher_iv); i++)
            cipher_iv[i] = (unsigned char)(0xf0 + i);
        cipher_ctx[0] = EVP_CIPHER_CTX_new();
        cipher_ctx[1] = EVP_CIPHER_CTX_new();
    }
    ctx = cipher_ctx[cipher_current];
    printf("%s:", line);
    memset(out, 0xee, sizeof(out));
    if (cipher_gcm_noiv[cipher_current]
        && (strcmp(command, "cupdate") == 0 || strcmp(command, "ccipher") == 0
            || strcmp(command, "cfinal") == 0 || strcmp(command, "caad") == 0
            || strcmp(command, "cmsglen") == 0)) {
        printf(" skipped: GCM without an IV\n");
        return 1;
    }
    if (cipher_turned[cipher_current]
        && (strcmp(command, "cupdate") == 0 || strcmp(command, "ccipher") == 0
            || strcmp(command, "cfinal") == 0)) {
        printf(" skipped: turned around without a key\n");
        return 1;
    }
    if (strcmp(command, "cctx") == 0) {
        sscanf(line, "%*s %ld", &n);
        cipher_current = n != 0;
        printf("\n");
        return 1;
    } else if (strcmp(command, "cinit") == 0) {
        EVP_CIPHER *ciph = NULL;
        int turns, was = EVP_CIPHER_CTX_is_encrypting(ctx);

        sscanf(line, "%*s %63s %ld %ld %ld", a, &n, &m, &k);
        turns = strcmp(a, "-") == 0 && n != -1 && (n != 0) != was
                && EVP_CIPHER_CTX_get0_cipher(ctx) != NULL
                && EVP_CIPHER_CTX_get_block_size(ctx) > 1
                && EVP_CIPHER_CTX_get_mode(ctx) != EVP_CIPH_WRAP_MODE
                && (EVP_CIPHER_CTX_get_block_size(ctx) != 8
                    || strncmp(EVP_CIPHER_get0_name(EVP_CIPHER_CTX_get0_cipher(ctx)), "DES", 3) != 0);
        if (turns && m == 0) {
            /*
             * ECB and CBC keep the old direction's key schedule in OpenSSL: turning around
             * without a key runs it the platform's way (docs/DEVIATIONS.md).
             */
            printf(" skipped\n");
            return 1;
        }
        if (strcmp(a, "-") != 0 && (ciph = EVP_CIPHER_fetch(NULL, a, NULL)) == NULL) {
            printf(" fetch failed");
            print_digest_errors();
            return 1;
        }
        r = EVP_CipherInit_ex(ctx, ciph, NULL, m ? cipher_key : NULL, k ? cipher_iv : NULL,
                              (int)n);
        if ((m && r) || ciph != NULL)
            cipher_turned[cipher_current] = 0;
        else if (turns && !r && EVP_CIPHER_CTX_is_encrypting(ctx) != was)
            cipher_turned[cipher_current] = 1;
        if (ciph != NULL) {
            cipher_keyed[cipher_current] = m && r;
            cipher_ready[cipher_current] = r;
        } else {
            cipher_keyed[cipher_current] |= m && r;
            cipher_ready[cipher_current] |= r;
        }
        if (EVP_CIPHER_CTX_get0_cipher(ctx) != NULL
            && EVP_CIPHER_CTX_get_mode(ctx) == EVP_CIPH_GCM_MODE && m && !k)
            cipher_gcm_noiv[cipher_current] = 1;
        else if (k && r)
            cipher_gcm_noiv[cipher_current] = 0;
        EVP_CIPHER_free(ciph);
        printf(" %d", r);
    } else if (strcmp(command, "cinitp") == 0) {
        EVP_CIPHER *ciph;
        OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
        size_t sz;
        unsigned int u;

        sscanf(line, "%*s %63s %31s %ld", a, key, &n);
        if ((ciph = EVP_CIPHER_fetch(NULL, a, NULL)) == NULL) {
            printf(" fetch failed");
            print_digest_errors();
            return 1;
        }
        sz = (size_t)n;
        u = (unsigned int)n;
        if (strcmp(key, "keylen") == 0 || strcmp(key, "ivlen") == 0)
            params[0] = OSSL_PARAM_construct_size_t(key, &sz);
        else
            params[0] = OSSL_PARAM_construct_uint(key, &u);
        r = EVP_CipherInit_ex2(ctx, ciph, cipher_key, cipher_iv, 1, params);
        if (r)
            cipher_gcm_noiv[cipher_current] = 0;
        cipher_keyed[cipher_current] = r;
        cipher_turned[cipher_current] = 0;
        cipher_ready[cipher_current] = r;
        EVP_CIPHER_free(ciph);
        printf(" %d", r);
    } else if (strcmp(command, "cupdate") == 0 || strcmp(command, "ccipher") == 0) {
        sscanf(line, "%*s %ld", &n);
        if (n < 0 || n > 1024)
            n = 1024;
        if (gcm_siv_unready(ctx)) {
            printf(" skipped\n");
            return 1;
        }
        if (!cipher_keyed[cipher_current]
            && (aes_wrap(ctx) || cipher_is(ctx, "DES3-WRAP")
                /* SIV with `speed` set uses the key's CMAC and CTR contexts unmade. */
                || (siv(ctx) && EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(ctx))
                                    == EVP_CIPH_SIV_MODE)
                /* A copy of XTS without a key points at key schedules never set. */
                || (EVP_CIPHER_CTX_get0_cipher(ctx) != NULL
                    && EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(ctx)) == EVP_CIPH_XTS_MODE)
                || (command[1] == 'u' && EVP_CIPHER_CTX_get0_cipher(ctx) != NULL
                    && (EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ctx))
                        & EVP_CIPH_FLAG_CTS) != 0))) {
            /*
             * Without a key, OpenSSL's AES key wraps and CTS crash and its triple-DES key
             * wrap runs on a key schedule never set (docs/DEVIATIONS.md).
             */
            printf(" skipped\n");
            return 1;
        }
        if (command[1] == 'u') {
            r = EVP_CipherUpdate(ctx, out, &outl, cipher_data + cipher_offset, (int)n);
            printf(" %d %d", r, outl);
            if (random_iv(ctx))
                printf(" random IV");
            else
                print_out(out, r ? outl : 0);
        } else if (EVP_CIPHER_CTX_get_block_size(ctx) > 1
                   && n % EVP_CIPHER_CTX_get_block_size(ctx) != 0) {
            printf(" skipped\n");
            return 1;
        } else {
            r = EVP_Cipher(ctx, out, cipher_data + cipher_offset, (unsigned int)n);
            printf(" %d", r);
            if (random_iv(ctx))
                printf(" random IV");
            else
                print_out(out, (int)n);
        }
        cipher_offset = (cipher_offset + (size_t)n * 3 + 1) % 1024;
    } else if (strcmp(command, "cfinal") == 0) {
        if (gcm_siv_unready(ctx)) {
            printf(" skipped\n");
            return 1;
        }
        r = EVP_CipherFinal_ex(ctx, out, &outl);
        printf(" %d %d", r, outl);
        print_out(out, r ? outl : 0);
    } else if (strcmp(command, "cpad") == 0 || strcmp(command, "ckeylen") == 0
               || strcmp(command, "cnum") == 0) {
        sscanf(line, "%*s %ld", &n);
        if (command[1] == 'k' && EVP_CIPHER_CTX_get0_cipher(ctx) == NULL) {
            /* OpenSSL dereferences the missing cipher (docs/DEVIATIONS.md). */
            printf(" skipped\n");
            return 1;
        }
        r = command[1] == 'p' ? EVP_CIPHER_CTX_set_padding(ctx, (int)n)
            : command[1] == 'k' ? EVP_CIPHER_CTX_set_key_length(ctx, (int)n)
                                : EVP_CIPHER_CTX_set_num(ctx, (int)n);
        printf(" %d", r);
    } else if (strcmp(command, "cflags") == 0) {
        unsigned int f = 0;

        sscanf(line, "%*s %63s %x", a, &f);
        if (strcmp(a, "set") == 0)
            EVP_CIPHER_CTX_set_flags(ctx, (int)f);
        else
            EVP_CIPHER_CTX_clear_flags(ctx, (int)f);
        printf(" %x", EVP_CIPHER_CTX_test_flags(ctx, 0x7fffffff));
    } else if (strcmp(command, "cstate") == 0) {
        unsigned char iv[16];
        int ivl;

        printf(" cipher %s key %d", EVP_CIPHER_CTX_get0_cipher(ctx) == NULL ? "-"
                                    : EVP_CIPHER_get0_name(EVP_CIPHER_CTX_get0_cipher(ctx)),
               EVP_CIPHER_CTX_get_key_length(ctx));
        ivl = EVP_CIPHER_CTX_get_iv_length(ctx);
        printf(" iv %d block %d num %d enc %d flags %x", ivl, EVP_CIPHER_CTX_get_block_size(ctx),
               EVP_CIPHER_CTX_get0_cipher(ctx) == NULL ? -9 : EVP_CIPHER_CTX_get_num(ctx),
               EVP_CIPHER_CTX_is_encrypting(ctx), EVP_CIPHER_CTX_test_flags(ctx, 0x7fffffff));
        if (random_iv(ctx)) {
            printf(" random IV");
        } else if (EVP_CIPHER_CTX_get0_cipher(ctx) != NULL && ivl > 0 && ivl <= 16) {
            memset(iv, 0, sizeof(iv));
            printf(" updated %d", EVP_CIPHER_CTX_get_updated_iv(ctx, iv, sizeof(iv)));
            print_out(iv, ivl);
            printf(" original %d", EVP_CIPHER_CTX_get_original_iv(ctx, iv, sizeof(iv)));
            print_out(iv, ivl);
        }
    } else if (strcmp(command, "cctrl") == 0) {
        sscanf(line, "%*s %ld %ld", &n, &m);
        if (n == EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE && EVP_CIPHER_CTX_get0_cipher(ctx) != NULL
            && (EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ctx))
                & EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK) != 0) {
            /* OpenSSL asserts a fragment size has been set (docs/DEVIATIONS.md). */
            printf(" skipped");
        } else if ((n == EVP_CTRL_GCM_SET_IV_FIXED || n == EVP_CTRL_GCM_SET_IV_INV) && m != -1
                   && EVP_CIPHER_CTX_get0_cipher(ctx) != NULL
                   && m > EVP_CIPHER_CTX_get_iv_length(ctx)) {
            /* OpenSSL copies past the IV (docs/DEVIATIONS.md). */
            printf(" skipped");
        } else if (EVP_CIPHER_CTX_get0_cipher(ctx) == NULL
                   || (n != EVP_CTRL_RAND_KEY && n != 0x19 && n != 0x1a)) {
            r = EVP_CIPHER_CTX_ctrl(ctx, (int)n, (int)m, out);
            printf(" %d", r);
        } else {
            printf(" skipped");
        }
    } else if (strcmp(command, "cname") == 0 || strcmp(command, "cnid") == 0) {
        const EVP_CIPHER *ciph;

        sscanf(line, "%*s %63s", a);
        ciph = command[1] == 'n' && command[2] == 'a' ? EVP_get_cipherbyname(a)
                                                     : EVP_get_cipherbynid(atoi(a));
        if (ciph == NULL)
            printf(" NULL");
        else
            printf(" %s %d %d", EVP_CIPHER_get0_name(ciph), EVP_CIPHER_get_nid(ciph),
                   EVP_CIPHER_get_type(ciph));
    } else if (strcmp(command, "caad") == 0 || strcmp(command, "cmsglen") == 0) {
        const EVP_CIPHER *ciph = EVP_CIPHER_CTX_get0_cipher(ctx);

        sscanf(line, "%*s %ld", &n);
        /*
         * Only an AEAD takes input without output (only CCM no input either): the others write
         * or read through NULL in OpenSSL (docs/DEVIATIONS.md).
         */
        if (ciph == NULL || (EVP_CIPHER_get_flags(ciph) & EVP_CIPH_FLAG_AEAD_CIPHER) == 0
            || (command[1] == 'm' && EVP_CIPHER_get_mode(ciph) != EVP_CIPH_CCM_MODE)
            /* The composites are AEADs to the flags but write through NULL, and SIV's
             * AAD crashes OpenSSL without a key (docs/DEVIATIONS.md). */
            || EVP_CIPHER_get_mode(ciph) == EVP_CIPH_CBC_MODE
            || (EVP_CIPHER_get_mode(ciph) == EVP_CIPH_SIV_MODE
                && !cipher_keyed[cipher_current])) {
            printf(" skipped\n");
            return 1;
        }
        if (n < 0 || n > 1024)
            n = 1024;
        r = EVP_CipherUpdate(ctx, NULL, &outl,
                             command[1] == 'a' ? cipher_data + cipher_offset : NULL, (int)n);
        printf(" %d %d", r, outl);
        if (command[1] == 'a')
            cipher_offset = (cipher_offset + (size_t)n * 5 + 3) % 1024;
    } else if (strcmp(command, "ctagget") == 0 || strcmp(command, "ctagset") == 0
               || strcmp(command, "ctaglen") == 0) {
        sscanf(line, "%*s %ld", &n);
        if (n < 0 || n > 16)
            n = 16;
        if (command[4] == 'l' && n == 16 && siv(ctx)) {
            /* A tag with no octets: OpenSSL copies 16 from NULL (docs/DEVIATIONS.md). */
            printf(" skipped\n");
            return 1;
        }
        if (command[4] == 'g') {
            memset(cipher_tag, 0, sizeof(cipher_tag));
            r = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)n, cipher_tag);
            printf(" %d", r);
            if (random_iv(ctx))
                printf(" random IV");
            else
                print_out(cipher_tag, r > 0 ? (int)n : 0);
        } else {
            r = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)n,
                                    command[4] == 's' ? cipher_tag : NULL);
            printf(" %d", r);
        }
    } else if (strcmp(command, "cparam") == 0) {
        /* A context parameter: `speed` as an unsigned int, the others as strings. */
        char v[32] = "";
        unsigned int u;
        OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

        sscanf(line, "%*s %63s %31s", a, v);
        u = (unsigned int)strtoul(v, NULL, 10);
        params[0] = strcmp(a, "speed") == 0 ? OSSL_PARAM_construct_uint(a, &u)
                                            : OSSL_PARAM_construct_utf8_string(a, v, 0);
        r = EVP_CIPHER_CTX_set_params(ctx, params);
        printf(" %d", r);
    } else if (strcmp(command, "ctlsaad") == 0) {
        /* A TLS record's AAD: sequence 0, type 23, the version, the length. */
        unsigned char aad[13] = { 0 };
        size_t pad = 0;
        OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

        sscanf(line, "%*s %lx %ld", &n, &m);
        aad[8] = 23;
        aad[9] = (unsigned char)(n >> 8);
        aad[10] = (unsigned char)n;
        aad[11] = (unsigned char)(m >> 8);
        aad[12] = (unsigned char)m;
        if (EVP_CIPHER_CTX_get0_cipher(ctx) == NULL) {
            printf(" skipped\n");
            return 1;
        }
        r = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, 13, aad);
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, &pad);
        printf(" %d length %d pad %d %zu", r, aad[11] << 8 | aad[12],
               EVP_CIPHER_CTX_get_params(ctx, params), pad);
    } else if (strcmp(command, "casn1") == 0) {
        /* The context's AlgorithmIdentifier parameters, then set back from them. */
        ASN1_TYPE *t = ASN1_TYPE_new();
        unsigned char *der = NULL;
        int len;

        if (EVP_CIPHER_CTX_get_iv_length(ctx) > EVP_MAX_IV_LENGTH) {
            /* OpenSSL asserts the IV fits its buffer (docs/DEVIATIONS.md). */
            printf(" skipped\n");
            ASN1_TYPE_free(t);
            return 1;
        }
        r = EVP_CIPHER_param_to_asn1(ctx, t);
        len = ASN1_TYPE_get(t) != 0 ? i2d_ASN1_TYPE(t, &der) : 0;
        printf(" %d", r);
        print_out(der, len > 0 ? len : 0);
        OPENSSL_free(der);
        print_digest_errors();
        printf(" back %d", EVP_CIPHER_asn1_to_param(ctx, t));
        ASN1_TYPE_free(t);
    } else if (strcmp(command, "ccopy") == 0) {
        cipher_keyed[!cipher_current] = cipher_keyed[cipher_current];
        cipher_ready[!cipher_current] = cipher_ready[cipher_current];
        cipher_gcm_noiv[!cipher_current] = cipher_gcm_noiv[cipher_current];
        cipher_turned[!cipher_current] = cipher_turned[cipher_current];
        r = EVP_CIPHER_CTX_copy(cipher_ctx[!cipher_current], ctx);
        printf(" %d", r);
        if (!r) {
            /*
             * A copy that fails in the provider leaves OpenSSL's destination with the cipher and
             * no algorithm context, which crashes when used (docs/DEVIATIONS.md): start it over.
             */
            EVP_CIPHER_CTX_reset(cipher_ctx[!cipher_current]);
            cipher_keyed[!cipher_current] = cipher_ready[!cipher_current] = 0;
        }
    } else {
        cipher_keyed[cipher_current] = 0;
        cipher_ready[cipher_current] = 0;
        cipher_gcm_noiv[cipher_current] = cipher_turned[cipher_current] = 0;
        printf(" %d", EVP_CIPHER_CTX_reset(ctx));
    }
    print_digest_errors();
    return 1;
}

static int err_command(const char *command, const char *line)
{
    static ERR_STATE *saved = NULL;
    const char *file = NULL, *func = NULL, *data = NULL;
    int number = 0, flags = 0;
    unsigned long code;

    if (strcmp(command, "errstr") == 0) {
        unsigned long e = 0;
        size_t len = 0;
        char buf[600];

        if (sscanf(line, "%*s %lx %zu", &e, &len) != 2 || len > sizeof(buf)) {
            printf("error bad errstr\n");
            return 1;
        }
        memset(buf, '#', sizeof(buf));
        ERR_error_string_n(e, buf, len);
        buf[sizeof(buf) - 1] = '\0';
        printf("errstr %lx %zu %s\n", e, len, len == 0 ? "-" : buf);
    } else if (strcmp(command, "raise") == 0) {
        int lib = 0, reason = 0;

        if (sscanf(line, "%*s %d %d", &lib, &reason) != 2) {
            printf("error bad raise\n");
            return 1;
        }
        ERR_raise(lib, reason);
        printf("raise %lx\n", ERR_peek_last_error());
    } else if (strcmp(command, "data") == 0) {
        char word[100] = "";

        if (sscanf(line, "%*s %99s", word) != 1)
            word[0] = '\0';
        ERR_add_error_data(1, word);
        printf("data\n");
    } else if (strcmp(command, "txt") == 0) {
        char separator[16] = "";
        size_t len = 0, every = 0;
        char *text;

        if (sscanf(line, "%*s %15s %zu %zu", separator, &len, &every) != 3 || len > 20000) {
            printf("error bad txt\n");
            return 1;
        }
        if (strcmp(separator, "-") == 0)
            separator[0] = '\0';
        text = make_text(separator, len, every);
        ERR_add_error_txt(separator, text);
        free(text);
        printf("txt\n");
    } else if (strcmp(command, "mark") == 0) {
        printf("mark %d\n", ERR_set_mark());
    } else if (strcmp(command, "pop") == 0) {
        printf("pop %d\n", ERR_pop());
    } else if (strcmp(command, "poptomark") == 0) {
        printf("poptomark %d\n", ERR_pop_to_mark());
    } else if (strcmp(command, "clearmark") == 0) {
        printf("clearmark %d\n", ERR_clear_last_mark());
    } else if (strcmp(command, "count") == 0) {
        printf("count %d\n", ERR_count_to_mark());
    } else if (strcmp(command, "clear") == 0) {
        ERR_clear_error();
        printf("clear\n");
    } else if (strcmp(command, "get") == 0) {
        code = ERR_get_error_all(&file, &number, &func, &data, &flags);
        print_error("get", code, file, number, func, data, flags);
    } else if (strcmp(command, "peek") == 0) {
        code = ERR_peek_error_all(&file, &number, &func, &data, &flags);
        print_error("peek", code, file, number, func, data, flags);
    } else if (strcmp(command, "last") == 0) {
        code = ERR_peek_last_error_all(&file, &number, &func, &data, &flags);
        print_error("last", code, file, number, func, data, flags);
    } else if (strcmp(command, "save") == 0 || strcmp(command, "savemark") == 0
               || strcmp(command, "restore") == 0) {
        if (saved == NULL)
            saved = OSSL_ERR_STATE_new();
        if (strcmp(command, "save") == 0)
            OSSL_ERR_STATE_save(saved);
        else if (strcmp(command, "savemark") == 0)
            OSSL_ERR_STATE_save_to_mark(saved);
        else
            OSSL_ERR_STATE_restore(saved);
        printf("%s\n", command);
    } else if (strcmp(command, "state") == 0) {
        print_err_state();
    } else {
        return 0;
    }
    return 1;
}

static void print_c_string(const char *label, char *text)
{
    printf(" %s=%s", label, text == NULL ? "(null)" : text);
    OPENSSL_free(text);
}

static int addr_command(const char *command, const char *line)
{
    char spec[256] = "", family[8] = "", hex[256] = "";
    int prio = 0, port = 0;

    if (strcmp(command, "hostserv") == 0) {
        char *host = (char *)"-", *service = (char *)"-";
        int ret;

        sscanf(line, "%*s %255s %d", spec, &prio);
        for (char *p = spec; *p != '\0'; p++)
            if (*p == '_')
                memmove(p, p + 1, strlen(p)), p--;
        ret = BIO_parse_hostserv(spec, &host, &service, prio);
        printf("hostserv %d", ret);
        if (ret) {
            if (strcmp(host != NULL ? host : "", "-") != 0 || host == NULL)
                print_c_string("host", host);
            else
                printf(" host=untouched");
            if (strcmp(service != NULL ? service : "", "-") != 0 || service == NULL)
                print_c_string("service", service);
            else
                printf(" service=untouched");
        } else {
            printf(" reason=%d", ERR_GET_REASON(ERR_peek_last_error()));
        }
        printf("\n");
        ERR_clear_error();
        return 1;
    }
    if (strcmp(command, "addr") == 0) {
        unsigned char raw[128];
        size_t len = 0, rawlen = 0;
        BIO_ADDR *a = BIO_ADDR_new();
        int fam, ret;

        sscanf(line, "%*s %7s %255s %d", family, hex, &port);
        if (!parse_hex(hex, raw, &len) || len > sizeof(raw) - 1) {
            printf("error bad hex\n");
            BIO_ADDR_free(a);
            return 1;
        }
        raw[len] = '\0';
        fam = family[0] == '4' ? AF_INET : family[0] == '6' ? AF_INET6 : AF_UNIX;
        ret = BIO_ADDR_rawmake(a, fam, raw, len, htons((unsigned short)port));
        printf("addr %d family=%d port=%u", ret, BIO_ADDR_family(a), ntohs(BIO_ADDR_rawport(a)));
        if (BIO_ADDR_rawaddress(a, NULL, &rawlen) && rawlen <= sizeof(raw)) {
            BIO_ADDR_rawaddress(a, raw, &rawlen);
            printf(" raw=");
            for (size_t i = 0; i < rawlen; i++)
                printf("%02x", raw[i]);
        }
        if (fam == AF_UNIX) {
            print_c_string("path", BIO_ADDR_path_string(a));
        } else if (ret) {
            print_c_string("host", BIO_ADDR_hostname_string(a, 1));
            print_c_string("service", BIO_ADDR_service_string(a, 1));
        }
        printf("\n");
        BIO_ADDR_free(a);
        ERR_clear_error();
        return 1;
    }
    return 0;
}

/* A typed argument of a printf command. */
typedef struct {
    int i;
    long long j;
    double d;
    const char *s;
} ARG;

/*
 * Calls CALL(arguments...) with the arguments typed as `sig` says (one letter each), so each
 * argument is passed as its own C type, as a real call would.
 */
#define V_i(a) (a).i
#define V_j(a) (a).j
#define V_d(a) (a).d
#define V_s(a) (a).s
#define C1(x) \
    if (strcmp(sig, #x) == 0) \
        return CALL(V_##x(a[0]));
#define C2(x, y) \
    if (strcmp(sig, #x #y) == 0) \
        return CALL(V_##x(a[0]), V_##y(a[1]));
#define C3(x, y, z) \
    if (strcmp(sig, #x #y #z) == 0) \
        return CALL(V_##x(a[0]), V_##y(a[1]), V_##z(a[2]));
#define L3(x, y) C3(x, y, i) C3(x, y, j) C3(x, y, d) C3(x, y, s)
#define L2(x) C2(x, i) C2(x, j) C2(x, d) C2(x, s) L3(x, i) L3(x, j) L3(x, d) L3(x, s)
#define EVERY_SIGNATURE C1(i) C1(j) C1(d) C1(s) L2(i) L2(j) L2(d) L2(s)

static int call_snprintf(char *buf, size_t n, const char *f, const char *sig, const ARG *a)
{
#define CALL(...) BIO_snprintf(buf, n, f, __VA_ARGS__)
    if (sig[0] == '\0')
        return CALL(0);
    EVERY_SIGNATURE
#undef CALL
    return -99;
}

static int call_printf(BIO *bio, const char *f, const char *sig, const ARG *a)
{
#define CALL(...) BIO_printf(bio, f, __VA_ARGS__)
    if (sig[0] == '\0')
        return CALL(0);
    EVERY_SIGNATURE
#undef CALL
    return -99;
}

static int printf_command(const char *command, const char *line)
{
    static BIO *mem = NULL;
    static char words[1024];
    char format[300], sig[4] = "", buf[128];
    ARG a[3];
    char *word, *save = NULL;
    size_t n = 0;
    int count = 0, ret;

    if (strcmp(command, "printf") != 0 && strcmp(command, "bioprintf") != 0)
        return 0;
    snprintf(words, sizeof(words), "%s", line);
    strtok_r(words, " ", &save);
    if (strcmp(command, "printf") == 0) {
        word = strtok_r(NULL, " ", &save);
        n = word == NULL ? 0 : strtoul(word, NULL, 10);
        if (n > 100)
            n = 100;
    }
    word = strtok_r(NULL, " ", &save);
    snprintf(format, sizeof(format), "%s", word == NULL ? "" : word);
    for (char *p = format; *p != '\0'; p++)
        if (*p == '_')
            *p = ' ';
    while ((word = strtok_r(NULL, " ", &save)) != NULL && count < 3) {
        memset(&a[count], 0, sizeof(a[count]));
        if (word[0] == '\0' || word[1] != ':') {
            printf("error bad argument %s\n", word);
            return 1;
        }
        switch (word[0]) {
        case 'i':
            a[count].i = (int)strtol(word + 2, NULL, 10);
            break;
        case 'j':
            a[count].j = strtoll(word + 2, NULL, 10);
            break;
        case 'd':
            a[count].d = strtod(word + 2, NULL);
            break;
        case 's':
            a[count].s = strcmp(word + 2, "-") == 0 ? NULL : word + 2;
            break;
        default:
            printf("error bad argument %s\n", word);
            return 1;
        }
        sig[count++] = word[0];
        sig[count] = '\0';
    }
    if (strcmp(command, "printf") == 0) {
        memset(buf, '#', sizeof(buf));
        ret = call_snprintf(buf, n, format, sig, a);
        print_escaped("printf", ret, buf, n + 1);
    } else {
        char *data = NULL;
        long len;

        if (mem == NULL)
            mem = BIO_new(BIO_s_mem());
        ret = call_printf(mem, format, sig, a);
        len = BIO_get_mem_data(mem, &data);
        print_escaped("bioprintf", ret, data, len > 0 ? (size_t)len : 0);
        (void)BIO_reset(mem);
    }
    ERR_clear_error();
    return 1;
}

/*
 * MACs (EVP_MAC(3)): two contexts, each made by name, initialized and set with parameters
 * written name=value (digest, cipher, and properties as strings; key and iv as that many
 * octets of the data; xof and the digest flags as ints; anything else as a size_t), updated
 * with the data, and finished. GMAC without an IV would make one up at random, and keyed
 * again without a new one runs as the platform's GCM does (docs/DEVIATIONS.md), so its
 * updates and finals are skipped until it has a new IV.
 */
static EVP_MAC_CTX *mac_ctx[2];
static int mac_current, mac_gmac[2], mac_iv[2], mac_used[2];
/*
 * OpenSSL's Poly1305 crashes used after its final, and HMAC's TLS mode without a digest
 * (docs/DEVIATIONS.md): each context's kind, and whether it's in either state.
 */
static int mac_poly[2], mac_poly_done[2], mac_hmac[2], mac_nodigest[2], mac_tls[2];
/* What the last parameter list had: a digest, a nonzero TLS data size, a key. */
static int mac_has_digest, mac_has_tls, mac_has_key;
static unsigned int mac_uints[8];
static uint64_t mac_u64s[8];
static size_t mac_offset;
static unsigned char mac_data[2048];

static int mac_params(const char *line, int skip, OSSL_PARAM *params, size_t *sizes, int *ints,
                      char (*strs)[64], int *has_cipher, int *has_iv)
{
    char tok[96];
    int n = 0, used, k = 0;
    size_t off = mac_offset;

    *has_cipher = *has_iv = 0;
    mac_has_digest = mac_has_tls = mac_has_key = 0;
    line += strcspn(line, " ");
    while (sscanf(line, "%95s%n", tok, &used) == 1 && n < 7) {
        char *eq = strchr(tok, '=');

        line += used;
        if (k++ < skip)
            continue;
        if (eq == NULL)
            continue;
        *eq = '\0';
        if (strcmp(tok, "digest") == 0 || strcmp(tok, "cipher") == 0
            || strcmp(tok, "properties") == 0 || strcmp(tok, "mac") == 0
            || strcmp(tok, "cekalg") == 0 || strcmp(tok, "type") == 0
            || (strcmp(tok, "mode") == 0 && (eq[1] < '0' || eq[1] > '9'))) {
            snprintf(strs[n], 64, "%s", eq + 1);
            params[n] = OSSL_PARAM_construct_utf8_string(tok, strs[n], 0);
            *has_cipher |= strcmp(tok, "cipher") == 0;
            mac_has_digest |= strcmp(tok, "digest") == 0;
        } else if (strcmp(tok, "key") == 0 || strcmp(tok, "iv") == 0
                   || strcmp(tok, "custom") == 0 || strcmp(tok, "salt") == 0
                   || strcmp(tok, "info") == 0 || strcmp(tok, "secret") == 0
                   || strcmp(tok, "seed") == 0 || strcmp(tok, "pass") == 0
                   || strcmp(tok, "prefix") == 0 || strcmp(tok, "label") == 0
                   || strcmp(tok, "data") == 0 || strcmp(tok, "xcghash") == 0
                   || strcmp(tok, "session_id") == 0 || strcmp(tok, "ukm") == 0
                   || strcmp(tok, "acvp-info") == 0 || strcmp(tok, "partyu-info") == 0
                   || strcmp(tok, "partyv-info") == 0 || strcmp(tok, "supp-pubinfo") == 0
                   || strcmp(tok, "supp-privinfo") == 0 || strcmp(tok, "constant") == 0
                   || strcmp(tok, "entropy") == 0 || strcmp(tok, "nonce") == 0
                   || strcmp(tok, "ad") == 0 || strcmp(tok, "test_entropy") == 0
                   || strcmp(tok, "test_nonce") == 0) {
            size_t len = strtoul(eq + 1, NULL, 10) % 200;

            params[n] = OSSL_PARAM_construct_octet_string(tok, mac_data + off, len);
            off = (off + len + 5) % 1024;
            *has_iv |= strcmp(tok, "iv") == 0;
            mac_has_key |= strcmp(tok, "key") == 0;
        } else if (strcmp(tok, "iter") == 0 || strcmp(tok, "n") == 0 || strcmp(tok, "p") == 0
                   || strcmp(tok, "maxmem_bytes") == 0) {
            mac_u64s[n] = strtoull(eq + 1, NULL, 10);
            params[n] = OSSL_PARAM_construct_uint64(tok, &mac_u64s[n]);
        } else if (strcmp(tok, "c-rounds") == 0 || strcmp(tok, "d-rounds") == 0) {
            mac_uints[n] = (unsigned int)strtoul(eq + 1, NULL, 10);
            params[n] = OSSL_PARAM_construct_uint(tok, &mac_uints[n]);
        } else if (strcmp(tok, "xof") == 0 || strcmp(tok, "digest-noinit") == 0
                   || strcmp(tok, "digest-oneshot") == 0 || strcmp(tok, "pkcs5") == 0
                   || strcmp(tok, "mode") == 0 || strcmp(tok, "r") == 0
                   || strcmp(tok, "use-l") == 0 || strcmp(tok, "use-separator") == 0
                   || strcmp(tok, "use-keybits") == 0) {
            ints[n] = atoi(eq + 1);
            params[n] = OSSL_PARAM_construct_int(tok, &ints[n]);
        } else {
            sizes[n] = strtoul(eq + 1, NULL, 10);
            params[n] = OSSL_PARAM_construct_size_t(tok, &sizes[n]);
            mac_has_tls |= strcmp(tok, "tls-data-size") == 0 && sizes[n] != 0;
        }
        /* The key names are the tokens' own text: keep them. */
        params[n].key = OPENSSL_strdup(params[n].key);
        n++;
    }
    params[n] = OSSL_PARAM_construct_end();
    return n;
}

static void mac_params_free(OSSL_PARAM *params)
{
    for (; params->key != NULL; params++)
        OPENSSL_free((char *)params->key);
}

static void mac_flags_after(int slot, int r, int has_cipher, int has_iv)
{
    if (has_cipher)
        mac_iv[slot] = 0;
    if (has_iv)
        mac_iv[slot] = r == 1;
}

static int mac_command(const char *command, const char *line)
{
    EVP_MAC_CTX *ctx;
    OSSL_PARAM params[8];
    size_t sizes[8], outl = 0, sz;
    int ints[8], has_cipher = 0, has_iv = 0, r = 0;
    char strs[8][64], a[64] = "";
    unsigned char out[300];
    unsigned long n = 0;

    if (command[0] != 'm' || (strcmp(command, "mctx") != 0 && strcmp(command, "mnew") != 0
            && strcmp(command, "minit") != 0 && strcmp(command, "mset") != 0
            && strcmp(command, "mupdate") != 0 && strcmp(command, "mfinal") != 0
            && strcmp(command, "mxof") != 0 && strcmp(command, "msize") != 0
            && strcmp(command, "mdup") != 0 && strcmp(command, "mfree") != 0
            && strcmp(command, "mget") != 0 && strcmp(command, "mq") != 0))
        return 0;
    if (mac_data[1] == 0) {
        size_t i;

        for (i = 0; i < sizeof(mac_data); i++)
            mac_data[i] = (unsigned char)(i * 11 + 5);
    }
    ctx = mac_ctx[mac_current];
    printf("%s:", line);
    memset(out, 0xee, sizeof(out));
    if (strcmp(command, "mctx") == 0) {
        sscanf(line, "%*s %lu", &n);
        mac_current = n != 0;
        printf("\n");
        return 1;
    } else if (strcmp(command, "mnew") == 0) {
        EVP_MAC *mac;

        sscanf(line, "%*s %63s", a);
        EVP_MAC_CTX_free(ctx);
        mac_ctx[mac_current] = NULL;
        mac = EVP_MAC_fetch(NULL, a, NULL);
        if (mac != NULL) {
            mac_ctx[mac_current] = EVP_MAC_CTX_new(mac);
            printf(" %s %s", EVP_MAC_get0_name(mac), mac_ctx[mac_current] != NULL ? "ok" : "failed");
            mac_gmac[mac_current] = EVP_MAC_is_a(mac, "GMAC");
            mac_iv[mac_current] = mac_used[mac_current] = 0;
            mac_poly[mac_current] = EVP_MAC_is_a(mac, "POLY1305");
            mac_hmac[mac_current] = EVP_MAC_is_a(mac, "HMAC");
            mac_poly_done[mac_current] = mac_tls[mac_current] = 0;
            mac_nodigest[mac_current] = 1;
        } else {
            printf(" fetch failed");
        }
        EVP_MAC_free(mac);
    } else if (strcmp(command, "mq") == 0) {
        char alg[64] = "", sub[64] = "";
        unsigned long keylen = 0, datalen = 0, outsize = 0;
        unsigned char *p;

        if (sscanf(line, "%*s %63s %63s %lu %lu %lu", alg, sub, &keylen, &datalen, &outsize) != 5)
            return printf(" usage\n"), 1;
        mac_params(line, 5, params, sizes, ints, strs, &has_cipher, &has_iv);
        ERR_set_mark();
        {
            EVP_MAC *mac = EVP_MAC_fetch(NULL, alg, NULL);

            r = mac != NULL && EVP_MAC_is_a(mac, "GMAC");
            EVP_MAC_free(mac);
        }
        ERR_pop_to_mark();
        if (r && !has_iv) {
            printf(" skipped: GMAC without an IV\n");
            mac_params_free(params);
            return 1;
        }
        p = EVP_Q_mac(NULL, alg, NULL, strcmp(sub, "-") == 0 ? NULL : sub, params,
                      mac_data + 100, keylen % 200, mac_data + 300, datalen % 1500,
                      outsize == 0 ? NULL : out, outsize % 300, &outl);
        printf(" %s", p == NULL ? "NULL" : p == out ? "out" : "allocated");
        if (p != NULL) {
            printf(" %zu ", outl);
            for (sz = 0; sz < outl && sz < 256; sz++)
                printf("%02x", p[sz]);
            if (p != out)
                OPENSSL_free(p);
        }
        mac_params_free(params);
    } else if (ctx == NULL) {
        printf(" no context\n");
        return 1;
    } else if (strcmp(command, "minit") == 0 || strcmp(command, "mset") == 0) {
        int init = command[1] == 'i';
        char keyarg[32] = "";

        mac_params(line, init, params, sizes, ints, strs, &has_cipher, &has_iv);
        if (init) {
            sscanf(line, "%*s %31s", keyarg);
            n = strtoul(keyarg, NULL, 10) % 200;
            r = EVP_MAC_init(ctx, strcmp(keyarg, "-") == 0 ? NULL : mac_data + 600, n,
                             params[0].key == NULL ? NULL : params);
        } else {
            r = EVP_MAC_CTX_set_params(ctx, params);
        }
        mac_flags_after(mac_current, r, has_cipher, has_iv);
        if (mac_has_digest)
            mac_nodigest[mac_current] = r != 1;
        if (mac_has_tls)
            mac_tls[mac_current] = 1;
        if (r == 1 && ((init && strcmp(keyarg, "-") != 0) || mac_has_key))
            mac_poly_done[mac_current] = 0;
        /* GMAC keyed again after use without a new IV: GCM's output is then the platform's. */
        if (((init && strcmp(keyarg, "-") != 0) || mac_has_key) && !has_iv
            && mac_used[mac_current])
            mac_iv[mac_current] = 0;
        if (has_iv || has_cipher)
            mac_used[mac_current] = 0;
        mac_params_free(params);
        printf(" %d", r);
    } else if ((strcmp(command, "mupdate") == 0 || strcmp(command, "mfinal") == 0
                || strcmp(command, "mxof") == 0)
               && mac_gmac[mac_current] && !mac_iv[mac_current]) {
        printf(" skipped: GMAC without an IV\n");
        return 1;
    } else if (((strcmp(command, "mfinal") == 0 || strcmp(command, "mxof") == 0)
                && mac_poly[mac_current] && mac_poly_done[mac_current])
               || (strcmp(command, "mupdate") == 0 && strtoul(line + 7, NULL, 10) != 0
                   && ((mac_poly[mac_current] && mac_poly_done[mac_current])
                       || (mac_hmac[mac_current] && mac_tls[mac_current]
                           && mac_nodigest[mac_current])))) {
        printf(" skipped\n");
        return 1;
    } else if (strcmp(command, "mupdate") == 0) {
        mac_used[mac_current] = 1;
        sscanf(line, "%*s %lu", &n);
        if (n > 1024)
            n = 1024;
        printf(" %d", EVP_MAC_update(ctx, mac_data + mac_offset, n));
        mac_offset = (mac_offset + n * 3 + 1) % 1024;
    } else if (strcmp(command, "mfinal") == 0) {
        n = 64;
        sscanf(line, "%*s %lu", &n);
        r = EVP_MAC_final(ctx, n > 256 ? NULL : out, &outl, n % 257);
        mac_used[mac_current] = 1;
        if (r == 1 && n <= 256)
            mac_poly_done[mac_current] = 1;
        /* The length is only set on success. */
        printf(" %d", r);
        if (r == 1) {
            printf(" %zu ", outl);
            for (sz = 0; sz < outl && sz < 256 && n <= 256; sz++)
                printf("%02x", out[sz]);
        }
    } else if (strcmp(command, "mxof") == 0) {
        sscanf(line, "%*s %lu", &n);
        if (n > 256)
            n = 256;
        r = EVP_MAC_finalXOF(ctx, out, n);
        mac_used[mac_current] = 1;
        if (r == 1)
            mac_poly_done[mac_current] = 1;
        printf(" %d ", r);
        for (sz = 0; sz < (r ? n : 0); sz++)
            printf("%02x", out[sz]);
    } else if (strcmp(command, "msize") == 0) {
        printf(" %zu %zu", EVP_MAC_CTX_get_mac_size(ctx), EVP_MAC_CTX_get_block_size(ctx));
    } else if (strcmp(command, "mget") == 0) {
        size_t size = 1234, block = 1234;

        params[0] = OSSL_PARAM_construct_size_t("size", &size);
        params[1] = OSSL_PARAM_construct_size_t("block-size", &block);
        params[2] = OSSL_PARAM_construct_end();
        r = EVP_MAC_CTX_get_params(ctx, params);
        printf(" %d %zu %zu", r, size, block);
    } else if (strcmp(command, "mdup") == 0) {
        EVP_MAC_CTX *dup = EVP_MAC_CTX_dup(ctx);

        printf(" %s", dup == NULL ? "NULL" : "ok");
        if (dup != NULL) {
            EVP_MAC_CTX_free(mac_ctx[!mac_current]);
            mac_ctx[!mac_current] = dup;
            mac_gmac[!mac_current] = mac_gmac[mac_current];
            mac_iv[!mac_current] = mac_iv[mac_current];
            mac_used[!mac_current] = mac_used[mac_current];
            mac_poly[!mac_current] = mac_poly[mac_current];
            mac_poly_done[!mac_current] = mac_poly_done[mac_current];
            mac_hmac[!mac_current] = mac_hmac[mac_current];
            mac_nodigest[!mac_current] = mac_nodigest[mac_current];
            mac_tls[!mac_current] = mac_tls[mac_current];
        }
    } else {
        EVP_MAC_CTX_free(ctx);
        mac_ctx[mac_current] = NULL;
    }
    print_digest_errors();
    /* A failed fetch's error text has the name's number, which differs between the libraries:
     * drop the buffers it sized. */
    OPENSSL_thread_stop();
    return 1;
}

/*
 * KDFs (EVP_KDF(3)): two contexts, each made by name, given parameters as the MAC commands
 * write them (with the KDFs' names: secret, seed, info, pass, prefix, label, data, constant,
 * entropy, nonce, and ad as octets of the data; iter as a uint64; pkcs5 and a numeric mode as
 * ints; mac and a named mode as strings; Argon2's numbers and pkcs12-id as size_t), and
 * derived from into buffers of the lengths asked for.
 */
static EVP_KDF_CTX *kdf_ctx[2];
static int kdf_current;
/*
 * What OpenSSL can't be given (docs/DEVIATIONS.md, and scrypt's cost): each context's kind,
 * whether a KBKDF has a MAC (its copy crashes without one), whether an SSHKDF's digest may be
 * NULL (it then loops forever), and whether a KRB5KDF's cipher is one known to make output a
 * block at a time (one that makes none would loop forever). scrypt derivations get a memory
 * limit of 4 MiB.
 */
static int kdf_scrypt[2], kdf_kbkdf[2], kdf_kb_mac[2], kdf_ssh[2], kdf_ssh_null[2];
static int kdf_krb5[2], kdf_krb5_safe[2];
static uint64_t kdf_maxmem = 4 << 20;

/* Whether the line's cipher (if it names one) is one KRB5KDF may derive with. */
static int kdf_krb5_cipher_ok(const char *line, int otherwise)
{
    static const char *safe[] = { "AES-128-CBC", "AES-256-CBC", "AES-192-ECB", "DES-EDE3-CBC",
                                  "CAMELLIA-256-CBC", "AES-128-CTR", "ARIA-128-CBC", "SM4-CBC",
                                  "AES-128-WRAP", "nonesuch", NULL };
    const char *c = strstr(line, " cipher=");
    size_t i, n;

    if (c == NULL)
        return otherwise;
    c += 8;
    n = strcspn(c, " ");
    for (i = 0; safe[i] != NULL; i++)
        if (strlen(safe[i]) == n && strncmp(c, safe[i], n) == 0)
            return 1;
    return 0;
}

/* Notes what a parameter call did to the context's guarded state. */
static void kdf_note(const char *line, int r)
{
    if (strstr(line, " mac=") != NULL)
        kdf_kb_mac[kdf_current] = r == 1;
    /* A failed call may have dropped the MAC: OpenSSL frees it when a MAC parameter fails. */
    if (r != 1)
        kdf_kb_mac[kdf_current] = 0;
    kdf_krb5_safe[kdf_current] = kdf_krb5_cipher_ok(line, kdf_krb5_safe[kdf_current]);
    if (strstr(line, " digest=NULL") != NULL)
        kdf_ssh_null[kdf_current] = 1;
    else if (strstr(line, " digest=") != NULL && r == 1)
        kdf_ssh_null[kdf_current] = 0;
}

static int kdf_command(const char *command, const char *line)
{
    EVP_KDF_CTX *ctx;
    OSSL_PARAM params[10];
    size_t sizes[10], sz;
    int ints[10], has_cipher = 0, has_iv = 0, r = 0;
    char strs[10][64], a[64] = "";
    unsigned char out[1100];
    unsigned long n = 0;

    if (command[0] != 'k' || (strcmp(command, "kctx") != 0 && strcmp(command, "knew") != 0
            && strcmp(command, "kset") != 0 && strcmp(command, "kderive") != 0
            && strcmp(command, "ksize") != 0 && strcmp(command, "kdup") != 0
            && strcmp(command, "kreset") != 0 && strcmp(command, "kfree") != 0
            && strcmp(command, "kget") != 0 && strcmp(command, "kpbkdf2") != 0))
        return 0;
    if (mac_data[1] == 0) {
        size_t i;

        for (i = 0; i < sizeof(mac_data); i++)
            mac_data[i] = (unsigned char)(i * 11 + 5);
    }
    ctx = kdf_ctx[kdf_current];
    printf("%s:", line);
    memset(out, 0xee, sizeof(out));
    if (strcmp(command, "kctx") == 0) {
        sscanf(line, "%*s %lu", &n);
        kdf_current = n != 0;
        printf("\n");
        return 1;
    } else if (strcmp(command, "knew") == 0) {
        EVP_KDF *kdf;

        sscanf(line, "%*s %63s", a);
        EVP_KDF_CTX_free(ctx);
        kdf = EVP_KDF_fetch(NULL, a, NULL);
        kdf_ctx[kdf_current] = EVP_KDF_CTX_new(kdf);
        kdf_scrypt[kdf_current] = kdf != NULL && EVP_KDF_is_a(kdf, "SCRYPT");
        kdf_kbkdf[kdf_current] = kdf != NULL && EVP_KDF_is_a(kdf, "KBKDF");
        kdf_ssh[kdf_current] = kdf != NULL && EVP_KDF_is_a(kdf, "SSHKDF");
        kdf_krb5[kdf_current] = kdf != NULL && EVP_KDF_is_a(kdf, "KRB5KDF");
        kdf_kb_mac[kdf_current] = kdf_ssh_null[kdf_current] = 0;
        kdf_krb5_safe[kdf_current] = 1;
        if (kdf != NULL)
            printf(" %s %s", EVP_KDF_get0_name(kdf), kdf_ctx[kdf_current] != NULL ? "ok" : "failed");
        else
            printf(" fetch failed");
        EVP_KDF_free(kdf);
    } else if (strcmp(command, "kpbkdf2") == 0) {
        int passlen = 0, saltlen = 0, iter = 0, keylen = 0;
        char md[64] = "";
        EVP_MD *digest;

        if (sscanf(line, "%*s %63s %d %d %d %d", md, &passlen, &saltlen, &iter, &keylen) != 5)
            return printf(" usage\n"), 1;
        digest = EVP_MD_fetch(NULL, md, NULL);
        if (digest == NULL) {
            printf(" fetch failed");
        } else if (passlen < -1 || saltlen < 0 || keylen < 0 || keylen > 1024) {
            /* OpenSSL reads and writes past them (docs/DEVIATIONS.md). */
            printf(" skipped");
        } else {
            r = PKCS5_PBKDF2_HMAC(passlen == -1 ? "password" : (const char *)mac_data + 50,
                                  passlen % 200, mac_data + 400, saltlen % 200, iter, digest,
                                  keylen, out);
            printf(" %d ", r);
            for (sz = 0; sz < (size_t)(r == 1 ? keylen : 0) && sz < 256; sz++)
                printf("%02x", out[sz]);
        }
        EVP_MD_free(digest);
    } else if (ctx == NULL) {
        printf(" no context\n");
        return 1;
    } else if (strcmp(command, "kset") == 0) {
        mac_params(line, 0, params, sizes, ints, strs, &has_cipher, &has_iv);
        r = EVP_KDF_CTX_set_params(ctx, params);
        printf(" %d", r);
        mac_params_free(params);
        kdf_note(line, r);
    } else if (strcmp(command, "kderive") == 0) {
        sscanf(line, "%*s %lu", &n);
        if (n > 1024)
            n = 1024;
        if (kdf_ssh[kdf_current] && n > 0
            && (kdf_ssh_null[kdf_current] || strstr(line, " digest=NULL") != NULL)) {
            printf(" skipped: SSHKDF over NULL\n");
            return 1;
        }
        if (kdf_krb5[kdf_current] && !kdf_krb5_cipher_ok(line, kdf_krb5_safe[kdf_current])) {
            printf(" skipped: KRB5KDF over an unknown cipher\n");
            return 1;
        }
        {
            int np = mac_params(line, 1, params, sizes, ints, strs, &has_cipher, &has_iv);

            if (kdf_scrypt[kdf_current]) {
                params[np] = OSSL_PARAM_construct_uint64("maxmem_bytes", &kdf_maxmem);
                params[np].key = OPENSSL_strdup(params[np].key);
                params[np + 1] = OSSL_PARAM_construct_end();
            }
        }
        r = EVP_KDF_derive(ctx, out, n, params[0].key == NULL ? NULL : params);
        mac_params_free(params);
        kdf_note(line, r);
        printf(" %d ", r);
        for (sz = 0; sz < (r == 1 ? n : 0) && sz < 256; sz++)
            printf("%02x", out[sz]);
    } else if (strcmp(command, "ksize") == 0) {
        printf(" %zu", EVP_KDF_CTX_get_kdf_size(ctx));
    } else if (strcmp(command, "kget") == 0) {
        size_t size = 1234;
        unsigned char info[64];

        params[0] = OSSL_PARAM_construct_size_t("size", &size);
        params[1] = OSSL_PARAM_construct_octet_string("info", info, sizeof(info));
        params[2] = OSSL_PARAM_construct_end();
        params[1].return_size = 4321;
        r = EVP_KDF_CTX_get_params(ctx, params);
        printf(" %d %zu %zu", r, size, params[1].return_size);
    } else if (strcmp(command, "kdup") == 0) {
        EVP_KDF_CTX *dup;

        if (kdf_kbkdf[kdf_current] && !kdf_kb_mac[kdf_current]) {
            printf(" skipped: KBKDF without a MAC\n");
            return 1;
        }
        dup = EVP_KDF_CTX_dup(ctx);
        printf(" %s", dup == NULL ? "NULL" : "ok");
        if (dup != NULL) {
            EVP_KDF_CTX_free(kdf_ctx[!kdf_current]);
            kdf_ctx[!kdf_current] = dup;
            kdf_scrypt[!kdf_current] = kdf_scrypt[kdf_current];
            kdf_kbkdf[!kdf_current] = kdf_kbkdf[kdf_current];
            kdf_kb_mac[!kdf_current] = kdf_kb_mac[kdf_current];
            kdf_ssh[!kdf_current] = kdf_ssh[kdf_current];
            kdf_ssh_null[!kdf_current] = kdf_ssh_null[kdf_current];
            kdf_krb5[!kdf_current] = kdf_krb5[kdf_current];
            kdf_krb5_safe[!kdf_current] = kdf_krb5_safe[kdf_current];
        }
    } else if (strcmp(command, "kreset") == 0) {
        EVP_KDF_CTX_reset(ctx);
        kdf_kb_mac[kdf_current] = kdf_ssh_null[kdf_current] = 0;
        kdf_krb5_safe[kdf_current] = 1;
    } else {
        EVP_KDF_CTX_free(ctx);
        kdf_ctx[kdf_current] = NULL;
    }
    print_digest_errors();
    /* A failed fetch's error text has the name's number: drop the buffers it sized. */
    OPENSSL_thread_stop();
    return 1;
}

/*
 * Random generators (EVP_RAND(3)): two contexts, each made by name (with "child", under the
 * other as its parent), given parameters as the MAC commands write them (test_entropy and
 * test_nonce as octets of the data, the numbers as size_t), instantiated, generated from (into
 * buffers of the lengths asked for, with additional input of the data), reseeded, asked for
 * nonces, states, and parameters. Output is printed only where it's deterministic: from
 * TEST-RAND, or from a DRBG directly under one (anything seeded by the operating system, or by
 * a DRBG, which mixes in its address, isn't).
 */
static EVP_RAND_CTX *rand_slot[2];
static int rand_current;
/*
 * What each context is, and what OpenSSL can't be given (docs/DEVIATIONS.md). A DRBG never
 * set up (no cipher, or digest, taken) isn't run: OpenSSL crashes instantiating a CTR-DRBG
 * without a cipher under a parent, loops forever on a HASH- or HMAC-DRBG that kept a digest it
 * refused, and seeds one of strength 0 without a parent from its RAND layer's seed source once
 * that exists (step 3.7b). A DRBG under a TEST-RAND in generating mode crashes asking for a
 * nonce's length, so no child is made under one, nor is a TEST-RAND with children put in that
 * mode.
 */
enum { R_OTHER, R_CTR, R_HASH, R_HMAC, R_SEED, R_TEST };
static int rand_kind[2], rand_parent[2], rand_det[2], rand_ctr_ok[2], rand_gen[2], rand_child[2];
static int rand_digest_ok[2], rand_digest_tried[2];
/* Whether the thread's public and private DRBGs were set to deterministic ones. */
static int rand_pub_det, rand_priv_det;
/*
 * The contexts installed as the thread's public and private DRBGs, and whether each is still
 * set up: a failed set can break one after it's installed (see rset), and RAND_bytes then
 * crashes the reference running it.
 */
static EVP_RAND_CTX *rand_pub_ctx, *rand_priv_ctx;
static int rand_pub_broken, rand_priv_broken;

static int rand_kind_of(const EVP_RAND *r)
{
    if (r == NULL)
        return R_OTHER;
    if (EVP_RAND_is_a(r, "CTR-DRBG"))
        return R_CTR;
    if (EVP_RAND_is_a(r, "HASH-DRBG"))
        return R_HASH;
    if (EVP_RAND_is_a(r, "HMAC-DRBG"))
        return R_HMAC;
    if (EVP_RAND_is_a(r, "SEED-SRC"))
        return R_SEED;
    return EVP_RAND_is_a(r, "TEST-RAND") ? R_TEST : R_OTHER;
}

static int rand_command(const char *command, const char *line)
{
    EVP_RAND_CTX *ctx;
    OSSL_PARAM params[10];
    size_t sizes[10], sz;
    int ints[10], has_cipher = 0, has_iv = 0, r = 0, c;
    char strs[10][64], a[64] = "", b[64] = "";
    unsigned char out[1100];
    unsigned long n = 0, m = 0, k = 0, pr = 0;

    if (command[0] != 'r' || (strcmp(command, "rctx") != 0 && strcmp(command, "rnew") != 0
            && strcmp(command, "rset") != 0 && strcmp(command, "rinst") != 0
            && strcmp(command, "rgen") != 0 && strcmp(command, "rreseed") != 0
            && strcmp(command, "rnonce") != 0 && strcmp(command, "runinst") != 0
            && strcmp(command, "rget") != 0 && strcmp(command, "rlock") != 0
            && strcmp(command, "rzero") != 0 && strcmp(command, "rfree") != 0
            && strcmp(command, "rsetpub") != 0 && strcmp(command, "rsetpriv") != 0
            && strcmp(command, "rbytes") != 0 && strcmp(command, "rprivbytes") != 0
            && strcmp(command, "rstatus") != 0 && strcmp(command, "rpoll") != 0
            && strcmp(command, "rreset") != 0))
        return 0;
    if (mac_data[1] == 0) {
        size_t i;

        for (i = 0; i < sizeof(mac_data); i++)
            mac_data[i] = (unsigned char)(i * 11 + 5);
    }
    c = rand_current;
    ctx = rand_slot[c];
    printf("%s:", line);
    memset(out, 0xee, sizeof(out));
    if (strcmp(command, "rctx") == 0) {
        sscanf(line, "%*s %lu", &n);
        rand_current = n != 0;
        printf("\n");
        return 1;
    } else if (strcmp(command, "rbytes") == 0 || strcmp(command, "rprivbytes") == 0) {
        int priv = command[1] == 'p';

        if (priv ? rand_priv_broken : rand_pub_broken) {
            printf(" skipped: a DRBG not set up\n");
            return 1;
        }
        sscanf(line, "%*s %lu %lu", &n, &m);
        if (n > 1024)
            n = 1024;
        r = priv ? RAND_priv_bytes_ex(NULL, out, n, (unsigned int)m)
                 : RAND_bytes_ex(NULL, out, n, (unsigned int)m);
        printf(" %d ", r);
        if (!(priv ? rand_priv_det : rand_pub_det))
            printf("(%s)", r == 1 ? "random" : "-");
        else
            for (sz = 0; sz < (r == 1 ? n : 0) && sz < 256; sz++)
                printf("%02x", out[sz]);
    } else if (strcmp(command, "rstatus") == 0) {
        printf(" %d", RAND_status());
    } else if (strcmp(command, "rpoll") == 0) {
        printf(" %d", RAND_poll());
    } else if (strcmp(command, "rreset") == 0) {
        printf(" %d %d", RAND_set0_public(NULL, NULL), RAND_set0_private(NULL, NULL));
        rand_pub_det = rand_priv_det = 0;
        rand_pub_ctx = rand_priv_ctx = NULL;
        rand_pub_broken = rand_priv_broken = 0;
    } else if (strcmp(command, "rnew") == 0) {
        EVP_RAND *rand;
        EVP_RAND_CTX *parent = NULL;

        sscanf(line, "%*s %63s %63s", a, b);
        if (strcmp(b, "child") == 0) {
            parent = rand_slot[!c];
            if (parent != NULL && rand_kind[!c] == R_TEST && rand_gen[!c]) {
                printf(" skipped: a child of TEST-RAND in generating mode\n");
                return 1;
            }
        }
        rand = EVP_RAND_fetch(NULL, a, NULL);
        EVP_RAND_CTX_free(ctx);
        rand_slot[c] = EVP_RAND_CTX_new(rand, parent);
        rand_kind[c] = rand_kind_of(rand);
        rand_parent[c] = parent != NULL;
        rand_ctr_ok[c] = rand_gen[c] = rand_child[c] = rand_digest_ok[c] = rand_digest_tried[c] = 0;
        rand_det[c] = rand_kind[c] == R_TEST
                      || (parent != NULL && rand_kind[!c] == R_TEST && rand_kind[c] != R_SEED);
        if (rand_slot[c] != NULL && parent != NULL)
            rand_child[!c] = 1;
        if (rand != NULL)
            printf(" %s %s", EVP_RAND_get0_name(rand), rand_slot[c] != NULL ? "ok" : "failed");
        else
            printf(" fetch failed");
        EVP_RAND_free(rand);
    } else if (ctx == NULL) {
        printf(" no context\n");
        return 1;
    } else if (strcmp(command, "rsetpub") == 0 || strcmp(command, "rsetpriv") == 0) {
        int priv = command[4] == 'p' && command[5] == 'r';

        /* The thread takes a reference; the slot keeps its own. A DRBG not set up isn't put
         * where RAND_bytes would run it (see above). */
        if (((rand_kind[c] == R_CTR && !rand_ctr_ok[c])
             || ((rand_kind[c] == R_HASH || rand_kind[c] == R_HMAC) && !rand_digest_ok[c]))) {
            printf(" skipped: a DRBG not set up\n");
            return 1;
        }
        EVP_RAND_CTX_up_ref(ctx);
        r = priv ? RAND_set0_private(NULL, ctx) : RAND_set0_public(NULL, ctx);
        printf(" %d", r);
        if (priv) {
            rand_priv_det = rand_det[c];
            rand_priv_ctx = ctx;
            rand_priv_broken = 0;
        } else {
            rand_pub_det = rand_det[c];
            rand_pub_ctx = ctx;
            rand_pub_broken = 0;
        }
    } else if (strcmp(command, "rset") == 0) {
        unsigned long g = 0;
        const char *gp = strstr(line, " generate=");

        if (gp != NULL)
            g = strtoul(gp + 10, NULL, 10);
        if (rand_kind[c] == R_TEST && g != 0 && rand_child[c]) {
            printf(" skipped: generating mode with children\n");
            return 1;
        }
        mac_params(line, 0, params, sizes, ints, strs, &has_cipher, &has_iv);
        r = EVP_RAND_CTX_set_params(ctx, params);
        printf(" %d", r);
        mac_params_free(params);
        if (has_cipher && r == 1)
            rand_ctr_ok[c] = 1;
        if (strstr(line, " digest=") != NULL) {
            rand_digest_tried[c] = 1;
            rand_digest_ok[c] |= r == 1;
        }
        /*
         * A failed set may have dropped what the DRBG had: OpenSSL frees the old digest, MAC,
         * or cipher before fetching the new one (and crashes using it after), so the DRBG
         * isn't set up any more.
         */
        if (r != 1 && (has_cipher || strstr(line, " digest=") != NULL || strstr(line, " mac=") != NULL)) {
            rand_ctr_ok[c] = 0;
            rand_digest_ok[c] = 0;
            if (rand_kind[c] == R_CTR || rand_kind[c] == R_HASH || rand_kind[c] == R_HMAC) {
                rand_pub_broken |= ctx == rand_pub_ctx;
                rand_priv_broken |= ctx == rand_priv_ctx;
            }
        }
        if (gp != NULL && r == 1 && rand_kind[c] == R_TEST)
            rand_gen[c] = g != 0;
    } else if (((rand_kind[c] == R_CTR && !rand_ctr_ok[c])
                || ((rand_kind[c] == R_HASH || rand_kind[c] == R_HMAC) && !rand_digest_ok[c]))
               && (strcmp(command, "rinst") == 0 || strcmp(command, "rgen") == 0
                   || strcmp(command, "rreseed") == 0 || strcmp(command, "rnonce") == 0)) {
        printf(" skipped: a DRBG not set up\n");
        return 1;
    } else if (strcmp(command, "rinst") == 0) {
        sscanf(line, "%*s %lu %lu %lu", &n, &pr, &m);
        r = EVP_RAND_instantiate(ctx, (unsigned int)n, (int)pr, m > 0 ? mac_data + 300 : NULL,
                                 m % 200, NULL);
        printf(" %d state %d", r, EVP_RAND_get_state(ctx));
    } else if (strcmp(command, "rgen") == 0) {
        sscanf(line, "%*s %lu %lu %lu %lu", &n, &m, &pr, &k);
        if (n > 1024)
            n = 1024;
        r = EVP_RAND_generate(ctx, out, n, (unsigned int)m, (int)pr, k > 0 ? mac_data + 600 : NULL,
                              k % 300);
        printf(" %d ", r);
        if (!rand_det[c])
            printf("(%s)", r == 1 ? "random" : "-");
        else
            for (sz = 0; sz < (r == 1 ? n : 0) && sz < 256; sz++)
                printf("%02x", out[sz]);
    } else if (strcmp(command, "rreseed") == 0) {
        sscanf(line, "%*s %lu %lu %lu", &pr, &m, &k);
        r = EVP_RAND_reseed(ctx, (int)pr, m > 0 ? mac_data + 900 : NULL, m % 200,
                            k > 0 ? mac_data + 1200 : NULL, k % 200);
        printf(" %d state %d", r, EVP_RAND_get_state(ctx));
    } else if (strcmp(command, "rnonce") == 0) {
        sscanf(line, "%*s %lu", &n);
        if (n > 1024)
            n = 1024;
        r = EVP_RAND_nonce(ctx, out, n);
        printf(" %d ", r);
        if (!rand_det[c])
            printf("(%s)", r == 1 ? "random" : "-");
        else
            for (sz = 0; sz < (r == 1 ? n : 0) && sz < 256; sz++)
                printf("%02x", out[sz]);
    } else if (strcmp(command, "runinst") == 0) {
        r = EVP_RAND_uninstantiate(ctx);
        printf(" %d state %d zero %d", r, EVP_RAND_get_state(ctx), EVP_RAND_verify_zeroization(ctx));
    } else if (strcmp(command, "rget") == 0) {
        int state = -9, use_df = -9;
        unsigned int strength = 9, counter = 9, requests = 9, gen = 9;
        size_t max = 9, min_e = 9, max_e = 9, min_n = 9, max_n = 9, max_p = 9, max_a = 9;
        char name[32] = "-";

        params[0] = OSSL_PARAM_construct_int("state", &state);
        params[1] = OSSL_PARAM_construct_uint("strength", &strength);
        params[2] = OSSL_PARAM_construct_size_t("max_request", &max);
        params[3] = OSSL_PARAM_construct_size_t("min_entropylen", &min_e);
        params[4] = OSSL_PARAM_construct_size_t("max_entropylen", &max_e);
        params[5] = OSSL_PARAM_construct_size_t("min_noncelen", &min_n);
        params[6] = OSSL_PARAM_construct_size_t("max_noncelen", &max_n);
        params[7] = OSSL_PARAM_construct_size_t("max_perslen", &max_p);
        params[8] = OSSL_PARAM_construct_size_t("max_adinlen", &max_a);
        params[9] = OSSL_PARAM_construct_end();
        r = EVP_RAND_CTX_get_params(ctx, params);
        printf(" %d: %d %u %zu %zu-%zu %zu-%zu %zu %zu", r, state, strength, max, min_e, max_e,
               min_n, max_n, max_p, max_a);
        params[0] = OSSL_PARAM_construct_uint("reseed_counter", &counter);
        params[1] = OSSL_PARAM_construct_uint("reseed_requests", &requests);
        params[2] = OSSL_PARAM_construct_uint("generate", &gen);
        params[3] = OSSL_PARAM_construct_int("use_derivation_function", &use_df);
        params[4] = OSSL_PARAM_construct_end();
        r = EVP_RAND_CTX_get_params(ctx, params);
        printf(" | %d: %u %u %u %d", r, counter, requests, gen, use_df);
        for (k = 0; k < 3; k++) {
            static const char *keys[] = { "cipher", "digest", "mac" };

            strcpy(name, "-");
            params[0] = OSSL_PARAM_construct_utf8_string(keys[k], name, sizeof(name));
            params[1] = OSSL_PARAM_construct_end();
            r = EVP_RAND_CTX_get_params(ctx, params);
            printf(" | %d %s", r, name);
        }
        printf(" | strength %u", EVP_RAND_get_strength(ctx));
    } else if (strcmp(command, "rlock") == 0) {
        printf(" %d", EVP_RAND_enable_locking(ctx));
    } else if (strcmp(command, "rzero") == 0) {
        printf(" %d", EVP_RAND_verify_zeroization(ctx));
    } else {
        EVP_RAND_CTX_free(ctx);
        rand_slot[c] = NULL;
    }
    print_digest_errors();
    /* A failed fetch's error text has the name's number: drop the buffers it sized. */
    OPENSSL_thread_stop();
    return 1;
}

/* ---------------------------------------------------------------------------------------- */

static BIGNUM *bn_reg[4];

static BIGNUM *bn_at(unsigned long i)
{
    i &= 3;
    if (bn_reg[i] == NULL)
        bn_reg[i] = BN_new();
    return bn_reg[i];
}

static void bn_print_value(const char *label, const BIGNUM *a)
{
    char *h = BN_bn2hex(a);

    printf(" %s=%s", label, h == NULL ? "(null)" : h);
    OPENSSL_free(h);
}

/* What a memory BIO holds, newlines as |. */
static void bn_print_bio(BIO *mem)
{
    char *p = NULL;
    long n = BIO_get_mem_data(mem, &p);

    printf(" [");
    for (long i = 0; i < n; i++)
        putchar(p[i] == '\n' ? '|' : p[i]);
    printf("]");
}

/* The current group of the EC commands, and its point registers. */
static EC_GROUP *ec_group = NULL;
static EC_POINT *ec_points[2] = { NULL, NULL };

/* A point's affine coordinates, its three encodings, and (when nothing random went into
 * them, or the generator is known, for the methods whose computation is OpenSSL's generic
 * one) its Jacobian coordinates. */
static void ec_print_point(const EC_POINT *p)
{
    BIGNUM *x = BN_new(), *y = BN_new(), *z = BN_new();
    static const point_conversion_form_t forms[] = {
        POINT_CONVERSION_COMPRESSED, POINT_CONVERSION_UNCOMPRESSED, POINT_CONVERSION_HYBRID
    };
    const EC_METHOD *m = EC_GROUP_method_of(ec_group);
    int generic = m == EC_GFp_mont_method() || m == EC_GF2m_simple_method();

    if (EC_POINT_is_at_infinity(ec_group, p)) {
        printf(" infinity");
    } else if (EC_POINT_get_affine_coordinates(ec_group, p, x, y, NULL)) {
        char *xs = BN_bn2hex(x), *ys = BN_bn2hex(y);

        printf(" (%s,%s)", xs, ys);
        OPENSSL_free(xs);
        OPENSSL_free(ys);
    } else {
        printf(" noaffine");
    }
    for (size_t i = 0; i < 3; i++) {
        unsigned char buf[300];
        size_t len = EC_POINT_point2oct(ec_group, p, forms[i], buf, sizeof(buf), NULL);

        printf(" ");
        for (size_t j = 0; j < len; j++)
            printf("%02x", buf[j]);
    }
    if (generic && rand_priv_det && m == EC_GFp_mont_method()
        && EC_POINT_get_Jprojective_coordinates_GFp(ec_group, p, x, y, z, NULL)) {
        char *xs = BN_bn2hex(x), *ys = BN_bn2hex(y), *zs = BN_bn2hex(z);

        printf(" [%s:%s:%s]", xs, ys, zs);
        OPENSSL_free(xs);
        OPENSSL_free(ys);
        OPENSSL_free(zs);
    }
    BN_free(x);
    BN_free(y);
    BN_free(z);
}

/* A key on the curve `sn` with private key `priv_hex` (and its public key), or NULL. */
static EC_KEY *ec_fixed_key(const char *sn, const char *priv_hex)
{
    EC_KEY *k = EC_KEY_new_by_curve_name(OBJ_sn2nid(sn));
    BIGNUM *priv = NULL;
    EC_POINT *P;

    if (k == NULL)
        return NULL;
    BN_hex2bn(&priv, priv_hex);
    P = EC_POINT_new(EC_KEY_get0_group(k));
    EC_POINT_mul(EC_KEY_get0_group(k), P, priv, NULL, NULL, NULL);
    EC_KEY_set_private_key(k, priv);
    EC_KEY_set_public_key(k, P);
    BN_free(priv);
    EC_POINT_free(P);
    return k;
}

/* ecgen, ecsign, ecsetup, ecverify, ecdh: ECDSA and ECDH with keys on named curves. */
static void ec_key_command(const char *command, const char *line)
{
    char sn[64] = "", a[700] = "-", b[700] = "-", c[700] = "-";
    unsigned char dg[300], sg[300];
    size_t dlen = 0, slen = 0;
    EC_KEY *k;

    sscanf(line, "%*s %63s %699s %699s %699s", sn, a, b, c);
    if (strcmp(command, "ecgen") == 0) {
        char *ph;
        unsigned char *pub = NULL;
        size_t pl;

        k = EC_KEY_new_by_curve_name(OBJ_sn2nid(sn));
        if (k == NULL) {
            printf(" no curve\n");
            return;
        }
        printf(" %d", EC_KEY_generate_key(k));
        ph = BN_bn2hex(EC_KEY_get0_private_key(k));
        pl = EC_KEY_key2buf(k, POINT_CONVERSION_UNCOMPRESSED, &pub, NULL);
        printf(" priv %s", ph != NULL ? ph : "-");
        print_hex(" pub", pub, pl);
        OPENSSL_free(ph);
        OPENSSL_free(pub);
        print_asn_errors();
        EC_KEY_free(k);
        return;
    }
    k = ec_fixed_key(sn, a);
    if (k == NULL) {
        printf(" no curve\n");
        return;
    }
    if (strcmp(command, "ecsign") == 0) {
        /* ecsign <curve> <priv> <digest> */
        unsigned int siglen = sizeof(sg);

        if (!parse_hex(b, dg, &dlen)) {
            printf(" bad hex\n");
            EC_KEY_free(k);
            return;
        }
        printf(" %d", ECDSA_sign(0, dg, (int)dlen, sg, &siglen, k));
        print_hex(" sig", sg, siglen);
        printf(" verify %d", ECDSA_verify(0, dg, (int)dlen, sg, (int)siglen, k));
    } else if (strcmp(command, "ecsetup") == 0) {
        BIGNUM *kinv = NULL, *r = NULL;
        char *kh, *rh;

        printf(" %d", ECDSA_sign_setup(k, NULL, &kinv, &r));
        kh = kinv != NULL ? BN_bn2hex(kinv) : NULL;
        rh = r != NULL ? BN_bn2hex(r) : NULL;
        printf(" kinv %s r %s", kh != NULL ? kh : "-", rh != NULL ? rh : "-");
        OPENSSL_free(kh);
        OPENSSL_free(rh);
        BN_clear_free(kinv);
        BN_clear_free(r);
    } else if (strcmp(command, "ecverify") == 0) {
        /* ecverify <curve> <priv> <digest> <signature> */
        if (!parse_hex(b, dg, &dlen) || !parse_hex(c, sg, &slen)) {
            printf(" bad hex\n");
            EC_KEY_free(k);
            return;
        }
        printf(" %d", ECDSA_verify(0, dg, (int)dlen, sg, (int)slen, k));
    } else {
        /* ecdh <curve> <priv> <peer's priv> <cofactor flag> */
        EC_KEY *peer = ec_fixed_key(sn, b);
        unsigned char sec[200];
        int n;

        if (strcmp(c, "1") == 0)
            EC_KEY_set_flags(k, EC_FLAG_COFACTOR_ECDH);
        n = ECDH_compute_key(sec, sizeof(sec), EC_KEY_get0_public_key(peer), k, NULL);
        printf(" %d", n);
        print_hex(" secret", sec, n > 0 ? (size_t)n : 0);
        EC_KEY_free(peer);
    }
    print_asn_errors();
    EC_KEY_free(k);
}

/* A parameter array on one line: each name and its value. */
static void ec_print_params(const OSSL_PARAM *p)
{
    for (; p != NULL && p->key != NULL; p++) {
        printf(" %s=", p->key);
        if (p->data_type == OSSL_PARAM_INTEGER) {
            int v = 0;

            printf("%d", OSSL_PARAM_get_int(p, &v) ? v : -999);
        } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
            BIGNUM *b = NULL;
            char *h = OSSL_PARAM_get_BN(p, &b) ? BN_bn2hex(b) : NULL;

            printf("%s/%zu", h != NULL ? h : "?", p->data_size);
            OPENSSL_free(h);
            BN_free(b);
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            printf("%.*s", (int)p->data_size, (const char *)p->data);
        } else {
            for (size_t i = 0; i < p->data_size; i++)
                printf("%02x", ((const unsigned char *)p->data)[i]);
        }
    }
}

/* eckm and sm2km: an EC key from data, then what the key manager (keytype's) makes of it. */
static void ec_keymgmt_command(const char *line, const char *keytype)
{
    char group[64] = "-", priv[700] = "-", pub[700] = "-", other[300] = "-";
    unsigned int sel = 0;
    unsigned char pb[300];
    size_t pl = 0;
    BIGNUM *d = NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *ps, *out = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, keytype, NULL);
    EVP_PKEY *k = NULL;

    sscanf(line, "%*s %x %63s %699s %699s %299s", &sel, group, priv, pub, other);
    if (strcmp(group, "-") != 0)
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
    if (strcmp(priv, "-") != 0 && BN_hex2bn(&d, priv) > 0)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d);
    if (strcmp(pub, "-") != 0 && parse_hex(pub, pb, &pl))
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pb, pl);
    if (strcmp(other, "-") != 0) {
        char *save = NULL;

        for (char *kv = strtok_r(other, ",", &save); kv != NULL; kv = strtok_r(NULL, ",", &save)) {
            char *eq = strchr(kv, '=');

            if (eq == NULL)
                continue;
            *eq = '\0';
            if (eq[1] == '#')
                OSSL_PARAM_BLD_push_int(bld, kv, atoi(eq + 2));
            else
                OSSL_PARAM_BLD_push_utf8_string(bld, kv, eq + 1, 0);
        }
    }
    ps = OSSL_PARAM_BLD_to_param(bld);
    printf(" %d", EVP_PKEY_fromdata_init(c));
    printf(" %d", EVP_PKEY_fromdata(c, &k, (int)sel, ps));
    print_asn_errors();
    if (k != NULL) {
        EVP_PKEY_CTX *v = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
        EVP_PKEY *dup = EVP_PKEY_dup(k);
        unsigned char *enc = NULL;
        size_t elen;

        printf("  todata %d", EVP_PKEY_todata(k, OSSL_KEYMGMT_SELECT_ALL, &out));
        ec_print_params(out);
        print_asn_errors();
        printf("  check %d", EVP_PKEY_check(v));
        printf(" public %d", EVP_PKEY_public_check(v));
        printf(" quick %d", EVP_PKEY_public_check_quick(v));
        printf(" private %d", EVP_PKEY_private_check(v));
        printf(" params %d", EVP_PKEY_param_check(v));
        print_asn_errors();
        elen = EVP_PKEY_get1_encoded_public_key(k, &enc);
        print_hex("  encoded", enc, elen);
        print_asn_errors();
        printf("  bits %d security %d size %d eq %d", EVP_PKEY_get_bits(k),
               EVP_PKEY_get_security_bits(k), EVP_PKEY_get_size(k), EVP_PKEY_eq(k, dup));
        printf(" set %d", EVP_PKEY_set_params(k, ps));
        print_asn_errors();
        OPENSSL_free(enc);
        EVP_PKEY_free(dup);
        EVP_PKEY_CTX_free(v);
    }
    OSSL_PARAM_free(out);
    OSSL_PARAM_free(ps);
    OSSL_PARAM_BLD_free(bld);
    BN_free(d);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
}

/* ecdhkem: a key generated from input key material. */
static void ec_dhkem_command(const char *line)
{
    char group[64] = "-", ikm[700] = "-";
    unsigned char ib[300];
    size_t il = 0;
    OSSL_PARAM ps[3];
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *k = NULL;
    OSSL_PARAM *out = NULL;
    int set;

    sscanf(line, "%*s %63s %699s", group, ikm);
    if (!parse_hex(ikm, ib, &il))
        il = 0;
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
    ps[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM, ib, il);
    ps[2] = OSSL_PARAM_construct_end();
    printf(" %d", EVP_PKEY_keygen_init(c));
    set = EVP_PKEY_CTX_set_params(c, ps);
    printf(" %d", set);
    printf(" %d", EVP_PKEY_keygen(c, &k));
    /* Without the input taken, the key is random. */
    if (set == 1 && k != NULL && EVP_PKEY_todata(k, EVP_PKEY_KEYPAIR, &out))
        ec_print_params(out);
    print_asn_errors();
    OSSL_PARAM_free(out);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
}

/* A key of keytype on the curve from a private number, or NULL. */
static EVP_PKEY *ec_fromdata_type(const char *keytype, const char *curve, const char *priv)
{
    BIGNUM *d = NULL;
    EC_GROUP *g = EC_GROUP_new_by_curve_name(OBJ_sn2nid(curve));
    EC_POINT *q = g != NULL ? EC_POINT_new(g) : NULL;
    unsigned char pub[300];
    size_t publen = 0;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *ps;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, keytype, NULL);
    EVP_PKEY *k = NULL;

    if (BN_hex2bn(&d, priv) > 0 && q != NULL && EC_POINT_mul(g, q, d, NULL, NULL, NULL))
        publen = EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED, pub, sizeof(pub), NULL);
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve, 0);
    if (d != NULL)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d);
    if (publen > 0)
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub, publen);
    ps = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_fromdata_init(c);
    printf(" %d", EVP_PKEY_fromdata(c, &k, EVP_PKEY_KEYPAIR, ps));
    OSSL_PARAM_free(ps);
    OSSL_PARAM_BLD_free(bld);
    EC_POINT_free(q);
    EC_GROUP_free(g);
    BN_free(d);
    EVP_PKEY_CTX_free(c);
    return k;
}

/* An EC key on the curve from a private number, or NULL. */
static EVP_PKEY *ec_fromdata(const char *curve, const char *priv)
{
    return ec_fromdata_type("EC", curve, priv);
}

/* ecdhx: a shared secret through the ECDH provider. */
static void ec_exchange_command(const char *line)
{
    char curve[64] = "-", a[700] = "-", b[700] = "-", md[64] = "-", ukm[700] = "-";
    int mode = -1;
    size_t outlen = 0, room = 0, len, ul = 0;
    unsigned char ub[300], out[600];
    EVP_PKEY *ka, *kb;

    sscanf(line, "%*s %63s %699s %699s %d %63s %zu %699s %zu", curve, a, b, &mode, md, &outlen,
           ukm, &room);
    if (room > sizeof(out) || (strcmp(ukm, "-") != 0 && !parse_hex(ukm, ub, &ul))) {
        printf(" bad input\n");
        return;
    }
    printf(" keys");
    ka = ec_fromdata(curve, a);
    kb = ec_fromdata(curve, b);
    print_asn_errors();
    if (ka != NULL && kb != NULL) {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, ka, NULL);
        OSSL_PARAM ps[6], *p = ps;
        int r;

        *p++ = OSSL_PARAM_construct_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, &mode);
        if (strcmp(md, "-") != 0) {
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, "X963KDF", 0);
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, md, 0);
            *p++ = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &outlen);
            if (ul > 0 || strcmp(ukm, "-") != 0)
                *p++ = OSSL_PARAM_construct_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, ub, ul);
        }
        *p = OSSL_PARAM_construct_end();
        r = EVP_PKEY_derive_init_ex(c, ps);
        r = r * 10 + EVP_PKEY_derive_set_peer(c, kb);
        len = 0;
        r = r * 10 + EVP_PKEY_derive(c, NULL, &len);
        printf("  init/peer/size %d %zu", r, len);
        print_asn_errors();
        len = room;
        r = EVP_PKEY_derive(c, out, &len);
        printf("  derive %d", r);
        if (r == 1)
            print_hex("", out, len);
        else
            print_asn_errors();
        EVP_PKEY_CTX_free(c);
    }
    EVP_PKEY_free(ka);
    EVP_PKEY_free(kb);
}

/* An SM2 cipher context for op on k, with the digest md (NULL for the default). */
static EVP_PKEY_CTX *sm2_crypt_ctx(EVP_PKEY *k, int enc, const char *md)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    int r = enc ? EVP_PKEY_encrypt_init(c) : EVP_PKEY_decrypt_init(c);

    if (r == 1 && md != NULL) {
        OSSL_PARAM p[2];

        p[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, (char *)md, 0);
        p[1] = OSSL_PARAM_construct_end();
        r = EVP_PKEY_CTX_set_params(c, p);
    }
    printf(" init %d", r);
    return c;
}

/* sm2enc: an SM2 key's encryption through the SM2 asymmetric cipher. */
static void sm2_enc_command(const char *line)
{
    char priv[700] = "-", md[64] = "-", msg[700] = "-", cthex[700] = "-";
    unsigned char mb[300], cb[300], out[400];
    size_t ml = 0, cl = 0, room = 0, len;
    const char *mdname;
    EVP_PKEY *k;
    EVP_PKEY_CTX *c;
    int r;

    sscanf(line, "%*s %699s %63s %699s %699s %zu", priv, md, msg, cthex, &room);
    mdname = strcmp(md, "-") == 0 ? NULL : md;
    if (room > sizeof(out) || !parse_hex(msg, mb, &ml)
        || (strcmp(cthex, "-") != 0 && !parse_hex(cthex, cb, &cl))) {
        printf(" bad input\n");
        return;
    }
    printf(" key");
    k = ec_fromdata_type("SM2", "SM2", priv);
    print_asn_errors();
    if (k == NULL)
        return;
    if (strcmp(cthex, "-") == 0) {
        printf("  encrypt");
        c = sm2_crypt_ctx(k, 1, mdname);
        len = 0;
        r = EVP_PKEY_encrypt(c, NULL, &len, mb, ml);
        printf(" size %d %zu", r, len);
        len = room;
        r = EVP_PKEY_encrypt(c, out, &len, mb, ml);
        printf(" %d", r);
        if (r == 1)
            print_hex("", out, len);
        else
            print_asn_errors();
        EVP_PKEY_CTX_free(c);
        if (r != 1) {
            EVP_PKEY_free(k);
            return;
        }
        memcpy(cb, out, len);
        cl = len;
        room = sizeof(out);
    }
    printf("  decrypt");
    c = sm2_crypt_ctx(k, 0, mdname);
    len = 0;
    r = EVP_PKEY_decrypt(c, NULL, &len, cb, cl);
    printf(" size %d %zu", r, len);
    print_asn_errors();
    len = room;
    memset(out, 0x77, sizeof(out));
    r = EVP_PKEY_decrypt(c, out, &len, cb, cl);
    printf("  %d", r);
    if (r == 1)
        print_hex("", out, len);
    else
        print_hex(" buffer", out, room);
    print_asn_errors();
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(k);
}

/* sm2sig: an SM2 key's signatures through the SM2 provider. */
static void sm2_sig_command(const char *line)
{
    char priv[700] = "-", id[300] = "-", md[64] = "-", msg[700] = "-", sighex[700] = "-";
    unsigned char mb[300], sb[300], ib[150], sig[300];
    size_t ml = 0, sl = 0, il = 0, len;
    const char *mdname;
    EVP_PKEY *k;

    sscanf(line, "%*s %699s %299s %63s %699s %699s", priv, id, md, msg, sighex);
    mdname = strcmp(md, "-") == 0 ? NULL : md;
    if (!parse_hex(msg, mb, &ml) || (strcmp(id, "-") != 0 && !parse_hex(id, ib, &il))
        || (strcmp(sighex, "-") != 0 && !parse_hex(sighex, sb, &sl))) {
        printf(" bad input\n");
        return;
    }
    printf(" key");
    k = ec_fromdata_type("SM2", "SM2", priv);
    print_asn_errors();
    if (k != NULL) {
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pc = NULL;
        int r;

        if (strcmp(sighex, "-") != 0) {
            r = EVP_DigestVerifyInit_ex(m, &pc, mdname, NULL, NULL, k, NULL);
            if (r == 1 && strcmp(id, "-") != 0)
                r = r * 10 + EVP_PKEY_CTX_set1_id(pc, ib, il);
            printf("  digest verify %d %d", r, EVP_DigestVerify(m, sb, sl, mb, ml));
            print_asn_errors();
            pc = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
            r = EVP_PKEY_verify_init(pc);
            printf("  verify %d %d", r, EVP_PKEY_verify(pc, sb, sl, mb, ml));
            print_asn_errors();
            EVP_PKEY_CTX_free(pc);
        } else {
            len = sizeof(sig);
            r = EVP_DigestSignInit_ex(m, &pc, mdname, NULL, NULL, k, NULL);
            if (r == 1 && strcmp(id, "-") != 0)
                r = r * 10 + EVP_PKEY_CTX_set1_id(pc, ib, il);
            r = r * 10 + EVP_DigestSign(m, sig, &len, mb, ml);
            printf("  digest sign %d", r);
            if (r % 10 == 1) {
                print_hex("", sig, len);
                r = EVP_DigestVerifyInit_ex(m, &pc, mdname, NULL, NULL, k, NULL);
                if (r == 1 && strcmp(id, "-") != 0)
                    r = r * 10 + EVP_PKEY_CTX_set1_id(pc, ib, il);
                printf("  verify %d %d", r, EVP_DigestVerify(m, sig, len, mb, ml));
            }
            print_asn_errors();
            pc = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
            len = sizeof(sig);
            r = EVP_PKEY_sign_init(pc);
            r = r * 10 + EVP_PKEY_sign(pc, sig, &len, mb, ml);
            printf("  sign %d", r);
            if (r == 11) {
                print_hex("", sig, len);
                r = EVP_PKEY_verify_init(pc);
                printf("  verify %d %d", r, EVP_PKEY_verify(pc, sig, len, mb, ml));
            }
            print_asn_errors();
            EVP_PKEY_CTX_free(pc);
        }
        EVP_MD_CTX_free(m);
    }
    EVP_PKEY_free(k);
}

/* ecsig: an EC key's signatures through the ECDSA provider. */
static void ec_sig_command(const char *line)
{
    char curve[64] = "-", priv[700] = "-", md[64] = "-", alg[64] = "-", msg[700] = "-";
    char sighex[700] = "-";
    unsigned int nonce = 0;
    unsigned char mb[300], sb[300], sig[300], pub[300];
    size_t ml = 0, sl = 0, len, publen;
    const char *mdname;
    BIGNUM *d = NULL;
    EC_GROUP *g;
    EC_POINT *q;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *ps;
    OSSL_PARAM np[2];
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *k = NULL;

    sscanf(line, "%*s %63s %699s %63s %u %63s %699s %699s", curve, priv, md, &nonce, alg, msg,
           sighex);
    mdname = strcmp(md, "-") == 0 ? NULL : md;
    if (!parse_hex(msg, mb, &ml) || BN_hex2bn(&d, priv) == 0
        || (strcmp(sighex, "-") != 0 && !parse_hex(sighex, sb, &sl))) {
        printf(" bad input\n");
        BN_free(d);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(c);
        return;
    }
    g = EC_GROUP_new_by_curve_name(OBJ_sn2nid(curve));
    q = EC_POINT_new(g);
    EC_POINT_mul(g, q, d, NULL, NULL, NULL);
    publen = EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED, pub, sizeof(pub), NULL);
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve, 0);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub, publen);
    ps = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_fromdata_init(c);
    printf(" key %d", EVP_PKEY_fromdata(c, &k, EVP_PKEY_KEYPAIR, ps));
    print_asn_errors();
    np[0] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce);
    np[1] = OSSL_PARAM_construct_end();
    if (k != NULL) {
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
        EVP_SIGNATURE *s = strcmp(alg, "-") == 0 ? NULL : EVP_SIGNATURE_fetch(NULL, alg, NULL);
        int r;

        if (strcmp(sighex, "-") != 0) {
            r = EVP_DigestVerifyInit_ex(m, NULL, mdname, NULL, NULL, k, NULL);
            printf("  digest verify %d", r);
            if (r == 1)
                printf(" %d", EVP_DigestVerify(m, sb, sl, mb, ml));
            print_asn_errors();
            r = EVP_PKEY_verify_init(pc);
            if (mdname != NULL)
                r = r * 10 + EVP_PKEY_CTX_set_signature_md(pc, EVP_get_digestbyname(mdname));
            printf("  verify %d %d", r, EVP_PKEY_verify(pc, sb, sl, mb, ml));
            print_asn_errors();
            if (s != NULL) {
                r = EVP_PKEY_verify_message_init(pc, s, NULL);
                r = r * 10 + EVP_PKEY_CTX_set_signature(pc, sb, sl);
                r = r * 10 + EVP_PKEY_verify_message_update(pc, mb, ml);
                printf("  %s verify %d %d", alg, r, EVP_PKEY_verify_message_final(pc));
                print_asn_errors();
            }
        } else {
            len = sizeof(sig);
            r = EVP_DigestSignInit_ex(m, NULL, mdname, NULL, NULL, k, np);
            r = r * 10 + EVP_DigestSign(m, sig, &len, mb, ml);
            printf("  digest sign %d", r);
            if (r == 11) {
                print_hex("", sig, len);
                printf("  verify %d", EVP_DigestVerifyInit_ex(m, NULL, mdname, NULL, NULL, k,
                                                               NULL));
                printf(" %d", EVP_DigestVerify(m, sig, len, mb, ml));
            }
            print_asn_errors();
            len = sizeof(sig);
            r = EVP_PKEY_sign_init_ex(pc, np);
            if (mdname != NULL)
                r = r * 10 + EVP_PKEY_CTX_set_signature_md(pc, EVP_get_digestbyname(mdname));
            r = r * 10 + EVP_PKEY_sign(pc, sig, &len, mb, ml);
            printf("  sign %d", r);
            if (r % 10 == 1) {
                print_hex("", sig, len);
                r = EVP_PKEY_verify_init(pc);
                if (mdname != NULL)
                    r = r * 10 + EVP_PKEY_CTX_set_signature_md(pc, EVP_get_digestbyname(mdname));
                printf("  verify %d %d", r, EVP_PKEY_verify(pc, sig, len, mb, ml));
            }
            print_asn_errors();
            if (s != NULL) {
                len = sizeof(sig);
                r = EVP_PKEY_sign_message_init(pc, s, np);
                r = r * 10 + EVP_PKEY_sign(pc, sig, &len, mb, ml);
                printf("  %s sign %d", alg, r);
                if (r == 11) {
                    print_hex("", sig, len);
                    r = EVP_PKEY_verify_message_init(pc, s, NULL);
                    r = r * 10 + EVP_PKEY_CTX_set_signature(pc, sig, len);
                    r = r * 10 + EVP_PKEY_verify_message_update(pc, mb, ml);
                    printf("  verify %d %d", r, EVP_PKEY_verify_message_final(pc));
                }
                print_asn_errors();
            }
        }
        EVP_SIGNATURE_free(s);
        EVP_PKEY_CTX_free(pc);
        EVP_MD_CTX_free(m);
    }
    OSSL_PARAM_free(ps);
    OSSL_PARAM_BLD_free(bld);
    EC_POINT_free(q);
    EC_GROUP_free(g);
    BN_free(d);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
}

/* ecxkm: an ECX key from data (or DHKEM input), and what its key manager makes of it. */
static void ecx_keymgmt_command(const char *line)
{
    char type[32] = "-", priv[300] = "-", pub[300] = "-", ikm[300] = "-";
    unsigned int sel = 0;
    unsigned char db[150], qb[150], ib[150], raw[200];
    size_t dl = 0, ql = 0, il = 0, n;
    OSSL_PARAM ps[3], *p = ps;
    EVP_PKEY_CTX *c;
    EVP_PKEY *k = NULL;
    OSSL_PARAM *out = NULL;
    int r;

    sscanf(line, "%*s %31s %x %299s %299s %299s", type, &sel, priv, pub, ikm);
    if ((strcmp(priv, "-") != 0 && !parse_hex(priv, db, &dl))
        || (strcmp(pub, "-") != 0 && !parse_hex(pub, qb, &ql))
        || (strcmp(ikm, "-") != 0 && !parse_hex(ikm, ib, &il))) {
        printf(" bad input\n");
        return;
    }
    c = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    if (strcmp(ikm, "-") != 0) {
        ps[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM, ib, il);
        ps[1] = OSSL_PARAM_construct_end();
        printf(" gen %d", EVP_PKEY_keygen_init(c));
        printf(" %d", EVP_PKEY_CTX_set_params(c, ps));
        printf(" %d", EVP_PKEY_keygen(c, &k));
    } else {
        if (strcmp(priv, "-") != 0)
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, db, dl);
        if (strcmp(pub, "-") != 0)
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, qb, ql);
        *p = OSSL_PARAM_construct_end();
        printf(" %d", EVP_PKEY_fromdata_init(c));
        printf(" %d", EVP_PKEY_fromdata(c, &k, (int)sel, ps));
    }
    print_asn_errors();
    if (k != NULL) {
        EVP_PKEY_CTX *v = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);

        printf("  todata %d", EVP_PKEY_todata(k, EVP_PKEY_KEYPAIR, &out));
        ec_print_params(out);
        print_asn_errors();
        n = sizeof(raw);
        r = EVP_PKEY_get_raw_public_key(k, raw, &n);
        printf("  raw public %d", r);
        if (r == 1)
            print_hex("", raw, n);
        n = sizeof(raw);
        r = EVP_PKEY_get_raw_private_key(k, raw, &n);
        printf("  raw private %d", r);
        if (r == 1)
            print_hex("", raw, n);
        print_asn_errors();
        printf("  check %d", EVP_PKEY_check(v));
        printf(" public %d", EVP_PKEY_public_check(v));
        printf(" private %d", EVP_PKEY_private_check(v));
        printf(" pairwise %d", EVP_PKEY_pairwise_check(v));
        printf(" bits %d security %d size %d", EVP_PKEY_get_bits(k),
               EVP_PKEY_get_security_bits(k), EVP_PKEY_get_size(k));
        print_asn_errors();
        EVP_PKEY_CTX_free(v);
    }
    OSSL_PARAM_free(out);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
}

/* Octets in hex after a space, on the same line. */
static void ecx_hex(const unsigned char *p, size_t n)
{
    printf(" ");
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
}

/* x25519x and x448x: the exchange of a private key and a peer's public key into room octets. */
static void x25519_exchange_command(const char *line, int id)
{
    char priv[300] = "-", pub[300] = "-";
    unsigned char db[150], qb[150], s[100];
    size_t dl = 0, ql = 0, room = 0, len;
    EVP_PKEY *k, *peer;
    EVP_PKEY_CTX *c;
    int r;

    sscanf(line, "%*s %299s %299s %zu", priv, pub, &room);
    if (!parse_hex(priv, db, &dl) || !parse_hex(pub, qb, &ql) || room > sizeof(s)) {
        printf(" bad input\n");
        return;
    }
    k = EVP_PKEY_new_raw_private_key(id, NULL, db, dl);
    peer = EVP_PKEY_new_raw_public_key(id, NULL, qb, ql);
    printf(" keys %d %d", k != NULL, peer != NULL);
    print_asn_errors();
    if (k != NULL && peer != NULL) {
        c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
        printf("  init %d", EVP_PKEY_derive_init(c));
        printf(" peer %d", EVP_PKEY_derive_set_peer(c, peer));
        len = 0;
        r = EVP_PKEY_derive(c, NULL, &len);
        printf(" size %d %zu", r, len);
        memset(s, 0x77, sizeof(s));
        len = room;
        r = EVP_PKEY_derive(c, s, &len);
        printf(" derive %d", r);
        printf(" buffer");
        ecx_hex(s, room < 56 ? room : 56);
        print_asn_errors();
        EVP_PKEY_CTX_free(c);
    }
    EVP_PKEY_free(k);
    EVP_PKEY_free(peer);
}

/*
 * ed25519 and ed448: EdDSA signatures with an algorithm (ED25519, ED25519ph, ED25519ctx, ED448,
 * ED448ph; - for EVP_DigestSign), an instance and a context string (each - for none), a
 * private key, and a message: with no signature, the message signed and verified; with one,
 * verified.
 */
static void ed25519_command(const char *line, int id)
{
    char alg[32] = "-", inst[32] = "-", ctxs[600] = "-", priv[300] = "-", msg[600] = "-",
         sig[300] = "-";
    unsigned char db[150], cb[300], mb[300], sb[150], out[150];
    size_t dl = 0, cl = 0, ml = 0, sl = 0, len = sizeof(out);
    OSSL_PARAM ps[3], *p = ps;
    EVP_PKEY *k;
    int r;

    sscanf(line, "%*s %31s %31s %599s %299s %599s %299s", alg, inst, ctxs, priv, msg, sig);
    if ((strcmp(ctxs, "-") != 0 && !parse_hex(ctxs, cb, &cl)) || !parse_hex(priv, db, &dl)
        || (strcmp(msg, "-") != 0 && !parse_hex(msg, mb, &ml))
        || (strcmp(sig, "-") != 0 && !parse_hex(sig, sb, &sl))) {
        printf(" bad input\n");
        return;
    }
    if (strcmp(inst, "-") != 0)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, inst, 0);
    if (strcmp(ctxs, "-") != 0)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, cb, cl);
    *p = OSSL_PARAM_construct_end();
    k = EVP_PKEY_new_raw_private_key(id, NULL, db, dl);
    printf(" key %d", k != NULL);
    if (k == NULL) {
        print_asn_errors();
        return;
    }
    if (strcmp(alg, "-") == 0) {
        EVP_MD_CTX *m = EVP_MD_CTX_new();

        if (strcmp(sig, "-") == 0) {
            r = EVP_DigestSignInit_ex(m, NULL, NULL, NULL, NULL, k, ps);
            printf(" sign %d", r);
            r = EVP_DigestSign(m, out, &len, mb, ml);
            printf(" %d", r);
            if (r == 1) {
                ecx_hex(out, len);
                memcpy(sb, out, len);
                sl = len;
            }
            print_asn_errors();
        }
        if (sl > 0) {
            r = EVP_DigestVerifyInit_ex(m, NULL, NULL, NULL, NULL, k, ps);
            printf("  verify %d", r);
            printf(" %d", EVP_DigestVerify(m, sb, sl, mb, ml));
            print_asn_errors();
        }
        EVP_MD_CTX_free(m);
    } else {
        EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, alg, NULL);
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);

        if (strcmp(sig, "-") == 0) {
            r = EVP_PKEY_sign_message_init(c, s, ps);
            printf(" sign %d", r);
            r = EVP_PKEY_sign(c, out, &len, mb, ml);
            printf(" %d", r);
            if (r == 1) {
                ecx_hex(out, len);
                memcpy(sb, out, len);
                sl = len;
            }
            print_asn_errors();
        }
        if (sl > 0) {
            r = EVP_PKEY_verify_message_init(c, s, ps);
            printf("  verify %d", r);
            printf(" %d", EVP_PKEY_verify(c, sb, sl, mb, ml));
            r = EVP_PKEY_verify_init_ex2(c, s, ps);
            printf(" through verify_init %d", r);
            printf(" %d", EVP_PKEY_verify(c, sb, sl, mb, ml));
            print_asn_errors();
        }
        EVP_PKEY_CTX_free(c);
        EVP_SIGNATURE_free(s);
    }
    EVP_PKEY_free(k);
}

/* The first 8 octets of the SHA-256 of the octets, after a space, with their length. */
static void ml_kem_digest(const unsigned char *p, size_t n)
{
    unsigned char d[32];
    unsigned int dl = 0;

    EVP_Digest(p, n, d, &dl, EVP_sha256(), NULL);
    printf(" %zu:", n);
    for (int i = 0; i < 8; i++)
        printf("%02x", d[i]);
}

/*
 * The private and public keys of the ML-KEM, ML-DSA, or SLH-DSA key of |alg| generated from a
 * seed (of pq_seed_len octets).
 */
/* The length of the seed that makes a key of |alg|: ML-KEM's, ML-DSA's, or SLH-DSA's 3n. */
static size_t pq_seed_len(const char *alg)
{
    if (strncmp(alg, "ML-DSA", 6) == 0)
        return 32;
    if (strncmp(alg, "SLH-DSA", 7) == 0)
        return strstr(alg, "128") != NULL ? 48 : strstr(alg, "192") != NULL ? 72 : 96;
    return 64;
}

static int ml_kem_keys_from_seed(const char *alg, const unsigned char *seed, unsigned char *priv,
                                 size_t *privlen, unsigned char *pub, size_t *publen)
{
    size_t seedlen = pq_seed_len(alg);
    OSSL_PARAM ps[2];
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *k = NULL;
    int ok;

    ps[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, (void *)seed,
                                              seedlen);
    ps[1] = OSSL_PARAM_construct_end();
    ok = c != NULL && EVP_PKEY_keygen_init(c) == 1 && EVP_PKEY_CTX_set_params(c, ps) == 1
        && EVP_PKEY_generate(c, &k) == 1 && EVP_PKEY_get_raw_private_key(k, priv, privlen) == 1
        && EVP_PKEY_get_raw_public_key(k, pub, publen) == 1;
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
    return ok;
}

/* Applies one edit (p@N^XX, p@N=XX, p#N, or the same with q) to the keys; 0 if malformed. */
static int ml_kem_edit(const char *e, unsigned char *priv, size_t *privlen, unsigned char *pub,
                       size_t *publen, size_t room)
{
    unsigned char *b = e[0] == 'p' ? priv : pub;
    size_t *len = e[0] == 'p' ? privlen : publen;
    size_t n;
    unsigned int x;
    char op;

    if (e[0] != 'p' && e[0] != 'q')
        return 0;
    if (e[1] == '#') {
        if (sscanf(e + 2, "%zu", &n) != 1 || n > room)
            return 0;
        if (n > *len)
            memset(b + *len, 0, n - *len);
        *len = n;
        return 1;
    }
    if (e[1] != '@' || sscanf(e + 2, "%zu%c%2x", &n, &op, &x) != 3 || n >= *len)
        return 0;
    if (op == '^')
        b[n] ^= (unsigned char)x;
    else if (op == '=')
        b[n] = (unsigned char)x;
    else
        return 0;
    return 1;
}

/*
 * mlkemkm, mldsakm, and slhdsakm: an ML-KEM, ML-DSA, or SLH-DSA key from data, and what its key
 * manager makes of it.
 */
static void ml_kem_keymgmt_command(const char *line)
{
    char alg[32] = "-", seed[300] = "-", privfrom[300] = "-", pubfrom[300] = "-";
    char edits[300] = "-";
    static unsigned char priv[6000], pub[3000], scratch[6000];
    unsigned char sb[150], fb[150];
    size_t sl = 0, fl = 0, privlen = 0, publen = 0, n;
    unsigned int sel = 0;
    OSSL_PARAM ps[4], *p = ps, *out = NULL;
    EVP_PKEY_CTX *c;
    EVP_PKEY *k = NULL;
    static const char *const parts[] = { OSSL_PKEY_PARAM_ML_KEM_SEED, OSSL_PKEY_PARAM_PRIV_KEY,
                                         OSSL_PKEY_PARAM_PUB_KEY };

    sscanf(line, "%*s %31s %x %299s %299s %299s %299s", alg, &sel, seed, privfrom, pubfrom,
           edits);
    if (strcmp(seed, "-") != 0 && !parse_hex(seed, sb, &sl)) {
        printf(" bad input\n");
        return;
    }
    if (strcmp(privfrom, "-") != 0) {
        size_t ql = sizeof(scratch);

        privlen = sizeof(priv);
        if (!parse_hex(privfrom, fb, &fl) || fl != pq_seed_len(alg)
            || !ml_kem_keys_from_seed(alg, fb, priv, &privlen, scratch, &ql)) {
            printf(" bad private seed\n");
            ERR_clear_error();
            return;
        }
    }
    if (strcmp(pubfrom, "-") != 0) {
        size_t dl = sizeof(scratch);

        publen = sizeof(pub);
        if (!parse_hex(pubfrom, fb, &fl) || fl != pq_seed_len(alg)
            || !ml_kem_keys_from_seed(alg, fb, scratch, &dl, pub, &publen)) {
            printf(" bad public seed\n");
            ERR_clear_error();
            return;
        }
    }
    if (strcmp(edits, "-") != 0) {
        for (char *e = strtok(edits, ","); e != NULL; e = strtok(NULL, ",")) {
            if (!ml_kem_edit(e, priv, &privlen, pub, &publen,
                             e[0] == 'p' ? sizeof(priv) : sizeof(pub))) {
                printf(" bad edit\n");
                return;
            }
        }
    }
    if (strcmp(seed, "-") != 0)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, sb, sl);
    if (strcmp(privfrom, "-") != 0)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, priv, privlen);
    if (strcmp(pubfrom, "-") != 0)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub, publen);
    *p = OSSL_PARAM_construct_end();
    c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    printf(" %d", EVP_PKEY_fromdata_init(c));
    printf(" %d", EVP_PKEY_fromdata(c, &k, (int)sel, ps));
    print_asn_errors();
    if (k != NULL) {
        EVP_PKEY_CTX *v = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);

        printf(" ");
        for (int i = 0; i < 3; i++) {
            n = 0;
            printf(" %s %d", parts[i],
                   EVP_PKEY_get_octet_string_param(k, parts[i], scratch, sizeof(scratch), &n));
            if (n > 0)
                ml_kem_digest(scratch, n);
        }
        print_asn_errors();
        printf("  check %d", EVP_PKEY_check(v));
        printf(" public %d", EVP_PKEY_public_check(v));
        printf(" private %d", EVP_PKEY_private_check(v));
        printf(" pairwise %d", EVP_PKEY_pairwise_check(v));
        printf(" bits %d security %d size %d", EVP_PKEY_get_bits(k),
               EVP_PKEY_get_security_bits(k), EVP_PKEY_get_size(k));
        print_asn_errors();
        printf("  todata %d", EVP_PKEY_todata(k, EVP_PKEY_KEYPAIR, &out));
        for (OSSL_PARAM *q = out; q != NULL && q->key != NULL; q++) {
            printf(" %s", q->key);
            ml_kem_digest(q->data, q->data_size);
        }
        print_asn_errors();
        EVP_PKEY_CTX_free(v);
    }
    OSSL_PARAM_free(out);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
}

/* mlkem: an encapsulation and the decapsulation of its ciphertext, edited. */
static void ml_kem_ops_command(const char *line)
{
    char alg[32] = "-", keyseed[300] = "-", ikme[300] = "-", edits[300] = "-";
    static unsigned char priv[4000], pub[2000], ct[2000];
    unsigned char kb[150], eb[150], ss[100], ss2[100];
    size_t kl = 0, el = 0, privlen = sizeof(priv), publen = sizeof(pub), croom = 0, sroom = 0;
    size_t clen, slen, s2;
    OSSL_PARAM ps[2];
    EVP_PKEY *k;
    EVP_PKEY_CTX *c;
    int r, random;

    sscanf(line, "%*s %31s %299s %299s %299s %zu %zu", alg, keyseed, ikme, edits, &croom, &sroom);
    random = strcmp(ikme, "-") == 0;
    if (!parse_hex(keyseed, kb, &kl) || kl != 64 || (!random && !parse_hex(ikme, eb, &el))
        || croom > sizeof(ct) || sroom > sizeof(ss)
        || !ml_kem_keys_from_seed(alg, kb, priv, &privlen, pub, &publen)) {
        printf(" bad input\n");
        ERR_clear_error();
        return;
    }
    k = EVP_PKEY_new_raw_private_key_ex(NULL, alg, NULL, priv, privlen);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    ps[0] = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, eb, el);
    ps[1] = OSSL_PARAM_construct_end();
    printf(" init %d", EVP_PKEY_encapsulate_init(c, random ? NULL : ps));
    memset(ct, 0x77, sizeof(ct));
    memset(ss, 0x77, sizeof(ss));
    clen = croom;
    slen = sroom;
    r = EVP_PKEY_encapsulate(c, ct, &clen, ss, &slen);
    printf(" encap %d %zu %zu", r, clen, slen);
    if (r == 1 && !random) {
        ml_kem_digest(ct, clen);
        ml_kem_digest(ss, slen);
    }
    print_asn_errors();
    if (r == 1) {
        if (strcmp(edits, "-") != 0) {
            for (char *e = strtok(edits, ","); e != NULL; e = strtok(NULL, ",")) {
                size_t n;
                unsigned int x;

                if (e[0] == 'c' && e[1] == '#' && sscanf(e + 2, "%zu", &n) == 1
                    && n <= sizeof(ct)) {
                    clen = n;
                } else if (e[0] == 'c' && e[1] == '@' && sscanf(e + 2, "%zu^%2x", &n, &x) == 2
                           && n < clen) {
                    ct[n] ^= (unsigned char)x;
                } else {
                    printf("  bad edit\n");
                    break;
                }
            }
        }
        printf("  decap init %d", EVP_PKEY_decapsulate_init(c, NULL));
        memset(ss2, 0x55, sizeof(ss2));
        s2 = sizeof(ss2);
        r = EVP_PKEY_decapsulate(c, ss2, &s2, ct, clen);
        printf(" decap %d %zu same %d", r, s2, memcmp(ss, ss2, 32) == 0);
        if (r == 1 && !random)
            ml_kem_digest(ss2, s2);
        print_asn_errors();
    }
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(k);
}

/* mldsa and slhdsa: a signature with the options given, then the verification of it, edited. */
static void ml_dsa_ops_command(const char *line)
{
    char alg[32] = "-", keyseed[200] = "-", msg[600] = "-", ctx[600] = "-", opts[700] = "-";
    char edits[300] = "-";
    static unsigned char priv[6000], pub[3000], sig[50000];
    unsigned char kb[300], mb[300], cb[300], eb[300], vm[300];
    size_t kl = 0, ml = 0, cl = 0, el = 0, privlen = sizeof(priv), publen = sizeof(pub);
    size_t room = 0, siglen;
    int det = 0, enc = 1, mu = 0, have_det = 0, have_enc = 0, have_mu = 0, have_ent = 0;
    int pubonly = 0, r, fixed;
    OSSL_PARAM ps[6], *p = ps;
    EVP_PKEY *k, *vk;
    EVP_PKEY_CTX *c;
    EVP_SIGNATURE *s;

    sscanf(line, "%*s %31s %199s %599s %599s %699s %zu %299s", alg, keyseed, msg, ctx, opts,
           &room, edits);
    if (!parse_hex(keyseed, kb, &kl) || kl != pq_seed_len(alg)
        || (strcmp(msg, "-") != 0 && !parse_hex(msg, mb, &ml))
        || (strcmp(ctx, "-") != 0 && strcmp(ctx, "e") != 0 && !parse_hex(ctx, cb, &cl))
        || room > sizeof(sig) || !ml_kem_keys_from_seed(alg, kb, priv, &privlen, pub, &publen)) {
        printf(" bad input\n");
        ERR_clear_error();
        return;
    }
    if (strcmp(opts, "-") != 0) {
        for (char *o = strtok(opts, ","); o != NULL; o = strtok(NULL, ",")) {
            if (sscanf(o, "det=%d", &det) == 1) {
                have_det = 1;
            } else if (sscanf(o, "enc=%d", &enc) == 1) {
                have_enc = 1;
            } else if (sscanf(o, "mu=%d", &mu) == 1) {
                have_mu = 1;
            } else if (strncmp(o, "ent=", 4) == 0 && parse_hex(o + 4, eb, &el)) {
                have_ent = 1;
            } else if (strcmp(o, "pub") == 0) {
                pubonly = 1;
            } else {
                printf(" bad option\n");
                return;
            }
        }
    }
    if (strcmp(ctx, "-") != 0)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, cb, cl);
    if (have_ent)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, eb, el);
    if (have_det)
        *p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    if (have_enc)
        *p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &enc);
    if (have_mu)
        *p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MU, &mu);
    *p = OSSL_PARAM_construct_end();
    /*
     * Signatures are fixed with test entropy of the right length (32 octets, or SLH-DSA's n), or
     * deterministic without any (ML-DSA's deterministic is 1, SLH-DSA's any nonzero value).
     */
    if (strncmp(alg, "SLH-DSA", 7) == 0)
        fixed = have_ent ? el == pq_seed_len(alg) / 3 : det != 0;
    else
        fixed = have_ent ? el == 32 : det == 1;

    k = EVP_PKEY_new_raw_private_key_ex(NULL, alg, NULL, priv, privlen);
    s = EVP_SIGNATURE_fetch(NULL, alg, NULL);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    printf(" init %d", EVP_PKEY_sign_message_init(c, s, ps));
    memset(sig, 0x77, sizeof(sig));
    siglen = room;
    r = EVP_PKEY_sign(c, room == 0 ? NULL : sig, &siglen, mb, ml);
    printf(" sign %d %zu", r, siglen);
    if (r == 1 && room != 0 && fixed)
        ml_kem_digest(sig, siglen);
    print_asn_errors();
    EVP_PKEY_CTX_free(c);
    if (r == 1 && room != 0) {
        memcpy(vm, mb, ml);
        if (strcmp(edits, "-") != 0) {
            for (char *e = strtok(edits, ","); e != NULL; e = strtok(NULL, ",")) {
                size_t n;
                unsigned int x;

                if (e[0] == 's' && e[1] == '#' && sscanf(e + 2, "%zu", &n) == 1
                    && n <= sizeof(sig)) {
                    siglen = n;
                } else if (e[0] == 's' && e[1] == '@' && sscanf(e + 2, "%zu^%2x", &n, &x) == 2
                           && n < siglen) {
                    sig[n] ^= (unsigned char)x;
                } else if (e[0] == 'm' && e[1] == '@' && sscanf(e + 2, "%zu^%2x", &n, &x) == 2
                           && n < ml) {
                    vm[n] ^= (unsigned char)x;
                } else {
                    printf("  bad edit\n");
                    break;
                }
            }
        }
        vk = pubonly ? EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, pub, publen) : k;
        c = EVP_PKEY_CTX_new_from_pkey(NULL, vk, NULL);
        printf("  vinit %d", EVP_PKEY_verify_message_init(c, s, ps));
        printf(" verify %d", EVP_PKEY_verify(c, sig, siglen, vm, ml));
        print_asn_errors();
        EVP_PKEY_CTX_free(c);
        if (vk != k)
            EVP_PKEY_free(vk);
    }
    EVP_SIGNATURE_free(s);
    EVP_PKEY_free(k);
}

/* |n| octets of SHA-256(seed || counter) blocks: a deterministic stream from a seed. */
static void hash_stream(const unsigned char *seed, size_t seedlen, unsigned char *out, size_t n)
{
    unsigned char block[32], ctr[4];
    unsigned int dl;
    size_t off = 0;
    uint32_t i = 0;

    while (off < n) {
        EVP_MD_CTX *m = EVP_MD_CTX_new();

        ctr[0] = (unsigned char)(i >> 24);
        ctr[1] = (unsigned char)(i >> 16);
        ctr[2] = (unsigned char)(i >> 8);
        ctr[3] = (unsigned char)i;
        EVP_DigestInit_ex(m, EVP_sha256(), NULL);
        EVP_DigestUpdate(m, seed, seedlen);
        EVP_DigestUpdate(m, ctr, 4);
        EVP_DigestFinal_ex(m, block, &dl);
        EVP_MD_CTX_free(m);
        memcpy(out + off, block, n - off < 32 ? n - off : 32);
        off += 32;
        i++;
    }
}

/* mlx: a hybrid key from data, and its KEM. */
static void mlx_command(const char *line)
{
    char alg[32] = "-", keyseed[300] = "-", ctseed[300] = "-";
    static unsigned char mpriv[4000], mpub[2000], priv[4000], pub[2000], ct[4000], buf[4000];
    unsigned char kb[150], cb[150], ss[200], ss2[200];
    size_t kl = 0, cl = 0, mprivlen = sizeof(mpriv), mpublen = sizeof(mpub), n;
    long ctdelta = 0;
    int big = strstr(alg, "1024") != NULL, nist, r;
    size_t xpriv, xpub, ctlen, slen, s2, privlen, publen;
    const char *mlkem;
    OSSL_PARAM ps[2];
    EVP_PKEY_CTX *c;
    EVP_PKEY *k = NULL, *pk = NULL, *xk = NULL;

    sscanf(line, "%*s %31s %299s %299s %ld", alg, keyseed, ctseed, &ctdelta);
    big = strstr(alg, "1024") != NULL;
    nist = strncmp(alg, "SecP", 4) == 0;
    mlkem = big ? "ML-KEM-1024" : "ML-KEM-768";
    if (!parse_hex(keyseed, kb, &kl) || kl != 64 || !parse_hex(ctseed, cb, &cl)
        || !ml_kem_keys_from_seed(mlkem, kb, mpriv, &mprivlen, mpub, &mpublen)) {
        printf(" bad input\n");
        ERR_clear_error();
        return;
    }
    /* The ECDH half: X25519's or X448's private key from the stream, or a NIST curve's. */
    if (strncmp(alg, "X25519", 6) == 0) {
        xpriv = 32;
        xk = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL, kb, 32);
    } else if (strncmp(alg, "X448", 4) == 0) {
        xpriv = 56;
        hash_stream(kb, kl, buf, 56);
        xk = EVP_PKEY_new_raw_private_key_ex(NULL, "X448", NULL, buf, 56);
    } else {
        xpriv = big ? 48 : 32;
        xk = EVP_PKEY_Q_keygen(NULL, NULL, "EC", big ? "P-384" : "P-256");
    }
    xpub = 0;
    EVP_PKEY_get_octet_string_param(xk, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, buf, sizeof(buf),
                                    &xpub);
    if (nist) {
        memcpy(pub, buf, xpub);
        memcpy(pub + xpub, mpub, mpublen);
    } else {
        memcpy(pub, mpub, mpublen);
        memcpy(pub + mpublen, buf, xpub);
        memcpy(priv, mpriv, mprivlen);
        n = xpriv;
        EVP_PKEY_get_raw_private_key(xk, priv + mprivlen, &n);
    }
    publen = mpublen + xpub;
    privlen = mprivlen + xpriv;

    /* The private key (X25519 and X448 only: a NIST curve's can't be imported as octets). */
    if (!nist) {
        ps[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, priv, privlen);
        ps[1] = OSSL_PARAM_construct_end();
        c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
        printf(" priv %d", EVP_PKEY_fromdata_init(c));
        printf(" %d", EVP_PKEY_fromdata(c, &k, EVP_PKEY_KEYPAIR, ps));
        EVP_PKEY_CTX_free(c);
        if (k != NULL) {
            n = 0;
            printf(" encoded %d", EVP_PKEY_get_octet_string_param(
                       k, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, buf, sizeof(buf), &n));
            ml_kem_digest(buf, n);
            printf(" same %d", n == publen && memcmp(buf, pub, n) == 0);
        }
        print_asn_errors();
    }
    ps[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub, publen);
    ps[1] = OSSL_PARAM_construct_end();
    c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    printf("  pub %d", EVP_PKEY_fromdata_init(c));
    printf(" %d", EVP_PKEY_fromdata(c, &pk, EVP_PKEY_PUBLIC_KEY, ps));
    EVP_PKEY_CTX_free(c);
    if (pk != NULL && k != NULL)
        printf(" eq %d", EVP_PKEY_eq(pk, k));
    print_asn_errors();

    ctlen = (big ? 1568 : 1088) + xpub;
    if (ctdelta < 0 && (size_t)-ctdelta > ctlen)
        ctdelta = -(long)ctlen;
    ctlen = (size_t)((long)ctlen + ctdelta);
    if (ctlen > sizeof(ct))
        ctlen = sizeof(ct);
    hash_stream(cb, cl, ct, ctlen);
    if (k != NULL) {
        c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
        slen = sizeof(ss);
        printf("  decap %d", EVP_PKEY_decapsulate_init(c, NULL));
        r = EVP_PKEY_decapsulate(c, ss, &slen, ct, ctlen);
        printf(" %d %zu", r, slen);
        if (r == 1)
            ml_kem_digest(ss, slen);
        print_asn_errors();
        EVP_PKEY_CTX_free(c);
    }
    if (pk != NULL) {
        c = EVP_PKEY_CTX_new_from_pkey(NULL, pk, NULL);
        n = sizeof(ct);
        slen = sizeof(ss);
        printf("  encap %d", EVP_PKEY_encapsulate_init(c, NULL));
        r = EVP_PKEY_encapsulate(c, ct, &n, ss, &slen);
        printf(" %d %zu %zu", r, n, slen);
        EVP_PKEY_CTX_free(c);
        if (r == 1 && k != NULL) {
            c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
            s2 = sizeof(ss2);
            EVP_PKEY_decapsulate_init(c, NULL);
            printf(" back %d", EVP_PKEY_decapsulate(c, ss2, &s2, ct, n));
            printf(" same %d", s2 == slen && memcmp(ss, ss2, slen) == 0);
            EVP_PKEY_CTX_free(c);
        }
        print_asn_errors();
    }
    EVP_PKEY_free(k);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(xk);
}

/* A number from hex (a named group's part "ffdhe2048:p" etc. for convenience), or NULL. */
static BIGNUM *dh_number(const char *spec)
{
    BIGNUM *b = NULL;
    const BIGNUM *p, *q, *g;
    char name[32];
    char part;
    int nid;
    DH *dh;

    if (strcmp(spec, "-") == 0)
        return NULL;
    if (sscanf(spec, "%31[^:]:%c", name, &part) == 2) {
        nid = OBJ_sn2nid(name);
        if (strcmp(name, "dh_1024_160") == 0)
            dh = DH_get_1024_160();
        else if (strcmp(name, "dh_2048_224") == 0)
            dh = DH_get_2048_224();
        else if (strcmp(name, "dh_2048_256") == 0)
            dh = DH_get_2048_256();
        else
            dh = DH_new_by_nid(nid);
        if (dh == NULL)
            return NULL;
        DH_get0_pqg(dh, &p, &q, &g);
        b = BN_dup(part == 'p' ? p : part == 'q' ? q : g);
        DH_free(dh);
        return b;
    }
    if (BN_hex2bn(&b, spec) == 0)
        return NULL;
    return b;
}

/* dhcheck: DH's checks of parameters and a public key from data. */
static void dh_check_command(const char *line)
{
    char ps[1200] = "-", qs[1200] = "-", gs[1200] = "-", ys[1200] = "-", edit[64] = "-";
    BIGNUM *p, *q, *g, *y;
    DH *dh = DH_new();
    int ret, r;
    unsigned int add;

    sscanf(line, "%*s %1199s %1199s %1199s %1199s %63s", ps, qs, gs, ys, edit);
    p = dh_number(ps);
    q = dh_number(qs);
    g = dh_number(gs);
    y = dh_number(ys);
    /* An edit: pN, qN, gN, yN adds N to that number. */
    if (sscanf(edit, "p%u", &add) == 1 && p != NULL)
        BN_add_word(p, add);
    else if (sscanf(edit, "q%u", &add) == 1 && q != NULL)
        BN_add_word(q, add);
    else if (sscanf(edit, "g%u", &add) == 1 && g != NULL)
        BN_add_word(g, add);
    else if (sscanf(edit, "y%u", &add) == 1 && y != NULL)
        BN_add_word(y, add);
    r = DH_set0_pqg(dh, p, q, g);
    if (r == 0) {
        BN_free(p);
        BN_free(q);
        BN_free(g);
    }
    printf(" set %d nid %d bits %d security %d", r, DH_get_nid(dh), DH_bits(dh),
           DH_security_bits(dh));
    ret = -1;
    r = DH_check(dh, &ret);
    printf(" check %d %#x", r, ret);
    ret = -1;
    r = DH_check_params(dh, &ret);
    printf(" params %d %#x", r, ret);
    if (y != NULL) {
        ret = -1;
        r = DH_check_pub_key(dh, y, &ret);
        printf(" pub %d %#x", r, ret);
    }
    print_asn_errors();
    printf("  ex %d %d", DH_check_ex(dh), DH_check_params_ex(dh));
    if (y != NULL)
        printf(" %d", DH_check_pub_key_ex(dh, y));
    print_asn_errors();
    BN_free(y);
    DH_free(dh);
}

/* dhder: d2i_DHparams or d2i_DHxparams of the octets, then what the parameters are. */
static void dh_der_command(const char *line)
{
    char kind[8] = "-", hexs[2100] = "-";
    static unsigned char der[1100];
    unsigned char *re = NULL;
    const unsigned char *pp = der;
    size_t n = 0, i;
    DH *dh;
    BIO *b;
    char *text;
    long tn;
    int rn, x942, ret = -1;

    sscanf(line, "%*s %7s %2099s", kind, hexs);
    x942 = strcmp(kind, "x") == 0;
    for (i = 0; hexs[2 * i] != '\0' && hexs[2 * i + 1] != '\0' && i < sizeof(der); i++) {
        unsigned int v;

        if (sscanf(hexs + 2 * i, "%2x", &v) != 1)
            break;
        der[i] = (unsigned char)v;
    }
    n = i;
    dh = x942 ? d2i_DHxparams(NULL, &pp, (long)n) : d2i_DHparams(NULL, &pp, (long)n);
    printf(" %s consumed %ld", dh == NULL ? "fails" : "ok", (long)(pp - der));
    print_asn_errors();
    if (dh == NULL)
        return;
    printf("  bits %d nid %d length %ld", DH_bits(dh), DH_get_nid(dh), DH_get_length(dh));
    rn = x942 ? i2d_DHxparams(dh, &re) : i2d_DHparams(dh, &re);
    printf(" re %d same %d", rn, rn == (int)n && memcmp(re, der, n) == 0);
    OPENSSL_free(re);
    DH_check_params(dh, &ret);
    printf(" params %#x", ret);
    b = BIO_new(BIO_s_mem());
    printf(" print %d", DHparams_print(b, dh));
    tn = BIO_get_mem_data(b, &text);
    ml_kem_digest((const unsigned char *)text, (size_t)tn);
    BIO_free(b);
    print_asn_errors();
    DH_free(dh);
}

/* dhkey: a DH or DHX key from data, then its checks and its encoded public key. */
static void dh_key_command(const char *line)
{
    char type[8] = "DH", ps[1200] = "-", qs[1200] = "-", gs[1200] = "-", ys[1200] = "-";
    char xs[1200] = "-", ls[32] = "-", edit[64] = "-";
    BIGNUM *p, *q, *g, *y = NULL, *x;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params;
    EVP_PKEY_CTX *c;
    EVP_PKEY *k = NULL, *k2;
    unsigned char *enc = NULL;
    size_t n;
    unsigned int add;
    int r;

    sscanf(line, "%*s %7s %1199s %1199s %1199s %1199s %1199s %31s %63s", type, ps, qs, gs, ys,
           xs, ls, edit);
    p = dh_number(ps);
    q = dh_number(qs);
    g = dh_number(gs);
    x = dh_number(xs);
    if (strcmp(ys, "gx") == 0) {
        BN_CTX *bc = BN_CTX_new();

        y = BN_new();
        if (p == NULL || g == NULL || x == NULL || !BN_mod_exp(y, g, x, p, bc)) {
            BN_free(y);
            y = NULL;
        }
        BN_CTX_free(bc);
    } else {
        y = dh_number(ys);
    }
    if (sscanf(edit, "p%u", &add) == 1 && p != NULL)
        BN_add_word(p, add);
    else if (sscanf(edit, "q%u", &add) == 1 && q != NULL)
        BN_add_word(q, add);
    else if (sscanf(edit, "g%u", &add) == 1 && g != NULL)
        BN_add_word(g, add);
    else if (sscanf(edit, "y%u", &add) == 1 && y != NULL)
        BN_add_word(y, add);
    else if (sscanf(edit, "x%u", &add) == 1 && x != NULL)
        BN_add_word(x, add);
    if (p != NULL)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p);
    if (q != NULL)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q);
    if (g != NULL)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g);
    if (y != NULL)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, y);
    if (x != NULL)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, x);
    if (strcmp(ls, "-") != 0)
        OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_DH_PRIV_LEN, atoi(ls));
    params = OSSL_PARAM_BLD_to_param(bld);
    c = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    printf(" fromdata %d", EVP_PKEY_fromdata_init(c));
    printf(" %d", EVP_PKEY_fromdata(c, &k, EVP_PKEY_KEYPAIR, params));
    EVP_PKEY_CTX_free(c);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(y);
    BN_free(x);
    print_asn_errors();
    if (k == NULL)
        return;
    printf("  bits %d security %d size %d", EVP_PKEY_get_bits(k), EVP_PKEY_get_security_bits(k),
           EVP_PKEY_get_size(k));
    c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    printf(" check %d", EVP_PKEY_check(c));
    printf(" public %d", EVP_PKEY_public_check(c));
    printf(" %d", EVP_PKEY_public_check_quick(c));
    printf(" param %d", EVP_PKEY_param_check(c));
    printf(" %d", EVP_PKEY_param_check_quick(c));
    printf(" private %d", EVP_PKEY_private_check(c));
    printf(" pairwise %d", EVP_PKEY_pairwise_check(c));
    EVP_PKEY_CTX_free(c);
    print_asn_errors();
    n = EVP_PKEY_get1_encoded_public_key(k, &enc);
    printf("  encoded %zu", n);
    if (n > 0)
        ml_kem_digest(enc, n);
    print_asn_errors();
    k2 = EVP_PKEY_dup(k);
    if (k2 != NULL) {
        r = EVP_PKEY_set1_encoded_public_key(k2, enc, n);
        printf("  set %d eq %d", r, EVP_PKEY_eq(k, k2));
        print_asn_errors();
    }
    OPENSSL_free(enc);
    EVP_PKEY_free(k2);
    EVP_PKEY_free(k);
}

/* A DH of a named group (by short name) with the private key x, its public key computed. */
static DH *dh_from_priv(const char *group, const char *x, const DH_METHOD *meth)
{
    DH *dh;
    BIGNUM *priv = NULL;

    if (strcmp(group, "dh_2048_256") == 0)
        dh = DH_get_2048_256();
    else if (strcmp(group, "dh_1024_160") == 0)
        dh = DH_get_1024_160();
    else
        dh = DH_new_by_nid(OBJ_sn2nid(group));
    if (dh == NULL)
        return NULL;
    if (meth != NULL)
        DH_set_method(dh, meth);
    if (BN_hex2bn(&priv, x) == 0) {
        DH_free(dh);
        return NULL;
    }
    DH_set0_key(dh, NULL, priv);
    DH_generate_key(dh);
    return dh;
}

/* dhexch: a DH exchange through the provider or the legacy method. */
static void dh_exch_command(const char *line)
{
    char how[4] = "p", group[32] = "ffdhe2048", xa[300] = "1", xb[300] = "1", edit[32] = "-";
    char kdf[300] = "-";
    int pad = 0;
    size_t room = 0, n = 0;
    static unsigned char out[1100];
    DH_METHOD *meth = NULL;
    DH *a, *b;
    EVP_PKEY *ka = EVP_PKEY_new(), *kb = EVP_PKEY_new();
    EVP_PKEY_CTX *c;
    int r;

    sscanf(line, "%*s %3s %31s %299s %299s %31s %d %299s %zu", how, group, xa, xb, edit, &pad,
           kdf, &room);
    if (strcmp(how, "l") == 0)
        meth = DH_meth_dup(DH_OpenSSL());
    a = dh_from_priv(group, xa, meth);
    b = dh_from_priv(group, xb, meth);
    if (a == NULL || b == NULL) {
        printf(" no keys\n");
        goto end;
    }
    {
        BIGNUM *y = BN_dup(DH_get0_pub_key(b));
        unsigned int add;

        if (strcmp(edit, "y=1") == 0)
            BN_one(y);
        else if (strcmp(edit, "y=p") == 0)
            BN_sub(y, DH_get0_p(b), BN_value_one());
        else if (sscanf(edit, "y%u", &add) == 1)
            BN_add_word(y, add);
        DH_set0_key(b, y, NULL);
    }
    EVP_PKEY_set1_DH(ka, a);
    EVP_PKEY_set1_DH(kb, b);
    c = EVP_PKEY_CTX_new(ka, NULL);
    printf(" init %d", EVP_PKEY_derive_init(c));
    printf(" peer %d", EVP_PKEY_derive_set_peer_ex(c, kb, 0));
    printf(" pad %d", EVP_PKEY_CTX_set_dh_pad(c, pad));
    if (strcmp(kdf, "-") != 0) {
        char md[64] = "", cek[64] = "", ukm[200] = "";
        int outlen = 0;

        sscanf(kdf, "%63[^:]:%d:%63[^:]:%199s", md, &outlen, cek, ukm);
        if (meth == NULL) {
            OSSL_PARAM ps[6], *q = ps;
            size_t ol = (size_t)outlen;
            unsigned char ub[100];
            long ul = 0;
            unsigned char *u = ukm[0] != '\0' ? OPENSSL_hexstr2buf(ukm, &ul) : NULL;

            if (u != NULL && ul > 0 && ul <= (long)sizeof(ub))
                memcpy(ub, u, (size_t)ul);
            *q++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE,
                                                    OSSL_KDF_NAME_X942KDF_ASN1, 0);
            *q++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, md, 0);
            *q++ = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &ol);
            *q++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG, cek, 0);
            if (u != NULL)
                *q++ = OSSL_PARAM_construct_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, ub,
                                                         (size_t)ul);
            *q = OSSL_PARAM_construct_end();
            printf(" kdf %d", EVP_PKEY_CTX_set_params(c, ps));
            OPENSSL_free(u);
        } else {
            long ul = 0;
            unsigned char *u = ukm[0] != '\0' ? OPENSSL_hexstr2buf(ukm, &ul) : NULL;
            ASN1_OBJECT *o = OBJ_txt2obj(cek, 0);

            r = EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_DH_KDF_TYPE,
                                  EVP_PKEY_DH_KDF_X9_42, NULL);
            r = r * 10 + EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_DH_KDF_MD, 0,
                                           (void *)EVP_get_digestbyname(md));
            r = r * 10 + EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE,
                                           EVP_PKEY_CTRL_DH_KDF_OUTLEN, outlen, NULL);
            r = r * 10 + EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_DH_KDF_OID,
                                           0, o);
            if (u != NULL)
                r = r * 10 + EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE,
                                               EVP_PKEY_CTRL_DH_KDF_UKM, (int)ul, u);
            printf(" kdf %d", r);
        }
    }
    r = EVP_PKEY_derive(c, NULL, &n);
    printf(" size %d %zu", r, n);
    if (meth != NULL && strcmp(kdf, "-") == 0 && room < n)
        room = n; /* OpenSSL's legacy method writes the whole secret (docs/DEVIATIONS.md). */
    n = room < sizeof(out) ? room : sizeof(out);
    r = EVP_PKEY_derive(c, out, &n);
    printf(" derive %d %zu", r, n);
    if (r > 0)
        ml_kem_digest(out, n);
    print_asn_errors();
    EVP_PKEY_CTX_free(c);
end:
    DH_free(a);
    DH_free(b);
    EVP_PKEY_free(ka);
    EVP_PKEY_free(kb);
    DH_meth_free(meth);
}

/* RFC 6979's DSA-1024 key (A.2.1), changed as `how` says. */
static DSA *rfc6979_dsa(const char *how)
{
    DSA *d = DSA_new();
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *y = NULL;

    BN_hex2bn(&p, "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447E6533B86B18B"
                  "ED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED8873ABFD3F5BA2E0A8C0A59082"
                  "EAC056935E529DAF7C610467899C77ADEDFC846C881870B7B19B2B58F9BE0521A17002E3BDD6"
                  "B86685EE90B3D9A1B02B782B1779");
    BN_hex2bn(&q, "996F967F6C8E388D9E28D01E205FBA957A5698B1");
    BN_hex2bn(&g, "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D89BBCD97E904"
                  "E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD87995A10A1C27CB7789B594B"
                  "A7EFB5C4326A9FE59A070E136DB77175464ADCA417BE5DCE2F40D10A46A3A3943F26AB7FD9C0"
                  "398FF8C76EE0A56826A8A88F1DBD");
    BN_hex2bn(&y, "5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F65392195A38B905"
                  "23E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D4CE935437DC11C3C8FD42633"
                  "8933EBFE739CB3465F4D3668C5E473508253B1E682F65CBDC4FAE93C2EA212390E54905A86E2"
                  "223170B44EAA7DA5DD9FFCFB7F3B");
    if (strcmp(how, "small") == 0)
        BN_rshift(q, q, 40);
    else if (strcmp(how, "q+2") == 0)
        BN_add_word(q, 2);
    else if (strcmp(how, "even") == 0)
        BN_add_word(p, 1);
    DSA_set0_pqg(d, p, q, g);
    if (strcmp(how, "nopub") == 0)
        BN_free(y);
    else
        DSA_set0_key(d, y, NULL);
    return d;
}

/* dsaverify: a DSA signature's decoding and verification. */
static void dsa_verify_command(const char *line)
{
    char dhex[300] = "-", shex[600] = "-", how[16] = "k";
    unsigned char *dg = NULL, *sg = NULL;
    long dl = 0, sl = 0;
    DSA *d;
    DSA_SIG *s;
    const unsigned char *pp;

    sscanf(line, "%*s %299s %599s %15s", dhex, shex, how);
    if (strcmp(dhex, "-") != 0)
        dg = OPENSSL_hexstr2buf(dhex, &dl);
    if (strcmp(shex, "-") != 0)
        sg = OPENSSL_hexstr2buf(shex, &sl);
    d = rfc6979_dsa(how);
    printf(" verify %d", DSA_verify(0, dg, (int)dl, sg, (int)sl, d));
    print_asn_errors();
    pp = sg;
    s = d2i_DSA_SIG(NULL, &pp, sl);
    printf("  d2i %s consumed %ld", s == NULL ? "fails" : "ok", (long)(pp - sg));
    if (s != NULL)
        printf(" do_verify %d", DSA_do_verify(dg, (int)dl, s, d));
    print_asn_errors();
    DSA_SIG_free(s);
    DSA_free(d);
    OPENSSL_free(dg);
    OPENSSL_free(sg);
}

/* dsader: one of DSA's decoders, then the key's encodings. */
static void dsa_der_command(const char *line)
{
    char kind[4] = "p", hexs[2100] = "";
    long n = 0;
    unsigned char *der, *re = NULL;
    const unsigned char *pp;
    DSA *d;
    int rn;

    sscanf(line, "%*s %3s %2099s", kind, hexs);
    der = OPENSSL_hexstr2buf(hexs, &n);
    pp = der;
    if (strcmp(kind, "k") == 0)
        d = d2i_DSAPrivateKey(NULL, &pp, n);
    else if (strcmp(kind, "u") == 0)
        d = d2i_DSAPublicKey(NULL, &pp, n);
    else
        d = d2i_DSAparams(NULL, &pp, n);
    printf(" %s consumed %ld", d == NULL ? "fails" : "ok", (long)(pp - der));
    print_asn_errors();
    if (d != NULL) {
        printf("  bits %d", DSA_bits(d));
        rn = strcmp(kind, "k") == 0   ? i2d_DSAPrivateKey(d, &re)
             : strcmp(kind, "u") == 0 ? i2d_DSAPublicKey(d, &re)
                                      : i2d_DSAparams(d, &re);
        printf(" re %d same %d", rn, rn == (int)n && re != NULL && memcmp(re, der, (size_t)n) == 0);
        OPENSSL_free(re);
        printf(" params %d public %d private %d", i2d_DSAparams(d, NULL), i2d_DSAPublicKey(d, NULL),
               i2d_DSAPrivateKey(d, NULL));
        print_asn_errors();
    }
    DSA_free(d);
    OPENSSL_free(der);
}

/* Runs a DH command; returns 0 if `command` isn't one. */
static int dh_command(const char *command, const char *line)
{
    if (strcmp(command, "dhcheck") != 0 && strcmp(command, "dhder") != 0
        && strcmp(command, "dhkey") != 0 && strcmp(command, "dhexch") != 0
        && strcmp(command, "dsaverify") != 0 && strcmp(command, "dsader") != 0)
        return 0;
    printf("%s:", line);
    if (strcmp(command, "dhder") == 0)
        dh_der_command(line);
    else if (strcmp(command, "dhkey") == 0)
        dh_key_command(line);
    else if (strcmp(command, "dhexch") == 0)
        dh_exch_command(line);
    else if (strcmp(command, "dsaverify") == 0)
        dsa_verify_command(line);
    else if (strcmp(command, "dsader") == 0)
        dsa_der_command(line);
    else
        dh_check_command(line);
    return 1;
}

/* Runs an ML-KEM or ML-DSA command; returns 0 if `command` isn't one. */
static int ml_kem_command(const char *command, const char *line)
{
    if (strcmp(command, "mlkemkm") != 0 && strcmp(command, "mlkem") != 0
        && strcmp(command, "mldsakm") != 0 && strcmp(command, "mldsa") != 0
        && strcmp(command, "slhdsakm") != 0 && strcmp(command, "slhdsa") != 0
        && strcmp(command, "mlx") != 0)
        return 0;
    printf("%s:", line);
    if (strcmp(command, "mlkem") == 0)
        ml_kem_ops_command(line);
    else if (strcmp(command, "mldsa") == 0 || strcmp(command, "slhdsa") == 0)
        ml_dsa_ops_command(line);
    else if (strcmp(command, "mlx") == 0)
        mlx_command(line);
    else
        ml_kem_keymgmt_command(line);
    return 1;
}

/* Runs an EC command; returns 0 if `command` isn't one. */
static int ec_command(const char *command, const char *line)
{
    char a[700] = "-", b[700] = "-", c[700] = "-";
    unsigned char buf[300];
    size_t len = 0;
    int ret;

    if (strcmp(command, "ecgrp") != 0 && strcmp(command, "ecpt") != 0
        && strcmp(command, "eccomp") != 0 && strcmp(command, "ecmul") != 0
        && strcmp(command, "ecadd") != 0 && strcmp(command, "ecpk") != 0
        && strcmp(command, "eckey") != 0 && strcmp(command, "ecgen") != 0
        && strcmp(command, "ecsign") != 0 && strcmp(command, "ecsetup") != 0
        && strcmp(command, "ecverify") != 0 && strcmp(command, "ecdh") != 0
        && strcmp(command, "eckm") != 0 && strcmp(command, "ecdhkem") != 0
        && strcmp(command, "ecsig") != 0 && strcmp(command, "ecdhx") != 0
        && strcmp(command, "sm2km") != 0 && strcmp(command, "sm2sig") != 0
        && strcmp(command, "sm2enc") != 0 && strcmp(command, "ecxkm") != 0
        && strcmp(command, "x25519x") != 0 && strcmp(command, "ed25519") != 0
        && strcmp(command, "x448x") != 0 && strcmp(command, "ed448") != 0)
        return 0;
    printf("%s:", line);
    if (strcmp(command, "x25519x") == 0 || strcmp(command, "x448x") == 0) {
        x25519_exchange_command(line,
                                strcmp(command, "x448x") == 0 ? EVP_PKEY_X448 : EVP_PKEY_X25519);
        return 1;
    }
    if (strcmp(command, "ed25519") == 0 || strcmp(command, "ed448") == 0) {
        ed25519_command(line, strcmp(command, "ed448") == 0 ? EVP_PKEY_ED448 : EVP_PKEY_ED25519);
        return 1;
    }
    if (strcmp(command, "ecxkm") == 0) {
        ecx_keymgmt_command(line);
        return 1;
    }
    if (strcmp(command, "sm2enc") == 0) {
        sm2_enc_command(line);
        return 1;
    }
    if (strcmp(command, "sm2sig") == 0) {
        sm2_sig_command(line);
        return 1;
    }
    if (strcmp(command, "ecdhx") == 0) {
        ec_exchange_command(line);
        return 1;
    }
    if (strcmp(command, "ecsig") == 0) {
        ec_sig_command(line);
        return 1;
    }
    if (strcmp(command, "eckm") == 0 || strcmp(command, "sm2km") == 0) {
        ec_keymgmt_command(line, command[0] == 's' ? "SM2" : "EC");
        return 1;
    }
    if (strcmp(command, "ecdhkem") == 0) {
        ec_dhkem_command(line);
        return 1;
    }
    if (strcmp(command, "ecgen") == 0 || strcmp(command, "ecsign") == 0
        || strcmp(command, "ecsetup") == 0 || strcmp(command, "ecverify") == 0
        || strcmp(command, "ecdh") == 0) {
        ec_key_command(command, line);
        return 1;
    }
    if (strcmp(command, "eckey") == 0) {
        /* eckey <hex>: d2i_ECPrivateKey, and the key it makes. */
        const unsigned char *p = buf;
        EC_KEY *k;

        sscanf(line, "%*s %699s", a);
        if (!parse_hex(a, buf, &len)) {
            printf(" bad hex\n");
            return 1;
        }
        k = d2i_ECPrivateKey(NULL, &p, (long)len);
        printf(" %s %ld", k != NULL ? "decoded" : "refused", (long)(p - buf));
        if (k != NULL) {
            unsigned char *der = NULL, *pub = NULL;
            int n;
            size_t pl;
            char *priv = BN_bn2hex(EC_KEY_get0_private_key(k));
            BIO *mem = BIO_new(BIO_s_mem());
            char *text;
            long tlen;

            printf(" curve %d flags %d enc %u form %d priv %s",
                   EC_GROUP_get_curve_name(EC_KEY_get0_group(k)), EC_KEY_get_flags(k),
                   EC_KEY_get_enc_flags(k), (int)EC_KEY_get_conv_form(k), priv);
            OPENSSL_free(priv);
            pl = EC_KEY_key2buf(k, POINT_CONVERSION_UNCOMPRESSED, &pub, NULL);
            print_hex(" pub", pub, pl);
            OPENSSL_free(pub);
            n = i2d_ECPrivateKey(k, &der);
            print_hex(" der", der, n > 0 ? (size_t)n : 0);
            OPENSSL_free(der);
            print_asn_errors();
            printf(" check %d", EC_KEY_check_key(k));
            print_asn_errors();
            printf(" print %d", EC_KEY_print(mem, k, 1));
            tlen = BIO_get_mem_data(mem, &text);
            for (long i = 0; i < tlen; i++)
                putchar(text[i] == '\n' ? '|' : text[i]);
            BIO_free(mem);
            EC_KEY_free(k);
        }
        print_asn_errors();
        return 1;
    }
    if (strcmp(command, "ecpk") == 0) {
        /* ecpk <hex>: d2i_ECPKParameters, and the group it makes. */
        const unsigned char *p = buf;
        EC_GROUP *g;

        sscanf(line, "%*s %699s", a);
        if (!parse_hex(a, buf, &len)) {
            printf(" bad hex\n");
            return 1;
        }
        g = d2i_ECPKParameters(NULL, &p, (long)len);
        printf(" %s %ld", g != NULL ? "decoded" : "refused", (long)(p - buf));
        if (g != NULL) {
            unsigned char *der = NULL;
            int n;
            BIO *mem = BIO_new(BIO_s_mem());
            char *text;
            long tlen;

            printf(" curve %d flag %d form %d seed %zu degree %d", EC_GROUP_get_curve_name(g),
                   EC_GROUP_get_asn1_flag(g), (int)EC_GROUP_get_point_conversion_form(g),
                   EC_GROUP_get0_seed(g) != NULL ? EC_GROUP_get_seed_len(g) : 0,
                   EC_GROUP_get_degree(g));
            n = i2d_ECPKParameters(g, &der);
            print_hex(" der", der, n > 0 ? (size_t)n : 0);
            OPENSSL_free(der);
            printf(" check %d", EC_GROUP_check(g, NULL));
            print_asn_errors();
            printf(" print %d", ECPKParameters_print(mem, g, 2));
            tlen = BIO_get_mem_data(mem, &text);
            for (long i = 0; i < tlen; i++)
                putchar(text[i] == '\n' ? '|' : text[i]);
            BIO_free(mem);
            EC_GROUP_free(g);
        }
        print_asn_errors();
        return 1;
    }
    if (strcmp(command, "ecgrp") == 0) {
        sscanf(line, "%*s %699s", a);
        for (int i = 0; i < 2; i++)
            EC_POINT_free(ec_points[i]);
        EC_GROUP_free(ec_group);
        ec_group = EC_GROUP_new_by_curve_name(OBJ_sn2nid(a));
        for (int i = 0; i < 2; i++)
            ec_points[i] = ec_group == NULL ? NULL : EC_POINT_new(ec_group);
        printf(" %s", ec_group == NULL ? "failed" : "ok");
        print_asn_errors();
        return 1;
    }
    if (ec_group == NULL) {
        printf(" no group\n");
        return 1;
    }
    if (strcmp(command, "ecpt") == 0) {
        unsigned long r = 0;

        sscanf(line, "%*s %lu %699s", &r, a);
        r %= 2;
        if (strcmp(a, "-") != 0 && !parse_hex(a, buf, &len)) {
            printf(" bad hex\n");
            return 1;
        }
        ret = EC_POINT_oct2point(ec_group, ec_points[r], buf, len, NULL);
        printf(" %d", ret);
        if (ret)
            ec_print_point(ec_points[r]);
        print_asn_errors();
    } else if (strcmp(command, "eccomp") == 0) {
        unsigned long r = 0;
        int bit = 0;
        BIGNUM *x = NULL;

        sscanf(line, "%*s %lu %699s %d", &r, a, &bit);
        r %= 2;
        BN_hex2bn(&x, a);
        ret = EC_POINT_set_compressed_coordinates(ec_group, ec_points[r], x, bit, NULL);
        printf(" %d", ret);
        if (ret)
            ec_print_point(ec_points[r]);
        print_asn_errors();
        BN_free(x);
    } else if (strcmp(command, "ecmul") == 0) {
        /* ecmul <r> <g scalar or -> <point register or -> <its scalar or -> */
        unsigned long r = 0;
        BIGNUM *k = NULL, *k2 = NULL;
        const EC_POINT *pt = NULL;
        const EC_METHOD *m;
        int offcurve;

        sscanf(line, "%*s %lu %699s %699s %699s", &r, a, b, c);
        r %= 2;
        if (strcmp(a, "-") != 0)
            BN_hex2bn(&k, a);
        if (strcmp(b, "-") != 0)
            pt = ec_points[strtoul(b, NULL, 10) % 2];
        if (strcmp(c, "-") != 0)
            BN_hex2bn(&k2, c);
        /* A point off the curve multiplied by a specialized method (not the generic prime
         * or binary ones) gives a meaningless result that depends on its formulas, so only
         * that is printed, and the register becomes infinity on both libraries. */
        m = EC_GROUP_method_of(ec_group);
        ERR_set_mark();
        offcurve = pt != NULL && k2 != NULL && m != EC_GFp_simple_method()
            && m != EC_GFp_mont_method() && m != EC_GFp_nist_method()
            && m != EC_GF2m_simple_method() && !EC_POINT_is_at_infinity(ec_group, pt)
            && EC_POINT_is_on_curve(ec_group, pt, NULL) != 1;
        ERR_pop_to_mark();
        ret = EC_POINT_mul(ec_group, ec_points[r], k, pt, k2, NULL);
        printf(" %d", ret);
        if (ret && offcurve) {
            printf(" offcurve");
            EC_POINT_set_to_infinity(ec_group, ec_points[r]);
        } else if (ret) {
            ec_print_point(ec_points[r]);
        }
        print_asn_errors();
        BN_free(k);
        BN_free(k2);
    } else {
        /* ecadd <r> <a> <b>: EC_POINT_add, or with r = a = b, the same object. */
        unsigned long r = 0, x = 0, y = 0;

        sscanf(line, "%*s %lu %lu %lu", &r, &x, &y);
        ret = EC_POINT_add(ec_group, ec_points[r % 2], ec_points[x % 2], ec_points[y % 2],
                           NULL);
        printf(" %d", ret);
        if (ret)
            ec_print_point(ec_points[r % 2]);
        print_asn_errors();
    }
    return 1;
}

static int bn_command(const char *command, const char *line)
{
    char op[16] = "", text[1000] = "";
    unsigned long r = 0, a = 0, b = 0;
    long n = 0;
    int ret = 0;
    BIGNUM *x;

    if (command[0] != 'b' || command[1] != 'n'
        || (strcmp(command, "bnset") != 0 && strcmp(command, "bntext") != 0
            && strcmp(command, "bnop") != 0 && strcmp(command, "bndiv") != 0
            && strcmp(command, "bnshift") != 0 && strcmp(command, "bnword") != 0
            && strcmp(command, "bnbit") != 0 && strcmp(command, "bnflag") != 0
            && strcmp(command, "bnshow") != 0 && strcmp(command, "bnto") != 0
            && strcmp(command, "bnfrom") != 0 && strcmp(command, "bnrand") != 0
            && strcmp(command, "bnrange") != 0 && strcmp(command, "bnasn1") != 0
            && strcmp(command, "bnparam") != 0 && strcmp(command, "bnmod") != 0
            && strcmp(command, "bnmshift") != 0 && strcmp(command, "bnexp") != 0
            && strcmp(command, "bnexp2") != 0 && strcmp(command, "bninv") != 0
            && strcmp(command, "bngcd") != 0 && strcmp(command, "bnkron") != 0
            && strcmp(command, "bncoprime") != 0 && strcmp(command, "bnsqrt") != 0
            && strcmp(command, "bnmont") != 0 && strcmp(command, "bnrecp") != 0
            && strcmp(command, "bnnist") != 0 && strcmp(command, "bnprime") != 0
            && strcmp(command, "bnisprime") != 0 && strcmp(command, "bngen") != 0
            && strcmp(command, "bngf2m") != 0))
        return 0;
    printf("%s:", line);
    if (strcmp(command, "bnset") == 0) {
        sscanf(line, "%*s %lu %999s", &r, text);
        x = bn_at(r);
        printf(" %d", BN_hex2bn(&x, text));
        bn_print_value("r", x);
    } else if (strcmp(command, "bntext") == 0) {
        sscanf(line, "%*s %lu %15s %999s", &r, op, text);
        x = bn_at(r);
        if (strcmp(op, "dec") == 0)
            ret = BN_dec2bn(&x, text);
        else if (strcmp(op, "hex") == 0)
            ret = BN_hex2bn(&x, text);
        else
            ret = BN_asc2bn(&x, text);
        printf(" %d", ret);
        bn_print_value("r", x);
    } else if (strcmp(command, "bnop") == 0) {
        BIGNUM *ra, *rb;

        sscanf(line, "%*s %15s %lu %lu %lu", op, &r, &a, &b);
        x = bn_at(r);
        ra = bn_at(a);
        rb = bn_at(b);
        if ((strcmp(op, "mul") == 0 || strcmp(op, "sqr") == 0)
            && BN_num_bits(ra) + BN_num_bits(strcmp(op, "sqr") == 0 ? ra : rb) > 200000) {
            printf(" skipped: too large\n");
            return 1;
        }
        if (strcmp(op, "add") == 0) {
            ret = BN_add(x, ra, rb);
        } else if (strcmp(op, "sub") == 0) {
            ret = BN_sub(x, ra, rb);
        } else if (strcmp(op, "uadd") == 0) {
            ret = BN_uadd(x, ra, rb);
        } else if (strcmp(op, "usub") == 0) {
            ret = BN_usub(x, ra, rb);
        } else if (strcmp(op, "mul") == 0) {
            BN_CTX *ctx = BN_CTX_new();

            ret = BN_mul(x, ra, rb, ctx);
            BN_CTX_free(ctx);
        } else if (strcmp(op, "sqr") == 0) {
            BN_CTX *ctx = BN_CTX_new();

            ret = BN_sqr(x, ra, ctx);
            BN_CTX_free(ctx);
        } else if (strcmp(op, "nnmod") == 0) {
            BN_CTX *ctx = BN_CTX_new();

            ret = BN_nnmod(x, ra, rb, ctx);
            BN_CTX_free(ctx);
        } else if (strcmp(op, "exp") == 0) {
            BN_CTX *ctx = BN_CTX_new();

            if (BN_num_bits(rb) > 16
                || (unsigned long)BN_num_bits(ra) * BN_get_word(rb) > 65536) {
                printf(" skipped: too large\n");
                BN_CTX_free(ctx);
                return 1;
            }
            ret = BN_exp(x, ra, rb, ctx);
            BN_CTX_free(ctx);
        } else if (strcmp(op, "cmp") == 0) {
            printf(" %d %d\n", BN_cmp(ra, rb), BN_ucmp(ra, rb));
            return 1;
        } else if (strcmp(op, "copy") == 0) {
            ret = BN_copy(x, ra) != NULL;
        } else if (strcmp(op, "swap") == 0) {
            BN_swap(ra, rb);
            bn_print_value("a", ra);
            bn_print_value("b", rb);
            printf(" flags %x %x\n", BN_get_flags(ra, ~0), BN_get_flags(rb, ~0));
            return 1;
        } else {
            printf(" unknown\n");
            return 1;
        }
        printf(" %d", ret);
        bn_print_value("r", x);
    } else if (strcmp(command, "bndiv") == 0) {
        char q[8] = "", rem[8] = "";
        BIGNUM *dv, *rv;
        BN_CTX *ctx = BN_CTX_new();

        sscanf(line, "%*s %7s %7s %lu %lu", q, rem, &a, &b);
        dv = q[0] == '-' ? NULL : bn_at(strtoul(q, NULL, 10));
        rv = rem[0] == '-' ? NULL : bn_at(strtoul(rem, NULL, 10));
        if (dv != NULL && dv == rv) {
            printf(" skipped: one register\n");
            BN_CTX_free(ctx);
            return 1;
        }
        ret = BN_div(dv, rv, bn_at(a), bn_at(b), ctx);
        BN_CTX_free(ctx);
        printf(" %d", ret);
        if (dv != NULL)
            bn_print_value("q", dv);
        if (rv != NULL)
            bn_print_value("rem", rv);
    } else if (strcmp(command, "bnshift") == 0) {
        sscanf(line, "%*s %15s %lu %lu %ld", op, &r, &a, &n);
        x = bn_at(r);
        if (n > 100000 || (op[0] == 'l' && BN_num_bits(bn_at(a)) + n > 300000)) {
            printf(" skipped: too far\n");
            return 1;
        }
        if (strcmp(op, "lshift") == 0)
            ret = BN_lshift(x, bn_at(a), (int)n);
        else if (strcmp(op, "rshift") == 0)
            ret = BN_rshift(x, bn_at(a), (int)n);
        else if (strcmp(op, "lshift1") == 0)
            ret = BN_lshift1(x, bn_at(a));
        else
            ret = BN_rshift1(x, bn_at(a));
        printf(" %d", ret);
        bn_print_value("r", x);
    } else if (strcmp(command, "bnword") == 0) {
        unsigned long long w = 0;

        sscanf(line, "%*s %15s %lu %llu", op, &r, &w);
        x = bn_at(r);
        if (strcmp(op, "add") == 0)
            printf(" %d", BN_add_word(x, (BN_ULONG)w));
        else if (strcmp(op, "sub") == 0)
            printf(" %d", BN_sub_word(x, (BN_ULONG)w));
        else if (strcmp(op, "mul") == 0)
            printf(" %d", BN_mul_word(x, (BN_ULONG)w));
        else if (strcmp(op, "div") == 0)
            printf(" %llu", (unsigned long long)BN_div_word(x, (BN_ULONG)w));
        else
            printf(" %llu", (unsigned long long)BN_mod_word(x, (BN_ULONG)w));
        bn_print_value("r", x);
    } else if (strcmp(command, "bnbit") == 0) {
        sscanf(line, "%*s %15s %lu %ld", op, &r, &n);
        x = bn_at(r);
        if (n > 100000) {
            printf(" skipped: too far\n");
            return 1;
        }
        if (strcmp(op, "set") == 0)
            ret = BN_set_bit(x, (int)n);
        else if (strcmp(op, "clear") == 0)
            ret = BN_clear_bit(x, (int)n);
        else if (strcmp(op, "isset") == 0)
            ret = BN_is_bit_set(x, (int)n);
        else
            ret = BN_mask_bits(x, (int)n);
        printf(" %d", ret);
        bn_print_value("r", x);
    } else if (strcmp(command, "bnflag") == 0) {
        sscanf(line, "%*s %lu", &r);
        BN_set_flags(bn_at(r), BN_FLG_CONSTTIME);
        printf(" %x", BN_get_flags(bn_at(r), ~0));
    } else if (strcmp(command, "bnshow") == 0) {
        BIO *mem = BIO_new(BIO_s_mem());
        char *d;

        sscanf(line, "%*s %lu", &r);
        x = bn_at(r);
        d = BN_bn2dec(x);
        bn_print_value("hex", x);
        printf(" dec=%s bits %d bytes %d zero %d one %d odd %d neg %d word %llx", d,
               BN_num_bits(x), BN_num_bytes(x), BN_is_zero(x), BN_is_one(x), BN_is_odd(x),
               BN_is_negative(x), (unsigned long long)BN_get_word(x));
        OPENSSL_free(d);
        printf(" print %d", BN_print(mem, x));
        bn_print_bio(mem);
        BIO_free(mem);
    } else if (strcmp(command, "bnto") == 0) {
        unsigned char out[600];

        sscanf(line, "%*s %lu %15s %ld", &r, op, &n);
        x = bn_at(r);
        if (n > 512 || BN_num_bytes(x) > 500) {
            printf(" skipped: too long\n");
            return 1;
        }
        memset(out, 0xee, sizeof(out));
        if (strcmp(op, "bin") == 0)
            ret = BN_bn2bin(x, out);
        else if (strcmp(op, "binpad") == 0)
            ret = BN_bn2binpad(x, out, (int)n);
        else if (strcmp(op, "lebin") == 0)
            ret = BN_bn2lebinpad(x, out, (int)n);
        else if (strcmp(op, "native") == 0)
            ret = BN_bn2nativepad(x, out, (int)n);
        else if (strcmp(op, "sbin") == 0)
            ret = BN_signed_bn2bin(x, out, (int)n);
        else if (strcmp(op, "slebin") == 0)
            ret = BN_signed_bn2lebin(x, out, (int)n);
        else if (strcmp(op, "snative") == 0)
            ret = BN_signed_bn2native(x, out, (int)n);
        else
            ret = BN_bn2mpi(x, out);
        printf(" %d ", ret);
        for (int i = 0; i < ret; i++)
            printf("%02x", out[i]);
    } else if (strcmp(command, "bnfrom") == 0) {
        unsigned char in[300];
        size_t len = 0;
        BIGNUM *got;

        sscanf(line, "%*s %lu %15s %999s", &r, op, text);
        x = bn_at(r);
        if (strcmp(text, "-") != 0 && !parse_hex(text, in, &len)) {
            printf(" bad hex\n");
            return 1;
        }
        if (strcmp(op, "bin") == 0)
            got = BN_bin2bn(in, (int)len, x);
        else if (strcmp(op, "lebin") == 0)
            got = BN_lebin2bn(in, (int)len, x);
        else if (strcmp(op, "native") == 0)
            got = BN_native2bn(in, (int)len, x);
        else if (strcmp(op, "sbin") == 0)
            got = BN_signed_bin2bn(in, (int)len, x);
        else if (strcmp(op, "slebin") == 0)
            got = BN_signed_lebin2bn(in, (int)len, x);
        else if (strcmp(op, "snative") == 0)
            got = BN_signed_native2bn(in, (int)len, x);
        else
            got = BN_mpi2bn(in, (int)len, x);
        printf(" %s", got == x ? "ok" : got == NULL ? "failed" : "other");
        bn_print_value("r", x);
    } else if (strcmp(command, "bnrand") == 0) {
        unsigned long kind = 0;
        long top = 0, bottom = 0;
        int det;

        sscanf(line, "%*s %lu %ld %ld %ld %lu", &r, &n, &top, &bottom, &kind);
        x = bn_at(r);
        if (n > 4096) {
            printf(" skipped: too long\n");
            return 1;
        }
        if (kind == 0) {
            ret = BN_rand(x, (int)n, (int)top, (int)bottom);
            det = rand_pub_det;
        } else if (kind == 1) {
            ret = BN_priv_rand(x, (int)n, (int)top, (int)bottom);
            det = rand_priv_det;
        } else {
            ret = BN_bntest_rand(x, (int)n, (int)top, (int)bottom);
            det = rand_pub_det && rand_priv_det;
        }
        printf(" %d", ret);
        if (det) {
            bn_print_value("r", x);
        } else {
            /* Zeroed after, so later commands don't see the random number. */
            printf(" (random) bits %s", BN_num_bits(x) <= n ? "ok" : "too many");
            BN_zero(x);
        }
    } else if (strcmp(command, "bnrange") == 0) {
        unsigned long kind = 0;
        BIGNUM *range;

        sscanf(line, "%*s %lu %lu %lu", &r, &a, &kind);
        x = bn_at(r);
        range = bn_at(a);
        if (x == range) {
            printf(" skipped: one register\n");
            return 1;
        }
        ret = kind == 0 ? BN_rand_range(x, range) : BN_priv_rand_range(x, range);
        printf(" %d", ret);
        if (kind == 0 ? rand_pub_det : rand_priv_det) {
            bn_print_value("r", x);
        } else {
            printf(" (random) %s", ret != 1 || BN_cmp(x, range) < 0 ? "ok" : "out of range");
            BN_zero(x);
        }
    } else if (strcmp(command, "bnasn1") == 0) {
        ASN1_INTEGER *ai;
        BIGNUM *back;
        BIO *mem = BIO_new(BIO_s_mem());

        sscanf(line, "%*s %lu", &r);
        x = bn_at(r);
        ai = BN_to_ASN1_INTEGER(x, NULL);
        if (ai != NULL) {
            printf(" type %d ", ai->type);
            for (int i = 0; i < ai->length && i < 300; i++)
                printf("%02x", ai->data[i]);
            back = ASN1_INTEGER_to_BN(ai, NULL);
            printf(" back %d", back != NULL && BN_cmp(back, x) == 0);
            BN_free(back);
        }
        ASN1_INTEGER_free(ai);
        printf(" print %d", ASN1_bn_print(mem, "n:", x, NULL, 2));
        bn_print_bio(mem);
        BIO_free(mem);
    } else if (strcmp(command, "bnmod") == 0) {
        unsigned long m = 0;
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *ra, *rb, *rm;

        sscanf(line, "%*s %15s %lu %lu %lu %lu", op, &r, &a, &b, &m);
        x = bn_at(r);
        ra = bn_at(a);
        rb = bn_at(b);
        rm = bn_at(m);
        if (BN_num_bits(ra) + BN_num_bits(rb) > 200000) {
            printf(" skipped: too large\n");
            BN_CTX_free(ctx);
            return 1;
        }
        if (strcmp(op, "add") == 0)
            ret = BN_mod_add(x, ra, rb, rm, ctx);
        else if (strcmp(op, "sub") == 0)
            ret = BN_mod_sub(x, ra, rb, rm, ctx);
        else if (strcmp(op, "mul") == 0)
            ret = BN_mod_mul(x, ra, rb, rm, ctx);
        else if (strcmp(op, "sqr") == 0)
            ret = BN_mod_sqr(x, ra, rm, ctx);
        else if (strcmp(op, "lshift1") == 0)
            ret = BN_mod_lshift1(x, ra, rm, ctx);
        else if (strcmp(op, "addq") == 0)
            ret = BN_mod_add_quick(x, ra, rb, rm);
        else if (strcmp(op, "subq") == 0)
            ret = BN_mod_sub_quick(x, ra, rb, rm);
        else
            ret = BN_mod_lshift1_quick(x, ra, rm);
        BN_CTX_free(ctx);
        printf(" %d", ret);
        bn_print_value("r", x);
    } else if (strcmp(command, "bnmshift") == 0) {
        unsigned long m = 0;
        BN_CTX *ctx = BN_CTX_new();

        sscanf(line, "%*s %15s %lu %lu %ld %lu", op, &r, &a, &n, &m);
        x = bn_at(r);
        if (n > 10000 || (op[0] == 'q' && x == bn_at(m))) {
            printf(" skipped: too far, or into the modulus\n");
            BN_CTX_free(ctx);
            return 1;
        }
        if (op[0] == 'q')
            ret = BN_mod_lshift_quick(x, bn_at(a), (int)n, bn_at(m));
        else
            ret = BN_mod_lshift(x, bn_at(a), (int)n, bn_at(m), ctx);
        BN_CTX_free(ctx);
        printf(" %d", ret);
        bn_print_value("r", x);
    } else if (strcmp(command, "bnexp") == 0) {
        unsigned long p = 0, m = 0;
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *ra, *rp, *rm;

        sscanf(line, "%*s %15s %lu %lu %lu %lu", op, &r, &a, &p, &m);
        x = bn_at(r);
        ra = bn_at(a);
        rp = bn_at(p);
        rm = bn_at(m);
        if (BN_num_bits(rp) > 2048 || BN_num_bits(rm) > 2048 || BN_num_bits(ra) > 4096) {
            printf(" skipped: too large\n");
            BN_CTX_free(ctx);
            return 1;
        }
        if (strcmp(op, "exp") == 0)
            ret = BN_mod_exp(x, ra, rp, rm, ctx);
        else if (strcmp(op, "mont") == 0)
            ret = BN_mod_exp_mont(x, ra, rp, rm, ctx, NULL);
        else if (strcmp(op, "ct") == 0)
            ret = BN_mod_exp_mont_consttime(x, ra, rp, rm, ctx, NULL);
        else if (strcmp(op, "recp") == 0)
            ret = BN_mod_exp_recp(x, ra, rp, rm, ctx);
        else if (strcmp(op, "simple") == 0)
            ret = BN_mod_exp_simple(x, ra, rp, rm, ctx);
        else
            ret = BN_mod_exp_mont_word(x, BN_get_word(ra), rp, rm, ctx, NULL);
        BN_CTX_free(ctx);
        printf(" %d", ret);
        bn_print_value("r", x);
    } else if (strcmp(command, "bnexp2") == 0) {
        unsigned long p1 = 0, a2 = 0, p2 = 0, m = 0;
        BN_CTX *ctx = BN_CTX_new();

        sscanf(line, "%*s %lu %lu %lu %lu %lu %lu", &r, &a, &p1, &a2, &p2, &m);
        x = bn_at(r);
        if (BN_num_bits(bn_at(p1)) > 2048 || BN_num_bits(bn_at(p2)) > 2048
            || BN_num_bits(bn_at(m)) > 2048 || BN_num_bits(bn_at(a)) > 4096
            || BN_num_bits(bn_at(a2)) > 4096) {
            printf(" skipped: too large\n");
            BN_CTX_free(ctx);
            return 1;
        }
        ret = BN_mod_exp2_mont(x, bn_at(a), bn_at(p1), bn_at(a2), bn_at(p2), bn_at(m), ctx, NULL);
        BN_CTX_free(ctx);
        printf(" %d", ret);
        bn_print_value("r", x);
    } else if (strcmp(command, "bninv") == 0) {
        char t[8] = "";
        BIGNUM *in, *got;
        BN_CTX *ctx = BN_CTX_new();

        sscanf(line, "%*s %7s %lu %lu", t, &a, &b);
        in = t[0] == '-' ? NULL : bn_at(strtoul(t, NULL, 10));
        /* OpenSSL's result into the modulus fails (or not) depending on its reduction. */
        if (in == bn_at(b)) {
            printf(" skipped: into the modulus\n");
            BN_CTX_free(ctx);
            return 1;
        }
        if (BN_num_bits(bn_at(b)) > 4096) {
            printf(" skipped: too large\n");
            BN_CTX_free(ctx);
            return 1;
        }
        got = BN_mod_inverse(in, bn_at(a), bn_at(b), ctx);
        BN_CTX_free(ctx);
        printf(" %s", got == NULL ? "none" : got == in ? "in" : "new");
        if (got != NULL)
            bn_print_value("r", got);
        if (got != NULL && got != in)
            BN_free(got);
    } else if (strcmp(command, "bngcd") == 0) {
        BN_CTX *ctx = BN_CTX_new();

        sscanf(line, "%*s %lu %lu %lu", &r, &a, &b);
        x = bn_at(r);
        if (BN_num_bits(bn_at(a)) > 4096 || BN_num_bits(bn_at(b)) > 4096) {
            printf(" skipped: too large\n");
            BN_CTX_free(ctx);
            return 1;
        }
        printf(" %d", BN_gcd(x, bn_at(a), bn_at(b), ctx));
        BN_CTX_free(ctx);
        bn_print_value("r", x);
    } else if (strcmp(command, "bnkron") == 0 || strcmp(command, "bncoprime") == 0) {
        BN_CTX *ctx = BN_CTX_new();

        sscanf(line, "%*s %lu %lu", &a, &b);
        if (BN_num_bits(bn_at(a)) > 4096 || BN_num_bits(bn_at(b)) > 4096) {
            printf(" skipped: too large\n");
            BN_CTX_free(ctx);
            return 1;
        }
        if (command[2] == 'k')
            printf(" %d", BN_kronecker(bn_at(a), bn_at(b), ctx));
        else
            printf(" %d flags %x", BN_are_coprime(bn_at(a), bn_at(b), ctx), BN_get_flags(bn_at(a), ~0));
        BN_CTX_free(ctx);
    } else if (strcmp(command, "bnsqrt") == 0) {
        char t[8] = "";
        BIGNUM *in, *got;
        BN_CTX *ctx = BN_CTX_new();

        sscanf(line, "%*s %7s %lu %lu", t, &a, &b);
        in = t[0] == '-' ? NULL : bn_at(strtoul(t, NULL, 10));
        /* OpenSSL writes the result while it still reads its operands. */
        if (in == bn_at(a) || in == bn_at(b)) {
            printf(" skipped: into an operand\n");
            BN_CTX_free(ctx);
            return 1;
        }
        if (BN_num_bits(bn_at(b)) > 512 || BN_num_bits(bn_at(a)) > 4096) {
            printf(" skipped: too large\n");
            BN_CTX_free(ctx);
            return 1;
        }
        got = BN_mod_sqrt(in, bn_at(a), bn_at(b), ctx);
        BN_CTX_free(ctx);
        printf(" %s", got == NULL ? "none" : got == in ? "in" : "new");
        if (got != NULL)
            bn_print_value("r", got);
        if (in != NULL)
            bn_print_value("in", in);
        if (got != NULL && got != in)
            BN_free(got);
    } else if (strcmp(command, "bnmont") == 0 || strcmp(command, "bnrecp") == 0) {
        unsigned long m = 0;
        BN_CTX *ctx = BN_CTX_new();
        BN_MONT_CTX *mont = BN_MONT_CTX_new();
        BN_RECP_CTX *recp = BN_RECP_CTX_new();

        sscanf(line, "%*s %15s %lu %lu %lu %lu", op, &r, &a, &b, &m);
        x = bn_at(r);
        if (BN_num_bits(bn_at(a)) > 8192 || BN_num_bits(bn_at(b)) > 8192 || BN_num_bits(bn_at(m)) > 4096) {
            printf(" skipped: too large\n");
        } else if (command[2] == 'm') {
            ret = BN_MONT_CTX_set(mont, bn_at(m), ctx);
            printf(" set %d", ret);
            /* A context whose set failed holds what OpenSSL's assembly makes of it. */
            if (ret == 0)
                printf(" skipped: no context");
            else if (strcmp(op, "mul") == 0)
                ret = BN_mod_mul_montgomery(x, bn_at(a), bn_at(b), mont, ctx);
            else if (strcmp(op, "to") == 0)
                ret = BN_to_montgomery(x, bn_at(a), mont, ctx);
            else
                ret = BN_from_montgomery(x, bn_at(a), mont, ctx);
            printf(" %d", ret);
            bn_print_value("r", x);
        } else {
            printf(" set %d", BN_RECP_CTX_set(recp, bn_at(m), ctx));
            if (strcmp(op, "div") == 0) {
                BIGNUM *rem = bn_at(r + 1);

                /* OpenSSL writes the quotient while it still reads the dividend. */
                if (rem == x || rem == bn_at(a) || x == bn_at(a)) {
                    printf(" skipped: one register\n");
                    BN_CTX_free(ctx);
                    BN_MONT_CTX_free(mont);
                    BN_RECP_CTX_free(recp);
                    return 1;
                }
                ret = BN_div_recp(x, rem, bn_at(a), recp, ctx);
                printf(" %d", ret);
                bn_print_value("q", x);
                bn_print_value("rem", rem);
            } else if (strcmp(op, "mul") == 0) {
                ret = BN_mod_mul_reciprocal(x, bn_at(a), bn_at(b), recp, ctx);
                printf(" %d", ret);
                bn_print_value("r", x);
            } else {
                ret = BN_reciprocal(x, bn_at(m), BN_num_bits(bn_at(b)), ctx);
                printf(" %d", ret);
                bn_print_value("r", x);
            }
        }
        BN_CTX_free(ctx);
        BN_MONT_CTX_free(mont);
        BN_RECP_CTX_free(recp);
    } else if (strcmp(command, "bnnist") == 0) {
        static int (*const funcs[])(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *) = {
            BN_nist_mod_192, BN_nist_mod_224, BN_nist_mod_256, BN_nist_mod_384, BN_nist_mod_521
        };
        static const int bits[] = {192, 224, 256, 384, 521};
        BN_CTX *ctx = BN_CTX_new();
        int i;

        sscanf(line, "%*s %ld %lu %lu", &n, &r, &a);
        for (i = 0; i < 4 && bits[i] != n; i++)
            continue;
        if (BN_num_bits(bn_at(a)) > 4096) {
            printf(" skipped: too large\n");
            BN_CTX_free(ctx);
            return 1;
        }
        ret = funcs[i](bn_at(r), bn_at(a), NULL, ctx);
        BN_CTX_free(ctx);
        printf(" %d func %d", ret, (int)(BN_nist_mod_func(bn_at(a)) != NULL));
        bn_print_value("r", bn_at(r));
    } else if (strcmp(command, "bnprime") == 0) {
        static BIGNUM *(*const rfc[])(BIGNUM *) = {
            BN_get_rfc2409_prime_768, BN_get_rfc2409_prime_1024, BN_get_rfc3526_prime_1536,
            BN_get_rfc3526_prime_2048, BN_get_rfc3526_prime_3072, BN_get_rfc3526_prime_4096,
            BN_get_rfc3526_prime_6144, BN_get_rfc3526_prime_8192
        };

        sscanf(line, "%*s %ld %lu", &n, &r);
        x = bn_at(r);
        printf(" %d bits %d", rfc[n & 7](x) == x, BN_num_bits(x));
    } else if (strcmp(command, "bnisprime") == 0) {
        BN_CTX *ctx = BN_CTX_new();

        sscanf(line, "%*s %lu %15s %ld", &r, op, &n);
        x = bn_at(r);
        if (BN_num_bits(x) > 1024) {
            printf(" skipped: too large\n");
            BN_CTX_free(ctx);
            return 1;
        }
        if (strcmp(op, "check") == 0)
            ret = BN_check_prime(x, ctx, NULL);
        else if (strcmp(op, "ex") == 0)
            ret = BN_is_prime_ex(x, (int)n, ctx, NULL);
        else
            ret = BN_is_prime_fasttest_ex(x, (int)n, ctx, 1, NULL);
        BN_CTX_free(ctx);
        printf(" %d", ret);
    } else if (strcmp(command, "bngen") == 0) {
        unsigned long safe = 0, addw = 0, remw = 0;
        BIGNUM *add = NULL, *rem = NULL;
        BN_CTX *ctx = BN_CTX_new();

        sscanf(line, "%*s %lu %ld %lu %lu %lu", &r, &n, &safe, &addw, &remw);
        x = bn_at(r);
        if (n > (safe ? 64 : 160)) {
            printf(" skipped: too large\n");
            BN_CTX_free(ctx);
            return 1;
        }
        if (addw != 0) {
            add = BN_new();
            BN_set_word(add, addw);
        }
        if (remw != 0) {
            rem = BN_new();
            BN_set_word(rem, remw);
        }
        ret = BN_generate_prime_ex2(x, (int)n, (int)safe, add, rem, NULL, ctx);
        BN_CTX_free(ctx);
        BN_free(add);
        BN_free(rem);
        printf(" %d", ret);
        if (rand_pub_det && rand_priv_det) {
            bn_print_value("r", x);
        } else {
            /* With add, a prime can run a bit longer than asked. */
            printf(" (random) bits %d", ret == 1 && addw == 0 ? BN_num_bits(x) : -1);
            BN_zero(x);
        }
    } else if (strcmp(command, "bngf2m") == 0) {
        static const int f163[] = {163, 7, 6, 3, 0, -1}, f233[] = {233, 74, 0, -1};
        static const int f4[] = {4, 1, 0, -1}, f10[] = {10, 3, 0, -1};
        static const int f8[] = {8, 6, 4, 3, 2, 1, 0, -1}, f9[] = {9, 1, -1};
        static const int *const arrays[] = {f163, f233, f4, f10, f8, f9};
        unsigned long fi = 0;
        BIGNUM *f = BN_new();
        BN_CTX *ctx = BN_CTX_new();
        const int *p;
        int random = 0;

        sscanf(line, "%*s %15s %lu %lu %lu %lu", op, &r, &a, &b, &fi);
        x = bn_at(r);
        p = arrays[fi % 6];
        if (fi % 6 == 5) {
            BN_set_bit(f, 9);
            BN_set_bit(f, 1);
        } else {
            BN_GF2m_arr2poly(p, f);
        }
        if (BN_num_bits(bn_at(a)) > 4096 || BN_num_bits(bn_at(b)) > 64) {
            printf(" skipped: too large\n");
            BN_free(f);
            BN_CTX_free(ctx);
            return 1;
        }
        if (strcmp(op, "mod") == 0)
            ret = BN_GF2m_mod(x, bn_at(a), f);
        else if (strcmp(op, "add") == 0)
            ret = BN_GF2m_add(x, bn_at(a), bn_at(b));
        else if (strcmp(op, "mul") == 0)
            ret = BN_GF2m_mod_mul(x, bn_at(a), bn_at(b), f, ctx);
        else if (strcmp(op, "sqr") == 0)
            ret = BN_GF2m_mod_sqr(x, bn_at(a), f, ctx);
        else if (strcmp(op, "inv") == 0)
            random = !(ret = BN_GF2m_mod_inv(x, bn_at(a), f, ctx));
        else if (strcmp(op, "div") == 0)
            ret = BN_GF2m_mod_div(x, bn_at(b), bn_at(a), f, ctx);
        else if (strcmp(op, "exp") == 0)
            ret = BN_GF2m_mod_exp(x, bn_at(a), bn_at(b), f, ctx);
        else if (strcmp(op, "sqrt") == 0)
            ret = BN_GF2m_mod_sqrt(x, bn_at(a), f, ctx);
        else if (strcmp(op, "solve") == 0)
            random = (ret = BN_GF2m_mod_solve_quad(x, bn_at(a), f, ctx)) == 1 && fi % 6 != 0
                     && fi % 6 != 1;
        else if (fi % 6 == 5)
            ret = -9; /* the array forms need an array ending with 0 */
        else if (strcmp(op, "modarr") == 0)
            ret = BN_GF2m_mod_arr(x, bn_at(a), p);
        else if (strcmp(op, "mularr") == 0)
            ret = BN_GF2m_mod_mul_arr(x, bn_at(a), bn_at(b), p, ctx);
        else if (strcmp(op, "sqrarr") == 0)
            ret = BN_GF2m_mod_sqr_arr(x, bn_at(a), p, ctx);
        else if (strcmp(op, "invarr") == 0)
            random = !(ret = BN_GF2m_mod_inv_arr(x, bn_at(a), p, ctx));
        else if (strcmp(op, "divarr") == 0)
            ret = BN_GF2m_mod_div_arr(x, bn_at(b), bn_at(a), p, ctx);
        else if (strcmp(op, "exparr") == 0)
            ret = BN_GF2m_mod_exp_arr(x, bn_at(a), bn_at(b), p, ctx);
        else if (strcmp(op, "sqrtarr") == 0)
            ret = BN_GF2m_mod_sqrt_arr(x, bn_at(a), p, ctx);
        else
            random = (ret = BN_GF2m_mod_solve_quad_arr(x, bn_at(a), p, ctx)) == 1 && fi % 6 != 0
                     && fi % 6 != 1;
        BN_free(f);
        BN_CTX_free(ctx);
        printf(" %d", ret);
        /* A failed inverse leaves a blinded product, and an even degree's solution depends on
         * a random start (where it exists, its other root differs by one). */
        if (random && !rand_priv_det) {
            printf(" (random)");
            BN_zero(x);
        } else {
            bn_print_value("r", x);
        }
    } else {
        unsigned char buf[64];
        char kind[4] = "u";
        OSSL_PARAM p[2];
        BIGNUM *got = NULL;

        sscanf(line, "%*s %lu %3s %ld", &r, kind, &n);
        x = bn_at(r);
        if (n < 0 || n > 64) {
            printf(" skipped: size\n");
            return 1;
        }
        memset(buf, 0xee, sizeof(buf));
        p[0] = OSSL_PARAM_construct_BN("n", buf, (size_t)n);
        if (kind[0] == 's')
            p[0].data_type = OSSL_PARAM_INTEGER;
        p[1] = OSSL_PARAM_construct_end();
        ret = OSSL_PARAM_set_BN(p, x);
        printf(" %d return %zu ", ret, p[0].return_size);
        for (long i = 0; i < n; i++)
            printf("%02x", buf[i]);
        if (ret == 1 && OSSL_PARAM_get_BN(p, &got))
            bn_print_value("got", got);
        BN_free(got);
    }
    print_digest_errors();
    return 1;
}


/* Keys (EVP_PKEY) of the MAC and KDF key types, in eight slots. */
static EVP_PKEY *pkeys[8];

static void print_hex_inline(const char *label, const void *data, size_t len)
{
    const unsigned char *d = data;

    printf(" %s=", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", d[i]);
}

static void pk_show(EVP_PKEY *k)
{
    const OSSL_PROVIDER *prov;
    unsigned char buf[128];
    size_t len = sizeof(buf);
    OSSL_PARAM *out = NULL, *p;

    if (k == NULL) {
        printf(" (none)");
        return;
    }
    prov = EVP_PKEY_get0_provider(k);
    printf(" id %d base %d name %s desc %s prov %s", EVP_PKEY_get_id(k), EVP_PKEY_get_base_id(k),
           EVP_PKEY_get0_type_name(k) == NULL ? "(null)" : EVP_PKEY_get0_type_name(k),
           EVP_PKEY_get0_description(k) == NULL ? "(null)" : EVP_PKEY_get0_description(k),
           prov == NULL ? "(null)" : OSSL_PROVIDER_get0_name(prov));
    /* A key typed without data reaches its ASN.1 method's functions, which need the data. */
    if (prov == NULL) {
        ERR_clear_error();
        return;
    }
    if (EVP_PKEY_get_raw_private_key(k, buf, &len) == 1)
        print_hex_inline("raw", buf, len);
    else
        printf(" raw -");
    if (EVP_PKEY_todata(k, OSSL_KEYMGMT_SELECT_ALL, &out) == 1) {
        printf(" data");
        for (p = out; p != NULL && p->key != NULL; p++) {
            if (p->data_type == OSSL_PARAM_UTF8_STRING)
                printf(" %s=%s", p->key, (const char *)p->data);
            else
                print_hex_inline(p->key, p->data, p->data_size);
        }
        OSSL_PARAM_free(out);
    }
    printf(" missing %d", EVP_PKEY_missing_parameters(k));
    ERR_clear_error();
}

static int pk_slot(const char *s)
{
    return (int)(strtoul(s, NULL, 10) % 8);
}

/*
 * Keys typed without data (EVP_PKEY_set_type) reach their ASN.1 methods' functions, which come
 * with the key types, and generating into one typed by name crashes the reference: those are
 * replaced or skipped.
 */
static int pk_typed(int s)
{
    return pkeys[s] != NULL && EVP_PKEY_get0_provider(pkeys[s]) == NULL;
}

static void pk_fresh(int s)
{
    if (pk_typed(s)) {
        EVP_PKEY_free(pkeys[s]);
        pkeys[s] = NULL;
    }
}

static size_t pk_hex(const char *text, unsigned char *out, size_t max)
{
    size_t n = 0;
    unsigned int b;

    if (strcmp(text, "-") == 0)
        return 0;
    while (n < max && text[0] != '\0' && text[1] != '\0' && sscanf(text, "%2x", &b) == 1) {
        out[n++] = (unsigned char)b;
        text += 2;
    }
    return n;
}

static int pk_selection(const char *name)
{
    if (strcmp(name, "public") == 0)
        return EVP_PKEY_PUBLIC_KEY;
    if (strcmp(name, "private") == 0)
        return OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    if (strcmp(name, "params") == 0)
        return EVP_PKEY_KEY_PARAMETERS;
    if (strcmp(name, "all") == 0)
        return OSSL_KEYMGMT_SELECT_ALL;
    return EVP_PKEY_KEYPAIR;
}

static EVP_PKEY_CTX *pk_ctx(const char *name)
{
    char *end;
    long id = strtol(name, &end, 10);

    if (*end == '\0')
        return EVP_PKEY_CTX_new_id((int)id, NULL);
    return EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
}

static int pkey_command(const char *command, const char *line)
{
    char a[64] = "", b[64] = "", c[600] = "";
    unsigned char key[300];
    size_t len;
    int s, t, r = 0;

    if (command[0] != 'p' || command[1] != 'k'
        || (strcmp(command, "pkraw") != 0 && strcmp(command, "pkrawid") != 0
            && strcmp(command, "pkpub") != 0 && strcmp(command, "pkcmac") != 0
            && strcmp(command, "pkmac") != 0 && strcmp(command, "pkgen") != 0
            && strcmp(command, "pkparamgen") != 0 && strcmp(command, "pkfrom") != 0
            && strcmp(command, "pkset") != 0 && strcmp(command, "pksetstr") != 0
            && strcmp(command, "pkeq") != 0 && strcmp(command, "pkcopy") != 0
            && strcmp(command, "pkdup") != 0 && strcmp(command, "pktype") != 0
            && strcmp(command, "pktypestr") != 0 && strcmp(command, "pkshow") != 0
            && strcmp(command, "pkcheck") != 0 && strcmp(command, "pkfree") != 0
            && strcmp(command, "pkdsign") != 0 && strcmp(command, "pkdsignone") != 0
            && strcmp(command, "pksiginit") != 0 && strcmp(command, "pkcansign") != 0))
        return 0;
    printf("%s:", line);
    sscanf(line, "%*s %63s %63s %599s", a, b, c);
    s = pk_slot(a);
    if (strcmp(command, "pkraw") == 0 || strcmp(command, "pkrawid") == 0
        || strcmp(command, "pkpub") == 0 || strcmp(command, "pkcmac") == 0
        || strcmp(command, "pkmac") == 0) {
        len = pk_hex(c, key, sizeof(key));
        EVP_PKEY_free(pkeys[s]);
        if (strcmp(command, "pkraw") == 0)
            pkeys[s] = EVP_PKEY_new_raw_private_key_ex(NULL, b, NULL, key, len);
        else if (strcmp(command, "pkrawid") == 0)
            pkeys[s] = EVP_PKEY_new_raw_private_key(atoi(b), NULL, key, len);
        else if (strcmp(command, "pkpub") == 0)
            pkeys[s] = EVP_PKEY_new_raw_public_key_ex(NULL, b, NULL, key, len);
        else if (strcmp(command, "pkcmac") == 0)
            pkeys[s] = EVP_PKEY_new_CMAC_key(NULL, key, len, EVP_get_cipherbyname(b));
        else
            pkeys[s] = EVP_PKEY_new_mac_key(atoi(b), NULL, key, (int)len);
        pk_show(pkeys[s]);
    } else if (strcmp(command, "pkgen") == 0 || strcmp(command, "pkparamgen") == 0) {
        EVP_PKEY_CTX *ctx = pk_ctx(b);
        int gen = strcmp(command, "pkgen") == 0;

        pk_fresh(s);
        printf(" ctx %d", ctx != NULL);
        if (ctx != NULL) {
            r = gen ? EVP_PKEY_keygen_init(ctx) : EVP_PKEY_paramgen_init(ctx);
            printf(" init %d", r);
            if (strcmp(c, "none") != 0) {
                len = pk_hex(c, key, sizeof(key));
                printf(" key %d", EVP_PKEY_CTX_set_mac_key(ctx, key, (int)len));
            }
            r = gen ? EVP_PKEY_keygen(ctx, &pkeys[s]) : EVP_PKEY_paramgen(ctx, &pkeys[s]);
            printf(" gen %d", r);
            EVP_PKEY_CTX_free(ctx);
        }
        pk_show(pkeys[s]);
    } else if (strcmp(command, "pkfrom") == 0) {
        /* pkfrom SLOT NAME SELECTION [key=value ...] */
        EVP_PKEY_CTX *ctx = pk_ctx(b);
        OSSL_PARAM params[5];
        static unsigned char data[4][300];
        static char strs[4][300];
        int n = 0, sel;
        const char *rest = line;
        char k[32], v[300];

        sscanf(line, "%*s %*s %*s %63s", c);
        sel = pk_selection(c);
        pk_fresh(s);
        for (t = 0; t < 4 && *rest != '\0'; t++) {
            rest = strchr(rest, ' ');
            if (rest == NULL)
                break;
            rest++;
        }
        while (rest != NULL && *rest != '\0' && n < 4
               && sscanf(rest, "%31[^=]=%299s", k, v) == 2) {
            if (strcmp(k, "priv") == 0 || strcmp(k, "pub") == 0) {
                len = pk_hex(v, data[n], sizeof(data[n]));
                params[n] = OSSL_PARAM_construct_octet_string(k[1] == 'r' ? "priv" : "pub",
                                                              data[n], len);
            } else {
                snprintf(strs[n], sizeof(strs[n]), "%s", v);
                params[n] = OSSL_PARAM_construct_utf8_string(
                    strcmp(k, "privstr") == 0 ? "priv" : strcmp(k, "cipher") == 0 ? "cipher"
                                                                                   : "properties",
                    strs[n], 0);
            }
            n++;
            rest = strchr(rest, ' ');
            if (rest != NULL)
                rest++;
        }
        params[n] = OSSL_PARAM_construct_end();
        printf(" ctx %d", ctx != NULL);
        if (ctx != NULL) {
            printf(" init %d", EVP_PKEY_fromdata_init(ctx));
            printf(" from %d", EVP_PKEY_fromdata(ctx, &pkeys[s], sel, params));
            EVP_PKEY_CTX_free(ctx);
        }
        pk_show(pkeys[s]);
    } else if (strcmp(command, "pkset") == 0) {
        len = pk_hex(c, key, sizeof(key));
        if (pkeys[s] != NULL)
            printf(" %d", EVP_PKEY_set_octet_string_param(pkeys[s], b, key, len));
        pk_show(pkeys[s]);
    } else if (strcmp(command, "pksetstr") == 0) {
        if (pkeys[s] != NULL)
            printf(" %d", EVP_PKEY_set_utf8_string_param(pkeys[s], b, c));
        pk_show(pkeys[s]);
    } else if (strcmp(command, "pkeq") == 0) {
        t = pk_slot(b);
        if (pk_typed(s) && pk_typed(t))
            printf(" skipped: typed");
        else if (pkeys[s] != NULL && pkeys[t] != NULL)
            printf(" eq %d params %d", EVP_PKEY_eq(pkeys[s], pkeys[t]),
                   EVP_PKEY_parameters_eq(pkeys[s], pkeys[t]));
    } else if (strcmp(command, "pkcopy") == 0) {
        t = pk_slot(b);
        if (pkeys[s] == NULL)
            pkeys[s] = EVP_PKEY_new();
        if (pkeys[t] == NULL || EVP_PKEY_get0_provider(pkeys[t]) == NULL)
            printf(" skipped: typed");
        else
            printf(" %d", EVP_PKEY_copy_parameters(pkeys[s], pkeys[t]));
        pk_show(pkeys[s]);
    } else if (strcmp(command, "pkdup") == 0) {
        t = pk_slot(b);
        if (pk_typed(t))
            printf(" skipped: typed");
        else if (pkeys[t] != NULL && s != t) {
            EVP_PKEY_free(pkeys[s]);
            pkeys[s] = EVP_PKEY_dup(pkeys[t]);
        }
        pk_show(pkeys[s]);
    } else if (strcmp(command, "pktype") == 0) {
        if (pkeys[s] == NULL)
            pkeys[s] = EVP_PKEY_new();
        printf(" %d", EVP_PKEY_set_type(pkeys[s], atoi(b)));
        pk_show(pkeys[s]);
    } else if (strcmp(command, "pktypestr") == 0) {
        if (pkeys[s] == NULL)
            pkeys[s] = EVP_PKEY_new();
        t = atoi(c);
        if (t > (int)strlen(b))
            t = -1;
        printf(" %d", EVP_PKEY_set_type_str(pkeys[s], b, t));
        pk_show(pkeys[s]);
    } else if (strcmp(command, "pkshow") == 0) {
        pk_show(pkeys[s]);
        if (pkeys[s] != NULL && EVP_PKEY_get0_provider(pkeys[s]) != NULL)
            printf(" bits %d size %d", EVP_PKEY_get_bits(pkeys[s]), EVP_PKEY_get_size(pkeys[s]));
    } else if (strcmp(command, "pkcheck") == 0) {
        if (pkeys[s] != NULL && EVP_PKEY_get0_provider(pkeys[s]) != NULL) {
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkeys[s], NULL);

            printf(" ctx %d", ctx != NULL);
            if (ctx != NULL)
                printf(" checks %d %d %d %d", EVP_PKEY_check(ctx), EVP_PKEY_public_check(ctx),
                       EVP_PKEY_param_check(ctx), EVP_PKEY_private_check(ctx));
            EVP_PKEY_CTX_free(ctx);
        }
    } else if (strcmp(command, "pkdsign") == 0 || strcmp(command, "pkdsignone") == 0) {
        /* pkdsign SLOT MDNAME|- FINALISE CHUNK... : sign through a digest context. */
        EVP_MD_CTX *md;
        const char *rest = line;
        char chunk[600];
        unsigned char out[128];
        size_t outlen;
        int fin = 0;

        if (pk_typed(s) || pkeys[s] == NULL) {
            printf(" skipped: no key");
            print_digest_errors();
            return 1;
        }
        sscanf(line, "%*s %*s %*s %d", &fin);
        md = EVP_MD_CTX_new();
        if (fin)
            EVP_MD_CTX_set_flags(md, EVP_MD_CTX_FLAG_FINALISE);
        printf(" init %d", EVP_DigestSignInit_ex(md, NULL, strcmp(b, "-") == 0 ? NULL : b,
                                                 NULL, NULL, pkeys[s], NULL));
        for (t = 0; t < 4 && rest != NULL; t++) {
            rest = strchr(rest, ' ');
            if (rest != NULL)
                rest++;
        }
        if (strcmp(command, "pkdsignone") == 0) {
            len = rest != NULL && sscanf(rest, "%599s", chunk) == 1 ? pk_hex(chunk, key, sizeof(key)) : 0;
            outlen = 0;
            r = EVP_DigestSign(md, NULL, &outlen, key, len);
            printf(" size %d %zu", r, outlen);
            outlen = sizeof(out);
            r = EVP_DigestSign(md, out, &outlen, key, len);
            printf(" sign %d", r);
            if (r == 1)
                print_hex_inline("sig", out, outlen);
            outlen = sizeof(out);
            printf(" again %d", EVP_DigestSign(md, out, &outlen, key, len));
        } else {
            while (rest != NULL && sscanf(rest, "%599s", chunk) == 1) {
                len = pk_hex(chunk, key, sizeof(key));
                printf(" up %d", EVP_DigestSignUpdate(md, key, len));
                rest = strchr(rest, ' ');
                if (rest != NULL)
                    rest++;
            }
            for (t = 0; t < 2; t++) {
                outlen = 0;
                r = EVP_DigestSignFinal(md, NULL, &outlen);
                printf(" size %d %zu", r, outlen);
                outlen = sizeof(out);
                r = EVP_DigestSignFinal(md, out, &outlen);
                printf(" final %d", r);
                if (r == 1)
                    print_hex_inline("sig", out, outlen);
            }
        }
        EVP_MD_CTX_free(md);
    } else if (strcmp(command, "pksiginit") == 0) {
        /* pksiginit SLOT OP [ALG]: the EVP_PKEY_sign family's inits and operations. */
        EVP_PKEY_CTX *ctx;
        EVP_SIGNATURE *alg = NULL;
        unsigned char out[64];
        size_t outlen = sizeof(out);

        if (pk_typed(s) || pkeys[s] == NULL) {
            printf(" skipped: no key");
            print_digest_errors();
            return 1;
        }
        ctx = EVP_PKEY_CTX_new(pkeys[s], NULL);
        if (c[0] != '\0' && strcmp(c, "-") != 0)
            alg = EVP_SIGNATURE_fetch(NULL, c, NULL);
        if (strcmp(b, "sign") == 0)
            r = EVP_PKEY_sign_init_ex2(ctx, alg, NULL);
        else if (strcmp(b, "verify") == 0)
            r = EVP_PKEY_verify_init_ex2(ctx, alg, NULL);
        else if (strcmp(b, "recover") == 0)
            r = EVP_PKEY_verify_recover_init_ex2(ctx, alg, NULL);
        else if (strcmp(b, "signmsg") == 0)
            r = EVP_PKEY_sign_message_init(ctx, alg, NULL);
        else
            r = EVP_PKEY_verify_message_init(ctx, alg, NULL);
        printf(" init %d op %d", r, EVP_PKEY_CTX_get_operation(ctx));
        if (strcmp(b, "sign") == 0)
            printf(" sign %d", EVP_PKEY_sign(ctx, out, &outlen, key, 4));
        else if (strcmp(b, "verify") == 0)
            printf(" verify %d", EVP_PKEY_verify(ctx, out, 4, key, 4));
        else if (strcmp(b, "recover") == 0)
            printf(" recover %d", EVP_PKEY_verify_recover(ctx, out, &outlen, key, 4));
        EVP_SIGNATURE_free(alg);
        EVP_PKEY_CTX_free(ctx);
    } else if (strcmp(command, "pkcansign") == 0) {
        if (pkeys[s] != NULL && (!pk_typed(s) || EVP_PKEY_get_base_id(pkeys[s]) != EVP_PKEY_EC))
            printf(" %d", EVP_PKEY_can_sign(pkeys[s]));
    } else {
        EVP_PKEY_free(pkeys[s]);
        pkeys[s] = NULL;
    }
    print_digest_errors();
    return 1;
}

/*
 * Key derivation and the ctrls (step 4.2c).
 *
 *   pkderive TYPE LEN [NAME=VALUE ...]   a derivation of LEN octets (0: the size) with a context
 *                                         for the key type TYPE (a name or number), after the
 *                                         ctrl strings
 *   pkctrl TYPE OP OPTYPE CMD ARG         one ctrl (CMD from the table below) on a context for
 *                                         TYPE initialized for OP (derive, keygen, paramgen,
 *                                         none), with OPTYPE as given
 *   pkcrypt SLOT OP                       an operation's init (encrypt, decrypt, encap, decap,
 *                                         derive) and its call on the slot's key
 *
 * The ctrls are named, not numbered: some read their pointer argument as a digest, a cipher,
 * or a BIGNUM, and some write through it, which the probe can only give where it's safe.
 */
enum pk_arg { PK_INT, PK_OCTETS, PK_MD, PK_CIPHER };

static const struct {
    const char *name;
    int cmd;
    enum pk_arg arg;
} pk_ctrls[] = {
    { "tls_md", EVP_PKEY_CTRL_TLS_MD, PK_MD },
    { "tls_secret", EVP_PKEY_CTRL_TLS_SECRET, PK_OCTETS },
    { "tls_seed", EVP_PKEY_CTRL_TLS_SEED, PK_OCTETS },
    { "hkdf_md", EVP_PKEY_CTRL_HKDF_MD, PK_MD },
    { "hkdf_salt", EVP_PKEY_CTRL_HKDF_SALT, PK_OCTETS },
    { "hkdf_key", EVP_PKEY_CTRL_HKDF_KEY, PK_OCTETS },
    { "hkdf_info", EVP_PKEY_CTRL_HKDF_INFO, PK_OCTETS },
    { "hkdf_mode", EVP_PKEY_CTRL_HKDF_MODE, PK_INT },
    { "pass", EVP_PKEY_CTRL_PASS, PK_OCTETS },
    { "scrypt_salt", EVP_PKEY_CTRL_SCRYPT_SALT, PK_OCTETS },
    { "scrypt_n", EVP_PKEY_CTRL_SCRYPT_N, PK_INT },
    { "scrypt_r", EVP_PKEY_CTRL_SCRYPT_R, PK_INT },
    { "scrypt_p", EVP_PKEY_CTRL_SCRYPT_P, PK_INT },
    { "scrypt_maxmem", EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES, PK_INT },
    { "mac_key", EVP_PKEY_CTRL_SET_MAC_KEY, PK_OCTETS },
    { "digest_size", EVP_PKEY_CTRL_SET_DIGEST_SIZE, PK_INT },
    { "set1_id", EVP_PKEY_CTRL_SET1_ID, PK_OCTETS },
    { "cipher", EVP_PKEY_CTRL_CIPHER, PK_CIPHER },
    { "md", EVP_PKEY_CTRL_MD, PK_MD },
    { "dh_pad", EVP_PKEY_CTRL_DH_PAD, PK_INT },
    { "unknown", 9999, PK_INT },
};

static void pk_derive_out(EVP_PKEY_CTX *ctx, size_t want)
{
    unsigned char out[256];
    size_t len = want < sizeof(out) ? want : sizeof(out);
    int r;

    if (want == 0) {
        r = EVP_PKEY_derive(ctx, NULL, &len);
        printf(" size %d %zu", r, len);
        return;
    }
    r = EVP_PKEY_derive(ctx, out, &len);
    printf(" derive %d", r);
    if (r > 0) {
        printf(" ");
        for (size_t i = 0; i < len; i++)
            printf("%02x", out[i]);
    }
}

static int derive_command(const char *command, const char *line)
{
    char type[64] = "", b[64] = "", c[64] = "", d[64] = "", e[600] = "";
    EVP_PKEY_CTX *ctx;
    int r, s;

    if (strcmp(command, "pkderive") != 0 && strcmp(command, "pkctrl") != 0
        && strcmp(command, "pkcrypt") != 0)
        return 0;
    printf("%s:", line);
    sscanf(line, "%*s %63s %63s %63s %63s %599s", type, b, c, d, e);
    if (strcmp(command, "pkderive") == 0) {
        const char *p = line;
        int field = 0;

        ctx = pk_ctx(type);
        r = EVP_PKEY_derive_init(ctx);
        printf(" init %d", r);
        /*
         * The NAME=VALUE fields after TYPE and LEN (none without a context: the reference
         * keeps a distinguishing ID in it before looking).
         */
        while (ctx != NULL && *p != '\0') {
            char tok[600], *eq;
            int n = 0;

            while (*p == ' ')
                p++;
            if (*p == '\0' || sscanf(p, "%599s%n", tok, &n) != 1)
                break;
            p += n;
            if (field++ < 3)
                continue;
            eq = strchr(tok, '=');
            if (eq == NULL)
                continue;
            *eq = '\0';
            printf(" %s=%d", tok, EVP_PKEY_CTX_ctrl_str(ctx, tok, eq + 1));
        }
        if (ctx != NULL)
            pk_derive_out(ctx, strtoul(b, NULL, 10));
        EVP_PKEY_CTX_free(ctx);
    } else if (strcmp(command, "pkctrl") == 0) {
        unsigned char oct[300];
        size_t i, n = 0;
        void *p2 = NULL;
        int p1 = 0, optype = (int)strtol(c, NULL, 10);

        for (i = 0; i < sizeof(pk_ctrls) / sizeof(pk_ctrls[0]); i++)
            if (strcmp(pk_ctrls[i].name, d) == 0)
                break;
        if (i == sizeof(pk_ctrls) / sizeof(pk_ctrls[0])) {
            printf(" unknown\n");
            return 1;
        }
        switch (pk_ctrls[i].arg) {
        case PK_INT:
            p1 = (int)strtol(e, NULL, 10);
            break;
        case PK_OCTETS:
            n = pk_hex(e, oct, sizeof(oct));
            p1 = (int)n;
            p2 = oct;
            break;
        case PK_MD:
            p2 = (void *)EVP_get_digestbyname(e);
            break;
        case PK_CIPHER:
            p2 = (void *)EVP_get_cipherbyname(e);
            break;
        }
        if ((pk_ctrls[i].arg == PK_MD || pk_ctrls[i].arg == PK_CIPHER) && p2 == NULL) {
            printf(" no such algorithm\n");
            return 1;
        }
        ctx = pk_ctx(type);
        if (strcmp(b, "derive") == 0)
            r = EVP_PKEY_derive_init(ctx);
        else if (strcmp(b, "keygen") == 0)
            r = EVP_PKEY_keygen_init(ctx);
        else if (strcmp(b, "paramgen") == 0)
            r = EVP_PKEY_paramgen_init(ctx);
        else
            r = 0;
        printf(" init %d ctrl %d", r,
               EVP_PKEY_CTX_ctrl(ctx, -1, optype, pk_ctrls[i].cmd, p1, p2));
        if (ctx != NULL && strcmp(b, "derive") == 0)
            pk_derive_out(ctx, 16);
        EVP_PKEY_CTX_free(ctx);
    } else {
        unsigned char out[64], sec[64];
        size_t outlen = sizeof(out), seclen = sizeof(sec);

        s = pk_slot(type);
        if (pk_typed(s) || pkeys[s] == NULL) {
            printf(" skipped: no key");
            print_digest_errors();
            return 1;
        }
        ctx = EVP_PKEY_CTX_new(pkeys[s], NULL);
        if (strcmp(b, "encrypt") == 0) {
            r = EVP_PKEY_encrypt_init(ctx);
            printf(" init %d op %d encrypt %d", r, EVP_PKEY_CTX_get_operation(ctx),
                   EVP_PKEY_encrypt(ctx, out, &outlen, (const unsigned char *)"data", 4));
        } else if (strcmp(b, "decrypt") == 0) {
            r = EVP_PKEY_decrypt_init(ctx);
            printf(" init %d op %d decrypt %d", r, EVP_PKEY_CTX_get_operation(ctx),
                   EVP_PKEY_decrypt(ctx, out, &outlen, (const unsigned char *)"data", 4));
        } else if (strcmp(b, "encap") == 0) {
            r = EVP_PKEY_encapsulate_init(ctx, NULL);
            printf(" init %d op %d encap %d", r, EVP_PKEY_CTX_get_operation(ctx),
                   EVP_PKEY_encapsulate(ctx, out, &outlen, sec, &seclen));
        } else if (strcmp(b, "decap") == 0) {
            r = EVP_PKEY_decapsulate_init(ctx, NULL);
            printf(" init %d op %d decap %d", r, EVP_PKEY_CTX_get_operation(ctx),
                   EVP_PKEY_decapsulate(ctx, sec, &seclen, (const unsigned char *)"data", 4));
        } else {
            r = EVP_PKEY_derive_init(ctx);
            printf(" init %d op %d derive %d peer %d", r, EVP_PKEY_CTX_get_operation(ctx),
                   EVP_PKEY_derive(ctx, out, &outlen), EVP_PKEY_derive_set_peer(ctx, pkeys[s]));
        }
        EVP_PKEY_CTX_free(ctx);
    }
    print_digest_errors();
    return 1;
}

/*
 * Applications' methods (step 4.2d).
 *
 *   methfind ID                    EVP_PKEY_asn1_find, EVP_PKEY_type, and EVP_PKEY_meth_find of ID
 *   methstr STR LEN                EVP_PKEY_asn1_find_str of LEN characters of STR (- empty)
 *   methparam TYPE OP DIR KEY PTYPE VALUE RET
 *                                  with a logging EVP_PKEY_METHOD added for TYPE (a name below)
 *                                  for the command, a context initialized for OP (sign, verify,
 *                                  verifyrecover, encrypt, decrypt, derive, keygen, paramgen,
 *                                  none, custom: none with a digest_custom), then
 *                                  EVP_PKEY_CTX_set_params (DIR set) or _get_params (get) of
 *                                  one parameter KEY of PTYPE (int, uint, utf8, octets, octptr)
 *                                  with VALUE; the method's ctrl answers RET
 *   methctrl TYPE OP KEYTYPE OPTYPE CMD P1 RET
 *                                  EVP_PKEY_CTX_ctrl (no pointer) on such a context
 *   methctrlstr TYPE OP NAME VALUE RET
 *                                  EVP_PKEY_CTX_ctrl_str on such a context; the method's
 *                                  ctrl_str sends VALUE to its ctrl with EVP_PKEY_CTX_str2ctrl
 *                                  (hex2ctrl for a NAME starting with "hex")
 *
 * The method's ctrl prints its command, p1, and whether p2 is NULL, never reading p2.
 */
static int meth_ret;

static int meth_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    (void)ctx;
    printf(" [ctrl %d %d %d]", type, p1, p2 != NULL);
    return meth_ret;
}

static int meth_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
    printf(" [ctrl_str %s]", type);
    if (strncmp(type, "hex", 3) == 0)
        return EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_ALG_CTRL + 1, value);
    return EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_ALG_CTRL + 1, value);
}

static int meth_transform(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                          const unsigned char *in, size_t inlen)
{
    (void)ctx, (void)out, (void)outlen, (void)in, (void)inlen;
    return 0;
}

static int meth_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
                       const unsigned char *tbs, size_t tbslen)
{
    (void)ctx, (void)sig, (void)siglen, (void)tbs, (void)tbslen;
    return 0;
}

static int meth_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
    (void)ctx, (void)key, (void)keylen;
    return 0;
}

static int meth_gen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    (void)ctx, (void)pkey;
    return 0;
}

static int meth_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    (void)ctx;
    (void)mctx;
    return 1;
}

static int meth_type(const char *name)
{
    static const struct {
        const char *name;
        int id;
    } types[] = {
        { "RSA", EVP_PKEY_RSA }, { "RSA-PSS", EVP_PKEY_RSA_PSS }, { "EC", EVP_PKEY_EC },
        { "SM2", EVP_PKEY_SM2 }, { "DH", EVP_PKEY_DH }, { "DHX", EVP_PKEY_DHX },
        { "DSA", EVP_PKEY_DSA }, { "X25519", EVP_PKEY_X25519 }, { "X448", EVP_PKEY_X448 },
        { "ED25519", EVP_PKEY_ED25519 }, { "HMAC", EVP_PKEY_HMAC },
    };
    static int toy = NID_undef;
    size_t i;

    for (i = 0; i < sizeof(types) / sizeof(types[0]); i++)
        if (strcmp(name, types[i].name) == 0)
            return types[i].id;
    if (toy == NID_undef)
        toy = OBJ_create("1.3.6.1.4.1.99999.9", "PROBETOY", "probe toy");
    return toy;
}

/* A context for TYPE with the logging method, initialized for OP; NULL if it can't be made. */
static EVP_PKEY_CTX *meth_ctx(EVP_PKEY_METHOD **pm, const char *type, const char *op)
{
    EVP_PKEY_CTX *ctx;
    int r = 1;

    *pm = EVP_PKEY_meth_new(meth_type(type), 0);
    EVP_PKEY_meth_set_ctrl(*pm, meth_ctrl, meth_ctrl_str);
    /* The operations are there only to be started. */
    EVP_PKEY_meth_set_sign(*pm, NULL, meth_transform);
    EVP_PKEY_meth_set_verify(*pm, NULL, meth_verify);
    EVP_PKEY_meth_set_verify_recover(*pm, NULL, meth_transform);
    EVP_PKEY_meth_set_encrypt(*pm, NULL, meth_transform);
    EVP_PKEY_meth_set_decrypt(*pm, NULL, meth_transform);
    EVP_PKEY_meth_set_derive(*pm, NULL, meth_derive);
    EVP_PKEY_meth_set_keygen(*pm, NULL, meth_gen);
    EVP_PKEY_meth_set_paramgen(*pm, NULL, meth_gen);
    if (strcmp(op, "custom") == 0)
        EVP_PKEY_meth_set_digest_custom(*pm, meth_custom);
    EVP_PKEY_meth_add0(*pm);
    ctx = EVP_PKEY_CTX_new_id(meth_type(type), NULL);
    if (ctx == NULL)
        return NULL;
    if (strcmp(op, "sign") == 0)
        r = EVP_PKEY_sign_init(ctx);
    else if (strcmp(op, "verify") == 0)
        r = EVP_PKEY_verify_init(ctx);
    else if (strcmp(op, "verifyrecover") == 0)
        r = EVP_PKEY_verify_recover_init(ctx);
    else if (strcmp(op, "encrypt") == 0)
        r = EVP_PKEY_encrypt_init(ctx);
    else if (strcmp(op, "decrypt") == 0)
        r = EVP_PKEY_decrypt_init(ctx);
    else if (strcmp(op, "derive") == 0)
        r = EVP_PKEY_derive_init(ctx);
    else if (strcmp(op, "keygen") == 0)
        r = EVP_PKEY_keygen_init(ctx);
    else if (strcmp(op, "paramgen") == 0)
        r = EVP_PKEY_paramgen_init(ctx);
    printf(" init %d op %d", r, EVP_PKEY_CTX_get_operation(ctx));
    return ctx;
}

static void meth_done(EVP_PKEY_METHOD *pm, EVP_PKEY_CTX *ctx)
{
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_meth_remove(pm);
    EVP_PKEY_meth_free(pm);
}

static void meth_info(const EVP_PKEY_ASN1_METHOD *a)
{
    int id = 0, base = 0, flags = 0;
    const char *info = NULL, *pem = NULL;

    if (EVP_PKEY_asn1_get0_info(&id, &base, &flags, &info, &pem, a) == 0) {
        printf(" none");
        return;
    }
    printf(" %d %d %#x %s %s", id, base, flags, or_dash(pem), or_dash(info));
}

static int meth_command(const char *command, const char *line)
{
    char a[64] = "", b[64] = "", c[64] = "", d[64] = "", e[64] = "", f[300] = "", g[32] = "";
    EVP_PKEY_METHOD *pm = NULL;
    EVP_PKEY_CTX *ctx;
    int r;

    if (strncmp(command, "meth", 4) != 0)
        return 0;
    printf("%s:", line);
    if (strcmp(command, "methfind") == 0) {
        const EVP_PKEY_METHOD *m;
        int id = 0, flags = 0;

        sscanf(line, "%*s %63s", a);
        meth_info(EVP_PKEY_asn1_find(NULL, atoi(a)));
        m = EVP_PKEY_meth_find(atoi(a));
        if (m != NULL)
            EVP_PKEY_meth_get0_info(&id, &flags, m);
        printf(" type %d meth %d %d %#x", EVP_PKEY_type(atoi(a)), m != NULL, id, flags);
    } else if (strcmp(command, "methstr") == 0) {
        sscanf(line, "%*s %63s %63s", a, b);
        meth_info(EVP_PKEY_asn1_find_str(NULL, strcmp(a, "-") == 0 ? "" : a, atoi(b)));
    } else if (strcmp(command, "methparam") == 0) {
        OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
        int iv = 0;
        unsigned int uv = 0;
        char sv[64] = "";
        unsigned char ov[64];
        size_t olen = 0;
        void *pv = NULL;

        sscanf(line, "%*s %63s %63s %63s %63s %63s %299s %31s", a, b, c, d, e, f, g);
        meth_ret = atoi(g);
        ctx = meth_ctx(&pm, a, b);
        if (strcmp(e, "int") == 0) {
            iv = atoi(f);
            params[0] = OSSL_PARAM_construct_int(d, &iv);
        } else if (strcmp(e, "uint") == 0) {
            uv = (unsigned int)strtoul(f, NULL, 0);
            params[0] = OSSL_PARAM_construct_uint(d, &uv);
        } else if (strcmp(e, "utf8") == 0) {
            if (strcmp(c, "set") == 0)
                snprintf(sv, sizeof(sv), "%.63s", f);
            params[0] = OSSL_PARAM_construct_utf8_string(d, sv, strcmp(c, "set") == 0 ? 0 : sizeof(sv));
        } else if (strcmp(e, "octets") == 0) {
            olen = pk_hex(f, ov, sizeof(ov));
            params[0] = OSSL_PARAM_construct_octet_string(d, ov, strcmp(c, "set") == 0 ? olen : sizeof(ov));
        } else {
            params[0] = OSSL_PARAM_construct_octet_ptr(d, &pv, 0);
        }
        if (ctx != NULL) {
            r = strcmp(c, "set") == 0 ? EVP_PKEY_CTX_set_params(ctx, params)
                                       : EVP_PKEY_CTX_get_params(ctx, params);
            printf(" -> %d size %zu", r, params[0].return_size);
            if (strcmp(c, "get") == 0) {
                if (strcmp(e, "int") == 0)
                    printf(" %d", iv);
                else if (strcmp(e, "uint") == 0)
                    printf(" %u", uv);
                else if (strcmp(e, "utf8") == 0)
                    printf(" '%s'", sv);
                else if (strcmp(e, "octptr") == 0)
                    printf(" ptr %d", pv != NULL);
            }
        }
        meth_done(pm, ctx);
    } else if (strcmp(command, "methctrl") == 0) {
        char h[32] = "";

        sscanf(line, "%*s %63s %63s %63s %63s %63s %299s %31s", a, b, c, d, e, f, h);
        meth_ret = atoi(h);
        ctx = meth_ctx(&pm, a, b);
        if (ctx != NULL) {
            r = EVP_PKEY_CTX_ctrl(ctx, atoi(c), atoi(d), atoi(e), atoi(f), NULL);
            printf(" -> %d", r);
        }
        meth_done(pm, ctx);
    } else if (strcmp(command, "methctrlstr") == 0) {
        sscanf(line, "%*s %63s %63s %63s %299s %31s", a, b, c, f, g);
        meth_ret = atoi(g);
        ctx = meth_ctx(&pm, a, b);
        if (ctx != NULL) {
            r = EVP_PKEY_CTX_ctrl_str(ctx, c, f);
            printf(" -> %d", r);
        }
        meth_done(pm, ctx);
    } else {
        printf(" unknown");
    }
    print_digest_errors();
    return 1;
}

/*
 * Printing keys and reading PEM blocks by name (step 4.2e).
 *
 *   pkprint SLOT PART INDENT      EVP_PKEY_print_PART (public, private, params) of the slot's key
 *                                  (a provided or blank one: a built-in key type's legacy print
 *                                  functions read data such keys don't have) to a memory BIO,
 *                                  or through a prefix BIO already indenting by 3 (PART ending
 *                                  in "+"); the output with "|" for each newline
 *   pembytes WANTED NAMES          PEM_bytes_read_bio for WANTED over blocks named NAMES
 *                                  (comma-separated, "_" for a space; the i-th block holds the
 *                                  INTEGER i), until it fails: each block's name and integer
 */
static int print_command(const char *command, const char *line)
{
    char a[64] = "", b[64] = "", c[600] = "";

    if (strcmp(command, "pkprint") != 0 && strcmp(command, "pembytes") != 0)
        return 0;
    printf("%s:", line);
    sscanf(line, "%*s %63s %63s %599s", a, b, c);
    if (strcmp(command, "pkprint") == 0) {
        EVP_PKEY *k = pkeys[pk_slot(a)];
        BIO *mem = BIO_new(BIO_s_mem()), *out = mem;
        int r = -9, plus = b[0] != '\0' && b[strlen(b) - 1] == '+';
        char *p = NULL;
        long n, i;

        if (plus) {
            out = BIO_push(BIO_new(BIO_f_prefix()), mem);
            BIO_set_indent(out, 3);
        }
        if (k != NULL && (EVP_PKEY_get0_provider(k) != NULL || EVP_PKEY_get_id(k) == EVP_PKEY_NONE)) {
            if (strncmp(b, "public", 6) == 0)
                r = EVP_PKEY_print_public(out, k, atoi(c), NULL);
            else if (strncmp(b, "private", 7) == 0)
                r = EVP_PKEY_print_private(out, k, atoi(c), NULL);
            else
                r = EVP_PKEY_print_params(out, k, atoi(c), NULL);
        }
        if (plus)
            printf(" indent %ld", (long)BIO_get_indent(out));
        n = BIO_get_mem_data(mem, &p);
        printf(" -> %d '", r);
        for (i = 0; i < n; i++)
            putchar(p[i] == '\n' ? '|' : p[i]);
        printf("'");
        if (plus)
            BIO_pop(out), BIO_free(out);
        BIO_free(mem);
    } else {
        char text[8000] = "", name[80], *wanted = a, *q;
        unsigned char der[3] = { 0x02, 0x01, 0 };
        unsigned char b64[8];
        int i = 0, r;
        BIO *bio;

        sscanf(line, "%*s %63s %599s", a, c);
        for (q = wanted; *q != '\0'; q++)
            if (*q == '_')
                *q = ' ';
        for (q = strtok(c, ","); q != NULL && strlen(text) < sizeof(text) - 200; q = strtok(NULL, ",")) {
            char *u;

            snprintf(name, sizeof(name), "%.60s", q);
            for (u = name; *u != '\0'; u++)
                if (*u == '_')
                    *u = ' ';
            der[2] = (unsigned char)++i;
            EVP_EncodeBlock(b64, der, 3);
            snprintf(text + strlen(text), sizeof(text) - strlen(text),
                     "-----BEGIN %s-----\n%s\n-----END %s-----\n", name, (char *)b64, name);
        }
        bio = BIO_new_mem_buf(text, -1);
        for (;;) {
            unsigned char *d = NULL;
            char *nm = NULL;
            long len = 0;

            r = PEM_bytes_read_bio(&d, &len, &nm, wanted, bio, NULL, NULL);
            if (r != 1)
                break;
            printf(" [%s %ld %d]", nm, len, len > 0 ? d[len - 1] : -1);
            OPENSSL_free(d);
            OPENSSL_free(nm);
        }
        printf(" end %d", r);
        BIO_free(bio);
    }
    print_digest_errors();
    return 1;
}

/*
 * Commands for the deprecated low-level hashes, one context each (static, so zeroed until
 * initialized), over the digest commands' data. ALG is sha1, sha224, sha256, sha384, sha512,
 * md4, md5, rmd160, mdc2, or wp; each command prints its result and then the whole context:
 *   llinit ALG                     ALG_Init
 *   llupdate ALG N                 ALG_Update with the next N octets (at most 1024)
 *   llbits N                       WHIRLPOOL_BitUpdate with N bits (at most 8192)
 *                                  (Whirlpool's updates are skipped where the reference's last
 *                                  step would run past its block, as an update of whole octets
 *                                  does after bits that end inside an octet: it then writes past
 *                                  the buffer, docs/DEVIATIONS.md)
 *   llfinal ALG                    ALG_Final, and the digest
 *   lltransform ALG OFF            ALG_Transform of the data at offset OFF (not sha224, sha384,
 *                                  mdc2, or wp, which have none)
 *   llset ALG FIELD V              sets md_len (sha224 to sha512) or pad_type (mdc2) to V, or
 *                                  Nl to V below 2^32 (or 2^64), to carry
 *   llone ALG N                    the one-shot ALG() of the next N octets, and the digest
 */
static union {
    SHA_CTX sha1;
    SHA256_CTX sha256;
    SHA512_CTX sha512;
    MD4_CTX md4;
    MD5_CTX md5;
    RIPEMD160_CTX rmd160;
    MDC2_CTX mdc2;
    WHIRLPOOL_CTX wp;
} ll_ctx[10];

static const char *const ll_names[] = { "sha1", "sha224", "sha256", "sha384", "sha512", "md4",
                                        "md5", "rmd160", "mdc2", "wp" };
static const size_t ll_sizes[] = { sizeof(SHA_CTX), sizeof(SHA256_CTX), sizeof(SHA256_CTX),
                                   sizeof(SHA512_CTX), sizeof(SHA512_CTX), sizeof(MD4_CTX),
                                   sizeof(MD5_CTX), sizeof(RIPEMD160_CTX), sizeof(MDC2_CTX),
                                   sizeof(WHIRLPOOL_CTX) };
static const int ll_md_sizes[] = { 20, 28, 32, 48, 64, 16, 16, 20, 16, 64 };

/* Whether the reference's WHIRLPOOL_BitUpdate of `bits` bits would run its last step past the
 * block: bit by bit (the buffered bits and the input not both whole octets, and not aligning
 * at the first step), the last few bits starting less than 8 bits before the block's end and
 * crossing it. */
static int ll_wp_overruns(unsigned int bitoff, size_t bits)
{
    size_t bitrem = bitoff % 8, inpgap = (8 - bits % 8) & 7, steps, last, before;

    if (bits == 0 || bitrem == 0 || bitrem == inpgap)
        return 0;
    steps = (bits - 1) / 8;
    last = bits - 8 * steps;
    before = (bitoff + 8 * steps) % 512;
    return before + last > 512;
}

static int lowlevel_command(const char *command, const char *line)
{
    char a[16] = "", b[16] = "";
    unsigned long n = 0, v = 0;
    unsigned char md[64];
    int alg, r = -9;
    void *c;

    if (strncmp(command, "ll", 2) != 0)
        return 0;
    if (strcmp(command, "llinit") != 0 && strcmp(command, "llupdate") != 0
        && strcmp(command, "llbits") != 0 && strcmp(command, "llfinal") != 0
        && strcmp(command, "lltransform") != 0 && strcmp(command, "llset") != 0
        && strcmp(command, "llone") != 0)
        return 0;
    if (digest_data[1] == 0) {
        size_t i;

        for (i = 0; i < sizeof(digest_data); i++)
            digest_data[i] = (unsigned char)(i * 7 + 3);
    }
    printf("%s:", line);
    if (strcmp(command, "llbits") == 0) {
        sscanf(line, "%*s %lu", &n);
        if (n > 8192)
            n = 8192;
        strcpy(a, "wp");
    } else {
        sscanf(line, "%*s %15s %15s %lu", a, b, &v);
        n = strtoul(b, NULL, 10);
    }
    for (alg = 0; alg < 10 && strcmp(a, ll_names[alg]) != 0; alg++)
        continue;
    if (alg == 10) {
        printf(" unknown\n");
        return 1;
    }
    c = &ll_ctx[alg];
    memset(md, 0xee, sizeof(md));
    if (strcmp(command, "llinit") == 0) {
        switch (alg) {
        case 0: r = SHA1_Init(c); break;
        case 1: r = SHA224_Init(c); break;
        case 2: r = SHA256_Init(c); break;
        case 3: r = SHA384_Init(c); break;
        case 4: r = SHA512_Init(c); break;
        case 5: r = MD4_Init(c); break;
        case 6: r = MD5_Init(c); break;
        case 7: r = RIPEMD160_Init(c); break;
        case 8: r = MDC2_Init(c); break;
        default: r = WHIRLPOOL_Init(c); break;
        }
        printf(" %d", r);
    } else if (strcmp(command, "llupdate") == 0 || strcmp(command, "llbits") == 0) {
        const unsigned char *d = digest_data + digest_offset;

        if (strcmp(command, "llbits") == 0) {
            if (ll_wp_overruns(ll_ctx[9].wp.bitoff, n)) {
                printf(" skipped\n");
                return 1;
            }
            WHIRLPOOL_BitUpdate(c, d, n);
            n = (n + 7) / 8;
        } else {
            if (n > 1024)
                n = 1024;
            if (alg == 9 && ll_wp_overruns(ll_ctx[9].wp.bitoff, n * 8)) {
                printf(" skipped\n");
                return 1;
            }
            switch (alg) {
            case 0: r = SHA1_Update(c, d, n); break;
            case 1: r = SHA224_Update(c, d, n); break;
            case 2: r = SHA256_Update(c, d, n); break;
            case 3: r = SHA384_Update(c, d, n); break;
            case 4: r = SHA512_Update(c, d, n); break;
            case 5: r = MD4_Update(c, d, n); break;
            case 6: r = MD5_Update(c, d, n); break;
            case 7: r = RIPEMD160_Update(c, d, n); break;
            case 8: r = MDC2_Update(c, d, n); break;
            default: r = WHIRLPOOL_Update(c, d, n); break;
            }
            printf(" %d", r);
        }
        digest_offset = (digest_offset + n * 3 + 1) % 1024;
    } else if (strcmp(command, "llfinal") == 0) {
        switch (alg) {
        case 0: r = SHA1_Final(md, c); break;
        case 1: r = SHA224_Final(md, c); break;
        case 2: r = SHA256_Final(md, c); break;
        case 3: r = SHA384_Final(md, c); break;
        case 4: r = SHA512_Final(md, c); break;
        case 5: r = MD4_Final(md, c); break;
        case 6: r = MD5_Final(md, c); break;
        case 7: r = RIPEMD160_Final(md, c); break;
        case 8: r = MDC2_Final(md, c); break;
        default: r = WHIRLPOOL_Final(md, c); break;
        }
        printf(" %d ", r);
        for (n = 0; n < sizeof(md); n++)
            printf("%02x", md[n]);
    } else if (strcmp(command, "lltransform") == 0) {
        const unsigned char *d = digest_data + n % 1024;

        switch (alg) {
        case 0: SHA1_Transform(c, d); break;
        case 2: SHA256_Transform(c, d); break;
        case 4: SHA512_Transform(c, d); break;
        case 5: MD4_Transform(c, d); break;
        case 6: MD5_Transform(c, d); break;
        case 7: RIPEMD160_Transform(c, d); break;
        default: printf(" none"); break;
        }
    } else if (strcmp(command, "llset") == 0) {
        if (strcmp(b, "md_len") == 0 && (alg == 1 || alg == 2))
            ll_ctx[alg].sha256.md_len = (unsigned int)v;
        else if (strcmp(b, "md_len") == 0 && (alg == 3 || alg == 4))
            ll_ctx[alg].sha512.md_len = (unsigned int)v;
        else if (strcmp(b, "pad_type") == 0 && alg == 8)
            ll_ctx[alg].mdc2.pad_type = (unsigned int)v;
        else if (strcmp(b, "Nl") == 0 && (alg == 3 || alg == 4))
            ll_ctx[alg].sha512.Nl = (SHA_LONG64)0 - v;
        else if (strcmp(b, "Nl") == 0 && alg == 0)
            ll_ctx[alg].sha1.Nl = 0u - (unsigned int)v;
        else if (strcmp(b, "Nl") == 0 && (alg == 1 || alg == 2))
            ll_ctx[alg].sha256.Nl = 0u - (unsigned int)v;
        else if (strcmp(b, "Nl") == 0 && alg == 5)
            ll_ctx[alg].md4.Nl = 0u - (unsigned int)v;
        else if (strcmp(b, "Nl") == 0 && alg == 6)
            ll_ctx[alg].md5.Nl = 0u - (unsigned int)v;
        else if (strcmp(b, "Nl") == 0 && alg == 7)
            ll_ctx[alg].rmd160.Nl = 0u - (unsigned int)v;
        else
            printf(" no such field");
    } else {
        const unsigned char *d = digest_data + digest_offset;
        unsigned char *p = NULL;

        if (n > 1024)
            n = 1024;
        switch (alg) {
        case 0: p = SHA1(d, n, md); break;
        case 1: p = SHA224(d, n, md); break;
        case 2: p = SHA256(d, n, md); break;
        case 3: p = SHA384(d, n, md); break;
        case 4: p = SHA512(d, n, md); break;
        case 5: p = MD4(d, n, md); break;
        case 6: p = MD5(d, n, md); break;
        case 7: p = RIPEMD160(d, n, md); break;
        case 8: p = MDC2(d, n, md); break;
        default: p = WHIRLPOOL(d, n, md); break;
        }
        digest_offset = (digest_offset + n * 3 + 1) % 1024;
        printf(" %s ", p == md ? "md" : "NULL");
        for (n = 0; n < (unsigned long)ll_md_sizes[alg]; n++)
            printf("%02x", md[n]);
        printf("\n");
        return 1;
    }
    printf(" |");
    for (n = 0; n < ll_sizes[alg]; n++)
        printf("%02x", ((unsigned char *)c)[n]);
    printf("\n");
    return 1;
}

/*
 * Commands for the deprecated AES functions and the modes.h helpers, over one encryption and
 * one decryption key, an IV (64 octets, for bi-IGE), a keystream block, and a position, all
 * kept between commands, and the digest commands' data:
 *   aeskey BITS                    AES_set_encrypt_key and AES_set_decrypt_key of BITS bits;
 *                                  the results and both keys whole
 *   aesiv [N]                      sets the IV from the data (with N, its last 32 bits to 2^32 - N,
 *                                  N blocks before the counter wraps), clears the keystream
 *                                  block, and sets the position to 0
 *   aesnum N                       sets the position (-5 to 15: past the block is a deviation)
 *   aesblock enc|dec|ecbN          AES_encrypt, AES_decrypt, or AES_ecb_encrypt with enc N
 *   aesmode MODE ENC LEN           MODE of LEN octets (at most 1000; bits for cfb1) with enc ENC: cbc, cfb128,
 *                                  cfb8, cfb1, ofb, ige, biige (whole blocks only); the output,
 *                                  the IV, and the position
 *   aeswrap FORM IV LEN            FORM wrap, wrap_pad, or aes (AES_wrap_key) of LEN octets,
 *                                  with the IV from the data (1) or the default (0); then the
 *                                  unwrap, and the unwrap of it with its last octet flipped
 *   cts FORM LEN                   cts or nistcts of LEN octets both ways, with the block and the
 *                                  CBC functions: the results, outputs, and IVs
 *   ctr FORM LEN                   CRYPTO_ctr128_encrypt (block) or _ctr32 (ctr32) of LEN
 *                                  octets on the IV, keystream block, and position
 */
static AES_KEY probe_ek, probe_dk;
static unsigned char probe_aes_iv[64], probe_ecount[16];
static int probe_num;

static void probe_enc_block(const unsigned char in[16], unsigned char out[16], const void *key)
{
    AES_encrypt(in, out, key);
}

static void probe_dec_block(const unsigned char in[16], unsigned char out[16], const void *key)
{
    AES_decrypt(in, out, key);
}

static void probe_cbc(const unsigned char *in, unsigned char *out, size_t len, const void *key,
                      unsigned char ivec[16], int enc)
{
    (void)key;
    AES_cbc_encrypt(in, out, len, enc ? &probe_ek : &probe_dk, ivec, enc);
}

static void probe_ctr32(const unsigned char *in, unsigned char *out, size_t blocks,
                        const void *key, const unsigned char ivec[16])
{
    unsigned char counter[16], k[16];
    size_t i, n;

    memcpy(counter, ivec, 16);
    for (i = 0; i < blocks; i++) {
        unsigned int c;

        AES_encrypt(counter, k, key);
        for (n = 0; n < 16; n++)
            out[16 * i + n] = in[16 * i + n] ^ k[n];
        c = ((unsigned int)counter[12] << 24 | (unsigned int)counter[13] << 16
             | (unsigned int)counter[14] << 8 | counter[15]) + 1;
        counter[12] = (unsigned char)(c >> 24);
        counter[13] = (unsigned char)(c >> 16);
        counter[14] = (unsigned char)(c >> 8);
        counter[15] = (unsigned char)c;
    }
}

static void probe_bytes(const char *label, const void *p, size_t n)
{
    const unsigned char *b = p;
    size_t i;

    printf(" %s ", label);
    for (i = 0; i < n; i++)
        printf("%02x", b[i]);
}

static int aes_command(const char *command, const char *line)
{
    char a[16] = "";
    long n = 0, m = 0;
    static unsigned char out[1100], back[1100];
    const unsigned char *d;

    if (strcmp(command, "aeskey") != 0 && strcmp(command, "aesiv") != 0
        && strcmp(command, "aesnum") != 0 && strcmp(command, "aesblock") != 0
        && strcmp(command, "aesmode") != 0 && strcmp(command, "aeswrap") != 0
        && strcmp(command, "cts") != 0 && strcmp(command, "ctr") != 0)
        return 0;
    if (digest_data[1] == 0) {
        size_t i;

        for (i = 0; i < sizeof(digest_data); i++)
            digest_data[i] = (unsigned char)(i * 7 + 3);
    }
    d = digest_data + digest_offset;
    printf("%s:", line);
    memset(out, 0xee, sizeof(out));
    memset(back, 0xee, sizeof(back));
    if (strcmp(command, "aeskey") == 0) {
        int r;

        sscanf(line, "%*s %ld", &n);
        memset(&probe_ek, 0xa5, sizeof(probe_ek));
        memset(&probe_dk, 0xa5, sizeof(probe_dk));
        r = AES_set_encrypt_key(d, (int)n, &probe_ek);
        printf(" %d %d", r, AES_set_decrypt_key(d, (int)n, &probe_dk));
        probe_bytes("enc", &probe_ek, sizeof(probe_ek));
        probe_bytes("dec", &probe_dk, sizeof(probe_dk));
        digest_offset = (digest_offset + 37) % 1024;
        if (r != 0) {
            /* Keep usable keys for the commands that follow. */
            AES_set_encrypt_key(digest_data, 128, &probe_ek);
            AES_set_decrypt_key(digest_data, 128, &probe_dk);
        }
    } else if (strcmp(command, "aesiv") == 0) {
        sscanf(line, "%*s %ld", &n);
        memcpy(probe_aes_iv, d, 64);
        if (n > 0) {
            unsigned int c = 0u - (unsigned int)n;

            probe_aes_iv[12] = (unsigned char)(c >> 24);
            probe_aes_iv[13] = (unsigned char)(c >> 16);
            probe_aes_iv[14] = (unsigned char)(c >> 8);
            probe_aes_iv[15] = (unsigned char)c;
        }
        memset(probe_ecount, 0, 16);
        probe_num = 0;
        digest_offset = (digest_offset + 11) % 1024;
    } else if (strcmp(command, "aesnum") == 0) {
        sscanf(line, "%*s %ld", &n);
        if (n >= -5 && n <= 15)
            probe_num = (int)n;
        printf(" %d", probe_num);
    } else if (strcmp(command, "aesblock") == 0) {
        sscanf(line, "%*s %15s", a);
        if (strcmp(a, "enc") == 0)
            AES_encrypt(d, out, &probe_ek);
        else if (strcmp(a, "dec") == 0)
            AES_decrypt(d, out, &probe_dk);
        else
            AES_ecb_encrypt(d, out, atoi(a + 3) == AES_ENCRYPT ? &probe_ek : &probe_dk, atoi(a + 3));
        probe_bytes("out", out, 16);
        digest_offset = (digest_offset + 5) % 1024;
    } else if (strcmp(command, "aesmode") == 0) {
        int enc;
        size_t len, octets;

        sscanf(line, "%*s %15s %ld %ld", a, &m, &n);
        enc = (int)m;
        len = n < 0 ? 0 : (size_t)n > 1000 ? 1000 : (size_t)n;
        octets = len;
        if (strcmp(a, "cbc") == 0) {
            AES_cbc_encrypt(d, out, len, enc ? &probe_ek : &probe_dk, probe_aes_iv, enc);
            octets = (len + 15) / 16 * 16;
        } else if (strcmp(a, "cfb128") == 0) {
            AES_cfb128_encrypt(d, out, len, &probe_ek, probe_aes_iv, &probe_num, enc);
        } else if (strcmp(a, "cfb8") == 0) {
            AES_cfb8_encrypt(d, out, len, &probe_ek, probe_aes_iv, &probe_num, enc);
        } else if (strcmp(a, "cfb1") == 0) {
            AES_cfb1_encrypt(d, out, len, &probe_ek, probe_aes_iv, &probe_num, enc);
            octets = (len + 7) / 8;
        } else if (strcmp(a, "ofb") == 0) {
            AES_ofb128_encrypt(d, out, len, &probe_ek, probe_aes_iv, &probe_num);
        } else if (strcmp(a, "ige") == 0) {
            len -= len % 16;
            octets = len;
            AES_ige_encrypt(d, out, len, enc == AES_ENCRYPT ? &probe_ek : &probe_dk, probe_aes_iv,
                            enc == AES_ENCRYPT ? AES_ENCRYPT : AES_DECRYPT);
        } else if (strcmp(a, "biige") == 0) {
            len -= len % 16;
            octets = len;
            AES_bi_ige_encrypt(d, out, len, enc == AES_ENCRYPT ? &probe_ek : &probe_dk, NULL,
                               probe_aes_iv, enc == AES_ENCRYPT ? AES_ENCRYPT : AES_DECRYPT);
        } else {
            printf(" unknown\n");
            return 1;
        }
        probe_bytes("out", out, octets + 1);
        probe_bytes("iv", probe_aes_iv, 32);
        printf(" num %d", probe_num);
        digest_offset = (digest_offset + len * 3 + 1) % 1024;
    } else if (strcmp(command, "aeswrap") == 0) {
        size_t w = 0, u, len;
        const unsigned char *iv;

        sscanf(line, "%*s %15s %ld %ld", a, &m, &n);
        len = n < 0 ? 0 : (size_t)n > 512 ? 512 : (size_t)n;
        iv = m ? digest_data + 900 : NULL;
        if (strcmp(a, "wrap") == 0)
            w = CRYPTO_128_wrap(&probe_ek, iv, out, d, len, probe_enc_block);
        else if (strcmp(a, "wrap_pad") == 0)
            w = CRYPTO_128_wrap_pad(&probe_ek, iv, out, d, len, probe_enc_block);
        else
            w = (size_t)AES_wrap_key(&probe_ek, iv, out, d, (unsigned int)len);
        printf(" %zu", w);
        probe_bytes("wrapped", out, w + 1);
        if (w >= 16) {
            if (strcmp(a, "wrap_pad") == 0)
                u = CRYPTO_128_unwrap_pad(&probe_dk, iv, back, out, w, probe_dec_block);
            else if (strcmp(a, "wrap") == 0)
                u = CRYPTO_128_unwrap(&probe_dk, iv, back, out, w, probe_dec_block);
            else
                u = (size_t)AES_unwrap_key(&probe_dk, iv, back, out, (unsigned int)w);
            printf(" unwrap %zu %d", u, memcmp(back, d, u) == 0);
            out[w - 1] ^= 1;
            memset(back, 0xee, w);
            if (strcmp(a, "wrap_pad") == 0)
                u = CRYPTO_128_unwrap_pad(&probe_dk, iv, back, out, w, probe_dec_block);
            else
                u = CRYPTO_128_unwrap(&probe_dk, iv, back, out, w, probe_dec_block);
            printf(" tampered %zu", u);
            probe_bytes("zeroed", back, w - 8);
        }
        digest_offset = (digest_offset + len + 3) % 1024;
    } else if (strcmp(command, "cts") == 0) {
        static unsigned char c[1100], e[1100];
        unsigned char iv1[16], iv2[16];
        size_t len, r1, r2, r3, r4;
        int nist;

        sscanf(line, "%*s %15s %ld", a, &n);
        len = n < 0 ? 0 : (size_t)n > 1000 ? 1000 : (size_t)n;
        nist = strcmp(a, "nistcts") == 0;
        memset(c, 0xee, sizeof(c));
        memset(e, 0xee, sizeof(e));
        memcpy(iv1, probe_aes_iv, 16);
        memcpy(iv2, probe_aes_iv, 16);
        r1 = nist ? CRYPTO_nistcts128_encrypt_block(d, out, len, &probe_ek, iv1, probe_enc_block)
                  : CRYPTO_cts128_encrypt_block(d, out, len, &probe_ek, iv1, probe_enc_block);
        r2 = nist ? CRYPTO_nistcts128_encrypt(d, c, len, &probe_ek, iv2, probe_cbc)
                  : CRYPTO_cts128_encrypt(d, c, len, &probe_ek, iv2, probe_cbc);
        printf(" %zu %zu same %d", r1, r2, memcmp(out, c, sizeof(c)) == 0 && memcmp(iv1, iv2, 16) == 0);
        probe_bytes("out", out, len + 1);
        probe_bytes("iv", iv1, 16);
        memcpy(iv1, probe_aes_iv, 16);
        memcpy(iv2, probe_aes_iv, 16);
        r3 = nist ? CRYPTO_nistcts128_decrypt_block(out, back, len, &probe_dk, iv1, probe_dec_block)
                  : CRYPTO_cts128_decrypt_block(out, back, len, &probe_dk, iv1, probe_dec_block);
        r4 = nist ? CRYPTO_nistcts128_decrypt(c, e, len, &probe_dk, iv2, probe_cbc)
                  : CRYPTO_cts128_decrypt(c, e, len, &probe_dk, iv2, probe_cbc);
        printf(" back %zu %zu same %d", r3, r4, memcmp(back, e, sizeof(e)) == 0);
        probe_bytes("back", back, len + 1);
        probe_bytes("iv", iv1, 16);
        probe_bytes("iv2", iv2, 16);
        digest_offset = (digest_offset + len + 7) % 1024;
    } else {
        unsigned int unum = (unsigned int)(probe_num < 0 ? 0 : probe_num);
        size_t len;

        sscanf(line, "%*s %15s %ld", a, &n);
        len = n < 0 ? 0 : (size_t)n > 1000 ? 1000 : (size_t)n;
        if (strcmp(a, "ctr32") == 0)
            CRYPTO_ctr128_encrypt_ctr32(d, out, len, &probe_ek, probe_aes_iv, probe_ecount, &unum,
                                        probe_ctr32);
        else
            CRYPTO_ctr128_encrypt(d, out, len, &probe_ek, probe_aes_iv, probe_ecount, &unum,
                                  probe_enc_block);
        probe_num = (int)unum;
        probe_bytes("out", out, len + 1);
        probe_bytes("iv", probe_aes_iv, 16);
        probe_bytes("ecount", probe_ecount, 16);
        printf(" num %d", probe_num);
        digest_offset = (digest_offset + len * 3 + 1) % 1024;
    }
    printf("\n");
    return 1;
}

/*
 * Commands for the AEAD helpers of modes.h over the AES commands' keys (AES-128 from the data
 * until an aeskey), one context each, and the digest commands' data; each prints its results:
 *   gcminit                        CRYPTO_gcm128_init (CRYPTO_gcm128_new the first time)
 *   gcmiv LEN                      CRYPTO_gcm128_setiv with LEN (at most 100) octets
 *   gcmaad LEN                     CRYPTO_gcm128_aad
 *   gcmenc|gcmdec LEN [ctr]        CRYPTO_gcm128_encrypt/decrypt (with ctr, the _ctr32 forms over
 *                                  a CTR function) of LEN (at most 1000) octets, and the output
 *   gcmfinish LEN                  CRYPTO_gcm128_finish against LEN octets of the last tag read
 *   gcmtag LEN                     CRYPTO_gcm128_tag of LEN octets
 *   ccminit M L                    CRYPTO_ccm128_init over the context as modes_local.h lays it out
 *   ccmiv NLEN MLEN                CRYPTO_ccm128_setiv
 *   ccmaad LEN                     CRYPTO_ccm128_aad
 *   ccmenc|ccmdec LEN [stream]     CRYPTO_ccm128_encrypt/decrypt (with stream, the _ccm64 forms)
 *   ccmtag LEN                     CRYPTO_ccm128_tag; each CCM command prints the nonce block,
 *                                  the CBC-MAC, and the block count
 *   ocbinit STREAM                 CRYPTO_ocb128_init (CRYPTO_ocb128_new the first time), with a
 *                                  bulk function if STREAM is 1
 *   ocbiv LEN TAGLEN, ocbaad LEN, ocbenc LEN, ocbdec LEN, ocbtag LEN, ocbfinish LEN, ocbcopy
 *                                  the OCB functions (ocbcopy copies the context into a second
 *                                  one and swaps them)
 *   xts ENC LEN                    CRYPTO_xts128_encrypt of LEN (at most 1000) octets
 */
struct ccm128_context {
    union {
        uint64_t u[2];
        unsigned char c[16];
    } nonce, cmac;
    uint64_t blocks;
    block128_f block;
    void *key;
};

struct xts128_context {
    void *key1, *key2;
    block128_f block1, block2;
};

static GCM128_CONTEXT *probe_gcm;
static struct ccm128_context probe_ccm;
static OCB128_CONTEXT *probe_ocb, *probe_ocb2;
static unsigned char probe_tag[16];

static void probe_ccm_fn(const unsigned char *in, unsigned char *out, size_t blocks,
                         const void *key, const unsigned char ivec[16], unsigned char cmac[16],
                         int enc)
{
    unsigned char counter[16], k[16];
    size_t i, n;

    memcpy(counter, ivec, 16);
    for (i = 0; i < blocks; i++) {
        AES_encrypt(counter, k, key);
        for (n = 0; n < 16; n++) {
            unsigned char x = in[16 * i + n], y = x ^ k[n];

            out[16 * i + n] = y;
            cmac[n] ^= enc ? x : y;
        }
        AES_encrypt(cmac, cmac, key);
        for (n = 15; n >= 8; n--)
            if (++counter[n] != 0)
                break;
    }
}

static void probe_ccm_enc(const unsigned char *in, unsigned char *out, size_t blocks,
                          const void *key, const unsigned char ivec[16], unsigned char cmac[16])
{
    probe_ccm_fn(in, out, blocks, key, ivec, cmac, 1);
}

static void probe_ccm_dec(const unsigned char *in, unsigned char *out, size_t blocks,
                          const void *key, const unsigned char ivec[16], unsigned char cmac[16])
{
    probe_ccm_fn(in, out, blocks, key, ivec, cmac, 0);
}

static void probe_ocb_fn(const unsigned char *in, unsigned char *out, size_t blocks,
                         const void *key, size_t start, unsigned char offset[16],
                         const unsigned char L[][16], unsigned char checksum[16])
{
    int dec = key == &probe_dk;
    size_t i, n;

    for (i = 0; i < blocks; i++) {
        unsigned char t[16];
        size_t idx = start + i;
        unsigned int z = 0;

        while (!(idx & 1)) {
            idx >>= 1;
            z++;
        }
        for (n = 0; n < 16; n++) {
            offset[n] ^= L[z][n];
            t[n] = in[16 * i + n] ^ offset[n];
        }
        if (dec)
            AES_decrypt(t, t, key);
        else
            AES_encrypt(t, t, key);
        for (n = 0; n < 16; n++) {
            out[16 * i + n] = t[n] ^ offset[n];
            checksum[n] ^= dec ? out[16 * i + n] : in[16 * i + n];
        }
    }
}

static int aead_command(const char *command, const char *line)
{
    char a[16] = "", b[16] = "";
    long n = 0, m = 0;
    static unsigned char out[1100];
    const unsigned char *d;
    size_t len;
    int r = -9;

    if (strncmp(command, "gcm", 3) != 0 && strncmp(command, "ccm", 3) != 0
        && strncmp(command, "ocb", 3) != 0 && strcmp(command, "xts") != 0)
        return 0;
    if (digest_data[1] == 0) {
        size_t i;

        for (i = 0; i < sizeof(digest_data); i++)
            digest_data[i] = (unsigned char)(i * 7 + 3);
    }
    if (probe_ek.rounds == 0) {
        AES_set_encrypt_key(digest_data, 128, &probe_ek);
        AES_set_decrypt_key(digest_data, 128, &probe_dk);
    }
    d = digest_data + digest_offset;
    sscanf(line, "%15s %ld %ld %15s", a, &n, &m, b);
    if (strcmp(command, "ccmenc") == 0 || strcmp(command, "ccmdec") == 0
        || strcmp(command, "gcmenc") == 0 || strcmp(command, "gcmdec") == 0)
        sscanf(line, "%*s %ld %15s", &n, b);
    len = n < 0 ? 0 : (size_t)n > 1000 ? 1000 : (size_t)n;
    printf("%s:", line);
    memset(out, 0xee, sizeof(out));
    if (strcmp(command, "gcminit") == 0) {
        if (probe_gcm == NULL)
            probe_gcm = CRYPTO_gcm128_new(&probe_ek, probe_enc_block);
        else
            CRYPTO_gcm128_init(probe_gcm, &probe_ek, probe_enc_block);
        printf(" %s\n", probe_gcm != NULL ? "ok" : "failed");
        return 1;
    }
    if (strncmp(command, "gcm", 3) == 0 && probe_gcm == NULL) {
        printf(" no context\n");
        return 1;
    }
    if (strcmp(command, "gcmiv") == 0) {
        CRYPTO_gcm128_setiv(probe_gcm, d, len > 100 ? 100 : len);
    } else if (strcmp(command, "gcmaad") == 0) {
        r = CRYPTO_gcm128_aad(probe_gcm, d, len);
        printf(" %d", r);
    } else if (strcmp(command, "gcmenc") == 0 || strcmp(command, "gcmdec") == 0) {
        int enc = command[3] == 'e', ctr = strcmp(b, "ctr") == 0;

        if (ctr)
            r = enc ? CRYPTO_gcm128_encrypt_ctr32(probe_gcm, d, out, len, probe_ctr32)
                    : CRYPTO_gcm128_decrypt_ctr32(probe_gcm, d, out, len, probe_ctr32);
        else
            r = enc ? CRYPTO_gcm128_encrypt(probe_gcm, d, out, len)
                    : CRYPTO_gcm128_decrypt(probe_gcm, d, out, len);
        printf(" %d", r);
        probe_bytes("out", out, len + 1);
    } else if (strcmp(command, "gcmfinish") == 0) {
        printf(" %d", CRYPTO_gcm128_finish(probe_gcm, probe_tag, len));
    } else if (strcmp(command, "gcmtag") == 0) {
        memset(probe_tag, 0xee, 16);
        CRYPTO_gcm128_tag(probe_gcm, probe_tag, len);
        probe_bytes("tag", probe_tag, 16);
    } else if (strcmp(command, "ccminit") == 0) {
        CRYPTO_ccm128_init(&probe_ccm, (unsigned int)n, (unsigned int)m, &probe_ek, probe_enc_block);
    } else if (strcmp(command, "ccmiv") == 0) {
        size_t mlen = m < 0 ? 0 : (size_t)m;

        printf(" %d", CRYPTO_ccm128_setiv(&probe_ccm, d, len > 16 ? 16 : len, mlen));
    } else if (strcmp(command, "ccmaad") == 0) {
        CRYPTO_ccm128_aad(&probe_ccm, d, len);
    } else if (strcmp(command, "ccmenc") == 0 || strcmp(command, "ccmdec") == 0) {
        int enc = command[3] == 'e', stream = strcmp(b, "stream") == 0;

        if (probe_ccm.block == NULL) {
            printf(" no context\n");
            return 1;
        }
        if (stream)
            r = enc ? CRYPTO_ccm128_encrypt_ccm64(&probe_ccm, d, out, len, probe_ccm_enc)
                    : CRYPTO_ccm128_decrypt_ccm64(&probe_ccm, d, out, len, probe_ccm_dec);
        else
            r = enc ? CRYPTO_ccm128_encrypt(&probe_ccm, d, out, len)
                    : CRYPTO_ccm128_decrypt(&probe_ccm, d, out, len);
        printf(" %d", r);
        probe_bytes("out", out, len + 1);
    } else if (strcmp(command, "ccmtag") == 0) {
        memset(probe_tag, 0xee, 16);
        printf(" %zu", CRYPTO_ccm128_tag(&probe_ccm, probe_tag, len > 16 ? 17 : len));
        probe_bytes("tag", probe_tag, 16);
    } else if (strcmp(command, "ocbinit") == 0) {
        ocb128_f f = n == 1 ? probe_ocb_fn : NULL;

        if (probe_ocb == NULL) {
            probe_ocb = CRYPTO_ocb128_new(&probe_ek, &probe_dk, probe_enc_block, probe_dec_block, f);
            probe_ocb2 = CRYPTO_ocb128_new(&probe_ek, &probe_dk, probe_enc_block, probe_dec_block, f);
            r = probe_ocb != NULL && probe_ocb2 != NULL;
        } else {
            r = CRYPTO_ocb128_init(probe_ocb, &probe_ek, &probe_dk, probe_enc_block, probe_dec_block, f);
        }
        printf(" %d\n", r);
        return 1;
    } else if (strncmp(command, "ocb", 3) == 0 && probe_ocb == NULL) {
        printf(" no context\n");
        return 1;
    } else if (strcmp(command, "ocbiv") == 0) {
        printf(" %d", CRYPTO_ocb128_setiv(probe_ocb, d, len > 20 ? 20 : len, (size_t)(m < 0 ? 0 : m)));
    } else if (strcmp(command, "ocbaad") == 0) {
        printf(" %d", CRYPTO_ocb128_aad(probe_ocb, d, len));
    } else if (strcmp(command, "ocbenc") == 0 || strcmp(command, "ocbdec") == 0) {
        r = command[3] == 'e' ? CRYPTO_ocb128_encrypt(probe_ocb, d, out, len)
                              : CRYPTO_ocb128_decrypt(probe_ocb, d, out, len);
        printf(" %d", r);
        probe_bytes("out", out, len + 1);
    } else if (strcmp(command, "ocbtag") == 0) {
        memset(probe_tag, 0xee, 16);
        printf(" %d", CRYPTO_ocb128_tag(probe_ocb, probe_tag, len > 16 ? 17 : len));
        probe_bytes("tag", probe_tag, 16);
    } else if (strcmp(command, "ocbfinish") == 0) {
        printf(" %d", CRYPTO_ocb128_finish(probe_ocb, probe_tag, len > 16 ? 17 : len));
    } else if (strcmp(command, "ocbcopy") == 0) {
        OCB128_CONTEXT *t;

        printf(" %d", CRYPTO_ocb128_copy_ctx(probe_ocb2, probe_ocb, NULL, NULL));
        t = probe_ocb;
        probe_ocb = probe_ocb2;
        probe_ocb2 = t;
    } else {
        struct xts128_context x = { &probe_ek, &probe_ek, probe_enc_block, probe_enc_block };
        struct xts128_context y = { &probe_dk, &probe_ek, probe_dec_block, probe_enc_block };

        sscanf(line, "%*s %ld %ld", &m, &n);
        len = n < 0 ? 0 : (size_t)n > 1000 ? 1000 : (size_t)n;
        r = CRYPTO_xts128_encrypt(m ? &x : &y, digest_data + 1500, d, out, len, (int)m);
        printf(" %d", r);
        probe_bytes("out", out, len + 1);
    }
    if (strncmp(command, "ccm", 3) == 0) {
        probe_bytes("nonce", probe_ccm.nonce.c, 16);
        probe_bytes("cmac", probe_ccm.cmac.c, 16);
        printf(" blocks %llu", (unsigned long long)probe_ccm.blocks);
    }
    digest_offset = (digest_offset + len * 3 + 1) % 1024;
    printf("\n");
    return 1;
}

/*
 * Commands for the deprecated DES functions over three schedules, an IV, and a position, kept
 * between commands, and the digest commands' data:
 *   deskey                         DES_set_key, DES_set_key_checked (into a junk schedule), and
 *                                  DES_set_key_unchecked of three keys from the data: the
 *                                  results and the first schedule
 *   desiv, desnum N                the IV from the data (and the position 0); the position
 *   desmode MODE ENC LEN [BITS]    MODE (ecb, ecb3, cbc, ncbc, xcbc, pcbc, ede3cbc, cfb, ede3cfb,
 *                                  ofb (LEN steps), cfb64, ede3cfb64, ofb64, ede3ofb64) of LEN
 *                                  (at most 500) octets with BITS bits a step (1 to 64 for the
 *                                  bit modes, 65 and up for cfb): the output, IV, and position
 *   descksum LEN COUNT             DES_cbc_cksum and DES_quad_cksum of LEN octets
 *   desstr LEN                     DES_string_to_key and _2keys of the data's first LEN octets
 *   descrypt LEN S0 S1             DES_fcrypt of the data's first LEN octets with salt octets
 */
static DES_key_schedule probe_ks1, probe_ks2, probe_ks3;
static DES_cblock probe_des_iv;
static int probe_des_num;

static int des_command(const char *command, const char *line)
{
    char a[16] = "";
    long n = 0, m = 0, k = 0;
    static unsigned char out[600], txt[600];
    const unsigned char *d;
    size_t len = 0;

    if (strncmp(command, "des", 3) != 0
        || (strcmp(command, "desiv") != 0 && strcmp(command, "desnum") != 0
            && strcmp(command, "deskey") != 0 && strcmp(command, "desmode") != 0
            && strcmp(command, "descksum") != 0 && strcmp(command, "desstr") != 0
            && strcmp(command, "descrypt") != 0))
        return 0;
    if (digest_data[1] == 0) {
        size_t i;

        for (i = 0; i < sizeof(digest_data); i++)
            digest_data[i] = (unsigned char)(i * 7 + 3);
    }
    d = digest_data + digest_offset;
    printf("%s:", line);
    memset(out, 0xee, sizeof(out));
    if (strcmp(command, "deskey") == 0) {
        DES_cblock k1, k2, k3;
        DES_key_schedule junk;

        memcpy(k1, d, 8);
        memcpy(k2, d + 8, 8);
        memcpy(k3, d + 16, 8);
        memset(&junk, 0xa5, sizeof(junk));
        printf(" %d %d %d", DES_set_key(&k1, &probe_ks1), DES_set_key_checked(&k2, &junk),
               DES_check_key_parity(&k3));
        DES_set_key_unchecked(&k2, &probe_ks2);
        DES_set_key_unchecked(&k3, &probe_ks3);
        probe_bytes("ks1", &probe_ks1, sizeof(probe_ks1));
        probe_bytes("junk", &junk, 16);
        digest_offset = (digest_offset + 29) % 1024;
    } else if (strcmp(command, "desiv") == 0) {
        memcpy(probe_des_iv, d, 8);
        probe_des_num = 0;
        digest_offset = (digest_offset + 13) % 1024;
    } else if (strcmp(command, "desnum") == 0) {
        sscanf(line, "%*s %ld", &n);
        probe_des_num = (int)n;
        printf(" %d", probe_des_num);
    } else if (strcmp(command, "desmode") == 0) {
        int enc;
        size_t octets;

        sscanf(line, "%*s %15s %ld %ld %ld", a, &m, &n, &k);
        enc = (int)m;
        len = n < 0 ? 0 : (size_t)n > 500 ? 500 : (size_t)n;
        octets = len;
        if (strcmp(a, "ecb") == 0) {
            DES_ecb_encrypt((const_DES_cblock *)d, (DES_cblock *)out, &probe_ks1, enc);
            octets = 8;
        } else if (strcmp(a, "ecb3") == 0) {
            DES_ecb3_encrypt((const_DES_cblock *)d, (DES_cblock *)out, &probe_ks1, &probe_ks2, &probe_ks3, enc);
            octets = 8;
        } else if (strcmp(a, "cbc") == 0) {
            DES_cbc_encrypt(d, out, (long)len, &probe_ks1, &probe_des_iv, enc);
            octets = (len + 7) / 8 * 8;
        } else if (strcmp(a, "ncbc") == 0) {
            DES_ncbc_encrypt(d, out, (long)len, &probe_ks1, &probe_des_iv, enc);
            octets = (len + 7) / 8 * 8;
        } else if (strcmp(a, "xcbc") == 0) {
            DES_xcbc_encrypt(d, out, (long)len, &probe_ks1, &probe_des_iv, (const_DES_cblock *)(digest_data + 1100),
                             (const_DES_cblock *)(digest_data + 1108), enc);
            octets = (len + 7) / 8 * 8;
        } else if (strcmp(a, "pcbc") == 0) {
            DES_pcbc_encrypt(d, out, (long)len, &probe_ks1, &probe_des_iv, enc);
            octets = (len + 7) / 8 * 8;
        } else if (strcmp(a, "ede3cbc") == 0) {
            DES_ede3_cbc_encrypt(d, out, (long)len, &probe_ks1, &probe_ks2, &probe_ks3, &probe_des_iv, enc);
            octets = (len + 7) / 8 * 8;
        } else if (strcmp(a, "cfb") == 0) {
            DES_cfb_encrypt(d, out, (int)k, (long)len, &probe_ks1, &probe_des_iv, enc);
        } else if (strcmp(a, "ede3cfb") == 0 && k > 0) {
            DES_ede3_cfb_encrypt(d, out, (int)k, (long)len, &probe_ks1, &probe_ks2, &probe_ks3, &probe_des_iv, enc);
        } else if (strcmp(a, "ofb") == 0 && k > 0) {
            if (len > 60)
                len = 60;
            DES_ofb_encrypt(d, out, (int)k, (long)len, &probe_ks1, &probe_des_iv);
            octets = len * 8;
        } else if (strcmp(a, "cfb64") == 0) {
            DES_cfb64_encrypt(d, out, (long)len, &probe_ks1, &probe_des_iv, &probe_des_num, enc);
        } else if (strcmp(a, "ede3cfb64") == 0) {
            DES_ede3_cfb64_encrypt(d, out, (long)len, &probe_ks1, &probe_ks2, &probe_ks3, &probe_des_iv, &probe_des_num, enc);
        } else if (strcmp(a, "ofb64") == 0) {
            DES_ofb64_encrypt(d, out, (long)len, &probe_ks1, &probe_des_iv, &probe_des_num);
        } else if (strcmp(a, "ede3ofb64") == 0) {
            DES_ede3_ofb64_encrypt(d, out, (long)len, &probe_ks1, &probe_ks2, &probe_ks3, &probe_des_iv, &probe_des_num);
        } else {
            printf(" skipped\n");
            return 1;
        }
        probe_bytes("out", out, octets + 1);
        probe_bytes("iv", probe_des_iv, 8);
        printf(" num %d", probe_des_num);
    } else if (strcmp(command, "descksum") == 0) {
        DES_cblock quad[4];
        DES_LONG r;

        sscanf(line, "%*s %ld %ld", &n, &m);
        len = n < 0 ? 0 : (size_t)n > 500 ? 500 : (size_t)n;
        r = DES_cbc_cksum(d, (DES_cblock *)out, (long)len, &probe_ks1, &probe_des_iv);
        printf(" %08x", (unsigned)r);
        probe_bytes("mac", out, 8);
        memset(quad, 0xee, sizeof(quad));
        r = DES_quad_cksum(d, quad, (long)len, (int)m, &probe_des_iv);
        printf(" %08x", (unsigned)r);
        probe_bytes("quad", quad, sizeof(quad));
    } else if (strcmp(command, "desstr") == 0) {
        DES_cblock k1, k2;

        sscanf(line, "%*s %ld", &n);
        len = n < 0 ? 0 : (size_t)n > 500 ? 500 : (size_t)n;
        memcpy(txt, d, len);
        txt[len] = '\0';
        DES_string_to_key((const char *)txt, &k1);
        probe_bytes("key", k1, 8);
        DES_string_to_2keys((const char *)txt, &k1, &k2);
        probe_bytes("keys", k1, 8);
        probe_bytes("", k2, 8);
    } else {
        char salt[3], ret[16];
        char *r;

        sscanf(line, "%*s %ld %ld %ld", &n, &m, &k);
        len = n < 0 ? 0 : (size_t)n > 500 ? 500 : (size_t)n;
        memcpy(txt, d, len);
        txt[len] = '\0';
        salt[0] = (char)m;
        salt[1] = (char)k;
        salt[2] = '\0';
        memset(ret, '#', sizeof(ret));
        ret[15] = '\0';
        r = DES_fcrypt((const char *)txt, salt, ret);
        printf(" %s", r == NULL ? "NULL" : "ret");
        probe_bytes("out", ret, 16);
    }
    digest_offset = (digest_offset + len * 3 + 1) % 1024;
    printf("\n");
    return 1;
}

/*
 * Commands for the deprecated Blowfish, CAST, RC2, and RC4 functions over one key each, an IV,
 * and a position, kept between commands, and the digest commands' data:
 *   lgkey bf|cast|rc2 LEN [BITS]   the key setter with LEN octets of the data (at most 300;
 *                                  RC2 with BITS effective bits): the key struct (Blowfish's
 *                                  P-array and S-box ends)
 *   lgiv, lgnum N                  the IV from the data (and the position 0); the position
 *   lgmode CIPHER MODE ENC LEN     MODE (ecb, cbc, cfb64, ofb64) of LEN (at most 500) octets:
 *                                  the output, IV, and position
 *   rc4key LEN                     RC4_set_key with LEN (1 to 300) octets: x, y, and the start
 *   rc4 LEN                        RC4 of LEN (at most 500) octets, and x and y
 */
static BF_KEY probe_bf;
static CAST_KEY probe_cast;
static RC2_KEY probe_rc2;
static RC4_KEY probe_rc4;
static unsigned char probe_lg_iv[8];
static int probe_lg_num;

static int legacy_command(const char *command, const char *line)
{
    char a[16] = "", b[16] = "";
    long n = 0, m = 0;
    static unsigned char out[600];
    const unsigned char *d;
    size_t len = 0;

    if (strcmp(command, "lgkey") != 0 && strcmp(command, "lgiv") != 0 && strcmp(command, "lgnum") != 0
        && strcmp(command, "lgmode") != 0 && strcmp(command, "rc4key") != 0 && strcmp(command, "rc4") != 0)
        return 0;
    if (digest_data[1] == 0) {
        size_t i;

        for (i = 0; i < sizeof(digest_data); i++)
            digest_data[i] = (unsigned char)(i * 7 + 3);
    }
    d = digest_data + digest_offset;
    printf("%s:", line);
    memset(out, 0xee, sizeof(out));
    if (strcmp(command, "lgkey") == 0) {
        sscanf(line, "%*s %15s %ld %ld", a, &n, &m);
        n = n > 300 ? 300 : n;
        if (strcmp(a, "bf") == 0) {
            BF_set_key(&probe_bf, (int)n, d);
            probe_bytes("P", probe_bf.P, sizeof(probe_bf.P));
            probe_bytes("S", probe_bf.S, 16);
            probe_bytes("", probe_bf.S + 1020, 16);
        } else if (strcmp(a, "cast") == 0) {
            CAST_set_key(&probe_cast, (int)n, d);
            probe_bytes("key", &probe_cast, sizeof(probe_cast));
        } else if (strcmp(a, "rc2") == 0 && n > 0) {
            RC2_set_key(&probe_rc2, (int)n, d, (int)m);
            probe_bytes("key", &probe_rc2, sizeof(probe_rc2));
        } else {
            printf(" skipped\n");
            return 1;
        }
        len = n < 0 ? 0 : (size_t)n;
    } else if (strcmp(command, "lgiv") == 0) {
        memcpy(probe_lg_iv, d, 8);
        probe_lg_num = 0;
        len = 3;
    } else if (strcmp(command, "lgnum") == 0) {
        sscanf(line, "%*s %ld", &n);
        probe_lg_num = (int)n;
        printf(" %d", probe_lg_num);
    } else if (strcmp(command, "lgmode") == 0) {
        int enc;
        size_t octets;

        sscanf(line, "%*s %15s %15s %ld %ld", a, b, &m, &n);
        enc = (int)m;
        len = n < 0 ? 0 : (size_t)n > 500 ? 500 : (size_t)n;
        octets = len;
        if (strcmp(b, "ecb") == 0) {
            if (strcmp(a, "bf") == 0)
                BF_ecb_encrypt(d, out, &probe_bf, enc);
            else if (strcmp(a, "cast") == 0)
                CAST_ecb_encrypt(d, out, &probe_cast, enc);
            else
                RC2_ecb_encrypt(d, out, &probe_rc2, enc);
            octets = 8;
        } else if (strcmp(b, "cbc") == 0) {
            if (strcmp(a, "bf") == 0)
                BF_cbc_encrypt(d, out, (long)len, &probe_bf, probe_lg_iv, enc);
            else if (strcmp(a, "cast") == 0)
                CAST_cbc_encrypt(d, out, (long)len, &probe_cast, probe_lg_iv, enc);
            else
                RC2_cbc_encrypt(d, out, (long)len, &probe_rc2, probe_lg_iv, enc);
            octets = (len + 7) / 8 * 8;
        } else if (strcmp(b, "cfb64") == 0) {
            if (strcmp(a, "bf") == 0)
                BF_cfb64_encrypt(d, out, (long)len, &probe_bf, probe_lg_iv, &probe_lg_num, enc);
            else if (strcmp(a, "cast") == 0)
                CAST_cfb64_encrypt(d, out, (long)len, &probe_cast, probe_lg_iv, &probe_lg_num, enc);
            else
                RC2_cfb64_encrypt(d, out, (long)len, &probe_rc2, probe_lg_iv, &probe_lg_num, enc);
        } else {
            if (strcmp(a, "bf") == 0)
                BF_ofb64_encrypt(d, out, (long)len, &probe_bf, probe_lg_iv, &probe_lg_num);
            else if (strcmp(a, "cast") == 0)
                CAST_ofb64_encrypt(d, out, (long)len, &probe_cast, probe_lg_iv, &probe_lg_num);
            else
                RC2_ofb64_encrypt(d, out, (long)len, &probe_rc2, probe_lg_iv, &probe_lg_num);
        }
        probe_bytes("out", out, octets + 1);
        probe_bytes("iv", probe_lg_iv, 8);
        printf(" num %d", probe_lg_num);
    } else if (strcmp(command, "rc4key") == 0) {
        sscanf(line, "%*s %ld", &n);
        if (n < 1 || n > 300) {
            printf(" skipped\n");
            return 1;
        }
        RC4_set_key(&probe_rc4, (int)n, d);
        printf(" x %u y %u", (unsigned)probe_rc4.x, (unsigned)probe_rc4.y);
        probe_bytes("data", probe_rc4.data, 16);
        len = (size_t)n;
    } else {
        sscanf(line, "%*s %ld", &n);
        len = n < 0 ? 0 : (size_t)n > 500 ? 500 : (size_t)n;
        RC4(&probe_rc4, len, d, out);
        probe_bytes("out", out, len + 1);
        printf(" x %u y %u", (unsigned)probe_rc4.x, (unsigned)probe_rc4.y);
    }
    digest_offset = (digest_offset + len * 3 + 1) % 1024;
    printf("\n");
    return 1;
}

/*
 * Commands for the deprecated IDEA, SEED, and Camellia functions over one key each, an IV, a
 * position, and a CTR keystream block, kept between commands, and the digest commands' data:
 *   ckey idea                      IDEA_set_encrypt_key and IDEA_set_decrypt_key: both schedules
 *   ckey idea-odd                  an encryption schedule of 32-bit words from the data, and
 *                                  IDEA_set_decrypt_key of it (through IDEA's inverse)
 *   ckey idea-inplace              IDEA_set_decrypt_key with the same schedule for both
 *   ckey seed                      SEED_set_key: the round keys
 *   ckey camellia BITS             Camellia_set_key: its result, grand rounds, and words
 *   civ, cnum N                    the IV from the data (and the positions 0, the keystream
 *                                  block zeros); the position (-5 to 15)
 *   cmode CIPHER MODE ENC LEN      MODE of LEN (at most 500) octets (bits for cfb1): ecb,
 *                                  cbc, cfb64 and ofb64 (IDEA), cfb128 and ofb128 (SEED,
 *                                  Camellia), cfb1, cfb8, and ctr (Camellia): the output, IV,
 *                                  and position
 *   cwords                         IDEA_encrypt on two unsigned longs from the data
 */
static IDEA_KEY_SCHEDULE probe_idea_ek, probe_idea_dk;
static SEED_KEY_SCHEDULE probe_seed;
static CAMELLIA_KEY probe_cmll;
static unsigned char probe_c_iv[16], probe_c_ecount[16];
static int probe_c_num;
static unsigned int probe_c_unum;

static int idea_seed_camellia_command(const char *command, const char *line)
{
    char a[16] = "", b[16] = "";
    long n = 0, m = 0;
    static unsigned char out[600];
    const unsigned char *d;
    size_t len = 0;

    if (strcmp(command, "ckey") != 0 && strcmp(command, "civ") != 0 && strcmp(command, "cnum") != 0
        && strcmp(command, "cmode") != 0 && strcmp(command, "cwords") != 0)
        return 0;
    if (digest_data[1] == 0) {
        size_t i;

        for (i = 0; i < sizeof(digest_data); i++)
            digest_data[i] = (unsigned char)(i * 7 + 3);
    }
    d = digest_data + digest_offset;
    printf("%s:", line);
    memset(out, 0xee, sizeof(out));
    if (strcmp(command, "ckey") == 0) {
        sscanf(line, "%*s %15s %ld", a, &n);
        if (strcmp(a, "idea") == 0) {
            IDEA_set_encrypt_key(d, &probe_idea_ek);
            IDEA_set_decrypt_key(&probe_idea_ek, &probe_idea_dk);
            probe_bytes("ek", &probe_idea_ek, sizeof(probe_idea_ek));
            probe_bytes("dk", &probe_idea_dk, sizeof(probe_idea_dk));
            len = 16;
        } else if (strcmp(a, "idea-odd") == 0) {
            IDEA_KEY_SCHEDULE k;
            size_t i;

            for (i = 0; i < 54; i++) {
                const unsigned char *w = d + i * 4;

                (&k.data[0][0])[i] = (IDEA_INT)w[0] << 24 | (IDEA_INT)w[1] << 16 | (IDEA_INT)w[2] << 8 | w[3];
                /* mostly small words, some near the modulus */
                if (w[0] & 1)
                    (&k.data[0][0])[i] &= w[0] & 2 ? 0x1ffff : 0xffff;
            }
            IDEA_set_decrypt_key(&k, &probe_idea_dk);
            probe_bytes("dk", &probe_idea_dk, 52 * sizeof(IDEA_INT));
            len = 70;
        } else if (strcmp(a, "idea-inplace") == 0) {
            IDEA_set_decrypt_key(&probe_idea_ek, &probe_idea_ek);
            probe_bytes("ek", &probe_idea_ek, sizeof(probe_idea_ek));
        } else if (strcmp(a, "seed") == 0) {
            SEED_set_key(d, &probe_seed);
            probe_bytes("ks", &probe_seed, sizeof(probe_seed));
            len = 16;
        } else if (strcmp(a, "camellia") == 0) {
            CAMELLIA_KEY k = probe_cmll;
            int r = Camellia_set_key(d, (int)n, &k);

            printf(" %d", r);
            if (r == 0) {
                probe_cmll = k;
                printf(" grand %d", probe_cmll.grand_rounds);
                probe_bytes("words", probe_cmll.u.rd_key, sizeof(probe_cmll.u.rd_key));
            }
            len = 32;
        } else {
            printf(" skipped\n");
            return 1;
        }
    } else if (strcmp(command, "civ") == 0) {
        memcpy(probe_c_iv, d, 16);
        memset(probe_c_ecount, 0, sizeof(probe_c_ecount));
        probe_c_num = 0;
        probe_c_unum = 0;
        len = 5;
    } else if (strcmp(command, "cnum") == 0) {
        sscanf(line, "%*s %ld", &n);
        if (n < -5 || n > 15) {
            printf(" skipped\n");
            return 1;
        }
        probe_c_num = (int)n;
        probe_c_unum = n < 0 ? 0 : (unsigned int)n;
        printf(" %d", probe_c_num);
    } else if (strcmp(command, "cwords") == 0) {
        unsigned long w[2];

        memcpy(w, d, sizeof(w));
        IDEA_encrypt(w, &probe_idea_ek);
        printf(" %08lx %08lx", w[0], w[1]);
        len = 16;
    } else {
        int enc;
        size_t octets;
        int idea = 0, seed = 0;

        sscanf(line, "%*s %15s %15s %ld %ld", a, b, &m, &n);
        enc = (int)m;
        len = n < 0 ? 0 : (size_t)n > 500 ? 500 : (size_t)n;
        octets = len;
        idea = strcmp(a, "idea") == 0;
        seed = strcmp(a, "seed") == 0;
        if (!idea && !seed && probe_cmll.grand_rounds == 0) {
            /* no Camellia key yet: OpenSSL would read past it */
            printf(" skipped\n");
            return 1;
        }
        if (strcmp(b, "ecb") == 0) {
            if (idea)
                IDEA_ecb_encrypt(d, out, enc ? &probe_idea_ek : &probe_idea_dk);
            else if (seed)
                SEED_ecb_encrypt(d, out, &probe_seed, enc);
            else
                Camellia_ecb_encrypt(d, out, &probe_cmll, enc);
            octets = idea ? 8 : 16;
        } else if (strcmp(b, "cbc") == 0) {
            if (idea) {
                IDEA_cbc_encrypt(d, out, (long)len, enc ? &probe_idea_ek : &probe_idea_dk, probe_c_iv, enc);
                octets = (len + 7) / 8 * 8;
            } else {
                if (seed)
                    SEED_cbc_encrypt(d, out, len, &probe_seed, probe_c_iv, enc);
                else
                    Camellia_cbc_encrypt(d, out, len, &probe_cmll, probe_c_iv, enc);
                octets = (len + 15) / 16 * 16;
            }
        } else if (strcmp(b, "cfb64") == 0) {
            IDEA_cfb64_encrypt(d, out, (long)len, &probe_idea_ek, probe_c_iv, &probe_c_num, enc);
        } else if (strcmp(b, "ofb64") == 0) {
            IDEA_ofb64_encrypt(d, out, (long)len, &probe_idea_ek, probe_c_iv, &probe_c_num);
        } else if (strcmp(b, "cfb128") == 0) {
            if (seed)
                SEED_cfb128_encrypt(d, out, len, &probe_seed, probe_c_iv, &probe_c_num, enc);
            else
                Camellia_cfb128_encrypt(d, out, len, &probe_cmll, probe_c_iv, &probe_c_num, enc);
        } else if (strcmp(b, "ofb128") == 0) {
            if (seed)
                SEED_ofb128_encrypt(d, out, len, &probe_seed, probe_c_iv, &probe_c_num);
            else
                Camellia_ofb128_encrypt(d, out, len, &probe_cmll, probe_c_iv, &probe_c_num);
        } else if (strcmp(b, "cfb1") == 0) {
            Camellia_cfb1_encrypt(d, out, len, &probe_cmll, probe_c_iv, &probe_c_num, enc);
            octets = (len + 7) / 8;
        } else if (strcmp(b, "cfb8") == 0) {
            Camellia_cfb8_encrypt(d, out, len, &probe_cmll, probe_c_iv, &probe_c_num, enc);
        } else {
            Camellia_ctr128_encrypt(d, out, len, &probe_cmll, probe_c_iv, probe_c_ecount, &probe_c_unum);
            probe_bytes("ecount", probe_c_ecount, 16);
            printf(" unum %u", probe_c_unum);
        }
        probe_bytes("out", out, octets + 1);
        probe_bytes("iv", probe_c_iv, 16);
        printf(" num %d", probe_c_num);
    }
    digest_offset = (digest_offset + len * 3 + 1) % 1024;
    printf("\n");
    return 1;
}

/*
 * Commands for the EVP filter BIOs, over the digest commands' data:
 *   bmd DIGEST LEN PIECE            LEN octets written in pieces of PIECE through a digest
 *                                   filter into a memory BIO: what went through, and BIO_gets
 *   bmdread DIGEST LEN CHUNK        LEN octets read through a digest filter in chunks
 *   benc CIPHER LEN PIECE           LEN octets written in pieces through an encrypting filter,
 *                                   then BIO_flush: the output's length, ends, and digest, and
 *                                   the status
 *   bdec CIPHER LEN CHUNK CORRUPT   LEN octets encrypted at once (the last octet flipped for
 *                                   CORRUPT 1), read back through a decrypting filter in chunks:
 *                                   the count, last result, EOF, status, and whether it matched
 */
static void bio_evp_digest(const char *what, const unsigned char *p, long n)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    EVP_Digest(p, (size_t)n, md, &len, EVP_sha256(), NULL);
    printf(" %s %ld", what, n);
    probe_bytes("sha256", md, 8);
    if (n > 0) {
        probe_bytes("head", p, n < 16 ? (size_t)n : 16);
        probe_bytes("tail", p + (n < 16 ? 0 : n - 16), n < 16 ? (size_t)n : 16);
    }
}

static int bio_evp_command(const char *command, const char *line)
{
    char name[32] = "";
    long len = 0, piece = 0, corrupt = 0;
    static const unsigned char key[64] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde";
    static const unsigned char iv[32] = "fedcba9876543210fedcba987654321";
    const unsigned char *d;

    if (strcmp(command, "bmd") != 0 && strcmp(command, "bmdread") != 0 && strcmp(command, "benc") != 0
        && strcmp(command, "bdec") != 0)
        return 0;
    if (digest_data[1] == 0) {
        size_t i;

        for (i = 0; i < sizeof(digest_data); i++)
            digest_data[i] = (unsigned char)(i * 7 + 3);
    }
    d = digest_data;
    sscanf(line, "%*s %31s %ld %ld %ld", name, &len, &piece, &corrupt);
    if (len < 0 || len > 2000 || piece < 1 || piece > 5000) {
        printf("%s: skipped\n", line);
        return 1;
    }
    printf("%s:", line);
    if (strcmp(command, "bmd") == 0 || strcmp(command, "bmdread") == 0) {
        const EVP_MD *md = EVP_get_digestbyname(name);
        BIO *b = BIO_new(BIO_f_md()), *mem;
        unsigned char out[EVP_MAX_MD_SIZE], buf[5000];
        long i, total = 0;
        int r;

        if (md == NULL || b == NULL) {
            printf(" no digest\n");
            BIO_free(b);
            return 1;
        }
        printf(" set %ld", (long)BIO_set_md(b, md));
        if (strcmp(command, "bmd") == 0) {
            mem = BIO_new(BIO_s_mem());
            BIO_push(b, mem);
            for (i = 0; i < len; i += piece) {
                r = BIO_write(b, d + i, (int)(len - i < piece ? len - i : piece));
                total += r > 0 ? r : 0;
            }
        } else {
            mem = BIO_new_mem_buf(d, (int)len);
            BIO_push(b, mem);
            while ((r = BIO_read(b, buf, (int)piece)) > 0)
                total += r;
            printf(" last %d", r);
        }
        r = BIO_gets(b, (char *)out, sizeof(out));
        printf(" moved %ld gets %d", total, r);
        if (r > 0)
            probe_bytes("md", out, (size_t)r);
        BIO_free_all(b);
    } else {
        const EVP_CIPHER *c = EVP_get_cipherbyname(name);
        BIO *b = BIO_new(BIO_f_cipher()), *mem;
        static unsigned char ct[2100], buf[5000];
        long total = 0, i;
        int r = 0, n = 0, f = 0;

        if (c == NULL || b == NULL) {
            printf(" no cipher\n");
            BIO_free(b);
            return 1;
        }
        if (strcmp(command, "benc") == 0) {
            char *p = NULL;

            printf(" set %d", BIO_set_cipher(b, c, key, iv, 1));
            mem = BIO_new(BIO_s_mem());
            BIO_push(b, mem);
            for (i = 0; i < len; i += piece) {
                r = BIO_write(b, d + i, (int)(len - i < piece ? len - i : piece));
                total += r > 0 ? r : 0;
            }
            printf(" wrote %ld pending %ld flush %d status %ld", total, (long)BIO_wpending(b), BIO_flush(b),
                BIO_get_cipher_status(b));
            {
                long m = BIO_get_mem_data(mem, &p);

                bio_evp_digest("out", (unsigned char *)p, m);
            }
        } else {
            EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();

            EVP_EncryptInit_ex(e, c, NULL, key, iv);
            EVP_EncryptUpdate(e, ct, &n, d, (int)len);
            EVP_EncryptFinal_ex(e, ct + n, &f);
            n += f;
            EVP_CIPHER_CTX_free(e);
            if (corrupt && n > 0)
                ct[n - 1] ^= 1;
            printf(" set %d", BIO_set_cipher(b, c, key, iv, 0));
            BIO_push(b, BIO_new_mem_buf(ct, n));
            while (total < (long)sizeof(buf) - piece && (r = BIO_read(b, buf + total, (int)piece)) > 0)
                total += r;
            printf(" read %ld last %d eof %d status %ld", total, r, BIO_eof(b), BIO_get_cipher_status(b));
            printf(" %s", total == len && memcmp(buf, d, (size_t)len) == 0 ? "match" : "differ");
            bio_evp_digest("plain", buf, total);
        }
        BIO_free_all(b);
    }
    printf("\n");
    ERR_clear_error();
    return 1;
}

/*
 * Commands for opaque symmetric keys, over the digest commands' data:
 *   symkey TYPE LEN                 EVP_SKEY_import_raw_key of LEN octets (at most 64) as TYPE:
 *                                   its type, provider, and raw key, or NULL
 *   symkeyenc CIPHER TYPE LEN IVLEN ENC
 *                                   a key as above through EVP_CipherInit_SKEY of CIPHER, with
 *                                   IVLEN octets of IV, for ENC, then 40 octets through it: the
 *                                   results, and whether they match the raw key's
 */
static int skey_command(const char *command, const char *line)
{
    char type[32] = "", cipher[32] = "";
    long len = 0, ivlen = 0, enc = 1;
    EVP_SKEY *k = NULL;
    const unsigned char *d;

    if (strcmp(command, "symkey") != 0 && strcmp(command, "symkeyenc") != 0)
        return 0;
    if (digest_data[1] == 0) {
        size_t i;

        for (i = 0; i < sizeof(digest_data); i++)
            digest_data[i] = (unsigned char)(i * 7 + 3);
    }
    d = digest_data + 100;
    if (strcmp(command, "symkey") == 0)
        sscanf(line, "%*s %31s %ld", type, &len);
    else
        sscanf(line, "%*s %31s %31s %ld %ld %ld", cipher, type, &len, &ivlen, &enc);
    if (len < 0 || len > 64 || ivlen < 0 || ivlen > 32) {
        printf("%s: skipped\n", line);
        return 1;
    }
    printf("%s:", line);
    k = EVP_SKEY_import_raw_key(NULL, type, (unsigned char *)d, (size_t)len, NULL);
    if (k == NULL) {
        printf(" NULL");
    } else {
        const unsigned char *raw = NULL;
        size_t rawlen = 0;

        printf(" %s/%s", EVP_SKEY_get0_skeymgmt_name(k), EVP_SKEY_get0_provider_name(k));
        if (EVP_SKEY_get0_raw_key(k, &raw, &rawlen) == 1)
            probe_bytes("raw", raw, rawlen);
    }
    if (strcmp(command, "symkeyenc") == 0 && k == NULL) {
        /* OpenSSL's ciphers that take key objects read through a NULL one and crash. */
        printf(" no key");
    } else if (strcmp(command, "symkeyenc") == 0) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, cipher, NULL);
        EVP_CIPHER_CTX *a = EVP_CIPHER_CTX_new(), *b = EVP_CIPHER_CTX_new();
        unsigned char out1[128], out2[128];
        int r1, r2, n1 = 0, n2 = 0, f1 = 0, f2 = 0;

        r1 = EVP_CipherInit_SKEY(a, c, k, d + 200, (size_t)ivlen, (int)enc, NULL);
        printf(" init %d", r1);
        if (r1 == 1) {
            r1 = EVP_CipherUpdate(a, out1, &n1, d + 300, 40) && EVP_CipherFinal_ex(a, out1 + n1, &f1);
            printf(" run %d", r1);
            if (r1 == 1)
                probe_bytes("out", out1, (size_t)(n1 + f1));
            /* The same cipher keyed with the raw octets, when their length is the cipher's. */
            if (c != NULL && len == EVP_CIPHER_get_key_length(c) && (ivlen == EVP_CIPHER_get_iv_length(c))) {
                r2 = EVP_CipherInit_ex2(b, c, d, d + 200, (int)enc, NULL)
                    && EVP_CipherUpdate(b, out2, &n2, d + 300, 40) && EVP_CipherFinal_ex(b, out2 + n2, &f2);
                printf(" %s", r1 == r2 && n1 + f1 == n2 + f2 && memcmp(out1, out2, (size_t)(n1 + f1)) == 0
                        ? "same" : "differ");
            }
        }
        EVP_CIPHER_CTX_free(a);
        EVP_CIPHER_CTX_free(b);
        EVP_CIPHER_free(c);
    }
    printf("\n");
    EVP_SKEY_free(k);
    ERR_clear_error();
    return 1;
}

/*
 * Commands for application-defined digests, over the digest commands' data:
 *   mdcopy NAME LEN PIECE           EVP_MD_meth_dup of the static digest NAME given its public
 *                                   state's size, over LEN octets (at most 1000) in pieces of
 *                                   PIECE: the digest, and whether it matches the static one's
 */
static int md_meth_command(const char *command, const char *line)
{
    static const struct {
        const char *name;
        int size;
    } sizes[] = {
        { "MD4", sizeof(MD4_CTX) }, { "MD5", sizeof(MD5_CTX) }, { "SHA1", sizeof(SHA_CTX) },
        { "SHA224", sizeof(SHA256_CTX) }, { "SHA256", sizeof(SHA256_CTX) },
        { "SHA384", sizeof(SHA512_CTX) }, { "SHA512", sizeof(SHA512_CTX) },
        { "SHA512-224", sizeof(SHA512_CTX) }, { "SHA512-256", sizeof(SHA512_CTX) },
        { "RIPEMD160", sizeof(RIPEMD160_CTX) }, { "MDC2", sizeof(MDC2_CTX) },
        { "WHIRLPOOL", sizeof(WHIRLPOOL_CTX) }, { "MD5-SHA1", sizeof(MD5_CTX) + sizeof(SHA_CTX) },
    };
    char name[32] = "";
    long len = 0, piece = 1;
    const EVP_MD *from;
    EVP_MD *md;
    EVP_MD_CTX *ctx;
    unsigned char out[64], want[64];
    unsigned int n = 0, w = 0;
    size_t i;
    int size = -1, r;

    if (strcmp(command, "mdcopy") != 0)
        return 0;
    if (digest_data[1] == 0) {
        for (i = 0; i < sizeof(digest_data); i++)
            digest_data[i] = (unsigned char)(i * 7 + 3);
    }
    sscanf(line, "%*s %31s %ld %ld", name, &len, &piece);
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
        if (strcmp(sizes[i].name, name) == 0)
            size = sizes[i].size;
    from = EVP_get_digestbyname(name);
    if (size < 0 || from == NULL || len < 0 || len > 1000 || piece < 1) {
        printf("%s: skipped\n", line);
        return 1;
    }
    md = EVP_MD_meth_dup(from);
    EVP_MD_meth_set_app_datasize(md, size);
    ctx = EVP_MD_CTX_new();
    r = EVP_DigestInit_ex(ctx, md, NULL);
    for (i = 0; r && i < (size_t)len; i += (size_t)piece)
        r = EVP_DigestUpdate(ctx, digest_data + i, (size_t)len - i < (size_t)piece ? (size_t)len - i : (size_t)piece);
    r = r && EVP_DigestFinal_ex(ctx, out, &n);
    printf("%s: %d", line, r);
    if (r)
        probe_bytes("md", out, n);
    /* The static digest as the default provider runs it (MD4 and MDC2 need the legacy one). */
    if (EVP_Digest(digest_data, (size_t)len, want, &w, from, NULL))
        printf(" %s", r && n == w && memcmp(out, want, n) == 0 ? "same" : "differ");
    printf("\n");
    EVP_MD_CTX_free(ctx);
    EVP_MD_meth_free(md);
    ERR_clear_error();
    return 1;
}

/* The state of cmeth's toy cipher: its key and IV, the keystream position, and its calls. */
struct toy_state {
    unsigned char key[16], iv[16];
    unsigned long pos;
    int inits, ctrls;
};

static int toy_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv,
    int enc)
{
    struct toy_state *s = EVP_CIPHER_CTX_get_cipher_data(ctx);

    (void)enc;
    s->inits++;
    if (key != NULL)
        memcpy(s->key, key, sizeof(s->key));
    if (iv != NULL)
        memcpy(s->iv, iv, sizeof(s->iv));
    s->pos = 0;
    return 1;
}

/* A keystream of the key, both IVs (the cipher's own and the context's), and the position. */
static int toy_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
    size_t inl)
{
    struct toy_state *s = EVP_CIPHER_CTX_get_cipher_data(ctx);
    const unsigned char *iv = EVP_CIPHER_CTX_iv(ctx);
    size_t i;

    for (i = 0; i < inl; i++, s->pos++)
        out[i] = in[i] ^ s->key[s->pos % 16] ^ s->iv[s->pos % 16] ^ iv[s->pos % 16]
            ^ (unsigned char)(s->pos * 31 + 7);
    return 1;
}

static int toy_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    struct toy_state *s = EVP_CIPHER_CTX_get_cipher_data(ctx);

    (void)arg;
    s->ctrls++;
    switch (type) {
    case EVP_CTRL_INIT:
    case EVP_CTRL_COPY:
    case EVP_CTRL_SET_KEY_LENGTH:
        return 1;
    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = 12;
        return 1;
    default:
        return -1;
    }
}

/*
 * Commands for application-defined ciphers, over the digest commands' data:
 *   cmeth MODE BS FLAGS LEN PIECE PAD TAMPER
 *                                   a toy cipher (a keystream) of the mode (stream, ecb, cbc,
 *                                   cfb, ofb, ctr), block size BS (1, 8, or 16), and the
 *                                   EVP_CIPH_* FLAGS (hex; those the toy can take) encrypting
 *                                   LEN octets (at most 512) in pieces of PIECE, padded or not
 *                                   (PAD), the IV set again, then decrypting the ciphertext
 *                                   (its octet TAMPER flipped, unless -1), copied half way:
 *                                   the lengths, results, ciphertext, and the calls made
 */
static int cipher_meth_command(const char *command, const char *line)
{
    static const struct {
        const char *name;
        int mode;
    } modes[] = {
        { "stream", EVP_CIPH_STREAM_CIPHER }, { "ecb", EVP_CIPH_ECB_MODE },
        { "cbc", EVP_CIPH_CBC_MODE }, { "cfb", EVP_CIPH_CFB_MODE },
        { "ofb", EVP_CIPH_OFB_MODE }, { "ctr", EVP_CIPH_CTR_MODE },
    };
    const unsigned long allowed = EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CUSTOM_IV
        | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_KEY_LENGTH
        | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH;
    static const unsigned char key[17] = "0123456789abcdef", iv[17] = "fedcba9876543210";
    char name[16] = "";
    long bs = 0, len = 0, piece = 1, pad = 1, tamper = -1;
    unsigned long flags = 0;
    EVP_CIPHER *c;
    EVP_CIPHER_CTX *e, *d, *d2;
    struct toy_state *s;
    unsigned char ct[600], pt[600], pt2[600];
    int r, n, total = 0, dtotal = 0, dtotal2 = 0, r2, mode = -1;
    long i;
    size_t m;

    if (strcmp(command, "cmeth") != 0)
        return 0;
    if (digest_data[1] == 0) {
        for (m = 0; m < sizeof(digest_data); m++)
            digest_data[m] = (unsigned char)(m * 7 + 3);
    }
    sscanf(line, "%*s %15s %ld %lx %ld %ld %ld %ld", name, &bs, &flags, &len, &piece, &pad,
        &tamper);
    for (m = 0; m < sizeof(modes) / sizeof(modes[0]); m++)
        if (strcmp(modes[m].name, name) == 0)
            mode = modes[m].mode;
    if (mode < 0 || (bs != 1 && bs != 8 && bs != 16) || (flags & ~allowed) != 0 || len < 0
        || len > 512 || piece < 1) {
        printf("%s: skipped\n", line);
        return 1;
    }
    c = EVP_CIPHER_meth_new(NID_undef, (int)bs, 16);
    EVP_CIPHER_meth_set_iv_length(c, 16);
    EVP_CIPHER_meth_set_flags(c, (unsigned long)mode | flags);
    EVP_CIPHER_meth_set_impl_ctx_size(c, sizeof(struct toy_state));
    EVP_CIPHER_meth_set_init(c, toy_init);
    EVP_CIPHER_meth_set_do_cipher(c, toy_do_cipher);
    EVP_CIPHER_meth_set_ctrl(c, toy_ctrl);
    printf("%s:", line);

    e = EVP_CIPHER_CTX_new();
    r = EVP_EncryptInit_ex(e, c, NULL, key, iv);
    printf(" init %d", r);
    if (r) {
        EVP_CIPHER_CTX_set_padding(e, (int)pad);
        printf(" keylen %d/%d ivlen %d", EVP_CIPHER_CTX_set_key_length(e, 10),
            EVP_CIPHER_CTX_get_key_length(e), EVP_CIPHER_CTX_get_iv_length(e));
        r = EVP_EncryptInit_ex(e, NULL, NULL, NULL, iv);
        for (i = 0; r && i < len; i += piece) {
            r = EVP_EncryptUpdate(e, ct + total, &n, digest_data + i,
                (int)(len - i < piece ? len - i : piece));
            total += r ? n : 0;
        }
        r = r && EVP_EncryptFinal_ex(e, ct + total, &n);
        total += r ? n : 0;
        s = EVP_CIPHER_CTX_get_cipher_data(e);
        printf(" enc %d %d inits %d ctrls %d", r, total, s->inits, s->ctrls);
        if (r)
            probe_bytes("ct", ct, (size_t)total);
        printf(" err %d", ERR_GET_REASON(ERR_peek_error()));
        ERR_clear_error();
    }
    if (tamper >= 0 && total > 0)
        ct[tamper % total] ^= 1;

    d = EVP_CIPHER_CTX_new();
    d2 = EVP_CIPHER_CTX_new();
    r = EVP_DecryptInit_ex(d, c, NULL, key, iv);
    if (r) {
        EVP_CIPHER_CTX_set_padding(d, (int)pad);
        for (i = 0; r && i < total / 2; i += piece) {
            r = EVP_DecryptUpdate(d, pt + dtotal, &n, ct + i,
                (int)(total / 2 - i < piece ? total / 2 - i : piece));
            dtotal += r ? n : 0;
        }
        r2 = r && EVP_CIPHER_CTX_copy(d2, d);
        printf(" copy %d", r2);
        if (r2)
            memcpy(pt2, pt, (size_t)dtotal);
        dtotal2 = dtotal;
        n = 0;
        r = r && EVP_DecryptUpdate(d, pt + dtotal, &n, ct + total / 2, total - total / 2);
        dtotal += r ? n : 0;
        r = r && EVP_DecryptFinal_ex(d, pt + dtotal, &n);
        dtotal += r ? n : 0;
        printf(" dec %d %d %s err %d", r, dtotal,
            r && dtotal == len && memcmp(pt, digest_data, (size_t)len) == 0 ? "same" : "differ",
            ERR_GET_REASON(ERR_peek_error()));
        ERR_clear_error();
        if (r2) {
            n = 0;
            r2 = EVP_DecryptUpdate(d2, pt2 + dtotal2, &n, ct + total / 2, total - total / 2);
            dtotal2 += r2 ? n : 0;
            r2 = r2 && EVP_DecryptFinal_ex(d2, pt2 + dtotal2, &n);
            dtotal2 += r2 ? n : 0;
            printf(" dec2 %d %d %s", r2, dtotal2,
                r == r2 && dtotal == dtotal2 && memcmp(pt, pt2, (size_t)dtotal) == 0 ? "same"
                                                                                       : "differ");
        }
    } else {
        printf(" decinit 0");
    }
    printf("\n");
    EVP_CIPHER_CTX_free(e);
    EVP_CIPHER_CTX_free(d);
    EVP_CIPHER_CTX_free(d2);
    EVP_CIPHER_meth_free(c);
    ERR_clear_error();
    return 1;
}

/*
 * Commands for configuration files, over the text given in hex:
 *   cnf METHOD HEX                  NCONF_load_bio of the octets HEX (at most 500; - for none)
 *                                   with the default (d) or WIN32 (w) method: the result, line,
 *                                   and errors; the dump, in the hash table's order; the
 *                                   section names; and each section's values in order
 */
static int conf_command(const char *command, const char *line)
{
    char method[4] = "", hex[1001] = "";
    unsigned char text[501];
    size_t n = 0, i;
    CONF *conf;
    BIO *b, *out;
    long eline = -7;
    int r, k, j;
    unsigned long code;
    const char *data;
    int flags;
    char *p;
    long len;
    STACK_OF(OPENSSL_CSTRING) *names;

    if (strcmp(command, "cnf") != 0)
        return 0;
    sscanf(line, "%*s %3s %1000s", method, hex);
    if (strcmp(hex, "-") != 0) {
        size_t h = strlen(hex);

        if (h % 2 != 0 || h / 2 > 500) {
            printf("%s: skipped\n", line);
            return 1;
        }
        for (i = 0; i < h / 2; i++) {
            unsigned int byte;

            if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
                printf("%s: skipped\n", line);
                return 1;
            }
            text[n++] = (unsigned char)byte;
        }
    }
    conf = NCONF_new(strcmp(method, "w") == 0 ? NCONF_WIN32() : NCONF_default());
    b = BIO_new_mem_buf(text, (int)n);
    r = NCONF_load_bio(conf, b, &eline);
    printf("%s: load %d line %ld errors:", line, r, eline);
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && data[0] != '\0')
            print_quoted(data);
    }
    out = BIO_new(BIO_s_mem());
    NCONF_dump_bio(conf, out);
    (void)BIO_write(out, "", 1);
    len = BIO_get_mem_data(out, &p);
    printf(" dump");
    if (len > 0)
        print_quoted(p);
    BIO_free(out);
    names = NCONF_get_section_names(conf);
    printf(" sections");
    for (k = 0; k < sk_OPENSSL_CSTRING_num(names); k++) {
        const char *name = sk_OPENSSL_CSTRING_value(names, k);
        STACK_OF(CONF_VALUE) *sk = NCONF_get_section(conf, name);

        print_quoted(name);
        printf(" {");
        for (j = 0; j < sk_CONF_VALUE_num(sk); j++) {
            CONF_VALUE *v = sk_CONF_VALUE_value(sk, j);

            print_quoted(v->name);
            print_quoted(v->value);
        }
        printf(" }");
    }
    printf("\n");
    sk_OPENSSL_CSTRING_free(names);
    BIO_free(b);
    NCONF_free(conf);
    ERR_clear_error();
    return 1;
}

/*
 *   cmod FLAGS HEX                  the configuration of the octets HEX (at most 500) loaded into
 *                                   a new library context and its modules run with the
 *                                   CONF_MFLAGS_* FLAGS (hex): the result, the providers, the
 *                                   default properties, and the errors (not the DSO library's
 *                                   data, which names the platform's loader messages); the
 *                                   thread's error state is freed afterwards, likewise
 */
static int conf_modules_command(const char *command, const char *line)
{
    char hex[1001] = "";
    unsigned long flags = 0, code;
    unsigned char text[501];
    size_t n = 0, i, h;
    OSSL_LIB_CTX *ctx;
    CONF *conf;
    BIO *b;
    char *props;
    const char *data;
    int r, eflags;

    if (strcmp(command, "cmod") != 0)
        return 0;
    sscanf(line, "%*s %lx %1000s", &flags, hex);
    h = strlen(hex);
    if (h % 2 != 0 || h / 2 > 500) {
        printf("%s: skipped\n", line);
        return 1;
    }
    for (i = 0; i < h / 2; i++) {
        unsigned int byte;

        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            printf("%s: skipped\n", line);
            return 1;
        }
        text[n++] = (unsigned char)byte;
    }
    ctx = OSSL_LIB_CTX_new();
    conf = NCONF_new_ex(ctx, NULL);
    b = BIO_new_mem_buf(text, (int)n);
    r = NCONF_load_bio(conf, b, NULL);
    printf("%s: load %d", line, r);
    if (r > 0) {
        r = CONF_modules_load(conf, NULL, flags);
        props = EVP_get1_default_properties(ctx);
        printf(" modules %d providers %d%d%d properties", r, OSSL_PROVIDER_available(ctx, "default"),
            OSSL_PROVIDER_available(ctx, "base"), OSSL_PROVIDER_available(ctx, "null"));
        print_quoted(props != NULL ? props : "(null)");
        OPENSSL_free(props);
    }
    printf(" errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &eflags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((eflags & ERR_TXT_STRING) != 0 && data[0] != '\0' && ERR_GET_LIB(code) != ERR_LIB_DSO)
            print_quoted(data);
    }
    printf("\n");
    BIO_free(b);
    NCONF_free(conf);
    OSSL_LIB_CTX_free(ctx);
    ERR_clear_error();
    /* No error slot keeps a buffer sized by a DSO message, which differs between libraries. */
    OPENSSL_thread_stop();
    return 1;
}

int main(void)
{
    for (int i = 0; i < 64; i++)
        pool[i] = i * 7 % 10;
    char line[1024], command[32], argument[1000];

    while (fgets(line, sizeof(line), stdin) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0') {
            printf("%s\n", line);
            continue;
        }
        argument[0] = '\0';
        if (sscanf(line, "%31s %999s", command, argument) < 1)
            continue;
        if (err_command(command, line) || stack_command(command, line)
            || lhash_command(command, line) || string_command(command, line)
            || bio_command(command, line) || printf_command(command, line)
            || addr_command(command, line) || obj_command(command, line)
            || asn_command(command, line) || int_command(command, line)
            || bit_command(command, line) || text_command(command, line)
            || time_command(command, line) || template_command(command, line)
            || params_command(command, line) || ctx_command(command, line)
            || prop_command(command, line) || prov_command(command, line)
            || fetch_command(command, line) || digest_command(command, line)
            || cipher_command(command, line) || mac_command(command, line)
            || kdf_command(command, line) || rand_command(command, line)
            || bn_command(command, line) || pkey_command(command, line)
            || derive_command(command, line) || meth_command(command, line)
            || print_command(command, line) || lowlevel_command(command, line)
            || aes_command(command, line) || aead_command(command, line)
            || des_command(command, line) || legacy_command(command, line)
            || idea_seed_camellia_command(command, line) || bio_evp_command(command, line)
            || skey_command(command, line) || md_meth_command(command, line)
            || cipher_meth_command(command, line) || conf_command(command, line)
            || conf_modules_command(command, line) || ec_command(command, line)
            || ml_kem_command(command, line) || dh_command(command, line)) {
            fflush(stdout);
            continue;
        } else if (strcmp(command, "new") == 0) {
            BUF_MEM_free(buffer);
            buffer = BUF_MEM_new_ex(strtoul(argument, NULL, 0));
            printf("new %s\n", buffer == NULL ? "failed" : "ok");
        } else if (strcmp(command, "reverse") == 0) {
            unsigned char in[256], out[256];
            size_t len;

            if (!parse_hex(argument, in, &len)) {
                printf("error bad hex\n");
                continue;
            }
            BUF_reverse(out, in, len);
            print_hex("reversed", out, len);
            BUF_reverse(in, NULL, len);
            print_hex("in-place", in, len);
        } else if (buffer == NULL) {
            printf("error no buffer\n");
        } else if (strcmp(command, "grow") == 0) {
            print_state("grow", BUF_MEM_grow(buffer, strtoul(argument, NULL, 0)));
        } else if (strcmp(command, "grow_clean") == 0) {
            print_state("grow_clean", BUF_MEM_grow_clean(buffer, strtoul(argument, NULL, 0)));
        } else if (strcmp(command, "fill") == 0) {
            if (buffer->length > 0)
                memset(buffer->data, (int)strtoul(argument, NULL, 0), buffer->length);
            printf("fill %zu\n", buffer->length);
        } else if (strcmp(command, "dump") == 0) {
            print_hex("data", (const unsigned char *)buffer->data, buffer->length);
        } else if (strcmp(command, "free") == 0) {
            BUF_MEM_free(buffer);
            buffer = NULL;
            printf("free\n");
        } else {
            printf("error unknown command %s\n", command);
        }
        fflush(stdout);
    }
    BUF_MEM_free(buffer);
    return 0;
}
