Fixtures for `tests/apps/ts.txt`, made once with the reference's `openssl` (replies carry
the time they were made, and queries a random nonce, so the corpus can't make them itself):

- `tsaca.pem` (key `tsaca_key.pem`): a CA; `tsa_cert1.pem` (key `tsa_key1.pem`): a TSA
  certificate it issued (`ext.cnf`'s `tsa_cert`); `tsa_cert2.pem` (`tsa_key2.pem`): one without
  the time stamping key usage (`non_tsa_cert`);
- `ts.cnf`: the TSA configuration the corpus uses;
- `req.tsq`: `ts -query -config ts.cnf -data data.txt -no_nonce -sha256 -cert`;
  `req-nonce.tsq`: `ts -query -config ts.cnf -data data.txt -sha512 -tspolicy tsa_policy2`;
- `resp.tsr`, `resp-nonce.tsr`: `ts -reply -config ts.cnf -queryfile <query> -signer
  tsa_cert1.pem -inkey tsa_key1.pem -chain tsaca.pem`; `resp2.tsr`: the same for `req.tsq` with
  `-section tsa_config2 -sha384`; `token.der`: `ts -reply -in resp.tsr -token_out`.
