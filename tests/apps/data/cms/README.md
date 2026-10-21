Fixtures for `tests/apps/cms.txt`, made once with the reference's `openssl cms` (their
signing times and receipt content IDs are random, so the corpus can't make them itself):

- `rr.msg`: `cms -sign -nodetach -signer smrsa1.pem -receipt_request_to test@openssl.org
  -receipt_request_from from@openssl.org` of `test/smcont.txt`;
- `rr-all.msg`, `rr-first.msg`: the same with `-receipt_request_all`, `-receipt_request_first`;
- `receipt.msg`: `cms -sign_receipt -in rr-all.msg -signer smrsa2.pem`.

The certificates are upstream's `test/smime-certs/`.
