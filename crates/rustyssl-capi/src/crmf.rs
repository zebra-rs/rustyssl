//! The Certificate Request Message Format (RFC 4211, `crypto/crmf`): request messages and
//! their templates, controls, and proof-of-possession; encrypted values and keys; and the
//! password-based MAC.

pub(crate) mod asn;
pub(crate) mod msg;
pub(crate) mod pbm;

/// `OSSL_MAX_NAME_SIZE` (an internal header's), the room for an algorithm's name.
const NAME_LEN: usize = 50;
