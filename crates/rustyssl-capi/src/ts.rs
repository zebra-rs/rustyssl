//! Time-stamping (RFC 3161, `crypto/ts`): requests, responses, and TSTInfo; printing them;
//! making responses as a TSA; verifying them; and configuring a TSA.

pub(crate) mod asn;
pub(crate) mod conf;
pub(crate) mod prn;
pub(crate) mod sign;
pub(crate) mod utils;
pub(crate) mod vfy;

/// `OSSL_MAX_NAME_SIZE` (an internal header's), the room for an algorithm's name.
const NAME_LEN: usize = 50;
