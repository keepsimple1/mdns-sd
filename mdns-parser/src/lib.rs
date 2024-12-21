//! DNS parsing utility with a focus on mDNS service discovery.
//!
//! - [DnsIncoming] is the logic representation of an incoming DNS message.
//! - [DnsOutgoing] is the logic representation of an outgoing DNS message.

// log for logging (optional).
#[cfg(feature = "logging")]
use log::trace;

#[cfg(not(feature = "logging"))]
#[macro_use]
mod log {
    macro_rules! trace {
        ($($arg:expr),*) => {
            {
                let _ = ($($arg),*); // avoid warnings about unused variables.
            }
        };
    }
}

mod dns_parser;

pub use dns_parser::{
    ip_address_rr_type, DnsAddress, DnsEntryExt, DnsIncoming, DnsNSec, DnsOutgoing, DnsPointer,
    DnsRecordBox, DnsRecordExt, DnsSrv, DnsTxt, RRType, TxtProperty, CLASS_CACHE_FLUSH, CLASS_IN,
    FLAGS_AA, FLAGS_QR_QUERY, FLAGS_QR_RESPONSE, MAX_MSG_ABSOLUTE,
};
