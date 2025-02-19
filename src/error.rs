use std::fmt;

/// A basic error type from this library.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Like a classic EAGAIN. The receiver should retry.
    Again,

    /// A generic error message.
    Msg(String),

    /// Error during parsing of ip address
    ParseIpAddr(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Msg(s) => write!(f, "{}", s),
            Self::ParseIpAddr(s) => write!(f, "parsing of ip addr failed, reason: {}", s),
            Self::Again => write!(f, "try again"),
        }
    }
}

impl std::error::Error for Error {}

/// One and only `Result` type from this library crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A simple macro to report all kinds of errors.
macro_rules! e_fmt {
    ($($arg:tt)+) => {
        Error::Msg(format!($($arg)+))
    };
  }

pub(crate) use e_fmt;
