use std::fmt;
use std::io;

#[derive(Debug)]
pub enum PyzorError {
    Comm(String),
    Protocol(String),
    Timeout(String),
    IncompleteMessage(String),
    UnsupportedVersion(String),
    Signature(String),
    Authorization(String),
    Io(io::Error),
}

impl PyzorError {
    pub fn code(&self) -> u16 {
        match self {
            Self::Timeout(_) => 504,
            Self::UnsupportedVersion(_) => 505,
            Self::Signature(_) => 401,
            Self::Authorization(_) => 403,
            Self::Comm(_) | Self::Protocol(_) | Self::IncompleteMessage(_) | Self::Io(_) => 400,
        }
    }
}

impl fmt::Display for PyzorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Comm(message)
            | Self::Protocol(message)
            | Self::Timeout(message)
            | Self::IncompleteMessage(message)
            | Self::UnsupportedVersion(message)
            | Self::Signature(message)
            | Self::Authorization(message) => f.write_str(message),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for PyzorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for PyzorError {
    fn from(value: io::Error) -> Self {
        if value.kind() == io::ErrorKind::TimedOut {
            Self::Timeout(value.to_string())
        } else {
            Self::Io(value)
        }
    }
}
