use molecule::error::VerificationError;
use std::{error, fmt};

use ckb_testtool::ckb_error;

#[derive(Debug)]
pub struct Error {
    details: String,
}

impl Error {
    pub fn new(msg: &str) -> Error {
        Error {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        &self.details
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Error {
        Error::new(err)
    }
}

impl From<ckb_occupied_capacity::Error> for Error {
    fn from(err: ckb_occupied_capacity::Error) -> Error {
        Error::new(&err.to_string())
    }
}

impl From<ckb_error::Error> for Error {
    fn from(err: ckb_error::Error) -> Error {
        Error::new(&err.to_string())
    }
}

impl From<k256::ecdsa::Error> for Error {
    fn from(err: k256::ecdsa::Error) -> Error {
        Error::new(&err.to_string())
    }
}

impl From<VerificationError> for Error {
    fn from(err: VerificationError) -> Error {
        Error::new(&err.to_string())
    }
}

impl From<Vec<Vec<u8>>> for Error {
    fn from(vs: Vec<Vec<u8>>) -> Error {
        Error::new(&format!("converting from nested vectors: {:?}", vs))
    }
}
