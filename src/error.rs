use std::fmt;

#[derive(Debug)]
pub enum SmartError {
    IoError(std::io::Error),
    IoctlError(String),
    IoKitError(String),
    DeviceNotFound(String),
    UnsupportedDevice,
    ParsingError(String),
}

impl fmt::Display for SmartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmartError::IoError(e) => write!(f, "I/O Error: {}", e),
            SmartError::IoctlError(s) => write!(f, "Ioctl Error: {}", s),
            SmartError::IoKitError(s) => write!(f, "I/O Kit Framework Error: {}", s),
            SmartError::DeviceNotFound(p) => write!(f, "Device not found: {}", p),
            SmartError::UnsupportedDevice => write!(f, "The device or its protocol is not supported by this library"),
            SmartError::ParsingError(s) => write!(f, "Failed to parse device data: {}", s),
        }
    }
}

impl std::error::Error for SmartError {}

impl From<std::io::Error> for SmartError {
    fn from(err: std::io::Error) -> Self {
        SmartError::IoError(err)
    }
}