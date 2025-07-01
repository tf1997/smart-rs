//! # smart-rs
//! A pure Rust library for reading disk SMART (Self-Monitoring, Analysis, and Reporting Technology)
//! data without relying on external tools like `smartctl`.
//!
//! ## Current Scope
//! *   **Linux**: Supports NVMe drives.
//! *   **Windows**: Supports ATA/SATA drives (compatible with Windows 7 and later).
//! *   **macOS**: Supports ATA/SATA drives.

pub mod error;
mod ata;
mod nvme;
mod platform;

use error::SmartError;
use std::path::PathBuf;

/// Represents a discovered physical storage device.
#[derive(Debug, Default)]
pub struct Device {
    /// The OS-specific path to the device (e.g., /dev/nvme0, \\.\PhysicalDrive0).
    pub path: PathBuf,
    /// The model number of the device.
    pub model: String,
    /// The serial number of the device.
    pub serial: String,
    /// A consolidated view of the most important health metrics.
    pub health_info: SmartHealth,
}

/// A user-friendly, abstracted view of a device's SMART health.
/// Fields are `Option<i64>` as not all drives report all attributes.
#[derive(Debug, Default)]
pub struct SmartHealth {
    pub temperature_celsius: Option<i64>,
    pub power_on_hours: Option<i64>,
    pub power_cycles: Option<i64>,
    pub reallocated_sectors: Option<i64>,
    pub percentage_used: Option<u8>,
    pub unsafe_shutdowns: Option<i64>,
}

/// Discovers all supported storage devices on the system and retrieves their SMART health information.
///
/// This is the main entry point for the library. It automatically selects the
/// correct backend for the current operating system.
///
/// # Returns
/// A `Result` containing a `Vec` of `Device` structs on success, or a `SmartError` on failure.
///
/// # Permissions
/// This function requires administrator/root privileges to access physical devices.
pub fn discover() -> Result<Vec<Device>, SmartError> {
    platform::discover_and_collect()
}