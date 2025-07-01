// src/platform/macos.rs

use crate::error::SmartError;
use crate::{Device, SmartHealth};
use std::process::Command;

/// The main public function for macOS, using the built-in `diskutil`.
pub fn discover_and_collect() -> Result<Vec<Device>, SmartError> {
    // Step 1: Execute `diskutil list` to find all whole disk identifiers.
    let list_output = Command::new("diskutil")
        .arg("list")
        .output()
        .map_err(|e| SmartError::IoError(e))?;
    
    if !list_output.status.success() {
        let stderr = String::from_utf8_lossy(&list_output.stderr);
        return Err(SmartError::IoKitError(format!("'diskutil list' failed: {}", stderr)));
    }
    
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    let mut device_ids = Vec::new();

    for line in list_stdout.lines() {
        if line.starts_with("/dev/disk") {
            if let Some(id) = line.split_whitespace().next() {
                // Use the corrected logic to filter out partitions (e.g., /dev/disk0s1).
                if !is_partition(id) {
                    device_ids.push(id.to_string());
                }
            }
        }
    }
    
    if device_ids.is_empty() {
        return Ok(Vec::new());
    }
    println!("Found devices via diskutil: {:?}", device_ids);

    // Step 2: For each disk, execute `diskutil info` to get its details.
    let mut devices = Vec::new();
    for id in device_ids {
        let info_output = Command::new("diskutil")
            .args(&["info", &id])
            .output()
            .map_err(|e| SmartError::IoError(e))?;
        
        if !info_output.status.success() { continue; }

        let info_stdout = String::from_utf8_lossy(&info_output.stdout);
        let mut model = "N/A".to_string();
        let mut serial = "N/A".to_string();
        let mut status = "N/A".to_string();

        for line in info_stdout.lines() {
            if let Some((key, val)) = line.split_once(':') {
                let key = key.trim();
                let val = val.trim().to_string();
                match key {
                    "Device / Media Name" => model = val,
                    "Serial Number" => serial = val,
                    "SMART Status" => status = val,
                    _ => {}
                }
            }
        }

        // `diskutil` only provides a simple pass/fail status.
        // We cannot get temperature or other specific attributes.
        let health_ok = if status.eq_ignore_ascii_case("verified") { 1 } else { 0 };
        
        devices.push(Device {
            path: id.into(),
            model,
            serial,
            health_info: SmartHealth {
                // Set all detailed metrics to None, as they are unavailable.
                temperature_celsius: None,
                power_on_hours: None,
                power_cycles: None,
                reallocated_sectors: None,
                percentage_used: None,
                unsafe_shutdowns: None,
            },
        });
    }
    Ok(devices)
}

/// Helper function to determine if a device identifier represents a partition.
fn is_partition(device_id: &str) -> bool {
    if let Some(after_disk) = device_id.strip_prefix("/dev/disk") {
        if let Some(s_index) = after_disk.find('s') {
            let slice_part = &after_disk[s_index + 1..];
            return !slice_part.is_empty() && slice_part.chars().all(char::is_numeric);
        }
    }
    false
}