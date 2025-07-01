// src/platform/windows.rs

use crate::ata::{IdentifyDeviceData, SmartDataBlock};
use crate::error::SmartError;
use crate::{Device, SmartHealth};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;

// --- Imports are correct from the previous, verified step ---
use windows_sys::Win32::{
    Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
    System::IO::DeviceIoControl,
    System::Ioctl::{
        IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_PROTOCOL_SPECIFIC_DATA,
        STORAGE_PROTOCOL_DATA_DESCRIPTOR, ProtocolTypeAta, AtaDataTypeIdentify,
        STORAGE_PROPERTY_QUERY, STORAGE_QUERY_TYPE, STORAGE_PROPERTY_ID,
        StorageDeviceProperty, PropertyStandardQuery,
    },
};

const ATA_IDENTIFY_DEVICE: u8 = 0xEC;
const ATA_SMART_CMD: u8 = 0xB0;
const SMART_READ_DATA: u8 = 0xD0;

struct WindowsDeviceHandle(HANDLE);
impl Drop for WindowsDeviceHandle { fn drop(&mut self) { if self.0 != INVALID_HANDLE_VALUE { unsafe { CloseHandle(self.0) }; } } }

pub fn discover_and_collect() -> Result<Vec<Device>, SmartError> {
    let mut devices = Vec::new();
    println!("[Debug] Starting device discovery loop on Windows...");

    for i in 0..16 {
        let path_str = format!("\\\\.\\PhysicalDrive{}", i);
        
        // Step 1: Try to open the device.
        match open_device(&path_str) {
            Ok(handle) => {
                println!("[Debug] Successfully opened handle for {}.", path_str);
                
                // Step 2: Try to get IDENTIFY data. This also verifies it's an ATA device.
                match get_identify_data(&handle) {
                    Ok(identity) => {
                        println!("[Debug] IDENTIFY success for {}. Model: {}", path_str, identity.model().trim());
                        
                        // Step 3: If IDENTIFY works, try to get SMART data.
                        match get_smart_data(&handle) {
                            Ok(smart_block) => {
                                println!("[SUCCESS] Successfully retrieved SMART data for {}. Adding to device list.", path_str);
                                let mut health = SmartHealth::default();
                                for attr in smart_block.attributes.iter() {
                                    if attr.id == 0 { continue; }
                                    match attr.id {
                                        5 => health.reallocated_sectors = Some(attr.raw_value()),
                                        9 => health.power_on_hours = Some(attr.raw_value()),
                                        12 => health.power_cycles = Some(attr.raw_value()),
                                        194 => health.temperature_celsius = Some(attr.raw_value()),
                                        _ => (),
                                    }
                                }
                                devices.push(Device {
                                    path: path_str.into(), model: identity.model(), serial: identity.serial(), health_info: health,
                                });
                            },
                            Err(e) => {
                                eprintln!("[Warning] Could not get SMART data from {}: {}. This device might not support SMART.", path_str, e);
                            }
                        }
                    },
                    Err(e) => {
                        // This failure is expected for non-ATA drives like NVMe or USB.
                        println!("[Info] Could not get IDENTIFY data from {}: {}. Skipping as it is likely not a supported ATA/SATA drive.", path_str, e);
                    }
                }
            },
            Err(e) => {
                if i < 2 { // Only print errors for the first few likely drives to avoid clutter.
                    eprintln!("[Debug] Failed to open {}: {}. This is the most common point of failure (Permissions?).", path_str, e);
                } else {
                    // We've likely just run out of devices to find.
                    break;
                }
            }
        }
    }
    println!("[Debug] Device discovery loop finished. Found {} supported devices.", devices.len());
    Ok(devices)
}

fn open_device(path: &str) -> Result<WindowsDeviceHandle, SmartError> {
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe { CreateFileW(  wide_path.as_ptr(),
                0, // No read/write access is needed for this query.
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),) };
    if handle == INVALID_HANDLE_VALUE { Err(SmartError::IoError(std::io::Error::last_os_error())) } else { Ok(WindowsDeviceHandle(handle)) }
}

/// Sends an ATA command using the IOCTL_STORAGE_QUERY_PROPERTY method.
fn send_ata_command(handle: &WindowsDeviceHandle, command: u8, features: u8, data_type: u32) -> Result<[u8; 512], SmartError> {
    let input_buffer_size = size_of::<STORAGE_PROPERTY_QUERY>() + size_of::<STORAGE_PROTOCOL_SPECIFIC_DATA>();
    let mut input_buffer: Vec<u8> = vec![0; input_buffer_size];
    
    let query = input_buffer.as_mut_ptr() as *mut STORAGE_PROPERTY_QUERY;
    unsafe {
        (*query).PropertyId = StorageDeviceProperty;
        (*query).QueryType = PropertyStandardQuery;
    }

    let protocol_data = unsafe { input_buffer.as_mut_ptr().add(size_of::<STORAGE_PROPERTY_QUERY>()) as *mut STORAGE_PROTOCOL_SPECIFIC_DATA };
    unsafe {
        (*protocol_data).ProtocolType = ProtocolTypeAta as i32;
        (*protocol_data).DataType = data_type;
        (*protocol_data).ProtocolDataRequestValue = command as u32;
        (*protocol_data).ProtocolDataRequestSubValue = features as u32;
        (*protocol_data).ProtocolDataOffset = 0;
        (*protocol_data).ProtocolDataLength = 0;
    }

    let output_buffer_size = size_of::<STORAGE_PROTOCOL_DATA_DESCRIPTOR>() + 512;
    let mut output_buffer: Vec<u8> = vec![0; output_buffer_size];
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle.0, IOCTL_STORAGE_QUERY_PROPERTY,
            input_buffer.as_ptr() as *const c_void, input_buffer.len() as u32,
            output_buffer.as_mut_ptr() as *mut c_void, output_buffer.len() as u32,
            &mut bytes_returned, null_mut(),
        )
    };

    if result == 0 { return Err(SmartError::IoError(std::io::Error::last_os_error())); }
    if bytes_returned < size_of::<STORAGE_PROTOCOL_DATA_DESCRIPTOR>() as u32 {
        return Err(SmartError::ParsingError("IOCTL returned insufficient data for descriptor.".into()));
    }
    
    let descriptor = unsafe { &*(output_buffer.as_ptr() as *const STORAGE_PROTOCOL_DATA_DESCRIPTOR) };
    let protocol_specific_data = &descriptor.ProtocolSpecificData;
    
    let data_offset = protocol_specific_data.ProtocolDataOffset as usize;
    if (data_offset + 512) > output_buffer.len() {
        return Err(SmartError::ParsingError("ProtocolDataOffset is out of bounds.".into()));
    }

    let mut response_data = [0u8; 512];
    response_data.copy_from_slice(&output_buffer[data_offset..data_offset + 512]);
    Ok(response_data)
}

fn get_identify_data(handle: &WindowsDeviceHandle) -> Result<IdentifyDeviceData, SmartError> {
    send_ata_command(handle, ATA_IDENTIFY_DEVICE, 0, AtaDataTypeIdentify as u32)
        .map(|buffer| unsafe { *(buffer.as_ptr() as *const IdentifyDeviceData) })
}

fn get_smart_data(handle: &WindowsDeviceHandle) -> Result<SmartDataBlock, SmartError> {
    send_ata_command(handle, ATA_SMART_CMD, SMART_READ_DATA, AtaDataTypeIdentify as u32)
        .map(|buffer| unsafe { *(buffer.as_ptr() as *const SmartDataBlock) })
}