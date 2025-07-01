// src/platform/windows.rs

use crate::ata::{IdentifyDeviceData, SmartDataBlock};
use crate::error::SmartError;
use crate::nvme::NvmeSmartLog;
use crate::{Device, SmartHealth};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;

// --- Imports as provided by you ---
use windows_sys::Win32::{
    Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE},
    Security::SECURITY_ATTRIBUTES, // Note: This import is unused in the provided code
    Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
    System::IO::DeviceIoControl,
    System::Ioctl::{
        IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_PROTOCOL_SPECIFIC_DATA,
        STORAGE_PROTOCOL_DATA_DESCRIPTOR, ProtocolTypeAta, ProtocolTypeNvme,
        AtaDataTypeIdentify, STORAGE_PROPERTY_QUERY, STORAGE_QUERY_TYPE,
        STORAGE_PROPERTY_ID, StorageDeviceProperty, PropertyStandardQuery, IDEREGS, // Note: IDEREGS is unused
    },
};

const ATA_IDENTIFY_DEVICE: u8 = 0xEC;
const ATA_SMART_CMD: u8 = 0xB0;
const SMART_READ_DATA: u8 = 0xD0;
const NVME_ADMIN_GET_LOG_PAGE: u8 = 0x02;
const NVME_LOG_SMART_INFO: u32 = 0x02;

struct WindowsDeviceHandle(HANDLE);
impl Drop for WindowsDeviceHandle { fn drop(&mut self) { if self.0 != INVALID_HANDLE_VALUE { unsafe { CloseHandle(self.0) }; } } }

pub fn discover_and_collect() -> Result<Vec<Device>, SmartError> {
    println!("[DEBUG] Starting Windows device discovery...");
    let mut devices = Vec::new();
    for i in 0..16 {
        let path_str = format!("\\\\.\\PhysicalDrive{}", i);
        println!("[DEBUG] Probing device path: {}", path_str);

        match open_device(&path_str) {
            Ok(handle) => {
                println!("[DEBUG]   Successfully opened handle for {}.", path_str);
                // Try NVMe first.
                println!("[DEBUG]   Attempting NVMe protocol...");
                match collect_nvme_data(&handle, &path_str) {
                    Ok(nvme_device) => {
                        println!("[DEBUG]   SUCCESS: Found NVMe device.");
                        devices.push(nvme_device);
                    },
                    Err(e) => {
                        // This is often an expected failure if the drive is ATA, so we log it and continue.
                        eprintln!("[DEBUG]   NVMe probe failed for {}: {}. Falling back to ATA protocol.", path_str, e);
                        
                        // Fallback to ATA.
                        println!("[DEBUG]   Attempting ATA protocol...");
                        match collect_ata_data(&handle, &path_str) {
                            Ok(ata_device) => {
                                println!("[DEBUG]   SUCCESS: Found ATA device.");
                                devices.push(ata_device);
                            },
                            Err(e) => {
                                eprintln!("[DEBUG]   ATA probe also failed for {}: {}. Skipping device.", path_str, e);
                            }
                        }
                    }
                }
            },
            Err(_) => {
                // This is an expected failure when we reach the last drive.
                // We can stop searching.
                println!("[DEBUG] Could not open {}. Assuming no more drives.", path_str);
                break;
            }
        }
    }
    println!("[DEBUG] Windows device discovery finished. Found {} supported device(s).", devices.len());
    Ok(devices)
}

fn open_device(path: &str) -> Result<WindowsDeviceHandle, SmartError> {
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe { CreateFileW(wide_path.as_ptr(),
                0, // Using the 0 access right from your provided code
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),) };
    if handle == INVALID_HANDLE_VALUE { Err(SmartError::IoError(std::io::Error::last_os_error())) } else { Ok(WindowsDeviceHandle(handle)) }
}

fn collect_nvme_data(handle: &WindowsDeviceHandle, path: &str) -> Result<Device, SmartError> {
    let log_page = send_nvme_command(handle)?;
    println!("[DEBUG]     Successfully received NVMe SMART log page.");
    
    let model = "NVMe SSD (Model N/A)".to_string();
    let serial = "N/A".to_string();

    let health = SmartHealth {
        temperature_celsius: Some(u16::from_le_bytes(log_page.temperature) as i64 - 273),
        percentage_used: Some(log_page.percentage_used),
        power_on_hours: Some(u128::from_le_bytes(log_page.power_on_hours) as i64),
        power_cycles: Some(u128::from_le_bytes(log_page.power_cycles) as i64),
        unsafe_shutdowns: Some(u128::from_le_bytes(log_page.unsafe_shutdowns) as i64),
        ..Default::default()
    };
    Ok(Device { path: path.into(), model, serial, health_info: health })
}

fn send_nvme_command(handle: &WindowsDeviceHandle) -> Result<NvmeSmartLog, SmartError> {
    let input_buffer_size = size_of::<STORAGE_PROPERTY_QUERY>() + size_of::<STORAGE_PROTOCOL_SPECIFIC_DATA>();
    let mut input_buffer: Vec<u8> = vec![0; input_buffer_size];
    let query = input_buffer.as_mut_ptr() as *mut STORAGE_PROPERTY_QUERY;
    unsafe { (*query).PropertyId = StorageDeviceProperty; (*query).QueryType = PropertyStandardQuery; }
    let protocol_data = unsafe { input_buffer.as_mut_ptr().add(size_of::<STORAGE_PROPERTY_QUERY>()) as *mut STORAGE_PROTOCOL_SPECIFIC_DATA };
    unsafe {
        (*protocol_data).ProtocolType = ProtocolTypeNvme;
        (*protocol_data).DataType = 1; // StorageDataTypeProtocol
        (*protocol_data).ProtocolDataRequestValue = NVME_ADMIN_GET_LOG_PAGE as u32;
        let numd = (size_of::<NvmeSmartLog>() / 4 - 1) as u32;
        (*protocol_data).ProtocolDataRequestSubValue = NVME_LOG_SMART_INFO | (numd << 16);
    }

    let output_buffer_size = size_of::<STORAGE_PROTOCOL_DATA_DESCRIPTOR>() + size_of::<NvmeSmartLog>();
    let mut output_buffer: Vec<u8> = vec![0; output_buffer_size];
    let mut bytes_returned: u32 = 0;
    
    println!("[DEBUG]     Sending NVMe IOCTL_STORAGE_QUERY_PROPERTY...");
    let result = unsafe { DeviceIoControl(handle.0, IOCTL_STORAGE_QUERY_PROPERTY, input_buffer.as_ptr() as _, input_buffer.len() as _, output_buffer.as_mut_ptr() as _, output_buffer.len() as _, &mut bytes_returned, null_mut()) };
    
    if result == 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("[DEBUG]     DeviceIoControl failed for NVMe command: {}", err);
        return Err(SmartError::IoError(err));
    }
    
    if bytes_returned < size_of::<STORAGE_PROTOCOL_DATA_DESCRIPTOR>() as u32 { return Err(SmartError::ParsingError("NVMe IOCTL insufficient data".into())); }
    
    let descriptor = unsafe { &*(output_buffer.as_ptr() as *const STORAGE_PROTOCOL_DATA_DESCRIPTOR) };
    let data_offset = descriptor.ProtocolSpecificData.ProtocolDataOffset as usize;
    if (data_offset + size_of::<NvmeSmartLog>()) > output_buffer.len() { return Err(SmartError::ParsingError("NVMe ProtocolDataOffset out of bounds.".into())); }
    
    let smart_log_ptr = unsafe { output_buffer.as_ptr().add(data_offset) as *const NvmeSmartLog };
    Ok(unsafe { *smart_log_ptr })
}

fn collect_ata_data(handle: &WindowsDeviceHandle, path: &str) -> Result<Device, SmartError> {
    println!("[DEBUG]     Getting ATA IDENTIFY data...");
    let identity = get_ata_identify_data(handle)?;
    println!("[DEBUG]     Getting ATA SMART data...");
    let smart_block = get_ata_smart_data(handle)?;
    
    println!("[DEBUG]     Parsing ATA SMART attributes...");
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
    Ok(Device { path: path.into(), model: identity.model(), serial: identity.serial(), health_info: health })
}

fn send_ata_command(handle: &WindowsDeviceHandle, command: u8, features: u8) -> Result<[u8; 512], SmartError> {
    let input_buffer_size = size_of::<STORAGE_PROPERTY_QUERY>() + size_of::<STORAGE_PROTOCOL_SPECIFIC_DATA>();
    let mut input_buffer: Vec<u8> = vec![0; input_buffer_size];
    let query = input_buffer.as_mut_ptr() as *mut STORAGE_PROPERTY_QUERY;
    unsafe { (*query).PropertyId = StorageDeviceProperty; (*query).QueryType = PropertyStandardQuery; }
    let protocol_data = unsafe { input_buffer.as_mut_ptr().add(size_of::<STORAGE_PROPERTY_QUERY>()) as *mut STORAGE_PROTOCOL_SPECIFIC_DATA };
    unsafe {
        (*protocol_data).ProtocolType = ProtocolTypeAta;
        (*protocol_data).DataType = AtaDataTypeIdentify as u32;
        (*protocol_data).ProtocolDataRequestValue = command as u32;
        (*protocol_data).ProtocolDataRequestSubValue = features as u32;
    }

    let output_buffer_size = size_of::<STORAGE_PROTOCOL_DATA_DESCRIPTOR>() + 512;
    let mut output_buffer: Vec<u8> = vec![0; output_buffer_size];
    let mut bytes_returned: u32 = 0;
    
    println!("[DEBUG]     Sending ATA IOCTL command: 0x{:X}", command);
    let result = unsafe { DeviceIoControl(handle.0, IOCTL_STORAGE_QUERY_PROPERTY, input_buffer.as_ptr() as _, input_buffer.len() as _, output_buffer.as_mut_ptr() as _, output_buffer.len() as _, &mut bytes_returned, null_mut()) };
    
    if result == 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("[DEBUG]     DeviceIoControl failed for ATA command 0x{:X}: {}", command, err);
        return Err(SmartError::IoError(err));
    }

    if bytes_returned < size_of::<STORAGE_PROTOCOL_DATA_DESCRIPTOR>() as u32 { return Err(SmartError::ParsingError("ATA IOCTL insufficient data".into())); }
    
    let descriptor = unsafe { &*(output_buffer.as_ptr() as *const STORAGE_PROTOCOL_DATA_DESCRIPTOR) };
    let data_offset = descriptor.ProtocolSpecificData.ProtocolDataOffset as usize;
    if (data_offset + 512) > output_buffer.len() { return Err(SmartError::ParsingError("ATA ProtocolDataOffset out of bounds.".into())); }
    
    let mut response_data = [0; 512];
    response_data.copy_from_slice(&output_buffer[data_offset..data_offset + 512]);
    Ok(response_data)
}

fn get_ata_identify_data(handle: &WindowsDeviceHandle) -> Result<IdentifyDeviceData, SmartError> {
    send_ata_command(handle, ATA_IDENTIFY_DEVICE, 0).map(|b| unsafe { *(b.as_ptr() as *const _) })
}

fn get_ata_smart_data(handle: &WindowsDeviceHandle) -> Result<SmartDataBlock, SmartError> {
    send_ata_command(handle, ATA_SMART_CMD, SMART_READ_DATA).map(|b| unsafe { *(b.as_ptr() as *const _) })
}