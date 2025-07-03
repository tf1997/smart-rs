// src/platform/windows.rs

use crate::ata::{IdentifyDeviceData, SmartDataBlock};
use crate::error::SmartError;
use crate::nvme::NvmeSmartLog;
use crate::{Device, SmartHealth};
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;

// Using the correct, verified import paths
use windows_sys::Win32::{
    Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
    System::IO::DeviceIoControl,
    // --- Import all necessary IOCTLs and structures ---
    System::Ioctl::{
        // Modern IOCTL_STORAGE_QUERY_PROPERTY
        IOCTL_STORAGE_QUERY_PROPERTY,
        STORAGE_PROTOCOL_DATA_DESCRIPTOR,
        STORAGE_PROTOCOL_SPECIFIC_DATA,
        STORAGE_PROPERTY_QUERY,
        StorageAdapterProtocolSpecificProperty,
        PropertyStandardQuery,
        ProtocolTypeAta,
        ProtocolTypeNvme,
        AtaDataTypeIdentify,
        NVMeDataTypeLogPage,

        // Classic SMART IOCTLs from ntdddisk.h
        SMART_RCV_DRIVE_DATA,
        IDEREGS,
        SENDCMDINPARAMS,
        SENDCMDOUTPARAMS,
    },
    Storage::IscsiDisc::{
        IOCTL_ATA_PASS_THROUGH,
        ATA_PASS_THROUGH_EX,
        // SCSI Pass-Through IOCTLs (structs and data directions)
        IOCTL_SCSI_PASS_THROUGH_DIRECT,
        SCSI_PASS_THROUGH_DIRECT,
        SCSI_IOCTL_DATA_IN,
    },
};

// SCSI command constants
const SCSI_INQUIRY: u8 = 0x12;
const SCSI_LOG_SENSE: u8 = 0x4D;
const SCSI_VPD_PAGE_DEVICE_IDENTIFICATION: u8 = 0x83;
const SCSI_LOG_PAGE_INFORMATIONAL_EXCEPTIONS: u8 = 0x1C;
const SCSI_LOG_PAGE_TEMPERATURE: u8 = 0x0D;
const SCSI_LOG_PAGE_SELF_TEST_RESULTS: u8 = 0x10;
const SCSI_SENSE_BUFFER_SIZE: u32 = 32; // Common size for SCSI sense data
const SCSI_INQUIRY_DATA_SIZE: u32 = 256; // Common size for Inquiry data
const SCSI_LOG_SENSE_DATA_SIZE: u32 = 512; // Common size for Log Sense data
const SCSI_STATUS_CHECK_CONDITION: u8 = 0x02; // Manually defined, as it's not in windows-sys::Win32::System::Ioctl

// ATA/NVMe command constants
const ATA_IDENTIFY_DEVICE: u8 = 0xEC;
const ATA_SMART_CMD: u8 = 0xB0;
const SMART_READ_DATA: u8 = 0xD0;
const NVME_ADMIN_GET_LOG_PAGE: u8 = 0x02;
const NVME_LOG_SMART_INFO: u32 = 0x02;

struct WindowsDeviceHandle(HANDLE);
impl Drop for WindowsDeviceHandle { fn drop(&mut self) { if self.0 != INVALID_HANDLE_VALUE { unsafe { CloseHandle(self.0) }; } } }

pub fn discover_and_collect() -> Result<Vec<Device>, SmartError> {
    println!("[DEBUG] Starting Windows device discovery (smartmontools strategy)...");
    let mut devices = Vec::new();
    for i in 0..16 {
        let path_str = format!("\\\\.\\PhysicalDrive{}", i);
        println!("[DEBUG] Probing device path: {}", path_str);
        
        match open_device(&path_str) {
            Ok(handle) => {
                println!("[DEBUG]   Successfully opened handle for {}.", path_str);
                
                // The collection function now contains the full fallback logic.
                // We try ATA first as it's the most common for PhysicalDrive paths.
                if let Ok(ata_device) = collect_ata_data(&handle, &path_str) {
                    println!("[DEBUG]   SUCCESS: Found and identified ATA/SATA device.");
                    devices.push(ata_device);
                } 
                // If ATA fails, we can try NVMe.
                else if let Ok(nvme_device) = collect_nvme_data(&handle, &path_str) {
                    println!("[DEBUG]   SUCCESS: Found and identified NVMe device.");
                    devices.push(nvme_device);
                }
                // If both ATA and NVMe fail, try SCSI.
                else if let Ok(scsi_device) = collect_scsi_data(&handle, &path_str) {
                    println!("[DEBUG]   SUCCESS: Found and identified SCSI device.");
                    devices.push(scsi_device);
                }
                else {
                    eprintln!("[DEBUG]   Failed to identify device {} with any known protocol. Skipping.", path_str);
                }
            },
            Err(e) => {
                println!("[DEBUG] Could not open {}: {}. Assuming no more drives.", path_str, e);
                break;
            }
        }
    }
    println!("[DEBUG] Windows device discovery finished. Found {} supported device(s).", devices.len());
    Ok(devices)
}

fn open_device(path: &str) -> Result<WindowsDeviceHandle, SmartError> {
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    // First, try to open with read/write access (requires admin)
    let mut handle = unsafe { CreateFileW(
        wide_path.as_ptr(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        null_mut(),
        OPEN_EXISTING,
        0,
        null_mut()
    ) };

    // If the first attempt fails with "Access Denied", try opening with no access rights.
    // This allows some IOCTLs to still succeed without admin privileges.
    if handle == INVALID_HANDLE_VALUE {
        let last_error = std::io::Error::last_os_error();
        if last_error.raw_os_error() == Some(5) { // ERROR_ACCESS_DENIED
            println!("[DEBUG]   Access denied. Retrying with limited access rights...");
            handle = unsafe { CreateFileW(
                wide_path.as_ptr(),
                0, // No access rights
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut()
            ) };
        }
    }

    if handle == INVALID_HANDLE_VALUE { 
        Err(SmartError::IoError(std::io::Error::last_os_error())) 
    } else { 
        Ok(WindowsDeviceHandle(handle)) 
    }
}

// =================================================================================
// --- ATA/SATA Collection with REVISED Fallback Logic ---
// =================================================================================

fn collect_ata_data(handle: &WindowsDeviceHandle, path: &str) -> Result<Device, SmartError> {
    println!("[DEBUG]   Attempting ATA protocol for {}", path);

    // --- REVISED Fallback Strategy (mimicking smartmontools) ---
    // 1. Classic (SMART_RCV_DRIVE_DATA): Most compatible.
    // 2. Legacy (IOCTL_ATA_PASS_THROUGH): Powerful, second best.
    // 3. Modern (IOCTL_STORAGE_QUERY_PROPERTY): High-level, least reliable for raw commands.

    println!("[DEBUG]     Attempting CLASSIC SMART IOCTL...");
    if let Ok(identity_bytes) = send_ata_command_smart_ioctl(handle, ATA_IDENTIFY_DEVICE, 0) {
        println!("[DEBUG]       -> Classic IDENTIFY command SUCCEEDED.");
        if let Ok(smart_bytes) = send_ata_command_smart_ioctl(handle, ATA_SMART_CMD, SMART_READ_DATA) {
            println!("[DEBUG]       -> Classic SMART command SUCCEEDED.");
            return parse_ata_data(identity_bytes, smart_bytes, path);
        } else {
            eprintln!("[DEBUG]       -> Classic SMART command FAILED. Continuing fallback.");
        }
    } else {
        eprintln!("[DEBUG]       -> Classic IDENTIFY command FAILED. Falling back.");
    }

    println!("[DEBUG]     Attempting LEGACY ATA IOCTL...");
    if let Ok(identity_bytes) = send_ata_command_legacy(handle, ATA_IDENTIFY_DEVICE, 0) {
        println!("[DEBUG]       -> Legacy IDENTIFY command SUCCEEDED.");
        if let Ok(smart_bytes) = send_ata_command_legacy(handle, ATA_SMART_CMD, SMART_READ_DATA) {
            println!("[DEBUG]       -> Legacy SMART command SUCCEEDED.");
            return parse_ata_data(identity_bytes, smart_bytes, path);
        } else {
            eprintln!("[DEBUG]       -> Legacy SMART command FAILED. Continuing fallback.");
        }
    } else {
        eprintln!("[DEBUG]       -> Legacy IDENTIFY command FAILED. Falling back.");
    }
    
    println!("[DEBUG]     Attempting MODERN ATA IOCTL...");
    if let Ok(identity_bytes) = send_ata_command_modern(handle, ATA_IDENTIFY_DEVICE, 0) {
        println!("[DEBUG]       -> Modern IDENTIFY command SUCCEEDED.");
        if let Ok(smart_bytes) = send_ata_command_modern(handle, ATA_SMART_CMD, SMART_READ_DATA) {
            println!("[DEBUG]       -> Modern SMART command SUCCEEDED.");
            return parse_ata_data(identity_bytes, smart_bytes, path);
        } else {
            eprintln!("[DEBUG]       -> Modern SMART command FAILED. All methods failed.");
        }
    } else {
        eprintln!("[DEBUG]       -> Modern IDENTIFY command FAILED. All methods failed.");
    }

    Err(SmartError::UnsupportedDevice)
}

/// Helper function to parse data once it has been successfully retrieved by any method.
fn parse_ata_data(identity_bytes: [u8; 512], smart_bytes: [u8; 512], path: &str) -> Result<Device, SmartError> {
    let identity: IdentifyDeviceData = unsafe { *(identity_bytes.as_ptr() as *const _) };
    let smart_block: SmartDataBlock = unsafe { *(smart_bytes.as_ptr() as *const _) };

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

// --- NEW: Classic SMART IOCTL Method ---
fn send_ata_command_smart_ioctl(handle: &WindowsDeviceHandle, command: u8, features: u8) -> Result<[u8; 512], SmartError> {
    let mut in_params: SENDCMDINPARAMS = unsafe { zeroed() };
    in_params.cBufferSize = 512;
    
    let mut regs: IDEREGS = unsafe { zeroed() };
    regs.bCommandReg = command;
    regs.bFeaturesReg = features;
    // Required for SMART commands
    if command == ATA_SMART_CMD {
        regs.bCylLowReg = 0x4F;
        regs.bCylHighReg = 0xC2;
    }
    // Set drive select to master (obsolete but required by some old drivers)
    regs.bDriveHeadReg = 0xA0;

    in_params.irDriveRegs = regs;

    // The output buffer needs to hold the SENDCMDOUTPARAMS struct AND the 512-byte data block.
    let mut out_buffer: Vec<u8> = vec![0; size_of::<SENDCMDOUTPARAMS>() - 1 + 512];
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle.0,
            SMART_RCV_DRIVE_DATA, // This IOCTL is for reading data
            &in_params as *const _ as _,
            size_of::<SENDCMDINPARAMS>() as u32 -1, // Per MS docs, size is struct minus placeholder buffer
            out_buffer.as_mut_ptr() as _,
            out_buffer.len() as u32,
            &mut bytes_returned,
            null_mut(),
        )
    };

    if result == 0 {
        return Err(SmartError::IoError(std::io::Error::last_os_error()));
    }

    let out_params = unsafe { &*(out_buffer.as_ptr() as *const SENDCMDOUTPARAMS) };

    if out_params.DriverStatus.bDriverError != 0 {
        return Err(SmartError::AtaError(out_params.DriverStatus.bIDEError));
    }

    let mut response_data = [0; 512];
    response_data.copy_from_slice(&out_params.bBuffer[..512]);
    Ok(response_data)
}


// --- Modern ATA IOCTL Method ---
fn send_ata_command_modern(handle: &WindowsDeviceHandle, command: u8, features: u8) -> Result<[u8; 512], SmartError> {
    let mut input_buffer: Vec<u8> = vec![0; size_of::<STORAGE_PROPERTY_QUERY>() + size_of::<STORAGE_PROTOCOL_SPECIFIC_DATA>()];
    let query = input_buffer.as_mut_ptr() as *mut STORAGE_PROPERTY_QUERY;
    unsafe { (*query).PropertyId = StorageAdapterProtocolSpecificProperty; (*query).QueryType = PropertyStandardQuery; }
    
    let protocol_data_ptr = unsafe { (query as *mut u8).add(size_of::<STORAGE_PROPERTY_QUERY>()) as *mut STORAGE_PROTOCOL_SPECIFIC_DATA };
    let protocol_data = unsafe { &mut *protocol_data_ptr };

    protocol_data.ProtocolType = ProtocolTypeAta;
    protocol_data.DataType = if command == ATA_IDENTIFY_DEVICE {
        AtaDataTypeIdentify as u32
    } else {
        2 // AtaDataTypeSmartData, not always defined in win-sys, but value is 2
    };
    protocol_data.ProtocolDataRequestValue = command as u32;
    // For SMART commands, some drivers expect the magic numbers in the SubValue field.
    if command == ATA_SMART_CMD {
        protocol_data.ProtocolDataRequestSubValue = features as u32 | (0x4F_u32 << 8) | (0xC2_u32 << 16);
    } else {
        protocol_data.ProtocolDataRequestSubValue = features as u32;
    }
    protocol_data.ProtocolDataOffset = 0;
    protocol_data.ProtocolDataLength = 0;

    let mut output_buffer: Vec<u8> = vec![0; size_of::<STORAGE_PROTOCOL_DATA_DESCRIPTOR>() + 512];
    let mut bytes_returned: u32 = 0;
    let result = unsafe { DeviceIoControl(handle.0, IOCTL_STORAGE_QUERY_PROPERTY, input_buffer.as_ptr() as _, input_buffer.len() as _, output_buffer.as_mut_ptr() as _, output_buffer.len() as _, &mut bytes_returned, null_mut()) };
    if result == 0 { return Err(SmartError::IoError(std::io::Error::last_os_error())); }
    
    let descriptor = unsafe { &*(output_buffer.as_ptr() as *const STORAGE_PROTOCOL_DATA_DESCRIPTOR) };
    let data_offset = descriptor.ProtocolSpecificData.ProtocolDataOffset as usize;
    if (data_offset + 512) > output_buffer.len() { return Err(SmartError::ParsingError("Modern ATA: ProtocolDataOffset out of bounds.".into())); }
    
    let mut response_data = [0; 512];
    response_data.copy_from_slice(&output_buffer[data_offset..data_offset + 512]);
    Ok(response_data)
}

// --- Legacy ATA IOCTL Method ---
fn send_ata_command_legacy(handle: &WindowsDeviceHandle, command: u8, features: u8) -> Result<[u8; 512], SmartError> {
    let mut buffer: Vec<u8> = vec![0; size_of::<ATA_PASS_THROUGH_EX>() + 512];
    let apt = buffer.as_mut_ptr() as *mut ATA_PASS_THROUGH_EX;
    unsafe {
        (*apt).Length = size_of::<ATA_PASS_THROUGH_EX>() as u16;
        (*apt).AtaFlags = 0x08; // ATA_FLAGS_DATA_IN
        (*apt).DataTransferLength = 512;
        (*apt).TimeOutValue = 10;
        (*apt).DataBufferOffset = size_of::<ATA_PASS_THROUGH_EX>() as _;
        let regs: *mut IDEREGS = (*apt).CurrentTaskFile.as_mut_ptr() as *mut IDEREGS;
        (*regs).bFeaturesReg = features;
        if command == ATA_SMART_CMD { 
            (*regs).bCylLowReg = 0x4F; 
            (*regs).bCylHighReg = 0xC2; 
        }
        (*regs).bDriveHeadReg = 0xA0; // Set drive select to master
        (*regs).bCommandReg = command;
    }
    let mut bytes_returned = 0;
    let result = unsafe { DeviceIoControl(handle.0, IOCTL_ATA_PASS_THROUGH, buffer.as_mut_ptr() as _, buffer.len() as _, buffer.as_mut_ptr() as _, buffer.len() as _, &mut bytes_returned, null_mut()) };
    if result == 0 { return Err(SmartError::IoError(std::io::Error::last_os_error())); }
    let mut response_data = [0; 512];
    let data_ptr = unsafe { buffer.as_ptr().add(size_of::<ATA_PASS_THROUGH_EX>()) };
    response_data.copy_from_slice(unsafe { std::slice::from_raw_parts(data_ptr, 512) });
    Ok(response_data)
}


// =================================================================================
// --- NVMe Collection (No fallback needed, only one method) ---
// =================================================================================

fn collect_nvme_data(handle: &WindowsDeviceHandle, path: &str) -> Result<Device, SmartError> {
    println!("[DEBUG]   Attempting NVMe protocol for {}", path);
    let log_page = send_nvme_command_modern(handle)?;
    let health = SmartHealth {
        temperature_celsius: Some(u16::from_le_bytes(log_page.temperature) as i64 - 273),
        percentage_used: Some(log_page.percentage_used),
        power_on_hours: Some(u128::from_le_bytes(log_page.power_on_hours) as i64),
        power_cycles: Some(u128::from_le_bytes(log_page.power_cycles) as i64),
        unsafe_shutdowns: Some(u128::from_le_bytes(log_page.unsafe_shutdowns) as i64),
        ..Default::default()
    };
    Ok(Device { path: path.into(), model: "NVMe SSD (Modern IOCTL)".to_string(), serial: "N/A".to_string(), health_info: health })
}

fn send_nvme_command_modern(handle: &WindowsDeviceHandle) -> Result<NvmeSmartLog, SmartError> {
    let mut input_buffer: Vec<u8> = vec![0; size_of::<STORAGE_PROPERTY_QUERY>() + size_of::<STORAGE_PROTOCOL_SPECIFIC_DATA>()];
    let query = input_buffer.as_mut_ptr() as *mut STORAGE_PROPERTY_QUERY;
    unsafe { (*query).PropertyId = StorageAdapterProtocolSpecificProperty; (*query).QueryType = PropertyStandardQuery; }
    let protocol_data = unsafe { &mut *((query as *mut u8).add(size_of::<STORAGE_PROPERTY_QUERY>()) as *mut STORAGE_PROTOCOL_SPECIFIC_DATA) };
    
    protocol_data.ProtocolType = ProtocolTypeNvme;
    protocol_data.DataType = NVMeDataTypeLogPage as u32;
    protocol_data.ProtocolDataRequestValue = NVME_ADMIN_GET_LOG_PAGE as u32;
    let numd = (size_of::<NvmeSmartLog>() as u32 / 4) - 1;
    protocol_data.ProtocolDataRequestSubValue = NVME_LOG_SMART_INFO | (numd << 16);
    protocol_data.ProtocolDataOffset = 0; 
    protocol_data.ProtocolDataLength = 0;
    
    let mut output_buffer: Vec<u8> = vec![0; size_of::<STORAGE_PROTOCOL_DATA_DESCRIPTOR>() + size_of::<NvmeSmartLog>()];
    let mut bytes_returned: u32 = 0;
    let result = unsafe { DeviceIoControl(handle.0, IOCTL_STORAGE_QUERY_PROPERTY, input_buffer.as_ptr() as _, input_buffer.len() as _, output_buffer.as_mut_ptr() as _, output_buffer.len() as _, &mut bytes_returned, null_mut()) };
    if result == 0 { return Err(SmartError::IoError(std::io::Error::last_os_error())); }
    
    let descriptor = unsafe { &*(output_buffer.as_ptr() as *const STORAGE_PROTOCOL_DATA_DESCRIPTOR) };
    let data_offset = descriptor.ProtocolSpecificData.ProtocolDataOffset as usize;
    if (data_offset + size_of::<NvmeSmartLog>()) > output_buffer.len() { return Err(SmartError::ParsingError("NVMe ProtocolDataOffset out of bounds".into())); }
    
    Ok(unsafe { *(output_buffer.as_ptr().add(data_offset) as *const NvmeSmartLog) })
}

// =================================================================================
// --- NEW: SCSI Collection ---
// =================================================================================

fn collect_scsi_data(handle: &WindowsDeviceHandle, path: &str) -> Result<Device, SmartError> {
    println!("[DEBUG]   Attempting SCSI protocol for {}", path);

    // 1. INQUIRY command to get basic device info
    let mut inquiry_data = vec![0; SCSI_INQUIRY_DATA_SIZE as usize];
    let mut cdb_inquiry = [0; 16]; // SCSI CDB can be up to 16 bytes
    cdb_inquiry[0] = SCSI_INQUIRY;
    cdb_inquiry[4] = SCSI_INQUIRY_DATA_SIZE as u8; // Allocation Length
    
    println!("[DEBUG]     Sending SCSI INQUIRY command...");
    send_scsi_command_direct(
        handle,
        &cdb_inquiry,
        &mut inquiry_data,
        SCSI_IOCTL_DATA_IN,
        SCSI_INQUIRY_DATA_SIZE,
    )?;

    // Extract Vendor, Product, Revision from Inquiry data
    let vendor = String::from_utf8_lossy(&inquiry_data[8..16]).trim().to_string();
    let product = String::from_utf8_lossy(&inquiry_data[16..32]).trim().to_string();
    let revision = String::from_utf8_lossy(&inquiry_data[32..36]).trim().to_string();
    let model = format!("{} {} {}", vendor, product, revision);

    // 2. LOG SENSE command for Informational Exceptions (0x1C)
    let mut ie_log_data = vec![0; SCSI_LOG_SENSE_DATA_SIZE as usize];
    let mut cdb_log_sense_ie = [0; 16];
    cdb_log_sense_ie[0] = SCSI_LOG_SENSE;
    cdb_log_sense_ie[2] = SCSI_LOG_PAGE_INFORMATIONAL_EXCEPTIONS; // Page Code
    cdb_log_sense_ie[7] = (SCSI_LOG_SENSE_DATA_SIZE >> 8) as u8; // Allocation Length MSB
    cdb_log_sense_ie[8] = (SCSI_LOG_SENSE_DATA_SIZE & 0xFF) as u8; // Allocation Length LSB

    println!("[DEBUG]     Sending SCSI LOG SENSE (Informational Exceptions) command...");
    let ie_result = send_scsi_command_direct(
        handle,
        &cdb_log_sense_ie,
        &mut ie_log_data,
        SCSI_IOCTL_DATA_IN,
        SCSI_LOG_SENSE_DATA_SIZE,
    );

    let mut health = SmartHealth::default();
    if let Ok(_) = ie_result {
        // Parse Informational Exceptions Log Page (Mode Page 0x1C)
        // Byte 2 (page 0x1C, byte 2) contains the IEC (Informational Exceptions Control) field.
        // Bit 1 of this field indicates if the device is reporting an impending failure.
        if ie_log_data.len() >= 2 && (ie_log_data[2] & 0x02) != 0 {
            health.overall_health = Some("FAILING".to_string());
        } else {
            health.overall_health = Some("OK".to_string());
        }
        println!("[DEBUG]       -> Informational Exceptions Log Page processed.");
    } else {
        eprintln!("[DEBUG]       -> Failed to get Informational Exceptions Log Page: {:?}", ie_result.err());
    }

    // 3. LOG SENSE command for Temperature (0x0D)
    let mut temp_log_data = vec![0; SCSI_LOG_SENSE_DATA_SIZE as usize];
    let mut cdb_log_sense_temp = [0; 16];
    cdb_log_sense_temp[0] = SCSI_LOG_SENSE;
    cdb_log_sense_temp[2] = SCSI_LOG_PAGE_TEMPERATURE; // Page Code
    cdb_log_sense_temp[7] = (SCSI_LOG_SENSE_DATA_SIZE >> 8) as u8;
    cdb_log_sense_temp[8] = (SCSI_LOG_SENSE_DATA_SIZE & 0xFF) as u8;

    println!("[DEBUG]     Sending SCSI LOG SENSE (Temperature) command...");
    let temp_result = send_scsi_command_direct(
        handle,
        &cdb_log_sense_temp,
        &mut temp_log_data,
        SCSI_IOCTL_DATA_IN,
        SCSI_LOG_SENSE_DATA_SIZE,
    );

    if let Ok(_) = temp_result {
        // Temperature Log Page (Mode Page 0x0D)
        // Byte 10 (page 0x0D, byte 10) typically contains the current temperature.
        if temp_log_data.len() >= 10 {
            health.temperature_celsius = Some(temp_log_data[10] as i64);
        }
        println!("[DEBUG]       -> Temperature Log Page processed.");
    } else {
        eprintln!("[DEBUG]       -> Failed to get Temperature Log Page: {:?}", temp_result.err());
    }

    // Note: Extracting serial number from SCSI devices is more complex, often requiring
    // VPD page 0x83 (Device Identification) or vendor-specific commands.
    // For now, we'll leave serial as "N/A" or try to get it from VPD 0x83 if needed.
    let serial = "N/A".to_string(); // Placeholder

    Ok(Device { path: path.into(), model: model, serial: serial, health_info: health })
}

/// Helper function to send a SCSI command using IOCTL_SCSI_PASS_THROUGH_DIRECT.
fn send_scsi_command_direct(
    handle: &WindowsDeviceHandle,
    cdb: &[u8],
    data_buffer: &mut [u8],
    data_in: u32, // SCSI_IOCTL_DATA_IN, SCSI_IOCTL_DATA_OUT, SCSI_IOCTL_DATA_UNSPECIFIED
    data_transfer_length: u32,
) -> Result<(), SmartError> {
    let sense_buffer_size = SCSI_SENSE_BUFFER_SIZE;
    let srb_size = size_of::<SCSI_PASS_THROUGH_DIRECT>() + sense_buffer_size as usize;
    let mut srb_buffer: Vec<u8> = vec![0; srb_size];

    let srb = srb_buffer.as_mut_ptr() as *mut SCSI_PASS_THROUGH_DIRECT;

    unsafe {
        (*srb).Length = size_of::<SCSI_PASS_THROUGH_DIRECT>() as u16;
        (*srb).CdbLength = cdb.len() as u8;
        std::ptr::copy_nonoverlapping(cdb.as_ptr(), (*srb).Cdb.as_mut_ptr(), cdb.len());
        
        (*srb).SenseInfoLength = sense_buffer_size as u8;
        (*srb).SenseInfoOffset = size_of::<SCSI_PASS_THROUGH_DIRECT>() as u32; // Offset to sense buffer
        
        (*srb).DataIn = data_in as u8; // Cast to u8
        (*srb).DataTransferLength = data_transfer_length;
        (*srb).DataBuffer = data_buffer.as_mut_ptr() as *mut std::ffi::c_void;
        (*srb).TimeOutValue = 60; // seconds
    }

    let mut bytes_returned: u32 = 0;
    let result = unsafe {
        DeviceIoControl(
            handle.0,
            IOCTL_SCSI_PASS_THROUGH_DIRECT,
            srb_buffer.as_mut_ptr() as _,
            srb_size as u32,
            srb_buffer.as_mut_ptr() as _,
            srb_size as u32,
            &mut bytes_returned,
            null_mut(),
        )
    };

    if result == 0 {
        let os_error = std::io::Error::last_os_error();
        eprintln!("[DEBUG]       -> SCSI IOCTL failed: {:?}", os_error);
        return Err(SmartError::IoError(os_error));
    }

    let scsi_status = unsafe { (*srb).ScsiStatus };
    if scsi_status != 0 {
        eprintln!("[DEBUG]       -> SCSI command returned status: 0x{:x}", scsi_status);
        if (scsi_status & SCSI_STATUS_CHECK_CONDITION) != 0 {
            let sense_info_ptr = unsafe { (srb_buffer.as_ptr() as *const u8).add(size_of::<SCSI_PASS_THROUGH_DIRECT>()) };
            let sense_info = unsafe { std::slice::from_raw_parts(sense_info_ptr, sense_buffer_size as usize) };
            eprintln!("[DEBUG]       -> Sense Data: {:x?}", sense_info);
            // A more robust implementation would parse the sense data for specific errors.
            // For now, we'll just report a generic SCSI error.
            return Err(SmartError::IoctlError(format!("SCSI command failed with status 0x{:x}, Sense Data: {:x?}", scsi_status, sense_info)));
        }
        return Err(SmartError::IoctlError(format!("SCSI command failed with status 0x{:x}", scsi_status)));
    }

    Ok(())
}
