// examples/identify_bus.rs

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;

// --- THIS IS YOUR CORRECT, VERIFIED IMPORT BLOCK ---
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    Security::SECURITY_ATTRIBUTES, // Needed for CreateFileW signature
    System::IO::DeviceIoControl,
    System::Ioctl::{
        IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_QUERY,
        PropertyStandardQuery, StorageDeviceProperty,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, STORAGE_BUS_TYPE,
        BusTypeAta, BusTypeNvme, BusTypeSata, BusTypeScsi, BusTypeUsb,
    },
};

fn main() {
    println!("--- Disk Bus Type Identifier for Windows ---");
    println!("NOTE: This requires administrator privileges to run.\n");

    for i in 0..16 {
        let path_str = format!("\\\\.\\PhysicalDrive{}", i);
        let wide_path: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();
        
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                0, // No read/write access is needed for this query.
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            if i > 0 { break; } else { continue; }
        }

        print!("Device: {} -> ", path_str);

        match get_bus_type(handle) {
            Ok(bus_type) => {
                let bus_type_str = match bus_type {
                    BusTypeAta => "ATA",
                    BusTypeSata => "SATA",
                    BusTypeNvme => "NVMe",
                    BusTypeScsi => "SCSI",
                    BusTypeUsb => "USB",
                    _ => "Other/Unknown",
                };
                println!("Bus Type: {}", bus_type_str);
            }
            Err(e) => {
                println!("Error querying bus type: {}", e);
            }
        }

        unsafe { CloseHandle(handle) };
    }
}

fn get_bus_type(handle: HANDLE) -> Result<STORAGE_BUS_TYPE, String> {
    // --- THIS IS THE CORRECTED CODE ---
    // We now use the global constants directly, not the `::` syntax.
    let mut query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };

    let mut buffer: [u8; 1024] = unsafe { zeroed() };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &mut query as *mut _ as *mut c_void,
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut bytes_returned,
            null_mut(),
        )
    };

    if result == 0 {
        return Err(format!("DeviceIoControl failed with OS error: {}", std::io::Error::last_os_error()));
    }

    if (bytes_returned as usize) < size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
         return Err("Received insufficient data from DeviceIoControl".to_string());
    }
    
    let descriptor = unsafe { &*(buffer.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR) };
    Ok(descriptor.BusType)
}