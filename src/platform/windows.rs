// src/platform/windows.rs

use crate::ata::{IdentifyDeviceData, SmartDataBlock};
use crate::error::SmartError;
use crate::{Device, SmartHealth};
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::null_mut;

use windows_sys::Win32::{
    Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
    Storage::IscsiDisc::{ATA_PASS_THROUGH_EX, IOCTL_ATA_PASS_THROUGH},
    System::IO::DeviceIoControl,
    System::Ioctl::IDEREGS,
};

const ATA_IDENTIFY_DEVICE: u8 = 0xEC;
const ATA_SMART_CMD: u8 = 0xB0;
const SMART_READ_DATA: u8 = 0xD0;

struct WindowsDeviceHandle(HANDLE);
impl Drop for WindowsDeviceHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}


pub fn discover_and_collect() -> Result<Vec<Device>, SmartError> {
    let mut devices = Vec::new();
    println!("[Debug] Starting device discovery loop on Windows...");
    for i in 0..16 {
        let path_str = format!("\\\\.\\PhysicalDrive{}", i);
        
        match open_device(&path_str) {
            Ok(handle) => {
                println!("[Debug] Successfully opened {}. Querying identity...", path_str);
                match get_identify_data(&handle) {
                    Ok(identity) => {
                        println!("[Debug] IDENTIFY success for {}. Model: {}. Querying SMART data...", path_str, identity.model().trim());
                        match get_smart_data(&handle) {
                            Ok(smart_block) => {
                                println!("[Debug] SMART READ success for {}. Adding to device list.", path_str);
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
                                    path: path_str.into(),
                                    model: identity.model(),
                                    serial: identity.serial(),
                                    health_info: health,
                                });
                            },
                            Err(e) => {
                                eprintln!("[Debug] Could not get SMART data from {}: {}. This device might not support SMART.", path_str, e);
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("[Debug] Could not get IDENTIFY data from {}: {}. This is likely not an ATA/SATA drive.", path_str, e);
                    }
                }
            },
            Err(_) => {
                // 当循环到不存在的驱动器号时，open_device 会失败。
                // 如果这是循环的开始（i=0或1），并且仍然失败，那很可能是一个权限问题。
                if i < 2 {
                    eprintln!("[Debug] Failed to open {}. This could be a permissions issue or the device doesn't exist.", path_str);
                }
                // 对于更高的数字，我们假设设备就是不存在，所以不需要打印错误。
            }
        }
    }
    println!("[Debug] Device discovery loop finished.");
    Ok(devices)
}

fn open_device(path: &str) -> Result<WindowsDeviceHandle, SmartError> {
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(SmartError::IoError(std::io::Error::last_os_error()))
    } else {
        Ok(WindowsDeviceHandle(handle))
    }
}
fn get_identify_data(handle: &WindowsDeviceHandle) -> Result<IdentifyDeviceData, SmartError> {
    let buffer_size = size_of::<ATA_PASS_THROUGH_EX>() + size_of::<IdentifyDeviceData>();
    let mut buffer = vec![0u8; buffer_size];
    let apt = buffer.as_mut_ptr() as *mut ATA_PASS_THROUGH_EX;
    unsafe {
        (*apt).Length = size_of::<ATA_PASS_THROUGH_EX>() as u16; (*apt).AtaFlags = 0x08;
        (*apt).DataTransferLength = size_of::<IdentifyDeviceData>() as u32; (*apt).TimeOutValue = 10;
        (*apt).DataBufferOffset = size_of::<ATA_PASS_THROUGH_EX>() as usize;
        let regs = (*apt).CurrentTaskFile.as_mut_ptr() as *mut IDEREGS;
        (*regs).bCommandReg = ATA_IDENTIFY_DEVICE;
    }
    send_device_control(handle.0, IOCTL_ATA_PASS_THROUGH, buffer.as_mut_ptr() as *mut c_void, buffer.len(), buffer.as_mut_ptr() as *mut c_void, buffer.len())?;
    let data_ptr = unsafe { buffer.as_ptr().add(size_of::<ATA_PASS_THROUGH_EX>()) };
    Ok(unsafe { *(data_ptr as *const IdentifyDeviceData) })
}
fn get_smart_data(handle: &WindowsDeviceHandle) -> Result<SmartDataBlock, SmartError> {
    let buffer_size = size_of::<ATA_PASS_THROUGH_EX>() + size_of::<SmartDataBlock>();
    let mut buffer = vec![0u8; buffer_size];
    let apt = buffer.as_mut_ptr() as *mut ATA_PASS_THROUGH_EX;
    unsafe {
        (*apt).Length = size_of::<ATA_PASS_THROUGH_EX>() as u16; (*apt).AtaFlags = 0x08;
        (*apt).DataTransferLength = size_of::<SmartDataBlock>() as u32; (*apt).TimeOutValue = 10;
        (*apt).DataBufferOffset = size_of::<ATA_PASS_THROUGH_EX>() as usize;
        let regs = (*apt).CurrentTaskFile.as_mut_ptr() as *mut IDEREGS;
        (*regs).bCommandReg = ATA_SMART_CMD; (*regs).bFeaturesReg = SMART_READ_DATA;
        (*regs).bCylLowReg = 0x4F; (*regs).bCylHighReg = 0xC2;
    }
    send_device_control(handle.0, IOCTL_ATA_PASS_THROUGH, buffer.as_mut_ptr() as *mut c_void, buffer.len(), buffer.as_mut_ptr() as *mut c_void, buffer.len())?;
    let data_ptr = unsafe { buffer.as_ptr().add(size_of::<ATA_PASS_THROUGH_EX>()) };
    Ok(unsafe { *(data_ptr as *const SmartDataBlock) })
}
fn send_device_control(handle: HANDLE, code: u32, in_buf: *mut c_void, in_size: usize, out_buf: *mut c_void, out_size: usize) -> Result<(), SmartError> {
    let mut bytes_returned = 0;
    if unsafe { DeviceIoControl(handle, code, in_buf, in_size as u32, out_buf, out_size as u32, &mut bytes_returned, null_mut()) } == 0 {
        Err(SmartError::IoError(std::io::Error::last_os_error()))
    } else { Ok(()) }
}