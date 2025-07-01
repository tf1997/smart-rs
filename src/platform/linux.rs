use crate::error::SmartError;
use crate::nvme::{NvmePassthruCommand, NvmeSmartLog, NVME_ADMIN_GET_LOG_PAGE, NVME_LOG_SMART_INFO};
use crate::{Device, SmartHealth};
use std::fs::{File, ReadDir};
use std::os::unix::io::AsRawFd;

ioctl_rs::ioctl_write_ptr!(nvme_admin_cmd, b'N', 0x41, NvmePassthruCommand);

pub fn discover_and_collect() -> Result<Vec<Device>, SmartError> {
    let mut devices = Vec::new();
    for entry in std::fs::read_dir("/dev/")? {
        let entry = entry?;
        let path = entry.path();
        if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
            if file_name.starts_with("nvme") && !file_name.contains('n') {
                if let Ok(file) = File::open(&path) {
                    if let Ok(log) = get_nvme_smart_health(&file) {
                        devices.push(Device {
                            path: path.clone(),
                            model: "NVMe Drive".to_string(), // IdentifyDevice not implemented for NVMe PoC
                            serial: "N/A".to_string(),      // IdentifyController needed for this
                            health_info: convert_log_to_health(&log),
                        });
                    }
                }
            }
        }
    }
    Ok(devices)
}

fn get_nvme_smart_health(file: &File) -> Result<NvmeSmartLog, SmartError> {
    let mut smart_log = NvmeSmartLog::default();
    let mut cmd = NvmePassthruCommand::default();
    cmd.opcode = NVME_ADMIN_GET_LOG_PAGE;
    cmd.nsid = 0xFFFFFFFF;
    cmd.addr = &smart_log as *const _ as u64;
    cmd.data_len = std::mem::size_of::<NvmeSmartLog>() as u32;
    let numd = (std::mem::size_of::<NvmeSmartLog>() as u32 / 4) - 1;
    cmd.cdw10 = NVME_LOG_SMART_INFO | (numd << 16);
    let fd = file.as_raw_fd();
    unsafe { nvme_admin_cmd(fd, &mut cmd) }.map(|_| smart_log).map_err(|e| SmartError::IoctlError(e.to_string()))
}

fn convert_log_to_health(log: &NvmeSmartLog) -> SmartHealth {
    SmartHealth {
        temperature_celsius: Some((log.temperature as i64) - 273),
        percentage_used: Some(log.percentage_used),
        power_on_hours: Some(u128::from_le_bytes(log.power_on_hours) as i64),
        power_cycles: Some(u128::from_le_bytes(log.power_cycles) as i64),
        unsafe_shutdowns: Some(u128::from_le_bytes(log.unsafe_shutdowns) as i64),
        ..Default::default()
    }
}