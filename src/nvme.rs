#[repr(C)]
#[derive(Debug, Default)]
pub struct NvmePassthruCommand {
    pub opcode: u8, pub flags: u8, pub rsvd1: u16, pub nsid: u32, pub cdw2: u32,
    pub cdw3: u32, pub metadata: u64, pub addr: u64, pub metadata_len: u32,
    pub data_len: u32, pub cdw10: u32, pub cdw11: u32, pub cdw12: u32,
    pub cdw13: u32, pub cdw14: u32, pub cdw15: u32, pub timeout_ms: u32, pub result: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct NvmeSmartLog {
    pub critical_warning: u8, pub temperature: u16, pub available_spare: u8,
    pub available_spare_threshold: u8, pub percentage_used: u8, pub rsvd1: [u8; 26],
    pub data_units_read: [u8; 16], pub data_units_written: [u8; 16], pub host_read_commands: [u8; 16],
    pub host_write_commands: [u8; 16], pub controller_busy_time: [u8; 16], pub power_cycles: [u8; 16],
    pub power_on_hours: [u8; 16], pub unsafe_shutdowns: [u8; 16], pub media_errors: [u8; 16],
    pub num_err_log_entries: [u8; 16],
}

pub const NVME_ADMIN_GET_LOG_PAGE: u8 = 0x02;
pub const NVME_LOG_SMART_INFO: u32 = 0x02;