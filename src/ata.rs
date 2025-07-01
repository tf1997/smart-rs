use std::fmt;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IdentifyDeviceData {
    pub _rsvd1: [u16; 10],
    pub serial_number: [u8; 20],
    pub _rsvd2: [u16; 3],
    pub firmware_version: [u8; 8],
    pub model_number: [u8; 40],
    _padding: [u16; 496 - 40],
}

impl IdentifyDeviceData {
    fn fix_string(bytes: &[u8]) -> String {
        bytes
            .chunks_exact(2)
            .flat_map(|chunk| [chunk[1], chunk[0]])
            .map(|b| b as char)
            .collect::<String>()
            .trim()
            .to_string()
    }
    
    pub fn model(&self) -> String { Self::fix_string(&self.model_number) }
    pub fn serial(&self) -> String { Self::fix_string(&self.serial_number) }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SmartAttribute {
    pub id: u8,
    pub status_flags: u16,
    pub value: u8,
    pub worst: u8,
    pub vendor_data: [u8; 6],
    pub _rsvd: u8,
}

impl SmartAttribute {
    pub fn raw_value(&self) -> i64 {
        i64::from_le_bytes([self.vendor_data[0], self.vendor_data[1], self.vendor_data[2], self.vendor_data[3], self.vendor_data[4], self.vendor_data[5], 0, 0])
    }
}

impl fmt::Debug for SmartAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmartAttribute").field("id", &self.id).field("raw_value", &self.raw_value()).finish()
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SmartDataBlock {
    pub _header: [u8; 2],
    pub attributes: [SmartAttribute; 30],
    pub _footer: [u8; 512 - 2 - (12 * 30)],
}