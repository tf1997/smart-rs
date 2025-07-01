// examples/read_smart.rs

use smart_rs::{discover, Device};

fn main() {
    println!("--- smart-rs Library: Data Collection Verification ---");
    println!("Attempting to discover devices and read SMART data...");
    println!("NOTE: This requires administrator or root privileges to run!\n");

    match discover() {
        Ok(devices) => {
            if devices.is_empty() {
                println!("No supported storage devices were found.");
                println!("(This PoC supports NVMe on Linux, and ATA/SATA on Windows/macOS)");
            } else {
                println!("Successfully found {} supported device(s):", devices.len());
                for device in devices {
                    print_device_info(&device);
                }
            }
        }
        Err(e) => {
            eprintln!("[ERROR] Failed to discover devices: {}", e);
            eprintln!("\nPlease ensure you are running this example with administrator/root privileges.");
            eprintln!("Common errors:");
            eprintln!("  - Windows: 'Access is denied. (os error 5)'");
            eprintln!("  - Linux/macOS: 'Permission denied (os error 13)'");
        }
    }
}

fn print_device_info(device: &Device) {
    println!("\n----------------------------------------");
    println!("  Device Path:  {}", device.path.display());
    println!("  Model:        {}", device.model);
    println!("  Serial:       {}", device.serial);
    println!("----------------------------------------");
    println!("  SMART Health Info:");

    let print_opt = |name: &str, val: Option<i64>| {
        let val_str = val.map_or("N/A".to_string(), |v| v.to_string());
        println!("    - {:<22}: {}", name, val_str);
    };
    
    let print_opt_u8 = |name: &str, val: Option<u8>| {
        let val_str = val.map_or("N/A".to_string(), |v| v.to_string());
        println!("    - {:<22}: {}", name, val_str);
    };

    print_opt("Temperature (Celsius)", device.health_info.temperature_celsius);
    print_opt("Power On Hours", device.health_info.power_on_hours);
    print_opt("Power Cycles", device.health_info.power_cycles);
    print_opt("Reallocated Sectors", device.health_info.reallocated_sectors);
    print_opt("Unsafe Shutdowns", device.health_info.unsafe_shutdowns);
    print_opt_u8("Percentage Used (SSD)", device.health_info.percentage_used);
    println!("----------------------------------------");
}