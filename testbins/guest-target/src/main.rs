use std::io::Write;
use std::ptr;
use std::thread;
use std::time::Duration;

const MAGIC: [u8; 16] = *b"DECANT::LIVE\x00\xCA\xFE\x55";

const SENTINEL: u64 = 0xDECA_F1ED_5107_C0DE;

#[repr(C)]
struct Target {
    magic: [u8; 16],
    counter: u64,
    slot: u64,
}

fn aob_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() {
    let mut boxed = Box::new(Target {
        magic: MAGIC,
        counter: 0,
        slot: 0,
    });

    let target: *mut Target = &mut *boxed;
    let base = target as u64;
    let counter_ptr: *mut u64 = unsafe { ptr::addr_of_mut!((*target).counter) };
    let slot_ptr: *mut u64 = unsafe { ptr::addr_of_mut!((*target).slot) };
    let counter_addr = counter_ptr as u64;
    let slot_addr = slot_ptr as u64;

    std::mem::forget(boxed);

    println!("guest-target: resident self-verifying target is live.");
    println!("  struct base : 0x{base:016X}");
    println!("  counter @   : 0x{counter_addr:016X}  (base + 0x10, u64, increments ~1/s)");
    println!("  slot    @   : 0x{slot_addr:016X}  (base + 0x18, u64, host writes here)");
    println!("  sentinel    : 0x{SENTINEL:016X}  (value the host writes to prove a write landed)");
    println!();
    println!("  magic AOB   : {}", aob_string(&MAGIC));
    println!("  find me with : decant-cli scan <PID> \"{}\"", aob_string(&MAGIC));
    println!();
    let _ = std::io::stdout().flush();

    loop {
        unsafe {
            let next = ptr::read_volatile(counter_ptr).wrapping_add(1);
            ptr::write_volatile(counter_ptr, next);

            let slot = ptr::read_volatile(slot_ptr);
            if slot == SENTINEL {
                println!("slot hit: sentinel observed (slot = 0x{slot:016X})");
            }
        }

        let _ = std::io::stdout().flush();
        thread::sleep(Duration::from_secs(1));
    }
}
