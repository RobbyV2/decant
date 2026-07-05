#[cfg(windows)]
mod probe;

#[cfg(windows)]
mod app {
    use std::ffi::c_void;
    use std::io::Write;
    use std::process::ExitCode;
    use std::ptr;
    use std::thread;
    use std::time::Duration;

    use crate::probe::{DLL_MARKER, MAGIC, Probe};

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryA(name: *const u8) -> *mut c_void;
    }

    static mut PROBE: Probe = Probe::new();

    pub fn main() -> ExitCode {
        let probe = ptr::addr_of_mut!(PROBE);
        unsafe {
            std::env::set_var(
                "DECANT_GUEST_PROBE_ADDR",
                format!("{:016X}", probe as usize),
            );
        }

        let args = std::env::args().collect::<Vec<_>>();
        match args.get(1).map(String::as_str) {
            Some("--self-load") => self_load(probe, args.get(2).map(String::as_str)),
            Some("--once") => {
                print_status(probe);
                ExitCode::SUCCESS
            }
            Some(other) => {
                eprintln!("unknown argument: {other}");
                ExitCode::from(2)
            }
            None => resident(probe),
        }
    }

    fn resident(probe: *mut Probe) -> ExitCode {
        print_status(probe);
        let mut observed = false;
        loop {
            unsafe {
                let tick = ptr::read_volatile(ptr::addr_of!((*probe).tick)).wrapping_add(1);
                ptr::write_volatile(ptr::addr_of_mut!((*probe).tick), tick);
                let marker = ptr::read_volatile(ptr::addr_of!((*probe).dll_marker));
                if marker == DLL_MARKER && !observed {
                    observed = true;
                    println!("guest-inject-target: dll marker observed");
                }
            }
            let _ = std::io::stdout().flush();
            thread::sleep(Duration::from_secs(1));
        }
    }

    fn self_load(probe: *mut Probe, dll: Option<&str>) -> ExitCode {
        let dll = dll.unwrap_or("guest_inject_probe.dll");
        let mut path = dll.as_bytes().to_vec();
        path.push(0);
        unsafe {
            let module = LoadLibraryA(path.as_ptr());
            if module.is_null() {
                eprintln!("guest-inject-target: LoadLibraryA({dll}) failed");
                return ExitCode::from(3);
            }
        }
        for _ in 0..50 {
            let marker = unsafe { ptr::read_volatile(ptr::addr_of!((*probe).dll_marker)) };
            if marker == DLL_MARKER {
                println!("guest-inject-target: self-load PASS");
                print_status(probe);
                return ExitCode::SUCCESS;
            }
            thread::sleep(Duration::from_millis(100));
        }
        eprintln!("guest-inject-target: self-load timed out");
        ExitCode::from(4)
    }

    fn print_status(probe: *mut Probe) {
        let dll_marker = unsafe { ptr::read_volatile(ptr::addr_of!((*probe).dll_marker)) };
        let dll_count = unsafe { ptr::read_volatile(ptr::addr_of!((*probe).dll_count)) };
        let tick = unsafe { ptr::read_volatile(ptr::addr_of!((*probe).tick)) };
        let probe_addr = probe as usize;
        let marker_addr = unsafe { ptr::addr_of!((*probe).dll_marker) as usize };
        println!("guest-inject-target: ready");
        println!("  probe @       : 0x{probe_addr:016X}");
        println!("  dll_marker @  : 0x{marker_addr:016X}");
        println!("  tick          : {tick}");
        println!("  dll_marker    : 0x{dll_marker:016X}");
        println!("  dll_count     : {dll_count}");
        println!("  expected mark : 0x{DLL_MARKER:016X}");
        println!("  magic AOB     : {}", aob_string(&MAGIC));
        println!("  probe env     : DECANT_GUEST_PROBE_ADDR=0x{probe_addr:016X}");
        let _ = std::io::stdout().flush();
    }

    fn aob_string(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    app::main()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("guest-inject-target is a Windows test fixture");
    std::process::exit(2);
}
