//! # mock-cheat (Phase 3) — runs UNDER WINE
//!
//! The full stand-in for an unmodified Cheat-Engine-style tool. With the carafe
//! injected (by `decant-launcher`, `DECANT_AUTOHOOK=1`) and a daemon serving the
//! deterministic demo guest, mock-cheat drives the whole intercepted Win32 surface
//! against the *fake guest* and prints one `PASS`/`FAIL` line per check, ending in
//! `mock-cheat: ALL PASS` only if every check passed (the `xtask phase3` gate
//! asserts on that line).
//!
//! Checks (all against guest pid 1234 `decant-target.exe`, via the daemon):
//!   1. `OpenProcess(1234)` returns a (synthetic) handle.
//!   2. `ReadProcessMemory` the 16-byte magic header == `DEMO_MAGIC`.
//!   3. `WriteProcessMemory` 8 bytes to the writable slot, read them back, changed.
//!   4. Walk the pointer chain with RPM: head -> node, node+0x10 -> u32 1337.
//!   5. `CreateToolhelp32Snapshot` + `Process32First/Next` find `decant-target.exe`.
//!   6. `EnumProcessModules` + `GetModuleBaseNameA` find the target's module.
//!   7. Real-handle forward: `ReadProcessMemory(GetCurrentProcess(), …)` still reads
//!      this process's *own* real memory (proving real handles are forwarded, not
//!      hijacked); `CloseHandle` on the synthetic handle returns TRUE.
//!
//! Modes:
//!   * `--spike`        daemon-free interception self-test (the old spike rung):
//!                      `CloseHandle` on a synthetic-range handle returns TRUE iff
//!                      hooked → prints `INTERCEPTED`, else `passthrough`.
//!   * `--cooperative`  load the carafe and call its installer before the run
//!                      (rung 1); combinable with `--spike`.
//!   * (default)        the full Phase 3 run above.
//!
//! Win32 entry points are declared by hand (like `dll-smoke`) to exercise the exact
//! public export ABI Decant intercepts (rule #4) and keep the cross-compile
//! dependency-free.

use std::ffi::c_void;
use std::process::ExitCode;

type Handle = *mut c_void;

// ---------------------------------------------------------------------------
// Demo-fixture constants. MIRRORED from `decant_backend::fixtures` (mock-cheat is
// windows-gnu and cannot depend on the host crate). Keep in sync with that file.
// ---------------------------------------------------------------------------
const DEMO_TARGET_PID: u32 = 1234;
const DEMO_MODULE_NAME: &str = "decant-target.exe";
const DEMO_MAGIC: [u8; 16] = *b"DECANT::MAGIC\x00\xDE\xAD";
const DEMO_MAGIC_ADDR: u64 = 0x0001_4001_0100;
const DEMO_CHAIN_HEAD: u64 = 0x0001_4001_0200;
const DEMO_CHAIN_NODE: u64 = 0x0001_4001_0280;
const DEMO_CHAIN_OFFSET: u64 = 0x10;
const DEMO_CHAIN_VALUE: u32 = 1337;
const DEMO_SLOT_ADDR: u64 = 0x0001_4001_0400;

// ---------------------------------------------------------------------------
// Win32 constants.
// ---------------------------------------------------------------------------
const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;

/// `PROCESSENTRY32` (ANSI) — layout mirrors the public Win32 struct (and the
/// carafe's `hooks::ProcessEntry32`).
#[repr(C)]
struct ProcessEntry32 {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u8; 260],
}

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(lp_lib_file_name: *const u8) -> Handle;
    fn GetProcAddress(h_module: Handle, lp_proc_name: *const u8) -> *mut c_void;
    fn GetCurrentProcess() -> Handle;
    fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> Handle;
    fn CloseHandle(object: Handle) -> i32;
    fn ReadProcessMemory(
        process: Handle,
        base_address: *const c_void,
        buffer: *mut c_void,
        size: usize,
        bytes_read: *mut usize,
    ) -> i32;
    fn WriteProcessMemory(
        process: Handle,
        base_address: *mut c_void,
        buffer: *const c_void,
        size: usize,
        bytes_written: *mut usize,
    ) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
    fn Process32First(snapshot: Handle, entry: *mut ProcessEntry32) -> i32;
    fn Process32Next(snapshot: Handle, entry: *mut ProcessEntry32) -> i32;
}

#[link(name = "psapi")]
extern "system" {
    fn EnumProcessModules(
        process: Handle,
        modules: *mut Handle,
        cb: u32,
        cb_needed: *mut u32,
    ) -> i32;
    fn GetModuleBaseNameA(process: Handle, module: Handle, base_name: *mut u8, size: u32) -> u32;
}

/// Decode a NUL-terminated ANSI fixed buffer into a `String`.
fn ansi(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Print a single check result and fold it into the running pass flag.
fn check(all_pass: &mut bool, name: &str, ok: bool, detail: &str) {
    let tag = if ok { "PASS" } else { "FAIL" };
    println!("check {name}: {tag} ({detail})");
    *all_pass &= ok;
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cooperative = args.iter().any(|a| a == "--cooperative");
    let spike = args.iter().any(|a| a == "--spike");

    if cooperative {
        if let Err(code) = install_via_loadlibrary() {
            return code;
        }
    }

    if spike {
        return run_spike_selftest();
    }

    run_phase3()
}

/// The full Phase 3 run against the daemon-served demo guest.
fn run_phase3() -> ExitCode {
    let mut all_pass = true;

    // 1. OpenProcess on the fake guest pid.
    let proc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, DEMO_TARGET_PID) };
    let open_ok = !proc.is_null();
    check(&mut all_pass, "open_process", open_ok, &format!("handle={proc:?}"));
    if !open_ok {
        println!("mock-cheat: ABORT (OpenProcess failed; is the daemon reachable?)");
        return ExitCode::from(10);
    }

    // 2. Read the planted magic header.
    let mut magic = [0u8; 16];
    let magic_ok = rpm(proc, DEMO_MAGIC_ADDR, &mut magic) && magic == DEMO_MAGIC;
    check(&mut all_pass, "read_magic", magic_ok, &format!("got={:02X?}", &magic));

    // 3. Write the slot, read it back, confirm it changed.
    let payload: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    let wrote = wpm(proc, DEMO_SLOT_ADDR, &payload);
    let mut readback = [0u8; 8];
    let read_back_ok = rpm(proc, DEMO_SLOT_ADDR, &mut readback);
    let write_ok = wrote && read_back_ok && readback == payload && readback != [0u8; 8];
    check(&mut all_pass, "write_then_read", write_ok, &format!("readback={:02X?}", &readback));

    // 4. Walk the pointer chain: head -> node, node+0x10 -> 1337.
    let mut head_bytes = [0u8; 8];
    let node = if rpm(proc, DEMO_CHAIN_HEAD, &mut head_bytes) {
        u64::from_le_bytes(head_bytes)
    } else {
        0
    };
    let mut term_bytes = [0u8; 4];
    let term_ok = node == DEMO_CHAIN_NODE
        && rpm(proc, node + DEMO_CHAIN_OFFSET, &mut term_bytes)
        && u32::from_le_bytes(term_bytes) == DEMO_CHAIN_VALUE;
    check(
        &mut all_pass,
        "pointer_chain",
        term_ok,
        &format!("node={node:#x} value={}", u32::from_le_bytes(term_bytes)),
    );

    // 5. Toolhelp process snapshot -> find decant-target.exe.
    let found_proc = toolhelp_find_target();
    check(
        &mut all_pass,
        "toolhelp_process",
        found_proc,
        &format!("looking for {DEMO_MODULE_NAME} pid {DEMO_TARGET_PID}"),
    );

    // 6. EnumProcessModules + GetModuleBaseNameA -> find the target's module.
    let found_mod = enum_modules_find_target(proc);
    check(&mut all_pass, "enum_modules", found_mod, &format!("looking for {DEMO_MODULE_NAME}"));

    // 7a. Real-handle forward: read this process's OWN memory via the real
    //     pseudo-handle; it must come back as the real bytes (not hijacked).
    let sentinel: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let mut probe = [0u8; 8];
    let mut n: usize = 0;
    let real_ok = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            sentinel.as_ptr() as *const c_void,
            probe.as_mut_ptr() as *mut c_void,
            8,
            &mut n,
        )
    } != 0
        && probe == sentinel;
    check(&mut all_pass, "real_handle_forward", real_ok, &format!("own-memory readback={:02X?}", &probe));

    // 7b. CloseHandle on the synthetic handle drops it (returns TRUE).
    let close_ok = unsafe { CloseHandle(proc) } != 0;
    check(&mut all_pass, "close_synthetic", close_ok, "CloseHandle(synthetic)==TRUE");

    if all_pass {
        println!("mock-cheat: ALL PASS");
        ExitCode::SUCCESS
    } else {
        println!("mock-cheat: FAILED (see check lines above)");
        ExitCode::from(11)
    }
}

/// `ReadProcessMemory` helper: fill `out` from guest `addr`, returning success.
fn rpm(proc: Handle, addr: u64, out: &mut [u8]) -> bool {
    let mut n: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            proc,
            addr as *const c_void,
            out.as_mut_ptr() as *mut c_void,
            out.len(),
            &mut n,
        )
    };
    ok != 0 && n == out.len()
}

/// `WriteProcessMemory` helper: write `data` to guest `addr`, returning success.
fn wpm(proc: Handle, addr: u64, data: &[u8]) -> bool {
    let mut n: usize = 0;
    let ok = unsafe {
        WriteProcessMemory(
            proc,
            addr as *mut c_void,
            data.as_ptr() as *const c_void,
            data.len(),
            &mut n,
        )
    };
    ok != 0 && n == data.len()
}

/// Snapshot all processes and look for the demo target by name + pid.
fn toolhelp_find_target() -> bool {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == (usize::MAX as Handle) || snap.is_null() {
            return false;
        }
        let mut entry: ProcessEntry32 = std::mem::zeroed();
        entry.dw_size = std::mem::size_of::<ProcessEntry32>() as u32;
        let mut found = false;
        let mut ok = Process32First(snap, &mut entry);
        while ok != 0 {
            let name = ansi(&entry.sz_exe_file);
            if name == DEMO_MODULE_NAME && entry.th32_process_id == DEMO_TARGET_PID {
                found = true;
                break;
            }
            ok = Process32Next(snap, &mut entry);
        }
        CloseHandle(snap);
        found
    }
}

/// Enumerate the target process's modules and look for the demo module by name.
fn enum_modules_find_target(proc: Handle) -> bool {
    unsafe {
        let mut modules: [Handle; 64] = [std::ptr::null_mut(); 64];
        let mut needed: u32 = 0;
        let cb = (modules.len() * std::mem::size_of::<Handle>()) as u32;
        if EnumProcessModules(proc, modules.as_mut_ptr(), cb, &mut needed) == 0 {
            return false;
        }
        let count = (needed as usize / std::mem::size_of::<Handle>()).min(modules.len());
        for &m in &modules[..count] {
            let mut name_buf = [0u8; 260];
            let len = GetModuleBaseNameA(proc, m, name_buf.as_mut_ptr(), name_buf.len() as u32);
            if len > 0 && ansi(&name_buf) == DEMO_MODULE_NAME {
                return true;
            }
        }
        false
    }
}

/// Daemon-free interception self-test (the old spike rung). A synthetic-range
/// handle fed to `CloseHandle` returns TRUE iff the carafe is hooked; with no
/// injection the real `CloseHandle` rejects it.
fn run_spike_selftest() -> ExitCode {
    let synthetic = 0xDEC0_0000_0000_0001usize as Handle;
    let r = unsafe { CloseHandle(synthetic) };
    if r != 0 {
        println!("INTERCEPTED");
    } else {
        println!("passthrough");
    }
    ExitCode::SUCCESS
}

/// Rung-1 cooperative bootstrap: load the carafe and call its exported installer.
fn install_via_loadlibrary() -> Result<(), ExitCode> {
    let dll = b"decant_interpose.dll\0";
    let sym = b"decant_install_hooks\0";
    unsafe {
        let module = LoadLibraryA(dll.as_ptr());
        if module.is_null() {
            eprintln!("mock-cheat: LoadLibraryA(decant_interpose.dll) failed");
            return Err(ExitCode::from(2));
        }
        let proc = GetProcAddress(module, sym.as_ptr());
        if proc.is_null() {
            eprintln!("mock-cheat: GetProcAddress(decant_install_hooks) failed");
            return Err(ExitCode::from(3));
        }
        let install: extern "system" fn() -> i32 = std::mem::transmute(proc);
        let patched = install();
        eprintln!("mock-cheat: decant_install_hooks patched {patched} slot(s)");
        if patched < 1 {
            eprintln!("mock-cheat: installer patched nothing");
            return Err(ExitCode::from(4));
        }
    }
    Ok(())
}
