use std::ffi::c_void;
use std::process::ExitCode;

type Handle = *mut c_void;

// mirror of decant_backend::fixtures; keep in sync
const DEMO_TARGET_PID: u32 = 1234;
const DEMO_MODULE_NAME: &str = "decant-target.exe";
const DEMO_MAGIC: [u8; 16] = *b"DECANT::MAGIC\x00\xDE\xAD";
const DEMO_MAGIC_ADDR: u64 = 0x0001_4001_0100;
const DEMO_CHAIN_HEAD: u64 = 0x0001_4001_0200;
const DEMO_CHAIN_NODE: u64 = 0x0001_4001_0280;
const DEMO_CHAIN_OFFSET: u64 = 0x10;
const DEMO_CHAIN_VALUE: u32 = 1337;
const DEMO_SLOT_ADDR: u64 = 0x0001_4001_0400;

// guest-target layout: magic at base, counter at base+0x10, slot at base+0x18
const TARGET_MAGIC: [u8; 16] = *b"DECANT::LIVE\x00\xCA\xFE\x55";
const TARGET_SENTINEL: u64 = 0xDECA_F1ED_5107_C0DE;

const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const MEM_COMMIT_RESERVE: u32 = 0x3000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_NOACCESS: u32 = 0x01;

#[repr(C)]
struct MemoryBasicInformation {
    base_address: usize,
    allocation_base: usize,
    allocation_protect: u32,
    align1: u32,
    region_size: usize,
    state: u32,
    protect: u32,
    type_: u32,
    align2: u32,
}

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
unsafe extern "system" {
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
    fn VirtualAllocEx(
        process: Handle,
        address: *mut c_void,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> *mut c_void;
    fn VirtualQueryEx(
        process: Handle,
        address: *const c_void,
        mbi: *mut MemoryBasicInformation,
        length: usize,
    ) -> usize;
}

#[link(name = "psapi")]
unsafe extern "system" {
    fn EnumProcessModules(
        process: Handle,
        modules: *mut Handle,
        cb: u32,
        cb_needed: *mut u32,
    ) -> i32;
    fn GetModuleBaseNameA(process: Handle, module: Handle, base_name: *mut u8, size: u32) -> u32;
}

fn ansi(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn check(all_pass: &mut bool, name: &str, ok: bool, detail: &str) {
    let tag = if ok { "PASS" } else { "FAIL" };
    println!("check {name}: {tag} ({detail})");
    *all_pass &= ok;
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cooperative = args.iter().any(|a| a == "--cooperative");
    let inject_test = args.iter().any(|a| a == "--inject-test");

    if cooperative {
        if let Err(code) = install_via_loadlibrary() {
            return code;
        }
    }

    if inject_test {
        return run_interception_selftest();
    }

    if args.iter().any(|a| a == "--dynamic") {
        return run_dynamic();
    }

    if let Ok(pid) = std::env::var("DECANT_TARGET_PID") {
        return run_target(&pid);
    }

    run_checks()
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse::<u64>().ok(),
    }
}

fn run_target(pid_s: &str) -> ExitCode {
    let pid = match parse_u64(pid_s) {
        Some(v) => v as u32,
        None => return ExitCode::from(20),
    };
    let base = match std::env::var("DECANT_TARGET_BASE").ok().and_then(|s| parse_u64(&s)) {
        Some(v) => v,
        None => {
            eprintln!("set DECANT_TARGET_BASE to guest-target's struct base");
            return ExitCode::from(21);
        }
    };
    let counter_addr = base + 0x10;
    let slot_addr = base + 0x18;

    let proc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if proc.is_null() {
        println!("open_process: FAIL (pid {pid})");
        return ExitCode::from(22);
    }
    println!("open_process: ok (pid {pid}, handle={proc:?})");

    let mut magic = [0u8; 16];
    let magic_ok = rpm(proc, base, &mut magic) && magic == TARGET_MAGIC;
    println!("read_magic: {} got={:02X?}", if magic_ok { "MATCH" } else { "mismatch" }, &magic);

    let mut c1b = [0u8; 8];
    rpm(proc, counter_addr, &mut c1b);
    std::thread::sleep(std::time::Duration::from_millis(1200));
    let mut c2b = [0u8; 8];
    rpm(proc, counter_addr, &mut c2b);
    let (c1, c2) = (u64::from_le_bytes(c1b), u64::from_le_bytes(c2b));
    println!("counter: {c1} -> {c2} (incrementing: {})", if c2 > c1 { "yes" } else { "no" });

    let wrote = wpm(proc, slot_addr, &TARGET_SENTINEL.to_le_bytes());
    let mut sb = [0u8; 8];
    let rb = rpm(proc, slot_addr, &mut sb);
    let slot_ok = wrote && rb && u64::from_le_bytes(sb) == TARGET_SENTINEL;
    println!(
        "write_sentinel: {} (slot readback={:#018x})",
        if slot_ok { "ok" } else { "bad" },
        u64::from_le_bytes(sb)
    );

    unsafe { CloseHandle(proc) };

    if magic_ok && slot_ok {
        println!("sample-tool target: PASS");
        ExitCode::SUCCESS
    } else {
        println!("sample-tool target: FAIL");
        ExitCode::from(23)
    }
}

fn run_checks() -> ExitCode {
    let mut all_pass = true;

    let proc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, DEMO_TARGET_PID) };
    let open_ok = !proc.is_null();
    check(&mut all_pass, "open_process", open_ok, &format!("handle={proc:?}"));
    if !open_ok {
        println!("sample-tool: ABORT (OpenProcess failed; is the daemon reachable?)");
        return ExitCode::from(10);
    }

    let mut magic = [0u8; 16];
    let magic_ok = rpm(proc, DEMO_MAGIC_ADDR, &mut magic) && magic == DEMO_MAGIC;
    check(&mut all_pass, "read_magic", magic_ok, &format!("got={:02X?}", &magic));

    let payload: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    let wrote = wpm(proc, DEMO_SLOT_ADDR, &payload);
    let mut readback = [0u8; 8];
    let read_back_ok = rpm(proc, DEMO_SLOT_ADDR, &mut readback);
    let write_ok = wrote && read_back_ok && readback == payload && readback != [0u8; 8];
    check(&mut all_pass, "write_then_read", write_ok, &format!("readback={:02X?}", &readback));

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

    let found_proc = toolhelp_find_target();
    check(
        &mut all_pass,
        "toolhelp_process",
        found_proc,
        &format!("looking for {DEMO_MODULE_NAME} pid {DEMO_TARGET_PID}"),
    );

    let found_mod = enum_modules_find_target(proc);
    check(&mut all_pass, "enum_modules", found_mod, &format!("looking for {DEMO_MODULE_NAME}"));

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

    let alloc = unsafe {
        VirtualAllocEx(proc, std::ptr::null_mut(), 0x1000, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    };
    let alloc_refused = alloc.is_null();
    check(&mut all_pass, "alloc_ex_refused", alloc_refused, &format!("VirtualAllocEx={alloc:?}"));

    let mut mbi: MemoryBasicInformation = unsafe { std::mem::zeroed() };
    let n = unsafe {
        VirtualQueryEx(
            proc,
            DEMO_MAGIC_ADDR as *const c_void,
            &mut mbi,
            std::mem::size_of::<MemoryBasicInformation>(),
        )
    };
    let query_ok = n == std::mem::size_of::<MemoryBasicInformation>() && mbi.protect != PAGE_NOACCESS;
    check(&mut all_pass, "query_ex_region", query_ok, &format!("ret={n} protect={:#x}", mbi.protect));

    let close_ok = unsafe { CloseHandle(proc) } != 0;
    check(&mut all_pass, "close_synthetic", close_ok, "CloseHandle(synthetic)==TRUE");

    if all_pass {
        println!("sample-tool: ALL PASS");
        ExitCode::SUCCESS
    } else {
        println!("sample-tool: FAILED (see check lines above)");
        ExitCode::from(11)
    }
}

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

fn run_interception_selftest() -> ExitCode {
    let synthetic = 0xDEC0_0000_0000_0001usize as Handle;
    let r = unsafe { CloseHandle(synthetic) };
    if r != 0 {
        println!("INTERCEPTED");
    } else {
        println!("passthrough");
    }
    ExitCode::SUCCESS
}

type NtQSI = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
type OpenProcFn = unsafe extern "system" fn(u32, i32, u32) -> Handle;
type RpmFn = unsafe extern "system" fn(Handle, *const c_void, *mut c_void, usize, *mut usize) -> i32;
type WpmFn = unsafe extern "system" fn(Handle, *mut c_void, *const c_void, usize, *mut usize) -> i32;

const SYSTEM_PROCESS_INFORMATION: u32 = 5;

unsafe fn resolve(module: &[u8], name: &[u8]) -> *mut c_void {
    unsafe {
        let h = LoadLibraryA(module.as_ptr());
        if h.is_null() {
            return std::ptr::null_mut();
        }
        GetProcAddress(h, name.as_ptr())
    }
}

fn find_dynamic_pid() -> Option<u32> {
    unsafe {
        let p = resolve(b"ntdll.dll\0", b"NtQuerySystemInformation\0");
        if p.is_null() {
            return None;
        }
        let nt_qsi: NtQSI = std::mem::transmute(p);
        let mut need: u32 = 0;
        nt_qsi(SYSTEM_PROCESS_INFORMATION, std::ptr::null_mut(), 0, &mut need);
        if need == 0 {
            return None;
        }
        let mut buf = vec![0u8; need as usize + 0x1000];
        let st = nt_qsi(
            SYSTEM_PROCESS_INFORMATION,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut need,
        );
        if st != 0 {
            return None;
        }
        let mut off = 0usize;
        loop {
            let entry = buf.as_ptr().add(off);
            let next = (entry as *const u32).read_unaligned();
            let name_len = (entry.add(0x38) as *const u16).read_unaligned() as usize;
            let name_buf = (entry.add(0x40) as *const u64).read_unaligned() as *const u16;
            let pid = (entry.add(0x50) as *const u64).read_unaligned() as u32;
            if !name_buf.is_null() && name_len > 0 {
                let units = std::slice::from_raw_parts(name_buf, name_len / 2);
                if String::from_utf16_lossy(units) == DEMO_MODULE_NAME {
                    return Some(pid);
                }
            }
            if next == 0 {
                break;
            }
            off += next as usize;
        }
        None
    }
}

fn run_dynamic() -> ExitCode {
    let mut all_pass = true;

    let pid = find_dynamic_pid();
    let enum_ok = pid == Some(DEMO_TARGET_PID);
    check(&mut all_pass, "dynamic_enumerate", enum_ok, &format!("found pid {pid:?}"));
    let pid = match pid {
        Some(p) => p,
        None => {
            println!("sample-tool dynamic: ABORT (NtQuerySystemInformation did not route)");
            return ExitCode::from(30);
        }
    };

    unsafe {
        let open: OpenProcFn = std::mem::transmute(resolve(b"kernel32.dll\0", b"OpenProcess\0"));
        let rpm: RpmFn = std::mem::transmute(resolve(b"kernel32.dll\0", b"ReadProcessMemory\0"));
        let wpm: WpmFn = std::mem::transmute(resolve(b"kernel32.dll\0", b"WriteProcessMemory\0"));

        let proc = open(PROCESS_ALL_ACCESS, 0, pid);
        check(&mut all_pass, "dynamic_open", !proc.is_null(), &format!("handle={proc:?}"));

        let mut magic = [0u8; 16];
        let mut n: usize = 0;
        let read_ok = rpm(
            proc,
            DEMO_MAGIC_ADDR as *const c_void,
            magic.as_mut_ptr() as *mut c_void,
            16,
            &mut n,
        ) != 0
            && magic == DEMO_MAGIC;
        check(&mut all_pass, "dynamic_read_magic", read_ok, &format!("got={:02X?}", &magic));

        let payload: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04];
        let mut nb: usize = 0;
        let wrote = wpm(
            proc,
            DEMO_SLOT_ADDR as *mut c_void,
            payload.as_ptr() as *const c_void,
            8,
            &mut nb,
        ) != 0;
        let mut back = [0u8; 8];
        let read_back = rpm(
            proc,
            DEMO_SLOT_ADDR as *const c_void,
            back.as_mut_ptr() as *mut c_void,
            8,
            &mut n,
        ) != 0;
        let write_ok = wrote && read_back && back == payload;
        check(&mut all_pass, "dynamic_write", write_ok, &format!("readback={:02X?}", &back));

        CloseHandle(proc);
    }

    if all_pass {
        println!("sample-tool dynamic: ALL PASS");
        ExitCode::SUCCESS
    } else {
        println!("sample-tool dynamic: FAILED");
        ExitCode::from(31)
    }
}

fn install_via_loadlibrary() -> Result<(), ExitCode> {
    let dll = b"decant_interpose.dll\0";
    let sym = b"decant_install_hooks\0";
    unsafe {
        let module = LoadLibraryA(dll.as_ptr());
        if module.is_null() {
            eprintln!("sample-tool: LoadLibraryA(decant_interpose.dll) failed");
            return Err(ExitCode::from(2));
        }
        let proc = GetProcAddress(module, sym.as_ptr());
        if proc.is_null() {
            eprintln!("sample-tool: GetProcAddress(decant_install_hooks) failed");
            return Err(ExitCode::from(3));
        }
        let install: extern "system" fn() -> i32 = std::mem::transmute(proc);
        let patched = install();
        eprintln!("sample-tool: decant_install_hooks patched {patched} slot(s)");
        if patched < 1 {
            eprintln!("sample-tool: installer patched nothing");
            return Err(ExitCode::from(4));
        }
    }
    Ok(())
}
