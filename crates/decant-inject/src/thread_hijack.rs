use std::ffi::c_void;

use crate::{
    InjectError, InjectionRequest, Injector, LoadInfo, Portability, sdk,
    thread_hijack_release_event_name,
};

const CONTEXT_CONTROL: u32 = 0x0010_0001;
const SYNCHRONIZE: u32 = 0x0010_0000;

pub struct ThreadHijackInjector;

impl Injector for ThreadHijackInjector {
    fn name(&self) -> &str {
        "thread-hijack"
    }

    fn portability(&self) -> Portability {
        Portability::PrologueBytes
    }

    fn inject(&self, req: &InjectionRequest) -> Result<LoadInfo, InjectError> {
        let mut path = req.carafe_path.to_string_lossy().into_owned().into_bytes();
        path.push(0);
        let mut release = thread_hijack_release_event_name(&req.ready.name).into_bytes();
        release.push(0);

        unsafe {
            let proc = req.target.0;
            let original_rip = thread_rip(req.main_thread.0)?;
            let load_library = kernel32_proc(b"LoadLibraryA\0")?;
            let open_event = kernel32_proc(b"OpenEventA\0")?;
            let wait = kernel32_proc(b"WaitForSingleObject\0")?;
            let close = kernel32_proc(b"CloseHandle\0")?;
            let code_len = stub(0, 0, 0, load_library, open_event, wait, close).len();
            let total = code_len + path.len() + release.len();
            let remote = sdk::alloc(proc, total, sdk::PAGE_EXECUTE_READWRITE)?;
            let remote_base = remote as usize;
            let path_addr = remote_base + code_len;
            let release_addr = path_addr + path.len();
            let mut bytes = stub(
                original_rip,
                path_addr,
                release_addr,
                load_library,
                open_event,
                wait,
                close,
            );
            bytes.extend_from_slice(&path);
            bytes.extend_from_slice(&release);
            sdk::write(proc, remote, &bytes)?;
            set_thread_rip(req.main_thread.0, remote_base)?;
            Ok(LoadInfo {
                method: self.name().to_string(),
                remote_base: Some(remote_base),
                notes: vec!["main thread context points at loader stub".into()],
            })
        }
    }
}

#[repr(C, align(16))]
struct Context {
    p1_home: u64,
    p2_home: u64,
    p3_home: u64,
    p4_home: u64,
    p5_home: u64,
    p6_home: u64,
    context_flags: u32,
    mx_csr: u32,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    eflags: u32,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    flt_save: [u8; 512],
    vector_register: [u8; 26 * 16],
    vector_control: u64,
    debug_control: u64,
    last_branch_to_rip: u64,
    last_branch_from_rip: u64,
    last_exception_to_rip: u64,
    last_exception_from_rip: u64,
}

unsafe fn thread_rip(thread: *mut c_void) -> Result<usize, InjectError> {
    let mut ctx: Context = unsafe { std::mem::zeroed() };
    ctx.context_flags = CONTEXT_CONTROL;
    match unsafe { sdk::raw::GetThreadContext(thread, &mut ctx as *mut Context as *mut c_void) } {
        0 => Err(InjectError::ThreadHijack(format!(
            "GetThreadContext failed (err={})",
            unsafe { sdk::raw::GetLastError() }
        ))),
        _ => Ok(ctx.rip as usize),
    }
}

unsafe fn set_thread_rip(thread: *mut c_void, rip: usize) -> Result<(), InjectError> {
    let mut ctx: Context = unsafe { std::mem::zeroed() };
    ctx.context_flags = CONTEXT_CONTROL;
    if unsafe { sdk::raw::GetThreadContext(thread, &mut ctx as *mut Context as *mut c_void) } == 0 {
        return Err(InjectError::ThreadHijack(format!(
            "GetThreadContext failed (err={})",
            unsafe { sdk::raw::GetLastError() }
        )));
    }
    ctx.rip = rip as u64;
    match unsafe { sdk::raw::SetThreadContext(thread, &ctx as *const Context as *const c_void) } {
        0 => Err(InjectError::ThreadHijack(format!(
            "SetThreadContext failed (err={})",
            unsafe { sdk::raw::GetLastError() }
        ))),
        _ => Ok(()),
    }
}

unsafe fn kernel32_proc(name: &[u8]) -> Result<usize, InjectError> {
    let kernel32 = unsafe { sdk::raw::GetModuleHandleA(b"kernel32.dll\0".as_ptr()) };
    let proc = unsafe { sdk::raw::GetProcAddress(kernel32, name.as_ptr()) };
    match proc.is_null() {
        true => Err(InjectError::ThreadHijack(format!(
            "could not resolve kernel32!{}",
            String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
        ))),
        false => Ok(proc as usize),
    }
}

fn stub(
    original_rip: usize,
    path: usize,
    release: usize,
    load_library: usize,
    open_event: usize,
    wait: usize,
    close: usize,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[
        0x9C, 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41,
        0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x49, 0x89, 0xE4, 0x48, 0x83, 0xE4,
        0xF0, 0x48, 0x83, 0xEC, 0x20,
    ]);
    mov_rcx(&mut b, path);
    mov_rax(&mut b, load_library);
    call_rax(&mut b);
    b.push(0xB9);
    b.extend_from_slice(&SYNCHRONIZE.to_le_bytes());
    b.extend_from_slice(&[0x31, 0xD2]);
    mov_r8(&mut b, release);
    mov_rax(&mut b, open_event);
    call_rax(&mut b);
    b.extend_from_slice(&[0x48, 0x85, 0xC0]);
    let je_at = b.len();
    b.extend_from_slice(&[0x74, 0x00]);
    b.extend_from_slice(&[0x48, 0x89, 0xC3, 0x48, 0x89, 0xC1, 0xBA]);
    b.extend_from_slice(&sdk::INFINITE.to_le_bytes());
    mov_rax(&mut b, wait);
    call_rax(&mut b);
    b.extend_from_slice(&[0x48, 0x89, 0xD9]);
    mov_rax(&mut b, close);
    call_rax(&mut b);
    let after_wait = b.len();
    b[je_at + 1] = (after_wait - (je_at + 2)) as u8;
    b.extend_from_slice(&[
        0x4C, 0x89, 0xE4, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A,
        0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58, 0x9D,
    ]);
    mov_rax(&mut b, original_rip);
    b.extend_from_slice(&[0xFF, 0xE0]);
    b
}

fn mov_rax(b: &mut Vec<u8>, value: usize) {
    b.extend_from_slice(&[0x48, 0xB8]);
    b.extend_from_slice(&(value as u64).to_le_bytes());
}

fn mov_rcx(b: &mut Vec<u8>, value: usize) {
    b.extend_from_slice(&[0x48, 0xB9]);
    b.extend_from_slice(&(value as u64).to_le_bytes());
}

fn mov_r8(b: &mut Vec<u8>, value: usize) {
    b.extend_from_slice(&[0x49, 0xB8]);
    b.extend_from_slice(&(value as u64).to_le_bytes());
}

fn call_rax(b: &mut Vec<u8>) {
    b.extend_from_slice(&[0xFF, 0xD0]);
}
