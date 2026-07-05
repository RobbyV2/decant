#[cfg(windows)]
use decant_inject::{
    DECANT_INJECT_ABI, DecantInjectRequest, InjectionRequest, Injector, ProcessHandle, ReadyToken,
    StandardInjector, ThreadHandle,
};

#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "system" fn decant_inject_abi() -> u32 {
    DECANT_INJECT_ABI
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn decant_inject(req: *mut DecantInjectRequest) -> i32 {
    let req = match unsafe { req.as_mut() } {
        Some(r) => r,
        None => return 1,
    };
    let path = wide_to_string(req.carafe_path);
    let token = wide_to_string(req.ready_token_name);
    let image = match req.carafe_image.is_null() || req.carafe_image_len == 0 {
        true => &[][..],
        false => unsafe { std::slice::from_raw_parts(req.carafe_image, req.carafe_image_len) },
    };
    let ir = InjectionRequest {
        target: ProcessHandle(req.target_process),
        main_thread: ThreadHandle(req.main_thread),
        target_pid: 0,
        carafe_path: std::path::Path::new(&path),
        carafe_image: image,
        ready: ReadyToken::new(token),
    };
    match StandardInjector.inject(&ir) {
        Ok(info) => {
            req.out_remote_base = info.remote_base.unwrap_or(0) as u64;
            0
        }
        Err(_) => 2,
    }
}

#[cfg(windows)]
fn wide_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}
