use std::ffi::c_void;
use std::fmt;
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Portability {
    PublicExportsOnly,
    LoaderInternals,
    PrologueBytes,
}

impl Portability {
    pub fn label(self) -> &'static str {
        match self {
            Portability::PublicExportsOnly => "public-exports-only",
            Portability::LoaderInternals => "loader-internals",
            Portability::PrologueBytes => "prologue-bytes",
        }
    }

    pub fn upholds_export_guarantee(self) -> bool {
        matches!(self, Portability::PublicExportsOnly)
    }
}

#[derive(Clone, Copy)]
pub struct ProcessHandle(pub *mut c_void);

#[derive(Clone, Copy)]
pub struct ThreadHandle(pub *mut c_void);

// The name of the sync primitive the carafe signals once its hooks are installed.
// The harness creates it, passes the name in, and waits on it before resuming the
// target; an empty name means no handshake is expected.
#[derive(Clone)]
pub struct ReadyToken {
    pub name: String,
}

impl ReadyToken {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub fn none() -> Self {
        Self {
            name: String::new(),
        }
    }
}

// Carries enough for both method classes: loader-based methods read carafe_path,
// manual-map methods read carafe_image. A method uses whichever it needs.
pub struct InjectionRequest<'a> {
    pub target: ProcessHandle,
    pub main_thread: ThreadHandle,
    pub carafe_path: &'a Path,
    pub carafe_image: &'a [u8],
    pub ready: ReadyToken,
}

pub struct LoadInfo {
    pub method: String,
    pub remote_base: Option<usize>,
    pub notes: Vec<String>,
}

#[derive(Debug)]
pub enum InjectError {
    RemoteAlloc(u32),
    RemoteWrite(u32),
    ResolveLoadLibrary,
    RemoteThread(u32),
    Timeout,
    Unsupported(String),
    Plugin(String),
    Config(String),
}

impl fmt::Display for InjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InjectError::RemoteAlloc(e) => write!(f, "remote allocation failed (err={e})"),
            InjectError::RemoteWrite(e) => write!(f, "remote write failed (err={e})"),
            InjectError::ResolveLoadLibrary => write!(f, "could not resolve kernel32!LoadLibraryA"),
            InjectError::RemoteThread(e) => write!(f, "remote thread creation failed (err={e})"),
            InjectError::Timeout => write!(f, "carafe did not signal ready before the timeout"),
            InjectError::Unsupported(m) => write!(f, "unsupported: {m}"),
            InjectError::Plugin(m) => write!(f, "plugin: {m}"),
            InjectError::Config(m) => write!(f, "config: {m}"),
        }
    }
}

impl std::error::Error for InjectError {}

pub trait Injector {
    fn name(&self) -> &str;
    fn portability(&self) -> Portability;
    fn inject(&self, req: &InjectionRequest) -> Result<LoadInfo, InjectError>;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Method {
    #[default]
    Standard,
    ManualMap,
    ThreadHijack,
    Plugin,
    External,
}

fn default_timeout_ms() -> u32 {
    5000
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InjectionConfig {
    #[serde(default)]
    pub method: Method,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u32,
    #[serde(default)]
    pub plugin_path: Option<std::path::PathBuf>,
    #[serde(default)]
    pub external_command: Option<Vec<String>>,
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            method: Method::Standard,
            timeout_ms: default_timeout_ms(),
            plugin_path: None,
            external_command: None,
        }
    }
}

#[derive(serde::Deserialize)]
struct ConfigFile {
    #[serde(default)]
    injection: InjectionConfig,
}

impl InjectionConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, InjectError> {
        toml::from_str::<ConfigFile>(s)
            .map(|c| c.injection)
            .map_err(|e| InjectError::Config(e.message().to_string()))
    }

    // Absent file resolves to defaults; a present but malformed file is an error.
    pub fn load(path: &Path) -> Result<Self, InjectError> {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::from_toml_str(&s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(InjectError::Config(e.to_string())),
        }
    }
}

#[cfg(windows)]
mod win32 {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn VirtualAllocEx(
            process: *mut c_void,
            address: *mut c_void,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut c_void;
        pub fn WriteProcessMemory(
            process: *mut c_void,
            base_address: *mut c_void,
            buffer: *const c_void,
            size: usize,
            written: *mut usize,
        ) -> i32;
        pub fn CreateRemoteThread(
            process: *mut c_void,
            thread_attributes: *const c_void,
            stack_size: usize,
            start_address: *mut c_void,
            parameter: *mut c_void,
            creation_flags: u32,
            thread_id: *mut u32,
        ) -> *mut c_void;
        pub fn GetModuleHandleA(module_name: *const u8) -> *mut c_void;
        pub fn GetProcAddress(module: *mut c_void, proc_name: *const u8) -> *mut c_void;
        pub fn LoadLibraryA(file_name: *const u8) -> *mut c_void;
        pub fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        pub fn CloseHandle(object: *mut c_void) -> i32;
        pub fn GetLastError() -> u32;
    }

    pub const MEM_COMMIT_RESERVE: u32 = 0x0000_1000 | 0x0000_2000;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const INFINITE: u32 = 0xFFFF_FFFF;
}

// Public-exports-only remote-thread LoadLibrary. Binds to documented kernel32
// exports only, so it holds across Wine versions (Portability::PublicExportsOnly).
#[cfg(windows)]
pub struct StandardInjector;

#[cfg(windows)]
impl Injector for StandardInjector {
    fn name(&self) -> &str {
        "standard"
    }

    fn portability(&self) -> Portability {
        Portability::PublicExportsOnly
    }

    fn inject(&self, req: &InjectionRequest) -> Result<LoadInfo, InjectError> {
        use win32::*;

        let mut path_bytes = req.carafe_path.to_string_lossy().into_owned().into_bytes();
        path_bytes.push(0);

        unsafe {
            let proc = req.target.0;
            let remote = VirtualAllocEx(
                proc,
                std::ptr::null_mut(),
                path_bytes.len(),
                MEM_COMMIT_RESERVE,
                PAGE_READWRITE,
            );
            if remote.is_null() {
                return Err(InjectError::RemoteAlloc(GetLastError()));
            }

            let mut written = 0usize;
            if WriteProcessMemory(
                proc,
                remote,
                path_bytes.as_ptr() as *const c_void,
                path_bytes.len(),
                &mut written,
            ) == 0
            {
                return Err(InjectError::RemoteWrite(GetLastError()));
            }

            let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
            let load_library = GetProcAddress(kernel32, b"LoadLibraryA\0".as_ptr());
            if load_library.is_null() {
                return Err(InjectError::ResolveLoadLibrary);
            }

            let thread = CreateRemoteThread(
                proc,
                std::ptr::null(),
                0,
                load_library,
                remote,
                0,
                std::ptr::null_mut(),
            );
            if thread.is_null() {
                return Err(InjectError::RemoteThread(GetLastError()));
            }

            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread);

            Ok(LoadInfo {
                method: self.name().to_string(),
                remote_base: Some(remote as usize),
                notes: Vec::new(),
            })
        }
    }
}

// Versioned C ABI for bring-your-own injectors. A plugin cdylib exports
// `decant_inject_abi() -> u32` returning this constant and
// `decant_inject(*mut DecantInjectRequest) -> i32` (0 = success). Bumped on any
// layout change to DecantInjectRequest.
pub const DECANT_INJECT_ABI: u32 = 1;

#[repr(C)]
pub struct DecantInjectRequest {
    pub abi_version: u32,
    pub target_process: *mut c_void,
    pub main_thread: *mut c_void,
    pub carafe_path: *const u16,
    pub carafe_image: *const u8,
    pub carafe_image_len: usize,
    pub ready_token_name: *const u16,
    pub out_remote_base: u64,
}

#[cfg(windows)]
fn wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// Loads a user cdylib against DECANT_INJECT_ABI and delegates the load to it.
// A plugin runs PE-side in the same Wine prefix, so it shares the handle
// namespace with the harness. The harness still owns the ready-token wait.
#[cfg(windows)]
pub struct PluginInjector {
    pub path: std::path::PathBuf,
}

#[cfg(windows)]
impl Injector for PluginInjector {
    fn name(&self) -> &str {
        "plugin"
    }

    fn portability(&self) -> Portability {
        Portability::LoaderInternals
    }

    fn inject(&self, req: &InjectionRequest) -> Result<LoadInfo, InjectError> {
        use win32::*;

        type AbiFn = unsafe extern "system" fn() -> u32;
        type InjectFn = unsafe extern "system" fn(*mut DecantInjectRequest) -> i32;

        let mut lib_path = self.path.to_string_lossy().into_owned().into_bytes();
        lib_path.push(0);

        let path_w = wide_z(&req.carafe_path.to_string_lossy());
        let token_w = wide_z(&req.ready.name);

        unsafe {
            let lib = LoadLibraryA(lib_path.as_ptr());
            if lib.is_null() {
                return Err(InjectError::Plugin(format!(
                    "loading plugin {} failed (err={}); a plugin must be a PE cdylib in this Wine prefix",
                    self.path.display(),
                    GetLastError()
                )));
            }

            let abi_sym = GetProcAddress(lib, b"decant_inject_abi\0".as_ptr());
            if abi_sym.is_null() {
                return Err(InjectError::Plugin(
                    "plugin missing export 'decant_inject_abi'".into(),
                ));
            }
            let abi = std::mem::transmute::<*mut c_void, AbiFn>(abi_sym)();
            if abi != DECANT_INJECT_ABI {
                return Err(InjectError::Plugin(format!(
                    "ABI mismatch: plugin reports {abi}, harness expects {DECANT_INJECT_ABI}"
                )));
            }

            let inject_sym = GetProcAddress(lib, b"decant_inject\0".as_ptr());
            if inject_sym.is_null() {
                return Err(InjectError::Plugin(
                    "plugin missing export 'decant_inject'".into(),
                ));
            }
            let inject = std::mem::transmute::<*mut c_void, InjectFn>(inject_sym);

            let mut c_req = DecantInjectRequest {
                abi_version: DECANT_INJECT_ABI,
                target_process: req.target.0,
                main_thread: req.main_thread.0,
                carafe_path: path_w.as_ptr(),
                carafe_image: req.carafe_image.as_ptr(),
                carafe_image_len: req.carafe_image.len(),
                ready_token_name: token_w.as_ptr(),
                out_remote_base: 0,
            };
            let rc = inject(&mut c_req);
            if rc != 0 {
                return Err(InjectError::Plugin(format!("plugin returned error {rc}")));
            }

            Ok(LoadInfo {
                method: self.name().to_string(),
                remote_base: (c_req.out_remote_base != 0).then_some(c_req.out_remote_base as usize),
                notes: Vec::new(),
            })
        }
    }
}

#[cfg(windows)]
impl InjectionConfig {
    pub fn injector(&self) -> Result<Box<dyn Injector>, InjectError> {
        match self.method {
            Method::Standard => Ok(Box::new(StandardInjector)),
            Method::ManualMap => Err(InjectError::Unsupported("manual-map".into())),
            Method::ThreadHijack => Err(InjectError::Unsupported("thread-hijack".into())),
            Method::Plugin => match &self.plugin_path {
                Some(p) => Ok(Box::new(PluginInjector { path: p.clone() })),
                None => Err(InjectError::Config(
                    "method = \"plugin\" requires plugin_path".into(),
                )),
            },
            Method::External => Err(InjectError::Unsupported("external".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_is_standard_defaults() {
        let c = InjectionConfig::from_toml_str("").unwrap();
        assert_eq!(c.method, Method::Standard);
        assert_eq!(c.timeout_ms, 5000);
        assert!(c.plugin_path.is_none());
    }

    #[test]
    fn injection_table_parses() {
        let c = InjectionConfig::from_toml_str(
            "[injection]\nmethod = \"manual-map\"\ntimeout_ms = 250\n",
        )
        .unwrap();
        assert_eq!(c.method, Method::ManualMap);
        assert_eq!(c.timeout_ms, 250);
    }

    #[test]
    fn unknown_method_errors() {
        assert!(matches!(
            InjectionConfig::from_toml_str("[injection]\nmethod = \"bogus\"\n"),
            Err(InjectError::Config(_))
        ));
    }
}
