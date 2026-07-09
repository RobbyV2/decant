//! Injection configuration, ABI, and loader implementations used by Decant.

#![allow(clippy::manual_c_str_literals, clippy::missing_safety_doc)]

use std::ffi::c_void;
use std::fmt;
use std::path::Path;

pub mod guest;
mod pe;

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
// target_pid lets out-of-process methods reopen the target by identifier rather
// than by a handle that is only valid inside the harness.
pub struct InjectionRequest<'a> {
    pub target: ProcessHandle,
    pub main_thread: ThreadHandle,
    pub target_pid: u32,
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
    RemoteRead(u32),
    RemoteWrite(u32),
    RemoteProtect(u32),
    ResolveLoadLibrary,
    RemoteThread(u32),
    Timeout,
    Unsupported(String),
    ManualMap(String),
    ThreadHijack(String),
    Plugin(String),
    External(String),
    Config(String),
}

impl fmt::Display for InjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InjectError::RemoteAlloc(e) => write!(f, "remote allocation failed (err={e})"),
            InjectError::RemoteRead(e) => write!(f, "remote read failed (err={e})"),
            InjectError::RemoteWrite(e) => write!(f, "remote write failed (err={e})"),
            InjectError::RemoteProtect(e) => write!(f, "remote protection change failed (err={e})"),
            InjectError::ResolveLoadLibrary => write!(f, "could not resolve kernel32!LoadLibraryA"),
            InjectError::RemoteThread(e) => write!(f, "remote thread creation failed (err={e})"),
            InjectError::Timeout => write!(f, "carafe did not signal ready before the timeout"),
            InjectError::Unsupported(m) => write!(f, "unsupported: {m}"),
            InjectError::ManualMap(m) => write!(f, "manual-map: {m}"),
            InjectError::ThreadHijack(m) => write!(f, "thread-hijack: {m}"),
            InjectError::Plugin(m) => write!(f, "plugin: {m}"),
            InjectError::External(m) => write!(f, "external: {m}"),
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

// Wire format for the external-process method: the harness writes one frame to
// the user command's stdin, the command reads it and performs the load out of
// process. Length-prefixed and platform-agnostic so both ends share this code
// and it round-trips in host tests.
pub mod external {
    use std::io::{self, Cursor, Read, Write};

    pub struct ExternalPayload {
        pub pid: u32,
        pub carafe_path: String,
        pub carafe_image: Vec<u8>,
        pub ready_token: String,
    }

    fn put(buf: &mut Vec<u8>, b: &[u8]) {
        buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
        buf.extend_from_slice(b);
    }

    pub fn write_request(
        w: &mut impl Write,
        pid: u32,
        carafe_path: &str,
        carafe_image: &[u8],
        ready_token: &str,
    ) -> io::Result<()> {
        let mut buf = pid.to_le_bytes().to_vec();
        put(&mut buf, carafe_path.as_bytes());
        put(&mut buf, carafe_image);
        put(&mut buf, ready_token.as_bytes());
        w.write_all(&buf)
    }

    fn read_u32(r: &mut impl Read) -> io::Result<u32> {
        let mut b = [0u8; 4];
        r.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn read_vec(r: &mut impl Read) -> io::Result<Vec<u8>> {
        let n = read_u32(r)? as usize;
        let mut v = vec![0u8; n];
        r.read_exact(&mut v)?;
        Ok(v)
    }

    pub fn read_request(r: &mut impl Read) -> io::Result<ExternalPayload> {
        let mut all = Vec::new();
        r.read_to_end(&mut all)?;
        let mut c = Cursor::new(all);
        let pid = read_u32(&mut c)?;
        let carafe_path = String::from_utf8_lossy(&read_vec(&mut c)?).into_owned();
        let carafe_image = read_vec(&mut c)?;
        let ready_token = String::from_utf8_lossy(&read_vec(&mut c)?).into_owned();
        Ok(ExternalPayload {
            pid,
            carafe_path,
            carafe_image,
            ready_token,
        })
    }
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

impl Method {
    pub fn label(self) -> &'static str {
        match self {
            Method::Standard => "standard",
            Method::ManualMap => "manual-map",
            Method::ThreadHijack => "thread-hijack",
            Method::Plugin => "plugin",
            Method::External => "external",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InjectionDomain {
    #[default]
    Tool,
    Guest,
}

fn default_timeout_ms() -> u32 {
    5000
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InjectionConfig {
    #[serde(default)]
    pub domain: InjectionDomain,
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
            domain: InjectionDomain::Tool,
            method: Method::Standard,
            timeout_ms: default_timeout_ms(),
            plugin_path: None,
            external_command: None,
        }
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct DecantConfig {
    #[serde(default)]
    pub injection: InjectionConfig,
    #[serde(default)]
    pub guest: guest::GuestInjectionConfig,
}

impl DecantConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, InjectError> {
        toml::from_str::<DecantConfig>(s).map_err(|e| InjectError::Config(e.message().to_string()))
    }

    pub fn load(path: &Path) -> Result<Self, InjectError> {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::from_toml_str(&s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(InjectError::Config(e.to_string())),
        }
    }
}

impl InjectionConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, InjectError> {
        DecantConfig::from_toml_str(s).map(|c| c.injection)
    }

    // Absent file resolves to defaults; a present but malformed file is an error.
    pub fn load(path: &Path) -> Result<Self, InjectError> {
        DecantConfig::load(path).map(|c| c.injection)
    }
}

#[cfg(windows)]
pub mod sdk;

#[cfg(windows)]
mod manual_map;

#[cfg(windows)]
mod thread_hijack;

#[cfg(windows)]
pub use manual_map::ManualMapInjector;
#[cfg(windows)]
pub use thread_hijack::ThreadHijackInjector;

pub fn thread_hijack_release_event_name(ready_name: &str) -> String {
    format!("{ready_name}_release")
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
        let mut path_bytes = req.carafe_path.to_string_lossy().into_owned().into_bytes();
        path_bytes.push(0);

        unsafe {
            let proc = req.target.0;
            let remote = sdk::alloc(proc, path_bytes.len(), sdk::PAGE_READWRITE)?;
            sdk::write(proc, remote, &path_bytes)?;

            let kernel32 = sdk::raw::GetModuleHandleA(b"kernel32.dll\0".as_ptr());
            let load_library = sdk::raw::GetProcAddress(kernel32, b"LoadLibraryA\0".as_ptr());
            if load_library.is_null() {
                return Err(InjectError::ResolveLoadLibrary);
            }

            sdk::create_remote_thread_and_wait(proc, load_library, remote)?;

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
        type AbiFn = unsafe extern "system" fn() -> u32;
        type InjectFn = unsafe extern "system" fn(*mut DecantInjectRequest) -> i32;

        let mut lib_path = self.path.to_string_lossy().into_owned().into_bytes();
        lib_path.push(0);

        let path_w = wide_z(&req.carafe_path.to_string_lossy());
        let token_w = wide_z(&req.ready.name);

        unsafe {
            let lib = sdk::raw::LoadLibraryA(lib_path.as_ptr());
            if lib.is_null() {
                return Err(InjectError::Plugin(format!(
                    "loading plugin {} failed (err={}); a plugin must be a PE cdylib in this Wine prefix",
                    self.path.display(),
                    sdk::raw::GetLastError()
                )));
            }

            let abi_sym = sdk::raw::GetProcAddress(lib, b"decant_inject_abi\0".as_ptr());
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

            let inject_sym = sdk::raw::GetProcAddress(lib, b"decant_inject\0".as_ptr());
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

// Hands the target PID plus the carafe path/bytes to a user-configured command
// over its stdin and lets that command perform the load out of process. The
// command must be a PE exe in the same Wine prefix to share the handle
// namespace. Verification is unchanged: the harness owns the ready-token wait,
// so whatever the command does, the target is resumed only once the carafe
// reports. The mechanism is opaque to the harness, so it reports below the
// public-export guarantee.
#[cfg(windows)]
pub struct ExternalInjector {
    pub command: Vec<String>,
}

#[cfg(windows)]
impl Injector for ExternalInjector {
    fn name(&self) -> &str {
        "external"
    }

    fn portability(&self) -> Portability {
        Portability::PrologueBytes
    }

    fn inject(&self, req: &InjectionRequest) -> Result<LoadInfo, InjectError> {
        use std::process::{Command, Stdio};

        let (prog, rest) = self
            .command
            .split_first()
            .ok_or_else(|| InjectError::Config("external_command is empty".into()))?;

        let mut child = Command::new(prog)
            .args(rest)
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| {
                InjectError::External(format!(
                    "spawning {prog}: {e}; the command must be a PE exe in this Wine prefix"
                ))
            })?;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| InjectError::External("command stdin unavailable".into()))?;
        external::write_request(
            &mut stdin,
            req.target_pid,
            &req.carafe_path.to_string_lossy(),
            req.carafe_image,
            &req.ready.name,
        )
        .map_err(|e| InjectError::External(format!("writing protocol frame: {e}")))?;
        drop(stdin);

        let status = child
            .wait()
            .map_err(|e| InjectError::External(format!("waiting on command: {e}")))?;
        match status.success() {
            true => Ok(LoadInfo {
                method: self.name().to_string(),
                remote_base: None,
                notes: vec![format!("delegated to: {}", self.command.join(" "))],
            }),
            false => Err(InjectError::External(format!(
                "command {prog} exited with {status}"
            ))),
        }
    }
}

#[cfg(windows)]
impl InjectionConfig {
    pub fn injector(&self) -> Result<Box<dyn Injector>, InjectError> {
        match self.method {
            Method::Standard => Ok(Box::new(StandardInjector)),
            Method::ManualMap => Ok(Box::new(ManualMapInjector)),
            Method::ThreadHijack => Ok(Box::new(ThreadHijackInjector)),
            Method::Plugin => match &self.plugin_path {
                Some(p) => Ok(Box::new(PluginInjector { path: p.clone() })),
                None => Err(InjectError::Config(
                    "method = \"plugin\" requires plugin_path".into(),
                )),
            },
            Method::External => match self.external_command.as_deref() {
                Some(cmd) if !cmd.is_empty() => Ok(Box::new(ExternalInjector {
                    command: cmd.to_vec(),
                })),
                _ => Err(InjectError::Config(
                    "method = \"external\" requires a non-empty external_command".into(),
                )),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_is_standard_defaults() {
        let c = InjectionConfig::from_toml_str("").unwrap();
        assert_eq!(c.domain, InjectionDomain::Tool);
        assert_eq!(c.method, Method::Standard);
        assert_eq!(c.timeout_ms, 5000);
        assert!(c.plugin_path.is_none());
    }

    #[test]
    fn injection_table_parses() {
        let c = InjectionConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\ntimeout_ms = 250\n",
        )
        .unwrap();
        assert_eq!(c.domain, InjectionDomain::Guest);
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

    #[test]
    fn external_command_parses() {
        let c = InjectionConfig::from_toml_str(
            "[injection]\nmethod = \"external\"\nexternal_command = [\"inject.exe\", \"--flag\"]\n",
        )
        .unwrap();
        assert_eq!(c.method, Method::External);
        assert_eq!(
            c.external_command.as_deref(),
            Some(&["inject.exe".to_string(), "--flag".to_string()][..])
        );
    }

    #[test]
    fn external_protocol_round_trips() {
        let mut buf = Vec::new();
        let image = [0xDEu8, 0xAD, 0xBE, 0xEF];
        external::write_request(
            &mut buf,
            4321,
            "c:/decant_interpose.dll",
            &image,
            "decant_ready_7",
        )
        .unwrap();
        let got = external::read_request(&mut &buf[..]).unwrap();
        assert_eq!(got.pid, 4321);
        assert_eq!(got.carafe_path, "c:/decant_interpose.dll");
        assert_eq!(got.carafe_image, image);
        assert_eq!(got.ready_token, "decant_ready_7");
    }

    #[test]
    fn decant_config_parses_guest_table() {
        let c = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\nprocess = \"notepad.exe\"\npayload_path = \"payload.dll\"\n",
        )
        .unwrap();
        let plan = guest::GuestInjectionPlan::from_config(&c).unwrap();
        assert_eq!(plan.method, Method::ManualMap);
        assert_eq!(plan.target.name.as_deref(), Some("notepad.exe"));
        assert_eq!(plan.payload_path, std::path::PathBuf::from("payload.dll"));
    }

    #[test]
    fn manual_map_flags_parse() {
        let c = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\nprocess = \"p\"\npayload_path = \"x.dll\"\n\
             delay_loads = \"skip\"\nsxs = \"probe\"\nforce_remap = true\n\
             high_memory = true\nis_dependency = true\nmanual_module_registry = \"track\"\n\
             dll_main_reserved_arg = [1, 2, 3, 4]\n",
        )
        .unwrap();
        let plan = guest::GuestInjectionPlan::from_config(&c).unwrap();
        assert_eq!(plan.delay_loads, guest::GuestDelayLoads::Skip);
        assert_eq!(plan.sxs, guest::GuestSxS::Probe);
        assert!(plan.force_remap);
        assert!(plan.high_memory);
        assert!(plan.is_dependency);
        assert_eq!(
            plan.manual_module_registry,
            guest::GuestManualModuleRegistry::Track
        );
        assert_eq!(
            plan.dll_main_reserved_arg.as_deref(),
            Some(&[1u8, 2, 3, 4][..])
        );
    }

    #[test]
    fn manual_map_flags_default() {
        let c = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\nprocess = \"p\"\npayload_path = \"x.dll\"\n",
        )
        .unwrap();
        let plan = guest::GuestInjectionPlan::from_config(&c).unwrap();
        assert_eq!(plan.delay_loads, guest::GuestDelayLoads::Resolve);
        assert_eq!(plan.sxs, guest::GuestSxS::Skip);
        assert!(!plan.force_remap);
        assert!(!plan.high_memory);
        assert!(!plan.is_dependency);
        assert_eq!(
            plan.manual_module_registry,
            guest::GuestManualModuleRegistry::Off
        );
        assert!(plan.dll_main_reserved_arg.is_none());
        assert!(plan.map_callback_path.is_none());
    }

    #[test]
    fn map_callback_parses() {
        let c = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\nprocess = \"p\"\npayload_path = \"x.dll\"\n\
             map_callback_path = \"callback.dll\"\n",
        )
        .unwrap();
        let plan = guest::GuestInjectionPlan::from_config(&c).unwrap();
        assert_eq!(
            plan.map_callback_path.as_deref(),
            Some(std::path::Path::new("callback.dll"))
        );
    }

    #[test]
    fn execution_methods_parse() {
        let methods = ["iat-hook", "remote-thread", "thread-hijack", "apc"];
        for m in &methods {
            let c = DecantConfig::from_toml_str(&format!(
                "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
                 [guest]\nprocess = \"p\"\npayload_path = \"x.dll\"\n\
                 [guest.execution]\nmethod = \"{m}\"\n"
            ))
            .unwrap();
            let plan = guest::GuestInjectionPlan::from_config(&c).unwrap();
            assert_eq!(plan.execution.method.label(), *m);
        }
    }
}
