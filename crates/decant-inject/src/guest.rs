use std::fmt;
use std::path::{Path, PathBuf};

use crate::{DecantConfig, InjectError, InjectionDomain, Method};

fn guest_timeout_ms() -> u32 {
    5000
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GuestPortability {
    GuestPublicExports,
    GuestLoaderInternals,
    GuestThreadContext,
    ExternalAgent,
}

impl GuestPortability {
    pub fn label(self) -> &'static str {
        match self {
            GuestPortability::GuestPublicExports => "guest-public-exports",
            GuestPortability::GuestLoaderInternals => "guest-loader-internals",
            GuestPortability::GuestThreadContext => "guest-thread-context",
            GuestPortability::ExternalAgent => "external-agent",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestAllocationMethod {
    #[default]
    VirtualAlloc,
    ExistingRegion,
    PageTableMap,
}

impl GuestAllocationMethod {
    pub fn label(self) -> &'static str {
        match self {
            GuestAllocationMethod::VirtualAlloc => "virtual-alloc",
            GuestAllocationMethod::ExistingRegion => "existing-region",
            GuestAllocationMethod::PageTableMap => "page-table-map",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestExecutionMethod {
    #[default]
    ThreadHijack,
    Apc,
    ExternalAgent,
    None,
}

impl GuestExecutionMethod {
    pub fn label(self) -> &'static str {
        match self {
            GuestExecutionMethod::ThreadHijack => "thread-hijack",
            GuestExecutionMethod::Apc => "apc",
            GuestExecutionMethod::ExternalAgent => "external-agent",
            GuestExecutionMethod::None => "none",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestVerificationMethod {
    #[default]
    ResultBlock,
    ExportPoll,
    None,
}

impl GuestVerificationMethod {
    pub fn label(self) -> &'static str {
        match self {
            GuestVerificationMethod::ResultBlock => "result-block",
            GuestVerificationMethod::ExportPoll => "export-poll",
            GuestVerificationMethod::None => "none",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestExecutionConfig {
    #[serde(default)]
    pub method: GuestExecutionMethod,
    #[serde(default = "guest_timeout_ms")]
    pub timeout_ms: u32,
}

impl Default for GuestExecutionConfig {
    fn default() -> Self {
        Self {
            method: GuestExecutionMethod::ThreadHijack,
            timeout_ms: guest_timeout_ms(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestVerificationConfig {
    #[serde(default)]
    pub method: GuestVerificationMethod,
    #[serde(default = "guest_timeout_ms")]
    pub timeout_ms: u32,
}

impl Default for GuestVerificationConfig {
    fn default() -> Self {
        Self {
            method: GuestVerificationMethod::ResultBlock,
            timeout_ms: guest_timeout_ms(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestInjectionConfig {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub process: Option<String>,
    #[serde(default)]
    pub payload_path: Option<PathBuf>,
    #[serde(default)]
    pub allocation: GuestAllocationMethod,
    #[serde(default)]
    pub execution: GuestExecutionConfig,
    #[serde(default)]
    pub verification: GuestVerificationConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestProcessSelector {
    pub pid: Option<u32>,
    pub name: Option<String>,
}

impl GuestProcessSelector {
    pub fn validate(&self) -> Result<(), GuestInjectError> {
        let name = self
            .name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        match (self.pid, name) {
            (Some(_), None) => Ok(()),
            (None, Some(_)) => Ok(()),
            (Some(_), Some(_)) => Err(GuestInjectError::Config(
                "set either guest.pid or guest.process, not both".into(),
            )),
            (None, None) => Err(GuestInjectError::Config(
                "set guest.pid or guest.process for guest injection".into(),
            )),
        }
    }

    pub fn label(&self) -> String {
        match (self.pid, self.name.as_deref()) {
            (Some(pid), None) => pid.to_string(),
            (None, Some(name)) => name.to_string(),
            (Some(pid), Some(name)) => format!("{name} ({pid})"),
            (None, None) => "<unset>".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestInjectionPlan {
    pub method: Method,
    pub target: GuestProcessSelector,
    pub payload_path: PathBuf,
    pub allocation: GuestAllocationMethod,
    pub execution: GuestExecutionConfig,
    pub verification: GuestVerificationConfig,
    pub timeout_ms: u32,
}

impl GuestInjectionPlan {
    pub fn from_config(config: &DecantConfig) -> Result<Self, GuestInjectError> {
        match config.injection.domain {
            InjectionDomain::Guest => {}
            InjectionDomain::Tool => {
                return Err(GuestInjectError::Config(
                    "set injection.domain = \"guest\" for guest injection".into(),
                ));
            }
        }
        match config.injection.method {
            Method::ManualMap => {}
            Method::ThreadHijack => {
                return Err(GuestInjectError::Config(
                    "for guest injection, set method = \"manual-map\" and guest.execution.method = \"thread-hijack\"".into(),
                ));
            }
            Method::Standard | Method::Plugin | Method::External => {
                return Err(GuestInjectError::Config(
                    "guest injection currently accepts method = \"manual-map\"".into(),
                ));
            }
        }
        let target = GuestProcessSelector {
            pid: config.guest.pid,
            name: config.guest.process.clone(),
        };
        target.validate()?;
        let payload_path = match &config.guest.payload_path {
            Some(path) => path.clone(),
            None => {
                return Err(GuestInjectError::Config(
                    "set guest.payload_path to the DLL image".into(),
                ));
            }
        };
        Ok(Self {
            method: config.injection.method,
            target,
            payload_path,
            allocation: config.guest.allocation,
            execution: config.guest.execution.clone(),
            verification: config.guest.verification.clone(),
            timeout_ms: config.injection.timeout_ms,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuestCapabilities {
    pub list_processes: bool,
    pub module_list: bool,
    pub module_exports: bool,
    pub read_memory: bool,
    pub write_memory: bool,
    pub memory_map: bool,
    pub allocate_memory: bool,
    pub protect_memory: bool,
    pub execute_thread_context: bool,
    pub wait_for_result: bool,
}

impl GuestCapabilities {
    pub fn memflow_passive() -> Self {
        Self {
            list_processes: true,
            module_list: true,
            module_exports: true,
            read_memory: true,
            write_memory: true,
            memory_map: true,
            allocate_memory: false,
            protect_memory: false,
            execute_thread_context: false,
            wait_for_result: true,
        }
    }

    pub fn missing_manual_map(self) -> Vec<&'static str> {
        let checks = [
            (self.list_processes, "list-processes"),
            (self.module_list, "module-list"),
            (self.module_exports, "module-exports"),
            (self.read_memory, "read-memory"),
            (self.write_memory, "write-memory"),
            (self.memory_map, "memory-map"),
            (self.allocate_memory, "allocate-memory"),
            (self.protect_memory, "protect-memory"),
            (self.execute_thread_context, "execute-thread-context"),
            (self.wait_for_result, "wait-for-result"),
        ];
        checks
            .into_iter()
            .filter_map(|(ok, name)| match ok {
                true => None,
                false => Some(name),
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestMemoryProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl GuestMemoryProtection {
    pub const READ_WRITE_EXECUTE: Self = Self {
        read: true,
        write: true,
        execute: true,
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestProcessInfo {
    pub pid: u32,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestMemoryRegion {
    pub base: u64,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

pub struct GuestInjectionRequest<'a> {
    pub plan: &'a GuestInjectionPlan,
    pub payload_path: &'a Path,
    pub payload_image: &'a [u8],
}

pub struct GuestLoadInfo {
    pub method: String,
    pub pid: u32,
    pub remote_base: Option<u64>,
    pub notes: Vec<String>,
}

#[derive(Debug)]
pub enum GuestInjectError {
    Config(String),
    Backend(String),
    Process(String),
    Image(String),
    Unsupported {
        operation: &'static str,
        reason: String,
    },
}

impl fmt::Display for GuestInjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuestInjectError::Config(m) => write!(f, "guest config: {m}"),
            GuestInjectError::Backend(m) => write!(f, "guest backend: {m}"),
            GuestInjectError::Process(m) => write!(f, "guest process: {m}"),
            GuestInjectError::Image(m) => write!(f, "guest image: {m}"),
            GuestInjectError::Unsupported { operation, reason } => {
                write!(f, "{operation} unsupported: {reason}")
            }
        }
    }
}

impl std::error::Error for GuestInjectError {}

impl From<InjectError> for GuestInjectError {
    fn from(value: InjectError) -> Self {
        GuestInjectError::Image(value.to_string())
    }
}

pub trait GuestMemoryBackend {
    fn capabilities(&self) -> GuestCapabilities;
    fn list_processes(&self) -> Result<Vec<GuestProcessInfo>, GuestInjectError>;
    fn module_list(&self, pid: u32) -> Result<Vec<GuestModuleInfo>, GuestInjectError>;
    fn module_exports(
        &self,
        pid: u32,
        module: &str,
    ) -> Result<Vec<(String, u64)>, GuestInjectError>;
    fn memory_map(&self, pid: u32) -> Result<Vec<GuestMemoryRegion>, GuestInjectError>;
    fn read(&self, pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, GuestInjectError>;
    fn write(&self, pid: u32, addr: u64, data: &[u8]) -> Result<(), GuestInjectError>;

    fn allocate(
        &self,
        _pid: u32,
        _size: usize,
        _protection: GuestMemoryProtection,
    ) -> Result<u64, GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "guest allocation",
            reason: "backend does not expose guest virtual allocation".into(),
        })
    }

    fn protect(
        &self,
        _pid: u32,
        _addr: u64,
        _size: usize,
        _protection: GuestMemoryProtection,
    ) -> Result<(), GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "guest protection change",
            reason: "backend does not expose guest page protection changes".into(),
        })
    }

    fn execute(
        &self,
        _pid: u32,
        _entry: u64,
        _argument: u64,
        _timeout_ms: u32,
    ) -> Result<u64, GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "guest execution",
            reason: "backend does not expose guest thread context control".into(),
        })
    }

    fn resolve_process(
        &self,
        target: &GuestProcessSelector,
    ) -> Result<GuestProcessInfo, GuestInjectError> {
        target.validate()?;
        let processes = self.list_processes()?;
        match (target.pid, target.name.as_deref()) {
            (Some(pid), _) => processes
                .into_iter()
                .find(|p| p.pid == pid)
                .ok_or_else(|| GuestInjectError::Process(format!("pid {pid} not found"))),
            (None, Some(name)) => processes
                .into_iter()
                .find(|p| p.name.eq_ignore_ascii_case(name))
                .ok_or_else(|| GuestInjectError::Process(format!("process {name:?} not found"))),
            (None, None) => Err(GuestInjectError::Config(
                "set guest.pid or guest.process for guest injection".into(),
            )),
        }
    }
}

pub trait GuestInjector {
    fn name(&self) -> &str;
    fn portability(&self) -> GuestPortability;
    fn inject(
        &self,
        backend: &dyn GuestMemoryBackend,
        req: &GuestInjectionRequest<'_>,
    ) -> Result<GuestLoadInfo, GuestInjectError>;
}

pub struct GuestManualMapInjector;

impl GuestInjector for GuestManualMapInjector {
    fn name(&self) -> &str {
        "manual-map"
    }

    fn portability(&self) -> GuestPortability {
        GuestPortability::GuestThreadContext
    }

    fn inject(
        &self,
        backend: &dyn GuestMemoryBackend,
        req: &GuestInjectionRequest<'_>,
    ) -> Result<GuestLoadInfo, GuestInjectError> {
        if req.payload_image.is_empty() {
            return Err(GuestInjectError::Image(
                "payload_image is empty; guest manual-map requires DLL bytes".into(),
            ));
        }
        let missing = backend.capabilities().missing_manual_map();
        if !missing.is_empty() {
            return Err(GuestInjectError::Unsupported {
                operation: "guest manual-map",
                reason: format!("backend missing {}", missing.join(", ")),
            });
        }
        let process = backend.resolve_process(&req.plan.target)?;
        Err(GuestInjectError::Unsupported {
            operation: "guest manual-map",
            reason: format!(
                "backend reports the required primitives for pid {}, but the guest PE mapper is not connected yet",
                process.pid
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_requires_pid_or_name() {
        let target = GuestProcessSelector {
            pid: None,
            name: None,
        };
        assert!(matches!(
            target.validate(),
            Err(GuestInjectError::Config(_))
        ));
    }

    #[test]
    fn memflow_capabilities_report_active_missing() {
        let missing = GuestCapabilities::memflow_passive().missing_manual_map();
        assert!(missing.contains(&"allocate-memory"));
        assert!(missing.contains(&"execute-thread-context"));
    }

    #[test]
    fn thread_hijack_is_an_execution_policy() {
        let config = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"thread-hijack\"\n\
             [guest]\npid = 1\npayload_path = \"payload.dll\"\n",
        )
        .unwrap();
        let err = GuestInjectionPlan::from_config(&config).unwrap_err();
        assert!(matches!(err, GuestInjectError::Config(_)));
    }
}
