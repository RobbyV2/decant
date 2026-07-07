use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::pe::{DLL_PROCESS_ATTACH, ImportSymbol, Pe, Section, u16_at, u32_at};
use crate::{DecantConfig, InjectError, InjectionDomain, Method};

const DEFAULT_HOOK_MODULE: &str = "kernel32.dll";
const DEFAULT_HOOK_FUNCTION: &str = "Sleep";
const STAGE_CAVE_SIZE: usize = 0x400;
const STAGE_RESULT_OFFSET: u64 = 0x20;
const STAGE_STUB_OFFSET: u64 = 0x100;
const STAGE_SCRATCH_OFFSET: u64 = 0x300;
const STAGE_UNWIND_OFFSET: u64 = 0x3E0;
const STAGE_SCRATCH_SIZE: usize = (STAGE_UNWIND_OFFSET - STAGE_SCRATCH_OFFSET) as usize;
const GUEST_PAGE_SIZE: usize = 0x1000;
const SCAN_CHUNK: u64 = 0x10000;
const SPOOFED_RETURN_SCAN_LIMIT: u64 = 0x40000;
const SPOOFED_CALL_LANDING_DELTA: u64 = 46;
const MEM_COMMIT_RESERVE: u64 = 0x0000_1000 | 0x0000_2000;
const PAGE_NOACCESS: u64 = 0x01;
const PAGE_READONLY: u64 = 0x02;
const PAGE_READWRITE: u64 = 0x04;
const PAGE_EXECUTE: u64 = 0x10;
const PAGE_EXECUTE_READ: u64 = 0x20;
const PAGE_EXECUTE_READWRITE: u64 = 0x40;
const CFG_CALL_TARGET_VALID: u64 = 0x1;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const RESULT_RUNNING: u64 = 1;
const RESULT_STATE: u64 = 2;
const RESULT_BLOCK_SIZE: usize = 16;
const OLD_PROTECT_RESULT_OFFSET: u64 = 12;
const MAX_EXPORT_FORWARD_DEPTH: usize = 8;
const EXPORT_HEADER_RETRIES: usize = 20;
const EXPORT_HEADER_RETRY_DELAY: Duration = Duration::from_millis(25);
const FRAMED_STUB_STACK_ALLOC: u8 = 0x68;

static ACTIVE_GUEST_INJECTIONS: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();

fn guest_timeout_ms() -> u32 {
    5000
}

fn default_hook_module() -> String {
    DEFAULT_HOOK_MODULE.into()
}

fn default_hook_function() -> String {
    DEFAULT_HOOK_FUNCTION.into()
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
    IatHook,
    RemoteThread,
    ThreadHijack,
    Apc,
    ExternalAgent,
    None,
}

impl GuestExecutionMethod {
    pub fn label(self) -> &'static str {
        match self {
            GuestExecutionMethod::IatHook => "iat-hook",
            GuestExecutionMethod::RemoteThread => "remote-thread",
            GuestExecutionMethod::ThreadHijack => "thread-hijack",
            GuestExecutionMethod::Apc => "apc",
            GuestExecutionMethod::ExternalAgent => "external-agent",
            GuestExecutionMethod::None => "none",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestDependencyPolicy {
    #[default]
    RequireLoaded,
    LoadWithGuestLoader,
}

impl GuestDependencyPolicy {
    pub fn label(self) -> &'static str {
        match self {
            GuestDependencyPolicy::RequireLoaded => "require-loaded",
            GuestDependencyPolicy::LoadWithGuestLoader => "load-with-guest-loader",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestTlsMode {
    #[default]
    CallbacksOnly,
    Skip,
    RequireStatic,
}

impl GuestTlsMode {
    pub fn label(self) -> &'static str {
        match self {
            GuestTlsMode::CallbacksOnly => "callbacks-only",
            GuestTlsMode::Skip => "skip",
            GuestTlsMode::RequireStatic => "require-static",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestFinalProtections {
    Rwx,
    #[default]
    Section,
}

impl GuestFinalProtections {
    pub fn label(self) -> &'static str {
        match self {
            GuestFinalProtections::Rwx => "rwx",
            GuestFinalProtections::Section => "section",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestLoaderMetadataPolicy {
    #[default]
    RejectUnsupported,
    BestEffort,
    AllowUnsupported,
}

impl GuestLoaderMetadataPolicy {
    pub fn label(self) -> &'static str {
        match self {
            GuestLoaderMetadataPolicy::RejectUnsupported => "reject-unsupported",
            GuestLoaderMetadataPolicy::BestEffort => "best-effort",
            GuestLoaderMetadataPolicy::AllowUnsupported => "allow-unsupported",
        }
    }

    fn allows_unregistered_metadata(self) -> bool {
        matches!(
            self,
            GuestLoaderMetadataPolicy::BestEffort | GuestLoaderMetadataPolicy::AllowUnsupported
        )
    }

    fn registers_public_metadata(self) -> bool {
        matches!(self, GuestLoaderMetadataPolicy::BestEffort)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestCallStackPolicy {
    #[default]
    Native,
    RegisteredUnwind,
}

impl GuestCallStackPolicy {
    pub fn label(self) -> &'static str {
        match self {
            GuestCallStackPolicy::Native => "native",
            GuestCallStackPolicy::RegisteredUnwind => "registered-unwind",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestPermissionTransitions {
    #[default]
    Standard,
    WriteThroughFinal,
}

impl GuestPermissionTransitions {
    pub fn label(self) -> &'static str {
        match self {
            GuestPermissionTransitions::Standard => "standard",
            GuestPermissionTransitions::WriteThroughFinal => "write-through-final",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestThreadStartPolicy {
    #[default]
    ExistingThread,
    RequireModuleBacked,
}

impl GuestThreadStartPolicy {
    pub fn label(self) -> &'static str {
        match self {
            GuestThreadStartPolicy::ExistingThread => "existing-thread",
            GuestThreadStartPolicy::RequireModuleBacked => "require-module-backed",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestImageBacking {
    #[default]
    Private,
    SecImage,
}

impl GuestImageBacking {
    pub fn label(self) -> &'static str {
        match self {
            GuestImageBacking::Private => "private",
            GuestImageBacking::SecImage => "sec-image",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestBaseAddress {
    #[default]
    Preferred,
    Randomized,
}

impl GuestBaseAddress {
    pub fn label(self) -> &'static str {
        match self {
            GuestBaseAddress::Preferred => "preferred",
            GuestBaseAddress::Randomized => "randomized",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestHeaderWipe {
    #[default]
    None,
    AfterLoad,
}

impl GuestHeaderWipe {
    pub fn label(self) -> &'static str {
        match self {
            GuestHeaderWipe::None => "none",
            GuestHeaderWipe::AfterLoad => "after-load",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestLoaderEntries {
    #[default]
    Absent,
    Synthesized,
}

impl GuestLoaderEntries {
    pub fn label(self) -> &'static str {
        match self {
            GuestLoaderEntries::Absent => "absent",
            GuestLoaderEntries::Synthesized => "synthesized",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestStackShaping {
    #[default]
    Native,
    Spoofed,
}

impl GuestStackShaping {
    pub fn label(self) -> &'static str {
        match self {
            GuestStackShaping::Native => "native",
            GuestStackShaping::Spoofed => "spoofed",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestCleanup {
    #[default]
    Resident,
    Tracked,
}

impl GuestCleanup {
    pub fn label(self) -> &'static str {
        match self {
            GuestCleanup::Resident => "resident",
            GuestCleanup::Tracked => "tracked",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestVadSpoof {
    #[default]
    Off,
    VadImageMap,
}

impl GuestVadSpoof {
    pub fn label(self) -> &'static str {
        match self {
            GuestVadSpoof::Off => "off",
            GuestVadSpoof::VadImageMap => "vad-image-map",
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
            method: GuestExecutionMethod::IatHook,
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
    pub image_path: Option<String>,
    #[serde(default)]
    pub session_id: Option<u32>,
    #[serde(default)]
    pub package_family_name: Option<String>,
    #[serde(default)]
    pub appcontainer_sid: Option<String>,
    #[serde(default)]
    pub process_pattern: Option<String>,
    #[serde(default)]
    pub payload_path: Option<PathBuf>,
    #[serde(default)]
    pub allocation: GuestAllocationMethod,
    #[serde(default)]
    pub target_module: Option<String>,
    #[serde(default)]
    pub stage_base: Option<u64>,
    #[serde(default)]
    pub stage_pattern: Option<String>,
    #[serde(default)]
    pub result_base: Option<u64>,
    #[serde(default)]
    pub result_pattern: Option<String>,
    #[serde(default = "default_hook_module")]
    pub hook_module: String,
    #[serde(default = "default_hook_function")]
    pub hook_function: String,
    #[serde(default)]
    pub execution: GuestExecutionConfig,
    #[serde(default)]
    pub dependency_policy: GuestDependencyPolicy,
    #[serde(default)]
    pub tls: GuestTlsMode,
    #[serde(default)]
    pub final_protections: GuestFinalProtections,
    #[serde(default)]
    pub loader_metadata: GuestLoaderMetadataPolicy,
    #[serde(default)]
    pub call_stack: GuestCallStackPolicy,
    #[serde(default)]
    pub permission_transitions: GuestPermissionTransitions,
    #[serde(default)]
    pub thread_starts: GuestThreadStartPolicy,
    #[serde(default)]
    pub image_backing: GuestImageBacking,
    #[serde(default)]
    pub base_address: GuestBaseAddress,
    #[serde(default)]
    pub header_wipe: GuestHeaderWipe,
    #[serde(default)]
    pub loader_entries: GuestLoaderEntries,
    #[serde(default)]
    pub stack_shaping: GuestStackShaping,
    #[serde(default)]
    pub cleanup: GuestCleanup,
    #[serde(default)]
    pub vad_spoof: GuestVadSpoof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestProcessSelector {
    pub pid: Option<u32>,
    pub name: Option<String>,
    pub pattern: Option<GuestBytePattern>,
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
        let base = match (self.pid, self.name.as_deref()) {
            (Some(pid), None) => pid.to_string(),
            (None, Some(name)) => name.to_string(),
            (Some(pid), Some(name)) => format!("{name} ({pid})"),
            (None, None) => "<unset>".into(),
        };
        match self.pattern {
            Some(_) => format!("{base} matching process_pattern"),
            None => base,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestBytePattern {
    bytes: Vec<Option<u8>>,
}

impl GuestBytePattern {
    fn find_in(&self, haystack: &[u8]) -> Option<usize> {
        if self.bytes.is_empty() {
            return Some(0);
        }
        haystack.windows(self.bytes.len()).position(|window| {
            window
                .iter()
                .zip(&self.bytes)
                .all(|(got, expected)| expected.is_none_or(|want| *got == want))
        })
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestInjectionPlan {
    pub method: Method,
    pub target: GuestProcessSelector,
    pub payload_path: PathBuf,
    pub allocation: GuestAllocationMethod,
    pub dependency_policy: GuestDependencyPolicy,
    pub tls: GuestTlsMode,
    pub final_protections: GuestFinalProtections,
    pub loader_metadata: GuestLoaderMetadataPolicy,
    pub call_stack: GuestCallStackPolicy,
    pub permission_transitions: GuestPermissionTransitions,
    pub thread_starts: GuestThreadStartPolicy,
    pub image_backing: GuestImageBacking,
    pub base_address: GuestBaseAddress,
    pub header_wipe: GuestHeaderWipe,
    pub loader_entries: GuestLoaderEntries,
    pub stack_shaping: GuestStackShaping,
    pub cleanup: GuestCleanup,
    pub vad_spoof: GuestVadSpoof,
    pub target_module: Option<String>,
    pub stage_base: Option<u64>,
    pub stage_pattern: Option<GuestBytePattern>,
    pub result_base: Option<u64>,
    pub result_pattern: Option<GuestBytePattern>,
    pub hook_module: String,
    pub hook_function: String,
    pub execution: GuestExecutionConfig,
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
                    "guest domain uses method = \"manual-map\"; guest.execution.method selects the execution path".into(),
                ));
            }
            Method::Standard | Method::Plugin | Method::External => {
                return Err(GuestInjectError::Config(
                    "guest domain uses method = \"manual-map\"".into(),
                ));
            }
        }
        let target = GuestProcessSelector {
            pid: config.guest.pid,
            name: config.guest.process.clone(),
            pattern: match config.guest.process_pattern.as_deref() {
                Some(pattern) => Some(parse_hex_pattern(pattern, "guest.process_pattern")?),
                None => None,
            },
        };
        if config.guest.image_path.is_some()
            || config.guest.session_id.is_some()
            || config.guest.package_family_name.is_some()
            || config.guest.appcontainer_sid.is_some()
        {
            return Err(GuestInjectError::Config(
                "guest image_path/session_id/package_family_name/appcontainer_sid selectors are parsed but not implemented by this backend".into(),
            ));
        }
        target.validate()?;
        let payload_path = match &config.guest.payload_path {
            Some(path) => path.clone(),
            None => {
                return Err(GuestInjectError::Config(
                    "set guest.payload_path to the DLL image".into(),
                ));
            }
        };
        if config.guest.image_backing == GuestImageBacking::SecImage
            && config.guest.final_protections == GuestFinalProtections::Rwx
        {
            return Err(GuestInjectError::Config(
                "guest.image_backing = \"sec-image\" requires final_protections = \"section\"; an image-file-backed mapping uses PE-derived page protections, not a single RWX region".into(),
            ));
        }
        if config.guest.image_backing == GuestImageBacking::SecImage
            && config.guest.allocation != GuestAllocationMethod::VirtualAlloc
        {
            return Err(GuestInjectError::Config(
                "guest.image_backing = \"sec-image\" requires allocation = \"virtual-alloc\"; VirtualAlloc is used for helper buffers while the payload image is mapped through SEC_IMAGE".into(),
            ));
        }
        if config.guest.loader_entries == GuestLoaderEntries::Synthesized
            && config.guest.image_backing == GuestImageBacking::SecImage
        {
            return Err(GuestInjectError::Config(
                "guest.loader_entries = \"synthesized\" is incompatible with image_backing = \"sec-image\"; SEC_IMAGE mappings already create real section state".into(),
            ));
        }
        if config.guest.vad_spoof == GuestVadSpoof::VadImageMap
            && config.guest.image_backing != GuestImageBacking::Private
        {
            return Err(GuestInjectError::Config(
                "guest.vad_spoof = \"vad-image-map\" applies only to image_backing = \"private\""
                    .into(),
            ));
        }
        Ok(Self {
            method: config.injection.method,
            target,
            payload_path,
            allocation: config.guest.allocation,
            dependency_policy: config.guest.dependency_policy,
            tls: config.guest.tls,
            final_protections: config.guest.final_protections,
            loader_metadata: config.guest.loader_metadata,
            call_stack: config.guest.call_stack,
            permission_transitions: config.guest.permission_transitions,
            thread_starts: config.guest.thread_starts,
            image_backing: config.guest.image_backing,
            base_address: config.guest.base_address,
            header_wipe: config.guest.header_wipe,
            loader_entries: config.guest.loader_entries,
            stack_shaping: config.guest.stack_shaping,
            cleanup: config.guest.cleanup,
            vad_spoof: config.guest.vad_spoof,
            target_module: config.guest.target_module.clone(),
            stage_base: config.guest.stage_base,
            stage_pattern: match config.guest.stage_pattern.as_deref() {
                Some(pattern) => Some(parse_hex_pattern(pattern, "guest.stage_pattern")?),
                None => None,
            },
            result_base: config.guest.result_base,
            result_pattern: match config.guest.result_pattern.as_deref() {
                Some(pattern) => Some(parse_hex_pattern(pattern, "guest.result_pattern")?),
                None => None,
            },
            hook_module: config.guest.hook_module.clone(),
            hook_function: config.guest.hook_function.clone(),
            execution: config.guest.execution.clone(),
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
    pub write_verify: bool,
    pub memory_map: bool,
    pub virtual_alloc: bool,
    pub virtual_free: bool,
    pub protect_memory: bool,
    pub iat_hook_execution: bool,
    pub deterministic_execution: bool,
    pub thread_context: bool,
    pub queue_apc: bool,
    pub create_thread: bool,
    pub wait_for_result: bool,
    pub forwarded_exports: bool,
    pub ordinal_imports: bool,
    pub delay_imports: bool,
    pub static_tls: bool,
    pub exception_registration: bool,
    pub loader_reference: bool,
    pub vad_spoof: bool,
}

impl GuestCapabilities {
    pub fn memflow_guest_injection() -> Self {
        Self {
            list_processes: true,
            module_list: true,
            module_exports: true,
            read_memory: true,
            write_memory: true,
            write_verify: true,
            memory_map: true,
            virtual_alloc: true,
            virtual_free: false,
            protect_memory: false,
            iat_hook_execution: true,
            deterministic_execution: false,
            thread_context: false,
            queue_apc: false,
            create_thread: false,
            wait_for_result: true,
            forwarded_exports: true,
            ordinal_imports: true,
            delay_imports: true,
            static_tls: false,
            exception_registration: true,
            loader_reference: false,
            vad_spoof: false,
        }
    }

    pub fn missing_manual_map(self) -> Vec<&'static str> {
        let checks = [
            (self.list_processes, "list-processes"),
            (self.module_list, "module-list"),
            (self.read_memory, "read-memory"),
            (self.write_memory, "write-memory"),
            (self.write_verify, "write-verify"),
            (self.memory_map, "memory-map"),
            (self.virtual_alloc, "virtual-alloc"),
            (self.iat_hook_execution, "iat-hook-execution"),
            (self.wait_for_result, "wait-for-result"),
            (self.forwarded_exports, "forwarded-exports"),
            (self.ordinal_imports, "ordinal-imports"),
            (self.delay_imports, "delay-imports"),
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

    fn call_iat_hook(
        &self,
        pid: u32,
        hook: &GuestIatHook,
        function: u64,
        args: [u64; 4],
        timeout_ms: u32,
    ) -> Result<u64, GuestInjectError> {
        memory_iat_call(self, pid, hook, function, args, timeout_ms)
    }

    fn touch_iat_hook(
        &self,
        pid: u32,
        hook: &GuestIatHook,
        addr: u64,
        len: usize,
        timeout_ms: u32,
    ) -> Result<(), GuestInjectError> {
        memory_iat_touch(self, pid, hook, addr, len, timeout_ms)
    }

    fn read_touch_iat_hook(
        &self,
        pid: u32,
        hook: &GuestIatHook,
        addr: u64,
        len: usize,
        timeout_ms: u32,
    ) -> Result<(), GuestInjectError> {
        memory_iat_read_touch(self, pid, hook, addr, len, timeout_ms)
    }

    fn preserve_touch_iat_hook(
        &self,
        pid: u32,
        hook: &GuestIatHook,
        addr: u64,
        len: usize,
        timeout_ms: u32,
    ) -> Result<(), GuestInjectError> {
        memory_iat_preserve_touch(self, pid, hook, addr, len, timeout_ms)
    }

    fn spoof_vad_type(&self, _pid: u32, _base: u64, _size: u64) -> Result<(), GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "VAD type spoofing",
            reason: "this backend does not expose kernel memory access".into(),
        })
    }

    fn resolve_process(
        &self,
        target: &GuestProcessSelector,
    ) -> Result<GuestProcessInfo, GuestInjectError> {
        target.validate()?;
        let processes = self.list_processes()?;
        tracing::debug!(
            selector = %target.label(),
            process_count = processes.len(),
            "resolving guest process selector"
        );
        match (target.pid, target.name.as_deref()) {
            (Some(pid), _) => processes
                .into_iter()
                .find(|p| p.pid == pid)
                .ok_or_else(|| GuestInjectError::Process(format!("pid {pid} not found")))
                .and_then(|process| match &target.pattern {
                    Some(pattern) => match find_process_pattern(self, process.pid, pattern)? {
                        Some(addr) => {
                            tracing::info!(
                                pid = process.pid,
                                process = %process.name,
                                pattern_addr = format_args!("{addr:#x}"),
                                "guest process selector matched pid and pattern"
                            );
                            Ok(process)
                        }
                        None => Err(GuestInjectError::Process(format!(
                            "pid {pid} does not contain guest.process_pattern"
                        ))),
                    },
                    None => {
                        tracing::info!(pid = process.pid, process = %process.name, "guest process selector matched pid");
                        Ok(process)
                    }
                }),
            (None, Some(name)) => {
                let candidates = processes
                    .into_iter()
                    .filter(|p| p.name.eq_ignore_ascii_case(name))
                    .collect::<Vec<_>>();
                tracing::debug!(
                    name,
                    candidates = candidates.len(),
                    pattern = target.pattern.is_some(),
                    "guest process name candidates collected"
                );
                if candidates.is_empty() {
                    return Err(GuestInjectError::Process(format!(
                        "process {name:?} not found"
                    )));
                }
                match &target.pattern {
                    Some(pattern) => {
                        let mut hits = Vec::new();
                        for process in candidates {
                            if let Some(addr) = find_process_pattern(self, process.pid, pattern)? {
                                tracing::debug!(
                                    pid = process.pid,
                                    process = %process.name,
                                    pattern_addr = format_args!("{addr:#x}"),
                                    "guest process selector candidate matched pattern"
                                );
                                hits.push((process, addr));
                            }
                        }
                        match hits.len() {
                            0 => Err(GuestInjectError::Process(format!(
                                "process {name:?} found, but none contained guest.process_pattern"
                            ))),
                            1 => {
                                let (process, addr) = hits.remove(0);
                                tracing::info!(
                                    pid = process.pid,
                                    process = %process.name,
                                    pattern_addr = format_args!("{addr:#x}"),
                                    "guest process selector matched name and pattern"
                                );
                                Ok(process)
                            }
                            _ => Err(GuestInjectError::Process(format!(
                                "multiple processes named {name:?} contained guest.process_pattern; set guest.pid"
                            ))),
                        }
                    }
                    None => {
                        let process = candidates.into_iter().next().unwrap();
                        tracing::info!(pid = process.pid, process = %process.name, "guest process selector matched name");
                        Ok(process)
                    }
                }
            }
            (None, None) => Err(GuestInjectError::Config(
                "set guest.pid or guest.process for guest injection".into(),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GuestIatHook {
    pub iat_slot: u64,
    pub original_target: u64,
    pub stub_addr: u64,
    pub result_addr: u64,
    pub call_stack: GuestCallStackPolicy,
    pub spoofed_return: Option<GuestSpoofedReturn>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestSpoofedReturn {
    pub gadget_addr: u64,
    pub stack_adjust: u8,
}

struct GuestInjectionLock {
    pid: u32,
}

impl GuestInjectionLock {
    fn acquire(pid: u32) -> Result<Self, GuestInjectError> {
        let active = ACTIVE_GUEST_INJECTIONS.get_or_init(|| Mutex::new(HashSet::new()));
        let mut active = active.lock().unwrap();
        if !active.insert(pid) {
            return Err(GuestInjectError::Unsupported {
                operation: "guest injection",
                reason: format!("another guest injection is already active for pid {pid}"),
            });
        }
        Ok(Self { pid })
    }
}

impl Drop for GuestInjectionLock {
    fn drop(&mut self) {
        if let Some(active) = ACTIVE_GUEST_INJECTIONS.get() {
            active.lock().unwrap().remove(&self.pid);
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
        GuestPortability::GuestLoaderInternals
    }

    fn inject(
        &self,
        backend: &dyn GuestMemoryBackend,
        req: &GuestInjectionRequest<'_>,
    ) -> Result<GuestLoadInfo, GuestInjectError> {
        tracing::info!(
            method = self.name(),
            target = %req.plan.target.label(),
            payload = %req.payload_path.display(),
            payload_bytes = req.payload_image.len(),
            allocation = req.plan.allocation.label(),
            dependency_policy = req.plan.dependency_policy.label(),
            execution = req.plan.execution.method.label(),
            tls = req.plan.tls.label(),
            final_protections = req.plan.final_protections.label(),
            loader_metadata = req.plan.loader_metadata.label(),
            call_stack = req.plan.call_stack.label(),
            permission_transitions = req.plan.permission_transitions.label(),
            thread_starts = req.plan.thread_starts.label(),
            image_backing = req.plan.image_backing.label(),
            vad_spoof = req.plan.vad_spoof.label(),
            hook_module = %req.plan.hook_module,
            hook_function = %req.plan.hook_function,
            timeout_ms = req.plan.execution.timeout_ms,
            "guest injection started"
        );

        let result = (|| {
            if req.payload_image.is_empty() {
                return Err(GuestInjectError::Image(
                    "payload_image is empty; guest injection requires DLL bytes".into(),
                ));
            }
            let capabilities = backend.capabilities();
            let missing = capabilities.missing_manual_map();
            if !missing.is_empty() {
                return Err(GuestInjectError::Unsupported {
                    operation: "guest injection",
                    reason: format!("manual-map method backend missing {}", missing.join(", ")),
                });
            }
            if req.plan.vad_spoof == GuestVadSpoof::VadImageMap && !capabilities.vad_spoof {
                return Err(GuestInjectError::Unsupported {
                    operation: "VAD type spoofing",
                    reason: "this backend does not expose validated VAD mutation support".into(),
                });
            }
            tracing::debug!("guest injection backend requirements satisfied");

            let process = backend.resolve_process(&req.plan.target)?;
            tracing::info!(pid = process.pid, process = %process.name, "guest target resolved");
            let _injection_lock = GuestInjectionLock::acquire(process.pid)?;

            match req.plan.execution.method {
                GuestExecutionMethod::IatHook | GuestExecutionMethod::RemoteThread => {}
                other => {
                    return Err(GuestInjectError::Unsupported {
                        operation: "guest injection",
                        reason: format!(
                            "guest execution method {} is not implemented",
                            other.label()
                        ),
                    });
                }
            }

            let stage = match req.plan.stage_base {
                Some(base) => {
                    validate_stub_region(backend, process.pid, base, STAGE_CAVE_SIZE)?;
                    tracing::info!(
                        pid = process.pid,
                        stage = format_args!("{base:#x}"),
                        "using configured guest stage"
                    );
                    base
                }
                None => {
                    tracing::debug!(pid = process.pid, "searching for guest execution stage");
                    let found = find_stage(backend, process.pid, req.plan.stage_pattern.as_ref())?;
                    validate_stub_region(backend, process.pid, found, STAGE_CAVE_SIZE)?;
                    tracing::info!(
                        pid = process.pid,
                        stage = format_args!("{found:#x}"),
                        "guest execution stage selected"
                    );
                    found
                }
            };
            let result_addr = match req.plan.result_base {
                Some(base) => {
                    validate_result_region(backend, process.pid, base)?;
                    tracing::info!(
                        pid = process.pid,
                        result = format_args!("{base:#x}"),
                        "using configured guest result block"
                    );
                    base
                }
                None => {
                    let found = find_result_block(
                        backend,
                        process.pid,
                        req.plan.result_pattern.as_ref(),
                        stage + STAGE_RESULT_OFFSET,
                    )?;
                    validate_result_region(backend, process.pid, found)?;
                    tracing::info!(
                        pid = process.pid,
                        result = format_args!("{found:#x}"),
                        "guest result block selected"
                    );
                    found
                }
            };

            let hook = find_iat_hook(backend, process.pid, req.plan)?;
            let hook = GuestIatHook {
                iat_slot: hook.iat_slot,
                original_target: hook.original_target,
                stub_addr: stage + STAGE_STUB_OFFSET,
                result_addr,
                call_stack: req.plan.call_stack,
                spoofed_return: if req.plan.stack_shaping == GuestStackShaping::Spoofed {
                    Some(find_spoofed_return(backend, process.pid)?)
                } else {
                    None
                },
            };
            tracing::info!(
                pid = process.pid,
                iat_slot = format_args!("{:#x}", hook.iat_slot),
                original_target = format_args!("{:#x}", hook.original_target),
                stub_addr = format_args!("{:#x}", hook.stub_addr),
                result_addr = format_args!("{:#x}", hook.result_addr),
                hook_module = %req.plan.hook_module,
                hook_function = %req.plan.hook_function,
                "guest IAT hook selected"
            );
            let mut thread_start_notes =
                validate_guest_thread_start_policy(backend, process.pid, req.plan, stage, &hook)?;
            let mut call_stack_notes = Vec::new();
            if req.plan.call_stack == GuestCallStackPolicy::RegisteredUnwind {
                register_guest_stub_unwind(
                    backend,
                    process.pid,
                    &hook,
                    stage,
                    req.plan.execution.timeout_ms,
                )?;
                call_stack_notes
                    .push("call stack: registered unwind metadata for IAT-hook stub".to_string());
            }

            let virtual_alloc =
                resolve_import_symbol(backend, process.pid, "kernel32.dll", "VirtualAlloc")?;
            tracing::info!(
                pid = process.pid,
                virtual_alloc = format_args!("{virtual_alloc:#x}"),
                "guest allocator resolved"
            );
            let virtual_protect = match req.plan.final_protections {
                GuestFinalProtections::Rwx => None,
                GuestFinalProtections::Section => {
                    let addr = resolve_import_symbol(
                        backend,
                        process.pid,
                        "kernel32.dll",
                        "VirtualProtect",
                    )?;
                    tracing::info!(
                        pid = process.pid,
                        virtual_protect = format_args!("{addr:#x}"),
                        "guest final section protector resolved"
                    );
                    Some(addr)
                }
            };
            let loader_apis = match req.plan.dependency_policy {
                GuestDependencyPolicy::RequireLoaded => None,
                GuestDependencyPolicy::LoadWithGuestLoader => {
                    let load_library = resolve_import_symbol(
                        backend,
                        process.pid,
                        "kernel32.dll",
                        "LoadLibraryA",
                    )?;
                    let get_proc_address = resolve_import_symbol(
                        backend,
                        process.pid,
                        "kernel32.dll",
                        "GetProcAddress",
                    )?;
                    tracing::info!(
                        pid = process.pid,
                        load_library = format_args!("{load_library:#x}"),
                        get_proc_address = format_args!("{get_proc_address:#x}"),
                        "guest dependency loader APIs resolved"
                    );
                    Some(GuestLoaderApis {
                        load_library,
                        get_proc_address,
                    })
                }
            };

            let pe = Pe::parse(req.payload_image)?;
            tracing::info!(
                image_base = format_args!("{:#x}", pe.image_base),
                entry_rva = format_args!("{:#x}", pe.entry_rva),
                size_of_image = pe.size_of_image,
                sections = pe.sections.len(),
                "payload PE parsed"
            );
            let allocation_protection = initial_allocation_protection(req.plan, &pe);
            let read_touch_materialization = req.plan.permission_transitions
                == GuestPermissionTransitions::WriteThroughFinal
                && !protection_is_writable(allocation_protection);

            let (remote_base, materialize_allocated_pages) =
                if req.plan.image_backing == GuestImageBacking::SecImage {
                    tracing::info!(
                        pid = process.pid,
                        "mapping payload through a guest SEC_IMAGE file-backed section"
                    );
                    let base = allocate_sec_image(
                        backend,
                        process.pid,
                        &hook,
                        virtual_alloc,
                        stage,
                        req.payload_image,
                        req.plan.execution.timeout_ms,
                    )?;
                    (base, false)
                } else {
                    match req.plan.allocation {
                        GuestAllocationMethod::VirtualAlloc => {
                            let remote = allocate_virtual(
                                backend,
                                process.pid,
                                &hook,
                                virtual_alloc,
                                &pe,
                                allocation_protection,
                                req.plan.base_address,
                                req.plan.execution.timeout_ms,
                            )?;
                            (remote, true)
                        }
                        GuestAllocationMethod::ExistingRegion => match req.plan.stage_base {
                            Some(base) => {
                                let remote = base + 0x1000;
                                tracing::info!(
                                    pid = process.pid,
                                    remote_base = format_args!("{remote:#x}"),
                                    "using configured guest existing region"
                                );
                                (remote, false)
                            }
                            None => {
                                return Err(GuestInjectError::Config(
                                "guest allocation = \"existing-region\" requires guest.stage_base"
                                    .into(),
                            ));
                            }
                        },
                        GuestAllocationMethod::PageTableMap => {
                            return Err(GuestInjectError::Unsupported {
                            operation: "guest page-table-map",
                            reason:
                                "use allocation = \"virtual-alloc\" for the in-process allocator"
                                    .into(),
                        });
                        }
                    }
                };
            if remote_base == 0 {
                return Err(GuestInjectError::Backend(
                    "guest image allocation returned NULL".into(),
                ));
            }
            tracing::info!(
                pid = process.pid,
                remote_base = format_args!("{remote_base:#x}"),
                "guest payload memory allocated"
            );
            if materialize_allocated_pages {
                match read_touch_materialization {
                    true => backend.read_touch_iat_hook(
                        process.pid,
                        &hook,
                        remote_base,
                        pe.size_of_image,
                        req.plan.execution.timeout_ms,
                    )?,
                    false => backend.touch_iat_hook(
                        process.pid,
                        &hook,
                        remote_base,
                        pe.size_of_image,
                        req.plan.execution.timeout_ms,
                    )?,
                }
                tracing::info!(
                    pid = process.pid,
                    remote_base = format_args!("{remote_base:#x}"),
                    bytes = pe.size_of_image,
                    read_touch = read_touch_materialization,
                    "guest payload pages materialized"
                );
            }

            let (mut image, sec_image_snapshot) =
                if req.plan.image_backing == GuestImageBacking::SecImage {
                    let snap = backend.read(process.pid, remote_base, pe.size_of_image)?;
                    let local_layout = pe.mapped_image(req.payload_image)?;
                    tracing::debug!(
                        pid = process.pid,
                        remote_base = format_args!("{remote_base:#x}"),
                        mapped_bytes = snap.len(),
                        "SEC_IMAGE view read back from guest for patch comparison"
                    );
                    tracing::debug!(
                        mapped_bytes = local_layout.len(),
                        "payload image laid out in local buffer"
                    );
                    (local_layout, Some(snap))
                } else {
                    let view = pe.mapped_image(req.payload_image)?;
                    tracing::debug!(
                        mapped_bytes = view.len(),
                        "payload image laid out in local buffer"
                    );
                    (view, None)
                };
            pe.apply_relocs(&mut image, remote_base)?;
            tracing::debug!(
                remote_base = format_args!("{remote_base:#x}"),
                "payload relocations applied"
            );
            let mut loader_metadata_notes = Vec::new();
            if req.plan.loader_metadata.registers_public_metadata() {
                let image_len = image.len();
                match pe.seed_security_cookie(
                    &mut image,
                    remote_base,
                    loader_security_cookie(process.pid, remote_base, image_len),
                )? {
                    Some(cookie) => {
                        tracing::info!(
                            pid = process.pid,
                            remote_base = format_args!("{remote_base:#x}"),
                            cookie = format_args!("{cookie:#x}"),
                            "payload load-config security cookie seeded"
                        );
                        loader_metadata_notes.push(
                            "loader metadata: seeded load-config security cookie".to_string(),
                        );
                    }
                    None if pe.has_load_config() => {
                        tracing::debug!(
                            pid = process.pid,
                            "payload load-config has no default security cookie to seed"
                        );
                    }
                    None => {}
                }
            }

            let dependency_scratch = stage + STAGE_SCRATCH_OFFSET;
            let mut resolve_payload_import = |module: &[u8],
                                              symbol: ImportSymbol<'_>|
             -> Result<usize, GuestInjectError> {
                let module = std::str::from_utf8(module)
                    .map_err(|e| GuestInjectError::Image(format!("import module name: {e}")))?;
                match symbol {
                    ImportSymbol::Name(name) => {
                        let name = std::str::from_utf8(name)
                            .map_err(|e| GuestInjectError::Image(format!("import name: {e}")))?;
                        let addr = resolve_import_symbol_with_dependency_policy(
                            backend,
                            process.pid,
                            &hook,
                            loader_apis,
                            dependency_scratch,
                            STAGE_SCRATCH_SIZE,
                            req.plan.execution.timeout_ms,
                            req.plan.dependency_policy,
                            module,
                            ImportSymbol::Name(name.as_bytes()),
                        )?;
                        tracing::debug!(
                            pid = process.pid,
                            module,
                            symbol = name,
                            address = format_args!("{addr:#x}"),
                            "payload import resolved"
                        );
                        Ok(addr as usize)
                    }
                    ImportSymbol::Ordinal(ordinal) => {
                        let addr = resolve_import_symbol_with_dependency_policy(
                            backend,
                            process.pid,
                            &hook,
                            loader_apis,
                            dependency_scratch,
                            STAGE_SCRATCH_SIZE,
                            req.plan.execution.timeout_ms,
                            req.plan.dependency_policy,
                            module,
                            ImportSymbol::Ordinal(ordinal),
                        )?;
                        tracing::debug!(
                            pid = process.pid,
                            module,
                            ordinal,
                            address = format_args!("{addr:#x}"),
                            "payload ordinal import resolved"
                        );
                        Ok(addr as usize)
                    }
                }
            };
            pe.resolve_imports(&mut image, &mut resolve_payload_import)?;
            tracing::info!("payload imports resolved");
            pe.resolve_delay_imports(&mut image, &mut resolve_payload_import)?;
            tracing::info!("payload delay imports resolved");
            let has_static_tls = pe.has_static_tls(&image)?;
            let mut tls_slot_index: Option<u32> = None;
            match (req.plan.tls, has_static_tls) {
                (GuestTlsMode::RequireStatic, _) => {
                    return Err(GuestInjectError::Unsupported {
                        operation: "guest static TLS",
                        reason: "static TLS registration requires loader-managed TLS slots; use tls = \"callbacks-only\" or tls = \"skip\" with the current backend".into(),
                    });
                }
                (_, true)
                    if !req.plan.loader_metadata.allows_unregistered_metadata()
                        && req.plan.loader_entries != GuestLoaderEntries::Synthesized =>
                {
                    return Err(GuestInjectError::Unsupported {
                        operation: "guest static TLS",
                        reason: "payload uses static TLS; guest injection can call TLS callbacks but cannot register loader-managed TLS slots. Rebuild without static TLS or set guest.loader_metadata = \"best-effort\"/\"allow-unsupported\" only when the payload does not read static TLS".into(),
                    });
                }
                (GuestTlsMode::CallbacksOnly, true)
                    if req.plan.loader_entries == GuestLoaderEntries::Synthesized =>
                {
                    let tls_alloc =
                        resolve_import_symbol(backend, process.pid, "kernel32.dll", "TlsAlloc")?;
                    let tls_set_value =
                        resolve_import_symbol(backend, process.pid, "kernel32.dll", "TlsSetValue")?;
                    let raw_slot = backend.call_iat_hook(
                        process.pid,
                        &hook,
                        tls_alloc,
                        [0, 0, 0, 0],
                        req.plan.execution.timeout_ms,
                    )?;
                    let slot = raw_slot as u32;
                    if slot == u32::MAX {
                        return Err(GuestInjectError::Backend(
                            "guest TlsAlloc returned TLS_OUT_OF_INDEXES".into(),
                        ));
                    }
                    if let Some(index_offset) = pe.tls_index_offset(&image, remote_base as usize)? {
                        image[index_offset..index_offset + 4].copy_from_slice(&slot.to_le_bytes());
                        tracing::info!(
                            pid = process.pid,
                            tls_slot = slot,
                            index_offset = format_args!("{index_offset:#x}"),
                            "static TLS slot allocated; index patched into local image buffer"
                        );
                        tls_slot_index = Some(slot);
                        if let Some(template) = pe.tls_template(&image, remote_base as usize)? {
                            let template_buf = backend.call_iat_hook(
                                process.pid,
                                &hook,
                                virtual_alloc,
                                [0, template.len() as u64, MEM_COMMIT_RESERVE, PAGE_READWRITE],
                                req.plan.execution.timeout_ms,
                            )?;
                            if template_buf != 0 {
                                backend.touch_iat_hook(
                                    process.pid,
                                    &hook,
                                    template_buf,
                                    template.len(),
                                    req.plan.execution.timeout_ms,
                                )?;
                                write_verified(
                                    backend,
                                    process.pid,
                                    template_buf,
                                    &template,
                                    "TLS template copy",
                                )?;
                                let set_ok = backend.call_iat_hook(
                                    process.pid,
                                    &hook,
                                    tls_set_value,
                                    [slot as u64, template_buf, 0, 0],
                                    req.plan.execution.timeout_ms,
                                )?;
                                if set_ok == 0 {
                                    tracing::warn!(
                                        pid = process.pid,
                                        slot,
                                        "guest TlsSetValue returned FALSE; static TLS template not installed for the current helper/target thread"
                                    );
                                } else {
                                    tracing::info!(
                                        pid = process.pid,
                                        slot,
                                        template_buf = format_args!("{template_buf:#x}"),
                                        template_len = template.len(),
                                        "static TLS template copied and TlsSetValue called for the current helper thread"
                                    );
                                    if req.plan.execution.method
                                        == GuestExecutionMethod::RemoteThread
                                    {
                                        tracing::warn!(
                                            pid = process.pid,
                                            slot,
                                            "remote-thread DllMain runs on a new thread; static TLS template is not propagated to that thread"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                (GuestTlsMode::CallbacksOnly, true) => {
                    tracing::warn!(
                        pid = process.pid,
                        "payload uses static TLS; guest injection will call TLS callbacks without registering loader-managed TLS slots"
                    );
                }
                (GuestTlsMode::Skip, _) | (GuestTlsMode::CallbacksOnly, false) => {}
            }

            match &sec_image_snapshot {
                Some(snap) => {
                    let vp = virtual_protect.expect(
                        "sec-image requires final_protections = section so VirtualProtect is resolved",
                    );
                    let mut patched_pages = 0u64;
                    let patched_ranges = sec_image_patched_ranges(&image, snap);
                    for (range_start, range_end) in &patched_ranges {
                        guest_virtual_protect(
                            backend,
                            process.pid,
                            &hook,
                            vp,
                            remote_base + *range_start as u64,
                            (range_end - range_start) as u64,
                            PAGE_READWRITE,
                            hook.result_addr + OLD_PROTECT_RESULT_OFFSET,
                            req.plan.execution.timeout_ms,
                            "SEC_IMAGE patched range",
                        )?;
                        backend.preserve_touch_iat_hook(
                            process.pid,
                            &hook,
                            remote_base + *range_start as u64,
                            range_end - range_start,
                            req.plan.execution.timeout_ms,
                        )?;
                        write_verified(
                            backend,
                            process.pid,
                            remote_base + *range_start as u64,
                            &image[*range_start..*range_end],
                            "SEC_IMAGE patched range",
                        )?;
                        patched_pages +=
                            ((range_end - range_start).div_ceil(GUEST_PAGE_SIZE)) as u64;
                    }
                    tracing::info!(
                        pid = process.pid,
                        remote_base = format_args!("{remote_base:#x}"),
                        patched_pages,
                        patched_ranges = patched_ranges.len(),
                        total_pages = image.len() as u64 / GUEST_PAGE_SIZE as u64,
                        "SEC_IMAGE patched pages written; unpatched pages remain file-backed"
                    );
                }
                None => {
                    write_verified(
                        backend,
                        process.pid,
                        remote_base,
                        &image,
                        "guest mapped payload image",
                    )?;
                    tracing::info!(
                        pid = process.pid,
                        remote_base = format_args!("{remote_base:#x}"),
                        bytes = image.len(),
                        "payload image written to guest"
                    );
                }
            }

            if pe.has_exception_directory() {
                match req.plan.loader_metadata {
                    GuestLoaderMetadataPolicy::RejectUnsupported => {
                        return Err(GuestInjectError::Unsupported {
                            operation: "guest exception metadata",
                            reason: "payload has an exception directory; set guest.loader_metadata = \"best-effort\" to register the x64 runtime function table or \"allow-unsupported\" only when the payload does not unwind across the mapped image".into(),
                        });
                    }
                    GuestLoaderMetadataPolicy::BestEffort => {
                        register_guest_exception_table(
                            backend,
                            process.pid,
                            &hook,
                            remote_base,
                            &pe,
                            req.plan.execution.timeout_ms,
                        )?;
                        loader_metadata_notes.push(
                            "loader metadata: registered x64 runtime function table".to_string(),
                        );
                    }
                    GuestLoaderMetadataPolicy::AllowUnsupported => {
                        tracing::warn!(
                            pid = process.pid,
                            "payload has an exception directory; guest injection did not register unwind data"
                        );
                    }
                }
            }
            if pe.has_load_config() {
                match req.plan.loader_metadata {
                    GuestLoaderMetadataPolicy::RejectUnsupported => {
                        return Err(GuestInjectError::Unsupported {
                            operation: "guest load-config metadata",
                            reason: "payload has a load-config directory; set guest.loader_metadata = \"best-effort\" to seed the security cookie when present or \"allow-unsupported\" only when load-config entries are inert for the payload".into(),
                        });
                    }
                    GuestLoaderMetadataPolicy::BestEffort => {
                        tracing::debug!(
                            pid = process.pid,
                            "payload load-config was processed with available public metadata hooks; broader loader-private entries are not synthesized"
                        );
                    }
                    GuestLoaderMetadataPolicy::AllowUnsupported => {
                        tracing::debug!(
                            pid = process.pid,
                            "payload has a load-config directory; security-cookie/CFG metadata is left as mapped"
                        );
                    }
                }
            }

            if let Some(virtual_protect) = virtual_protect {
                protect_guest_sections(
                    backend,
                    process.pid,
                    &hook,
                    virtual_protect,
                    remote_base,
                    &pe,
                    protect_skip_initial(req.plan, allocation_protection),
                    req.plan.execution.timeout_ms,
                )?;
            }

            if req.plan.tls == GuestTlsMode::Skip {
                tracing::info!("payload TLS callbacks skipped by config");
            } else {
                let callbacks = pe.tls_callbacks(&image, remote_base as usize)?;
                tracing::info!(
                    count = callbacks.len(),
                    "payload TLS callback list prepared"
                );
                for callback in callbacks {
                    tracing::info!(
                        pid = process.pid,
                        callback = format_args!("{callback:#x}"),
                        "calling payload TLS callback"
                    );
                    let _ = backend.call_iat_hook(
                        process.pid,
                        &hook,
                        callback as u64,
                        [remote_base, DLL_PROCESS_ATTACH as u64, 0, 0],
                        req.plan.execution.timeout_ms,
                    )?;
                }
            }

            let mut peb_entry_addr: Option<u64> = None;
            let mut peb_entry_unlinked = false;
            let mut cfg_marked = false;
            let mut cfg_target_count = 0u32;
            if req.plan.loader_entries == GuestLoaderEntries::Synthesized {
                if should_request_cfg_call_target(req.plan, &pe)
                    && let Ok(set_valid_call_targets) = resolve_import_symbol(
                        backend,
                        process.pid,
                        "kernel32.dll",
                        "SetProcessValidCallTargets",
                    )
                {
                    let targets = pe.cfg_call_targets(&image)?;
                    cfg_target_count = targets.len() as u32;
                    if !targets.is_empty() {
                        let info_bytes = targets.len() * 16;
                        let cfg_info = backend.call_iat_hook(
                            process.pid,
                            &hook,
                            virtual_alloc,
                            [0, info_bytes as u64, MEM_COMMIT_RESERVE, PAGE_READWRITE],
                            req.plan.execution.timeout_ms,
                        )?;
                        if cfg_info != 0 {
                            backend.touch_iat_hook(
                                process.pid,
                                &hook,
                                cfg_info,
                                info_bytes,
                                req.plan.execution.timeout_ms,
                            )?;
                            let mut info = vec![0u8; info_bytes];
                            for (i, &rva) in targets.iter().enumerate() {
                                let off = i * 16;
                                info[off..off + 8].copy_from_slice(&(rva as u64).to_le_bytes());
                                info[off + 8..off + 16]
                                    .copy_from_slice(&CFG_CALL_TARGET_VALID.to_le_bytes());
                            }
                            write_verified(
                                backend,
                                process.pid,
                                cfg_info,
                                &info,
                                "CFG_CALL_TARGET_INFO array",
                            )?;
                            let ok = call_guest_proc(
                                backend,
                                process.pid,
                                &hook,
                                stage + STAGE_TRAMPOLINE_OFFSET,
                                stage + STAGE_PARAM_OFFSET,
                                set_valid_call_targets,
                                &cfg_call_target_registration_args(
                                    remote_base,
                                    pe.size_of_image as u64,
                                    targets.len() as u64,
                                    cfg_info,
                                ),
                                req.plan.execution.timeout_ms,
                                "SetProcessValidCallTargets",
                            )?;
                            if let Ok(virtual_free) = resolve_import_symbol(
                                backend,
                                process.pid,
                                "kernel32.dll",
                                "VirtualFree",
                            ) {
                                let _ = backend.call_iat_hook(
                                    process.pid,
                                    &hook,
                                    virtual_free,
                                    [cfg_info, 0, MEM_RELEASE, 0],
                                    req.plan.execution.timeout_ms,
                                );
                            }
                            if ok != 0 {
                                cfg_marked = true;
                                tracing::info!(
                                    pid = process.pid,
                                    remote_base = format_args!("{remote_base:#x}"),
                                    target_count = targets.len(),
                                    "CFG: marked all export/entry targets as valid indirect call targets"
                                );
                            } else {
                                tracing::debug!(
                                    pid = process.pid,
                                    "CFG: SetProcessValidCallTargets returned FALSE; process may not have CFG enabled"
                                );
                            }
                        }
                    }
                }
                let dll_name = req
                    .payload_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("payload.dll");
                let entry_point = pe
                    .entry(remote_base as usize)?
                    .map(|e| e as u64)
                    .unwrap_or(0);
                peb_entry_addr = Some(synthesize_peb_loader_entry(
                    backend,
                    process.pid,
                    &hook,
                    virtual_alloc,
                    stage,
                    remote_base,
                    entry_point,
                    pe.size_of_image as u32,
                    dll_name,
                    req.plan.execution.timeout_ms,
                )?);
                if req.plan.cleanup == GuestCleanup::Tracked
                    && let Some(peb_entry) = peb_entry_addr
                {
                    unlink_synthesized_peb_loader_entry(backend, process.pid, peb_entry)?;
                    peb_entry_unlinked = true;
                }
            }

            if req.plan.vad_spoof == GuestVadSpoof::VadImageMap {
                if req.plan.image_backing != GuestImageBacking::Private {
                    return Err(GuestInjectError::Unsupported {
                        operation: "VAD type spoofing",
                        reason: "vad-image-map applies only to private image backing".into(),
                    });
                }
                backend.spoof_vad_type(process.pid, remote_base, pe.size_of_image as u64)?;
                tracing::info!(
                    pid = process.pid,
                    remote_base = format_args!("{remote_base:#x}"),
                    "VAD type spoofed to VadImageMap for private mapping"
                );
            }

            if let Some(entry) = pe.entry(remote_base as usize)? {
                tracing::info!(
                    pid = process.pid,
                    entry = format_args!("{entry:#x}"),
                    execution = req.plan.execution.method.label(),
                    "calling payload DllMain"
                );
                let ok = match req.plan.execution.method {
                    GuestExecutionMethod::RemoteThread => invoke_dllmain_remote_thread(
                        backend,
                        process.pid,
                        &hook,
                        virtual_alloc,
                        stage,
                        entry as u64,
                        remote_base,
                        &image,
                        &pe,
                        req.plan.thread_starts == GuestThreadStartPolicy::RequireModuleBacked,
                        req.plan.execution.timeout_ms,
                    )?,
                    _ => backend.call_iat_hook(
                        process.pid,
                        &hook,
                        entry as u64,
                        [remote_base, DLL_PROCESS_ATTACH as u64, 0, 0],
                        req.plan.execution.timeout_ms,
                    )?,
                };
                tracing::info!(
                    pid = process.pid,
                    entry_result = ok,
                    "payload DllMain returned"
                );
                if ok == 0 {
                    return Err(GuestInjectError::Image("DllMain returned FALSE".into()));
                }
            } else {
                tracing::info!("payload has no entry point");
            }

            if req.plan.header_wipe == GuestHeaderWipe::AfterLoad {
                let wipe_len = pe.size_of_headers.min(0x1000);
                let zeros = vec![0u8; wipe_len];
                if req.plan.image_backing == GuestImageBacking::SecImage {
                    let vp = virtual_protect.expect(
                        "header wipe requires final_protections = section so VirtualProtect is resolved",
                    );
                    guest_virtual_protect(
                        backend,
                        process.pid,
                        &hook,
                        vp,
                        remote_base,
                        wipe_len as u64,
                        PAGE_READWRITE,
                        hook.result_addr + OLD_PROTECT_RESULT_OFFSET,
                        req.plan.execution.timeout_ms,
                        "header wipe",
                    )?;
                }
                write_verified(backend, process.pid, remote_base, &zeros, "PE header wipe")?;
                tracing::info!(
                    pid = process.pid,
                    remote_base = format_args!("{remote_base:#x}"),
                    bytes = wipe_len,
                    "PE headers wiped"
                );
            }

            let mut notes = vec![
                format!(
                    "manual-mapped {} bytes from {}",
                    req.payload_image.len(),
                    req.payload_path.display()
                ),
                format!(
                    "execution via {}!{} IAT slot {:#x}",
                    req.plan.hook_module, req.plan.hook_function, hook.iat_slot
                ),
                format!(
                    "dependencies={}, tls={}, final_protections={}",
                    req.plan.dependency_policy.label(),
                    req.plan.tls.label(),
                    req.plan.final_protections.label()
                ),
                format!("loader_metadata={}", req.plan.loader_metadata.label()),
                format!("call_stack={}", req.plan.call_stack.label()),
                format!(
                    "permission_transitions={}",
                    req.plan.permission_transitions.label()
                ),
                format!("thread_starts={}", req.plan.thread_starts.label()),
                format!("image_backing={}", req.plan.image_backing.label()),
                format!("base_address={}", req.plan.base_address.label()),
                format!("header_wipe={}", req.plan.header_wipe.label()),
                format!("loader_entries={}", req.plan.loader_entries.label()),
                format!("stack_shaping={}", req.plan.stack_shaping.label()),
                format!("cleanup={}", req.plan.cleanup.label()),
                format!("vad_spoof={}", req.plan.vad_spoof.label()),
            ];
            notes.append(&mut loader_metadata_notes);
            notes.append(&mut call_stack_notes);
            notes.append(&mut thread_start_notes);
            if let Some(peb_entry) = peb_entry_addr {
                match peb_entry_unlinked {
                    true => notes.push(format!(
                        "loader entries: synthesized transient LDR_DATA_TABLE_ENTRY at {peb_entry:#x}, then unlinked from PEB InLoadOrder/InMemoryOrder lists by cleanup=tracked"
                    )),
                    false => notes.push(format!(
                        "loader entries: synthesized LDR_DATA_TABLE_ENTRY at {peb_entry:#x} linked into PEB InLoadOrder/InMemoryOrder lists"
                    )),
                }
            }
            if let Some(slot) = tls_slot_index {
                let thread_scope = match req.plan.execution.method {
                    GuestExecutionMethod::RemoteThread => {
                        "current helper thread only; the remote DllMain thread and other existing threads are not covered"
                    }
                    _ => "current target thread only; other threads are not covered",
                };
                notes.push(format!(
                    "static TLS: allocated slot {slot} via TlsAlloc, patched index into image, copied TLS template, and called TlsSetValue for {thread_scope}"
                ));
            }
            if cfg_marked {
                notes.push(format!(
                    "CFG: marked {cfg_target_count} export/entry targets as valid indirect call targets via SetProcessValidCallTargets before DllMain"
                ));
            }
            notes.extend(guest_artifact_notes(req, &pe, remote_base, has_static_tls));

            Ok(GuestLoadInfo {
                method: self.name().into(),
                pid: process.pid,
                remote_base: Some(remote_base),
                notes,
            })
        })();

        match &result {
            Ok(info) => tracing::info!(
                pid = info.pid,
                remote_base = info.remote_base.map(|base| format!("{base:#x}")).as_deref(),
                "guest injection completed"
            ),
            Err(err) => tracing::error!(error = %err, "guest injection failed"),
        }
        result
    }
}

struct RemoteIatHook {
    iat_slot: u64,
    original_target: u64,
}

struct IatHookTransaction<'a, B: GuestMemoryBackend + ?Sized> {
    backend: &'a B,
    pid: u32,
    hook: GuestIatHook,
    original_iat: [u8; 8],
    original_stub: Vec<u8>,
    original_result: Vec<u8>,
    restored: bool,
}

impl<'a, B: GuestMemoryBackend + ?Sized> IatHookTransaction<'a, B> {
    fn prepare(
        backend: &'a B,
        pid: u32,
        hook: &GuestIatHook,
        stub_len: usize,
    ) -> Result<Self, GuestInjectError> {
        let current_iat = backend.read(pid, hook.iat_slot, 8)?;
        let expected_iat = hook.original_target.to_le_bytes();
        if current_iat != expected_iat {
            return Err(GuestInjectError::Unsupported {
                operation: "guest iat-hook execution",
                reason: format!(
                    "IAT slot {:#x} changed before arming; refusing nested or stale hook",
                    hook.iat_slot
                ),
            });
        }
        let original_stub = backend.read(pid, hook.stub_addr, stub_len)?;
        let original_result = backend.read(pid, hook.result_addr, RESULT_BLOCK_SIZE)?;
        Ok(Self {
            backend,
            pid,
            hook: *hook,
            original_iat: expected_iat,
            original_stub,
            original_result,
            restored: false,
        })
    }

    fn restore(&mut self) -> Result<(), GuestInjectError> {
        if self.restored {
            return Ok(());
        }
        let mut errors = Vec::new();
        for (addr, bytes, label) in [
            (self.hook.iat_slot, self.original_iat.as_slice(), "IAT slot"),
            (
                self.hook.stub_addr,
                self.original_stub.as_slice(),
                "stub bytes",
            ),
            (
                self.hook.result_addr,
                self.original_result.as_slice(),
                "result bytes",
            ),
        ] {
            if let Err(err) = self.backend.write(self.pid, addr, bytes) {
                errors.push(format!("{label} at {addr:#x}: {err}"));
            }
        }
        self.restored = true;
        match errors.is_empty() {
            true => Ok(()),
            false => Err(GuestInjectError::Backend(format!(
                "failed restoring guest IAT hook transaction: {}",
                errors.join("; ")
            ))),
        }
    }
}

impl<B: GuestMemoryBackend + ?Sized> Drop for IatHookTransaction<'_, B> {
    fn drop(&mut self) {
        if !self.restored
            && let Err(err) = self.restore()
        {
            tracing::warn!(pid = self.pid, error = %err, "guest IAT-hook transaction restore failed");
        }
    }
}

fn memory_iat_call<B: GuestMemoryBackend + ?Sized>(
    backend: &B,
    pid: u32,
    hook: &GuestIatHook,
    function: u64,
    args: [u64; 4],
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    let zero_result = vec![0u8; RESULT_BLOCK_SIZE];
    let stub = call_stub(hook, function, args);
    let mut transaction = IatHookTransaction::prepare(backend, pid, hook, stub.len())?;
    tracing::debug!(
        pid,
        function = format_args!("{function:#x}"),
        iat_slot = format_args!("{:#x}", hook.iat_slot),
        original_target = format_args!("{:#x}", hook.original_target),
        stub_addr = format_args!("{:#x}", hook.stub_addr),
        result_addr = format_args!("{:#x}", hook.result_addr),
        arg0 = format_args!("{:#x}", args[0]),
        arg1 = format_args!("{:#x}", args[1]),
        arg2 = format_args!("{:#x}", args[2]),
        arg3 = format_args!("{:#x}", args[3]),
        timeout_ms,
        "guest IAT-hook call installing stub"
    );
    write_verified(
        backend,
        pid,
        hook.result_addr,
        &zero_result,
        "guest IAT-hook result block",
    )?;
    write_verified(
        backend,
        pid,
        hook.stub_addr,
        &stub,
        "guest IAT-hook call stub",
    )?;
    write_verified(
        backend,
        pid,
        hook.iat_slot,
        &hook.stub_addr.to_le_bytes(),
        "guest IAT-hook thunk",
    )?;
    tracing::debug!(
        pid,
        iat_slot = format_args!("{:#x}", hook.iat_slot),
        stub_bytes = stub.len(),
        "guest IAT-hook call armed"
    );
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    loop {
        let result = backend.read(pid, hook.result_addr, RESULT_BLOCK_SIZE)?;
        let state = u64::from_le_bytes(result[0..8].try_into().unwrap());
        let value = u64::from_le_bytes(result[8..16].try_into().unwrap());
        if state == RESULT_STATE {
            tracing::debug!(
                pid,
                function = format_args!("{function:#x}"),
                return_value = format_args!("{value:#x}"),
                "guest IAT-hook call completed"
            );
            transaction.restore()?;
            return Ok(value);
        }
        if Instant::now() >= deadline {
            let restore_result = transaction.restore();
            tracing::warn!(
                pid,
                function = format_args!("{function:#x}"),
                iat_slot = format_args!("{:#x}", hook.iat_slot),
                result_state = format_args!("{state:#x}"),
                result_value = format_args!("{value:#x}"),
                timeout_ms,
                "guest IAT-hook call timed out; restored original IAT target"
            );
            if let Err(err) = restore_result {
                tracing::warn!(pid, error = %err, "guest IAT-hook timeout restore failed");
            }
            return Err(GuestInjectError::Unsupported {
                operation: "guest iat-hook execution",
                reason: format!(
                    "target did not call the configured import before {} ms",
                    timeout_ms
                ),
            });
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn memory_iat_touch<B: GuestMemoryBackend + ?Sized>(
    backend: &B,
    pid: u32,
    hook: &GuestIatHook,
    addr: u64,
    len: usize,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let zero_result = vec![0u8; RESULT_BLOCK_SIZE];
    let stub = touch_stub(hook, addr, len);
    let mut transaction = IatHookTransaction::prepare(backend, pid, hook, stub.len())?;
    tracing::debug!(
        pid,
        iat_slot = format_args!("{:#x}", hook.iat_slot),
        original_target = format_args!("{:#x}", hook.original_target),
        stub_addr = format_args!("{:#x}", hook.stub_addr),
        result_addr = format_args!("{:#x}", hook.result_addr),
        addr = format_args!("{addr:#x}"),
        len,
        timeout_ms,
        "guest IAT-hook page touch installing stub"
    );
    write_verified(
        backend,
        pid,
        hook.result_addr,
        &zero_result,
        "guest IAT-hook result block",
    )?;
    write_verified(
        backend,
        pid,
        hook.stub_addr,
        &stub,
        "guest IAT-hook page-touch stub",
    )?;
    write_verified(
        backend,
        pid,
        hook.iat_slot,
        &hook.stub_addr.to_le_bytes(),
        "guest IAT-hook thunk",
    )?;
    tracing::debug!(
        pid,
        iat_slot = format_args!("{:#x}", hook.iat_slot),
        stub_bytes = stub.len(),
        "guest IAT-hook page touch armed"
    );
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    loop {
        let result = backend.read(pid, hook.result_addr, RESULT_BLOCK_SIZE)?;
        let state = u64::from_le_bytes(result[0..8].try_into().unwrap());
        let value = u64::from_le_bytes(result[8..16].try_into().unwrap());
        if state == RESULT_STATE {
            tracing::debug!(
                pid,
                addr = format_args!("{addr:#x}"),
                len,
                return_value = format_args!("{value:#x}"),
                "guest IAT-hook page touch completed"
            );
            transaction.restore()?;
            return Ok(());
        }
        if Instant::now() >= deadline {
            let restore_result = transaction.restore();
            tracing::warn!(
                pid,
                iat_slot = format_args!("{:#x}", hook.iat_slot),
                result_state = format_args!("{state:#x}"),
                result_value = format_args!("{value:#x}"),
                timeout_ms,
                "guest IAT-hook page touch timed out; restored original IAT target"
            );
            if let Err(err) = restore_result {
                tracing::warn!(pid, error = %err, "guest IAT-hook page-touch timeout restore failed");
            }
            return Err(GuestInjectError::Unsupported {
                operation: "guest iat-hook page touch",
                reason: format!(
                    "target did not call the configured import before {} ms",
                    timeout_ms
                ),
            });
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn memory_iat_read_touch<B: GuestMemoryBackend + ?Sized>(
    backend: &B,
    pid: u32,
    hook: &GuestIatHook,
    addr: u64,
    len: usize,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let zero_result = vec![0u8; RESULT_BLOCK_SIZE];
    let stub = read_touch_stub(hook, addr, len);
    let mut transaction = IatHookTransaction::prepare(backend, pid, hook, stub.len())?;
    tracing::debug!(
        pid,
        iat_slot = format_args!("{:#x}", hook.iat_slot),
        original_target = format_args!("{:#x}", hook.original_target),
        stub_addr = format_args!("{:#x}", hook.stub_addr),
        result_addr = format_args!("{:#x}", hook.result_addr),
        addr = format_args!("{addr:#x}"),
        len,
        timeout_ms,
        "guest IAT-hook read-touch installing stub"
    );
    write_verified(
        backend,
        pid,
        hook.result_addr,
        &zero_result,
        "guest IAT-hook result block",
    )?;
    write_verified(
        backend,
        pid,
        hook.stub_addr,
        &stub,
        "guest IAT-hook read-touch stub",
    )?;
    write_verified(
        backend,
        pid,
        hook.iat_slot,
        &hook.stub_addr.to_le_bytes(),
        "guest IAT-hook thunk",
    )?;
    tracing::debug!(
        pid,
        iat_slot = format_args!("{:#x}", hook.iat_slot),
        stub_bytes = stub.len(),
        "guest IAT-hook read touch armed"
    );
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    loop {
        let result = backend.read(pid, hook.result_addr, RESULT_BLOCK_SIZE)?;
        let state = u64::from_le_bytes(result[0..8].try_into().unwrap());
        let value = u64::from_le_bytes(result[8..16].try_into().unwrap());
        if state == RESULT_STATE {
            tracing::debug!(
                pid,
                addr = format_args!("{addr:#x}"),
                len,
                return_value = format_args!("{value:#x}"),
                "guest IAT-hook read touch completed"
            );
            transaction.restore()?;
            return Ok(());
        }
        if Instant::now() >= deadline {
            let restore_result = transaction.restore();
            tracing::warn!(
                pid,
                iat_slot = format_args!("{:#x}", hook.iat_slot),
                result_state = format_args!("{state:#x}"),
                result_value = format_args!("{value:#x}"),
                timeout_ms,
                "guest IAT-hook read touch timed out; restored original IAT target"
            );
            if let Err(err) = restore_result {
                tracing::warn!(pid, error = %err, "guest IAT-hook read-touch timeout restore failed");
            }
            return Err(GuestInjectError::Unsupported {
                operation: "guest iat-hook read touch",
                reason: format!(
                    "target did not call the configured import before {} ms",
                    timeout_ms
                ),
            });
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn memory_iat_preserve_touch<B: GuestMemoryBackend + ?Sized>(
    backend: &B,
    pid: u32,
    hook: &GuestIatHook,
    addr: u64,
    len: usize,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let zero_result = vec![0u8; RESULT_BLOCK_SIZE];
    let stub = preserve_touch_stub(hook, addr, len);
    let mut transaction = IatHookTransaction::prepare(backend, pid, hook, stub.len())?;
    tracing::debug!(
        pid,
        iat_slot = format_args!("{:#x}", hook.iat_slot),
        original_target = format_args!("{:#x}", hook.original_target),
        stub_addr = format_args!("{:#x}", hook.stub_addr),
        result_addr = format_args!("{:#x}", hook.result_addr),
        addr = format_args!("{addr:#x}"),
        len,
        timeout_ms,
        "guest IAT-hook preserve-touch installing stub"
    );
    write_verified(
        backend,
        pid,
        hook.result_addr,
        &zero_result,
        "guest IAT-hook result block",
    )?;
    write_verified(
        backend,
        pid,
        hook.stub_addr,
        &stub,
        "guest IAT-hook preserve-touch stub",
    )?;
    write_verified(
        backend,
        pid,
        hook.iat_slot,
        &hook.stub_addr.to_le_bytes(),
        "guest IAT-hook thunk",
    )?;
    tracing::debug!(
        pid,
        iat_slot = format_args!("{:#x}", hook.iat_slot),
        stub_bytes = stub.len(),
        "guest IAT-hook preserve touch armed"
    );
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    loop {
        let result = backend.read(pid, hook.result_addr, RESULT_BLOCK_SIZE)?;
        let state = u64::from_le_bytes(result[0..8].try_into().unwrap());
        let value = u64::from_le_bytes(result[8..16].try_into().unwrap());
        if state == RESULT_STATE {
            tracing::debug!(
                pid,
                addr = format_args!("{addr:#x}"),
                len,
                return_value = format_args!("{value:#x}"),
                "guest IAT-hook preserve touch completed"
            );
            transaction.restore()?;
            return Ok(());
        }
        if Instant::now() >= deadline {
            let restore_result = transaction.restore();
            tracing::warn!(
                pid,
                iat_slot = format_args!("{:#x}", hook.iat_slot),
                result_state = format_args!("{state:#x}"),
                result_value = format_args!("{value:#x}"),
                timeout_ms,
                "guest IAT-hook preserve touch timed out; restored original IAT target"
            );
            if let Err(err) = restore_result {
                tracing::warn!(
                    pid,
                    error = %err,
                    "guest IAT-hook preserve-touch timeout restore failed"
                );
            }
            return Err(GuestInjectError::Unsupported {
                operation: "guest iat-hook preserve touch",
                reason: format!(
                    "target did not call the configured import before {} ms",
                    timeout_ms
                ),
            });
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn guest_artifact_notes(
    req: &GuestInjectionRequest<'_>,
    pe: &Pe,
    remote_base: u64,
    has_static_tls: bool,
) -> Vec<String> {
    let mut notes = vec![
        match req.plan.image_backing {
            GuestImageBacking::Private => format!(
                "artifact audit: payload image is a private committed mapping at {remote_base:#x}, not a loader-created SEC_IMAGE section"
            ),
            GuestImageBacking::SecImage => format!(
                "artifact audit: payload image at {remote_base:#x} is backed by a real SEC_IMAGE section over a staged guest copy of the payload file; the section object and image-file VAD backing are kernel-created, not forged; only patched pages (imports, security cookie) become copy-on-write private, unpatched pages remain file-backed"
            ),
        },
        match req.plan.loader_entries {
            GuestLoaderEntries::Absent => {
                "artifact audit: PEB loader lists, normal module enumeration, and loader VAD/section-object metadata are not synthesized by guest manual-map".into()
            }
            GuestLoaderEntries::Synthesized if req.plan.cleanup == GuestCleanup::Tracked => {
                "artifact audit: synthesized LDR_DATA_TABLE_ENTRY is linked transiently into PEB InLoadOrder/InMemoryOrder lists, then unlinked by cleanup=tracked to avoid leaving loader-owned shutdown state behind".into()
            }
            GuestLoaderEntries::Synthesized => {
                "artifact audit: synthesized LDR_DATA_TABLE_ENTRY linked into PEB InLoadOrder/InMemoryOrder lists; initialization-order links are left private to avoid loader shutdown ownership of the manual map".into()
            }
        },
        match req.plan.image_backing {
            GuestImageBacking::Private => {
                "artifact audit: PE headers, sections, imports, relocations, delay imports, TLS callbacks, and entrypoint were processed by decant rather than the Windows loader".into()
            }
            GuestImageBacking::SecImage => {
                "artifact audit: SEC_IMAGE provided the image section layout; relocations, imports, delay imports, TLS callbacks, and entrypoint were processed by decant rather than the Windows loader".into()
            }
        },
        format!(
            "artifact audit: execution method {} runs DllMain{}; {}",
            req.plan.execution.method.label(),
            match req.plan.execution.method {
                GuestExecutionMethod::RemoteThread => " on a kernel-created remote thread through a ThreadProc thunk",
                _ => " on the target thread that calls the hooked import",
            },
            match req.plan.execution.method {
                GuestExecutionMethod::RemoteThread => "the kernel-recorded thread start is the helper thunk, not the payload entrypoint",
                _ => "no remote thread or APC is created by this path",
            }
        ),
    ];

    match req.plan.final_protections {
        GuestFinalProtections::Rwx => notes.push(
            "artifact audit: final_protections=rwx leaves the mapped image writable and executable"
                .into(),
        ),
        GuestFinalProtections::Section => match req.plan.permission_transitions {
            GuestPermissionTransitions::Standard => notes.push(
                "artifact audit: final_protections=section allocates RW memory, writes the image, then applies PE-derived page protections before TLS callbacks and DllMain"
                    .into(),
            ),
            GuestPermissionTransitions::WriteThroughFinal => notes.push(
                "artifact audit: permission_transitions=write-through-final allocates with final-ish image permissions, materializes pages by read touch when possible, writes through memflow, and skips section protects that already match the initial protection"
                    .into(),
            ),
        },
    }
    match req.plan.call_stack {
        GuestCallStackPolicy::Native => notes.push(
            "artifact audit: call_stack=native leaves the IAT-hook stub without dynamic unwind registration"
                .into(),
        ),
        GuestCallStackPolicy::RegisteredUnwind => notes.push(
            "artifact audit: call_stack=registered-unwind registers x64 unwind metadata for the IAT-hook stub; caller frames are not spoofed"
                .into(),
        ),
    }
    match req.plan.thread_starts {
        GuestThreadStartPolicy::ExistingThread => {
            if req.plan.execution.method == GuestExecutionMethod::RemoteThread {
                notes.push(
                    "artifact audit: thread_starts=existing-thread is not applicable to remote-thread execution; a guest thread is created with a helper thunk as its recorded start address, using a temporary thunk when no payload-image cave is available"
                        .into(),
                );
            } else {
                notes.push(
                    "artifact audit: thread_starts=existing-thread creates no guest thread, so no new thread start address is recorded by this path"
                        .into(),
                );
            }
        }
        GuestThreadStartPolicy::RequireModuleBacked => {
            if req.plan.execution.method == GuestExecutionMethod::RemoteThread {
                notes.push(
                    "artifact audit: thread_starts=require-module-backed requires the remote-thread ThreadProc thunk to be placed in a payload-image executable code cave; no temporary thread-start fallback is allowed"
                        .into(),
                );
            } else {
                notes.push(
                    "artifact audit: thread_starts=require-module-backed verified the IAT-hook plumbing is inside loaded module ranges; payload entrypoints and helper calls are not thread-start metadata"
                        .into(),
                );
            }
        }
    }

    if req.plan.dependency_policy == GuestDependencyPolicy::LoadWithGuestLoader {
        notes.push(
            "artifact audit: missing dependencies are loaded through guest LoadLibraryA/GetProcAddress; the payload image itself remains manual-mapped"
                .into(),
        );
    }
    if req.plan.loader_metadata == GuestLoaderMetadataPolicy::BestEffort {
        notes.push(
            "artifact audit: loader_metadata=best-effort registers public runtime metadata that can be expressed through guest exports"
                .into(),
        );
    }
    if has_static_tls {
        match req.plan.loader_entries {
            GuestLoaderEntries::Synthesized => {
                let thread_scope = match req.plan.execution.method {
                    GuestExecutionMethod::RemoteThread => {
                        "the current helper thread only; the remote DllMain thread and other existing threads are not covered"
                    }
                    _ => "the current target thread only; other threads are not covered",
                };
                notes.push(format!(
                    "artifact audit: static TLS slot allocated via TlsAlloc, index patched into image buffer, template copied and TlsSetValue called for {thread_scope}"
                ));
            }
            GuestLoaderEntries::Absent => notes.push(
                "artifact audit: static TLS directory is present, but loader-managed TLS slots are not registered".into(),
            ),
        }
    }
    if pe.has_exception_directory() {
        match req.plan.loader_metadata {
            GuestLoaderMetadataPolicy::BestEffort => notes.push(
                "artifact audit: exception directory is present and RtlAddFunctionTable was called for the mapped image"
                    .into(),
            ),
            _ => notes.push(
                "artifact audit: exception directory is present, but unwind function tables are not registered"
                    .into(),
            ),
        }
    }
    if pe.has_load_config() {
        match req.plan.loader_metadata {
            GuestLoaderMetadataPolicy::BestEffort => notes.push(
                "artifact audit: load-config directory is present; default security-cookie state is seeded when exposed, and a CFG valid-call-target mark is requested when loader_entries=synthesized; broader loader-private entries are not synthesized"
                    .into(),
            ),
            _ => notes.push(
                "artifact audit: load-config directory is present, but CFG/security-cookie loader metadata is not processed"
                    .into(),
            ),
        }
    }
    match req.plan.header_wipe {
        GuestHeaderWipe::None => {}
        GuestHeaderWipe::AfterLoad => notes.push(
            "artifact audit: PE headers (DOS header, NT headers, section headers) were zeroed after DllMain returned".into(),
        ),
    }
    match req.plan.stack_shaping {
        GuestStackShaping::Native => {}
        GuestStackShaping::Spoofed => {
            if req.plan.execution.method == GuestExecutionMethod::RemoteThread {
                notes.push(
                    "artifact audit: stack_shaping=spoofed is disabled for remote-thread launch helpers; remote-thread DllMain runs through a ThreadProc thunk and is not stack-shaped"
                        .into(),
                );
            } else {
                notes.push(
                    "artifact audit: stack_shaping=spoofed writes a synthetic return address from a loaded module onto the stack before payload calls so stack walks attribute the call to a legitimate module"
                        .into(),
                );
            }
        }
    }
    match req.plan.cleanup {
        GuestCleanup::Resident => {}
        GuestCleanup::Tracked => notes.push(
            "artifact audit: cleanup=tracked removes transient loader-list links after load; payload memory remains resident for the running fixture".into(),
        ),
    }
    match req.plan.vad_spoof {
        GuestVadSpoof::Off => {}
        GuestVadSpoof::VadImageMap => notes.push(
            "artifact audit: vad_spoof=vad-image-map completed before DllMain; this mutates only VAD metadata for a private mapping and does not create a real SEC_IMAGE section object, so deep kernel inspection may still distinguish it from loader-created image backing".into(),
        ),
    }
    notes
}

#[allow(clippy::too_many_arguments)]
fn protect_guest_sections(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    virtual_protect: u64,
    remote_base: u64,
    pe: &Pe,
    skip_initial_protect: Option<u64>,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let old_protect = hook.result_addr + OLD_PROTECT_RESULT_OFFSET;
    if pe.size_of_headers != 0 {
        match skip_initial_protect == Some(PAGE_READONLY) {
            true => tracing::debug!(
                pid,
                remote_base = format_args!("{remote_base:#x}"),
                "guest final header protection already matches initial allocation"
            ),
            false => guest_virtual_protect(
                backend,
                pid,
                hook,
                virtual_protect,
                remote_base,
                pe.size_of_headers as u64,
                PAGE_READONLY,
                old_protect,
                timeout_ms,
                "headers",
            )?,
        }
    }

    let mut applied = 0usize;
    let mut skipped = 0usize;
    for section in &pe.sections {
        let size = guest_section_size(section);
        if size == 0 {
            continue;
        }
        let addr = remote_base
            .checked_add(u64::from(section.virtual_address))
            .ok_or_else(|| GuestInjectError::Image("section address overflows".into()))?;
        let protect = guest_section_protect(section.characteristics);
        if skip_initial_protect == Some(protect) {
            skipped += 1;
            tracing::debug!(
                pid,
                addr = format_args!("{addr:#x}"),
                protect = format_args!("{protect:#x}"),
                "guest final section protection already matches initial allocation"
            );
            continue;
        }
        guest_virtual_protect(
            backend,
            pid,
            hook,
            virtual_protect,
            addr,
            u64::from(size),
            protect,
            old_protect,
            timeout_ms,
            "section",
        )?;
        applied += 1;
    }
    tracing::info!(
        pid,
        remote_base = format_args!("{remote_base:#x}"),
        sections = applied,
        skipped,
        "guest final section protections applied"
    );
    Ok(())
}

fn find_spoofed_return(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
) -> Result<GuestSpoofedReturn, GuestInjectError> {
    let modules = backend.module_list(pid)?;
    let regions = backend.memory_map(pid).unwrap_or_else(|err| {
        tracing::debug!(
            pid,
            error = %err,
            "stack spoofing: guest memory map unavailable; falling back to bounded module scan"
        );
        Vec::new()
    });

    for preferred in ["ntdll.dll", "kernel32.dll", "kernelbase.dll"] {
        for module in modules
            .iter()
            .filter(|module| module.name.eq_ignore_ascii_case(preferred))
        {
            for (start, end) in spoofed_return_scan_ranges(module, &regions) {
                if let Some(gadget) = find_spoofed_return_in_guest_range(backend, pid, start, end)?
                {
                    tracing::info!(
                        pid,
                        addr = format_args!("{:#x}", gadget.gadget_addr),
                        module = %module.name,
                        stack_adjust = format_args!("{:#x}", gadget.stack_adjust),
                        range_start = format_args!("{start:#x}"),
                        range_end = format_args!("{end:#x}"),
                        "stack spoofing: found shadow-space-safe return gadget"
                    );
                    return Ok(gadget);
                }
            }
        }
    }

    Err(GuestInjectError::Backend(
        "stack spoofing: no shadow-space-safe return gadget found in readable executable ntdll/kernel32/kernelbase ranges".into(),
    ))
}

fn spoofed_return_scan_ranges(
    module: &GuestModuleInfo,
    regions: &[GuestMemoryRegion],
) -> Vec<(u64, u64)> {
    let module_end = module.base.saturating_add(module.size);
    let mut ranges = Vec::new();
    let mut remaining = module.size.min(SPOOFED_RETURN_SCAN_LIMIT);

    for region in regions {
        if remaining == 0 {
            break;
        }
        if !region.readable || !region.executable {
            continue;
        }
        let region_end = region.base.saturating_add(region.size);
        let start = region.base.max(module.base);
        let end = region_end.min(module_end);
        if start >= end {
            continue;
        }
        let capped_end = start.saturating_add((end - start).min(remaining));
        ranges.push((start, capped_end));
        remaining = remaining.saturating_sub(capped_end - start);
    }

    if ranges.is_empty() && module.size != 0 {
        ranges.push((
            module.base,
            module
                .base
                .saturating_add(module.size.min(SPOOFED_RETURN_SCAN_LIMIT)),
        ));
    }

    ranges
}

fn find_spoofed_return_in_guest_range(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    start: u64,
    end: u64,
) -> Result<Option<GuestSpoofedReturn>, GuestInjectError> {
    let mut addr = start;
    while addr < end {
        let len = (end - addr).min(GUEST_PAGE_SIZE as u64) as usize;
        match backend.read(pid, addr, len) {
            Ok(bytes) => {
                if let Some((off, stack_adjust)) = find_spoofed_return_gadget(&bytes) {
                    return Ok(Some(GuestSpoofedReturn {
                        gadget_addr: addr + off as u64,
                        stack_adjust,
                    }));
                }
            }
            Err(err) if is_process_gone_error(&err) => return Err(err),
            Err(err) => {
                tracing::debug!(
                    pid,
                    addr = format_args!("{addr:#x}"),
                    len,
                    error = %err,
                    "stack spoofing: skipping unreadable scan chunk"
                );
            }
        }
        addr = addr.saturating_add(len as u64);
    }
    Ok(None)
}

fn find_spoofed_return_gadget(bytes: &[u8]) -> Option<(usize, u8)> {
    for (stack_adjust, pattern) in [
        (0x20, [0x48, 0x83, 0xC4, 0x20, 0xC3]),
        (0x28, [0x48, 0x83, 0xC4, 0x28, 0xC3]),
    ] {
        if let Some(off) = bytes.windows(pattern.len()).position(|w| w == pattern) {
            return Some((off, stack_adjust));
        }
    }
    None
}

fn random_base_address() -> u64 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    let mut state = time ^ pid.rotate_left(17) ^ 0x9E37_79B9_7F4A_7C15;
    state ^= state >> 33;
    state = state.wrapping_mul(0xff51_afd7_ed55_8ccd);
    state ^= state >> 33;
    let range = 0x7FF0_0000_0000u64 - 0x1000_0000u64;
    let offset = state % range;
    let base = 0x1000_0000u64 + offset;
    base & !0xFFFF
}

fn remote_thread_param_block(
    entry_point: u64,
    remote_base: u64,
    exit_code: u64,
    status: u64,
) -> [u8; REMOTE_THREAD_PARAM_SIZE] {
    let values = [
        entry_point,
        remote_base,
        DLL_PROCESS_ATTACH as u64,
        0,
        exit_code,
        status,
    ];
    let mut block = [0u8; REMOTE_THREAD_PARAM_SIZE];
    for (i, value) in values.into_iter().enumerate() {
        let off = i * 8;
        block[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }
    block
}

fn poll_remote_thread_exit(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    status_addr: u64,
    exit_code_addr: u64,
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    loop {
        let status = read_remote_u32(backend, pid, status_addr)?;
        if status != 0 {
            return read_remote_u32(backend, pid, exit_code_addr).map(u64::from);
        }
        if Instant::now() >= deadline {
            return Err(GuestInjectError::Backend(format!(
                "remote thread did not complete within {timeout_ms} ms"
            )));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn best_effort_virtual_free(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    virtual_free: u64,
    addr: u64,
    timeout_ms: u32,
) {
    if addr != 0 {
        let _ = backend.call_iat_hook(
            pid,
            hook,
            virtual_free,
            [addr, 0, MEM_RELEASE, 0],
            timeout_ms,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn invoke_dllmain_remote_thread(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    virtual_alloc: u64,
    stage: u64,
    entry_point: u64,
    remote_base: u64,
    image: &[u8],
    pe: &Pe,
    require_module_backed_start: bool,
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    let helper_hook = GuestIatHook {
        spoofed_return: None,
        ..*hook
    };
    let hook = &helper_hook;
    let trampoline = stage + STAGE_TRAMPOLINE_OFFSET;
    let param_block = stage + STAGE_PARAM_OFFSET;
    let create_thread = resolve_import_symbol(backend, pid, "kernel32.dll", "CreateThread")?;
    let virtual_free = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualFree")?;
    let close_handle = resolve_import_symbol(backend, pid, "kernel32.dll", "CloseHandle")?;
    let virtual_protect = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualProtect")?;

    let thunk_code_size = REMOTE_THREAD_DLLMAIN_THUNK.len();
    let scratch = backend.call_iat_hook(
        pid,
        hook,
        virtual_alloc,
        [
            0,
            REMOTE_THREAD_THUNK_ALLOCATION_SIZE,
            MEM_COMMIT_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ],
        timeout_ms,
    )?;
    if scratch == 0 {
        return Err(GuestInjectError::Backend(
            "VirtualAlloc returned NULL for remote-thread scratch".into(),
        ));
    }
    if let Err(err) = backend.touch_iat_hook(
        pid,
        hook,
        scratch,
        REMOTE_THREAD_THUNK_ALLOCATION_SIZE as usize,
        timeout_ms,
    ) {
        best_effort_virtual_free(backend, pid, hook, virtual_free, scratch, timeout_ms);
        return Err(err);
    }

    let thunk_param = scratch + REMOTE_THREAD_PARAM_OFFSET;
    let exit_code_slot = scratch + REMOTE_THREAD_EXIT_CODE_OFFSET;
    let status_slot = scratch + REMOTE_THREAD_STATUS_OFFSET;
    let tid_slot = scratch + REMOTE_THREAD_THREAD_ID_OFFSET;
    let mut scratch_region = vec![0u8; REMOTE_THREAD_THREAD_ID_OFFSET as usize + 8];
    scratch_region[REMOTE_THREAD_PARAM_OFFSET as usize
        ..REMOTE_THREAD_PARAM_OFFSET as usize + REMOTE_THREAD_PARAM_SIZE]
        .copy_from_slice(&remote_thread_param_block(
            entry_point,
            remote_base,
            exit_code_slot,
            status_slot,
        ));

    let (thunk_addr, thread_start_location) = match find_in_image_code_cave(
        pe,
        image,
        thunk_code_size,
    ) {
        Some(thunk_offset) => {
            let thunk_addr = remote_base + thunk_offset as u64;
            if let Err(err) = guest_virtual_protect(
                backend,
                pid,
                hook,
                virtual_protect,
                thunk_addr,
                thunk_code_size as u64,
                PAGE_EXECUTE_READWRITE,
                hook.result_addr + OLD_PROTECT_RESULT_OFFSET,
                timeout_ms,
                "remote-thread in-image thunk",
            ) {
                best_effort_virtual_free(backend, pid, hook, virtual_free, scratch, timeout_ms);
                return Err(err);
            }
            let old_protect =
                match backend.read(pid, hook.result_addr + OLD_PROTECT_RESULT_OFFSET, 4) {
                    Ok(old_protect) => old_protect,
                    Err(err) => {
                        best_effort_virtual_free(
                            backend,
                            pid,
                            hook,
                            virtual_free,
                            scratch,
                            timeout_ms,
                        );
                        return Err(err);
                    }
                };
            if let Err(err) = write_verified(
                backend,
                pid,
                thunk_addr,
                REMOTE_THREAD_DLLMAIN_THUNK,
                "remote-thread in-image thunk",
            ) {
                best_effort_virtual_free(backend, pid, hook, virtual_free, scratch, timeout_ms);
                return Err(err);
            }
            let old_protect = u32::from_le_bytes(old_protect[0..4].try_into().unwrap()) as u64;
            if old_protect != 0 {
                let _ = guest_virtual_protect(
                    backend,
                    pid,
                    hook,
                    virtual_protect,
                    thunk_addr,
                    thunk_code_size as u64,
                    old_protect,
                    hook.result_addr + OLD_PROTECT_RESULT_OFFSET,
                    timeout_ms,
                    "remote-thread in-image thunk restore",
                );
            }
            tracing::info!(
                pid,
                thunk_addr = format_args!("{thunk_addr:#x}"),
                entry_point = format_args!("{entry_point:#x}"),
                "DllMain thunk written into payload image code cave; thread start will be module-backed"
            );
            (thunk_addr, "payload-image code cave")
        }
        None => {
            if require_module_backed_start {
                best_effort_virtual_free(backend, pid, hook, virtual_free, scratch, timeout_ms);
                return Err(GuestInjectError::Backend(
                    "remote-thread module-backed start requires an executable payload-image code cave for the DllMain thunk"
                        .into(),
                ));
            }
            scratch_region[..thunk_code_size].copy_from_slice(REMOTE_THREAD_DLLMAIN_THUNK);
            tracing::info!(
                pid,
                thunk_addr = format_args!("{scratch:#x}"),
                entry_point = format_args!("{entry_point:#x}"),
                "remote-thread: no payload-image code cave available; using temporary ThreadProc thunk"
            );
            (scratch, "temporary helper allocation")
        }
    };
    if let Err(err) = write_verified(
        backend,
        pid,
        scratch,
        &scratch_region,
        "remote-thread scratch",
    ) {
        best_effort_virtual_free(backend, pid, hook, virtual_free, scratch, timeout_ms);
        return Err(err);
    }

    let saved = match backend.read(pid, trampoline, GUEST_PROC_TRAMPOLINE.len()) {
        Ok(saved) => saved,
        Err(err) => {
            best_effort_virtual_free(backend, pid, hook, virtual_free, scratch, timeout_ms);
            return Err(err);
        }
    };
    if let Err(err) = write_verified(
        backend,
        pid,
        trampoline,
        GUEST_PROC_TRAMPOLINE,
        "remote-thread trampoline",
    ) {
        best_effort_virtual_free(backend, pid, hook, virtual_free, scratch, timeout_ms);
        return Err(err);
    }

    let thread_handle = call_guest_proc(
        backend,
        pid,
        hook,
        trampoline,
        param_block,
        create_thread,
        &[0, 0, thunk_addr, thunk_param, 0, tid_slot],
        timeout_ms,
        "CreateThread",
    );
    if let Err(err) = backend.write(pid, trampoline, &saved) {
        tracing::warn!(
            pid,
            error = %err,
            "failed to restore guest proc trampoline after remote-thread create"
        );
    }
    let thread_handle = match thread_handle {
        Ok(handle) => handle,
        Err(err) => {
            best_effort_virtual_free(backend, pid, hook, virtual_free, scratch, timeout_ms);
            return Err(err);
        }
    };
    if thread_handle == 0 {
        best_effort_virtual_free(backend, pid, hook, virtual_free, scratch, timeout_ms);
        return Err(GuestInjectError::Backend(
            "CreateThread returned NULL".into(),
        ));
    }
    tracing::info!(
        pid,
        thread_handle = format_args!("{thread_handle:#x}"),
        thunk_addr = format_args!("{thunk_addr:#x}"),
        thread_start = thread_start_location,
        "guest thread created; kernel-recorded start address selected"
    );

    let exit_code =
        match poll_remote_thread_exit(backend, pid, status_slot, exit_code_slot, timeout_ms) {
            Ok(exit_code) => exit_code,
            Err(err) => {
                let _ = backend.call_iat_hook(
                    pid,
                    hook,
                    close_handle,
                    [thread_handle, 0, 0, 0],
                    timeout_ms.min(250),
                );
                best_effort_virtual_free(
                    backend,
                    pid,
                    hook,
                    virtual_free,
                    scratch,
                    timeout_ms.min(250),
                );
                return Err(err);
            }
        };
    let _ = backend.call_iat_hook(
        pid,
        hook,
        close_handle,
        [thread_handle, 0, 0, 0],
        timeout_ms.min(250),
    );
    best_effort_virtual_free(
        backend,
        pid,
        hook,
        virtual_free,
        scratch,
        timeout_ms.min(250),
    );
    tracing::info!(
        pid,
        thread_handle = format_args!("{thread_handle:#x}"),
        exit_code,
        "remote thread completed; DllMain return value retrieved"
    );
    Ok(exit_code)
}

fn find_in_image_code_cave(pe: &Pe, image: &[u8], size: usize) -> Option<usize> {
    for section in &pe.sections {
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let start = section.virtual_address as usize;
        let sec_size = guest_section_size(section) as usize;
        if start + sec_size > image.len() {
            continue;
        }
        if let Some(off) = find_code_cave(&image[start..start + sec_size], size) {
            return Some(start + off);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn allocate_virtual(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    virtual_alloc: u64,
    pe: &Pe,
    allocation_protection: u64,
    base_policy: GuestBaseAddress,
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    let size = pe.size_of_image as u64;
    let try_alloc = |addr: u64| {
        backend.call_iat_hook(
            pid,
            hook,
            virtual_alloc,
            [addr, size, MEM_COMMIT_RESERVE, allocation_protection],
            timeout_ms,
        )
    };
    match base_policy {
        GuestBaseAddress::Preferred => {
            tracing::info!(
                pid,
                preferred_base = format_args!("{:#x}", pe.image_base),
                size,
                protection = format_args!("{allocation_protection:#x}"),
                "calling guest VirtualAlloc at preferred image base through IAT hook"
            );
            let preferred = try_alloc(pe.image_base)?;
            if preferred != 0 || !pe.has_relocation_directory() {
                return Ok(preferred);
            }
            tracing::info!(
                pid,
                preferred_base = format_args!("{:#x}", pe.image_base),
                "preferred image base unavailable; retrying guest VirtualAlloc at any base"
            );
            try_alloc(0)
        }
        GuestBaseAddress::Randomized => {
            if !pe.has_relocation_directory() {
                tracing::info!(
                    pid,
                    "base_address=randomized but payload has no relocation directory; using preferred base"
                );
                return try_alloc(pe.image_base);
            }
            for attempt in 0..3u32 {
                let candidate = random_base_address();
                tracing::info!(
                    pid,
                    attempt,
                    candidate = format_args!("{candidate:#x}"),
                    size,
                    "calling guest VirtualAlloc at randomized base"
                );
                let result = try_alloc(candidate)?;
                if result != 0 {
                    return Ok(result);
                }
            }
            tracing::info!(
                pid,
                "randomized base attempts exhausted; falling back to any base"
            );
            try_alloc(0)
        }
    }
}

fn initial_allocation_protection(plan: &GuestInjectionPlan, pe: &Pe) -> u64 {
    match (plan.final_protections, plan.permission_transitions) {
        (GuestFinalProtections::Rwx, _) => PAGE_EXECUTE_READWRITE,
        (GuestFinalProtections::Section, GuestPermissionTransitions::Standard) => PAGE_READWRITE,
        (GuestFinalProtections::Section, GuestPermissionTransitions::WriteThroughFinal) => {
            final_image_allocation_protection(pe)
        }
    }
}

fn final_image_allocation_protection(pe: &Pe) -> u64 {
    let mut has_execute = false;
    for section in &pe.sections {
        if guest_section_size(section) == 0 {
            continue;
        }
        let executable = section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let writable = section.characteristics & IMAGE_SCN_MEM_WRITE != 0;
        if executable && writable {
            return PAGE_EXECUTE_READWRITE;
        }
        has_execute |= executable;
    }
    match has_execute {
        true => PAGE_EXECUTE_READ,
        false => PAGE_READONLY,
    }
}

fn protection_is_writable(protect: u64) -> bool {
    matches!(protect, PAGE_READWRITE | PAGE_EXECUTE_READWRITE)
}

fn protect_skip_initial(plan: &GuestInjectionPlan, initial_protect: u64) -> Option<u64> {
    match (plan.final_protections, plan.permission_transitions) {
        (GuestFinalProtections::Section, GuestPermissionTransitions::WriteThroughFinal) => {
            Some(initial_protect)
        }
        _ => None,
    }
}

fn validate_guest_thread_start_policy(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    plan: &GuestInjectionPlan,
    stage: u64,
    hook: &GuestIatHook,
) -> Result<Vec<String>, GuestInjectError> {
    match plan.thread_starts {
        GuestThreadStartPolicy::ExistingThread => {
            if plan.execution.method == GuestExecutionMethod::RemoteThread {
                Ok(vec![
                    "thread starts: remote-thread execution creates a guest thread; thread_starts=existing-thread is not applicable to this execution method"
                        .into(),
                ])
            } else {
                Ok(vec![
                    "thread starts: existing target thread is used; decant does not create guest thread-start metadata"
                        .into(),
                ])
            }
        }
        GuestThreadStartPolicy::RequireModuleBacked => {
            if plan.execution.method == GuestExecutionMethod::RemoteThread {
                return Ok(vec![
                    "thread starts: remote-thread execution requires a payload-image code cave for a module-backed ThreadProc thunk"
                        .into(),
                    "thread starts: payloads without a large enough executable cave fail rather than falling back to a temporary thread start"
                        .into(),
                ]);
            }
            if plan.execution.method != GuestExecutionMethod::IatHook {
                return Err(GuestInjectError::Unsupported {
                    operation: "guest thread start policy",
                    reason: format!(
                        "thread_starts = \"require-module-backed\" is implemented for iat-hook and remote-thread execution, not {}",
                        plan.execution.method.label()
                    ),
                });
            }
            let modules = backend.module_list(pid)?;
            let stage_module =
                module_covering_range(&modules, stage, STAGE_CAVE_SIZE as u64, "staging cave")?;
            let iat_module = module_covering_range(&modules, hook.iat_slot, 8, "IAT slot")?;
            let target_module =
                module_covering_range(&modules, hook.original_target, 1, "original import target")?;
            tracing::info!(
                pid,
                stage = format_args!("{stage:#x}"),
                stage_module = %stage_module.name,
                iat_slot = format_args!("{:#x}", hook.iat_slot),
                iat_module = %iat_module.name,
                original_target = format_args!("{:#x}", hook.original_target),
                target_module = %target_module.name,
                "guest thread-start policy verified module-backed IAT-hook path"
            );
            Ok(vec![
                "thread starts: no guest thread is created; existing target thread-start metadata remains target-owned".into(),
                format!(
                    "thread starts: IAT-hook staging cave is module-backed by {}",
                    stage_module.name
                ),
                format!(
                    "thread starts: IAT-hook slot is module-backed by {}; original import target is module-backed by {}",
                    iat_module.name, target_module.name
                ),
            ])
        }
    }
}

fn module_covering_range<'a>(
    modules: &'a [GuestModuleInfo],
    addr: u64,
    len: u64,
    label: &str,
) -> Result<&'a GuestModuleInfo, GuestInjectError> {
    modules
        .iter()
        .find(|module| module_contains_range(module, addr, len))
        .ok_or_else(|| GuestInjectError::Unsupported {
            operation: "guest module-backed thread starts",
            reason: format!("{label} range {addr:#x}+{len:#x} is not inside a loaded module"),
        })
}

fn module_contains_range(module: &GuestModuleInfo, addr: u64, len: u64) -> bool {
    let Some(end) = addr.checked_add(len) else {
        return false;
    };
    let Some(module_end) = module.base.checked_add(module.size) else {
        return false;
    };
    addr >= module.base && end <= module_end
}

fn register_guest_stub_unwind(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    stage: u64,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let metadata_addr = stage
        .checked_add(STAGE_UNWIND_OFFSET)
        .ok_or_else(|| GuestInjectError::Image("stub unwind metadata address overflows".into()))?;
    let metadata = stub_unwind_metadata()?;
    write_verified(
        backend,
        pid,
        metadata_addr,
        &metadata,
        "guest IAT-hook unwind metadata",
    )?;
    let rtl_add_function_table =
        resolve_import_symbol(backend, pid, "kernel32.dll", "RtlAddFunctionTable")
            .or_else(|_| resolve_import_symbol(backend, pid, "ntdll.dll", "RtlAddFunctionTable"))?;
    tracing::info!(
        pid,
        stage = format_args!("{stage:#x}"),
        function_table = format_args!("{metadata_addr:#x}"),
        "registering guest IAT-hook runtime function table"
    );
    let ok = backend.call_iat_hook(
        pid,
        hook,
        rtl_add_function_table,
        [metadata_addr, 1, stage, 0],
        timeout_ms,
    )?;
    if ok == 0 {
        return Err(GuestInjectError::Backend(format!(
            "guest RtlAddFunctionTable({metadata_addr:#x}, 1, {stage:#x}) returned FALSE"
        )));
    }
    Ok(())
}

fn stub_unwind_metadata() -> Result<Vec<u8>, GuestInjectError> {
    let begin = u32::try_from(STAGE_STUB_OFFSET)
        .map_err(|_| GuestInjectError::Image("stub begin RVA exceeds u32".into()))?;
    let end = u32::try_from(STAGE_SCRATCH_OFFSET)
        .map_err(|_| GuestInjectError::Image("stub end RVA exceeds u32".into()))?;
    let unwind = u32::try_from(STAGE_UNWIND_OFFSET + 12)
        .map_err(|_| GuestInjectError::Image("stub unwind RVA exceeds u32".into()))?;
    let alloc_info = (FRAMED_STUB_STACK_ALLOC / 8)
        .checked_sub(1)
        .ok_or_else(|| GuestInjectError::Image("invalid framed stub allocation".into()))?;
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&begin.to_le_bytes());
    out.extend_from_slice(&end.to_le_bytes());
    out.extend_from_slice(&unwind.to_le_bytes());
    out.push(1);
    out.push(4);
    out.push(1);
    out.push(0);
    out.push(4);
    out.push((alloc_info << 4) | 2);
    out.extend_from_slice(&[0, 0]);
    Ok(out)
}

fn register_guest_exception_table(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    remote_base: u64,
    pe: &Pe,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    if pe.exception.rva == 0 || pe.exception.size == 0 {
        return Ok(());
    }
    let function_table = remote_base
        .checked_add(u64::from(pe.exception.rva))
        .ok_or_else(|| GuestInjectError::Image("exception table address overflows".into()))?;
    let entry_count = pe.exception.size / 12;
    if entry_count == 0 {
        return Ok(());
    }
    let rtl_add_function_table =
        resolve_import_symbol(backend, pid, "kernel32.dll", "RtlAddFunctionTable")
            .or_else(|_| resolve_import_symbol(backend, pid, "ntdll.dll", "RtlAddFunctionTable"))?;
    tracing::info!(
        pid,
        function_table = format_args!("{function_table:#x}"),
        entry_count,
        base = format_args!("{remote_base:#x}"),
        "registering guest runtime function table"
    );
    let ok = backend.call_iat_hook(
        pid,
        hook,
        rtl_add_function_table,
        [function_table, u64::from(entry_count), remote_base, 0],
        timeout_ms,
    )?;
    if ok == 0 {
        return Err(GuestInjectError::Backend(format!(
            "guest RtlAddFunctionTable({function_table:#x}, {entry_count}, {remote_base:#x}) returned FALSE"
        )));
    }
    Ok(())
}

fn loader_security_cookie(pid: u32, remote_base: u64, image_len: usize) -> u64 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    let mut value = time
        ^ remote_base.rotate_left(17)
        ^ ((pid as u64) << 32)
        ^ (image_len as u64).rotate_left(7);
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value & 0x0000_FFFF_FFFF_FFFF
}

const GENERIC_READ: u64 = 0x8000_0000;
const GENERIC_WRITE: u64 = 0x4000_0000;
const CREATE_ALWAYS: u64 = 2;
const FILE_ATTRIBUTE_NORMAL: u64 = 0x80;
const FILE_FLAG_DELETE_ON_CLOSE: u64 = 0x0400_0000;
const SEC_IMAGE: u64 = 0x0100_0000;
const FILE_MAP_COPY: u64 = 1;
const MEM_RELEASE: u64 = 0x8000;
const STAGE_TRAMPOLINE_OFFSET: u64 = STAGE_SCRATCH_OFFSET;
const STAGE_PARAM_OFFSET: u64 = STAGE_SCRATCH_OFFSET + 0x60;
const GUEST_PARAM_BLOCK_SIZE: usize = 0x58;

const REMOTE_THREAD_THUNK_ALLOCATION_SIZE: u64 = 0x1000;
const REMOTE_THREAD_PARAM_OFFSET: u64 = 0x80;
const REMOTE_THREAD_PARAM_SIZE: usize = 0x30;
const REMOTE_THREAD_EXIT_CODE_OFFSET: u64 = 0x100;
const REMOTE_THREAD_STATUS_OFFSET: u64 = 0x108;
const REMOTE_THREAD_THREAD_ID_OFFSET: u64 = 0x110;

const _: () = {
    assert!(
        REMOTE_THREAD_PARAM_OFFSET + REMOTE_THREAD_PARAM_SIZE as u64
            <= REMOTE_THREAD_EXIT_CODE_OFFSET
    );
    assert!(REMOTE_THREAD_EXIT_CODE_OFFSET + 4 <= REMOTE_THREAD_STATUS_OFFSET);
    assert!(REMOTE_THREAD_STATUS_OFFSET + 4 <= REMOTE_THREAD_THREAD_ID_OFFSET);
    assert!(REMOTE_THREAD_THREAD_ID_OFFSET + 8 <= REMOTE_THREAD_THUNK_ALLOCATION_SIZE);
};

const SEC_IMAGE_PATH_CHARS: u64 = 0x400;
const SEC_IMAGE_PATH_BYTES: u64 = SEC_IMAGE_PATH_CHARS * 2;

const GUEST_PROC_TRAMPOLINE: &[u8] = &[
    0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x40, 0x4C, 0x8B, 0x11, 0x48,
    0x8B, 0x41, 0x30, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x41, 0x38, 0x48, 0x89, 0x44, 0x24,
    0x28, 0x48, 0x8B, 0x41, 0x40, 0x48, 0x89, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x41, 0x48, 0x48, 0x89,
    0x44, 0x24, 0x38, 0x4C, 0x8B, 0x49, 0x28, 0x4C, 0x8B, 0x41, 0x20, 0x48, 0x8B, 0x51, 0x18, 0x48,
    0x8B, 0x49, 0x10, 0x4C, 0x89, 0xD0, 0xFF, 0xD0, 0x48, 0x89, 0xEC, 0x5D, 0xC3,
];
const GUEST_GET_PEB_TRAMPOLINE: &[u8] =
    &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xC3];
const REMOTE_THREAD_DLLMAIN_THUNK: &[u8] = &[
    0x53, // push rbx
    0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
    0x48, 0x89, 0xCB, // mov rbx, rcx
    0x48, 0x8B, 0x03, // mov rax, [rbx]
    0x48, 0x8B, 0x4B, 0x08, // mov rcx, [rbx+8]
    0x48, 0x8B, 0x53, 0x10, // mov rdx, [rbx+0x10]
    0x4C, 0x8B, 0x43, 0x18, // mov r8, [rbx+0x18]
    0xFF, 0xD0, // call rax
    0x4C, 0x8B, 0x53, 0x20, // mov r10, [rbx+0x20]
    0x41, 0x89, 0x02, // mov [r10], eax
    0x4C, 0x8B, 0x53, 0x28, // mov r10, [rbx+0x28]
    0x41, 0xC7, 0x02, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [r10], 1
    0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
    0x5B, // pop rbx
    0xC3, // ret
];

struct SecImageCleanup<'a> {
    backend: &'a dyn GuestMemoryBackend,
    pid: u32,
    hook: &'a GuestIatHook,
    unmap_view: u64,
    close_handle: u64,
    virtual_free: u64,
    trampoline: u64,
    saved_trampoline: Vec<u8>,
    timeout_ms: u32,
    path_buf: u64,
    payload_buf: u64,
    file_handle: u64,
    mapping_handle: u64,
    view_base: u64,
}

impl Drop for SecImageCleanup<'_> {
    fn drop(&mut self) {
        if self.view_base != 0 {
            let _ = self.backend.call_iat_hook(
                self.pid,
                self.hook,
                self.unmap_view,
                [self.view_base, 0, 0, 0],
                self.timeout_ms,
            );
        }
        if self.mapping_handle != 0 {
            let _ = self.backend.call_iat_hook(
                self.pid,
                self.hook,
                self.close_handle,
                [self.mapping_handle, 0, 0, 0],
                self.timeout_ms,
            );
        }
        if self.file_handle != 0 {
            let _ = self.backend.call_iat_hook(
                self.pid,
                self.hook,
                self.close_handle,
                [self.file_handle, 0, 0, 0],
                self.timeout_ms,
            );
        }
        if self.payload_buf != 0 {
            let _ = self.backend.call_iat_hook(
                self.pid,
                self.hook,
                self.virtual_free,
                [self.payload_buf, 0, MEM_RELEASE, 0],
                self.timeout_ms,
            );
        }
        if self.path_buf != 0 {
            let _ = self.backend.call_iat_hook(
                self.pid,
                self.hook,
                self.virtual_free,
                [self.path_buf, 0, MEM_RELEASE, 0],
                self.timeout_ms,
            );
        }
        let _ = self
            .backend
            .write(self.pid, self.trampoline, &self.saved_trampoline);
    }
}

fn sec_image_error(label: &str, err: impl std::fmt::Display) -> GuestInjectError {
    GuestInjectError::Backend(format!("guest SEC_IMAGE {label}: {err}"))
}

fn encode_wide(s: &str) -> Vec<u8> {
    let mut out: Vec<u16> = s.encode_utf16().collect();
    out.push(0);
    let mut bytes = Vec::with_capacity(out.len() * 2);
    for word in out {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn decode_wide(bytes: &[u8]) -> String {
    let pairs: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let len = pairs.iter().position(|&w| w == 0).unwrap_or(pairs.len());
    String::from_utf16_lossy(&pairs[..len])
}

fn should_request_cfg_call_target(plan: &GuestInjectionPlan, pe: &Pe) -> bool {
    plan.loader_entries == GuestLoaderEntries::Synthesized
        && plan.loader_metadata == GuestLoaderMetadataPolicy::BestEffort
        && pe.has_load_config()
}

fn cfg_call_target_registration_args(
    remote_base: u64,
    region_size: u64,
    target_count: u64,
    cfg_info: u64,
) -> [u64; 5] {
    [u64::MAX, remote_base, region_size, target_count, cfg_info]
}

#[allow(clippy::too_many_arguments)]
fn call_guest_proc(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    trampoline: u64,
    param_block: u64,
    target: u64,
    args: &[u64],
    timeout_ms: u32,
    label: &str,
) -> Result<u64, GuestInjectError> {
    let mut block = [0u8; GUEST_PARAM_BLOCK_SIZE];
    block[0..8].copy_from_slice(&target.to_le_bytes());
    for (i, &value) in args.iter().take(8).enumerate() {
        let off = 0x10 + i * 8;
        block[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }
    write_verified(backend, pid, param_block, &block, "guest proc param block")?;
    tracing::debug!(
        pid,
        label,
        target = format_args!("{target:#x}"),
        arg_count = args.len(),
        "guest proc call armed"
    );
    backend.call_iat_hook(pid, hook, trampoline, [param_block, 0, 0, 0], timeout_ms)
}

#[allow(clippy::too_many_arguments)]
fn allocate_sec_image(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    virtual_alloc: u64,
    stage: u64,
    payload_image: &[u8],
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    let trampoline = stage + STAGE_TRAMPOLINE_OFFSET;
    let param_block = stage + STAGE_PARAM_OFFSET;
    let saved_trampoline = backend.read(pid, trampoline, GUEST_PROC_TRAMPOLINE.len())?;
    let get_temp_path = resolve_import_symbol(backend, pid, "kernel32.dll", "GetTempPathW")?;
    let create_file = resolve_import_symbol(backend, pid, "kernel32.dll", "CreateFileW")?;
    let write_file = resolve_import_symbol(backend, pid, "kernel32.dll", "WriteFile")?;
    let close_handle = resolve_import_symbol(backend, pid, "kernel32.dll", "CloseHandle")?;
    let virtual_free = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualFree")?;

    let create_file_mapping =
        resolve_import_symbol(backend, pid, "kernel32.dll", "CreateFileMappingW")?;
    let map_view = resolve_import_symbol(backend, pid, "kernel32.dll", "MapViewOfFile")?;
    let unmap_view = resolve_import_symbol(backend, pid, "kernel32.dll", "UnmapViewOfFile")?;

    let mut cleanup = SecImageCleanup {
        backend,
        pid,
        hook,
        unmap_view,
        close_handle,
        virtual_free,
        trampoline,
        saved_trampoline,
        timeout_ms,
        path_buf: 0,
        payload_buf: 0,
        file_handle: 0,
        mapping_handle: 0,
        view_base: 0,
    };
    write_verified(
        backend,
        pid,
        trampoline,
        GUEST_PROC_TRAMPOLINE,
        "guest proc trampoline",
    )?;

    cleanup.path_buf = backend.call_iat_hook(
        pid,
        hook,
        virtual_alloc,
        [0, SEC_IMAGE_PATH_BYTES, MEM_COMMIT_RESERVE, PAGE_READWRITE],
        timeout_ms,
    )?;
    if cleanup.path_buf == 0 {
        return Err(sec_image_error("path buffer", "VirtualAlloc returned NULL"));
    }
    cleanup.payload_buf = backend.call_iat_hook(
        pid,
        hook,
        virtual_alloc,
        [
            0,
            payload_image.len() as u64,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        ],
        timeout_ms,
    )?;
    if cleanup.payload_buf == 0 {
        return Err(sec_image_error(
            "payload buffer",
            "VirtualAlloc returned NULL",
        ));
    }
    backend.touch_iat_hook(
        pid,
        hook,
        cleanup.payload_buf,
        payload_image.len(),
        timeout_ms,
    )?;
    write_verified(
        backend,
        pid,
        cleanup.payload_buf,
        payload_image,
        "guest SEC_IMAGE payload buffer",
    )?;

    let temp_len = backend.call_iat_hook(
        pid,
        hook,
        get_temp_path,
        [SEC_IMAGE_PATH_CHARS, cleanup.path_buf, 0, 0],
        timeout_ms,
    )?;
    if temp_len == 0 || temp_len >= SEC_IMAGE_PATH_CHARS {
        return Err(sec_image_error(
            "GetTempPathW",
            format!("returned unusable length {temp_len}"),
        ));
    }
    let temp_bytes = backend.read(pid, cleanup.path_buf, (temp_len as usize) * 2)?;
    let temp_dir = decode_wide(&temp_bytes);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let full_path = format!("{temp_dir}decant_{stamp:x}.dll");
    let wide_path = encode_wide(&full_path);
    if wide_path.len() > SEC_IMAGE_PATH_BYTES as usize {
        return Err(sec_image_error(
            "temp path",
            format!("path buffer too small for {full_path}"),
        ));
    }
    write_verified(
        backend,
        pid,
        cleanup.path_buf,
        &wide_path,
        "guest SEC_IMAGE wide path",
    )?;

    let write_len = u32::try_from(payload_image.len())
        .map_err(|_| sec_image_error("WriteFile", "payload exceeds DWORD byte count"))?;
    let written_slot = cleanup.path_buf;
    cleanup.file_handle = call_guest_proc(
        backend,
        pid,
        hook,
        trampoline,
        param_block,
        create_file,
        &[
            cleanup.path_buf,
            GENERIC_READ | GENERIC_WRITE,
            0,
            0,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
            0,
        ],
        timeout_ms,
        "CreateFileW",
    )?;
    let invalid_handle = u64::MAX;
    if cleanup.file_handle == 0 || cleanup.file_handle == invalid_handle {
        return Err(sec_image_error(
            "CreateFileW",
            format!("returned invalid handle for {full_path}"),
        ));
    }
    write_verified(
        backend,
        pid,
        written_slot,
        &[0; 8],
        "guest SEC_IMAGE WriteFile byte-count slot",
    )?;
    let write_ok = call_guest_proc(
        backend,
        pid,
        hook,
        trampoline,
        param_block,
        write_file,
        &[
            cleanup.file_handle,
            cleanup.payload_buf,
            u64::from(write_len),
            written_slot,
            0,
        ],
        timeout_ms,
        "WriteFile",
    )?;
    if write_ok == 0 {
        return Err(sec_image_error(
            "WriteFile",
            format!("returned FALSE for {full_path}"),
        ));
    }
    let written = read_remote_u32(backend, pid, written_slot)?;
    if written != write_len {
        return Err(sec_image_error(
            "WriteFile",
            format!(
                "wrote {written} of {} bytes for {full_path}",
                payload_image.len()
            ),
        ));
    }
    let _ = backend.call_iat_hook(
        pid,
        hook,
        virtual_free,
        [cleanup.payload_buf, 0, MEM_RELEASE, 0],
        timeout_ms,
    );
    cleanup.payload_buf = 0;

    cleanup.mapping_handle = call_guest_proc(
        backend,
        pid,
        hook,
        trampoline,
        param_block,
        create_file_mapping,
        &[cleanup.file_handle, 0, PAGE_READONLY | SEC_IMAGE, 0, 0, 0],
        timeout_ms,
        "CreateFileMappingW",
    )?;
    if cleanup.mapping_handle == 0 {
        return Err(sec_image_error(
            "CreateFileMappingW",
            format!("returned NULL for {full_path}"),
        ));
    }
    cleanup.view_base = call_guest_proc(
        backend,
        pid,
        hook,
        trampoline,
        param_block,
        map_view,
        &[cleanup.mapping_handle, FILE_MAP_COPY, 0, 0, 0],
        timeout_ms,
        "MapViewOfFile",
    )?;
    let _ = backend.call_iat_hook(
        pid,
        hook,
        close_handle,
        [cleanup.mapping_handle, 0, 0, 0],
        timeout_ms,
    );
    cleanup.mapping_handle = 0;
    let _ = backend.call_iat_hook(
        pid,
        hook,
        close_handle,
        [cleanup.file_handle, 0, 0, 0],
        timeout_ms,
    );
    cleanup.file_handle = 0;
    let _ = backend.call_iat_hook(
        pid,
        hook,
        virtual_free,
        [cleanup.path_buf, 0, MEM_RELEASE, 0],
        timeout_ms,
    );
    cleanup.path_buf = 0;
    if cleanup.view_base == 0 {
        return Err(GuestInjectError::Backend(format!(
            "guest MapViewOfFile(SEC_IMAGE, {full_path}) returned NULL"
        )));
    }
    let view_base = cleanup.view_base;
    cleanup.view_base = 0;
    tracing::info!(
        pid,
        remote_base = format_args!("{view_base:#x}"),
        path = %full_path,
        bytes = payload_image.len(),
        "guest SEC_IMAGE mapping installed; file and mapping handles released, trampoline restored, view retained"
    );
    Ok(view_base)
}

#[allow(clippy::too_many_arguments)]
fn synthesize_peb_loader_entry(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    virtual_alloc: u64,
    stage: u64,
    remote_base: u64,
    entry_point: u64,
    size_of_image: u32,
    dll_name: &str,
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    let trampoline = stage + STAGE_TRAMPOLINE_OFFSET;
    let saved = backend.read(pid, trampoline, GUEST_GET_PEB_TRAMPOLINE.len())?;
    write_verified(
        backend,
        pid,
        trampoline,
        GUEST_GET_PEB_TRAMPOLINE,
        "PEB lookup trampoline",
    )?;

    let peb = backend.call_iat_hook(pid, hook, trampoline, [0, 0, 0, 0], timeout_ms)?;
    let _ = backend.write(pid, trampoline, &saved);
    if peb == 0 {
        return Err(GuestInjectError::Backend(
            "PEB synthesis: guest PEB lookup returned null".into(),
        ));
    }
    let ldr_bytes = backend.read(pid, peb + 0x18, 8)?;
    let ldr = u64::from_le_bytes(ldr_bytes[0..8].try_into().unwrap());
    if ldr == 0 {
        return Err(GuestInjectError::Backend(format!(
            "PEB Ldr is null for guest PEB {peb:#x}"
        )));
    }

    let entry_size = 0x830u64;
    let entry = backend.call_iat_hook(
        pid,
        hook,
        virtual_alloc,
        [0, entry_size, MEM_COMMIT_RESERVE, PAGE_READWRITE],
        timeout_ms,
    )?;
    if entry == 0 {
        let _ = backend.write(pid, trampoline, &saved);
        return Err(GuestInjectError::Backend(
            "PEB synthesis: VirtualAlloc for LDR entry returned NULL".into(),
        ));
    }
    backend.touch_iat_hook(pid, hook, entry, entry_size as usize, timeout_ms)?;

    let mut entry_data = vec![0u8; entry_size as usize];
    entry_data[0x30..0x38].copy_from_slice(&remote_base.to_le_bytes());
    entry_data[0x38..0x40].copy_from_slice(&entry_point.to_le_bytes());
    entry_data[0x40..0x44].copy_from_slice(&size_of_image.to_le_bytes());
    let init_links = entry + 0x20;
    entry_data[0x20..0x28].copy_from_slice(&init_links.to_le_bytes());
    entry_data[0x28..0x30].copy_from_slice(&init_links.to_le_bytes());

    let base_name_wide = encode_wide(dll_name);
    let full_name = format!("C:\\Windows\\System32\\{dll_name}");
    let full_name_wide = encode_wide(&full_name);
    let base_name_offset = 0x200usize;
    let full_name_offset = 0x410usize;
    entry_data[base_name_offset..base_name_offset + base_name_wide.len()]
        .copy_from_slice(&base_name_wide);
    entry_data[full_name_offset..full_name_offset + full_name_wide.len()]
        .copy_from_slice(&full_name_wide);

    let base_name_len = (base_name_wide.len() - 2) as u16;
    let full_name_len = (full_name_wide.len() - 2) as u16;
    entry_data[0x48..0x4A].copy_from_slice(&full_name_len.to_le_bytes());
    entry_data[0x4A..0x4C].copy_from_slice(&(full_name_wide.len() as u16).to_le_bytes());
    entry_data[0x50..0x58].copy_from_slice(&(entry + full_name_offset as u64).to_le_bytes());
    entry_data[0x58..0x5A].copy_from_slice(&base_name_len.to_le_bytes());
    entry_data[0x5A..0x5C].copy_from_slice(&(base_name_wide.len() as u16).to_le_bytes());
    entry_data[0x60..0x68].copy_from_slice(&(entry + base_name_offset as u64).to_le_bytes());

    write_verified(backend, pid, entry, &entry_data, "LDR_DATA_TABLE_ENTRY")?;

    let list_insert = |list_head: u64, links_offset: u64| -> Result<(), GuestInjectError> {
        let links = entry + links_offset;
        let head_blink_bytes = backend.read(pid, list_head + 8, 8)?;
        let head_blink = u64::from_le_bytes(head_blink_bytes[0..8].try_into().unwrap());
        let flink = list_head.to_le_bytes();
        let blink = head_blink.to_le_bytes();
        backend.write(pid, links, &flink)?;
        backend.write(pid, links + 8, &blink)?;
        backend.write(pid, head_blink, &links.to_le_bytes())?;
        backend.write(pid, list_head + 8, &links.to_le_bytes())?;
        Ok(())
    };
    list_insert(ldr + 0x10, 0x00)?;
    list_insert(ldr + 0x20, 0x10)?;

    let _ = backend.write(pid, trampoline, &saved);
    tracing::info!(
        pid,
        peb = format_args!("{peb:#x}"),
        ldr = format_args!("{ldr:#x}"),
        entry = format_args!("{entry:#x}"),
        remote_base = format_args!("{remote_base:#x}"),
        "synthesized PEB loader entry linked into InLoadOrder and InMemoryOrder lists"
    );
    Ok(entry)
}

fn unlink_synthesized_peb_loader_entry(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    entry: u64,
) -> Result<(), GuestInjectError> {
    unlink_guest_list_entry(backend, pid, entry)?;
    unlink_guest_list_entry(backend, pid, entry + 0x10)?;
    tracing::info!(
        pid,
        entry = format_args!("{entry:#x}"),
        "unlinked synthesized PEB loader entry from load and memory lists"
    );
    Ok(())
}

fn unlink_guest_list_entry(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    links: u64,
) -> Result<(), GuestInjectError> {
    let bytes = backend.read(pid, links, 16)?;
    let flink = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let blink = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if flink == 0 || blink == 0 {
        return Err(GuestInjectError::Backend(format!(
            "PEB synthesis cleanup: list entry {links:#x} has null links"
        )));
    }
    backend.write(pid, flink + 8, &blink.to_le_bytes())?;
    backend.write(pid, blink, &flink.to_le_bytes())?;
    backend.write(pid, links, &links.to_le_bytes())?;
    backend.write(pid, links + 8, &links.to_le_bytes())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn guest_virtual_protect(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    virtual_protect: u64,
    addr: u64,
    size: u64,
    protect: u64,
    old_protect: u64,
    timeout_ms: u32,
    label: &str,
) -> Result<(), GuestInjectError> {
    tracing::debug!(
        pid,
        label,
        addr = format_args!("{addr:#x}"),
        size,
        protect = format_args!("{protect:#x}"),
        "calling guest VirtualProtect"
    );
    let ok = backend.call_iat_hook(
        pid,
        hook,
        virtual_protect,
        [addr, size, protect, old_protect],
        timeout_ms,
    )?;
    if ok == 0 {
        return Err(GuestInjectError::Backend(format!(
            "guest VirtualProtect({label} at {addr:#x}, size {size:#x}, protect {protect:#x}) returned FALSE"
        )));
    }
    Ok(())
}

fn guest_section_size(section: &Section) -> u32 {
    match section.virtual_size {
        0 => section.raw_size,
        v => v,
    }
}

fn guest_section_protect(characteristics: u32) -> u64 {
    let executable = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
    let readable = characteristics & IMAGE_SCN_MEM_READ != 0;
    let writable = characteristics & IMAGE_SCN_MEM_WRITE != 0;
    match (executable, readable, writable) {
        (true, _, true) => PAGE_EXECUTE_READWRITE,
        (true, true, false) => PAGE_EXECUTE_READ,
        (true, false, false) => PAGE_EXECUTE,
        (false, _, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_READONLY,
        (false, false, false) => PAGE_NOACCESS,
    }
}

fn write_verified<B: GuestMemoryBackend + ?Sized>(
    backend: &B,
    pid: u32,
    addr: u64,
    data: &[u8],
    label: &str,
) -> Result<(), GuestInjectError> {
    backend.write(pid, addr, data)?;
    let got = backend.read(pid, addr, data.len())?;
    if got != data {
        return Err(GuestInjectError::Backend(format!(
            "guest write verification failed for {label} at {addr:#x}: wrote {} bytes",
            data.len()
        )));
    }
    Ok(())
}

fn sec_image_patched_ranges(image: &[u8], snapshot: &[u8]) -> Vec<(usize, usize)> {
    debug_assert_eq!(image.len(), snapshot.len());
    let len = image.len().min(snapshot.len());
    let mut ranges = Vec::new();
    let mut i = 0usize;
    while i < len {
        if image[i] == snapshot[i] {
            i += 1;
            continue;
        }

        let range_start = i & !(GUEST_PAGE_SIZE - 1);
        let mut range_end = (range_start + GUEST_PAGE_SIZE).min(len);
        let mut scan = range_end;
        while scan < len {
            let page_end = (scan + GUEST_PAGE_SIZE).min(len);
            if image[scan..page_end]
                .iter()
                .zip(&snapshot[scan..page_end])
                .any(|(image, snapshot)| image != snapshot)
            {
                range_end = page_end;
                scan = page_end;
            } else {
                break;
            }
        }
        ranges.push((range_start, range_end));
        i = range_end;
    }
    ranges
}

fn call_stub(hook: &GuestIatHook, function: u64, args: [u64; 4]) -> Vec<u8> {
    if hook.call_stack == GuestCallStackPolicy::RegisteredUnwind {
        return framed_call_stub(hook, function, args);
    }
    let mut code = X64Stub::new();
    preserve_import_args(&mut code);
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.xor_eax_eax();
    code.mov_abs(Reg64::R11, RESULT_RUNNING);
    code.lock_cmpxchg_rax_at_r10_with_r11();
    let skip_call = code.jne_rel32_placeholder();

    code.mov_abs(Reg64::Rcx, args[0]);
    code.mov_abs(Reg64::Rdx, args[1]);
    code.mov_abs(Reg64::R8, args[2]);
    code.mov_abs(Reg64::R9, args[3]);
    match hook.spoofed_return {
        Some(gadget) => emit_spoofed_call(&mut code, hook, function, gadget, 0),
        None => {
            code.mov_abs(Reg64::Rax, function);
            code.call_rax_windows_x64();
        }
    }
    code.mov_abs(Reg64::R10, hook.result_addr + 8);
    code.store_rax_at_r10();
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.mov_abs(Reg64::Rax, RESULT_STATE);
    code.store_rax_at_r10();

    let tail_original = code.len();
    code.patch_rel32(skip_call, tail_original);
    tail_jump_original_import(&mut code, hook.original_target);
    code.finish()
}

fn framed_call_stub(hook: &GuestIatHook, function: u64, args: [u64; 4]) -> Vec<u8> {
    let mut code = X64Stub::new();
    framed_prologue(&mut code);
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.xor_eax_eax();
    code.mov_abs(Reg64::R11, RESULT_RUNNING);
    code.lock_cmpxchg_rax_at_r10_with_r11();
    let skip_call = code.jne_rel32_placeholder();

    code.mov_abs(Reg64::Rcx, args[0]);
    code.mov_abs(Reg64::Rdx, args[1]);
    code.mov_abs(Reg64::R8, args[2]);
    code.mov_abs(Reg64::R9, args[3]);
    match hook.spoofed_return {
        Some(gadget) => emit_spoofed_call(&mut code, hook, function, gadget, 8),
        None => {
            code.mov_abs(Reg64::Rax, function);
            code.call_rax_with_current_frame();
        }
    }
    code.mov_abs(Reg64::R10, hook.result_addr + 8);
    code.store_rax_at_r10();
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.mov_abs(Reg64::Rax, RESULT_STATE);
    code.store_rax_at_r10();

    let tail_original = code.len();
    code.patch_rel32(skip_call, tail_original);
    framed_tail_jump_original_import(&mut code, hook.original_target);
    code.finish()
}

fn touch_stub(hook: &GuestIatHook, addr: u64, len: usize) -> Vec<u8> {
    if hook.call_stack == GuestCallStackPolicy::RegisteredUnwind {
        return framed_touch_stub(hook, addr, len, TouchMode::WriteZero);
    }
    let mut code = X64Stub::new();
    preserve_import_args(&mut code);
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.xor_eax_eax();
    code.mov_abs(Reg64::R11, RESULT_RUNNING);
    code.lock_cmpxchg_rax_at_r10_with_r11();
    let skip_touch = code.jne_rel32_placeholder();

    emit_touch_loop(&mut code, addr, len, TouchMode::WriteZero);

    code.mov_abs(Reg64::R10, hook.result_addr + 8);
    code.mov_abs(Reg64::Rax, addr);
    code.store_rax_at_r10();
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.mov_abs(Reg64::Rax, RESULT_STATE);
    code.store_rax_at_r10();

    let tail_original = code.len();
    code.patch_rel32(skip_touch, tail_original);
    tail_jump_original_import(&mut code, hook.original_target);
    code.finish()
}

fn read_touch_stub(hook: &GuestIatHook, addr: u64, len: usize) -> Vec<u8> {
    if hook.call_stack == GuestCallStackPolicy::RegisteredUnwind {
        return framed_touch_stub(hook, addr, len, TouchMode::ReadOnly);
    }
    touch_mode_stub(hook, addr, len, TouchMode::ReadOnly)
}

fn preserve_touch_stub(hook: &GuestIatHook, addr: u64, len: usize) -> Vec<u8> {
    if hook.call_stack == GuestCallStackPolicy::RegisteredUnwind {
        return framed_touch_stub(hook, addr, len, TouchMode::WriteSame);
    }
    touch_mode_stub(hook, addr, len, TouchMode::WriteSame)
}

fn touch_mode_stub(hook: &GuestIatHook, addr: u64, len: usize, mode: TouchMode) -> Vec<u8> {
    let mut code = X64Stub::new();
    preserve_import_args(&mut code);
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.xor_eax_eax();
    code.mov_abs(Reg64::R11, RESULT_RUNNING);
    code.lock_cmpxchg_rax_at_r10_with_r11();
    let skip_touch = code.jne_rel32_placeholder();

    emit_touch_loop(&mut code, addr, len, mode);

    code.mov_abs(Reg64::R10, hook.result_addr + 8);
    code.mov_abs(Reg64::Rax, addr);
    code.store_rax_at_r10();
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.mov_abs(Reg64::Rax, RESULT_STATE);
    code.store_rax_at_r10();

    let tail_original = code.len();
    code.patch_rel32(skip_touch, tail_original);
    tail_jump_original_import(&mut code, hook.original_target);
    code.finish()
}

#[derive(Clone, Copy)]
enum TouchMode {
    WriteZero,
    ReadOnly,
    WriteSame,
}

fn framed_touch_stub(hook: &GuestIatHook, addr: u64, len: usize, mode: TouchMode) -> Vec<u8> {
    let mut code = X64Stub::new();
    framed_prologue(&mut code);
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.xor_eax_eax();
    code.mov_abs(Reg64::R11, RESULT_RUNNING);
    code.lock_cmpxchg_rax_at_r10_with_r11();
    let skip_touch = code.jne_rel32_placeholder();

    emit_touch_loop(&mut code, addr, len, mode);

    code.mov_abs(Reg64::R10, hook.result_addr + 8);
    code.mov_abs(Reg64::Rax, addr);
    code.store_rax_at_r10();
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.mov_abs(Reg64::Rax, RESULT_STATE);
    code.store_rax_at_r10();

    let tail_original = code.len();
    code.patch_rel32(skip_touch, tail_original);
    framed_tail_jump_original_import(&mut code, hook.original_target);
    code.finish()
}

fn emit_touch_loop(code: &mut X64Stub, addr: u64, len: usize, mode: TouchMode) {
    let page_count = len.div_ceil(GUEST_PAGE_SIZE) as u64;
    if page_count == 0 {
        return;
    }
    code.mov_abs(Reg64::Rdx, addr);
    code.mov_abs(Reg64::Rcx, page_count);
    let touch_loop = code.len();
    match mode {
        TouchMode::WriteZero => code.mov_byte_zero_at_rdx(),
        TouchMode::ReadOnly => code.movzx_eax_byte_at_rdx(),
        TouchMode::WriteSame => {
            code.movzx_eax_byte_at_rdx();
            code.mov_al_at_rdx();
        }
    }
    code.add_rdx_imm32(GUEST_PAGE_SIZE as u32);
    code.dec_rcx();
    let repeat = code.jne_rel32_placeholder();
    code.patch_rel32(repeat, touch_loop);
}

fn preserve_import_args(code: &mut X64Stub) {
    code.push(Reg64::Rcx);
    code.push(Reg64::Rdx);
    code.push(Reg64::R8);
    code.push(Reg64::R9);
}

fn emit_spoofed_call(
    code: &mut X64Stub,
    hook: &GuestIatHook,
    function: u64,
    gadget: GuestSpoofedReturn,
    desired_frame_mod: u8,
) {
    let (frame_size, post_add) = spoofed_stack_frame(gadget.stack_adjust, desired_frame_mod);
    let landing = code.len();
    let landing_addr = hook.stub_addr + landing as u64 + SPOOFED_CALL_LANDING_DELTA;
    code.sub_rsp(frame_size);
    code.mov_abs(Reg64::R11, gadget.gadget_addr);
    code.store_reg_at_rsp_disp(Reg64::R11, 0);
    code.mov_abs(Reg64::Rax, landing_addr);
    code.store_reg_at_rsp_disp(Reg64::Rax, 8 + gadget.stack_adjust);
    code.mov_abs(Reg64::Rax, function);
    code.jmp_rax();
    if post_add != 0 {
        code.add_rsp(post_add);
    }
}

fn spoofed_stack_frame(stack_adjust: u8, desired_frame_mod: u8) -> (u8, u8) {
    let base = 16u16 + u16::from(stack_adjust);
    let desired = u16::from(desired_frame_mod);
    let post_add = (16 + desired - (base % 16)) % 16;
    let frame_size = base + post_add;
    (
        u8::try_from(frame_size).expect("spoofed stack frame fits in imm8"),
        u8::try_from(post_add).expect("spoofed stack fixup fits in imm8"),
    )
}

fn tail_jump_original_import(code: &mut X64Stub, original_target: u64) {
    code.pop(Reg64::R9);
    code.pop(Reg64::R8);
    code.pop(Reg64::Rdx);
    code.pop(Reg64::Rcx);
    code.mov_abs(Reg64::Rax, original_target);
    code.jmp_rax();
}

fn framed_prologue(code: &mut X64Stub) {
    code.sub_rsp(FRAMED_STUB_STACK_ALLOC);
    code.store_reg_at_rsp_disp(Reg64::Rcx, 0x28);
    code.store_reg_at_rsp_disp(Reg64::Rdx, 0x30);
    code.store_reg_at_rsp_disp(Reg64::R8, 0x38);
    code.store_reg_at_rsp_disp(Reg64::R9, 0x40);
}

fn framed_tail_jump_original_import(code: &mut X64Stub, original_target: u64) {
    code.load_reg_from_rsp_disp(Reg64::Rcx, 0x28);
    code.load_reg_from_rsp_disp(Reg64::Rdx, 0x30);
    code.load_reg_from_rsp_disp(Reg64::R8, 0x38);
    code.load_reg_from_rsp_disp(Reg64::R9, 0x40);
    code.add_rsp(FRAMED_STUB_STACK_ALLOC);
    code.mov_abs(Reg64::Rax, original_target);
    code.jmp_rax();
}

#[derive(Clone, Copy)]
enum Reg64 {
    Rax,
    Rcx,
    Rdx,
    R8,
    R9,
    R10,
    R11,
}

struct X64Stub {
    bytes: Vec<u8>,
}

impl X64Stub {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(192),
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn mov_abs(&mut self, reg: Reg64, value: u64) {
        match reg {
            Reg64::Rax => self.bytes.extend_from_slice(&[0x48, 0xB8]),
            Reg64::Rcx => self.bytes.extend_from_slice(&[0x48, 0xB9]),
            Reg64::Rdx => self.bytes.extend_from_slice(&[0x48, 0xBA]),
            Reg64::R8 => self.bytes.extend_from_slice(&[0x49, 0xB8]),
            Reg64::R9 => self.bytes.extend_from_slice(&[0x49, 0xB9]),
            Reg64::R10 => self.bytes.extend_from_slice(&[0x49, 0xBA]),
            Reg64::R11 => self.bytes.extend_from_slice(&[0x49, 0xBB]),
        }
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn store_rax_at_r10(&mut self) {
        self.bytes.extend_from_slice(&[0x49, 0x89, 0x02]);
    }

    fn push(&mut self, reg: Reg64) {
        match reg {
            Reg64::Rax => self.bytes.push(0x50),
            Reg64::Rcx => self.bytes.push(0x51),
            Reg64::Rdx => self.bytes.push(0x52),
            Reg64::R8 => self.bytes.extend_from_slice(&[0x41, 0x50]),
            Reg64::R9 => self.bytes.extend_from_slice(&[0x41, 0x51]),
            Reg64::R10 => self.bytes.extend_from_slice(&[0x41, 0x52]),
            Reg64::R11 => self.bytes.extend_from_slice(&[0x41, 0x53]),
        }
    }

    fn pop(&mut self, reg: Reg64) {
        match reg {
            Reg64::Rax => self.bytes.push(0x58),
            Reg64::Rcx => self.bytes.push(0x59),
            Reg64::Rdx => self.bytes.push(0x5A),
            Reg64::R8 => self.bytes.extend_from_slice(&[0x41, 0x58]),
            Reg64::R9 => self.bytes.extend_from_slice(&[0x41, 0x59]),
            Reg64::R10 => self.bytes.extend_from_slice(&[0x41, 0x5A]),
            Reg64::R11 => self.bytes.extend_from_slice(&[0x41, 0x5B]),
        }
    }

    fn mov_byte_zero_at_rdx(&mut self) {
        self.bytes.extend_from_slice(&[0xC6, 0x02, 0x00]);
    }

    fn movzx_eax_byte_at_rdx(&mut self) {
        self.bytes.extend_from_slice(&[0x0F, 0xB6, 0x02]);
    }

    fn mov_al_at_rdx(&mut self) {
        self.bytes.extend_from_slice(&[0x88, 0x02]);
    }

    fn xor_eax_eax(&mut self) {
        self.bytes.extend_from_slice(&[0x31, 0xC0]);
    }

    fn lock_cmpxchg_rax_at_r10_with_r11(&mut self) {
        self.bytes
            .extend_from_slice(&[0xF0, 0x4D, 0x0F, 0xB1, 0x1A]);
    }

    fn jne_rel32_placeholder(&mut self) -> usize {
        self.bytes.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]);
        self.bytes.len() - 4
    }

    fn patch_rel32(&mut self, imm_offset: usize, target: usize) {
        let next = imm_offset + 4;
        let rel = (target as isize)
            .checked_sub(next as isize)
            .expect("stub branch target fits in isize");
        let rel = i32::try_from(rel).expect("stub branch target fits in rel32");
        self.bytes[imm_offset..imm_offset + 4].copy_from_slice(&rel.to_le_bytes());
    }

    fn call_rax_windows_x64(&mut self) {
        self.sub_rsp(0x28);
        self.bytes.extend_from_slice(&[0xFF, 0xD0]);
        self.add_rsp(0x28);
    }

    fn call_rax_with_current_frame(&mut self) {
        self.bytes.extend_from_slice(&[0xFF, 0xD0]);
    }

    fn sub_rsp(&mut self, amount: u8) {
        self.bytes.extend_from_slice(&[0x48, 0x83, 0xEC, amount]);
    }

    fn add_rsp(&mut self, amount: u8) {
        self.bytes.extend_from_slice(&[0x48, 0x83, 0xC4, amount]);
    }

    fn add_rdx_imm32(&mut self, amount: u32) {
        self.bytes.extend_from_slice(&[0x48, 0x81, 0xC2]);
        self.bytes.extend_from_slice(&amount.to_le_bytes());
    }

    fn jmp_rax(&mut self) {
        self.bytes.extend_from_slice(&[0xFF, 0xE0]);
    }

    fn dec_rcx(&mut self) {
        self.bytes.extend_from_slice(&[0x48, 0xFF, 0xC9]);
    }

    fn store_reg_at_rsp_disp(&mut self, reg: Reg64, disp: u8) {
        match reg {
            Reg64::Rax => self
                .bytes
                .extend_from_slice(&[0x48, 0x89, 0x44, 0x24, disp]),
            Reg64::Rcx => self
                .bytes
                .extend_from_slice(&[0x48, 0x89, 0x4C, 0x24, disp]),
            Reg64::Rdx => self
                .bytes
                .extend_from_slice(&[0x48, 0x89, 0x54, 0x24, disp]),
            Reg64::R8 => self
                .bytes
                .extend_from_slice(&[0x4C, 0x89, 0x44, 0x24, disp]),
            Reg64::R9 => self
                .bytes
                .extend_from_slice(&[0x4C, 0x89, 0x4C, 0x24, disp]),
            Reg64::R11 => self
                .bytes
                .extend_from_slice(&[0x4C, 0x89, 0x5C, 0x24, disp]),
            _ => unreachable!("unsupported stack spill register"),
        }
    }

    fn load_reg_from_rsp_disp(&mut self, reg: Reg64, disp: u8) {
        match reg {
            Reg64::Rcx => self
                .bytes
                .extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, disp]),
            Reg64::Rdx => self
                .bytes
                .extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, disp]),
            Reg64::R8 => self
                .bytes
                .extend_from_slice(&[0x4C, 0x8B, 0x44, 0x24, disp]),
            Reg64::R9 => self
                .bytes
                .extend_from_slice(&[0x4C, 0x8B, 0x4C, 0x24, disp]),
            _ => unreachable!("unsupported stack reload register"),
        }
    }
}

#[cfg(test)]
fn windows_x64_call_sequence_offset(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(10)
        .position(|w| w == [0x48, 0x83, 0xEC, 0x28, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28])
}

fn find_stage(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    pattern: Option<&GuestBytePattern>,
) -> Result<u64, GuestInjectError> {
    if let Some(pattern) = pattern
        && let Some(addr) = find_stage_pattern(backend, pid, pattern)?
    {
        return Ok(addr);
    }
    find_writable_executable_code_cave(backend, pid, STAGE_CAVE_SIZE)
}

fn find_stage_pattern(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    pattern: &GuestBytePattern,
) -> Result<Option<u64>, GuestInjectError> {
    for region in backend.memory_map(pid)? {
        if !region.readable || !region.executable || region.size < pattern.len() as u64 {
            continue;
        }
        let mut pos = 0u64;
        while pos < region.size {
            let len = (region.size - pos).min(SCAN_CHUNK + pattern.len() as u64) as usize;
            let addr = region.base + pos;
            if let Ok(bytes) = backend.read(pid, addr, len)
                && let Some(off) = pattern.find_in(&bytes)
            {
                return Ok(Some(addr + off as u64));
            }
            pos += SCAN_CHUNK;
        }
    }
    Ok(None)
}

fn find_result_block(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    pattern: Option<&GuestBytePattern>,
    fallback: u64,
) -> Result<u64, GuestInjectError> {
    if let Some(pattern) = pattern
        && let Some(addr) = find_writable_pattern(backend, pid, pattern)?
    {
        return Ok(addr);
    }
    validate_result_region(backend, pid, fallback)?;
    Ok(fallback)
}

fn find_writable_pattern(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    pattern: &GuestBytePattern,
) -> Result<Option<u64>, GuestInjectError> {
    for region in backend.memory_map(pid)? {
        if !region.readable || !region.writable || region.size < pattern.len() as u64 {
            continue;
        }
        let mut pos = 0u64;
        while pos < region.size {
            let len = (region.size - pos).min(SCAN_CHUNK + pattern.len() as u64) as usize;
            let addr = region.base + pos;
            if let Ok(bytes) = backend.read(pid, addr, len)
                && let Some(off) = pattern.find_in(&bytes)
            {
                return Ok(Some(addr + off as u64));
            }
            pos += SCAN_CHUNK;
        }
    }
    Ok(None)
}

fn validate_stub_region(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    stage: u64,
    size: usize,
) -> Result<(), GuestInjectError> {
    let end = stage
        .checked_add(size as u64)
        .ok_or_else(|| GuestInjectError::Config("guest stage range overflows".into()))?;
    for region in backend.memory_map(pid)? {
        let region_end = region.base.saturating_add(region.size);
        if stage >= region.base && end <= region_end {
            if region.readable && region.executable {
                return Ok(());
            }
            return Err(GuestInjectError::Config(format!(
                "guest execution stub at {stage:#x} must be readable+executable; region permissions are {}{}{}",
                if region.readable { 'r' } else { '-' },
                if region.writable { 'w' } else { '-' },
                if region.executable { 'x' } else { '-' },
            )));
        }
    }
    Err(GuestInjectError::Config(format!(
        "guest execution stub at {stage:#x} does not fit in one mapped region"
    )))
}

fn validate_result_region(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    result: u64,
) -> Result<(), GuestInjectError> {
    let end = result
        .checked_add(RESULT_BLOCK_SIZE as u64)
        .ok_or_else(|| GuestInjectError::Config("guest result block range overflows".into()))?;
    for region in backend.memory_map(pid)? {
        let region_end = region.base.saturating_add(region.size);
        if result >= region.base && end <= region_end {
            if region.readable && region.writable {
                return Ok(());
            }
            return Err(GuestInjectError::Config(format!(
                "guest result block at {result:#x} must be readable+writable; region permissions are {}{}{}",
                if region.readable { 'r' } else { '-' },
                if region.writable { 'w' } else { '-' },
                if region.executable { 'x' } else { '-' },
            )));
        }
    }
    Err(GuestInjectError::Config(format!(
        "guest result block at {result:#x} does not fit in one mapped region"
    )))
}

fn find_writable_executable_code_cave(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    size: usize,
) -> Result<u64, GuestInjectError> {
    for region in backend.memory_map(pid)? {
        if !region.readable || !region.writable || !region.executable || region.size < size as u64 {
            continue;
        }
        let mut pos = 0u64;
        while pos < region.size {
            let len = (region.size - pos).min(SCAN_CHUNK + size as u64) as usize;
            let addr = region.base + pos;
            if let Ok(bytes) = backend.read(pid, addr, len)
                && let Some(off) = find_code_cave(&bytes, size)
            {
                return Ok(addr + off as u64);
            }
            pos += SCAN_CHUNK;
        }
    }
    Err(GuestInjectError::Config(
        "guest IAT-hook execution needs guest.stage_base, guest.stage_pattern, or a writable+executable staging region; refusing to patch arbitrary RX code".into(),
    ))
}

fn find_process_pattern<B: GuestMemoryBackend + ?Sized>(
    backend: &B,
    pid: u32,
    pattern: &GuestBytePattern,
) -> Result<Option<u64>, GuestInjectError> {
    let regions = match backend.memory_map(pid) {
        Ok(regions) => regions,
        Err(err) if is_process_gone_error(&err) => return Ok(None),
        Err(err) => return Err(err),
    };
    for region in regions {
        if !region.readable || region.size < pattern.len() as u64 {
            continue;
        }
        let mut pos = 0u64;
        while pos < region.size {
            let len = (region.size - pos).min(SCAN_CHUNK + pattern.len() as u64) as usize;
            let addr = region.base + pos;
            if let Ok(bytes) = backend.read(pid, addr, len)
                && let Some(off) = pattern.find_in(&bytes)
            {
                return Ok(Some(addr + off as u64));
            }
            pos += SCAN_CHUNK;
        }
    }
    Ok(None)
}

fn is_process_gone_error(err: &GuestInjectError) -> bool {
    match err {
        GuestInjectError::Process(_) => true,
        GuestInjectError::Backend(message) => message.contains("no such process"),
        _ => false,
    }
}

fn find_code_cave(bytes: &[u8], size: usize) -> Option<usize> {
    let mut start = None;
    for (idx, byte) in bytes.iter().enumerate() {
        if matches!(*byte, 0x00 | 0x90 | 0xCC) {
            let aligned = match start {
                Some(pos) => pos,
                None => align_up(idx, 16),
            };
            start = Some(aligned);
            if idx + 1 >= aligned + size {
                return Some(aligned);
            }
        } else {
            start = None;
        }
    }
    None
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn find_iat_hook(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    plan: &GuestInjectionPlan,
) -> Result<RemoteIatHook, GuestInjectError> {
    let module = target_module(backend, pid, plan)?;
    let mut errors = Vec::new();
    for hook_module in import_module_candidates(&plan.hook_module) {
        match find_import_iat(backend, pid, module.base, &hook_module, &plan.hook_function) {
            Ok(import) => return Ok(import),
            Err(err) => errors.push(format!("{hook_module}: {err}")),
        }
    }
    Err(GuestInjectError::Image(format!(
        "target import {}!{} not found via {}",
        plan.hook_module,
        plan.hook_function,
        errors.join("; ")
    )))
}

fn target_module(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    plan: &GuestInjectionPlan,
) -> Result<GuestModuleInfo, GuestInjectError> {
    let modules = backend.module_list(pid)?;
    match plan.target_module.as_deref() {
        Some(name) => modules
            .into_iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| GuestInjectError::Process(format!("module {name:?} not found"))),
        None => modules
            .into_iter()
            .find(|m| m.name.to_ascii_lowercase().ends_with(".exe"))
            .ok_or_else(|| GuestInjectError::Process("target exe module not found".into())),
    }
}

fn find_import_iat(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    base: u64,
    module_name: &str,
    function_name: &str,
) -> Result<RemoteIatHook, GuestInjectError> {
    let hdr = backend.read(pid, base, 0x1000)?;
    if u16_at(&hdr, 0).map_err(GuestInjectError::from)? != 0x5A4D {
        return Err(GuestInjectError::Image(
            "target module missing MZ header".into(),
        ));
    }
    let nt = u32_at(&hdr, 0x3C).map_err(GuestInjectError::from)? as usize;
    if u32_at(&hdr, nt).map_err(GuestInjectError::from)? != 0x0000_4550 {
        return Err(GuestInjectError::Image(
            "target module missing PE header".into(),
        ));
    }
    let opt = nt + 24;
    let import_rva = u32_at(&hdr, opt + 112 + 8).map_err(GuestInjectError::from)? as u64;
    if import_rva == 0 {
        return Err(GuestInjectError::Image(
            "target module has no import table".into(),
        ));
    }
    let mut desc_addr = base + import_rva;
    loop {
        let desc = backend.read(pid, desc_addr, 20)?;
        let original_first_thunk = u32_at(&desc, 0).map_err(GuestInjectError::from)? as u64;
        let name_rva = u32_at(&desc, 12).map_err(GuestInjectError::from)? as u64;
        let first_thunk = u32_at(&desc, 16).map_err(GuestInjectError::from)? as u64;
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        let remote_name = read_remote_cstr(backend, pid, base + name_rva, 256)?;
        if remote_name.eq_ignore_ascii_case(module_name) {
            let lookup = match original_first_thunk {
                0 => first_thunk,
                rva => rva,
            };
            let mut index = 0u64;
            loop {
                let thunk = read_remote_u64(backend, pid, base + lookup + index * 8)?;
                if thunk == 0 {
                    break;
                }
                if thunk & 0x8000_0000_0000_0000 == 0 {
                    let name = read_remote_cstr(backend, pid, base + thunk + 2, 256)?;
                    if name == function_name {
                        let iat_slot = base + first_thunk + index * 8;
                        return Ok(RemoteIatHook {
                            iat_slot,
                            original_target: read_remote_u64(backend, pid, iat_slot)?,
                        });
                    }
                }
                index += 1;
            }
        }
        desc_addr += 20;
    }
    Err(GuestInjectError::Image(format!(
        "target import {module_name}!{function_name} not found"
    )))
}

fn resolve_import_symbol(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    module: &str,
    name: &str,
) -> Result<u64, GuestInjectError> {
    let candidates = import_module_candidates(module);
    let mut errors = Vec::new();
    tracing::debug!(
        pid,
        requested_module = module,
        symbol = name,
        candidates = %candidates.join(","),
        "resolving guest import symbol"
    );
    for candidate in &candidates {
        match resolve_export_name(backend, pid, candidate, name, 0) {
            Ok(addr) => {
                tracing::debug!(
                    pid,
                    requested_module = module,
                    resolved_module = candidate,
                    symbol = name,
                    address = format_args!("{addr:#x}"),
                    "guest import symbol resolved"
                );
                return Ok(addr);
            }
            Err(err) => {
                tracing::debug!(
                    pid,
                    requested_module = module,
                    candidate,
                    symbol = name,
                    error = %err,
                    "guest import candidate failed"
                );
                errors.push(format!("{candidate}: {err}"));
            }
        }
    }
    Err(GuestInjectError::Image(format!(
        "import {module}!{name} not found via {}",
        errors.join("; ")
    )))
}

fn resolve_import_symbol_ordinal(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    module: &str,
    ordinal: u16,
) -> Result<u64, GuestInjectError> {
    let candidates = import_module_candidates(module);
    let mut errors = Vec::new();
    tracing::debug!(
        pid,
        requested_module = module,
        ordinal,
        candidates = %candidates.join(","),
        "resolving guest ordinal import"
    );
    for candidate in &candidates {
        match resolve_export_ordinal(backend, pid, candidate, ordinal, 0) {
            Ok(addr) => {
                tracing::debug!(
                    pid,
                    requested_module = module,
                    resolved_module = candidate,
                    ordinal,
                    address = format_args!("{addr:#x}"),
                    "guest ordinal import resolved"
                );
                return Ok(addr);
            }
            Err(err) => {
                tracing::debug!(
                    pid,
                    requested_module = module,
                    candidate,
                    ordinal,
                    error = %err,
                    "guest ordinal import candidate failed"
                );
                errors.push(format!("{candidate}: {err}"));
            }
        }
    }
    Err(GuestInjectError::Image(format!(
        "import {module}!#{ordinal} not found via {}",
        errors.join("; ")
    )))
}

#[allow(clippy::too_many_arguments)]
fn resolve_import_symbol_with_dependency_policy(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    loader_apis: Option<GuestLoaderApis>,
    scratch_addr: u64,
    scratch_len: usize,
    timeout_ms: u32,
    policy: GuestDependencyPolicy,
    module: &str,
    symbol: ImportSymbol<'_>,
) -> Result<u64, GuestInjectError> {
    let resolve = |backend: &dyn GuestMemoryBackend| match symbol {
        ImportSymbol::Name(name) => {
            let name = std::str::from_utf8(name)
                .map_err(|e| GuestInjectError::Image(format!("import name: {e}")))?;
            resolve_import_symbol(backend, pid, module, name)
        }
        ImportSymbol::Ordinal(ordinal) => {
            resolve_import_symbol_ordinal(backend, pid, module, ordinal)
        }
    };

    match resolve(backend) {
        Ok(addr) => return Ok(addr),
        Err(err) if policy == GuestDependencyPolicy::LoadWithGuestLoader => {
            tracing::info!(
                pid,
                module,
                error = %err,
                "guest import dependency missing; loading through guest loader"
            );
        }
        Err(err) => return Err(err),
    }

    let loader_apis = loader_apis.ok_or_else(|| GuestInjectError::Unsupported {
        operation: "guest dependency loading",
        reason: "LoadLibraryA/GetProcAddress were not resolved".into(),
    })?;
    let load_name = dependency_load_name(module);
    let loaded_base = load_guest_dependency(
        backend,
        pid,
        hook,
        loader_apis.load_library,
        scratch_addr,
        scratch_len,
        timeout_ms,
        &load_name,
    )?;
    match resolve(backend) {
        Ok(addr) => Ok(addr),
        Err(err) => {
            tracing::debug!(
                pid,
                module,
                loaded_module = load_name,
                loaded_base = format_args!("{loaded_base:#x}"),
                error = %err,
                "guest module-list import retry failed; resolving export through guest GetProcAddress"
            );
            resolve_loaded_import_symbol(
                backend,
                pid,
                hook,
                loader_apis.get_proc_address,
                scratch_addr,
                scratch_len,
                timeout_ms,
                &load_name,
                loaded_base,
                symbol,
            )
        }
    }
}

#[derive(Clone, Copy)]
struct GuestLoaderApis {
    load_library: u64,
    get_proc_address: u64,
}

fn dependency_load_name(module: &str) -> String {
    let lower = module.to_ascii_lowercase();
    if lower.starts_with("api-ms-win-crt-") {
        "ucrtbase.dll".into()
    } else if lower.starts_with("api-ms-win-core-") {
        "kernelbase.dll".into()
    } else {
        module.into()
    }
}

#[allow(clippy::too_many_arguments)]
fn load_guest_dependency(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    load_library: u64,
    scratch_addr: u64,
    scratch_len: usize,
    timeout_ms: u32,
    module: &str,
) -> Result<u64, GuestInjectError> {
    let mut bytes = module.as_bytes().to_vec();
    bytes.push(0);
    if bytes.len() > scratch_len {
        return Err(GuestInjectError::Unsupported {
            operation: "guest dependency loading",
            reason: format!(
                "module name {module:?} needs {} scratch bytes, only {scratch_len} available",
                bytes.len()
            ),
        });
    }

    let original = backend.read(pid, scratch_addr, bytes.len())?;
    write_verified(
        backend,
        pid,
        scratch_addr,
        &bytes,
        "guest dependency module name",
    )?;
    let call_result =
        backend.call_iat_hook(pid, hook, load_library, [scratch_addr, 0, 0, 0], timeout_ms);
    let restore_result = backend.write(pid, scratch_addr, &original);
    if let Err(err) = restore_result {
        tracing::warn!(
            pid,
            scratch_addr = format_args!("{scratch_addr:#x}"),
            error = %err,
            "failed to restore guest dependency scratch bytes"
        );
    }

    let module_base = call_result?;
    if module_base == 0 {
        return Err(GuestInjectError::Backend(format!(
            "guest LoadLibraryA({module:?}) returned NULL"
        )));
    }
    tracing::info!(
        pid,
        module,
        module_base = format_args!("{module_base:#x}"),
        "guest dependency loaded"
    );
    Ok(module_base)
}

#[allow(clippy::too_many_arguments)]
fn resolve_loaded_import_symbol(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    get_proc_address: u64,
    scratch_addr: u64,
    scratch_len: usize,
    timeout_ms: u32,
    module: &str,
    module_base: u64,
    symbol: ImportSymbol<'_>,
) -> Result<u64, GuestInjectError> {
    let proc = match symbol {
        ImportSymbol::Name(name) => {
            let name = std::str::from_utf8(name)
                .map_err(|e| GuestInjectError::Image(format!("import name: {e}")))?;
            guest_get_proc_address(
                backend,
                pid,
                hook,
                get_proc_address,
                scratch_addr,
                scratch_len,
                timeout_ms,
                module_base,
                name,
            )?
        }
        ImportSymbol::Ordinal(ordinal) => backend.call_iat_hook(
            pid,
            hook,
            get_proc_address,
            [module_base, u64::from(ordinal), 0, 0],
            timeout_ms,
        )?,
    };
    if proc == 0 {
        return Err(GuestInjectError::Image(format!(
            "export {module}!{} not found",
            symbol.label()
        )));
    }
    tracing::debug!(
        pid,
        module,
        module_base = format_args!("{module_base:#x}"),
        symbol = %symbol.label(),
        address = format_args!("{proc:#x}"),
        "guest loaded dependency export resolved through GetProcAddress"
    );
    Ok(proc)
}

#[allow(clippy::too_many_arguments)]
fn guest_get_proc_address(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    get_proc_address: u64,
    scratch_addr: u64,
    scratch_len: usize,
    timeout_ms: u32,
    module_base: u64,
    name: &str,
) -> Result<u64, GuestInjectError> {
    let mut bytes = name.as_bytes().to_vec();
    bytes.push(0);
    if bytes.len() > scratch_len {
        return Err(GuestInjectError::Unsupported {
            operation: "guest dependency export lookup",
            reason: format!(
                "symbol name {name:?} needs {} scratch bytes, only {scratch_len} available",
                bytes.len()
            ),
        });
    }

    let original = backend.read(pid, scratch_addr, bytes.len())?;
    write_verified(
        backend,
        pid,
        scratch_addr,
        &bytes,
        "guest dependency symbol name",
    )?;
    let call_result = backend.call_iat_hook(
        pid,
        hook,
        get_proc_address,
        [module_base, scratch_addr, 0, 0],
        timeout_ms,
    );
    let restore_result = backend.write(pid, scratch_addr, &original);
    if let Err(err) = restore_result {
        tracing::warn!(
            pid,
            scratch_addr = format_args!("{scratch_addr:#x}"),
            error = %err,
            "failed to restore guest dependency symbol scratch bytes"
        );
    }
    call_result
}

impl ImportSymbol<'_> {
    fn label(&self) -> String {
        match self {
            ImportSymbol::Name(name) => String::from_utf8_lossy(name).into_owned(),
            ImportSymbol::Ordinal(ordinal) => format!("#{ordinal}"),
        }
    }
}

#[derive(Clone, Copy)]
enum ExportLookup<'a> {
    Name(&'a str),
    Ordinal(u16),
}

fn resolve_export_name(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    module: &str,
    name: &str,
    depth: usize,
) -> Result<u64, GuestInjectError> {
    resolve_export(backend, pid, module, ExportLookup::Name(name), depth)
}

fn resolve_export_ordinal(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    module: &str,
    ordinal: u16,
    depth: usize,
) -> Result<u64, GuestInjectError> {
    resolve_export(backend, pid, module, ExportLookup::Ordinal(ordinal), depth)
}

fn resolve_export(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    module: &str,
    lookup: ExportLookup<'_>,
    depth: usize,
) -> Result<u64, GuestInjectError> {
    if depth > MAX_EXPORT_FORWARD_DEPTH {
        return Err(GuestInjectError::Image(format!(
            "forwarded export chain exceeded {MAX_EXPORT_FORWARD_DEPTH} hops"
        )));
    }
    let module = find_module_ci(backend, pid, module)?;
    let export_rva = find_export_rva(backend, pid, &module, lookup)?;
    let export_dir = export_directory(backend, pid, module.base)?;
    if export_rva >= export_dir.rva as u64
        && export_rva < export_dir.rva as u64 + export_dir.size as u64
    {
        let forwarder = read_remote_cstr(backend, pid, module.base + export_rva, 256)?;
        tracing::debug!(
            pid,
            module = %module.name,
            forwarder,
            "guest export is forwarded"
        );
        return resolve_forwarded_export(backend, pid, &forwarder, depth + 1);
    }
    Ok(module.base + export_rva)
}

fn resolve_forwarded_export(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    forwarder: &str,
    depth: usize,
) -> Result<u64, GuestInjectError> {
    let (module, symbol) = forwarder.rsplit_once('.').ok_or_else(|| {
        GuestInjectError::Image(format!("bad forwarded export string {forwarder:?}"))
    })?;
    let module = normalize_forwarder_module(module);
    match symbol.strip_prefix('#') {
        Some(ordinal) => {
            let ordinal = ordinal.parse::<u16>().map_err(|e| {
                GuestInjectError::Image(format!("bad forwarded export ordinal {forwarder:?}: {e}"))
            })?;
            resolve_export_ordinal(backend, pid, &module, ordinal, depth)
        }
        None => resolve_export_name(backend, pid, &module, symbol, depth),
    }
}

fn normalize_forwarder_module(module: &str) -> String {
    let lower = module.to_ascii_lowercase();
    if lower.ends_with(".dll") || lower.ends_with(".exe") {
        module.to_string()
    } else {
        format!("{module}.dll")
    }
}

fn find_module_ci(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    module: &str,
) -> Result<GuestModuleInfo, GuestInjectError> {
    let modules = backend.module_list(pid)?;
    modules
        .into_iter()
        .find(|m| {
            m.name.eq_ignore_ascii_case(module)
                || m.name
                    .rsplit(['\\', '/'])
                    .next()
                    .is_some_and(|base| base.eq_ignore_ascii_case(module))
        })
        .ok_or_else(|| GuestInjectError::Process(format!("module {module:?} not found")))
}

fn find_export_rva(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    module: &GuestModuleInfo,
    lookup: ExportLookup<'_>,
) -> Result<u64, GuestInjectError> {
    let export = export_directory(backend, pid, module.base)?;
    let dir = backend.read(pid, module.base + export.rva as u64, 40)?;
    let ordinal_base = u32_at(&dir, 16).map_err(GuestInjectError::from)?;
    let function_count = u32_at(&dir, 20).map_err(GuestInjectError::from)?;
    let name_count = u32_at(&dir, 24).map_err(GuestInjectError::from)?;
    let functions_rva = u32_at(&dir, 28).map_err(GuestInjectError::from)? as u64;
    let names_rva = u32_at(&dir, 32).map_err(GuestInjectError::from)? as u64;
    let ordinals_rva = u32_at(&dir, 36).map_err(GuestInjectError::from)? as u64;

    let index = match lookup {
        ExportLookup::Name(want) => {
            let mut found = None;
            for i in 0..name_count.min(65_536) {
                let name_rva =
                    read_remote_u32(backend, pid, module.base + names_rva + u64::from(i) * 4)?;
                let name = read_remote_cstr(backend, pid, module.base + u64::from(name_rva), 512)?;
                if name == want {
                    found = Some(u32::from(read_remote_u16(
                        backend,
                        pid,
                        module.base + ordinals_rva + u64::from(i) * 2,
                    )?));
                    break;
                }
            }
            found.ok_or_else(|| {
                GuestInjectError::Image(format!("export {}!{want} not found", module.name))
            })?
        }
        ExportLookup::Ordinal(ordinal) => {
            let ordinal = u32::from(ordinal);
            if ordinal < ordinal_base {
                return Err(GuestInjectError::Image(format!(
                    "export {}!#{ordinal} precedes ordinal base {ordinal_base}",
                    module.name
                )));
            }
            ordinal - ordinal_base
        }
    };

    if index >= function_count {
        return Err(GuestInjectError::Image(format!(
            "export {} index {index} exceeds function count {function_count}",
            module.name
        )));
    }
    let rva = read_remote_u32(
        backend,
        pid,
        module.base + functions_rva + u64::from(index) * 4,
    )?;
    if rva == 0 {
        return Err(GuestInjectError::Image(format!(
            "export {} index {index} is null",
            module.name
        )));
    }
    Ok(u64::from(rva))
}

fn export_directory(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    base: u64,
) -> Result<crate::pe::Dir, GuestInjectError> {
    let mut last = None;
    for attempt in 0..=EXPORT_HEADER_RETRIES {
        match export_directory_once(backend, pid, base) {
            Ok(dir) => return Ok(dir),
            Err(err)
                if is_transient_export_header_error(&err) && attempt < EXPORT_HEADER_RETRIES =>
            {
                tracing::debug!(
                    pid,
                    base = format_args!("{base:#x}"),
                    attempt = attempt + 1,
                    error = %err,
                    "guest export header not ready; retrying"
                );
                last = Some(err);
                thread::sleep(EXPORT_HEADER_RETRY_DELAY);
            }
            Err(err) => return Err(err),
        }
    }
    Err(last.unwrap_or_else(|| GuestInjectError::Image("export module header not ready".into())))
}

fn export_directory_once(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    base: u64,
) -> Result<crate::pe::Dir, GuestInjectError> {
    let hdr = backend.read(pid, base, 0x1000)?;
    if u16_at(&hdr, 0).map_err(GuestInjectError::from)? != 0x5A4D {
        return Err(GuestInjectError::Image(format!(
            "export module at {base:#x} missing MZ header"
        )));
    }
    let nt = u32_at(&hdr, 0x3C).map_err(GuestInjectError::from)? as usize;
    if u32_at(&hdr, nt).map_err(GuestInjectError::from)? != 0x0000_4550 {
        return Err(GuestInjectError::Image(format!(
            "export module at {base:#x} missing PE header"
        )));
    }
    let opt = nt + 24;
    let rva = u32_at(&hdr, opt + 112).map_err(GuestInjectError::from)?;
    let size = u32_at(&hdr, opt + 116).map_err(GuestInjectError::from)?;
    if rva == 0 || size == 0 {
        return Err(GuestInjectError::Image(format!(
            "export module at {base:#x} has no export directory"
        )));
    }
    Ok(crate::pe::Dir { rva, size })
}

fn is_transient_export_header_error(err: &GuestInjectError) -> bool {
    match err {
        GuestInjectError::Image(message) => {
            message.contains("missing MZ header") || message.contains("missing PE header")
        }
        GuestInjectError::Backend(message) => message.contains("read"),
        _ => false,
    }
}

fn import_module_candidates(module: &str) -> Vec<String> {
    let mut out = vec![module.to_string()];
    let lower = module.to_ascii_lowercase();
    if lower == "kernel32.dll" {
        out.push("kernelbase.dll".into());
    } else if lower.starts_with("api-ms-win-crt-") {
        out.push("ucrtbase.dll".into());
    } else if lower.starts_with("api-ms-win-core-") {
        out.push("kernelbase.dll".into());
        out.push("kernel32.dll".into());
        out.push("ntdll.dll".into());
    }
    out.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    out
}

fn read_remote_u64(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    addr: u64,
) -> Result<u64, GuestInjectError> {
    let bytes = backend.read(pid, addr, 8)?;
    Ok(u64::from_le_bytes(bytes[0..8].try_into().unwrap()))
}

fn read_remote_u32(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    addr: u64,
) -> Result<u32, GuestInjectError> {
    let bytes = backend.read(pid, addr, 4)?;
    Ok(u32::from_le_bytes(bytes[0..4].try_into().unwrap()))
}

fn read_remote_u16(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    addr: u64,
) -> Result<u16, GuestInjectError> {
    let bytes = backend.read(pid, addr, 2)?;
    Ok(u16::from_le_bytes(bytes[0..2].try_into().unwrap()))
}

fn read_remote_cstr(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    addr: u64,
    max: usize,
) -> Result<String, GuestInjectError> {
    let bytes = backend.read(pid, addr, max)?;
    let len = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| GuestInjectError::Image(format!("unterminated string at {addr:#x}")))?;
    Ok(String::from_utf8_lossy(&bytes[..len]).into_owned())
}

fn parse_hex_pattern(pattern: &str, field: &str) -> Result<GuestBytePattern, GuestInjectError> {
    let mut out = Vec::new();
    for token in pattern.split_whitespace() {
        if token == "?" || token == "??" {
            out.push(None);
        } else {
            let hex = token.trim_start_matches("0x");
            let byte = u8::from_str_radix(hex, 16).map_err(|e| {
                GuestInjectError::Config(format!("bad {field} byte {token:?}: {e}"))
            })?;
            out.push(Some(byte));
        }
    }
    match out.is_empty() {
        true => Err(GuestInjectError::Config(format!("{field} cannot be empty"))),
        false => Ok(GuestBytePattern { bytes: out }),
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
            pattern: None,
        };
        assert!(matches!(
            target.validate(),
            Err(GuestInjectError::Config(_))
        ));
    }

    #[test]
    fn memflow_capabilities_cover_iat_hook_manual_map() {
        let capabilities = GuestCapabilities::memflow_guest_injection();
        let missing = capabilities.missing_manual_map();
        assert!(missing.is_empty(), "{missing:?}");
        assert!(capabilities.exception_registration);
        assert!(!capabilities.vad_spoof);
    }

    struct VadRejectBackend;

    impl GuestMemoryBackend for VadRejectBackend {
        fn capabilities(&self) -> GuestCapabilities {
            GuestCapabilities::memflow_guest_injection()
        }

        fn list_processes(&self) -> Result<Vec<GuestProcessInfo>, GuestInjectError> {
            panic!("vad spoof rejection should happen before process access")
        }

        fn module_list(&self, _pid: u32) -> Result<Vec<GuestModuleInfo>, GuestInjectError> {
            panic!("vad spoof rejection should happen before module access")
        }

        fn module_exports(
            &self,
            _pid: u32,
            _module: &str,
        ) -> Result<Vec<(String, u64)>, GuestInjectError> {
            panic!("vad spoof rejection should happen before export access")
        }

        fn memory_map(&self, _pid: u32) -> Result<Vec<GuestMemoryRegion>, GuestInjectError> {
            panic!("vad spoof rejection should happen before memory-map access")
        }

        fn read(&self, _pid: u32, _addr: u64, _len: usize) -> Result<Vec<u8>, GuestInjectError> {
            panic!("vad spoof rejection should happen before memory reads")
        }

        fn write(&self, _pid: u32, _addr: u64, _data: &[u8]) -> Result<(), GuestInjectError> {
            panic!("vad spoof rejection should happen before memory writes")
        }
    }

    #[test]
    fn vad_spoof_is_rejected_before_guest_access_when_backend_cannot_do_it() {
        let config = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\npid = 1\npayload_path = \"payload.dll\"\n\
             vad_spoof = \"vad-image-map\"\n",
        )
        .unwrap();
        let plan = GuestInjectionPlan::from_config(&config).unwrap();
        let injector = GuestManualMapInjector;
        let req = GuestInjectionRequest {
            plan: &plan,
            payload_path: std::path::Path::new("payload.dll"),
            payload_image: &[0x4d],
        };

        match injector.inject(&VadRejectBackend, &req) {
            Err(GuestInjectError::Unsupported { operation, reason }) => {
                assert_eq!(operation, "VAD type spoofing");
                assert!(reason.contains("VAD mutation support"), "{reason}");
            }
            Ok(_) => panic!("expected VAD spoof rejection"),
            Err(err) => panic!("expected VAD spoof unsupported error, got {err:?}"),
        }
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

    #[test]
    fn import_candidates_cover_forwarded_and_api_set_imports() {
        assert_eq!(
            import_module_candidates("KERNEL32.dll"),
            vec!["KERNEL32.dll", "kernelbase.dll"]
        );
        assert_eq!(
            import_module_candidates("api-ms-win-core-synch-l1-2-0.dll"),
            vec![
                "api-ms-win-core-synch-l1-2-0.dll",
                "kernelbase.dll",
                "kernel32.dll",
                "ntdll.dll"
            ]
        );
        assert_eq!(
            import_module_candidates("api-ms-win-crt-runtime-l1-1-0.dll"),
            vec!["api-ms-win-crt-runtime-l1-1-0.dll", "ucrtbase.dll"]
        );
        assert_eq!(normalize_forwarder_module("KERNELBASE"), "KERNELBASE.dll");
    }

    #[test]
    fn iat_hook_stub_uses_windows_x64_shadow_space() {
        let hook = GuestIatHook {
            iat_slot: 0x1000,
            original_target: 0x2000,
            stub_addr: 0x3000,
            result_addr: 0x4000,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        let stub = call_stub(&hook, 0x5000, [1, 2, 3, 4]);
        assert!(
            windows_x64_call_sequence_offset(&stub).is_some(),
            "stub must reserve 32 bytes of Windows x64 shadow space and keep stack alignment"
        );
        assert!(
            stub.windows(5).any(|w| w == [0xF0, 0x4D, 0x0F, 0xB1, 0x1A]),
            "stub must atomically claim the result block so only one thread runs the injection call"
        );
        assert!(
            !stub.windows(8).any(|w| w == hook.iat_slot.to_le_bytes()),
            "stub must not write the guest IAT; the host transaction restores it"
        );
        assert!(
            stub.starts_with(&[0x51, 0x52, 0x41, 0x50, 0x41, 0x51]),
            "stub must save the import caller's register arguments before the injected call"
        );
        assert!(
            !stub
                .windows(10)
                .any(|w| w == [0x48, 0x83, 0xEC, 0x20, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x20]),
            "0x20 would misalign the nested Windows x64 call from an IAT tail jump"
        );
        assert!(
            stub.windows(8)
                .any(|w| w == hook.original_target.to_le_bytes()),
            "stub must tail-jump to the original imported function after publishing the result"
        );
        assert_eq!(
            &stub[stub.len() - 2..],
            &[0xFF, 0xE0],
            "stub should tail-jump through RAX to the original import target"
        );
    }

    #[test]
    fn iat_hook_spoofed_stub_keeps_landing_after_shadow_space() {
        let hook = GuestIatHook {
            iat_slot: 0x1000,
            original_target: 0x2000,
            stub_addr: 0x3000,
            result_addr: 0x4000,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: Some(GuestSpoofedReturn {
                gadget_addr: 0x7000,
                stack_adjust: 0x20,
            }),
        };
        let stub = call_stub(&hook, 0x5000, [1, 2, 3, 4]);
        assert!(
            stub.windows(4).any(|w| w == [0x48, 0x83, 0xEC, 0x30]),
            "native spoofed call must reserve return, shadow space, and continuation"
        );
        assert!(
            stub.windows(5).any(|w| w == [0x4C, 0x89, 0x5C, 0x24, 0x00]),
            "spoofed gadget must be placed as the callee return address"
        );
        assert!(
            stub.windows(5).any(|w| w == [0x48, 0x89, 0x44, 0x24, 0x28]),
            "real continuation must be stored after the 32-byte Windows x64 shadow space"
        );
        assert!(
            !stub.windows(3).any(|w| w == [0x50, 0x41, 0x53]),
            "spoofed call must not put the continuation in the callee shadow space with pushes"
        );
    }

    #[test]
    fn spoofed_stack_frame_restores_native_and_framed_callers() {
        assert_eq!(spoofed_stack_frame(0x20, 0), (0x30, 0));
        assert_eq!(spoofed_stack_frame(0x28, 0), (0x40, 0x08));
        assert_eq!(spoofed_stack_frame(0x20, 8), (0x38, 0x08));
        assert_eq!(spoofed_stack_frame(0x28, 8), (0x38, 0));
    }

    #[test]
    fn iat_hook_touch_stub_materializes_pages_without_iat_write() {
        let hook = GuestIatHook {
            iat_slot: 0x1000,
            original_target: 0x2000,
            stub_addr: 0x3000,
            result_addr: 0x4000,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        let stub = touch_stub(&hook, 0x5000, GUEST_PAGE_SIZE + 1);
        assert!(
            stub.windows(3).any(|w| w == [0xC6, 0x02, 0x00]),
            "touch stub must fault in pages by writing through RDX"
        );
        assert!(
            stub.windows(7)
                .any(|w| w == [0x48, 0x81, 0xC2, 0x00, 0x10, 0x00, 0x00]),
            "touch stub must advance by guest page size"
        );
        assert!(
            !stub.windows(8).any(|w| w == hook.iat_slot.to_le_bytes()),
            "touch stub must not write the guest IAT; the host transaction restores it"
        );
        assert!(
            stub.windows(8)
                .any(|w| w == hook.original_target.to_le_bytes()),
            "touch stub must tail-jump to the original imported function"
        );
        assert_eq!(
            &stub[stub.len() - 2..],
            &[0xFF, 0xE0],
            "touch stub should tail-jump through RAX to the original import target"
        );
    }

    #[test]
    fn iat_hook_read_touch_stub_materializes_without_writes() {
        let hook = GuestIatHook {
            iat_slot: 0x1000,
            original_target: 0x2000,
            stub_addr: 0x3000,
            result_addr: 0x4000,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        let stub = read_touch_stub(&hook, 0x5000, GUEST_PAGE_SIZE + 1);
        assert!(
            stub.windows(3).any(|w| w == [0x0F, 0xB6, 0x02]),
            "read-touch stub must fault in pages by reading through RDX"
        );
        assert!(
            !stub.windows(3).any(|w| w == [0xC6, 0x02, 0x00]),
            "read-touch stub must not write to materialized pages"
        );
        assert!(
            !stub.windows(8).any(|w| w == hook.iat_slot.to_le_bytes()),
            "read-touch stub must not write the guest IAT; the host transaction restores it"
        );
    }

    #[test]
    fn iat_hook_preserve_touch_stub_writes_same_byte() {
        let hook = GuestIatHook {
            iat_slot: 0x1000,
            original_target: 0x2000,
            stub_addr: 0x3000,
            result_addr: 0x4000,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        let stub = preserve_touch_stub(&hook, 0x5000, GUEST_PAGE_SIZE + 1);
        assert!(
            stub.windows(5).any(|w| w == [0x0F, 0xB6, 0x02, 0x88, 0x02]),
            "preserve-touch stub must fault in pages by writing the original byte back"
        );
        assert!(
            !stub.windows(3).any(|w| w == [0xC6, 0x02, 0x00]),
            "preserve-touch stub must not zero image-backed page contents"
        );
        assert!(
            !stub.windows(8).any(|w| w == hook.iat_slot.to_le_bytes()),
            "preserve-touch stub must not write the guest IAT; the host transaction restores it"
        );
    }

    #[test]
    fn sec_image_patch_ranges_batch_contiguous_changed_pages() {
        let mut image = vec![0u8; GUEST_PAGE_SIZE * 5];
        let snapshot = image.clone();
        image[17] = 1;
        image[GUEST_PAGE_SIZE + 2] = 2;
        image[(GUEST_PAGE_SIZE * 3) + 4] = 3;

        assert_eq!(
            sec_image_patched_ranges(&image, &snapshot),
            vec![
                (0, GUEST_PAGE_SIZE * 2),
                (GUEST_PAGE_SIZE * 3, GUEST_PAGE_SIZE * 4),
            ]
        );
    }

    #[test]
    fn spoofed_return_scan_uses_executable_module_regions() {
        let module = GuestModuleInfo {
            name: "ntdll.dll".into(),
            base: 0x1000,
            size: 0x8000,
        };
        let regions = vec![
            GuestMemoryRegion {
                base: 0x1000,
                size: 0x1000,
                readable: true,
                writable: false,
                executable: false,
            },
            GuestMemoryRegion {
                base: 0x2000,
                size: 0x2000,
                readable: true,
                writable: false,
                executable: true,
            },
            GuestMemoryRegion {
                base: 0x9000,
                size: 0x1000,
                readable: true,
                writable: false,
                executable: true,
            },
        ];

        assert_eq!(
            spoofed_return_scan_ranges(&module, &regions),
            vec![(0x2000, 0x4000)]
        );
    }

    #[test]
    fn spoofed_return_scan_falls_back_to_bounded_module_range() {
        let module = GuestModuleInfo {
            name: "kernel32.dll".into(),
            base: 0x7fff_0000,
            size: SPOOFED_RETURN_SCAN_LIMIT + 0x1000,
        };

        assert_eq!(
            spoofed_return_scan_ranges(&module, &[]),
            vec![(0x7fff_0000, 0x7fff_0000 + SPOOFED_RETURN_SCAN_LIMIT)]
        );
    }

    #[test]
    fn spoofed_return_gadget_scan_requires_shadow_space_adjustment() {
        assert_eq!(
            find_spoofed_return_gadget(&[0x90, 0x48, 0x83, 0xC4, 0x20, 0xC3]),
            Some((1, 0x20))
        );
        assert_eq!(find_spoofed_return_gadget(&[0x90, 0xC3]), None);
    }

    #[test]
    fn registered_unwind_stub_uses_single_frame_allocation() {
        let hook = GuestIatHook {
            iat_slot: 0x1000,
            original_target: 0x2000,
            stub_addr: 0x3000,
            result_addr: 0x4000,
            call_stack: GuestCallStackPolicy::RegisteredUnwind,
            spoofed_return: None,
        };
        let stub = call_stub(&hook, 0x5000, [1, 2, 3, 4]);
        assert!(
            stub.starts_with(&[0x48, 0x83, 0xEC, FRAMED_STUB_STACK_ALLOC]),
            "registered-unwind stub must use one unwindable stack allocation"
        );
        assert!(
            !stub.starts_with(&[0x51, 0x52, 0x41, 0x50, 0x41, 0x51]),
            "registered-unwind stub must not use volatile pushes that cannot be represented in x64 unwind metadata"
        );
        assert!(
            !stub
                .windows(10)
                .any(|w| w == [0x48, 0x83, 0xEC, 0x28, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28]),
            "registered-unwind stub keeps its shadow space inside the fixed frame"
        );
        assert_eq!(
            &stub[stub.len() - 2..],
            &[0xFF, 0xE0],
            "registered-unwind stub should tail-jump through RAX to the original import target"
        );
    }

    #[test]
    fn stub_unwind_metadata_describes_registered_frame() {
        let metadata = stub_unwind_metadata().unwrap();
        assert_eq!(&metadata[0..4], &(STAGE_STUB_OFFSET as u32).to_le_bytes());
        assert_eq!(
            &metadata[4..8],
            &(STAGE_SCRATCH_OFFSET as u32).to_le_bytes()
        );
        assert_eq!(
            &metadata[8..12],
            &((STAGE_UNWIND_OFFSET + 12) as u32).to_le_bytes()
        );
        assert_eq!(metadata[12], 1);
        assert_eq!(metadata[13], 4);
        assert_eq!(metadata[14], 1);
        assert_eq!(metadata[17], ((FRAMED_STUB_STACK_ALLOC / 8 - 1) << 4) | 2);
    }

    #[test]
    fn guest_section_protection_matches_pe_section_flags() {
        assert_eq!(
            guest_section_protect(IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ),
            PAGE_EXECUTE_READ
        );
        assert_eq!(
            guest_section_protect(IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE),
            PAGE_EXECUTE_READWRITE
        );
        assert_eq!(
            guest_section_protect(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE),
            PAGE_READWRITE
        );
        assert_eq!(guest_section_protect(IMAGE_SCN_MEM_READ), PAGE_READONLY);
        assert_eq!(guest_section_protect(0), PAGE_NOACCESS);
    }

    #[test]
    fn write_through_final_selects_non_writable_initial_protection() {
        let pe = Pe {
            image_base: 0,
            entry_rva: 0,
            size_of_image: 0,
            size_of_headers: 0,
            import: crate::pe::Dir { rva: 0, size: 0 },
            exception: crate::pe::Dir { rva: 0, size: 0 },
            reloc: crate::pe::Dir { rva: 0, size: 0 },
            tls: crate::pe::Dir { rva: 0, size: 0 },
            load_config: crate::pe::Dir { rva: 0, size: 0 },
            delay_import: crate::pe::Dir { rva: 0, size: 0 },
            export_dir: crate::pe::Dir { rva: 0, size: 0 },
            sections: vec![
                Section {
                    virtual_size: 0x1000,
                    virtual_address: 0x1000,
                    raw_size: 0x1000,
                    raw_ptr: 0,
                    characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
                },
                Section {
                    virtual_size: 0x1000,
                    virtual_address: 0x2000,
                    raw_size: 0x1000,
                    raw_ptr: 0,
                    characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
                },
            ],
        };
        assert_eq!(final_image_allocation_protection(&pe), PAGE_EXECUTE_READ);
    }

    #[test]
    fn module_backed_range_requires_complete_containment() {
        let module = GuestModuleInfo {
            name: "target.exe".into(),
            base: 0x1400_0000,
            size: 0x2000,
        };
        assert!(module_contains_range(&module, 0x1400_0100, 0x100));
        assert!(module_contains_range(&module, 0x1400_1FF0, 0x10));
        assert!(!module_contains_range(&module, 0x1400_1FF0, 0x11));
        assert!(!module_contains_range(&module, 0x13FF_FFF0, 0x20));
    }

    #[test]
    fn code_cave_finder_uses_generic_padding() {
        let mut bytes = vec![0x41; 128];
        bytes[23..23 + 64].fill(0xCC);
        assert_eq!(find_code_cave(&bytes, 32), Some(32));

        bytes[23..23 + 64].fill(0x90);
        assert_eq!(find_code_cave(&bytes, 32), Some(32));

        bytes[23..23 + 64].fill(0x00);
        assert_eq!(find_code_cave(&bytes, 32), Some(32));
    }

    #[test]
    fn guest_pattern_supports_wildcards() {
        let pattern = parse_hex_pattern("44 45 ?? 41", "guest.process_pattern").unwrap();
        assert_eq!(pattern.find_in(b"DECANT"), Some(0));
        assert_eq!(pattern.find_in(b"DEZANT"), Some(0));
        assert_eq!(pattern.find_in(b"DE"), None);
    }

    #[test]
    fn guest_mapper_policies_parse() {
        let config = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\npid = 1\npayload_path = \"payload.dll\"\n\
             dependency_policy = \"require-loaded\"\ntls = \"skip\"\nfinal_protections = \"rwx\"\nloader_metadata = \"reject-unsupported\"\ncall_stack = \"registered-unwind\"\npermission_transitions = \"write-through-final\"\nthread_starts = \"require-module-backed\"\nvad_spoof = \"vad-image-map\"\nresult_base = 8192\nresult_pattern = \"44 45\"\n",
        )
        .unwrap();
        let plan = GuestInjectionPlan::from_config(&config).unwrap();
        assert_eq!(plan.dependency_policy, GuestDependencyPolicy::RequireLoaded);
        assert_eq!(plan.tls, GuestTlsMode::Skip);
        assert_eq!(plan.final_protections, GuestFinalProtections::Rwx);
        assert_eq!(
            plan.loader_metadata,
            GuestLoaderMetadataPolicy::RejectUnsupported
        );
        assert_eq!(plan.call_stack, GuestCallStackPolicy::RegisteredUnwind);
        assert_eq!(
            plan.permission_transitions,
            GuestPermissionTransitions::WriteThroughFinal
        );
        assert_eq!(
            plan.thread_starts,
            GuestThreadStartPolicy::RequireModuleBacked
        );
        assert_eq!(plan.vad_spoof, GuestVadSpoof::VadImageMap);
        assert_eq!(plan.result_base, Some(8192));
        assert!(plan.result_pattern.is_some());
    }

    #[test]
    fn guest_final_protections_default_to_section() {
        let config = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\npid = 1\npayload_path = \"payload.dll\"\n",
        )
        .unwrap();
        let plan = GuestInjectionPlan::from_config(&config).unwrap();
        assert_eq!(plan.final_protections, GuestFinalProtections::Section);
    }

    #[test]
    fn guest_loader_metadata_best_effort_parses() {
        let config = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\npid = 1\npayload_path = \"payload.dll\"\n\
             loader_metadata = \"best-effort\"\n",
        )
        .unwrap();
        let plan = GuestInjectionPlan::from_config(&config).unwrap();
        assert_eq!(plan.loader_metadata, GuestLoaderMetadataPolicy::BestEffort);
        assert!(plan.loader_metadata.allows_unregistered_metadata());
        assert!(plan.loader_metadata.registers_public_metadata());
    }

    #[test]
    fn guest_package_selectors_are_parsed_but_not_implemented() {
        let config = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\nprocess = \"target.exe\"\npackage_family_name = \"pkg\"\npayload_path = \"payload.dll\"\n",
        )
        .unwrap();
        let err = GuestInjectionPlan::from_config(&config).unwrap_err();
        assert!(matches!(err, GuestInjectError::Config(_)));
    }

    #[test]
    fn guest_image_backing_defaults_to_private() {
        let config = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\npid = 1\npayload_path = \"payload.dll\"\n",
        )
        .unwrap();
        let plan = GuestInjectionPlan::from_config(&config).unwrap();
        assert_eq!(plan.image_backing, GuestImageBacking::Private);
    }

    #[test]
    fn guest_sec_image_parses_and_requires_section_protections() {
        let ok = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\npid = 1\npayload_path = \"payload.dll\"\n\
             image_backing = \"sec-image\"\nfinal_protections = \"section\"\n",
        )
        .unwrap();
        let plan = GuestInjectionPlan::from_config(&ok).unwrap();
        assert_eq!(plan.image_backing, GuestImageBacking::SecImage);

        let err = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\npid = 1\npayload_path = \"payload.dll\"\n\
             image_backing = \"sec-image\"\nfinal_protections = \"rwx\"\n",
        )
        .unwrap();
        match GuestInjectionPlan::from_config(&err).unwrap_err() {
            GuestInjectError::Config(msg) => assert!(
                msg.contains("sec-image") && msg.contains("section"),
                "unexpected config error: {msg}"
            ),
            other => panic!("expected config error, got {other:?}"),
        }

        let err = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\npid = 1\npayload_path = \"payload.dll\"\n\
             image_backing = \"sec-image\"\nfinal_protections = \"section\"\nallocation = \"existing-region\"\n",
        )
        .unwrap();
        match GuestInjectionPlan::from_config(&err).unwrap_err() {
            GuestInjectError::Config(msg) => assert!(
                msg.contains("sec-image") && msg.contains("virtual-alloc"),
                "unexpected config error: {msg}"
            ),
            other => panic!("expected config error, got {other:?}"),
        }

        let err = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\npid = 1\npayload_path = \"payload.dll\"\n\
             image_backing = \"sec-image\"\nfinal_protections = \"section\"\nvad_spoof = \"vad-image-map\"\n",
        )
        .unwrap();
        match GuestInjectionPlan::from_config(&err).unwrap_err() {
            GuestInjectError::Config(msg) => assert!(
                msg.contains("vad-image-map") && msg.contains("private"),
                "unexpected config error: {msg}"
            ),
            other => panic!("expected config error, got {other:?}"),
        }
    }

    #[test]
    fn guest_proc_trampoline_loads_args_from_param_block() {
        assert_eq!(GUEST_PROC_TRAMPOLINE.len(), 77);
        assert_eq!(GUEST_PROC_TRAMPOLINE[0], 0x55);
        assert_eq!(*GUEST_PROC_TRAMPOLINE.last().unwrap(), 0xC3);
        assert_eq!(
            GUEST_GET_PEB_TRAMPOLINE,
            &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0, 0, 0, 0xC3]
        );
        assert_eq!(GUEST_PARAM_BLOCK_SIZE, 0x58);
        assert!(STAGE_PARAM_OFFSET + GUEST_PARAM_BLOCK_SIZE as u64 <= STAGE_UNWIND_OFFSET);
    }

    #[test]
    fn remote_thread_thunk_calls_dllmain_with_three_args() {
        assert_eq!(&REMOTE_THREAD_DLLMAIN_THUNK[..4], &[0x53, 0x48, 0x83, 0xEC]);
        assert!(
            REMOTE_THREAD_DLLMAIN_THUNK
                .windows(2)
                .any(|w| w == [0xFF, 0xD0])
        );
        assert!(
            REMOTE_THREAD_DLLMAIN_THUNK
                .windows(3)
                .any(|w| w == [0x41, 0x89, 0x02])
        );
        assert!(
            REMOTE_THREAD_DLLMAIN_THUNK
                .windows(7)
                .any(|w| w == [0x41, 0xC7, 0x02, 0x01, 0, 0, 0])
        );
        assert_eq!(*REMOTE_THREAD_DLLMAIN_THUNK.last().unwrap(), 0xC3);
        assert!(REMOTE_THREAD_DLLMAIN_THUNK.len() < REMOTE_THREAD_PARAM_OFFSET as usize);
    }

    #[test]
    fn cfg_call_target_registration_requires_best_effort_load_config() {
        let config = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\npid = 1\npayload_path = \"payload.dll\"\n\
             loader_entries = \"synthesized\"\nloader_metadata = \"best-effort\"\n",
        )
        .unwrap();
        let plan = GuestInjectionPlan::from_config(&config).unwrap();
        let mut pe = Pe {
            image_base: 0,
            entry_rva: 0,
            size_of_image: 0,
            size_of_headers: 0,
            import: crate::pe::Dir { rva: 0, size: 0 },
            exception: crate::pe::Dir { rva: 0, size: 0 },
            reloc: crate::pe::Dir { rva: 0, size: 0 },
            tls: crate::pe::Dir { rva: 0, size: 0 },
            load_config: crate::pe::Dir { rva: 0, size: 0 },
            delay_import: crate::pe::Dir { rva: 0, size: 0 },
            export_dir: crate::pe::Dir { rva: 0, size: 0 },
            sections: Vec::new(),
        };

        assert!(!should_request_cfg_call_target(&plan, &pe));
        pe.load_config = crate::pe::Dir {
            rva: 0x40,
            size: 0x60,
        };
        assert!(should_request_cfg_call_target(&plan, &pe));

        let reject_config = DecantConfig::from_toml_str(
            "[injection]\ndomain = \"guest\"\nmethod = \"manual-map\"\n\
             [guest]\npid = 1\npayload_path = \"payload.dll\"\n\
             loader_entries = \"synthesized\"\nloader_metadata = \"reject-unsupported\"\n",
        )
        .unwrap();
        let reject_plan = GuestInjectionPlan::from_config(&reject_config).unwrap();
        assert!(!should_request_cfg_call_target(&reject_plan, &pe));
    }

    #[test]
    fn wide_roundtrip_preserves_ascii_paths() {
        let path = "C:\\Users\\lobby\\Temp\\decant_payload.dll";
        assert_eq!(decode_wide(&encode_wide(path)), path);
        let bytes = encode_wide(path);
        assert_eq!(bytes.len(), (path.len() + 1) * 2);
        assert_eq!(bytes[bytes.len() - 2], 0);
        assert_eq!(bytes[bytes.len() - 1], 0);
    }

    #[test]
    fn code_cave_finder_rejects_short_padding() {
        let mut bytes = vec![0x41; 128];
        bytes[16..31].fill(0xCC);
        assert_eq!(find_code_cave(&bytes, 16), None);
    }
}
