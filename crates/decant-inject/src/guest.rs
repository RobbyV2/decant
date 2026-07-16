use std::collections::{HashMap, HashSet};
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
const DEFAULT_IAT_STAGE_POOL_SLOTS: u32 = 1024;
const IAT_STAGE_POOL_MAGIC: [u8; 16] = *b"DECANT::IATPOOL3";
const IAT_STAGE_POOL_HEADER_SIZE: usize = 24;
const STAGE_RESULT_OFFSET: u64 = 0x20;
const STAGE_STUB_OFFSET: u64 = 0x100;
const STAGE_SCRATCH_OFFSET: u64 = 0x300;
const STAGE_UNWIND_OFFSET: u64 = 0x3E0;
const STAGE_SCRATCH_SIZE: usize = (STAGE_UNWIND_OFFSET - STAGE_SCRATCH_OFFSET) as usize;
const GUEST_PAGE_SIZE: usize = 0x1000;
// Out-of-band KVM writes cannot fault in a Windows demand-zero page. Keep a
// nonzero byte in a reserved region of every pool page so each stage slot is
// externally writable after the bootstrap completes.
const IAT_STAGE_POOL_SLOTS_PER_PAGE: u32 = (GUEST_PAGE_SIZE / STAGE_CAVE_SIZE) as u32 - 1;
const IAT_STAGE_POOL_CANARY_OFFSET: u64 = (GUEST_PAGE_SIZE - STAGE_CAVE_SIZE) as u64;
const IAT_STAGE_POOL_CANARY_VALUE: u8 = 0xA5;
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
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
const RESULT_RUNNING: u64 = 1;
const RESULT_STATE: u64 = 2;
const RESULT_INFLIGHT_OFFSET: u64 = 16;
const RESULT_BLOCK_SIZE: usize = 24;
const IAT_QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(1);
const IAT_QUIESCENCE_POLL_INTERVAL: Duration = Duration::from_millis(1);
const IAT_RESTORE_GRACE: Duration = Duration::from_millis(10);
const MAX_IAT_IMPORT_DESCRIPTORS: usize = 2048;
const MAX_IAT_IMPORTS_PER_MODULE: usize = 16384;
const MAX_IAT_HOOK_CANDIDATES: usize = 32768;
const OLD_PROTECT_RESULT_OFFSET: u64 = 12;
const MAX_EXPORT_FORWARD_DEPTH: usize = 8;
const EXPORT_HEADER_RETRIES: usize = 20;
const EXPORT_HEADER_RETRY_DELAY: Duration = Duration::from_millis(25);
const FRAMED_STUB_STACK_ALLOC: u8 = 0x68;
const FRAMED_SAVED_REG_OFFSET: u8 = 0x48;
const FRAMED_MAX_STACK_ARGS: usize = (FRAMED_SAVED_REG_OFFSET - 0x20) as usize / 8;
const SYSCALL_STUB_LEN: usize = 8;
const SYSCALL_STUB_PREFIX: [u8; 3] = [0x4C, 0x8B, 0xD1];
const SYSCALL_STUB_OPCODE: u8 = 0xB8;

static ACTIVE_GUEST_INJECTIONS: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();
static MANUAL_MODULE_REGISTRY: OnceLock<Mutex<HashMap<(u32, u64), ModuleRecord>>> = OnceLock::new();
static IAT_STAGE_POOLS: OnceLock<Mutex<HashMap<IatStagePoolKey, IatStagePool>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct IatStagePoolKey {
    pid: u32,
    iat_slot: u64,
    bootstrap_stub_addr: u64,
}

#[derive(Clone, Copy, Debug)]
struct IatStagePool {
    base: u64,
    slots: u32,
    next_slot: u32,
}

#[derive(Clone, Debug)]
struct ModuleRecord {
    base: u64,
    #[allow(dead_code)]
    size: u64,
    #[allow(dead_code)]
    refcount: u32,
    #[allow(dead_code)]
    dependencies: Vec<u64>,
    entry_point: u64,
    tls_callbacks: Vec<u64>,
    function_tables: Vec<(u64, u32)>,
    actctx_handle: Option<u64>,
    actctx_cookie: Option<u64>,
    tls_slot: Option<u32>,
    tls_template_bufs: Vec<u64>,
    tls_slot_bindings: Vec<TlsSlotBinding>,
    peb_loader_entry: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TlsSlotBinding {
    slot_addr: u64,
    value: u64,
}

fn update_module_record(pid: u32, base: u64, f: impl FnOnce(&mut ModuleRecord)) {
    if let Some(registry) = MANUAL_MODULE_REGISTRY.get() {
        if let Ok(mut reg) = registry.lock() {
            if let Some(record) = reg.get_mut(&(pid, base)) {
                f(record);
            }
        }
    }
}

fn guest_timeout_ms() -> u32 {
    5000
}

fn default_hook_module() -> String {
    DEFAULT_HOOK_MODULE.into()
}

fn default_hook_function() -> String {
    DEFAULT_HOOK_FUNCTION.into()
}

fn default_iat_stage_pool_slots() -> u32 {
    DEFAULT_IAT_STAGE_POOL_SLOTS
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
pub enum GuestDelayLoads {
    #[default]
    Resolve,
    Skip,
}

impl GuestDelayLoads {
    pub fn label(self) -> &'static str {
        match self {
            GuestDelayLoads::Resolve => "resolve",
            GuestDelayLoads::Skip => "skip",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestSxS {
    #[default]
    Skip,
    Probe,
}

impl GuestSxS {
    pub fn label(self) -> &'static str {
        match self {
            GuestSxS::Skip => "skip",
            GuestSxS::Probe => "probe",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestManualModuleRegistry {
    #[default]
    Off,
    Track,
}

impl GuestManualModuleRegistry {
    pub fn label(self) -> &'static str {
        match self {
            GuestManualModuleRegistry::Off => "off",
            GuestManualModuleRegistry::Track => "track",
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
    #[serde(default = "default_iat_stage_pool_slots")]
    pub iat_stage_pool_slots: u32,
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
    #[serde(default)]
    pub delay_loads: GuestDelayLoads,
    #[serde(default)]
    pub sxs: GuestSxS,
    #[serde(default)]
    pub force_remap: bool,
    #[serde(default)]
    pub high_memory: bool,
    #[serde(default)]
    pub is_dependency: bool,
    #[serde(default)]
    pub manual_module_registry: GuestManualModuleRegistry,
    #[serde(default)]
    pub dll_main_reserved_arg: Option<Vec<u8>>,
    #[serde(default)]
    pub map_callback_path: Option<PathBuf>,
    #[serde(default)]
    pub clr: Option<GuestClrConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct GuestClrConfig {
    pub assembly_path: PathBuf,
    pub class_name: String,
    pub method_name: String,
    #[serde(default)]
    pub argument: Option<String>,
    #[serde(default)]
    pub net_version: Option<String>,
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
    pub delay_loads: GuestDelayLoads,
    pub sxs: GuestSxS,
    pub force_remap: bool,
    pub high_memory: bool,
    pub is_dependency: bool,
    pub manual_module_registry: GuestManualModuleRegistry,
    pub dll_main_reserved_arg: Option<Vec<u8>>,
    pub map_callback_path: Option<PathBuf>,
    pub target_module: Option<String>,
    pub stage_base: Option<u64>,
    pub stage_pattern: Option<GuestBytePattern>,
    pub result_base: Option<u64>,
    pub result_pattern: Option<GuestBytePattern>,
    pub iat_stage_pool_slots: u32,
    pub hook_module: String,
    pub hook_function: String,
    pub execution: GuestExecutionConfig,
    pub timeout_ms: u32,
    pub clr: Option<GuestClrConfig>,
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
            delay_loads: config.guest.delay_loads,
            sxs: config.guest.sxs,
            force_remap: config.guest.force_remap,
            high_memory: config.guest.high_memory,
            is_dependency: config.guest.is_dependency,
            manual_module_registry: config.guest.manual_module_registry,
            dll_main_reserved_arg: config.guest.dll_main_reserved_arg.clone(),
            map_callback_path: config.guest.map_callback_path.clone(),
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
            iat_stage_pool_slots: match config.guest.iat_stage_pool_slots {
                0 => default_iat_stage_pool_slots(),
                slots => slots,
            },
            hook_module: config.guest.hook_module.clone(),
            hook_function: config.guest.hook_function.clone(),
            execution: config.guest.execution.clone(),
            timeout_ms: config.injection.timeout_ms,
            clr: config.guest.clr.clone(),
        })
    }
}

const S_OK: i32 = 0;

#[derive(Clone, Copy, Debug)]
#[allow(clippy::upper_case_acronyms)]
struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl GUID {
    fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&self.data1.to_le_bytes());
        out[4..6].copy_from_slice(&self.data2.to_le_bytes());
        out[6..8].copy_from_slice(&self.data3.to_le_bytes());
        out[8..16].copy_from_slice(&self.data4);
        out
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
    /// The backend can prove no target thread can execute a previously fetched
    /// IAT target while staging bytes are restored.
    ///
    /// This requires a real target-thread barrier. Memory-only backends must
    /// leave it false and retain a completed pass-through stub instead.
    pub iat_hook_stage_restore: bool,
    /// Executes guest stubs without waiting for an imported target function.
    ///
    /// A backend advertising this must override the IAT-named execution helpers
    /// below and treat `GuestIatHook::stub_addr` / `result_addr` as its staging
    /// contract. This keeps the mapper transport-agnostic while retaining the
    /// existing IAT-hook fallback for memory-only backends.
    pub independent_execution: bool,
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
    pub thread_enumeration: bool,
    pub teb_read: bool,
    pub thread_suspend_resume: bool,
    pub thread_terminate: bool,
    pub hardware_breakpoints: bool,
    pub module_unload: bool,
    pub module_unlink_full: bool,
    pub inline_hooks: bool,
    pub raw_syscalls: bool,
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
            iat_hook_stage_restore: false,
            independent_execution: false,
            deterministic_execution: false,
            thread_context: true,
            queue_apc: true,
            create_thread: true,
            wait_for_result: true,
            forwarded_exports: true,
            ordinal_imports: true,
            delay_imports: true,
            static_tls: true,
            exception_registration: true,
            loader_reference: true,
            vad_spoof: true,
            thread_enumeration: true,
            teb_read: true,
            thread_suspend_resume: true,
            thread_terminate: true,
            hardware_breakpoints: true,
            module_unload: true,
            module_unlink_full: true,
            inline_hooks: true,
            raw_syscalls: true,
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
            (
                self.iat_hook_execution || self.independent_execution,
                "execution-bootstrap",
            ),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestThreadState {
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    Other(u8),
}

impl From<u8> for GuestThreadState {
    fn from(value: u8) -> Self {
        match value {
            0 => GuestThreadState::Initialized,
            1 => GuestThreadState::Ready,
            2 => GuestThreadState::Running,
            3 => GuestThreadState::Standby,
            4 => GuestThreadState::Terminated,
            5 => GuestThreadState::Waiting,
            6 => GuestThreadState::Transition,
            7 => GuestThreadState::DeferredReady,
            other => GuestThreadState::Other(other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestThreadInfo {
    pub tid: u32,
    pub teb: u64,
    pub start_address: u64,
    pub state: GuestThreadState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestTeb {
    pub base: u64,
    pub exception_list: u64,
    pub stack_base: u64,
    pub stack_limit: u64,
    pub arbitrary_user_pointer: u64,
    pub tls_array: u64,
    pub last_error_value: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestHwbpType {
    Execute,
    Access,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestHwbpLength {
    One,
    Two,
    Four,
    Eight,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestHwbp {
    pub addr: u64,
    pub kind: GuestHwbpType,
    pub length: GuestHwbpLength,
}

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestThreadContext {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mx_csr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub eflags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
}

impl GuestThreadContext {
    pub const CONTEXT_CONTROL: u32 = 0x0010_0001;
    pub const CONTEXT_INTEGER: u32 = 0x0010_0002;
    pub const CONTEXT_FULL: u32 = Self::CONTEXT_CONTROL | Self::CONTEXT_INTEGER;

    pub const fn zeroed() -> Self {
        Self {
            p1_home: 0,
            p2_home: 0,
            p3_home: 0,
            p4_home: 0,
            p5_home: 0,
            p6_home: 0,
            context_flags: 0,
            mx_csr: 0,
            seg_cs: 0,
            seg_ds: 0,
            seg_es: 0,
            seg_fs: 0,
            seg_gs: 0,
            seg_ss: 0,
            eflags: 0,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rsp: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
        }
    }
}

pub struct GuestInjectionRequest<'a> {
    pub plan: &'a GuestInjectionPlan,
    pub payload_path: &'a Path,
    pub payload_image: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MapHandle(pub u64);

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

fn independent_execution_override_required(operation: &'static str) -> GuestInjectError {
    GuestInjectError::Unsupported {
        operation: "independent guest execution",
        reason: format!(
            "backend advertised independent_execution but did not override {operation}; refusing to fall back to an IAT hook"
        ),
    }
}

fn find_rx_code_cave(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    size: usize,
) -> Result<u64, GuestInjectError> {
    for region in backend.memory_map(pid)? {
        if !region.readable || !region.executable || region.size < size as u64 {
            continue;
        }
        let mut pos = 0u64;
        while pos < region.size {
            let len = (region.size - pos).min(0x10000 + size as u64) as usize;
            let addr = region.base + pos;
            if let Ok(bytes) = backend.read(pid, addr, len) {
                if let Some(off) = find_code_cave(&bytes, size) {
                    let cave = addr + off as u64;
                    tracing::debug!(pid, cave = format_args!("{cave:#x}"), "found RX code cave");
                    return Ok(cave);
                }
            }
            pos += 0x10000;
        }
    }
    Err(GuestInjectError::Backend(
        "no RX code cave found in process memory".into(),
    ))
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
        args: &[u64],
        timeout_ms: u32,
    ) -> Result<u64, GuestInjectError> {
        if self.capabilities().independent_execution {
            return Err(independent_execution_override_required(
                "guest function call",
            ));
        }
        let slot = reserve_iat_stage_slot(pid, hook)?;
        memory_iat_call(self, pid, &slot, function, args, timeout_ms)
    }

    fn touch_iat_hook(
        &self,
        pid: u32,
        hook: &GuestIatHook,
        addr: u64,
        len: usize,
        timeout_ms: u32,
    ) -> Result<(), GuestInjectError> {
        if self.capabilities().independent_execution {
            return Err(independent_execution_override_required("guest page touch"));
        }
        let slot = reserve_iat_stage_slot(pid, hook)?;
        memory_iat_touch(self, pid, &slot, addr, len, timeout_ms)
    }

    fn read_touch_iat_hook(
        &self,
        pid: u32,
        hook: &GuestIatHook,
        addr: u64,
        len: usize,
        timeout_ms: u32,
    ) -> Result<(), GuestInjectError> {
        if self.capabilities().independent_execution {
            return Err(independent_execution_override_required(
                "guest read page touch",
            ));
        }
        let slot = reserve_iat_stage_slot(pid, hook)?;
        memory_iat_read_touch(self, pid, &slot, addr, len, timeout_ms)
    }

    fn preserve_touch_iat_hook(
        &self,
        pid: u32,
        hook: &GuestIatHook,
        addr: u64,
        len: usize,
        timeout_ms: u32,
    ) -> Result<(), GuestInjectError> {
        if self.capabilities().independent_execution {
            return Err(independent_execution_override_required(
                "guest preserve page touch",
            ));
        }
        let slot = reserve_iat_stage_slot(pid, hook)?;
        memory_iat_preserve_touch(self, pid, &slot, addr, len, timeout_ms)
    }

    fn spoof_vad_type(&self, _pid: u32, _base: u64, _size: u64) -> Result<(), GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "VAD type spoofing",
            reason: "this backend does not expose kernel memory access".into(),
        })
    }

    fn configure_va_protection(
        &self,
        _pid: u32,
        _base: u64,
        _size: u64,
        _protection: u32,
    ) -> Result<(), GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "VAD protection configuration",
            reason: "this backend does not expose kernel memory access".into(),
        })
    }

    fn patch_entry_point(
        &self,
        _pid: u32,
        _module_base: u64,
        _new_entry: u64,
    ) -> Result<(), GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "PE entry point patching",
            reason: "this backend does not expose write access to remote process memory".into(),
        })
    }

    fn map_remote_region(
        &self,
        _pid: u32,
        _base: u64,
        _size: u64,
    ) -> Result<MapHandle, GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "remote region mapping",
            reason: "this backend does not support local mapping of remote regions".into(),
        })
    }

    fn translate_address(
        &self,
        _map: MapHandle,
        _remote_addr: u64,
    ) -> Result<usize, GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "address translation",
            reason: "this backend does not support local mapping of remote regions".into(),
        })
    }

    fn unmap_remote_region(&self, _map: MapHandle) -> Result<(), GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "remote region unmapping",
            reason: "this backend does not support local mapping of remote regions".into(),
        })
    }

    fn resolve_loader_symbol(
        &self,
        _pid: u32,
        _symbol_name: &str,
    ) -> Result<u64, GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "loader symbol resolution",
            reason: "this backend does not scan ntdll for loader-internal symbols".into(),
        })
    }

    fn list_threads(&self, _pid: u32) -> Result<Vec<GuestThreadInfo>, GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "thread enumeration",
            reason: "this backend does not walk EPROCESS.ThreadListHead".into(),
        })
    }

    fn read_teb(&self, _pid: u32, _tid: u32) -> Result<GuestTeb, GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "TEB read",
            reason: "this backend does not expose per-thread TEB addresses".into(),
        })
    }

    fn suspend_thread(
        &self,
        _pid: u32,
        _tid: u32,
        _hook: &GuestIatHook,
        _timeout_ms: u32,
    ) -> Result<(), GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "thread suspend",
            reason: "this backend cannot call SuspendThread".into(),
        })
    }

    fn resume_thread(
        &self,
        _pid: u32,
        _tid: u32,
        _hook: &GuestIatHook,
        _timeout_ms: u32,
    ) -> Result<(), GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "thread resume",
            reason: "this backend cannot call ResumeThread".into(),
        })
    }

    fn get_thread_context(
        &self,
        _pid: u32,
        _tid: u32,
        _hook: &GuestIatHook,
        _timeout_ms: u32,
    ) -> Result<GuestThreadContext, GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "thread context get",
            reason: "this backend cannot call GetThreadContext".into(),
        })
    }

    fn set_thread_context(
        &self,
        _pid: u32,
        _tid: u32,
        _ctx: &GuestThreadContext,
        _hook: &GuestIatHook,
        _timeout_ms: u32,
    ) -> Result<(), GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "thread context set",
            reason: "this backend cannot call SetThreadContext".into(),
        })
    }

    fn terminate_thread(
        &self,
        _pid: u32,
        _tid: u32,
        _exit_code: u32,
        _hook: &GuestIatHook,
        _timeout_ms: u32,
    ) -> Result<(), GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "thread terminate",
            reason: "this backend cannot call TerminateThread".into(),
        })
    }

    fn add_hwbp(
        &self,
        _pid: u32,
        _tid: u32,
        _bp: GuestHwbp,
        _hook: &GuestIatHook,
        _timeout_ms: u32,
    ) -> Result<u8, GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "hardware breakpoint install",
            reason: "this backend cannot call SetThreadContext for DR registers".into(),
        })
    }

    fn remove_hwbp(
        &self,
        _pid: u32,
        _tid: u32,
        _index: u8,
        _hook: &GuestIatHook,
        _timeout_ms: u32,
    ) -> Result<(), GuestInjectError> {
        Err(GuestInjectError::Unsupported {
            operation: "hardware breakpoint remove",
            reason: "this backend cannot call SetThreadContext for DR registers".into(),
        })
    }

    fn validate_module(&self, pid: u32, base: u64) -> Result<bool, GuestInjectError> {
        let header = self.read(pid, base, 0x40)?;
        if header.len() < 0x40 || u16::from_le_bytes([header[0], header[1]]) != 0x5A4D {
            return Ok(false);
        }
        let nt_off =
            u32::from_le_bytes([header[0x3C], header[0x3D], header[0x3E], header[0x3F]]) as usize;
        if nt_off == 0 || nt_off > 0x400 {
            return Ok(false);
        }
        let sig = self.read(pid, base + nt_off as u64, 4)?;
        if sig.len() < 4 {
            return Ok(false);
        }
        Ok(u32::from_le_bytes([sig[0], sig[1], sig[2], sig[3]]) == 0x0000_4550)
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
    /// Whether this stub may restore `iat_slot` from guest mode.
    ///
    /// This requires both a writable page and a backend execution barrier.
    /// Memory-only backends restore the slot from the host transaction instead,
    /// because they cannot synchronize a guest write with an external patch.
    pub iat_slot_guest_writable: bool,
    pub call_stack: GuestCallStackPolicy,
    pub spoofed_return: Option<GuestSpoofedReturn>,
}

fn iat_stage_pool_key(pid: u32, hook: &GuestIatHook) -> IatStagePoolKey {
    IatStagePoolKey {
        pid,
        iat_slot: hook.iat_slot,
        bootstrap_stub_addr: hook.stub_addr,
    }
}

fn activate_iat_stage_pool(
    pid: u32,
    hook: &GuestIatHook,
    base: u64,
    slots: u32,
) -> Result<(), GuestInjectError> {
    if slots == 0 {
        return Err(GuestInjectError::Config(
            "guest.iat_stage_pool_slots must be greater than zero".into(),
        ));
    }
    let key = iat_stage_pool_key(pid, hook);
    let pools = IAT_STAGE_POOLS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut pools = pools.lock().map_err(|_| {
        GuestInjectError::Backend("guest IAT stage-pool registry lock was poisoned".into())
    })?;
    if pools
        .insert(
            key,
            IatStagePool {
                base,
                slots,
                next_slot: 0,
            },
        )
        .is_some()
    {
        return Err(GuestInjectError::Backend(format!(
            "guest IAT stage pool already exists for pid {pid} and IAT slot {:#x}",
            hook.iat_slot
        )));
    }
    Ok(())
}

fn iat_stage_pool_header(slots: u32) -> [u8; IAT_STAGE_POOL_HEADER_SIZE] {
    let mut header = [0u8; IAT_STAGE_POOL_HEADER_SIZE];
    header[..IAT_STAGE_POOL_MAGIC.len()].copy_from_slice(&IAT_STAGE_POOL_MAGIC);
    header[16..24].copy_from_slice(&u64::from(slots).to_le_bytes());
    header
}

fn iat_stage_pool_page_count(slots: u32) -> Result<u64, GuestInjectError> {
    if slots == 0 {
        return Err(GuestInjectError::Config(
            "guest.iat_stage_pool_slots must be greater than zero".into(),
        ));
    }
    Ok(u64::from(slots).div_ceil(u64::from(IAT_STAGE_POOL_SLOTS_PER_PAGE)))
}

fn iat_stage_pool_size(slots: u32) -> Result<u64, GuestInjectError> {
    iat_stage_pool_page_count(slots)?
        .checked_mul(GUEST_PAGE_SIZE as u64)
        .ok_or_else(|| GuestInjectError::Config("guest IAT stage-pool size overflows".into()))
}

fn iat_stage_pool_slot_offset(slot: u32) -> Result<u64, GuestInjectError> {
    let page = u64::from(slot / IAT_STAGE_POOL_SLOTS_PER_PAGE);
    let slot_in_page = u64::from(slot % IAT_STAGE_POOL_SLOTS_PER_PAGE);
    page.checked_mul(GUEST_PAGE_SIZE as u64)
        .and_then(|offset| {
            slot_in_page
                .checked_mul(STAGE_CAVE_SIZE as u64)
                .and_then(|slot_offset| offset.checked_add(slot_offset))
        })
        .ok_or_else(|| {
            GuestInjectError::Backend("guest IAT stage-pool slot offset overflows".into())
        })
}

fn recover_iat_stage_pool(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
) -> Result<Option<u64>, GuestInjectError> {
    let key = iat_stage_pool_key(pid, hook);
    if let Some(pools) = IAT_STAGE_POOLS.get() {
        let pool = pools
            .lock()
            .map_err(|_| {
                GuestInjectError::Backend("guest IAT stage-pool registry lock was poisoned".into())
            })?
            .get(&key)
            .copied();
        if let Some(pool) = pool {
            let header = backend.read(pid, pool.base, IAT_STAGE_POOL_HEADER_SIZE)?;
            if header == iat_stage_pool_header(pool.slots) {
                return Ok(Some(pool.base));
            }
            let mut pools = pools.lock().map_err(|_| {
                GuestInjectError::Backend("guest IAT stage-pool registry lock was poisoned".into())
            })?;
            pools.remove(&key);
        }
    }

    let pattern = GuestBytePattern {
        bytes: IAT_STAGE_POOL_MAGIC.iter().copied().map(Some).collect(),
    };
    let Some(base) = find_writable_pattern(backend, pid, &pattern)? else {
        return Ok(None);
    };
    let header = backend.read(pid, base, IAT_STAGE_POOL_HEADER_SIZE)?;
    let slots = u64::from_le_bytes(header[16..24].try_into().unwrap());
    let slots = u32::try_from(slots).map_err(|_| {
        GuestInjectError::Backend("guest IAT stage-pool header has an invalid slot count".into())
    })?;
    if slots == 0 || header != iat_stage_pool_header(slots) {
        return Err(GuestInjectError::Backend(
            "guest IAT stage-pool header is invalid".into(),
        ));
    }
    let mut next_slot = 0u32;
    while next_slot < slots {
        let offset = iat_stage_pool_slot_offset(next_slot)?
            .checked_add(STAGE_RESULT_OFFSET)
            .ok_or_else(|| {
                GuestInjectError::Backend("guest IAT stage-pool result offset overflows".into())
            })?;
        let state = backend.read(pid, base + offset, 8)?;
        if state == [0; 8] {
            break;
        }
        next_slot += 1;
    }
    activate_iat_stage_pool(pid, hook, base, slots)?;
    let pools = IAT_STAGE_POOLS
        .get()
        .expect("stage pool registry initialized");
    let mut pools = pools.lock().map_err(|_| {
        GuestInjectError::Backend("guest IAT stage-pool registry lock was poisoned".into())
    })?;
    let pool = pools
        .get_mut(&key)
        .expect("stage pool registration inserted the requested key");
    pool.next_slot = next_slot;
    tracing::info!(
        pid,
        base = format_args!("{base:#x}"),
        slots,
        next_slot,
        "recovered persistent guest IAT stage pool"
    );
    Ok(Some(base))
}

fn ensure_iat_stage_pool(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    bootstrap_hook: &GuestIatHook,
    virtual_alloc: u64,
    slots: u32,
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    if let Some(base) = recover_iat_stage_pool(backend, pid, bootstrap_hook)? {
        return Ok(base);
    }
    let base = allocate_iat_stage_pool(
        backend,
        pid,
        bootstrap_hook,
        virtual_alloc,
        slots,
        timeout_ms,
    )?;
    write_verified(
        backend,
        pid,
        base,
        &iat_stage_pool_header(slots),
        "guest IAT stage-pool header",
    )?;
    activate_iat_stage_pool(pid, bootstrap_hook, base, slots)?;
    Ok(base)
}

fn reserve_iat_stage_slot(pid: u32, hook: &GuestIatHook) -> Result<GuestIatHook, GuestInjectError> {
    let key = iat_stage_pool_key(pid, hook);
    let Some(pools) = IAT_STAGE_POOLS.get() else {
        return Ok(*hook);
    };
    let mut pools = pools.lock().map_err(|_| {
        GuestInjectError::Backend("guest IAT stage-pool registry lock was poisoned".into())
    })?;
    let Some(pool) = pools.get_mut(&key) else {
        return Ok(*hook);
    };
    if pool.next_slot >= pool.slots {
        return Err(GuestInjectError::Unsupported {
            operation: "guest IAT-hook execution",
            reason: format!(
                "guest IAT stage pool exhausted after {} one-shot calls; increase guest.iat_stage_pool_slots",
                pool.slots
            ),
        });
    }
    let slot_offset = iat_stage_pool_slot_offset(pool.next_slot)?;
    pool.next_slot += 1;
    let slot_base = pool.base.checked_add(slot_offset).ok_or_else(|| {
        GuestInjectError::Backend("guest IAT stage-pool slot address overflows".into())
    })?;
    let mut slot_hook = *hook;
    slot_hook.stub_addr = slot_base.checked_add(STAGE_STUB_OFFSET).ok_or_else(|| {
        GuestInjectError::Backend("guest IAT stage-pool stub address overflows".into())
    })?;
    slot_hook.result_addr = slot_base.checked_add(STAGE_RESULT_OFFSET).ok_or_else(|| {
        GuestInjectError::Backend("guest IAT stage-pool result address overflows".into())
    })?;
    Ok(slot_hook)
}

fn iat_stage_pool_slot_count(
    pid: u32,
    hook: &GuestIatHook,
) -> Result<Option<u32>, GuestInjectError> {
    let Some(pools) = IAT_STAGE_POOLS.get() else {
        return Ok(None);
    };
    let pools = pools.lock().map_err(|_| {
        GuestInjectError::Backend("guest IAT stage-pool registry lock was poisoned".into())
    })?;
    Ok(pools
        .get(&iat_stage_pool_key(pid, hook))
        .map(|pool| pool.slots))
}

/// One import-address-table entry that can be used as an execution trigger.
///
/// The entry is reported exactly as it appears in the importing module. API-set
/// names are intentionally not normalized: they must match the IAT descriptor
/// when used for a subsequent liveness probe or injection plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestIatHookCandidate {
    pub source_module: String,
    pub import_module: String,
    pub symbol: String,
    pub iat_slot: u64,
    pub original_target: u64,
    pub priority: u8,
}

/// Result of a bounded IAT liveness probe.
///
/// The probe uses the normal guest call stub to invoke GetCurrentThreadId when
/// the selected import fires, then tail-jumps to the original import target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestIatHookProbe {
    pub candidate: GuestIatHookCandidate,
    pub observed: bool,
    pub servicing_tid: Option<u32>,
    pub timeout_ms: u32,
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
            let injection_lock = GuestInjectionLock::acquire(process.pid)?;

            match req.plan.execution.method {
                GuestExecutionMethod::IatHook
                | GuestExecutionMethod::RemoteThread
                | GuestExecutionMethod::ThreadHijack
                | GuestExecutionMethod::Apc => {}
                GuestExecutionMethod::ExternalAgent | GuestExecutionMethod::None => {
                    return Err(GuestInjectError::Unsupported {
                        operation: "guest injection",
                        reason: "external-agent and none execution methods are not implemented"
                            .into(),
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

            let hook = select_execution_hook(
                backend,
                process.pid,
                req.plan,
                stage,
                result_addr,
                capabilities.independent_execution,
                capabilities.iat_hook_stage_restore,
            )?;
            let mut thread_start_notes = if capabilities.independent_execution {
                vec![
                    "execution bootstrap: backend executes guest stubs independently of target IAT call cadence"
                        .into(),
                ]
            } else {
                validate_guest_thread_start_policy(backend, process.pid, req.plan, stage, &hook)?
            };

            let virtual_alloc =
                resolve_import_symbol(backend, process.pid, "kernel32.dll", "VirtualAlloc")?;
            tracing::info!(
                pid = process.pid,
                virtual_alloc = format_args!("{virtual_alloc:#x}"),
                "guest allocator resolved"
            );
            let iat_stage_pool_base = if capabilities.independent_execution {
                None
            } else {
                Some(ensure_iat_stage_pool(
                    backend,
                    process.pid,
                    &hook,
                    virtual_alloc,
                    req.plan.iat_stage_pool_slots,
                    req.plan.execution.timeout_ms,
                )?)
            };
            let mut call_stack_notes = Vec::new();
            if req.plan.call_stack == GuestCallStackPolicy::RegisteredUnwind {
                register_guest_stub_unwind(
                    backend,
                    process.pid,
                    &hook,
                    iat_stage_pool_base.unwrap_or(stage),
                    req.plan.execution.timeout_ms,
                )?;
                call_stack_notes
                    .push("call stack: registered unwind metadata for IAT-hook stub".to_string());
            }
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
                subsystem = pe.subsystem,
                dll_characteristics = format_args!("{:#06x}", pe.dll_characteristics),
                characteristics = format_args!("{:#010x}", pe.characteristics),
                is_dll = pe.is_dll(),
                is_exe = pe.is_exe(),
                is_pure_il = pe.is_pure_il(),
                manifest_id = ?pe.manifest_id(req.payload_image).ok().flatten(),
                "payload PE parsed"
            );

            if pe.is_pure_il() {
                let clr = req.plan.clr.as_ref().ok_or_else(|| GuestInjectError::Config(
                    "payload is a pure-IL .NET assembly; guest.clr.assembly_path, guest.clr.class_name, and guest.clr.method_name are required".into()
                ))?;
                let virtual_alloc =
                    resolve_import_symbol(backend, process.pid, "kernel32.dll", "VirtualAlloc")?;
                let virtual_free =
                    resolve_import_symbol(backend, process.pid, "kernel32.dll", "VirtualFree")?;
                let alloc_wide = |s: &str| -> Result<u64, GuestInjectError> {
                    let mut wide: Vec<u16> = s.encode_utf16().collect();
                    wide.push(0);
                    let bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_le_bytes()).collect();
                    let buf = allocate_helper_buffer(
                        backend,
                        process.pid,
                        &hook,
                        virtual_alloc,
                        bytes.len(),
                        req.plan.execution.timeout_ms,
                    )?;
                    backend.write(process.pid, buf, &bytes)?;
                    Ok(buf)
                };
                let mut remote_strings = Vec::with_capacity(4);
                let hosted_result = (|| -> Result<u32, GuestInjectError> {
                    let assembly_path_remote = alloc_wide(&clr.assembly_path.to_string_lossy())?;
                    remote_strings.push(assembly_path_remote);
                    let class_name_remote = alloc_wide(&clr.class_name)?;
                    remote_strings.push(class_name_remote);
                    let method_name_remote = alloc_wide(&clr.method_name)?;
                    remote_strings.push(method_name_remote);
                    let argument_remote = alloc_wide(clr.argument.as_deref().unwrap_or(""))?;
                    remote_strings.push(argument_remote);
                    let net_version = clr.net_version.as_deref().unwrap_or("v4.0.30319");
                    guest_inject_pure_il(
                        backend,
                        process.pid,
                        &hook,
                        stage,
                        net_version,
                        assembly_path_remote,
                        class_name_remote,
                        method_name_remote,
                        argument_remote,
                        req.plan.execution.timeout_ms,
                    )
                })();
                for remote in remote_strings {
                    best_effort_virtual_free(
                        backend,
                        process.pid,
                        &hook,
                        virtual_free,
                        remote,
                        req.plan.execution.timeout_ms,
                    );
                }
                let exit_code = hosted_result?;
                return Ok(GuestLoadInfo {
                    method: self.name().to_string(),
                    pid: process.pid,
                    remote_base: None,
                    notes: vec![format!(
                        "CLR hosted .NET assembly executed with return value {exit_code}"
                    )],
                });
            }

            if !req.plan.force_remap && !req.plan.is_dependency {
                if let Some(payload_name) = payload_module_name(req) {
                    if let Some(existing) = find_module_ci(backend, process.pid, &payload_name)
                        .ok()
                        .into_iter()
                        .next()
                    {
                        tracing::info!(
                            pid = process.pid,
                            module = %payload_name,
                            existing_base = format_args!("{:#x}", existing.base),
                            "payload module already loaded in target; use force_remap = true to remap"
                        );
                        return Err(GuestInjectError::Image(format!(
                            "module {payload_name} already loaded at {:#x}; set force_remap = true to remap",
                            existing.base
                        )));
                    }
                }
            }

            if req.plan.is_dependency {
                tracing::info!(
                    pid = process.pid,
                    "is_dependency = true; module mapped as a dependency (skips already-loaded check, no DllMain call in some paths)"
                );
            }

            if req.plan.sxs == GuestSxS::Probe {
                tracing::info!(
                    pid = process.pid,
                    "sxs = probe; activation context will be created from module resources before DllMain"
                );
            }

            if let Some(ref cb) = req.plan.map_callback_path {
                tracing::info!(
                    pid = process.pid,
                    callback = %cb.display(),
                    "map_callback_path configured; pre-mapping callback stage"
                );
            }

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
                                req.plan.high_memory,
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
            let mut loaded_dependencies = Vec::new();
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
                            &mut loaded_dependencies,
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
                            &mut loaded_dependencies,
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
            match req.plan.delay_loads {
                GuestDelayLoads::Resolve => {
                    pe.resolve_delay_imports(&mut image, &mut resolve_payload_import)?;
                    tracing::info!("payload delay imports resolved");
                }
                GuestDelayLoads::Skip => {
                    tracing::info!(pid = process.pid, "delay imports skipped per config");
                }
            }
            let has_static_tls = pe.has_static_tls(&image)?;
            let mut tls_slot_index: Option<u32> = None;
            let mut tls_template_bufs: Vec<u64> = Vec::new();
            let mut tls_slot_bindings: Vec<TlsSlotBinding> = Vec::new();
            let mut dllmain_tls: Option<DllMainThreadTls> = None;
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
                        &[0, 0, 0, 0],
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
                                &[0, template.len() as u64, MEM_COMMIT_RESERVE, PAGE_READWRITE],
                                req.plan.execution.timeout_ms,
                            )?;
                            if template_buf != 0 {
                                tls_template_bufs.push(template_buf);
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
                                    &[slot as u64, template_buf, 0, 0],
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
                                    let dllmain_template_buf = allocate_tls_template_copy(
                                        backend,
                                        process.pid,
                                        &hook,
                                        virtual_alloc,
                                        &template,
                                        req.plan.execution.timeout_ms,
                                        "DllMain-thread TLS template copy",
                                    )?;
                                    tls_template_bufs.push(dllmain_template_buf);
                                    dllmain_tls = Some(DllMainThreadTls {
                                        tls_set_value,
                                        slot,
                                        value: dllmain_template_buf,
                                    });
                                    match backend.list_threads(process.pid) {
                                        Ok(all_threads) => {
                                            let mut propagated = 0u32;
                                            for t in &all_threads {
                                                if t.state == GuestThreadState::Terminated
                                                    || t.teb == 0
                                                {
                                                    continue;
                                                }
                                                if slot >= 64 {
                                                    tracing::warn!(
                                                        pid = process.pid,
                                                        tid = t.tid,
                                                        slot,
                                                        "skipping direct TLS propagation for expansion TLS slot"
                                                    );
                                                    continue;
                                                }
                                                let thread_template_buf =
                                                    match allocate_tls_template_copy(
                                                        backend,
                                                        process.pid,
                                                        &hook,
                                                        virtual_alloc,
                                                        &template,
                                                        req.plan.execution.timeout_ms,
                                                        "per-thread TLS template copy",
                                                    ) {
                                                        Ok(remote) => remote,
                                                        Err(e) => {
                                                            tracing::warn!(
                                                                pid = process.pid,
                                                                tid = t.tid,
                                                                error = %e,
                                                                "failed to allocate per-thread TLS template"
                                                            );
                                                            continue;
                                                        }
                                                    };
                                                let slot_addr = t.teb + 0x1480 + (slot as u64) * 8;
                                                match backend.write(
                                                    process.pid,
                                                    slot_addr,
                                                    &thread_template_buf.to_le_bytes(),
                                                ) {
                                                    Ok(()) => {
                                                        tls_template_bufs.push(thread_template_buf);
                                                        tls_slot_bindings.push(TlsSlotBinding {
                                                            slot_addr,
                                                            value: thread_template_buf,
                                                        });
                                                        propagated += 1;
                                                    }
                                                    Err(e) => {
                                                        if let Ok(virtual_free) =
                                                            resolve_import_symbol(
                                                                backend,
                                                                process.pid,
                                                                "kernel32.dll",
                                                                "VirtualFree",
                                                            )
                                                        {
                                                            best_effort_virtual_free(
                                                                backend,
                                                                process.pid,
                                                                &hook,
                                                                virtual_free,
                                                                thread_template_buf,
                                                                req.plan.execution.timeout_ms,
                                                            );
                                                        }
                                                        tracing::warn!(
                                                            pid = process.pid,
                                                            tid = t.tid,
                                                            teb = format_args!("{:#x}", t.teb),
                                                            error = %e,
                                                            "failed to propagate TLS slot to thread"
                                                        );
                                                    }
                                                }
                                            }
                                            tracing::info!(
                                                pid = process.pid,
                                                slot,
                                                propagated,
                                                total_threads = all_threads.len(),
                                                "static TLS slot propagated to all non-terminated threads via direct TEB write"
                                            );
                                        }
                                        Err(e) => tracing::warn!(
                                            pid = process.pid,
                                            error = %e,
                                            "failed to enumerate threads for TLS propagation"
                                        ),
                                    }
                                    if req.plan.execution.method
                                        == GuestExecutionMethod::RemoteThread
                                    {
                                        tracing::info!(
                                            pid = process.pid,
                                            slot,
                                            "remote-thread DllMain runs on a new thread; the DllMain thunk calls TlsSetValue before entering the payload"
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

                    if let Some(ref cb) = req.plan.map_callback_path {
                        tracing::info!(
                            pid = process.pid,
                            callback = %cb.display(),
                            remote_base = format_args!("{remote_base:#x}"),
                            "map_callback post-mapping stage"
                        );
                    }
                }
            }

            let mut record_function_tables: Vec<(u64, u32)> = Vec::new();
            let record_tls_callbacks: Vec<u64> = pe
                .tls_callbacks(&image, remote_base as usize)?
                .iter()
                .map(|&c| c as u64)
                .collect();
            let record_entry_point = pe
                .entry(remote_base as usize)?
                .map(|e| e as u64)
                .unwrap_or(0);

            if req.plan.manual_module_registry == GuestManualModuleRegistry::Track {
                let registry = MANUAL_MODULE_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
                registry.lock().unwrap().insert(
                    (process.pid, remote_base),
                    ModuleRecord {
                        base: remote_base,
                        size: pe.size_of_image as u64,
                        refcount: 1,
                        dependencies: loaded_dependencies,
                        entry_point: record_entry_point,
                        tls_callbacks: record_tls_callbacks.clone(),
                        function_tables: Vec::new(),
                        actctx_handle: None,
                        actctx_cookie: None,
                        tls_slot: None,
                        tls_template_bufs: Vec::new(),
                        tls_slot_bindings: Vec::new(),
                        peb_loader_entry: None,
                    },
                );
                tracing::info!(
                    pid = process.pid,
                    remote_base = format_args!("{remote_base:#x}"),
                    "module registered in manual module registry for unmap-all"
                );
                if let Some(slot) = tls_slot_index {
                    let bufs = std::mem::take(&mut tls_template_bufs);
                    tracing::info!(
                        pid = process.pid,
                        slot,
                        template_count = bufs.len(),
                        "static TLS cleanup metadata recorded for tracked unload"
                    );
                    update_module_record(process.pid, remote_base, |r| {
                        r.tls_slot = Some(slot);
                        r.tls_template_bufs = bufs;
                        r.tls_slot_bindings = std::mem::take(&mut tls_slot_bindings);
                    });
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
                        let ft_addr = remote_base
                            .checked_add(u64::from(pe.exception.rva))
                            .unwrap_or(0);
                        let ft_count = pe.exception.size / 12;
                        record_function_tables.push((ft_addr, ft_count));
                        if req.plan.manual_module_registry == GuestManualModuleRegistry::Track {
                            update_module_record(process.pid, remote_base, |r| {
                                r.function_tables = record_function_tables.clone();
                            });
                        }
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
                        &[remote_base, DLL_PROCESS_ATTACH as u64, 0, 0],
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
                            &[0, info_bytes as u64, MEM_COMMIT_RESERVE, PAGE_READWRITE],
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
                                    &[cfg_info, 0, MEM_RELEASE, 0],
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
                    stage,
                    remote_base,
                    entry_point,
                    pe.size_of_image as u32,
                    dll_name,
                    req.plan.execution.timeout_ms,
                )?);
                if req.plan.manual_module_registry == GuestManualModuleRegistry::Track {
                    update_module_record(process.pid, remote_base, |r| {
                        r.peb_loader_entry = peb_entry_addr;
                    });
                }
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

            let mut sxs_actctx: Option<(DllMainActCtx, u64)> = None;
            if req.plan.sxs == GuestSxS::Probe {
                let has_manifest = pe.manifest_id(&image)?.is_some();
                if has_manifest {
                    let actctx_handle = guest_create_module_actctx(
                        backend,
                        process.pid,
                        &hook,
                        remote_base,
                        1,
                        req.plan.execution.timeout_ms,
                    )?;
                    let cookie_buf = allocate_helper_buffer(
                        backend,
                        process.pid,
                        &hook,
                        virtual_alloc,
                        8,
                        req.plan.execution.timeout_ms,
                    )?;
                    let activate = resolve_import_symbol(
                        backend,
                        process.pid,
                        "kernel32.dll",
                        "ActivateActCtx",
                    )?;
                    let deactivate = resolve_import_symbol(
                        backend,
                        process.pid,
                        "kernel32.dll",
                        "DeactivateActCtx",
                    )?;
                    tracing::info!(
                        pid = process.pid,
                        handle = format_args!("{actctx_handle:#x}"),
                        cookie_addr = format_args!("{cookie_buf:#x}"),
                        "activation context prepared for DllMain execution thread"
                    );
                    sxs_actctx = Some((
                        DllMainActCtx {
                            activate,
                            deactivate,
                            handle: actctx_handle,
                            cookie_addr: cookie_buf,
                        },
                        cookie_buf,
                    ));
                } else {
                    tracing::info!(
                        pid = process.pid,
                        "sxs = probe but payload has no embedded manifest; skipping activation context"
                    );
                }
            }

            if let Some(entry) = pe.entry(remote_base as usize)? {
                tracing::info!(
                    pid = process.pid,
                    entry = format_args!("{entry:#x}"),
                    execution = req.plan.execution.method.label(),
                    "calling payload DllMain"
                );
                let reserved_arg_remote: u64 = match req.plan.dll_main_reserved_arg.as_deref() {
                    Some(bytes) if !bytes.is_empty() => {
                        let remote = allocate_helper_buffer(
                            backend,
                            process.pid,
                            &hook,
                            virtual_alloc,
                            bytes.len(),
                            req.plan.execution.timeout_ms,
                        )?;
                        backend.write(process.pid, remote, bytes)?;
                        tracing::info!(
                            pid = process.pid,
                            reserved_arg_remote = format_args!("{remote:#x}"),
                            bytes = bytes.len(),
                            "DllMain reserved arg (CustomArgs_t) staged"
                        );
                        remote
                    }
                    _ => 0,
                };
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
                        reserved_arg_remote,
                        dllmain_tls,
                        sxs_actctx.map(|(actctx, _)| actctx),
                        req.plan.thread_starts,
                        req.plan.execution.timeout_ms,
                    )?,
                    GuestExecutionMethod::ThreadHijack => {
                        let hook_servicing_tid = match resolve_import_symbol(
                            backend,
                            process.pid,
                            "kernel32.dll",
                            "GetCurrentThreadId",
                        )
                        .and_then(|get_current_thread_id| {
                            backend.call_iat_hook(
                                process.pid,
                                &hook,
                                get_current_thread_id,
                                &[0, 0, 0, 0],
                                req.plan.execution.timeout_ms,
                            )
                        }) {
                            Ok(tid) if tid != 0 && tid <= u32::MAX as u64 => Some(tid as u32),
                            Ok(tid) => {
                                tracing::warn!(
                                    pid = process.pid,
                                    tid = format_args!("{tid:#x}"),
                                    "thread-hijack: ignoring invalid hook-servicing TID"
                                );
                                None
                            }
                            Err(e) => {
                                tracing::warn!(
                                    pid = process.pid,
                                    error = %e,
                                    "thread-hijack: could not identify hook-servicing thread"
                                );
                                None
                            }
                        };
                        let threads = backend.list_threads(process.pid)?;
                        let candidates = select_execution_thread_candidates(
                            process.pid,
                            &threads,
                            hook_servicing_tid,
                        )?;
                        let mut selected = None;
                        let mut last_context_error = None;
                        for target_thread in candidates {
                            match backend.get_thread_context(
                                process.pid,
                                target_thread.tid,
                                &hook,
                                req.plan.execution.timeout_ms,
                            ) {
                                Ok(ctx) => {
                                    selected = Some((target_thread, ctx));
                                    break;
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        pid = process.pid,
                                        tid = target_thread.tid,
                                        error = %error,
                                        "thread-hijack: candidate became unavailable while acquiring its context; trying the next candidate"
                                    );
                                    last_context_error = Some(error.to_string());
                                }
                            }
                        }
                        let (target_thread, ctx) = selected.ok_or_else(|| {
                            let suffix = last_context_error
                                .as_deref()
                                .map(|error| format!("; last error: {error}"))
                                .unwrap_or_default();
                            GuestInjectError::Backend(format!(
                                "thread-hijack found no usable non-hook target thread in pid {}{suffix}",
                                process.pid
                            ))
                        })?;
                        let target_tid = target_thread.tid;
                        tracing::info!(
                            pid = process.pid,
                            tid = target_tid,
                            hook_servicing_tid,
                            teb = format_args!("{:#x}", target_thread.teb),
                            start_address = format_args!("{:#x}", target_thread.start_address),
                            state = ?target_thread.state,
                            active_threads = threads
                                .iter()
                                .filter(|t| t.state != GuestThreadState::Terminated)
                                .count(),
                            "thread-hijack: selected target thread"
                        );
                        let original_rip = ctx.rip;

                        let (thunk_addr, param_addr, exit_code_addr, status_addr) =
                            prepare_dllmain_scratch(
                                backend,
                                process.pid,
                                &hook,
                                virtual_alloc,
                                entry as u64,
                                remote_base,
                                reserved_arg_remote,
                                Some(ctx),
                                dllmain_tls,
                                sxs_actctx.map(|(actctx, _)| actctx),
                                req.plan.execution.timeout_ms,
                            )?;

                        let mut new_ctx = ctx;
                        new_ctx.rip = thunk_addr;
                        new_ctx.rbx = param_addr;
                        backend.set_thread_context(
                            process.pid,
                            target_tid,
                            &new_ctx,
                            &hook,
                            req.plan.execution.timeout_ms,
                        )?;
                        tracing::info!(
                            pid = process.pid,
                            tid = target_tid,
                            original_rip = format_args!("{original_rip:#x}"),
                            thunk = format_args!("{thunk_addr:#x}"),
                            "thread-hijack: RIP redirected to DllMain thunk"
                        );
                        match poll_remote_thread_exit(
                            backend,
                            process.pid,
                            status_addr,
                            exit_code_addr,
                            req.plan.execution.timeout_ms,
                        ) {
                            Ok(ret) => {
                                tracing::info!(
                                    pid = process.pid,
                                    tid = target_tid,
                                    dllmain_result = ret,
                                    "thread-hijack: DllMain completed and thunk is restoring the captured thread context"
                                );
                                ret
                            }
                            Err(e) => {
                                tracing::warn!(
                                    pid = process.pid,
                                    tid = target_tid,
                                    error = %e,
                                    "thread-hijack: DllMain did not complete within timeout; suspending thread and restoring original RIP"
                                );
                                let _ = backend.suspend_thread(
                                    process.pid,
                                    target_tid,
                                    &hook,
                                    req.plan.execution.timeout_ms,
                                );
                                let restore_ctx = backend.get_thread_context(
                                    process.pid,
                                    target_tid,
                                    &hook,
                                    req.plan.execution.timeout_ms,
                                )?;
                                let mut restored = restore_ctx;
                                restored.rip = original_rip;
                                let _ = backend.set_thread_context(
                                    process.pid,
                                    target_tid,
                                    &restored,
                                    &hook,
                                    req.plan.execution.timeout_ms,
                                );
                                let _ = backend.resume_thread(
                                    process.pid,
                                    target_tid,
                                    &hook,
                                    req.plan.execution.timeout_ms,
                                );
                                if let Some((actctx, cookie_buf)) = sxs_actctx {
                                    guest_release_module_actctx(
                                        backend,
                                        process.pid,
                                        &hook,
                                        actctx.handle,
                                        cookie_buf,
                                        req.plan.execution.timeout_ms,
                                    );
                                }
                                return Err(e);
                            }
                        }
                    }
                    GuestExecutionMethod::Apc => {
                        let hook_servicing_tid = match resolve_import_symbol(
                            backend,
                            process.pid,
                            "kernel32.dll",
                            "GetCurrentThreadId",
                        )
                        .and_then(|get_current_thread_id| {
                            backend.call_iat_hook(
                                process.pid,
                                &hook,
                                get_current_thread_id,
                                &[0, 0, 0, 0],
                                req.plan.execution.timeout_ms,
                            )
                        }) {
                            Ok(tid) if tid != 0 && tid <= u32::MAX as u64 => Some(tid as u32),
                            Ok(tid) => {
                                tracing::warn!(
                                    pid = process.pid,
                                    tid = format_args!("{tid:#x}"),
                                    "APC: ignoring invalid hook-servicing TID"
                                );
                                None
                            }
                            Err(error) => {
                                tracing::warn!(
                                    pid = process.pid,
                                    error = %error,
                                    "APC: could not identify hook-servicing thread"
                                );
                                None
                            }
                        };
                        let threads = backend.list_threads(process.pid)?;
                        let candidates = select_execution_thread_candidates(
                            process.pid,
                            &threads,
                            hook_servicing_tid,
                        )?;

                        let (thunk_addr, param_addr, exit_code_addr, status_addr) =
                            prepare_dllmain_scratch(
                                backend,
                                process.pid,
                                &hook,
                                virtual_alloc,
                                entry as u64,
                                remote_base,
                                reserved_arg_remote,
                                None,
                                dllmain_tls,
                                sxs_actctx.map(|(actctx, _)| actctx),
                                req.plan.execution.timeout_ms,
                            )?;

                        let queue_apc = resolve_import_symbol(
                            backend,
                            process.pid,
                            "kernel32.dll",
                            "QueueUserAPC",
                        )?;
                        let mut queued = None;
                        for candidate in candidates {
                            let thread_handle = match guest_open_thread(
                                backend,
                                process.pid,
                                candidate.tid,
                                THREAD_SET_CONTEXT,
                                &hook,
                                req.plan.execution.timeout_ms,
                            ) {
                                Ok(handle) => handle,
                                Err(error) => {
                                    tracing::warn!(
                                        pid = process.pid,
                                        tid = candidate.tid,
                                        error = %error,
                                        "APC: candidate became unavailable before QueueUserAPC; trying the next candidate"
                                    );
                                    continue;
                                }
                            };
                            let apc_result = backend.call_iat_hook(
                                process.pid,
                                &hook,
                                queue_apc,
                                &[thunk_addr, thread_handle, param_addr, 0],
                                req.plan.execution.timeout_ms,
                            );
                            guest_close_handle(
                                backend,
                                process.pid,
                                thread_handle,
                                &hook,
                                req.plan.execution.timeout_ms,
                            );
                            let apc_result = apc_result?;
                            if apc_result != 0 {
                                queued = Some((candidate.tid, apc_result));
                                break;
                            }
                            tracing::warn!(
                                pid = process.pid,
                                tid = candidate.tid,
                                "APC: QueueUserAPC rejected a stale candidate; trying the next candidate"
                            );
                        }
                        let (target_tid, apc_result) = queued.ok_or_else(|| {
                            GuestInjectError::Backend(format!(
                                "QueueUserAPC rejected every non-hook target thread in pid {}",
                                process.pid
                            ))
                        })?;
                        tracing::info!(
                            pid = process.pid,
                            tid = target_tid,
                            hook_servicing_tid,
                            apc_result,
                            thunk = format_args!("{thunk_addr:#x}"),
                            "APC: queued DllMain thunk to target thread"
                        );
                        match poll_remote_thread_exit(
                            backend,
                            process.pid,
                            status_addr,
                            exit_code_addr,
                            req.plan.execution.timeout_ms,
                        ) {
                            Ok(ret) => {
                                tracing::info!(
                                    pid = process.pid,
                                    tid = target_tid,
                                    dllmain_result = ret,
                                    "APC: DllMain completed via alertable wait"
                                );
                                ret
                            }
                            Err(e) => {
                                tracing::warn!(
                                    pid = process.pid,
                                    tid = target_tid,
                                    error = %e,
                                    "APC: DllMain did not complete within timeout; target thread may not have entered an alertable wait state"
                                );
                                if let Some((actctx, cookie_buf)) = sxs_actctx {
                                    guest_release_module_actctx(
                                        backend,
                                        process.pid,
                                        &hook,
                                        actctx.handle,
                                        cookie_buf,
                                        req.plan.execution.timeout_ms,
                                    );
                                }
                                return Err(e);
                            }
                        }
                    }
                    _ => {
                        if let Some((actctx, _)) = sxs_actctx {
                            let (thunk_addr, param_addr, exit_code_addr, status_addr) =
                                prepare_dllmain_scratch(
                                    backend,
                                    process.pid,
                                    &hook,
                                    virtual_alloc,
                                    entry as u64,
                                    remote_base,
                                    reserved_arg_remote,
                                    None,
                                    dllmain_tls,
                                    Some(actctx),
                                    req.plan.execution.timeout_ms,
                                )?;
                            if let Err(e) = backend.call_iat_hook(
                                process.pid,
                                &hook,
                                thunk_addr,
                                &[param_addr, 0, 0, 0],
                                req.plan.execution.timeout_ms,
                            ) {
                                if let Some((actctx, cookie_buf)) = sxs_actctx {
                                    guest_release_module_actctx(
                                        backend,
                                        process.pid,
                                        &hook,
                                        actctx.handle,
                                        cookie_buf,
                                        req.plan.execution.timeout_ms,
                                    );
                                }
                                return Err(e);
                            }
                            poll_remote_thread_exit(
                                backend,
                                process.pid,
                                status_addr,
                                exit_code_addr,
                                req.plan.execution.timeout_ms,
                            )?
                        } else {
                            match backend.call_iat_hook(
                                process.pid,
                                &hook,
                                entry as u64,
                                &[
                                    remote_base,
                                    DLL_PROCESS_ATTACH as u64,
                                    reserved_arg_remote,
                                    0,
                                ],
                                req.plan.execution.timeout_ms,
                            ) {
                                Ok(r) => r,
                                Err(e) => return Err(e),
                            }
                        }
                    }
                };
                if let Some((actctx, cookie_buf)) = sxs_actctx {
                    guest_release_module_actctx(
                        backend,
                        process.pid,
                        &hook,
                        actctx.handle,
                        cookie_buf,
                        req.plan.execution.timeout_ms,
                    );
                }
                tracing::info!(
                    pid = process.pid,
                    entry_result = ok,
                    "payload DllMain returned"
                );
                if ok == 0 {
                    return Err(GuestInjectError::Image("DllMain returned FALSE".into()));
                }
            } else {
                if let Some((actctx, cookie_buf)) = sxs_actctx {
                    guest_release_module_actctx(
                        backend,
                        process.pid,
                        &hook,
                        actctx.handle,
                        cookie_buf,
                        req.plan.execution.timeout_ms,
                    );
                }
                tracing::info!("payload has no entry point");
            }

            for section in &pe.sections {
                if section.characteristics & IMAGE_SCN_MEM_DISCARDABLE == 0 {
                    continue;
                }
                let size = guest_section_size(section);
                if size == 0 {
                    continue;
                }
                let addr = remote_base
                    .checked_add(u64::from(section.virtual_address))
                    .ok_or_else(|| {
                        GuestInjectError::Image("discardable section address overflows".into())
                    })?;
                let zeros = vec![0u8; size as usize];
                if req.plan.image_backing == GuestImageBacking::SecImage {
                    let vp = virtual_protect.expect(
                        "discardable wipe requires final_protections = section so VirtualProtect is resolved",
                    );
                    let _ = guest_virtual_protect(
                        backend,
                        process.pid,
                        &hook,
                        vp,
                        addr,
                        size as u64,
                        PAGE_READWRITE,
                        hook.result_addr + OLD_PROTECT_RESULT_OFFSET,
                        req.plan.execution.timeout_ms,
                        "discardable section wipe",
                    );
                }
                let _ = backend.write(process.pid, addr, &zeros);
                tracing::info!(
                    pid = process.pid,
                    addr = format_args!("{addr:#x}"),
                    size,
                    "discardable section wiped"
                );
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
            if let Some(pool_base) = iat_stage_pool_base {
                notes.push(format!(
                    "IAT execution pool: using {} one-shot {}-byte RWX stage slots at {pool_base:#x}; slots are retained until target exit so late IAT callers cannot enter reused code",
                    req.plan.iat_stage_pool_slots,
                    STAGE_CAVE_SIZE,
                ));
            }
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
                    GuestExecutionMethod::RemoteThread
                    | GuestExecutionMethod::ThreadHijack
                    | GuestExecutionMethod::Apc => {
                        "existing direct TLS-slot threads plus the DllMain execution thread"
                    }
                    _ => "existing direct TLS-slot threads and the current target thread",
                };
                notes.push(format!(
                    "static TLS: allocated slot {slot} via TlsAlloc, patched index into image, copied TLS template, and called TlsSetValue for {thread_scope}"
                ));
                notes.push(format!(
                    "static TLS post-mapping: threads created after mapping start with NULL in slot {slot}; the payload must guard against NULL or lazily construct the template. Unload frees the slot and all template buffers via TlsFree/VirtualFree"
                ));
            }
            if cfg_marked {
                notes.push(format!(
                    "CFG: marked {cfg_target_count} export/entry targets as valid indirect call targets via SetProcessValidCallTargets before DllMain"
                ));
            }
            notes.extend(guest_artifact_notes(req, &pe, remote_base, has_static_tls));

            let info = GuestLoadInfo {
                method: self.name().into(),
                pid: process.pid,
                remote_base: Some(remote_base),
                notes,
            };
            drop(injection_lock);
            Ok(info)
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
    armed: bool,
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
            armed: false,
            restored: false,
        })
    }

    fn arm(&mut self) -> Result<(), GuestInjectError> {
        // Treat a failed verification as armed: the backend may have completed
        // the write before its read-back failed, so Drop must restore the slot.
        self.armed = true;
        write_verified(
            self.backend,
            self.pid,
            self.hook.iat_slot,
            &self.hook.stub_addr.to_le_bytes(),
            "guest IAT-hook thunk",
        )
    }

    fn restore(&mut self) -> Result<(), GuestInjectError> {
        if self.restored {
            return Ok(());
        }
        let mut errors = Vec::new();
        if self.armed {
            // Disarm before touching the stage. A thread may have already fetched
            // the stub address, so leave its instruction bytes and result block
            // intact until every stub invocation has tail-jumped to the original
            // import target.
            if let Err(err) = write_verified(
                self.backend,
                self.pid,
                self.hook.iat_slot,
                &self.original_iat,
                "guest IAT-hook slot restore",
            ) {
                self.restored = true;
                return Err(GuestInjectError::Backend(format!(
                    "failed restoring guest IAT hook transaction: IAT slot at {:#x}: {err}; \
                     stage and result bytes were deliberately retained because the slot state is uncertain",
                    self.hook.iat_slot
                )));
            }
            if let Err(err) = self.wait_for_stub_quiescence() {
                self.restored = true;
                return Err(GuestInjectError::Backend(format!(
                    "failed restoring guest IAT hook transaction: {err}; \
                     stage and result bytes were deliberately retained while guest stub invocations remain in flight"
                )));
            }
            if !self.backend.capabilities().iat_hook_stage_restore {
                // The IAT slot is back to its original target, but a target
                // thread may already have fetched the temporary stub address.
                // Retain a completed stub so that late execution only
                // tail-jumps to the original import instead of entering bytes
                // restored from an unrelated code cave.
                if let Err(err) = write_verified(
                    self.backend,
                    self.pid,
                    self.hook.result_addr,
                    &RESULT_STATE.to_le_bytes(),
                    "guest IAT-hook completed-state fence",
                ) {
                    self.restored = true;
                    return Err(GuestInjectError::Backend(format!(
                        "failed finalizing guest IAT hook transaction: {err}; \
                         stage and result bytes were deliberately retained"
                    )));
                }
                self.restored = true;
                tracing::debug!(
                    pid = self.pid,
                    iat_slot = format_args!("{:#x}", self.hook.iat_slot),
                    stub_addr = format_args!("{:#x}", self.hook.stub_addr),
                    "guest IAT-hook transaction retained completed stage for late callers"
                );
                return Ok(());
            }
            thread::sleep(IAT_RESTORE_GRACE);
        }
        for (addr, bytes, label) in [
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

    fn wait_for_stub_quiescence(&self) -> Result<(), GuestInjectError> {
        let counter_addr = self
            .hook
            .result_addr
            .checked_add(RESULT_INFLIGHT_OFFSET)
            .ok_or_else(|| {
                GuestInjectError::Backend("guest IAT in-flight counter overflows".into())
            })?;
        let deadline = Instant::now() + IAT_QUIESCENCE_TIMEOUT;
        loop {
            let bytes = self.backend.read(self.pid, counter_addr, 8)?;
            let in_flight = u64::from_le_bytes(bytes.as_slice().try_into().map_err(|_| {
                GuestInjectError::Backend("guest IAT in-flight counter read was truncated".into())
            })?);
            if in_flight == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(GuestInjectError::Backend(format!(
                    "guest IAT stubs did not quiesce within {} ms (in_flight={in_flight})",
                    IAT_QUIESCENCE_TIMEOUT.as_millis()
                )));
            }
            thread::sleep(IAT_QUIESCENCE_POLL_INTERVAL);
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
    args: &[u64],
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
        nargs = args.len(),
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
    transaction.arm()?;
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

fn memory_iat_bootstrap_stage_pool<B: GuestMemoryBackend + ?Sized>(
    backend: &B,
    pid: u32,
    hook: &GuestIatHook,
    virtual_alloc: u64,
    size: u64,
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    let zero_result = vec![0u8; RESULT_BLOCK_SIZE];
    let stub = stage_pool_bootstrap_stub(hook, virtual_alloc, size)?;
    let mut transaction = IatHookTransaction::prepare(backend, pid, hook, stub.len())?;
    tracing::debug!(
        pid,
        virtual_alloc = format_args!("{virtual_alloc:#x}"),
        size,
        iat_slot = format_args!("{:#x}", hook.iat_slot),
        stub_addr = format_args!("{:#x}", hook.stub_addr),
        result_addr = format_args!("{:#x}", hook.result_addr),
        "guest IAT-hook stage-pool bootstrap installing allocation/materialization stub"
    );
    write_verified(
        backend,
        pid,
        hook.result_addr,
        &zero_result,
        "guest IAT stage-pool bootstrap result block",
    )?;
    write_verified(
        backend,
        pid,
        hook.stub_addr,
        &stub,
        "guest IAT stage-pool bootstrap stub",
    )?;
    transaction.arm()?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    loop {
        let result = backend.read(pid, hook.result_addr, RESULT_BLOCK_SIZE)?;
        let state = u64::from_le_bytes(result[0..8].try_into().unwrap());
        let value = u64::from_le_bytes(result[8..16].try_into().unwrap());
        if state == RESULT_STATE {
            transaction.restore()?;
            return Ok(value);
        }
        if Instant::now() >= deadline {
            let restore_result = transaction.restore();
            if let Err(err) = restore_result {
                tracing::warn!(pid, error = %err, "guest IAT stage-pool bootstrap timeout restore failed");
            }
            return Err(GuestInjectError::Unsupported {
                operation: "guest IAT stage-pool bootstrap",
                reason: format!(
                    "target did not call the configured import before {} ms",
                    timeout_ms
                ),
            });
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn memory_iat_probe<B: GuestMemoryBackend + ?Sized>(
    backend: &B,
    pid: u32,
    hook: &GuestIatHook,
    probe_function: u64,
    timeout_ms: u32,
) -> Result<Option<u32>, GuestInjectError> {
    let zero_result = vec![0u8; RESULT_BLOCK_SIZE];
    let stub = call_stub(hook, probe_function, &[]);
    let mut transaction = IatHookTransaction::prepare(backend, pid, hook, stub.len())?;
    write_verified(
        backend,
        pid,
        hook.result_addr,
        &zero_result,
        "guest IAT-hook probe result block",
    )?;
    write_verified(
        backend,
        pid,
        hook.stub_addr,
        &stub,
        "guest IAT-hook probe stub",
    )?;
    transaction.arm()?;
    tracing::debug!(
        pid,
        iat_slot = format_args!("{:#x}", hook.iat_slot),
        original_target = format_args!("{:#x}", hook.original_target),
        probe_function = format_args!("{probe_function:#x}"),
        timeout_ms,
        "guest IAT liveness probe armed through GetCurrentThreadId call stub"
    );

    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    loop {
        let result = backend.read(pid, hook.result_addr, RESULT_BLOCK_SIZE)?;
        let state = u64::from_le_bytes(result[0..8].try_into().unwrap());
        if state == RESULT_STATE {
            let tid = u64::from_le_bytes(result[8..16].try_into().unwrap()) as u32;
            transaction.restore()?;
            tracing::info!(
                pid,
                iat_slot = format_args!("{:#x}", hook.iat_slot),
                tid,
                "guest IAT liveness probe observed call"
            );
            return Ok(Some(tid));
        }
        if Instant::now() >= deadline {
            transaction.restore()?;
            tracing::info!(
                pid,
                iat_slot = format_args!("{:#x}", hook.iat_slot),
                timeout_ms,
                "guest IAT liveness probe observed no call"
            );
            return Ok(None);
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
    transaction.arm()?;
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
    transaction.arm()?;
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
    transaction.arm()?;
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
                "artifact audit: payload image at {remote_base:#x} is backed by a real SEC_IMAGE section over a staged guest copy of the fully patched payload file; the section object and image-file VAD backing are kernel-created; the view matches the on-disk image exactly"
            ),
        },
        match req.plan.loader_entries {
            GuestLoaderEntries::Absent => {
                "artifact audit: PEB loader lists are not synthesized; the mapped image is absent from normal module enumeration".into()
            }
            GuestLoaderEntries::Synthesized if req.plan.cleanup == GuestCleanup::Tracked => {
                "artifact audit: synthesized full LDR_DATA_TABLE_ENTRY with DDAG node and LoadCount=-1, linked transiently into all three PEB loader lists, then unlinked by cleanup=tracked".into()
            }
            GuestLoaderEntries::Synthesized => {
                "artifact audit: synthesized full LDR_DATA_TABLE_ENTRY with DDAG node, LoadCount=-1, Flags=0x80004, linked into InLoadOrder, InMemoryOrder, and InInitializationOrder lists".into()
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
            match (
                req.plan.execution.method,
                req.plan.thread_starts,
            ) {
                (
                    GuestExecutionMethod::RemoteThread,
                    GuestThreadStartPolicy::RequireModuleBacked,
                ) => " on a kernel-created remote thread through an in-image DllMain thunk",
                (GuestExecutionMethod::RemoteThread, _) => {
                    " on a kernel-created remote thread through a ThreadProc helper"
                }
                (GuestExecutionMethod::Apc, _) => {
                    " on an alertable existing target thread through a queued user APC"
                }
                _ => " on the target thread that calls the hooked import",
            },
            match (
                req.plan.execution.method,
                req.plan.thread_starts,
            ) {
                (
                    GuestExecutionMethod::RemoteThread,
                    GuestThreadStartPolicy::RequireModuleBacked,
                ) => "the kernel-recorded thread start is inside the mapped image via the in-image thunk",
                (GuestExecutionMethod::RemoteThread, _) => {
                    "the kernel-recorded thread start is the selected helper thunk, module-backed when a payload-image code cave is available and otherwise a temporary helper allocation"
                }
                (GuestExecutionMethod::Apc, _) => {
                    "QueueUserAPC queues a user-mode APC on an existing thread; no new thread is created"
                }
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
                    "artifact audit: thread_starts=existing-thread with remote-thread; a guest thread is created, using a payload-image ThreadProc thunk when an executable cave is available and a temporary helper allocation otherwise".into(),
                );
            } else {
                notes.push(
                    "artifact audit: thread_starts=existing-thread creates no guest thread, so no new thread start address is recorded by this path".into(),
                );
            }
        }
        GuestThreadStartPolicy::RequireModuleBacked => {
            if req.plan.execution.method == GuestExecutionMethod::RemoteThread {
                notes.push(
                    "artifact audit: thread_starts=require-module-backed with remote-thread; the DllMain thunk is placed in a payload-image executable code cave, and the kernel-recorded thread start is inside the mapped image".into(),
                );
            } else {
                notes.push(
                    "artifact audit: thread_starts=require-module-backed verified the IAT-hook plumbing is inside loaded module ranges".into(),
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
                    GuestExecutionMethod::RemoteThread
                    | GuestExecutionMethod::ThreadHijack
                    | GuestExecutionMethod::Apc => {
                        "existing direct TLS-slot threads plus the DllMain execution thread"
                    }
                    _ => "existing direct TLS-slot threads and the current target thread",
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
                    "artifact audit: stack_shaping=spoofed is not applied to remote-thread launch frames; remote-thread DllMain runs through a ThreadProc helper".into(),
                );
            } else {
                notes.push(
                    "artifact audit: stack_shaping=spoofed writes a synthetic return address from a loaded module onto the stack before payload calls so stack walks attribute the call to a legitimate module".into(),
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
            "artifact audit: vad_spoof=vad-image-map changed the kernel VAD type for the private mapping to VadImageMap via EPROCESS/VadRoot writes; the allocation appears as image-backed to NtQueryVirtualMemory".into(),
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

fn random_base_address(high_memory: bool) -> u64 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    let mut state = time ^ pid.rotate_left(17) ^ 0x9E37_79B9_7F4A_7C15;
    state ^= state >> 33;
    state = state.wrapping_mul(0xff51_afd7_ed55_8ccd);
    state ^= state >> 33;
    let (lo, hi) = match high_memory {
        true => (0x1_0000_0000u64, 0x7FF0_0000_0000u64),
        false => (0x1000_0000u64, 0x7FF0_0000_0000u64),
    };
    let range = hi - lo;
    let offset = state % range;
    let base = lo + offset;
    base & !0xFFFF
}

#[derive(Clone, Copy)]
struct DllMainThreadTls {
    tls_set_value: u64,
    slot: u32,
    value: u64,
}

#[derive(Clone, Copy)]
struct DllMainActCtx {
    activate: u64,
    deactivate: u64,
    handle: u64,
    cookie_addr: u64,
}

fn remote_thread_param_block(
    entry_point: u64,
    remote_base: u64,
    reserved: u64,
    exit_code: u64,
    status: u64,
    tls: Option<DllMainThreadTls>,
    actctx: Option<DllMainActCtx>,
) -> [u8; REMOTE_THREAD_PARAM_SIZE] {
    let mut block = [0u8; REMOTE_THREAD_PARAM_SIZE];
    let values = [
        (0x00, entry_point),
        (0x08, remote_base),
        (0x10, DLL_PROCESS_ATTACH as u64),
        (0x18, reserved),
        (0x20, exit_code),
        (0x28, status),
    ];
    for (off, value) in values {
        block[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }
    if let Some(tls) = tls {
        block[0x30..0x38].copy_from_slice(&tls.tls_set_value.to_le_bytes());
        block[0x38..0x40].copy_from_slice(&(tls.slot as u64).to_le_bytes());
        block[0x40..0x48].copy_from_slice(&tls.value.to_le_bytes());
    }
    if let Some(actctx) = actctx {
        block[0x48..0x50].copy_from_slice(&actctx.activate.to_le_bytes());
        block[0x50..0x58].copy_from_slice(&actctx.deactivate.to_le_bytes());
        block[0x58..0x60].copy_from_slice(&actctx.handle.to_le_bytes());
        block[0x60..0x68].copy_from_slice(&actctx.cookie_addr.to_le_bytes());
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
            return match status {
                DLLMAIN_STATUS_COMPLETE => {
                    read_remote_u32(backend, pid, exit_code_addr).map(u64::from)
                }
                DLLMAIN_STATUS_ACTCTX_ACTIVATION_FAILED => Err(GuestInjectError::Backend(
                    "ActivateActCtx returned FALSE on the DllMain execution thread".into(),
                )),
                unexpected => Err(GuestInjectError::Backend(format!(
                    "DllMain thunk returned unexpected completion status {unexpected}"
                ))),
            };
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
            &[addr, 0, MEM_RELEASE, 0],
            timeout_ms,
        );
    }
}

fn allocate_helper_buffer(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    virtual_alloc: u64,
    size: usize,
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    allocate_helper_buffer_with_protect(
        backend,
        pid,
        hook,
        virtual_alloc,
        size,
        PAGE_READWRITE,
        timeout_ms,
    )
}

fn allocate_helper_buffer_with_protect(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    virtual_alloc: u64,
    size: usize,
    protect: u64,
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    let aligned = (size + 0xFFF) & !0xFFF;
    let remote = backend.call_iat_hook(
        pid,
        hook,
        virtual_alloc,
        &[0, aligned as u64, MEM_COMMIT_RESERVE, protect],
        timeout_ms,
    )?;
    if remote == 0 {
        return Err(GuestInjectError::Backend(format!(
            "VirtualAlloc for {size}-byte helper buffer returned null"
        )));
    }
    backend.touch_iat_hook(pid, hook, remote, aligned, timeout_ms)?;
    Ok(remote)
}

fn allocate_iat_stage_pool(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    bootstrap_hook: &GuestIatHook,
    virtual_alloc: u64,
    slots: u32,
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    if slots == 0 {
        return Err(GuestInjectError::Config(
            "guest.iat_stage_pool_slots must be greater than zero".into(),
        ));
    }
    let size = iat_stage_pool_size(slots)?;
    let base = memory_iat_bootstrap_stage_pool(
        backend,
        pid,
        bootstrap_hook,
        virtual_alloc,
        size,
        timeout_ms,
    )?;
    if base == 0 {
        return Err(GuestInjectError::Backend(format!(
            "VirtualAlloc returned NULL for {slots}-slot guest IAT stage pool"
        )));
    }
    tracing::info!(
        pid,
        base = format_args!("{base:#x}"),
        slots,
        size,
        "guest IAT stage pool allocated; each guest call uses a one-shot slot"
    );
    Ok(base)
}

fn allocate_tls_template_copy(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    virtual_alloc: u64,
    template: &[u8],
    timeout_ms: u32,
    label: &str,
) -> Result<u64, GuestInjectError> {
    let size = template.len().max(1);
    let remote = allocate_helper_buffer(backend, pid, hook, virtual_alloc, size, timeout_ms)?;
    if !template.is_empty() {
        write_verified(backend, pid, remote, template, label)?;
    }
    Ok(remote)
}

fn select_execution_thread_candidates(
    pid: u32,
    threads: &[GuestThreadInfo],
    hook_servicing_tid: Option<u32>,
) -> Result<Vec<GuestThreadInfo>, GuestInjectError> {
    let active: Vec<GuestThreadInfo> = threads
        .iter()
        .copied()
        .filter(|t| t.state != GuestThreadState::Terminated && t.teb != 0)
        .collect();
    if active.len() < 2 {
        return Err(GuestInjectError::Backend(format!(
            "guest execution requires at least two active threads in pid {pid} when calls are serviced through an IAT hook; refusing to target the only hook-servicing thread"
        )));
    }
    let mut candidates: Vec<_> = active
        .into_iter()
        .filter(|t| Some(t.tid) != hook_servicing_tid)
        .collect();
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.tid));
    if candidates.is_empty() {
        return Err(GuestInjectError::Backend(format!(
            "guest execution found no active non-hook-servicing thread in pid {pid}"
        )));
    }
    Ok(candidates)
}

const THREAD_SUSPEND_RESUME: u64 = 0x0002;
const THREAD_GET_CONTEXT: u64 = 0x0008;
const THREAD_SET_CONTEXT: u64 = 0x0010;
const THREAD_QUERY_INFORMATION: u64 = 0x0040;
const THREAD_TERMINATE: u64 = 0x0001;
const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_CONTROL_AMD64: u32 = CONTEXT_AMD64 | 0x01;
const CONTEXT_INTEGER_AMD64: u32 = CONTEXT_AMD64 | 0x02;
const CONTEXT_DEBUG_REGISTERS_AMD64: u32 = CONTEXT_AMD64 | 0x10;
const CONTEXT_FULL_AMD64: u32 = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;
const CONTEXT_SIZE: usize = 0x4D0;

pub fn guest_open_thread(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    access: u64,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    let open_thread = resolve_import_symbol(backend, pid, "kernel32.dll", "OpenThread")?;
    let handle = backend.call_iat_hook(
        pid,
        hook,
        open_thread,
        &[access, 0, tid as u64, 0],
        timeout_ms,
    )?;
    if handle == 0 {
        return Err(GuestInjectError::Backend(format!(
            "OpenThread(tid={tid}, access={access:#x}) returned null"
        )));
    }
    Ok(handle)
}

pub fn guest_close_handle(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    handle: u64,
    hook: &GuestIatHook,
    timeout_ms: u32,
) {
    let close = resolve_import_symbol(backend, pid, "kernel32.dll", "CloseHandle").ok();
    if let Some(close_addr) = close {
        let _ = backend.call_iat_hook(pid, hook, close_addr, &[handle, 0, 0, 0], timeout_ms);
    }
}

pub fn guest_suspend_thread(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let handle = guest_open_thread(backend, pid, tid, THREAD_SUSPEND_RESUME, hook, timeout_ms)?;
    let suspend = resolve_import_symbol(backend, pid, "kernel32.dll", "SuspendThread")?;
    let _ = backend.call_iat_hook(pid, hook, suspend, &[handle, 0, 0, 0], timeout_ms)?;
    guest_close_handle(backend, pid, handle, hook, timeout_ms);
    Ok(())
}

pub fn guest_resume_thread(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let handle = guest_open_thread(backend, pid, tid, THREAD_SUSPEND_RESUME, hook, timeout_ms)?;
    let resume = resolve_import_symbol(backend, pid, "kernel32.dll", "ResumeThread")?;
    let _ = backend.call_iat_hook(pid, hook, resume, &[handle, 0, 0, 0], timeout_ms)?;
    guest_close_handle(backend, pid, handle, hook, timeout_ms);
    Ok(())
}

pub fn guest_terminate_thread(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    exit_code: u32,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let handle = guest_open_thread(backend, pid, tid, THREAD_TERMINATE, hook, timeout_ms)?;
    let terminate = resolve_import_symbol(backend, pid, "kernel32.dll", "TerminateThread")?;
    let ok = backend.call_iat_hook(
        pid,
        hook,
        terminate,
        &[handle, exit_code as u64, 0, 0],
        timeout_ms,
    )?;
    guest_close_handle(backend, pid, handle, hook, timeout_ms);
    if ok == 0 {
        return Err(GuestInjectError::Backend(format!(
            "TerminateThread(tid={tid}) returned FALSE"
        )));
    }
    Ok(())
}

fn context_to_bytes(ctx: &GuestThreadContext) -> [u8; CONTEXT_SIZE] {
    let mut buf = [0u8; CONTEXT_SIZE];
    buf[0x000..0x008].copy_from_slice(&ctx.p1_home.to_le_bytes());
    buf[0x008..0x010].copy_from_slice(&ctx.p2_home.to_le_bytes());
    buf[0x010..0x018].copy_from_slice(&ctx.p3_home.to_le_bytes());
    buf[0x018..0x020].copy_from_slice(&ctx.p4_home.to_le_bytes());
    buf[0x020..0x028].copy_from_slice(&ctx.p5_home.to_le_bytes());
    buf[0x028..0x030].copy_from_slice(&ctx.p6_home.to_le_bytes());
    buf[0x030..0x034].copy_from_slice(&ctx.context_flags.to_le_bytes());
    buf[0x034..0x038].copy_from_slice(&ctx.mx_csr.to_le_bytes());
    buf[0x038..0x03A].copy_from_slice(&ctx.seg_cs.to_le_bytes());
    buf[0x03A..0x03C].copy_from_slice(&ctx.seg_ds.to_le_bytes());
    buf[0x03C..0x03E].copy_from_slice(&ctx.seg_es.to_le_bytes());
    buf[0x03E..0x040].copy_from_slice(&ctx.seg_fs.to_le_bytes());
    buf[0x040..0x042].copy_from_slice(&ctx.seg_gs.to_le_bytes());
    buf[0x042..0x044].copy_from_slice(&ctx.seg_ss.to_le_bytes());
    buf[0x044..0x048].copy_from_slice(&ctx.eflags.to_le_bytes());
    buf[0x048..0x050].copy_from_slice(&ctx.dr0.to_le_bytes());
    buf[0x050..0x058].copy_from_slice(&ctx.dr1.to_le_bytes());
    buf[0x058..0x060].copy_from_slice(&ctx.dr2.to_le_bytes());
    buf[0x060..0x068].copy_from_slice(&ctx.dr3.to_le_bytes());
    buf[0x068..0x070].copy_from_slice(&ctx.dr6.to_le_bytes());
    buf[0x070..0x078].copy_from_slice(&ctx.dr7.to_le_bytes());
    buf[0x078..0x080].copy_from_slice(&ctx.rax.to_le_bytes());
    buf[0x080..0x088].copy_from_slice(&ctx.rcx.to_le_bytes());
    buf[0x088..0x090].copy_from_slice(&ctx.rdx.to_le_bytes());
    buf[0x090..0x098].copy_from_slice(&ctx.rbx.to_le_bytes());
    buf[0x098..0x0A0].copy_from_slice(&ctx.rsp.to_le_bytes());
    buf[0x0A0..0x0A8].copy_from_slice(&ctx.rbp.to_le_bytes());
    buf[0x0A8..0x0B0].copy_from_slice(&ctx.rsi.to_le_bytes());
    buf[0x0B0..0x0B8].copy_from_slice(&ctx.rdi.to_le_bytes());
    buf[0x0B8..0x0C0].copy_from_slice(&ctx.r8.to_le_bytes());
    buf[0x0C0..0x0C8].copy_from_slice(&ctx.r9.to_le_bytes());
    buf[0x0C8..0x0D0].copy_from_slice(&ctx.r10.to_le_bytes());
    buf[0x0D0..0x0D8].copy_from_slice(&ctx.r11.to_le_bytes());
    buf[0x0D8..0x0E0].copy_from_slice(&ctx.r12.to_le_bytes());
    buf[0x0E0..0x0E8].copy_from_slice(&ctx.r13.to_le_bytes());
    buf[0x0E8..0x0F0].copy_from_slice(&ctx.r14.to_le_bytes());
    buf[0x0F0..0x0F8].copy_from_slice(&ctx.r15.to_le_bytes());
    buf[0x0F8..0x100].copy_from_slice(&ctx.rip.to_le_bytes());
    buf
}

fn bytes_to_context(buf: &[u8]) -> Result<GuestThreadContext, GuestInjectError> {
    if buf.len() < 0x100 {
        return Err(GuestInjectError::Backend("CONTEXT buffer too short".into()));
    }
    let g = |off: usize| -> u64 { u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) };
    let gu16 = |off: usize| -> u16 { u16::from_le_bytes([buf[off], buf[off + 1]]) };
    let gu32 = |off: usize| -> u32 {
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    };
    Ok(GuestThreadContext {
        p1_home: g(0x000),
        p2_home: g(0x008),
        p3_home: g(0x010),
        p4_home: g(0x018),
        p5_home: g(0x020),
        p6_home: g(0x028),
        context_flags: gu32(0x030),
        mx_csr: gu32(0x034),
        seg_cs: gu16(0x038),
        seg_ds: gu16(0x03A),
        seg_es: gu16(0x03C),
        seg_fs: gu16(0x03E),
        seg_gs: gu16(0x040),
        seg_ss: gu16(0x042),
        eflags: gu32(0x044),
        dr0: g(0x048),
        dr1: g(0x050),
        dr2: g(0x058),
        dr3: g(0x060),
        dr6: g(0x068),
        dr7: g(0x070),
        rax: g(0x078),
        rcx: g(0x080),
        rdx: g(0x088),
        rbx: g(0x090),
        rsp: g(0x098),
        rbp: g(0x0A0),
        rsi: g(0x0A8),
        rdi: g(0x0B0),
        r8: g(0x0B8),
        r9: g(0x0C0),
        r10: g(0x0C8),
        r11: g(0x0D0),
        r12: g(0x0D8),
        r13: g(0x0E0),
        r14: g(0x0E8),
        r15: g(0x0F0),
        rip: g(0x0F8),
    })
}

pub fn guest_get_thread_context(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<GuestThreadContext, GuestInjectError> {
    guest_get_thread_context_with_flags(backend, pid, tid, hook, timeout_ms, CONTEXT_FULL_AMD64)
}

fn guest_get_thread_context_with_flags(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    hook: &GuestIatHook,
    timeout_ms: u32,
    context_flags: u32,
) -> Result<GuestThreadContext, GuestInjectError> {
    let handle = guest_open_thread(
        backend,
        pid,
        tid,
        THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
        hook,
        timeout_ms,
    )?;
    let suspend = resolve_import_symbol(backend, pid, "kernel32.dll", "SuspendThread")?;
    if let Err(e) = backend.call_iat_hook(pid, hook, suspend, &[handle, 0, 0, 0], timeout_ms) {
        guest_close_handle(backend, pid, handle, hook, timeout_ms);
        return Err(e);
    }

    let ctx = (|| {
        let virtual_alloc = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualAlloc")?;
        let buf_addr =
            allocate_helper_buffer(backend, pid, hook, virtual_alloc, CONTEXT_SIZE, timeout_ms)?;

        let mut ctx_buf = [0u8; CONTEXT_SIZE];
        ctx_buf[0x30..0x034].copy_from_slice(&context_flags.to_le_bytes());
        backend.write(pid, buf_addr, &ctx_buf)?;

        let get_ctx = resolve_import_symbol(backend, pid, "kernel32.dll", "GetThreadContext")?;
        let ok =
            backend.call_iat_hook(pid, hook, get_ctx, &[handle, buf_addr, 0, 0], timeout_ms)?;

        let ctx = if ok == 0 {
            Err(GuestInjectError::Backend(format!(
                "GetThreadContext(tid={tid}) returned FALSE"
            )))
        } else {
            let read_buf = backend.read(pid, buf_addr, CONTEXT_SIZE)?;
            bytes_to_context(&read_buf)
        };

        let virtual_free = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualFree")?;
        best_effort_virtual_free(backend, pid, hook, virtual_free, buf_addr, timeout_ms);
        ctx
    })();

    let resume_result = resolve_import_symbol(backend, pid, "kernel32.dll", "ResumeThread")
        .and_then(|resume| {
            backend
                .call_iat_hook(pid, hook, resume, &[handle, 0, 0, 0], timeout_ms)
                .map(|_| ())
        });
    if let Err(e) = &resume_result {
        tracing::warn!(pid, tid, error = %e, "GetThreadContext cleanup failed to resume thread");
    }
    guest_close_handle(backend, pid, handle, hook, timeout_ms);
    if ctx.is_ok() {
        resume_result?;
    }
    ctx
}

pub fn guest_set_thread_context(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    ctx: &GuestThreadContext,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    guest_set_thread_context_with_flags(
        backend,
        pid,
        tid,
        ctx,
        hook,
        timeout_ms,
        CONTEXT_FULL_AMD64,
    )
}

fn guest_set_thread_context_with_flags(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    ctx: &GuestThreadContext,
    hook: &GuestIatHook,
    timeout_ms: u32,
    context_flags: u32,
) -> Result<(), GuestInjectError> {
    let handle = guest_open_thread(
        backend,
        pid,
        tid,
        THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
        hook,
        timeout_ms,
    )?;
    let suspend = resolve_import_symbol(backend, pid, "kernel32.dll", "SuspendThread")?;
    if let Err(e) = backend.call_iat_hook(pid, hook, suspend, &[handle, 0, 0, 0], timeout_ms) {
        guest_close_handle(backend, pid, handle, hook, timeout_ms);
        return Err(e);
    }

    let result = (|| {
        let virtual_alloc = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualAlloc")?;
        let buf_addr =
            allocate_helper_buffer(backend, pid, hook, virtual_alloc, CONTEXT_SIZE, timeout_ms)?;

        let mut ctx_buf = context_to_bytes(ctx);
        ctx_buf[0x30..0x034].copy_from_slice(&context_flags.to_le_bytes());
        backend.write(pid, buf_addr, &ctx_buf)?;

        let set_ctx = resolve_import_symbol(backend, pid, "kernel32.dll", "SetThreadContext")?;
        let ok =
            backend.call_iat_hook(pid, hook, set_ctx, &[handle, buf_addr, 0, 0], timeout_ms)?;

        let virtual_free = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualFree")?;
        best_effort_virtual_free(backend, pid, hook, virtual_free, buf_addr, timeout_ms);

        if ok == 0 {
            return Err(GuestInjectError::Backend(format!(
                "SetThreadContext(tid={tid}) returned FALSE"
            )));
        }
        Ok(())
    })();

    let resume_result = resolve_import_symbol(backend, pid, "kernel32.dll", "ResumeThread")
        .and_then(|resume| {
            backend
                .call_iat_hook(pid, hook, resume, &[handle, 0, 0, 0], timeout_ms)
                .map(|_| ())
        });
    if let Err(e) = &resume_result {
        tracing::warn!(pid, tid, error = %e, "SetThreadContext cleanup failed to resume thread");
    }
    guest_close_handle(backend, pid, handle, hook, timeout_ms);
    if result.is_ok() {
        resume_result?;
    }
    result
}

pub fn guest_add_hwbp(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    bp: GuestHwbp,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<u8, GuestInjectError> {
    let hwbp_context_flags = CONTEXT_FULL_AMD64 | CONTEXT_DEBUG_REGISTERS_AMD64;
    let mut ctx = guest_get_thread_context_with_flags(
        backend,
        pid,
        tid,
        hook,
        timeout_ms,
        hwbp_context_flags,
    )?;
    let mut dr7 = ctx.dr7;
    for i in 0..4u8 {
        let enabled = (dr7 >> (2 * i as u64)) & 1;
        if enabled == 0 {
            let addr = match i {
                0 => &mut ctx.dr0,
                1 => &mut ctx.dr1,
                2 => &mut ctx.dr2,
                3 => &mut ctx.dr3,
                _ => unreachable!(),
            };
            *addr = bp.addr;
            let rw = match bp.kind {
                GuestHwbpType::Execute => 0u64,
                GuestHwbpType::Write => 1u64,
                GuestHwbpType::Access => 3u64,
            };
            let len = match bp.length {
                GuestHwbpLength::One => 0u64,
                GuestHwbpLength::Two => 1u64,
                GuestHwbpLength::Four => 3u64,
                GuestHwbpLength::Eight => 2u64,
            };
            let shift = 16 + 4 * i as u64;
            dr7 |= 1u64 << (2 * i as u64);
            dr7 &= !0xFu64 << shift;
            dr7 |= (rw | (len << 2)) << shift;
            ctx.dr7 = dr7;
            guest_set_thread_context_with_flags(
                backend,
                pid,
                tid,
                &ctx,
                hook,
                timeout_ms,
                hwbp_context_flags,
            )?;
            return Ok(i);
        }
    }
    Err(GuestInjectError::Backend(
        "all 4 hardware breakpoint slots are in use".into(),
    ))
}

pub fn guest_remove_hwbp(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    index: u8,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    if index > 3 {
        return Err(GuestInjectError::Backend(format!(
            "invalid HWBP index {index}; must be 0-3"
        )));
    }
    let hwbp_context_flags = CONTEXT_FULL_AMD64 | CONTEXT_DEBUG_REGISTERS_AMD64;
    let mut ctx = guest_get_thread_context_with_flags(
        backend,
        pid,
        tid,
        hook,
        timeout_ms,
        hwbp_context_flags,
    )?;
    match index {
        0 => ctx.dr0 = 0,
        1 => ctx.dr1 = 0,
        2 => ctx.dr2 = 0,
        3 => ctx.dr3 = 0,
        _ => unreachable!(),
    }
    ctx.dr7 &= !(1u64 << (2 * index as u64));
    ctx.dr7 &= !(0xFu64 << (16 + 4 * index as u64));
    guest_set_thread_context_with_flags(
        backend,
        pid,
        tid,
        &ctx,
        hook,
        timeout_ms,
        hwbp_context_flags,
    )
}

pub fn guest_unload_module(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    module_base: u64,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let free_library = resolve_import_symbol(backend, pid, "kernel32.dll", "FreeLibrary")?;
    let ok = backend.call_iat_hook(pid, hook, free_library, &[module_base, 0, 0, 0], timeout_ms)?;
    if ok == 0 {
        return Err(GuestInjectError::Backend(format!(
            "FreeLibrary({module_base:#x}) returned FALSE"
        )));
    }
    tracing::info!(
        pid,
        module_base = format_args!("{module_base:#x}"),
        "module unloaded via FreeLibrary"
    );
    Ok(())
}

fn guest_unload_module_full(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    record: &ModuleRecord,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let base = record.base;

    for callback in record.tls_callbacks.iter().rev() {
        tracing::info!(
            pid,
            callback = format_args!("{callback:#x}"),
            base = format_args!("{base:#x}"),
            "calling TLS callback with DLL_PROCESS_DETACH"
        );
        let _ = backend.call_iat_hook(pid, hook, *callback, &[base, 0, 0, 0], timeout_ms)?;
    }

    if record.entry_point != 0 {
        tracing::info!(
            pid,
            entry = format_args!("{:#x}", record.entry_point),
            base = format_args!("{base:#x}"),
            "calling DllMain with DLL_PROCESS_DETACH"
        );
        let ok =
            backend.call_iat_hook(pid, hook, record.entry_point, &[base, 0, 0, 0], timeout_ms)?;
        if ok == 0 {
            tracing::warn!(
                pid,
                base = format_args!("{base:#x}"),
                "DllMain(DETACH) returned FALSE; proceeding with cleanup"
            );
        }
    }

    for &(ft_addr, ft_count) in &record.function_tables {
        let rtl_delete_function_table =
            resolve_import_symbol(backend, pid, "kernel32.dll", "RtlDeleteFunctionTable").or_else(
                |_| resolve_import_symbol(backend, pid, "ntdll.dll", "RtlDeleteFunctionTable"),
            );
        match rtl_delete_function_table {
            Ok(f) => {
                let ok = backend.call_iat_hook(
                    pid,
                    hook,
                    f,
                    &[ft_addr, ft_count as u64, 0, 0],
                    timeout_ms,
                )?;
                if ok == 0 {
                    tracing::warn!(
                        pid,
                        ft_addr = format_args!("{ft_addr:#x}"),
                        "RtlDeleteFunctionTable returned FALSE"
                    );
                } else {
                    tracing::info!(
                        pid,
                        ft_addr = format_args!("{ft_addr:#x}"),
                        "function table deleted"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(pid, ft_addr = format_args!("{ft_addr:#x}"), error = %e, "could not resolve RtlDeleteFunctionTable")
            }
        }
    }

    if let Some(actctx) = record.actctx_handle {
        let cookie = record.actctx_cookie.unwrap_or(0);
        match resolve_import_symbol(backend, pid, "kernel32.dll", "DeactivateActCtx")
            .and_then(|f| backend.call_iat_hook(pid, hook, f, &[0, cookie, 0, 0], timeout_ms))
        {
            Ok(_) => {}
            Err(e) => tracing::warn!(pid, error = %e, "DeactivateActCtx failed during cleanup"),
        }
        match resolve_import_symbol(backend, pid, "kernel32.dll", "ReleaseActCtx")
            .and_then(|f| backend.call_iat_hook(pid, hook, f, &[actctx, 0, 0, 0], timeout_ms))
        {
            Ok(_) => {}
            Err(e) => tracing::warn!(pid, error = %e, "ReleaseActCtx failed during cleanup"),
        }
        tracing::info!(
            pid,
            actctx = format_args!("{actctx:#x}"),
            cookie = format_args!("{cookie:#x}"),
            "activation context deactivated and released"
        );
    }

    if let Some(peb_entry) = record.peb_loader_entry {
        if let Err(e) = unlink_synthesized_peb_loader_entry(backend, pid, peb_entry) {
            tracing::warn!(pid, peb_entry = format_args!("{peb_entry:#x}"), error = %e, "failed to unlink PEB loader entry during unload");
        } else {
            tracing::info!(
                pid,
                peb_entry = format_args!("{peb_entry:#x}"),
                "PEB loader entry unlinked"
            );
        }
    }

    match resolve_import_symbol(backend, pid, "kernel32.dll", "FreeLibrary") {
        Ok(free_library) => {
            for dep_base in record.dependencies.iter().rev() {
                match backend.call_iat_hook(
                    pid,
                    hook,
                    free_library,
                    &[*dep_base, 0, 0, 0],
                    timeout_ms,
                ) {
                    Ok(ok) if ok != 0 => tracing::info!(
                        pid,
                        dep_base = format_args!("{dep_base:#x}"),
                        "dependency freed"
                    ),
                    _ => tracing::warn!(
                        pid,
                        dep_base = format_args!("{dep_base:#x}"),
                        "FreeLibrary(dependency) returned FALSE"
                    ),
                }
            }
        }
        Err(e) => {
            tracing::warn!(pid, error = %e, "could not resolve FreeLibrary; skipping dependency free")
        }
    }

    for binding in &record.tls_slot_bindings {
        let current = read_remote_u64(backend, pid, binding.slot_addr)?;
        if current == 0 {
            continue;
        }
        if current == binding.value || record.tls_template_bufs.contains(&current) {
            backend.write(pid, binding.slot_addr, &0u64.to_le_bytes())?;
        } else {
            tracing::warn!(
                pid,
                slot_addr = format_args!("{:#x}", binding.slot_addr),
                current = format_args!("{current:#x}"),
                "tracked TLS slot no longer references a Decant allocation; leaving it untouched"
            );
        }
    }
    if !record.tls_slot_bindings.is_empty() {
        tracing::info!(
            pid,
            count = record.tls_slot_bindings.len(),
            "tracked TLS slot pointers cleared before template cleanup"
        );
    }

    match resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualFree") {
        Ok(virtual_free) => {
            for buf in &record.tls_template_bufs {
                let _ = backend.call_iat_hook(
                    pid,
                    hook,
                    virtual_free,
                    &[*buf, 0, MEM_RELEASE, 0],
                    timeout_ms,
                );
            }
            if !record.tls_template_bufs.is_empty() {
                tracing::info!(
                    pid,
                    count = record.tls_template_bufs.len(),
                    "TLS template buffers freed"
                );
            }
            if let Some(slot) = record.tls_slot {
                match resolve_import_symbol(backend, pid, "kernel32.dll", "TlsFree") {
                    Ok(tls_free) => {
                        let _ = backend.call_iat_hook(
                            pid,
                            hook,
                            tls_free,
                            &[slot as u64, 0, 0, 0],
                            timeout_ms,
                        );
                        tracing::info!(pid, slot, "TLS slot freed via TlsFree");
                    }
                    Err(e) => tracing::warn!(pid, slot, error = %e, "could not resolve TlsFree"),
                }
            }
            let released = backend.call_iat_hook(
                pid,
                hook,
                virtual_free,
                &[base, 0, MEM_RELEASE, 0],
                timeout_ms,
            )?;
            if released == 0 {
                return Err(GuestInjectError::Backend(format!(
                    "VirtualFree({base:#x}, MEM_RELEASE) returned FALSE during tracked unload"
                )));
            }
            tracing::info!(
                pid,
                base = format_args!("{base:#x}"),
                "module memory released"
            );
        }
        Err(e) => {
            tracing::warn!(pid, error = %e, "could not resolve VirtualFree; module memory not freed")
        }
    }
    Ok(())
}

pub fn unmap_all_modules(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<usize, GuestInjectError> {
    let registry = MANUAL_MODULE_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let keys: Vec<(u32, u64)> = {
        let reg = registry.lock().unwrap();
        reg.keys().filter(|(p, _)| *p == pid).copied().collect()
    };
    let mut count = 0;
    for key in keys {
        let record = {
            let reg = registry.lock().unwrap();
            reg.get(&key).cloned()
        };
        let Some(record) = record else { continue };
        match guest_unload_module_full(backend, pid, &record, hook, timeout_ms) {
            Ok(()) => {
                if let Some(reg) = MANUAL_MODULE_REGISTRY.get() {
                    if let Ok(mut reg) = reg.lock() {
                        reg.remove(&key);
                    }
                }
                count += 1;
            }
            Err(e) => {
                tracing::warn!(
                    pid,
                    base = format_args!("{:#x}", key.1),
                    error = %e,
                    "unload failed; module remains in registry for retry"
                );
            }
        }
    }
    tracing::info!(pid, modules_unmapped = count, "unmap_all_modules complete");
    Ok(count)
}

/// Removes every manual-mapped module tracked by this daemon for the configured target.
///
/// The configuration supplies the same target, staging, result-block, and hook settings used
/// for injection. `payload_path` is parsed as part of `GuestInjectionPlan`, but its file is not
/// read by this operation.
pub fn unmap_all_tracked_modules(
    backend: &dyn GuestMemoryBackend,
    plan: &GuestInjectionPlan,
) -> Result<(u32, usize), GuestInjectError> {
    let capabilities = backend.capabilities();
    let missing = capabilities.missing_manual_map();
    if !missing.is_empty() {
        return Err(GuestInjectError::Unsupported {
            operation: "guest module unload",
            reason: format!("manual-map method backend missing {}", missing.join(", ")),
        });
    }

    let process = backend.resolve_process(&plan.target)?;
    let _injection_lock = GuestInjectionLock::acquire(process.pid)?;

    let stage = match plan.stage_base {
        Some(base) => {
            validate_stub_region(backend, process.pid, base, STAGE_CAVE_SIZE)?;
            base
        }
        None => {
            let found = find_stage(backend, process.pid, plan.stage_pattern.as_ref())?;
            validate_stub_region(backend, process.pid, found, STAGE_CAVE_SIZE)?;
            found
        }
    };
    let result_addr = match plan.result_base {
        Some(base) => {
            validate_result_region(backend, process.pid, base)?;
            base
        }
        None => {
            let found = find_result_block(
                backend,
                process.pid,
                plan.result_pattern.as_ref(),
                stage + STAGE_RESULT_OFFSET,
            )?;
            validate_result_region(backend, process.pid, found)?;
            found
        }
    };
    let hook = select_execution_hook(
        backend,
        process.pid,
        plan,
        stage,
        result_addr,
        capabilities.independent_execution,
        capabilities.iat_hook_stage_restore,
    )?;

    if !capabilities.independent_execution {
        validate_guest_thread_start_policy(backend, process.pid, plan, stage, &hook)?;
    }
    let iat_stage_pool_base = if capabilities.independent_execution {
        None
    } else {
        let virtual_alloc =
            resolve_import_symbol(backend, process.pid, "kernel32.dll", "VirtualAlloc")?;
        Some(ensure_iat_stage_pool(
            backend,
            process.pid,
            &hook,
            virtual_alloc,
            plan.iat_stage_pool_slots,
            plan.execution.timeout_ms,
        )?)
    };
    if plan.call_stack == GuestCallStackPolicy::RegisteredUnwind {
        register_guest_stub_unwind(
            backend,
            process.pid,
            &hook,
            iat_stage_pool_base.unwrap_or(stage),
            plan.execution.timeout_ms,
        )?;
    }

    let count = unmap_all_modules(backend, process.pid, &hook, plan.execution.timeout_ms)?;
    Ok((process.pid, count))
}

pub const INLINE_JMP14_SIZE: usize = 14;

pub fn install_inline_hook(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    target_addr: u64,
    hook_addr: u64,
) -> Result<Vec<u8>, GuestInjectError> {
    let original = backend.read(pid, target_addr, INLINE_JMP14_SIZE)?;
    let mut patch = [0u8; INLINE_JMP14_SIZE];
    patch[0] = 0xFF;
    patch[1] = 0x25;
    patch[2..6].copy_from_slice(&0u32.to_le_bytes());
    patch[6..14].copy_from_slice(&hook_addr.to_le_bytes());
    backend.write(pid, target_addr, &patch)?;
    tracing::info!(
        pid,
        target = format_args!("{target_addr:#x}"),
        hook = format_args!("{hook_addr:#x}"),
        "inline hook installed (14-byte absolute JMP)"
    );
    Ok(original)
}

pub fn remove_inline_hook(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    target_addr: u64,
    original: &[u8],
) -> Result<(), GuestInjectError> {
    backend.write(pid, target_addr, original)?;
    tracing::info!(
        pid,
        target = format_args!("{target_addr:#x}"),
        bytes = original.len(),
        "inline hook removed, original bytes restored"
    );
    Ok(())
}

pub fn install_vtable_hook(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    vtable_ptr: u64,
    index: usize,
    new_func: u64,
) -> Result<u64, GuestInjectError> {
    let slot = vtable_ptr + (index as u64) * 8;
    let original_bytes = backend.read(pid, slot, 8)?;
    let original = u64::from_le_bytes(original_bytes[0..8].try_into().unwrap());
    backend.write(pid, slot, &new_func.to_le_bytes())?;
    tracing::info!(
        pid,
        vtable = format_args!("{vtable_ptr:#x}"),
        index,
        slot = format_args!("{slot:#x}"),
        original = format_args!("{original:#x}"),
        new = format_args!("{new_func:#x}"),
        "vtable hook installed"
    );
    Ok(original)
}

pub fn remove_vtable_hook(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    vtable_ptr: u64,
    index: usize,
    original: u64,
) -> Result<(), GuestInjectError> {
    let slot = vtable_ptr + (index as u64) * 8;
    backend.write(pid, slot, &original.to_le_bytes())?;
    tracing::info!(
        pid,
        vtable = format_args!("{vtable_ptr:#x}"),
        index,
        slot = format_args!("{slot:#x}"),
        "vtable hook removed, original restored"
    );
    Ok(())
}

pub fn guest_suspend_all_threads(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<usize, GuestInjectError> {
    let threads = backend.list_threads(pid)?;
    let mut count = 0;
    for t in &threads {
        if t.state == GuestThreadState::Terminated {
            continue;
        }
        match backend.suspend_thread(pid, t.tid, hook, timeout_ms) {
            Ok(()) => count += 1,
            Err(e) => {
                tracing::warn!(pid, tid = t.tid, error = %e, "suspend_all_threads: failed to suspend")
            }
        }
    }
    tracing::info!(pid, suspended = count, "suspend_all_threads complete");
    Ok(count)
}

pub fn guest_resume_all_threads(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<usize, GuestInjectError> {
    let threads = backend.list_threads(pid)?;
    let mut count = 0;
    for t in &threads {
        if t.state == GuestThreadState::Terminated {
            continue;
        }
        match backend.resume_thread(pid, t.tid, hook, timeout_ms) {
            Ok(()) => count += 1,
            Err(e) => {
                tracing::warn!(pid, tid = t.tid, error = %e, "resume_all_threads: failed to resume")
            }
        }
    }
    tracing::info!(pid, resumed = count, "resume_all_threads complete");
    Ok(count)
}

pub fn guest_terminate_process(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    exit_code: u32,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let open_process = resolve_import_symbol(backend, pid, "kernel32.dll", "OpenProcess")?;
    let handle = backend.call_iat_hook(
        pid,
        hook,
        open_process,
        &[PROCESS_TERMINATE_ACCESS, 0, pid as u64, 0],
        timeout_ms,
    )?;
    if handle == 0 {
        return Err(GuestInjectError::Backend(format!(
            "OpenProcess(pid={pid}, PROCESS_TERMINATE) returned null"
        )));
    }
    let terminate = resolve_import_symbol(backend, pid, "kernel32.dll", "TerminateProcess")?;
    let ok = backend.call_iat_hook(
        pid,
        hook,
        terminate,
        &[handle, exit_code as u64, 0, 0],
        timeout_ms,
    )?;
    guest_close_handle(backend, pid, handle, hook, timeout_ms);
    if ok == 0 {
        return Err(GuestInjectError::Backend(format!(
            "TerminateProcess(pid={pid}) returned FALSE"
        )));
    }
    tracing::info!(pid, exit_code, "process terminated");
    Ok(())
}

pub fn guest_ensure_init(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let load_library = resolve_import_symbol(backend, pid, "kernel32.dll", "LoadLibraryA")?;
    let virtual_alloc = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualAlloc")?;
    let buf = allocate_helper_buffer(backend, pid, hook, virtual_alloc, 1, timeout_ms)?;
    let null_byte = [0u8];
    backend.write(pid, buf, &null_byte)?;
    let result = backend.call_iat_hook(pid, hook, load_library, &[buf, 0, 0, 0], timeout_ms)?;
    let virtual_free = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualFree")?;
    best_effort_virtual_free(backend, pid, hook, virtual_free, buf, timeout_ms);
    tracing::info!(
        pid,
        result = format_args!("{result:#x}"),
        "ensure_init: LoadLibraryA(NULL) called to force loader initialization"
    );
    Ok(())
}

pub fn guest_create_actctx(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    manifest_path_remote: u64,
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    let create_actctx = resolve_import_symbol(backend, pid, "kernel32.dll", "CreateActCtxW")?;
    let virtual_alloc = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualAlloc")?;
    let actctx_size = 0x40;
    let actctx_buf =
        allocate_helper_buffer(backend, pid, hook, virtual_alloc, actctx_size, timeout_ms)?;
    let mut actctx = vec![0u8; actctx_size];
    actctx[0..4].copy_from_slice(&actctx_size.to_le_bytes());
    actctx[4..8].copy_from_slice(&0u32.to_le_bytes());
    actctx[8..12].copy_from_slice(&0x0010u32.to_le_bytes());
    actctx[16..24].copy_from_slice(&manifest_path_remote.to_le_bytes());
    backend.write(pid, actctx_buf, &actctx)?;
    let handle =
        backend.call_iat_hook(pid, hook, create_actctx, &[actctx_buf, 0, 0, 0], timeout_ms)?;
    let virtual_free = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualFree")?;
    best_effort_virtual_free(backend, pid, hook, virtual_free, actctx_buf, timeout_ms);
    if handle == u64::MAX {
        return Err(GuestInjectError::Backend(
            "CreateActCtxW returned INVALID_HANDLE_VALUE".into(),
        ));
    }
    tracing::info!(
        pid,
        handle = format_args!("{handle:#x}"),
        "activation context created"
    );
    Ok(handle)
}

fn guest_create_module_actctx(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    module_base: u64,
    resource_id: u32,
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    let create_actctx = resolve_import_symbol(backend, pid, "kernel32.dll", "CreateActCtxW")?;
    let virtual_alloc = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualAlloc")?;
    let actctx_struct_size: u32 = 56;
    let actctx_buf = allocate_helper_buffer(
        backend,
        pid,
        hook,
        virtual_alloc,
        actctx_struct_size as usize,
        timeout_ms,
    )?;
    let flags: u32 = 0x008 | 0x080;
    let mut actctx = vec![0u8; actctx_struct_size as usize];
    actctx[0..4].copy_from_slice(&actctx_struct_size.to_le_bytes());
    actctx[4..8].copy_from_slice(&flags.to_le_bytes());
    actctx[32..40].copy_from_slice(&(resource_id as u64).to_le_bytes());
    actctx[48..56].copy_from_slice(&module_base.to_le_bytes());
    backend.write(pid, actctx_buf, &actctx)?;
    let handle =
        backend.call_iat_hook(pid, hook, create_actctx, &[actctx_buf, 0, 0, 0], timeout_ms)?;
    let virtual_free = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualFree")?;
    best_effort_virtual_free(backend, pid, hook, virtual_free, actctx_buf, timeout_ms);
    if handle == u64::MAX {
        return Err(GuestInjectError::Backend(
            "CreateActCtxW(HMODULE) returned INVALID_HANDLE_VALUE".into(),
        ));
    }
    tracing::info!(
        pid,
        handle = format_args!("{handle:#x}"),
        module_base = format_args!("{module_base:#x}"),
        resource_id,
        "activation context created from module resources"
    );
    Ok(handle)
}

fn guest_release_actctx(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    handle: u64,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let release = resolve_import_symbol(backend, pid, "kernel32.dll", "ReleaseActCtx")?;
    let _ = backend.call_iat_hook(pid, hook, release, &[handle, 0, 0, 0], timeout_ms)?;
    tracing::info!(
        pid,
        handle = format_args!("{handle:#x}"),
        "activation context released"
    );
    Ok(())
}

fn guest_release_module_actctx(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    handle: u64,
    cookie_buf: u64,
    timeout_ms: u32,
) {
    let _ = guest_release_actctx(backend, pid, hook, handle, timeout_ms);
    let virtual_free = match resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualFree") {
        Ok(f) => f,
        Err(_) => return,
    };
    best_effort_virtual_free(backend, pid, hook, virtual_free, cookie_buf, timeout_ms);
}

pub fn guest_call_remote(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    func_addr: u64,
    args: &[u64],
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    if args.len() > 16 {
        return Err(GuestInjectError::Unsupported {
            operation: "remote call",
            reason: format!("{} args exceeds the 16-arg limit", args.len()),
        });
    }
    let mut padded: Vec<u64> = args.to_vec();
    while padded.len() < 4 {
        padded.push(0);
    }
    backend.call_iat_hook(pid, hook, func_addr, &padded, timeout_ms)
}

const PROCESS_TERMINATE_ACCESS: u64 = 0x0001;
#[allow(dead_code)]
const PROCESS_CREATE_THREAD_ACCESS: u64 = 0x0002;
#[allow(dead_code)]
const PROCESS_VM_OPERATION_ACCESS: u64 = 0x0008;
#[allow(dead_code)]
const PROCESS_VM_WRITE_ACCESS: u64 = 0x0020;
#[allow(dead_code)]
const PROCESS_QUERY_INFORMATION_ACCESS: u64 = 0x0400;
#[allow(dead_code)]
const PROCESS_ALL_ACCESS: u64 = 0x1F0FFF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestRemoteContext {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
    pub rsp: u64,
    pub rip: u64,
    pub return_address: u64,
    pub last_error: u32,
}

pub fn read_remote_context(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<GuestRemoteContext, GuestInjectError> {
    let ctx = backend.get_thread_context(pid, tid, hook, timeout_ms)?;
    let teb = backend.read_teb(pid, tid)?;
    let return_address_bytes = backend.read(pid, ctx.rsp, 8)?;
    let return_address = u64::from_le_bytes(return_address_bytes[0..8].try_into().unwrap());
    Ok(GuestRemoteContext {
        rax: ctx.rax,
        rcx: ctx.rcx,
        rdx: ctx.rdx,
        r8: ctx.r8,
        r9: ctx.r9,
        rsp: ctx.rsp,
        rip: ctx.rip,
        return_address,
        last_error: teb.last_error_value,
    })
}

pub fn set_remote_return_value(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    value: u64,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let ctx = backend.get_thread_context(pid, tid, hook, timeout_ms)?;
    let mut new_ctx = ctx;
    new_ctx.rax = value;
    backend.set_thread_context(pid, tid, &new_ctx, hook, timeout_ms)
}

pub fn set_remote_return_address(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    return_addr: u64,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    let ctx = backend.get_thread_context(pid, tid, hook, timeout_ms)?;
    backend.write(pid, ctx.rsp, &return_addr.to_le_bytes())?;
    tracing::info!(
        pid,
        tid,
        return_addr = format_args!("{return_addr:#x}"),
        "return address overwritten"
    );
    Ok(())
}

pub fn set_remote_arg(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    index: u8,
    value: u64,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<(), GuestInjectError> {
    if index > 15 {
        return Err(GuestInjectError::Backend(format!(
            "arg index {index} out of range (0-15)"
        )));
    }
    let ctx = backend.get_thread_context(pid, tid, hook, timeout_ms)?;
    let mut new_ctx = ctx;
    match index {
        0 => new_ctx.rcx = value,
        1 => new_ctx.rdx = value,
        2 => new_ctx.r8 = value,
        3 => new_ctx.r9 = value,
        n => {
            let stack_offset = (n - 3) as u64 * 8;
            backend.write(pid, ctx.rsp + stack_offset, &value.to_le_bytes())?;
            return Ok(());
        }
    }
    backend.set_thread_context(pid, tid, &new_ctx, hook, timeout_ms)
}

#[derive(Clone, Debug)]
pub struct GuestTracePath {
    pub nodes: Vec<GuestTraceNode>,
}

#[derive(Clone, Copy, Debug)]
pub struct GuestTraceNode {
    pub addr: u64,
    pub is_call: bool,
    pub is_return: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn install_trace_hook(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    path: &GuestTracePath,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<u8, GuestInjectError> {
    if path.nodes.is_empty() {
        return Err(GuestInjectError::Backend("trace path is empty".into()));
    }
    let first = path.nodes[0];
    let bp = GuestHwbp {
        addr: first.addr,
        kind: GuestHwbpType::Execute,
        length: GuestHwbpLength::One,
    };
    let idx = backend.add_hwbp(pid, tid, bp, hook, timeout_ms)?;
    tracing::info!(
        pid,
        tid,
        hwbp_index = idx,
        target = format_args!("{:#x}", first.addr),
        path_len = path.nodes.len(),
        "trace hook installed at first path node"
    );
    Ok(idx)
}

#[allow(clippy::too_many_arguments)]
pub fn advance_trace_hook(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    tid: u32,
    current_index: u8,
    path: &GuestTracePath,
    step: usize,
    hook: &GuestIatHook,
    timeout_ms: u32,
) -> Result<Option<u8>, GuestInjectError> {
    backend.remove_hwbp(pid, tid, current_index, hook, timeout_ms)?;
    let next = step + 1;
    if next >= path.nodes.len() {
        tracing::info!(pid, tid, step = next, "trace path complete");
        return Ok(None);
    }
    let node = path.nodes[next];
    let bp = GuestHwbp {
        addr: node.addr,
        kind: GuestHwbpType::Execute,
        length: GuestHwbpLength::One,
    };
    let idx = backend.add_hwbp(pid, tid, bp, hook, timeout_ms)?;
    tracing::info!(
        pid,
        tid,
        hwbp_index = idx,
        target = format_args!("{:#x}", node.addr),
        step = next,
        "trace hook advanced to next path node"
    );
    Ok(Some(idx))
}

#[allow(clippy::too_many_arguments)]
pub fn guest_inject_pure_il(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    stage: u64,
    net_version: &str,
    assembly_path_remote: u64,
    class_name_remote: u64,
    method_name_remote: u64,
    args_remote: u64,
    timeout_ms: u32,
) -> Result<u32, GuestInjectError> {
    let virtual_alloc = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualAlloc")?;
    let virtual_free = resolve_import_symbol(backend, pid, "kernel32.dll", "VirtualFree")?;
    let load_library = resolve_import_symbol(backend, pid, "kernel32.dll", "LoadLibraryA")?;
    let get_proc_address = resolve_import_symbol(backend, pid, "kernel32.dll", "GetProcAddress")?;

    let mut bufs: Vec<u64> = Vec::new();
    let mut interfaces: Vec<(u64, u64)> = Vec::new();

    let result = (|| -> Result<u32, GuestInjectError> {
        let mscoree_name =
            allocate_helper_buffer(backend, pid, hook, virtual_alloc, 12, timeout_ms)?;
        bufs.push(mscoree_name);
        backend.write(pid, mscoree_name, b"mscoree.dll\0")?;
        let mscoree_handle = backend.call_iat_hook(
            pid,
            hook,
            load_library,
            &[mscoree_name, 0, 0, 0],
            timeout_ms,
        )?;
        if mscoree_handle == 0 {
            return Err(GuestInjectError::Backend(
                "LoadLibraryA(\"mscoree.dll\") returned null; .NET runtime may not be installed"
                    .into(),
            ));
        }

        let clr_create_name =
            allocate_helper_buffer(backend, pid, hook, virtual_alloc, 18, timeout_ms)?;
        bufs.push(clr_create_name);
        backend.write(pid, clr_create_name, b"CLRCreateInstance\0")?;
        let clr_create = backend.call_iat_hook(
            pid,
            hook,
            get_proc_address,
            &[mscoree_handle, clr_create_name, 0, 0],
            timeout_ms,
        )?;
        if clr_create == 0 {
            return Err(GuestInjectError::Backend(
                "GetProcAddress(mscoree.dll, \"CLRCreateInstance\") returned null".into(),
            ));
        }

        let clsid_meta_host = GUID {
            data1: 0x9280188D,
            data2: 0x0E8E,
            data3: 0x4867,
            data4: [0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE],
        };
        let iid_meta_host = GUID {
            data1: 0xD332DB9E,
            data2: 0xB9B3,
            data3: 0x4125,
            data4: [0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16],
        };
        let iid_runtime_info = GUID {
            data1: 0xBD39D1D2,
            data2: 0xBA2F,
            data3: 0x486A,
            data4: [0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91],
        };
        let clsid_runtime_host = GUID {
            data1: 0x90F1A06E,
            data2: 0x7712,
            data3: 0x4762,
            data4: [0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02],
        };
        let iid_runtime_host = GUID {
            data1: 0x90F1A06C,
            data2: 0x7712,
            data3: 0x4762,
            data4: [0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02],
        };

        let clsid_meta_host_buf =
            allocate_helper_buffer(backend, pid, hook, virtual_alloc, 16, timeout_ms)?;
        bufs.push(clsid_meta_host_buf);
        backend.write(pid, clsid_meta_host_buf, &clsid_meta_host.to_bytes())?;
        let iid_meta_host_buf =
            allocate_helper_buffer(backend, pid, hook, virtual_alloc, 16, timeout_ms)?;
        bufs.push(iid_meta_host_buf);
        backend.write(pid, iid_meta_host_buf, &iid_meta_host.to_bytes())?;
        let iid_runtime_info_buf =
            allocate_helper_buffer(backend, pid, hook, virtual_alloc, 16, timeout_ms)?;
        bufs.push(iid_runtime_info_buf);
        backend.write(pid, iid_runtime_info_buf, &iid_runtime_info.to_bytes())?;
        let clsid_runtime_host_buf =
            allocate_helper_buffer(backend, pid, hook, virtual_alloc, 16, timeout_ms)?;
        bufs.push(clsid_runtime_host_buf);
        backend.write(pid, clsid_runtime_host_buf, &clsid_runtime_host.to_bytes())?;
        let iid_runtime_host_buf =
            allocate_helper_buffer(backend, pid, hook, virtual_alloc, 16, timeout_ms)?;
        bufs.push(iid_runtime_host_buf);
        backend.write(pid, iid_runtime_host_buf, &iid_runtime_host.to_bytes())?;

        let meta_host_ppv =
            allocate_helper_buffer(backend, pid, hook, virtual_alloc, 8, timeout_ms)?;
        bufs.push(meta_host_ppv);
        let runtime_info_ppv =
            allocate_helper_buffer(backend, pid, hook, virtual_alloc, 8, timeout_ms)?;
        bufs.push(runtime_info_ppv);
        let runtime_host_ppv =
            allocate_helper_buffer(backend, pid, hook, virtual_alloc, 8, timeout_ms)?;
        bufs.push(runtime_host_ppv);
        let retval_buf = allocate_helper_buffer(backend, pid, hook, virtual_alloc, 4, timeout_ms)?;
        bufs.push(retval_buf);

        let mut version_wide: Vec<u16> = net_version.encode_utf16().collect();
        version_wide.push(0);
        let version_bytes: Vec<u8> = version_wide.iter().flat_map(|w| w.to_le_bytes()).collect();
        let version_remote = allocate_helper_buffer(
            backend,
            pid,
            hook,
            virtual_alloc,
            version_bytes.len(),
            timeout_ms,
        )?;
        bufs.push(version_remote);
        backend.write(pid, version_remote, &version_bytes)?;

        let hr = backend.call_iat_hook(
            pid,
            hook,
            clr_create,
            &[clsid_meta_host_buf, iid_meta_host_buf, meta_host_ppv, 0],
            timeout_ms,
        )?;
        if hr as i32 != S_OK {
            return Err(GuestInjectError::Backend(format!(
                "CLRCreateInstance returned HRESULT {:#x}",
                hr as i32
            )));
        }
        let meta_host = read_remote_u64(backend, pid, meta_host_ppv)?;
        if meta_host == 0 {
            return Err(GuestInjectError::Backend(
                "CLRCreateInstance set *ppv = NULL".into(),
            ));
        }
        let meta_vtable = read_remote_u64(backend, pid, meta_host)?;
        interfaces.push((meta_host, meta_vtable));

        let get_runtime = read_remote_u64(backend, pid, meta_vtable + 3 * 8)?;
        let hr = backend.call_iat_hook(
            pid,
            hook,
            get_runtime,
            &[
                meta_host,
                version_remote,
                iid_runtime_info_buf,
                runtime_info_ppv,
            ],
            timeout_ms,
        )?;
        if hr as i32 != S_OK {
            return Err(GuestInjectError::Backend(format!(
                "ICLRMetaHost::GetRuntime returned HRESULT {:#x}",
                hr as i32
            )));
        }
        let runtime_info = read_remote_u64(backend, pid, runtime_info_ppv)?;
        if runtime_info == 0 {
            return Err(GuestInjectError::Backend(
                "ICLRMetaHost::GetRuntime set *ppv = NULL".into(),
            ));
        }
        let runtime_info_vtable = read_remote_u64(backend, pid, runtime_info)?;
        interfaces.push((runtime_info, runtime_info_vtable));

        let get_interface = read_remote_u64(backend, pid, runtime_info_vtable + 9 * 8)?;
        let hr = backend.call_iat_hook(
            pid,
            hook,
            get_interface,
            &[
                runtime_info,
                clsid_runtime_host_buf,
                iid_runtime_host_buf,
                runtime_host_ppv,
            ],
            timeout_ms,
        )?;
        if hr as i32 != S_OK {
            return Err(GuestInjectError::Backend(format!(
                "ICLRRuntimeInfo::GetInterface returned HRESULT {:#x}",
                hr as i32
            )));
        }
        let runtime_host = read_remote_u64(backend, pid, runtime_host_ppv)?;
        if runtime_host == 0 {
            return Err(GuestInjectError::Backend(
                "ICLRRuntimeInfo::GetInterface set *ppv = NULL".into(),
            ));
        }
        let runtime_host_vtable = read_remote_u64(backend, pid, runtime_host)?;
        interfaces.push((runtime_host, runtime_host_vtable));

        let start_method = read_remote_u64(backend, pid, runtime_host_vtable + 3 * 8)?;
        let start_hr = backend.call_iat_hook(
            pid,
            hook,
            start_method,
            &[runtime_host, 0, 0, 0],
            timeout_ms,
        )?;
        if start_hr as i32 != S_OK {
            return Err(GuestInjectError::Backend(format!(
                "ICLRRuntimeHost::Start returned HRESULT {:#x}",
                start_hr as i32
            )));
        }

        let execute_method = read_remote_u64(backend, pid, runtime_host_vtable + 11 * 8)?;
        let trampoline = stage + STAGE_TRAMPOLINE_OFFSET;
        let param_block = stage + STAGE_PARAM_OFFSET;
        let saved_trampoline = backend.read(pid, trampoline, GUEST_PROC_TRAMPOLINE.len())?;
        write_verified(
            backend,
            pid,
            trampoline,
            GUEST_PROC_TRAMPOLINE,
            "CLR ExecuteInDefaultAppDomain trampoline",
        )?;
        let execute_result = call_guest_proc(
            backend,
            pid,
            hook,
            trampoline,
            param_block,
            execute_method,
            &[
                runtime_host,
                assembly_path_remote,
                class_name_remote,
                method_name_remote,
                args_remote,
                retval_buf,
            ],
            timeout_ms,
            "ICLRRuntimeHost::ExecuteInDefaultAppDomain",
        );
        if let Err(error) = backend.write(pid, trampoline, &saved_trampoline) {
            return Err(GuestInjectError::Backend(format!(
                "failed restoring CLR execution trampoline: {error}"
            )));
        }
        let execute_hr = execute_result?;
        if execute_hr as i32 != S_OK {
            return Err(GuestInjectError::Backend(format!(
                "ICLRRuntimeHost::ExecuteInDefaultAppDomain returned HRESULT {:#x}",
                execute_hr as i32
            )));
        }

        let retval = read_remote_u32(backend, pid, retval_buf)?;
        tracing::info!(
            pid,
            net_version,
            runtime_host = format_args!("{runtime_host:#x}"),
            assembly = format_args!("{assembly_path_remote:#x}"),
            retval,
            "CLR hosted assembly executed"
        );
        Ok(retval)
    })();

    for &(ptr, vtable) in interfaces.iter().rev() {
        if let Ok(release_fn) = read_remote_u64(backend, pid, vtable + 2 * 8) {
            let _ = backend.call_iat_hook(pid, hook, release_fn, &[ptr, 0, 0, 0], timeout_ms);
        }
    }
    for &buf in &bufs {
        best_effort_virtual_free(backend, pid, hook, virtual_free, buf, timeout_ms);
    }

    result
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
    reserved_arg_remote: u64,
    dllmain_tls: Option<DllMainThreadTls>,
    dllmain_actctx: Option<DllMainActCtx>,
    thread_starts: GuestThreadStartPolicy,
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
        &[
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
            reserved_arg_remote,
            exit_code_slot,
            status_slot,
            dllmain_tls,
            dllmain_actctx,
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
            if thread_starts == GuestThreadStartPolicy::RequireModuleBacked {
                best_effort_virtual_free(backend, pid, hook, virtual_free, scratch, timeout_ms);
                return Err(GuestInjectError::Backend(
                    "remote-thread requires an executable payload-image code cave for the in-image DllMain thunk; the payload must contain at least one executable section with sufficient zero-padded alignment space".into(),
                ));
            }
            scratch_region[..thunk_code_size].copy_from_slice(REMOTE_THREAD_DLLMAIN_THUNK);
            tracing::info!(
                pid,
                thunk_addr = format_args!("{scratch:#x}"),
                entry_point = format_args!("{entry_point:#x}"),
                "remote-thread: no payload-image code cave available; using temporary ThreadProc thunk"
            );
            (scratch, "temporary executable helper allocation")
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
                    &[thread_handle, 0, 0, 0],
                    timeout_ms,
                );
                best_effort_virtual_free(backend, pid, hook, virtual_free, scratch, timeout_ms);
                return Err(err);
            }
        };
    let _ = backend.call_iat_hook(
        pid,
        hook,
        close_handle,
        &[thread_handle, 0, 0, 0],
        timeout_ms,
    );
    best_effort_virtual_free(backend, pid, hook, virtual_free, scratch, timeout_ms);
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
    high_memory: bool,
    timeout_ms: u32,
) -> Result<u64, GuestInjectError> {
    let size = pe.size_of_image as u64;
    let try_alloc = |addr: u64| {
        backend.call_iat_hook(
            pid,
            hook,
            virtual_alloc,
            &[addr, size, MEM_COMMIT_RESERVE, allocation_protection],
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
                let candidate = random_base_address(high_memory);
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
    let metadata = stub_unwind_metadata(iat_stage_pool_slot_count(pid, hook)?)?;
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
        &[metadata_addr, 1, stage, 0],
        timeout_ms,
    )?;
    if ok == 0 {
        return Err(GuestInjectError::Backend(format!(
            "guest RtlAddFunctionTable({metadata_addr:#x}, 1, {stage:#x}) returned FALSE"
        )));
    }
    Ok(())
}

fn stub_unwind_metadata(stage_pool_slots: Option<u32>) -> Result<Vec<u8>, GuestInjectError> {
    let (begin, end) = match stage_pool_slots {
        Some(slots) if slots > 1 => {
            let begin = (STAGE_CAVE_SIZE as u64)
                .checked_add(STAGE_STUB_OFFSET)
                .ok_or_else(|| {
                    GuestInjectError::Image("IAT stage-pool unwind begin overflows".into())
                })?;
            let end = u64::from(slots)
                .checked_mul(STAGE_CAVE_SIZE as u64)
                .ok_or_else(|| {
                    GuestInjectError::Image("IAT stage-pool unwind end overflows".into())
                })?;
            (begin, end)
        }
        Some(_) => {
            return Err(GuestInjectError::Config(
                "call_stack=registered-unwind requires at least two guest.iat_stage_pool_slots"
                    .into(),
            ));
        }
        None => (STAGE_STUB_OFFSET, STAGE_SCRATCH_OFFSET),
    };
    let begin = u32::try_from(begin)
        .map_err(|_| GuestInjectError::Image("stub begin RVA exceeds u32".into()))?;
    let end = u32::try_from(end)
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
        &[function_table, u64::from(entry_count), remote_base, 0],
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
const REMOTE_THREAD_PARAM_OFFSET: u64 = 0x100;
const REMOTE_THREAD_PARAM_SIZE: usize = 0x68;
const DLLMAIN_STATUS_COMPLETE: u32 = 1;
const DLLMAIN_STATUS_ACTCTX_ACTIVATION_FAILED: u32 = 2;
const REMOTE_THREAD_EXIT_CODE_OFFSET: u64 = 0x180;
const REMOTE_THREAD_STATUS_OFFSET: u64 = 0x188;
const REMOTE_THREAD_THREAD_ID_OFFSET: u64 = 0x190;

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
    0x48, 0x8B, 0x43, 0x30, // mov rax, [rbx+0x30] (optional TlsSetValue)
    0x48, 0x85, 0xC0, // test rax, rax
    0x74, 0x09, // je +9
    0x8B, 0x4B, 0x38, // mov ecx, [rbx+0x38] (TLS slot)
    0x48, 0x8B, 0x53, 0x40, // mov rdx, [rbx+0x40] (TLS value)
    0xFF, 0xD0, // call rax
    0x48, 0x8B, 0x43, 0x48, // mov rax, [rbx+0x48] (optional ActivateActCtx)
    0x48, 0x85, 0xC0, // test rax, rax
    0x74, 0x2A, // je DllMain
    0x48, 0x8B, 0x4B, 0x58, // mov rcx, [rbx+0x58] (ACTCTX handle)
    0x48, 0x8B, 0x53, 0x60, // mov rdx, [rbx+0x60] (cookie address)
    0xFF, 0xD0, // call rax
    0x85, 0xC0, // test eax, eax
    0x75, 0x1C, // jne DllMain
    0x4C, 0x8B, 0x53, 0x20, // mov r10, [rbx+0x20]
    0x41, 0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [r10], 0
    0x4C, 0x8B, 0x53, 0x28, // mov r10, [rbx+0x28]
    0x41, 0xC7, 0x02, 0x02, 0x00, 0x00, 0x00, // mov dword ptr [r10], 2
    0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
    0x5B, // pop rbx
    0xC3, // ret
    0x48, 0x8B, 0x03, // mov rax, [rbx]
    0x48, 0x8B, 0x4B, 0x08, // mov rcx, [rbx+8]
    0x48, 0x8B, 0x53, 0x10, // mov rdx, [rbx+0x10]
    0x4C, 0x8B, 0x43, 0x18, // mov r8, [rbx+0x18]
    0xFF, 0xD0, // call rax
    0x4C, 0x8B, 0x53, 0x20, // mov r10, [rbx+0x20]
    0x41, 0x89, 0x02, // mov [r10], eax
    0x48, 0x8B, 0x43, 0x50, // mov rax, [rbx+0x50] (optional DeactivateActCtx)
    0x48, 0x85, 0xC0, // test rax, rax
    0x74, 0x0B, // je completion
    0x31, 0xC9, // xor ecx, ecx
    0x48, 0x8B, 0x53, 0x60, // mov rdx, [rbx+0x60] (cookie address)
    0x48, 0x8B, 0x12, // mov rdx, [rdx] (activation cookie)
    0xFF, 0xD0, // call rax
    0x4C, 0x8B, 0x53, 0x28, // mov r10, [rbx+0x28]
    0x41, 0xC7, 0x02, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [r10], 1
    0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
    0x5B, // pop rbx
    0xC3, // ret
];

const THREAD_HIJACK_THUNK: &[u8] = &[
    // RBX is the parameter-block pointer. The hijacked thread keeps its original RSP until
    // this thunk returns, so dynamically align it before calling into arbitrary payload code.
    0x48, 0x83, 0xE4, 0xF0, // and rsp, -16
    0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
    0x48, 0x8B, 0x43, 0x30, // mov rax, [rbx+0x30] (optional TlsSetValue)
    0x48, 0x85, 0xC0, // test rax, rax
    0x74, 0x09, // je +9
    0x8B, 0x4B, 0x38, // mov ecx, [rbx+0x38] (TLS slot)
    0x48, 0x8B, 0x53, 0x40, // mov rdx, [rbx+0x40] (TLS value)
    0xFF, 0xD0, // call rax
    0x48, 0x8B, 0x83, 0xD8, 0x00, 0x00, 0x00, // mov rax, [rbx+0xd8] (ActivateActCtx)
    0x48, 0x85, 0xC0, // test rax, rax
    0x74, 0x2F, // je DllMain
    0x48, 0x8B, 0x8B, 0xE8, 0x00, 0x00, 0x00, // mov rcx, [rbx+0xe8] (ACTCTX handle)
    0x48, 0x8B, 0x93, 0xF0, 0x00, 0x00, 0x00, // mov rdx, [rbx+0xf0] (cookie address)
    0xFF, 0xD0, // call rax
    0x85, 0xC0, // test eax, eax
    0x75, 0x1B, // jne DllMain
    0x4C, 0x8B, 0x53, 0x20, // mov r10, [rbx+0x20]
    0x41, 0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [r10], 0
    0x4C, 0x8B, 0x53, 0x28, // mov r10, [rbx+0x28]
    0x41, 0xC7, 0x02, 0x02, 0x00, 0x00, 0x00, // mov dword ptr [r10], 2
    0xE9, 0x3D, 0x00, 0x00, 0x00, // jmp to the interrupted-context restore path
    0x48, 0x8B, 0x03, // mov rax, [rbx]
    0x48, 0x8B, 0x4B, 0x08, // mov rcx, [rbx+8]
    0x48, 0x8B, 0x53, 0x10, // mov rdx, [rbx+0x10]
    0x4C, 0x8B, 0x43, 0x18, // mov r8, [rbx+0x18]
    0xFF, 0xD0, // call rax
    0x4C, 0x8B, 0x53, 0x20, // mov r10, [rbx+0x20]
    0x41, 0x89, 0x02, // mov [r10], eax
    0x48, 0x8B, 0x83, 0xE0, 0x00, 0x00, 0x00, // mov rax, [rbx+0xe0] (DeactivateActCtx)
    0x48, 0x85, 0xC0, // test rax, rax
    0x74, 0x0E, // je completion
    0x31, 0xC9, // xor ecx, ecx
    0x48, 0x8B, 0x93, 0xF0, 0x00, 0x00, 0x00, // mov rdx, [rbx+0xf0] (cookie address)
    0x48, 0x8B, 0x12, // mov rdx, [rdx] (activation cookie)
    0xFF, 0xD0, // call rax
    0x4C, 0x8B, 0x53, 0x28, // mov r10, [rbx+0x28]
    0x41, 0xC7, 0x02, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [r10], 1
    // Restore the exact interrupted integer/control context. Push the saved RIP on the
    // original stack and RET so RSP is also returned to its pre-hijack value.
    0xFF, 0xB3, 0xD0, 0x00, 0x00, 0x00, // push qword ptr [rbx+0xd0] (RFLAGS)
    0x9D, // popfq
    0x48, 0x8B, 0x63, 0x50, // mov rsp, [rbx+0x50] (original RSP)
    0xFF, 0x73, 0x48, // push qword ptr [rbx+0x48] (original RIP)
    0x48, 0x8B, 0x43, 0x58, // mov rax, [rbx+0x58]
    0x48, 0x8B, 0x4B, 0x60, // mov rcx, [rbx+0x60]
    0x48, 0x8B, 0x53, 0x68, // mov rdx, [rbx+0x68]
    0x48, 0x8B, 0x6B, 0x78, // mov rbp, [rbx+0x78]
    0x48, 0x8B, 0xB3, 0x80, 0x00, 0x00, 0x00, // mov rsi, [rbx+0x80]
    0x48, 0x8B, 0xBB, 0x88, 0x00, 0x00, 0x00, // mov rdi, [rbx+0x88]
    0x4C, 0x8B, 0x83, 0x90, 0x00, 0x00, 0x00, // mov r8, [rbx+0x90]
    0x4C, 0x8B, 0x8B, 0x98, 0x00, 0x00, 0x00, // mov r9, [rbx+0x98]
    0x4C, 0x8B, 0x93, 0xA0, 0x00, 0x00, 0x00, // mov r10, [rbx+0xa0]
    0x4C, 0x8B, 0x9B, 0xA8, 0x00, 0x00, 0x00, // mov r11, [rbx+0xa8]
    0x4C, 0x8B, 0xA3, 0xB0, 0x00, 0x00, 0x00, // mov r12, [rbx+0xb0]
    0x4C, 0x8B, 0xAB, 0xB8, 0x00, 0x00, 0x00, // mov r13, [rbx+0xb8]
    0x4C, 0x8B, 0xB3, 0xC0, 0x00, 0x00, 0x00, // mov r14, [rbx+0xc0]
    0x4C, 0x8B, 0xBB, 0xC8, 0x00, 0x00, 0x00, // mov r15, [rbx+0xc8]
    0x48, 0x8B, 0x5B, 0x70, // mov rbx, [rbx+0x70]
    0xC3, // ret
];

const HIJACK_PARAM_SIZE: usize = 0x100;
const HIJACK_SCRATCH_SIZE: usize = 0x400;
const HIJACK_PARAM_OFFSET: u64 = 0x200;
const HIJACK_EXIT_CODE_OFFSET: u64 = 0x300;
const HIJACK_STATUS_OFFSET: u64 = 0x308;

const _: () = {
    assert!(THREAD_HIJACK_THUNK.len() <= HIJACK_PARAM_OFFSET as usize);
    assert!(HIJACK_PARAM_OFFSET + HIJACK_PARAM_SIZE as u64 <= HIJACK_EXIT_CODE_OFFSET);
    assert!(HIJACK_EXIT_CODE_OFFSET + 4 <= HIJACK_STATUS_OFFSET);
    assert!(HIJACK_STATUS_OFFSET + 4 <= HIJACK_SCRATCH_SIZE as u64);
};

#[allow(clippy::too_many_arguments)]
fn prepare_dllmain_scratch(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    hook: &GuestIatHook,
    virtual_alloc: u64,
    entry: u64,
    remote_base: u64,
    reserved: u64,
    original_context: Option<GuestThreadContext>,
    tls: Option<DllMainThreadTls>,
    actctx: Option<DllMainActCtx>,
    timeout_ms: u32,
) -> Result<(u64, u64, u64, u64), GuestInjectError> {
    let scratch = allocate_helper_buffer_with_protect(
        backend,
        pid,
        hook,
        virtual_alloc,
        HIJACK_SCRATCH_SIZE,
        PAGE_EXECUTE_READWRITE,
        timeout_ms,
    )?;
    let thunk_offset = 0x00u64;
    let param_offset = HIJACK_PARAM_OFFSET;
    let exit_code_offset = HIJACK_EXIT_CODE_OFFSET;
    let status_offset = HIJACK_STATUS_OFFSET;

    let thunk = match original_context {
        Some(_) => THREAD_HIJACK_THUNK,
        None => REMOTE_THREAD_DLLMAIN_THUNK,
    };
    backend.write(pid, scratch + thunk_offset, thunk)?;

    let mut param = [0u8; HIJACK_PARAM_SIZE];
    param[0x00..0x08].copy_from_slice(&entry.to_le_bytes());
    param[0x08..0x10].copy_from_slice(&remote_base.to_le_bytes());
    param[0x10..0x18].copy_from_slice(&(DLL_PROCESS_ATTACH as u64).to_le_bytes());
    param[0x18..0x20].copy_from_slice(&reserved.to_le_bytes());
    param[0x20..0x28].copy_from_slice(&(scratch + exit_code_offset).to_le_bytes());
    param[0x28..0x30].copy_from_slice(&(scratch + status_offset).to_le_bytes());
    if let Some(tls) = tls {
        param[0x30..0x38].copy_from_slice(&tls.tls_set_value.to_le_bytes());
        param[0x38..0x40].copy_from_slice(&(tls.slot as u64).to_le_bytes());
        param[0x40..0x48].copy_from_slice(&tls.value.to_le_bytes());
    }
    let actctx_offset = if original_context.is_some() {
        0xD8
    } else {
        0x48
    };
    if let Some(actctx) = actctx {
        let values = [
            (actctx_offset, actctx.activate),
            (actctx_offset + 8, actctx.deactivate),
            (actctx_offset + 16, actctx.handle),
            (actctx_offset + 24, actctx.cookie_addr),
        ];
        for (offset, value) in values {
            param[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    if let Some(ctx) = original_context {
        let values = [
            (0x48, ctx.rip),
            (0x50, ctx.rsp),
            (0x58, ctx.rax),
            (0x60, ctx.rcx),
            (0x68, ctx.rdx),
            (0x70, ctx.rbx),
            (0x78, ctx.rbp),
            (0x80, ctx.rsi),
            (0x88, ctx.rdi),
            (0x90, ctx.r8),
            (0x98, ctx.r9),
            (0xA0, ctx.r10),
            (0xA8, ctx.r11),
            (0xB0, ctx.r12),
            (0xB8, ctx.r13),
            (0xC0, ctx.r14),
            (0xC8, ctx.r15),
            (0xD0, u64::from(ctx.eflags)),
        ];
        for (offset, value) in values {
            param[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    backend.write(pid, scratch + param_offset, &param)?;

    backend.write(pid, scratch + status_offset, &0u32.to_le_bytes())?;

    Ok((
        scratch + thunk_offset,
        scratch + param_offset,
        scratch + exit_code_offset,
        scratch + status_offset,
    ))
}

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
                &[self.view_base, 0, 0, 0],
                self.timeout_ms,
            );
        }
        if self.mapping_handle != 0 {
            let _ = self.backend.call_iat_hook(
                self.pid,
                self.hook,
                self.close_handle,
                &[self.mapping_handle, 0, 0, 0],
                self.timeout_ms,
            );
        }
        if self.file_handle != 0 {
            let _ = self.backend.call_iat_hook(
                self.pid,
                self.hook,
                self.close_handle,
                &[self.file_handle, 0, 0, 0],
                self.timeout_ms,
            );
        }
        if self.payload_buf != 0 {
            let _ = self.backend.call_iat_hook(
                self.pid,
                self.hook,
                self.virtual_free,
                &[self.payload_buf, 0, MEM_RELEASE, 0],
                self.timeout_ms,
            );
        }
        if self.path_buf != 0 {
            let _ = self.backend.call_iat_hook(
                self.pid,
                self.hook,
                self.virtual_free,
                &[self.path_buf, 0, MEM_RELEASE, 0],
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
    backend.call_iat_hook(pid, hook, trampoline, &[param_block, 0, 0, 0], timeout_ms)
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
        &[0, SEC_IMAGE_PATH_BYTES, MEM_COMMIT_RESERVE, PAGE_READWRITE],
        timeout_ms,
    )?;
    if cleanup.path_buf == 0 {
        return Err(sec_image_error("path buffer", "VirtualAlloc returned NULL"));
    }
    cleanup.payload_buf = backend.call_iat_hook(
        pid,
        hook,
        virtual_alloc,
        &[
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
        &[SEC_IMAGE_PATH_CHARS, cleanup.path_buf, 0, 0],
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
        &[cleanup.payload_buf, 0, MEM_RELEASE, 0],
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
        &[cleanup.mapping_handle, 0, 0, 0],
        timeout_ms,
    );
    cleanup.mapping_handle = 0;
    let _ = backend.call_iat_hook(
        pid,
        hook,
        close_handle,
        &[cleanup.file_handle, 0, 0, 0],
        timeout_ms,
    );
    cleanup.file_handle = 0;
    let _ = backend.call_iat_hook(
        pid,
        hook,
        virtual_free,
        &[cleanup.path_buf, 0, MEM_RELEASE, 0],
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
    let peb = backend.call_iat_hook(pid, hook, trampoline, &[0, 0, 0, 0], timeout_ms)?;
    if peb == 0 {
        let _ = backend.write(pid, trampoline, &saved);
        return Err(GuestInjectError::Backend("PEB lookup returned null".into()));
    }
    let ldr_bytes = backend.read(pid, peb + 0x18, 8)?;
    let ldr = u64::from_le_bytes(ldr_bytes[0..8].try_into().unwrap());
    if ldr == 0 {
        let _ = backend.write(pid, trampoline, &saved);
        return Err(GuestInjectError::Backend(format!(
            "PEB Ldr is null for PEB {peb:#x}"
        )));
    }
    let process_heap_bytes = backend.read(pid, peb + 0x30, 8)?;
    let process_heap = u64::from_le_bytes(process_heap_bytes[0..8].try_into().unwrap());

    write_verified(
        backend,
        pid,
        trampoline,
        GUEST_PROC_TRAMPOLINE,
        "proc trampoline",
    )?;
    let rtl_allocate_heap = resolve_import_symbol(backend, pid, "ntdll.dll", "RtlAllocateHeap")?;
    let _rtl_free_heap = resolve_import_symbol(backend, pid, "ntdll.dll", "RtlFreeHeap")?;
    const HEAP_ZERO_MEMORY: u64 = 0x08;

    let alloc_on_heap = |size: u64| -> Result<u64, GuestInjectError> {
        call_guest_proc(
            backend,
            pid,
            hook,
            trampoline,
            stage + STAGE_PARAM_OFFSET,
            rtl_allocate_heap,
            &[process_heap, HEAP_ZERO_MEMORY, size, 0],
            timeout_ms,
            "RtlAllocateHeap",
        )
    };

    let ddag_size = 0x48u64;
    let ddag = alloc_on_heap(ddag_size)?;
    if ddag == 0 {
        let _ = backend.write(pid, trampoline, &saved);
        return Err(GuestInjectError::Backend(
            "RtlAllocateHeap for DDAG returned NULL".into(),
        ));
    }
    let mut ddag_data = vec![0u8; ddag_size as usize];
    let ddag_modules = ddag;
    ddag_data[0x00..0x08].copy_from_slice(&ddag_modules.to_le_bytes());
    ddag_data[0x08..0x10].copy_from_slice(&ddag_modules.to_le_bytes());
    let ddag_load_count: i32 = -1;
    ddag_data[0x18..0x1C].copy_from_slice(&ddag_load_count.to_le_bytes());
    let ddag_ref: u32 = 1;
    ddag_data[0x1C..0x20].copy_from_slice(&ddag_ref.to_le_bytes());
    let ddag_state: u32 = 9;
    ddag_data[0x34..0x38].copy_from_slice(&ddag_state.to_le_bytes());
    write_verified(backend, pid, ddag, &ddag_data, "LDR_DDAG_NODE")?;

    let entry_size = 0x200u64;
    let entry = alloc_on_heap(entry_size)?;
    if entry == 0 {
        let _ = backend.write(pid, trampoline, &saved);
        return Err(GuestInjectError::Backend(
            "RtlAllocateHeap for LDR entry returned NULL".into(),
        ));
    }
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
    let base_name_offset = 0xC0usize;
    let full_name_offset = 0x160usize;
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

    entry_data[0x68..0x6C].copy_from_slice(&0x80004u32.to_le_bytes());
    let load_count: u16 = 0xFFFF;
    entry_data[0x6C..0x6E].copy_from_slice(&load_count.to_le_bytes());
    entry_data[0x98..0xA0].copy_from_slice(&ddag.to_le_bytes());
    let hash_val = compute_ldr_hash(&base_name_wide[..base_name_wide.len() - 2]);
    entry_data[0x108..0x10C].copy_from_slice(&hash_val.to_le_bytes());
    let hash_links = entry + 0x70;
    entry_data[0x70..0x78].copy_from_slice(&hash_links.to_le_bytes());
    entry_data[0x78..0x80].copy_from_slice(&hash_links.to_le_bytes());
    let base_name_index_node = entry + 0xC8;
    entry_data[0xC8..0xD0].copy_from_slice(&base_name_index_node.to_le_bytes());
    entry_data[0xD0..0xD8].copy_from_slice(&base_name_index_node.to_le_bytes());
    entry_data[0xD8..0xE0].copy_from_slice(&base_name_index_node.to_le_bytes());

    write_verified(backend, pid, entry, &entry_data, "LDR_DATA_TABLE_ENTRY")?;

    let list_insert = |list_head: u64, links_offset: u64| -> Result<(), GuestInjectError> {
        let links = entry + links_offset;
        let head_blink_bytes = backend.read(pid, list_head + 8, 8)?;
        let head_blink = u64::from_le_bytes(head_blink_bytes[0..8].try_into().unwrap());
        backend.write(pid, links, &list_head.to_le_bytes())?;
        backend.write(pid, links + 8, &head_blink.to_le_bytes())?;
        backend.write(pid, head_blink, &links.to_le_bytes())?;
        backend.write(pid, list_head + 8, &links.to_le_bytes())?;
        Ok(())
    };
    list_insert(ldr + 0x10, 0x00)?;
    list_insert(ldr + 0x20, 0x10)?;
    list_insert(ldr + 0x30, 0x20)?;

    let hash_bucket = find_ldr_hash_bucket(backend, pid, ldr, hash_val)?;
    if hash_bucket != 0 {
        let hash_head_blink_bytes = backend.read(pid, hash_bucket + 8, 8)?;
        let hash_head_blink = u64::from_le_bytes(hash_head_blink_bytes[0..8].try_into().unwrap());
        backend.write(pid, entry + 0x70, &hash_bucket.to_le_bytes())?;
        backend.write(pid, entry + 0x78, &hash_head_blink.to_le_bytes())?;
        backend.write(pid, hash_head_blink, &(entry + 0x70).to_le_bytes())?;
        backend.write(pid, hash_bucket + 8, &(entry + 0x70).to_le_bytes())?;
        tracing::info!(
            pid,
            hash_bucket = format_args!("{hash_bucket:#x}"),
            hash = hash_val,
            "inserted into LdrpHashTable"
        );
    }

    let _ = backend.write(pid, trampoline, &saved);
    tracing::info!(
        pid,
        peb = format_args!("{peb:#x}"),
        ldr = format_args!("{ldr:#x}"),
        entry = format_args!("{entry:#x}"),
        ddag = format_args!("{ddag:#x}"),
        hash = hash_val,
        remote_base = format_args!("{remote_base:#x}"),
        "synthesized full LDR_DATA_TABLE_ENTRY with DDAG node, LoadCount=-1, hash table insertion, linked into all three PEB loader lists"
    );
    Ok(entry)
}

fn compute_ldr_hash(name_wide: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for chunk in name_wide.chunks_exact(2) {
        let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
        let up = (ch as u8).to_ascii_uppercase() as u32;
        hash = hash.wrapping_add(0x1003fu32.wrapping_mul(up));
    }
    hash
}

fn find_ldr_hash_bucket(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    ldr: u64,
    target_hash: u32,
) -> Result<u64, GuestInjectError> {
    let init_first_bytes = backend.read(pid, ldr + 0x30, 8)?;
    let init_first = u64::from_le_bytes(init_first_bytes[0..8].try_into().unwrap());
    if init_first == 0 {
        return Ok(0);
    }
    let ntdll_entry = init_first;
    let ntdll_base_bytes = backend.read(pid, ntdll_entry + 0x30, 8)?;
    let ntdll_base = u64::from_le_bytes(ntdll_base_bytes[0..8].try_into().unwrap());
    let ntdll_size_bytes = backend.read(pid, ntdll_entry + 0x40, 4)?;
    let ntdll_size = u32::from_le_bytes(ntdll_size_bytes[0..4].try_into().unwrap()) as u64;
    let ntdll_end = ntdll_base.saturating_add(ntdll_size);

    let ntdll_name_buf_bytes = backend.read(pid, ntdll_entry + 0x60, 8)?;
    let ntdll_name_buf = u64::from_le_bytes(ntdll_name_buf_bytes[0..8].try_into().unwrap());
    if ntdll_name_buf == 0 {
        return Ok(0);
    }
    let ntdll_name_wide = backend.read(pid, ntdll_name_buf, 520)?;
    let null_pos = ntdll_name_wide
        .windows(2)
        .position(|w| w == [0, 0])
        .unwrap_or(ntdll_name_wide.len());
    let ntdll_hash = compute_ldr_hash(&ntdll_name_wide[..null_pos]);
    let ntdll_hash_index = (ntdll_hash & 0x1F) as u64;

    let mut current = ntdll_entry + 0x70;
    for _ in 0..256 {
        let flink_bytes = backend.read(pid, current, 8)?;
        let flink = u64::from_le_bytes(flink_bytes[0..8].try_into().unwrap());
        if flink == 0 {
            break;
        }
        if flink >= ntdll_base && flink < ntdll_end {
            let ldrp_hash_table = flink - ntdll_hash_index * 16;
            let target_index = (target_hash & 0x1F) as u64;
            let target_bucket = ldrp_hash_table + target_index * 16;
            return Ok(target_bucket);
        }
        current = flink;
    }
    Ok(0)
}

fn unlink_synthesized_peb_loader_entry(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    entry: u64,
) -> Result<(), GuestInjectError> {
    unlink_guest_list_entry(backend, pid, entry)?;
    unlink_guest_list_entry(backend, pid, entry + 0x10)?;
    unlink_guest_list_entry(backend, pid, entry + 0x20)?;
    unlink_guest_list_entry(backend, pid, entry + 0x70).or_else(|err| {
        let bytes = backend.read(pid, entry + 0x70, 16)?;
        let flink = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let blink = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        if flink == entry + 0x70 && blink == entry + 0x70 {
            Ok(())
        } else {
            Err(err)
        }
    })?;
    tracing::info!(
        pid,
        entry = format_args!("{entry:#x}"),
        "unlinked synthesized PEB loader entry from InLoadOrder, InMemoryOrder, InInitializationOrder, and HashLinks lists"
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
        &[addr, size, protect, old_protect],
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

fn call_stub(hook: &GuestIatHook, function: u64, args: &[u64]) -> Vec<u8> {
    if hook.call_stack == GuestCallStackPolicy::RegisteredUnwind {
        return framed_call_stub(hook, function, args);
    }
    let mut code = X64Stub::new();
    preserve_import_args(&mut code);
    increment_inflight_counter(&mut code, hook);
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.xor_eax_eax();
    code.mov_abs(Reg64::R11, RESULT_RUNNING);
    code.lock_cmpxchg_rax_at_r10_with_r11();
    let skip_call = code.jne_rel32_placeholder();

    stage_register_args(&mut code, args);
    let n_stack = args.len().saturating_sub(4);
    let spoofed = if n_stack > 0 {
        None
    } else {
        hook.spoofed_return
    };
    match spoofed {
        Some(gadget) => emit_spoofed_call(&mut code, hook, function, gadget, 0),
        None => emit_direct_call(&mut code, function, &args[4.min(args.len())..]),
    }
    code.mov_abs(Reg64::R10, hook.result_addr + 8);
    code.store_rax_at_r10();
    if hook.iat_slot_guest_writable {
        disarm_iat_slot(&mut code, hook);
    }
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.mov_abs(Reg64::Rax, RESULT_STATE);
    code.store_rax_at_r10();

    let tail_original = code.len();
    code.patch_rel32(skip_call, tail_original);
    tail_jump_original_import(&mut code, hook);
    code.finish()
}

fn stage_pool_bootstrap_stub(
    hook: &GuestIatHook,
    virtual_alloc: u64,
    size: u64,
) -> Result<Vec<u8>, GuestInjectError> {
    let page_count = size.div_ceil(GUEST_PAGE_SIZE as u64);
    if page_count == 0 {
        return Err(GuestInjectError::Config(
            "guest IAT stage-pool bootstrap size must be nonzero".into(),
        ));
    }
    let mut code = X64Stub::new();
    let framed = hook.call_stack == GuestCallStackPolicy::RegisteredUnwind;
    if framed {
        framed_prologue(&mut code);
    } else {
        preserve_import_args(&mut code);
    }
    increment_inflight_counter(&mut code, hook);
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.xor_eax_eax();
    code.mov_abs(Reg64::R11, RESULT_RUNNING);
    code.lock_cmpxchg_rax_at_r10_with_r11();
    let skip_call = code.jne_rel32_placeholder();

    stage_register_args(
        &mut code,
        &[0, size, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE],
    );
    if framed {
        code.mov_abs(Reg64::Rax, virtual_alloc);
        code.call_rax_with_current_frame();
    } else {
        emit_direct_call(&mut code, virtual_alloc, &[]);
    }

    code.test_rax_rax();
    let skip_touch = code.je_rel32_placeholder();
    code.mov_rdx_rax();
    code.add_rdx_imm32(IAT_STAGE_POOL_CANARY_OFFSET as u32);
    code.mov_abs(Reg64::Rcx, page_count);
    let touch_loop = code.len();
    code.write_byte_at_rdx(IAT_STAGE_POOL_CANARY_VALUE);
    code.add_rdx_imm32(GUEST_PAGE_SIZE as u32);
    code.dec_rcx();
    let repeat_touch = code.jne_rel32_placeholder();
    code.patch_rel32(repeat_touch, touch_loop);
    let after_touch = code.len();
    code.patch_rel32(skip_touch, after_touch);

    code.mov_abs(Reg64::R10, hook.result_addr + 8);
    code.store_rax_at_r10();
    if hook.iat_slot_guest_writable {
        disarm_iat_slot(&mut code, hook);
    }
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.mov_abs(Reg64::Rax, RESULT_STATE);
    code.store_rax_at_r10();

    let tail_original = code.len();
    code.patch_rel32(skip_call, tail_original);
    if framed {
        framed_tail_jump_original_import(&mut code, hook);
    } else {
        tail_jump_original_import(&mut code, hook);
    }
    let stub = code.finish();
    if stub.len() > (STAGE_SCRATCH_OFFSET - STAGE_STUB_OFFSET) as usize {
        return Err(GuestInjectError::Backend(format!(
            "guest IAT stage-pool bootstrap stub is {} bytes, exceeding the {}-byte stage slot",
            stub.len(),
            STAGE_SCRATCH_OFFSET - STAGE_STUB_OFFSET
        )));
    }
    Ok(stub)
}

fn framed_call_stub(hook: &GuestIatHook, function: u64, args: &[u64]) -> Vec<u8> {
    let n_stack = args.len().saturating_sub(4);
    assert!(
        n_stack <= FRAMED_MAX_STACK_ARGS,
        "framed_call_stub supports at most {FRAMED_MAX_STACK_ARGS} stack args (frame {FRAMED_STUB_STACK_ALLOC:#x}); got {n_stack} stack args ({} total)",
        args.len()
    );
    let mut code = X64Stub::new();
    framed_prologue(&mut code);
    increment_inflight_counter(&mut code, hook);
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.xor_eax_eax();
    code.mov_abs(Reg64::R11, RESULT_RUNNING);
    code.lock_cmpxchg_rax_at_r10_with_r11();
    let skip_call = code.jne_rel32_placeholder();

    stage_register_args(&mut code, args);
    let n_stack = args.len().saturating_sub(4);
    let spoofed = if n_stack > 0 {
        None
    } else {
        hook.spoofed_return
    };
    stage_stack_args(&mut code, &args[4.min(args.len())..]);
    match spoofed {
        Some(gadget) => emit_spoofed_call(&mut code, hook, function, gadget, 8),
        None => {
            code.mov_abs(Reg64::Rax, function);
            code.call_rax_with_current_frame();
        }
    }
    code.mov_abs(Reg64::R10, hook.result_addr + 8);
    code.store_rax_at_r10();
    if hook.iat_slot_guest_writable {
        disarm_iat_slot(&mut code, hook);
    }
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.mov_abs(Reg64::Rax, RESULT_STATE);
    code.store_rax_at_r10();

    let tail_original = code.len();
    code.patch_rel32(skip_call, tail_original);
    framed_tail_jump_original_import(&mut code, hook);
    code.finish()
}

fn increment_inflight_counter(code: &mut X64Stub, hook: &GuestIatHook) {
    code.mov_abs(Reg64::R10, hook.result_addr + RESULT_INFLIGHT_OFFSET);
    code.lock_inc_qword_at_r10();
}

fn disarm_iat_slot(code: &mut X64Stub, hook: &GuestIatHook) {
    code.mov_abs(Reg64::R10, hook.iat_slot);
    code.mov_abs(Reg64::Rax, hook.original_target);
    code.store_rax_at_r10();
}

fn touch_stub(hook: &GuestIatHook, addr: u64, len: usize) -> Vec<u8> {
    if hook.call_stack == GuestCallStackPolicy::RegisteredUnwind {
        return framed_touch_stub(hook, addr, len, TouchMode::ForceMaterialize);
    }
    let mut code = X64Stub::new();
    preserve_import_args(&mut code);
    increment_inflight_counter(&mut code, hook);
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.xor_eax_eax();
    code.mov_abs(Reg64::R11, RESULT_RUNNING);
    code.lock_cmpxchg_rax_at_r10_with_r11();
    let skip_touch = code.jne_rel32_placeholder();

    emit_touch_loop(&mut code, addr, len, TouchMode::ForceMaterialize);

    code.mov_abs(Reg64::R10, hook.result_addr + 8);
    code.mov_abs(Reg64::Rax, addr);
    code.store_rax_at_r10();
    if hook.iat_slot_guest_writable {
        disarm_iat_slot(&mut code, hook);
    }
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.mov_abs(Reg64::Rax, RESULT_STATE);
    code.store_rax_at_r10();

    let tail_original = code.len();
    code.patch_rel32(skip_touch, tail_original);
    tail_jump_original_import(&mut code, hook);
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
    increment_inflight_counter(&mut code, hook);
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.xor_eax_eax();
    code.mov_abs(Reg64::R11, RESULT_RUNNING);
    code.lock_cmpxchg_rax_at_r10_with_r11();
    let skip_touch = code.jne_rel32_placeholder();

    emit_touch_loop(&mut code, addr, len, mode);

    code.mov_abs(Reg64::R10, hook.result_addr + 8);
    code.mov_abs(Reg64::Rax, addr);
    code.store_rax_at_r10();
    if hook.iat_slot_guest_writable {
        disarm_iat_slot(&mut code, hook);
    }
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.mov_abs(Reg64::Rax, RESULT_STATE);
    code.store_rax_at_r10();

    let tail_original = code.len();
    code.patch_rel32(skip_touch, tail_original);
    tail_jump_original_import(&mut code, hook);
    code.finish()
}

#[derive(Clone, Copy)]
enum TouchMode {
    ForceMaterialize,
    ReadOnly,
    WriteSame,
}

fn framed_touch_stub(hook: &GuestIatHook, addr: u64, len: usize, mode: TouchMode) -> Vec<u8> {
    let mut code = X64Stub::new();
    framed_prologue(&mut code);
    increment_inflight_counter(&mut code, hook);
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.xor_eax_eax();
    code.mov_abs(Reg64::R11, RESULT_RUNNING);
    code.lock_cmpxchg_rax_at_r10_with_r11();
    let skip_touch = code.jne_rel32_placeholder();

    emit_touch_loop(&mut code, addr, len, mode);

    code.mov_abs(Reg64::R10, hook.result_addr + 8);
    code.mov_abs(Reg64::Rax, addr);
    code.store_rax_at_r10();
    if hook.iat_slot_guest_writable {
        disarm_iat_slot(&mut code, hook);
    }
    code.mov_abs(Reg64::R10, hook.result_addr);
    code.mov_abs(Reg64::Rax, RESULT_STATE);
    code.store_rax_at_r10();

    let tail_original = code.len();
    code.patch_rel32(skip_touch, tail_original);
    framed_tail_jump_original_import(&mut code, hook);
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
        TouchMode::ForceMaterialize => code.force_materialize_byte_at_rdx(),
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

fn tail_jump_original_import(code: &mut X64Stub, hook: &GuestIatHook) {
    code.pop(Reg64::R9);
    code.pop(Reg64::R8);
    code.pop(Reg64::Rdx);
    code.pop(Reg64::Rcx);
    code.mov_abs(Reg64::Rax, hook.original_target);
    code.mov_abs(Reg64::R10, hook.result_addr + RESULT_INFLIGHT_OFFSET);
    code.lock_dec_qword_at_r10();
    code.jmp_rax();
}

fn stage_register_args(code: &mut X64Stub, args: &[u64]) {
    const REGS: [Reg64; 4] = [Reg64::Rcx, Reg64::Rdx, Reg64::R8, Reg64::R9];
    for (idx, reg) in REGS.iter().enumerate() {
        if let Some(&v) = args.get(idx) {
            code.mov_abs(*reg, v);
        }
    }
}

fn stage_stack_args(code: &mut X64Stub, stack_args: &[u64]) {
    for (i, &v) in stack_args.iter().enumerate() {
        let disp = 0x20u8 + (i as u8) * 8;
        code.mov_abs(Reg64::Rax, v);
        code.store_reg_at_rsp_disp(Reg64::Rax, disp);
    }
}

fn emit_direct_call(code: &mut X64Stub, function: u64, stack_args: &[u64]) {
    let n = stack_args.len() as u32;
    let mut frame = 0x28u32 + n * 8;
    if frame % 16 != 8 {
        frame += 8;
    }
    let frame8 = u8::try_from(frame).expect("direct call frame fits in imm8");
    code.sub_rsp(frame8);
    stage_stack_args(code, stack_args);
    code.mov_abs(Reg64::Rax, function);
    code.call_rax_with_current_frame();
    code.add_rsp(frame8);
}

fn framed_prologue(code: &mut X64Stub) {
    code.sub_rsp(FRAMED_STUB_STACK_ALLOC);
    code.store_reg_at_rsp_disp(Reg64::Rcx, 0x48);
    code.store_reg_at_rsp_disp(Reg64::Rdx, 0x50);
    code.store_reg_at_rsp_disp(Reg64::R8, 0x58);
    code.store_reg_at_rsp_disp(Reg64::R9, 0x60);
}

fn framed_tail_jump_original_import(code: &mut X64Stub, hook: &GuestIatHook) {
    code.load_reg_from_rsp_disp(Reg64::Rcx, 0x48);
    code.load_reg_from_rsp_disp(Reg64::Rdx, 0x50);
    code.load_reg_from_rsp_disp(Reg64::R8, 0x58);
    code.load_reg_from_rsp_disp(Reg64::R9, 0x60);
    code.add_rsp(FRAMED_STUB_STACK_ALLOC);
    code.mov_abs(Reg64::Rax, hook.original_target);
    code.mov_abs(Reg64::R10, hook.result_addr + RESULT_INFLIGHT_OFFSET);
    code.lock_dec_qword_at_r10();
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

    fn force_materialize_byte_at_rdx(&mut self) {
        // A zero store can be optimized against a demand-zero page. Flip twice
        // to preserve its byte while forcing a concrete guest write fault.
        self.bytes
            .extend_from_slice(&[0x80, 0x32, 0xA5, 0x80, 0x32, 0xA5]);
    }

    fn write_byte_at_rdx(&mut self, value: u8) {
        self.bytes.extend_from_slice(&[0xC6, 0x02, value]);
    }

    fn mov_rdx_rax(&mut self) {
        self.bytes.extend_from_slice(&[0x48, 0x89, 0xC2]);
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

    fn test_rax_rax(&mut self) {
        self.bytes.extend_from_slice(&[0x48, 0x85, 0xC0]);
    }

    fn lock_cmpxchg_rax_at_r10_with_r11(&mut self) {
        self.bytes
            .extend_from_slice(&[0xF0, 0x4D, 0x0F, 0xB1, 0x1A]);
    }

    fn lock_inc_qword_at_r10(&mut self) {
        self.bytes.extend_from_slice(&[0xF0, 0x49, 0xFF, 0x02]);
    }

    fn lock_dec_qword_at_r10(&mut self) {
        self.bytes.extend_from_slice(&[0xF0, 0x49, 0xFF, 0x0A]);
    }

    fn jne_rel32_placeholder(&mut self) -> usize {
        self.bytes.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]);
        self.bytes.len() - 4
    }

    fn je_rel32_placeholder(&mut self) -> usize {
        self.bytes.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]);
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
    match find_writable_executable_code_cave(backend, pid, STAGE_CAVE_SIZE) {
        Ok(addr) => Ok(addr),
        Err(_) => {
            tracing::info!(pid, "no RWX code cave; falling back to RX search");
            find_rx_code_cave(backend, pid, STAGE_CAVE_SIZE)
        }
    }
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
    // First try: single region containing the full range.
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
    // Fallback: the stub may span adjacent regions of the same permission
    // (memflow VAD reporting can split a single allocation into multiple regions).
    // Accept if all overlapping regions are readable+executable.
    let mut covered_start = stage;
    let mut all_rx = true;
    let mut found_any = false;
    for region in backend.memory_map(pid)? {
        let region_end = region.base.saturating_add(region.size);
        if region_end <= stage || region.base >= end {
            continue;
        }
        found_any = true;
        if !(region.readable && region.executable) {
            all_rx = false;
        }
        if region_end > covered_start {
            covered_start = region_end;
        }
    }
    if found_any && covered_start >= end && all_rx {
        return Ok(());
    }
    // Final fallback: memflow may not report freshly allocated pages. Accept
    // the stub if no region overlaps at all (the page was VirtualAlloc'd by
    // the injector itself, so it exists even if the VAD isn't refreshed).
    if !found_any {
        return Ok(());
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
    // First try: single region.
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
    // Fallback: accept adjacent RW regions.
    let mut covered_start = result;
    let mut all_rw = true;
    let mut found_any = false;
    for region in backend.memory_map(pid)? {
        let region_end = region.base.saturating_add(region.size);
        if region_end <= result || region.base >= end {
            continue;
        }
        found_any = true;
        if !(region.readable && region.writable) {
            all_rw = false;
        }
        if region_end > covered_start {
            covered_start = region_end;
        }
    }
    if found_any && covered_start >= end && all_rw {
        return Ok(());
    }
    if !found_any {
        return Ok(());
    }
    Err(GuestInjectError::Config(format!(
        "guest result block at {result:#x} does not fit in one mapped region"
    )))
}

fn guest_range_is_writable(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    addr: u64,
    len: u64,
) -> bool {
    let Some(end) = addr.checked_add(len) else {
        return false;
    };
    match backend.memory_map(pid) {
        Ok(regions) => regions.into_iter().any(|region| {
            region.writable && addr >= region.base && end <= region.base.saturating_add(region.size)
        }),
        Err(error) => {
            tracing::debug!(
                pid,
                addr = format_args!("{addr:#x}"),
                len,
                error = %error,
                "IAT slot writability unavailable; requiring host-side restoration"
            );
            false
        }
    }
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

fn select_execution_hook(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    plan: &GuestInjectionPlan,
    stage: u64,
    result_addr: u64,
    independent_execution: bool,
    allow_guest_self_disarm: bool,
) -> Result<GuestIatHook, GuestInjectError> {
    let spoofed_return = if plan.stack_shaping == GuestStackShaping::Spoofed {
        Some(find_spoofed_return(backend, pid)?)
    } else {
        None
    };
    let mut hook = GuestIatHook {
        iat_slot: 0,
        original_target: 0,
        stub_addr: stage + STAGE_STUB_OFFSET,
        result_addr,
        iat_slot_guest_writable: false,
        call_stack: plan.call_stack,
        spoofed_return,
    };

    if independent_execution {
        tracing::info!(
            pid,
            stub_addr = format_args!("{:#x}", hook.stub_addr),
            result_addr = format_args!("{:#x}", hook.result_addr),
            "using backend-provided independent guest execution bootstrap"
        );
        return Ok(hook);
    }

    let selected = find_iat_hook(backend, pid, plan)?;
    hook.iat_slot = selected.iat_slot;
    hook.original_target = selected.original_target;
    hook.iat_slot_guest_writable =
        allow_guest_self_disarm && guest_range_is_writable(backend, pid, hook.iat_slot, 8);
    tracing::info!(
        pid,
        iat_slot = format_args!("{:#x}", hook.iat_slot),
        original_target = format_args!("{:#x}", hook.original_target),
        stub_addr = format_args!("{:#x}", hook.stub_addr),
        result_addr = format_args!("{:#x}", hook.result_addr),
        guest_self_disarm = hook.iat_slot_guest_writable,
        hook_module = %plan.hook_module,
        hook_function = %plan.hook_function,
        "guest IAT hook selected"
    );
    Ok(hook)
}

/// Enumerates named and ordinal IAT entries from one module or every loaded module.
///
/// Entries are read from the original thunk table when present, so this remains useful
/// after the Windows loader has rewritten the IAT with resolved addresses.
pub fn inspect_iat_hook_candidates(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    source_module: Option<&str>,
) -> Result<Vec<GuestIatHookCandidate>, GuestInjectError> {
    let modules = backend.module_list(pid)?;
    let selected: Vec<_> = match source_module {
        Some(name) => vec![
            modules
                .into_iter()
                .find(|module| module.name.eq_ignore_ascii_case(name))
                .ok_or_else(|| GuestInjectError::Process(format!("module {name:?} not found")))?,
        ],
        None => modules,
    };

    let mut candidates = Vec::new();
    for module in selected {
        match inspect_module_iat_hooks(backend, pid, &module) {
            Ok(mut entries) => {
                candidates.append(&mut entries);
                if candidates.len() > MAX_IAT_HOOK_CANDIDATES {
                    return Err(GuestInjectError::Unsupported {
                        operation: "IAT hook discovery",
                        reason: format!(
                            "found more than {MAX_IAT_HOOK_CANDIDATES} entries; specify a target module"
                        ),
                    });
                }
            }
            Err(err) if source_module.is_none() => {
                tracing::debug!(
                    pid,
                    module = %module.name,
                    error = %err,
                    "skipping module whose IAT could not be inspected"
                );
            }
            Err(err) => return Err(err),
        }
    }
    candidates.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.source_module.cmp(&right.source_module))
            .then_with(|| left.import_module.cmp(&right.import_module))
            .then_with(|| left.symbol.cmp(&right.symbol))
    });
    Ok(candidates)
}

/// Arms a bounded liveness probe for one IAT entry.
///
/// When the selected import fires, the normal guest call stub invokes
/// GetCurrentThreadId, records the servicing thread id, then tail-jumps to the
/// original target. The probe restores the slot before returning; memory-only
/// backends retain a completed pass-through stub for late callers. It never
/// maps a payload or invokes DllMain.
#[allow(clippy::too_many_arguments)]
pub fn probe_iat_hook_candidate(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    source_module: &str,
    import_module: &str,
    symbol: &str,
    stage_base: Option<u64>,
    result_base: Option<u64>,
    timeout_ms: u32,
) -> Result<GuestIatHookProbe, GuestInjectError> {
    let candidates = inspect_iat_hook_candidates(backend, pid, Some(source_module))?;
    let import_candidates = import_module_candidates(import_module);
    let candidate = candidates
        .into_iter()
        .find(|candidate| {
            import_candidates
                .iter()
                .any(|module| candidate.import_module.eq_ignore_ascii_case(module))
                && candidate.symbol.eq_ignore_ascii_case(symbol)
        })
        .ok_or_else(|| {
            GuestInjectError::Image(format!(
                "target import {import_module}!{symbol} not found in {source_module}"
            ))
        })?;

    let stage = match stage_base {
        Some(base) => base,
        None => find_stage(backend, pid, None)?,
    };
    validate_stub_region(backend, pid, stage, STAGE_CAVE_SIZE)?;
    let result_addr = result_base.unwrap_or(stage + STAGE_RESULT_OFFSET);
    validate_result_region(backend, pid, result_addr)?;

    let hook = GuestIatHook {
        iat_slot: candidate.iat_slot,
        original_target: candidate.original_target,
        stub_addr: stage + STAGE_STUB_OFFSET,
        result_addr,
        iat_slot_guest_writable: backend.capabilities().iat_hook_stage_restore
            && guest_range_is_writable(backend, pid, candidate.iat_slot, 8),
        call_stack: GuestCallStackPolicy::Native,
        spoofed_return: None,
    };
    let get_current_thread_id =
        resolve_import_symbol(backend, pid, "kernel32.dll", "GetCurrentThreadId")?;
    let servicing_tid = memory_iat_probe(backend, pid, &hook, get_current_thread_id, timeout_ms)?;
    Ok(GuestIatHookProbe {
        candidate,
        observed: servicing_tid.is_some(),
        servicing_tid,
        timeout_ms,
    })
}

fn inspect_module_iat_hooks(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    module: &GuestModuleInfo,
) -> Result<Vec<GuestIatHookCandidate>, GuestInjectError> {
    let header = backend.read(pid, module.base, 0x1000)?;
    if u16_at(&header, 0).map_err(GuestInjectError::from)? != 0x5A4D {
        return Err(GuestInjectError::Image(format!(
            "module {} at {:#x} is missing an MZ header",
            module.name, module.base
        )));
    }
    let nt = u32_at(&header, 0x3C).map_err(GuestInjectError::from)? as usize;
    if nt + 24 + 128 > header.len()
        || u32_at(&header, nt).map_err(GuestInjectError::from)? != 0x0000_4550
    {
        return Err(GuestInjectError::Image(format!(
            "module {} at {:#x} is missing a PE header",
            module.name, module.base
        )));
    }
    let optional = nt + 24;
    if u16_at(&header, optional).map_err(GuestInjectError::from)? != 0x20B {
        return Err(GuestInjectError::Unsupported {
            operation: "IAT hook discovery",
            reason: format!("module {} is not a PE32+ image", module.name),
        });
    }
    let import_rva = u32_at(&header, optional + 120).map_err(GuestInjectError::from)? as u64;
    let import_size = u32_at(&header, optional + 124).map_err(GuestInjectError::from)? as u64;
    if import_rva == 0 || import_size == 0 {
        return Ok(Vec::new());
    }
    if import_rva >= module.size {
        return Err(GuestInjectError::Image(format!(
            "module {} has import directory RVA {import_rva:#x} outside image size {:#x}",
            module.name, module.size
        )));
    }

    let descriptor_count = (import_size as usize / 20).clamp(1, MAX_IAT_IMPORT_DESCRIPTORS);
    let mut entries = Vec::new();
    for index in 0..descriptor_count {
        let descriptor_addr = module.base + import_rva + (index * 20) as u64;
        let descriptor = backend.read(pid, descriptor_addr, 20)?;
        let original_first_thunk = u32_at(&descriptor, 0).map_err(GuestInjectError::from)? as u64;
        let name_rva = u32_at(&descriptor, 12).map_err(GuestInjectError::from)? as u64;
        let first_thunk = u32_at(&descriptor, 16).map_err(GuestInjectError::from)? as u64;
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        if name_rva == 0 || first_thunk == 0 {
            continue;
        }
        let import_module = read_remote_cstr(backend, pid, module.base + name_rva, 256)?;
        if import_module.is_empty() {
            continue;
        }
        let lookup = if original_first_thunk == 0 {
            first_thunk
        } else {
            original_first_thunk
        };
        for thunk_index in 0..MAX_IAT_IMPORTS_PER_MODULE {
            let thunk = read_remote_u64(
                backend,
                pid,
                module.base + lookup + (thunk_index * 8) as u64,
            )?;
            if thunk == 0 {
                break;
            }
            let symbol = if thunk & 0x8000_0000_0000_0000 != 0 {
                format!("#{}", thunk as u16)
            } else {
                read_remote_cstr(backend, pid, module.base + thunk + 2, 256)?
            };
            if symbol.is_empty() {
                continue;
            }
            let iat_slot = module.base + first_thunk + (thunk_index * 8) as u64;
            entries.push(GuestIatHookCandidate {
                source_module: module.name.clone(),
                import_module: import_module.clone(),
                priority: iat_hook_priority(&symbol),
                symbol,
                iat_slot,
                original_target: read_remote_u64(backend, pid, iat_slot)?,
            });
        }
    }
    Ok(entries)
}

fn iat_hook_priority(symbol: &str) -> u8 {
    match symbol.to_ascii_lowercase().as_str() {
        "sleep" | "sleepex" | "ntdelayexecution" => 100,
        "gettickcount" | "gettickcount64" | "queryperformancecounter" => 90,
        "getcurrentthreadid" | "getcurrentprocessid" => 80,
        "waitforsingleobject" | "waitformultipleobjects" | "msgwaitformultipleobjects" => 70,
        "dispatchmessagew" | "peekmessagew" | "getmessagew" => 60,
        _ => 0,
    }
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

fn parse_syscall_stub(bytes: &[u8]) -> Result<u32, GuestInjectError> {
    if bytes.len() < SYSCALL_STUB_LEN {
        return Err(GuestInjectError::Image(format!(
            "syscall stub too short: got {} bytes, need {SYSCALL_STUB_LEN}",
            bytes.len()
        )));
    }
    if bytes[0..3] != SYSCALL_STUB_PREFIX {
        return Err(GuestInjectError::Image(format!(
            "syscall stub prefix mismatch: expected 4C 8B D1, got {:02X} {:02X} {:02X}",
            bytes[0], bytes[1], bytes[2]
        )));
    }
    if bytes[3] != SYSCALL_STUB_OPCODE {
        return Err(GuestInjectError::Image(format!(
            "syscall stub opcode mismatch: expected B8, got {:02X}",
            bytes[3]
        )));
    }
    Ok(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
}

pub fn resolve_syscall_number(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
    function_name: &str,
) -> Result<u32, GuestInjectError> {
    let addr = resolve_import_symbol(backend, pid, "ntdll.dll", function_name)?;
    tracing::debug!(
        pid,
        function = function_name,
        address = format_args!("{addr:#x}"),
        "reading ntdll syscall stub"
    );
    let bytes = backend.read(pid, addr, SYSCALL_STUB_LEN)?;
    let num = parse_syscall_stub(&bytes)?;
    tracing::debug!(
        pid,
        function = function_name,
        syscall_number = num,
        "resolved guest syscall number"
    );
    Ok(num)
}

pub fn resolve_all_syscalls(
    backend: &dyn GuestMemoryBackend,
    pid: u32,
) -> Result<Vec<(String, u32)>, GuestInjectError> {
    let exports = backend.module_exports(pid, "ntdll.dll")?;
    tracing::debug!(
        pid,
        export_count = exports.len(),
        "scanning ntdll exports for syscall stubs"
    );
    let mut out = Vec::new();
    for (name, addr) in exports {
        if !(name.starts_with("Nt") || name.starts_with("Zw")) {
            continue;
        }
        let bytes = backend.read(pid, addr, SYSCALL_STUB_LEN)?;
        match parse_syscall_stub(&bytes) {
            Ok(num) => {
                tracing::debug!(
                    pid,
                    function = %name,
                    syscall_number = num,
                    "resolved guest syscall number"
                );
                out.push((name, num));
            }
            Err(err) => {
                tracing::debug!(
                    pid,
                    function = %name,
                    error = %err,
                    "skipping ntdll export; stub did not match syscall pattern"
                );
            }
        }
    }
    Ok(out)
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
    loaded_dependencies: &mut Vec<u64>,
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
    if !loaded_dependencies.contains(&loaded_base) {
        loaded_dependencies.push(loaded_base);
    }
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
    let call_result = backend.call_iat_hook(
        pid,
        hook,
        load_library,
        &[scratch_addr, 0, 0, 0],
        timeout_ms,
    );
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
            &[module_base, u64::from(ordinal), 0, 0],
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
        &[module_base, scratch_addr, 0, 0],
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

fn payload_module_name(req: &GuestInjectionRequest<'_>) -> Option<String> {
    let path = req.payload_path;
    let file_name = path.file_name()?.to_str()?.to_string();
    if file_name.eq_ignore_ascii_case("payload.dll") || file_name.is_empty() {
        return None;
    }
    Some(file_name)
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

    if lower.starts_with("api-ms-win-") || lower.starts_with("ext-ms-win-") {
        out.extend(api_set_hosts(&lower));
    } else if lower == "kernel32.dll" {
        out.push("kernelbase.dll".into());
        out.push("ntdll.dll".into());
    } else if lower == "advapi32.dll" {
        out.push("sechost.dll".into());
        out.push("kernelbase.dll".into());
    } else if lower == "user32.dll" {
        out.push("user32.dll".into());
    } else if lower == "gdi32.dll" {
        out.push("gdi32full.dll".into());
    }

    out.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    out
}

fn api_set_hosts(lower: &str) -> Vec<String> {
    if lower.starts_with("api-ms-win-crt-") {
        return vec!["ucrtbase.dll".into()];
    }
    if let Some(sub) = lower.strip_prefix("api-ms-win-core-") {
        let hosts = match sub.split('-').next().unwrap_or("") {
            "console" => vec!["kernel32.dll"],
            "processthreads" | "processthreads-l1" => vec!["kernel32.dll", "kernelbase.dll"],
            "kernel32" | "kernel32legacy" => vec!["kernel32.dll"],
            "time" => vec!["kernel32.dll", "kernelbase.dll"],
            "rtlsupport" => vec!["ntdll.dll"],
            "xstate" => vec!["ntdll.dll", "kernelbase.dll"],
            "string" | "sysinfo" | "memory" | "heap" | "handle" | "synch" | "file" | "io"
            | "debug" | "errorhandling" | "fibers" | "interlocked" | "libraryloader"
            | "localization" | "namedpipe" | "processenvironment" | "profile" | "realtime"
            | "registry" | "security" | "threadpool" | "util" | "timezone" | "enclave" | "job"
            | "processsnapshot" | "wow64" | "delayload" | "sidebyside" => {
                vec!["kernelbase.dll", "ntdll.dll"]
            }
            _ => vec!["kernelbase.dll", "kernel32.dll", "ntdll.dll"],
        };
        return hosts.into_iter().map(|s| s.into()).collect();
    }
    if lower.starts_with("api-ms-win-security-") {
        return vec!["sechost.dll".into(), "kernelbase.dll".into()];
    }
    if lower.starts_with("api-ms-win-eventing-") {
        return vec!["sechost.dll".into(), "kernelbase.dll".into()];
    }
    if lower.starts_with("api-ms-win-service-") {
        return vec!["sechost.dll".into()];
    }
    if lower.starts_with("api-ms-win-shcore-") {
        return vec!["shcore.dll".into()];
    }
    if lower.starts_with("api-ms-win-shlwapi-") {
        return vec!["shlwapi.dll".into()];
    }
    if lower.starts_with("api-ms-win-psapi-") {
        return vec!["kernel32.dll".into(), "psapi.dll".into()];
    }
    if lower.starts_with("api-ms-win-ntdll-") {
        return vec!["ntdll.dll".into()];
    }
    if lower.starts_with("api-ms-win-gdi-") {
        return vec!["gdi32.dll".into(), "gdi32full.dll".into()];
    }
    if lower.starts_with("api-ms-win-com-") || lower.starts_with("api-ms-win-ole32-") {
        return vec!["combase.dll".into(), "ole32.dll".into()];
    }
    if lower.starts_with("api-ms-win-power-") {
        return vec!["powrprof.dll".into()];
    }
    if lower.starts_with("api-ms-win-devices-") {
        return vec!["kernelbase.dll".into()];
    }
    if lower.starts_with("api-ms-win-downlevel-") {
        return vec!["kernelbase.dll".into(), "shcore.dll".into()];
    }
    if lower.starts_with("api-ms-win-app-") {
        return vec!["kernel.appcore.dll".into()];
    }
    if lower.starts_with("api-ms-win-net-") {
        return vec!["ws2_32.dll".into(), "iphlpapi.dll".into()];
    }
    if lower.starts_with("ext-ms-win-") {
        return vec!["kernelbase.dll".into(), "kernel32.dll".into()];
    }
    vec![
        "kernelbase.dll".into(),
        "kernel32.dll".into(),
        "ntdll.dll".into(),
    ]
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

    const IAT_TEST_PID: u32 = 7;
    const IAT_TEST_IMAGE: u64 = 0x1000;
    const IAT_TEST_STAGE: u64 = 0x4000;

    fn mov_immediate_offset(stub: &[u8], opcode: [u8; 2], immediate: [u8; 8]) -> usize {
        let mut instruction = opcode.to_vec();
        instruction.extend_from_slice(&immediate);
        stub.windows(instruction.len())
            .position(|window| window == instruction)
            .expect("stub must contain expected mov-immediate instruction")
    }

    fn assert_stub_disarms_before_completion(stub: &[u8], hook: &GuestIatHook) {
        let disarm = mov_immediate_offset(stub, [0x49, 0xBA], hook.iat_slot.to_le_bytes());
        let completion = mov_immediate_offset(stub, [0x48, 0xB8], RESULT_STATE.to_le_bytes());
        assert!(
            disarm < completion,
            "stub must restore the IAT slot before publishing completion"
        );
    }

    fn test_iat_hook() -> GuestIatHook {
        GuestIatHook {
            iat_slot: IAT_TEST_IMAGE + 0x700,
            original_target: IAT_TEST_IMAGE + 0x800,
            stub_addr: IAT_TEST_STAGE + STAGE_STUB_OFFSET,
            result_addr: IAT_TEST_STAGE + STAGE_RESULT_OFFSET,
            iat_slot_guest_writable: false,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        }
    }

    #[test]
    fn iat_stage_pool_reserves_distinct_immutable_slots() {
        let hook = test_iat_hook();
        activate_iat_stage_pool(IAT_TEST_PID, &hook, 0x9000, 4).unwrap();
        let first = reserve_iat_stage_slot(IAT_TEST_PID, &hook).unwrap();
        let second = reserve_iat_stage_slot(IAT_TEST_PID, &hook).unwrap();
        let third = reserve_iat_stage_slot(IAT_TEST_PID, &hook).unwrap();
        let fourth = reserve_iat_stage_slot(IAT_TEST_PID, &hook).unwrap();

        assert_eq!(first.stub_addr, 0x9000 + STAGE_STUB_OFFSET);
        assert_eq!(second.stub_addr, 0x9400 + STAGE_STUB_OFFSET);
        assert_eq!(third.stub_addr, 0x9800 + STAGE_STUB_OFFSET);
        assert_eq!(fourth.stub_addr, 0xa000 + STAGE_STUB_OFFSET);
        assert_eq!(first.result_addr, 0x9000 + STAGE_RESULT_OFFSET);
        assert_eq!(second.result_addr, 0x9400 + STAGE_RESULT_OFFSET);
        assert_eq!(third.result_addr, 0x9800 + STAGE_RESULT_OFFSET);
        assert_eq!(fourth.result_addr, 0xa000 + STAGE_RESULT_OFFSET);

        let err = reserve_iat_stage_slot(IAT_TEST_PID, &hook).unwrap_err();
        assert!(err.to_string().contains("stage pool exhausted"));
        IAT_STAGE_POOLS
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .remove(&iat_stage_pool_key(IAT_TEST_PID, &hook));
    }

    #[test]
    fn iat_stage_pool_bootstrap_materializes_each_page_before_completion() {
        let hook = test_iat_hook();
        let stub = stage_pool_bootstrap_stub(&hook, 0x1810, 3 * GUEST_PAGE_SIZE as u64).unwrap();

        assert!(
            stub.windows(3).any(|window| window == [0x48, 0x85, 0xC0]),
            "bootstrap must skip the touch loop when VirtualAlloc returns NULL"
        );
        assert!(
            stub.windows(3).any(|window| window == [0x48, 0x89, 0xC2]),
            "bootstrap must use the returned allocation base as the touch address"
        );
        assert!(
            stub.windows(3)
                .any(|window| window == [0xC6, 0x02, IAT_STAGE_POOL_CANARY_VALUE]),
            "bootstrap must leave a nonzero canary on every pool page"
        );
        let completion = mov_immediate_offset(&stub, [0x48, 0xB8], RESULT_STATE.to_le_bytes());
        let touch = stub
            .windows(3)
            .position(|window| window == [0xC6, 0x02, IAT_STAGE_POOL_CANARY_VALUE])
            .unwrap();
        assert!(
            touch < completion,
            "pool pages must be touched before completion"
        );
    }

    #[test]
    fn iat_stage_pool_reserves_one_nonzero_canary_region_per_page() {
        assert_eq!(iat_stage_pool_page_count(1).unwrap(), 1);
        assert_eq!(iat_stage_pool_page_count(3).unwrap(), 1);
        assert_eq!(iat_stage_pool_page_count(4).unwrap(), 2);
        assert_eq!(iat_stage_pool_size(4).unwrap(), 2 * GUEST_PAGE_SIZE as u64);
        assert_eq!(iat_stage_pool_slot_offset(0).unwrap(), 0);
        assert_eq!(iat_stage_pool_slot_offset(2).unwrap(), 0x800);
        assert_eq!(
            iat_stage_pool_slot_offset(3).unwrap(),
            GUEST_PAGE_SIZE as u64
        );
    }

    #[test]
    fn guest_injection_lock_releases_pid_on_drop() {
        const PID: u32 = 0x7f00_0001;
        let first = GuestInjectionLock::acquire(PID).unwrap();
        assert!(GuestInjectionLock::acquire(PID).is_err());
        drop(first);
        drop(GuestInjectionLock::acquire(PID).unwrap());
    }

    #[test]
    fn iat_stage_pool_recovers_after_host_state_is_lost() {
        let backend = IatTestBackend::new();
        let hook = test_iat_hook();
        let base = 0x5000;
        backend
            .write(IAT_TEST_PID, base, &iat_stage_pool_header(3))
            .unwrap();
        backend
            .write(
                IAT_TEST_PID,
                base + STAGE_RESULT_OFFSET,
                &RESULT_STATE.to_le_bytes(),
            )
            .unwrap();
        activate_iat_stage_pool(IAT_TEST_PID, &hook, base, 3).unwrap();

        IAT_STAGE_POOLS.get().unwrap().lock().unwrap().clear();

        assert_eq!(
            recover_iat_stage_pool(&backend, IAT_TEST_PID, &hook).unwrap(),
            Some(base)
        );
        let next = reserve_iat_stage_slot(IAT_TEST_PID, &hook).unwrap();
        assert_eq!(
            next.stub_addr,
            base + STAGE_CAVE_SIZE as u64 + STAGE_STUB_OFFSET
        );
        IAT_STAGE_POOLS
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .remove(&iat_stage_pool_key(IAT_TEST_PID, &hook));
    }

    struct IatTestBackend {
        memory: Mutex<Vec<u8>>,
        stage_restore_safe: bool,
    }

    impl IatTestBackend {
        fn new() -> Self {
            let mut memory = vec![0u8; 0x6000];
            let put = |memory: &mut Vec<u8>, rva: usize, bytes: &[u8]| {
                memory[rva..rva + bytes.len()].copy_from_slice(bytes);
            };
            put(&mut memory, 0, &0x5A4Du16.to_le_bytes());
            put(&mut memory, 0x3C, &0x80u32.to_le_bytes());
            put(&mut memory, 0x80, &0x0000_4550u32.to_le_bytes());
            put(&mut memory, 0x80 + 24, &0x20Bu16.to_le_bytes());
            put(&mut memory, 0x80 + 24 + 120, &0x400u32.to_le_bytes());
            put(&mut memory, 0x80 + 24 + 124, &0x28u32.to_le_bytes());

            // IMAGE_IMPORT_DESCRIPTOR for KERNEL32.dll!GetTickCount64.
            put(&mut memory, 0x400, &0x500u32.to_le_bytes());
            put(&mut memory, 0x400 + 12, &0x600u32.to_le_bytes());
            put(&mut memory, 0x400 + 16, &0x700u32.to_le_bytes());
            put(&mut memory, 0x500, &0x800u64.to_le_bytes());
            put(&mut memory, 0x700, &0x1800u64.to_le_bytes());
            put(&mut memory, 0x600, b"KERNEL32.dll\0");
            put(&mut memory, 0x800 + 2, b"GetTickCount64\0");

            Self {
                memory: Mutex::new(memory),
                stage_restore_safe: false,
            }
        }

        fn with_stage_restore() -> Self {
            let mut backend = Self::new();
            backend.stage_restore_safe = true;
            backend
        }

        fn offset(addr: u64) -> usize {
            (addr - IAT_TEST_IMAGE) as usize
        }
    }

    impl GuestMemoryBackend for IatTestBackend {
        fn capabilities(&self) -> GuestCapabilities {
            let mut capabilities = GuestCapabilities::memflow_guest_injection();
            capabilities.iat_hook_stage_restore = self.stage_restore_safe;
            capabilities
        }

        fn list_processes(&self) -> Result<Vec<GuestProcessInfo>, GuestInjectError> {
            Ok(vec![GuestProcessInfo {
                pid: IAT_TEST_PID,
                name: "fixture.exe".into(),
            }])
        }

        fn module_list(&self, _pid: u32) -> Result<Vec<GuestModuleInfo>, GuestInjectError> {
            Ok(vec![GuestModuleInfo {
                name: "fixture.exe".into(),
                base: IAT_TEST_IMAGE,
                size: 0x3000,
            }])
        }

        fn module_exports(
            &self,
            _pid: u32,
            _module: &str,
        ) -> Result<Vec<(String, u64)>, GuestInjectError> {
            Ok(Vec::new())
        }

        fn memory_map(&self, _pid: u32) -> Result<Vec<GuestMemoryRegion>, GuestInjectError> {
            Ok(vec![GuestMemoryRegion {
                base: IAT_TEST_IMAGE,
                size: 0x6000,
                readable: true,
                writable: true,
                executable: true,
            }])
        }

        fn read(&self, _pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, GuestInjectError> {
            let start = Self::offset(addr);
            let end = start
                .checked_add(len)
                .ok_or_else(|| GuestInjectError::Backend("synthetic read overflow".into()))?;
            self.memory
                .lock()
                .unwrap()
                .get(start..end)
                .map(|bytes| bytes.to_vec())
                .ok_or_else(|| GuestInjectError::Backend("synthetic read out of range".into()))
        }

        fn write(&self, _pid: u32, addr: u64, data: &[u8]) -> Result<(), GuestInjectError> {
            let start = Self::offset(addr);
            let end = start
                .checked_add(data.len())
                .ok_or_else(|| GuestInjectError::Backend("synthetic write overflow".into()))?;
            let mut memory = self.memory.lock().unwrap();
            let destination = memory
                .get_mut(start..end)
                .ok_or_else(|| GuestInjectError::Backend("synthetic write out of range".into()))?;
            destination.copy_from_slice(data);
            Ok(())
        }
    }

    struct FailingIatRestoreBackend {
        inner: IatTestBackend,
    }

    impl FailingIatRestoreBackend {
        fn new() -> Self {
            Self {
                inner: IatTestBackend::new(),
            }
        }
    }

    impl GuestMemoryBackend for FailingIatRestoreBackend {
        fn capabilities(&self) -> GuestCapabilities {
            self.inner.capabilities()
        }

        fn list_processes(&self) -> Result<Vec<GuestProcessInfo>, GuestInjectError> {
            self.inner.list_processes()
        }

        fn module_list(&self, pid: u32) -> Result<Vec<GuestModuleInfo>, GuestInjectError> {
            self.inner.module_list(pid)
        }

        fn module_exports(
            &self,
            pid: u32,
            module: &str,
        ) -> Result<Vec<(String, u64)>, GuestInjectError> {
            self.inner.module_exports(pid, module)
        }

        fn memory_map(&self, pid: u32) -> Result<Vec<GuestMemoryRegion>, GuestInjectError> {
            self.inner.memory_map(pid)
        }

        fn read(&self, pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, GuestInjectError> {
            self.inner.read(pid, addr, len)
        }

        fn write(&self, pid: u32, addr: u64, data: &[u8]) -> Result<(), GuestInjectError> {
            if addr == IAT_TEST_IMAGE + 0x700 && data == 0x1800u64.to_le_bytes() {
                return Err(GuestInjectError::Backend(
                    "synthetic IAT restore failure".into(),
                ));
            }
            self.inner.write(pid, addr, data)
        }
    }

    #[test]
    fn iat_hook_discovery_reports_named_import_slot_and_priority() {
        let backend = IatTestBackend::new();
        let candidates =
            inspect_iat_hook_candidates(&backend, IAT_TEST_PID, Some("fixture.exe")).unwrap();
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.source_module, "fixture.exe");
        assert_eq!(candidate.import_module, "KERNEL32.dll");
        assert_eq!(candidate.symbol, "GetTickCount64");
        assert_eq!(candidate.iat_slot, IAT_TEST_IMAGE + 0x700);
        assert_eq!(candidate.original_target, 0x1800);
        assert_eq!(candidate.priority, 90);
    }

    #[test]
    fn iat_hook_probe_timeout_restores_iat_and_retains_completed_stage() {
        let backend = IatTestBackend::new();
        let iat_before = backend
            .read(IAT_TEST_PID, IAT_TEST_IMAGE + 0x700, 8)
            .unwrap();
        let stub_before = backend
            .read(IAT_TEST_PID, IAT_TEST_STAGE + STAGE_STUB_OFFSET, 64)
            .unwrap();
        let result_before = backend
            .read(
                IAT_TEST_PID,
                IAT_TEST_STAGE + STAGE_RESULT_OFFSET,
                RESULT_BLOCK_SIZE,
            )
            .unwrap();

        let hook = GuestIatHook {
            iat_slot: IAT_TEST_IMAGE + 0x700,
            original_target: 0x1800,
            stub_addr: IAT_TEST_STAGE + STAGE_STUB_OFFSET,
            result_addr: IAT_TEST_STAGE + STAGE_RESULT_OFFSET,
            iat_slot_guest_writable: true,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        assert_eq!(
            memory_iat_probe(&backend, IAT_TEST_PID, &hook, 0x1810, 0).unwrap(),
            None
        );
        assert_eq!(
            backend
                .read(IAT_TEST_PID, IAT_TEST_IMAGE + 0x700, 8)
                .unwrap(),
            iat_before
        );
        assert_ne!(
            backend
                .read(IAT_TEST_PID, IAT_TEST_STAGE + STAGE_STUB_OFFSET, 64)
                .unwrap(),
            stub_before
        );
        assert_eq!(
            u64::from_le_bytes(
                backend
                    .read(IAT_TEST_PID, IAT_TEST_STAGE + STAGE_RESULT_OFFSET, 8)
                    .unwrap()
                    .try_into()
                    .unwrap()
            ),
            RESULT_STATE
        );
        assert_ne!(
            backend
                .read(
                    IAT_TEST_PID,
                    IAT_TEST_STAGE + STAGE_RESULT_OFFSET,
                    RESULT_BLOCK_SIZE
                )
                .unwrap(),
            result_before
        );
    }

    #[test]
    fn iat_hook_probe_timeout_restores_stage_with_proven_thread_barrier() {
        let backend = IatTestBackend::with_stage_restore();
        let stub_before = backend
            .read(IAT_TEST_PID, IAT_TEST_STAGE + STAGE_STUB_OFFSET, 64)
            .unwrap();
        let result_before = backend
            .read(
                IAT_TEST_PID,
                IAT_TEST_STAGE + STAGE_RESULT_OFFSET,
                RESULT_BLOCK_SIZE,
            )
            .unwrap();
        let hook = GuestIatHook {
            iat_slot: IAT_TEST_IMAGE + 0x700,
            original_target: 0x1800,
            stub_addr: IAT_TEST_STAGE + STAGE_STUB_OFFSET,
            result_addr: IAT_TEST_STAGE + STAGE_RESULT_OFFSET,
            iat_slot_guest_writable: true,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };

        assert_eq!(
            memory_iat_probe(&backend, IAT_TEST_PID, &hook, 0x1810, 0).unwrap(),
            None
        );
        assert_eq!(
            backend
                .read(IAT_TEST_PID, IAT_TEST_STAGE + STAGE_STUB_OFFSET, 64)
                .unwrap(),
            stub_before
        );
        assert_eq!(
            backend
                .read(
                    IAT_TEST_PID,
                    IAT_TEST_STAGE + STAGE_RESULT_OFFSET,
                    RESULT_BLOCK_SIZE
                )
                .unwrap(),
            result_before
        );
    }

    #[test]
    fn iat_hook_restore_retains_stage_when_disarming_the_slot_fails() {
        let backend = FailingIatRestoreBackend::new();
        let hook = GuestIatHook {
            iat_slot: IAT_TEST_IMAGE + 0x700,
            original_target: 0x1800,
            stub_addr: IAT_TEST_STAGE + STAGE_STUB_OFFSET,
            result_addr: IAT_TEST_STAGE + STAGE_RESULT_OFFSET,
            iat_slot_guest_writable: false,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        let mut transaction = IatHookTransaction::prepare(&backend, IAT_TEST_PID, &hook, 64)
            .expect("transaction should snapshot the intact IAT slot");
        let armed_stub = vec![0xA5; 64];
        let armed_result = vec![0x5A; RESULT_BLOCK_SIZE];
        backend
            .write(IAT_TEST_PID, hook.stub_addr, &armed_stub)
            .unwrap();
        backend
            .write(IAT_TEST_PID, hook.result_addr, &armed_result)
            .unwrap();
        transaction.armed = true;

        let err = transaction.restore().unwrap_err();
        assert!(err.to_string().contains("deliberately retained"));
        assert_eq!(
            backend
                .read(IAT_TEST_PID, hook.stub_addr, armed_stub.len())
                .unwrap(),
            armed_stub,
            "stage code must remain intact when IAT restoration is uncertain"
        );
        assert_eq!(
            backend
                .read(IAT_TEST_PID, hook.result_addr, armed_result.len())
                .unwrap(),
            armed_result,
            "result memory must remain intact when IAT restoration is uncertain"
        );
    }

    #[test]
    fn iat_hook_restore_waits_for_inflight_stubs_before_restoring_stage() {
        let backend = IatTestBackend::with_stage_restore();
        let hook = GuestIatHook {
            iat_slot: IAT_TEST_IMAGE + 0x700,
            original_target: 0x1800,
            stub_addr: IAT_TEST_STAGE + STAGE_STUB_OFFSET,
            result_addr: IAT_TEST_STAGE + STAGE_RESULT_OFFSET,
            iat_slot_guest_writable: false,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        let mut transaction = IatHookTransaction::prepare(&backend, IAT_TEST_PID, &hook, 64)
            .expect("transaction should snapshot the intact IAT slot");
        let armed_stub = vec![0xA5; 64];
        backend
            .write(IAT_TEST_PID, hook.stub_addr, &armed_stub)
            .unwrap();
        backend
            .write(
                IAT_TEST_PID,
                hook.result_addr + RESULT_INFLIGHT_OFFSET,
                &1u64.to_le_bytes(),
            )
            .unwrap();
        transaction.armed = true;

        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(5));
                assert_eq!(
                    backend
                        .read(IAT_TEST_PID, hook.stub_addr, armed_stub.len())
                        .unwrap(),
                    armed_stub,
                    "stage must remain intact until in-flight stubs have exited"
                );
                backend
                    .write(
                        IAT_TEST_PID,
                        hook.result_addr + RESULT_INFLIGHT_OFFSET,
                        &0u64.to_le_bytes(),
                    )
                    .unwrap();
            });
            transaction.restore().unwrap();
        });
    }

    #[test]
    fn independent_execution_satisfies_the_bootstrap_capability_requirement() {
        let mut capabilities = GuestCapabilities::default();
        capabilities.independent_execution = true;
        let missing = capabilities.missing_manual_map();
        assert!(
            !missing.contains(&"execution-bootstrap"),
            "independent execution is a valid replacement for IAT-hook bootstrap"
        );
    }

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
        assert!(capabilities.vad_spoof);
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
    fn thread_hijack_selector_requires_separate_target_thread() {
        let threads = [GuestThreadInfo {
            tid: 100,
            teb: 0x7000,
            start_address: 0x140001000,
            state: GuestThreadState::Waiting,
        }];
        let err = select_execution_thread_candidates(42, &threads, None).unwrap_err();
        assert!(err.to_string().contains("at least two active threads"));
    }

    #[test]
    fn thread_hijack_selector_prefers_later_worker_thread() {
        let threads = [
            GuestThreadInfo {
                tid: 100,
                teb: 0x7000,
                start_address: 0x140001000,
                state: GuestThreadState::Waiting,
            },
            GuestThreadInfo {
                tid: 144,
                teb: 0x9000,
                start_address: 0x140002000,
                state: GuestThreadState::Waiting,
            },
        ];
        let selected = select_execution_thread_candidates(42, &threads, None)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(selected.tid, 144);
    }

    #[test]
    fn thread_hijack_selector_excludes_hook_servicing_thread() {
        let threads = [
            GuestThreadInfo {
                tid: 100,
                teb: 0x7000,
                start_address: 0x140001000,
                state: GuestThreadState::Waiting,
            },
            GuestThreadInfo {
                tid: 144,
                teb: 0x9000,
                start_address: 0x140002000,
                state: GuestThreadState::Waiting,
            },
        ];
        let selected = select_execution_thread_candidates(42, &threads, Some(144))
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(selected.tid, 100);
    }

    #[test]
    fn thread_hijack_candidates_fall_back_in_descending_tid_order() {
        let threads = [
            GuestThreadInfo {
                tid: 100,
                teb: 0x7000,
                start_address: 0x140001000,
                state: GuestThreadState::Waiting,
            },
            GuestThreadInfo {
                tid: 144,
                teb: 0x9000,
                start_address: 0x140002000,
                state: GuestThreadState::Waiting,
            },
            GuestThreadInfo {
                tid: 200,
                teb: 0xB000,
                start_address: 0x140003000,
                state: GuestThreadState::Waiting,
            },
        ];
        let candidates = select_execution_thread_candidates(42, &threads, Some(144)).unwrap();
        assert_eq!(
            candidates
                .iter()
                .map(|thread| thread.tid)
                .collect::<Vec<_>>(),
            vec![200, 100]
        );
    }

    #[test]
    fn import_candidates_cover_forwarded_and_api_set_imports() {
        assert_eq!(
            import_module_candidates("KERNEL32.dll"),
            vec!["KERNEL32.dll", "kernelbase.dll", "ntdll.dll"]
        );
        assert_eq!(
            import_module_candidates("api-ms-win-core-synch-l1-2-0.dll"),
            vec![
                "api-ms-win-core-synch-l1-2-0.dll",
                "kernelbase.dll",
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
            iat_slot_guest_writable: true,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        let stub = call_stub(&hook, 0x5000, &[1, 2, 3, 4]);
        assert!(
            stub.windows(4).any(|w| w == [0x48, 0x83, 0xEC, 0x28]),
            "stub must reserve 32 bytes of Windows x64 shadow space plus an alignment qword"
        );
        assert!(
            stub.windows(4).any(|w| w == [0x48, 0x83, 0xC4, 0x28]),
            "stub must release the shadow space frame after the injected call"
        );
        assert!(
            stub.windows(2).any(|w| w == [0xFF, 0xD0]),
            "stub must invoke the target function via call rax"
        );
        assert!(
            stub.windows(5).any(|w| w == [0xF0, 0x4D, 0x0F, 0xB1, 0x1A]),
            "stub must atomically claim the result block so only one thread runs the injection call"
        );
        assert_stub_disarms_before_completion(&stub, &hook);
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
            iat_slot_guest_writable: true,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: Some(GuestSpoofedReturn {
                gadget_addr: 0x7000,
                stack_adjust: 0x20,
            }),
        };
        let stub = call_stub(&hook, 0x5000, &[1, 2, 3, 4]);
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
    fn iat_hook_touch_stub_materializes_pages_and_self_disarms() {
        let hook = GuestIatHook {
            iat_slot: 0x1000,
            original_target: 0x2000,
            stub_addr: 0x3000,
            result_addr: 0x4000,
            iat_slot_guest_writable: true,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        let stub = touch_stub(&hook, 0x5000, GUEST_PAGE_SIZE + 1);
        assert!(
            stub.windows(6)
                .any(|w| w == [0x80, 0x32, 0xA5, 0x80, 0x32, 0xA5]),
            "touch stub must fault in pages by flipping and restoring a byte through RDX"
        );
        assert!(
            stub.windows(7)
                .any(|w| w == [0x48, 0x81, 0xC2, 0x00, 0x10, 0x00, 0x00]),
            "touch stub must advance by guest page size"
        );
        assert_stub_disarms_before_completion(&stub, &hook);
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
            iat_slot_guest_writable: true,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        let stub = read_touch_stub(&hook, 0x5000, GUEST_PAGE_SIZE + 1);
        assert!(
            stub.windows(3).any(|w| w == [0x0F, 0xB6, 0x02]),
            "read-touch stub must fault in pages by reading through RDX"
        );
        assert!(
            !stub
                .windows(6)
                .any(|w| w == [0x80, 0x32, 0xA5, 0x80, 0x32, 0xA5]),
            "read-touch stub must not write to materialized pages"
        );
        assert_stub_disarms_before_completion(&stub, &hook);
    }

    #[test]
    fn iat_hook_preserve_touch_stub_writes_same_byte() {
        let hook = GuestIatHook {
            iat_slot: 0x1000,
            original_target: 0x2000,
            stub_addr: 0x3000,
            result_addr: 0x4000,
            iat_slot_guest_writable: true,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        let stub = preserve_touch_stub(&hook, 0x5000, GUEST_PAGE_SIZE + 1);
        assert!(
            stub.windows(5).any(|w| w == [0x0F, 0xB6, 0x02, 0x88, 0x02]),
            "preserve-touch stub must fault in pages by writing the original byte back"
        );
        assert!(
            !stub
                .windows(6)
                .any(|w| w == [0x80, 0x32, 0xA5, 0x80, 0x32, 0xA5]),
            "preserve-touch stub must not zero image-backed page contents"
        );
        assert_stub_disarms_before_completion(&stub, &hook);
    }

    #[test]
    fn iat_hook_framed_touch_stub_self_disarms() {
        let hook = GuestIatHook {
            iat_slot: 0x1000,
            original_target: 0x2000,
            stub_addr: 0x3000,
            result_addr: 0x4000,
            iat_slot_guest_writable: true,
            call_stack: GuestCallStackPolicy::RegisteredUnwind,
            spoofed_return: None,
        };
        let stub = touch_stub(&hook, 0x5000, GUEST_PAGE_SIZE);
        assert_stub_disarms_before_completion(&stub, &hook);
        assert_eq!(
            &stub[stub.len() - 2..],
            &[0xFF, 0xE0],
            "framed touch stub should tail-jump through RAX to the original import target"
        );
    }

    #[test]
    fn iat_hook_stubs_leave_read_only_slots_for_host_restoration() {
        let hook = GuestIatHook {
            iat_slot: 0x1000,
            original_target: 0x2000,
            stub_addr: 0x3000,
            result_addr: 0x4000,
            iat_slot_guest_writable: false,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        let mut slot_restore = vec![0x49, 0xBA];
        slot_restore.extend_from_slice(&hook.iat_slot.to_le_bytes());

        for stub in [
            call_stub(&hook, 0x5000, &[1, 2, 3, 4]),
            touch_stub(&hook, 0x5000, GUEST_PAGE_SIZE),
        ] {
            assert!(
                !stub
                    .windows(slot_restore.len())
                    .any(|window| window == slot_restore),
                "read-only IAT slots must be restored by the host transaction"
            );
        }
    }

    #[test]
    fn iat_hook_stubs_track_inflight_execution_until_the_tail_jump() {
        let hook = GuestIatHook {
            iat_slot: 0x1000,
            original_target: 0x2000,
            stub_addr: 0x3000,
            result_addr: 0x4000,
            iat_slot_guest_writable: false,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        for stub in [
            call_stub(&hook, 0x5000, &[1, 2, 3, 4]),
            touch_stub(&hook, 0x5000, GUEST_PAGE_SIZE),
        ] {
            let increment = stub
                .windows(4)
                .position(|window| window == [0xF0, 0x49, 0xFF, 0x02])
                .expect("stub must increment the in-flight counter");
            let decrement = stub
                .windows(4)
                .position(|window| window == [0xF0, 0x49, 0xFF, 0x0A])
                .expect("stub must decrement the in-flight counter");
            assert!(increment < decrement);
            assert_eq!(&stub[stub.len() - 2..], &[0xFF, 0xE0]);
        }
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
            iat_slot_guest_writable: true,
            call_stack: GuestCallStackPolicy::RegisteredUnwind,
            spoofed_return: None,
        };
        let stub = call_stub(&hook, 0x5000, &[1, 2, 3, 4]);
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
        let metadata = stub_unwind_metadata(None).unwrap();
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
    fn pooled_stub_unwind_metadata_excludes_bootstrap_slot() {
        let metadata = stub_unwind_metadata(Some(3)).unwrap();
        assert_eq!(
            &metadata[0..4],
            &((STAGE_CAVE_SIZE as u32) + (STAGE_STUB_OFFSET as u32)).to_le_bytes()
        );
        assert_eq!(
            &metadata[4..8],
            &((STAGE_CAVE_SIZE as u32) * 3).to_le_bytes()
        );
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
            com_descriptor: crate::pe::Dir { rva: 0, size: 0 },
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
            characteristics: 0,
            subsystem: 0,
            dll_characteristics: 0,
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
        assert!(
            GUEST_PROC_TRAMPOLINE
                .windows(5)
                .any(|w| w == [0x48, 0x89, 0x44, 0x24, 0x20])
        );
        assert!(
            GUEST_PROC_TRAMPOLINE
                .windows(5)
                .any(|w| w == [0x48, 0x89, 0x44, 0x24, 0x28])
        );
    }

    #[test]
    fn direct_iat_call_stages_six_arguments_with_x64_stack_alignment() {
        let hook = GuestIatHook {
            iat_slot: 0x1000,
            original_target: 0x2000,
            stub_addr: 0x3000,
            result_addr: 0x4000,
            iat_slot_guest_writable: true,
            call_stack: GuestCallStackPolicy::Native,
            spoofed_return: None,
        };
        let stub = call_stub(&hook, 0x5000, &[1, 2, 3, 4, 5, 6]);
        assert!(stub.windows(4).any(|w| w == [0x48, 0x83, 0xEC, 0x38]));
        assert!(stub.windows(5).any(|w| w == [0x48, 0x89, 0x44, 0x24, 0x20]));
        assert!(stub.windows(5).any(|w| w == [0x48, 0x89, 0x44, 0x24, 0x28]));
    }

    #[test]
    fn remote_thread_thunk_installs_tls_then_calls_dllmain() {
        assert_eq!(&REMOTE_THREAD_DLLMAIN_THUNK[..4], &[0x53, 0x48, 0x83, 0xEC]);
        assert!(
            REMOTE_THREAD_DLLMAIN_THUNK
                .windows(4)
                .any(|w| w == [0x8B, 0x4B, 0x38, 0x48])
        );
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
    fn dllmain_thunks_activate_and_deactivate_actctx_on_execution_thread() {
        fn find_bytes(haystack: &[u8], needle: &[u8]) -> usize {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
                .expect("instruction sequence must be present")
        }
        fn short_jump_target(code: &[u8], opcode_offset: usize) -> usize {
            assert!(matches!(code[opcode_offset], 0x74 | 0x75));
            (opcode_offset + 2) + (code[opcode_offset + 1] as i8 as isize) as usize
        }

        let remote_activate = find_bytes(
            REMOTE_THREAD_DLLMAIN_THUNK,
            &[0x48, 0x8B, 0x43, 0x48, 0x48, 0x85, 0xC0, 0x74],
        );
        let remote_dllmain = short_jump_target(REMOTE_THREAD_DLLMAIN_THUNK, remote_activate + 7);
        assert_eq!(
            &REMOTE_THREAD_DLLMAIN_THUNK[remote_dllmain..remote_dllmain + 3],
            &[0x48, 0x8B, 0x03]
        );
        assert_eq!(
            short_jump_target(REMOTE_THREAD_DLLMAIN_THUNK, remote_activate + 21),
            remote_dllmain
        );
        let remote_deactivate = find_bytes(
            REMOTE_THREAD_DLLMAIN_THUNK,
            &[0x48, 0x8B, 0x43, 0x50, 0x48, 0x85, 0xC0, 0x74],
        );
        let remote_completion =
            short_jump_target(REMOTE_THREAD_DLLMAIN_THUNK, remote_deactivate + 7);
        assert_eq!(
            &REMOTE_THREAD_DLLMAIN_THUNK[remote_completion..remote_completion + 4],
            &[0x4C, 0x8B, 0x53, 0x28]
        );

        let hijack_activate = find_bytes(
            THREAD_HIJACK_THUNK,
            &[0x48, 0x8B, 0x83, 0xD8, 0, 0, 0, 0x48, 0x85, 0xC0, 0x74],
        );
        let hijack_dllmain = short_jump_target(THREAD_HIJACK_THUNK, hijack_activate + 10);
        assert_eq!(
            &THREAD_HIJACK_THUNK[hijack_dllmain..hijack_dllmain + 3],
            &[0x48, 0x8B, 0x03]
        );
        assert_eq!(
            short_jump_target(THREAD_HIJACK_THUNK, hijack_activate + 30),
            hijack_dllmain
        );
        let activation_failure_restore = find_bytes(THREAD_HIJACK_THUNK, &[0xE9, 0x3D, 0, 0, 0]);
        let restore_start = activation_failure_restore + 5 + 0x3D;
        assert_eq!(
            &THREAD_HIJACK_THUNK[restore_start..restore_start + 2],
            &[0xFF, 0xB3]
        );
        let hijack_deactivate = find_bytes(
            THREAD_HIJACK_THUNK,
            &[0x48, 0x8B, 0x83, 0xE0, 0, 0, 0, 0x48, 0x85, 0xC0, 0x74],
        );
        let hijack_completion = short_jump_target(THREAD_HIJACK_THUNK, hijack_deactivate + 10);
        assert_eq!(
            &THREAD_HIJACK_THUNK[hijack_completion..hijack_completion + 4],
            &[0x4C, 0x8B, 0x53, 0x28]
        );
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
            com_descriptor: crate::pe::Dir { rva: 0, size: 0 },
            sections: Vec::new(),
            characteristics: 0,
            subsystem: 0,
            dll_characteristics: 0,
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

    #[test]
    fn syscall_stub_parser_extracts_immediate_from_synthetic_buffer() {
        let stub = [
            0x4C, 0x8B, 0xD1, 0xB8, 0x09, 0x01, 0x00, 0x00, 0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE,
            0x7F, 0x01, 0x75, 0x03, 0x0F, 0x05, 0xC3,
        ];
        assert_eq!(parse_syscall_stub(&stub).unwrap(), 0x109);

        let minimal = [0x4C, 0x8B, 0xD1, 0xB8, 0x33, 0x00, 0x00, 0x00];
        assert_eq!(parse_syscall_stub(&minimal).unwrap(), 0x33);

        let bad_prefix = [0x90, 0x90, 0x90, 0xB8, 0x33, 0x00, 0x00, 0x00];
        assert!(parse_syscall_stub(&bad_prefix).is_err());

        let bad_opcode = [0x4C, 0x8B, 0xD1, 0x33, 0x09, 0x01, 0x00, 0x00];
        assert!(parse_syscall_stub(&bad_opcode).is_err());

        let short = [0x4C, 0x8B, 0xD1];
        assert!(parse_syscall_stub(&short).is_err());
    }
}
