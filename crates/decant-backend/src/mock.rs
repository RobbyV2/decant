use crate::{BackendError, MemoryBackend, Result};
use decant_protocol::{MemRegion, ModuleInfo, Pid, ProcessInfo};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

const PAGE: u64 = 0x1000;

#[derive(Debug, Clone)]
struct Region {
    base: u64,
    size: u64,
    readable: bool,
    writable: bool,
    executable: bool,
}

impl Region {
    fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.size
    }
    fn to_mem_region(&self) -> MemRegion {
        MemRegion {
            base: self.base,
            size: self.size,
            readable: self.readable,
            writable: self.writable,
            executable: self.executable,
        }
    }
}

#[derive(Debug)]
struct Process {
    info: ProcessInfo,
    modules: Vec<ModuleInfo>,
    exports: BTreeMap<String, Vec<(String, u64)>>,
    regions: Vec<Region>,
    mem: BTreeMap<u64, u8>,
}

impl Process {
    fn region_at(&self, addr: u64) -> Option<&Region> {
        self.regions.iter().find(|r| r.contains(addr))
    }
}

#[derive(Debug, Clone)]
pub struct MockGuest {
    inner: Arc<RwLock<Vec<Process>>>,
}

impl MockGuest {
    pub fn builder() -> GuestBuilder {
        GuestBuilder {
            processes: Vec::new(),
        }
    }
}

pub struct GuestBuilder {
    processes: Vec<Process>,
}

impl GuestBuilder {
    pub fn process(self, name: &str, pid: Pid) -> ProcessBuilder {
        ProcessBuilder {
            parent: self,
            proc: Process {
                info: ProcessInfo {
                    pid,
                    name: name.to_string(),
                },
                modules: Vec::new(),
                exports: BTreeMap::new(),
                regions: Vec::new(),
                mem: BTreeMap::new(),
            },
            cur_region: None,
        }
    }

    pub fn build(self) -> MockGuest {
        MockGuest {
            inner: Arc::new(RwLock::new(self.processes)),
        }
    }
}

struct PendingRegion {
    base: u64,
    readable: bool,
    writable: bool,
    executable: bool,
    max_written: Option<u64>,
}

pub struct ProcessBuilder {
    parent: GuestBuilder,
    proc: Process,
    cur_region: Option<PendingRegion>,
}

impl ProcessBuilder {
    pub fn module(mut self, name: &str, base: u64, size: u64) -> Self {
        self.proc.modules.push(ModuleInfo {
            name: name.to_string(),
            base,
            size,
        });
        self
    }

    pub fn export(mut self, module: &str, name: &str, addr: u64) -> Self {
        self.proc
            .exports
            .entry(module.to_ascii_lowercase())
            .or_default()
            .push((name.to_string(), addr));
        self
    }

    pub fn region(mut self, base: u64, perms: &str) -> Self {
        self.finalize_region();
        let p = perms.as_bytes();
        self.cur_region = Some(PendingRegion {
            base,
            readable: p.first() == Some(&b'r'),
            writable: p.get(1) == Some(&b'w'),
            executable: p.get(2) == Some(&b'x'),
            max_written: None,
        });
        self
    }

    pub fn bytes_at(mut self, addr: u64, bytes: &[u8]) -> Self {
        {
            let region = self
                .cur_region
                .as_mut()
                .expect("bytes_at called before .region(); open a region first");
            assert!(
                addr >= region.base,
                "bytes_at {addr:#x} is below the current region base {:#x}",
                region.base
            );
            let end = addr + bytes.len().saturating_sub(1) as u64;
            region.max_written = Some(region.max_written.map_or(end, |m| m.max(end)));
        }
        for (i, b) in bytes.iter().enumerate() {
            self.proc.mem.insert(addr + i as u64, *b);
        }
        self
    }

    pub fn u64_at(self, addr: u64, value: u64) -> Self {
        self.bytes_at(addr, &value.to_le_bytes())
    }

    pub fn u32_at(self, addr: u64, value: u32) -> Self {
        self.bytes_at(addr, &value.to_le_bytes())
    }

    fn finalize_region(&mut self) {
        if let Some(r) = self.cur_region.take() {
            let span = match r.max_written {
                Some(m) => m - r.base + 1,
                None => 0,
            };
            let size = span.div_ceil(PAGE).max(1) * PAGE;
            self.proc.regions.push(Region {
                base: r.base,
                size,
                readable: r.readable,
                writable: r.writable,
                executable: r.executable,
            });
        }
    }

    pub fn done(mut self) -> GuestBuilder {
        self.finalize_region();
        for v in self.proc.exports.values_mut() {
            v.sort();
        }
        let mut parent = self.parent;
        parent.processes.push(self.proc);
        parent
    }
}

#[derive(Debug, Clone)]
pub struct MockBackend {
    guest: MockGuest,
}

impl MockBackend {
    pub fn new(guest: MockGuest) -> Self {
        MockBackend { guest }
    }

    pub fn guest(&self) -> MockGuest {
        self.guest.clone()
    }
}

fn idx_by_pid(procs: &[Process], pid: Pid) -> Result<usize> {
    procs
        .iter()
        .position(|p| p.info.pid == pid)
        .ok_or(BackendError::NoSuchProcess {
            pid: Some(pid.0),
            name: None,
        })
}

impl MemoryBackend for MockBackend {
    fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
        let g = self.guest.inner.read().unwrap();
        Ok(g.iter().map(|p| p.info.clone()).collect())
    }

    fn process_by_pid(&self, pid: Pid) -> Result<ProcessInfo> {
        let g = self.guest.inner.read().unwrap();
        Ok(g[idx_by_pid(&g, pid)?].info.clone())
    }

    fn process_by_name(&self, name: &str) -> Result<ProcessInfo> {
        let g = self.guest.inner.read().unwrap();
        g.iter()
            .find(|p| p.info.name.eq_ignore_ascii_case(name))
            .map(|p| p.info.clone())
            .ok_or_else(|| BackendError::NoSuchProcess {
                pid: None,
                name: Some(name.to_string()),
            })
    }

    fn module_list(&self, pid: Pid) -> Result<Vec<ModuleInfo>> {
        let g = self.guest.inner.read().unwrap();
        Ok(g[idx_by_pid(&g, pid)?].modules.clone())
    }

    fn module_by_name(&self, pid: Pid, name: &str) -> Result<ModuleInfo> {
        let g = self.guest.inner.read().unwrap();
        let p = &g[idx_by_pid(&g, pid)?];
        p.modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
            .cloned()
            .ok_or_else(|| BackendError::NoSuchModule {
                pid: pid.0,
                module: name.to_string(),
            })
    }

    fn module_exports(&self, pid: Pid, module: &str) -> Result<Vec<(String, u64)>> {
        let g = self.guest.inner.read().unwrap();
        let p = &g[idx_by_pid(&g, pid)?];
        if !p
            .modules
            .iter()
            .any(|m| m.name.eq_ignore_ascii_case(module))
        {
            return Err(BackendError::NoSuchModule {
                pid: pid.0,
                module: module.to_string(),
            });
        }
        Ok(p.exports
            .get(&module.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default())
    }

    fn read(&self, pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>> {
        let g = self.guest.inner.read().unwrap();
        let p = &g[idx_by_pid(&g, pid)?];
        let mut out = Vec::with_capacity(len);
        for i in 0..len as u64 {
            let a = addr + i;
            match p.region_at(a) {
                Some(r) if r.readable => out.push(p.mem.get(&a).copied().unwrap_or(0)),
                _ => {
                    return Err(BackendError::ReadFailed {
                        addr,
                        len: len as u64,
                        reason: format!("address {a:#x} is not in a readable region"),
                    });
                }
            }
        }
        Ok(out)
    }

    fn write(&self, pid: Pid, addr: u64, data: &[u8]) -> Result<usize> {
        let mut g = self.guest.inner.write().unwrap();
        let i = idx_by_pid(&g, pid)?;
        for off in 0..data.len() as u64 {
            let a = addr + off;
            match g[i].region_at(a) {
                Some(r) if r.writable => {}
                _ => {
                    return Err(BackendError::WriteFailed {
                        addr,
                        reason: format!("address {a:#x} is not in a writable region"),
                    });
                }
            }
        }
        for (off, b) in data.iter().enumerate() {
            g[i].mem.insert(addr + off as u64, *b);
        }
        Ok(data.len())
    }

    fn memory_map(&self, pid: Pid) -> Result<Vec<MemRegion>> {
        let g = self.guest.inner.read().unwrap();
        Ok(g[idx_by_pid(&g, pid)?]
            .regions
            .iter()
            .map(Region::to_mem_region)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC: &[u8] = b"\xDE\xCA\x47\x00MAGIC";

    fn guest() -> MockGuest {
        MockGuest::builder()
            .process("target.exe", Pid(1234))
            .module("target.exe", 0x1400000000, 0x80000)
            .export("target.exe", "tick", 0x1400001000)
            .region(0x1400010000, "rw-")
            .bytes_at(0x1400010100, MAGIC)
            .u64_at(0x1400010200, 0x1400010300)
            .u32_at(0x1400010300 + 0x10, 1337)
            .done()
            .process("explorer.exe", Pid(4))
            .done()
            .build()
    }

    #[test]
    fn enumerates_processes_and_modules() {
        let b = MockBackend::new(guest());
        let procs = b.list_processes().unwrap();
        assert_eq!(procs.len(), 2);
        assert_eq!(b.process_by_name("TARGET.EXE").unwrap().pid, Pid(1234));
        assert_eq!(b.process_by_pid(Pid(4)).unwrap().name, "explorer.exe");
        let mods = b.module_list(Pid(1234)).unwrap();
        assert_eq!(mods[0].base, 0x1400000000);
    }

    #[test]
    fn planted_bytes_read_back() {
        let b = MockBackend::new(guest());
        let got = b.read(Pid(1234), 0x1400010100, MAGIC.len()).unwrap();
        assert_eq!(got, MAGIC);
        let hop = b.read(Pid(1234), 0x1400010200, 8).unwrap();
        assert_eq!(u64::from_le_bytes(hop.try_into().unwrap()), 0x1400010300);
        let term = b.read(Pid(1234), 0x1400010310, 4).unwrap();
        assert_eq!(u32::from_le_bytes(term.try_into().unwrap()), 1337);
    }

    #[test]
    fn writes_round_trip() {
        let b = MockBackend::new(guest());
        let n = b
            .write(Pid(1234), 0x1400010400, &[0xAA, 0xBB, 0xCC, 0xDD])
            .unwrap();
        assert_eq!(n, 4);
        let got = b.read(Pid(1234), 0x1400010400, 4).unwrap();
        assert_eq!(got, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn write_to_readonly_region_fails() {
        let g = MockGuest::builder()
            .process("ro.exe", Pid(1))
            .region(0x2000, "r-x")
            .bytes_at(0x2000, &[0; 8])
            .done()
            .build();
        let b = MockBackend::new(g);
        assert!(b.write(Pid(1), 0x2000, &[1]).is_err());
    }

    #[test]
    fn unwritten_bytes_in_region_read_zero() {
        let b = MockBackend::new(guest());
        let got = b.read(Pid(1234), 0x1400010000, 16).unwrap();
        assert_eq!(got, vec![0u8; 16]);
    }

    #[test]
    fn read_outside_region_fails() {
        let b = MockBackend::new(guest());
        assert!(b.read(Pid(1234), 0xdead_0000, 4).is_err());
    }

    #[test]
    fn memory_map_covers_planted_addresses() {
        let b = MockBackend::new(guest());
        let map = b.memory_map(Pid(1234)).unwrap();
        assert_eq!(map.len(), 1);
        let r = map[0];
        assert_eq!(r.base, 0x1400010000);
        assert!(r.readable && r.writable && !r.executable);
        assert!(r.base + r.size > 0x1400010314);
    }

    #[test]
    fn unknown_pid_and_module_error() {
        let b = MockBackend::new(guest());
        assert!(b.process_by_pid(Pid(9999)).is_err());
        assert!(b.module_by_name(Pid(1234), "nope.dll").is_err());
        assert!(b.module_exports(Pid(1234), "nope.dll").is_err());
    }

    #[test]
    fn declared_module_exports_returned_sorted() {
        let b = MockBackend::new(guest());
        let ex = b.module_exports(Pid(1234), "target.exe").unwrap();
        assert_eq!(ex, vec![("tick".to_string(), 0x1400001000)]);
    }
}
