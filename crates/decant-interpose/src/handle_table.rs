use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use decant_protocol::{ModuleInfo, Pid, ProcessInfo};

pub const SYNTH_TAG: usize = 0xDEC0;

#[inline]
pub const fn is_synthetic(h: usize) -> bool {
    (h >> 48) == SYNTH_TAG
}

#[inline]
const fn make_handle(index: usize) -> usize {
    (SYNTH_TAG << 48) | (index & 0x0000_FFFF_FFFF_FFFF)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Process(Pid),
    ProcessSnapshot { items: Vec<ProcessInfo>, cursor: usize },
    ModuleSnapshot { items: Vec<ModuleInfo>, cursor: usize },
}

#[derive(Debug, Default)]
pub struct HandleTable {
    next_index: usize,
    map: HashMap<usize, Entry>,
}

impl HandleTable {
    pub fn new() -> Self {
        HandleTable { next_index: 1, map: HashMap::new() }
    }

    fn alloc(&mut self, entry: Entry) -> usize {
        let index = self.next_index;
        self.next_index += 1;
        let handle = make_handle(index);
        self.map.insert(handle, entry);
        handle
    }

    pub fn alloc_process(&mut self, pid: Pid) -> usize {
        self.alloc(Entry::Process(pid))
    }

    pub fn alloc_process_snapshot(&mut self, items: Vec<ProcessInfo>) -> usize {
        self.alloc(Entry::ProcessSnapshot { items, cursor: 0 })
    }

    pub fn alloc_module_snapshot(&mut self, items: Vec<ModuleInfo>) -> usize {
        self.alloc(Entry::ModuleSnapshot { items, cursor: 0 })
    }

    pub fn pid_for(&self, h: usize) -> Option<Pid> {
        match self.map.get(&h) {
            Some(Entry::Process(p)) => Some(*p),
            _ => None,
        }
    }

    pub fn free(&mut self, h: usize) -> bool {
        self.map.remove(&h).is_some()
    }

    pub fn snapshot_next_process(&mut self, h: usize, reset: bool) -> Option<ProcessInfo> {
        match self.map.get_mut(&h) {
            Some(Entry::ProcessSnapshot { items, cursor }) => {
                if reset {
                    *cursor = 0;
                }
                if *cursor < items.len() {
                    let item = items[*cursor].clone();
                    *cursor += 1;
                    Some(item)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn snapshot_next_module(&mut self, h: usize, reset: bool) -> Option<ModuleInfo> {
        match self.map.get_mut(&h) {
            Some(Entry::ModuleSnapshot { items, cursor }) => {
                if reset {
                    *cursor = 0;
                }
                if *cursor < items.len() {
                    let item = items[*cursor].clone();
                    *cursor += 1;
                    Some(item)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

fn table() -> &'static Mutex<HandleTable> {
    static TABLE: OnceLock<Mutex<HandleTable>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HandleTable::new()))
}

pub fn open_process(pid: Pid) -> usize {
    table().lock().map(|mut t| t.alloc_process(pid)).unwrap_or(0)
}

pub fn new_process_snapshot(items: Vec<ProcessInfo>) -> usize {
    table().lock().map(|mut t| t.alloc_process_snapshot(items)).unwrap_or(0)
}

pub fn new_module_snapshot(items: Vec<ModuleInfo>) -> usize {
    table().lock().map(|mut t| t.alloc_module_snapshot(items)).unwrap_or(0)
}

pub fn pid_for(h: usize) -> Option<Pid> {
    table().lock().ok().and_then(|t| t.pid_for(h))
}

pub fn free(h: usize) -> bool {
    table().lock().map(|mut t| t.free(h)).unwrap_or(false)
}

pub fn snapshot_next_process(h: usize, reset: bool) -> Option<ProcessInfo> {
    table().lock().ok().and_then(|mut t| t.snapshot_next_process(h, reset))
}

pub fn snapshot_next_module(h: usize, reset: bool) -> Option<ModuleInfo> {
    table().lock().ok().and_then(|mut t| t.snapshot_next_module(h, reset))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAUSIBLE_REAL: &[usize] = &[
        0x0,
        0x4,
        0x8,
        0x4c,
        0x1234,
        0x0000_7FFF_FFFF_0000,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFE,
        0x0000_0000_FFFF_FFFF,
    ];

    #[test]
    fn synthetic_handles_never_collide_with_real_ones() {
        for &real in PLAUSIBLE_REAL {
            assert!(!is_synthetic(real), "real handle {real:#x} misclassified as synthetic");
        }
        let mut t = HandleTable::new();
        let mut minted = Vec::new();
        for i in 0..1000 {
            minted.push(t.alloc_process(Pid(i)));
        }
        minted.push(t.alloc_process_snapshot(vec![]));
        minted.push(t.alloc_module_snapshot(vec![]));
        for &h in &minted {
            assert!(is_synthetic(h), "minted handle {h:#x} not recognized as synthetic");
            assert!(!PLAUSIBLE_REAL.contains(&h));
        }
    }

    #[test]
    fn allocations_are_distinct() {
        let mut t = HandleTable::new();
        let a = t.alloc_process(Pid(1));
        let b = t.alloc_process(Pid(1));
        let c = t.alloc_process_snapshot(vec![]);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn pid_lookup_only_for_process_handles() {
        let mut t = HandleTable::new();
        let p = t.alloc_process(Pid(1234));
        let snap = t.alloc_process_snapshot(vec![]);
        assert_eq!(t.pid_for(p), Some(Pid(1234)));
        assert_eq!(t.pid_for(snap), None, "a snapshot handle is not a process handle");
        assert_eq!(t.pid_for(0x4), None, "a real handle has no pid");
    }

    #[test]
    fn double_close_reports_false_the_second_time() {
        let mut t = HandleTable::new();
        let h = t.alloc_process(Pid(7));
        assert!(t.free(h), "first free of a live handle is true");
        assert!(!t.free(h), "double-free is false");
        assert_eq!(t.pid_for(h), None, "a freed handle resolves to nothing");
    }

    #[test]
    fn free_of_unknown_handle_is_false() {
        let mut t = HandleTable::new();
        assert!(!t.free(make_handle(999)), "freeing a never-issued synthetic handle is false");
        assert!(!t.free(0x4), "freeing a real handle via the table is false");
    }

    #[test]
    fn freed_index_is_not_reissued() {
        let mut t = HandleTable::new();
        let a = t.alloc_process(Pid(1));
        t.free(a);
        let b = t.alloc_process(Pid(2));
        assert_ne!(a, b);
    }

    #[test]
    fn process_snapshot_iterates_with_first_then_next() {
        let mut t = HandleTable::new();
        let items = vec![
            ProcessInfo { pid: Pid(1234), name: "decant-target.exe".into() },
            ProcessInfo { pid: Pid(4), name: "explorer.exe".into() },
        ];
        let h = t.alloc_process_snapshot(items);
        let first = t.snapshot_next_process(h, true).unwrap();
        assert_eq!(first.name, "decant-target.exe");
        let second = t.snapshot_next_process(h, false).unwrap();
        assert_eq!(second.name, "explorer.exe");
        assert!(t.snapshot_next_process(h, false).is_none());
        assert_eq!(t.snapshot_next_process(h, true).unwrap().name, "decant-target.exe");
    }

    #[test]
    fn module_snapshot_iterates_and_rejects_wrong_kind() {
        let mut t = HandleTable::new();
        let modules = vec![ModuleInfo { name: "decant-target.exe".into(), base: 0x1_4000_0000, size: 0x40000 }];
        let h = t.alloc_module_snapshot(modules);
        assert_eq!(t.snapshot_next_module(h, true).unwrap().name, "decant-target.exe");
        assert!(t.snapshot_next_module(h, false).is_none());
        assert!(t.snapshot_next_process(h, true).is_none());
    }
}
