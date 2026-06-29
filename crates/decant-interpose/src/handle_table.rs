//! # handle_table — the synthetic handle table (and its host-testable core)
//!
//! Decant's interposer hands the tool **synthetic handles** for everything that
//! maps to the daemon: `OpenProcess` returns one bound to a guest pid, and each
//! `CreateToolhelp32Snapshot`/`EnumProcesses` result is captured into one holding
//! the daemon-sourced list plus an iteration cursor. A handle the carafe minted is
//! "ours"; anything else is a real Wine handle that must be **forwarded**
//! untouched (spec Phase 3: "mine vs forward-to-Wine").
//!
//! ## Disambiguation that never collides with a real handle
//!
//! Real Win32 handles are small, kernel-allocated values (low, ~`< 2^24`, multiples
//! of four) or the pseudo-handles `-1`/`-2` (top bits all-ones). We mint ours from a
//! recognizable high tag, [`SYNTH_TAG`] in the top 16 bits, so [`is_synthetic`] is a
//! pure range test that can never alias a plausible real handle. The red-team unit
//! tests below assert exactly that.
//!
//! ## Why the core is platform-agnostic
//!
//! The pure logic ([`HandleTable`], [`is_synthetic`], alloc/lookup/free, snapshot
//! cursors) touches no Win32 — it is a `HashMap` and some integers — so it lives
//! here unconditionally and is unit-tested by `cargo test` on the host with no Wine
//! (spec Phase 3: "handle-table red-team green"). The `#[cfg(windows)]` global
//! wrappers at the bottom are the only part that needs a process-wide singleton.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use decant_protocol::{ModuleInfo, Pid, ProcessInfo};

/// Tag occupying the top 16 bits of every synthetic handle. `0xDEC0` ("decant") is
/// outside the range any real Wine handle or pseudo-handle occupies.
pub const SYNTH_TAG: usize = 0xDEC0;

/// `true` iff `h` is a handle the carafe minted (top 16 bits == [`SYNTH_TAG`]).
///
/// Pure and `const`: a real handle (small integer) has top bits `0x0000`; the
/// pseudo-handles `-1`/`-2` have top bits `0xFFFF`; neither equals `0xDEC0`.
#[inline]
pub const fn is_synthetic(h: usize) -> bool {
    (h >> 48) == SYNTH_TAG
}

/// Compose the synthetic handle value for table index `index` (1-based).
#[inline]
const fn make_handle(index: usize) -> usize {
    (SYNTH_TAG << 48) | (index & 0x0000_FFFF_FFFF_FFFF)
}

/// What a synthetic handle stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// An opened guest process — `ReadProcessMemory`/`WriteProcessMemory` on this
    /// handle marshal to the daemon for this pid.
    Process(Pid),
    /// A `TH32CS_SNAPPROCESS` snapshot: the captured process list + a cursor that
    /// `Process32First`/`Process32Next` walk.
    ProcessSnapshot { items: Vec<ProcessInfo>, cursor: usize },
    /// A `TH32CS_SNAPMODULE` snapshot: the captured module list + a cursor that
    /// `Module32First`/`Module32Next` walk.
    ModuleSnapshot { items: Vec<ModuleInfo>, cursor: usize },
}

/// The pure, allocator-agnostic handle table. One process owns one of these behind
/// a `Mutex`; the methods here are deliberately free of any Win32 so the host test
/// suite can red-team them directly.
#[derive(Debug, Default)]
pub struct HandleTable {
    next_index: usize,
    map: HashMap<usize, Entry>,
}

impl HandleTable {
    /// A fresh, empty table. First issued index is 1 (never 0, so a synthetic
    /// handle is never `NULL`).
    pub fn new() -> Self {
        HandleTable { next_index: 1, map: HashMap::new() }
    }

    /// Insert `entry`, returning its freshly minted synthetic handle.
    fn alloc(&mut self, entry: Entry) -> usize {
        let index = self.next_index;
        self.next_index += 1;
        let handle = make_handle(index);
        self.map.insert(handle, entry);
        handle
    }

    /// Mint a process handle bound to `pid`.
    pub fn alloc_process(&mut self, pid: Pid) -> usize {
        self.alloc(Entry::Process(pid))
    }

    /// Capture a process-snapshot list into a new handle (cursor at the start).
    pub fn alloc_process_snapshot(&mut self, items: Vec<ProcessInfo>) -> usize {
        self.alloc(Entry::ProcessSnapshot { items, cursor: 0 })
    }

    /// Capture a module-snapshot list into a new handle (cursor at the start).
    pub fn alloc_module_snapshot(&mut self, items: Vec<ModuleInfo>) -> usize {
        self.alloc(Entry::ModuleSnapshot { items, cursor: 0 })
    }

    /// The guest pid behind a process handle, or `None` if `h` is not a process
    /// handle we issued (a snapshot handle, a freed handle, or a real one).
    pub fn pid_for(&self, h: usize) -> Option<Pid> {
        match self.map.get(&h) {
            Some(Entry::Process(p)) => Some(*p),
            _ => None,
        }
    }

    /// Drop a synthetic handle. Returns `true` iff it was present (so a double-free
    /// reports `false` on the second call).
    pub fn free(&mut self, h: usize) -> bool {
        self.map.remove(&h).is_some()
    }

    /// Walk a process snapshot. `reset` (used by `Process32First`) rewinds the
    /// cursor to the start first; otherwise (`Process32Next`) it advances. Returns
    /// the next entry, or `None` past the end / on a non-process-snapshot handle.
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

    /// Walk a module snapshot. Mirrors [`snapshot_next_process`].
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

    /// Number of live synthetic handles (test/diagnostic helper).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the table holds no live handles.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Process-wide singleton + thin global wrappers used by the hooks.
//
// These are not gated on `windows`: they are pure std (`Mutex`/`OnceLock`) and
// keeping them buildable on the host means the whole module — including these —
// is exercised by `cargo test`.
// ---------------------------------------------------------------------------

/// The one table for this process, created on first use.
fn table() -> &'static Mutex<HandleTable> {
    static TABLE: OnceLock<Mutex<HandleTable>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HandleTable::new()))
}

/// Mint a process handle for `pid` (0 on lock poisoning — treated as failure).
pub fn open_process(pid: Pid) -> usize {
    table().lock().map(|mut t| t.alloc_process(pid)).unwrap_or(0)
}

/// Capture a process snapshot, returning its handle (0 on lock poisoning).
pub fn new_process_snapshot(items: Vec<ProcessInfo>) -> usize {
    table().lock().map(|mut t| t.alloc_process_snapshot(items)).unwrap_or(0)
}

/// Capture a module snapshot, returning its handle (0 on lock poisoning).
pub fn new_module_snapshot(items: Vec<ModuleInfo>) -> usize {
    table().lock().map(|mut t| t.alloc_module_snapshot(items)).unwrap_or(0)
}

/// The pid behind a process handle, if any.
pub fn pid_for(h: usize) -> Option<Pid> {
    table().lock().ok().and_then(|t| t.pid_for(h))
}

/// Drop a synthetic handle, reporting whether it was present.
pub fn free(h: usize) -> bool {
    table().lock().map(|mut t| t.free(h)).unwrap_or(false)
}

/// Next process entry from a snapshot handle.
pub fn snapshot_next_process(h: usize, reset: bool) -> Option<ProcessInfo> {
    table().lock().ok().and_then(|mut t| t.snapshot_next_process(h, reset))
}

/// Next module entry from a snapshot handle.
pub fn snapshot_next_module(h: usize, reset: bool) -> Option<ModuleInfo> {
    table().lock().ok().and_then(|mut t| t.snapshot_next_module(h, reset))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Handle values a real Wine/Windows process could plausibly hand us. None may
    /// ever be mistaken for synthetic.
    const PLAUSIBLE_REAL: &[usize] = &[
        0x0,
        0x4,
        0x8,
        0x4c,
        0x1234,
        0x0000_7FFF_FFFF_0000, // a high but legitimate user-space pointer-ish handle
        0xFFFF_FFFF_FFFF_FFFF, // GetCurrentProcess pseudo-handle (-1)
        0xFFFF_FFFF_FFFF_FFFE, // GetCurrentThread pseudo-handle (-2)
        0x0000_0000_FFFF_FFFF, // 32-bit all-ones
    ];

    #[test]
    fn synthetic_handles_never_collide_with_real_ones() {
        for &real in PLAUSIBLE_REAL {
            assert!(!is_synthetic(real), "real handle {real:#x} misclassified as synthetic");
        }
        let mut t = HandleTable::new();
        // Mint a pile of handles of every kind; every one must read back synthetic
        // and must differ from every plausible real value.
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
        let b = t.alloc_process(Pid(1)); // same pid, must still be a distinct handle
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
        // The cursor only ever moves forward, so a freed handle's value cannot be
        // handed back out (no use-after-free aliasing).
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
        // First rewinds + returns [0]; Next returns [1]; Next again ends.
        let first = t.snapshot_next_process(h, true).unwrap();
        assert_eq!(first.name, "decant-target.exe");
        let second = t.snapshot_next_process(h, false).unwrap();
        assert_eq!(second.name, "explorer.exe");
        assert!(t.snapshot_next_process(h, false).is_none());
        // First again rewinds to the start.
        assert_eq!(t.snapshot_next_process(h, true).unwrap().name, "decant-target.exe");
    }

    #[test]
    fn module_snapshot_iterates_and_rejects_wrong_kind() {
        let mut t = HandleTable::new();
        let modules = vec![ModuleInfo { name: "decant-target.exe".into(), base: 0x1_4000_0000, size: 0x40000 }];
        let h = t.alloc_module_snapshot(modules);
        assert_eq!(t.snapshot_next_module(h, true).unwrap().name, "decant-target.exe");
        assert!(t.snapshot_next_module(h, false).is_none());
        // A process-snapshot walk over a module handle yields nothing.
        assert!(t.snapshot_next_process(h, true).is_none());
    }
}
