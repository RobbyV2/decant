use crate::pattern::Pattern;
use crate::{CoreError, Result};
use decant_backend::{MemoryBackend, Pid};

pub const DEFAULT_CHUNK: usize = 1024 * 1024;

pub fn scan(backend: &dyn MemoryBackend, pid: Pid, pattern: &Pattern) -> Result<Vec<u64>> {
    scan_with_chunk(backend, pid, pattern, DEFAULT_CHUNK)
}

pub fn scan_with_chunk(
    backend: &dyn MemoryBackend,
    pid: Pid,
    pattern: &Pattern,
    chunk: usize,
) -> Result<Vec<u64>> {
    let plen = pattern.len();
    if plen == 0 {
        return Err(CoreError::Pattern("empty pattern".into()));
    }
    let chunk = chunk.max(1);
    let overlap = (plen - 1) as u64;

    let mut hits = Vec::new();
    for region in backend.memory_map(pid)? {
        if !region.readable || region.size < plen as u64 {
            continue;
        }
        let region_end = region.base + region.size;
        let mut pos: u64 = 0;

        while pos < region.size {
            let win_start = region.base + pos;
            let win_len = ((chunk as u64) + overlap).min(region.size - pos);
            let bytes = match backend.read(pid, win_start, win_len as usize) {
                Ok(b) => b,
                Err(_) => break,
            };

            let is_last = pos + (chunk as u64) >= region.size;
            for off in pattern.find_all(&bytes) {
                // accept only matches starting in this chunk's core, except final window
                if (off as u64) < chunk as u64 || is_last {
                    hits.push(win_start + off as u64);
                }
            }
            pos += chunk as u64;
        }
        debug_assert!(region.base + pos.min(region.size) <= region_end);
    }

    hits.sort_unstable();
    hits.dedup();
    Ok(hits)
}

pub fn scan_str(backend: &dyn MemoryBackend, pid: Pid, pattern: &str) -> Result<Vec<u64>> {
    let pat = Pattern::parse(pattern)?;
    scan(backend, pid, &pat)
}

pub fn scan_with_handler<F: FnMut(u64) -> bool>(
    backend: &dyn MemoryBackend,
    pid: Pid,
    pattern: &Pattern,
    mut handler: F,
) -> Result<()> {
    scan_with_handler_and_chunk(backend, pid, pattern, DEFAULT_CHUNK, &mut handler)
}

pub fn scan_with_handler_and_chunk<F: FnMut(u64) -> bool>(
    backend: &dyn MemoryBackend,
    pid: Pid,
    pattern: &Pattern,
    chunk: usize,
    handler: &mut F,
) -> Result<()> {
    let plen = pattern.len();
    if plen == 0 {
        return Err(CoreError::Pattern("empty pattern".into()));
    }
    let chunk = chunk.max(1);
    let overlap = (plen - 1) as u64;
    let mut stop = false;
    for region in backend.memory_map(pid)? {
        if stop {
            break;
        }
        if !region.readable || region.size < plen as u64 {
            continue;
        }
        let mut pos: u64 = 0;
        while pos < region.size {
            let win_start = region.base + pos;
            let win_len = ((chunk as u64) + overlap).min(region.size - pos);
            let bytes = match backend.read(pid, win_start, win_len as usize) {
                Ok(b) => b,
                Err(_) => break,
            };
            let is_last = pos + (chunk as u64) >= region.size;
            pattern.find_all_with_handler(&bytes, |off| {
                if (off as u64) < chunk as u64 || is_last {
                    let hit = win_start + off as u64;
                    if !handler(hit) {
                        stop = true;
                        return false;
                    }
                }
                true
            });
            if stop {
                break;
            }
            pos += chunk as u64;
        }
    }
    Ok(())
}

pub fn scan_region(
    backend: &dyn MemoryBackend,
    pid: Pid,
    pattern: &Pattern,
    base: u64,
    size: u64,
) -> Result<Vec<u64>> {
    let plen = pattern.len();
    if plen == 0 {
        return Err(CoreError::Pattern("empty pattern".into()));
    }
    if size < plen as u64 {
        return Ok(Vec::new());
    }
    let chunk = DEFAULT_CHUNK.min(size as usize);
    let overlap = (plen - 1) as u64;
    let mut hits = Vec::new();
    let mut pos: u64 = 0;
    while pos < size {
        let win_start = base + pos;
        let win_len = ((chunk as u64) + overlap).min(size - pos);
        let bytes = match backend.read(pid, win_start, win_len as usize) {
            Ok(b) => b,
            Err(_) => break,
        };
        let is_last = pos + (chunk as u64) >= size;
        for off in pattern.find_all(&bytes) {
            if (off as u64) < chunk as u64 || is_last {
                hits.push(win_start + off as u64);
            }
        }
        pos += chunk as u64;
    }
    hits.sort_unstable();
    hits.dedup();
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use decant_backend::fixtures::{DEMO_MAGIC, DEMO_MAGIC_ADDR, DEMO_TARGET_PID, demo_backend};
    use decant_backend::{MockBackend, MockGuest};

    #[test]
    fn finds_demo_magic_by_signature() {
        let b = demo_backend();
        let pat = Pattern::from_bytes(&DEMO_MAGIC);
        let hits = scan(&b, DEMO_TARGET_PID, &pat).unwrap();
        assert_eq!(hits, vec![DEMO_MAGIC_ADDR]);
    }

    #[test]
    fn finds_magic_with_wildcards() {
        let b = demo_backend();
        let pat = Pattern::parse("44 45 43 41 4E 54 3A 3A 4D 41 47 49 43 00 ?? ??").unwrap();
        let hits = scan(&b, DEMO_TARGET_PID, &pat).unwrap();
        assert_eq!(hits, vec![DEMO_MAGIC_ADDR]);
    }

    #[test]
    fn no_match_returns_empty() {
        let b = demo_backend();
        let pat = Pattern::parse("11 22 33 44 55 66 77 88").unwrap();
        assert!(scan(&b, DEMO_TARGET_PID, &pat).unwrap().is_empty());
    }

    #[test]
    fn matches_straddling_chunk_boundary_found_once() {
        let b = demo_backend();
        let pat = Pattern::from_bytes(&DEMO_MAGIC);
        for chunk in [1usize, 2, 3, 5, 7, 8, 16, 17] {
            let hits = scan_with_chunk(&b, DEMO_TARGET_PID, &pat, chunk).unwrap();
            assert_eq!(hits, vec![DEMO_MAGIC_ADDR], "chunk={chunk}");
        }
    }

    #[test]
    fn multiple_matches_across_a_region() {
        let marker = [0xAB, 0xCD, 0xEF];
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(0x10000, "rw-")
            .bytes_at(0x10010, &marker)
            .bytes_at(0x10800, &marker)
            .done()
            .build();
        let b = MockBackend::new(guest);
        let pat = Pattern::from_bytes(&marker);
        assert_eq!(scan(&b, Pid(1), &pat).unwrap(), vec![0x10010, 0x10800]);
    }

    #[test]
    fn non_readable_regions_are_skipped() {
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(0x20000, "-w-")
            .bytes_at(0x20000, &[0xAA, 0xBB])
            .done()
            .build();
        let b = MockBackend::new(guest);
        assert!(
            scan(&b, Pid(1), &Pattern::parse("AA BB").unwrap())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn scan_handler_stops_early() {
        let marker = [0xAB, 0xCD, 0xEF];
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(0x10000, "rw-")
            .bytes_at(0x10010, &marker)
            .bytes_at(0x10800, &marker)
            .bytes_at(0x11000, &marker)
            .done()
            .build();
        let b = MockBackend::new(guest);
        let pat = Pattern::from_bytes(&marker);
        let mut hits = Vec::new();
        scan_with_handler(&b, Pid(1), &pat, |addr| {
            hits.push(addr);
            hits.len() < 2
        })
        .unwrap();
        assert_eq!(hits, vec![0x10010, 0x10800]);
    }

    #[test]
    fn scan_region_targets_one_window() {
        let marker = [0xAB, 0xCD, 0xEF];
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(0x10000, "rw-")
            .bytes_at(0x10010, &marker)
            .bytes_at(0x10800, &marker)
            .bytes_at(0x11000, &marker)
            .done()
            .build();
        let b = MockBackend::new(guest);
        let pat = Pattern::from_bytes(&marker);
        let hits = scan_region(&b, Pid(1), &pat, 0x10500, 0x800).unwrap();
        assert_eq!(hits, vec![0x10800]);
    }

    use decant_backend::Pid;
}
