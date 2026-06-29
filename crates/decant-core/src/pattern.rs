//! AOB (array-of-bytes) signature patterns with `??` wildcards.
//!
//! A pattern is a sequence of bytes, each either a concrete value or a wildcard
//! that matches anything. The textual form is space-separated tokens — two hex
//! digits (`4D`) or a wildcard (`??` or `?`), e.g. `"DE CA ?? 00 4D 41"` — the
//! same notation Cheat Engine and most signature tools use.

use crate::CoreError;

/// A parsed signature: `None` entries are wildcards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    bytes: Vec<Option<u8>>,
}

impl Pattern {
    /// Parse the space-separated AOB form. Empty patterns are rejected (an empty
    /// pattern would "match" everywhere and is never what the caller means).
    pub fn parse(s: &str) -> Result<Pattern, CoreError> {
        let mut bytes = Vec::new();
        for tok in s.split_whitespace() {
            if tok == "??" || tok == "?" {
                bytes.push(None);
            } else if tok.len() == 2 && tok.bytes().all(|c| c.is_ascii_hexdigit()) {
                bytes.push(Some(u8::from_str_radix(tok, 16).unwrap()));
            } else {
                return Err(CoreError::Pattern(format!(
                    "token {tok:?} is not a hex byte or `??` wildcard"
                )));
            }
        }
        if bytes.is_empty() {
            return Err(CoreError::Pattern("pattern is empty".into()));
        }
        Ok(Pattern { bytes })
    }

    /// Number of bytes the pattern spans.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Does the pattern match `hay` starting exactly at index 0? `hay` must be at
    /// least `self.len()` long.
    fn matches_at_start(&self, hay: &[u8]) -> bool {
        self.bytes
            .iter()
            .zip(hay)
            .all(|(p, &h)| match p {
                Some(b) => *b == h,
                None => true,
            })
    }

    /// Every offset in `hay` where the pattern matches (overlapping matches
    /// included). Returns empty if `hay` is shorter than the pattern.
    pub fn find_all(&self, hay: &[u8]) -> Vec<usize> {
        let plen = self.bytes.len();
        if hay.len() < plen {
            return Vec::new();
        }
        (0..=hay.len() - plen)
            .filter(|&i| self.matches_at_start(&hay[i..i + plen]))
            .collect()
    }

    /// Build a pattern directly from concrete bytes (no wildcards) — handy for
    /// callers that have raw bytes (e.g. a known magic header).
    pub fn from_bytes(bytes: &[u8]) -> Pattern {
        Pattern { bytes: bytes.iter().map(|b| Some(*b)).collect() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_and_wildcards() {
        let p = Pattern::parse("DE CA ?? 00 4d").unwrap();
        assert_eq!(p.len(), 5);
        assert_eq!(p.bytes, vec![Some(0xDE), Some(0xCA), None, Some(0x00), Some(0x4D)]);
    }

    #[test]
    fn rejects_garbage_and_empty() {
        assert!(Pattern::parse("ZZ").is_err());
        assert!(Pattern::parse("DEAD").is_err()); // 4 digits is not one byte token
        assert!(Pattern::parse("   ").is_err());
        assert!(Pattern::parse("").is_err());
    }

    #[test]
    fn single_question_mark_is_a_wildcard() {
        let p = Pattern::parse("AA ? BB").unwrap();
        assert_eq!(p.bytes, vec![Some(0xAA), None, Some(0xBB)]);
    }

    #[test]
    fn find_all_with_wildcards_and_overlap() {
        let hay = [0xAA, 0xBB, 0xAA, 0xBB, 0xAA];
        assert_eq!(Pattern::parse("AA BB").unwrap().find_all(&hay), vec![0, 2]);
        // Wildcard matches anything.
        assert_eq!(Pattern::parse("AA ??").unwrap().find_all(&hay), vec![0, 2]);
        // Overlapping matches are all reported.
        let hh = [0x5A, 0x5A, 0x5A, 0x5A];
        assert_eq!(Pattern::parse("5A 5A").unwrap().find_all(&hh), vec![0, 1, 2]);
    }

    #[test]
    fn no_match_and_too_short() {
        assert!(Pattern::parse("AA BB").unwrap().find_all(&[0xAA]).is_empty());
        assert!(Pattern::parse("FF").unwrap().find_all(&[0x00, 0x01]).is_empty());
    }
}
