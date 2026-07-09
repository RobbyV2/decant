use crate::CoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    bytes: Vec<Option<u8>>,
}

impl Pattern {
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

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn matches_at_start(&self, hay: &[u8]) -> bool {
        self.bytes.iter().zip(hay).all(|(p, &h)| match p {
            Some(b) => *b == h,
            None => true,
        })
    }

    fn has_wildcards(&self) -> bool {
        self.bytes.iter().any(|b| b.is_none())
    }

    fn bmh_shift_table(&self) -> [usize; 256] {
        let plen = self.bytes.len();
        let mut table = [plen; 256];
        for (i, b) in self.bytes.iter().enumerate() {
            if let Some(v) = b {
                table[*v as usize] = plen - 1 - i;
            }
        }
        table
    }

    pub fn find_all(&self, hay: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        self.find_all_with_handler(hay, |off| {
            out.push(off);
            true
        });
        out
    }

    pub fn find_all_with_handler<F: FnMut(usize) -> bool>(&self, hay: &[u8], mut handler: F) {
        let plen = self.bytes.len();
        if plen == 0 || hay.len() < plen {
            return;
        }
        if self.has_wildcards() {
            for i in 0..=hay.len() - plen {
                if self.matches_at_start(&hay[i..i + plen]) && !handler(i) {
                    return;
                }
            }
            return;
        }
        let table = self.bmh_shift_table();
        let mut i = 0usize;
        while i + plen <= hay.len() {
            let mut j = plen;
            while j > 0 && self.bytes[j - 1] == Some(hay[i + j - 1]) {
                j -= 1;
            }
            if j == 0 {
                if !handler(i) {
                    return;
                }
                i += 1;
            } else {
                let shift = table[hay[i + plen - 1] as usize];
                i += shift.max(1);
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Pattern {
        Pattern {
            bytes: bytes.iter().map(|b| Some(*b)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_and_wildcards() {
        let p = Pattern::parse("DE CA ?? 00 4d").unwrap();
        assert_eq!(p.len(), 5);
        assert_eq!(
            p.bytes,
            vec![Some(0xDE), Some(0xCA), None, Some(0x00), Some(0x4D)]
        );
    }

    #[test]
    fn rejects_garbage_and_empty() {
        assert!(Pattern::parse("ZZ").is_err());
        assert!(Pattern::parse("DEAD").is_err());
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
        assert_eq!(Pattern::parse("AA ??").unwrap().find_all(&hay), vec![0, 2]);
        let hh = [0x5A, 0x5A, 0x5A, 0x5A];
        assert_eq!(
            Pattern::parse("5A 5A").unwrap().find_all(&hh),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn no_match_and_too_short() {
        assert!(
            Pattern::parse("AA BB")
                .unwrap()
                .find_all(&[0xAA])
                .is_empty()
        );
        assert!(
            Pattern::parse("FF")
                .unwrap()
                .find_all(&[0x00, 0x01])
                .is_empty()
        );
    }

    #[test]
    fn bmh_exact_pattern_matches_naive() {
        let mut hay = vec![0u8; 4096];
        for (i, b) in hay.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        hay[100..104].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        hay[2000..2004].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let pat = Pattern::parse("DE AD BE EF").unwrap();
        let naive: Vec<usize> = (0..=hay.len() - 4)
            .filter(|&i| pat.matches_at_start(&hay[i..i + 4]))
            .collect();
        assert_eq!(pat.find_all(&hay), naive);
        assert_eq!(pat.find_all(&hay), vec![100, 2000]);
    }

    #[test]
    fn handler_early_stop() {
        let hay = [0xAA, 0xBB, 0xCC, 0xAA, 0xBB, 0xCC, 0xAA, 0xBB, 0xCC];
        let pat = Pattern::parse("AA BB").unwrap();
        let mut hits = Vec::new();
        let mut count = 0;
        pat.find_all_with_handler(&hay, |off| {
            count += 1;
            hits.push(off);
            count < 2
        });
        assert_eq!(hits, vec![0, 3]);
    }

    #[test]
    fn handler_wildcard_early_stop() {
        let hay = [0xAA, 0x01, 0xBB, 0xAA, 0x02, 0xBB, 0xAA, 0x03, 0xBB];
        let pat = Pattern::parse("AA ?? BB").unwrap();
        let mut hits = Vec::new();
        pat.find_all_with_handler(&hay, |off| {
            hits.push(off);
            false
        });
        assert_eq!(hits, vec![0]);
    }
}
