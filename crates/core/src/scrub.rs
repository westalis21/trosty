use crate::placeholder;
use crate::vault::{SecretName, MIN_SECRET_LEN};
use aho_corasick::{AhoCorasick, MatchKind};
use base64::Engine;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

pub struct Scrubber {
    ac: Option<AhoCorasick>,
    replacements: Vec<String>,
    max_len: usize,
}

fn variants(value: &str) -> Vec<String> {
    let mut out = vec![
        value.to_string(),
        base64::engine::general_purpose::STANDARD.encode(value),
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(value),
        hex::encode(value),
        utf8_percent_encode(value, NON_ALPHANUMERIC).to_string(),
    ];
    out.sort();
    out.dedup();
    out.retain(|v| v.len() >= MIN_SECRET_LEN);
    out
}

impl Scrubber {
    pub fn new(secrets: &[(SecretName, String)]) -> Self {
        let mut patterns = Vec::new();
        let mut replacements = Vec::new();
        for (name, value) in secrets {
            for v in variants(value) {
                patterns.push(v);
                replacements.push(placeholder(&name.to_string()));
            }
        }
        let max_len = patterns.iter().map(String::len).max().unwrap_or(0);
        let ac = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&patterns)
                    .expect("static patterns"),
            )
        };
        Self {
            ac,
            replacements,
            max_len,
        }
    }

    pub fn max_pattern_len(&self) -> usize {
        self.max_len
    }

    pub fn scrub(&self, text: &str) -> String {
        match &self.ac {
            None => text.to_string(),
            Some(ac) => {
                let mut out = String::with_capacity(text.len());
                let mut last = 0;
                for m in ac.find_iter(text) {
                    out.push_str(&text[last..m.start()]);
                    out.push_str(&self.replacements[m.pattern().as_usize()]);
                    last = m.end();
                }
                out.push_str(&text[last..]);
                out
            }
        }
    }

    pub fn stream(&self) -> StreamScrubber<'_> {
        StreamScrubber {
            scrubber: self,
            carry: String::new(),
        }
    }
}

pub struct StreamScrubber<'a> {
    scrubber: &'a Scrubber,
    carry: String,
}

impl StreamScrubber<'_> {
    /// Feed a chunk; returns masked text that is safe to emit now.
    /// Holds back up to (max_pattern_len - 1) trailing bytes in case a
    /// secret is split across chunk boundaries.
    pub fn feed(&mut self, chunk: &str) -> String {
        self.carry.push_str(chunk);
        let hold = self.scrubber.max_pattern_len().saturating_sub(1);
        if self.carry.len() <= hold {
            return String::new();
        }
        // Candidate cut point: everything except the held tail.
        let mut cut = self.carry.len() - hold;
        while !self.carry.is_char_boundary(cut) {
            cut -= 1;
        }
        // Don't cut through a match that starts before `cut`.
        if let Some(ac) = &self.scrubber.ac {
            for m in ac.find_iter(&self.carry) {
                if m.start() < cut && m.end() > cut {
                    cut = m.start();
                }
            }
        }
        let emit: String = self.scrubber.scrub(&self.carry[..cut]);
        self.carry.drain(..cut);
        emit
    }

    pub fn finish(self) -> String {
        self.scrubber.scrub(&self.carry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn scr() -> Scrubber {
        let n = SecretName::from_str("proj/key").unwrap();
        Scrubber::new(&[(n, "s3cretVALUE".into())])
    }

    #[test]
    fn masks_raw_value() {
        assert_eq!(scr().scrub("token=s3cretVALUE;"), "token={{proj/key}};");
    }

    #[test]
    fn masks_base64_and_hex() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode("s3cretVALUE");
        let hexed = hex::encode("s3cretVALUE");
        let out = scr().scrub(&format!("a {b64} b {hexed} c"));
        assert_eq!(out, "a {{proj/key}} b {{proj/key}} c");
    }

    #[test]
    fn masks_two_adjacent_and_substring_safe() {
        let a = SecretName::from_str("a_key").unwrap();
        let b = SecretName::from_str("b_key").unwrap();
        // "longsecret" contains "secret" — longest match must win
        let s = Scrubber::new(&[(a, "longsecret".into()), (b, "secret".into())]);
        assert_eq!(s.scrub("xlongsecretsecrety"), "x{{a_key}}{{b_key}}y");
    }

    #[test]
    fn plain_text_untouched() {
        assert_eq!(scr().scrub("nothing here"), "nothing here");
    }

    #[test]
    fn stream_masks_value_split_across_chunks() {
        let s = scr();
        let mut st = s.stream();
        let mut out = String::new();
        out.push_str(&st.feed("token=s3cret"));
        out.push_str(&st.feed("VALUE;done"));
        out.push_str(&st.finish());
        assert_eq!(out, "token={{proj/key}};done");
    }

    #[test]
    fn stream_passes_clean_text_through() {
        let s = scr();
        let mut st = s.stream();
        let mut out = String::new();
        for chunk in ["hello ", "wor", "ld"] {
            out.push_str(&st.feed(chunk));
        }
        out.push_str(&st.finish());
        assert_eq!(out, "hello world");
    }
}
