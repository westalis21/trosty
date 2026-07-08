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
        base64::engine::general_purpose::URL_SAFE.encode(value),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value),
        hex::encode(value),
        hex::encode_upper(value),
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

    pub fn scrub_bytes(&self, data: &[u8]) -> Vec<u8> {
        match &self.ac {
            None => data.to_vec(),
            Some(ac) => {
                let mut out = Vec::with_capacity(data.len());
                let mut last = 0;
                for m in ac.find_iter(data) {
                    out.extend_from_slice(&data[last..m.start()]);
                    out.extend_from_slice(self.replacements[m.pattern().as_usize()].as_bytes());
                    last = m.end();
                }
                out.extend_from_slice(&data[last..]);
                out
            }
        }
    }

    pub fn scrub(&self, text: &str) -> String {
        String::from_utf8(self.scrub_bytes(text.as_bytes()))
            .expect("placeholders are valid UTF-8 and input was valid UTF-8")
    }

    pub fn stream(&self) -> StreamScrubber<'_> {
        StreamScrubber {
            scrubber: self,
            carry: Vec::new(),
        }
    }
}

pub struct StreamScrubber<'a> {
    scrubber: &'a Scrubber,
    carry: Vec<u8>,
}

impl StreamScrubber<'_> {
    pub fn feed_bytes(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.carry.extend_from_slice(chunk);
        let hold = self.scrubber.max_pattern_len().saturating_sub(1);
        if self.carry.len() <= hold {
            return Vec::new();
        }
        let mut cut = self.carry.len() - hold;
        if let Some(ac) = &self.scrubber.ac {
            for m in ac.find_iter(&self.carry) {
                if m.start() < cut && m.end() > cut {
                    cut = m.start();
                }
            }
        }
        let emit = self.scrubber.scrub_bytes(&self.carry[..cut]);
        self.carry.drain(..cut);
        emit
    }

    pub fn finish_bytes(self) -> Vec<u8> {
        self.scrubber.scrub_bytes(&self.carry)
    }

    /// Feed a chunk; returns masked text that is safe to emit now.
    /// Holds back up to (max_pattern_len - 1) trailing bytes in case a
    /// secret is split across chunk boundaries.
    pub fn feed(&mut self, chunk: &str) -> String {
        String::from_utf8_lossy(&self.feed_bytes(chunk.as_bytes())).into_owned()
    }

    pub fn finish(self) -> String {
        String::from_utf8_lossy(&self.finish_bytes()).into_owned()
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
        let hexed_upper = hex::encode_upper("s3cretVALUE");
        let out = scr().scrub(&format!("a {b64} b {hexed} c {hexed_upper} d"));
        assert_eq!(out, "a {{proj/key}} b {{proj/key}} c {{proj/key}} d");
    }

    #[test]
    fn masks_url_safe_base64() {
        use base64::Engine;
        // Value chosen so its standard base64 uses '+' where url-safe base64
        // uses '-' — proves the URL_SAFE variant is matched, not just STANDARD.
        let n = SecretName::from_str("proj/key").unwrap();
        let value = "P(,+n|@B>,";
        let standard = base64::engine::general_purpose::STANDARD.encode(value);
        let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
        assert_ne!(
            standard, url_safe,
            "fixture must exercise the url-safe alphabet"
        );
        let s = Scrubber::new(&[(n, value.into())]);
        assert_eq!(s.scrub(&format!("a {url_safe} b")), "a {{proj/key}} b");
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

    #[test]
    fn bytes_masks_secret_between_invalid_utf8() {
        let s = scr();
        let mut data = vec![0xFF, 0xFE];
        data.extend_from_slice(b"s3cretVALUE");
        data.push(0xFF);
        let out = s.scrub_bytes(&data);
        let expected: Vec<u8> = [&[0xFF, 0xFE][..], b"{{proj/key}}", &[0xFF][..]].concat();
        assert_eq!(out, expected);
    }

    #[test]
    fn stream_bytes_split_mid_multibyte_char_around_secret() {
        // "п" = 0xD0 0xBF; split the stream between its bytes right before the secret
        let s = scr();
        let mut st = s.stream();
        let mut out = Vec::new();
        out.extend(st.feed_bytes(&[0xD0]));
        out.extend(st.feed_bytes(&[0xBF]));
        out.extend(st.feed_bytes(b"s3cret"));
        out.extend(st.feed_bytes(b"VALUE!"));
        out.extend(st.finish_bytes());
        let expected: Vec<u8> = [&[0xD0, 0xBF][..], b"{{proj/key}}", b"!"].concat();
        assert_eq!(out, expected);
    }
}
