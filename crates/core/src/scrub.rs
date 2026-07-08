use crate::placeholder;
use crate::vault::{SecretName, MIN_SECRET_LEN};
use aho_corasick::{AhoCorasick, MatchKind};
use base64::Engine;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

pub struct Scrubber {
    ac: Option<AhoCorasick>,
    replacements: Vec<String>,
    max_len: usize,
    /// Byte form of every pattern (raw value + all encoded variants), kept
    /// around so `StreamScrubber` can check whether a trailing carry suffix
    /// is a strict prefix of some pattern (see `feed_bytes`).
    patterns: Vec<Vec<u8>>,
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
        let byte_patterns = patterns.iter().map(|p| p.as_bytes().to_vec()).collect();
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
            patterns: byte_patterns,
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

/// Shared logic for feeding a chunk into a stream scrubber.
/// Appends chunk to carry, computes prefix-aware hold, emits scrubbed bytes, drains carry.
fn stream_feed(scrubber: &Scrubber, carry: &mut Vec<u8>, chunk: &[u8]) -> Vec<u8> {
    carry.extend_from_slice(chunk);

    // Hold back only the longest suffix of the carry that could still
    // grow into a pattern — i.e. that is a STRICT prefix of some
    // pattern (a full-length match would already have been found by
    // find_iter below, so only a shorter, still-extendable prefix
    // matters here). Everything else is safe to flush now: it cannot
    // ever become part of a masked match no matter what bytes arrive
    // next. This is what keeps an interactive prompt from lagging by
    // (max_pattern_len - 1) bytes with nothing held.
    let cap = scrubber.max_pattern_len().saturating_sub(1);
    let limit = cap.min(carry.len());
    let mut hold = 0usize;
    for k in (1..=limit).rev() {
        let suffix = &carry[carry.len() - k..];
        if scrubber
            .patterns
            .iter()
            .any(|p| p.len() > k && p.starts_with(suffix))
        {
            hold = k;
            break;
        }
    }

    let mut cut = carry.len() - hold;
    if let Some(ac) = &scrubber.ac {
        for m in ac.find_iter(&carry) {
            if m.start() < cut && m.end() > cut {
                cut = m.start();
            }
        }
    }
    let emit = scrubber.scrub_bytes(&carry[..cut]);
    carry.drain(..cut);
    emit
}

impl StreamScrubber<'_> {
    pub fn feed_bytes(&mut self, chunk: &[u8]) -> Vec<u8> {
        stream_feed(self.scrubber, &mut self.carry, chunk)
    }

    pub fn finish_bytes(self) -> Vec<u8> {
        self.scrubber.scrub_bytes(&self.carry)
    }

    /// Feed a chunk; returns masked text that is safe to emit now.
    /// Holds back only the trailing bytes that are themselves a strict
    /// prefix of some pattern (up to max_pattern_len - 1 of them) in case a
    /// secret is split across chunk boundaries — everything else (e.g. a
    /// shell prompt) is flushed immediately, with no idle-timeout needed.
    pub fn feed(&mut self, chunk: &str) -> String {
        String::from_utf8_lossy(&self.feed_bytes(chunk.as_bytes())).into_owned()
    }

    pub fn finish(self) -> String {
        String::from_utf8_lossy(&self.finish_bytes()).into_owned()
    }
}

pub struct SwappableStream {
    scrubber: std::sync::Arc<Scrubber>,
    carry: Vec<u8>,
}

impl SwappableStream {
    pub fn new(scrubber: std::sync::Arc<Scrubber>) -> Self {
        Self {
            scrubber,
            carry: Vec::new(),
        }
    }

    pub fn feed_bytes(&mut self, chunk: &[u8]) -> Vec<u8> {
        stream_feed(&self.scrubber, &mut self.carry, chunk)
    }

    pub fn set_scrubber(&mut self, scrubber: std::sync::Arc<Scrubber>) {
        self.scrubber = scrubber; // carry intentionally preserved
    }

    pub fn finish_bytes(self) -> Vec<u8> {
        self.scrubber.scrub_bytes(&self.carry)
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
    fn stream_prompt_flushes_immediately_no_held_tail() {
        // Regression test for interactive latency: a shell prompt has no
        // suffix that is a prefix of any variant of "s3cretVALUE", so it
        // must come through in full on the first feed — no lag waiting for
        // more bytes that may never come in a live session.
        let s = scr();
        let mut st = s.stream();
        assert_eq!(st.feed_bytes(b"PROMPT> "), b"PROMPT> ".to_vec());
    }

    #[test]
    fn stream_holds_only_the_prefix_suffix_not_the_whole_tail() {
        // "xs" ends in "s", which IS a strict prefix of "s3cretVALUE", so
        // only that one byte must be held back — "x" must flush now.
        let s = scr();
        let mut st = s.stream();
        assert_eq!(st.feed_bytes(b"xs"), b"x".to_vec());
        let mut out = Vec::new();
        out.extend(st.feed_bytes(b"3cretVALUE done"));
        out.extend(st.finish_bytes());
        assert_eq!(out, b"{{proj/key}} done".to_vec());
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

    #[test]
    fn swappable_swap_mid_stream_masks_new_secret() {
        use std::sync::Arc;
        let old = Arc::new(Scrubber::new(&[]));
        let n = SecretName::from_str("proj/key").unwrap();
        let new = Arc::new(Scrubber::new(&[(n, "s3cretVALUE".into())]));
        let mut st = SwappableStream::new(old);
        let mut out = Vec::new();
        out.extend(st.feed_bytes(b"before s3cretVALUE after;"));
        st.set_scrubber(new);
        out.extend(st.feed_bytes(b" now s3cret"));
        out.extend(st.feed_bytes(b"VALUE end"));
        out.extend(st.finish_bytes());
        let s = String::from_utf8(out).unwrap();
        // before swap: unmasked (no secrets registered then)
        assert!(s.starts_with("before s3cretVALUE after;"));
        // after swap: masked, even split across chunks
        assert!(s.ends_with(" now {{proj/key}} end"), "got: {s}");
    }

    #[test]
    fn swappable_preserves_carry_across_swap() {
        use std::sync::Arc;
        let n = SecretName::from_str("proj/key").unwrap();
        let sc = Arc::new(Scrubber::new(&[(n.clone(), "s3cretVALUE".into())]));
        let mut st = SwappableStream::new(sc.clone());
        let mut out = Vec::new();
        out.extend(st.feed_bytes(b"x s3cret")); // "s3cret" held (prefix of pattern)
        st.set_scrubber(sc); // same scrubber, swap must not flush carry raw
        out.extend(st.feed_bytes(b"VALUE y"));
        out.extend(st.finish_bytes());
        assert_eq!(String::from_utf8(out).unwrap(), "x {{proj/key}} y");
    }
}
