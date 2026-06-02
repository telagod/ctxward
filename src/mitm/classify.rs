//! SNI-based routing: decide whether a host is intercepted (TLS-terminated and
//! run through the detection pipeline) or passed through as an opaque tunnel.
//!
//! Also holds the [`PinCache`]: hosts whose clients rejected our leaf cert (cert
//! pinning) are remembered for a TTL so the client's retry is spliced rather than
//! re-intercepted.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use regex::Regex;

use crate::config::{HostPattern, ProxyAction, ProxyConfig};

/// A compiled host matcher.
enum Matcher {
    Exact(String),
    /// `*.example.com` — matches any single-or-multi label prefix under the suffix.
    Wildcard(String),
    Regex(Regex),
}

impl Matcher {
    fn compile(pattern: &HostPattern) -> Result<Self, regex::Error> {
        Ok(match pattern {
            HostPattern::Exact(h) => Matcher::Exact(h.to_ascii_lowercase()),
            HostPattern::Wildcard(h) => {
                // Store the suffix after the leading "*." (or the whole thing if no prefix).
                let suffix = h
                    .strip_prefix("*.")
                    .unwrap_or(h.as_str())
                    .to_ascii_lowercase();
                Matcher::Wildcard(suffix)
            }
            HostPattern::Regex(r) => {
                // Hosts are lowercased before matching (see `classify`), so the
                // pattern must match case-insensitively for consistency with the
                // Exact/Wildcard arms.
                Matcher::Regex(regex::RegexBuilder::new(r).case_insensitive(true).build()?)
            }
        })
    }

    fn matches(&self, host: &str) -> bool {
        match self {
            Matcher::Exact(h) => host == h,
            Matcher::Wildcard(suffix) => {
                // `*.openai.azure.com` matches `x.openai.azure.com` and `a.b.openai.azure.com`,
                // but NOT the bare apex `openai.azure.com`.
                host.ends_with(suffix.as_str())
                    && host.len() > suffix.len()
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            }
            Matcher::Regex(re) => re.is_match(host),
        }
    }
}

/// Compiled classifier for one [`ProxyConfig`].
pub struct Classifier {
    intercept: Vec<Matcher>,
    passthrough: Vec<Matcher>,
    default: ProxyAction,
}

impl Classifier {
    /// Compile a classifier from config. Invalid regexes are skipped with a warning
    /// rather than failing the whole proxy.
    pub fn from_config(cfg: &ProxyConfig) -> Self {
        let compile_all = |patterns: &[HostPattern]| -> Vec<Matcher> {
            patterns
                .iter()
                .filter_map(|p| match Matcher::compile(p) {
                    Ok(m) => Some(m),
                    Err(err) => {
                        tracing::warn!(?p, %err, "skipping invalid host pattern");
                        None
                    }
                })
                .collect()
        };
        Self {
            intercept: compile_all(&cfg.intercept),
            passthrough: compile_all(&cfg.passthrough),
            default: cfg.default_action,
        }
    }

    /// Decide the action for a host. Passthrough wins ties (fail-open / least-surprise),
    /// then intercept, then the configured default for unknown hosts.
    pub fn classify(&self, host: &str) -> ProxyAction {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if self.passthrough.iter().any(|m| m.matches(&host)) {
            return ProxyAction::Passthrough;
        }
        if self.intercept.iter().any(|m| m.matches(&host)) {
            return ProxyAction::Intercept;
        }
        self.default
    }
}

/// Remembers `(client_ip, sni)` pairs whose TLS leaf was rejected by the client,
/// so the retry is spliced (passed through) for a TTL.
pub struct PinCache {
    ttl: Duration,
    inner: Mutex<HashMap<(String, String), Instant>>,
}

impl PinCache {
    pub fn new(cfg: &ProxyConfig) -> Self {
        Self {
            ttl: Duration::from_secs(cfg.pin_fallback.block_ttl_secs),
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Mark `(peer, sni)` as pinned: future `is_pinned` checks return true until the TTL elapses.
    pub fn mark(&self, peer: &str, sni: &str) {
        let deadline = Instant::now() + self.ttl;
        self.inner
            .lock()
            .insert((peer.to_string(), sni.to_ascii_lowercase()), deadline);
    }

    /// Whether `(peer, sni)` is currently pinned. Expired entries are evicted lazily.
    pub fn is_pinned(&self, peer: &str, sni: &str) -> bool {
        let key = (peer.to_string(), sni.to_ascii_lowercase());
        let mut map = self.inner.lock();
        match map.get(&key) {
            Some(deadline) if *deadline > Instant::now() => true,
            Some(_) => {
                map.remove(&key);
                false
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PinFallbackConfig;

    fn cfg(
        intercept: Vec<HostPattern>,
        passthrough: Vec<HostPattern>,
        default: ProxyAction,
    ) -> ProxyConfig {
        ProxyConfig {
            listen_addr: "127.0.0.1:0".into(),
            ca_dir: "./certs".into(),
            ca_key_path: None,
            ca_cert_path: None,
            ca_key_path_env: "UNSET".into(),
            leaf_ttl_days: 7,
            cert_cache_size: 16,
            intercept,
            passthrough,
            default_action: default,
            per_app_rules: vec![],
            pin_fallback: PinFallbackConfig::default(),
            ruleset_url: None,
            ruleset_poll_secs: 300,
        }
    }

    #[test]
    fn exact_match_intercepts() {
        let c = Classifier::from_config(&cfg(
            vec![HostPattern::Exact("api.openai.com".into())],
            vec![],
            ProxyAction::Passthrough,
        ));
        assert_eq!(c.classify("api.openai.com"), ProxyAction::Intercept);
        assert_eq!(c.classify("API.OpenAI.com"), ProxyAction::Intercept);
        assert_eq!(c.classify("api.openai.com."), ProxyAction::Intercept); // trailing dot
        assert_eq!(c.classify("evil.com"), ProxyAction::Passthrough);
    }

    #[test]
    fn wildcard_matches_subdomains_not_apex() {
        let c = Classifier::from_config(&cfg(
            vec![HostPattern::Wildcard("*.openai.azure.com".into())],
            vec![],
            ProxyAction::Passthrough,
        ));
        assert_eq!(c.classify("foo.openai.azure.com"), ProxyAction::Intercept);
        assert_eq!(c.classify("a.b.openai.azure.com"), ProxyAction::Intercept);
        assert_eq!(c.classify("openai.azure.com"), ProxyAction::Passthrough); // apex not matched
        assert_eq!(c.classify("notopenai.azure.com"), ProxyAction::Passthrough);
    }

    #[test]
    fn regex_matches() {
        let c = Classifier::from_config(&cfg(
            vec![HostPattern::Regex(
                r"^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$".into(),
            )],
            vec![],
            ProxyAction::Passthrough,
        ));
        assert_eq!(
            c.classify("bedrock-runtime.us-east-1.amazonaws.com"),
            ProxyAction::Intercept
        );
        assert_eq!(
            c.classify("s3.us-east-1.amazonaws.com"),
            ProxyAction::Passthrough
        );
    }

    #[test]
    fn regex_is_case_insensitive() {
        // hosts are lowercased before matching; an uppercase-containing pattern
        // must still match (regression: previously compiled case-sensitively).
        let c = Classifier::from_config(&cfg(
            vec![HostPattern::Regex(r"^API\.OpenAI\.com$".into())],
            vec![],
            ProxyAction::Passthrough,
        ));
        assert_eq!(c.classify("api.openai.com"), ProxyAction::Intercept);
    }

    #[test]
    fn passthrough_wins_over_intercept() {
        let c = Classifier::from_config(&cfg(
            vec![HostPattern::Wildcard("*.openai.com".into())],
            vec![HostPattern::Exact("chat.openai.com".into())],
            ProxyAction::Passthrough,
        ));
        assert_eq!(c.classify("api.openai.com"), ProxyAction::Intercept);
        assert_eq!(c.classify("chat.openai.com"), ProxyAction::Passthrough);
    }

    #[test]
    fn unknown_uses_default() {
        let c = Classifier::from_config(&cfg(vec![], vec![], ProxyAction::Intercept));
        assert_eq!(c.classify("whatever.example"), ProxyAction::Intercept);
        let c2 = Classifier::from_config(&cfg(vec![], vec![], ProxyAction::Passthrough));
        assert_eq!(c2.classify("whatever.example"), ProxyAction::Passthrough);
    }

    #[test]
    fn pin_cache_marks_and_expires() {
        let mut config = cfg(vec![], vec![], ProxyAction::Passthrough);
        config.pin_fallback.block_ttl_secs = 0; // immediate expiry
        let pins = PinCache::new(&config);
        pins.mark("1.2.3.4", "api.openai.com");
        // ttl 0 => already expired
        assert!(!pins.is_pinned("1.2.3.4", "api.openai.com"));

        let mut config2 = cfg(vec![], vec![], ProxyAction::Passthrough);
        config2.pin_fallback.block_ttl_secs = 300;
        let pins2 = PinCache::new(&config2);
        pins2.mark("1.2.3.4", "API.openai.com");
        assert!(pins2.is_pinned("1.2.3.4", "api.openai.com")); // case-insensitive
        assert!(!pins2.is_pinned("5.6.7.8", "api.openai.com")); // different peer
    }
}
