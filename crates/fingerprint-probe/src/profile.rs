//! The profile format.
//!
//! A profile stores **full ordered field lists**, not only the derived hashes. A
//! JA4 string is sorted and therefore lossy, so it cannot be replayed. Emulation
//! in a later milestone reproduces from these lists, and it is cheaper to store
//! them correctly now than to migrate the format later.
//!
//! GREASE values are never stored. They rotate on every connection (M0 finding 2),
//! so a profile holding them literally would fail to match the same browser twice.
//! Positions and counts are stored instead.

use fingerprint_core::grease;
use serde::{Deserialize, Serialize};

use crate::probe::ClientReport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Order {
    /// Literal wire order must match. Firefox, Safari, curl.
    Fixed,
    /// Only the multiset matters. Chrome and Chromium derivatives permute.
    Permuted,
    /// Not enough samples to tell. One handshake cannot distinguish the two, and
    /// claiming `Fixed` from a single observation is how a profile becomes
    /// silently wrong.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Equivalence {
    pub cipher_order: Order,
    pub extension_order: Order,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsProfile {
    pub ja4: String,
    /// GREASE removed. Positions are recorded separately.
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub grease_cipher_positions: Vec<usize>,
    pub grease_ext_positions: Vec<usize>,
    pub sig_algs: Vec<u16>,
    pub alpn: Option<String>,
    pub has_sni: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct H2Profile {
    pub akamai: String,
    pub settings: Vec<(u16, u32)>,
    pub window_update: Option<u32>,
    pub pseudo_order: String,
}

/// The HTTP layer, stored as comparable fields rather than a hash.
///
/// Only client-identifying fields are kept. Method, referer and cookie counts are
/// request scoped, so storing them in a *client* profile would make the same
/// browser fail to match itself on a different page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProfileStored {
    /// Request-scoped headers already removed.
    pub header_names: Vec<String>,
    pub header_count: usize,
    pub has_accept_language: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub label: String,
    /// Browser family this profile represents, as one of `crate::ua::Family`'s
    /// names. Compared against a client's User-Agent claim, so a profile without
    /// one simply cannot participate in mismatch detection.
    #[serde(default)]
    pub family: String,
    pub captured: String,
    pub source: String,
    /// `Some("resumed")` when the capture included `pre_shared_key`, which changes
    /// the extension count and therefore the JA4. Recorded so a comparison can
    /// treat it as session dependent rather than as a different client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    pub equivalence: Equivalence,
    pub tls: TlsProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2: Option<H2Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpProfileStored>,
}

/// `pre_shared_key`. Present only when resuming, so its presence or absence is not
/// by itself evidence of a different client.
pub const EXT_PRE_SHARED_KEY: u16 = 41;

impl Profile {
    /// Builds a profile from a single observation.
    ///
    /// Equivalence is `Unknown` because one handshake cannot distinguish a fixed
    /// ordering from a permuted one. `fpd capture --samples` upgrades it.
    pub fn from_report(report: &ClientReport, label: &str, captured: &str) -> Self {
        let tls = &report.tls;
        let session = tls
            .extensions
            .contains(&EXT_PRE_SHARED_KEY)
            .then(|| "resumed".to_string());

        Self {
            label: label.to_string(),
            family: String::new(),
            captured: captured.to_string(),
            source: "manual".to_string(),
            session,
            equivalence: Equivalence {
                cipher_order: Order::Unknown,
                extension_order: Order::Unknown,
            },
            tls: TlsProfile {
                ja4: tls.ja4.clone(),
                ciphers: grease::strip(&tls.ciphers),
                extensions: grease::strip(&tls.extensions),
                grease_cipher_positions: tls.grease_cipher_positions.clone(),
                grease_ext_positions: tls.grease_ext_positions.clone(),
                sig_algs: Vec::new(),
                alpn: tls.alpn.clone(),
                has_sni: tls.has_sni,
            },
            http: report.h2.as_ref().map(|h| HttpProfileStored {
                header_names: h.http.comparable_headers(),
                header_count: h.http.header_count,
                has_accept_language: h.http.has_accept_language,
            }),
            h2: report.h2.as_ref().map(|h| H2Profile {
                akamai: h.akamai.clone(),
                settings: h.settings.clone(),
                window_update: h.window_update,
                pseudo_order: h.pseudo_order.clone(),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown profile `{0}`. available: {1}")]
    Unknown(String, String),
}

#[derive(Debug, Clone, Default)]
pub struct ProfileDb {
    profiles: Vec<Profile>,
}

impl ProfileDb {
    /// Profiles compiled into the binary. Shipping them as files would mean a
    /// deployment could silently lose its ground truth.
    pub fn shipped() -> Result<Self, ProfileError> {
        let mut profiles = Vec::new();
        for text in [
            include_str!("../profiles/curl-8.7.1-macos.json"),
            include_str!("../profiles/chrome-macos.json"),
        ] {
            profiles.push(serde_json::from_str(text)?);
        }
        Ok(Self { profiles })
    }

    pub fn from_dir(dir: &std::path::Path) -> Result<Self, ProfileError> {
        let mut profiles = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                profiles.push(serde_json::from_str(&std::fs::read_to_string(&path)?)?);
            }
        }
        Ok(Self { profiles })
    }

    pub fn get(&self, label: &str) -> Result<&Profile, ProfileError> {
        self.profiles
            .iter()
            .find(|p| p.label == label)
            .ok_or_else(|| ProfileError::Unknown(label.to_string(), self.labels().join(", ")))
    }

    pub fn labels(&self) -> Vec<String> {
        self.profiles.iter().map(|p| p.label.clone()).collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Profile> {
        self.profiles.iter()
    }
}
