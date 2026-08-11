//! Comparing an observation against a profile.
//!
//! Every M0 finding lands here, and each one is a way to get a permanently flaky
//! comparison if ignored:
//!
//! 1. Chrome permutes extension order per connection, so a permuted profile must
//!    accept any ordering of the same set.
//! 2. GREASE values rotate, so they are normalised away and only counts compare.
//! 3. Cipher order is fixed even for Chrome. The two axes are independent.
//! 5. `pre_shared_key` appears only when resuming, so its presence is not evidence
//!    of a different client.

use std::fmt;

use fingerprint_core::grease;

use crate::probe::ClientReport;
use crate::profile::{Order, Profile, EXT_PRE_SHARED_KEY};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every checked field agreed.
    Exact,
    /// Some agreed, some did not.
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDiff {
    pub field: String,
    pub ok: bool,
    pub observed: String,
    pub expected: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    pub label: String,
    pub fields: Vec<FieldDiff>,
}

impl Diff {
    pub fn is_clean(&self) -> bool {
        self.fields.iter().all(|f| f.ok)
    }

    pub fn verdict(&self) -> Verdict {
        if self.is_clean() {
            Verdict::Exact
        } else {
            Verdict::Partial
        }
    }

    /// Fraction of checked fields that agreed. Reported rather than used as a
    /// threshold, because "61% Chrome" is not a client.
    pub fn score(&self) -> f32 {
        if self.fields.is_empty() {
            return 0.0;
        }
        let ok = self.fields.iter().filter(|f| f.ok).count();
        ok as f32 / self.fields.len() as f32
    }
}

impl fmt::Display for Diff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for d in &self.fields {
            let mark = if d.ok { '✓' } else { '✗' };
            write!(f, "  {mark} {:<16}", d.field)?;
            if d.ok {
                writeln!(f, "{}", d.observed)?;
            } else {
                write!(f, "{}", d.observed)?;
                if !d.expected.is_empty() {
                    write!(f, "  ({}: {})", self.label, d.expected)?;
                }
                match &d.note {
                    Some(n) => writeln!(f, "  {n}")?,
                    None => writeln!(f)?,
                }
            }
        }
        if self.is_clean() {
            writeln!(f, "  verdict: matches {}", self.label)?;
        } else {
            writeln!(
                f,
                "  verdict: NOT {} ({:.0}% match)",
                self.label,
                self.score() * 100.0
            )?;
        }
        Ok(())
    }
}

fn join_refs(v: &[&String]) -> String {
    v.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")
}

fn list(v: &[u16]) -> String {
    v.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Compares two lists under an ordering rule. `Unknown` is treated as `Permuted`,
/// because a profile built from one sample cannot claim an order is stable and the
/// safe reading is the looser one.
fn compare_ordered(observed: &[u16], expected: &[u16], order: Order) -> bool {
    match order {
        Order::Fixed => observed == expected,
        Order::Permuted | Order::Unknown => {
            let mut a = observed.to_vec();
            let mut b = expected.to_vec();
            a.sort_unstable();
            b.sort_unstable();
            a == b
        }
    }
}

fn field(name: &str, ok: bool, observed: String, expected: String) -> FieldDiff {
    FieldDiff {
        field: name.to_string(),
        ok,
        observed,
        expected,
        note: None,
    }
}

pub fn diff(report: &ClientReport, profile: &Profile) -> Diff {
    let mut fields = Vec::new();

    // --- TLS ciphers. Fixed even for Chrome; only extensions permute. ---------
    let obs_ciphers = grease::strip(&report.tls.ciphers);
    let ok = compare_ordered(
        &obs_ciphers,
        &profile.tls.ciphers,
        profile.equivalence.cipher_order,
    );
    let mut d = field(
        "ciphers",
        ok,
        format!("{} ciphers", obs_ciphers.len()),
        format!("{} ciphers", profile.tls.ciphers.len()),
    );
    if !ok {
        d.note = Some(format!(
            "order rule: {:?}",
            profile.equivalence.cipher_order
        ));
        d.observed = list(&obs_ciphers);
        d.expected = list(&profile.tls.ciphers);
    }
    fields.push(d);

    // --- TLS extensions. pre_shared_key is session dependent on both sides. ---
    let strip_psk = |v: &[u16]| -> Vec<u16> {
        grease::strip(v)
            .into_iter()
            .filter(|e| *e != EXT_PRE_SHARED_KEY)
            .collect()
    };
    let obs_ext = strip_psk(&report.tls.extensions);
    let exp_ext = strip_psk(&profile.tls.extensions);
    let ok = compare_ordered(&obs_ext, &exp_ext, profile.equivalence.extension_order);
    let mut d = field(
        "extensions",
        ok,
        format!("{} extensions", obs_ext.len()),
        format!("{} extensions", exp_ext.len()),
    );
    if !ok {
        d.note = Some(format!(
            "order rule: {:?}",
            profile.equivalence.extension_order
        ));
        d.observed = list(&obs_ext);
        d.expected = list(&exp_ext);
    }
    fields.push(d);

    // --- GREASE. Counts and positions, never values. --------------------------
    let obs_gc = report.tls.grease_cipher_positions.len();
    let exp_gc = profile.tls.grease_cipher_positions.len();
    let obs_ge = report.tls.grease_ext_positions.len();
    let exp_ge = profile.tls.grease_ext_positions.len();
    let ok = obs_gc == exp_gc && obs_ge == exp_ge;
    let mut d = field(
        "GREASE",
        ok,
        format!("{obs_gc} cipher, {obs_ge} extension"),
        format!("{exp_gc} cipher, {exp_ge} extension"),
    );
    if !ok && obs_gc == 0 && obs_ge == 0 {
        d.note = Some("absent entirely; no browser omits GREASE".to_string());
    }
    fields.push(d);

    // --- ALPN and SNI ---------------------------------------------------------
    let obs_alpn = report.tls.alpn.clone().unwrap_or_else(|| "none".into());
    let exp_alpn = profile.tls.alpn.clone().unwrap_or_else(|| "none".into());
    fields.push(field("ALPN", obs_alpn == exp_alpn, obs_alpn, exp_alpn));

    fields.push(field(
        "SNI",
        report.tls.has_sni == profile.tls.has_sni,
        if report.tls.has_sni {
            "present"
        } else {
            "absent"
        }
        .into(),
        if profile.tls.has_sni {
            "present"
        } else {
            "absent"
        }
        .into(),
    ));

    // --- HTTP/2 ---------------------------------------------------------------
    match (&report.h2, &profile.h2) {
        (Some(obs), Some(exp)) => {
            let settings_str = |s: &[(u16, u32)]| {
                s.iter()
                    .map(|(i, v)| format!("{i}:{v}"))
                    .collect::<Vec<_>>()
                    .join(";")
            };
            let o = settings_str(&obs.settings);
            let e = settings_str(&exp.settings);
            let ok = o == e;
            let mut d = field("SETTINGS", ok, o.clone(), e.clone());
            if !ok {
                let obs_ids: Vec<u16> = obs.settings.iter().map(|(i, _)| *i).collect();
                let exp_ids: Vec<u16> = exp.settings.iter().map(|(i, _)| *i).collect();
                if obs_ids.contains(&3) && !exp_ids.contains(&3) {
                    d.note = Some("sends id 3, which no browser does".to_string());
                }
            }
            fields.push(d);

            fields.push(field(
                "WINDOW_UPDATE",
                obs.window_update == exp.window_update,
                obs.window_update.map(|v| v.to_string()).unwrap_or_default(),
                exp.window_update.map(|v| v.to_string()).unwrap_or_default(),
            ));

            fields.push(field(
                "pseudo-header",
                obs.pseudo_order == exp.pseudo_order,
                obs.pseudo_order.clone(),
                exp.pseudo_order.clone(),
            ));
        }
        (None, Some(_)) => fields.push(field(
            "HTTP/2",
            false,
            "not captured".into(),
            "expected".into(),
        )),
        _ => {}
    }

    // --- HTTP layer ----------------------------------------------------------
    // fpd's own design, not JA4H. Only client-identifying fields are compared;
    // method, referer and cookie counts vary between requests from one client and
    // would make a browser fail to match its own profile.
    if let (Some(obs), Some(exp)) = (&report.h2, &profile.http) {
        let obs_headers = obs.http.comparable_headers();
        let ok = obs_headers == exp.header_names;
        let mut d = field(
            "header order",
            ok,
            format!("{} headers", obs_headers.len()),
            format!("{} headers", exp.header_names.len()),
        );
        if !ok {
            d.observed = obs_headers.join(",");
            d.expected = exp.header_names.join(",");
            let missing: Vec<&String> = exp
                .header_names
                .iter()
                .filter(|h| !obs_headers.contains(h))
                .collect();
            if !missing.is_empty() {
                d.note = Some(format!("missing: {}", join_refs(&missing)));
            }
        }
        fields.push(d);

        fields.push(field(
            "accept-language",
            obs.http.has_accept_language == exp.has_accept_language,
            if obs.http.has_accept_language {
                "present"
            } else {
                "absent"
            }
            .into(),
            if exp.has_accept_language {
                "present"
            } else {
                "absent"
            }
            .into(),
        ));
    }

    Diff {
        label: profile.label.clone(),
        fields,
    }
}
