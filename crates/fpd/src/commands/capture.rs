//! `fpd capture` — record a browser profile from live handshakes.

use std::time::Duration;

use fingerprint_probe::probe::{ClientReport, Probe};
use fingerprint_probe::profile::{Order, Profile};

pub struct Args {
    pub label: String,
    pub samples: usize,
    pub out: String,
    pub timeout_secs: u64,
}

/// Infers an ordering rule from repeated observations.
///
/// **One sample can never yield `Fixed`.** A single handshake is not evidence that
/// an order is stable, and a profile asserting `Fixed` from one observation would
/// reject the very same browser on its next connection, because Chrome permutes
/// its extension order every time. One sample is honestly `Unknown`.
pub fn infer_order(samples: &[Vec<u16>]) -> Order {
    if samples.len() < 2 {
        return Order::Unknown;
    }
    let Some(first) = samples.first() else {
        return Order::Unknown;
    };
    if samples.iter().all(|s| s == first) {
        Order::Fixed
    } else {
        Order::Permuted
    }
}

pub fn run(args: Args) -> u8 {
    if args.samples == 0 {
        eprintln!("fpd: --samples must be at least 1");
        return 2;
    }

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fpd: runtime: {e}");
            return 2;
        }
    };

    rt.block_on(async move {
        let probe = match Probe::bind().await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("fpd: cannot start probe: {e}");
                return 2;
            }
        };

        println!(
            "Point the client at {} ({} sample(s) needed).",
            probe.url(),
            args.samples
        );
        if args.samples == 1 {
            println!("Note: a single sample cannot tell a fixed field order from a");
            println!("      permuted one, so equivalence will be recorded as unknown.");
        }

        let mut reports: Vec<ClientReport> = Vec::new();
        for n in 1..=args.samples {
            match probe
                .accept_one(Duration::from_secs(args.timeout_secs))
                .await
            {
                Ok(r) => {
                    println!("  sample {n}/{}: {}", args.samples, r.tls.ja4);
                    reports.push(r);
                }
                Err(e) => {
                    eprintln!("fpd: sample {n} failed: {e}");
                    return 2;
                }
            }
        }

        let Some(last) = reports.last() else {
            eprintln!("fpd: no samples captured");
            return 2;
        };

        let today = "unknown";
        let mut profile = Profile::from_report(last, &args.label, today);

        let cipher_samples: Vec<Vec<u16>> = reports
            .iter()
            .map(|r| fingerprint_core::grease::strip(&r.tls.ciphers))
            .collect();
        let ext_samples: Vec<Vec<u16>> = reports
            .iter()
            .map(|r| fingerprint_core::grease::strip(&r.tls.extensions))
            .collect();

        profile.equivalence.cipher_order = infer_order(&cipher_samples);
        profile.equivalence.extension_order = infer_order(&ext_samples);
        profile.source = format!("capture/{}", args.samples);

        let path = std::path::Path::new(&args.out).join(format!("{}.json", args.label));
        let text = match serde_json::to_string_pretty(&profile) {
            Ok(t) => t + "\n",
            Err(e) => {
                eprintln!("fpd: serialise: {e}");
                return 2;
            }
        };
        if let Err(e) = std::fs::write(&path, text) {
            eprintln!("fpd: cannot write {}: {e}", path.display());
            return 2;
        }

        println!("wrote {}", path.display());
        println!(
            "  cipher order: {:?}, extension order: {:?}",
            profile.equivalence.cipher_order, profile.equivalence.extension_order
        );
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_sample_yields_unknown_not_fixed() {
        assert_eq!(infer_order(&[vec![1, 2, 3]]), Order::Unknown);
        assert_eq!(infer_order(&[]), Order::Unknown);
    }

    #[test]
    fn identical_repeated_samples_yield_fixed() {
        let s = vec![vec![1, 2, 3], vec![1, 2, 3], vec![1, 2, 3]];
        assert_eq!(infer_order(&s), Order::Fixed);
    }

    #[test]
    fn samples_that_vary_in_order_yield_permuted() {
        let s = vec![vec![1, 2, 3], vec![3, 1, 2]];
        assert_eq!(infer_order(&s), Order::Permuted);
    }

    /// A different set, not merely a different order, is still reported as
    /// permuted here. Distinguishing the two is the diff engine's job, not the
    /// inference rule's.
    #[test]
    fn samples_with_different_contents_are_not_reported_as_fixed() {
        let s = vec![vec![1, 2, 3], vec![1, 2, 4]];
        assert_ne!(infer_order(&s), Order::Fixed);
    }
}
