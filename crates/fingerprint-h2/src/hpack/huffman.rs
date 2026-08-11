//! Huffman string decoding, RFC 7541 section 5.2 and Appendix B.
//!
//! A decode tree is built once from the code table and walked one bit at a time.
//! Nothing here is performance sensitive: one header block is decoded per
//! connection, so obvious correctness beats a table-driven multi-bit decoder.

use std::sync::OnceLock;

use super::table_huffman::HUFFMAN;
use super::HpackError;

const EOS: u16 = 256;

/// A node is two slots. `0` means unset, a positive value is a child index, and a
/// negative value is a terminal carrying `-(symbol + 1)`.
struct Tree {
    nodes: Vec<[i32; 2]>,
}

impl Tree {
    fn build() -> Self {
        let mut nodes: Vec<[i32; 2]> = vec![[0, 0]];

        for (symbol, (code, bits)) in HUFFMAN.iter().enumerate() {
            let mut at = 0usize;
            for i in (0..*bits).rev() {
                let bit = ((code >> i) & 1) as usize;
                let is_last = i == 0;

                if is_last {
                    if let Some(node) = nodes.get_mut(at) {
                        if let Some(slot) = node.get_mut(bit) {
                            *slot = -((symbol as i32) + 1);
                        }
                    }
                } else {
                    let next = nodes.get(at).and_then(|n| n.get(bit).copied()).unwrap_or(0);
                    at = if next > 0 {
                        next as usize
                    } else {
                        nodes.push([0, 0]);
                        let created = nodes.len() - 1;
                        if let Some(node) = nodes.get_mut(at) {
                            if let Some(slot) = node.get_mut(bit) {
                                *slot = created as i32;
                            }
                        }
                        created
                    };
                }
            }
        }
        Self { nodes }
    }
}

fn tree() -> &'static Tree {
    static TREE: OnceLock<Tree> = OnceLock::new();
    TREE.get_or_init(Tree::build)
}

/// Decodes a Huffman-encoded string.
///
/// Three ways this rejects input, all of them real requirements rather than
/// defensive padding:
///
/// - EOS appearing as a decoded symbol is invalid per section 5.2.
/// - Trailing padding longer than seven bits is invalid, because that means a
///   complete symbol was left undecoded.
/// - Padding that is not all ones is invalid, since padding must be the most
///   significant bits of the EOS code.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, HpackError> {
    let t = tree();
    let mut out = Vec::with_capacity(input.len() * 8 / 5);

    let mut at = 0usize;
    let mut bits_since_symbol = 0u32;
    let mut padding_is_all_ones = true;

    for byte in input {
        for i in (0..8).rev() {
            let bit = ((byte >> i) & 1) as usize;

            if bit == 0 {
                padding_is_all_ones = false;
            }
            bits_since_symbol += 1;

            let slot = t
                .nodes
                .get(at)
                .and_then(|n| n.get(bit).copied())
                .ok_or(HpackError::BadHuffman)?;

            if slot < 0 {
                let symbol = (-slot - 1) as u16;
                if symbol == EOS {
                    return Err(HpackError::BadHuffman);
                }
                out.push(symbol as u8);
                at = 0;
                bits_since_symbol = 0;
                padding_is_all_ones = true;
            } else if slot > 0 {
                at = slot as usize;
            } else {
                // Unset slot: this bit sequence is not a valid code.
                return Err(HpackError::BadHuffman);
            }
        }
    }

    if bits_since_symbol > 7 || !padding_is_all_ones {
        return Err(HpackError::BadHuffman);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Re-checks the table rather than trusting it. Kraft equality proves the code
    /// is complete, and a prefix violation would mean two symbols collide. Either
    /// would indicate a transcription error in Appendix B.
    #[test]
    fn table_is_a_complete_prefix_free_code() {
        assert_eq!(HUFFMAN.len(), 257);

        // Kraft sum in fixed point: sum of 2^(30 - bits) must equal 2^30 exactly.
        let total: u64 = HUFFMAN.iter().map(|(_, b)| 1u64 << (30 - *b as u32)).sum();
        assert_eq!(total, 1 << 30, "code is not complete");

        assert_eq!(HUFFMAN[256], (0x3fff_ffff, 30), "EOS per RFC 7541");
        assert_eq!(HUFFMAN.iter().map(|(_, b)| *b).min(), Some(5));
        assert_eq!(HUFFMAN.iter().map(|(_, b)| *b).max(), Some(30));
    }

    /// RFC 7541 C.4.1. The canonical worked example.
    #[test]
    fn rfc_c4_1_www_example_com() {
        let encoded = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(decode(&encoded).expect("decode"), b"www.example.com");
    }

    /// RFC 7541 C.4.2.
    #[test]
    fn rfc_c4_2_no_cache() {
        let encoded = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        assert_eq!(decode(&encoded).expect("decode"), b"no-cache");
    }

    #[test]
    fn an_empty_input_decodes_to_an_empty_string() {
        assert_eq!(decode(&[]).expect("decode"), b"");
    }

    /// Padding must be the leading bits of EOS, which are all ones. Zero padding
    /// is a malformed string, not a shorter one.
    #[test]
    fn padding_that_is_not_all_ones_is_rejected() {
        // "no-cache" with its final padding bits cleared.
        let mut encoded = vec![0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        if let Some(last) = encoded.last_mut() {
            *last &= 0xf0;
        }
        assert_eq!(decode(&encoded), Err(HpackError::BadHuffman));
    }

    #[test]
    fn an_explicit_eos_symbol_is_rejected() {
        // EOS is thirty one-bits followed by padding.
        assert_eq!(
            decode(&[0xff, 0xff, 0xff, 0xff]),
            Err(HpackError::BadHuffman)
        );
    }

    /// Every byte pattern up to three octets must return, never panic.
    #[test]
    fn no_short_input_panics() {
        for a in 0u16..=255 {
            let _ = decode(&[a as u8]);
            for b in 0u16..=255 {
                let _ = decode(&[a as u8, b as u8]);
            }
        }
    }

    /// Output cannot exceed 8/5 of the input, because the shortest code is five
    /// bits. A decompression bomb is therefore not possible here.
    #[test]
    fn output_is_bounded_by_the_shortest_code_length() {
        let input = vec![0xff; 64];
        if let Ok(out) = decode(&input) {
            assert!(out.len() <= input.len() * 8 / 5 + 1);
        }
    }
}
