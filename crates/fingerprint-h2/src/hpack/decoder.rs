//! Representation dispatch, RFC 7541 section 6.
//!
//! Five representations, distinguished by the leading bits of the first octet:
//!
//! ```text
//! 1xxxxxxx  indexed header field                    7-bit prefix index
//! 01xxxxxx  literal with incremental indexing       6-bit prefix index
//! 001xxxxx  dynamic table size update               5-bit prefix size
//! 0001xxxx  literal never indexed                   4-bit prefix index
//! 0000xxxx  literal without indexing                4-bit prefix index
//! ```
//!
//! Order matters when matching: `0001` must be tested before `0000`.

use super::table::{lookup, DynamicTable};
use super::{huffman, integer, HpackError};

/// Longest header name or value accepted. A single block cannot legitimately
/// carry more, and the bound keeps a hostile peer from making us allocate.
const MAX_STRING: u64 = 1 << 16;

/// Most headers a single block may produce, so a block of one-byte indexed
/// representations cannot make us build an unbounded list.
const MAX_HEADERS: usize = 512;

/// Decodes a header block into `(name, value)` pairs in wire order.
///
/// Order is the fingerprint, so the result is a `Vec` and never a map.
pub fn decode(block: &[u8]) -> Result<Vec<(String, String)>, HpackError> {
    let mut dynamic = DynamicTable::new();
    let mut out = Vec::new();
    let mut pos = 0usize;

    while pos < block.len() {
        if out.len() >= MAX_HEADERS {
            return Err(HpackError::BadInteger);
        }
        let first = *block.get(pos).ok_or(HpackError::Truncated)?;
        let rest = block.get(pos..).ok_or(HpackError::Truncated)?;

        if first & 0x80 != 0 {
            // Indexed header field.
            let (index, used) = integer::decode(rest, 7)?;
            pos += used;
            out.push(lookup(index, &dynamic)?);
        } else if first & 0xc0 == 0x40 {
            // Literal with incremental indexing.
            let (name, value, used) = literal(rest, 6, &dynamic)?;
            pos += used;
            dynamic.insert(name.clone(), value.clone());
            out.push((name, value));
        } else if first & 0xe0 == 0x20 {
            // Dynamic table size update.
            let (size, used) = integer::decode(rest, 5)?;
            pos += used;
            dynamic.set_max_size(size);
        } else if first & 0xf0 == 0x10 {
            // Literal never indexed.
            let (name, value, used) = literal(rest, 4, &dynamic)?;
            pos += used;
            out.push((name, value));
        } else {
            // Literal without indexing.
            let (name, value, used) = literal(rest, 4, &dynamic)?;
            pos += used;
            out.push((name, value));
        }
    }

    Ok(out)
}

/// A literal representation: an index or an inline name, then a value.
fn literal(
    buf: &[u8],
    prefix_bits: u8,
    dynamic: &DynamicTable,
) -> Result<(String, String, usize), HpackError> {
    let (index, mut used) = integer::decode(buf, prefix_bits)?;

    let name = if index == 0 {
        let rest = buf.get(used..).ok_or(HpackError::Truncated)?;
        let (s, n) = string(rest)?;
        used += n;
        s
    } else {
        lookup(index, dynamic)?.0
    };

    let rest = buf.get(used..).ok_or(HpackError::Truncated)?;
    let (value, n) = string(rest)?;
    used += n;

    Ok((name, value, used))
}

/// A string literal, RFC 7541 section 5.2. The top bit of the length octet says
/// whether the octets are Huffman encoded.
fn string(buf: &[u8]) -> Result<(String, usize), HpackError> {
    let first = *buf.first().ok_or(HpackError::Truncated)?;
    let huffman_encoded = first & 0x80 != 0;

    let (len, prefix_used) = integer::decode(buf, 7)?;
    if len > MAX_STRING {
        return Err(HpackError::BadInteger);
    }
    let len = usize::try_from(len).map_err(|_| HpackError::BadInteger)?;

    let end = prefix_used.checked_add(len).ok_or(HpackError::Truncated)?;
    let raw = buf.get(prefix_used..end).ok_or(HpackError::Truncated)?;

    let bytes = if huffman_encoded {
        huffman::decode(raw)?
    } else {
        raw.to_vec()
    };

    // Header field values are not required to be UTF-8. Lossy conversion keeps a
    // binary value visible rather than discarding the whole block over it.
    Ok((String::from_utf8_lossy(&bytes).into_owned(), end))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7541 C.3.1, the first request of the worked example sequence, using
    /// literals without Huffman.
    #[test]
    fn rfc_c3_1_first_request_without_huffman() {
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ];
        assert_eq!(
            decode(&block).expect("decode"),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
            ]
        );
    }

    /// RFC 7541 C.4.1, the same request Huffman encoded.
    #[test]
    fn rfc_c4_1_first_request_with_huffman() {
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        assert_eq!(
            decode(&block).expect("decode"),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
            ]
        );
    }

    /// An entry added by a literal with incremental indexing must be referencable
    /// by index later in the same block. This is why a dynamic table is needed at
    /// all when only one block is ever decoded.
    #[test]
    fn an_entry_added_in_this_block_can_be_referenced_later_in_it() {
        // Literal with incremental indexing, new name "x" value "y", then index 62.
        let block = [0x40, 0x01, b'x', 0x01, b'y', 0xbe];
        assert_eq!(
            decode(&block).expect("decode"),
            vec![("x".into(), "y".into()), ("x".into(), "y".into())]
        );
    }

    #[test]
    fn literal_never_indexed_does_not_enter_the_dynamic_table() {
        // 0x10 = never indexed, new name.
        let block = [0x10, 0x01, b'x', 0x01, b'y', 0xbe];
        // The trailing index 62 must fail, because nothing was added.
        assert!(decode(&block).is_err());
    }

    #[test]
    fn a_size_update_is_consumed_without_producing_a_header() {
        // 0x20 is a size update to 0, then an indexed :method GET.
        assert_eq!(
            decode(&[0x20, 0x82]).expect("decode"),
            vec![(":method".into(), "GET".into())]
        );
    }

    // --- the failure modes this module exists to get right -------------------

    /// The exact input that panics fluke-hpack 0.3.1. It must be an error here.
    #[test]
    fn the_input_that_panics_fluke_hpack_is_an_error() {
        assert_eq!(decode(&[0x3f]), Err(HpackError::Truncated));
        assert_eq!(decode(&[0x3f, 0xff]), Err(HpackError::Truncated));
        assert!(decode(&[0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
    }

    /// `0xff` saturates the 7-bit prefix at 127 and `0x00` adds nothing, so the
    /// index is 127. That is past the static table and the dynamic table is empty.
    #[test]
    fn an_index_that_does_not_exist_is_an_error() {
        assert_eq!(decode(&[0xff, 0x00]), Err(HpackError::BadIndex(127)));
        assert_eq!(decode(&[0xbe]), Err(HpackError::BadIndex(62)));
    }

    #[test]
    fn a_string_longer_than_its_buffer_is_truncated() {
        assert_eq!(decode(&[0x40, 0x7f, 0x00]), Err(HpackError::Truncated));
    }

    #[test]
    fn an_empty_block_decodes_to_nothing() {
        assert_eq!(decode(&[]).expect("decode"), Vec::new());
    }

    /// Exhaustive over short inputs. The contract is that nothing panics, ever.
    #[test]
    fn no_short_input_panics() {
        for a in 0u16..=255 {
            let _ = decode(&[a as u8]);
            for b in 0u16..=255 {
                let _ = decode(&[a as u8, b as u8]);
                let _ = decode(&[a as u8, b as u8, 0x00]);
            }
        }
    }
}
