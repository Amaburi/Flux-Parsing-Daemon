//! The header tables, RFC 7541 section 2.3.
//!
//! Indexing runs over the static table first, then the dynamic table newest
//! first. The dynamic table is needed even though only one header block is
//! decoded per connection, because a block may reference an entry it added
//! earlier in that same block.

use std::collections::VecDeque;

use super::table_static::STATIC_TABLE;
use super::HpackError;

/// RFC 7541 section 4.1. Every entry costs its name and value lengths plus 32.
const ENTRY_OVERHEAD: usize = 32;

/// The default cap when no SETTINGS_HEADER_TABLE_SIZE has been seen.
pub const DEFAULT_MAX_SIZE: usize = 4096;

/// A hard ceiling on what a peer may ask for. Without it a size update could make
/// the table grow to whatever a u64 allows.
pub const ABSOLUTE_MAX_SIZE: usize = 1 << 20;

#[derive(Debug, Clone, Default)]
pub struct DynamicTable {
    entries: VecDeque<(String, String)>,
    size: usize,
    max_size: usize,
}

impl DynamicTable {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size: DEFAULT_MAX_SIZE,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Applies a dynamic table size update, evicting until the table fits.
    ///
    /// A request above the absolute ceiling is clamped rather than rejected. This
    /// is a fingerprinting reader, not a conformance checker, and refusing the
    /// whole block over a large size update would lose the headers.
    pub fn set_max_size(&mut self, size: u64) {
        self.max_size = usize::try_from(size)
            .unwrap_or(ABSOLUTE_MAX_SIZE)
            .min(ABSOLUTE_MAX_SIZE);
        self.evict_to_fit();
    }

    pub fn insert(&mut self, name: String, value: String) {
        let entry_size = name.len() + value.len() + ENTRY_OVERHEAD;

        // Section 4.4: an entry larger than the whole table empties it and is not
        // inserted. Without this the eviction loop would never terminate.
        if entry_size > self.max_size {
            self.entries.clear();
            self.size = 0;
            return;
        }

        self.entries.push_front((name, value));
        self.size += entry_size;
        self.evict_to_fit();
    }

    fn evict_to_fit(&mut self) {
        while self.size > self.max_size {
            match self.entries.pop_back() {
                Some((n, v)) => {
                    self.size = self.size.saturating_sub(n.len() + v.len() + ENTRY_OVERHEAD);
                }
                None => {
                    self.size = 0;
                    break;
                }
            }
        }
    }
}

/// Resolves an index across the static table then the dynamic table.
///
/// Index 0 is not a valid header index. Static indices run 1 to 61, and dynamic
/// indices continue from 62 with the most recently added entry first.
pub fn lookup(index: u64, dynamic: &DynamicTable) -> Result<(String, String), HpackError> {
    if index == 0 {
        return Err(HpackError::BadIndex(0));
    }
    let idx = usize::try_from(index).map_err(|_| HpackError::BadIndex(index))?;

    if idx <= STATIC_TABLE.len() {
        let (n, v) = STATIC_TABLE
            .get(idx - 1)
            .ok_or(HpackError::BadIndex(index))?;
        return Ok((n.to_string(), v.to_string()));
    }

    let dyn_idx = idx - STATIC_TABLE.len() - 1;
    dynamic
        .entries
        .get(dyn_idx)
        .cloned()
        .ok_or(HpackError::BadIndex(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anchors from RFC 7541 Appendix A, re-asserted so a bad transcription of the
    /// table cannot pass silently.
    #[test]
    fn static_table_anchors_match_the_rfc() {
        assert_eq!(STATIC_TABLE.len(), 61);
        let d = DynamicTable::new();
        assert_eq!(lookup(1, &d).expect("1"), (":authority".into(), "".into()));
        assert_eq!(lookup(2, &d).expect("2"), (":method".into(), "GET".into()));
        assert_eq!(lookup(4, &d).expect("4"), (":path".into(), "/".into()));
        assert_eq!(
            lookup(7, &d).expect("7"),
            (":scheme".into(), "https".into())
        );
        assert_eq!(lookup(8, &d).expect("8"), (":status".into(), "200".into()));
        assert_eq!(
            lookup(61, &d).expect("61"),
            ("www-authenticate".into(), "".into())
        );
    }

    #[test]
    fn index_zero_is_never_valid() {
        assert_eq!(
            lookup(0, &DynamicTable::new()),
            Err(HpackError::BadIndex(0))
        );
    }

    #[test]
    fn an_index_past_the_end_is_an_error_not_a_panic() {
        let d = DynamicTable::new();
        assert!(lookup(62, &d).is_err(), "dynamic table is empty");
        assert!(lookup(u64::MAX, &d).is_err());
    }

    #[test]
    fn dynamic_entries_are_indexed_newest_first_from_sixty_two() {
        let mut d = DynamicTable::new();
        d.insert("first".into(), "1".into());
        d.insert("second".into(), "2".into());
        assert_eq!(lookup(62, &d).expect("62"), ("second".into(), "2".into()));
        assert_eq!(lookup(63, &d).expect("63"), ("first".into(), "1".into()));
    }

    #[test]
    fn eviction_removes_the_oldest_entry_first() {
        let mut d = DynamicTable::new();
        d.set_max_size(70); // room for one entry of this size
        d.insert("aaaa".into(), "bbbb".into());
        d.insert("cccc".into(), "dddd".into());
        assert_eq!(d.len(), 1);
        assert_eq!(lookup(62, &d).expect("62"), ("cccc".into(), "dddd".into()));
    }

    /// RFC 7541 section 4.4. Without this the eviction loop would spin forever.
    #[test]
    fn an_entry_larger_than_the_table_empties_it_and_is_not_inserted() {
        let mut d = DynamicTable::new();
        d.insert("a".into(), "b".into());
        d.set_max_size(40);
        d.insert("x".repeat(100), "y".repeat(100));
        assert!(d.is_empty());
        assert_eq!(d.size(), 0);
    }

    #[test]
    fn a_size_update_beyond_the_ceiling_is_clamped_not_honoured() {
        let mut d = DynamicTable::new();
        d.set_max_size(u64::MAX);
        assert_eq!(d.max_size(), ABSOLUTE_MAX_SIZE);
    }

    #[test]
    fn a_size_update_to_zero_evicts_everything() {
        let mut d = DynamicTable::new();
        d.insert("a".into(), "b".into());
        d.set_max_size(0);
        assert!(d.is_empty());
    }
}
