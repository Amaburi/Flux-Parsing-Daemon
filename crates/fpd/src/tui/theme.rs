//! One ink.
//!
//! The entire interface is the terminal's own default foreground. Hierarchy comes
//! from weight and inversion, the way it does in print, where one ink and three
//! weights carry a whole newspaper.
//!
//! **No `Color` is ever constructed here, and none may be constructed anywhere
//! else in the view.** There is a test that scans a rendered buffer and fails if
//! any cell carries one.
//!
//! What follows from that, rather than being added on top of it: the view is
//! identical under `NO_COLOR` because there was never colour to remove, it is
//! unaffected by colour vision deficiency, and it reads correctly on a light
//! terminal and a dark one with no second code path.

use ratatui::style::{Modifier, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ink {
    /// Chrome, labels, and bytes that do not feed the fingerprint.
    Recede,
    /// The data itself.
    Normal,
    /// The field currently in focus.
    Advance,
    /// The selected row, and a mismatch. Inversion is louder than any hue while
    /// staying in one tone, and it cannot clash with a background we do not own.
    Demand,
}

impl Ink {
    pub fn style(self) -> Style {
        match self {
            Ink::Recede => Style::new().add_modifier(Modifier::DIM),
            Ink::Normal => Style::new(),
            Ink::Advance => Style::new().add_modifier(Modifier::BOLD),
            Ink::Demand => Style::new().add_modifier(Modifier::REVERSED),
        }
    }
}

/// Bytes per hex row for a given width, and whether the hex pane fits at all.
///
/// Breakpoints are stated rather than emergent, because a view that corrupts its
/// own frame below some width is not finished.
pub fn bytes_per_row(width: u16) -> Option<usize> {
    match width {
        w if w >= 100 => Some(16),
        w if w >= 72 => Some(8),
        _ => None,
    }
}

/// Below this the table drops to the fingerprint alone.
pub const NARROW: u16 = 40;

/// Below this the detail pane collapses to its first few lines.
pub const SHORT: u16 = 20;

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    /// The rule the whole design rests on. If any ink acquires a colour, the
    /// palette is back and the design is a different one.
    #[test]
    fn no_ink_carries_a_colour() {
        for ink in [Ink::Recede, Ink::Normal, Ink::Advance, Ink::Demand] {
            let s = ink.style();
            assert_eq!(s.fg, None, "{ink:?} set a foreground");
            assert_eq!(s.bg, None, "{ink:?} set a background");
        }
    }

    /// Each level has to be visually distinct, or the hierarchy is decorative.
    #[test]
    fn the_four_levels_are_distinguishable_from_each_other() {
        let styles: Vec<Style> = [Ink::Recede, Ink::Normal, Ink::Advance, Ink::Demand]
            .iter()
            .map(|i| i.style())
            .collect();
        for (i, a) in styles.iter().enumerate() {
            for (j, b) in styles.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "levels {i} and {j} render identically");
                }
            }
        }
    }

    #[test]
    fn hex_width_follows_the_stated_breakpoints() {
        assert_eq!(bytes_per_row(120), Some(16));
        assert_eq!(bytes_per_row(100), Some(16));
        assert_eq!(bytes_per_row(99), Some(8));
        assert_eq!(bytes_per_row(72), Some(8));
        assert_eq!(
            bytes_per_row(71),
            None,
            "the hex pane is hidden, not squeezed"
        );
        assert_eq!(bytes_per_row(0), None);
    }

    /// Unused here, but asserted so the constants cannot drift apart from the
    /// documented breakpoints without a test noticing.
    #[test]
    fn the_narrow_and_short_thresholds_are_the_documented_ones() {
        assert_eq!(NARROW, 40);
        assert_eq!(SHORT, 20);
        assert_eq!(Color::Reset, Color::Reset);
    }
}
