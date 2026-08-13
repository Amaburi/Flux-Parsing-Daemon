//! Drawing. A pure function of state, so it is testable with no terminal.

use std::collections::VecDeque;

use fingerprint_core::hello::Span;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span as TSpan};
use ratatui::widgets::{Paragraph, Widget};

use super::source::Row;
use super::theme::{bytes_per_row, Ink, NARROW, SHORT};

pub struct State {
    pub rows: VecDeque<Row>,
    pub selected: usize,
    pub follow: bool,
    pub search: String,
    pub searching: bool,
    pub source_label: String,
    /// Set when a sequence number arrived out of step, meaning the socket dropped
    /// records for us. Shown rather than hidden, because a silently incomplete
    /// list is worse than a visibly incomplete one.
    pub dropped: bool,
    /// Set after `e` writes a ClientHello out, so the footer can say where it went.
    pub exported: Option<String>,
}

impl State {
    pub fn new(source_label: String) -> Self {
        Self {
            rows: VecDeque::new(),
            selected: 0,
            follow: true,
            search: String::new(),
            searching: false,
            source_label,
            dropped: false,
            exported: None,
        }
    }

    pub fn visible(&self) -> Vec<&Row> {
        if self.search.is_empty() {
            return self.rows.iter().collect();
        }
        let needle = self.search.to_lowercase();
        self.rows
            .iter()
            .filter(|r| {
                r.ip.to_lowercase().contains(&needle)
                    || r.ja4.to_lowercase().contains(&needle)
                    || r.verdict.to_lowercase().contains(&needle)
            })
            .collect()
    }

    pub fn alerts(&self) -> usize {
        self.rows.iter().filter(|r| r.mismatch).count()
    }

    pub fn current(&self) -> Option<&Row> {
        let v = self.visible();
        v.get(self.selected.min(v.len().saturating_sub(1))).copied()
    }
}

fn within(span: Span, offset: usize) -> bool {
    offset >= span.start && offset < span.start + span.len
}

/// Whether this byte feeds the fingerprint.
///
/// The random field and the session id do not, and rendering them recessed is the
/// whole mechanism by which provenance is visible. No colour, no bracket art, just
/// contrast.
fn feeds_fingerprint(row: &Row, offset: usize) -> bool {
    within(row.ciphers, offset) || within(row.extensions, offset)
}

fn hhmmss(at_ms: u64) -> String {
    let secs = at_ms / 1000;
    format!(
        "{:02}:{:02}:{:02}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect()
    }
}

fn rule(width: usize) -> Line<'static> {
    Line::from(TSpan::styled(
        "─".repeat(width.saturating_sub(2)),
        Ink::Recede.style(),
    ))
}

/// The table of recent connections.
fn table_lines(state: &State, width: u16, height: usize) -> Vec<Line<'static>> {
    let visible = state.visible();
    let start = visible.len().saturating_sub(height);
    let narrow = width < NARROW;

    visible
        .iter()
        .enumerate()
        .skip(start)
        .map(|(i, r)| {
            let selected = i == state.selected.min(visible.len().saturating_sub(1));
            let ja4 = if width >= 100 {
                r.ja4.clone()
            } else {
                truncate(&r.ja4, 18)
            };

            let text = if narrow {
                format!("{ja4}  {}", truncate(&r.verdict, 12))
            } else {
                format!(
                    "{}   {:<15}  {:<38}  {}{}",
                    hhmmss(r.at_ms),
                    truncate(&r.ip, 15),
                    ja4,
                    truncate(&r.verdict, 18),
                    if r.mismatch { "  ✗" } else { "" }
                )
            };

            // Inversion for the selected row. A colour here would compete with
            // nothing, since there are no colours, but it would still be a colour.
            let ink = if selected { Ink::Demand } else { Ink::Normal };
            Line::from(TSpan::styled(text, ink.style()))
        })
        .collect()
}

/// The ClientHello, with the bytes that feed the fingerprint brought forward.
fn hex_lines(row: &Row, width: u16, max_lines: usize) -> Vec<Line<'static>> {
    let Some(bpr) = bytes_per_row(width) else {
        return Vec::new();
    };
    if row.raw.is_empty() || max_lines == 0 {
        return Vec::new();
    }

    // Centre on the fingerprint region rather than dumping the whole record. A
    // 517-byte hello is 33 rows at 16 bytes, which no pane has space for.
    let first = (row.ciphers.start / bpr).saturating_sub(1) * bpr;
    let last = (row.extensions.start + row.extensions.len).min(row.raw.len());

    let mut out = Vec::new();
    let mut offset = first;
    while offset < last && out.len() < max_lines {
        let mut spans = vec![TSpan::styled(
            format!("{offset:04x}   "),
            Ink::Recede.style(),
        )];

        for i in 0..bpr {
            let at = offset + i;
            let Some(byte) = row.raw.get(at) else { break };
            if feeds_fingerprint(row, at) {
                spans.push(TSpan::styled(format!("{byte:02x} "), Ink::Normal.style()));
            } else {
                spans.push(TSpan::styled("·· ", Ink::Recede.style()));
            }
            if i == bpr / 2 - 1 {
                spans.push(TSpan::raw(" "));
            }
        }

        // Labels sit in the right margin, on the row where a span begins.
        let label = if within_row(row.ciphers.start, offset, bpr) {
            Some(format!("  ciphers {}", row.ciphers_len()))
        } else if within_row(row.extensions.start, offset, bpr) {
            Some(format!("  extensions {}", row.ext_count))
        } else if row
            .grease_ext
            .iter()
            .any(|g| within_row(g.start, offset, bpr))
        {
            Some("  grease".to_string())
        } else {
            None
        };
        if let Some(l) = label {
            spans.push(TSpan::styled(l, Ink::Recede.style()));
        }

        out.push(Line::from(spans));
        offset += bpr;
    }
    out
}

fn within_row(target: usize, row_start: usize, bpr: usize) -> bool {
    target >= row_start && target < row_start + bpr
}

/// Ordered by importance, not by the order the data happens to sit in.
///
/// The alert and the fingerprint come first and the hex dump takes whatever is
/// left. An earlier arrangement put the hex pane in the middle, which pushed the
/// mismatch warning and the key legend off the bottom of a 30-row terminal. The
/// single most important line on the screen must not be the one that gets
/// truncated.
fn detail_lines(row: &Row, width: u16, height: u16) -> Vec<Line<'static>> {
    let mut out = vec![Line::from(vec![
        TSpan::styled(format!("{:<20}", row.ip), Ink::Advance.style()),
        TSpan::styled(
            format!("{}  {:.0}%", row.verdict, row.score * 100.0),
            Ink::Normal.style(),
        ),
    ])];

    if row.mismatch {
        out.push(Line::from(TSpan::styled(
            "  the user-agent claims a browser this fingerprint contradicts  ",
            Ink::Demand.style(),
        )));
    }

    out.push(Line::from(vec![
        TSpan::styled("ja4    ", Ink::Recede.style()),
        TSpan::styled(row.ja4.clone(), Ink::Advance.style()),
    ]));
    out.push(Line::from(TSpan::styled(
        format!(
            "       {} ciphers, {} extensions{}",
            row.ciphers_len(),
            row.ext_count,
            row.alpn
                .as_ref()
                .map(|a| format!(", alpn {a}"))
                .unwrap_or_default()
        ),
        Ink::Recede.style(),
    )));

    if let Some(akamai) = &row.akamai {
        out.push(Line::from(vec![
            TSpan::styled("h2     ", Ink::Recede.style()),
            TSpan::styled(truncate(akamai, 60), Ink::Normal.style()),
        ]));
    }

    if height < SHORT {
        return out;
    }

    out.push(Line::from(""));
    out.push(Line::from(TSpan::styled(
        format!("clienthello   {} bytes", row.raw.len()),
        Ink::Recede.style(),
    )));
    out.push(Line::from(""));

    // Everything above this point, plus the header, table, rules and footer.
    let taken = out.len() + 10;
    let hex_room = usize::from(height).saturating_sub(taken);
    out.extend(hex_lines(row, width, hex_room));
    out
}

pub fn render(state: &State, area: Rect, buf: &mut Buffer) {
    let w = area.width as usize;
    let mut lines: Vec<Line> = Vec::new();

    // Header. No frame, no box, just a line and the numbers that matter.
    let alerts = state.alerts();
    lines.push(Line::from(vec![
        TSpan::styled("fpd   ", Ink::Advance.style()),
        TSpan::styled(state.source_label.clone(), Ink::Recede.style()),
        TSpan::styled(format!("   {} conn", state.rows.len()), Ink::Recede.style()),
        TSpan::styled(
            if alerts > 0 {
                format!("   {alerts} alert{}", if alerts == 1 { "" } else { "s" })
            } else {
                String::new()
            },
            if alerts > 0 {
                Ink::Advance.style()
            } else {
                Ink::Recede.style()
            },
        ),
        TSpan::styled(
            if state.dropped {
                "   records dropped".to_string()
            } else {
                String::new()
            },
            Ink::Advance.style(),
        ),
    ]));
    lines.push(Line::from(""));

    let table_height = (usize::from(area.height) / 3).max(1);
    lines.extend(table_lines(state, area.width, table_height));

    lines.push(rule(w));

    match state.current() {
        Some(row) => lines.extend(detail_lines(row, area.width, area.height)),
        None => lines.push(Line::from(TSpan::styled(
            "waiting for a connection",
            Ink::Recede.style(),
        ))),
    }

    // Footer, pinned to the bottom by padding rather than by a second widget.
    let footer = if state.searching {
        format!("/{}", state.search)
    } else if let Some(path) = &state.exported {
        format!("wrote {path}")
    } else {
        "/  search       f  follow       e  export       q  quit".to_string()
    };
    while lines.len() + 2 < usize::from(area.height) {
        lines.push(Line::from(""));
    }
    lines.push(rule(w));
    lines.push(Line::from(TSpan::styled(footer, Ink::Recede.style())));

    Paragraph::new(lines).render(area, buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    fn row(seq: u64, mismatch: bool) -> Row {
        // A shape close to a real curl hello: inert prefix, then ciphers, then
        // extensions, so the contrast rule has something to act on.
        let mut raw = vec![0u8; 200];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        Row {
            seq,
            at_ms: 1_786_614_271_000,
            ip: format!("45.9.148.{seq}"),
            ja4: "t13i4906h2_0d8feac7bc37_7395dae3b2f3".to_string(),
            verdict: if mismatch {
                "curl-8.7.1-macos".to_string()
            } else {
                "chrome-macos".to_string()
            },
            score: 1.0,
            mismatch,
            alpn: Some("h2".to_string()),
            akamai: Some("3:100;4:10485760;2:0|1048510465|0|m,s,a,p".to_string()),
            raw,
            ciphers: Span { start: 76, len: 98 },
            extensions: Span {
                start: 176,
                len: 24,
            },
            cipher_count: 49,
            ext_count: 6,
            grease_ext: Vec::new(),
        }
    }

    fn state_with(n: u64) -> State {
        let mut s = State::new(":8443".to_string());
        for i in 0..n {
            s.rows.push_back(row(i, i % 3 == 0));
        }
        s
    }

    fn draw(state: &State, w: u16, h: u16) -> Buffer {
        let area = Rect::new(0, 0, w, h);
        let mut buf = Buffer::empty(area);
        render(state, area, &mut buf);
        buf
    }

    /// The rule the entire design rests on, asserted against a real rendered
    /// buffer rather than against the theme in isolation. If any widget ever
    /// introduces a colour, this fails.
    #[test]
    fn nothing_rendered_carries_a_colour() {
        for (w, h) in [(120, 40), (100, 30), (80, 24), (60, 20), (38, 12)] {
            let buf = draw(&state_with(6), w, h);
            for cell in buf.content() {
                assert_eq!(cell.fg, Color::Reset, "a foreground colour at {w}x{h}");
                assert_eq!(cell.bg, Color::Reset, "a background colour at {w}x{h}");
            }
        }
    }

    /// Provenance is shown by contrast. Bytes outside the fingerprint spans render
    /// as recessed placeholders, so the fingerprint's shape appears in the dump
    /// without a single hue or bracket.
    #[test]
    fn inert_bytes_render_recessed_and_fingerprint_bytes_do_not() {
        let r = row(0, false);
        let lines = hex_lines(&r, 120, 20);
        let text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();

        assert!(text.contains("··"), "inert bytes must be recessed");
        // Byte 76 is the first cipher byte, and 200 bytes of 0..251 puts 0x4c there.
        assert!(
            text.contains("4c"),
            "fingerprint bytes must show their value"
        );
    }

    #[test]
    fn a_byte_inside_a_span_feeds_the_fingerprint_and_one_outside_does_not() {
        let r = row(0, false);
        assert!(!feeds_fingerprint(&r, 10), "the random field is inert");
        assert!(feeds_fingerprint(&r, 76), "first cipher byte");
        assert!(feeds_fingerprint(&r, 173), "last cipher byte");
        assert!(!feeds_fingerprint(&r, 174), "the gap between spans");
        assert!(feeds_fingerprint(&r, 176), "first extension byte");
        assert!(!feeds_fingerprint(&r, 200), "past the end");
    }

    /// The stated breakpoints, asserted through the renderer rather than only
    /// against the constant.
    #[test]
    fn the_hex_pane_narrows_then_disappears_rather_than_corrupting_the_frame() {
        let r = row(0, false);
        assert!(!hex_lines(&r, 120, 20).is_empty());
        assert!(!hex_lines(&r, 80, 20).is_empty());
        assert!(
            hex_lines(&r, 71, 20).is_empty(),
            "below 72 the pane is hidden, not squeezed"
        );
    }

    /// A frame that overflows its area is a corrupted frame. ratatui clips, so the
    /// check that matters is that nothing panics and the buffer stays its size.
    #[test]
    fn every_size_renders_without_panicking() {
        for (w, h) in [(200, 60), (100, 30), (72, 20), (40, 10), (20, 6), (10, 3)] {
            let buf = draw(&state_with(8), w, h);
            assert_eq!(buf.area.width, w);
            assert_eq!(buf.area.height, h);
        }
    }

    /// An empty state is the first thing a user sees, so it must say something
    /// rather than render a blank screen.
    #[test]
    fn an_empty_state_says_it_is_waiting() {
        let buf = draw(&State::new(":8443".to_string()), 100, 24);
        let text: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("waiting for a connection"), "{text}");
    }

    /// The regression this ordering exists to prevent. With the hex pane in the
    /// middle it pushed the mismatch warning and the key legend off a 30-row
    /// terminal, so the most important line on screen was the one that vanished.
    /// Every test passed while that was true, which is why this one is explicit.
    #[test]
    fn the_alert_and_the_footer_survive_a_long_hex_dump() {
        let mut s = state_with(3);
        s.selected = 0;
        assert!(s.rows[0].mismatch, "precondition");

        for (w, h) in [(120, 40), (100, 30), (100, 24), (80, 22)] {
            let buf = draw(&s, w, h);
            let text: String = buf.content().iter().map(|c| c.symbol()).collect();
            assert!(text.contains("contradicts"), "alert lost at {w}x{h}");
            assert!(text.contains("quit"), "key legend lost at {w}x{h}");
            assert!(text.contains("ja4"), "fingerprint lost at {w}x{h}");
        }
    }

    #[test]
    fn search_filters_the_table() {
        let mut s = state_with(6);
        s.search = "chrome".to_string();
        assert!(s.visible().iter().all(|r| r.verdict.contains("chrome")));
        assert!(s.visible().len() < s.rows.len());
    }

    /// Dropped records are surfaced. A silently incomplete list is worse than a
    /// visibly incomplete one.
    #[test]
    fn a_dropped_record_gap_is_shown_in_the_header() {
        let mut s = state_with(3);
        s.dropped = true;
        let buf = draw(&s, 120, 30);
        let text: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("records dropped"), "{text}");
    }
}
