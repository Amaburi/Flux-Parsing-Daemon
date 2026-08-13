//! The event loop, and the terminal's lifecycle.

use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

use super::render::{render, State};
use super::source::Row;

/// The buffer a viewer keeps. Independent of `serve`'s, since a viewer may be
/// attached for far longer than the server's window.
const VIEW_CAPACITY: usize = 2000;

/// A terminal can usefully repaint about this often. Under a busy `serve` the
/// socket delivers faster than that, so anything arriving in between is coalesced
/// into the next frame. Redrawing identical frames at socket speed would peg a core
/// for nothing.
const FRAME: Duration = Duration::from_millis(33);

/// Puts the terminal back the way it was found.
///
/// Called on the normal path and from a panic hook. A crash that leaves raw mode
/// enabled leaves the user with a shell that does not echo, which is a worse
/// failure than whatever caused the panic.
fn restore() {
    let _ = disable_raw_mode();
    let _ = crossterm::execute!(io::stdout(), LeaveAlternateScreen);
    let _ = crossterm::execute!(io::stdout(), crossterm::cursor::Show);
}

fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore();
        previous(info);
    }));
}

/// Reads terminal events on a blocking thread and forwards them.
///
/// `event::read` blocks, so it cannot sit in an async task without stalling the
/// runtime that is also feeding us rows.
fn spawn_events() -> mpsc::Receiver<Event> {
    let (tx, rx) = mpsc::channel(64);
    std::thread::spawn(move || loop {
        match event::poll(Duration::from_millis(100)) {
            Ok(true) => match event::read() {
                Ok(ev) => {
                    if tx.blocking_send(ev).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            },
            Ok(false) => {
                if tx.is_closed() {
                    return;
                }
            }
            Err(_) => return,
        }
    });
    rx
}

/// What a key press did, so the loop knows whether a repaint is warranted.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Redraw,
    Ignore,
    Quit,
}

/// Key handling, kept pure so it can be tested without a terminal.
pub fn on_key(state: &mut State, code: KeyCode, mods: KeyModifiers) -> Action {
    if state.searching {
        match code {
            KeyCode::Esc => {
                state.searching = false;
                state.search.clear();
            }
            KeyCode::Enter => state.searching = false,
            KeyCode::Backspace => {
                state.search.pop();
            }
            KeyCode::Char(c) => state.search.push(c),
            _ => return Action::Ignore,
        }
        state.selected = 0;
        return Action::Redraw;
    }

    match code {
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => Action::Quit,
        KeyCode::Char('/') => {
            state.searching = true;
            state.search.clear();
            Action::Redraw
        }
        KeyCode::Char('f') => {
            state.follow = !state.follow;
            Action::Redraw
        }
        KeyCode::Char('e') => {
            export(state);
            Action::Redraw
        }
        KeyCode::Up | KeyCode::Char('k') => {
            // Moving off the newest row means the user is reading, not watching.
            state.follow = false;
            state.selected = state.selected.saturating_sub(1);
            Action::Redraw
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.follow = false;
            let last = state.visible().len().saturating_sub(1);
            state.selected = (state.selected + 1).min(last);
            Action::Redraw
        }
        _ => Action::Ignore,
    }
}

/// Writes the selected ClientHello to a file, so it can be fed to `tshark` or
/// committed as a fixture. The bytes are the evidence, so exporting them rather
/// than a rendering of them is the useful thing.
fn export(state: &mut State) {
    let Some(row) = state.current() else {
        return;
    };
    let name = format!("fpd-{}-{}.bin", row.verdict, row.seq);
    if std::fs::write(&name, &row.raw).is_ok() {
        state.exported = Some(name);
    }
}

pub async fn run(mut rows: mpsc::Receiver<Row>, source_label: String) -> io::Result<()> {
    install_panic_hook();
    enable_raw_mode()?;
    crossterm::execute!(io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let mut state = State::new(source_label);
    let mut events = spawn_events();
    let mut dirty = true;
    let mut last_draw = Instant::now() - FRAME;

    loop {
        if dirty && last_draw.elapsed() >= FRAME {
            terminal.draw(|f| render(&state, f.area(), f.buffer_mut()))?;
            dirty = false;
            last_draw = Instant::now();
        }

        tokio::select! {
            Some(row) = rows.recv() => {
                // A jump in seq means the socket dropped records for us. Surfaced
                // rather than hidden, since the alternative is a quietly
                // incomplete list.
                if let Some(last) = state.rows.back() {
                    if row.seq > last.seq + 1 {
                        state.dropped = true;
                    }
                }
                state.rows.push_back(row);
                while state.rows.len() > VIEW_CAPACITY {
                    state.rows.pop_front();
                }
                if state.follow {
                    state.selected = state.visible().len().saturating_sub(1);
                }
                dirty = true;
            }
            Some(ev) = events.recv() => {
                match ev {
                    Event::Key(k) if k.kind == KeyEventKind::Press => {
                        match on_key(&mut state, k.code, k.modifiers) {
                            Action::Quit => break,
                            Action::Redraw => dirty = true,
                            Action::Ignore => {}
                        }
                    }
                    Event::Resize(_, _) => dirty = true,
                    _ => {}
                }
            }
            // Neither source is ready. Wake anyway so a coalesced repaint lands.
            () = tokio::time::sleep(FRAME) => {}
        }
    }

    restore();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint_core::hello::Span;

    fn row(seq: u64) -> Row {
        Row {
            seq,
            at_ms: 0,
            ip: format!("10.0.0.{seq}"),
            ja4: "t13i4906h2_0d8feac7bc37_7395dae3b2f3".to_string(),
            verdict: "curl-8.7.1-macos".to_string(),
            score: 1.0,
            mismatch: false,
            alpn: None,
            akamai: None,
            raw: vec![0; 32],
            ciphers: Span { start: 0, len: 4 },
            extensions: Span { start: 4, len: 4 },
            cipher_count: 2,
            ext_count: 1,
            grease_ext: Vec::new(),
        }
    }

    fn state_with(n: u64) -> State {
        let mut s = State::new(":8443".to_string());
        for i in 0..n {
            s.rows.push_back(row(i));
        }
        s
    }

    #[test]
    fn q_and_escape_and_ctrl_c_all_quit() {
        let mut s = state_with(3);
        assert_eq!(
            on_key(&mut s, KeyCode::Char('q'), KeyModifiers::NONE),
            Action::Quit
        );
        assert_eq!(
            on_key(&mut s, KeyCode::Esc, KeyModifiers::NONE),
            Action::Quit
        );
        assert_eq!(
            on_key(&mut s, KeyCode::Char('c'), KeyModifiers::CONTROL),
            Action::Quit
        );
    }

    /// Selection must not walk off either end, at any list length including zero.
    #[test]
    fn selection_is_clamped_at_both_ends() {
        let mut s = state_with(3);
        for _ in 0..10 {
            on_key(&mut s, KeyCode::Down, KeyModifiers::NONE);
        }
        assert_eq!(s.selected, 2, "must not pass the last row");
        for _ in 0..10 {
            on_key(&mut s, KeyCode::Up, KeyModifiers::NONE);
        }
        assert_eq!(s.selected, 0, "must not pass the first row");

        let mut empty = State::new(":8443".to_string());
        on_key(&mut empty, KeyCode::Down, KeyModifiers::NONE);
        on_key(&mut empty, KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(empty.selected, 0, "an empty list must not panic or wrap");
    }

    /// Moving the selection means the user is reading history, so following the
    /// newest row has to stop or their selection is yanked away on the next
    /// connection.
    #[test]
    fn moving_the_selection_turns_off_follow() {
        let mut s = state_with(3);
        assert!(s.follow, "follow starts on");
        on_key(&mut s, KeyCode::Up, KeyModifiers::NONE);
        assert!(!s.follow);
    }

    #[test]
    fn f_toggles_follow_back_and_forth() {
        let mut s = state_with(1);
        let before = s.follow;
        on_key(&mut s, KeyCode::Char('f'), KeyModifiers::NONE);
        assert_eq!(s.follow, !before);
        on_key(&mut s, KeyCode::Char('f'), KeyModifiers::NONE);
        assert_eq!(s.follow, before);
    }

    /// While searching, keys are text rather than commands. Otherwise typing
    /// "queue" would quit on the first letter.
    #[test]
    fn typing_a_query_does_not_trigger_commands() {
        let mut s = state_with(3);
        on_key(&mut s, KeyCode::Char('/'), KeyModifiers::NONE);
        assert!(s.searching);

        for c in "queue".chars() {
            assert_eq!(
                on_key(&mut s, KeyCode::Char(c), KeyModifiers::NONE),
                Action::Redraw,
                "{c} was treated as a command"
            );
        }
        assert_eq!(s.search, "queue");
        assert!(s.searching, "still searching, not quit");
    }

    #[test]
    fn escape_abandons_a_search_and_enter_keeps_it() {
        let mut s = state_with(3);
        on_key(&mut s, KeyCode::Char('/'), KeyModifiers::NONE);
        on_key(&mut s, KeyCode::Char('c'), KeyModifiers::NONE);
        on_key(&mut s, KeyCode::Esc, KeyModifiers::NONE);
        assert!(!s.searching);
        assert_eq!(s.search, "", "escape clears the query");

        on_key(&mut s, KeyCode::Char('/'), KeyModifiers::NONE);
        on_key(&mut s, KeyCode::Char('c'), KeyModifiers::NONE);
        on_key(&mut s, KeyCode::Enter, KeyModifiers::NONE);
        assert!(!s.searching);
        assert_eq!(s.search, "c", "enter keeps the query as a filter");
    }

    #[test]
    fn backspace_edits_the_query() {
        let mut s = state_with(1);
        on_key(&mut s, KeyCode::Char('/'), KeyModifiers::NONE);
        for c in "abc".chars() {
            on_key(&mut s, KeyCode::Char(c), KeyModifiers::NONE);
        }
        on_key(&mut s, KeyCode::Backspace, KeyModifiers::NONE);
        assert_eq!(s.search, "ab");
    }

    /// An unbound key must not cost a repaint, because the loop uses the return
    /// value to decide whether to draw.
    #[test]
    fn an_unbound_key_asks_for_no_redraw() {
        let mut s = state_with(1);
        assert_eq!(
            on_key(&mut s, KeyCode::Char('z'), KeyModifiers::NONE),
            Action::Ignore
        );
    }
}
