# fpd M4a — The Verdict Engine and Claim Mismatch

> Execute task-by-task, in order. Steps use checkbox (`- [ ]`) syntax. Every task ends at a hard stop for review and commit.

**Goal:** Identify an unknown client against the whole profile database, and detect when a client's `User-Agent` contradicts what its fingerprint says it is.

**Architecture:** Pure additions to `fingerprint-probe`. `verdict.rs` scores a report against every profile and returns the best match with a confidence. `ua.rs` extracts a claimed browser family from a User-Agent string, conservatively. Both are fixture-driven and open no sockets.

**Tech Stack:** No new dependencies expected. Existing `fingerprint-probe`, `fingerprint-core`, `fingerprint-h2`.

---

## ⚠ Decision required before Task 3: this feature reads one header value

The README currently states, without qualification:

> Header values are never read, logged or stored. Only names, order and counts.

**Claim mismatch cannot work under that rule.** Detecting that a client says "Chrome 131"
while fingerprinting as `python-requests` requires reading the `User-Agent` *value*.
There is no way around it. The claim is the value.

So one of three things has to happen, and it is your call:

1. **Narrow the promise, keep the feature.** Read `user-agent` only, document it
   explicitly, and keep every other value unread. The wording becomes: *"Header values
   are not read, with one exception. `user-agent` is read because mismatch detection
   compares what a client claims against what it is. Cookie, authorization and all other
   values never enter the fingerprint path."*
2. **Keep the promise, drop the feature.** Mismatch detection is the single most useful
   output in the design (§6.4). Dropping it is a real loss.
3. **Make it opt-in.** Off by default, enabled with `--detect-ua-mismatch`. The promise
   holds for the default build, and enabling it is an informed choice.

**Recommendation: option 1.** The purpose of the original rule was to never touch
credentials, and `user-agent` is not a credential. Stating the exception precisely is
more honest than an absolute claim that the code then quietly breaks. Option 3 sounds
safer but produces a tool whose headline feature is off by default, which is worse
documentation than a clear exception.

Whichever is chosen, **Task 6 updates the README to match the code**. A privacy claim
that the code contradicts is worse than having no claim.

---

## Global Constraints

- No test opens a socket. This whole milestone is pure.
- Every expected value comes from a committed fixture or its recorded oracle.
- `user-agent` is the only header value any code in this milestone may read. Cookie and
  authorization values remain untouched, and a test enforces that.

## Commit Protocol

**The implementer never runs `git commit` or `git push`.** Every task ends at a STOP:
confirm tests pass, print the suggested commit command, wait.

---

### Task 1: Scoring a report against the whole database

**Files:** `crates/fingerprint-probe/src/verdict.rs`

**Interfaces:**
- Consumes: `diff::diff`, `ProfileDb`, `ClientReport`.
- Produces: `Verdict { best: Option<Match>, ranked: Vec<Match> }`, `Match { label, score, diff }`, `identify(&ClientReport, &ProfileDb) -> Verdict`.

`check` currently answers "does this match profile X". This answers "which profile is
this, if any".

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn curl_is_identified_as_the_curl_profile() {
    let v = identify(&report("curl"), &db());
    let best = v.best.as_ref().expect("a match");
    assert_eq!(best.label, "curl-8.7.1-macos");
    assert_eq!(best.score, 1.0);
}

#[test]
fn chrome_is_identified_as_the_chrome_profile() {
    let v = identify(&report("chrome"), &db());
    assert_eq!(v.best.as_ref().expect("a match").label, "chrome-macos");
}

/// Ranking must be ordered, because the second-best match is what tells an
/// operator whether the identification was close or obvious.
#[test]
fn matches_are_ranked_best_first() {
    let v = identify(&report("curl"), &db());
    for pair in v.ranked.windows(2) {
        assert!(pair[0].score >= pair[1].score);
    }
}

/// A client resembling nothing in the database must say so rather than pick the
/// least-bad option. A tool that always names a browser is useless.
#[test]
fn a_client_matching_nothing_reports_no_best_match() {
    let mut r = report("curl");
    r.tls.ciphers = vec![0x1301];
    r.tls.extensions = vec![0x0001];
    r.h2 = None;
    assert!(identify(&r, &db()).best.is_none());
    assert!(!identify(&r, &db()).ranked.is_empty(), "ranking is still reported");
}

/// An exact match must be reachable, or the confidence number means nothing.
#[test]
fn an_exact_match_scores_one_and_a_partial_scores_below_it() {
    let exact = identify(&report("curl"), &db());
    let mut altered = report("curl");
    altered.tls.extensions.reverse();
    let partial = identify(&altered, &db());
    assert!(
        exact.best.expect("m").score > partial.best.map(|m| m.score).unwrap_or(0.0)
    );
}
```

The threshold below which `best` is `None` needs a value. Pick it from the data rather
than from taste: measure what curl scores against the Chrome profile (roughly 0.2 today)
and set the floor above that, then record the measured numbers in a comment so a future
change can see why.

- [ ] **Step 2: Run to verify it fails.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: STOP — commit**

```bash
git add crates/fingerprint-probe/
git commit -m "feat(probe): identify a client against the whole profile database"
```

---

### Task 2: Extracting a claimed family from a User-Agent

**Files:** `crates/fingerprint-probe/src/ua.rs`

**Interfaces:** `Family { Chrome, Firefox, Safari, Edge, Curl, Python, Go, Node, Unknown }`, `claimed_family(&str) -> Family`.

**This must be conservative.** The design calls mismatch detection near-zero false
positive, and that property comes entirely from refusing to guess. `Unknown` is a
perfectly good answer and must be the default for anything unrecognised.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn real_user_agents_are_classified() {
    let cases = [
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
          (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", Family::Chrome),
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) \
          Gecko/20100101 Firefox/133.0", Family::Firefox),
        ("curl/8.7.1", Family::Curl),
        ("python-requests/2.31.0", Family::Python),
        ("Go-http-client/2.0", Family::Go),
    ];
    for (ua, want) in cases {
        assert_eq!(claimed_family(ua), want, "{ua}");
    }
}

/// Chrome's UA contains the literal word "Safari", and Edge's contains "Chrome".
/// Naive substring matching gets both wrong, and both are common enough that a
/// wrong answer here would produce constant false mismatches.
#[test]
fn chrome_is_not_mistaken_for_safari_and_edge_is_not_mistaken_for_chrome() {
    let chrome = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) \
                  Chrome/131.0.0.0 Safari/537.36";
    assert_eq!(claimed_family(chrome), Family::Chrome);

    let edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0";
    assert_eq!(claimed_family(edge), Family::Edge);

    let safari = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
                  (KHTML, like Gecko) Version/17.6 Safari/605.1.15";
    assert_eq!(claimed_family(safari), Family::Safari);
}

/// Anything unrecognised is Unknown, never a guess.
#[test]
fn unrecognised_and_empty_agents_are_unknown() {
    for ua in ["", "x", "Mozilla/5.0", "SomeInternalTool/1.2", "🙂"] {
        assert_eq!(claimed_family(ua), Family::Unknown, "{ua}");
    }
}

/// The observed Chrome fixture, so this is checked against real traffic and not
/// only against strings typed into a test.
#[test]
fn the_chrome_fixture_user_agent_classifies_as_chrome() {
    let ua = fixture_user_agent("chrome");
    assert_eq!(claimed_family(&ua), Family::Chrome);
}
```

- [ ] **Step 2–4:** red, implement, green. Match Edge before Chrome, and Chrome before
  Safari, since each later family's token appears in the earlier one's string.
- [ ] **Step 5: STOP — commit**

```bash
git add crates/fingerprint-probe/
git commit -m "feat(probe): conservative User-Agent family extraction"
```

---

### Task 3: Claim mismatch

Blocked on the decision at the top of this document.

**Files:** `crates/fingerprint-probe/src/verdict.rs`, `src/profile.rs`

**Interfaces:** `Profile::family`, `Verdict::ua_mismatch: Option<UaMismatch>`, `UaMismatch { claimed: Family, observed: Family }`.

Each shipped profile gains a `family` field, so the identified profile can be compared
against the claim.

- [ ] **Step 1: Write the failing tests**

```rust
/// The headline case: a client claiming Chrome whose fingerprint is curl.
#[test]
fn a_curl_fingerprint_claiming_chrome_is_a_mismatch() {
    let mut r = report("curl");
    set_user_agent(&mut r, "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 \
                            (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36");
    let v = identify(&r, &db());
    let m = v.ua_mismatch.expect("mismatch");
    assert_eq!(m.claimed, Family::Chrome);
    assert_eq!(m.observed, Family::Curl);
}

/// An honest client must never be flagged. This is the false-positive guard and
/// matters more than the detection itself.
#[test]
fn an_honest_client_is_never_flagged() {
    for name in ["curl", "chrome"] {
        assert!(identify(&report(name), &db()).ua_mismatch.is_none(), "{name}");
    }
}

/// No claim, no mismatch. Silence is not evidence.
#[test]
fn an_absent_or_unknown_user_agent_produces_no_mismatch() {
    let mut r = report("curl");
    set_user_agent(&mut r, "SomeInternalTool/1.0");
    assert!(identify(&r, &db()).ua_mismatch.is_none());

    let mut r2 = report("curl");
    remove_user_agent(&mut r2);
    assert!(identify(&r2, &db()).ua_mismatch.is_none());
}

/// If the fingerprint matches nothing, there is nothing to contradict the claim.
/// Reporting a mismatch here would flag every client the database has not seen.
#[test]
fn an_unidentified_fingerprint_produces_no_mismatch() {
    let mut r = report("curl");
    r.tls.ciphers = vec![0x1301];
    set_user_agent(&mut r, "Mozilla/5.0 ... Chrome/131.0.0.0 Safari/537.36");
    assert!(identify(&r, &db()).ua_mismatch.is_none());
}

/// Only header values on the allowlist may be read. This test exists because the
/// privacy promise is a stated property of the product, not an implementation
/// detail, and it must fail loudly if someone starts reading cookies.
#[test]
fn no_header_value_other_than_user_agent_is_read() {
    let mut r = report("chrome");
    set_header_value(&mut r, "cookie", "session=SECRETVALUE");
    set_header_value(&mut r, "authorization", "Bearer SECRETTOKEN");
    let v = identify(&r, &db());
    let rendered = format!("{v:?}");
    assert!(!rendered.contains("SECRETVALUE"));
    assert!(!rendered.contains("SECRETTOKEN"));
}
```

- [ ] **Step 2–4:** red, implement, green.
- [ ] **Step 5: STOP — commit**

```bash
git add crates/fingerprint-probe/
git commit -m "feat(probe): claim mismatch detection, conservative by construction"
```

---

### Task 4: `fpd check` without a profile identifies the client

**Files:** `crates/fpd/src/commands/check.rs`, `src/cli.rs`, `crates/fpd/tests/check.rs`

`--profile` becomes optional. Without it, `check` reports what the client looks like
rather than comparing against a name.

```console
$ fpd check -- curl -sk --http2 '{url}'
  identified: curl-8.7.1-macos (100% match)
  runner-up:  chrome-macos (20%)
  ✓ every checked field agrees
```

- [ ] **Step 1: Write the failing integration tests**

```rust
#[test]
fn check_without_a_profile_identifies_curl() {
    fpd(&accepted()).args(["check", "--", "curl", "-sk", "--http2", "{url}"])
        .assert().success()
        .stdout(predicate::str::contains("identified: curl-8.7.1-macos"));
}

#[test]
fn check_with_a_profile_still_compares_against_it() {
    fpd(&accepted())
        .args(["check", "--profile", "chrome-macos", "--", "curl", "-sk", "--http2", "{url}"])
        .assert().code(1)
        .stdout(predicate::str::contains("NOT chrome-macos"));
}
```

- [ ] **Step 2–4:** red, implement, green.
- [ ] **Step 5: STOP — commit**

---

### Task 5: Profile families and a regenerated database

Each shipped profile gains `family`, and the generator is updated. Without this, Task 3
has nothing to compare a claim against.

- [ ] Add `family` to `Profile`, regenerate both shipped profiles, assert every profile
      in the database has one.
- [ ] STOP — commit.

---

### Task 6: Documentation, including the privacy wording

- [ ] Update the README privacy section to match whichever option was chosen at the top
      of this document. **Do not skip this.** A privacy claim the code contradicts is
      worse than no claim.
- [ ] Document `check` without `--profile`, and mismatch detection, with real output.
- [ ] Update the status table.
- [ ] STOP — commit.

---

## Self-Review

**Spec coverage.** §6.4 verdict engine, exact/partial/unknown, and `ua_mismatch` → Tasks
1 to 3. The claim in §6.4 that mismatch has a near-zero false-positive rate is what
Task 2's conservatism and Task 3's three negative tests exist to earn.

**Deliberately excluded.** `fpd serve`, header injection, structured logging and
`fingerprint-tower`. Those are M4b and M4c.

**Known risks.**
1. **Only two profiles exist**, so identification is a two-way choice. The scoring floor
   in Task 1 is calibrated against a database that will grow, and it should be
   re-measured when Firefox and Safari profiles arrive.
2. **UA parsing is a heuristic and will drift.** Browsers change their strings, and the
   UA-reduction effort has been shrinking them for years. The mitigation is
   conservatism: `Unknown` on anything unrecognised, never a guess.
3. **A false mismatch is worse than a missed one.** An operator who sees one wrong flag
   stops trusting all of them. Task 3's negative tests outnumber its positive test three
   to one, deliberately.
4. **Profile families are hand-assigned** in Task 5. With two profiles that is fine. With
   fifty it becomes a source of quiet error and would want deriving from the label.
