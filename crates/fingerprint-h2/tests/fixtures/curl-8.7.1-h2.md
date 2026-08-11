# curl-8.7.1-h2

Decrypted HTTP/2 connection preamble, 103 bytes: preface + SETTINGS + WINDOW_UPDATE +
HEADERS.

| | |
|---|---|
| Client | curl 8.7.1 (macOS system stack, nghttp2) |
| OS | macOS 15 (Darwin 25.5.0), arm64 |
| Captured | 2026-08-11 |
| Command | `curl -sk --http2 https://127.0.0.1:8444/` |

## Oracle values

```
settings ids (wire order)   3,4,2          ← NOT ascending
  3 max_concurrent_streams  100
  4 initial_window_size     10485760
  2 enable_push             0
window_update increment     1048510465
header names (HPACK)        :method, :scheme, :authority, :path, user-agent, accept
```

**Expected Akamai fingerprint:**

```
3:100;4:10485760;2:0|1048510465|0|m,s,a,p
```

## Notes

- **SETTINGS arrive as `3, 4, 2` — not in ascending order.** Any implementation that
  sorts or normalises settings destroys the fingerprint. This is the concrete reason
  `settings` is modelled as an ordered `Vec<(u16, u32)>`.
- **`3:100` is the curl tell.** No browser sends SETTINGS id 3 at all; see
  `chrome-h2.md` for the contrast.
- **WINDOW_UPDATE 1048510465 = 1048576000 − 65535** — curl raising the connection window
  from the protocol default to 1000 MiB. A client configuration artefact, which is
  exactly why it discriminates.
- Pseudo-header order `m,s,a,p`, differing from Chrome's `m,a,s,p`.
- Only six headers, versus Chrome's twenty-one — the `sec-ch-ua*` / `sec-fetch-*` block
  is absent entirely.
