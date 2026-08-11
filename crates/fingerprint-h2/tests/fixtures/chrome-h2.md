# chrome-h2

Decrypted HTTP/2 connection preamble, 679 bytes: preface + SETTINGS + WINDOW_UPDATE +
HEADERS.

| | |
|---|---|
| Client | Google Chrome (stable), macOS |
| OS | macOS 15 (Darwin 25.5.0), arm64 |
| Captured | 2026-08-11 |
| Target | `https://127.0.0.1:8444/`, ALPN restricted to `h2` |

These bytes exist only **after** TLS termination, so unlike the TLS fixtures they cannot
be captured with `tcpdump`. Recorded by `spikes/s2-h2-replay/src/bin/dump_h2.rs`.

## Oracle values

tshark 4.4.9, with the HTTP/2 dissector forced onto the synthesised pcap:

```bash
python3 scripts/bin2pcap.py crates/fingerprint-h2/tests/fixtures/chrome-h2.bin /tmp/h2.pcap
tshark -r /tmp/h2.pcap -d tcp.port==443,http2 -T fields \
  -e http2.settings.id -e http2.window_update.window_size_increment -e http2.header.name
```

```
settings ids (wire order)   1,2,4,6
  1 header_table_size       65536
  2 enable_push             0
  4 initial_window_size     6291456
  6 max_header_list_size    262144
window_update increment     15663105
header names (HPACK)        :method, :authority, :scheme, :path, cache-control,
                            sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform,
                            upgrade-insecure-requests, user-agent, accept,
                            sec-fetch-site, sec-fetch-mode, sec-fetch-user,
                            sec-fetch-dest, accept-encoding, accept-language,
                            cookie, cookie, cookie, priority
```

**Expected Akamai fingerprint:**

```
1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

## The two discriminators, both measured

**1. No SETTINGS id 3.** Chrome does not send `MAX_CONCURRENT_STREAMS` at all, while
curl announces `3:100`. Presence alone separates the families — which is why `settings`
must be an ordered list of what was literally on the wire, never a map with defaults
filled in.

**2. Pseudo-header order `m,a,s,p`.** Chrome sends `:method, :authority, :scheme, :path`.
curl sends `:method, :scheme, :authority, :path` = `m,s,a,p`. A client claiming to be
Chrome while ordering pseudo-headers like curl is caught on its first request.

## Notes

- **No PRIORITY frames.** Chrome uses RFC 9218 extensible priorities — visible as the
  trailing `priority` *header* rather than a PRIORITY frame. The Akamai priority field is
  therefore `0`. Firefox still sends a priority tree and would exercise that parsing
  path; worth capturing when Firefox fixtures arrive.
- **Three separate `cookie` headers.** HPACK splits the cookie header for better
  compression. Relevant later for JA4H, which counts and hashes cookie fields.
- The `sec-ch-ua*` and `sec-fetch-*` header block is itself strongly Chrome-shaped;
  header names and order feed JA4H rather than the Akamai fingerprint.
