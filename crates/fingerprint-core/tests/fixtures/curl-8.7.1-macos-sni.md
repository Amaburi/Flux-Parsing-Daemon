# curl-8.7.1-macos-sni

Raw ClientHello record, 321 bytes. Same client as `curl-8.7.1-macos`, differing **only**
in that a hostname was supplied, so the SNI extension is present.

| | |
|---|---|
| Client | curl 8.7.1 (macOS system stack) |
| OS | macOS 15 (Darwin 25.5.0), arm64 |
| Captured | 2026-08-11 |
| Command | `curl -sk --http2 --resolve example.com:8443:127.0.0.1 https://example.com:8443/` |
| Target | `example.com` resolved to `127.0.0.1:8443` — **SNI present**, value `example.com` |

## Oracle values

```
JA4    t13d4907h2_0d8feac7bc37_7395dae3b2f3
```

## Why this fixture exists

It is the controlled pair for `curl-8.7.1-macos`. Same client, same ciphers, same
extensions apart from SNI — so the diff isolates exactly two JA4 rules:

```
no SNI    t13i4906h2_0d8feac7bc37_7395dae3b2f3
SNI       t13d4907h2_0d8feac7bc37_7395dae3b2f3
             ↑  ↑↑
             |  extension count 06 → 07   SNI IS counted in segment (a)
             i → d                        SNI presence flips the flag

          segments (b) and (c) are IDENTICAL
          → SNI is EXCLUDED from the (c) hash
```

Without this pair, "SNI is counted in (a) but excluded from (c)" is a rule read from a
document. With it, the rule is an executable assertion over real traffic — and a wrong
implementation cannot pass both fixtures at once.
