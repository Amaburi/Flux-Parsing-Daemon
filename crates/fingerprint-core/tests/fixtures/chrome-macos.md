# chrome-macos

Raw ClientHello record, 1818 bytes.

| | |
|---|---|
| Client | Google Chrome (stable), macOS |
| OS | macOS 15 (Darwin 25.5.0), arm64 |
| Captured | 2026-08-11 |
| Target | `127.0.0.1:8443` — **bare IP, so no SNI extension** |
| Record header | `16 03 01 07 15` (handshake, legacy version TLS 1.0, length 1813) |

## Oracle values

```
JA4    t13i1516h2_8daaf6152771_a87ad97598a9
```

JA4_r:

```
a         t13i1516h2
ciphers   002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9
ext+sig   0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,fe0d,ff01
          _0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601
```

The cipher-list hash `8daaf6152771` is the widely published Chrome value — independent
evidence that this capture is genuinely Chrome-shaped rather than something local.

## ⚠ This capture is a *resuming* session

`ja4_r` contains extension `0029` = 41 = `pre_shared_key`. Per M0 finding 5, Chrome
sends 17 extensions on a fresh connection and 18 when resuming. This fixture is the
**18** case:

```
18 on the wire  =  16 non-GREASE  +  2 GREASE
16 non-GREASE   =  15 in the (c) hash  +  ALPN (0010, excluded from the hash)
```

So segment (a) reads `16`. A non-resuming Chrome capture would read `15` and produce a
**different JA4** for the same browser build.

**Consequence for tests:** never assert a hand-predicted JA4 for Chrome. Assert against
the oracle value recorded here, and treat segment (a)'s extension count as
session-dependent. This is a property of JA4, not a defect in the parser.

## GREASE

2 GREASE extensions and 1 GREASE cipher were present. **Their values are one arbitrary
draw** (M0 finding 2) and must never be asserted literally — only positions and counts.
The `ja4_r` lists above already have GREASE removed, which is why they are stable.

## Notes

- `44cd` = 17613 = `application_settings` (ALPS)
- `fe0d` = 65037 = `encrypted_client_hello` (ECH GREASE)
- `ff01` = 65281 = `renegotiation_info`
- `001b` = 27 = `compress_certificate`
- Wire extension order is **permuted per connection** (M0 finding 1). Only the sorted
  set is stable, which is precisely why JA4 sorts and JA3 does not survive.
