# curl-8.7.1-macos

Raw ClientHello record, 301 bytes.

| | |
|---|---|
| Client | curl 8.7.1 (macOS system LibreSSL/OpenSSL stack) |
| OS | macOS 15 (Darwin 25.5.0), arm64 |
| Captured | 2026-08-11 |
| Command | `curl -sk --http2 https://127.0.0.1:8443/` |
| Target | `127.0.0.1:8443` — **bare IP, so no SNI extension** |
| Record header | `16 03 01 01 28` (handshake, legacy version TLS 1.0, length 296) |

## Oracle values

Independently computed by **tshark 4.4.9** (`tls.handshake.ja4`) over a pcap whose
payload is byte-identical to `curl-8.7.1-macos.bin`. Regenerate with:

```bash
python3 scripts/bin2pcap.py crates/fingerprint-core/tests/fixtures/curl-8.7.1-macos.bin /tmp/f.pcap
tshark -r /tmp/f.pcap -T fields -e tls.handshake.ja4 -e tls.handshake.ja4_r
```

```
JA4    t13i4906h2_0d8feac7bc37_7395dae3b2f3
JA3    4f2655722e37c542ebeaf1eed48cbbbb
```

JA4_r (the pre-hash strings, which is what makes a mismatch diagnosable):

```
a         t13i4906h2
ciphers   0004,0005,000a,0016,002f,0033,0035,0039,003c,003d,0041,0045,0067,006b,
          0081,0084,0088,009c,009d,009e,009f,00ba,00be,00c0,00c4,00ff,1301,1302,
          1303,c007,c008,c009,c00a,c011,c012,c013,c014,c023,c024,c027,c028,c02b,
          c02c,c02f,c030,cca8,cca9,ccaa,ff85
ext+sig   000a,000b,000d,002b,0033_0806,0601,0603,0805,0501,0503,0804,0401,0403,
          0201,0203
```

Both hashes verified independently with `shasum -a 256 | cut -c1-12`:
`0d8feac7bc37` and `7395dae3b2f3`.

## Notes

- 49 cipher suites, **no GREASE** — curl does not send GREASE. This is the contrast
  case against the Chrome fixture.
- 6 extensions on the wire: `002b, 0033, 000b, 000a, 000d, 0010`.
- Only **5** appear in the JA4 (c) hash: ALPN (`0010`) is excluded per spec, and SNI is
  absent. Extension count in segment (a) is nonetheless `06`.
- Wire extension order is **fixed** for curl; unlike Chrome it does not permute.
