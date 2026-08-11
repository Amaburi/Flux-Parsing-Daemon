# Upstream report: panic in fluke-hpack on a malformed dynamic table size update

Ready to file against `fluke-hpack`. Everything below has been reproduced locally
against 0.3.1 on Rust 1.91.1.

Kept in this repository as the record of the finding, since fpd no longer depends on
the crate. See `crates/fingerprint-h2/src/hpack/` for the replacement.

---

## Title

Panic on malformed dynamic table size update, reachable from untrusted input

## Version

`fluke-hpack` 0.3.1, Rust 1.91.1

## Summary

`Decoder::decode` panics instead of returning `Err` when a header block contains a
dynamic table size update whose integer is truncated. The shortest input that triggers
it is a single byte.

Because header blocks arrive from the network, any server decoding HPACK with this crate
can be made to panic by a remote peer. In a per-connection task that is a denial of
service for that connection, and in a build using `panic = "abort"` it takes down the
process.

## Reproducer

```rust
fn main() {
    // 0x3f is 001_11111: a dynamic table size update whose 5-bit prefix is
    // saturated, so the value continues into following octets. None follow.
    let block = [0x3fu8];
    let result = fluke_hpack::Decoder::new().decode(&block);
    println!("{result:?}");
}
```

Observed:

```
thread 'main' panicked at fluke-hpack-0.3.1/src/decoder.rs:505:64:
called `Option::unwrap()` on a `None` value
```

Expected: `Err(DecoderError::IntegerDecodingError(IntegerDecodingError::NotEnoughOctets))`

## Scope

Only a size update with a saturated prefix reaches the failing path. Non-saturated ones
are handled correctly, which is why this is easy to miss in normal testing.

| Input | Result |
|---|---|
| `[0x3f]` | **panic** |
| `[0x3f, 0xff]` | **panic** |
| `[0x20]` | `Err(SizeUpdateAtEnd)` |
| `[0x3e]` | `Err(SizeUpdateAtEnd)` |
| `[0x1f]` | `Err(IntegerDecodingError(NotEnoughOctets))` |

The panic is also reachable from larger, mostly well formed blocks. A decoder desync can
land on a `001xxxxx` octet near the end of the buffer and take the same path, so an input
does not have to begin with a size update to hit it.

## Root cause

`src/decoder.rs:505`, inside `update_max_dynamic_size`:

```rust
fn update_max_dynamic_size(&mut self, buf: &[u8]) -> Result<usize, DecoderError> {
    let (new_size, consumed) = decode_integer(buf, 5).ok().unwrap();
```

The function returns `Result<usize, DecoderError>`, and `decode_integer` already returns
`Result<(usize, usize), DecoderError>`, the same error type. Every other call site in the
file propagates it:

```
135:  let (len, consumed) = decode_integer(buf, 7)?;
441:  let (index, consumed) = decode_integer(buf, 7)?;
475:  let (table_index, mut consumed) = decode_integer(buf, prefix)?;
505:  let (new_size, consumed) = decode_integer(buf, 5).ok().unwrap();
```

Line 505 appears to be the only one that does not.

## Suggested fix

```diff
-        let (new_size, consumed) = decode_integer(buf, 5).ok().unwrap();
+        let (new_size, consumed) = decode_integer(buf, 5)?;
```

No conversion is needed because the error types already match.

There is a second instance of the same pattern in the test module at line 540
(`decode_integer(&[10], 5).ok().unwrap()`). That one is in a test, so it is harmless, but
it may be worth changing for consistency.

## How it was found

A property test asserting that no byte sequence can panic the decoder, run while
integrating the crate into a TLS and HTTP/2 fingerprinting tool. The tool reads header
blocks straight off a socket, so panic freedom on hostile input is a hard requirement.

The failing case was found within seconds of the property test being written, which
suggests the input space reaching it is not small.
