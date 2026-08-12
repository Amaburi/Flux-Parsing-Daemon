#!/usr/bin/env python3
"""Wrap a raw TLS record in a minimal Ethernet/IPv4/TCP pcap so tshark can dissect it.

The point is that the pcap payload is byte-identical to the .bin fixture, so any
JA4 tshark reports is computed from exactly the bytes our parser will see.
"""
import struct
import sys

def build(payload: bytes) -> bytes:
    # pcap global header: magic, v2.4, tz, sigfigs, snaplen, linktype=1 (Ethernet)
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"

    tcp = struct.pack(
        ">HHIIBBHHH",
        54321,      # sport
        443,        # dport, 443 so tshark's TLS dissector engages
        1, 1,       # seq, ack
        0x50,       # data offset 5 words, no options
        0x18,       # PSH | ACK
        65535,      # window
        0, 0,       # checksum, urgent
    )

    total_len = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total_len,
        1, 0,
        64, 6, 0,   # ttl, proto=TCP, checksum 0 (tshark dissects regardless)
        bytes([127, 0, 0, 1]),
        bytes([127, 0, 0, 2]),
    )

    frame = eth + ip + tcp + payload
    out += struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    return out


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    with open(sys.argv[2], "wb") as f:
        f.write(build(data))
    print(f"wrote {sys.argv[2]} ({len(data)} byte payload)")
