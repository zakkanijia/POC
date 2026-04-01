#!/usr/bin/env python3
from pathlib import Path
import sys

def make_multiframe_gif(path: str, frames: int) -> None:
    if frames <= 0:
        raise ValueError("frames must be > 0")

    out = bytearray()

    # Header
    out += b"GIF89a"

    # Logical Screen Descriptor: width=1, height=1
    out += (1).to_bytes(2, "little")
    out += (1).to_bytes(2, "little")

    # Packed:
    # bit7   : global color table flag = 1
    # bit6-4 : color resolution = 0
    # bit3   : sort flag = 0
    # bit2-0 : GCT size code = 0 -> 2 entries
    out += bytes([0x80])

    # Background color index, pixel aspect ratio
    out += b"\x00\x00"

    # Global Color Table: 2 colors
    # index 0 = black, index 1 = white
    out += b"\x00\x00\x00\xff\xff\xff"

    # 每一帧都放一个最小的 1x1 图像
    for _ in range(frames):
        # Image Descriptor
        out += b"\x2c"                  # image separator
        out += b"\x00\x00"              # left
        out += b"\x00\x00"              # top
        out += b"\x01\x00"              # width = 1
        out += b"\x01\x00"              # height = 1
        out += b"\x00"                  # no local color table

        # Image Data
        # LZW minimum code size = 2
        # one data sub-block of size 2: 4c 01
        # then block terminator 00
        out += b"\x02\x02\x4c\x01\x00"

    # Trailer
    out += b"\x3b"

    Path(path).write_bytes(out)

def main() -> int:
    out_path = sys.argv[1] if len(sys.argv) > 1 else "giftool_2049_frames.gif"
    frames = int(sys.argv[2]) if len(sys.argv) > 2 else 2049
    make_multiframe_gif(out_path, frames)
    print(f"[+] wrote {out_path} with {frames} frames")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())