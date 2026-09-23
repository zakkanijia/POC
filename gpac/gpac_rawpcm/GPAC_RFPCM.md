# GPAC `rfpcm` Reverse Playback Stack Buffer Overflow

---

## 1. Summary

- **Project/Product**: GPAC
- **Affected component**: PCM reframer filter `rfpcm` (`src/filters/reframe_rawpcm.c`)
- **Vulnerability class**: **Stack-based Buffer Overflow** (out-of-bounds **write**) via unchecked `memcpy`
- **Trigger**: Processing a crafted **WAVE (.wav)** file with a **large channel count** such that `bytes_per_sample = channels * (bits_per_sample/8) > 100` **while reverse playback is enabled** (negative playback speed).
- **Impact**: At minimum **Denial of Service (crash)**. Because this is a **stack OOB write**, memory corruption may be exploitable depending on build flags and stack layout (not demonstrated here).
- **Attack vector**: Victim opens/plays a crafted `.wav` in a GPAC-based application that supports reverse playback (or runs `gpac` with negative playback speed).

---

## 2. Affected Versions

- **Confirmed vulnerable (code audit)**: GPAC **2.4.0**
- **Potentially affected**: other versions containing the same `rfpcm` reverse-swap logic.

> Note: The `asan.txt` attached in this conversation corresponds to a different test case (VobSub) and is **not** the ASan output for this issue.

---

## 3. Root Cause

### 3.1 Location

- File: `src/filters/reframe_rawpcm.c`
- Function: `pcmreframe_flush_packet(GF_PCMReframeCtx *ctx)`
- Code region: reverse playback sample swapping loop

### 3.2 Root cause details (fixed-size stack buffer used for variable-sized sample)

When `ctx->reverse_play` is enabled, `pcmreframe_flush_packet` reverses samples in-place:

- It computes `nb_bytes_in_sample = ctx->Bps * ctx->ch`.
- It uses a fixed-size stack buffer `char store[100];` as a swap temporary.
- It copies `nb_bytes_in_sample` bytes into `store` without checking whether `nb_bytes_in_sample <= sizeof(store)`.

`ctx->ch` (channel count) and `ctx->Bps` (bytes-per-sample, derived from WAV bit depth) are controlled by the WAV header.  
For example, `channels=64` and `bits_per_sample=16` give `nb_bytes_in_sample = 64 * 2 = 128 > 100`, causing a **stack buffer overflow**.

Reverse playback is enabled when `evt->play.speed < 0` in `pcmreframe_process_event(...)`.

---

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 PoC generator

Attachment: `poc_rfpcm_reverse_stack_overflow.py`

Generates `poc_rfpcm_reverse_stack_overflow.wav` with:

- `channels=64`
- `bits_per_sample=16`
- `bytes_per_sample(all channels)=128 (>100)`

### 4.2 Generate PoC

```bash
python3 poc_rfpcm_reverse_stack_overflow.py
```

### 4.3 Reproduction command (recommended)

Run with an ASan-enabled `gpac` build and force reverse playback by setting negative speed:

```bash
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1 \
./bin/gcc/gpac -speed=-1 -i poc_rfpcm_reverse_stack_overflow.wav:rfpcm -o null
```

---

## 5. Impact Assessment

- **Minimum impact**: DoS (crash) when reverse playback is requested on a crafted `.wav`.
- **Security risk**: **Stack out-of-bounds write** (memory corruption). Exploitability is build- and environment-dependent and not demonstrated here.

---

## 6. Suggested Fix

- Replace `char store[100];` with a buffer sized to `nb_bytes_in_sample` (heap or dynamically sized stack buffer), or at minimum guard `nb_bytes_in_sample <= sizeof(store)` before copying.

---

## 7. Attachments

- `reframe_rawpcm.c` : vulnerable `rfpcm` code
- `poc_rfpcm_reverse_stack_overflow.py` : runnable PoC generator

