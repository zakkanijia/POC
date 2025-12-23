# GPAC VobSub `dmx_vobsub` Heap Out-of-Bounds Read

---

## 1. Summary

- **Project/Product**: GPAC
- **Affected component**: VobSub demuxer filter (`vobsubdmx`) / VobSub bitstream parsing (`media_tools/vobsub.c`)
- **Vulnerability class**: Heap-based Buffer Overflow (**Out-of-Bounds Read**)
- **Trigger**: Parsing a crafted VobSub `.idx` + `.sub` pair (or a single `.idx` that causes GPAC to open the matching `.sub`) where the attacker controls the `psize` / `dsize` fields in the `.sub` PES header
- **Impact**: At minimum **Denial of Service (crash)** when processing a malicious subtitle file. Because this is an OOB **read**, it is primarily a stability issue; potential information disclosure depends on how the read value is later exposed (not demonstrated here).
- **Attack vector**: An attacker supplies a crafted VobSub subtitle package; the victim opens/processes it with GPAC or a GPAC-based application.

---

## 2. Affected Versions

- **Confirmed vulnerable**: GPAC **2.4.0**

---

## 3. Root Cause

### 3.1 Location

- File: `src/filters/dmx_vobsub.c`
  - Function: `vobsubdmx_send_stream(...)`
  - Code path: reads `psize` and `dsize` from `.sub` chunk and forwards them to the duration parser

- File: `src/media_tools/vobsub.c`
  - Function: `vobsub_get_subpic_duration(...)`
  - Crashing access: **line ~492** in GPAC 2.4.0 build (per ASan trace)

### 3.2 Root cause details (missing bounds check on attacker-controlled `dsize`)

In `vobsubdmx_send_stream`, the demuxer reads two 16-bit values from the `.sub` data stream:

```c
psize = (buf[buf[0x16] + 0x18] << 8) + buf[buf[0x16] + 0x19];
dsize = (buf[buf[0x16] + 0x1a] << 8) + buf[buf[0x16] + 0x1b];
...
dst_pck = gf_filter_pck_new_alloc(pid, psize, &packet);
...
if (vobsub_get_subpic_duration(packet, psize, dsize, &duration) != GF_OK) { ... }
```

`psize` controls the allocation size of `packet`. `dsize` is attacker-controlled and is **not validated** against `psize` before calling `vobsub_get_subpic_duration(...)`.

With a crafted file where `dsize >= psize - 1`, `vobsub_get_subpic_duration(...)` performs a read that goes past the end of the heap buffer (e.g., reading a 16-bit value from `packet[dsize]` and `packet[dsize+1]`), producing an **out-of-bounds read**.

The provided PoC sets:

- `psize = 0x20` (32 bytes)
- `dsize = 0x1F` (31 bytes)

which results in a one-byte OOB read at `packet[0x20]` (exactly one past the allocated region).

---

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 PoC files

- `poc_vobsub.idx`
- `poc_vobsub.sub`

These can be generated using the attached script `gpac_idx.py` (see below).

### 4.2 Generate PoC

```bash
python3 gpac_idx.py --out poc_vobsub --psize 0x20 --dsize 0x1f
# produces: poc_vobsub.idx  poc_vobsub.sub
```

### 4.3 Reproduction command

Run with an AddressSanitizer-enabled GPAC build:

```bash
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1 \
UBSAN_OPTIONS=halt_on_error=1 \
./bin/gcc/gpac -i poc_vobsub.idx inspect:deep
```

### 4.4 Expected result (key excerpt)

ASan reports a heap-buffer-overflow **READ** and points to `vobsub_get_subpic_duration`:

```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 1
#0 ... in vobsub_get_subpic_duration media_tools/vobsub.c:492
#1 ... in vobsubdmx_send_stream filters/dmx_vobsub.c:338
...
0 bytes after 32-byte region [.., ..)
allocated by ... gf_filter_pck_new_alloc ... filters/dmx_vobsub.c:316
```

---

## 5. Impact Assessment

- **Minimum impact**: Denial of Service (crash) when opening/processing crafted VobSub subtitles.
- **Security risk**: This issue is an **out-of-bounds read** (not a write). The primary demonstrated impact is a crash. Whether it can be turned into an information disclosure depends on additional program behavior and is not demonstrated in this report.

---

## 6. Attachments

- `asan.txt` : ASan output showing the crash and stack trace
- `gpac_idx.py` : PoC generator (creates `poc_vobsub.idx` + `poc_vobsub.sub`)

