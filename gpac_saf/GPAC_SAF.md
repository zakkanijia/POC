# GPAC SAF `dmx_saf` Stack Buffer Overflow in `safdmx_check_dur`

---

## 1. Summary

- **Project/Product**: GPAC
- **Affected component**: SAF demuxer filter (`dmx_saf`)
- **Vulnerability class**: **Stack-based Buffer Overflow** (out-of-bounds **write**) / missing bounds check
- **Trigger**: Parsing a crafted SAF bitstream containing **more than 1024 unique `stream_id` values** in Access Units that carry a `ts_res` field
- **Impact**: At minimum **Denial of Service (crash)**. Because this is a **stack OOB write**, memory corruption may be exploitable depending on build flags and surrounding stack layout (not demonstrated here).
- **Attack vector**: Victim opens/processes a crafted `.saf` file with GPAC or a GPAC-based application.

---

## 2. Affected Versions

- **Confirmed vulnerable**: GPAC **2.4.0

---

## 3. Root Cause

### 3.1 Location

- File: `src/filters/dmx_saf.c`
- Function: `safdmx_check_dur(...)`
- Problem: `StreamInfo si[1024]` is indexed by `nb_streams` **without bounds checking**.

### 3.2 Root cause details

`safdmx_check_dur(...)` attempts to remember per-stream `ts_res` values in a fixed-size stack array:

```c
typedef struct {
    u32 stream_id;
    u32 ts_res;
} StreamInfo;

StreamInfo si[1024];
u32 nb_streams = 0;
```

During parsing, when `ts_res` is not found yet and `au_type` is one of `(1, 2, 7)`, the function records a new entry and increments `nb_streams`. There is **no check** that `nb_streams < 1024`:

```c
 270 		au_type = gf_bs_read_int(bs, 4);
 271 		stream_id = gf_bs_read_int(bs, 12);
 272 		au_size-=2;
 273 		ts_res = 0;
 274 		for (i=0; i<nb_streams; i++) {
 275 			if (si[i].stream_id==stream_id) ts_res = si[i].ts_res;
 276 		}
 277 		if (!ts_res) {
 278 			if ((au_type==1) || (au_type==2) || (au_type==7)) {
 279 				gf_bs_read_u16(bs);
 280 				ts_res = gf_bs_read_u24(bs);
 281 				au_size -= 5;
 282 				si[nb_streams].stream_id = stream_id;
 283 				si[nb_streams].ts_res = ts_res;
 284 				nb_streams++;
 285 			}
 286 		}
 287 		if (ts_res && (au_type==4)) {
 288 			Double ts = cts;
```

An attacker can craft a SAF stream containing **1025+** distinct `stream_id` values that satisfy the `(au_type==1 || au_type==2 || au_type==7)` condition, causing `nb_streams` to reach 1024 and the write at `si[1024]` to occur (one-past-end), corrupting the stack.

---

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 PoC generator

Attachment: `gen_poc_saf_stack_oob.py`

It generates a minimal `.saf` file containing `n=1025` Access Units with distinct `stream_id`s to trigger the overflow.

### 4.2 Generate PoC

```bash
python3 gen_poc_saf_stack_oob.py
# outputs: poc_saf_stack_oob_streaminfo.saf
```

### 4.3 Reproduction command

Run with UBSan and/or ASan enabled build of GPAC:

```bash
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1 \
./bin/gcc/gpac -i poc_saf_stack_oob_streaminfo.saf inspect:deep -o null
```

### 4.4 Expected result

UBSan typically reports something like:

- `runtime error: index 1024 out of bounds for type 'StreamInfo [1024]'`
- stack trace pointing to `safdmx_check_dur` in `filters/dmx_saf.c`

(Exact output depends on your build/flags.)

---

## 5. Impact Assessment

- **Minimum impact**: Denial of Service (crash) on processing a malicious `.saf` file.
- **Security risk**: This is a **stack out-of-bounds write**, i.e., memory corruption. Exploitability is build- and environment-dependent and has not been demonstrated in this report.

---

## 6. Suggested Fix

- Add an upper bound check before writing to `si[nb_streams]`, e.g.:

  - If `nb_streams >= GF_ARRAY_LENGTH(si)`, either:
    - stop tracking new streams, or
    - return an error / mark the file as invalid.

- Consider using a dynamically sized structure (e.g., map/list) with a hard cap and proper validation.

---

## 7. Attachments

- `gen_poc_saf_stack_oob.py` : PoC generator script

