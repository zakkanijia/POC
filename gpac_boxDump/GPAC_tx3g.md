# GPAC Timed Text (`tx3g`) UTF-16 Stack Buffer Overflow in `dump_ttxt_sample`

---

## 1. Summary

- **Project/Product**: GPAC
- **Affected component**: ISO Media dump / Timed Text XML export (`MP4Box -ttxt`), `isomedia/box_dump.c`
- **Vulnerability class**: **Stack-based Buffer Overflow** (out-of-bounds **write**) via unchecked `memcpy`
- **Trigger**: A crafted MP4 with a `tx3g` timed-text sample whose **text length** field is large and whose payload starts with a **UTF-16 BE BOM** (`0xFE 0xFF`)
- **Impact**: At minimum **Denial of Service (crash)**. Because this is a **stack OOB write**, memory corruption may be exploitable depending on build flags and stack layout (not demonstrated here).
- **Attack vector**: Victim runs `MP4Box -ttxt` (or any GPAC code path that dumps timed text tracks) on a crafted MP4 file.

---

## 2. Affected Versions

- **Confirmed vulnerable**: GPAC **2.4.0** (ASan crash reproduced)
- **Potentially affected**: other versions that contain the same `dump_ttxt_sample` logic

---

## 3. Root Cause

### 3.1 Location

- File: `src/isomedia/box_dump.c`
- Function: `dump_ttxt_sample(...)`
- Crashing line (GPAC 2.4.0 build): **`box_dump.c:3605`**

### 3.2 Root cause details

`dump_ttxt_sample(...)` allocates a fixed-size UTF-16 buffer on the stack:

- `unsigned short utf16Line[10000];`  → **20,000 bytes**

When the sample text begins with a UTF-16 BE BOM, the code performs:

- `memcpy((char*)utf16Line, s_txt->text + 2, s_txt->len);`

The attacker controls `s_txt->len` via the `tx3g` sample’s 16-bit length field.  
If `s_txt->len > sizeof(utf16Line)` (i.e., **> 20000 bytes**), the `memcpy` writes past the end of `utf16Line`, corrupting the stack.

This is a classic missing bounds check / length mismatch (it also appears to copy `len` bytes starting at `text+2`, i.e., it should likely copy `len-2` and cap it).

---

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 PoC generator

Attachment: `poc_tx3g_utf16_stack_overflow.py`

It generates a minimal MP4 containing a `tx3g` sample with:

- `text_len = 30000`
- payload starts with `0xFE 0xFF`

### 4.2 Generate PoC

```bash
python3 poc_tx3g_utf16_stack_overflow.py
# outputs: poc_tx3g_utf16_stack_overflow.mp4
```

### 4.3 Reproduction command

Run with an AddressSanitizer-enabled GPAC build:

```bash
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1 ./bin/gcc/MP4Box -ttxt 1 poc_tx3g_utf16_stack_overflow.mp4
```

### 4.4 Expected result (key excerpt)

ASan reports a **stack-buffer-overflow** with a write originating from `memcpy`:

- `WRITE of size 30000`
- `dump_ttxt_sample isomedia/box_dump.c:3605`

Full ASan output is provided in `asan.txt`.

---

## 5. Impact Assessment

- **Minimum impact**: Denial of Service (crash) when processing a malicious MP4 timed-text track.
- **Security risk**: This is a **stack out-of-bounds write** (memory corruption). Exploitability is build- and environment-dependent and is not demonstrated in this report.

---

## 6. Suggested Fix

- Before `memcpy`, validate the copy length against the stack buffer size, accounting for BOM and terminator(s), e.g.:

  - `copy_len = min(s_txt->len - 2, sizeof(utf16Line) - 2)` (bytes)
  - reject/return error if `s_txt->len` is unreasonably large for this path

- Consider using a dynamically allocated buffer sized from validated input.

---

## 7. Attachments

- `asan.txt` : ASan output showing the stack-buffer-overflow and stack trace
- `box_dump.c` : vulnerable code context (`dump_ttxt_sample`)
- `poc_tx3g_utf16_stack_overflow.py` : PoC generator script

