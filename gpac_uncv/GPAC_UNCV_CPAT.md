# GPAC UNCV `cpat` Heap Out-of-Bounds Write

---

## 1. Summary

- **Project/Product**: GPAC
- **Affected component**: UNCV decoder filter (`uncvdec`)
- **Vulnerability class**: Heap-based Buffer Overflow (Out-of-Bounds Write)
- **Trigger**: Parsing the UNCV decoder configuration `cpat` box from a crafted media file (MP4/ISOBMFF)
- **Impact**: At minimum **Denial of Service (crash)**. Because this is a heap memory corruption (OOB write), further exploitation may be possible depending on allocator/heap layout and subsequent code paths.
- **Attack vector**: An attacker supplies a crafted media file; the victim opens/processes it with GPAC or a GPAC-based application.

---

## 2. Affected Versions

- **Confirmed vulnerable**: GPAC **2.4.0**

---

## 3. Root Cause

### 3.1 Location

- File: `src/filters/dec_uncv.c`
- Function: `uncv_parse_config(...)`
- Branch: parsing the `cpat` (component pattern) box in UNCV decoder configuration

### 3.2 Root cause details (incorrect 2D indexing stride)

In the `cpat` parsing logic, the code allocates `fa_map` for a `fa_width * fa_height` grid:

- `uncv->fa_map = gf_malloc(sizeof(u16) * uncv->fa_width * uncv->fa_height);`

However, when writing into the array, the index computation uses `i * fa_height` (**incorrect**) instead of `i * fa_width`:

- **Buggy**: `uncv->fa_map[j + i*uncv->fa_height] = ...;`
- **Correct**: `uncv->fa_map[j + i*uncv->fa_width] = ...;`

When `fa_height > fa_width` (and `fa_height > 1`), the computed index can exceed the allocated range, causing a **heap out-of-bounds write** (the target is a `u16` element).

---

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 PoC file

- Filename: `poc_uncv_cpat_oobwrite.mp4`
- Description: Minimal MP4 containing UNCV decoder configuration with a `cpat` box crafted such that `fa_width=1` and `fa_height=2`, triggering the OOB write during parsing.
- Delivery: Attach this file to the report / upload it to the CVE submission portal.

### 4.2 Reproduction command

Run with an AddressSanitizer-enabled GPAC build (example):

```bash
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1 \
UBSAN_OPTIONS=halt_on_error=1 \
./bin/gcc/gpac -i poc_uncv_cpat_oobwrite.mp4 uncvdec inspect:deep
```

### 4.3 Expected result (key excerpt)

ASan should report a heap-buffer-overflow (WRITE of size 2) and point into `uncv_parse_config`:

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 2
#0 ... in uncv_parse_config filters/dec_uncv.c:402
...
allocated by ... gf_malloc ... uncv_parse_config filters/dec_uncv.c:394
```

---

## 5. Impact Assessment

- **Minimum impact**: Denial of Service (process crash) when opening/processing a crafted media file.
- **Security risk**: This is a **heap OOB write** with attacker-influenced data (written as `u16`, derived from file input). Depending on heap layout and subsequent allocations/uses, memory corruption could potentially be exploitable. A full exploitability assessment is outside the scope of this report.

---

## 6. Attachments

- asan.txt : asan output
- gpc_uncv.py : poc

