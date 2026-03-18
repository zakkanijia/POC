# OpenJPEG `openjpip` `cidx` Error-Path Double Free

## 1. Summary

- **Project/Product**: OpenJPEG
- **Affected component**: `openjpip` JP2/JPIP index parser
- **Vulnerability class**: Double Free
- **Trigger**: Parsing a crafted JP2/JPIP-style file through the standard entry `opj_jpip_test`, specifically a malformed `cidx/manf` layout that passes initial parsing but omits required boxes such as `tpix`
- **Impact**: At minimum **Denial of Service (process abort/crash)**. Because this is a double-free on heap memory, further exploitation may be possible depending on allocator behavior, heap layout, and subsequent code paths, but exploitability has not been established
- **Attack vector**: An attacker supplies a crafted file; the victim opens/processes it with an OpenJPEG build that includes `openjpip`

## 2. Affected Version Information

- **Git commit tested**: `d33cbecc148d3affcdf403211fddc2cc5d442379`
- **Git describe**: `v2.5.4-7-gd33cbecc`
- **Confirmed vulnerable**: yes, in the above source revision
- **Version mapping**: the tested revision is based on the `v2.5.4` tag with additional commits; exact downstream package mapping should be confirmed before disclosure

## 3. Root Cause

### 3.1 Location

- File: `src/lib/openjpip/index_manager.c`
- Functions:
  - `parse_jp2file(...)`
  - `set_cidxdata(...)`

### 3.2 Root cause details

The bug is an **ownership mismatch** on the heap object `jp2idx` (type `index_param_t`).

`parse_jp2file(...)` allocates `jp2idx` and calls `set_cidxdata(cidx, jp2idx)`.
If `set_cidxdata(...)` fails, `parse_jp2file(...)` frees `jp2idx` and returns failure.

However, `set_cidxdata(...)` also frees the same caller-owned `jp2idx` object on several error paths, including the path where required boxes are missing from the `manf` box, such as:

- `mhix`
- `tpix`
- `thix`
- `ppix`

The vulnerable sequence is therefore:

1. `parse_jp2file(...)` allocates `jp2idx`
2. `parse_jp2file(...)` calls `set_cidxdata(...)`
3. `set_cidxdata(...)` detects malformed `cidx/manf` contents, e.g. missing `tpix`
4. `set_cidxdata(...)` frees `jp2idx` and returns `OPJ_FALSE`
5. `parse_jp2file(...)` receives failure and frees `jp2idx` again

This results in a **double-free** of the same heap allocation.

### 3.3 Why the PoC triggers this path

The PoC file is intentionally constructed so that:

- top-level parsing succeeds far enough to reach `cidx`
- `set_cidxdata(...)` is entered
- `manf` is present
- required sub-boxes such as `tpix` are missing

As observed during reproduction, the program prints:

```text
Error: Boxheader tpix not found
Error: tpix box not present in manfbox
Error: Not correctl format in cidx box
```

After this, the double-free occurs.

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 PoC files

- Filename: `siz4.jp2`
- Description: Crafted JP2/JPIP-style parser-oriented file that reaches `set_cidxdata(...)` but intentionally omits `tpix` in the `manf` structure, triggering the error-path double-free
- Supporting generator: `make_min_jpip_siz_poc.py`

### 4.2 Reproduction command

Run with an AddressSanitizer-enabled OpenJPEG build:

```bash
python3 make_min_jpip_siz_poc.py rgba16x16.j2k siz4.jp2 --csiz 4

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1"
./build-asan/bin/opj_jpip_test siz4.jp2
```

### 4.3 Expected result (key excerpt)

The program first reports malformed `cidx` / missing `tpix`, then ASan reports a double-free:

```text
Error: Boxheader tpix not found
Error: tpix box not present in manfbox
Error: Not correctl format in cidx box
=================================================================
ERROR: AddressSanitizer: attempting double-free
...
#0 in free
#1 in opj_free ... src/lib/openjp2/opj_malloc.c:248
#2 in parse_jp2file ... src/lib/openjpip/index_manager.c:106
...
freed by thread T0 here:
...
#2 in set_cidxdata ... src/lib/openjpip/index_manager.c
...
previously allocated by thread T0 here:
...
#2 in parse_jp2file ... src/lib/openjpip/index_manager.c:102
```

## 5. Impact Assessment

- **Minimum impact**: Denial of Service (process abort/crash) when parsing a crafted file
- **Security risk**: This is a **double-free of heap memory** reachable from an external file through a standard parser entry. Depending on allocator behavior and surrounding code paths, double-free conditions can sometimes be exploitable. No claim of practical code execution is made here
- **Reliability**: In the tested environment, the crash is reliably detected by AddressSanitizer

## 6. Attachments

- `asan.txt`: ASan crash output for the double-free
- `make_min_jpip_siz_poc.py`: PoC generator
- `siz4.jp2`: generated PoC file

