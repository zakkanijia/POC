# OpenJPEG `openjpip` Heap Buffer Overflow in `set_SIZmkrdata`

---

## 1. Summary

- **Project/Product**: OpenJPEG
- **Affected component**: `openjpip` JP2/JPIP index parser
- **Vulnerability class**: Heap Buffer Overflow
- **Trigger**: Parsing a crafted JP2/JPIP-style file through the standard entry `opj_jpip_test`, causing an out-of-bounds write in `set_SIZmkrdata()`
- **Impact**: At minimum **Denial of Service (process crash/abort)**. Because this is a heap-based out-of-bounds write on attacker-controlled input, further exploitation may be possible depending on allocator behavior and target environment, but exploitability has not been established
- **Attack vector**: An attacker supplies a crafted file; the victim opens/processes it with an OpenJPEG build that includes `openjpip`

---

## 2. Affected Version

- **Git commit**: `d33cbecc148d3affcdf403211fddc2cc5d442379`
- **Git describe**: `v2.5.4-7-gd33cbecc`
- **Confirmed vulnerable**: the above revision in the tested environment

---

## 3. Root Cause

### 3.1 Location

- File: `src/lib/openjpip/index_manager.c`
- Functions:
  - `set_SIZmkrdata(...)`
  - called from `set_mainmhixdata(...)`
  - called from `set_cidxdata(...)`
  - called from `parse_jp2file(...)`

### 3.2 Root cause details

`set_SIZmkrdata(...)` parses the SIZ marker and writes component-related values into fixed-size arrays inside `SIZmarker_param_t`:

- `Ssiz[3]`
- `XRsiz[3]`
- `YRsiz[3]`

However, the function uses the file-controlled `Csiz` value as the loop bound and continues writing component entries without enforcing that the number of components fits the fixed-size buffers.

As a result, a crafted file with a sufficiently large `Csiz` causes writes beyond the end of the destination object, ultimately producing a heap-buffer-overflow when `SIZmarker_param_t` is embedded in the heap-allocated `index_param_t` structure.

### 3.3 Trigger path

The externally reachable call chain is:

1. `opj_jpip_test <crafted_file>`
2. `main()`
3. `get_index_from_JP2file()`
4. `parse_jp2file()`
5. `set_cidxdata()`
6. `set_mainmhixdata()`
7. `set_SIZmkrdata()`

The crafted file is built so that parsing reaches the `cidx/mhix` marker-processing path and then feeds a malicious SIZ marker with an oversized `Csiz` value to `set_SIZmkrdata()`.

---

## 4. Proof of Concept and Reproduction

### 4.1 PoC files

- Base codestream: `rgba16x16.j2k`
- Crafted JP2/JPIP-style file: `siz64.jp2`
- PoC generator: `make_min_jpip_siz_poc.py`

The PoC file is parser-oriented and intentionally minimal. It is designed to drive execution through the standard `openjpip` parsing path until the vulnerable SIZ handling code is reached.

### 4.2 Reproduction steps

1. Generate a small JPEG 2000 codestream:

```bash
./build-asan/bin/opj_compress -i rgba16x16.png -o rgba16x16.j2k -n 1
```

2. Build the crafted JP2/JPIP-style file with an oversized `Csiz` value:

```bash
python3 make_min_jpip_siz_poc.py rgba16x16.j2k siz64.jp2 --csiz 64
```

3. Run the standard parser entry under ASan:

```bash
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1"
./build-asan/bin/opj_jpip_test siz64.jp2
```

### 4.3 Observed ASan result 

```text
=================================================================
ERROR: AddressSanitizer: heap-buffer-overflow on address ...
WRITE of size 1 at ...
    #0 in set_SIZmkrdata ... src/lib/openjpip/index_manager.c:667
    #1 in set_mainmhixdata ... src/lib/openjpip/index_manager.c:481
    #2 in set_cidxdata ... src/lib/openjpip/index_manager.c:368
    #3 in parse_jp2file ... src/lib/openjpip/index_manager.c:104
    #4 in get_index_from_JP2file ... src/lib/openjpip/openjpip.c:473
    #5 in main ... src/bin/jpip/opj_jpip_test.c:65

0 bytes to the right of 144-byte region [...)
allocated by thread T0 here:
    #0 in __interceptor_malloc
    #1 in opj_malloc ... src/lib/openjp2/opj_malloc.c:196
    #2 in parse_jp2file ... src/lib/openjpip/index_manager.c:102
```

This demonstrates a heap-based out-of-bounds write reachable from a crafted external file through the standard program entry.

---

## 5. Impact Assessment

- **Minimum impact**: Denial of Service (process abort/crash)
- **Security significance**: This is a heap out-of-bounds write on attacker-controlled input through a standard parsing path
- **Exploitability**: Not established in this analysis. No claim of code execution is made
- **Reliability**: The crash is reproducible with the crafted PoC in an ASan-instrumented build

---

## 6. Attachments

- `make_min_jpip_siz_poc.py` : PoC generator
- `siz64.jp2` : crafted PoC file
- `asan.txt` : ASan crash output for the heap-buffer-overflow

