# GPAC AVI `indx` SuperIndex Heap Buffer Overflow

## Summary
GPAC contains a heap-based buffer overflow in its AVI (OpenDML) demuxer while parsing the `indx` (SuperIndex) chunk. A crafted AVI file can trigger an out-of-bounds heap write in `avi_parse_input_file()` (in `media_tools/avilib.c`), leading to a crash and potentially exploitable memory corruption.

## Affected Product
- **Project**: GPAC
- **Component**: AVI demuxer (`avidmx`) / AVILIB (`media_tools/avilib.c`)
- **Known affected version**: GPAC **2.4.0**
- **Build configuration used to reproduce**: `--enable-avi --enable-sanitizer --enable-debug`

> Note: Additional versions may be affected, but this report confirms reproducibility on 2.4.0.

## Vulnerability Type
- **Heap-based Buffer Overflow (Out-of-Bounds Write)**
- CWE suggestion: **CWE-122 (Heap-based Buffer Overflow)**

## Attack Vector / Trigger
An attacker can craft an AVI file containing an OpenDML `indx` SuperIndex chunk with a small/invalid `wLongsPerEntry` (e.g., `2`) and at least one entry. GPAC allocates a buffer sized using `wLongsPerEntry * nEntriesInUse`, but then writes fixed-size SuperIndex entries (16 bytes each), causing heap out-of-bounds writes.

Typical scenario:
- User opens/inspects a malicious `.avi` file using `gpac` (or any application that uses GPAC’s AVI demuxer).

## Technical Details (Root Cause)
During OpenDML `indx` SuperIndex parsing in `avi_parse_input_file()`:
- The code allocates storage based on `wLongsPerEntry * nEntriesInUse * sizeof(u32)`.
- The parser then writes a fixed-size structure per entry (16 bytes: `qwOffset` + `dwSize` + `dwDuration`), which corresponds to 4 DWORDs, regardless of `wLongsPerEntry`.
- If `wLongsPerEntry < 4`, the allocation is too small and the subsequent writes go out of bounds.

This is a **library parsing bug** (not an API misuse), reachable via standard AVI demuxing.

## Impact
- **Denial of Service**: reliable crash.
- **Memory corruption**: heap overwrite suggests potential for code execution depending on allocator/layout and downstream use, though exploitation was not attempted here.

## Proof of Concept (PoC)

### PoC generator (Python)
Save as `gpac_avi.py` and run it to generate `poc_avi_indx_wLongsPerEntry_2.avi`.


### Build steps (reproducer’s environment)
```bash
CC=/usr/bin/gcc-12 CXX=/usr/bin/g++-12 ./configure --enable-sanitizer --enable-debug --enable-avi --sdl-cfg=/bin/false
make -j"$(nproc)"
```

### Reproduction command
```bash
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1 \
UBSAN_OPTIONS=halt_on_error=1 \
./bin/gcc/gpac -no-dynf -no-probe \
  -i poc_avi_indx_wLongsPerEntry_2.avi:ext=avi avidmx inspect:deep=true
```

## Crash Evidence (ASAN)
AddressSanitizer reports a heap-buffer-overflow (write) in `avi_parse_input_file()`:

- Write site: `media_tools/avilib.c:2204`
- Allocation site: `media_tools/avilib.c:2198`

Example excerpt:
- `ERROR: AddressSanitizer: heap-buffer-overflow`
- `WRITE of size 4 ... in avi_parse_input_file media_tools/avilib.c:2204`
- `allocated by thread T0 ... in avi_parse_input_file media_tools/avilib.c:2198`

## Suggested Fix / Mitigations
- Validate `wLongsPerEntry` for SuperIndex entries:
  - For OpenDML SuperIndex, entries are 16 bytes (4 DWORDs). Reject files where `wLongsPerEntry != 4` (or at least `< 4`).
- Add bounds checks ensuring the `indx` chunk has enough remaining bytes for `nEntriesInUse * 16`.
- Allocate using the real entry structure size (`nEntriesInUse * sizeof(entry)`), not `wLongsPerEntry`.

## Discoverer / Credits
- Discoverer: zakka

## Attachments
- asan.txt : Asan output
- gpac_avi.py : poc

