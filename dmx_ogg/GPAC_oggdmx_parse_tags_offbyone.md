# GPAC OGG Demuxer Off-by-One Read/Write in `oggdmx_parse_tags`

- **Project:** GPAC
- **Component:** OGG demuxer filter (`src/filters/dmx_ogg.c`)
- **Function:** `oggdmx_parse_tags(...)`
- **Issue type:** Off-by-one **out-of-bounds read** (1 byte) + **out-of-bounds write** (1 byte)
- **Tested version:** gpac-2.4.0 (local build, clang-17 + ASan/UBSan)
- **Reporter:** zakka
- **Date:** 2025-12-19

## Summary

`oggdmx_parse_tags()` reads a 32-bit length (`t_size`) from attacker-controlled OGG/OpusTags metadata and checks only:

```c
if (size < t_size) return;
```

It then performs:

```c
sep = data[t_size];
data[t_size] = 0;
...
data[t_size] = sep;
```

When `size == t_size`, the access `data[t_size]` becomes `data[size]`, which is **one byte past the valid buffer range** (`data[0..size-1]`), producing a **1-byte OOB read** and a **1-byte OOB write** (off-by-one). The write is transient (written to `0`, then restored).

## Root Cause

The code assumes `t_size` is a valid index into the `data` buffer, but the boundary check allows equality.

- **Expected safety condition before reading/writing `data[t_size]`:** `t_size < size`
- **Implemented check:** `size < t_size` (missing equality case)

## Impact / Severity Notes

- The OOB is **exactly 1 byte**.
- The write is **transient** (`FF/BE -> 00 -> FF/BE` conceptually), which often prevents straightforward exploitation.
- Practical impact can still include **undefined behavior** and potential **crashes** depending on buffer layout and allocator behavior.
- In many builds, ASan may *not* report because the access can land inside the same underlying allocation (intra-buffer overflow), but the OOB is still real relative to the function's `size` contract.

## Reproduction

### 1) Build (clang-17 + ASan/UBSan)

Use the provided build script `build_a.sh` (paths assume gpac-2.4.0 under `~/Desktop/g2fuzz_eval/`):

```bash
bash ./build_a.sh
```

Key properties of the build script:
- toolchain: `clang-17`, `llvm-ar-17`, `llvm-ranlib-17`
- sanitizers: `-fsanitize=address,undefined`
- exports `CFLAGS/CXXFLAGS/LDFLAGS/LIBS` for consistent compile+link flags
- copies `libclang_rt.asan-x86_64.so` into `bin/gcc/` for runtime resolution

### 2) Generate PoC OGG

Use the provided PoC generator `poc_offbyone.py`:

```bash
python3 poc_offbyone.py
# -> writes poc_offbyone.ogg
```

This creates a minimal OGG with:
- `OpusHead`
- `OpusTags` with a single user comment `ARTIST=A`

### 3) Run GPAC

```bash
./bin/gcc/gpac -i poc_offbyone.ogg -o null
```

ASan may not crash (intra-buffer off-by-one), so we use GDB proof below.

## GDB Proof (Deterministic)

Goal: show that at the moment `size == t_size`, the program writes to `data[size]` (one past the end), flipping that byte to `0x00`.

### Breakpoints

```gdb
b filters/dmx_ogg.c:667   # sep = data[t_size];
b filters/dmx_ogg.c:668   # data[t_size] = 0;
b filters/dmx_ogg.c:699   # data[t_size] = sep;
run
```

### Observed evidence (example transcript)

At `sep = data[t_size]`:

- `size=8`, `t_size=8`  -> `t_size == size` (off-by-one condition)
- dump around end shows the byte at `data+size`:

```text
x/16bx data+size-8
0x...55227: 41 52 54 49 53 54 3d 41
0x...5522f: be be be be be be be be
```

At `data[t_size] = 0;` **after executing the instruction**:

```text
x/16bx data+size-8
0x...55227: 41 52 54 49 53 54 3d 41
0x...5522f: 00 be be be be be be be
```

This proves a write occurred to `data[size]` (one byte past the declared buffer length of 8).

> Note: to see the "restore" take effect, step over line 699 and re-dump the memory.

## Proposed Fix

Change the boundary check to disallow equality before touching `data[t_size]`:

```diff
- if (size < t_size) return;
+ if (size <= t_size) return;
```

(or equivalently ensure `t_size < size` before accessing `data[t_size]`).

## Attachments

- `build_a.sh` (build script)

- `poc_offbyone.py` (PoC generator)

- `gdb.txt`

   

