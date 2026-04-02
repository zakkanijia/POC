# giflib `gifclrmp` image-selection NULL Pointer Dereference

---

## 1. Summary

- **Project/Product**: giflib
- **Affected component**: `gifclrmp`
- **Vulnerability class**: NULL Pointer Dereference
- **Trigger**: Processing a crafted GIF file with no global screen color map while using the `-i` option to select an image for color-map modification
- **Impact**: At minimum **Denial of Service (crash)**. I have confirmed a NULL pointer dereference with ASan/UBSan, but I have not demonstrated code execution.
- **Attack vector**: An attacker supplies a crafted GIF file such as `local_only.gif` that lacks a global screen color map. When the victim runs `gifclrmp -i 1` on that file, the selected-image path calls `ModifyColorMap(...)` with `GifFileIn->SColorMap == NULL` and crashes.

---

## 2. Affected Versions

- **Confirmed vulnerable**: giflib **6.1.2**
- **Affected scope**: confirmed in the `gifclrmp` utility path
- **Other versions**: may also be affected if they retain the same selected-image modification logic without checking for a NULL screen color map

---

## 3. Root Cause

### 3.1 Location

- File: `gifclrmp.c`
- Function: `main(...)`
- File: `gifclrmp.c`
- Function: `ModifyColorMap(...)`

### 3.2 Root cause details

In `gifclrmp.c`, the default non-`-i` path checks whether `GifFileIn->SColorMap` exists before modifying it:

```c
if (!ImageNFlag) {
    if (!GifFileIn->SColorMap) {
        GIF_EXIT("No colormap to modify");
    }
    GifFileIn->SColorMap = ModifyColorMap(GifFileIn->SColorMap);
}
```

However, when the user specifies `-i` and the selected image is reached, the code does:

```c
if ((++ImageNum == ImageN) && ImageNFlag) {
    GifFileIn->SColorMap = ModifyColorMap(GifFileIn->SColorMap);
}
```

There is no NULL check in this path. As a result, if the input GIF has no global screen color map (`GifFileIn->SColorMap == NULL`), `ModifyColorMap(...)` is called with a NULL pointer.

`ModifyColorMap(...)` dereferences `ColorMap` immediately, for example by reading `ColorMap->ColorCount`, which causes a NULL pointer dereference and crash.

### 3.3 Why the supplied repro triggers it

The supplied repro uses:

```bash
./gifclrmp -i 1 local_only.gif > /dev/null
```

where `local_only.gif` lacks a global screen color map.

As a result:

1. the initial non-`-i` NULL-check path is skipped,
2. the first image record satisfies `(++ImageNum == ImageN) && ImageNFlag`,
3. `ModifyColorMap(GifFileIn->SColorMap)` is called with `GifFileIn->SColorMap == NULL`,
4. `ModifyColorMap(...)` dereferences the NULL pointer and crashes.

---

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 Reproduction command

Run with ASan/UBSan-enabled builds:

```bash
ASAN_OPTIONS=detect_leaks=0 ./gifclrmp -i 1 local_only.gif > /dev/null
```

### 4.2 Expected result (key excerpt)

The supplied crash output shows UBSan/ASan reporting a NULL pointer dereference:

```text
gifclrmp.c:324:29: runtime error: member access within null pointer of type 'ColorMapObject'
gifclrmp.c:324:29: runtime error: load of null pointer of type 'int'
AddressSanitizer:DEADLYSIGNAL
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
#0 ... in ModifyColorMap /home/dell/data/giflib-6.1.2/gifclrmp.c:324:29
#1 ... in main /home/dell/data/giflib-6.1.2/gifclrmp.c:164:9
```

This confirms that the selected-image path reaches `ModifyColorMap(...)` with a NULL color-map pointer and crashes.

---

## 5. Impact Assessment

- **Minimum impact**: Denial of Service (process crash) when `gifclrmp` processes attacker-controlled input
- **Security relevance**: This is a real, externally triggerable NULL pointer dereference in a file-processing utility
- **Exploitability**: The current evidence supports a crash / denial-of-service claim. I have not demonstrated code execution.

---

## 6. Attachments

- `asan.txt`: crash output
- `gifclrmp.c`: vulnerable source
- crafted `local_only.gif`

---
