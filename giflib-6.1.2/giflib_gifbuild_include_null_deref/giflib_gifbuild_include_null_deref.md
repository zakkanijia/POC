# giflib `gifbuild` include-handling NULL Pointer Dereference

---

## 1. Summary

- **Project/Product**: giflib
- **Affected component**: `gifbuild` utility / include-handling path in `Icon2Gif(...)`
- **Vulnerability class**: NULL Pointer Dereference
- **Trigger**: Processing a crafted `gifbuild` text input that defines a global color map and then uses the `include` directive on a GIF file that does not have a global color map (`SColorMap == NULL`)
- **Impact**: At minimum **Denial of Service (crash)**. I have confirmed a NULL pointer dereference with ASan/UBSan, but I have not demonstrated code execution.
- **Attack vector**: An attacker supplies a crafted `gifbuild` text input together with a referenced GIF file that contains only local image color maps and no global screen color map. When the victim runs `gifbuild` on the crafted input, the include-handling logic calls `GifUnionColorMap(...)` with a NULL second argument and crashes.

---

## 2. Affected Versions

- **Confirmed vulnerable**: giflib **6.1.2**
- **Affected scope**: confirmed in the `gifbuild` utility path
- **Other versions**: may also be affected if they retain the same include-handling logic without validating `Inclusion->SColorMap`

---

## 3. Root Cause

### 3.1 Location

- File: `gifbuild.c`
- Function: `Icon2Gif(...)`
- File: `gifalloc.c`
- Function: `GifUnionColorMap(...)`

### 3.2 Root cause details

In `gifbuild.c`, when the input text uses the `include` directive, `Icon2Gif(...)` opens the referenced GIF and, if the current output object already has a global color map, performs color-map merging by calling:

```c
UnionMap = GifUnionColorMap(
    GifFileOut->SColorMap, Inclusion->SColorMap, Translation);
```

However, there is no check that `Inclusion->SColorMap` is non-NULL before this call.

This is reachable with a GIF file that has no global screen color map and instead uses only local image color maps. In that case, `Inclusion->SColorMap == NULL`, but the merge path is still taken if `GifFileOut->SColorMap != NULL`.

`GifUnionColorMap(...)` dereferences its input color-map pointers unconditionally, which leads to a NULL pointer dereference and crash.

### 3.3 Why the supplied repro triggers it

The supplied repro uses a crafted `gifbuild` text input that creates a global color map for the output object and then includes a GIF file such as `local_only.gif` whose screen/global color map is NULL.

As a result:

1. `GifFileOut->SColorMap` is non-NULL,
2. `Inclusion->SColorMap` is NULL,
3. `Icon2Gif(...)` still calls `GifUnionColorMap(GifFileOut->SColorMap, Inclusion->SColorMap, Translation)`,
4. `GifUnionColorMap(...)` dereferences a NULL color-map pointer and crashes.

---

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 Reproduction command

Run with ASan/UBSan-enabled builds:

```bash
ASAN_OPTIONS=detect_leaks=0 ./gifbuild < repro_gifbuild_local_only.txt > /dev/null
```

### 4.2 Expected result (key excerpt)

The supplied crash output shows UBSan/ASan reporting a NULL pointer dereference:

```text
gifalloc.c:125:6: runtime error: member access within null pointer of type 'const ColorMapObject'
gifalloc.c:125:6: runtime error: load of null pointer of type 'const int'
AddressSanitizer:DEADLYSIGNAL
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
#0 ... in GifUnionColorMap /home/dell/data/giflib-6.1.2/gifalloc.c:125:6
#1 ... in Icon2Gif /home/dell/data/giflib-6.1.2/gifbuild.c:327:16
#2 ... in main /home/dell/data/giflib-6.1.2/gifbuild.c:77:4
```

This confirms that the bug is reachable from the `gifbuild` include-handling path and results in a NULL-pointer read crash.

---

## 5. Impact Assessment

- **Minimum impact**: Denial of Service (process crash) when `gifbuild` processes attacker-controlled input
- **Security relevance**: This is a real, externally triggerable NULL pointer dereference in a file-processing utility
- **Exploitability**: The current evidence supports a crash / denial-of-service claim. I have not demonstrated code execution.

---

## 6. Attachments

- `asan.txt`: crash output
- `gifbuild.c`: include-handling source
- `gifalloc.c`: `GifUnionColorMap(...)` source
- crafted `repro_gifbuild_local_only.txt`
- referenced `local_only.gif`

---
