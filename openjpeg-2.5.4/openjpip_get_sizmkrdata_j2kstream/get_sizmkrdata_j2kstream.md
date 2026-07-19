# Vulnerability Report: Stack-based Buffer Overflow in OpenJPEG OpenJPIP j2kheader_manager (SIZ Csiz)

## Summary

`get_SIZmkrdata_from_j2kstream()` parses the SIZ marker segment of a raw J2K codestream and reads the number-of-components field `Csiz` directly as an unvalidated, attacker-controlled 2-byte big-endian value (range 0-65535). It then loops `Csiz` times writing per-component bytes into `SIZ.Ssiz[i]`/`SIZ.XRsiz[i]`/`SIZ.YRsiz[i]`, three fixed 3-element arrays in the stack-local `SIZmarker_param_t SIZ` this function returns by value. Any `Csiz > 3` overflows all three arrays. AddressSanitizer confirms a real stack-buffer-overflow write with a project source frame at the exact vulnerable write.

## Affected Product

- **Vendor**: OpenJPEG Project
- **Product**: OpenJPEG
- **Component**: OpenJPIP
- **Source File**: `src/lib/openjpip/j2kheader_manager.c`
- **Function**: `get_SIZmkrdata_from_j2kstream()`
- **Tested Version**: OpenJPEG 2.5.4
- **Tested Commit**: local baseline `5fa5bd029da7087f7862e4b50788f78a5d7d404d` (see build.txt)
- **Build Configuration**: ASan-only build of `j2kheader_manager.c` (see build.txt for why a second, UBSan-free build was needed for this specific finding)

## Vulnerability Type

- **Type**: Stack-based Buffer Overflow
- **Operation**: Out-of-Bounds Write
- **Sanitizer Result**: `AddressSanitizer: stack-buffer-overflow`

## Technical Details

- Object: `SIZmarker_param_t SIZ` (`index_manager.h:55-72`), a stack-local variable in `get_SIZmkrdata_from_j2kstream()`, declaring `Byte_t Ssiz[3]; Byte_t XRsiz[3]; Byte_t YRsiz[3];` (`index_manager.h:69-71`).
- Capacity: 3 valid indices (0..2) per array.
- Attacker-controlled length: `SIZ.Csiz = big2(SIZstream + 36);` (`j2kheader_manager.c:104`) reads the `Csiz` field straight from the raw, caller-supplied J2K codestream bytes with no range check anywhere before it is used as a loop bound.
- Missing check: the `for` loop immediately after reading `Csiz` (`j2kheader_manager.c:109`) iterates `i` from `0` to `Csiz-1` with no comparison against the arrays' fixed capacity of 3.
- First illegal access: `SIZ.Ssiz[i] = *(SIZstream + (38 + i * 3));` at `j2kheader_manager.c:110` is logically the first out-of-bounds write once `i >= 3`; AddressSanitizer (in the ASan-only build used to get past a UBSan array-bounds trap at the same point, see build.txt) proves genuine stack memory corruption at the third array's write, `SIZ.YRsiz[i] = *(SIZstream + (40 + i * 3));`, `j2kheader_manager.c:112`.

## Vulnerable Code

```c
/* src/lib/openjpip/j2kheader_manager.c */
SIZmarker_param_t get_SIZmkrdata_from_j2kstream(Byte_t *SIZstream)
{
    SIZmarker_param_t SIZ;
    int i;

    if (*SIZstream++ != 0xff || *SIZstream++ != 0x51) { ... }

    SIZ.Lsiz   = big2(SIZstream);
    ...
    SIZ.Csiz   = big2(SIZstream + 36);     /* <-- attacker-controlled, unvalidated, 0-65535 */

    SIZ.XTnum  = (SIZ.Xsiz - SIZ.XTOsiz + SIZ.XTsiz - 1) / SIZ.XTsiz;
    SIZ.YTnum  = (SIZ.Ysiz - SIZ.YTOsiz + SIZ.YTsiz - 1) / SIZ.YTsiz;

    for (i = 0; i < (int)SIZ.Csiz; i++) {  /* <-- no check against Ssiz/XRsiz/YRsiz[3] capacity */
        SIZ.Ssiz[i]  = *(SIZstream + (38 + i * 3));
        SIZ.XRsiz[i] = *(SIZstream + (39 + i * 3));
        SIZ.YRsiz[i] = *(SIZstream + (40 + i * 3));   /* j2kheader_manager.c:112 -- ASan-proven OOB write */
    }

    return SIZ;
}
```

```c
/* src/lib/openjpip/index_manager.h */
typedef struct SIZmarker_param {
    ...
    Byte2_t Csiz;              /**< number of the components in the image*/
    Byte_t  Ssiz[3];           /**< precision (depth) in bits and sign of the component samples*/
    Byte_t  XRsiz[3];          /**< horizontal separation of a sample of component with respect to the reference grid*/
    Byte_t  YRsiz[3];          /**< vertical separation of a sample of component with respect to the reference grid*/
} SIZmarker_param_t;
```

## Attack Surface and Reachability

```
Target's raw J2K codestream bytes (malicious JP2/J2K/JPX file)
  -> get_mainheader_from_j2kstream()   [src/lib/openjpip/j2kheader_manager.c:52, exported]
    -> get_SIZmkrdata_from_j2kstream() [src/lib/openjpip/j2kheader_manager.c:82]  <-- overflow here
       (real callers: src/lib/openjpip/jp2k_encoder.c, jpipstream_manager.c,
        building JPT-stream/JPP-stream responses from a target codestream)
```

This verification calls the real, unmodified, non-static exported entry point `get_mainheader_from_j2kstream(j2kstream, &SIZ, NULL)` from a small harness linked against a real compilation of `j2kheader_manager.c`; this is exactly the function `jp2k_encoder.c`/`jpipstream_manager.c` call internally when constructing a JPIP stream response for a served target. `COD=NULL` isolates the SIZ-marker path under test; no project logic was reimplemented.

Entry class: **JP2/J2K/JPX file** (a malicious target codestream reachable through OpenJPIP's JPT-stream/JPP-stream response construction).

## Proof of Concept

### Generate the input

```bash
python3 poc.py            # writes mal_siz.bin, Csiz=50
```

### Run

```bash
export ASAN_OPTIONS='abort_on_error=1:halt_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1'
./harness_j2kheader_asanonly mal_siz.bin
```

Note: this must be run against the ASan-only build described in `build.txt` -- the project's own recommended combined `-fsanitize=address,undefined` build instead surfaces a UBSan runtime array-bounds finding at `i==3` first, masking the deeper genuine stack overflow this report documents.

## ASAN Evidence

```
==PID==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...
WRITE of size 1 at 0x... thread T0
    #0 ... in get_SIZmkrdata_from_j2kstream /path/to/openjpeg/src/lib/openjpip/j2kheader_manager.c:112:22
    #1 ... in get_mainheader_from_j2kstream /path/to/openjpeg/src/lib/openjpip/j2kheader_manager.c:61:16
    #2 ... in main /path/to/harness/harness_j2kheader.c:47:10

Address 0x... is located in stack of thread T0 at offset 88 in frame
    #0 ... in get_mainheader_from_j2kstream /path/to/openjpeg/src/lib/openjpip/j2kheader_manager.c:54
    [32, 88) 'tmp' (line 61) <== Memory access at offset 88 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow /path/to/openjpeg/src/lib/openjpip/j2kheader_manager.c:112:22 in get_SIZmkrdata_from_j2kstream
```

Full output see `asan.txt`.

## Attachments

- `poc.py`
- `j2kheader_manager.c`
- `asan.txt`
