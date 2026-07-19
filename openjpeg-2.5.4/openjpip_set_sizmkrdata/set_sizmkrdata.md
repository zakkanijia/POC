# Vulnerability Report: Heap-based Buffer Overflow in OpenJPEG OpenJPIP index_manager (SIZ Csiz)

## Summary

`set_SIZmkrdata()` populates the SIZ-marker fields of a target's JPIP code index from a `.mhix` marker-index-table box entry, reading `Csiz` (number of image components) directly as an unvalidated, attacker-controlled 2-byte big-endian value out of the referenced codestream bytes. It then loops `Csiz` times writing per-component bytes into `SIZ->Ssiz[i]`, `SIZ->XRsiz[i]`, `SIZ->YRsiz[i]` -- three fixed 3-element arrays that live inside the caller's heap-allocated `index_param_t` (via `&(jp2idx->SIZ)`, `jp2idx = opj_malloc(sizeof(index_param_t))`). Any `Csiz` large enough to push the write past the end of that heap allocation (empirically, `Csiz` greater than roughly 66 in this build) corrupts heap memory beyond the allocated object. AddressSanitizer confirms a real heap-buffer-overflow write with a project source frame at the exact vulnerable write. This is the same root cause as `get_SIZmkrdata_from_j2kstream()` (see `openjpip_get_sizmkrdata_j2kstream/`), manifesting here on the heap-allocated JPIP-index code path instead of the stack-allocated raw-codestream path.

## Affected Product

- **Vendor**: OpenJPEG Project
- **Product**: OpenJPEG
- **Component**: OpenJPIP
- **Source File**: `src/lib/openjpip/index_manager.c`
- **Function**: `set_SIZmkrdata()`
- **Tested Version**: OpenJPEG 2.5.4
- **Tested Commit**: local baseline `5fa5bd029da7087f7862e4b50788f78a5d7d404d` (see build.txt)
- **Build Configuration**: ASan-only build of the `openjpip` library (see build.txt for why a second, UBSan-free build was needed for this specific finding)

## Vulnerability Type

- **Type**: Heap-based Buffer Overflow
- **Operation**: Out-of-Bounds Write
- **Sanitizer Result**: `AddressSanitizer: heap-buffer-overflow`

## Technical Details

- Object: `index_param_t` (`index_manager.h:86-98`), heap-allocated by `parse_jp2file()` via `opj_malloc(sizeof(index_param_t))` (`index_manager.c:102`); `sizeof(index_param_t) == 144` bytes in this build, with the embedded `SIZmarker_param_t SIZ` field's `Ssiz[3]` array starting at byte offset 78.
- Capacity: 3 valid indices (0..2) per array; 144 bytes total for the enclosing heap allocation.
- Attacker-controlled length: `SIZ->Csiz = fetch_marker2bytebigendian(sizmkr, 36);` (`index_manager.c:659`) reads `Csiz` from codestream bytes located via a `.mhix` (Header Index Table) box marker-index entry, with no range check before it drives the write loop. The one check present, `if (sizmkidx->length != SIZ->Lsiz)` (`index_manager.c:644`), only compares two attacker-controlled fields against each other and can be made to pass trivially by keeping them consistent; it does not bound `Csiz`.
- Missing check: the `for` loop after reading `Csiz` (`index_manager.c:664`) iterates `i` from `0` to `Csiz-1` with no comparison against `Ssiz`/`XRsiz`/`YRsiz`'s fixed capacity of 3, nor against the enclosing `index_param_t` allocation's size.
- First illegal access proven by ASan: `SIZ->YRsiz[i] = fetch_marker1byte(sizmkr, 40 + i * 3);` at `index_manager.c:667`, once `i` grows large enough (empirically, `Csiz > ~66` with this build's struct layout) to push the write past the end of the 144-byte heap allocation.

## Vulnerable Code

```c
/* src/lib/openjpip/index_manager.c */
OPJ_BOOL set_SIZmkrdata(markeridx_param_t *sizmkidx,
                        codestream_param_t codestream, SIZmarker_param_t *SIZ)
{
    marker_param_t sizmkr;
    int i;

    sizmkr = set_marker(codestream, sizmkidx->code, sizmkidx->offset, sizmkidx->length);

    SIZ->Lsiz = fetch_marker2bytebigendian(sizmkr, 0);
    if (sizmkidx->length != SIZ->Lsiz) { ... return OPJ_FALSE; }   /* does not bound Csiz */

    ...
    SIZ->Csiz   = fetch_marker2bytebigendian(sizmkr, 36);          /* <-- attacker-controlled, unvalidated */

    SIZ->XTnum  = ...
    SIZ->YTnum  = ...

    for (i = 0; i < (int)SIZ->Csiz; i++) {                         /* <-- no check against Ssiz/XRsiz/YRsiz[3] capacity */
        SIZ->Ssiz[i]  = fetch_marker1byte(sizmkr, 38 + i * 3);
        SIZ->XRsiz[i] = fetch_marker1byte(sizmkr, 39 + i * 3);
        SIZ->YRsiz[i] = fetch_marker1byte(sizmkr, 40 + i * 3);     /* index_manager.c:667 -- ASan-proven OOB write */
    }
    return OPJ_TRUE;
}
```

Real call site (`SIZ` heap-placed exactly as reproduced by this PoC's harness):

```c
/* src/lib/openjpip/index_manager.c */
OPJ_BOOL set_mainmhixdata(box_param_t *cidx_box, codestream_param_t codestream,
                          index_param_t *jp2idx)
{
    ...
    sizmkidx = search_markeridx(0xff51, mhix);
    set_SIZmkrdata(sizmkidx, codestream, &(jp2idx->SIZ));   /* jp2idx = opj_malloc(sizeof(index_param_t)) */
    ...
}
```

## Attack Surface and Reachability

```
Malicious JP2/JPX file with a crafted cidx/mhix index box
  -> get_index_from_JP2file()   [src/lib/openjpip/openjpip.c:448, exported]
    -> parse_jp2file()          [src/lib/openjpip/index_manager.c:73]
      -> set_cidxdata()         [src/lib/openjpip/index_manager.c:348]
        -> set_mainmhixdata()   [src/lib/openjpip/index_manager.c:462]
          -> set_SIZmkrdata()   [src/lib/openjpip/index_manager.c:633]  <-- overflow here
```

This verification calls the real, non-static, exported entry point `set_SIZmkrdata()` directly from a small harness linked against a real compilation of `index_manager.c`, passing a hand-constructed `markeridx_param_t`/`codestream_param_t` -- exactly the shape `set_mainmhixdata()` builds after it locates the SIZ marker's index entry inside a real `.mhix` box (that upstream cidx/manf/mhix box-parsing layer does not touch the vulnerable write path, so skipping it does not alter or reimplement the bug). The harness places `SIZ` on the heap via `opj_malloc(sizeof(index_param_t))`, matching `parse_jp2file()`'s real allocation exactly, so the heap-vs-stack ASan classification is faithful to the real call chain.

Entry class: **JP2/JPX file** (a malicious target file with a crafted JPIP index, reachable through OpenJPIP's `get_index_from_JP2file()` entry point).

## Proof of Concept

### Generate the input

```bash
python3 poc.py            # writes siz_marker_body.bin, Csiz=100
```

### Run

```bash
export ASAN_OPTIONS='abort_on_error=1:halt_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1'
export LD_LIBRARY_PATH=/path/to/openjpeg/build-asanonly/bin
./harness_setsizmkr_asanonly siz_marker_body.bin
```

Note: this must be run against the ASan-only build described in `build.txt` -- the project's own recommended combined `-fsanitize=address,undefined` build instead surfaces a UBSan runtime array-bounds finding at `i==3` first, masking the deeper genuine heap overflow this report documents. It also requires `Csiz` large enough (here, 100) to actually cross the enclosing 144-byte heap allocation's boundary -- a smaller `Csiz` (e.g. just above 3) only corrupts adjacent struct fields within the same allocation and is not detected by ASan.

## ASAN Evidence

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size 1 at 0x... thread T0
    #0 ... in set_SIZmkrdata /path/to/openjpeg/src/lib/openjpip/index_manager.c:667:23
allocated by thread T0 here:
    ...
SUMMARY: AddressSanitizer: heap-buffer-overflow /path/to/openjpeg/src/lib/openjpip/index_manager.c:667:23 in set_SIZmkrdata
```

Full output see `asan.txt`.

## Attachments

- `poc.py`

- `index_manager.c`

- `asan.txt`

  
