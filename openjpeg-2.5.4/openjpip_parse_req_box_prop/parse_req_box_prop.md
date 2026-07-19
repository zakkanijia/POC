# Vulnerability Report: Heap-based Buffer Overflow in OpenJPEG OpenJPIP query_parser (req-box-prop index)

## Summary

`parse_metareq()` splits the JPIP `metareq=[...]` query value into an attacker-controlled number of `;`-separated `req-box-prop` segments and calls `parse_req_box_prop(segment, idx, query_param)` once per segment, with `idx` simply counting up from 0 for every segment seen -- with no check that `idx` stays below `MAX_NUMOFBOX` (10). `parse_req_box_prop()` then writes `query_param->box_type[idx]`, `limit[idx]`, `w[idx]`, `s[idx]`, `g[idx]`, `a[idx]`, `priority[idx]` -- all fixed 10-element arrays inside the single heap block `get_initquery()` allocates for `query_param_t` (`opj_malloc(sizeof(query_param_t))`, 384 bytes in this build). Supplying enough segments drives `idx` far enough past 10 to write beyond the end of that 384-byte allocation. AddressSanitizer confirms a real heap-buffer-overflow write, with a project source frame at the vulnerable write.

## Affected Product

- **Vendor**: OpenJPEG Project
- **Product**: OpenJPEG
- **Component**: OpenJPIP
- **Source File**: `src/lib/openjpip/query_parser.c`
- **Function**: `parse_req_box_prop()`
- **Tested Version**: OpenJPEG 2.5.4
- **Tested Commit**: local baseline `5fa5bd029da7087f7862e4b50788f78a5d7d404d` (see build.txt)
- **Build Configuration**: ASan-only build of `query_parser.c` (see build.txt for why a second, UBSan-free build was needed for this specific finding)

## Vulnerability Type

- **Type**: Heap-based Buffer Overflow
- **Operation**: Out-of-Bounds Write
- **Sanitizer Result**: `AddressSanitizer: heap-buffer-overflow`

## Technical Details

- Object: `query_param_t` (`query_parser.h:47`), allocated on the heap by `get_initquery()` via `opj_malloc(sizeof(query_param_t))` (`query_parser.c:175`); `sizeof(query_param_t) == 144+... == 384` bytes in this build. It embeds `char box_type[MAX_NUMOFBOX][4]`, `int limit[MAX_NUMOFBOX]`, and four `OPJ_BOOL` arrays of the same length, all with `MAX_NUMOFBOX == 10` (`query_parser.h:38,60-66`).
- Capacity: 10 valid indices (0..9) per array; the whole struct occupies 384 bytes.
- Attacker-controlled index: `numofboxreq`, a local counter in `parse_metareq()` incremented once per `;`/trailing `req-box-prop` segment found in the client-supplied `metareq=[...]` value, passed straight through as `idx` to `parse_req_box_prop()`.
- Missing check: neither `parse_metareq()` (the caller, which owns `numofboxreq`) nor `parse_req_box_prop()` itself ever compares `idx` against `MAX_NUMOFBOX` before indexing `box_type[idx]`, `limit[idx]`, `w[idx]`, `s[idx]`, `g[idx]`, `a[idx]`, `priority[idx]`.
- First illegal access proven by ASan: `query_param->g[idx] = OPJ_TRUE;` at `query_parser.c:400`, once `idx` grows large enough (empirically, around 34-40 with this build's struct layout) to push the write past the end of the 384-byte heap allocation.

## Vulnerable Code

```c
/* src/lib/openjpip/query_parser.c */
void parse_metareq(char *field, query_param_t *query_param)
{
    char req_box_prop[20];
    char *ptr, *src;
    int numofboxreq = 0;                       /* <-- unbounded index source */
    ...
    while (*ptr != ']') {
        if (*ptr == ';') {
            ...
            parse_req_box_prop(req_box_prop, numofboxreq++, query_param);  /* <-- no idx < MAX_NUMOFBOX check */
            ...
        }
        ptr++;
    }
    ...
    parse_req_box_prop(req_box_prop, numofboxreq++, query_param);          /* <-- no idx < MAX_NUMOFBOX check */
    ...
}

void parse_req_box_prop(char *req_box_prop, int idx, query_param_t *query_param)
{
    char *ptr;

    if (*req_box_prop == '*') {
        query_param->box_type[idx][0] = '*';        /* <-- OOB once idx >= MAX_NUMOFBOX */
    } else {
        strncpy(query_param->box_type[idx], req_box_prop, 4);
    }
    ...
    } else {
        query_param->g[idx] = OPJ_TRUE;              /* query_parser.c:400 -- first ASan-proven OOB write */
        query_param->s[idx] = OPJ_TRUE;
        query_param->w[idx] = OPJ_TRUE;
    }
    ...
}
```

## Attack Surface and Reachability

```
FastCGI QUERY_STRING (opj_server, real JPIP HTTP request)
  -> parse_querystring()          [src/lib/openjpip/openjpip.c, SERVER build]
    -> parse_query()              [src/lib/openjpip/query_parser.c]
      -> parse_metareq()          [src/lib/openjpip/query_parser.c:332]
        -> parse_req_box_prop()   [src/lib/openjpip/query_parser.c:378]  <-- overflow here
           (invoked once per ';'-delimited req-box-prop segment)
```

This verification calls `parse_query()` directly from a small harness linked against a real, unmodified compilation of `query_parser.c`; `parse_query()` dispatches to `parse_metareq()` -> `parse_req_box_prop()` exactly as it would for a real "metareq=" field with many segments on the `QUERY_STRING`. No project logic was reimplemented.

Entry class: **JPIP protocol / FastCGI HTTP query**.

## Proof of Concept

### Generate the input

```bash
python3 poc.py
```

### Run

```bash
export ASAN_OPTIONS='abort_on_error=1:halt_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1'
./harness_query_direct_asanonly "$(cat query_string.txt)"
```

Note: this must be run against the ASan-only build described in `build.txt` -- the project's own recommended combined `-fsanitize=address,undefined` build instead surfaces a UBSan array-bounds finding at `idx==10` first (a logical bounds check on the `box_type[10][4]` static array type, not itself memory corruption and out of this verification's scope), masking the deeper genuine heap overflow this report documents.

## ASAN Evidence

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size 4 at 0x... thread T0
    #0 ... in parse_req_box_prop /path/to/openjpeg/src/lib/openjpip/query_parser.c:400:29
    #1 ... in parse_metareq /path/to/openjpeg/src/lib/openjpip/query_parser.c:337:13
    #2 ... in parse_query /path/to/openjpeg/src/lib/openjpip/query_parser.c:144:17
    ...
SUMMARY: AddressSanitizer: heap-buffer-overflow /path/to/openjpeg/src/lib/openjpip/query_parser.c:400:29 in parse_req_box_prop
```

Full output see `asan.txt`.

## Attachments

- `poc.py`
- `query_parser.c`
- `asan.txt`
