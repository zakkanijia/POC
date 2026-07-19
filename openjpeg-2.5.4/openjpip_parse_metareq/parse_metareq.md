# Vulnerability Report: Stack-based Buffer Overflow in OpenJPEG OpenJPIP query_parser (metareq)

## Summary

`parse_metareq()` parses the JPIP `metareq` query field, whose value has the form `[req-box-prop;req-box-prop;...]R<n>D<n>`. Each `;`/`]`-delimited `req-box-prop` segment is copied with `strncpy()` into a fixed 20-byte stack buffer (`char req_box_prop[20]`) using the segment's raw length (distance between delimiters in attacker-controlled input) with no bound against the buffer's declared capacity. A single segment longer than 19 characters overflows it. AddressSanitizer confirms a real stack-buffer-overflow write with a project source frame at the exact vulnerable `strncpy()` call.

## Affected Product

- **Vendor**: OpenJPEG Project
- **Product**: OpenJPEG
- **Component**: OpenJPIP
- **Source File**: `src/lib/openjpip/query_parser.c`
- **Function**: `parse_metareq()`
- **Tested Version**: OpenJPEG 2.5.4
- **Tested Commit**: local baseline `5fa5bd029da7087f7862e4b50788f78a5d7d404d` (see build.txt)
- **Build Configuration**: `-DBUILD_JPIP=ON -DBUILD_JPIP_SERVER=ON`, `-fsanitize=address,undefined`

## Vulnerability Type

- **Type**: Stack-based Buffer Overflow
- **Operation**: Out-of-Bounds Write
- **Sanitizer Result**: `AddressSanitizer: stack-buffer-overflow`

## Technical Details

- Object: `char req_box_prop[20]`, a local stack buffer in `parse_metareq()` (`query_parser.c:334`).
- Capacity: 20 bytes.
- Attacker-controlled length: `ptr - src`, the number of bytes between successive `;`/`]` delimiters inside the `metareq=[...]` value.
- Missing check: neither of the two `strncpy()` call sites in `parse_metareq()` (one inside the segment-splitting loop, one for the trailing segment after the loop) compares the segment length to `sizeof(req_box_prop)` before copying.
- First illegal access: `strncpy(req_box_prop, src, (size_t)(ptr - src))` at `query_parser.c:345` (loop body) or the equivalent trailing-segment copy at `query_parser.c:356`, whichever fires first for a given input; this PoC's single, over-length segment triggers the trailing-segment copy at line 345.

## Vulnerable Code

```c
/* src/lib/openjpip/query_parser.c */
void parse_metareq(char *field, query_param_t *query_param)
{
    char req_box_prop[20];
    char *ptr, *src;
    int numofboxreq = 0;

    memset(req_box_prop, 0, 20);

    /* req-box-prop*/
    ptr = strchr(field, '[');
    ptr++;
    src = ptr;
    while (*ptr != ']') {
        if (*ptr == ';') {
            assert(ptr - src >= 0);
            strncpy(req_box_prop, src, (size_t)(ptr - src));   /* <-- no bound vs sizeof(req_box_prop) */
            parse_req_box_prop(req_box_prop, numofboxreq++, query_param);
            ptr++;
            src = ptr;
            memset(req_box_prop, 0, 20);
        }
        ptr++;
    }
    assert(ptr - src >= 0);
    strncpy(req_box_prop, src, (size_t)(ptr - src));           /* <-- no bound vs sizeof(req_box_prop) */

    parse_req_box_prop(req_box_prop, numofboxreq++, query_param);
    ...
}
```

## Attack Surface and Reachability

```
FastCGI QUERY_STRING (opj_server, real JPIP HTTP request)
  -> parse_querystring()          [src/lib/openjpip/openjpip.c, SERVER build]
    -> parse_query()              [src/lib/openjpip/query_parser.c]
      -> parse_metareq()          [src/lib/openjpip/query_parser.c:332]  <-- overflow here
         (invoked when the query string contains a "metareq=" field)
```

This verification calls `parse_query()` directly from a small harness linked against the real, unmodified `libopenjpip.so`; `parse_query()` dispatches to `parse_metareq()` exactly as it would for a real "metareq=" field on the `QUERY_STRING`. No project source was modified or reimplemented.

Entry class: **JPIP protocol / FastCGI HTTP query**.

## Proof of Concept

### Generate the input

```bash
python3 poc.py
```

### Run

```bash
export ASAN_OPTIONS='abort_on_error=1:halt_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1'
export LD_LIBRARY_PATH=/path/to/openjpeg/build-asan/bin
./harness_query "$(cat query_string.txt)"
```

## ASAN Evidence

```
==PID==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...
WRITE of size 21 at 0x... thread T0
    #0 ... in __interceptor_strncpy
    #1 ... in parse_metareq /path/to/openjpeg/src/lib/openjpip/query_parser.c:345:5
    #2 ... in parse_query /path/to/openjpeg/src/lib/openjpip/query_parser.c:144:17
    ...
SUMMARY: AddressSanitizer: stack-buffer-overflow ... in __interceptor_strncpy
```

Full output see `asan.txt`.

## Attachments

- `poc.py`
- `query_parser.c`
- `asan.txt`
