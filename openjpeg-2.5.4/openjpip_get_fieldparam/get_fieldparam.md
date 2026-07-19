# Vulnerability Report: Stack-based Buffer Overflow in OpenJPEG OpenJPIP query_parser

## Summary

`get_fieldparam()` in the OpenJPIP JPIP-query parser splits a `fieldname=fieldval&...` style string (the FastCGI `QUERY_STRING` a JPIP client sends to `opj_server`) into a field name and a field value using `strchr()` to find the `=` and `&` delimiters, then copies each piece with `strncpy()` into caller-supplied fixed-size stack buffers (`char fieldname[10]`, `char fieldval[128]` in `parse_query()`) using the delimiter-derived length directly, with no check against the destination buffers' actual capacity. A field name longer than 9 characters, or a field value longer than 127 characters, overflows the corresponding stack buffer. AddressSanitizer confirms a real stack-buffer-overflow write with a project source frame at the exact vulnerable `strncpy()` call.

## Affected Product

- **Vendor**: OpenJPEG Project
- **Product**: OpenJPEG
- **Component**: OpenJPIP
- **Source File**: `src/lib/openjpip/query_parser.c`
- **Function**: `get_fieldparam()`
- **Tested Version**: OpenJPEG 2.5.4
- **Tested Commit**: local baseline `5fa5bd029da7087f7862e4b50788f78a5d7d404d` (see build.txt)
- **Build Configuration**: `-DBUILD_JPIP=ON -DBUILD_JPIP_SERVER=ON`, `-fsanitize=address,undefined`

## Vulnerability Type

- **Type**: Stack-based Buffer Overflow
- **Operation**: Out-of-Bounds Write
- **Sanitizer Result**: `AddressSanitizer: stack-buffer-overflow`

## Details

- Object: `char fieldname[MAX_LENOFFIELDNAME]` where `MAX_LENOFFIELDNAME` is `10` (`query_parser.c:83`), a local stack buffer in `parse_query()` (`query_parser.c:92`).
- Attacker-controlled length: `eqp - stringptr`, the number of bytes in the client-supplied query string before the first `=` character. 
- Missing check: `get_fieldparam()` computes the copy length purely from delimiter positions and never compares it to the destination buffers' declared sizes before calling `strncpy()`.
- First illegal access: the `strncpy(fieldname, stringptr, (size_t)(eqp - stringptr))` call at `query_parser.c:229` writes past the end of `fieldname[10]` as soon as the field-name portion of the query string exceeds 9 characters.
- The sibling field-value copy, `strncpy(fieldval, eqp + 1, (size_t)(andp - eqp - 1))` at `query_parser.c:232`, has the identical unbounded-length pattern against `fieldval[128]`; a value longer than 127 characters overflows it the same way (not exercised by this PoC, which keeps the value short to isolate the field-name bug).

## Vulnerable Code

```c
/* src/lib/openjpip/query_parser.c */

/** maximum length of field name*/
#define MAX_LENOFFIELDNAME 10

/** maximum length of field value*/
#define MAX_LENOFFIELDVAL 128

query_param_t * parse_query(const char *query_string)
{
    query_param_t *query_param;
    const char *pquery;
    char fieldname[MAX_LENOFFIELDNAME], fieldval[MAX_LENOFFIELDVAL];
    ...
    while (pquery != NULL) {
        pquery = get_fieldparam(pquery, fieldname, fieldval);
        ...
    }
    ...
}

char * get_fieldparam(const char *stringptr, char *fieldname, char *fieldval)
{
    char *eqp, *andp, *nexfieldptr;

    if ((eqp = strchr(stringptr, '=')) == NULL) { ... return NULL; }
    if ((andp = strchr(stringptr, '&')) == NULL) {
        andp = strchr(stringptr, '\0');
        nexfieldptr = NULL;
    } else {
        nexfieldptr = andp + 1;
    }

    assert((size_t)(eqp - stringptr));
    strncpy(fieldname, stringptr, (size_t)(eqp - stringptr));   /* <-- no bound vs sizeof(fieldname) */
    fieldname[eqp - stringptr] = '\0';
    assert(andp - eqp - 1 >= 0);
    strncpy(fieldval, eqp + 1, (size_t)(andp - eqp - 1));       /* <-- no bound vs sizeof(fieldval) */
    fieldval[andp - eqp - 1] = '\0';

    return nexfieldptr;
}
```

## Proof of Concept

```bash
python3 poc.py
```

```bash
export ASAN_OPTIONS='abort_on_error=1:halt_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1'
export LD_LIBRARY_PATH=/path/to/openjpeg/build-asan/bin
./harness_query "$(cat query_string.txt)"
```

## ASAN Evidence

AddressSanitizer reports a `WRITE of size 20` into a `char[10]` ('fieldname')
stack object, with the crashing frame inside `get_fieldparam()` at
`query_parser.c:229`, called from the real `parse_query()` at
`query_parser.c:100`:

```
==PID==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...
WRITE of size 20 at 0x... thread T0
    #0 ... in __interceptor_strncpy
    #1 ... in get_fieldparam /path/to/openjpeg/src/lib/openjpip/query_parser.c:229:5
    #2 ... in parse_query /path/to/openjpeg/src/lib/openjpip/query_parser.c:100:18
    #3 ... in main /path/to/harness/harness_query.c:28:9

Address 0x... is located in stack of thread T0 at offset 42 in frame
    #0 ... in parse_query /path/to/openjpeg/src/lib/openjpip/query_parser.c:89

  This frame has 2 object(s):
    [32, 42) 'fieldname' (line 92) <== Memory access at offset 42 overflows this variable
    [64, 192) 'fieldval' (line 92)
SUMMARY: AddressSanitizer: stack-buffer-overflow ... in __interceptor_strncpy
```

Full output see `asan.txt`.

## Root Cause

`get_fieldparam()` derives the number of bytes to copy purely from the
positions of `=`/`&` delimiters in attacker-controlled input and never
clamps that length against the compile-time capacity of the caller's
`fieldname`/`fieldval` buffers before calling `strncpy()`.

## Attachments

- `poc.py`
- `query_parser.c`
- `asan.txt`
