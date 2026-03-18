# OpenJPEG `openjpip` `query_param_t` Out-of-Bounds Write

---

## 1. Summary

- **Project/Product**: OpenJPEG
- **Affected component**: `openjpip` query parser
- **Vulnerability class**: Out-of-Bounds Write / Adjacent-Field Overwrite in a heap-allocated parser state object
- **Trigger**: Parsing a crafted JPIP query string containing an oversized `metareq=[...]` list
- **Impact**: Confirmed memory corruption of parser state. At minimum, this can cause parser state corruption and may lead to denial of service or other unsafe behavior depending on surrounding code paths. A direct object-boundary AddressSanitizer crash was not demonstrated on the standard `parse_query()` path.
- **Attack vector**: An attacker supplies a crafted JPIP query string to the OpenJPEG `openjpip` query parser.

---

## 2. Affected Versions

- **Confirmed on source tree**: commit `d33cbecc148d3affcdf403211fddc2cc5d442379`
- **Git description**: `v2.5.4-7-gd33cbecc`
- **Release mapping**: exact affected upstream release range has not yet been verified.

---

## 3. Root Cause

### 3.1 Location

- File: `src/lib/openjpip/query_parser.h`
- File: `src/lib/openjpip/query_parser.c`
- Functions:
  - `parse_query(...)`
  - `parse_metareq(...)`
  - `parse_req_box_prop(...)`

### 3.2 Root cause details

`query_param_t` contains several fixed-size arrays indexed by metadata request count:

- `box_type[MAX_NUMOFBOX][4]`
- `limit[MAX_NUMOFBOX]`
- `w[MAX_NUMOFBOX]`
- `s[MAX_NUMOFBOX]`
- `g[MAX_NUMOFBOX]`
- `a[MAX_NUMOFBOX]`
- `priority[MAX_NUMOFBOX]`

where `MAX_NUMOFBOX` is defined as `10`.

The parser accepts `metareq=[...]` entries and, for each parsed request box property, calls `parse_req_box_prop(req_box_prop, idx, query_param)` with a monotonically increasing index. However, neither `parse_metareq(...)` nor `parse_req_box_prop(...)` verifies that `idx < MAX_NUMOFBOX` before writing into the fixed arrays.

As a result, when more than 10 request boxes are supplied, writes intended for `box_type[idx]` and related per-entry fields cross the valid array bounds and overwrite adjacent fields within the same heap-allocated `query_param_t` object.

### 3.3 Concrete corruption demonstrated

A crafted query with 11 request-box entries reaches `idx == 10` on the 11th element.

Debugger evidence shows that:

- `&query_param->box_type[10] == &query_param->limit[0]`
- executing `strncpy(query_param->box_type[idx], req_box_prop, 4)` with `req_box_prop = "kkkk!"`
- changes `query_param->limit[0]` from `0x0` to `0x6b6b6b6b`

This demonstrates an actual attacker-controlled overwrite of an adjacent parser-state field.

---

## 4. Proof of Concept and Reproduction

### 4.1 PoC source

- Filename: `poc_openjpeg_query.c`
- Description: Minimal reproducer that directly invokes `parse_query()` with a crafted `metareq=[...]` string containing 11 entries.

PoC query payload:

```text
metareq=[aaaa!;bbbb!;cccc!;dddd!;eeee!;ffff!;gggg!;hhhh!;iiii!;jjjj!;kkkk!]
```

### 4.2 Reproduction approach

Build and run the uploaded PoC against the vulnerable OpenJPEG source tree with debug symbols enabled. Then use GDB to break on the 11th request-box parse:

```bash
break parse_req_box_prop if idx==10
run
```

At the breakpoint, inspect the relevant addresses and values:

```gdb
p &query_param->box_type[10]
p &query_param->limit[0]
next
p/x query_param->limit[0]
```

### 4.3 Expected result

The uploaded debugger log confirms:

- `idx == 10`
- `&query_param->box_type[10]` and `&query_param->limit[0]` are the same address
- after `strncpy(..., 4)`, `limit[0]` becomes `0x6b6b6b6b`

Representative excerpt:

```text
Breakpoint 1, parse_req_box_prop (..., idx=10, ...)
...
p &query_param->box_type[10]
$2 = ... 0x42131c
p &query_param->limit[0]
$4 = ... 0x42131c
...
p/x query_param->limit[0]
$11 = 0x0
...
next
...
p/x query_param->limit[0]
$15 = 0x6b6b6b6b
```

---

## 5. Impact Assessment

- **Minimum impact**: Parser state corruption from attacker-controlled input.
- **Security risk**: This is a real out-of-bounds write into adjacent fields of a heap-allocated parser object. Although a clean AddressSanitizer object-boundary overflow was not demonstrated on the standard `parse_query()` path, the corruption is directly observable and attacker-controlled.
- **Practical effect**: At minimum, malformed JPIP metadata requests can corrupt parser state and may cause denial of service or unsafe downstream behavior. Additional end-to-end impact testing would strengthen the assessment.

## 6. Attachments

- `poc_openjpeg_query.c` : minimal reproducer
- `gdb.txt` : debugger transcript demonstrating adjacent-field overwrite
- `query_parser.c` : affected source file
- `query_parser.h` : affected header / structure definition
