# Vulnerability Report: Heap-based Buffer Overflow in GPAC GHI Demuxer

## Summary
GPAC contains a heap-based buffer overflow vulnerability in the GHI demuxer filter (`filters/dmx_ghi.c`). The vulnerability exists in the `ghi_dmx_declare_opid_bin` function when parsing property lists of type `GF_PROP_VEC2I_LIST`. The application calculates memory allocation size based on a single 32-bit integer (`sizeof(u32)`), but subsequently writes two 32-bit integers (`x` and `y`) for each item, causing a heap out-of-bounds write. This can lead to a denial of service (application crash) or potential code execution.

## Affected Product
- **Vendor**: GPAC
- **Product**: GPAC / Multimedia Framework
- **Component**: `ghidmx` filter 
- **Source File**: `filters/dmx_ghi.c`
- **Function**: `ghi_dmx_declare_opid_bin`
- **Affected Version**: GPAC 2.4.0 

## Vulnerability Type
- **Type**: Heap-based Buffer Overflow (Out-of-Bounds Write)

## Technical Details (Root Cause Analysis)
The vulnerability is located in the function `ghi_dmx_declare_opid_bin` in `filters/dmx_ghi.c`. This function is responsible for parsing properties from a binary GHI file.

When handling the property type `GF_PROP_VEC2I_LIST` (Vector 2 Integer List), the code reads the number of items (`nb_items`) and allocates memory.

**Vulnerable Code Snippet (`filters/dmx_ghi.c`):**

```c
case GF_PROP_VEC2I_LIST:
    p.value.v2i_list.nb_items = gf_bs_read_u32(bs);
    // [VULNERABILITY] Allocation size is calculated using sizeof(u32) (4 bytes)
    p.value.v2i_list.vals = gf_malloc(sizeof(u32) * p.value.string_list.nb_items);
    
    for (pidx=0; pidx<p.value.v2i_list.nb_items; pidx++) {
        // Writes the first 4 bytes (x) - fits in allocation if nb_items=1
        p.value.v2i_list.vals[pidx].x = gf_bs_read_u32(bs);
        // [OVERFLOW] Writes the next 4 bytes (y) - overflows the buffer
        p.value.v2i_list.vals[pidx].y = gf_bs_read_u32(bs);
    }
    break;
```

**Analysis:**

1. **Allocation**: The code allocates `nb_items * 4` bytes (`sizeof(u32)`).
2. **Write Operation**: The loop iterates `nb_items` times. In each iteration, it writes a `GF_Vec2i` structure, which consists of two `u32` integers (`x` and `y`), totaling 8 bytes.
3. **Result**: For every item in the list, 4 bytes are written out of bounds. If `nb_items` is 1, the code allocates 4 bytes but writes 8 bytes, corrupting the heap metadata or adjacent data.

## Proof of Concept (PoC)

### 1. PoC Generation Script (`poc.py`)

Run the following Python script to generate a malicious GHI file (`poc_ghi_vec2i_list_heap_overflow.ghi`).

### 2. Reproduction Steps

```
./bin/gcc/gpac -i poc_ghi_vec2i_list_heap_overflow.ghi:sn=1 inspect:full
```

## Crash Evidence (ASAN Log)

AddressSanitizer confirms a **Write of size 4** happening immediately after a **4-byte region**, which confirms the 4-byte overflow (8 bytes written into a 4-byte buffer).

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000003494 at pc 0x7fe2c0733e51 bp 0x7ffcdd153e40 sp 0x7ffcdd153e30
WRITE of size 4 at 0x602000003494 thread T0
    #0 0x7fe2c0733e50 in ghi_dmx_declare_opid_bin filters/dmx_ghi.c:609
    #1 0x7fe2c073d321 in ghi_dmx_init filters/dmx_ghi.c:1048
    #2 0x7fe2c073ec03 in ghi_dmx_process filters/dmx_ghi.c:1113
    ...
0x602000003494 is located 0 bytes after 4-byte region [0x602000003490,0x602000003494)
allocated by thread T0 here:
    #0 0x7fe2c68defdf in __interceptor_malloc ...
    #1 0x7fe2be80de6c in gf_malloc utils/alloc.c:150
    #2 0x7fe2c0733c3a in ghi_dmx_declare_opid_bin filters/dmx_ghi.c:606
```

## Attachments

- asan.txt : Asan report
- poc.py