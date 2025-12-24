# GPAC GSF `gsfdmx` OOB Read via Non‑NUL “magic” Logging

---

## 1. Summary

- **Project/Product**: GPAC
- **Affected component**: GSF demuxer filter (`gsfdmx`) — `src/filters/dmx_gsf.c`
- **Vulnerability class**: Heap out-of-bounds **read** (missing NUL terminator / unbounded string read)
- **Trigger**: A crafted `.gsf` file whose “tune-in” header contains a `magic` field of length `len>0`, which is read into a heap buffer of size `len` (no NUL), then logged using `"%s"`.
- **Impact**:
  - **Denial of Service (crash)** in some builds / sanitizer builds (ASan catches the OOB read).
  - Potential **information disclosure via logs** if out-of-bounds bytes are printed before a `NUL` byte is encountered (not demonstrated here).
- **Attack vector**: Victim opens/processes a crafted `.gsf` file with GPAC / `gpac` filter graph that instantiates `gsfdmx`.

---

## 2. Affected Versions

- **Confirmed vulnerable**: GPAC **2.4.0**
- **Potentially affected**: other versions containing the same `gsfdmx` “magic” parsing/logging logic.

---

## 3. Root Cause

### 3.1 Location

- File: `src/filters/dmx_gsf.c`
- Function: `gsfdmx_tune(...)` (tune-in packet parsing)

### 3.2 Root cause details

When parsing the tune-in header, `gsfdmx` reads a variable-length `len`, allocates exactly `len` bytes, and reads `len` bytes into that buffer:

```c
len = gsfdmx_read_vlen(bs);
if (len) {
    char *magic = gf_malloc(sizeof(char)*len);
    gf_bs_read_data(bs, magic, len);
    ...
    GF_LOG(GF_LOG_INFO, GF_LOG_CONTAINER,
        ("[GSFDemux] tuning in stream, magic %s\n", magic));
    gf_free(magic);
}
```

Because `magic` is **not NUL-terminated**, the `"%s"` formatter causes `printf`-style code to read past the heap allocation until it finds a `NUL` byte, leading to a heap **out-of-bounds read**.

**Secondary issue (also an OOB read risk):**
`memcmp(ctx->magic, magic, len)` uses attacker-controlled `len`. If `len > strlen(ctx->magic)` (where `ctx->magic` comes from the filter argument), `memcmp` may read past the end of `ctx->magic`.

---

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 PoC generator

Attachment: `gen_poc_gsf_magic_oobread.py`

This script creates `poc_gsf_magic_oobread.gsf` containing a tune-in header with `magic_len=4` and `magic_bytes="ABCD"` (no NUL).

### 4.2 Generate PoC

```bash
python3 gen_poc_gsf_magic_oobread.py
# outputs: poc_gsf_magic_oobread.gsf
```

### 4.3 Reproduction command

```bash
# Ensure gsfdmx checks the magic and reaches the log line:
gpac -i poc_gsf_magic_oobread.gsf:gsfdmx:magic=ABCD inspect:deep
```

> Note: An ASan build is recommended to reliably detect the heap OOB read.

---

## 5. Impact Assessment

- **Minimum impact**: DoS (crash) for some builds / with sanitizers.
- **Potential info leak**: Out-of-bounds bytes may be read and printed as part of the logged “magic” string until a NUL byte is encountered. This depends on allocator behavior and logging output availability and is not demonstrated here.

Because this is an **OOB read** (not a write), this issue is primarily stability / potential information disclosure, rather than direct memory corruption.

---

## 6. Suggested Fix

- Allocate `len+1` bytes and NUL-terminate:

  - `magic = gf_malloc(len + 1);`
  - `gf_bs_read_data(bs, magic, len);`
  - `magic[len] = 0;`

- Or, avoid `"%s"` entirely and log with an explicit length:

  - `GF_LOG(..., ("... magic %.*s\n", len, magic));`

- Harden the comparison:
  - Compare lengths first (e.g., require `len == strlen(ctx->magic)`), then `memcmp` with the validated length.

---

## 7. Attachments

- `dmx_gsf.c` : affected code (context for magic parsing and logging)
- `gen_poc_gsf_magic_oobread.py` : PoC generator script

