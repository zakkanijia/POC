# libsndfile CAF `caf_read_strings` negative-size-param

---

## 1. Summary

- **Project/Product**: libsndfile
- **Affected component**: CAF parser (`caf_read_header` / `caf_read_strings`) as reached through `sndfile-info`
- **Vulnerability class**: Integer truncation leading to invalid length passed to memory operation (`negative-size-param` / denial of service)
- **Trigger**: Parsing a crafted CAF file with an oversized `info` chunk string area whose length exceeds `INT_MAX`
- **Impact**: At minimum **Denial of Service (crash)**. The current proof demonstrates a crash in `memset` caused by a negative size derived from attacker-controlled chunk length. I have not demonstrated reliable code execution.
- **Attack vector**: An attacker supplies a crafted CAF file. When the victim opens or inspects it with a libsndfile-based program such as `sndfile-info`, the parser reaches `caf_read_strings(...)` and triggers the bug.

---

## 2. Affected Versions

- **Confirmed vulnerable**: the tested `libsndfile` snapshot used in the supplied ASan output
- **Affected scope**: confirmed in the CAF parsing path
- **Other versions**: may also be affected if they retain the same `caf_read_strings(...)` -> `psf_binheader_readf("...b", ..., size_t)` logic together with `int count` in the `b` read-format handler

---

## 3. Root Cause

### 3.1 Location

- File: `src/caf.c`
- Function: `caf_read_strings(...)`
- File: `src/common.c`
- Function: `psf_binheader_readf(...)`
- Relevant path: `caf_read_header(...)` -> `caf_read_strings(...)` -> `psf_binheader_readf(...)`

### 3.2 Root cause details

In `caf_read_header(...)`, the parser accepts an `info` chunk if its size is at least 4 and not larger than the remaining file length:

```c
case info_MARKER :
    if (chunk_size < 4)
        return SFE_MALFORMED_FILE ;
    else if (chunk_size > psf->filelength - psf->header.indx)
        return SFE_MALFORMED_FILE ;
    if (chunk_size > 4)
        caf_read_strings (psf, chunk_size - 4) ;
    break ;
```

`caf_read_strings(...)` then allocates a buffer using the attacker-controlled `chunk_size` and passes it to `psf_binheader_readf(...)` using the `b` format with a `size_t` argument:

```c
if ((buf = malloc (chunk_size + 1)) == NULL)
    return (psf->error = SFE_MALLOC_FAILED) ;

psf_binheader_readf (psf, "E4b", &count, buf, (size_t) chunk_size) ;
buf [chunk_size] = 0 ;
```

In `psf_binheader_readf(...)`, the `b` handler reads that argument into an `int` named `count`:

```c
case 'b' : /* Raw bytes */
    charptr = va_arg (argptr, char*) ;
    count = va_arg (argptr, size_t) ;
    memset (charptr, 0, count) ;
    read_bytes = header_read (psf, charptr, count) ;
    break ;
```

This is the core bug:

- the caller supplies a **`size_t`**
- the callee stores it in an **`int`**
- if the value exceeds `INT_MAX`, it truncates/wraps to a negative value
- the resulting negative `count` is then passed to `memset(...)`

Therefore, a crafted CAF file with a sufficiently large `info` chunk can cause an invalid negative length to reach `memset`, producing the observed `negative-size-param` crash.

### 3.3 Why the supplied PoC triggers it

The supplied PoC generator sets:

- `strings_len = 0x8000000C` (`2147483660`)
- `info_chunk_size = strings_len + 4`

It then emits a CAF `info` chunk whose string area length is greater than `INT_MAX`, while also making the file sparse so that the large chunk size remains consistent with file length checks.

As a result:

1. `caf_read_header(...)` accepts the `info` chunk,
2. `caf_read_strings(...)` calls `malloc(chunk_size + 1)` and then
3. passes `(size_t) chunk_size` into `psf_binheader_readf(...)`,
4. where the `b` handler truncates it into `int count`,
5. and `memset(charptr, 0, count)` receives a negative size.

---

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 PoC generator

Use the supplied script:

```bash
python3 poc_gen.py
```

This writes `caf_info_big.caf` with an oversized CAF `info` chunk string area.

### 4.2 Reproduction command

Run with an AddressSanitizer-enabled build of libsndfile's `sndfile-info`:

```bash
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 ./build-asan/sndfile-info caf_info_big.caf
```

### 4.3 Expected result (key excerpt)

ASan reports `negative-size-param` and points to `psf_binheader_readf(...)`:

```text
ERROR: AddressSanitizer: negative-size-param: (size=-2147483636)
#0 ... in __asan_memset
#1 ... in psf_binheader_readf /home/dell/data/libsndfile/src/common.c:1125:6
#2 ... in caf_read_strings /home/dell/data/libsndfile/src/caf.c:849:2
#3 ... in caf_read_header /home/dell/data/libsndfile/src/caf.c:536:6
...
allocated by thread T0 here:
#0 ... in __interceptor_malloc
#1 ... in caf_read_strings /home/dell/data/libsndfile/src/caf.c:846:13
```

This shows both the crashing sink and the allocation site for the attacker-controlled buffer.

---

## 5. Impact Assessment

- **Minimum impact**: Denial of Service (process crash) when a libsndfile-based program parses a crafted CAF file
- **Security relevance**: This is a real parser bug caused by integer truncation and attacker-controlled chunk size flowing into a memory operation
- **Exploitability**: The supplied material demonstrates a crash. I have not demonstrated reliable code execution, so the safest present claim is **crafted-file DoS via negative-size-param / invalid memory operation**

---

## 6. Attachments

- `asan.txt`: AddressSanitizer crash output
- `caf.c`: CAF parser source
- `common.c`: shared binary header reader source
- `poc_gen.py`: PoC generator for `caf_info_big.caf`

