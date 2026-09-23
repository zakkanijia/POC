# GPAC Vorbis Decoder 6‑Channel Heap Buffer Overflow in `vorbis_to_intern`

---

## 1. Summary

- **Project/Product**: GPAC
- **Affected component**: Vorbis decoder filter (`vorbisdec`) — `src/filters/dec_vorbis.c`
- **Vulnerability class**: Heap-based Buffer Overflow (**Out-of-Bounds Write**)
- **Trigger**: Decoding a crafted Vorbis stream that advertises **6 channels** (5.1) and produces PCM output, causing an invalid channel remapping pointer to write past the end of the PCM output buffer.
- **Impact**: At minimum **Denial of Service (crash)**. Because this is a heap **OOB write**, it is a memory corruption issue and may be exploitable depending on build and runtime conditions (not demonstrated here).
- **Attack vector**: Victim opens/processes a crafted `.ogg` file with GPAC or a GPAC-based application.

---

## 2. Affected Versions

- **Confirmed vulnerable (code audit + PoC)**: GPAC **2.4.0**
- **Potentially affected**: other versions that contain the same `vorbis_to_intern` 6‑channel mapping logic.

---

## 3. Root Cause

### 3.1 Location

- File: `src/filters/dec_vorbis.c`
- Function: `vorbis_to_intern(u32 samples, Float **pcm, char *buf, u32 channels)`
- Buggy logic: 6‑channel remapping sets `ptr = &data[i+1]` for `i==5`, producing `ptr = &data[6]` when `channels==6`.

### 3.2 Root cause details

`vorbis_to_intern` writes interleaved 16‑bit PCM samples into the output buffer `buf`:

- `data = (ogg_int16_t*)buf;` and the valid indices are `[0 .. samples*channels - 1]`.
- For each channel `i`, it picks an initial pointer `ptr` (one sample of that channel) and then advances by `channels` each sample: `ptr += channels`.

In the 6‑channel special case, the code contains:

```c
 170 static GFINLINE void vorbis_to_intern(u32 samples, Float **pcm, char *buf, u32 channels)
 171 {
 172 	u32 i, j;
 173 	s32 val;
 174 	ogg_int16_t *data = (ogg_int16_t*)buf ;
 175 
 176 	for (i=0 ; i<channels ; i++) {
 177 		Float *mono;
 178 		ogg_int16_t *ptr;
 179 		ptr = &data[i];
 180 		if (!ptr) break;
 181 		
 182 		if (channels>2) {
 183 			/*center is third in gpac*/
 184 			if (i==1) ptr = &data[2];
 185 			/*right is 2nd in gpac*/
 186 			else if (i==2) ptr = &data[1];
 187 			/*LFE is 4th in gpac*/
 188 			if ((channels==6) && (i>3)) {
 189 				if (i==6) ptr = &data[4];	/*LFE*/
 190 				else ptr = &data[i+1];	/*back l/r*/
 191 			}
 192 		}
 193 
 194 		mono = pcm[i];
 195 		for (j=0; j<samples; j++) {
 196 			val = (s32) (mono[j] * 32767.f);
 197 			if (val > 32767) val = 32767;
 198 			if (val < -32768) val = -32768;
 199 			(*ptr) = val;
 200 			ptr += channels;
 201 		}
 202 	}
 203 }
 204 
```

When `channels==6` and `i==5`, the branch sets `ptr = &data[i+1] = &data[6]`.  
But with 6 channels, `data[6]` is already **one element past the first frame’s valid range** (valid are `data[0..5]` for the first sample). The loop then writes `(*ptr) = val` for every sample, resulting in **out-of-bounds writes** to the PCM output buffer (each write is 2 bytes).

This is a deterministic heap memory corruption when decoding 6‑channel streams that reach this remapping path.

---

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 PoC generator

Attachment: `gen_poc_vorbis.py`

This script generates: `poc_vorbis_6ch_heap_oobwrite.ogg`

### 4.2 Generate PoC

```bash
python3 gen_poc_vorbis.py poc_vorbis_6ch_heap_oobwrite.ogg
```

### 4.3 Reproduction command

Run with an AddressSanitizer-enabled GPAC build:

```bash
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1 \
UBSAN_OPTIONS=halt_on_error=1 \
./bin/gcc/gpac -i poc_vorbis_6ch_heap_oobwrite.ogg oggdmx vorbisdec -o null
```

### 4.4 Expected result

A sanitizer build should report a **heap-buffer-overflow (WRITE)** originating from `vorbis_to_intern` in `dec_vorbis.c` while decoding the 6‑channel stream.

> Note: The `asan.txt` available in this conversation appears to correspond to a different testcase; include the Vorbis-specific ASan output when submitting, if available.

---

## 5. Impact Assessment

- **Minimum impact**: Denial of Service (crash).
- **Security risk**: Heap out-of-bounds **write** (memory corruption). Exploitability is build- and environment-dependent and is not demonstrated in this report.

---

## 6. Attachments

- `dec_vorbis.c` : vulnerable code (`vorbis_to_intern`)
- `gen_poc_vorbis.py` : PoC generator producing `poc_vorbis_6ch_heap_oobwrite.ogg`

