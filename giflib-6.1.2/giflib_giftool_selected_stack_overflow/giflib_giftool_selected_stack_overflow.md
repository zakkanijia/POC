# giflib_giftool_selected_stack_overflow

---

## 1. Summary

- **Project/Product**: giflib
- **Affected component**: `giftool`
- **Vulnerability class**: Stack-based Buffer Overflow (Out-of-Bounds Write)
- **Trigger**: Processing a crafted GIF file containing more than 2048 images/frames through `giftool` without an explicit `-n` selection argument
- **Impact**: At minimum **Denial of Service (crash)**. Because this is a stack out-of-bounds write, further exploitation may be possible depending on compiler, platform, and stack layout. I have confirmed the memory-safety violation with ASan, but I have not demonstrated code execution.
- **Attack vector**: An attacker supplies a crafted multi-frame GIF file. When the victim runs `giftool` on that file, the default image-selection logic writes beyond a fixed-size stack array.

---

## 2. Affected Versions

- **Confirmed vulnerable**: giflib **6.1.2**
- **Affected component scope**: confirmed in the `giftool` utility path
- **Other versions**: may also be affected if they retain the same fixed-size `selected[MAX_IMAGES]` logic without bounds checking, but I have only verified 6.1.2

---

## 3. Root Cause

### 3.1 Location

- File: `giftool.c`
- Function: `main(...)`

### 3.2 Root cause details

`giftool.c` defines a fixed-size stack array for selected image indices:

```c
#define MAX_IMAGES 2048
int selected[MAX_IMAGES], nselected = 0;
```

After `DGifSlurp(...)` parses the input GIF, the program computes a default selection when the user does not provide `-n`:

```c
if (!have_selection) {
    for (i = nselected = 0; i < GifFileIn->ImageCount; i++) {
        selected[nselected++] = i;
    }
}
```

There is no check that `GifFileIn->ImageCount` is less than or equal to `MAX_IMAGES`. Therefore, if an attacker supplies a GIF containing more than 2048 images, the loop writes past the end of the stack array `selected`, causing a **stack-based out-of-bounds write**.

### 3.3 Why the supplied PoC triggers it

The supplied PoC generator creates a minimal multi-frame GIF and defaults to **2049** frames:

```python
frames = int(sys.argv[2]) if len(sys.argv) > 2 else 2049
```

This makes `GifFileIn->ImageCount == 2049` after parsing, so the default-selection loop attempts to write 2049 integers into `selected[2048]`, overflowing the stack buffer by at least one element.

---

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 PoC generator

Use the supplied Python script to generate the triggering GIF:

```bash
python3 make_giftool_poc.py giftool_2049_frames.gif 2049
```

This creates a minimal valid GIF with 2049 1x1 image frames.

### 4.2 Reproduction command

Run `giftool` with an ASan-enabled build and feed the crafted GIF through stdin:

```bash
ASAN_OPTIONS=detect_leaks=0 ./giftool < giftool_2049_frames.gif > /dev/null
```

### 4.3 Expected result (key excerpt)

ASan reports a stack-buffer-overflow write in `giftool.c`:

```text
ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 4
#0 ... in main /home/dell/data/giflib-6.1.2/giftool.c:245:26
...
[4672, 12864) 'selected' (line 118) <== Memory access at offset 12864 overflows this variable
...
SUMMARY: AddressSanitizer: stack-buffer-overflow /home/dell/data/giflib-6.1.2/giftool.c:245:26 in main
```

This matches the default-selection loop and confirms that the out-of-bounds write targets the stack array `selected`.

---

## 5. Impact Assessment

- **Minimum impact**: Denial of Service (process crash) when `giftool` processes a crafted GIF containing more than 2048 images
- **Security relevance**: This is a real stack out-of-bounds write reachable from attacker-controlled file input
- **Exploitability**: I have confirmed a crash and memory corruption with ASan, but I have not proven code execution. The most defensible current claim is **stack-based buffer overflow leading to crash / denial of service**

---

## 6. Attachments

- `asan.txt`: AddressSanitizer crash output
- `giftool.c`: vulnerable source file
- `make_giftool_poc.py`: PoC generator for the crafted 2049-frame GIF

