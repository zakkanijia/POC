# giflib `giftool` / `EGifGCBToSavedExtension` Heap Buffer Overflow via Truncated GCE Extension

---

## 1. Summary

- **Project/Product**: giflib
- **Affected component**: `egif_lib.c` (`EGifGCBToSavedExtension` / `EGifGCBToExtension`), reachable via `giftool`
- **Vulnerability class**: Heap-based Buffer Overflow (**Out-of-Bounds Write**)
- **Trigger**: A crafted GIF containing a **Graphics Control Extension (GCE)** block with a **truncated extension byte count** (e.g., length `1` instead of `4`). When `giftool` modifies delay time (`-d`), it attempts to rewrite the GCE in-place and writes 4 bytes into an allocation of 1 byte.
- **Impact**: At minimum **Denial of Service (crash)**. This is a **heap OOB write** (memory corruption) and may be exploitable depending on allocator/layout (not demonstrated here).
- **Attack vector**: Victim runs `giftool` (or a program using giflib and calling `EGifGCBToSavedExtension`) on a crafted GIF.

---

## 2. Affected Versions

- **Confirmed vulnerable**: giflib **5.2.2** (ASan reproduction attached)
- **Potentially affected**: versions containing the same `EGifGCBToSavedExtension` in-place overwrite logic.

---

## 3. Root Cause

### 3.1 Location

- File: `egif_lib.c`
  - `EGifGCBToExtension(...)` writes **4 bytes** of GCE payload.
  - `EGifGCBToSavedExtension(...)` overwrites an existing extension block’s `ep->Bytes` **without validating** the existing `ByteCount`.

### 3.2 Root cause details

When a saved image already contains a GCE extension block (`ep->Function == GRAPHICS_EXT_FUNC_CODE`), the code unconditionally renders a new 4-byte GCE into `ep->Bytes`:

```c
 648 
 649 size_t EGifGCBToExtension(const GraphicsControlBlock *GCB,
 650                           GifByteType *GifExtension) {
 651 	GifExtension[0] = 0;
 652 	GifExtension[0] |=
 653 	    (GCB->TransparentColor == NO_TRANSPARENT_COLOR) ? 0x00 : 0x01;
 654 	GifExtension[0] |= GCB->UserInputFlag ? 0x02 : 0x00;
 655 	GifExtension[0] |= ((GCB->DisposalMode & 0x07) << 2);
 656 	GifExtension[1] = LOBYTE(GCB->DelayTime);
 657 	GifExtension[2] = HIBYTE(GCB->DelayTime);
 658 	GifExtension[3] = (char)GCB->TransparentColor;
 659 	return 4;
 660 }
 661 
 662 /******************************************************************************
 663  Replace the Graphics Control Block for a saved image, if it exists.
 664 ******************************************************************************/
 665 
 666 int EGifGCBToSavedExtension(const GraphicsControlBlock *GCB,
 667                             GifFileType *GifFile, int ImageIndex) {
 668 	int i;
 669 	size_t Len;
 670 	GifByteType buf[sizeof(GraphicsControlBlock)]; /* a bit dodgy... */
 671 
 672 	if (ImageIndex < 0 || ImageIndex > GifFile->ImageCount - 1) {
 673 		return GIF_ERROR;
 674 	}
 675 
 676 	for (i = 0; i < GifFile->SavedImages[ImageIndex].ExtensionBlockCount;
 677 	     i++) {
 678 		ExtensionBlock *ep =
 679 		    &GifFile->SavedImages[ImageIndex].ExtensionBlocks[i];
 680 		if (ep->Function == GRAPHICS_EXT_FUNC_CODE) {
 681 			EGifGCBToExtension(GCB, ep->Bytes);
 682 			return GIF_OK;
 683 		}
 684 	}
 685 
 686 	Len = EGifGCBToExtension(GCB, (GifByteType *)buf);
 687 	if (GifAddExtensionBlock(
 688 	        &GifFile->SavedImages[ImageIndex].ExtensionBlockCount,
 689 	        &GifFile->SavedImages[ImageIndex].ExtensionBlocks,
```

If the input GIF contains a malformed/truncated GCE where `ep->ByteCount` is **less than 4**, then `ep->Bytes` is allocated with that smaller size during parsing (e.g., 1 byte). The subsequent overwrite via `EGifGCBToExtension(GCB, ep->Bytes)` writes 4 bytes, resulting in a heap buffer overflow (OOB write).

`giftool` reaches this path when applying the delay time operation (`-d`), which calls `EGifGCBToSavedExtension(...)`:

```c
 265 			GifFileIn->SBackGroundColor = op->color;
 266 			break;
 267 
 268 		case delaytime:
 269 			for (i = 0; i < nselected; i++) {
 270 				GraphicsControlBlock gcb;
 271 
 272 				DGifSavedExtensionToGCB(GifFileIn, selected[i],
 273 				                        &gcb);
 274 				gcb.DelayTime = op->delay;
 275 				EGifGCBToSavedExtension(&gcb, GifFileIn,
 276 				                        selected[i]);
 277 			}
 278 			break;
 279 
```

---

## 4. Proof of Concept (PoC) and Reproduction

### 4.1 PoC generator

Attachment: `gen_poc_giftool_gce_len1.py`

It creates a GIF where the GCE extension block has an invalid short length (e.g., `1`), ensuring `ep->Bytes` is allocated as 1 byte.

### 4.2 Generate PoC

```bash
python3 gen_poc_giftool_gce_len1.py > poc.gif
```

### 4.3 Reproduction command

Run with an AddressSanitizer-enabled build of giflib/giftool:

```bash
./giftool -d 1 < ./poc.gif > /dev/null
```

### 4.4 Expected result (ASan excerpt)

```text
zakka@dell-PowerEdge-R750:~/Desktop/geminiTalk/giflib/build-asan/giflib-5.2.2$ ./giftool -d 1 < ./poc.gif > /dev/null
=================================================================
==585992==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031 at pc 0x5a3170f7cf51 bp 0x7fff87f9ed70 sp 0x7fff87f9ed68
WRITE of size 1 at 0x602000000031 thread T0
    #0 0x5a3170f7cf50 in EGifGCBToExtension /home/zakka/Desktop/geminiTalk/giflib/build-asan/giflib-5.2.2/egif_lib.c:656:18
    #1 0x5a3170f7db13 in EGifGCBToSavedExtension /home/zakka/Desktop/geminiTalk/giflib/build-asan/giflib-5.2.2/egif_lib.c:681:4
    #2 0x5a3170f518f3 in main /home/zakka/Desktop/geminiTalk/giflib/build-asan/giflib-5.2.2/giftool.c:275:5
    #3 0x7743c5029d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #4 0x7743c5029e3f in __libc_start_main csu/../csu/libc-start.c:392:3
    #5 0x5a3170e90354 in _start (/home/zakka/Desktop/geminiTalk/giflib/build-asan/giflib-5.2.2/giftool+0x3a354) (BuildId: bb4c8049db34e8a7986f49a064d4ba7c2d3df754)

0x602000000031 is located 0 bytes to the right of 1-byte region [0x602000000030,0x602000000031)
allocated by thread T0 here:
    #0 0x5a3170f1319e in __interceptor_malloc (/home/zakka/Desktop/geminiTalk/giflib/build-asan/giflib-5.2.2/giftool+0xbd19e) (BuildId: bb4c8049db34e8a7986f49a064d4ba7c2d3df754)
    #1 0x5a3170f86ada in GifAddExtensionBlock /home/zakka/Desktop/geminiTalk/giflib/build-asan/giflib-5.2.2/gifalloc.c:251:29
    #2 0x5a3170f6ed04 in DGifSlurp /home/zakka/Desktop/geminiTalk/giflib/build-asan/giflib-5.2.2/dgif_lib.c:1269:9
    #3 0x5a3170f5089d in main /home/zakka/Desktop/geminiTalk/giflib/build-asan/giflib-5.2.2/giftool.c:235:6
    #4 0x7743c5029d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
...

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/zakka/Desktop/geminiTalk/giflib/build-asan/giflib-5.2.2/egif_lib.c:656:18 in EGifGCBToExtension
Shadow bytes around the buggy address:
  0x0c047fff7fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c047fff8000: fa fa 06 fa fa fa[01]fa fa fa 01 fa fa fa fa fa
  0x0c047fff8010: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
```

ASan reports a **heap-buffer-overflow** with a **WRITE** in `EGifGCBToExtension` (writing `GifExtension[1..3]` into a 1-byte allocation).

---

## 5. Impact Assessment

- **Minimum impact**: Denial of Service (crash).
- **Security risk**: Heap out-of-bounds **write** (memory corruption). Exploitability is environment-dependent and not demonstrated in this report.

---

## 6. Attachments

- `asan.txt` : ASan crash log (heap-buffer-overflow WRITE)
- `egif_lib.c` : vulnerable code
- `giftool.c` : caller path (`-d` delaytime operation)
- `gen_poc_giftool_gce_len1.py` : PoC generator

