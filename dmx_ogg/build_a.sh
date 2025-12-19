#!/usr/bin/env bash
set -euxo pipefail

ROOT=~/Desktop/g2fuzz_eval/gpac-2.4.0
cd "$ROOT"


make distclean >/dev/null 2>&1 || true
rm -f config.mak config.log >/dev/null 2>&1 || true
rm -rf bin/gcc/modules >/dev/null 2>&1 || true


export CC=clang-17
export CXX=clang++-17
export LD=clang-17
export AR=/usr/bin/llvm-ar-17
export RANLIB=/usr/bin/llvm-ranlib-17

SAN="-fsanitize=address,undefined"
COMMON="-O1 -g -fno-omit-frame-pointer -fPIC"

export CFLAGS="$COMMON $SAN"
export CXXFLAGS="$COMMON $SAN"

export LDFLAGS="$SAN"
export LIBS="$SAN"

./configure --enable-debug --static-modules \
  --disable-sdl --disable-x11 --disable-pulseaudio || ./configure --enable-debug --static-modules

make -j"$(nproc)" V=1

cp -a /usr/lib/llvm-17/lib/clang/17/lib/linux/libclang_rt.asan-x86_64.so bin/gcc/ || true
cp -a /usr/lib/llvm-17/lib/clang/17/lib/linux/libclang_rt.ubsan_standalone-x86_64.so bin/gcc/ 2>/dev/null || true

mkdir -p ~/.gpac/modules

echo "[+] verify asan dependency:"
ldd bin/gcc/gpac | grep -E 'clang_rt\.asan|libasan' || true

echo "[+] verify asan symbols:"
nm -D bin/gcc/gpac 2>/dev/null | grep -E '__asan_init|__ubsan_handle' | head || true

echo "[+] done"
