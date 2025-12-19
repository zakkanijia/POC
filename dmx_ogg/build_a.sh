#!/usr/bin/env bash
set -euxo pipefail

ROOT=~/Desktop/g2fuzz_eval/gpac-2.4.0
cd "$ROOT"

# 0) 清理
make distclean >/dev/null 2>&1 || true
rm -f config.mak config.log >/dev/null 2>&1 || true
rm -rf bin/gcc/modules >/dev/null 2>&1 || true

# 1) 工具链统一到 17
export CC=clang-17
export CXX=clang++-17
export LD=clang-17
export AR=/usr/bin/llvm-ar-17
export RANLIB=/usr/bin/llvm-ranlib-17

# 2) Sanitizer flags
SAN="-fsanitize=address,undefined"
COMMON="-O1 -g -fno-omit-frame-pointer -fPIC"

# 只用 export 让 configure 写进 config.mak；不要在 make 命令行覆盖 CFLAGS（会丢 -I）
export CFLAGS="$COMMON $SAN"
export CXXFLAGS="$COMMON $SAN"

# 链接阶段也要有 sanitizer（确保 libgpac.so/gpac/mp4box 都能找到 runtime）
export LDFLAGS="$SAN"
export LIBS="$SAN"

# 3) 配置
# 注意：你的版本不认识 --disable-gl，就别写；只保留确定存在的 disable 项
./configure --enable-debug --static-modules \
  --disable-sdl --disable-x11 --disable-pulseaudio || ./configure --enable-debug --static-modules

# 4) 编译（不要传 LDFLAGS=... 去覆盖！）
make -j"$(nproc)" V=1

# 5) 解决 ASan runtime：由于 RUNPATH=$ORIGIN，把 runtime 拷到 bin/gcc 即可
cp -a /usr/lib/llvm-17/lib/clang/17/lib/linux/libclang_rt.asan-x86_64.so bin/gcc/ || true
cp -a /usr/lib/llvm-17/lib/clang/17/lib/linux/libclang_rt.ubsan_standalone-x86_64.so bin/gcc/ 2>/dev/null || true

# 6) 解决 modules 提示：建立一个可用的 modules 目录（至少让 gpac 不再报找不到）
#   你的源码树里有 ./modules（源码/列表）和 ./src/modules（源码），但这次是 static-modules，
#   运行时仍会去找 ~/.gpac/modules。我们放一个空目录也能让它不再提示 HOME path 缺失。
mkdir -p ~/.gpac/modules

# 7) 验证
echo "[+] verify asan dependency:"
ldd bin/gcc/gpac | grep -E 'clang_rt\.asan|libasan' || true

echo "[+] verify asan symbols:"
nm -D bin/gcc/gpac 2>/dev/null | grep -E '__asan_init|__ubsan_handle' | head || true

echo "[+] done"
