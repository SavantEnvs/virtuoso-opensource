#!/usr/bin/env bash
#
# mayhem/build.sh — build the Virtuoso fuzz harnesses and the oracle binaries.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem (SRC). Virtuoso is an
# in-tree autotools project (out-of-tree configure is not supported), so the tree is configured and
# built twice, in this order:
#   1. NORMAL flags  -> /mayhem/oracle-build/{virtuoso-t,isql}   (what mayhem/test.sh runs)
#   2. SANITIZED     -> static libraries linked into the harnesses
# `make clean` between the two; every step is re-runnable and needs no network.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Benign upstream idioms that trip UBSan before the server even finishes starting (pointer
# arithmetic on NULL, offsetof-style casts, calls through differently-typed function pointers,
# shifts of negative values, packed/misaligned box headers): relax exactly those checks, keep the
# rest of UBSan and all of ASan halting.
RELAX=""
case "$SANITIZER_FLAGS" in
  *undefined*) RELAX="-fno-sanitize=null,object-size,function,shift,alignment,pointer-overflow,nonnull-attribute" ;;
esac
# ASan's fake stack (use-after-return) moves frames to the heap, which breaks Virtuoso's own
# stack-overflow guard (it compares frame addresses to the thread's stack bounds) and makes every
# SQL compile fail with SQ200.
case "$SANITIZER_FLAGS" in
  *address*) RELAX="$RELAX -fsanitize-address-use-after-return=never" ;;
esac

CONFIGURE_ARGS=(--disable-all-vads --without-iodbc --disable-openldap --disable-imagemagick
  --disable-proj4 --disable-geos --disable-graphql --disable-hslookup --disable-wbxml2
  --disable-bz2 --disable-lzma --enable-static --disable-shared)

# configure's OpenSSL probe runs a sanitized binary; LeakSanitizer would fail it.
export ASAN_OPTIONS=detect_leaks=0

[ -f configure ] || ./autogen.sh

# Objects do not track CFLAGS, so wipe what the previous configuration built (a plain top-level
# `make clean` also enters binsrc/tests/suite, whose clean-local rule fails).
clean_build() {
  [ -f libsrc/Makefile ] && make -C libsrc clean >/dev/null
  [ -f binsrc/virtuoso/Makefile ] && make -C binsrc/virtuoso clean >/dev/null
  [ -f binsrc/tests/Makefile ] && make -C binsrc/tests SUBDIRS= clean >/dev/null
  return 0
}

# 1) Oracle build: the project's normal flags, only what test.sh needs.
mkdir -p oracle-build
clean_build
./configure CC="$CC" CXX="$CXX" CFLAGS="-O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" "${CONFIGURE_ARGS[@]}"
make -j"$MAYHEM_JOBS" -C libsrc
make -j"$MAYHEM_JOBS" -C binsrc/virtuoso virtuoso-t
make -j"$MAYHEM_JOBS" -C binsrc/tests isql
cp binsrc/virtuoso/virtuoso-t binsrc/tests/isql oracle-build/
clean_build

# 2) Sanitized build of the project itself.
FUZZ_CFLAGS="$SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -O1"
./configure CC="$CC" CXX="$CXX" CFLAGS="$FUZZ_CFLAGS" "${CONFIGURE_ARGS[@]}"
make -j"$MAYHEM_JOBS" -C libsrc
make -j"$MAYHEM_JOBS" -C binsrc/virtuoso

INC="-DHAVE_CONFIG_H -Ilibsrc -Ilibsrc/Dk -Ilibsrc/Wi -Ilibsrc/Thread -Ilibsrc/odbcsdk/include
 -Ilibsrc/plugin -Ilibsrc/langfunc -Ilibsrc/Xml.new -DPOINTER_64 -Dlinux -D_GNU_SOURCE -DFILE64
 -D_LARGEFILE64_SOURCE -DOPENSSL_NO_KRB5 -DNDEBUG"
LIBS="binsrc/virtuoso/.libs/libvirtuoso-t.a libsrc/Wi/.libs/libwi.a libsrc/Wi/.libs/libwic.a
 libsrc/Dk/.libs/libdksrv.a libsrc/Thread/.libs/libthrp.a libsrc/Xml.new/.libs/libxml.a
 libsrc/plugin/.libs/libplugin.a libsrc/langfunc/.libs/liblangfunc.a libsrc/Tidy/.libs/libtidy.a
 libsrc/util/.libs/libutil.a libsrc/zlib/.libs/libz.a"
SYSLIBS="-lssl -lcrypto -lpthread -lm -ldl"

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o /tmp/lsan_off.o
$CC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -O1 -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CC $INC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -O1 -c mayhem/fuzz_sql.c -o /tmp/fuzz_sql.o
$CC $INC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -O1 -c mayhem/fuzz_sql_compile.c -o /tmp/fuzz_sql_compile.o
$CC $INC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -O1 -c mayhem/fuzz_fuzzy.c -o /tmp/fuzz_fuzzy.o
$CC $INC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -O1 -c libsrc/Wi/fuzzy_algorithms.c -o /tmp/fuzzy_algorithms.o

# fuzz_sql: the embedded server (libvirtuoso-t.a) driven in-process.
$CC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS $LIB_FUZZING_ENGINE /tmp/fuzz_sql.o /tmp/lsan_off.o \
  -Wl,--start-group $LIBS -Wl,--end-group $SYSLIBS -o /mayhem/fuzz_sql
$CC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS /tmp/standalone_main.o /tmp/fuzz_sql.o /tmp/lsan_off.o \
  -Wl,--start-group $LIBS -Wl,--end-group $SYSLIBS -o /mayhem/fuzz_sql-standalone

# fuzz_sql_compile: the same embedded server, but inputs are only compiled (never executed or stored),
# so the database stays untouched and a crash replays from its single input.
$CC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS $LIB_FUZZING_ENGINE /tmp/fuzz_sql_compile.o /tmp/lsan_off.o \
  -Wl,--start-group $LIBS -Wl,--end-group $SYSLIBS -o /mayhem/fuzz_sql_compile
$CC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS /tmp/standalone_main.o /tmp/fuzz_sql_compile.o /tmp/lsan_off.o \
  -Wl,--start-group $LIBS -Wl,--end-group $SYSLIBS -o /mayhem/fuzz_sql_compile-standalone

# fuzz_fuzzy: the self-contained string-similarity algorithms.
$CC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS $LIB_FUZZING_ENGINE /tmp/fuzz_fuzzy.o /tmp/fuzzy_algorithms.o \
  /tmp/lsan_off.o -lm -o /mayhem/fuzz_fuzzy
$CC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS /tmp/standalone_main.o /tmp/fuzz_fuzzy.o /tmp/fuzzy_algorithms.o \
  /tmp/lsan_off.o -lm -o /mayhem/fuzz_fuzzy-standalone
