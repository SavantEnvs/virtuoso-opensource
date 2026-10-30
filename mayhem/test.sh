#!/usr/bin/env bash
#
# mayhem/test.sh — behavioural oracle: boot the normally-built virtuoso-t (oracle-build/, made by
# mayhem/build.sh) on a scratch database, run known SQL/SPARQL/XPath inputs through isql, and assert
# the exact values that come back. Emits a CTRF summary; exit 0 iff every assertion held.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


BIN="$SRC/oracle-build"
for f in virtuoso-t isql; do
  [ -x "$BIN/$f" ] || { echo "missing $BIN/$f (mayhem/build.sh should have produced it)" >&2; emit_ctrf "virtuoso-isql" 0 1 0; exit 1; }
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/virt-oracle.XXXXXX")"
PORT=$((20000 + RANDOM % 20000))
SRV_PID=
cleanup() { [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

cat > "$WORK/virtuoso.ini" <<INI
[Database]
DatabaseFile=$WORK/virtuoso.db
ErrorLogFile=$WORK/virtuoso.log
LockFile=$WORK/virtuoso.lck
TransactionFile=$WORK/virtuoso.trx
xa_persistent_file=$WORK/virtuoso.pxa
ErrorLogLevel=7
FileExtend=200
MaxCheckpointRemap=2000
Striping=0
TempStorage=TempDatabase
[TempDatabase]
DatabaseFile=$WORK/virtuoso-temp.db
TransactionFile=$WORK/virtuoso-temp.trx
MaxCheckpointRemap=2000
Striping=0
[Parameters]
ServerPort=127.0.0.1:$PORT
LiteMode=0
DisableUnixSocket=1
MaxClientConnections=10
CheckpointInterval=0
O_DIRECT=0
CaseMode=2
MaxStaticCursorRows=5000
AllowOSCalls=0
DirsAllowed=$WORK
NumberOfBuffers=10000
MaxDirtyBuffers=6000
ThreadsPerQuery=2
INI

(cd "$WORK" && exec "$BIN/virtuoso-t" +foreground +configfile "$WORK/virtuoso.ini" >"$WORK/stdout.log" 2>&1) &
SRV_PID=$!

# isql decodes '+' in EXEC= as a space, so statements below avoid the plus operator.
# sql <statement> : print the first value of the first result row (empty on any failure)
sql() {
  timeout 60 "$BIN/isql" "127.0.0.1:$PORT" dba dba VERBOSE=OFF BANNER=OFF PROMPT=OFF ERRORS=stdout "EXEC=$1" 2>&1 \
    | awk 'NF { sub(/^[ \t]+/, ""); sub(/[ \t]+$/, ""); print; exit }'
}

up=0
for _ in $(seq 1 180); do
  kill -0 "$SRV_PID" 2>/dev/null || break
  [ "$(sql 'select 1;')" = 1 ] && { up=1; break; }
  sleep 1
done

passed=0; failed=0
check() { # check <name> <expected> <statement>
  local got; got="$(sql "$3")"
  if [ "$got" = "$2" ]; then passed=$((passed + 1)); echo "ok   - $1"
  else failed=$((failed + 1)); echo "FAIL - $1: expected '$2', got '$got'"; fi
}

if [ "$up" = 1 ]; then
  check "integer arithmetic"            7   'select 2 * 5 - 3;'
  check "md5 known answer"              900150983cd24fb0d6963f7d28e17f72 "select md5 ('abc');"
  check "levenshtein kitten/sitting"    3   "select levenshtein ('kitten', 'sitting');"
  check "jaro_winkler MARTHA/MARHTA"    961 "select cast (jaro_winkler ('MARTHA', 'MARHTA') * 1000 as integer);"
  check "string functions"              ABC-3 "select ucase ('abc') || '-' || cast (length ('xyz') as varchar);"
  sql 'create table ORACLE_T (id integer primary key, v integer);' >/dev/null
  sql 'insert into ORACLE_T values (1, 10);' >/dev/null
  sql 'insert into ORACLE_T values (2, 20);' >/dev/null
  sql 'insert into ORACLE_T values (3, 30);' >/dev/null
  check "table insert and aggregate"    60  'select sum (v) from ORACLE_T;'
  check "table filter"                  2   'select id from ORACLE_T where v = 20;'
  sql "sparql insert data { graph <urn:oracle:g> { <urn:oracle:s> <urn:oracle:p> \"hello\" } };" >/dev/null
  check "sparql insert/select roundtrip" hello 'sparql select ?o from <urn:oracle:g> where { <urn:oracle:s> <urn:oracle:p> ?o };'
  check "xpath count"                   3   "select cast (xpath_eval ('count(//b)', xtree_doc ('<a><b/><b/><b/></a>')) as integer);"
  sql 'create procedure ORACLE_SUM (in n integer) { declare i, acc integer; i := 0; acc := 0; while (i < n) { acc := acc - (0 - i); i := i - (0 - 1); } return acc; };' >/dev/null
  check "stored procedure"              45  'select ORACLE_SUM (10);'
else
  failed=$((failed + 1)); echo "FAIL - server did not come up"; tail -20 "$WORK/stdout.log" 2>/dev/null
fi

sql 'shutdown;' >/dev/null 2>&1
emit_ctrf "virtuoso-isql" "$passed" "$failed" 0
