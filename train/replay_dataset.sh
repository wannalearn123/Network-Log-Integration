#!/bin/bash
#
# replay_dataset.sh — replay CICIDS2017 flows as firewall syslog lines.
#
# Takes real flow captures (packet sizes, ports, attack timing from the
# dataset) and re-emits them in the exact syslog formats the C collector
# already parses (iptables kernel form + FortiGate CEF form, copied from
# docker/firewall/log_generator.sh). The pipeline (collector -> ingest ->
# PostgreSQL -> detector) runs unchanged; the replayed traffic simply
# replaces the Docker container feed.
#
# Run with NO arguments for the default replay:
#   ./train/replay_dataset.sh
#
# Every default is overridable via environment or --flag:
#   INPUT=... SPEED=realtime ./train/replay_dataset.sh
#   ./train/replay_dataset.sh --input ... --speed realtime --limit 5000
#
# IMPORTANT: stop the Docker device containers before replaying so
# replayed lines don't mix with generator lines:
#   docker compose -f docker/docker-compose.yml stop router switch ap firewall

set -u

# ── Defaults (env overrides these, flags override env) ──────────────
: "${INPUT:=train/data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv}"
: "${BENIGN_MIX:=train/data/Monday-WorkingHours.pcap_ISCX.csv}"
: "${BENIGN_EVERY:=10}"       # keep every Nth row of the benign mix file
: "${SPEED:=fast}"            # fast = bulk emit, realtime = paced emit
: "${ATTACKER_IP:=172.20.0.50}"
: "${OUTPUT:=data/syslog/firewall.log}"
: "${MANIFEST:=train/data/replay_manifest.csv}"
: "${LIMIT:=0}"               # 0 = no limit, else max emitted lines
: "${DRY_RUN:=0}"             # 1 = print to stdout, write nothing
: "${FAST_CHUNK:=500}"        # fast mode: sleep FAST_SLEEP per FAST_CHUNK lines
: "${FAST_SLEEP:=0.25}"       #   (~2000 lines/s — keeps ingest from dropping)
: "${RT_RATE:=50}"            # realtime mode: ~RT_RATE lines/s
: "${TIME_SPAN:=0}"           # 0 = stamp wall-clock time; N = spread synthetic
                              # timestamps over the past N hours (file order
                              # preserved, so burst episodes land honestly —
                              # gives 120 windows/hour for training volume)
: "${SPAN_END:=0}"            # hours ago the synthetic span ENDS (default: now).
                              # episode layout: benign run with
                              #   --time-span 4 --span-end 4, then attack run
                              #   with --time-span 4 --span-end 0

usage() {
    cat <<EOF
Usage: $0 [options]

  --input FILE        attack-mix CSV (default: $INPUT)
  --benign-mix FILE   background normal CSV, every \$BENIGN_EVERY-th row kept
  --benign-every N    benign sampling (default: $BENIGN_EVERY)
  --speed fast|realtime
  --attacker-ip IP    source IP for attack lines (default: $ATTACKER_IP)
  --output FILE       syslog file to append to (default: $OUTPUT)
  --manifest FILE     ground-truth CSV (default: $MANIFEST)
  --limit N           stop after N emitted lines (default: unlimited)
  --time-span H       spread timestamps over past H hours (default: 0 =
                      wall-clock; use 8 for training volume: ~960 windows)
  --span-end H        hours ago the synthetic span ends (default: 0 = now;
                      pair with --time-span to lay out benign/attack episodes)
  --dry-run           print lines to stdout, write nothing
  --help              this text

All options also work as environment variables (INPUT=... $0).
EOF
}

# ── Flag parsing (flags win over env) ────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --input)       INPUT="$2"; shift 2;;
        --benign-mix)  BENIGN_MIX="$2"; shift 2;;
        --benign-every) BENIGN_EVERY="$2"; shift 2;;
        --speed)       SPEED="$2"; shift 2;;
        --attacker-ip) ATTACKER_IP="$2"; shift 2;;
        --output)      OUTPUT="$2"; shift 2;;
        --manifest)    MANIFEST="$2"; shift 2;;
        --limit)       LIMIT="$2"; shift 2;;
        --time-span)   TIME_SPAN="$2"; shift 2;;
        --span-end)    SPAN_END="$2"; shift 2;;
        --dry-run)     DRY_RUN=1; shift;;
        --help|-h)     usage; exit 0;;
        *) echo "Unknown option: $1 (see --help)" >&2; exit 1;;
    esac
done

if [ "$SPEED" != "fast" ] && [ "$SPEED" != "realtime" ]; then
    echo "ERROR: --speed must be fast or realtime (got: $SPEED)" >&2
    exit 1
fi
if [ ! -f "$INPUT" ]; then
    echo "ERROR: input not found: $INPUT" >&2
    exit 1
fi
if [ ! -f "$BENIGN_MIX" ]; then
    echo "ERROR: benign mix not found: $BENIGN_MIX" >&2
    exit 1
fi

if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p "$(dirname "$OUTPUT")"
    mkdir -p "$(dirname "$MANIFEST")"
    if [ ! -f "$MANIFEST" ]; then
        echo "timestamp,src_ip,label" > "$MANIFEST"
    fi
fi

# ── Synthetic time span (training volume without wall-clock waiting) ──
# Needs gawk for epoch->ISO formatting.
AWK_BIN="$(command -v gawk || command -v awk)"
TS_START=0
LINES_TOTAL=1
if [ "$TIME_SPAN" != "0" ]; then
    if ! "$AWK_BIN" 'BEGIN{exit !(strftime("%Y", 0, 1) != "")}' 2>/dev/null; then
        echo "ERROR: --time-span needs gawk (strftime), none found" >&2
        exit 1
    fi
    NOW_EPOCH=$(date -u +%s)
    TS_START=$((NOW_EPOCH - SPAN_END * 3600 - TIME_SPAN * 3600))
    ATTACK_ROWS=$(( $(wc -l < "$INPUT") - 1 ))
    BENIGN_ROWS=$(( $(wc -l < "$BENIGN_MIX") - 1 ))
    POOL_SIZE=$((BENIGN_ROWS / BENIGN_EVERY))
    if [ "$POOL_SIZE" -gt "$ATTACK_ROWS" ]; then POOL_SIZE=$ATTACK_ROWS; fi
    LINES_TOTAL=$((ATTACK_ROWS + POOL_SIZE))
    echo "[REPLAY] time-span: ${TIME_SPAN}h synthetic clock over ~${LINES_TOTAL} lines" >&2
fi

echo "[REPLAY] input=$INPUT" >&2
echo "[REPLAY] benign_mix=$BENIGN_MIX (every ${BENIGN_EVERY}th row)" >&2
echo "[REPLAY] speed=$SPEED attacker=$ATTACKER_IP limit=$LIMIT dry_run=$DRY_RUN" >&2
if [ "$DRY_RUN" -eq 0 ]; then
    echo "[REPLAY] output=$OUTPUT manifest=$MANIFEST" >&2
fi

# ── Main pass (awk: fast enough for ~300K rows, bash would take 10x) ──
# Col 1  = ' Destination Port' (real destination port from the capture)
# Col $NF = ' Label'           (BENIGN / PortScan / DDoS / ...)
"$AWK_BIN" -F',' \
    -v benign_mix_keep="$BENIGN_EVERY" \
    -v attacker="$ATTACKER_IP" \
    -v speed="$SPEED" \
    -v limit="$LIMIT" \
    -v dryrun="$DRY_RUN" \
    -v outfile="$OUTPUT" \
    -v manifest="$MANIFEST" \
    -v fast_chunk="$FAST_CHUNK" \
    -v fast_sleep="$FAST_SLEEP" \
    -v rt_rate="$RT_RATE" \
    -v time_span="$TIME_SPAN" \
    -v ts_start="$TS_START" \
    -v lines_total="$LINES_TOTAL" \
'
function trim(s) { gsub(/^\x20+|\x20+$/, "", s); gsub(/\r/, "", s); return s }

function clock_now(    t) {
    # Wall-clock timestamp (one fork per call — callers refresh sparingly).
    "date -u +%Y-%m-%dT%H:%M:%S+00:00" | getline t
    close("date -u +%Y-%m-%dT%H:%M:%S+00:00")
    return t
}

function clock_for(n) {
    # Synthetic clock: line n of ~lines_total spread over time_span hours.
    # File order preserved, so burst episodes land in honest positions.
    if (time_span == 0) return clock_now()
    return strftime("%Y-%m-%dT%H:%M:%S+00:00",
                    ts_start + (n / lines_total) * time_span * 3600, 1)
}

function valid_port(p) {
    return (p ~ /^[0-9]+$/ && p + 0 >= 1 && p + 0 <= 65535) ? p + 0 : 80
}

# proto cycles deterministically TCP/TCP/TCP/UDP/ICMP (same mix the old
# converter used randomly — now reproducible).
function proto_of(n,    m) {
    m = n % 5
    if (m < 3) return "TCP"
    if (m == 3) return "UDP"
    return "ICMP"
}
function pnum_of(proto) {
    if (proto == "TCP") return 6
    if (proto == "UDP") return 17
    return 1
}

function emit(ts, tag, msg,    line) {
    line = ts " firewall " tag ": " msg
    if (dryrun) { print line; return }
    print line >> outfile
}

function emit_iptables(ts, action, src, proto, spt, dpt, extra) {
    emit(ts, "kernel",
        "[FW " action "] IN=eth0 OUT= SRC=" src " DST=172.20.0.4" \
        " PROTO=" proto " SPT=" spt " DPT=" dpt extra)
}

function emit_cef(ts, allow, logid, devid, src, spt, dpt, pnum,    act, txt) {
    if (allow) { act = "close"; txt = "allow" }
    else       { act = "deny";  txt = "deny" }
    emit(ts, "fortigate",
        "CEF: 0|Fortinet|FortiGate|v7.0.0|00010|traffic:forward " txt \
        "|3|deviceExternalId=FGT100F" devid " FTNTFGTlogid=" logid \
        " cat=traffic:forward src=" src " dst=172.20.0.4" \
        " spt=" spt " dpt=" dpt " proto=" pnum " act=" act)
}

function emit_flow(ts, n, is_attack, dpt, src,    proto, spt, pnum, logid, devid) {
    proto = proto_of(n)
    pnum  = pnum_of(proto)
    spt   = 1024 + (n * 7919 % 60000)
    logid = sprintf("%010d", n)
    devid = sprintf("%012d", n)
    if (n % 2 == 0) {
        if (is_attack) emit_iptables(ts, "DROP", src, proto, spt, dpt,
                                     (proto == "TCP" && atk_type == "ddos") ? " SYN" : "")
        else           emit_iptables(ts, "ALLOW", src, proto, spt, dpt, "")
    } else {
        emit_cef(ts, !is_attack, logid, devid, src, spt, dpt, pnum)
    }
}

function pace(n) {
    if (dryrun) return
    if (speed == "fast") {
        if (n % fast_chunk == 0) system("sleep " fast_sleep)
    } else {
        if (n % rt_rate == 0) system("sleep 1")
    }
}

BEGIN {
    n = 0          # emitted lines
    atk = 0        # attack lines
    ben = 0        # benign lines
    bn = 0         # benign-src cursor
    ts = clock_for(0)
    bi = 0         # benign-pool cursor
    # Same benign source pool as docker/firewall/log_generator.sh
    benign_src[0] = "172.20.100.1"
    benign_src[1] = "172.20.100.5"
    benign_src[2] = "172.20.100.10"
    benign_src[3] = "172.20.100.25"
    benign_src[4] = "172.20.100.48"
}

# Pass 1: sample the benign mix file (store destination ports only).
FNR == NR {
    if (FNR == 1) next
    if ((FNR % benign_mix_keep) == 0) {
        pool[++npool] = valid_port(trim($1))
    }
    next
}

# Pass 2: the attack-mix file, interleaved 1:1 with pooled benign rows.
FNR == 1 { next }

{
    if (limit > 0 && n >= limit) exit
    # Wall-clock mode refreshes every 200 lines; synthetic mode stamps
    # every line from the shared clock (cheap: pure arithmetic + strftime).
    if (time_span == 0) {
        if (++since_ts >= 200) { ts = clock_now(); since_ts = 0 }
    }

    label = trim($NF)
    dpt = valid_port(trim($1))
    n++
    if (time_span != 0) ts = clock_for(n)

    if (label == "BENIGN") {
        src = benign_src[bn++ % 5]
        emit_flow(ts, n, 0, dpt, src)
        ben++
    } else {
        # Attack type only selects message details + manifest label.
        # Detection stays pattern-based: DROP lines, real ports, real rates.
        if      (label ~ /DDoS/)                            atk_type = "ddos"
        else if (label ~ /PortScan/)                        atk_type = "scan"
        else if (label ~ /Patator/ || label ~ /[Bb]rute/)   atk_type = "brute"
        else if (label ~ /Bot/)                             atk_type = "bot"
        else if (label ~ /XSS/ || label ~ /Sql/ || label ~ /Web Attack/) atk_type = "web"
        else if (label ~ /Infiltration/)                    atk_type = "infil"
        else                                                atk_type = "other"
        emit_flow(ts, n, 1, dpt, attacker)
        atk++
        if (!dryrun) print ts "," attacker ",\"" label "\"" >> manifest
    }

    # Interleave one pooled benign row per attack-file row while pool lasts.
    if (bi < npool) {
        if (limit > 0 && n >= limit) exit
        src = benign_src[bn++ % 5]
        n++
        emit_flow(ts, n, 0, pool[++bi], src)
        ben++
    }

    pace(n)
}

END {
    if (!dryrun) {
        close(outfile)
        close(manifest)
    }
    printf "[REPLAY] done: %d lines (%d attack, %d benign), manifest=%s\n",
        n, atk, ben, (dryrun ? "(dry-run, none)" : manifest) > "/dev/stderr"
}
' "$BENIGN_MIX" "$INPUT"
