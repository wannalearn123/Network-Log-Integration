#!/bin/bash
# Palo Alto PAN-OS traffic log generator. Different envelope from every other
# simulator, so the built-in extractor can do nothing and a parser profile is
# genuinely required.
#
# Envelope: ISO timestamp host event=traffic subtype=DENY|END state=deny|allow|close|drop src=172.20.x.y sport=port dport=proto=DSTIP=/SRCIP=
# Every key is one word with =, including src/dst as srcip/dstip and sport/dport (not SPT/DPT).
# No field names overlap with built-in extractors except `src`/`dst` but we use `srcip`/`dstip`.

HOSTNAME="pa-edge1"
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))

        # Single steady-state traffic line, no bursts yet.
        SRCP="172.20.0.50"
        DSTP="172.20.0.4"
        SPORT=$((1024 + RANDOM % 50000))
        DPORT=$((RANDOM % 50000 + 1024))
        case $((RANDOM % 3)) in
            0) PROTO="TCP" ;;
            1) PROTO="UDP" ;;
            *) PROTO="ICMP" ;;
        esac
        STATE="allow"; STATE="allow"
        case $((RANDOM % 5)) in
            0) STATE="close" ;;
            1) STATE="drop" ;;
            *) STATE="deny" ;;
        esac
        # Reject deny lines ~60% of the time so anomaly rules stay quiet until bursts are added later.
        if [ $((RANDOM % 10)) -lt 5 ]; then STATE="allow"; fi

        logger -t "pa-pulse" "$HOSTNAME event=traffic subtype=$STATE state=$STATE srcip=$SRCP dstip=$DSTP sport=$SPORT dport=$DPORT proto=$PROTO"
        sleep 1
    done
) &
