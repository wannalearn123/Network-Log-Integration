#!/bin/bash

# Firewall log generator — realistic traffic patterns
# Produces iptables kernel logs and FortiGate CEF logs.
# Attacks are represented as traffic patterns, NOT explicit labels.
# Detection depends on pattern analysis by rules engine + ML.
#
# Attack frequency (demo mode):
#   Rotating attack every ~3 min: scan -> brute -> DDoS-lite
#   Volumes set above rule thresholds so detector flags each one.
#
# Normal traffic still dominates background events.

# Pool of attacker IPs — one is picked at random per attack burst.
# .50/.51 are log labels only (no real containers), free of collisions
# with the Docker LAN (.2 .3 .4 .10 .11 .20).
ATTACKER_IPS=("172.20.0.50" "172.20.0.51")

# Normal firewall events (background loop)
# Produces regular fw_allow/fw_block/fw_reject entries with src_ip and dst_port so rules engine can detect patterns
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))

        # Connection tracking stats (occasional, no src_ip needed)
        if [ -f /proc/net/nf_conntrack ]; then
            CONNS=$(wc -l < /proc/net/nf_conntrack 2>/dev/null || echo "0")
            logger -t fwdaemon "Connection tracking: $CONNS entries"
        fi

        # Simulated rule evaluations — dual-brand normal traffic
        # 0=iptables kernel form, 1=FortiGate form
        # Every iteration produces a firewall event with src_ip and dst_port
        ACTIONS=("ALLOW" "DROP" "REJECT")
        PROTOS=("TCP" "UDP" "ICMP")
        SRC_IPS=("172.20.100.1" "172.20.100.5" "172.20.100.10" "172.20.100.25" "172.20.100.48")
        DST_PORTS=(22 80 443 53 514 8080 3306)

        ACTION=${ACTIONS[$((RANDOM % 3))]}
        PROTO=${PROTOS[$((RANDOM % 3))]}
        SRC=${SRC_IPS[$((RANDOM % ${#SRC_IPS[@]}))]}
        DST_PORT=${DST_PORTS[$((RANDOM % ${#DST_PORTS[@]}))]}
        SPT=$((1024 + RANDOM % 60000))
        BRAND=$((RANDOM % 2))

        if [ "$BRAND" -eq 0 ]; then
            # iptables/nftables kernel form (SRC=/DPT=)
            logger -t kernel "[FW $ACTION] IN=eth0 OUT= SRC=$SRC DST=172.20.0.4 PROTO=$PROTO SPT=$SPT DPT=$DST_PORT"
        else
            # FortiGate CEF traffic log (real format)
            case "$PROTO" in
                TCP) PNUM=6;; UDP) PNUM=17;; *) PNUM=1;;
            esac
            case "$ACTION" in
                ALLOW) ACT=close; ACT_TEXT="allow";;
                DROP)  ACT=deny;  ACT_TEXT="deny";;
                *)     ACT=deny;  ACT_TEXT="deny";;
            esac
            LOGID=$(printf '%010d' $COUNTER)
            DEVID=$(printf '%012d' $((COUNTER + RANDOM % 10000)))
            logger -t fortigate "CEF: 0|Fortinet|FortiGate|v7.0.0|00010|traffic:forward $ACT_TEXT|3|deviceExternalId=FGT100F$DEVID FTNTFGTlogid=$LOGID cat=traffic:forward src=$SRC dst=172.20.0.4 spt=$SPT dpt=$DST_PORT proto=$PNUM act=$ACT"
        fi

        # NAT events (less frequent, no src_ip needed)
        if [ $((COUNTER % 5)) -eq 0 ]; then
            NAT_SRC="172.20.100.$((1 + RANDOM % 50))"
            logger -t fwdaemon "[NAT] $NAT_SRC -> masqueraded via 172.20.0.4"
        fi

        sleep 1  # Produce firewall event every second (60/min)
    done
) &

# Attack patterns (background loop)
# Generates realistic traffic patterns that rules engine detects.
# NO explicit labels — detection is pattern-based.
#
# Attack frequency (demo mode):
#   One rotating attack every ~3 min: scan -> brute -> DDoS-lite
#   Volumes set above rule thresholds so each one flags.
#
# Normal traffic still dominates background events.

(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))

        # One attack every 6 x 30s = ~3 min, rotating type
        if [ $((COUNTER % 6)) -eq 0 ]; then
            # One attacker per burst: the whole burst keeps a single src_ip
            # so per-IP rule thresholds (>=12 ports / >=12 fails) still fire.
            ATTACKER_IP=${ATTACKER_IPS[$((RANDOM % ${#ATTACKER_IPS[@]}))]}
            ATTACK_SLOT=$(( (COUNTER / 6) % 3 ))

            # --- Port scan: 20 unique ports, needs >=12 for PORT_SCAN ---
            if [ "$ATTACK_SLOT" -eq 0 ]; then
                for SCAN_PORT in $(seq 4000 4019); do
                    SCAN_SPT=$((1024 + RANDOM % 60000))
                    BRAND=$((RANDOM % 2))
                    if [ "$BRAND" -eq 0 ]; then
                        logger -t kernel "[FW DROP] IN=eth0 SRC=$ATTACKER_IP DST=172.20.0.4 PROTO=TCP SPT=$SCAN_SPT DPT=$SCAN_PORT"
                    else
                        logger -t fortigate "CEF: 0|Fortinet|FortiGate|v7.0.0|00010|traffic:forward deny|3|deviceExternalId=FGT100F0000000013 FTNTFGTlogid=0000000013 cat=traffic:forward src=$ATTACKER_IP dst=172.20.0.4 spt=$SCAN_SPT dpt=$SCAN_PORT proto=6 act=deny"
                    fi
                done
            fi

            # --- Brute force: 20 attempts to :22, needs >=12 for BRUTE_FORCE ---
            if [ "$ATTACK_SLOT" -eq 1 ]; then
                for _ in $(seq 1 20); do
                    AUTH_SPT=$((1024 + RANDOM % 60000))
                    BRAND=$((RANDOM % 2))
                    if [ "$BRAND" -eq 0 ]; then
                        logger -t kernel "[FW DROP] IN=eth0 SRC=$ATTACKER_IP DST=172.20.0.4 PROTO=TCP SPT=$AUTH_SPT DPT=22"
                    else
                        logger -t fortigate "CEF: 0|Fortinet|FortiGate|v7.0.0|00010|traffic:forward deny|3|deviceExternalId=FGT100F0000000013 FTNTFGTlogid=0000000013 cat=traffic:forward src=$ATTACKER_IP dst=172.20.0.4 spt=$AUTH_SPT dpt=22 proto=6 act=deny"
                    fi
                done
            fi

            # --- DDoS-lite: 150 packets to :80, needs >=100 for HIGH_DROP_RATE ---
            if [ "$ATTACK_SLOT" -eq 2 ]; then
                for _ in $(seq 1 260); do
                    FLOOD_SPT=$((1024 + RANDOM % 60000))
                    BRAND=$((RANDOM % 2))
                    if [ "$BRAND" -eq 0 ]; then
                        logger -t kernel "[FW DROP] IN=eth0 SRC=$ATTACKER_IP DST=172.20.0.4 PROTO=TCP SPT=$FLOOD_SPT DPT=80 SYN"
                    else
                        logger -t fortigate "CEF: 0|Fortinet|FortiGate|v7.0.0|00010|traffic:forward deny|3|deviceExternalId=FGT100F0000000013 FTNTFGTlogid=0000000013 cat=traffic:forward src=$ATTACKER_IP dst=172.20.0.4 spt=$FLOOD_SPT dpt=80 proto=6 act=deny"
                    fi
                done
            fi
        fi

        sleep 30  # 6 iters x 30s = one attack every ~3 min
    done
) &

# Generate some traffic to trigger nftables LOG rules
# (real packets through the firewall, not just logger)

(
    while true; do
        # TCP connections to trigger forward chain logging
        nc -z -w1 172.20.0.10 514 2>/dev/null
        sleep 25
    done
) &

echo "[firewall] Log generation started — realistic traffic patterns"
