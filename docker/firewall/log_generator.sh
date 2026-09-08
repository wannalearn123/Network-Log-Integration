#!/bin/bash

# ============================================================
# Firewall log generator — normal traffic + attack detection
# All attack logs come from the firewall, as they would in a
# real network where the firewall is the detection point.
# ============================================================

ATTACKER_IP="172.20.0.50"

# ------------------------------------------------------------
# Normal firewall events (background loop)
# ------------------------------------------------------------
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))

        # Connection tracking stats
        if [ -f /proc/net/nf_conntrack ]; then
            CONNS=$(wc -l < /proc/net/nf_conntrack 2>/dev/null || echo "0")
            logger -t fwdaemon "Connection tracking: $CONNS entries"
        fi

        # Simulated rule evaluations — dual-brand normal traffic
        # 0=iptables kernel form, 1=FortiGate form
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
            # FortiGate FortiOS form (srcip=/dstport=, proto number)
            case "$PROTO" in
                TCP) PNUM=6;; UDP) PNUM=17;; *) PNUM=1;;
            esac
            case "$ACTION" in
                ALLOW) FACT=accept;; DROP) FACT=deny;; *) FACT=deny;;
            esac
            logger -t fortigate "date=2026-09-08 devname=FG100F action=$FACT srcip=$SRC dstip=172.20.0.4 proto=$PNUM dstport=$DST_PORT policyid=1"
        fi

        # NAT events
        if [ $((COUNTER % 4)) -eq 0 ]; then
            NAT_SRC="172.20.100.$((1 + RANDOM % 50))"
            logger -t fwdaemon "[NAT] $NAT_SRC -> masqueraded via 172.20.0.4"
        fi

        sleep 10
    done
) &

# ------------------------------------------------------------
# Attack detection events (background loop)
# Simulates what a real firewall would detect and log
# ------------------------------------------------------------
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))

        # --- Port scan detection ---
        if [ $((COUNTER % 7)) -eq 0 ]; then
            PORTS_SCANNED=$((5 + RANDOM % 20))
            DURATION=$((1 + RANDOM % 5))
            logger -t fwdaemon "[SCAN DETECTED] Port scan from $ATTACKER_IP - $PORTS_SCANNED ports in ${DURATION}s"
            # Per-packet evidence burst (dual-counts as drop+scan)
            for _ in $(seq 1 $((3 + RANDOM % 5))); do
                SCAN_PORT=$((1 + RANDOM % 1024))
                SCAN_SPT=$((1024 + RANDOM % 60000))
                if [ $((RANDOM % 2)) -eq 0 ]; then
                    logger -t kernel "[FW BLOCK SCAN] IN=eth0 SRC=$ATTACKER_IP DST=172.20.0.4 PROTO=TCP SPT=$SCAN_SPT DPT=$SCAN_PORT"
                else
                    logger -t fortigate "date=2026-09-08 devname=FG100F action=deny srcip=$ATTACKER_IP dstip=172.20.0.4 proto=6 dstport=$SCAN_PORT policyid=1 scan detected"
                fi
            done

            # Sometimes accompanied by brute force
            AUTH_FAILURES=$((RANDOM % 15))
            if [ "$AUTH_FAILURES" -gt 8 ]; then
                logger -t fwdaemon "[BRUTE FORCE] $AUTH_FAILURES failed SSH attempts from $ATTACKER_IP"
            fi
        fi

        # --- SYN flood detection ---
        if [ $((COUNTER % 12)) -eq 0 ]; then
            PKT_COUNT=$((200 + RANDOM % 800))
            logger -t fwdaemon "[DDOS DETECTED] SYN flood from $ATTACKER_IP - $PKT_COUNT packets in 10s"
        fi

        # --- ARP spoofing detection ---
        if [ $((COUNTER % 15)) -eq 0 ]; then
            SPOOFED_IP="172.20.0.$((1 + RANDOM % 20))"
            logger -t fwdaemon "[ARP SPOOF] $ATTACKER_IP is claiming gateway $SPOOFED_IP - duplicate MAC detected"
        fi

        # --- DNS spoofing detection ---
        if [ $((COUNTER % 18)) -eq 0 ]; then
            FAKE_DOMAINS=("google.com" "github.com" "microsoft.com" "cloudflare.com")
            DOMAIN=${FAKE_DOMAINS[$((RANDOM % ${#FAKE_DOMAINS[@]}))]}
            logger -t fwdaemon "[DNS SPOOF] forged reply for $DOMAIN -> $ATTACKER_IP from 172.20.0.1"
        fi

        # --- Rogue DHCP server ---
        if [ $((COUNTER % 20)) -eq 0 ]; then
            ROGUE_IP="172.20.100.$((1 + RANDOM % 50))"
            logger -t fwdaemon "[ROGUE DHCP] unauthorized DHCP offer from $ATTACKER_IP serving $ROGUE_IP"
        fi

        # --- VLAN hopping attempt ---
        if [ $((COUNTER % 25)) -eq 0 ]; then
            PORT=$((RANDOM % 8 + 1))
            logger -t fwdaemon "[VLAN HOP] double-tagged frame from $ATTACKER_IP on port $PORT - blocked"
        fi

        # --- Brute force web login ---
        if [ $((COUNTER % 10)) -eq 0 ]; then
            ATTEMPTS=$((10 + RANDOM % 40))
            TARGET_PORT=$((RANDOM % 2 == 0 ? 80 : 443))
            logger -t fwdaemon "[BRUTE FORCE] $ATTEMPTS failed HTTP login attempts from $ATTACKER_IP to port $TARGET_PORT"
        fi

        sleep 8
    done
) &

# ------------------------------------------------------------
# Generate some traffic to trigger nftables LOG rules
# (real packets through the firewall, not just logger)
# ------------------------------------------------------------
(
    while true; do
        # TCP connections to trigger forward chain logging
        nc -z -w1 172.20.0.10 514 2>/dev/null
        sleep 25
    done
) &

echo "[firewall] Log generation started — normal + attack detection"
