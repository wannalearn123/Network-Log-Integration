#!/bin/bash

# Switch log generator — Cisco IOS + Ruijie templates (same IOS mnemonics).
# Background noise stays below thresholds; attack bursts at bottom.
# See docker/simulated-traffic.md for thresholds and timing.

# Create a bridge interface to simulate a managed switch
brctl addbr br0 2>/dev/null || true
ip link set br0 up

echo "[switch] Bridge br0 created and up"

# Periodically log MAC table / bridge info
(
    while true; do
        BRAND=$((RANDOM % 2))
        MAC_TABLE=$(brctl showmacs br0 2>/dev/null | tail -n +2)
        if [ -n "$MAC_TABLE" ]; then
            logger -t switchd "[MAC LEARNING] Bridge br0 table updated: $(echo $MAC_TABLE | wc -l) entries learned"
        fi

        # Log STP-like events periodically
        PORT=$((RANDOM % 8 + 1))
        if [ "$BRAND" -eq 0 ]; then
            logger -t ios "%SPANTREE-5-ROOTCHANGE: Root changed on VLAN1 — new root Gi1/0/$PORT"
        else
            logger -t rgos "%SPANTREE-5-ROOTCHANGE: Root changed on VLAN1 — new root Gi0/$PORT"
        fi

        # Log port status
        for iface in $(ip link show type bridge_slave 2>/dev/null | grep -oP '^\d+: \K[^@:]+'); do
            STATE=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "unknown")
            if [ "$BRAND" -eq 0 ]; then
                logger -t ios "%LINK-3-UPDOWN: Interface $iface, changed state to $STATE"
            else
                logger -t rgos "%LINK-3-UPDOWN: Interface $iface, changed state to $STATE"
            fi
        done

        sleep 30
    done
) &

# Generate periodic MAC learning/flapping events
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))
        BRAND=$((RANDOM % 2))
        DOTMAC=$(printf "%04x.%04x.%04x" $((RANDOM%65536)) $((RANDOM%65536)) $((RANDOM%65536)))
        FAKE_PORT=$((RANDOM % 4 + 1))
        VLAN=$((RANDOM % 20 + 1))
        if [ "$BRAND" -eq 0 ]; then
            logger -t ios "%MATM-5-LEARN: Host $DOTMAC learned on Gi1/0/$FAKE_PORT vlan $VLAN"
        else
            logger -t rgos "%MATM-5-LEARN: Host $DOTMAC learned on Gi0/$FAKE_PORT vlan $VLAN"
        fi

        # Occasional MAC flapping event
        if [ $((COUNTER % 10)) -eq 0 ]; then
            FLAP_PORT_A=$((RANDOM % 4 + 1))
            FLAP_PORT_B=$((RANDOM % 4 + 1))
            if [ "$BRAND" -eq 0 ]; then
                logger -t ios "%SW_MATM-4-MACFLAP_NOTIF: Host $DOTMAC in vlan $VLAN is flapping between port Gi1/0/$FLAP_PORT_A and port Gi1/0/$FLAP_PORT_B"
            else
                logger -t rgos "%SW_MATM-4-MACFLAP_NOTIF: Host $DOTMAC in vlan $VLAN is flapping between port Gi0/$FLAP_PORT_A and port Gi0/$FLAP_PORT_B"
            fi
        fi

        sleep 10
    done
) &

# Attack: insider L2 bursts, one every ~3 min (alternating types).
# Fixed MAC per burst so the burst groups; noise uses random MACs.
# See docker/simulated-traffic.md.
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))
        if [ $((COUNTER % 6)) -eq 0 ]; then
            SLOT=$(( (COUNTER / 6) % 2 ))
            VICTIM_MAC="02:aa:aa:bb:cc:dd"
            VLAN=10
            if [ "$SLOT" -eq 0 ]; then
                # MAC flap storm
                for _ in $(seq 1 5); do
                    logger -t ios "%SW_MATM-4-MACFLAP_NOTIF: Host $VICTIM_MAC in vlan $VLAN is flapping between port Gi1/0/1 and port Gi1/0/2"
                done
            else
                # STP instability
                for PORT in 7 2 7; do
                    logger -t ios "%SPANTREE-5-ROOTCHANGE: Root changed on VLAN1 — new root Gi1/0/$PORT"
                done
            fi
        fi
        sleep 30
    done
) &

echo "[switch] Log generation started"
