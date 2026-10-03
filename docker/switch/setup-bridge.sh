#!/bin/bash

# Switch log generator — Cisco IOS + Ruijie templates.
# Background noise (MAC learning, occasional flap/STP) stays below rule
# thresholds. The attack loop at the bottom emits insider (east-west)
# bursts — MAC flap storm + STP instability — that the rules engine flags.
# No explicit labels; detection is pattern-based.

# Create a bridge interface to simulate a managed switch
brctl addbr br0 2>/dev/null || true
ip link set br0 up

echo "[switch] Bridge br0 created and up"

# Periodically log MAC table / bridge info (Cisco + Ruijie templates)
(
    while true; do
        BRAND=$((RANDOM % 2)) # 0=cisco, 1=ruijie
        # Log bridge port state (simulates MAC learning)
        MAC_TABLE=$(brctl showmacs br0 2>/dev/null | tail -n +2)
        if [ -n "$MAC_TABLE" ]; then
            logger -t switchd "[MAC LEARNING] Bridge br0 table updated: $(echo $MAC_TABLE | wc -l) entries learned"
        fi

        # Log STP-like events periodically (Ruijie uses same IOS format)
        PORT=$((RANDOM % 8 + 1))
        if [ "$BRAND" -eq 0 ]; then
            logger -t ios "%SPANTREE-5-ROOTCHANGE: Root changed on VLAN1 — new root Gi1/0/$PORT"
        else
            logger -t rgos "%SPANTREE-5-ROOTCHANGE: Root changed on VLAN1 — new root Gi0/$PORT"
        fi

        # Log port status (Ruijie uses same IOS format)
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

# Generate periodic MAC learning/flapping events (Cisco + Ruijie)
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))
        BRAND=$((RANDOM % 2)) # 0=cisco, 1=ruijie
        # Cisco dot-MAC + colon-MAC variants
        DOTMAC=$(printf "%04x.%04x.%04x" $((RANDOM%65536)) $((RANDOM%65536)) $((RANDOM%65536)))
        FAKE_PORT=$((RANDOM % 4 + 1))
        VLAN=$((RANDOM % 20 + 1))
        # Ruijie uses same Cisco IOS mnemonics
        if [ "$BRAND" -eq 0 ]; then
            logger -t ios "%MATM-5-LEARN: Host $DOTMAC learned on Gi1/0/$FAKE_PORT vlan $VLAN"
        else
            logger -t rgos "%MATM-5-LEARN: Host $DOTMAC learned on Gi0/$FAKE_PORT vlan $VLAN"
        fi

        # Occasional MAC flapping event (Ruijie uses same Cisco IOS mnemonic)
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

# Insider attack bursts (lateral / east-west movement inside the LAN).
# A compromised host or rogue switch never touches the firewall, so the
# only trace is here: L2 anomalies. One rotating burst every ~3 min
# (6 x 30s), alternating flap storm <-> STP instability.
# Volumes sit above rule thresholds but far below FLOOD (240/30s):
#   flap storm: 5 flaps of one MAC (needs >=3 for MAC_FLAP)
#   STP burst:  3 root changes (needs >=2 for STP_FLAP)
# Fixed identity per burst so the rules engine groups them; no labels.
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))
        if [ $((COUNTER % 6)) -eq 0 ]; then
            SLOT=$(( (COUNTER / 6) % 2 ))
            # Fixed victim MAC per burst — background noise uses random
            # MACs, so only this identity crosses the threshold.
            VICTIM_MAC="02:aa:aa:bb:cc:dd"
            VLAN=10
            if [ "$SLOT" -eq 0 ]; then
                # --- MAC flap storm: MITM / spoof / loop signature ---
                for _ in $(seq 1 5); do
                    logger -t ios "%SW_MATM-4-MACFLAP_NOTIF: Host $VICTIM_MAC in vlan $VLAN is flapping between port Gi1/0/1 and port Gi1/0/2"
                done
            else
                # --- STP instability: rogue-root / topology flap signature ---
                for PORT in 7 2 7; do
                    logger -t ios "%SPANTREE-5-ROOTCHANGE: Root changed on VLAN1 — new root Gi1/0/$PORT"
                done
            fi
        fi
        sleep 30
    done
) &

echo "[switch] Log generation started"
