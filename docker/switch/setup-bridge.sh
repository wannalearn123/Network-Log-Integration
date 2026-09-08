#!/bin/bash

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

        # Log STP-like events periodically
        if [ "$BRAND" -eq 0 ]; then
            logger -t ios "%SPANTREE-2-BLOCK_PVID_PEER: Blocking port Gi1/0/$((RANDOM % 8 + 1)) - STP root bridge election"
        else
            logger -t rgos "%STP-6-PORT_STATE: Port Gi0/$((RANDOM % 8 + 1)) STP state Forwarding"
        fi

        # Log port status
        for iface in $(ip link show type bridge_slave 2>/dev/null | grep -oP '^\d+: \K[^@:]+'); do
            STATE=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "unknown")
            if [ "$BRAND" -eq 0 ]; then
                logger -t ios "%LINK-3-UPDOWN: Interface $iface, changed state to $STATE"
            else
                logger -t rgos "%LINK-3-UPDOWN: Interface Gi0/$((RANDOM % 8 + 1)) link $STATE"
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
        FAKE_MAC=$(printf "02:00:00:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
        FAKE_PORT=$((RANDOM % 4 + 1))
        VLAN=$((RANDOM % 20 + 1))
        if [ "$BRAND" -eq 0 ]; then
            logger -t ios "%MATM-5-LEARN: Host $DOTMAC learned on Gi1/0/$FAKE_PORT vlan $VLAN"
        else
            logger -t rgos "%MATR-5-LEARN: Mac $DOTMAC learned on Gi0/$FAKE_PORT in VLAN $VLAN"
        fi

        # Occasional MAC flapping event
        if [ $((COUNTER % 10)) -eq 0 ]; then
            FLAP_PORT_A=$((RANDOM % 4 + 1))
            FLAP_PORT_B=$((RANDOM % 4 + 1))
            if [ "$BRAND" -eq 0 ]; then
                logger -t ios "%SW_MATM-4-MACFLAP_NOTIF: Host $DOTMAC in vlan $VLAN is flapping between port Gi1/0/$FLAP_PORT_A and port Gi1/0/$FLAP_PORT_B"
            else
                logger -t rgos "%MACFLAP-4-FLAP_DETECTED: Mac $DOTMAC flap between Gi0/$FLAP_PORT_A and Gi0/$FLAP_PORT_B in VLAN $VLAN"
            fi
        fi

        sleep 10
    done
) &

echo "[switch] Log generation started"
