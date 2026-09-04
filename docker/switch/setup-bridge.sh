#!/bin/bash

# Create a bridge interface to simulate a managed switch
brctl addbr br0 2>/dev/null || true
ip link set br0 up

echo "[switch] Bridge br0 created and up"

# Periodically log MAC table / bridge info (simulates MAC learning events)
(
    while true; do
        # Log bridge port state (simulates MAC learning)
        MAC_TABLE=$(brctl showmacs br0 2>/dev/null | tail -n +2)
        if [ -n "$MAC_TABLE" ]; then
            logger -t switchd "[MAC LEARNING] Bridge br0 table updated: $(echo $MAC_TABLE | wc -l) entries"
        fi

        # Log STP-like events periodically
        logger -t switchd "[STP] Bridge br0: root bridge election cycle"

        # Log port status
        for iface in $(ip link show type bridge_slave 2>/dev/null | grep -oP '^\d+: \K[^@:]+'); do
            STATE=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "unknown")
            logger -t switchd "[PORT] Interface $iface state: $STATE"
        done

        sleep 30
    done
) &

# Generate periodic MAC flapping events for realism
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))
        # Simulate MAC learning events
        FAKE_MAC=$(printf "02:00:00:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
        FAKE_PORT=$((RANDOM % 4 + 1))
        logger -t switchd "[MAC LEARN] learned $FAKE_MAC on br0 port $FAKE_PORT"

        # Occasional MAC flapping event
        if [ $((COUNTER % 10)) -eq 0 ]; then
            FLAP_PORT_A=$((RANDOM % 4 + 1))
            FLAP_PORT_B=$((RANDOM % 4 + 1))
            logger -t switchd "[MAC FLAP] $FAKE_MAC flapping between port $FLAP_PORT_A and port $FLAP_PORT_B"
        fi

        sleep 10
    done
) &

echo "[switch] Log generation started"
