#!/bin/bash
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))
        IFACE="ge-0/0/$((1 + RANDOM % 4))"
        VLAN=$((10 + RANDOM % 20))
        MAC=$(printf "%02x:%02x:%02x:%02x:%02x:%02x" $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))
        case $((RANDOM % 3)) in
            0) STATE="down" ;;
            1) STATE="up" ;;
            *) STATE="flap" ;;
        esac
        logger -t aruba "aruba: iface=$IFACE vlan=$VLAN mac=$MAC state=$STATE"
        sleep 1
    done
) &
