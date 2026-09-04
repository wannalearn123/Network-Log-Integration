#!/bin/bash

# Enable IP forwarding (may fail in Docker without --privileged, that's OK)
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "[router] Warning: could not enable IP forwarding"

# Flush existing rules
iptables -F
iptables -t nat -F

# Set default policies
iptables -P FORWARD ACCEPT
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT

# NAT for the building LAN
iptables -t nat -A POSTROUTING -s 172.20.0.0/16 -o eth0 -j MASQUERADE

# Log forwarding/INPUT activity
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "[ROUTER INPUT] " --log-level 4
iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "[ROUTER FORWARD] " --log-level 4

echo "[router] iptables rules applied"

# Background: generate realistic router log events
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))

        # Interface status reports
        for iface in $(ls /sys/class/net/ | grep -v lo); do
            STATE=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "unknown")
            SPEED=$(cat /sys/class/net/$iface/speed 2>/dev/null || echo "N/A")
            logger -t routerd "Interface $iface: state=$STATE speed=${SPEED}Mbps"
        done

        # Route table status
        ROUTES=$(ip route | wc -l)
        logger -t routerd "Routing table: $ROUTES entries active"

        # NAT connection tracking
        if [ -f /proc/net/nf_conntrack ]; then
            CONNS=$(wc -l < /proc/net/nf_conntrack 2>/dev/null || echo "0")
            logger -t routerd "NAT conntrack: $CONNS active connections"
        fi

        # Simulated DHCP lease events
        if [ $((COUNTER % 5)) -eq 0 ]; then
            CLIENT_IP="172.20.100.$((1 + RANDOM % 50))"
            logger -t dhcpd "DHCPACK on $CLIENT_IP to aa:bb:cc:$(printf '%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))"
        fi

        # Occasional route change events
        if [ $((COUNTER % 8)) -eq 0 ]; then
            logger -t routerd "[ROUTE CHANGE] Default route metric adjusted"
        fi

        sleep 15
    done
) &

# Generate some traffic to trigger iptables LOG rules
(
    while true; do
        # Ping other devices (triggers INPUT LOG rule)
        ping -c 1 -W 1 172.20.0.2 >/dev/null 2>&1
        ping -c 1 -W 1 172.20.0.3 >/dev/null 2>&1
        sleep 20
    done
) &
