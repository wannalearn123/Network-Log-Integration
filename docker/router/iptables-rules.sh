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

# Background: generate realistic router log events (Cisco IOS + MikroTik)
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))
        BRAND=$((RANDOM % 2)) # 0=cisco, 1=mikrotik

        # Interface status reports
        for iface in $(ls /sys/class/net/ | grep -v lo); do
            STATE=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "unknown")
            SPEED=$(cat /sys/class/net/$iface/speed 2>/dev/null || echo "N/A")
            if [ "$BRAND" -eq 0 ]; then
                logger -t ios "%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/0 ($iface), changed state to $STATE"
            else
                logger -t interface "interface,info $iface link $STATE"
            fi
        done

        # Route table status
        ROUTES=$(ip route | wc -l)
        NBR="172.20.0.$((1 + RANDOM % 20))"
        if [ "$BRAND" -eq 0 ]; then
            logger -t ios "%OSPF-5-ADJCHG: Process 1, Nbr $NBR on GigabitEthernet0/0 from LOADING to FULL ($ROUTES routes)"
        else
            logger -t route "route,info route added dst-address=172.20.100.0/24 gateway=$NBR ($ROUTES routes)"
        fi

        # NAT connection tracking
        if [ -f /proc/net/nf_conntrack ]; then
            CONNS=$(wc -l < /proc/net/nf_conntrack 2>/dev/null || echo "0")
            if [ "$BRAND" -eq 0 ]; then
                logger -t routerd "NAT conntrack: $CONNS active connections"
            else
                logger -t firewall "firewall,info connection tracking: $CONNS entries"
            fi
        fi

        # Simulated DHCP lease events (both map to dhcp_ack)
        if [ $((COUNTER % 5)) -eq 0 ]; then
            CLIENT_IP="172.20.100.$((1 + RANDOM % 50))"
            MAC="aa:bb:cc:$(printf '%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))"
            if [ "$BRAND" -eq 0 ]; then
                logger -t dhcpd "DHCPACK to $CLIENT_IP ($MAC) via eth0"
            else
                logger -t dhcp "dhcp,info defconf assigned $CLIENT_IP to $MAC"
            fi
        fi

        # Occasional route change events (keep "route change" anchor)
        if [ $((COUNTER % 8)) -eq 0 ]; then
            if [ "$BRAND" -eq 0 ]; then
                logger -t ios "%IP-5-ROUTE_CHANGE: Default route metric adjusted - route change"
            else
                logger -t route "route,info default route change gateway=$NBR"
            fi
        fi

        sleep 15
    done
) &

# Routing-plane attack burst (control-plane compromise).
# A rogue OSPF speaker never appears at L2 or in the data path, and the
# firewall only sees the resulting traffic as ordinary flows — the only
# trace is here, on the router itself.
# One burst every ~3 min (6 x 30s): 8 adjacency resets toward one foreign
# router-id (needs >=6 for ROUTE_CHURN).
# Both brands emit "Nbr <router-id>", which the collector maps to src_ip +
# ospf_nbr, so every row survives the detector's attributable-identity
# filter and the burst attributes to a single peer.
# Volume sits above the rule threshold with ~1.4x headroom (same margin as
# the switch and AP generators) so window alignment jitter can't drop it
# below. Fixed router-id per burst so the rules engine groups it while
# background noise (random neighbours) stays well under.
# No explicit labels; detection is pattern-based.
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))
        if [ $((COUNTER % 6)) -eq 0 ]; then
            # Rogue router-id — background noise uses random neighbours, so
            # only this identity crosses the threshold.
            ROGUE_RID="6.6.6.6"

            # --- OSPF rogue adjacency: foreign router-id keeps forming and
            #     dropping adjacencies (MITM / LS poisoning signature) ---
            for _ in $(seq 1 8); do
                BRAND=$((RANDOM % 2))
                if [ "$BRAND" -eq 0 ]; then
                    logger -t ios "%OSPF-5-ADJCHG: Process 1, Nbr $ROGUE_RID on GigabitEthernet0/0 from FULL to DOWN, reason: bad neighbor"
                else
                    logger -t route "ospf,info neighbor $ROGUE_RID state change from Full to Down on GigabitEthernet0/0"
                fi
            done
        fi
        sleep 30  # 6 iters x 30s = one burst every ~3 min
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
