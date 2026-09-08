#!/bin/bash

# Simulates hostapd/wpa_supplicant-style authentication logs
# Since real hostapd needs wireless hardware, we simulate the log output

DEVICE_NAMES=("laptop-01" "phone-02" "tablet-03" "printer-04" "iot-cam-05" \
              "laptop-06" "phone-07" "smart-tv-08" "workstation-09" "tablet-10")
CLIENT_IPS=("172.20.100.1" "172.20.100.2" "172.20.100.3" "172.20.100.4" "172.20.100.5" \
             "172.20.100.6" "172.20.100.7" "172.20.100.8" "172.20.100.9" "172.20.100.10")

generate_mac() {
    printf "aa:bb:cc:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
}

generate_dotmac() {
    printf "%04x.%04x.%04x" $((RANDOM%65536)) $((RANDOM%65536)) $((RANDOM%65536))
}

echo "[ap] Starting auth simulation (hostapd + Ruijie)"

# Simulate initial client associations (alternate brands)
sleep 5
for i in 0 1 2 3 4; do
    MAC=$(generate_mac)
    DOTMAC=$(generate_dotmac)
    if [ $((i % 2)) -eq 0 ]; then
        logger -t hostapd "wlan0: AP-STA-CONNECTED $MAC"
        logger -t wpa_supplicant "Station $MAC associated to wlan0"
    else
        logger -t DOT11 "DOT11-6-ASSOC: Station $DOTMAC associated to WLAN wlan1 (SSID Campus)"
        logger -t DOT11 "STA $DOTMAC authentication success"
    fi
done

# Ongoing simulation (dual-brand: 0-4 hostapd, 5-9 ruijie equivalents)
(
    while true; do
        IDX=$((RANDOM % ${#DEVICE_NAMES[@]}))
        MAC=$(generate_mac)
        DOTMAC=$(generate_dotmac)
        EVENT=$((RANDOM % 10))

        case $EVENT in
            0)
                # New client association (hostapd)
                logger -t hostapd "wlan0: AP-STA-CONNECTED $MAC"
                logger -t wpa_supplicant "wlan0: STA $MAC IEEE 802.11: associated"
                ;;
            1)
                # Client disassociation (hostapd)
                logger -t hostapd "wlan0: AP-STA-DISCONNECTED $MAC reason=3"
                logger -t wpa_supplicant "Station $MAC disassociated (reason=3)"
                ;;
            2)
                # Authentication failure (hostapd)
                ATTEMPT_MAC=$(generate_mac)
                logger -t hostapd "wlan0: AP-STA-FAILED $ATTEMPT_MAC status=1 invalid_auth"
                logger -t wpa_supplicant "Authentication error for $ATTEMPT_MAC: Invalid credentials"
                ;;
            3)
                # Deauthentication (hostapd)
                logger -t hostapd "wlan0: AP-STA-DEAUTH $MAC reason=4"
                ;;
            4)
                # Normal activity: signal strength report (shared)
                SIGNAL=$((20 + RANDOM % 60))
                logger -t hostapd "wlan0: Station $MAC signal=$SIGNAL dBm tx_rate=$((1 + RANDOM % 54))Mbps"
                ;;
            5)
                # New client association (Ruijie)
                logger -t DOT11 "DOT11-6-ASSOC: Station $DOTMAC associated to WLAN wlan1 (SSID Campus)"
                logger -t DOT11 "STA $DOTMAC authentication success"
                ;;
            6)
                # Client disassociation (Ruijie)
                logger -t DOT11 "DOT11-6-DISASSOC: Station $DOTMAC disassociated (reason=3)"
                ;;
            7)
                # Authentication failure (Ruijie)
                ATTEMPT_DOT=$(generate_dotmac)
                logger -t DOT11 "DOT11-4-AUTH_FAILED: Station $ATTEMPT_DOT authentication failed"
                ;;
            8)
                # Deauthentication (Ruijie)
                logger -t DOT11 "DOT11-6-DEAUTH: Station $DOTMAC deauthenticated (reason=4)"
                ;;
            9)
                # WPA handshake completed (hostapd vendor-real)
                logger -t hostapd "wlan0: STA $MAC WPA: pairwise key handshake completed"
                ;;
        esac

        sleep $((5 + RANDOM % 10))
    done
) &

echo "[ap] Auth simulation running in background"
