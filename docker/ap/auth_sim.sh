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

echo "[ap] Starting auth simulation"

# Simulate initial client associations
sleep 5
for i in 0 1 2 3 4; do
    MAC=$(generate_mac)
    logger -t hostapd "wlan0: AP-STA-CONNECTED $MAC ${CLIENT_IPS[$i]} ${DEVICE_NAMES[$i]}"
    logger -t wpa_supplicant "Station $MAC associated with ${DEVICE_NAMES[$i]}"
done

# Ongoing simulation
(
    while true; do
        IDX=$((RANDOM % ${#DEVICE_NAMES[@]}))
        MAC=$(generate_mac)
        EVENT=$((RANDOM % 5))

        case $EVENT in
            0)
                # New client association
                logger -t hostapd "wlan0: AP-STA-CONNECTED $MAC ${CLIENT_IPS[$IDX]} ${DEVICE_NAMES[$IDX]}"
                logger -t wpa_supplicant "Station $MAC authenticated with ${DEVICE_NAMES[$IDX]}"
                ;;
            1)
                # Client disassociation
                logger -t hostapd "wlan0: AP-STA-DISCONNECTED $MAC reason=3 ${DEVICE_NAMES[$IDX]}"
                logger -t wpa_supplicant "Station $MAC disassociated (reason=3)"
                ;;
            2)
                # Authentication failure (simulates wrong password attempt)
                ATTEMPT_MAC=$(generate_mac)
                logger -t hostapd "wlan0: AP-STA-FAILED $ATTEMPT_MAC status=1 invalid_auth"
                logger -t wpa_supplicant "Authentication error for $ATTEMPT_MAC: Invalid credentials"
                ;;
            3)
                # Deauthentication
                logger -t hostapd "wlan0: AP-STA-DEAUTH $MAC reason=4 ${DEVICE_NAMES[$IDX]}"
                ;;
            4)
                # Normal activity: signal strength report
                SIGNAL=$((20 + RANDOM % 60))
                logger -t hostapd "wlan0: Station $MAC signal=$SIGNAL dBm tx_rate=$((1 + RANDOM % 54))Mbps"
                ;;
        esac

        sleep $((5 + RANDOM % 10))
    done
) &

echo "[ap] Auth simulation running in background"
