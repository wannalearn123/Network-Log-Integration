#!/bin/bash

# Simulates hostapd/wpa_supplicant-style authentication logs
# Since real hostapd needs wireless hardware, we simulate the log output
# Background noise stays below rule thresholds; the attack loop at the
# bottom emits insider WiFi bursts (deauth storm + auth brute-force).

generate_mac() {
    printf "aa:bb:cc:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
}

generate_dotmac() {
    printf "%04x.%04x.%04x" $((RANDOM%65536)) $((RANDOM%65536)) $((RANDOM%65536))
}

echo "[ap] Starting auth simulation (hostapd + Ruijie)"

# Simulate initial client associations (alternate brands)
sleep 5
for i in $(seq 0 4); do
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
                logger -t hostapd "wlan0: Station $MAC signal=$((20 + RANDOM % 60)) dBm tx_rate=$((1 + RANDOM % 54))Mbps"
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

# Insider WiFi attack bursts (lateral / over-the-air).
# A deauth flood needs no LAN access at all — frames are unauthenticated —
# and password guessing hits the AP directly, so the firewall never sees
# either. One rotating burst every ~3 min (6 x 30s):
#   deauth storm: 12x from one MAC (needs >=9 for DEAUTH_STORM, MEDIUM)
#   auth brute:   15x failures, one MAC (needs >=12 for BRUTE_FORCE, CRITICAL)
# Fixed identity per burst so the rules engine groups them; no labels.
(
    COUNTER=0
    while true; do
        COUNTER=$((COUNTER + 1))
        if [ $((COUNTER % 6)) -eq 0 ]; then
            SLOT=$(( (COUNTER / 6) % 2 ))
            # Fixed target MAC — background noise uses random MACs.
            TARGET_MAC="aa:bb:cc:99:88:77"
            if [ "$SLOT" -eq 0 ]; then
                # --- Deauth storm: DoS / evil-twin setup signature ---
                for _ in $(seq 1 12); do
                    logger -t hostapd "wlan0: AP-STA-DEAUTH $TARGET_MAC reason=4"
                done
            else
                # --- Auth brute-force: PSK/EAP guessing signature ---
                for _ in $(seq 1 15); do
                    logger -t hostapd "wlan0: AP-STA-FAILED $TARGET_MAC status=1 invalid_auth"
                done
            fi
        fi
        sleep 30
    done
) &

echo "[ap] Auth simulation running in background"
