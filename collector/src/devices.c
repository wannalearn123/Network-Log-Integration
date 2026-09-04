#include "devices.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// ============================================================
// Device type detection from hostname
// ============================================================
void detect_device_type(log_entry_t* entry) {
    if (!entry->hostname[0]) {
        snprintf(entry->device_type, sizeof(entry->device_type), "unknown");
        return;
    }

    char host_lower[64];
    int i;
    for (i = 0; entry->hostname[i] && i < 63; i++) {
        host_lower[i] = tolower(entry->hostname[i]);
    }
    host_lower[i] = '\0';

    if (strstr(host_lower, "router"))       snprintf(entry->device_type, sizeof(entry->device_type), "router");
    else if (strstr(host_lower, "switch"))  snprintf(entry->device_type, sizeof(entry->device_type), "switch");
    else if (strstr(host_lower, "ap"))      snprintf(entry->device_type, sizeof(entry->device_type), "ap");
    else if (strstr(host_lower, "firewall")) snprintf(entry->device_type, sizeof(entry->device_type), "firewall");
    else if (strstr(host_lower, "fw"))      snprintf(entry->device_type, sizeof(entry->device_type), "firewall");
    else if (strstr(host_lower, "syslog"))  snprintf(entry->device_type, sizeof(entry->device_type), "syslog");
    else snprintf(entry->device_type, sizeof(entry->device_type), "other");
}

// ============================================================
// Extract field from key=value pattern
// ============================================================
static int extract_kv(const char* msg, const char* key, char* out, int out_size) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "%s=", key);

    const char* start = strstr(msg, pattern);
    if (!start) return 0;
    start += strlen(pattern);

    int i = 0;
    while (*start && *start != ' ' && *start != '\n' && *start != '\t' && i < out_size - 1) {
        out[i++] = *start++;
    }
    out[i] = '\0';
    return i > 0;
}

static int extract_kv_int(const char* msg, const char* key) {
    char buf[32];
    if (extract_kv(msg, key, buf, sizeof(buf))) {
        return atoi(buf);
    }
    return -1;
}

// ============================================================
// Device-type-specific field extraction
// ============================================================
void extract_fields(log_entry_t* entry) {
    const char* msg = entry->raw_line;
    if (!msg[0]) return;

    // Firewall: SRC=, DST=, PROTO=, DPT=
    if (strcmp(entry->device_type, "firewall") == 0) {
        extract_kv(msg, "SRC", entry->src_ip, sizeof(entry->src_ip));
        extract_kv(msg, "DST", entry->dst_ip, sizeof(entry->dst_ip));
        extract_kv(msg, "PROTO", entry->proto, sizeof(entry->proto));
        entry->dst_port = extract_kv_int(msg, "DPT");

        // Detect event type
        if (strstr(msg, "BLOCK") || strstr(msg, "DROP")) {
            snprintf(entry->event, sizeof(entry->event), "fw_block");
        } else if (strstr(msg, "ALLOW") || strstr(msg, "ACCEPT")) {
            snprintf(entry->event, sizeof(entry->event), "fw_allow");
        } else if (strstr(msg, "REJECT")) {
            snprintf(entry->event, sizeof(entry->event), "fw_reject");
        } else if (strstr(msg, "SCAN DETECTED")) {
            snprintf(entry->event, sizeof(entry->event), "scan_detected");
        } else if (strstr(msg, "BRUTE FORCE")) {
            snprintf(entry->event, sizeof(entry->event), "brute_force");
        } else if (strstr(msg, "NAT")) {
            snprintf(entry->event, sizeof(entry->event), "nat_event");
        } else {
            snprintf(entry->event, sizeof(entry->event), "fw_event");
        }
        return;
    }

    // Router
    if (strcmp(entry->device_type, "router") == 0) {
        if (strstr(msg, "Interface")) {
            snprintf(entry->event, sizeof(entry->event), "interface_status");
        } else if (strstr(msg, "Routing table")) {
            snprintf(entry->event, sizeof(entry->event), "route_update");
        } else if (strstr(msg, "NAT conntrack")) {
            snprintf(entry->event, sizeof(entry->event), "nat_conntrack");
        } else if (strstr(msg, "DHCPACK")) {
            snprintf(entry->event, sizeof(entry->event), "dhcp_ack");
            // Extract client IP from DHCPACK
            const char* dhcp_start = strstr(msg, "DHCPACK on ");
            if (dhcp_start) {
                dhcp_start += 11;
                int i = 0;
                while (*dhcp_start && *dhcp_start != ' ' && i < 45) {
                    entry->dst_ip[i++] = *dhcp_start++;
                }
                entry->dst_ip[i] = '\0';
            }
        } else if (strstr(msg, "ROUTE CHANGE")) {
            snprintf(entry->event, sizeof(entry->event), "route_change");
        } else if (strstr(msg, "ROUTER INPUT") || strstr(msg, "ROUTER FORWARD")) {
            snprintf(entry->event, sizeof(entry->event), "packet_log");
            extract_kv(msg, "SRC", entry->src_ip, sizeof(entry->src_ip));
            extract_kv(msg, "DST", entry->dst_ip, sizeof(entry->dst_ip));
            extract_kv(msg, "PROTO", entry->proto, sizeof(entry->proto));
        } else {
            snprintf(entry->event, sizeof(entry->event), "router_event");
        }
        return;
    }

    // Switch
    if (strcmp(entry->device_type, "switch") == 0) {
        if (strstr(msg, "MAC LEARN")) {
            snprintf(entry->event, sizeof(entry->event), "mac_learn");
        } else if (strstr(msg, "MAC FLAP")) {
            snprintf(entry->event, sizeof(entry->event), "mac_flap");
        } else if (strstr(msg, "STP")) {
            snprintf(entry->event, sizeof(entry->event), "stp_event");
        } else if (strstr(msg, "PORT")) {
            snprintf(entry->event, sizeof(entry->event), "port_status");
        } else {
            snprintf(entry->event, sizeof(entry->event), "switch_event");
        }
        return;
    }

    // AP
    if (strcmp(entry->device_type, "ap") == 0) {
        if (strstr(msg, "AP-STA-CONNECTED") || strstr(msg, "authenticated")) {
            snprintf(entry->event, sizeof(entry->event), "client_connect");
        } else if (strstr(msg, "AP-STA-DISCONNECTED") || strstr(msg, "disassociated")) {
            snprintf(entry->event, sizeof(entry->event), "client_disconnect");
        } else if (strstr(msg, "AP-STA-FAILED") || strstr(msg, "Authentication error")) {
            snprintf(entry->event, sizeof(entry->event), "auth_failure");
        } else if (strstr(msg, "AP-STA-DEAUTH")) {
            snprintf(entry->event, sizeof(entry->event), "deauth");
        } else if (strstr(msg, "signal=")) {
            snprintf(entry->event, sizeof(entry->event), "signal_report");
        } else {
            snprintf(entry->event, sizeof(entry->event), "ap_event");
        }
        return;
    }

    // Default
    snprintf(entry->event, sizeof(entry->event), "unknown");
}
