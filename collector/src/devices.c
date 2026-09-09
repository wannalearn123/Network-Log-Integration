#include "devices.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Device type detection from hostname.
// Token match: split on .-_, match exactly or followed by digits.
static int host_has_token(const char *host_lower, const char *tok) {
    size_t tlen = strlen(tok);
    const char *p = host_lower;
    while (*p) {
        while (*p == '.' || *p == '-' || *p == '_') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != '.' && *e != '-' && *e != '_') e++;
        size_t len = (size_t)(e - p);
        if (len >= tlen && strncmp(p, tok, tlen) == 0) {
            int ok = 1;
            for (size_t i = tlen; i < len; i++) {
                if (!isdigit((unsigned char)p[i])) { ok = 0; break; }
            }
            if (ok) return 1;
        }
        p = e;
    }
    return 0;
}

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
    else if (host_has_token(host_lower, "ap")) snprintf(entry->device_type, sizeof(entry->device_type), "ap");
    else if (strstr(host_lower, "firewall")) snprintf(entry->device_type, sizeof(entry->device_type), "firewall");
    else if (strstr(host_lower, "fw"))      snprintf(entry->device_type, sizeof(entry->device_type), "firewall");
    else if (strstr(host_lower, "syslog"))  snprintf(entry->device_type, sizeof(entry->device_type), "syslog");
    else snprintf(entry->device_type, sizeof(entry->device_type), "other");
}

// Case-insensitive key=value extraction. Value ends at space, comma, bracket, etc.
static const char *find_kv_key(const char *msg, const char *key) {
    size_t klen = strlen(key);
    for (const char *p = msg; *p; p++) {
        size_t i;
        for (i = 0; i < klen && p[i]; i++) {
            if (tolower((unsigned char)p[i]) != tolower((unsigned char)key[i]))
                break;
        }
        if (i == klen && p[i] == '=')
            return p + klen + 1;
    }
    return NULL;
}

static int is_value_end(char c) {
    return c == '\0' || c == ' ' || c == '\n' || c == '\r' || c == '\t' ||
           c == ',' || c == ';' || c == ']' || c == ')' || c == '"' || c == '\'';
}

static int extract_kv(const char* msg, const char* key, char* out, int out_size) {
    const char* start = find_kv_key(msg, key);
    if (!start) return 0;

    int i = 0;
    while (*start && !is_value_end(*start) && i < out_size - 1) {
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

// Device-agnostic field extraction. device_type used only for fallback event names.

static void to_lower_copy(const char *src, char *dst, size_t n) {
    size_t i;
    for (i = 0; src[i] && i + 1 < n; i++)
        dst[i] = tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

static int contains_ci(const char *haystack_low, const char *needle_low) {
    return strstr(haystack_low, needle_low) != NULL;
}

// Whole-word match to avoid false positives like "accept" containing "cp".
static int contains_word(const char *low, const char *word) {
    size_t wlen = strlen(word);
    const char *p = low;
    while ((p = strstr(p, word)) != NULL) {
        char before = (p == low) ? ' ' : *(p - 1);
        char after = *(p + wlen);
        if (!isalnum((unsigned char)before) && !isalnum((unsigned char)after))
            return 1;
        p++;
    }
    return 0;
}

static int valid_ipv4(const char *s, int len, char *out, int out_size) {
    if (len < 7 || len > 15 || len >= out_size) return 0;
    char tmp[16];
    memcpy(tmp, s, len);
    tmp[len] = '\0';
    int a, b, c, d;
    char extra;
    if (sscanf(tmp, "%d.%d.%d.%d%c", &a, &b, &c, &d, &extra) != 4) return 0;
    if (a < 0 || a > 255 || b < 0 || b > 255 ||
        c < 0 || c > 255 || d < 0 || d > 255) return 0;
    snprintf(out, out_size, "%d.%d.%d.%d", a, b, c, d);
    return 1;
}

// Collect up to 2 IPv4 addresses in message order.
static int collect_ips(const char *msg, char ip0[46], char ip1[46]) {
    int found = 0;
    for (const char *p = msg; *p; p++) {
        if (!isdigit((unsigned char)*p)) continue;
        // Candidate: digits and dots, max 15 chars
        const char *q = p;
        while (*q && (isdigit((unsigned char)*q) || *q == '.') &&
               (q - p) < 15) q++;
        int len = (int)(q - p);
        char norm[46];
        if (valid_ipv4(p, len, norm, sizeof(norm))) {
            if (found == 0) snprintf(ip0, 46, "%s", norm);
            else if (found == 1) snprintf(ip1, 46, "%s", norm);
            found++;
            if (found >= 2) return found;
            p = q - 1;
        }
    }
    return found;
}

// Generic port extraction: DPT=/dport/dstport > "port N" > ":PORT" after "->".
static int extract_port_generic(const char *msg, const char *low) {
    int v = extract_kv_int(msg, "DPT");
    if (v > 0 && v <= 65535) return v;
    v = extract_kv_int(msg, "DPORT");
    if (v > 0 && v <= 65535) return v;
    v = extract_kv_int(msg, "DSTPORT"); // FortiGate dstport=
    if (v > 0 && v <= 65535) return v;
    v = extract_kv_int(msg, "DST-PORT"); // MikroTik dst-port=
    if (v > 0 && v <= 65535) return v;

    const char *pp = strstr(low, "port ");
    if (pp) {
        pp += 5;
        while (*pp == ' ') pp++;
        int p2 = atoi(pp);
        if (p2 > 0 && p2 <= 65535) return p2;
    }

    // ":PORT" after "->" (e.g. "a -> b:53")
    const char *arrow = strstr(msg, "->");
    if (arrow) {
        const char *colon = strrchr(arrow, ':');
        if (colon) {
            int p2 = atoi(colon + 1);
            if (p2 > 0 && p2 <= 65535) return p2;
        }
    }
    return -1;
}

// Generic proto: PROTO= (name or number) > bare TCP/UDP/ICMP word.
static void extract_proto_generic(const char *msg, const char *low,
                                  char *out, int out_size) {
    char buf[16];
    if (extract_kv(msg, "PROTO", buf, sizeof(buf))) {
        if (contains_ci(low, "proto=tcp") || strcmp(buf, "6") == 0)
            snprintf(out, out_size, "TCP");
        else if (contains_ci(low, "proto=udp") || strcmp(buf, "17") == 0)
            snprintf(out, out_size, "UDP");
        else if (contains_ci(low, "proto=icmp") || strcmp(buf, "1") == 0)
            snprintf(out, out_size, "ICMP");
        else
            snprintf(out, out_size, "%.7s", buf);
        return;
    }
    // Whole-word match to avoid "accept" containing "cp".
    const char *words[] = {"tcp", "udp", "icmp"};
    const char *names[] = {"TCP", "UDP", "ICMP"};
    for (int w = 0; w < 3; w++) {
        const char *p = low;
        while ((p = strstr(p, words[w])) != NULL) {
            char before = (p == low) ? ' ' : *(p - 1);
            char after = *(p + strlen(words[w]));
            if (!isalnum((unsigned char)before) && !isalnum((unsigned char)after)) {
                snprintf(out, out_size, "%s", names[w]);
                return;
            }
            p++;
        }
    }
}

void extract_fields(log_entry_t* entry) {
    const char* msg = entry->raw_line;
    if (!msg || !msg[0]) return;

    size_t msg_len = strlen(msg);
    char *low = malloc(msg_len + 1);
    if (!low) return;
    to_lower_copy(msg, low, msg_len + 1);

    entry->dst_port = -1;

    // Structured k=v extraction (iptables / FortiGate / MikroTik aliases).
    extract_kv(msg, "SRC", entry->src_ip, sizeof(entry->src_ip));
    extract_kv(msg, "DST", entry->dst_ip, sizeof(entry->dst_ip));
    if (!entry->src_ip[0])
        extract_kv(msg, "SRCIP", entry->src_ip, sizeof(entry->src_ip));
    if (!entry->dst_ip[0])
        extract_kv(msg, "DSTIP", entry->dst_ip, sizeof(entry->dst_ip));
    if (!entry->src_ip[0])
        extract_kv(msg, "SRC-ADDRESS", entry->src_ip, sizeof(entry->src_ip));
    if (!entry->dst_ip[0])
        extract_kv(msg, "DST-ADDRESS", entry->dst_ip, sizeof(entry->dst_ip));
    char *colon = strchr(entry->src_ip, ':');
    if (colon) *colon = '\0';
    colon = strchr(entry->dst_ip, ':');
    if (colon) *colon = '\0';
    extract_proto_generic(msg, low, entry->proto, sizeof(entry->proto));
    entry->dst_port = extract_port_generic(msg, low);

    // Fallback: positional IPs.
    if (!entry->src_ip[0] && !entry->dst_ip[0]) {
        char ip0[46] = "", ip1[46] = "";
        int n = collect_ips(msg, ip0, ip1);
        if (n == 1) {
            if (contains_ci(low, "dhcpack") || contains_ci(low, "dhcp") ||
                contains_ci(low, "assigned") || contains_ci(low, "lease") ||
                contains_ci(low, "connected") ||
                contains_ci(low, "associated") || contains_ci(low, "authenticated") ||
                contains_ci(low, "learned")) {
                snprintf(entry->dst_ip, sizeof(entry->dst_ip), "%s", ip0);
            } else {
                snprintf(entry->src_ip, sizeof(entry->src_ip), "%s", ip0);
            }
        } else if (n >= 2) {
            // "from A to B" / "A -> B" ordered pair, else message order
            snprintf(entry->src_ip, sizeof(entry->src_ip), "%s", ip0);
            snprintf(entry->dst_ip, sizeof(entry->dst_ip), "%s", ip1);
        }
        if (!entry->dst_ip[0] && contains_ci(low, "dhcpack")) {
            const char *d = strstr(low, "dhcpack on ");
            if (d) {
                char ip0b[46] = "", ip1b[46] = "";
                if (collect_ips(d, ip0b, ip1b) >= 1)
                    snprintf(entry->dst_ip, sizeof(entry->dst_ip), "%s", ip0b);
            } else {
                const char *d2 = strstr(low, "dhcpack to ");
                if (d2) {
                    char ip0b[46] = "", ip1b[46] = "";
                    if (collect_ips(d2, ip0b, ip1b) >= 1)
                        snprintf(entry->dst_ip, sizeof(entry->dst_ip), "%s", ip0b);
                }
            }
        }
    } else if (entry->src_ip[0] && !entry->dst_ip[0]) {
        char ip0[46] = "", ip1[46] = "";
        if (collect_ips(msg, ip0, ip1) >= 2)
            snprintf(entry->dst_ip, sizeof(entry->dst_ip), "%s", ip1);
    }

    // Event classification (attack-specific first for rules_engine/ml_engine visibility).
    const char *ev = NULL;
    if (contains_ci(low, "scan detected") || contains_ci(low, "port scan"))
        ev = "scan_detected";
    else if (contains_ci(low, "brute force"))
        ev = "brute_force";
    else if (contains_ci(low, "ddos") || contains_ci(low, "syn flood"))
        ev = "ddos_flood";
    else if (contains_ci(low, "arp spoof"))
        ev = "arp_spoof";
    else if (contains_ci(low, "dns spoof"))
        ev = "dns_spoof";
    else if (contains_ci(low, "rogue dhcp"))
        ev = "rogue_dhcp";
    else if (contains_ci(low, "vlan hop"))
        ev = "vlan_hop";
    else if (contains_ci(low, "ap-sta-failed") || contains_ci(low, "invalid_auth") ||
             contains_ci(low, "authentication error") || contains_ci(low, "handshake failed") ||
             (contains_ci(low, "failed") && contains_ci(low, "auth")))
        ev = "auth_failure";
    else if (contains_ci(low, "ap-sta-deauth") || contains_ci(low, "deauth"))
        ev = "deauth";
    else if (contains_ci(low, "ap-sta-disconnected") || contains_ci(low, "disassociated") ||
             contains_ci(low, "disconnected"))
        ev = "client_disconnect";
    else if (contains_ci(low, "ap-sta-connected") || contains_ci(low, "associated") ||
             contains_ci(low, "authenticated") || contains_ci(low, "handshake completed") ||
             contains_ci(low, "authentication success") || contains_ci(low, "auth success"))
        ev = "client_connect";
    else if (contains_ci(low, "dhcpack") ||
             (contains_ci(low, "dhcp") && (contains_ci(low, "assigned") ||
              contains_ci(low, "lease") || contains_ci(low, "ack"))))
        ev = "dhcp_ack";
    else if (contains_ci(low, "mac flap") || contains_ci(low, "macflap") ||
             contains_ci(low, "flapping") || contains_word(low, "flap"))
        ev = "mac_flap";
    else if (contains_ci(low, "mac learn") || contains_ci(low, "learned"))
        ev = "mac_learn";
    else if (contains_ci(low, "block") || contains_ci(low, "drop") ||
             contains_ci(low, "deny"))
        ev = "fw_block";
    else if (contains_ci(low, "reject"))
        ev = "fw_reject";
    else if (contains_ci(low, "allow") || contains_ci(low, "accept"))
        ev = "fw_allow";
    else if (contains_ci(low, "signal="))
        ev = "signal_report";
    else if (contains_ci(low, "stp") || contains_ci(low, "spantree") ||
             contains_ci(low, "root bridge"))
        ev = "stp_event";
    else if (contains_ci(low, "lineproto") || contains_word(low, "link") ||
             contains_ci(low, "updown") || contains_word(low, "port"))
        ev = (strcmp(entry->device_type, "switch") == 0) ? "port_status" : "interface_status";
    else if (contains_ci(low, "routing table") || contains_ci(low, "ospf") ||
             contains_ci(low, "adjchg") || contains_word(low, "route"))
        ev = (strcmp(entry->device_type, "router") == 0) ? "route_update" : "route_change";
    else if (contains_ci(low, "conntrack") || contains_ci(low, "connection tracking"))
        ev = "nat_conntrack";
    else if (contains_ci(low, "masquerad") || (contains_ci(low, "nat") && !contains_ci(low, "donat")))
        ev = "nat_event";
    else if (contains_ci(low, "router input") || contains_ci(low, "router forward") ||
             contains_ci(low, "forward"))
        ev = "packet_log";

    if (ev) {
        snprintf(entry->event, sizeof(entry->event), "%s", ev);
        free(low);
        return;
    }

    // Fallback: per-device generic event names.
    if (strcmp(entry->device_type, "firewall") == 0)
        snprintf(entry->event, sizeof(entry->event), "fw_event");
    else if (strcmp(entry->device_type, "router") == 0)
        snprintf(entry->event, sizeof(entry->event), "router_event");
    else if (strcmp(entry->device_type, "switch") == 0)
        snprintf(entry->event, sizeof(entry->event), "switch_event");
    else if (strcmp(entry->device_type, "ap") == 0)
        snprintf(entry->event, sizeof(entry->event), "ap_event");
    else
        snprintf(entry->event, sizeof(entry->event), "unknown");
    free(low);
}
