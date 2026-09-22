#include "devices.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void to_lower_copy(const char *src, char *dst, size_t n) {
    size_t i;
    for (i = 0; src[i] && i + 1 < n; i++)
        dst[i] = tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

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

// Case-insensitive substring search, returns pointer into hay or NULL.
static const char *find_ci(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    if (!n) return NULL;
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        for (; i < n && p[i]; i++) {
            if (tolower((unsigned char)p[i]) != tolower((unsigned char)needle[i]))
                break;
        }
        if (i == n) return p;
    }
    return NULL;
}

// Copy a token (alnum + '/' + '.') from src into out. Returns length or 0.
static int copy_token(const char *src, char *out, int out_size) {
    int i = 0;
    while (src[i] && (isalnum((unsigned char)src[i]) || src[i] == '/' || src[i] == '.')
            && i < out_size - 1) {
        out[i] = src[i];
        i++;
    }
    out[i] = '\0';
    return i;
}

// Colon-form MAC xx:xx:xx:xx:xx:xx (17 chars) at s.
static int is_mac_colon(const char *s) {
    for (int g = 0; g < 6; g++) {
        if (!isxdigit((unsigned char)s[0]) || !isxdigit((unsigned char)s[1]))
            return 0;
        if (g < 5) {
            if (s[2] != ':') return 0;
            s += 3;
        }
    }
    return 1;
}

// Cisco dot-form MAC xxxx.xxxx.xxxx (14 chars) at s.
static int is_mac_dot(const char *s) {
    for (int g = 0; g < 3; g++) {
        for (int i = 0; i < 4; i++) {
            if (!isxdigit((unsigned char)s[i])) return 0;
        }
        if (g < 2) {
            if (s[4] != '.') return 0;
            s += 5;
        }
    }
    return 1;
}

// First MAC (colon or dot form) in message. Returns 1 if found.
static int extract_first_mac(const char *msg, char *out, int out_size) {
    for (const char *p = msg; *p; p++) {
        char before = (p == msg) ? ' ' : p[-1];
        if (is_mac_colon(p) && !isxdigit((unsigned char)before) && before != ':') {
            char after = p[17];
            if (!isxdigit((unsigned char)after) && after != ':') {
                snprintf(out, out_size, "%.17s", p);
                return 1;
            }
        }
        if (is_mac_dot(p) && !isxdigit((unsigned char)before) && before != '.') {
            char after = p[14];
            if (!isxdigit((unsigned char)after) && after != '.') {
                snprintf(out, out_size, "%.14s", p);
                return 1;
            }
        }
    }
    return 0;
}

// Find first interface token in low (lowercased copy), copy original case
// from msg at the same offset. Returns 1 if found.
static int find_iface_at(const char *msg, const char *low, int from_off,
                         char *out, int out_size) {
    for (const char *p = low + from_off; *p; p++) {
        char before = (p == low) ? ' ' : p[-1];
        if (isalnum((unsigned char)before) || before == '-' || before == '_')
            continue;
        int n = -1;
        if (strncmp(p, "gigabitethernet", 15) == 0 && isdigit((unsigned char)p[15]))
            n = 15;
        else if (p[0] == 'g' && p[1] == 'i' && isdigit((unsigned char)p[2]))
            n = 2;
        else if (strncmp(p, "ether", 5) == 0 && isdigit((unsigned char)p[5]))
            n = 5;
        else if (strncmp(p, "eth", 3) == 0 && isdigit((unsigned char)p[3]))
            n = 3;
        else if (strncmp(p, "wlan", 4) == 0 && isdigit((unsigned char)p[4]))
            n = 4;
        else if (p[0] == 'b' && p[1] == 'r' && isdigit((unsigned char)p[2]))
            n = 2;
        if (n < 0) continue;
        const char *s = msg + (p - low);
        int i = 0;
        while (s[i] && (isalnum((unsigned char)s[i]) || s[i] == '/') && i < out_size - 1) {
            out[i] = s[i];
            i++;
        }
        if (i == 0) continue;
        out[i] = '\0';
        return 1;
    }
    return 0;
}

void detect_device_type(log_entry_t* entry) {
    if (!entry->hostname[0]) {
        snprintf(entry->device_type, sizeof(entry->device_type), "unknown");
        return;
    }

    char host_lower[64];
    to_lower_copy(entry->hostname, host_lower, sizeof(host_lower));

    if (strstr(host_lower, "router")) snprintf(entry->device_type, sizeof(entry->device_type), "router");
    else if (strstr(host_lower, "switch")) snprintf(entry->device_type, sizeof(entry->device_type), "switch");
    else if (host_has_token(host_lower, "ap")) snprintf(entry->device_type, sizeof(entry->device_type), "ap");
    else if (strstr(host_lower, "firewall") || strstr(host_lower, "fw"))
        snprintf(entry->device_type, sizeof(entry->device_type), "firewall");
    else if (strstr(host_lower, "syslog")) snprintf(entry->device_type, sizeof(entry->device_type), "syslog");
    else snprintf(entry->device_type, sizeof(entry->device_type), "other");
}

void extract_fields(log_entry_t* entry) {
    const char* msg = entry->raw_line;
    if (!msg || !msg[0]) return;

    size_t msg_len = strlen(msg);
    char *low = malloc(msg_len + 1);
    if (!low) return;
    to_lower_copy(msg, low, msg_len + 1);

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

    // v2 fields: source port (SPT=/spt=).
    {
        int v = extract_kv_int(msg, "SPT");
        if (v > 0 && v <= 65535) entry->src_port = v;
    }

    // v2: action (allow|deny|reject|close), normalized.
    {
        char buf[16];
        if (extract_kv(msg, "act", buf, sizeof(buf))) {
            char ab[16];
            to_lower_copy(buf, ab, sizeof(ab));
            if (strcmp(ab, "accept") == 0 || strcmp(ab, "allow") == 0)
                snprintf(entry->action, sizeof(entry->action), "allow");
            else if (strcmp(ab, "drop") == 0 || strcmp(ab, "deny") == 0)
                snprintf(entry->action, sizeof(entry->action), "deny");
            else if (strcmp(ab, "reject") == 0)
                snprintf(entry->action, sizeof(entry->action), "reject");
            else if (strcmp(ab, "close") == 0)
                snprintf(entry->action, sizeof(entry->action), "close");
            else
                snprintf(entry->action, sizeof(entry->action), "%.15s", ab);
        } else if (contains_ci(low, "[fw allow]")) {
            snprintf(entry->action, sizeof(entry->action), "allow");
        } else if (contains_ci(low, "[fw drop]") || contains_ci(low, "[fw deny")) {
            snprintf(entry->action, sizeof(entry->action), "deny");
        } else if (contains_ci(low, "[fw reject")) {
            snprintf(entry->action, sizeof(entry->action), "reject");
        } else if (contains_word(low, "drop") || contains_word(low, "deny")) {
            snprintf(entry->action, sizeof(entry->action), "deny");
        } else if (contains_word(low, "reject")) {
            snprintf(entry->action, sizeof(entry->action), "reject");
        } else if (contains_word(low, "allow") || contains_word(low, "accept")) {
            snprintf(entry->action, sizeof(entry->action), "allow");
        }
    }

    // v2: TCP flags (SYN|ACK|FIN|RST|URG), first match wins.
    {
        const char *flags[] = {"syn", "ack", "fin", "rst", "urg"};
        const char *names[] = {"SYN", "ACK", "FIN", "RST", "URG"};
        for (int w = 0; w < 5; w++) {
            if (contains_word(low, flags[w])) {
                snprintf(entry->tcp_flags, sizeof(entry->tcp_flags), "%s", names[w]);
                break;
            }
        }
    }

    // v2: MAC / client MAC / DHCP MAC (first MAC in line, routed by context).
    {
        char mbuf[24];
        if (extract_first_mac(msg, mbuf, sizeof(mbuf))) {
            if (contains_ci(low, "dhcpack") ||
                    (contains_ci(low, "dhcp") && contains_ci(low, "assigned"))) {
                snprintf(entry->dhcp_mac, sizeof(entry->dhcp_mac), "%s", mbuf);
            } else if (strcmp(entry->device_type, "ap") == 0) {
                snprintf(entry->client_mac, sizeof(entry->client_mac), "%s", mbuf);
            } else if (strcmp(entry->device_type, "switch") == 0) {
                snprintf(entry->mac, sizeof(entry->mac), "%s", mbuf);
            }
        }
    }

    // v2: VLAN id ("vlan 6", "VLAN1", "in vlan 10").
    {
        const char *vp = find_ci(msg, "vlan");
        if (vp) {
            vp += 4;
            while (*vp == ' ' || *vp == '\t' || *vp == '=') vp++;
            int v = atoi(vp);
            if (v > 0 && v <= 4094) entry->vlan_id = v;
        }
    }

    // v2: interface name + flap peer ("between port A and port B").
    {
        if (find_iface_at(msg, low, 0, entry->ifname, sizeof(entry->ifname))) {
            const char *ap = find_ci(low, " and port ");
            if (!ap) ap = find_ci(low, " and ");
            if (ap) {
                int off = (int)(ap - low);
                find_iface_at(msg, low, off, entry->peer_ifname, sizeof(entry->peer_ifname));
            }
        }
        // v2: STP new root ("new root Gi0/5").
        const char *rp = find_ci(low, "new root ");
        if (rp) {
            copy_token(msg + (rp - low) + 9, entry->stp_root, sizeof(entry->stp_root));
        }
    }

    // v2: AP radio (wlan0/wlan1).
    {
        const char *wp = find_ci(low, "wlan");
        if (wp && isdigit((unsigned char)wp[4])) {
            const char *s = msg + (wp - low);
            int i = 0;
            while (s[i] && isalnum((unsigned char)s[i]) && i < (int)sizeof(entry->radio) - 1) {
                entry->radio[i] = s[i];
                i++;
            }
            entry->radio[i] = '\0';
        }
    }

    // v2: AP SSID ("(SSID Campus)" / "SSID=foo").
    {
        const char *sp = find_ci(msg, "ssid");
        if (sp) {
            sp += 4;
            while (*sp == ' ' || *sp == '\t' || *sp == '=') sp++;
            int i = 0;
            while (sp[i] && sp[i] != ')' && sp[i] != '\n' && sp[i] != '\r'
                    && i < (int)sizeof(entry->ssid) - 1) {
                entry->ssid[i] = sp[i];
                i++;
            }
            while (i > 0 && (entry->ssid[i-1] == ' ' || entry->ssid[i-1] == '\t')) i--;
            entry->ssid[i] = '\0';
        }
    }

    // v2: AP reason code (reason=3 / reason=4).
    {
        int v = extract_kv_int(msg, "reason");
        if (v >= 0) entry->reason = v;
    }

    // v2: AP signal + tx rate (signal=67 dBm, tx_rate=29Mbps).
    {
        int v = extract_kv_int(msg, "signal");
        if (v != -1) entry->signal_dbm = v;
        v = extract_kv_int(msg, "tx_rate");
        if (v > 0) entry->tx_rate_mbps = v;
    }

    // v2: AP EAP/auth outcome.
    if (strcmp(entry->device_type, "ap") == 0) {
        if (contains_ci(low, "auth_failed") || contains_word(low, "failed") ||
                contains_ci(low, "invalid credentials") ||
                contains_ci(low, "authentication error") ||
                contains_ci(low, "ap-sta-failed")) {
            snprintf(entry->eap_status, sizeof(entry->eap_status), "failed");
        } else if (contains_ci(low, "authentication success") ||
                contains_ci(low, "handshake completed") ||
                contains_ci(low, "auth success")) {
            snprintf(entry->eap_status, sizeof(entry->eap_status), "success");
        }
    }

    // v2: router OSPF neighbor ("Nbr 172.20.0.9").
    {
        const char *np = find_ci(low, "nbr ");
        if (np) {
            copy_token(msg + (np - low) + 4, entry->ospf_nbr, sizeof(entry->ospf_nbr));
        }
    }

    // v2: router gateway= and dst-address=.
    {
        char gbuf[46];
        if (extract_kv(msg, "gateway", gbuf, sizeof(gbuf)))
            snprintf(entry->gateway, sizeof(entry->gateway), "%.45s", gbuf);
        if (extract_kv(msg, "dst-address", gbuf, sizeof(gbuf)))
            snprintf(entry->route_dst, sizeof(entry->route_dst), "%.45s", gbuf);
    }

    // v2: connection tracking count ("tracking: 5 entries" / "conntrack: 5 ...").
    {
        const char *cp = find_ci(low, "tracking:");
        if (!cp) cp = find_ci(low, "conntrack:");
        if (cp) {
            cp = strchr(cp, ':');
            if (cp) {
                int v = atoi(cp + 1);
                if (v >= 0) entry->conntrack_count = v;
            }
        }
    }

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

    // Event classification (single-line keywords only; multi-event attacks
    // like scans / brute force / DDoS are detected downstream by
    // pipeline/rules_engine.py rate counting, not here).
    const char *ev = NULL;
    if (contains_ci(low, "ap-sta-failed") || contains_ci(low, "invalid_auth") ||
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
    // CEF action-based classification (FortiGate traffic logs).
    // Placed before generic keyword matches to avoid false positives
    // from CEF header fields like "cat=traffic:forward".
    else if (contains_ci(low, "act=close") || contains_ci(low, "act=accept"))
        ev = "fw_allow";
    else if (contains_ci(low, "act=deny") || contains_ci(low, "act=drop") ||
             contains_ci(low, "act=reject"))
        ev = "fw_block";
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
    else if (contains_ci(low, "router input") || contains_ci(low, "router forward"))
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
