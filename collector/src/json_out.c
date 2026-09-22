#include "json_out.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Worst-case escaped length of a string (control chars -> \uXXXX = 6 bytes).
static size_t json_escaped_len(const char* s) {
    size_t n = 0;
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\' || c == '\n' || c == '\r'
                || c == '\t' || c == '\b' || c == '\f') {
            n += 2;
        } else if (c < 0x20) {
            n += 6;
        } else {
            n += 1;
        }
    }
    return n;
}

// Write s with full JSON escaping. dst must have json_escaped_len(s)+1 bytes.
static char* json_write_escaped(char* dst, const char* s) {
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  *dst++ = '\\'; *dst++ = '"';  break;
            case '\\': *dst++ = '\\'; *dst++ = '\\'; break;
            case '\n': *dst++ = '\\'; *dst++ = 'n';  break;
            case '\r': *dst++ = '\\'; *dst++ = 'r';  break;
            case '\t': *dst++ = '\\'; *dst++ = 't';  break;
            case '\b': *dst++ = '\\'; *dst++ = 'b';  break;
            case '\f': *dst++ = '\\'; *dst++ = 'f';  break;
            default:
                if (c < 0x20) {
                    dst += sprintf(dst, "\\u%04x", c);
                } else {
                    *dst++ = *s;
                }
        }
    }
    return dst;
}

char* to_json(const log_entry_t* entry) {
    if (!entry) return NULL;
    const char *raw = entry->raw_line ? entry->raw_line : "";

    // Single allocation: fixed overhead + worst-case escaped lengths, capped at 8MB
    // (1MB line * 6x \uXXXX escaping + overhead). Larger lines are dropped, counted upstream.
    size_t need = 768
        + json_escaped_len(entry->timestamp) + json_escaped_len(entry->hostname)
        + json_escaped_len(entry->facility) + json_escaped_len(entry->severity)
        + json_escaped_len(entry->device_type) + json_escaped_len(entry->event)
        + json_escaped_len(entry->src_ip) + json_escaped_len(entry->dst_ip)
        + json_escaped_len(entry->proto) + 16 /* dst_port */
        + json_escaped_len(entry->action) + json_escaped_len(entry->tcp_flags)
        + json_escaped_len(entry->mac) + json_escaped_len(entry->ifname)
        + json_escaped_len(entry->peer_ifname) + json_escaped_len(entry->stp_root)
        + json_escaped_len(entry->client_mac) + json_escaped_len(entry->ssid)
        + json_escaped_len(entry->radio) + json_escaped_len(entry->eap_status)
        + json_escaped_len(entry->ospf_nbr) + json_escaped_len(entry->gateway)
        + json_escaped_len(entry->route_dst) + json_escaped_len(entry->dhcp_mac)
        + 16 * 8 /* optional ints: v, src_port, dst_port, vlan_id, reason,
                     signal_dbm, tx_rate_mbps, conntrack_count */
        + json_escaped_len(raw) + 32;
    if (need > 8 * 1024 * 1024) {
        fprintf(stderr, "collector: JSON over 8MB, dropping line\n");
        return NULL;
    }

    char* buf = malloc(need);
    if (!buf) return NULL;
    char* end = buf + need;
    char* p = buf;
    int n;

#define APPEND_FMT(fmt, ...) do { \
        n = snprintf(p, (size_t)(end - p), fmt, __VA_ARGS__); \
        if (n < 0 || (size_t)n >= (size_t)(end - p)) { free(buf); return NULL; } \
        p += n; \
    } while (0)

#define APPEND_STR(key, field) do { \
        APPEND_FMT("\"%s\":\"%s", key, ""); \
        p = json_write_escaped(p, field); \
        if (p >= end) { free(buf); return NULL; } \
        APPEND_FMT("%s", "\""); \
    } while (0)

#define APPEND_INT(key, val) do { \
        APPEND_FMT(",\"%s\":%d", key, (val)); \
    } while (0)

    APPEND_FMT("%s", "{\"v\":2,");
    APPEND_STR("timestamp", entry->timestamp);
    APPEND_FMT("%s", ",");
    APPEND_STR("hostname", entry->hostname);
    APPEND_FMT("%s", ",");
    APPEND_STR("facility", entry->facility);
    APPEND_FMT("%s", ",");
    APPEND_STR("severity", entry->severity);
    APPEND_FMT("%s", ",");
    APPEND_STR("device_type", entry->device_type);
    APPEND_FMT("%s", ",");
    APPEND_STR("event", entry->event);

    if (entry->src_ip[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("src_ip", entry->src_ip);
    }
    if (entry->dst_ip[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("dst_ip", entry->dst_ip);
    }
    if (entry->proto[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("proto", entry->proto);
    }
    if (entry->dst_port >= 0) {
        APPEND_FMT(",\"dst_port\":%d", entry->dst_port);
    }
    if (entry->src_port > 0) {
        APPEND_FMT(",\"src_port\":%d", entry->src_port);
    }
    if (entry->action[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("action", entry->action);
    }
    if (entry->tcp_flags[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("tcp_flags", entry->tcp_flags);
    }
    if (entry->mac[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("mac", entry->mac);
    }
    if (entry->vlan_id > 0) {
        APPEND_INT("vlan_id", entry->vlan_id);
    }
    if (entry->ifname[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("ifname", entry->ifname);
    }
    if (entry->peer_ifname[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("peer_ifname", entry->peer_ifname);
    }
    if (entry->stp_root[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("stp_root", entry->stp_root);
    }
    if (entry->client_mac[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("client_mac", entry->client_mac);
    }
    if (entry->ssid[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("ssid", entry->ssid);
    }
    if (entry->radio[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("radio", entry->radio);
    }
    if (entry->reason >= 0) {
        APPEND_INT("reason", entry->reason);
    }
    if (entry->signal_dbm != UNSET_INT) {
        APPEND_INT("signal_dbm", entry->signal_dbm);
    }
    if (entry->tx_rate_mbps > 0) {
        APPEND_INT("tx_rate_mbps", entry->tx_rate_mbps);
    }
    if (entry->eap_status[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("eap_status", entry->eap_status);
    }
    if (entry->ospf_nbr[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("ospf_nbr", entry->ospf_nbr);
    }
    if (entry->gateway[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("gateway", entry->gateway);
    }
    if (entry->route_dst[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("route_dst", entry->route_dst);
    }
    if (entry->dhcp_mac[0]) {
        APPEND_FMT("%s", ",");
        APPEND_STR("dhcp_mac", entry->dhcp_mac);
    }
    if (entry->conntrack_count >= 0) {
        APPEND_INT("conntrack_count", entry->conntrack_count);
    }

    APPEND_FMT("%s", ",");
    APPEND_FMT("\"raw_line\":\"%s", "");
    p = json_write_escaped(p, raw);
    if (p >= end) { free(buf); return NULL; }
    APPEND_FMT("%s", "\"}");

#undef APPEND_FMT
#undef APPEND_STR

    return buf;
}
