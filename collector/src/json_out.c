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

    // Single allocation: fixed overhead + worst-case escaped lengths, capped at 64KB.
    size_t need = 256
        + json_escaped_len(entry->timestamp) + json_escaped_len(entry->hostname)
        + json_escaped_len(entry->facility) + json_escaped_len(entry->severity)
        + json_escaped_len(entry->device_type) + json_escaped_len(entry->event)
        + json_escaped_len(entry->src_ip) + json_escaped_len(entry->dst_ip)
        + json_escaped_len(entry->proto) + 16 /* dst_port */
        + json_escaped_len(entry->raw_line) + 32;
    if (need > 65536) {
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

    APPEND_FMT("%s", "{");
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

    APPEND_FMT("%s", ",");
    APPEND_FMT("\"raw_line\":\"%s", "");
    p = json_write_escaped(p, entry->raw_line);
    if (p >= end) { free(buf); return NULL; }
    APPEND_FMT("%s", "\"}");

#undef APPEND_FMT
#undef APPEND_STR

    return buf;
}
