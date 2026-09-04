#include "json_out.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================
// Convert to JSON
// ============================================================

// Worst-case escaped length of a string (control chars -> \uXXXX = 6 bytes)
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
// Returns pointer to the terminating position (not NUL-terminated by this fn).
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

    // Exact-size single allocation: fixed overhead + field lengths +
    // worst-case escaped raw_line. raw_line caps at 2047 chars x6 = ~12KB,
    // so this stays bounded (~13KB typical, hard cap 64KB sanity).
    size_t need = 256
        + strlen(entry->timestamp) + strlen(entry->hostname)
        + strlen(entry->facility) + strlen(entry->severity)
        + strlen(entry->device_type) + strlen(entry->event)
        + strlen(entry->src_ip) + strlen(entry->dst_ip)
        + strlen(entry->proto) + 16 /* dst_port */
        + json_escaped_len(entry->raw_line) + 32;
    if (need > 65536) {
        return NULL;  // unreachable with current struct sizes; fail loud, not corrupt
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

    APPEND_FMT("{\"timestamp\":\"%s\","
        "\"hostname\":\"%s\","
        "\"facility\":\"%s\","
        "\"severity\":\"%s\","
        "\"device_type\":\"%s\","
        "\"event\":\"%s\"",
        entry->timestamp,
        entry->hostname,
        entry->facility,
        entry->severity,
        entry->device_type,
        entry->event);

    if (entry->src_ip[0]) {
        APPEND_FMT(",\"src_ip\":\"%s\"", entry->src_ip);
    }
    if (entry->dst_ip[0]) {
        APPEND_FMT(",\"dst_ip\":\"%s\"", entry->dst_ip);
    }
    if (entry->proto[0]) {
        APPEND_FMT(",\"proto\":\"%s\"", entry->proto);
    }
    if (entry->dst_port >= 0) {
        APPEND_FMT(",\"dst_port\":%d", entry->dst_port);
    }

    APPEND_FMT(",\"raw_line\":\"%s", "");
    p = json_write_escaped(p, entry->raw_line);
    APPEND_FMT("%s", "\"}");

#undef APPEND_FMT

    return buf;
}
