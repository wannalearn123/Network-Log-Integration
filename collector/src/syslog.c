#include "syslog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// ============================================================
// Syslog facility names
// ============================================================
static const char* facility_name(int num) {
    switch (num) {
        case 0: return "kern";
        case 1: return "user";
        case 2: return "mail";
        case 3: return "daemon";
        case 4: return "auth";
        case 5: return "syslog";
        case 6: return "lpr";
        case 7: return "news";
        case 8: return "uucp";
        case 9: return "cron";
        case 10: return "authpriv";
        case 11: return "ftp";
        case 13: return "security";
        case 14: return "console";
        case 15: return "solaris-cron";
        case 16: return "local0";
        case 17: return "local1";
        case 18: return "local2";
        case 19: return "local3";
        case 20: return "local4";
        case 21: return "local5";
        case 22: return "local6";
        case 23: return "local7";
        default: return "unknown";
    }
}

static const char* severity_name(int num) {
    switch (num) {
        case 0: return "emerg";
        case 1: return "alert";
        case 2: return "crit";
        case 3: return "err";
        case 4: return "warning";
        case 5: return "notice";
        case 6: return "info";
        case 7: return "debug";
        default: return "unknown";
    }
}

// ============================================================
// Header field parsers (moved verbatim from parser.c)
// Format: <PRI>TIMESTAMP HOSTNAME TAG: MSG
// rsyslog format: YYYY-MM-DDTHH:MM:SS+00:00 HOSTNAME TAG: MSG
// ============================================================
void parse_priority(log_entry_t* entry, const char** cursor) {
    const char* p = *cursor;

    // Check for syslog priority <PRI>
    if (*p == '<') {
        p++;
        int pri = atoi(p);
        int facility_num = pri / 8;
        int severity_num = pri % 8;

        strncpy(entry->facility, facility_name(facility_num), sizeof(entry->facility) - 1);
        strncpy(entry->severity, severity_name(severity_num), sizeof(entry->severity) - 1);

        // Skip past >
        while (*p && *p != '>') p++;
        if (*p == '>') p++;
    } else {
        // Default values if no priority
        strncpy(entry->facility, "user", sizeof(entry->facility) - 1);
        strncpy(entry->severity, "info", sizeof(entry->severity) - 1);
    }

    // Skip leading space
    while (*p == ' ') p++;

    *cursor = p;
}

void parse_timestamp(log_entry_t* entry, const char** cursor) {
    const char* p = *cursor;

    // Parse timestamp — rsyslog ISO format: YYYY-MM-DDTHH:MM:SS+00:00
    // Or traditional: "Aug 31 10:23:01"
    if (isdigit(*p) && *(p+4) == '-') {
        // ISO format: 2026-08-31T04:44:43+00:00
        int i = 0;
        while (*p && *p != ' ' && i < 63) {
            entry->timestamp[i++] = *p++;
        }
        entry->timestamp[i] = '\0';
    } else {
        // Traditional: "Aug 31 10:23:01"
        int i = 0;
        while (*p && *p != ' ' && i < 63) {
            entry->timestamp[i++] = *p++;
        }
        entry->timestamp[i] = '\0';

        // May need to grab the year or just use what we have
        // For now, keep the 3-part timestamp
    }

    // Skip space
    while (*p == ' ') p++;

    *cursor = p;
}

void parse_hostname(log_entry_t* entry, const char** cursor) {
    const char* p = *cursor;

    // Parse hostname (until next space)
    {
        int i = 0;
        while (*p && *p != ' ' && *p != ':' && i < 63) {
            entry->hostname[i++] = *p++;
        }
        entry->hostname[i] = '\0';
    }

    // Skip ": " after hostname (rsyslog format) or space
    while (*p == ' ' || *p == ':') p++;

    *cursor = p;
}

void skip_tag(const char** cursor) {
    const char* p = *cursor;

    // Skip tag (process name like "routerd:", "switchd:", etc.)
    // The tag is everything up to ": " or just the first word before ":"
    while (*p && *p != '\0') {
        if (*p == ':' && *(p+1) == ' ') {
            p += 2;  // skip ": "
            break;
        }
        if (*p == ':' && *(p+1) != ' ') {
            // Could be part of tag like "hostapd:" — keep going
            p++;
            continue;
        }
        p++;
    }

    // Skip leading space of message
    while (*p == ' ') p++;

    *cursor = p;
}
