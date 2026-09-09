#include "syslog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

// Syslog facility names
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
        case 12: return "ntp";
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

// Header field parsers.
void parse_priority(log_entry_t* entry, const char** cursor) {
    const char* p = *cursor;

    if (*p == '<') {
        p++;
        int pri = atoi(p);
        int facility_num = pri / 8;
        int severity_num = pri % 8;

        strncpy(entry->facility, facility_name(facility_num), sizeof(entry->facility) - 1);
        strncpy(entry->severity, severity_name(severity_num), sizeof(entry->severity) - 1);

        while (*p && *p != '>') p++;
        if (*p == '>') p++;
    } else {
        strncpy(entry->facility, "user", sizeof(entry->facility) - 1);
        strncpy(entry->severity, "info", sizeof(entry->severity) - 1);
    }

    while (*p == ' ') p++;
    *cursor = p;
}

void parse_timestamp(log_entry_t* entry, const char** cursor) {
    const char* p = *cursor;

    if (isdigit((unsigned char)*p) && *(p+4) == '-') {
        int i = 0;
        while (*p && *p != ' ' && i < 63) {
            entry->timestamp[i++] = *p++;
        }
        entry->timestamp[i] = '\0';
    } else if (isalpha((unsigned char)*p)) {
        // Traditional MMM DD HH:MM:SS — normalize to ISO with current year.
        char mon[4] = "";
        int day = 0, hh = 0, mm = 0, ss = 0;
        int month = 0;
        static const char *names[] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        };
        if (sscanf(p, "%3s %d %d:%d:%d", mon, &day, &hh, &mm, &ss) == 5) {
            for (int m = 0; m < 12; m++) {
                if (strcmp(mon, names[m]) == 0) {
                    month = m + 1;
                    break;
                }
            }
        }
        if (month >= 1 && month <= 12
                && day >= 1 && day <= 31
                && hh >= 0 && hh <= 23
                && mm >= 0 && mm <= 59
                && ss >= 0 && ss <= 60) {
            time_t now = time(NULL);
            struct tm *tm = gmtime(&now);
            int year = (tm ? tm->tm_year + 1900 : 2026);
            snprintf(entry->timestamp, sizeof(entry->timestamp),
                "%04d-%02d-%02dT%02d:%02d:%02d+00:00",
                year, month, day, hh, mm, ss);
            for (int t = 0; t < 3 && *p; t++) {
                while (*p && *p != ' ') p++;
                while (*p == ' ') p++;
            }
        } else {
            // Unparseable: use received time so the row stays insertable.
            time_t now = time(NULL);
            struct tm *tm = gmtime(&now);
            if (tm) {
                snprintf(entry->timestamp, sizeof(entry->timestamp),
                    "%04d-%02d-%02dT%02d:%02d:%02d+00:00",
                    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                    tm->tm_hour, tm->tm_min, tm->tm_sec);
            }
        }
    } else {
        // Unparseable: use received time so the row stays insertable.
        time_t now = time(NULL);
        struct tm *tm = gmtime(&now);
        if (tm) {
            snprintf(entry->timestamp, sizeof(entry->timestamp),
                "%04d-%02d-%02dT%02d:%02d:%02d+00:00",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
        }
    }

    while (*p == ' ') p++;
    *cursor = p;
}

void parse_hostname(log_entry_t* entry, const char** cursor) {
    const char* p = *cursor;

    {
        int i = 0;
        while (*p && *p != ' ' && *p != ':' && i < 63) {
            entry->hostname[i++] = *p++;
        }
        entry->hostname[i] = '\0';
    }

    // Skip ": " or space after hostname
    while (*p == ' ' || *p == ':') p++;

    *cursor = p;
}

void skip_tag(const char** cursor) {
    const char* p = *cursor;

    // Skip past ": " separator and process tag.
    while (*p && *p != '\0') {
        if (*p == ':' && *(p+1) == ' ') {
            p += 2;  // skip ": "
            break;
        }
        if (*p == ':' && *(p+1) != ' ') {
            p++;
            continue;
        }
        p++;
    }

    while (*p == ' ') p++;

    *cursor = p;
}
