#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Parse syslog line: header, device type, and field extraction.
log_entry_t* parse_syslog_line(const char* line) {
    if (!line || !line[0]) return NULL;

    log_entry_t* entry = calloc(1, sizeof(log_entry_t));
    if (!entry) return NULL;

    strncpy(entry->raw_line, line, sizeof(entry->raw_line) - 1);
    entry->raw_line[sizeof(entry->raw_line) - 1] = '\0';
    int len = strlen(entry->raw_line);
    while (len > 0 && (entry->raw_line[len-1] == '\n' || entry->raw_line[len-1] == '\r')) {
        entry->raw_line[--len] = '\0';
    }

    const char* p = line;

    parse_priority(entry, &p);
    parse_timestamp(entry, &p);
    parse_hostname(entry, &p);
    skip_tag(&p);

    detect_device_type(entry);
    extract_fields(entry);

    return entry;
}

void free_entry(log_entry_t* entry) {
    free(entry);
}
