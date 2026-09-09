#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Parse syslog line: header, device type, and field extraction.
log_entry_t* parse_syslog_line(const char* line) {
    if (!line || !line[0]) return NULL;

    log_entry_t* entry = calloc(1, sizeof(log_entry_t));
    if (!entry) return NULL;

    size_t len = strlen(line);
    entry->raw_line = malloc(len + 1);
    if (!entry->raw_line) { free(entry); return NULL; }
    memcpy(entry->raw_line, line, len + 1);
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
    if (!entry) return;
    free(entry->raw_line);
    free(entry);
}
