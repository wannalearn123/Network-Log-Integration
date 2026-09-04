#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================
// Parse syslog line: orchestrate header, device, and field parsing.
// Format: <PRI>TIMESTAMP HOSTNAME TAG: MSG
// rsyslog format: YYYY-MM-DDTHH:MM:SS+00:00 HOSTNAME TAG: MSG
// ============================================================
log_entry_t* parse_syslog_line(const char* line) {
    if (!line || !line[0]) return NULL;

    log_entry_t* entry = calloc(1, sizeof(log_entry_t));
    if (!entry) return NULL;

    // Store raw line (truncate if needed)
    strncpy(entry->raw_line, line, sizeof(entry->raw_line) - 1);
    entry->raw_line[sizeof(entry->raw_line) - 1] = '\0';

    // Strip trailing newline
    int len = strlen(entry->raw_line);
    while (len > 0 && (entry->raw_line[len-1] == '\n' || entry->raw_line[len-1] == '\r')) {
        entry->raw_line[--len] = '\0';
    }

    const char* p = line;

    parse_priority(entry, &p);
    parse_timestamp(entry, &p);
    parse_hostname(entry, &p);
    skip_tag(&p);

    // Now p points to the actual message body
    // We already stored it in raw_line, but let's update it
    // Actually, raw_line has the full line. The message body is what follows the tag.
    // For field extraction, we use raw_line which has the full content.

    // Detect device type
    detect_device_type(entry);

    // Extract device-specific fields
    extract_fields(entry);

    return entry;
}

void free_entry(log_entry_t* entry) {
    free(entry);
}
