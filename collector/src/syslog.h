#ifndef SYSLOG_H
#define SYSLOG_H

#include "parser.h"

// Parse the <PRI> prefix into facility/severity, advancing the cursor.
void parse_priority(log_entry_t* entry, const char** cursor);

// Parse the timestamp (rsyslog ISO or traditional), advancing the cursor.
void parse_timestamp(log_entry_t* entry, const char** cursor);

// Parse the hostname token, advancing the cursor.
void parse_hostname(log_entry_t* entry, const char** cursor);

// Skip the ": " separator and process tag, advancing to the message body.
void skip_tag(const char** cursor);

#endif
