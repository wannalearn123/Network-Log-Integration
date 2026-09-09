#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>

typedef struct {
    char timestamp[64];
    char hostname[64];
    char facility[16];
    char severity[16];
    char device_type[32];
    char event[64];
    char src_ip[46];
    char dst_ip[46];
    char proto[8];
    int  dst_port;
    char *raw_line; /* heap-allocated full line, never truncated (1MB cap in collector) */
} log_entry_t;

#include "syslog.h"
#include "devices.h"
#include "json_out.h"

// Parse a raw syslog line into a log_entry_t.
log_entry_t* parse_syslog_line(const char* line);

// Free a log_entry_t.
void free_entry(log_entry_t* entry);

#endif
