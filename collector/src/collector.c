#define _POSIX_C_SOURCE 200809L
#include "collector.h"
#include "parser.h"
#include "json_out.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define LINE_MAX_BYTES (1024 * 1024) /* 1MB abuse cap — larger lines dropped + counted */

// Emit one complete line (without trailing \n) as JSON.
static void emit_line(char *line) {
    if (!line[0]) return;
    log_entry_t* entry = parse_syslog_line(line);
    if (entry) {
        char* json = to_json(entry);
        if (json) {
            puts(json);
            fflush(stdout);
            free(json);
        }
        free_entry(entry);
    }
}

int collector_run(const char* source) {
    FILE* in;

    if (source) {
        in = fopen(source, "r");
        if (!in) {
            fprintf(stderr, "collector: cannot open %s\n", source);
            return 1;
        }
    } else {
        in = stdin;
    }

    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    size_t oversize_dropped = 0;

    while ((len = getline(&line, &cap, in)) != -1) {
        if (len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';
        if (len > LINE_MAX_BYTES) {
            oversize_dropped++;
            fprintf(stderr, "collector: dropped oversize line (>%d bytes), total dropped=%zu\n", LINE_MAX_BYTES, oversize_dropped);
            continue;
        }
        if (len > 0)
            emit_line(line);
    }

    free(line);
    if (source) fclose(in);
    return 0;
}
