#include "collector.h"
#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_INIT_CAP 4096
#define LINE_MAX_BYTES (1024 * 1024) /* 1MB abuse cap — larger lines dropped + counted */

// Emit one complete line (without trailing \n) as JSON.
static void emit_line(char *line) {
    if (!line[0]) return;
    log_entry_t* entry = parse_syslog_line(line);
    if (entry) {
        char* json = to_json(entry);
        if (json) {
            fputs(json, stdout);
            fputc('\n', stdout);
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

    size_t cap = LINE_INIT_CAP;
    size_t pos = 0;
    size_t oversize_dropped = 0;
    int over_limit = 0;
    char *line = malloc(cap);
    if (!line) {
        fprintf(stderr, "collector: out of memory\n");
        if (source) fclose(in);
        return 1;
    }

    while (1) {
        int c = fgetc(in);

        if (c == EOF) {
            if (over_limit) {
                oversize_dropped++;
                fprintf(stderr, "collector: dropped oversize line (>%d bytes), total dropped=%zu\n",
                        LINE_MAX_BYTES, oversize_dropped);
            } else if (pos > 0) {
                line[pos] = '\0';
                emit_line(line);
            }
            break;
        }

        if (c == '\n') {
            if (over_limit) {
                over_limit = 0;
                pos = 0;
                oversize_dropped++;
                fprintf(stderr, "collector: dropped oversize line (>%d bytes), total dropped=%zu\n",
                        LINE_MAX_BYTES, oversize_dropped);
                continue;
            }
            line[pos] = '\0';
            if (pos > 0) emit_line(line);
            pos = 0;
            continue;
        }

        if (over_limit) continue;

        if (pos + 1 >= cap) {
            if (cap >= LINE_MAX_BYTES) {
                over_limit = 1;
                pos = 0;
                continue;
            }
            size_t ncap = cap * 2;
            if (ncap > LINE_MAX_BYTES) ncap = LINE_MAX_BYTES;
            char *nline = realloc(line, ncap);
            if (!nline) {
                fprintf(stderr, "collector: out of memory growing to %zu\n", ncap);
                free(line);
                if (source) fclose(in);
                return 1;
            }
            line = nline;
            cap = ncap;
        }
        line[pos++] = (char)c;
    }

    free(line);
    if (source) {
        fclose(in);
    }

    return 0;
}
