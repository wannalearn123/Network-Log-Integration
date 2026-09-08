#include "collector.h"
#include "parser.h"
#include <stdio.h>
#include <stdlib.h>

#define LINE_BUF_SIZE 4096

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

    char line[LINE_BUF_SIZE];
    int pos = 0;
    int discarding = 0;

    while (1) {
        int c = fgetc(in);

        if (c == EOF) {
            if (pos > 0) {
                line[pos] = '\0';
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
            break;
        }

        if (c == '\n') {
            if (discarding) {
                discarding = 0;
                pos = 0;
                continue;
            }
            line[pos] = '\0';

            if (pos > 0) {
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

            pos = 0;
            continue;
        }

        if (discarding) {
            continue;
        }
        if (pos < LINE_BUF_SIZE - 1) {
            line[pos++] = (char)c;
        } else {
            fprintf(stderr, "collector: line exceeded %d bytes, truncated\n", LINE_BUF_SIZE);
            discarding = 1;
            pos = 0;
        }
    }

    if (source) {
        fclose(in);
    }

    return 0;
}
