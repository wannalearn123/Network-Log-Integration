#ifndef COLLECTOR_H
#define COLLECTOR_H

// Run the collector: read syslog from source, output JSON to stdout
// source: NULL for stdin, or file path
// Returns 0 on success, 1 on error
int collector_run(const char* source);

#endif
