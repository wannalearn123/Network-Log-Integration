#ifndef COLLECTOR_H
#define COLLECTOR_H

// Run the collector: read syslog from source (NULL=stdin, or file path), output JSON to stdout.
int collector_run(const char* source);

#endif
