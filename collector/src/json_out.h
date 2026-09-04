#ifndef JSON_OUT_H
#define JSON_OUT_H

#include "parser.h"

// Convert a log_entry_t to a JSON string (caller must free)
char* to_json(const log_entry_t* entry);

#endif
