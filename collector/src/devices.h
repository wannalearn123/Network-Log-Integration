#ifndef DEVICES_H
#define DEVICES_H

#include "parser.h"

// Detect device type from hostname.
void detect_device_type(log_entry_t* entry);

// Extract fields and classify event from message body.
void extract_fields(log_entry_t* entry);

#endif
