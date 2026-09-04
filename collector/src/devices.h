#ifndef DEVICES_H
#define DEVICES_H

#include "parser.h"

// Detect device type from hostname
void detect_device_type(log_entry_t* entry);

// Extract device-type-specific fields from the message body
void extract_fields(log_entry_t* entry);

#endif
