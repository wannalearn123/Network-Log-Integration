CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
SRC = src/main.c src/parser.c src/syslog.c src/devices.c src/json_out.c src/collector.c

# Default: build the collector
all: log_collector

log_collector: $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

# Build and run tests
test: tests/test_parser.c src/parser.c src/syslog.c src/devices.c src/json_out.c
	$(CC) $(CFLAGS) -o test_parser $^
	./test_parser

# Clean build artifacts
clean:
	rm -f log_collector test_parser src/*.o

.PHONY: all test clean
