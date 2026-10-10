CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
SRC = src/main.c src/parser.c src/syslog.c src/devices.c src/json_out.c src/collector.c
HEADERS = $(wildcard src/*.h)

# Default: build the collector
all: log_collector

log_collector: $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SRC)

# Build and run tests
test: tests/test_parser.c src/parser.c src/syslog.c src/devices.c src/json_out.c
	$(CC) $(CFLAGS) -o test_parser $^
	./test_parser

# Parser safety pass for malformed and boundary-oriented test inputs.
asan: tests/test_parser.c src/parser.c src/syslog.c src/devices.c src/json_out.c
	$(CC) $(CFLAGS) -g -fno-omit-frame-pointer -fsanitize=address,undefined -o test_parser_asan $^
	ASAN_OPTIONS=detect_leaks=1 ./test_parser_asan

# Clean build artifacts
clean:
	rm -f log_collector test_parser test_parser_asan src/*.o

.PHONY: all test asan clean
