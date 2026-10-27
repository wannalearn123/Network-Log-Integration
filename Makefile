.PHONY: all build test test-unit vet fmt run clean

# Build only project packages. Using `./...` would walk data/pgdata, which the
# PostgreSQL container owns with mode 0700.
PKGS := ./cmd/... ./internal/...

# Packages whose tests do not touch PostgreSQL.
UNIT_PKGS := ./internal/config/... ./internal/parser/... ./internal/rules/... \
             ./internal/notify/... ./internal/tui/...

BIN := siskamlan

all: build

build:
	go build -o $(BIN) ./cmd/siskamlan

# Full suite. Requires PostgreSQL (docker compose up -d postgres); store tests
# fail rather than skip so query and schema bugs cannot hide.
test:
	go test $(PKGS)

# Hermetic subset: no database needed.
test-unit:
	go test $(UNIT_PKGS)

vet:
	go vet $(PKGS)

fmt:
	gofmt -w $$(find cmd internal -name '*.go')

run: build
	./$(BIN)

clean:
	rm -f $(BIN)