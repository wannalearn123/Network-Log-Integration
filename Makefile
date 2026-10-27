.PHONY: all build test vet fmt run clean

# Build only project packages. Using `./...` would walk data/pgdata, which the
# PostgreSQL container owns with restrictive permissions.
PKGS := $(shell go list ./cmd/... ./internal/...)

BIN := siskamlan

all: build

build:
	go build -o $(BIN) ./cmd/siskamlan

test:
	go test $(or $(PKGS),./cmd/... ./internal/...)

vet:
	go vet $(or $(PKGS),./cmd/... ./internal/...)

fmt:
	gofmt -w $$(find cmd internal -name '*.go')

run: build
	./$(BIN) all

clean:
	rm -f $(BIN)