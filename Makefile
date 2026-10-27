.PHONY: all build test vet fmt run clean

# Build only project packages. Using `./...` would walk data/pgdata, which the
# PostgreSQL container owns with mode 0700.
PKGS := ./cmd/... ./internal/...

BIN := siskamlan

all: build

build:
	go build -o $(BIN) ./cmd/siskamlan

test:
	go test $(PKGS)

vet:
	go vet $(PKGS)

fmt:
	gofmt -w $$(find cmd internal -name '*.go')

run: build
	./$(BIN)

clean:
	rm -f $(BIN)