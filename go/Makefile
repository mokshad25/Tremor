GO ?= go
BIN := bin

.PHONY: build test race vet check run loadgen maxrate overload chaos clean

build:
	$(GO) build -o $(BIN)/tremor ./cmd/tremor
	$(GO) build -o $(BIN)/loadgen ./cmd/loadgen
	$(GO) build -o $(BIN)/chaos ./cmd/chaos

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

check: vet race

run: build
	$(BIN)/tremor -config config.example.yaml

loadgen: build
	$(BIN)/loadgen -rate 20000 -services 10 -duration 30s

maxrate: build
	bench/maxrate.sh

overload: build
	bench/overload.sh

chaos: build
	bench/chaos.sh

clean:
	rm -rf $(BIN) bench/out data
