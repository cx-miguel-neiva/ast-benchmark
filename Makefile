# Makefile for the AST Benchmark tool

BINARY_NAME=ast-benchmark.exe

all: build

build:
    @CGO_ENABLED=1 go build -o $(BINARY_NAME) .
    @echo "Build complete: $(BINARY_NAME)"

run-seed:
	@CGO_ENABLED=1 go run . db:seed

dev:
	@cd web/ui && npm run start:dev

clean:
	@rm -f $(BINARY_NAME)
	@rm -f data/benchmark.db