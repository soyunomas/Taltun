BINARY_NAME=vpn
BUILD_DIR=bin
SCRIPT_DIR=scripts

.PHONY: all build clean test bench perf profile integration deps

all: build

deps:
	@echo "📦 Descargando dependencias..."
	go mod tidy

build:
	@echo "🔨 Compilando..."
	mkdir -p $(BUILD_DIR)
	# -ldflags="-s -w" reduce el tamaño del binario (strip debug symbols)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/vpn
	go build -ldflags="-s -w" -o $(BUILD_DIR)/taltun-keygen ./cmd/keygen

test:
	@echo "🧪 Ejecutando tests unitarios..."
	go test -v -race ./...

bench:
	@echo "🔥 Ejecutando microbenchmarks reproducibles..."
	go test -run=^$ -bench=. -benchmem ./pkg/... ./internal/session/...

perf: build
	@echo "📈 Ejecutando benchmark end-to-end (requiere root, iperf3, jq y curl)..."
	sudo env PATH="$PATH" BENCH_OUT="$PWD/benchmark-results" ./$(SCRIPT_DIR)/bench_throughput.sh

integration: build
	@echo "🌍 Ejecutando test de integración (requiere sudo)..."
	chmod +x $(SCRIPT_DIR)/run_integration_test.sh
	sudo ./$(SCRIPT_DIR)/run_integration_test.sh

profile:
	@echo "🕵️ El benchmark end-to-end genera benchmark-results/cpu.prof"
	@echo "Ejecuta: make perf && go tool pprof -top benchmark-results/cpu.prof"

clean:
	@echo "🧹 Limpiando..."
	rm -rf $(BUILD_DIR)
	rm -f *.prof *.test *.log
