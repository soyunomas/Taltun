BINARY_NAME=vpn
BUILD_DIR=bin
SCRIPT_DIR=scripts

.PHONY: all build clean test bench profile integration deps

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
	@echo "🔥 Ejecutando benchmarks..."
	go test -bench=. -benchmem ./pkg/...

integration: build
	@echo "🌍 Ejecutando test de integración (requiere sudo)..."
	chmod +x $(SCRIPT_DIR)/run_integration_test.sh
	sudo ./$(SCRIPT_DIR)/run_integration_test.sh

profile:
	@echo "🕵️ Generando perfil de CPU..."
	go test -bench=. -cpuprofile=cpu.prof ./internal/engine
	go tool pprof -http=:8080 cpu.prof

clean:
	@echo "🧹 Limpiando..."
	rm -rf $(BUILD_DIR)
	rm -f *.prof *.test *.log
