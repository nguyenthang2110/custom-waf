.PHONY: build test run clean docker docker-run

GOCACHE_DIR := $(CURDIR)/.gocache

build:
	GOFLAGS= GOCACHE=$(GOCACHE_DIR) go build -o bin/waf ./cmd/waf

test:
	GOFLAGS= GOCACHE=$(GOCACHE_DIR) go test ./...

run: build
	./bin/waf -config configs/config.yaml

clean:
	rm -rf bin ./tmp ./logs

docker:
	docker build -t waf:latest -f deployments/docker/Dockerfile .

docker-run:
	docker-compose -f deployments/docker/docker-compose.yml up -d
