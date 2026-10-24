BINARY := p2pd
VERSION ?= dev
FUZZTIME ?= 60s

.PHONY: build test vet lint fuzz run smoke docker clean help

build:  ## 构建二进制 → bin/p2pd
	go build -trimpath -ldflags "-w -s -X 'github.com/oekit/core/version.Version=$(VERSION)'" -o bin/$(BINARY) ./cmd/p2pd

test:   ## 全量测试(-race)
	go test -race ./...

vet:
	go vet ./...

lint:   ## golangci-lint(CI 同款门禁)
	golangci-lint run ./...

fuzz:   ## 原生 fuzz 短跑(目标=CI 同款;FUZZTIME=60s 可调)
	go test -run xxx -fuzz '^FuzzReadMsg$$'            -fuzztime $(FUZZTIME) ./internal/wire/
	go test -run xxx -fuzz '^FuzzWriteReadRoundTrip$$' -fuzztime $(FUZZTIME) ./internal/wire/
	go test -run xxx -fuzz '^FuzzReadLine$$'           -fuzztime $(FUZZTIME) ./internal/relay/
	go test -run xxx -fuzz '^FuzzClientFrame$$'        -fuzztime $(FUZZTIME) ./internal/signaling/
	go test -run xxx -fuzz '^FuzzRegisterHandler$$'    -fuzztime $(FUZZTIME) ./internal/server/
	go test -run xxx -fuzz '^FuzzAnnounceHandler$$'    -fuzztime $(FUZZTIME) ./internal/server/

run: build  ## 本地起服务
	./bin/$(BINARY) --config ./configs/config.yaml

smoke: build  ## 冒烟:健康检查/签名注册/公告/解析/管理端
	bash scripts/smoke.sh

docker:  ## 本地构建镜像
	docker build -t ghcr.io/pigeonbox/p2p:dev .

clean:
	rm -rf bin/
