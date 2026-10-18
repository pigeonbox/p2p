# PigeonBox P2P 注册中心镜像(纯 Go 静态构建,天然多架构)。
#
# 构建上下文为本仓库即可,零生态依赖(不 import core/contracts)。
#   cd p2p && docker build -t p2p:latest .
# GOPROXY 可用 --build-arg GOPROXY=... 覆盖(默认国内加速;海外 CI 传空走默认)。

# ========== Stage 1: 构建 p2pd ==========
FROM golang:1.26-alpine AS builder

ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /workspace/p2p

# 先复制模块描述再下载依赖(利用层缓存)
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

# 纯静态(CGO_ENABLED=0):无 sqlite 等本地依赖;p2pc=直传客户端随镜像分发
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-w -s \
    -X 'github.com/oekit/core/version.Version=${VERSION}' \
    -X 'github.com/oekit/core/version.BuildCommit=${COMMIT}' \
    -X 'github.com/oekit/core/version.BuildTime=${BUILD_TIME}'" \
    -o /out/p2pd ./cmd/p2pd && \
    CGO_ENABLED=0 go build -trimpath \
    -ldflags="-w -s \
    -X 'github.com/oekit/core/version.Version=${VERSION}' \
    -X 'github.com/oekit/core/version.BuildCommit=${COMMIT}' \
    -X 'github.com/oekit/core/version.BuildTime=${BUILD_TIME}'" \
    -o /out/p2pc ./cmd/p2pc

# ========== Stage 2: 运行时镜像 ==========
FROM alpine:3.24

RUN apk --no-cache add ca-certificates tzdata

# 非 root 用户(与生态对齐 uid 1000)
RUN addgroup -g 1000 app && \
    adduser -D -s /bin/sh -u 1000 -G app app

WORKDIR /app

COPY --from=builder /out/p2pd ./
COPY --from=builder /out/p2pc ./
# 随镜像携带默认配置:裸 docker run 开箱可用;生产经 env/compose 覆盖。
COPY configs/config.yaml ./configs/config.yaml

RUN mkdir -p data && chown -R app:app /app

USER app

EXPOSE 12346 12347/udp 12347

# wget --spider 发 HEAD,/health 未注册 HEAD 恒 404 → 健康检查永不通过,须显式 GET
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:12346/health || exit 1

CMD ["./p2pd"]
