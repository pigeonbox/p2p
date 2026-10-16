// Package reflect 实现轻量 UDP 地址反射器（STUN-lite）。
//
// 打洞的前提是知道自己的公网映射地址：客户端从其 UDP 套接字发一个魔法
// 报文，本服务以观察到的源地址回应。恒开（默认）、按魔法串门控、每 IP
// 限流——不构成开放放大器（响应≈2 倍请求体积）。
//
// 线上协议（UDP, ASCII）：
//
//	请求: "fcb-reflect-v1"
//	响应: "fcb-reflect-v1-addr <ip:port>\n"
package reflect

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/oekit/concurrency/ratelimit"
)

const (
	reqMagic  = "fcb-reflect-v1"
	respMagic = "fcb-reflect-v1-addr "
)

// Serve 在已绑定的 UDP 连接上服务反射请求，直到 ctx 结束。
func Serve(ctx context.Context, conn *net.UDPConn, log *slog.Logger) {
	lim := ratelimit.NewKeyedLimiter(func() ratelimit.Limiter {
		return ratelimit.NewTokenBucket(10, 20) // 每 IP 10/s 突发 20
	}, 30*time.Minute)
	defer lim.Close()
	go func() {
		<-ctx.Done()
		lim.Close()
	}()
	buf := make([]byte, len(reqMagic)+8)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if n < len(reqMagic) || string(buf[:len(reqMagic)]) != reqMagic {
			continue
		}
		if !lim.Allow(raddr.IP.String()) {
			continue
		}
		resp := []byte(respMagic + raddr.String() + "\n")
		if _, err := conn.WriteToUDP(resp, raddr); err != nil && log != nil {
			log.Debug("reflect 回复失败", "addr", raddr, "err", err)
		}
	}
}

// Query 以给定套接字向反射器查询自身公网映射地址。
func Query(sock *net.UDPConn, serverAddr string, timeout time.Duration) (*net.UDPAddr, error) {
	raddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("反射器地址解析: %w", err)
	}
	if _, err := sock.WriteToUDP([]byte(reqMagic), raddr); err != nil {
		return nil, fmt.Errorf("反射请求发送: %w", err)
	}
	_ = sock.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 128)
	n, _, err := sock.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("反射响应接收: %w", err)
	}
	line := strings.TrimSpace(string(buf[:n]))
	if !strings.HasPrefix(line, respMagic) {
		return nil, fmt.Errorf("反射响应非法: %q", line)
	}
	addr, err := net.ResolveUDPAddr("udp", strings.TrimPrefix(line, respMagic))
	if err != nil {
		return nil, fmt.Errorf("反射响应地址解析: %w", err)
	}
	return addr, nil
}
