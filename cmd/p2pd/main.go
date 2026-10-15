// p2pd — PigeonBox P2P 联邦注册中心。
//
// 单进程单二进制:节点租约注册/心跳、口令公告路由(SHA-256 哈希,不接触明文)、
// 管理端与 Prometheus 指标。M3 起追加 WS 信令与加密中继。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	reflectPkg "github.com/pigeonbox/p2p/internal/reflect"
	relayPkg "github.com/pigeonbox/p2p/internal/relay"

	"github.com/pigeonbox/kit/async"
	"github.com/pigeonbox/kit/shutdown"
	"github.com/pigeonbox/kit/version"
	"github.com/pigeonbox/p2p/internal/config"
	"github.com/pigeonbox/p2p/internal/registry"
	"github.com/pigeonbox/p2p/internal/server"
	"github.com/pigeonbox/p2p/internal/store/memory"
)

const sweepInterval = 30 * time.Second

func main() {
	configPath := flag.String("config", "", "配置文件路径(缺省依次找 CONFIG_PATH env / ./configs/config.yaml,均无则用内置默认)")
	showVersion := flag.Bool("version", false, "打印版本后退出")
	flag.Parse()

	if *showVersion {
		fmt.Printf("p2pd %s (commit %s, built %s)\n", version.Version, version.BuildCommit, version.BuildTime)
		return
	}
	path := resolveConfigPath(*configPath)

	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.Log.Level)
	slog.SetDefault(logger)
	// kit/async.GoSafe 的 panic 收编日志接线:落结构化 slog(与 core bootstrap
	// 同款)——不接则 panic 只走 stdlib log 落 stderr,脱离日志体系。
	async.SetPanicHandler(func(msg string, stack []byte) {
		logger.Error("goroutine panic recovered", "msg", msg, "stack", string(stack))
	})
	for _, w := range cfg.Warnings {
		logger.Warn(w)
	}

	memStore := memory.New()
	if cfg.Store.SnapshotPath != "" {
		if err := restoreSnapshot(memStore, cfg.Store.SnapshotPath, logger); err != nil {
			logger.Warn("快照恢复失败,以空存储启动", "path", cfg.Store.SnapshotPath, "err", err)
		}
	}

	svc := registry.New(registry.Params{
		Store:             memStore,
		RequireToken:      registrationToken(cfg),
		MinNodeTTL:        cfg.Registration.MinNodeTTL,
		MaxNodeTTL:        cfg.Registration.MaxNodeTTL,
		MaxAnnounces:      cfg.Announce.MaxPerNode,
		MaxAnnounceTTL:    cfg.Announce.MaxTTL,
		MaxNodes:          cfg.Registration.MaxNodes,
		MaxTotalAnnounces: cfg.Announce.MaxTotal,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	metrics := server.NewMetrics()
	srv := server.New(ctx, server.Params{
		Service: svc,
		Config:  *cfg,
		Logger:  logger,
		Metrics: metrics,
		Version: version.Version,
	})

	// 清扫循环:物理回收过期租约/公告并刷新活跃量指标。
	go func() {
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				nodes, announces := svc.Sweep(context.Background())
				// 刷新活跃量仪表(2026-10-05 审计运维项:此前仪表未接线恒 0)
				if liveNodes, liveAnnounces, err := svc.Stats(context.Background()); err == nil {
					metrics.SetGauges(liveNodes, liveAnnounces)
				}
				if nodes > 0 || announces > 0 {
					logger.Info("清扫完成", "nodes_expired", nodes, "announces_expired", announces)
				}
			}
		}
	}()

	// UDP 地址反射器（打洞前提;与 HTTP 同端口,协议不同互不冲突）。
	if cfg.Reflector.Enabled {
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: cfg.Server.Port})
		if err != nil {
			logger.Warn("UDP 反射器启动失败(客户端打洞将退化为仅 LAN/中继)", "err", err)
		} else {
			go reflectPkg.Serve(ctx, udpConn, logger)
		}
	}

	// 加密中继（M3 打洞兜底;默认关）。
	if cfg.Relay.Enabled {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Relay.Port))
		if err != nil {
			logger.Error("中继监听失败", "port", cfg.Relay.Port, "err", err)
			os.Exit(1)
		}
		go func() {
			p := relayPkg.Params{
				BytesPerSec:    cfg.Relay.MbpsPerChannel * 1_000_000 / 8,
				MaxWaiting:     cfg.Relay.MaxWaiting,
				MaxConnsPerIP:  cfg.Relay.MaxConnsPerIP,
				WaitingTimeout: cfg.Relay.WaitingTimeout,
				Log:            logger,
			}
			if err := relayPkg.Serve(ctx, ln, p); err != nil {
				logger.Error("中继异常退出", "err", err)
			}
		}()
	}

	// 快照周期落盘（store.snapshot_path 非空时启用;atomic rename 保证不写坏）。
	if cfg.Store.SnapshotPath != "" {
		interval := cfg.Store.SnapshotInterval
		if interval <= 0 {
			interval = 30 * time.Second
		}
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := saveSnapshot(memStore, cfg.Store.SnapshotPath); err != nil {
						logger.Warn("快照落盘失败", "path", cfg.Store.SnapshotPath, "err", err)
					}
				}
			}
		}()
	}

	httpSrv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      srv.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		var err error
		if cfg.Server.TLSCert != "" {
			err = httpSrv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	logger.Info("p2pd 已启动",
		"version", version.Version, "commit", version.BuildCommit,
		"port", cfg.Server.Port,
		"tls", cfg.Server.TLSCert != "",
		"registration_mode", cfg.Registration.Mode,
		"admin_enabled", cfg.Admin.Password != "",
		"metrics_strict", cfg.Metrics.Strict,
		"relay_enabled", cfg.Relay.Enabled,
		"relay_port", cfg.Relay.Port,
		"reflector_enabled", cfg.Reflector.Enabled,
		"snapshot", cfg.Store.SnapshotPath,
	)

	// 优雅停机编排(kit/shutdown):teardown(取消根 ctx→清扫/反射器/中继/快照退出)
	// 先于 http 排水执行;每个资源独立超时预算,panic 隔离不中断剩余清理。
	mgr := shutdown.New(10 * time.Second)
	mgr.AddTeardown(stop)
	if cfg.Store.SnapshotPath != "" {
		mgr.Add("snapshot", func(context.Context) error {
			if err := saveSnapshot(memStore, cfg.Store.SnapshotPath); err != nil {
				logger.Warn("停机快照落盘失败", "path", cfg.Store.SnapshotPath, "err", err)
			}
			return nil
		}, 5*time.Second)
	}
	mgr.Add("http", func(ctx context.Context) error { return httpSrv.Shutdown(ctx) }, 10*time.Second)
	shutdownDone := make(chan struct{})
	go func() {
		mgr.Listen(os.Interrupt, syscall.SIGTERM)
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
	case err := <-errCh:
		if err != nil {
			logger.Error("服务器异常退出", "err", err)
			os.Exit(1)
		}
	}
	logger.Info("p2pd 已退出")
}

// saveSnapshot 内存存储 → 快照文件(临时文件+atomic rename,进程任意时刻
// 被杀都不会留下写了一半的快照)。
func saveSnapshot(s *memory.Store, path string) error {
	data, err := s.Snapshot()
	if err != nil {
		return fmt.Errorf("序列化: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("写临时文件: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("原子替换: %w", err)
	}
	return nil
}

// restoreSnapshot 从快照文件恢复存储。文件不存在视为首次启动(返回 nil);
// 损坏由调用方按告警处理——快照只是加速自愈的逃生门,节点会自动重注册。
func restoreSnapshot(s *memory.Store, path string, log *slog.Logger) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		log.Info("快照文件不存在,以空存储启动(节点将自动重注册)", "path", path)
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.Restore(data); err != nil {
		return err
	}
	nodes, announces, err := s.Stats()
	if err != nil {
		return err
	}
	log.Info("快照已恢复", "path", path, "nodes", nodes, "announces", announces)
	return nil
}

// resolveConfigPath 解析配置路径:显式指定 > CONFIG_PATH > 默认位置(存在才用)。
func resolveConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if p := os.Getenv("CONFIG_PATH"); p != "" {
		return p
	}
	const def = "./configs/config.yaml"
	if _, err := os.Stat(def); err == nil {
		return def
	}
	return ""
}

func registrationToken(cfg *config.Config) string {
	if cfg.Registration.Mode == "token" {
		return cfg.Registration.Token
	}
	return ""
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
}
