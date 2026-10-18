// Package config 加载 p2pd 配置。
//
// 优先级(高→低): PB_P2P_* 环境变量 > 配置文件(--config / CONFIG_PATH) > 内置默认。
// 所有键均有默认值,配置文件可省略。
package config

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config p2pd 全量配置。
type Config struct {
	Server       Server
	Registration Registration
	Announce     Announce
	Admin        Admin
	Signaling    Signaling
	Pairing      Pairing
	Relay        Relay
	Reflector    Reflector
	Store        Store
	Metrics      Metrics
	Log          Log
	// Warnings Load 阶段的非致命告警(如未识别的配置键),由装配层打日志。
	// 不属于配置语义,勿序列化进快照/管理端。
	Warnings []string `json:"-"`
}

// Server HTTP 服务参数。
type Server struct {
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	// BehindProxy 为 true 时从 X-Forwarded-For 解析客户端 IP(反代部署,如 nginx/openresty);
	// 默认 false,直取 RemoteAddr,防止伪造头绕过限流。
	BehindProxy bool
	// TrustedProxies 可信反代网段(CIDR,逗号分隔,如 "10.0.0.0/8,172.16.0.0/12")。
	// behind_proxy=true 时仅当直连对端落在可信网段才采信 XFF,且从最右段向左
	// 跳过可信跳取第一个不可信地址;空 = 信任直连对端(单层反代)。
	// env: PB_P2P_SERVER_TRUSTED_PROXIES
	TrustedProxies []string
	// TLS 证书与私钥路径。两者都非空时 HTTP/WS(信令)以 TLS 提供;
	// 推荐反代终结 TLS,直连 TLS 用于裸机公网部署。UDP 反射器/中继不受影响。
	// env: PB_P2P_TLS_CERT / PB_P2P_TLS_KEY
	TLSCert string
	TLSKey  string
}

// Relay 加密中继配置（M3 打洞失败的兜底;默认整机关闭）。
type Relay struct {
	// Enabled 总开关(默认 true——行业共识:中继是打洞失败的必要兜底,
	// 无中继=对端不可直连即传输失败)。非开放代理:配对须 PAKE 派生令牌,
	// 无令牌连接 60s 等待超时即断;另有等待槽/单 IP/带宽三重上限。个人
	// 纯内网部署可显式关闭。
	// env: PB_P2P_RELAY_ENABLED
	Enabled bool
	// Port 中继 TCP 端口。env: PB_P2P_RELAY_PORT
	Port int
	// MbpsPerChannel 单信道带宽上限（Mbps,0=不限）。env: PB_P2P_RELAY_MBPS
	MbpsPerChannel int64
	// MaxWaiting 等待配对连接数上限(0=内置默认 1024)。
	// env: PB_P2P_RELAY_MAX_WAITING
	MaxWaiting int
	// MaxConnsPerIP 单 IP 并发连接上限(0=内置默认 16;防随机 token 占满
	// 全局等待槽的拒绝服务,2026-10-05 审计 P2)。
	// env: PB_P2P_RELAY_MAX_CONNS_PER_IP
	MaxConnsPerIP int
	// WaitingTimeout 等待配对超时(0=内置默认 60s)。
	// env: PB_P2P_RELAY_WAITING_TIMEOUT
	WaitingTimeout time.Duration
}

// Reflector UDP 地址反射器（打洞前提;与 HTTP 同端口,默认开）。
type Reflector struct {
	// Enabled 总开关。env: PB_P2P_REFLECTOR_ENABLED
	Enabled bool
}

// Store 存储与持久化。
type Store struct {
	// SnapshotPath 快照文件路径(空=不持久化,纯内存)。设置后周期落盘+
	// 优雅停机落盘,重启时恢复——公共节点重启不再有公告"失联窗口"。
	// env: PB_P2P_STORE_SNAPSHOT_PATH
	SnapshotPath string
	// SnapshotInterval 快照落盘周期(默认 30s;≤0 用默认)。
	// env: PB_P2P_STORE_SNAPSHOT_INTERVAL
	SnapshotInterval time.Duration
}

// Metrics 观测配置。
type Metrics struct {
	// Strict 公共部署加固:未配置管理口令时 /metrics 直接 404 而非默认开放。
	// env: PB_P2P_METRICS_STRICT
	Strict bool
}

// Signaling WS 信令信道配置（M3 设备直传；默认开——准入由节点签名把守，
// 关闭只影响直传配对，不影响注册/公告/解析）。
type Signaling struct {
	// Enabled 总开关。env: PB_P2P_SIGNALING_ENABLED
	Enabled bool
	// SessionTTL 会话最长生命周期（含等待配对）。env: PB_P2P_SIGNALING_SESSION_TTL
	SessionTTL time.Duration
	// IdleTimeout 连接空闲上限（pong 与数据帧均续期）。env: PB_P2P_SIGNALING_IDLE_TIMEOUT
	IdleTimeout time.Duration
	// HelloTimeout 接入后交 hello 的时限。env: PB_P2P_SIGNALING_HELLO_TIMEOUT
	HelloTimeout time.Duration
	// MaxFrameBytes data 帧负载上限（字节）。env: PB_P2P_SIGNALING_MAX_FRAME_BYTES
	MaxFrameBytes int
	// MaxSessionsPerNode 单节点并发会话上限。env: PB_P2P_SIGNALING_MAX_PER_NODE
	MaxSessionsPerNode int
	// MaxTotalSessions 全局并发会话上限。env: PB_P2P_SIGNALING_MAX_TOTAL
	MaxTotalSessions int
}

// Pairing 配对码会话配置（2026-10-18，spec 见 hub docs/specs/2026-10-18-p2p-pairing-code-design.md）。
type Pairing struct {
	// Enabled 总开关（默认开；false 时 /v1/pair/* 整体 404，客户端明确降级
	// 到口令直传）。env: PB_P2P_PAIRING_ENABLED
	Enabled bool
	// CodeTTL 配对码有效窗。env: PB_P2P_PAIRING_CODE_TTL
	CodeTTL time.Duration
	// SessionTTL 会话总寿命上限（GC 硬顶，须 ≥ CodeTTL）。env: PB_P2P_PAIRING_SESSION_TTL
	SessionTTL time.Duration
	// CodeLen 配对码位数（4-8；默认 4，运营遇枚举压力可升 6）。
	// env: PB_P2P_PAIRING_CODE_LEN
	CodeLen int
	// MaxPerNode 单节点活跃会话上限。env: PB_P2P_PAIRING_MAX_PER_NODE
	MaxPerNode int
	// MaxTotal 全局会话上限（内存耗尽防护）。env: PB_P2P_PAIRING_MAX_TOTAL
	MaxTotal int
}

// Registration 节点注册策略。
type Registration struct {
	// Mode: open(开放注册) | token(邀请制,须携带共享注册密钥)。
	Mode  string
	Token string
	// MinNodeTTL/MaxNodeTTL 限制节点租约时长,节点须周期心跳续租。
	MinNodeTTL time.Duration
	MaxNodeTTL time.Duration
	// MaxNodes 全局节点租约上限(2026-10-05 审计 P2:开放注册内存耗尽防护)。
	MaxNodes int
}

// Announce 公告(口令路由)配额。
type Announce struct {
	MaxPerNode int
	MaxTTL     time.Duration
	// MaxTotal 全局公告上限(内存耗尽防护)。
	MaxTotal int
}

// Admin 管理端点。Password 为空时管理 API 整体禁用(403)。
// 推荐仅经环境变量 PB_P2P_ADMIN_PASSWORD 注入,不落配置文件。
type Admin struct {
	Password string
}

// Log 日志。
type Log struct {
	Level string
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.port", 12346)
	v.SetDefault("server.read_timeout", 10*time.Second)
	v.SetDefault("server.write_timeout", 30*time.Second)
	v.SetDefault("server.idle_timeout", 120*time.Second)
	v.SetDefault("server.behind_proxy", false)
	v.SetDefault("server.trusted_proxies", "")
	v.SetDefault("server.tls_cert", "")
	v.SetDefault("server.tls_key", "")
	v.SetDefault("registration.mode", "open")
	v.SetDefault("registration.token", "")
	v.SetDefault("registration.min_node_ttl", 5*time.Minute)
	v.SetDefault("registration.max_node_ttl", 24*time.Hour)
	v.SetDefault("announce.max_per_node", 1000)
	v.SetDefault("announce.max_ttl", 168*time.Hour)
	v.SetDefault("registration.max_nodes", 5000)
	v.SetDefault("announce.max_total", 50000)
	v.SetDefault("admin.password", "")
	v.SetDefault("log.level", "info")
	// 信令信道（M3；准入由节点签名把守，默认开）
	v.SetDefault("signaling.enabled", true)
	v.SetDefault("signaling.session_ttl", 10*time.Minute)
	v.SetDefault("signaling.idle_timeout", 2*time.Minute)
	v.SetDefault("signaling.hello_timeout", 10*time.Second)
	v.SetDefault("signaling.ping_period", 20*time.Second)
	v.SetDefault("signaling.write_wait", 10*time.Second)
	v.SetDefault("signaling.max_frame_bytes", 16384)
	v.SetDefault("signaling.max_sessions_per_node", 8)
	v.SetDefault("signaling.max_total_sessions", 1024)
	// 配对码（默认开；TTL/寿命/位数/配额见 Pairing 结构注释）
	v.SetDefault("pairing.enabled", true)
	v.SetDefault("pairing.code_ttl", 5*time.Minute)
	v.SetDefault("pairing.session_ttl", 10*time.Minute)
	v.SetDefault("pairing.code_len", 4)
	v.SetDefault("pairing.max_per_node", 8)
	v.SetDefault("pairing.max_total", 4096)
	// 中继(M3 兜底;默认关)+UDP 反射器(打洞前提;默认开)
	v.SetDefault("relay.enabled", true)
	v.SetDefault("relay.port", 12347)
	v.SetDefault("relay.mbps_per_channel", 10)
	v.SetDefault("relay.max_waiting", 1024)
	v.SetDefault("relay.max_conns_per_ip", 16)
	v.SetDefault("relay.waiting_timeout", 60*time.Second)
	v.SetDefault("reflector.enabled", true)
	// 快照持久化(默认关=纯内存)与 metrics 加固
	v.SetDefault("store.snapshot_path", "")
	v.SetDefault("store.snapshot_interval", 30*time.Second)
	v.SetDefault("metrics.strict", false)
}

// knownKeys 合法配置键全集(与 setDefaults 一一对应;Load 未知键告警消费)。
var knownKeys = map[string]bool{
	"server.port": true, "server.read_timeout": true, "server.write_timeout": true,
	"server.idle_timeout": true, "server.behind_proxy": true, "server.trusted_proxies": true,
	"server.tls_cert": true, "server.tls_key": true,
	"registration.mode": true, "registration.token": true,
	"registration.min_node_ttl": true, "registration.max_node_ttl": true,
	"registration.max_nodes": true,
	"announce.max_per_node":  true, "announce.max_ttl": true, "announce.max_total": true,
	"admin.password": true, "log.level": true,
	"signaling.enabled": true, "signaling.session_ttl": true, "signaling.idle_timeout": true,
	"signaling.hello_timeout": true, "signaling.ping_period": true, "signaling.write_wait": true,
	"signaling.max_frame_bytes": true, "signaling.max_sessions_per_node": true,
	"signaling.max_total_sessions": true,
	"pairing.enabled":              true, "pairing.code_ttl": true, "pairing.session_ttl": true,
	"pairing.code_len": true, "pairing.max_per_node": true, "pairing.max_total": true,
	"relay.enabled": true, "relay.port": true, "relay.mbps_per_channel": true,
	"relay.max_waiting": true, "relay.max_conns_per_ip": true, "relay.waiting_timeout": true,
	"reflector.enabled":   true,
	"store.snapshot_path": true, "store.snapshot_interval": true,
	"metrics.strict": true,
}

// Load 读取配置。path 为空时仅用默认值+环境变量。
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetEnvPrefix("PB_P2P")
	v.AutomaticEnv()
	// server.port → PB_P2P_SERVER_PORT
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	setDefaults(v)

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("读取配置 %s: %w", path, err)
		}
	}

	c := &Config{
		Server: Server{
			Port:         v.GetInt("server.port"),
			ReadTimeout:  v.GetDuration("server.read_timeout"),
			WriteTimeout: v.GetDuration("server.write_timeout"),
			IdleTimeout:  v.GetDuration("server.idle_timeout"),
			BehindProxy:  v.GetBool("server.behind_proxy"),
			// 配置文件写 YAML 列表或 env 写逗号分隔均可:GetString 对 YAML 列表
			// 返回 "[a b]" 形式,splitProxies 两种形态都拆得开
			TrustedProxies: splitProxies(v.GetString("server.trusted_proxies")),
			TLSCert:        v.GetString("server.tls_cert"),
			TLSKey:         v.GetString("server.tls_key"),
		},
		Registration: Registration{
			Mode:       v.GetString("registration.mode"),
			Token:      v.GetString("registration.token"),
			MinNodeTTL: v.GetDuration("registration.min_node_ttl"),
			MaxNodeTTL: v.GetDuration("registration.max_node_ttl"),
			// 2026-10-09 修复:此前 defaults 里设了值但 Load 漏读,配置不生效
			// (靠 registry.Service 的内置默认兜底恰好同值才没出事故)
			MaxNodes: v.GetInt("registration.max_nodes"),
		},
		Announce: Announce{
			MaxPerNode: v.GetInt("announce.max_per_node"),
			MaxTTL:     v.GetDuration("announce.max_ttl"),
			MaxTotal:   v.GetInt("announce.max_total"),
		},
		Admin: Admin{
			Password: v.GetString("admin.password"),
		},
		Signaling: Signaling{
			Enabled:            v.GetBool("signaling.enabled"),
			SessionTTL:         v.GetDuration("signaling.session_ttl"),
			IdleTimeout:        v.GetDuration("signaling.idle_timeout"),
			HelloTimeout:       v.GetDuration("signaling.hello_timeout"),
			MaxFrameBytes:      v.GetInt("signaling.max_frame_bytes"),
			MaxSessionsPerNode: v.GetInt("signaling.max_sessions_per_node"),
			MaxTotalSessions:   v.GetInt("signaling.max_total_sessions"),
		},
		Pairing: Pairing{
			Enabled:    v.GetBool("pairing.enabled"),
			CodeTTL:    v.GetDuration("pairing.code_ttl"),
			SessionTTL: v.GetDuration("pairing.session_ttl"),
			CodeLen:    v.GetInt("pairing.code_len"),
			MaxPerNode: v.GetInt("pairing.max_per_node"),
			MaxTotal:   v.GetInt("pairing.max_total"),
		},
		Relay: Relay{
			Enabled:        v.GetBool("relay.enabled"),
			Port:           v.GetInt("relay.port"),
			MbpsPerChannel: v.GetInt64("relay.mbps_per_channel"),
			MaxWaiting:     v.GetInt("relay.max_waiting"),
			MaxConnsPerIP:  v.GetInt("relay.max_conns_per_ip"),
			WaitingTimeout: v.GetDuration("relay.waiting_timeout"),
		},
		Reflector: Reflector{
			Enabled: v.GetBool("reflector.enabled"),
		},
		Store: Store{
			SnapshotPath:     v.GetString("store.snapshot_path"),
			SnapshotInterval: v.GetDuration("store.snapshot_interval"),
		},
		Metrics: Metrics{
			Strict: v.GetBool("metrics.strict"),
		},
		Log: Log{
			Level: v.GetString("log.level"),
		},
	}
	// 未知键告警(P2-9):viper 对拼错的键静默走默认值,是运营事故源
	for _, k := range v.AllKeys() {
		if !knownKeys[k] {
			c.Warnings = append(c.Warnings, "未识别的配置键(将忽略,检查拼写): "+k)
		}
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// splitProxies 解析可信代理网段列表:env 的逗号分隔串 / YAML 列表的
// "[a b]" 串两种形态均支持;空白项丢弃。
func splitProxies(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	var out []string
	for _, p := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *Config) validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port 非法: %d", c.Server.Port)
	}
	for _, p := range c.Server.TrustedProxies {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(p)); err != nil {
			return fmt.Errorf("server.trusted_proxies 项非法(须 CIDR): %q", p)
		}
	}
	switch c.Registration.Mode {
	case "open", "token":
	case "":
		c.Registration.Mode = "open"
	default:
		return fmt.Errorf("registration.mode 仅支持 open|token,当前: %q", c.Registration.Mode)
	}
	if c.Registration.Mode == "token" && c.Registration.Token == "" {
		return fmt.Errorf("registration.mode=token 时必须设置 registration.token(或 PB_P2P_REGISTRATION_TOKEN)")
	}
	if c.Registration.MinNodeTTL <= 0 || c.Registration.MaxNodeTTL < c.Registration.MinNodeTTL {
		return fmt.Errorf("node TTL 区间非法: min=%s max=%s", c.Registration.MinNodeTTL, c.Registration.MaxNodeTTL)
	}
	if c.Announce.MaxPerNode < 1 || c.Announce.MaxTTL <= 0 {
		return fmt.Errorf("announce 配额非法: max_per_node=%d max_ttl=%s", c.Announce.MaxPerNode, c.Announce.MaxTTL)
	}
	if c.Signaling.Enabled {
		if c.Signaling.SessionTTL <= 0 || c.Signaling.IdleTimeout <= 0 || c.Signaling.HelloTimeout <= 0 {
			return fmt.Errorf("signaling 时长参数非法: ttl=%s idle=%s hello=%s",
				c.Signaling.SessionTTL, c.Signaling.IdleTimeout, c.Signaling.HelloTimeout)
		}
		if c.Signaling.MaxFrameBytes < 1024 || c.Signaling.MaxFrameBytes > 1<<20 {
			return fmt.Errorf("signaling.max_frame_bytes 须在 [1KB,1MB],当前: %d", c.Signaling.MaxFrameBytes)
		}
		if c.Signaling.MaxSessionsPerNode < 1 || c.Signaling.MaxTotalSessions < 1 {
			return fmt.Errorf("signaling 会话上限非法: per_node=%d total=%d",
				c.Signaling.MaxSessionsPerNode, c.Signaling.MaxTotalSessions)
		}
	}
	if c.Pairing.Enabled {
		if c.Pairing.CodeTTL <= 0 || c.Pairing.SessionTTL < c.Pairing.CodeTTL {
			return fmt.Errorf("pairing 时长非法: code_ttl=%s session_ttl=%s(须 session_ttl ≥ code_ttl > 0)",
				c.Pairing.CodeTTL, c.Pairing.SessionTTL)
		}
		if c.Pairing.CodeLen < 4 || c.Pairing.CodeLen > 8 {
			return fmt.Errorf("pairing.code_len 须在 [4,8],当前: %d", c.Pairing.CodeLen)
		}
		if c.Pairing.MaxPerNode < 1 || c.Pairing.MaxTotal < 1 {
			return fmt.Errorf("pairing 配额非法: per_node=%d total=%d", c.Pairing.MaxPerNode, c.Pairing.MaxTotal)
		}
	}
	if c.Relay.Enabled {
		if c.Relay.Port < 1 || c.Relay.Port > 65535 {
			return fmt.Errorf("relay.port 非法: %d", c.Relay.Port)
		}
		if c.Relay.MbpsPerChannel < 0 {
			return fmt.Errorf("relay.mbps_per_channel 非法: %d", c.Relay.MbpsPerChannel)
		}
		if c.Relay.MaxWaiting < 0 || c.Relay.MaxConnsPerIP < 0 || c.Relay.WaitingTimeout < 0 {
			return fmt.Errorf("relay 容量参数不可为负: max_waiting=%d max_conns_per_ip=%d waiting_timeout=%s",
				c.Relay.MaxWaiting, c.Relay.MaxConnsPerIP, c.Relay.WaitingTimeout)
		}
	}
	// TLS:要么都配要么都不配;证书文件存在性由启动时加载报错(此处只查形态)
	if (c.Server.TLSCert == "") != (c.Server.TLSKey == "") {
		return fmt.Errorf("server.tls_cert 与 server.tls_key 必须同时设置(或同时留空走明文)")
	}
	return nil
}
