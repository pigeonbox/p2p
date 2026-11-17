// Package config 加载 p2pd 配置。
//
// 优先级(高→低): PB_P2P_* 环境变量 > 配置文件(--config / CONFIG_PATH) > 内置默认。
// 所有键均有默认值,配置文件可省略。
package config

import (
	"fmt"
	"net"
	"strconv"
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
	// IdleTimeout 配对后管道空闲上限(0=内置默认 2min;无字节即关,与信令
	// idle_timeout 口径对齐)。env: PB_P2P_RELAY_IDLE_TIMEOUT
	IdleTimeout time.Duration
	// MaxChannelLifetime 配对后管道最长生命周期(0=内置默认 30min;持续流量
	// 也不顺延)。env: PB_P2P_RELAY_MAX_CHANNEL_LIFETIME
	MaxChannelLifetime time.Duration
	// MaxActiveChannels 全局活动信道上限(0=内置默认 1024;对齐 max_waiting
	// 的容量设计,超限拒绝新配对)。env: PB_P2P_RELAY_MAX_ACTIVE_CHANNELS
	MaxActiveChannels int
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

// Direct 直传客户端策略(p2p#51:中继回退的触发条件与延迟)。
//
// 决策方在**客户端**(p2pc):回退与否由客户端的打洞结果决定,p2pd 不参与
// ⇒ 这些旋钮**不进 p2pd 的配置文件键集**(避免 p2pd#38 同款「死配置」:
// 登记了键却没人读)。注入方式是环境变量(PB_P2P_DIRECT_*),与本包的 env
// 约定同构(PB_P2P 前缀 + "."→"_" 替换)。
//
// ⚠️ 缺省值逐字等于 2026-11-15 前的硬编码行为 ⇒ **不配置时行为与今天
// 完全一致**(回退决策链见 internal/client/client.go 的 establish)。
type Direct struct {
	// FastPunchBudget 快打洞预算:直连尝试多久后回退中继(=回退触发延迟)。
	// 缺省 1.5s(与旧硬编码一致)。env: PB_P2P_DIRECT_FAST_PUNCH_BUDGET
	FastPunchBudget time.Duration
	// PunchBudget 长打洞兜底预算:回退路径里「没有中继可用」时的直连尝试
	// 时长。缺省 4s(与 client.Options.PunchBudget 的缺省一致)。
	// env: PB_P2P_DIRECT_PUNCH_BUDGET
	PunchBudget time.Duration
	// RelayProbeTimeout 中继可达性探测超时:探测窗口多长算中继不可用。
	// 缺省 2s(与旧硬编码一致)。env: PB_P2P_DIRECT_RELAY_PROBE_TIMEOUT
	RelayProbeTimeout time.Duration
	// RelayFallbackEnabled 是否允许回退中继(false=只长打洞兜底,等同
	// client.Options.NoRelay 的语义)。缺省 true(中继是打洞失败的必要兜底)。
	// env: PB_P2P_DIRECT_RELAY_FALLBACK_ENABLED
	RelayFallbackEnabled bool
}

// 直传策略缺省值(逐字等于 2026-11-15 前的硬编码行为;改动即改行为,须同步
// internal/client 的回退决策链与本包的断言)。
const (
	DefaultDirectFastPunchBudget     = 1500 * time.Millisecond
	DefaultDirectPunchBudget         = 4 * time.Second
	DefaultDirectRelayProbeTimeout   = 2 * time.Second
	DefaultDirectRelayFallbackEnable = true
)

// LoadDirect 读取直传策略:环境变量优先,缺省=内置缺省。
//
// 返回的告警串由调用方打日志(客户端侧)。非法取值**钳回缺省**而非报错:
// p2pc 是无状态 CLI,策略拼错不该让它起不来(p2pd 侧的配置错误是
// refuse-to-start,这里是 best-effort + 告警)。
func LoadDirect() (Direct, []string) {
	v := viper.New()
	v.SetEnvPrefix("PB_P2P")
	v.AutomaticEnv()
	// direct.fast_punch_budget → PB_P2P_DIRECT_FAST_PUNCH_BUDGET
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetDefault("direct.fast_punch_budget", DefaultDirectFastPunchBudget)
	v.SetDefault("direct.punch_budget", DefaultDirectPunchBudget)
	v.SetDefault("direct.relay_probe_timeout", DefaultDirectRelayProbeTimeout)
	v.SetDefault("direct.relay_fallback_enabled", DefaultDirectRelayFallbackEnable)
	d := Direct{
		FastPunchBudget:   v.GetDuration("direct.fast_punch_budget"),
		PunchBudget:       v.GetDuration("direct.punch_budget"),
		RelayProbeTimeout: v.GetDuration("direct.relay_probe_timeout"),
	}
	// 开关自己解析(不走 viper.GetBool):cast.ToBool 对无法识别的串一律给
	// false ⇒ 一次手误("flase")就会**静默关掉中继回退**。这里只认白名单
	// 取值,其余折回缺省并告警(不能静默:运维要知道自己写错了)。
	var warns []string
	switch strings.ToLower(strings.TrimSpace(v.GetString("direct.relay_fallback_enabled"))) {
	case "1", "t", "true", "yes", "y", "on":
		d.RelayFallbackEnabled = true
	case "0", "f", "false", "no", "n", "off":
		d.RelayFallbackEnabled = false
	default:
		warns = append(warns, "direct.relay_fallback_enabled 取值非法,已回退缺省 "+strconv.FormatBool(DefaultDirectRelayFallbackEnable))
		d.RelayFallbackEnabled = DefaultDirectRelayFallbackEnable
	}
	d, normWarns := NormalizeDirect(d)
	return d, append(warns, normWarns...)
}

// NormalizeDirect 钳制策略取值:非法值回退缺省,返回告警串。
//
// 客户端显式指定策略时也走这里(显式值同样要过钳制——零值/负值会让打洞
// 预算变成 0 ⇒ 快打洞立刻判负 ⇒ 行为比不配置更糟)。
func NormalizeDirect(d Direct) (Direct, []string) {
	var warns []string
	if d.FastPunchBudget <= 0 {
		warns = append(warns, "direct.fast_punch_budget 取值非法,已回退缺省 "+DefaultDirectFastPunchBudget.String())
		d.FastPunchBudget = DefaultDirectFastPunchBudget
	}
	if d.PunchBudget <= 0 {
		warns = append(warns, "direct.punch_budget 取值非法,已回退缺省 "+DefaultDirectPunchBudget.String())
		d.PunchBudget = DefaultDirectPunchBudget
	}
	if d.RelayProbeTimeout <= 0 {
		warns = append(warns, "direct.relay_probe_timeout 取值非法,已回退缺省 "+DefaultDirectRelayProbeTimeout.String())
		d.RelayProbeTimeout = DefaultDirectRelayProbeTimeout
	}
	return d, warns
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
	// PingPeriod 服务端 ping 周期(须 < IdleTimeout,否则读截止先于首次 ping
	// 触发 ⇒ 心跳永远来不及发,健康连接被空闲超时踢掉)。env: PB_P2P_SIGNALING_PING_PERIOD
	PingPeriod time.Duration
	// WriteWait 单次写/控制帧超时。env: PB_P2P_SIGNALING_WRITE_WAIT
	WriteWait time.Duration
	// MaxFrameBytes data 帧负载上限（字节）。env: PB_P2P_SIGNALING_MAX_FRAME_BYTES
	MaxFrameBytes int
	// MaxSessionsPerNode 单节点并发会话上限。env: PB_P2P_SIGNALING_MAX_PER_NODE
	MaxSessionsPerNode int
	// MaxTotalSessions 全局并发会话上限。env: PB_P2P_SIGNALING_MAX_TOTAL
	MaxTotalSessions int
	// MaxUnpairedPerIP 单 IP 未配对(waiting)会话上限(p2p#46;0=不限)。
	// env: PB_P2P_SIGNALING_MAX_UNPAIRED_PER_IP
	MaxUnpairedPerIP int
	// UnpairedTTL 未配对会话短 TTL(p2p#46;0 或 >session_ttl 时退回
	// session_ttl)。env: PB_P2P_SIGNALING_UNPAIRED_TTL
	UnpairedTTL time.Duration
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
	v.SetDefault("signaling.max_unpaired_per_ip", 64)
	v.SetDefault("signaling.unpaired_ttl", 5*time.Minute)
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
	v.SetDefault("relay.idle_timeout", 2*time.Minute)
	v.SetDefault("relay.max_channel_lifetime", 30*time.Minute)
	v.SetDefault("relay.max_active_channels", 1024)
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
	"signaling.max_total_sessions":  true,
	"signaling.max_unpaired_per_ip": true, "signaling.unpaired_ttl": true,
	"pairing.enabled": true, "pairing.code_ttl": true, "pairing.session_ttl": true,
	"pairing.code_len": true, "pairing.max_per_node": true, "pairing.max_total": true,
	"relay.enabled": true, "relay.port": true, "relay.mbps_per_channel": true,
	"relay.max_waiting": true, "relay.max_conns_per_ip": true, "relay.waiting_timeout": true,
	"relay.idle_timeout": true, "relay.max_channel_lifetime": true, "relay.max_active_channels": true,
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
			Enabled:      v.GetBool("signaling.enabled"),
			SessionTTL:   v.GetDuration("signaling.session_ttl"),
			IdleTimeout:  v.GetDuration("signaling.idle_timeout"),
			HelloTimeout: v.GetDuration("signaling.hello_timeout"),
			// 2026-11-13 修复(p2p#38):此前 defaults+knownKeys 登记了这两个键但
			// 结构体无字段、Load 漏读 ⇒ 死配置(拼错键会告警、改这两个键零告警
			// 且改了等于没改),server.New 另用字面量硬编码。
			PingPeriod:         v.GetDuration("signaling.ping_period"),
			WriteWait:          v.GetDuration("signaling.write_wait"),
			MaxFrameBytes:      v.GetInt("signaling.max_frame_bytes"),
			MaxSessionsPerNode: v.GetInt("signaling.max_sessions_per_node"),
			MaxTotalSessions:   v.GetInt("signaling.max_total_sessions"),
			MaxUnpairedPerIP:   v.GetInt("signaling.max_unpaired_per_ip"),
			UnpairedTTL:        v.GetDuration("signaling.unpaired_ttl"),
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
			Enabled:            v.GetBool("relay.enabled"),
			Port:               v.GetInt("relay.port"),
			MbpsPerChannel:     v.GetInt64("relay.mbps_per_channel"),
			MaxWaiting:         v.GetInt("relay.max_waiting"),
			MaxConnsPerIP:      v.GetInt("relay.max_conns_per_ip"),
			WaitingTimeout:     v.GetDuration("relay.waiting_timeout"),
			IdleTimeout:        v.GetDuration("relay.idle_timeout"),
			MaxChannelLifetime: v.GetDuration("relay.max_channel_lifetime"),
			MaxActiveChannels:  v.GetInt("relay.max_active_channels"),
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
		// p2p#38:兑现 Config.PingPeriod 注释里已声明的不变量。此前 PingPeriod
		// 不可配、validate 只查 IdleTimeout>0 ⇒ 运维把 idle_timeout 调到 ≤ ping
		// 周期时 validate 放行、启动成功,但 readPump 的读截止先于 pingPump 首次
		// ping 触发 ⇒ 所有信令连接必然被空闲超时踢掉(两端其实都健康)。
		// >0 同查:接入配置后 time.NewTicker(0) 会 panic、写截止立即到期。
		if c.Signaling.PingPeriod <= 0 || c.Signaling.WriteWait <= 0 || c.Signaling.PingPeriod >= c.Signaling.IdleTimeout {
			return fmt.Errorf("signaling 时长参数非法: ping=%s write_wait=%s(须 ping>0、write_wait>0、ping<idle=%s)",
				c.Signaling.PingPeriod, c.Signaling.WriteWait, c.Signaling.IdleTimeout)
		}
		if c.Signaling.MaxFrameBytes < 1024 || c.Signaling.MaxFrameBytes > 1<<20 {
			return fmt.Errorf("signaling.max_frame_bytes 须在 [1KB,1MB],当前: %d", c.Signaling.MaxFrameBytes)
		}
		if c.Signaling.MaxSessionsPerNode < 1 || c.Signaling.MaxTotalSessions < 1 {
			return fmt.Errorf("signaling 会话上限非法: per_node=%d total=%d",
				c.Signaling.MaxSessionsPerNode, c.Signaling.MaxTotalSessions)
		}
		if c.Signaling.MaxUnpairedPerIP < 0 || c.Signaling.UnpairedTTL < 0 {
			return fmt.Errorf("signaling p2p#46 配额不可为负: max_unpaired_per_ip=%d unpaired_ttl=%s",
				c.Signaling.MaxUnpairedPerIP, c.Signaling.UnpairedTTL)
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
		if c.Relay.MaxWaiting < 0 || c.Relay.MaxConnsPerIP < 0 || c.Relay.WaitingTimeout < 0 ||
			c.Relay.IdleTimeout < 0 || c.Relay.MaxChannelLifetime < 0 || c.Relay.MaxActiveChannels < 0 {
			return fmt.Errorf("relay 容量参数不可为负: max_waiting=%d max_conns_per_ip=%d waiting_timeout=%s idle_timeout=%s max_channel_lifetime=%s max_active_channels=%d",
				c.Relay.MaxWaiting, c.Relay.MaxConnsPerIP, c.Relay.WaitingTimeout,
				c.Relay.IdleTimeout, c.Relay.MaxChannelLifetime, c.Relay.MaxActiveChannels)
		}
	}
	// TLS:要么都配要么都不配;证书文件存在性由启动时加载报错(此处只查形态)
	if (c.Server.TLSCert == "") != (c.Server.TLSKey == "") {
		return fmt.Errorf("server.tls_cert 与 server.tls_key 必须同时设置(或同时留空走明文)")
	}
	return nil
}
