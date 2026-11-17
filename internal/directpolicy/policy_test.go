package directpolicy

import (
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// ---- 参考实现(viper 口径)与对账 ----

// refLoadViper 是本包落地前的**原实现**(internal/config 里的 viper 版本)逐字复刻。
//
// 它只活在测试里:生产代码必须无 viper(见 TestNoViperDependencyInClientPath),
// 但「换实现」必须证明**行为逐字不变** ⇒ 这里保留一份旧口径做逐项对账。
func refLoadViper() (Policy, []string) {
	v := viper.New()
	v.SetEnvPrefix("PB_P2P")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetDefault("direct.fast_punch_budget", DefaultFastPunchBudget)
	v.SetDefault("direct.punch_budget", DefaultPunchBudget)
	v.SetDefault("direct.relay_probe_timeout", DefaultRelayProbeTimeout)
	v.SetDefault("direct.relay_fallback_enabled", DefaultRelayFallbackEnable)
	d := Policy{
		FastPunchBudget:   v.GetDuration("direct.fast_punch_budget"),
		PunchBudget:       v.GetDuration("direct.punch_budget"),
		RelayProbeTimeout: v.GetDuration("direct.relay_probe_timeout"),
	}
	var warns []string
	switch strings.ToLower(strings.TrimSpace(v.GetString("direct.relay_fallback_enabled"))) {
	case "1", "t", "true", "yes", "y", "on":
		d.RelayFallbackEnabled = true
	case "0", "f", "false", "no", "n", "off":
		d.RelayFallbackEnabled = false
	default:
		warns = append(warns, "direct.relay_fallback_enabled 取值非法,已回退缺省 "+strconv.FormatBool(DefaultRelayFallbackEnable))
		d.RelayFallbackEnabled = DefaultRelayFallbackEnable
	}
	d, normWarns := Normalize(d)
	return d, append(warns, normWarns...)
}

// allEnvKeys 四个策略环境变量键(测试里逐个清空以保证缺省口径)。
var allEnvKeys = []string{
	EnvFastPunchBudget,
	EnvPunchBudget,
	EnvRelayProbeTimeout,
	EnvRelayFallbackEnable,
}

// clearEnv 清空策略环境变量(空值按未设置处理)。
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range allEnvKeys {
		t.Setenv(k, "")
	}
}

// TestLoadDefaults 缺省取值必须逐字等于 2026-11-15 前的硬编码行为。
func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	p, warns := Load()
	if len(warns) != 0 {
		t.Fatalf("缺省不应告警: %v", warns)
	}
	if p.FastPunchBudget != 1500*time.Millisecond {
		t.Fatalf("快打洞预算缺省 = %s, want 1.5s", p.FastPunchBudget)
	}
	if p.PunchBudget != 4*time.Second {
		t.Fatalf("长打洞预算缺省 = %s, want 4s", p.PunchBudget)
	}
	if p.RelayProbeTimeout != 2*time.Second {
		t.Fatalf("中继探测超时缺省 = %s, want 2s", p.RelayProbeTimeout)
	}
	if !p.RelayFallbackEnabled {
		t.Fatal("中继回退缺省应为启用")
	}
}

// TestParityWithViperReference 与原 viper 实现**逐项对账**:取值与告警
// (含顺序与文案)都必须逐字相同。
//
// 负对照:任何一侧改动口径(例如时长解析规则、布尔白名单、告警文案或
// 告警出现顺序)⇒ 本用例变红 —— 这正是「换实现不改行为」的机器证明。
func TestParityWithViperReference(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"全部未设置", nil},
		{"合法覆盖", map[string]string{
			EnvFastPunchBudget:     "800ms",
			EnvPunchBudget:         "6s",
			EnvRelayProbeTimeout:   "300ms",
			EnvRelayFallbackEnable: "false",
		}},
		{"时长解析失败", map[string]string{EnvFastPunchBudget: "not-a-duration"}},
		{"时长为零", map[string]string{EnvFastPunchBudget: "0"}},
		{"时长为负", map[string]string{EnvFastPunchBudget: "-1s"}},
		{"无单位数字(纳秒口径)", map[string]string{EnvFastPunchBudget: "5"}},
		{"天单位(无单位字母⇒按纳秒解析⇒非法)", map[string]string{EnvFastPunchBudget: "5d"}},
		{"小时", map[string]string{EnvRelayProbeTimeout: "1h"}},
		{"小数秒", map[string]string{EnvPunchBudget: "1.5s"}},
		{"微秒", map[string]string{EnvPunchBudget: "1500us"}},
		{"布尔手误", map[string]string{EnvRelayFallbackEnable: "flase"}},
		{"布尔未知值", map[string]string{EnvRelayFallbackEnable: "maybe"}},
		{"布尔真值集", map[string]string{EnvRelayFallbackEnable: "1"}},
		{"布尔假值集", map[string]string{EnvRelayFallbackEnable: "0"}},
		{"布尔 yes/no", map[string]string{EnvRelayFallbackEnable: "yes"}},
		{"布尔 n", map[string]string{EnvRelayFallbackEnable: "n"}},
		{"布尔 ON/OFF", map[string]string{EnvRelayFallbackEnable: "ON"}},
		{"布尔 OFF", map[string]string{EnvRelayFallbackEnable: "OFF"}},
		{"布尔带空格", map[string]string{EnvRelayFallbackEnable: "  true  "}},
		{"布尔空串(按未设置)", map[string]string{EnvRelayFallbackEnable: ""}},
		{"时长与布尔同时非法(告警顺序)", map[string]string{
			EnvFastPunchBudget:     "not-a-duration",
			EnvRelayFallbackEnable: "flase",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			got, gotWarns := Load()
			want, wantWarns := refLoadViper()
			if got != want {
				t.Fatalf("取值漂移:\n got=%+v\nwant=%+v", got, want)
			}
			if !reflect.DeepEqual(gotWarns, wantWarns) {
				t.Fatalf("告警漂移:\n got=%v\nwant=%v", gotWarns, wantWarns)
			}
		})
	}
}

// TestNormalizeClamps 显式指定的策略同样要过钳制(零值/负值 ⇒ 快打洞立刻
// 判负 ⇒ 行为比不配置更糟)。
func TestNormalizeClamps(t *testing.T) {
	p, warns := Normalize(Policy{})
	if len(warns) != 3 {
		t.Fatalf("零值策略应告警 3 条, got %d: %v", len(warns), warns)
	}
	if p.FastPunchBudget != DefaultFastPunchBudget ||
		p.PunchBudget != DefaultPunchBudget ||
		p.RelayProbeTimeout != DefaultRelayProbeTimeout {
		t.Fatalf("零值策略未钳回缺省: %+v", p)
	}
}

// ---- 机器守卫:生产路径不得链入 viper ----

// TestNoViperDependencyInClientPath 直传策略所在包与客户端包**不得**依赖
// viper(或经 internal/config 间接依赖)。
//
// 为什么是硬门:internal/config 带 viper,而 p2pc 二进制只需要直传策略
// ⇒ 策略留在 config 会把 viper(+~900KB)链进 p2pc;NAS 三端随包发的 p2pc
// 也一起胖。
//
// 负对照:任何人在 client/config 侧重新 import viper 或 internal/config ⇒
// 本用例变红。
func TestNoViperDependencyInClientPath(t *testing.T) {
	forbidden := map[string]string{
		"github.com/spf13/viper":                   "viper 会把 p2pc 二进制撑大 ~900KB",
		"github.com/pigeonbox/p2p/internal/config": "internal/config 带 viper ⇒ 等价于把 viper 链进 p2pc",
	}
	// "." = 本包(directpolicy);"../client" = 客户端包。
	// _test.go 不在扫描范围:测试二进制不随包分发,不影响产物体积。
	for _, dir := range []string{".", "../client"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatalf("扫描 %s 失败: %v", dir, err)
		}
		if len(files) == 0 {
			t.Fatalf("扫描 %s 一个文件都没扫到(路径写错?)", dir)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("解析 %s 失败: %v", f, err)
			}
			for _, imp := range af.Imports {
				p := strings.Trim(imp.Path.Value, "\"")
				if why, bad := forbidden[p]; bad {
					t.Errorf("%s 不得 import %s(%s)", f, p, why)
				}
			}
		}
	}
}

// TestP2PCBinaryDepsHaveNoViper 终局口径:p2pc 的**依赖树**里没有 viper。
//
// 这是 AST 守卫的兜底(能抓「经第三方的间接依赖」)。工具链不可用时跳过
// (离线环境),主门禁仍是上面的 AST 守卫。
func TestP2PCBinaryDepsHaveNoViper(t *testing.T) {
	if testing.Short() {
		t.Skip("短跑模式跳过依赖树检查")
	}
	cmd := exec.Command("go", "list", "-deps", "./cmd/p2pc")
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("go list 不可用(离线/无工具链),跳过: %v", err)
	}
	if strings.Contains(string(out), "github.com/spf13/viper") {
		t.Fatal("p2pc 依赖树里出现 viper ⇒ 直传策略必须留在 internal/directpolicy(无 viper 子包)")
	}
}
