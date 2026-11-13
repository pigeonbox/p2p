package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSplitProxies(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"10.0.0.0/8", []string{"10.0.0.0/8"}},
		{"10.0.0.0/8,172.16.0.0/12", []string{"10.0.0.0/8", "172.16.0.0/12"}},
		{" 10.0.0.0/8 , 172.16.0.0/12 ", []string{"10.0.0.0/8", "172.16.0.0/12"}},
		// YAML 列表经 GetString 的形态
		{"[10.0.0.0/8 172.16.0.0/12]", []string{"10.0.0.0/8", "172.16.0.0/12"}},
		{",,", nil},
	}
	for _, c := range cases {
		got := splitProxies(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("splitProxies(%q)=%v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("splitProxies(%q)=%v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestLoadUnknownKeyWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "server:\n  port: 12346\n  prot: 12345\n" // prot=拼写错误
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Warnings) == 0 {
		t.Fatal("拼写错误的键应产生告警")
	}
	found := false
	for _, w := range c.Warnings {
		if strings.Contains(w, "server.prot") {
			found = true
		}
	}
	if !found {
		t.Fatalf("告警应点名 server.prot: %v", c.Warnings)
	}
	if c.Server.Port != 12346 {
		t.Fatalf("合法键不受影响: %d", c.Server.Port)
	}
}

func TestLoadCapacityKeysReachStructs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// 2026-10-09 前这两个键 defaults 有值但 Load 漏读(死配置)
	body := "registration:\n  max_nodes: 123\nannounce:\n  max_total: 456\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Registration.MaxNodes != 123 || c.Announce.MaxTotal != 456 {
		t.Fatalf("容量键未生效: max_nodes=%d max_total=%d", c.Registration.MaxNodes, c.Announce.MaxTotal)
	}
}

func TestTLSValidation(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	c.Server.TLSCert = "/tmp/a.pem"
	if err := c.validate(); err == nil {
		t.Fatal("只配证书不配私钥应报错")
	}
	c.Server.TLSKey = "/tmp/a.key"
	if err := c.validate(); err != nil {
		t.Fatalf("成对配置应通过: %v", err)
	}
}

func TestRelayCapacityValidation(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	c.Relay.Enabled = true
	c.Relay.MaxConnsPerIP = -1
	if err := c.validate(); err == nil {
		t.Fatal("负容量应报错")
	}
	c.Relay.MaxConnsPerIP = 0 // 0=用内置默认,合法
	c.Relay.WaitingTimeout = 45 * time.Second
	if err := c.validate(); err != nil {
		t.Fatalf("合法容量应通过: %v", err)
	}
}

// p2p#38 死配置判据(与 TestLoadCapacityKeysReachStructs 同形状):
// signaling.ping_period / write_wait 此前 defaults+knownKeys 都有,但结构体
// 无字段、Load 漏读 ⇒ 拼错键会告警、改这两个键却零告警且改了等于没改。
func TestLoadSignalingPingWriteWaitReachStructs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "signaling:\n  ping_period: 3s\n  write_wait: 77s\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Signaling.PingPeriod != 3*time.Second || c.Signaling.WriteWait != 77*time.Second {
		t.Fatalf("ping/write_wait 未生效(死配置?): ping=%s write_wait=%s",
			c.Signaling.PingPeriod, c.Signaling.WriteWait)
	}
	if len(c.Warnings) != 0 {
		t.Fatalf("合法键不应产生告警: %v", c.Warnings)
	}
}

// p2p#38 不变量判据:启动期必须拒绝(PingPeriod ≥ IdleTimeout 会让读截止先于
// 首次 ping 触发 ⇒ 心跳永远来不及发,健康连接必然被空闲超时踢掉),不许静默放行。
func TestSignalingPingPeriodBelowIdleTimeoutRejected(t *testing.T) {
	defaults, err := Load("") // 20s/10s/idle 120s:存量默认必须仍通过
	if err != nil {
		t.Fatal(err)
	}
	if err := defaults.validate(); err != nil {
		t.Fatalf("默认参数必须通过校验: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		wantOK bool
	}{
		{"ping 等于 idle(违例)", func(c *Config) { c.Signaling.PingPeriod = c.Signaling.IdleTimeout }, false},
		{"ping 大于 idle(违例)", func(c *Config) { c.Signaling.PingPeriod = c.Signaling.IdleTimeout + time.Second }, false},
		{"ping 为 0(Ticker panic 面)", func(c *Config) { c.Signaling.PingPeriod = 0 }, false},
		{"ping 为负(违例)", func(c *Config) { c.Signaling.PingPeriod = -time.Second }, false},
		{"write_wait 为 0(写截止立即到期)", func(c *Config) { c.Signaling.WriteWait = 0 }, false},
		{"ping 小于 idle(合法)", func(c *Config) { c.Signaling.PingPeriod = c.Signaling.IdleTimeout - time.Second }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load("")
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(c)
			err = c.validate()
			if tc.wantOK && err != nil {
				t.Fatalf("合法参数应通过: %v", err)
			}
			if !tc.wantOK {
				if err == nil {
					t.Fatal("违例参数必须被启动期拒绝(而非静默生效)")
				}
				if !strings.Contains(err.Error(), "signaling 时长参数非法") {
					t.Fatalf("报错应与其他 signaling 校验同款措辞,得到: %v", err)
				}
			}
		})
	}
}
