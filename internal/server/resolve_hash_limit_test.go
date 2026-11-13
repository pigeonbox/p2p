package server

import (
	"net/http"
	"testing"

	"github.com/pigeonbox/p2p/internal/registry"
)

// TestResolveHashLimitSharesNormalizedKey per-hash 限流键必须与业务键同源归一
// (registry.NormalizeHash 单源):空白变体若各拿一份 burst,「IP 池绕不过」的
// 枚举防线即静默失效(p2p#37)。
//
// 两段判据分别钉住两侧,任一处回退即转红:
//  1. 业务键段(基线):变体必须与规范键命中同一公告 —— 404 ⇒ 业务侧归一漏;
//  2. 限流键段:规范键打满后,变体必须 429 —— 200 ⇒ 限流键漏归一(各拿新桶)。
func TestResolveHashLimitSharesNormalizedKey(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	c := testClient{t: t, base: ts}
	k := newNodeKey(t)
	if resp := c.register(k, "https://a.example.com"); resp.StatusCode != 200 {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	const code = "http-code-1234567890"
	if resp := c.announce(k, code); resp.StatusCode != 200 {
		t.Fatalf("announce: %d", resp.StatusCode)
	}
	hash := registry.CodeHash(code)

	// issue p2p#37 列举的形态:前后缀 %20 / %09;外加全角空格(unicode.IsSpace,
	// TrimSpace 同样吃掉,task 口径「全角空格类」)。
	variants := []struct{ name, path string }{
		{"尾随空格", hash + "%20"},
		{"前导空格", "%20" + hash},
		{"尾随tab", hash + "%09"},
		{"尾随全角空格", hash + "%E3%80%80"},
		{"前导全角空格", "%E3%80%80" + hash},
	}

	// 基线:规范键可解析。
	resp, body := c.do(http.MethodGet, "/v1/resolve/"+hash, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("规范键基线: %d %s", resp.StatusCode, body)
	}
	// 判据 1(业务键):变体必须命中同一公告 —— 否则业务侧归一与公告键脱钩。
	for _, v := range variants {
		resp, body := c.do(http.MethodGet, "/v1/resolve/"+v.path, nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s 变体应命中同一公告(业务键同源归一),得到 %d %s", v.name, resp.StatusCode, body)
		}
	}

	// 打满规范键的 per-hash 桶(burst 60,10/s 回填)。
	// 预算:基线 1+5 + 打满 ≤80 + 变体复查 ≤25 = ≤111 < per-IP 桶(resolveLim
	// burst 120),保证先见 per-hash 429 而非 per-IP 429(两者同码同体,靠预算区分)。
	sawLimit := false
	for i := 0; i < 80; i++ {
		resp, _ := c.do(http.MethodGet, "/v1/resolve/"+hash, nil, nil)
		if resp.StatusCode == http.StatusTooManyRequests {
			sawLimit = true
			break
		}
	}
	if !sawLimit {
		t.Fatal("规范键 80 次内未触发 per-hash 429")
	}

	// 判据 2(限流键):变体此刻必须同桶受限(修复前各自新桶 ⇒ 恒 200)。
	// 每形态最多 5 次:容忍回填 1~2 个令牌(10/s),修复前自己的桶有 60 ⇒ 不可能 429。
	for _, v := range variants {
		limited := false
		for i := 0; i < 5; i++ {
			resp, _ := c.do(http.MethodGet, "/v1/resolve/"+v.path, nil, nil)
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("%s 变体意外状态 %d", v.name, resp.StatusCode)
			}
			if resp.StatusCode == http.StatusTooManyRequests {
				limited = true
				break
			}
		}
		if !limited {
			t.Fatalf("%s 变体绕过同桶限流(期望 429):限流键未与业务键同源归一", v.name)
		}
	}
}
