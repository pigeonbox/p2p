package registry

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ---- T1 名录(presence directory) ----

const testBoxPub = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 字节 hex

// dirRegister 注册（可带名录扩展字段；新字段齐发=扩展负载签名）。
func dirRegister(t *testing.T, f *fixture, n testNode, discoverable bool, publicURL, boxPub string) {
	t.Helper()
	in := RegisterInput{
		NodeID: n.id, URL: "https://node.example.com", Name: "node-" + n.id[:6], Version: "v1",
		Caps: []string{"download"}, TTLSeconds: 3600, Nonce: "n-" + n.id[:8], TS: time.Now().Unix(),
		Discoverable: &discoverable, PublicURL: publicURL, BoxPub: boxPub,
	}
	in.Sig = n.sign(t, in.NodeID, in.URL, in.Name, in.Version, "download",
		itoa(in.TTLSeconds), in.Nonce, itoa(in.TS),
		"1", publicURL, boxPub) // 扩展负载:追加 discoverable|public_url|box_pub
	if _, err := f.svc.RegisterNode(context.Background(), in, "10.0.0.1"); err != nil {
		t.Fatalf("注册失败: %v", err)
	}
}

func TestDirectoryOnlyDiscoverable(t *testing.T) {
	f := newFixture(t)
	a, b := newNode(t), newNode(t)
	dirRegister(t, f, a, true, "https://a.example.com", testBoxPub)
	f.register(t, b, 3600) // 旧格式注册=不可发现

	entries, err := f.svc.Directory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("名录应仅含 discoverable 节点,实得 %d: %+v", len(entries), entries)
	}
	if entries[0].NodeID != a.id || entries[0].BoxPub != testBoxPub ||
		entries[0].URL != "https://a.example.com" || entries[0].Name == "" {
		t.Fatalf("名录条目字段不符: %+v", entries[0])
	}
	if entries[0].OnlineSince <= 0 {
		t.Fatalf("online_since 缺失: %+v", entries[0])
	}
}

func TestDirectoryLeaseExpiry(t *testing.T) {
	f := newFixture(t)
	a := newNode(t)
	dirRegister(t, f, a, true, "https://a.example.com", testBoxPub)

	entries, _ := f.svc.Directory(context.Background())
	if len(entries) != 1 {
		t.Fatalf("注册后应可见: %d", len(entries))
	}
	// 推进时钟越过租约
	f.svc.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	entries, _ = f.svc.Directory(context.Background())
	if len(entries) != 0 {
		t.Fatalf("租约过期后应不可见: %d", len(entries))
	}
}

func TestRegisterExtendedFieldsForgedRejected(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	// 携带扩展字段但只签旧负载 → 必须拒绝（防旧签名客户端伪装 discoverable）
	in := RegisterInput{
		NodeID: n.id, URL: "https://n.example.com", Name: "n", Version: "v1",
		Caps: []string{"download"}, TTLSeconds: 3600, Nonce: "nx", TS: time.Now().Unix(),
		Discoverable: &[]bool{true}[0], PublicURL: "https://n.example.com", BoxPub: testBoxPub,
	}
	in.Sig = n.sign(t, in.NodeID, in.URL, in.Name, in.Version, "download",
		itoa(in.TTLSeconds), in.Nonce, itoa(in.TS)) // 旧格式签名
	_, err := f.svc.RegisterNode(context.Background(), in, "10.0.0.1")
	if err == nil || !strings.Contains(err.Error(), ErrBadSignature.Error()) {
		t.Fatalf("扩展字段须扩展签名,伪造应拒绝: %v", err)
	}
}

func TestRegisterOldClientPresenceSticky(t *testing.T) {
	f := newFixture(t)
	a := newNode(t)
	dirRegister(t, f, a, true, "https://a.example.com", testBoxPub)
	// 旧格式续租(不带扩展字段): 名录状态必须保留而非清零
	// (federation 心跳/p2pc 直传双写同一 node_id,非 sticky 互踩)
	in := RegisterInput{
		NodeID: a.id, URL: "http://direct.invalid", Name: "renamed", Version: "v2",
		Caps: []string{"direct"}, TTLSeconds: 3600, Nonce: "n2", TS: time.Now().Unix(),
	}
	in.Sig = a.sign(t, in.NodeID, in.URL, in.Name, in.Version, "direct",
		itoa(in.TTLSeconds), in.Nonce, itoa(in.TS))
	if _, err := f.svc.RegisterNode(context.Background(), in, "10.0.0.2"); err != nil {
		t.Fatal(err)
	}
	entries, _ := f.svc.Directory(context.Background())
	if len(entries) != 1 || entries[0].BoxPub != testBoxPub || entries[0].URL != "https://a.example.com" {
		t.Fatalf("旧格式续租不得清除名录状态: %+v", entries)
	}
}

func TestRegisterDiscoverableRequiresBoxPub(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	in := RegisterInput{
		NodeID: n.id, URL: "https://n.example.com", Name: "n", Version: "v1",
		Caps: []string{"download"}, TTLSeconds: 3600, Nonce: "nb", TS: time.Now().Unix(),
		Discoverable: &[]bool{true}[0],
	}
	in.Sig = n.sign(t, in.NodeID, in.URL, in.Name, in.Version, "download",
		itoa(in.TTLSeconds), in.Nonce, itoa(in.TS), "1", "", "")
	if _, err := f.svc.RegisterNode(context.Background(), in, "10.0.0.1"); err == nil {
		t.Fatal("discoverable 缺 box_pub 须拒绝(名录条目必须可被密封)")
	}
}

func TestRegisterBoxPubValidation(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	badHex := "zzzz" // 非 hex
	in := RegisterInput{
		NodeID: n.id, URL: "https://n.example.com", Name: "n", Version: "v1",
		Caps: []string{"download"}, TTLSeconds: 3600, Nonce: "nc", TS: time.Now().Unix(),
		Discoverable: &[]bool{true}[0], BoxPub: badHex,
	}
	in.Sig = n.sign(t, in.NodeID, in.URL, in.Name, in.Version, "download",
		itoa(in.TTLSeconds), in.Nonce, itoa(in.TS), "1", "", badHex)
	if _, err := f.svc.RegisterNode(context.Background(), in, "10.0.0.1"); err == nil {
		t.Fatal("box_pub 非 32 字节 hex 须拒绝")
	}
}

func TestRegisterPublicURLValidation(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	in := RegisterInput{
		NodeID: n.id, URL: "https://n.example.com", Name: "n", Version: "v1",
		Caps: []string{"download"}, TTLSeconds: 3600, Nonce: "nd", TS: time.Now().Unix(),
		Discoverable: &[]bool{true}[0], PublicURL: "ftp://bad", BoxPub: testBoxPub,
	}
	in.Sig = n.sign(t, in.NodeID, in.URL, in.Name, in.Version, "download",
		itoa(in.TTLSeconds), in.Nonce, itoa(in.TS), "1", "ftp://bad", testBoxPub)
	if _, err := f.svc.RegisterNode(context.Background(), in, "10.0.0.1"); err == nil {
		t.Fatal("public_url 非 http/https 须拒绝")
	}
}
