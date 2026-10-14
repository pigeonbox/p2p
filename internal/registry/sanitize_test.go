package registry

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ---- 渗透回归:显示字段入口消毒(2026-10-15) ----

func TestRegisterNameControlCharsStripped(t *testing.T) {
	f := newFixture(t)
	n := newNode(t)
	in := RegisterInput{
		NodeID: n.id, URL: "https://evil.example.com", Name: "<img>\x1aEvil\x07站", Version: "v\x00x",
		Caps: []string{"download"}, TTLSeconds: 3600, Nonce: "ns1", TS: time.Now().Unix(),
		Discoverable: &[]bool{true}[0], BoxPub: testBoxPub,
	}
	// 签名用原文(客户端契约:负载=请求原文;消毒只影响存储值)
	in.Sig = n.sign(t, in.NodeID, in.URL, in.Name, in.Version, "download",
		itoa(in.TTLSeconds), in.Nonce, itoa(in.TS), "1", "", testBoxPub)
	got, err := f.svc.RegisterNode(context.Background(), in, "10.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "<img>Evil站" {
		t.Fatalf("控制符应被剥离且原文保留: %q", got.Name)
	}
	if strings.ContainsRune(got.Version, 0) {
		t.Fatalf("version 控制符应被剥离: %q", got.Version)
	}
	// 名录输出同步消毒
	entries, _ := f.svc.Directory(context.Background())
	for _, e := range entries {
		if e.NodeID == n.id && e.Name != "<img>Evil站" {
			t.Fatalf("名录 name 未同步: %q", e.Name)
		}
	}
}
