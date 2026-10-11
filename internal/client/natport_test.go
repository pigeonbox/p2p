package client

import (
	"net"
	"testing"
)

func TestUsableExt(t *testing.T) {
	cases := []struct {
		name string
		addr *net.UDPAddr
		want bool
	}{
		{"nil", nil, false},
		{"零地址", &net.UDPAddr{}, false},
		{"空映射 0.0.0.0:0(真机实测)", &net.UDPAddr{IP: net.IPv4zero, Port: 0}, false},
		{"未指定 IP 带端口", &net.UDPAddr{IP: net.IPv4zero, Port: 12345}, false},
		{"端口为 0", &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 0}, false},
		{"有效 v4", &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 12345}, true},
		{"有效 v6", &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 12345}, true},
	}
	for _, c := range cases {
		if got := usableExt(c.addr); got != c.want {
			t.Errorf("usableExt(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPickUDPSkipsUnusable(t *testing.T) {
	ci := &candInfo{
		UDPPublic: "",
		UDPMapped: "0.0.0.0:0", // 网关 ACK 的空映射,不得当候选
		UDPLAN:    []string{"192.168.1.10:54321"},
	}
	got := ci.pickUDP("v4")
	if got == nil || got.String() != "192.168.1.10:54321" {
		t.Fatalf("pickUDP = %v, want 192.168.1.10:54321", got)
	}

	// 全部候选不可用时返回 nil 而不是垃圾地址
	allBad := &candInfo{UDPPublic: "0.0.0.0:0", UDPMapped: "", UDPLAN: []string{":0"}}
	if got := allBad.pickUDP("v4"); got != nil {
		t.Fatalf("pickUDP 全不可用 = %v, want nil", got)
	}
}
