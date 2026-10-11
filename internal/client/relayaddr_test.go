package client

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
)

func hostPortOf(raw string, port int) string {
	u, err := url.Parse(raw)
	if err != nil {
		t := raw
		return t
	}
	return u.Hostname() + ":" + strconv.Itoa(port)
}

func TestRelayAddrDiscovery(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","version":"test","relay_port":56787}`))
	}))
	defer ts.Close()

	c := &Client{opt: Options{Registry: ts.URL}}
	want := hostPortOf(ts.URL, 56787)
	if got := c.relayAddr(); got != want {
		t.Fatalf("relayAddr = %q, want %q", got, want)
	}
	if got := c.relayAddr(); got != want || hits.Load() != 1 {
		t.Fatalf("缓存失效: got=%q hits=%d", got, hits.Load())
	}
}

func TestRelayAddrFallbackLegacy(t *testing.T) {
	// 老服务器 /health 无 relay_port → 回退 registry host:12347
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","version":"old"}`))
	}))
	defer ts.Close()

	c := &Client{opt: Options{Registry: ts.URL}}
	want := hostPortOf(ts.URL, 12347)
	if got := c.relayAddr(); got != want {
		t.Fatalf("relayAddr = %q, want %q (老服务器回退)", got, want)
	}
}

func TestRelayAddrExplicitWins(t *testing.T) {
	c := &Client{opt: Options{Registry: "http://127.0.0.1:1", RelayAddr: "relay.example:9999"}}
	if got := c.relayAddr(); got != "relay.example:9999" {
		t.Fatalf("显式 --relay 未生效: %q", got)
	}
}
