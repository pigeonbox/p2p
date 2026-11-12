package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/pigeonbox/p2p/internal/wire"
)

// ---- p2p#33 根因修复的构造判据（2026-11-12）----
//
// 三个行为用例 + 一个上游语义钉版 + 一个 AST 守卫，覆盖：
//   ① 双栈错位（两侧快打洞胜出族相反）直连仍成立——修「拨号族≠监听族 ⇒
//      QUIC 等满预算 50s 超时」；
//   ② 错位 + 快打洞后 QUIC 握手败 ⇒ 回退长打洞跑在健康双族套接字上重新打成
//      ——修「败族被 Close ⇒ 回退 45s 空转后硬失败」；
//   ③ 拨号目标 = punch 验证过的地址——修 establishQUICBudget 文档与调用点
//      （peer.pickUDP 静态候选）的背离；
//   ④ quic-go Transport.Close 对用户 conn 的复位语义钉版（②的复用前提）。
//
// 与既有 isEstablishFlake 有界重试（U2a 容忍口径，client_test.go）正交：重试
// 是 CI 容忍的第二道防线，本文件判据是根因修复的第一道防线，互不替代。

// rootfixOpts 直连建立判据的客户端参数：仅直连（NoRelay——中继不参与判据，
// 失败恒走「长打洞兜底」分支）、预算收紧（quicOpBudget=PunchBudget+5s=7s，
// 修复前的错位红约 7s 出，负对照跑得住）。Registry 指向黑洞：判据直连驱动
// establish，不触注册中心/反射器（候选在用例内手工构造）。
func rootfixOpts(tag string) Options {
	return Options{
		Registry:    "http://127.0.0.1:1",
		NodeKeyPath: filepath.Join(os.TempDir(), fmt.Sprintf("fcb-rootfix-%s-%d.key", tag, time.Now().UnixNano())),
		NoRelay:     true,
		PunchBudget: 2 * time.Second,
		Quiet:       !testLogEnabled(),
	}
}

func mustRootfixClient(t *testing.T, opt Options) *Client {
	t.Helper()
	c, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// punchRaceLog injectPunchDelay 的构造断言面：记录每侧「首个未被延迟的
// 验证成功族」= 该侧 punchDual 的胜出族（被延迟的族注定后到落败）。
type punchRaceLog struct {
	mu    sync.Mutex
	first map[string]string // 侧名 → 胜出族
}

// injectPunchDelay p2p#33 错位构造：punchDual 先返回者胜——给指定套接字的
// 单族 punch 在**验证成功之后**再延迟返回 ⇒ 被延迟的族注定当败者；延迟只作用
// 于返回时点，探针收发全程照常 ⇒ 两族都能真实验证成功（不破坏验证面）。
// 按套接字登记（同一进程两侧共用包级 punchOne；本包用例无并行）。
func injectPunchDelay(t *testing.T, delayBySock map[*net.UDPConn]time.Duration, sideOf map[*net.UDPConn]string) *punchRaceLog {
	t.Helper()
	orig := punchOne
	race := &punchRaceLog{first: map[string]string{}}
	punchOne = func(sock *net.UDPConn, peer *candInfo, k [32]byte, budget time.Duration) (*net.UDPAddr, error) {
		addr, err := orig(sock, peer, k, budget)
		if err == nil {
			d := delayBySock[sock]
			if side, ok := sideOf[sock]; ok && d == 0 {
				race.mu.Lock()
				if _, seen := race.first[side]; !seen {
					race.first[side] = famOf(sock)
				}
				race.mu.Unlock()
			}
			if d > 0 {
				time.Sleep(d)
			}
		}
		return addr, err
	}
	t.Cleanup(func() { punchOne = orig })
	return race
}

// closeRootfixSockets 注册套接字收尾（establish 成功路径不关套接字——由
// xport 收尾/进程回收，判据里显式关掉防 fd 叠加）。
func closeRootfixSockets(t *testing.T, socks ...*net.UDPConn) {
	t.Helper()
	t.Cleanup(func() {
		for _, s := range socks {
			if s != nil {
				_ = s.Close()
			}
		}
	})
}

// establishSide 一侧 establish 驱动所需的一切。
type establishSide struct {
	name         string
	c            *Client
	sock4, sock6 *net.UDPConn
	cert         tls.Certificate
	peer         *candInfo // 本侧持有的对端候选（含对端 CertFP）
	sw           *xswap
}

type establishResult struct {
	via string
	err error
	x   *xport
}

// establishConcurrent 并发驱动两侧 establish（两侧可能互等 ⇒ 必须真并发），
// 30s 看门狗（判据用例最坏链路 <20s：快 7s + 回退打洞 2s + 回退 QUIC 7s）。
func establishConcurrent(t *testing.T, session []byte, a, b *establishSide) (establishResult, establishResult) {
	t.Helper()
	type named struct {
		side string
		res  establishResult
	}
	ch := make(chan named, 2)
	run := func(s *establishSide, isSender bool) {
		x, via, err := s.c.establish(s.sw, s.sock4, s.sock6, "", session, s.cert, s.peer, isSender, nil)
		if isSender && err == nil && x != nil {
			// 等价于 sendAll 紧接 establish 后写 MsgMeta（transfer.go:342）：
			// quic-go 只在首字节到达时才向对端宣告流打开 ⇒ 判据驱动不写的话，
			// 接收侧 AcceptStream 会挂满预算（生产链路由 sendAll 解除，这里补
			// 同一动作；接收侧 establish 不读该帧，wire.New 无 IO）。
			_ = x.ctrl.WriteMsg(wire.MsgMeta, []byte(`{"probe":true}`))
		}
		ch <- named{side: s.name, res: establishResult{via: via, err: err, x: x}}
	}
	go run(a, true)
	go run(b, false)
	got := map[string]establishResult{}
	for i := 0; i < 2; i++ {
		select {
		case n := <-ch:
			got[n.side] = n.res
		case <-time.After(30 * time.Second):
			t.Fatalf("establish 30s 看门狗超时（已到: %v）", got)
		}
	}
	for _, s := range []*establishSide{a, b} {
		if x := got[s.name].x; x != nil {
			x := x
			t.Cleanup(x.cleanup)
		}
	}
	return got[a.name], got[b.name]
}

// TestEstablishDualStackMismatchDirect p2p#33 根因①判据：双栈错位（发送侧
// 快打洞胜 v4、接收侧胜 v6，两侧胜出族相反且无协商）时直连必须仍成立。
//
// 构造：两侧候选两族全给（LAN 含 loopback），按套接字注入延迟定向——发送侧
// v6 验证成功后延迟 1s 返回 ⇒ 胜者必为 v4；接收侧 v4 延迟 ⇒ 胜者必为 v6；
// race.first 显式断言两侧胜出族确实相反（构造不成立即红，不假绿）。
//
// 修复前（负对照，回退 listenFirst→单族 tgt.sock 监听即复现）：接收侧在本侧
// v6 套接字上拨发送侧 v6 地址、发送侧只在 v4 监听 ⇒ 拨号族≠监听族 ⇒ 双侧
// QUIC 等满 quicOpBudget(7s) 超时 ⇒ 落回退（旧代码败族已 Close ⇒ 回退长打洞
// 2s 空转）⇒ 两侧硬红。
func TestEstablishDualStackMismatchDirect(t *testing.T) {
	session := make([]byte, 32)
	_, _ = rand.Read(session)
	ca := mustRootfixClient(t, rootfixOpts("mm-send"))
	cb := mustRootfixClient(t, rootfixOpts("mm-recv"))
	s4, s6, _, _ := ca.punchSockets()
	r4, r6, _, _ := cb.punchSockets()
	if s4 == nil || r4 == nil {
		t.Fatal("v4 套接字创建失败")
	}
	if s6 == nil || r6 == nil {
		t.Skip("环境无 IPv6，无法构造双栈错位")
	}
	closeRootfixSockets(t, s4, s6, r4, r6)

	certA, fpA, err := sessionCert()
	if err != nil {
		t.Fatal(err)
	}
	certB, fpB, err := sessionCert()
	if err != nil {
		t.Fatal(err)
	}
	race := injectPunchDelay(t,
		map[*net.UDPConn]time.Duration{s6: time.Second, r4: time.Second},
		map[*net.UDPConn]string{s4: "send", s6: "send", r4: "recv", r6: "recv"})

	a := &establishSide{
		name: "send", c: ca, sock4: s4, sock6: s6, cert: certA, sw: &xswap{},
		peer: &candInfo{UDPLAN: lanCandidates(r4), UDPLAN6: lanCandidates6(r6), CertFP: fpB},
	}
	b := &establishSide{
		name: "recv", c: cb, sock4: r4, sock6: r6, cert: certB, sw: &xswap{},
		peer: &candInfo{UDPLAN: lanCandidates(s4), UDPLAN6: lanCandidates6(s6), CertFP: fpA},
	}
	ra, rb := establishConcurrent(t, session, a, b)

	race.mu.Lock()
	gotSend, gotRecv := race.first["send"], race.first["recv"]
	race.mu.Unlock()
	if gotSend != "v4" || gotRecv != "v6" {
		t.Fatalf("错位构造失效（期望发送侧胜 v4、接收侧胜 v6）：send=%q recv=%q", gotSend, gotRecv)
	}
	if ra.err != nil {
		t.Fatalf("错位下发送侧 establish 失败（双族监听竞速应兜住）：%v", ra.err)
	}
	if rb.err != nil {
		t.Fatalf("错位下接收侧 establish 失败：%v", rb.err)
	}
	if !strings.HasPrefix(ra.via, "quic-direct(") || !strings.HasPrefix(rb.via, "quic-direct(") {
		t.Fatalf("非直连通道：send=%q recv=%q", ra.via, rb.via)
	}
	if ra.via != rb.via {
		t.Fatalf("两侧通道族不一致（拨号族≠监听族又出现了）：send=%q recv=%q", ra.via, rb.via)
	}
}

// TestEstablishMismatchFallbackQuicError p2p#33 根因②判据：错位 + 快打洞成功
// 但 QUIC 握手败（发送侧持有的对端 CertFP 故意错）时，回退长打洞必须跑在健康
// 双族套接字上重新打成——最终错误必须点名「quic 建立」（第二次握手败），**不得**
// 是「打洞失败(v4/v6 均未通)」。套接字不可用（旧代码：败族已 Close ⇒ 回退段
// 两侧探针全部落向对方已关端口 ⇒ 满 PunchBudget 报打洞失败）即判据红。
//
// 负对照：回退「胜出即 Close 败族」⇒ 本用例红（错误形态变回打洞失败）。
func TestEstablishMismatchFallbackQuicError(t *testing.T) {
	session := make([]byte, 32)
	_, _ = rand.Read(session)
	ca := mustRootfixClient(t, rootfixOpts("fb-send"))
	cb := mustRootfixClient(t, rootfixOpts("fb-recv"))
	s4, s6, _, _ := ca.punchSockets()
	r4, r6, _, _ := cb.punchSockets()
	if s4 == nil || r4 == nil {
		t.Fatal("v4 套接字创建失败")
	}
	if s6 == nil || r6 == nil {
		t.Skip("环境无 IPv6，无法构造双栈错位")
	}
	closeRootfixSockets(t, s4, s6, r4, r6)

	certA, fpA, err := sessionCert()
	if err != nil {
		t.Fatal(err)
	}
	certB, _, err := sessionCert()
	if err != nil {
		t.Fatal(err)
	}
	injectPunchDelay(t,
		map[*net.UDPConn]time.Duration{s6: time.Second, r4: time.Second},
		map[*net.UDPConn]string{s4: "send", s6: "send", r4: "recv", r6: "recv"})

	// 快路径 QUIC 注入失败（每角色第一次 establishQUICBudget 调用）：
	// quic-go 服务端 Accept 只收**完成握手**的连接、握手失败被吞（server.go
	// baseServer.accept）⇒ 单靠坏指纹造不出「两侧同时落回退」——接收侧（客户端
	// 侧握手失败）秒回、发送侧要等满预算 ⇒ 回退段单边跑、对端已走 ⇒ 判据误红。
	// 注入把快路径失败对称化（两侧毫秒级同落回退）；回退段走真实实现，坏指纹
	// 继续让回退段 QUIC 必败（判据看的就是回退段的错误形态）。
	origQUIC := establishQUICBudget
	var seamMu sync.Mutex
	faked := map[string]int{}
	establishQUICBudget = func(ctx context.Context, sock *net.UDPConn, session []byte, cert tls.Certificate, peerFP string, remote *net.UDPAddr, isSender bool, budget time.Duration, log *slog.Logger) (*xport, error) {
		role := "recv"
		if isSender {
			role = "send"
		}
		seamMu.Lock()
		faked[role]++
		n := faked[role]
		seamMu.Unlock()
		if n == 1 {
			return nil, fmt.Errorf("quic 拨号: 快路径建立失败(判据注入, p2p#33)")
		}
		return origQUIC(ctx, sock, session, cert, peerFP, remote, isSender, budget, log)
	}
	t.Cleanup(func() { establishQUICBudget = origQUIC })

	// 发送侧持有的对端指纹是**错的** ⇒ 回退段两轮 QUIC 都必败：
	// 接收侧（客户端侧）握手失败秒回；发送侧服务端 Accept 吞握手失败、
	// 等满预算超时——两侧最终错误都必须点名「quic 建立」。
	badFP := strings.Repeat("ab", 32)
	a := &establishSide{
		name: "send", c: ca, sock4: s4, sock6: s6, cert: certA, sw: &xswap{},
		peer: &candInfo{UDPLAN: lanCandidates(r4), UDPLAN6: lanCandidates6(r6), CertFP: badFP},
	}
	b := &establishSide{
		name: "recv", c: cb, sock4: r4, sock6: r6, cert: certB, sw: &xswap{},
		peer: &candInfo{UDPLAN: lanCandidates(s4), UDPLAN6: lanCandidates6(s6), CertFP: fpA},
	}
	start := time.Now()
	ra, rb := establishConcurrent(t, session, a, b)
	elapsed := time.Since(start)

	for _, r := range []struct {
		side string
		res  establishResult
	}{{"发送侧", ra}, {"接收侧", rb}} {
		if r.res.err == nil {
			t.Fatalf("%s应报错（对端指纹错）却成功了：%s", r.side, r.res.via)
		}
		msg := r.res.err.Error()
		if !strings.Contains(msg, "quic 建立") {
			t.Fatalf("%s最终错误未点名「quic 建立」——回退长打洞没打成（套接字不健康？）：%s", r.side, msg)
		}
		if strings.Contains(msg, "打洞失败") {
			t.Fatalf("%s最终错误是打洞失败——回退长打洞在错位下空转（败族被关的旧病复发？）：%s", r.side, msg)
		}
	}
	// 接收侧还必须给出**活握手**证据：回退拨号打到了对端仍在监听的套接字并
	// 走到 TLS 指纹钉定（坏指纹 ⇒ "tls: bad certificate"）。仅凭错误点名
	// 「quic 建立」不够——快打洞残留在套接字缓冲区的旧探针会让回退打洞「秒验」
	// （75µs 级，实测），败族被关时回退拨号打的是已关端口 ⇒ 只会等到
	// context deadline exceeded、永无握手。bad certificate = 套接字健康且
	// 双族可达的直接证据。
	if !strings.Contains(rb.err.Error(), "bad certificate") {
		t.Fatalf("接收侧回退拨号没有走到活握手（败族被关/套接字不健康的旧病？）：%s", rb.err)
	}
	if elapsed > 15*time.Second {
		t.Fatalf("回退链路耗时 %s 超 15s——出现预算空转（本判据 PunchBudget=2s，应秒级出）", elapsed)
	}
}

// TestEstablishDialsVerifiedAddrNotStaticCandidate p2p#33 根因①（doc/impl 背离）
// 判据：接收侧拨号目标必须是 punch 验证过的对端地址，而不是 pickUDP 按
// UDPPublic→UDPMapped→UDPLAN 挑出的静态候选。
//
// 构造：v4 单族（对端候选不给 v6 ⇒ 两侧 v6 分支「无可用候选」即败，胜出族
// 稳定 v4，无需注入）+ 埋毒：对端 UDPPublic/UDPMapped = 192.0.2.1:9
// （TEST-NET-1，usableExt 判可用但黑洞）——punch 照常在 LAN/loopback 候选上
// 验证成功，旧实现拨号却优先取毒化 UDPPublic ⇒ 必败；修复后拨 tgt.addr ⇒ 成。
//
// 负对照：拨号改回 peer.pickUDP ⇒ 本用例红（约 quicOpBudget 7s 或路由即错）。
func TestEstablishDialsVerifiedAddrNotStaticCandidate(t *testing.T) {
	session := make([]byte, 32)
	_, _ = rand.Read(session)
	ca := mustRootfixClient(t, rootfixOpts("va-send"))
	cb := mustRootfixClient(t, rootfixOpts("va-recv"))
	s4, s6, _, _ := ca.punchSockets()
	r4, r6, _, _ := cb.punchSockets()
	if s4 == nil || r4 == nil {
		t.Fatal("v4 套接字创建失败")
	}
	closeRootfixSockets(t, s4, s6, r4, r6)

	certA, fpA, err := sessionCert()
	if err != nil {
		t.Fatal(err)
	}
	certB, fpB, err := sessionCert()
	if err != nil {
		t.Fatal(err)
	}
	const poison = "192.0.2.1:9"
	t0 := time.Now()
	t.Logf("[timing] setup done at %s", time.Since(t0))
	a := &establishSide{
		name: "send", c: ca, sock4: s4, sock6: s6, cert: certA, sw: &xswap{},
		peer: &candInfo{UDPPublic: poison, UDPMapped: poison, UDPLAN: lanCandidates(r4), CertFP: fpB},
	}
	b := &establishSide{
		name: "recv", c: cb, sock4: r4, sock6: r6, cert: certB, sw: &xswap{},
		peer: &candInfo{UDPPublic: poison, UDPMapped: poison, UDPLAN: lanCandidates(s4), CertFP: fpA},
	}
	ra, rb := establishConcurrent(t, session, a, b)
	t.Logf("[timing] establish done at %s", time.Since(t0))
	if ra.err != nil {
		t.Fatalf("发送侧失败：%v", ra.err)
	}
	if rb.err != nil {
		t.Fatalf("接收侧失败（拨了毒化候选而非验证地址？）：%v", rb.err)
	}
	if !strings.HasPrefix(rb.via, "quic-direct(") {
		t.Fatalf("非直连通道：%q", rb.via)
	}
}

// TestTransportCloseRestoresRawConn p2p#33 修复依据的上游语义钉版：quic-go
// v0.65 Transport.Close 对**用户传入的 conn** 是「停读循环（deadline=now 踢出）
// → 等 listening 退出 → defer 把读截止归零」，**不关 fd**（只有 createdConn
// 才关）。establish 所有失败路径都 tr.Close() ⇒ 失败后套接字可显式交回回退
// 长打洞/升级通道复用（回退段的前提）。
//
// 上游一旦改为关 conn、残留过期读截止、或 Close 后不让 re-Transport ⇒ 本用例
// 红 ⇒ 修复须改走「同端口换新套接字」（不是悄悄继续裸复用）。
func TestTransportCloseRestoresRawConn(t *testing.T) {
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	peer, err := net.DialUDP("udp4", nil, sock.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	cert, _, err := sessionCert()
	if err != nil {
		t.Fatal(err)
	}
	tlsBase := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{quicALPN}}

	tr := &quic.Transport{Conn: sock}
	ln, err := tr.Listen(tlsBase, &quic.Config{})
	if err != nil {
		t.Fatalf("首次监听: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("Transport.Close: %v", err)
	}
	_ = ln.Close()

	// 1) conn 未被关、读截止已归零：**不设截止直接读**——过期截止会立即超时
	//    报错，归零则读到对端在 Close 后补发的报文。
	if _, err := peer.Write([]byte("ping")); err != nil {
		t.Fatalf("对端写入: %v", err)
	}
	type rd struct {
		err error
	}
	done := make(chan rd, 1)
	go func() {
		buf := make([]byte, 16)
		_, _, err := sock.ReadFromUDP(buf)
		done <- rd{err: err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Close 后原始读失败（上游不再复位 conn？）：%v", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close 后原始读无响应（读截止被残留/读循环未退出？）")
	}

	// 2) 同一 conn 可再包一层新 Transport 并监听——升级通道 fastTgt 复用
	//    （startUpgradeSender 拿失败/成功路径回收的同一套接字再 Listen）依赖此语义。
	tr2 := &quic.Transport{Conn: sock}
	ln2, err := tr2.Listen(tlsBase, &quic.Config{})
	if err != nil {
		t.Fatalf("Close 后 re-Transport 监听失败（升级通道复用前提被破坏）：%v", err)
	}
	_ = ln2.Close()
	_ = tr2.Close()
}

// TestDialUsesVerifiedAddr 守卫：establishQUICBudget 调用实参里不得再出现
// pickUDP(...)（p2p#33 根因①：直连拨号必须传 punch 验证地址，文档与实现
// 曾背离）。行为级判据见 TestEstablishDialsVerifiedAddrNotStaticCandidate。
// 升级通道经变量 remote 传 offer 协商族的候选（族经信令对齐、无 punch 验证面，
// 见 establishQUICBudget 文档），不在本守卫射程——本守卫拦的是「把 pickUDP
// 重新写回直连调用点」这一具体回退动作。
func TestDialUsesVerifiedAddr(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "client.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 client.go 失败: %v", err)
	}
	checked := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		}
		if name != "establishQUICBudget" {
			return true
		}
		checked++
		for _, arg := range call.Args {
			ast.Inspect(arg, func(a ast.Node) bool {
				sel, ok := a.(*ast.SelectorExpr)
				if ok && sel.Sel.Name == "pickUDP" {
					t.Errorf("establishQUICBudget 实参里出现 pickUDP（拨回静态候选，p2p#33 根因①回退）——直连必须拨 punch 验证地址")
				}
				return true
			})
		}
		return true
	})
	if checked == 0 {
		t.Fatal("没扫到 establishQUICBudget 调用点（判据失效）")
	}
}
