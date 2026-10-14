package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/pigeonbox/p2p/internal/wire"
)

// ---- 传输建立：打洞成功走 QUIC(打洞套接字),失败走中继 TCP ----

const quicALPN = "fcb-p2p/1"

// xport 传输承载:控制流(握手/元数据/收尾) + 数据流工厂(v3 多流并行,
// 仅 QUIC 直传路径;中继单管道 open/accept 为 nil,数据全部走控制流)。
type xport struct {
	ctrl *wire.Conn
	// open/accept 打开/接受第 i 条数据流。数据流用独立派生密钥(data-seg<i>)
	// ——各流 AEAD 序号都从 0 起算,同密钥会跨流 nonce 重用。QUIC 的
	// AcceptStream 顺序与 OpenStreamSync 顺序一致(stream id 单调),两侧
	// 按同序号派生即配对。
	open   func(ctx context.Context, seg int) (*wire.Conn, error)
	accept func(ctx context.Context, seg int) (*wire.Conn, error)
	// direct 是否 QUIC 直传(多流可用)。
	direct bool
	// peerClosed 对端关闭连接的信号(QUIC 接收侧接入)。QUIC Transport.Close
	// 不保证在途数据交付——接收方发完 final 帧若立刻拆传输,末帧可能在送达
	// 前被丢(CI 高载实测:发送方 final 接收 60s idle 超时)。finish() 据此
	// 等对端先关,再拆本端。
	peerClosed <-chan struct{}
	cleanup    func()
}

// finish 收尾:接收侧先等对端关闭(上限 2s,防对端异常时悬挂)以确保末帧
// 送达,再拆本端传输;发送侧对端无需再收任何帧,直接拆。
func (x *xport) finish(isSender bool) {
	if !isSender && x.peerClosed != nil {
		select {
		case <-x.peerClosed:
		case <-time.After(2 * time.Second):
		}
	}
	x.cleanup()
}

// segKeyLabel 第 i 条数据流的派生标签。
func segKeyLabel(i int) string { return "data-seg-" + strconv.Itoa(i) }

// relayToken 由会话密钥派生的中继信道凭据（无口令不可计算;窃取仅构成 DoS——
// 传输层首帧 AEAD 认证,攻击者产不出合法帧）。
func relayToken(session []byte) string {
	k := wire.DeriveKey(session, "relay")
	return hex.EncodeToString(k[:])
}

// sessionCert 生成会话级临时自签证书（P-256,2h 有效;指纹经 PAKE 加密信道
// 交换,QUIC 握手双向按指纹钉定——无指纹者握手必败）。
func sessionCert() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "fcb-p2p-session"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	fpBytes := sha256.Sum256(der)
	fp := hex.EncodeToString(fpBytes[:])
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, fp, nil
}

// verifyFP 证书指纹钉定校验器（替代链式校验——只认 PAKE 加密信道里
// 交换过的那张证书,信任锚=口令本身）。
func verifyFP(want string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("对端未出示证书")
		}
		sum := sha256.Sum256(rawCerts[0])
		if hex.EncodeToString(sum[:]) != want {
			return fmt.Errorf("对端证书指纹不匹配")
		}
		return nil
	}
}

// establishQUIC 在打洞成功的 UDP 套接字上建立 QUIC 传输。
// sender 作为服务端监听;receiver 拨号 punch 验证过的对端地址。
// 套接字交给 quic.Transport 后不得再用于原始读写(打洞循环须已停止)。
// 返回控制流 + 数据流工厂(v3 多流)与清理函数。
func establishQUIC(sock *net.UDPConn, session []byte, cert tls.Certificate, peerFP string, remote *net.UDPAddr, isSender bool) (*xport, error) {
	return establishQUICBudget(sock, session, cert, peerFP, remote, isSender, 8*time.Second)
}

// establishQUICBudget 同上,接受/拨号预算可调(先通后优:发送方监听窗口
// 放宽到升级预算,等接收方补拨)。
func establishQUICBudget(sock *net.UDPConn, session []byte, cert tls.Certificate, peerFP string, remote *net.UDPAddr, isSender bool, budget time.Duration) (*xport, error) {
	tlsBase := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{quicALPN},
	}
	if isSender {
		tlsBase.ClientAuth = tls.RequireAnyClientCert
	} else {
		tlsBase.InsecureSkipVerify = true // 证书校验由指纹钉定承担
	}
	tlsBase.VerifyPeerCertificate = verifyFP(peerFP)
	qcfg := &quic.Config{
		MaxIdleTimeout:       60 * time.Second,
		HandshakeIdleTimeout: 10 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
		// 流控窗口(2026-10-14 大文件失败带修复):缺省窗口在高吞吐路径上
		// 提前耗尽——100MB 实测恒停 ~68MB(双侧 "no recent network activity",
		// 回环仅 3-4MB/s)。发送侧被流控阻塞 + 接收侧应用层短暂停顿(写盘/
		// 压缩)即断流。显式放大到局域网 BDP 量级,给写盘抖动留缓冲。
		InitialStreamReceiveWindow:     8 << 20,
		MaxStreamReceiveWindow:         32 << 20,
		InitialConnectionReceiveWindow: 16 << 20,
		MaxConnectionReceiveWindow:     64 << 20,
	}
	if qlogDir := os.Getenv("PB_P2P_QLOG"); qlogDir != "" {
		_ = os.MkdirAll(qlogDir, 0o755)
		role := "server"
		if !isSender {
			role = "client"
		}
		qcfg.Tracer = func(_ context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
			f, _ := os.Create(filepath.Join(qlogDir, role+"-"+connID.String()+".qlog"))
			return qlogwriter.NewConnectionFileSeq(f, isClient, connID, []string{qlog.EventSchema})
		}
	}
	tr := &quic.Transport{Conn: sock}

	// 流方向: 发送方(QUIC 服务端)打开流并率先写 meta——QUIC 流在首字节
	// 上线前对端 AcceptStream 不会返回,故接收方以"收到 meta 帧"为准,
	// 不存在空等;错口令在首个 AEAD 帧解密处暴露。
	// 接受/拨号预算与打洞预算同量级:打洞结果不对称时(一侧直连一侧
	// 只能中继),快速失败让双方对齐到中继,避免 15s 级死等
	opCtx, opCancel := context.WithTimeout(context.Background(), budget)
	defer opCancel()
	var stream *quic.Stream
	var qc *quic.Conn
	if isSender {
		ln, err := tr.Listen(tlsBase, qcfg)
		if err != nil {
			_ = tr.Close()
			return nil, fmt.Errorf("quic 监听: %w", err)
		}
		qc, err = ln.Accept(opCtx)
		if err != nil {
			_ = tr.Close()
			return nil, fmt.Errorf("quic 接受连接: %w", err)
		}
		stream, err = qc.OpenStreamSync(opCtx)
		if err != nil {
			_ = tr.Close()
			return nil, fmt.Errorf("quic 打开流: %w", err)
		}
	} else {
		var err error
		qc, err = tr.Dial(opCtx, remote, tlsBase, qcfg)
		if err != nil {
			_ = tr.Close()
			return nil, fmt.Errorf("quic 拨号: %w", err)
		}
		stream, err = qc.AcceptStream(opCtx)
		if err != nil {
			_ = tr.Close()
			return nil, fmt.Errorf("quic 接受流: %w", err)
		}
	}
	ctrl, err := wire.New(stream, wire.DeriveKey(session, "data"), isSender)
	if err != nil {
		_ = tr.Close()
		return nil, err
	}
	x := &xport{ctrl: ctrl, direct: true, cleanup: func() { _ = tr.Close() }}
	if !isSender {
		// 接收侧挂对端关闭信号:final 帧送达后再拆传输(见 xport.peerClosed)
		x.peerClosed = qc.Context().Done()
	}
	if isSender {
		x.open = func(ctx context.Context, seg int) (*wire.Conn, error) {
			st, err := qc.OpenStreamSync(ctx)
			if err != nil {
				return nil, fmt.Errorf("quic 打开数据流 seg%d: %w", seg, err)
			}
			return wire.New(st, wire.DeriveKey(session, segKeyLabel(seg)), true)
		}
	} else {
		x.accept = func(ctx context.Context, seg int) (*wire.Conn, error) {
			st, err := qc.AcceptStream(ctx)
			if err != nil {
				return nil, fmt.Errorf("quic 接受数据流 seg%d: %w", seg, err)
			}
			return wire.New(st, wire.DeriveKey(session, segKeyLabel(seg)), false)
		}
	}
	return x, nil
}

// establishRelay 经中继建立传输：TCP 接入 + 令牌配对 + AEAD 消息帧。
// 首帧即完成认证(无口令者产不出合法帧)。isSender 用于 AEAD 方向标签
// （nonce 空间分离，防跨方向 nonce 重用）。中继为单管道:数据全部走控制流。
func establishRelay(session []byte, relayAddr, token string, isSender bool) (*xport, error) {
	tcp, err := net.DialTimeout("tcp", relayAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("中继接入: %w", err)
	}
	if _, err := tcp.Write([]byte("RELAY " + token + "\n")); err != nil {
		_ = tcp.Close()
		return nil, fmt.Errorf("中继令牌发送: %w", err)
	}
	ctrl, err := wire.New(tcp, wire.DeriveKey(session, "data"), isSender)
	if err != nil {
		_ = tcp.Close()
		return nil, err
	}
	return &xport{ctrl: ctrl, cleanup: func() { _ = tcp.Close() }}, nil
}
