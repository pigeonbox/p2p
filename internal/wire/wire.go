// Package wire 提供传输无关的 AEAD 消息帧：QUIC 流与中继 TCP 共用同一条
// 消息语义，上层传输逻辑（打洞成功/中继兜底）不感知差异。
//
// 线上格式（大端）：
//
//	u32(len) || nonce(12) || ciphertext
//	plaintext = type(1) || body(len-type-1)
//
// nonce 布局（12B）：
//
//	[0]      方向标签（'S' 发送方→接收方 / 'R' 接收方→发送方）
//	[1:4]    epoch（承载实例标识，见 nextEpoch；v2~v4 恒零）
//	[4:12]   发送序号 seq
//
// 密钥来自 PAKE 会话密钥派生（k_data）；无密钥者既不能读也不能产生合法帧——
// 首帧即完成双向认证（中继路径无 TLS，靠它防令牌窃用）。
package wire

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// 消息类型（M3 传输协议）。
const (
	MsgMeta  byte = 1 // 发送方→接收方：JSON {name,size,sha256}
	MsgReady byte = 2 // 接收方→发送方：JSON {offset}（断点续传起点）
	MsgChunk byte = 3 // 发送方→接收方：原始文件字节
	MsgFinal byte = 4 // 接收方→发送方：JSON {ok,message}
	// v3 多流并行(2026-10-09):控制流信令帧 + 数据流分段帧
	MsgPlan byte = 5 // 发送方→接收方(控制流)：JSON {streams}——将打开的数据流条数
	MsgSeg  byte = 6 // 发送方→接收方(数据流)：JSON {start}——本流起始偏移,后随 chunk 至流 FIN
	// v4 多文件 manifest 流(2026-10-09)
	MsgManifest byte = 7  // 发→收(控制流)：JSON {files:[{id,name,size}],compress,hash_after}
	MsgAccept   byte = 8  // 收→发(控制流)：JSON {accepted:[id]}——逐文件授权,可部分接受
	MsgHash     byte = 9  // 发→收(控制流)：JSON {id,sha256}——hash_after 模式的补发全量校验
	MsgFileAck  byte = 10 // 收→发(控制流)：JSON {id,ok,message}——单文件回执
	MsgSwap     byte = 11 // 发→收(控制流)：空负载——文件边界换源标记(先通后优直连升级)
)

// MaxMessageSize 单条消息明文上限(v4 提升至 1MB:压缩模式 256KB 明文批量
// + zstd 裕量;不压缩模式仍以 64KB chunk 为主)。
const MaxMessageSize = 1 << 20

// ErrCorrupt 帧无法解密/格式非法（对端无密钥或流被破坏）。
var ErrCorrupt = errors.New("wire: 帧校验失败")

// ErrEmptyPlaintext 帧解密成功但明文为空（无 type 前缀）——协议违例。
// 与 ErrCorrupt 分开：长度下界（帧格式层）与本检查（明文层）是两道防线，
// 守卫须能分辨是哪一道拦下的。
var ErrEmptyPlaintext = errors.New("wire: 空明文帧(无 type 前缀)")

// ErrReplay 重放帧：入站序号未前进（同一 nonce 二次出现）。
var ErrReplay = errors.New("wire: 重放帧(序号未前进)")

// Conn 消息化连接。
//
// 缓冲复用(2026-10-09):帧缓冲按 Conn 内部复用,ReadMsg 返回的 body 切片
// 仅在**下次 ReadMsg 前**有效(调用方现均即取即用);读写方向各自独立缓冲,
// 但同方向调用须在同一 goroutine 串行——与现有传输循环一致。大文件传输
// 每 64KB chunk 省两次堆分配,长传输 GC 压力显著下降。
type Conn struct {
	rw   io.ReadWriter
	aead cipher.AEAD
	seq  uint64 // 发送序号，作为 nonce 前缀 material
	// epoch 承载实例标识(2026-10-26 审计 P0 修复):同一会话密钥下,中继腿与
	// 直连腿各自 seq 从 0 起算 ⇒ (key, nonce) 完全重用(ChaCha20-Poly1305
	// 密钥流重用 + Poly1305 一次性密钥复用 ⇒ 可伪造任意合法帧)。epoch 落在
	// nonce 的空闲字节 [1:4],把「承载」纳入 nonce 空间。
	epoch uint32

	// dirTag/peerTag 方向标签（nonce 首字节）。2026-10-05 审计 P1 修复：
	// 此前两侧共用同一 data 密钥且 seq 均从 0 起算——发送方首帧 MsgMeta 与
	// 接收方首帧 MsgReady 的 key+nonce 完全相同（中继路径明文 TCP 上密钥流
	// 重用泄漏双向明文异或；Poly1305 一次性密钥重用可伪造合法帧）。现约定
	// 发送侧写 dirSend/读 dirRecv，接收侧写 dirRecv/读 dirSend，双向 nonce
	// 空间恒不相交。
	dirTag  byte
	peerTag byte

	// 入站重放窗口(2026-10-26 审计 P2 修复):nonce 随帧明文传输,不校验序号
	// 则抓到的帧可原样重放并通过认证。每方向记录已接受的最大 seq,seq 不
	// 前进即拒（窗口随承载实例走——换源=新 Conn=新窗口）。
	recvMu   sync.Mutex
	recvSeen bool
	recvLast uint64

	readBuf  []byte // 入站整帧复用(头+nonce+密文;解密原地覆写)
	frameBuf []byte // 出站整帧复用(头+nonce+明文;加密原地覆写)
}

// 方向标签取可打印 ASCII，便于抓包排查；无密码学含义（仅分离 nonce 空间）。
const (
	dirSend byte = 'S' // 发送方→接收方方向的帧
	dirRecv byte = 'R' // 接收方→发送方方向的帧
)

// nonce 中 epoch 的位置与长度（v2~v4 恒零的空闲位）。
const (
	epochOffset = 1
	epochBytes  = 3
)

// epochSeq 进程内 epoch 计数器（原子）。epoch 取自本计数器 ⇒ **同一进程内**
// 任意两条 wire.Conn 的 epoch 互不相同 ⇒ 同密钥同方向的 nonce 空间不相交。
//
// 为什么用计数器而不是「每连接随机」（2026-10-26 审计 P0 修复的设计推理）：
//   - nonce 随帧**明文传输**，epoch 无需不可猜测（新鲜性由序号窗口保证）；
//   - 随机 epoch 在同一会话的两条腿间仍有 2^-24 碰撞概率（计数器是硬保证）；
//   - 跨进程碰撞无害：同一密钥下只有发送方写 'S' 方向、接收方写 'R' 方向，
//     方向标签已经把两个方向的 nonce 空间彻底分开。
//
// epoch 宽度 24bit ⇒ 单进程 16.7M 条连接后回绕；回绕后同密钥复用需两条
// 连接恰好同 epoch（实际不可达：单进程连接数远低于该量级）。
var epochSeq = newEpochSeq()

func newEpochSeq() *atomic.Uint64 {
	var b [4]byte
	v := uint64(0)
	if _, err := rand.Read(b[:]); err == nil {
		v = uint64(binary.BigEndian.Uint32(b[:])) & 0xFFFFFF
	}
	s := &atomic.Uint64{}
	s.Store(v)
	return s
}

// nextEpoch 取下一个进程内唯一的 epoch（24bit）。
func nextEpoch() uint32 {
	return uint32(epochSeq.Add(1) & 0xFFFFFF)
}

// New 以 32 字节会话密钥构造；isSender 标明本端角色（发送侧/接收侧），
// 决定本端出站帧的方向标签。
func New(rw io.ReadWriter, key [32]byte, isSender bool) (*Conn, error) {
	return newConn(rw, key, isSender, nextEpoch())
}

// newConn 以指定 epoch 构造（epoch=0 即 v2~v4 的旧形态：nonce[1:4] 恒零），
// 供互操作回归测试构造「旧端」用。
func newConn(rw io.ReadWriter, key [32]byte, isSender bool, epoch uint32) (*Conn, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("wire: %w", err)
	}
	dir, peer := dirSend, dirRecv
	if !isSender {
		dir, peer = dirRecv, dirSend
	}
	return &Conn{rw: rw, aead: aead, dirTag: dir, peerTag: peer, epoch: epoch & 0xFFFFFF}, nil
}

// Close 关闭底层承载(QUIC 流/中继 TCP;底层不支持时为 no-op)。
func (c *Conn) Close() error {
	if cl, ok := c.rw.(io.Closer); ok {
		return cl.Close()
	}
	return nil
}

// DeriveKey 从 PAKE 会话密钥按用途派生子密钥（HKDF-SHA256，salt 空即
// hash-len 零串，info 绑定用途标签与协议域）。2026-10-05 审计 P3：原实现为
// sha256(session||label) 裸拼接，已按最佳实践换 HKDF；输出随本变更整体
// 轮换（与方向标签 nonce 修复同属传输协议破坏性变更，客户端须同版升级）。
func DeriveKey(session []byte, label string) [32]byte {
	out, err := hkdf.Key(sha256.New, session, nil, "fcb-p2p/v2/"+label, 32)
	if err != nil || len(out) != 32 {
		// HKDF-SHA256 输出 32B 不会失败；防御性兜底
		sum := sha256.Sum256(session)
		return sum
	}
	var k [32]byte
	copy(k[:], out)
	return k
}

// WriteMsg 编码、加密并写出一条消息(整帧单次 Write,出站缓冲 Conn 内复用)。
func (c *Conn) WriteMsg(msgType byte, body []byte) error {
	if len(body)+1 > MaxMessageSize {
		return fmt.Errorf("wire: 消息超限 %d", len(body)+1)
	}
	total := len(body) + 1 // type 前缀
	frameLen := 4 + chacha20poly1305.NonceSize + total + 16
	if cap(c.frameBuf) < frameLen {
		c.frameBuf = make([]byte, frameLen)
	}
	frame := c.frameBuf[:frameLen]
	binary.BigEndian.PutUint32(frame, uint32(chacha20poly1305.NonceSize+total+16))

	nonce := frame[4 : 4+chacha20poly1305.NonceSize]
	nonce[0] = c.dirTag
	// epoch 落在 nonce[1:4]（v2~v4 恒零的空闲位）：同一密钥下的不同承载
	// （中继腿 / 直连腿）由此获得不相交的 nonce 空间——修 (key, nonce) 重用。
	// 帧格式不变（nonce 仍是 12B 且逐字节在帧内传输）⇒ 新旧端互操作不受影响。
	nonce[epochOffset+0] = byte(c.epoch >> 16)
	nonce[epochOffset+1] = byte(c.epoch >> 8)
	nonce[epochOffset+2] = byte(c.epoch)
	binary.BigEndian.PutUint64(nonce[4:], c.seq)
	c.seq++

	// 明文(含 type 前缀)就位后原地加密:dst=pt[:0] 复用明文存储,密文含
	// 16B tag 恰好填满 frame 尾部
	pt := frame[16 : 16+total]
	pt[0] = msgType
	copy(pt[1:], body)
	c.aead.Seal(pt[:0], nonce, pt, nil)

	_, err := c.rw.Write(frame)
	return err
}

// ReadMsg 读取并解密一条消息。返回的 body 切片在下次 ReadMsg 前有效。
func (c *Conn) ReadMsg() (byte, []byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(c.rw, head[:]); err != nil {
		return 0, nil, err
	}
	total := binary.BigEndian.Uint32(head[:])
	// 下界 = nonce(12) + tag(16) + 明文最少 1 字节（type 前缀）。
	// 旧下界 NonceSize+16 放行了 total==28（零长明文）⇒ AEAD Open 对空明文
	// 返回长度 0 的切片 ⇒ 后续 plaintext[0] 越界 panic（控制流无 recover ⇒
	// 整个 p2pc 进程被打挂）。
	if total < chacha20poly1305.NonceSize+16+1 || total > MaxMessageSize+chacha20poly1305.NonceSize+16 {
		return 0, nil, ErrCorrupt
	}
	if cap(c.readBuf) < int(total) {
		c.readBuf = make([]byte, total)
	}
	buf := c.readBuf[:total]
	if _, err := io.ReadFull(c.rw, buf); err != nil {
		return 0, nil, err
	}
	nonce, ct := buf[:chacha20poly1305.NonceSize], buf[chacha20poly1305.NonceSize:]
	// 入站帧必须携带对端方向标签：错标签=密钥不一致或流错乱，直接拒
	// （错口令场景本就在 AEAD Open 处暴露，此处提前到标签位）
	if nonce[0] != c.peerTag {
		return 0, nil, ErrCorrupt
	}
	// 原地解密:dst=ct[:0] 是 x/crypto 明文允许的密文存储复用形态
	plaintext, err := c.aead.Open(ct[:0], nonce, ct, nil)
	if err != nil {
		return 0, nil, ErrCorrupt
	}
	// 兜底：零长明文（无 type 前缀）不可解引用——长度下界已挡，此处防
	// 下界被改/绕过时再崩一次。
	typ, body, err := splitPlaintext(plaintext)
	if err != nil {
		return 0, nil, err
	}
	// 重放窗口：nonce 明文在帧内，AEAD 只保机密性+完整性、不保新鲜度。
	// 同一 nonce 二次出现（重放）⇒ 序号不前进 ⇒ 拒。
	// 判定放在解密之后：未认证的帧不得推进窗口（否则伪造帧可毒化窗口）。
	seq := binary.BigEndian.Uint64(nonce[4:])
	c.recvMu.Lock()
	if c.recvSeen && seq <= c.recvLast {
		c.recvMu.Unlock()
		return 0, nil, ErrReplay
	}
	c.recvSeen = true
	c.recvLast = seq
	c.recvMu.Unlock()
	return typ, body, nil
}

// splitPlaintext 拆出消息 type 与 body。零长明文（无 type 前缀）判为协议违例——
// AEAD 允许空明文（Seal/Open 对空明文不报错），直接取 plaintext[0] 会越界。
func splitPlaintext(plaintext []byte) (byte, []byte, error) {
	if len(plaintext) == 0 {
		return 0, nil, ErrEmptyPlaintext
	}
	return plaintext[0], plaintext[1:], nil
}
