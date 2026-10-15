package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/pigeonbox/kit/async"
	"github.com/pigeonbox/p2p/internal/wire"
)

// ---- 传输协议 v4:多文件/文件夹 manifest 流 ----
//
// 控制流帧序:
//
//	MsgManifest{files:[{id,name,size}...], compress, hash_after}   发→收
//	MsgAccept{accepted:[id...]}                                    收→发(逐文件授权,可部分接受)
//	对每个被接受文件(按 manifest 序):
//	  MsgMeta{name,size,sha256?} → MsgReady{offset} → chunk* →
//	  [MsgHash{id,sha256}(hash_after)] → MsgFileAck{id,ok}
//	MsgSwap{}            文件边界换源标记(先通后优:双方直连就绪后由发送方发出)
//	MsgFinal{ok}         全部完成
//
// compress=true:chunk/段数据帧负载为独立 zstd 帧(明文字节上哈希,与不压缩
// 一致);hash_after=true:meta 不带 sha256,发送方流式计算后补发(单遍发送,
// 免全文件预读)。互斥规则:hash_after 强制单流+禁续传(流式哈希依赖文件序,
// 多流乱序/续传前缀都无法流式拼合——多流沿用盘上重读定稿)。
//
// 路径安全:name 为发送侧相对路径(/ 分隔);接收方 sanitizeRel 拒绝绝对路径/
// .. 段/盘符,落盘恒在 dir 之下。
//
// 断点续传:接收方以既有部分文件字节数回 ready{offset};多流仅全新传输启用
// (多流半成品含零洞,续传恒单流顺序写)。

const chunkSize = 64 << 10

// 压缩模式单帧明文批量(zstd 摊薄帧头开销);小文件不划算。
// 阈值为变量:测试可收紧触发各路径(包内顺序用例,无并发改写)。
var (
	compressedChunkSize = 256 << 10
	minMultiStreamSize  = int64(8 << 20)
	maxDataStreams      = 3
	segOpenBudget       = 10 * time.Second
	compressMinTotal    = int64(1 << 20)
	hashAfterMinTotal   = int64(64 << 20)
	maxManifestFiles    = 10000
)

type manifestEntry struct {
	ID   int    `json:"id"`
	Name string `json:"name"` // 相对路径,/ 分隔
	Size int64  `json:"size"`
}

type manifestMsg struct {
	Files     []manifestEntry `json:"files"`
	Compress  bool            `json:"compress,omitempty"`
	HashAfter bool            `json:"hash_after,omitempty"`
}

type acceptMsg struct {
	Accepted []int `json:"accepted"`
}

type readyMsg struct {
	Offset int64 `json:"offset"`
}

type finalMsg struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// hashMsg hash_after 模式:文件流结束后的全量 sha256(十六进制)。
type hashMsg struct {
	ID     int    `json:"id"`
	SHA256 string `json:"sha256"`
}

// fileAckMsg 单文件回执(成功/校验失败/写盘错误均走这里)。
type fileAckMsg struct {
	ID      int    `json:"id"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

type metaMsg struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type planMsg struct {
	Streams int `json:"streams"`
}

type segMsg struct {
	Start int64 `json:"start"`
}

var errPeerAborted = errors.New("对端中止传输")

// zstd 编解码器:EncodeAll/DecodeAll 无状态,进程级复用且并发安全。
var (
	zEnc, _ = zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest))
	zDec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
)

// transferOpts 传输选项(manifest 宣告,双方按此执行)。
type transferOpts struct {
	Compress  bool
	HashAfter bool
}

// srcGetter 传输源获取器:先通后优的文件边界升级换源点——调用方在直连就绪后
// 原子换出直连 xport,循环每文件重新取用。
type srcGetter func() *xport

// collectFiles 展开发送输入:目录递归为相对路径清单,单文件原样。
func collectFiles(paths []string) ([]manifestEntry, []string, int64, error) {
	var entries []manifestEntry
	var abs []string
	var total int64
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("%s: %w", p, err)
		}
		if !st.IsDir() {
			entries = append(entries, manifestEntry{ID: len(entries), Name: filepath.Base(p), Size: st.Size()})
			abs = append(abs, p)
			total += st.Size()
			continue
		}
		err = filepath.WalkDir(p, func(walkPath string, d os.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() {
				return nil
			}
			rel, rerr := filepath.Rel(p, walkPath)
			if rerr != nil {
				return rerr
			}
			info, ierr := d.Info()
			if ierr != nil {
				return ierr
			}
			entries = append(entries, manifestEntry{
				ID:   len(entries),
				Name: path.Join(filepath.Base(p), filepath.ToSlash(rel)),
				Size: info.Size(),
			})
			abs = append(abs, walkPath)
			total += info.Size()
			return nil
		})
		if err != nil {
			return nil, nil, 0, err
		}
	}
	if len(entries) == 0 {
		return nil, nil, 0, errors.New("没有可发送的文件")
	}
	if len(entries) > maxManifestFiles {
		return nil, nil, 0, fmt.Errorf("文件数超上限 %d", maxManifestFiles)
	}
	return entries, abs, total, nil
}

// sanitizeRel 接收方路径消毒:拒绝绝对路径/父目录段/盘符/反斜杠,输出恒为
// dir 之下的相对路径。
func sanitizeRel(name string) (string, error) {
	n := filepath.ToSlash(strings.TrimSpace(name))
	if n == "" || strings.HasPrefix(n, "/") || strings.Contains(n, "\\") {
		return "", fmt.Errorf("非法文件名: %q", name)
	}
	if filepath.VolumeName(n) != "" {
		return "", fmt.Errorf("非法文件名(盘符): %q", name)
	}
	// 盘符形态跨平台拦截("C:/..." 在非 Windows 平台 VolumeName 为空)
	if len(n) > 1 && n[1] == ':' && ((n[0] >= 'a' && n[0] <= 'z') || (n[0] >= 'A' && n[0] <= 'Z')) {
		return "", fmt.Errorf("非法文件名(盘符): %q", name)
	}
	clean := path.Clean(n)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("非法文件名(越界): %q", name)
	}
	return clean, nil
}

// sendAll v4 发送主流程。
func sendAll(getX srcGetter, paths []string, progress func(sent, total int64), boundary func() bool) (int, error) {
	entries, absPaths, total, err := collectFiles(paths)
	if err != nil {
		return 0, err
	}
	useCompress := total >= compressMinTotal
	useHashAfter := total >= hashAfterMinTotal

	x := getX()
	meta, _ := json.Marshal(manifestMsg{Files: entries, Compress: useCompress, HashAfter: useHashAfter})
	if err := x.ctrl.WriteMsg(wire.MsgManifest, meta); err != nil {
		return 0, fmt.Errorf("manifest 发送: %w", err)
	}
	msgType, body, err := x.ctrl.ReadMsg()
	if err != nil {
		return 0, fmt.Errorf("accept 接收: %w", err)
	}
	if msgType != wire.MsgAccept {
		return 0, fmt.Errorf("期望 accept 帧,得到 type=%d", msgType)
	}
	var acc acceptMsg
	if err := json.Unmarshal(body, &acc); err != nil {
		return 0, fmt.Errorf("accept 解析: %w", err)
	}
	accepted := map[int]bool{}
	for _, id := range acc.Accepted {
		accepted[id] = true
	}

	opts := transferOpts{Compress: useCompress, HashAfter: useHashAfter}
	var sent, done atomic.Int64
	stopProgress := make(chan struct{})
	if progress != nil {
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-stopProgress:
					progress(sent.Load(), total)
					return
				case <-t.C:
					progress(sent.Load(), total)
				}
			}
		}()
	}

	count := 0
	for i, entry := range entries {
		if !accepted[entry.ID] {
			continue
		}
		if boundary != nil && boundary() {
			// 先通后优:直连就绪,在旧承载(中继)上发换源标记,再换源
			_ = x.ctrl.WriteMsg(wire.MsgSwap, nil)
			x = getX()
			progress(0, 0)
		} else {
			x = getX() // 文件边界:常规取源
		}
		f, ferr := os.Open(absPaths[i])
		if ferr != nil {
			close(stopProgress)
			return count, ferr
		}
		err := sendOneFile(x, f, entry, opts, func(d int64) { sent.Add(d) })
		_ = f.Close()
		if err != nil {
			close(stopProgress)
			return count, fmt.Errorf("%s: %w", entry.Name, err)
		}
		count++
		done.Add(1)
	}
	close(stopProgress)
	fin, _ := json.Marshal(finalMsg{OK: true, Message: fmt.Sprintf("%d 个文件", count)})
	if err := getX().ctrl.WriteMsg(wire.MsgFinal, fin); err != nil {
		return count, fmt.Errorf("final 发送: %w", err)
	}
	return count, nil
}

// sendOneFile 单文件:meta → ready → chunks(多流视规则) → [hash] → ack。
func sendOneFile(x *xport, f *os.File, entry manifestEntry, opts transferOpts, progress func(int64)) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() != entry.Size {
		return fmt.Errorf("文件大小变化 %d→%d(发送中勿改动)", entry.Size, st.Size())
	}

	var expectHash string
	if !opts.HashAfter {
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		expectHash = hex.EncodeToString(h.Sum(nil))
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	meta, _ := json.Marshal(metaMsg{Name: entry.Name, Size: st.Size(), SHA256: expectHash})
	if err := x.ctrl.WriteMsg(wire.MsgMeta, meta); err != nil {
		return fmt.Errorf("meta 发送: %w", err)
	}
	msgType, body, err := x.ctrl.ReadMsg()
	if err != nil {
		return fmt.Errorf("ready 接收: %w", err)
	}
	if msgType != wire.MsgReady {
		return fmt.Errorf("期望 ready 帧,得到 type=%d", msgType)
	}
	var ready readyMsg
	if err := json.Unmarshal(body, &ready); err != nil {
		return fmt.Errorf("ready 解析: %w", err)
	}
	if ready.Offset < 0 || ready.Offset > st.Size() {
		return fmt.Errorf("对端 offset 非法: %d", ready.Offset)
	}
	if _, err := f.Seek(ready.Offset, io.SeekStart); err != nil {
		return err
	}

	var hasher hash.Hash
	if opts.HashAfter {
		hasher = sha256.New() // 流式累计(offset 恒 0,见互斥规则)
	}

	remaining := st.Size() - ready.Offset
	useMulti := !opts.HashAfter && x.open != nil && ready.Offset == 0 && remaining >= minMultiStreamSize
	if useMulti {
		if err := sendFileMulti(x, f, st.Size(), opts, progress); err != nil {
			return err
		}
	} else {
		if err := streamChunks(x.ctrl, f, ready.Offset, st.Size(), opts, hasher, progress); err != nil {
			return err
		}
	}

	if opts.HashAfter {
		hm, _ := json.Marshal(hashMsg{ID: entry.ID, SHA256: hex.EncodeToString(hasher.Sum(nil))})
		if err := x.ctrl.WriteMsg(wire.MsgHash, hm); err != nil {
			return fmt.Errorf("hash 发送: %w", err)
		}
	}
	return awaitFileAck(x.ctrl, entry.ID)
}

// streamChunks 单流顺序发送(压缩可选;hasher 非空时流式累计明文)。
func streamChunks(ctrl *wire.Conn, f *os.File, from, to int64, opts transferOpts, hasher hash.Hash, progress func(int64)) error {
	size := chunkSize
	if opts.Compress {
		size = compressedChunkSize
	}
	buf := make([]byte, size)
	for pos := from; pos < to; {
		n := int64(len(buf))
		if remain := to - pos; remain < n {
			n = remain
		}
		if _, err := f.ReadAt(buf[:n], pos); err != nil {
			return err
		}
		if hasher != nil {
			hasher.Write(buf[:n])
		}
		payload := buf[:n]
		if opts.Compress {
			payload = zEnc.EncodeAll(buf[:n], nil)
		}
		if err := ctrl.WriteMsg(wire.MsgChunk, payload); err != nil {
			return fmt.Errorf("chunk 发送: %w", err)
		}
		pos += n
		if progress != nil {
			progress(n)
		}
	}
	return nil
}

// awaitFileAck 等待单文件回执。
func awaitFileAck(ctrl *wire.Conn, id int) error {
	msgType, body, err := ctrl.ReadMsg()
	if err != nil {
		return fmt.Errorf("fileAck 接收: %w", err)
	}
	if msgType != wire.MsgFileAck {
		return fmt.Errorf("期望 fileAck 帧,得到 type=%d", msgType)
	}
	var ack fileAckMsg
	if err := json.Unmarshal(body, &ack); err != nil {
		return fmt.Errorf("fileAck 解析: %w", err)
	}
	if ack.ID != id {
		return fmt.Errorf("fileAck id 不符: %d≠%d", ack.ID, id)
	}
	if !ack.OK {
		return fmt.Errorf("对端校验失败: %s", ack.Message)
	}
	return nil
}

// recvAll v4 接收主流程。choose 非 nil 时由调用方决定接受哪些文件(部分接受)。
func recvAll(getX srcGetter, dir string, choose func(mf manifestMsg) []manifestEntry, progress func(got, total int64)) ([]string, error) {
	x := getX()
	msgType, body, err := x.ctrl.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("manifest 接收: %w", err)
	}
	if msgType != wire.MsgManifest {
		return nil, fmt.Errorf("期望 manifest 帧,得到 type=%d", msgType)
	}
	var mf manifestMsg
	if err := json.Unmarshal(body, &mf); err != nil {
		return nil, fmt.Errorf("manifest 解析: %w", err)
	}
	if len(mf.Files) == 0 || len(mf.Files) > maxManifestFiles {
		return nil, fmt.Errorf("manifest 非法: %d 个文件", len(mf.Files))
	}
	seen := map[int]bool{}
	for _, e := range mf.Files {
		if seen[e.ID] || e.Name == "" || e.Size < 0 {
			return nil, fmt.Errorf("manifest 条目非法: %+v", e)
		}
		seen[e.ID] = true
	}
	accepted := mf.Files
	if choose != nil {
		accepted = choose(mf)
	}
	ids := make([]int, 0, len(accepted))
	var total int64
	for _, e := range accepted {
		ids = append(ids, e.ID)
		total += e.Size
	}
	acc, _ := json.Marshal(acceptMsg{Accepted: ids})
	if err := x.ctrl.WriteMsg(wire.MsgAccept, acc); err != nil {
		return nil, fmt.Errorf("accept 发送: %w", err)
	}

	opts := transferOpts{Compress: mf.Compress, HashAfter: mf.HashAfter}
	var got atomic.Int64
	stopProgress := make(chan struct{})
	if progress != nil {
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-stopProgress:
					progress(got.Load(), total)
					return
				case <-t.C:
					progress(got.Load(), total)
				}
			}
		}()
	}

	var out []string
	for range accepted {
		// 边界:先读一帧——若是 MsgSwap 则换源(先通后优),否则即为下一文件的 meta
		x = getX()
		nextType, nextBody, err := x.ctrl.ReadMsg()
		if err != nil {
			close(stopProgress)
			return out, fmt.Errorf("meta 接收: %w", err)
		}
		if nextType == wire.MsgSwap {
			x = getX() // 双方已就绪,换直连
			nextType, nextBody, err = x.ctrl.ReadMsg()
			if err != nil {
				close(stopProgress)
				return out, fmt.Errorf("swap 后 meta 接收: %w", err)
			}
		}
		var e manifestEntry
		if len(accepted) > 0 {
			// 与发送方同序:按 manifest 序取当前条目
			e = accepted[0]
			accepted = accepted[1:]
		}
		if nextType != wire.MsgMeta {
			close(stopProgress)
			return out, fmt.Errorf("期望 meta 帧,得到 type=%d", nextType)
		}
		p, err := recvOneFile(x, dir, e, opts, &got, nextBody)
		if err != nil {
			close(stopProgress)
			return out, err
		}
		out = append(out, p)
	}
	close(stopProgress)
	msgType, _, err = x.ctrl.ReadMsg()
	if err == nil && msgType != wire.MsgFinal {
		return out, fmt.Errorf("期望 final 帧,得到 type=%d", msgType)
	}
	return out, nil
}

// recvOneFile 单文件接收。metaBody 为调用方边界预读出的 meta 帧负载。
func recvOneFile(x *xport, dir string, e manifestEntry, opts transferOpts, got *atomic.Int64, metaBody []byte) (string, error) {
	return recvOneFileMeta(x, dir, e, opts, got, metaBody)
}

func recvOneFileMeta(x *xport, dir string, e manifestEntry, opts transferOpts, got *atomic.Int64, body []byte) (string, error) {
	var meta metaMsg
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", fmt.Errorf("meta 解析: %w", err)
	}
	rel, err := sanitizeRel(meta.Name)
	if err != nil {
		return "", err
	}
	out := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return "", err
	}
	// 迅雷式暂存（2026-10-14 GB 级设计）：传输写 <name>.part，完成才原子改名
	// ——半成品不伪装成完整文件；断点续传按 .part 的字节数续。
	work := out + ".part"
	complete := false

	offset := int64(0)
	resume := !opts.HashAfter // 单遍哈希与续传互斥
	if resume {
		if fi, err := os.Stat(work); err == nil && !fi.IsDir() && fi.Size() <= meta.Size {
			offset = fi.Size()
		} else if fi, err := os.Stat(out); err == nil && !fi.IsDir() && fi.Size() == meta.Size {
			offset = fi.Size() // 已完整（改名前的历史残留场景）：零传输快进
		}
	}
	f, err := os.OpenFile(work, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = f.Close()
		if complete {
			_ = os.Rename(work, out)
		}
	}()

	hasher := sha256.New()
	if offset > 0 {
		// GB 级续传:前缀哈希必须流式(曾用 os.ReadFile 整读——500MB 续传
		// 即 500MB 内存尖峰)。读校验失败(size 变了/读错误)=前缀不可信,
		// 回退全量重传。
		pf, perr := os.Open(work)
		if perr != nil {
			offset = 0
		} else {
			n, cerr := io.CopyN(hasher, pf, offset)
			_ = pf.Close()
			if cerr != nil || n != offset {
				offset = 0
				hasher.Reset()
			}
		}
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return "", err
	}
	if err := f.Truncate(offset); err != nil {
		return "", err
	}
	rd, _ := json.Marshal(readyMsg{Offset: offset})
	if err := x.ctrl.WriteMsg(wire.MsgReady, rd); err != nil {
		return "", fmt.Errorf("ready 发送: %w", err)
	}

	var gotNow int64
	writeChunk := func(chunk []byte) error {
		if opts.Compress {
			plain, derr := zDec.DecodeAll(chunk, nil)
			if derr != nil {
				return fmt.Errorf("chunk 解压: %w", derr)
			}
			chunk = plain
		}
		if _, err := f.Write(chunk); err != nil {
			return err
		}
		hasher.Write(chunk)
		gotNow += int64(len(chunk))
		got.Add(int64(len(chunk)))
		return nil
	}

	useMulti := !opts.HashAfter && x.accept != nil && offset == 0 && meta.Size >= minMultiStreamSize
	if useMulti {
		if err := recvFileMulti(x, f, work, meta, opts, got); err != nil {
			return "", err
		}
	} else {
		for gotNow+offset < meta.Size {
			mt, chunk, rerr := x.ctrl.ReadMsg()
			if rerr != nil {
				return "", fmt.Errorf("chunk 接收: %w", rerr)
			}
			if mt != wire.MsgChunk {
				return "", fmt.Errorf("期望 chunk 帧,得到 type=%d", mt)
			}
			if err := writeChunk(chunk); err != nil {
				return "", err
			}
		}
	}

	// 全量校验:hash_after 用补发帧;多流用盘上重读(乱序到达,流式哈希无效);
	// 单流用流式累计(含续传前缀)。
	expect := meta.SHA256
	switch {
	case opts.HashAfter:
		mt, hbody, rerr := x.ctrl.ReadMsg()
		if rerr != nil {
			return "", fmt.Errorf("hash 接收: %w", rerr)
		}
		if mt != wire.MsgHash {
			return "", fmt.Errorf("期望 hash 帧,得到 type=%d", mt)
		}
		var hm hashMsg
		if err := json.Unmarshal(hbody, &hm); err != nil {
			return "", fmt.Errorf("hash 解析: %w", err)
		}
		if hm.ID != e.ID {
			return "", fmt.Errorf("hash id 不符: %d≠%d", hm.ID, e.ID)
		}
		expect = hm.SHA256
		sum := hex.EncodeToString(hasher.Sum(nil))
		name, ferr := finishFileAck(x, f, work, e.ID, expect, sum)
		if ferr == nil {
			complete = true
			name = out
		}
		return name, ferr
	case useMulti:
		_ = f.Sync()
		rd2, rerr := os.Open(work)
		if rerr != nil {
			return "", rerr
		}
		h := sha256.New()
		_, cerr := io.Copy(h, rd2)
		_ = rd2.Close()
		if cerr != nil {
			return "", fmt.Errorf("全量校验读回: %w", cerr)
		}
		name, ferr := finishFileAck(x, f, work, e.ID, expect, hex.EncodeToString(h.Sum(nil)))
		if ferr == nil {
			complete = true
			name = out
		}
		return name, ferr
	default:
		name, ferr := finishFileAck(x, f, work, e.ID, expect, hex.EncodeToString(hasher.Sum(nil)))
		if ferr == nil {
			complete = true
			name = out
		}
		return name, ferr
	}
}

// finishFileAck 单文件回执 + 坏内容清理。
func finishFileAck(x *xport, f *os.File, out string, id int, expect, sum string) (string, error) {
	ack := fileAckMsg{ID: id, OK: sum == expect}
	if !ack.OK {
		ack.Message = fmt.Sprintf("sha256 不匹配(期望 %s 实际 %s)", expect, sum)
	}
	ab, _ := json.Marshal(ack)
	if err := x.ctrl.WriteMsg(wire.MsgFileAck, ab); err != nil {
		return "", err
	}
	if !ack.OK {
		// 校验失败删除半成品(2026-10-05 审计 P3:坏内容不以正式文件名残留)
		_ = f.Close()
		_ = os.Remove(out)
		return "", errors.New(ack.Message)
	}
	return out, nil
}

// startSegWorker 多流段处理 goroutine 统一形态(发送/接收两侧共用):独立
// goroutine 跑 fn,panic 与段错误同待遇非阻塞转投 errCh,成功零投递。
//
// defer 注册顺序是正确性关键(终审 F3,2026-10-16 修):先注册 wg.Done、
// 后注册 panic-recover——LIFO 展开下 panic 路径先走 recover(向 errCh 投递)
// 再 wg.Done,主协程 wg.Wait 返回时错误必已在 errCh;反序则 wg.Done 先执行,
// 主协程 wg.Wait 返回后 select errCh 落 default,段 panic 被吞成假成功
// (端到端盘上重读哈希校验能兜住坏数据,但双端成败显示不一致)。
func startSegWorker(wg *sync.WaitGroup, errCh chan<- error, cancel func(), seg int, fn func() error) {
	wg.Add(1)
	async.GoSafe(func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				select {
				case errCh <- fmt.Errorf("seg%d panic: %v", seg, r):
				default:
				}
				if cancel != nil {
					cancel()
				}
			}
		}()
		if err := fn(); err != nil {
			select {
			case errCh <- fmt.Errorf("seg%d: %w", seg, err):
			default:
			}
			if cancel != nil {
				cancel()
			}
		}
	})
}

// sendFileMulti v3 多流(v4 语义:压缩段帧+盘上重读定稿由接收侧负责)。
func sendFileMulti(x *xport, f *os.File, size int64, opts transferOpts, progress func(int64)) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	plan, _ := json.Marshal(planMsg{Streams: maxDataStreams})
	if err := x.ctrl.WriteMsg(wire.MsgPlan, plan); err != nil {
		return fmt.Errorf("plan 发送: %w", err)
	}

	boundaries := make([]int64, maxDataStreams+1)
	for i := 0; i <= maxDataStreams; i++ {
		boundaries[i] = size * int64(i) / int64(maxDataStreams)
	}

	openCtx, openCancel := context.WithTimeout(ctx, segOpenBudget)
	conns := make([]*wire.Conn, maxDataStreams)
	for i := 0; i < maxDataStreams; i++ {
		c, err := x.open(openCtx, i)
		if err != nil {
			openCancel()
			cancel()
			return fmt.Errorf("建立数据流: %w", err)
		}
		conns[i] = c
	}
	openCancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	for i := 0; i < maxDataStreams; i++ {
		start, end := boundaries[i], boundaries[i+1]
		// 多流并发是传输栈受压最大的路径(自研 wire 帧+zstd 并发搬运):
		// 段 goroutine 统一挂 startSegWorker——panic 与段错误同待遇转投
		// errCh(否则 wg.Wait 后读不到错误,发送方假成功挂死在 hash/ack);
		// 成功不投递——GoSafeWithErrChannel 成功也会发 nil,会被下方
		// select 误判为失败并误删半成品,故此处只报错误。
		startSegWorker(&wg, errCh, cancel, i, func() error {
			return writeSegment(ctx, conns[i], f, start, end, opts)
		})
	}

	var sent atomic.Int64
	stopProgress := make(chan struct{})
	if progress != nil {
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-stopProgress:
					progress(sent.Load())
					return
				case <-t.C:
					progress(sent.Load())
				}
			}
		}()
	}
	wg.Wait()
	close(stopProgress)
	select {
	case err := <-errCh:
		return err
	default:
	}
	return nil
}

// writeSegment 单数据流:seg 首帧 + 区间 chunk(压缩可选)+ 关流(FIN)。
// ReadAt 并发安全;⚠️ 末尾必须关流——接收方以 FIN 为段结束信号。
func writeSegment(ctx context.Context, c *wire.Conn, f *os.File, start, end int64, opts transferOpts) error {
	defer func() { _ = c.Close() }()
	seg, _ := json.Marshal(segMsg{Start: start})
	if err := c.WriteMsg(wire.MsgSeg, seg); err != nil {
		return fmt.Errorf("seg 帧: %w", err)
	}
	size := chunkSize
	if opts.Compress {
		size = compressedChunkSize
	}
	buf := make([]byte, size)
	for pos := start; pos < end; {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n := int64(len(buf))
		if remain := end - pos; remain < n {
			n = remain
		}
		if _, err := f.ReadAt(buf[:n], pos); err != nil {
			return fmt.Errorf("读源文件: %w", err)
		}
		payload := buf[:n]
		if opts.Compress {
			payload = zEnc.EncodeAll(buf[:n], nil)
		}
		if err := c.WriteMsg(wire.MsgChunk, payload); err != nil {
			return fmt.Errorf("chunk 发送: %w", err)
		}
		pos += n
	}
	return nil
}

// recvFileMulti v3 多流接收(串行 accept 防并发 FIFO 错配;压缩段帧)。
// 全量校验由调用方以盘上重读完成(乱序到达流式哈希无效)。
func recvFileMulti(x *xport, f *os.File, out string, meta metaMsg, opts transferOpts, got *atomic.Int64) error {
	msgType, body, err := x.ctrl.ReadMsg()
	if err != nil {
		return fmt.Errorf("plan 接收: %w", err)
	}
	if msgType != wire.MsgPlan {
		return fmt.Errorf("期望 plan 帧,得到 type=%d", msgType)
	}
	var plan planMsg
	if err := json.Unmarshal(body, &plan); err != nil {
		return fmt.Errorf("plan 解析: %w", err)
	}
	if plan.Streams < 0 || plan.Streams > 64 {
		return fmt.Errorf("plan.streams 非法: %d", plan.Streams)
	}
	streams := plan.Streams

	boundaries := make([]int64, streams+1)
	for i := 0; i <= streams; i++ {
		boundaries[i] = meta.Size * int64(i) / int64(streams)
	}

	var gotNow atomic.Int64
	errCh := make(chan error, 1)
	accCtx, cancelAcc := context.WithTimeout(context.Background(), segOpenBudget)
	defer cancelAcc()

	conns := make([]*wire.Conn, streams)
	for i := 0; i < streams; i++ {
		c, err := x.accept(accCtx, i)
		if err != nil {
			for _, oc := range conns[:i] {
				_ = oc.Close()
			}
			return fmt.Errorf("seg%d accept: %w", i, err)
		}
		conns[i] = c
	}

	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		start, end := boundaries[i], boundaries[i+1]
		// 同发送侧多流:panic 转段错误进 errCh,由调用方走"失败即清半成品"
		// 路径;成功不投递(同 GoSafeWithErrChannel 的 nil 陷阱)。
		startSegWorker(&wg, errCh, nil, i, func() error {
			return recvSegment(conns[i], f, start, end, opts, &gotNow)
		})
	}
	wg.Wait()
	got.Add(gotNow.Load())
	select {
	case err := <-errCh:
		_ = f.Close()
		_ = os.Remove(out) // 失败即清,不留多流零洞半成品
		return err
	default:
	}
	return nil
}

// recvSegment 单数据流:校验 seg 起始 → chunk(压缩可选)落盘至流 FIN。
func recvSegment(c *wire.Conn, f *os.File, start, end int64, opts transferOpts, got *atomic.Int64) error {
	defer func() { _ = c.Close() }()

	msgType, body, err := c.ReadMsg()
	if err != nil {
		return fmt.Errorf("seg 帧接收: %w", err)
	}
	if msgType != wire.MsgSeg {
		return fmt.Errorf("期望 seg 帧,得到 type=%d", msgType)
	}
	var sm segMsg
	if err := json.Unmarshal(body, &sm); err != nil {
		return fmt.Errorf("seg 解析: %w", err)
	}
	if sm.Start != start {
		return fmt.Errorf("seg 起始不符: 期望 %d 实际 %d", start, sm.Start)
	}

	pos := start
	for {
		msgType, body, err = c.ReadMsg()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break // 发送方发完本段即关流:干净 EOF=正常收尾
			}
			return fmt.Errorf("chunk 接收: %w", err)
		}
		if msgType != wire.MsgChunk {
			return fmt.Errorf("期望 chunk 帧,得到 type=%d", msgType)
		}
		if opts.Compress {
			plain, derr := zDec.DecodeAll(body, nil)
			if derr != nil {
				return fmt.Errorf("chunk 解压: %w", derr)
			}
			body = plain
		}
		if _, err := f.WriteAt(body, pos); err != nil {
			return err
		}
		pos += int64(len(body))
		got.Add(int64(len(body)))
		if pos > end {
			return fmt.Errorf("段越界: 已写 %d 超过边界 %d", pos, end)
		}
	}
	if pos != end {
		return fmt.Errorf("段不完整: %d/%d 字节", pos-start, end-start)
	}
	return nil
}

// 导出别名:上层(CLI/网页/桌面)实现逐文件授权回调用。
type (
	// Manifest 对端发来的文件清单。
	Manifest = manifestMsg
	// ManifestEntry 清单条目(ID 从 0 起;Name 为相对路径;Size 字节)。
	ManifestEntry = manifestEntry
)
