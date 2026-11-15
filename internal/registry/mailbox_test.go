package registry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// ---- T2 信箱(mailbox):密封邀请投递,纯密文,p2pd 不验内容 ----
// p2p#45:投递须发端签名、弹出须收端签名——信箱此前是唯一无调用方约束的写面。

func mboxFixture(t *testing.T) (*fixture, testNode) {
	t.Helper()
	f := newFixture(t)
	n := newNode(t)
	f.register(t, n, 3600)
	return f, n
}

// testFromHex 匿名测试用的假 from(非任何真实私钥)。
const testFromHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// sealedPost 构造带发端签名的投递(from|to_node|ts|nonce)。sender 无需
// 注册——签名即身份(与 issue 修复方向一致:拒绝匿名、可溯源)。
func sealedPost(t *testing.T, sender testNode, to, nonce, boxed string, now time.Time) MailboxInput {
	t.Helper()
	ts := now.Unix()
	in := MailboxInput{From: sender.id, Nonce: nonce, Boxed: boxed, TS: ts}
	in.Sig = sender.sign(t, sender.id, to, itoa(ts), nonce)
	return in
}

// popAuth 构造带收端签名的弹出(node_id|ts|nonce)。
func popAuth(t *testing.T, target testNode, nonce string, now time.Time) PopAuth {
	t.Helper()
	ts := now.Unix()
	return PopAuth{Nonce: nonce, TS: ts,
		Sig: target.sign(t, target.id, itoa(ts), nonce)}
}

func TestMailboxPostPopRoundtrip(t *testing.T) {
	f, n := mboxFixture(t)
	ctx := context.Background()
	sender := newNode(t)

	if err := f.svc.MailboxPost(ctx, n.id,
		sealedPost(t, sender, n.id, "b(nonNzb24NCg==", "Ym94ZWQ=", time.Now())); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
	entries, err := f.svc.MailboxPop(ctx, n.id, popAuth(t, n, "pop-1", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Boxed != "Ym94ZWQ=" || entries[0].From != sender.id {
		t.Fatalf("弹出条目不符: %+v", entries)
	}
	if entries[0].TS <= 0 {
		t.Fatalf("服务端须盖到达时间戳: %+v", entries[0])
	}
	// 取后即删(新 nonce 再弹即空)
	if entries, _ := f.svc.MailboxPop(ctx, n.id, popAuth(t, n, "pop-2", time.Now())); len(entries) != 0 {
		t.Fatalf("取后即删违反,残余 %d", len(entries))
	}
}

// p2p#45 复现:匿名(无签名)投递/弹出必须被拒——修复前两者皆放行。
func TestMailboxUnsignedPostPopRejected(t *testing.T) {
	f, n := mboxFixture(t)
	ctx := context.Background()

	// 匿名投递:无 ts/sig
	err := f.svc.MailboxPost(ctx, n.id, MailboxInput{From: testFromHex, Nonce: "x", Boxed: "Yg=="})
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("匿名投递须 401 语义(ErrBadSignature),实得: %v", err)
	}
	// 匿名弹出
	if _, err := f.svc.MailboxPop(ctx, n.id, PopAuth{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("匿名弹出须拒,实得: %v", err)
	}
}

// p2p#45:伪造签名(非发端私钥)必须被拒。
func TestMailboxForgedSignatureRejected(t *testing.T) {
	f, n := mboxFixture(t)
	ctx := context.Background()
	sender := newNode(t)
	attacker := newNode(t)

	in := sealedPost(t, sender, n.id, "n1", "Yg==", time.Now())
	in.Sig = attacker.sign(t, sender.id, n.id, itoa(in.TS), in.Nonce) // 他人私钥冒签
	if err := f.svc.MailboxPost(ctx, n.id, in); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("伪造签名投递须拒,实得: %v", err)
	}
	// 收端弹出被冒签
	auth := popAuth(t, n, "p1", time.Now())
	auth.Sig = attacker.sign(t, n.id, itoa(auth.TS), auth.Nonce)
	if _, err := f.svc.MailboxPop(ctx, n.id, auth); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("伪造签名弹出须拒,实得: %v", err)
	}
}

// p2p#45:同一签名请求在时间窗内重放须拒(防重复占箱/重复抢收)。
func TestMailboxReplayRejected(t *testing.T) {
	f, n := mboxFixture(t)
	ctx := context.Background()
	sender := newNode(t)

	in := sealedPost(t, sender, n.id, "same-nonce", "Yg==", time.Now())
	if err := f.svc.MailboxPost(ctx, n.id, in); err != nil {
		t.Fatalf("首次投递失败: %v", err)
	}
	if err := f.svc.MailboxPost(ctx, n.id, in); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("重放投递须拒,实得: %v", err)
	}
	auth := popAuth(t, n, "same-pop", time.Now())
	if _, err := f.svc.MailboxPop(ctx, n.id, auth); err != nil {
		t.Fatalf("首次弹出失败: %v", err)
	}
	if _, err := f.svc.MailboxPop(ctx, n.id, auth); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("重放弹出须拒,实得: %v", err)
	}
}

// p2p#45:时间窗外的签名(过期)须拒。
func TestMailboxStaleTimestampRejected(t *testing.T) {
	f, n := mboxFixture(t)
	ctx := context.Background()
	sender := newNode(t)

	stale := time.Now().Add(-10 * time.Minute)
	in := sealedPost(t, sender, n.id, "stale", "Yg==", stale)
	if err := f.svc.MailboxPost(ctx, n.id, in); !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("过期签名投递须拒,实得: %v", err)
	}
	auth := popAuth(t, n, "stale-pop", stale)
	if _, err := f.svc.MailboxPop(ctx, n.id, auth); !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("过期签名弹出须拒,实得: %v", err)
	}
}

func TestMailboxTTLExpiry(t *testing.T) {
	f, n := mboxFixture(t)
	ctx := context.Background()
	sender := newNode(t)
	if err := f.svc.MailboxPost(ctx, n.id,
		sealedPost(t, sender, n.id, "b g==", "Yg==", time.Now())); err != nil {
		t.Fatal(err)
	}
	f.svc.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	// 弹出签名须用拨钟后时间(否则先被时间窗拒绝,测不到 TTL 路径)
	entries, err := f.svc.MailboxPop(ctx, n.id, popAuth(t, n, "ttl-pop", f.svc.now()))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("TTL 15min 过期应不可取: %d", len(entries))
	}
}

func TestMailboxFullBoxRejected(t *testing.T) {
	f, n := mboxFixture(t)
	ctx := context.Background()
	sender := newNode(t)
	for i := 0; i < maxMailboxPerNode; i++ {
		if err := f.svc.MailboxPost(ctx, n.id,
			sealedPost(t, sender, n.id, "n"+itoa(int64(i)), "Yg==", time.Now())); err != nil {
			t.Fatalf("第 %d 条投递失败: %v", i+1, err)
		}
	}
	err := f.svc.MailboxPost(ctx, n.id,
		sealedPost(t, sender, n.id, "overflow", "Yg==", time.Now()))
	if err == nil || !strings.Contains(err.Error(), ErrQuotaExceeded.Error()) {
		t.Fatalf("满箱须拒: %v", err)
	}
}

func TestMailboxOversizedRejected(t *testing.T) {
	f, n := mboxFixture(t)
	sender := newNode(t)
	big := strings.Repeat("QQ==", 2048) // 解码 8KB > 4KB
	// 形态闸先于验签:超限无需有效签名即拒
	err := f.svc.MailboxPost(context.Background(), n.id,
		sealedPost(t, sender, n.id, "big", big, time.Now()))
	if err == nil || !strings.Contains(err.Error(), ErrInvalidRequest.Error()) {
		t.Fatalf("超限密封体须拒: %v", err)
	}
}

func TestMailboxUnknownNodeRejected(t *testing.T) {
	f, _ := mboxFixture(t)
	sender := newNode(t)
	ghost := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	err := f.svc.MailboxPost(context.Background(), ghost,
		sealedPost(t, sender, ghost, "g", "Yg==", time.Now()))
	if err == nil || !strings.Contains(err.Error(), ErrNotFound.Error()) {
		t.Fatalf("投递到未注册节点须 404 语义: %v", err)
	}
}

func TestMailboxMalformedFromRejected(t *testing.T) {
	f, n := mboxFixture(t)
	sender := newNode(t)
	in := sealedPost(t, sender, n.id, "b g==", "Yg==", time.Now())
	in.From = "not-hex!!"
	if err := f.svc.MailboxPost(context.Background(), n.id, in); err == nil {
		t.Fatal("from 非 hex64 须拒绝")
	}
}

func TestMailboxNodeExpiryCascade(t *testing.T) {
	f, n := mboxFixture(t)
	ctx := context.Background()
	sender := newNode(t)
	if err := f.svc.MailboxPost(ctx, n.id,
		sealedPost(t, sender, n.id, "b g==", "Yg==", time.Now())); err != nil {
		t.Fatal(err)
	}
	// 节点租约过期后 Sweep:信箱级联清除
	f.svc.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	f.svc.Sweep(ctx)
	// 节点不在租约内,pop 即 404 语义(查活先于验签)
	_, err := f.svc.MailboxPop(ctx, n.id, popAuth(t, n, "gone", f.svc.now()))
	if err == nil || !strings.Contains(err.Error(), ErrNotFound.Error()) {
		t.Fatalf("节点过期后信箱须级联清除: %v", err)
	}
}
