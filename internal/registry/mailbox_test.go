package registry

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ---- T2 信箱(mailbox):密封邀请投递,纯密文,p2pd 不验内容 ----

func mboxFixture(t *testing.T) (*fixture, testNode) {
	t.Helper()
	f := newFixture(t)
	n := newNode(t)
	f.register(t, n, 3600)
	return f, n
}

const testFromHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func sealedBody(nonce, boxed string) MailboxInput {
	return MailboxInput{From: testFromHex, Nonce: nonce, Boxed: boxed}
}

func TestMailboxPostPopRoundtrip(t *testing.T) {
	f, n := mboxFixture(t)
	ctx := context.Background()

	if err := f.svc.MailboxPost(ctx, n.id, sealedBody("b(nonNzb24NCg==", "Ym94ZWQ=")); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
	entries, err := f.svc.MailboxPop(ctx, n.id)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Boxed != "Ym94ZWQ=" || entries[0].From != testFromHex {
		t.Fatalf("弹出条目不符: %+v", entries)
	}
	if entries[0].TS <= 0 {
		t.Fatalf("服务端须盖到达时间戳: %+v", entries[0])
	}
	// 取后即删
	if entries, _ := f.svc.MailboxPop(ctx, n.id); len(entries) != 0 {
		t.Fatalf("取后即删违反,残余 %d", len(entries))
	}
}

func TestMailboxTTLExpiry(t *testing.T) {
	f, n := mboxFixture(t)
	ctx := context.Background()
	if err := f.svc.MailboxPost(ctx, n.id, sealedBody("b g==", "Yg==")); err != nil {
		t.Fatal(err)
	}
	f.svc.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	entries, err := f.svc.MailboxPop(ctx, n.id)
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
	for i := 0; i < maxMailboxPerNode; i++ {
		if err := f.svc.MailboxPost(ctx, n.id, sealedBody("b g==", "Yg==")); err != nil {
			t.Fatalf("第 %d 条投递失败: %v", i+1, err)
		}
	}
	err := f.svc.MailboxPost(ctx, n.id, sealedBody("b g==", "Yg=="))
	if err == nil || !strings.Contains(err.Error(), ErrQuotaExceeded.Error()) {
		t.Fatalf("满箱须拒: %v", err)
	}
}

func TestMailboxOversizedRejected(t *testing.T) {
	f, n := mboxFixture(t)
	big := strings.Repeat("QQ==", 2048) // 解码 8KB > 4KB
	err := f.svc.MailboxPost(context.Background(), n.id, sealedBody("b g==", big))
	if err == nil || !strings.Contains(err.Error(), ErrInvalidRequest.Error()) {
		t.Fatalf("超限密封体须拒: %v", err)
	}
}

func TestMailboxUnknownNodeRejected(t *testing.T) {
	f, _ := mboxFixture(t)
	err := f.svc.MailboxPost(context.Background(), "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", sealedBody("b g==", "Yg=="))
	if err == nil || !strings.Contains(err.Error(), ErrNotFound.Error()) {
		t.Fatalf("投递到未注册节点须 404 语义: %v", err)
	}
}

func TestMailboxMalformedFromRejected(t *testing.T) {
	f, n := mboxFixture(t)
	in := sealedBody("b g==", "Yg==")
	in.From = "not-hex!!"
	if err := f.svc.MailboxPost(context.Background(), n.id, in); err == nil {
		t.Fatal("from 非 hex64 须拒绝")
	}
}

func TestMailboxNodeExpiryCascade(t *testing.T) {
	f, n := mboxFixture(t)
	ctx := context.Background()
	if err := f.svc.MailboxPost(ctx, n.id, sealedBody("b g==", "Yg==")); err != nil {
		t.Fatal(err)
	}
	// 节点租约过期后 Sweep:信箱级联清除
	f.svc.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	f.svc.Sweep(ctx)
	// 节点不在租约内,pop 即 404 语义
	_, err := f.svc.MailboxPop(ctx, n.id)
	if err == nil || !strings.Contains(err.Error(), ErrNotFound.Error()) {
		t.Fatalf("节点过期后信箱须级联清除: %v", err)
	}
}
