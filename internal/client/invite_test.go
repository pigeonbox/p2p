package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---- T3 名录邀请链路(对真实 p2pd fixture 端到端) ----

func inviteOpts(f *fixture, tag string) Options {
	return Options{
		Registry:    f.base,
		NodeKeyPath: filepath.Join(os.TempDir(), "fcb-invite-"+tag+".key"),
		Quiet:       true,
	}
}

func TestSendInviteEndToEnd(t *testing.T) {
	f := newFixture(t, false)
	senderOpts := inviteOpts(f, "sender")
	receiverOpts := inviteOpts(f, "receiver")

	// 接收方先入名录(watcher 形态:discoverable 注册)
	recvID, err := newNodeIdentity(receiverOpts.NodeKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	reg := newRegistryAPI(f.base)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := reg.registerPresence(ctx, recvID, "接收站B", time.Hour, true); err != nil {
		t.Fatalf("接收方名录注册: %v", err)
	}

	// 发送方投递密封邀请
	code := "KJ8Y-WCYZ-E249"
	senderID, err := newNodeIdentity(senderOpts.NodeKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := SendInvite(senderOpts, code, recvID.id, "发送站A", "设计稿三件套"); err != nil {
		t.Fatalf("SendInvite: %v", err)
	}

	// 接收方弹出+开箱验真
	var got []InvitePayload
	err = RunMailbox(MailboxOptions{
		Options:      receiverOpts,
		Discoverable: true,
		DisplayName:  "接收站B",
		MaxCycles:    1,
	}, func(inv InvitePayload) { got = append(got, inv) })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("应收 1 条邀请,实得 %d", len(got))
	}
	inv := got[0]
	if inv.Code != code || inv.NodeID != senderID.id || inv.Name != "发送站A" || inv.Note != "设计稿三件套" {
		t.Fatalf("邀请负载不符: %+v", inv)
	}
}

func TestMailboxSkipsUnlistableSender(t *testing.T) {
	f := newFixture(t, false)
	receiverOpts := inviteOpts(f, "rx2")
	recvID, err := newNodeIdentity(receiverOpts.NodeKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reg := newRegistryAPI(f.base)
	if err := reg.registerPresence(ctx, recvID, "接收站B", time.Hour, true); err != nil {
		t.Fatal(err)
	}

	// 幽灵发端(不在名录)直接投密文 → 接收方必须跳过
	ghostOpts := inviteOpts(f, "ghost")
	ghost, err := newNodeIdentity(ghostOpts.NodeKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	nonce, boxed, err := SealInvite(receiverBoxPub(t, recvID), ghost.priv, InvitePayload{
		NodeID: ghost.id, Code: "AAAA-BBBB-CCCC",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.mailboxPost(ctx, recvID.id, ghost.id, nonce, boxed); err != nil {
		t.Fatal(err)
	}
	var got []InvitePayload
	err = RunMailbox(MailboxOptions{Options: receiverOpts, Discoverable: true, MaxCycles: 1},
		func(inv InvitePayload) { got = append(got, inv) })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("发端不在名录的密文必须被跳过,实得 %d: %+v", len(got), got)
	}
}

// receiverBoxPub 接收方密封公钥(测试辅助)。
func receiverBoxPub(t *testing.T, id *nodeIdentity) *[32]byte {
	t.Helper()
	pub, _, err := BoxKeypair(id.priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
