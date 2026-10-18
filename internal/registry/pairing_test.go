package registry

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ---- 配对码测试脚手架 ----

// newPairFixture 复用 service_test 的内存仓 fixture 注册双方租约，
// 配对服务以同一 *Service 为租约来源（liveNode 校验因此可过）。
func newPairFixture(t *testing.T, cfg PairingConfig) (*PairingService, *fixture, testNode, testNode) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := newFixture(t)
	svc := NewPairingService(ctx, cfg, f.svc)
	creator, claimant := newNode(t), newNode(t)
	f.register(t, creator, 3600)
	f.register(t, claimant, 3600)
	return svc, f, creator, claimant
}

func pairCreate(t *testing.T, svc *PairingService, n testNode, secret string) (string, time.Duration) {
	t.Helper()
	ts := time.Now().Unix()
	code, ttl, err := svc.Create(context.Background(), PairCreateInput{
		NodeID: n.id, Secret: secret, TS: ts,
		Sig: n.sign(t, "pair-create", n.id, secret, itoa(ts)),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return code, ttl
}

func pairClaim(t *testing.T, svc *PairingService, n testNode, code, claimID string) (PairClaimResult, error) {
	t.Helper()
	ts := time.Now().Unix()
	return svc.Claim(context.Background(), PairClaimInput{
		NodeID: n.id, Code: code, ClaimID: claimID, TS: ts,
		Sig: n.sign(t, "pair-claim", n.id, code, claimID, itoa(ts)),
	})
}

func pairApprove(t *testing.T, svc *PairingService, n testNode, code, decision, claimer string) error {
	t.Helper()
	ts := time.Now().Unix()
	return svc.Approve(context.Background(), PairApproveInput{
		NodeID: n.id, Code: code, Decision: decision, Claimer: claimer, TS: ts,
		Sig: n.sign(t, "pair-approve", n.id, code, decision, claimer, itoa(ts)),
	})
}

func pairRequests(t *testing.T, svc *PairingService, n testNode) []PairSessionView {
	t.Helper()
	ts := time.Now().Unix()
	views, err := svc.Requests(context.Background(), PairRequestsInput{
		NodeID: n.id, TS: ts,
		Sig: n.sign(t, "pair-requests", n.id, itoa(ts)),
	})
	if err != nil {
		t.Fatalf("requests: %v", err)
	}
	return views
}

// ---- 用例 ----

func TestPairHappyPath(t *testing.T) {
	svc, f, creator, claimant := newPairFixture(t, PairingConfig{})
	code, ttl := pairCreate(t, svc, creator, "ABCDEFGHJKMNPQRSTWXYZ123")
	if ttl != 5*time.Minute {
		t.Fatalf("缺省 TTL 应为 5m, 实际 %s", ttl)
	}
	if len(code) != 4 {
		t.Fatalf("缺省码长应为 4, 实际 %q", code)
	}

	// 批准前 requests 无待确认项
	views := pairRequests(t, svc, creator)
	if len(views) != 1 || len(views[0].Requests) != 0 {
		t.Fatalf("批准前不应有待确认请求: %+v", views)
	}

	res, err := pairClaim(t, svc, claimant, code, "claim-1")
	if err != nil || res.Status != "pending" {
		t.Fatalf("首 claim 应 pending: %+v err=%v", res, err)
	}
	if res.ExpiresIn <= 0 || res.ExpiresIn > 300 {
		t.Fatalf("pending 应带码剩余窗: %d", res.ExpiresIn)
	}

	// 亮码方看到敲门人
	views = pairRequests(t, svc, creator)
	if len(views) != 1 || len(views[0].Requests) != 1 || views[0].Requests[0].NodeID != claimant.id {
		t.Fatalf("requests 应含 claimant: %+v", views)
	}

	// 他人同码不同 claim_id → busy
	other := newNode(t)
	f.register(t, other, 3600)
	if _, err := pairClaim(t, svc, other, code, "claim-hijack"); !errors.Is(err, ErrConflict) {
		t.Fatalf("抢入应 ErrConflict, 实际 %v", err)
	}

	if err := pairApprove(t, svc, creator, code, "accept", claimant.id); err != nil {
		t.Fatalf("approve: %v", err)
	}
	res, err = pairClaim(t, svc, claimant, code, "claim-1")
	if err != nil || res.Status != "granted" {
		t.Fatalf("批准后 claim 应 granted: %+v err=%v", res, err)
	}
	if res.Secret != "ABCDEFGHJKMNPQRSTWXYZ123" || res.Creator != creator.id {
		t.Fatalf("兑换内容不符: %+v", res)
	}

	// secret 一次性发放：出表后重复轮询得干净 404
	if _, err := pairClaim(t, svc, claimant, code, "claim-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("兑换后应 ErrNotFound, 实际 %v", err)
	}
	if svc.Stats() != 0 {
		t.Fatalf("终态会话应出表, 活跃 %d", svc.Stats())
	}
}

func TestPairDenyBurnsCode(t *testing.T) {
	svc, _, creator, claimant := newPairFixture(t, PairingConfig{})
	code, _ := pairCreate(t, svc, creator, "SECRETXSECRETX12")
	if _, err := pairClaim(t, svc, claimant, code, "c1"); err != nil {
		t.Fatal(err)
	}
	if err := pairApprove(t, svc, creator, code, "deny", claimant.id); err != nil {
		t.Fatal(err)
	}
	if _, err := pairClaim(t, svc, claimant, code, "c1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("拒绝即烧码, 轮询应 404, 实际 %v", err)
	}
}

func TestPairUnknownCodeNotFound(t *testing.T) {
	svc, _, _, claimant := newPairFixture(t, PairingConfig{})
	if _, err := pairClaim(t, svc, claimant, "0000", "c1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("未知码应 ErrNotFound, 实际 %v", err)
	}
}

func TestPairBadSignatureRejected(t *testing.T) {
	svc, _, creator, claimant := newPairFixture(t, PairingConfig{})
	ts := time.Now().Unix()
	in := PairCreateInput{NodeID: creator.id, Secret: "SECRETXSECRETX12", TS: ts,
		Sig: claimant.sign(t, "pair-create", creator.id, "SECRETXSECRETX12", itoa(ts))}
	if _, _, err := svc.Create(context.Background(), in); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("他人签名应 ErrBadSignature, 实际 %v", err)
	}
}

func TestPairStaleTimestampRejected(t *testing.T) {
	svc, _, creator, _ := newPairFixture(t, PairingConfig{})
	old := time.Now().Add(-11 * time.Minute).Unix()
	in := PairCreateInput{NodeID: creator.id, Secret: "SECRETXSECRETX12", TS: old,
		Sig: creator.sign(t, "pair-create", creator.id, "SECRETXSECRETX12", itoa(old))}
	if _, _, err := svc.Create(context.Background(), in); !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("过期时间戳应 ErrStaleTimestamp, 实际 %v", err)
	}
}

func TestPairExpired(t *testing.T) {
	svc, _, creator, claimant := newPairFixture(t, PairingConfig{CodeTTL: 30 * time.Millisecond})
	code, _ := pairCreate(t, svc, creator, "SECRETXSECRETX12")
	time.Sleep(60 * time.Millisecond)
	if _, err := pairClaim(t, svc, claimant, code, "c1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("过期码应 ErrNotFound, 实际 %v", err)
	}
	if svc.Stats() != 0 {
		t.Fatalf("过期会话应出表")
	}
}

func TestPairQuotaPerNode(t *testing.T) {
	svc, _, creator, _ := newPairFixture(t, PairingConfig{MaxPerNode: 1})
	pairCreate(t, svc, creator, "SECRETXSECRETX12")
	ts := time.Now().Unix()
	_, _, err := svc.Create(context.Background(), PairCreateInput{
		NodeID: creator.id, Secret: "SECRETXSECRETX34", TS: ts,
		Sig: creator.sign(t, "pair-create", creator.id, "SECRETXSECRETX34", itoa(ts)),
	})
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("超配额应 ErrQuotaExceeded, 实际 %v", err)
	}
}

func TestPairNoLeaseRejected(t *testing.T) {
	svc, _, _, _ := newPairFixture(t, PairingConfig{})
	ghost := newNode(t) // 未注册租约
	ts := time.Now().Unix()
	_, _, err := svc.Create(context.Background(), PairCreateInput{
		NodeID: ghost.id, Secret: "SECRETXSECRETX12", TS: ts,
		Sig: ghost.sign(t, "pair-create", ghost.id, "SECRETXSECRETX12", itoa(ts)),
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("无租约应 ErrNotFound, 实际 %v", err)
	}
}

func TestPairApproveBindsClaimer(t *testing.T) {
	svc, f, creator, claimant := newPairFixture(t, PairingConfig{})
	code, _ := pairCreate(t, svc, creator, "SECRETXSECRETX12")
	if _, err := pairClaim(t, svc, claimant, code, "c1"); err != nil {
		t.Fatal(err)
	}
	// 裁决对象与 pending claimer 不符 → 冲突
	other := newNode(t)
	f.register(t, other, 3600)
	if err := pairApprove(t, svc, creator, code, "accept", other.id); !errors.Is(err, ErrConflict) {
		t.Fatalf("裁决他人应 ErrConflict, 实际 %v", err)
	}
	// 非亮码方不能裁决
	if err := pairApprove(t, svc, claimant, code, "accept", claimant.id); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("非亮码方裁决应 ErrUnauthorized, 实际 %v", err)
	}
}

func TestPairCodeUniqueness(t *testing.T) {
	svc, _, creator, _ := newPairFixture(t, PairingConfig{MaxPerNode: 100})
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		code, _ := pairCreate(t, svc, creator, "SECRETXSECRETX"+string(rune('A'+i%26))+"1")
		if seen[code] {
			t.Fatalf("配对码碰撞: %s", code)
		}
		seen[code] = true
	}
}

func TestPairSecretValidation(t *testing.T) {
	svc, _, creator, _ := newPairFixture(t, PairingConfig{})
	ts := time.Now().Unix()
	for _, secret := range []string{"short", "", "has space in secret padding!!"} {
		_, _, err := svc.Create(context.Background(), PairCreateInput{
			NodeID: creator.id, Secret: secret, TS: ts,
			Sig: creator.sign(t, "pair-create", creator.id, secret, itoa(ts)),
		})
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("非法 secret %q 应 ErrInvalidRequest, 实际 %v", secret, err)
		}
	}
}
