package client

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"
)

// TestQUICBudgetSymmetry 守卫：QUIC 接受/拨号的预算必须**两侧同源**。
//
// 根因（p2p#20，2026-11-03 实测）：拨号侧固定 8s、发送侧 PunchBudget+5s ⇒ 不对称。
// QUIC 窗口各自从**自己**打洞结束那刻起算 ⇒ 两侧打洞结束时刻相差 Δ 时,
// 拨号方必须活过 Δ ⇒ 实测 Δ 已达 6~8s(贴着 8s 边缘)⇒ 负载一抖就
// "quic 拨号: context deadline exceeded" ⇒ CI 随机红。
//
// 守卫判据：**每一个** establishQUICBudget 调用点的预算实参必须来自
// ① c.quicOpBudget()（直连通道，两侧同源）或
// ② upgradeOpBudget（升级通道，两侧同源）
// ⇒ 任何"随手写个 8*time.Second"的调用点都会红。
//
// 负对照：把某个调用点的预算改回字面量 8*time.Second ⇒ 本用例红。
func TestQUICBudgetSymmetry(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "client.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 client.go 失败: %v", err)
	}
	allowed := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		// 包级函数（Ident）或方法调用（SelectorExpr）都算
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
		if len(call.Args) == 0 {
			t.Fatalf("establishQUICBudget 调用缺预算实参")
		}
		arg := call.Args[len(call.Args)-1]
		switch e := arg.(type) {
		case *ast.Ident:
			// upgradeOpBudget（常量名）
			if e.Name != "upgradeOpBudget" {
				t.Fatalf("QUIC 预算实参用了未登记的标识符 %q（只允许 c.quicOpBudget() / upgradeOpBudget）", e.Name)
			}
			allowed[e.Name] = true
		case *ast.CallExpr:
			// c.quicOpBudget()
			inner, ok := e.Fun.(*ast.SelectorExpr)
			if !ok || inner.Sel.Name != "quicOpBudget" {
				t.Fatalf("QUIC 预算实参是别的调用（%T）⇒ 必须用 c.quicOpBudget() 或 upgradeOpBudget", arg)
			}
			allowed["c.quicOpBudget()"] = true
		case *ast.BinaryExpr:
			// 字面量表达式（如 8*time.Second）⇒ 不允许
			t.Fatalf("QUIC 预算实参是字面量表达式 ⇒ 两侧会再次不同步（p2p#20）")
		default:
			t.Fatalf("QUIC 预算实参形态未知: %T", arg)
		}
		return true
	})
	if len(allowed) == 0 {
		t.Fatalf("没扫到任何 establishQUICBudget 调用点（判据失效）")
	}
	t.Logf("已登记的预算来源: %v", allowed)
}

// TestEstablishQUICWrapperRemoved 守卫：**不再提供**带默认预算的 establishQUIC 包装。
//
// 有了它，某侧就会悄悄拿到另一个硬编码值（8s）⇒ 两侧不同步 ⇒ p2p#20 复发。
// ⇒ 任何 QUIC 建立都必须显式给预算。
func TestEstablishQUICWrapperRemoved(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "transport.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 transport.go 失败: %v", err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name.Name == "establishQUIC" {
			t.Fatalf("transport.go 里还有 establishQUIC（带默认预算的包装）⇒ 有人会拿到硬编码预算")
		}
	}
}

// TestQuicOpBudgetCoversPunch 守卫：直连预算必须**盖住**打洞预算（对侧最晚就绪时刻）。
//
// 拨号方要在对侧就绪前活着 ⇒ 预算 ≥ 打洞预算 + 握手余量。
// 生产默认 PunchBudget=4s ⇒ 9s；测试常用 20s ⇒ 25s。
func TestQuicOpBudgetCoversPunch(t *testing.T) {
	cases := []struct {
		punch time.Duration
		want  time.Duration
	}{
		{4 * time.Second, 9 * time.Second},
		{20 * time.Second, 25 * time.Second},
	}
	for _, tc := range cases {
		c := &Client{opt: Options{PunchBudget: tc.punch}}
		got := c.quicOpBudget()
		if got != tc.want {
			t.Fatalf("PunchBudget=%s ⇒ 预算=%s，期望 %s", tc.punch, got, tc.want)
		}
		if got <= tc.punch {
			t.Fatalf("预算 %s 必须盖过打洞预算 %s（对侧最晚就绪时刻）", got, tc.punch)
		}
	}
}
