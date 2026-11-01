// no_bare_go_guard_test.go 规则 1：禁裸 `go` 语句（机械守卫）。
//
// ## 为什么立这条
//
// 裸 goroutine 的 panic **无人接** ⇒ 直接带走整个进程。p2p 的三个进程
// （p2pd 注册/信令、p2pc 直传、p2pcweb 网页直传）全是**长驻**的
// ⇒ 一个后台协程（清扫/心跳/进度条/中继连接处理）里的 nil 解引用就能把
// 整个节点/会话打挂，现场只剩一句 stack。
//
// 修法不是"记得 recover"，而是**用 oekit/concurrency/async 的 GoSafe 家族**：
// panic 被收编，并经**全局 handler** 上报（三个 cmd 入口都已装
// async.SetPanicHandler ⇒ 落结构化日志 + stack，不是静默吞掉）。
//
// 轮次内的 panic 早已由 RunSafeLabeled 逐轮收编（清扫/心跳/快照/信令 janitor）；
// 本守卫管的是**协程外壳**——外壳 panic 同样会带走进程。
//
// ## 例外：主服务协程
//
// 白名单只登记「主服务协程」——进程的存在意义就是它，panic 应**带崩进程**
// 让 supervisor 重启（租约会过期、对端自动绕行，节点"活着但不服务"比直接死掉
// 更难诊断）。改成 GoSafe 会让错误永不投递到 errCh ⇒ 主流程挂死。
//
// ## 棘轮
//
// 白名单按「文件 + 所在函数」计数，**只许减不许增**；条目失效（该处已无裸 go）
// 也判红 ⇒ 白名单不会悄悄变成"什么都放行"的垃圾桶。
package convention

import (
	"fmt"
	"go/ast"
	"sort"
	"strings"
	"testing"
)

// bareGoAllowEntry 白名单条目。
type bareGoAllowEntry struct {
	file   string // 模块根相对路径（斜杠分隔）
	fn     string // 所在函数名
	count  int    // 允许的裸 go 语句条数
	reason string // 放行理由
}

// bareGoAllow 例外白名单。
//
// 新增条目须写明「为什么 panic 在这里应当带崩进程」，并接受棘轮（只许减）。
var bareGoAllow = []bareGoAllowEntry{
	{
		file:  "cmd/p2pd/main.go",
		fn:    "main",
		count: 1,
		reason: "主服务协程（httpSrv.ListenAndServe）：进程的存在意义就是它 ⇒ panic 应带崩进程让 supervisor 重启；" +
			"改成 GoSafe 会让 errCh 永不投递 ⇒ 主流程永久挂死（活着但不服务比死掉更难诊断）",
	},
}

// TestNoBareGoStatement 规则 1：生产代码里不得出现裸 `go` 语句。
//
// 判据是 **AST 级**（`go/ast` 的 *ast.GoStmt）：文本 grep 会把注释、字符串、
// 以及 `//go:xxx` 指令误判，也认不出 `go someFunc()` 这种非字面量形态。
func TestNoBareGoStatement(t *testing.T) {
	root := moduleRoot(t)

	// 实际命中：file → func → 条数
	actual := map[string]map[string]int{}
	var violations []string

	walkProductionGoFiles(t, root, func(rel, abs string) {
		fset, f := parseGoFile(t, abs)
		ast.Inspect(f, func(n ast.Node) bool {
			gs, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			fn := enclosingFuncName(f, gs)
			if actual[rel] == nil {
				actual[rel] = map[string]int{}
			}
			actual[rel][fn]++
			line := fset.Position(gs.Pos()).Line
			allowed := false
			for _, e := range bareGoAllow {
				if e.file == rel && e.fn == fn && actual[rel][fn] <= e.count {
					allowed = true
					break
				}
			}
			if !allowed {
				violations = append(violations, fmt.Sprintf(
					"规则1 裸 go 语句: %s:%d（函数 %s）——改用 async.GoSafe/GoSafeLabeled"+
						"（panic 经全局 async.SetPanicHandler 落日志，不静默）", rel, line, fn))
			}
			return true
		})
	})

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Errorf("发现 %d 处裸 go 语句:\n%s", len(violations), strings.Join(violations, "\n"))
	}

	// 棘轮二：白名单条目失效（该处已无裸 go / 条数减少）⇒ 判红，请删条目。
	for _, e := range bareGoAllow {
		got := actual[e.file][e.fn]
		if got < e.count {
			t.Errorf("规则1 白名单条目失效: %s 的 %s 登记 %d 处、实际 %d 处 —— 请删除或下调条目（棘轮只许减）",
				e.file, e.fn, e.count, got)
		}
	}
}
