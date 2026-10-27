// Package convention 固化 p2p 的**代码约定**守卫（禁裸 `go` 语句，
// 见 no_bare_go_guard_test.go）。
//
// 与 core 的同名包同款实现（两仓独立、互不依赖 ⇒ 各存一份；规则口径必须一致）。
package convention

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// moduleRoot 从 go test 的 CWD（包目录）向上定位模块根。
func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			return root
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("向上未找到 go.mod，无法定位模块根")
		}
		root = parent
	}
}

// walkProductionGoFiles 遍历全部非测试 .go 文件（rel 为模块根相对路径，斜杠分隔）。
//
// 排除目录：.git / bin / data / node_modules / vendor（第三方代码不归本仓管）。
func walkProductionGoFiles(t *testing.T, root string, fn func(rel, abs string)) {
	t.Helper()
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "data", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		fn(filepath.ToSlash(rel), path)
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
}

// enclosingFuncName 返回某节点所在的最内层函数名（拿不到时返回空串）。
func enclosingFuncName(f *ast.File, node ast.Node) string {
	name := ""
	ast.Inspect(f, func(n ast.Node) bool {
		if name != "" {
			return false
		}
		if fd, ok := n.(*ast.FuncDecl); ok && fd.Body != nil &&
			fd.Pos() <= node.Pos() && node.End() <= fd.End() {
			name = fd.Name.Name
			return false
		}
		return true
	})
	return name
}

// parseGoFile 解析单个 .go 文件。
func parseGoFile(t *testing.T, abs string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, abs, nil, 0)
	if err != nil {
		t.Fatalf("解析失败 %s: %v", abs, err)
	}
	return fset, f
}
