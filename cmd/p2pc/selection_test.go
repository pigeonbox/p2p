package main

// 选文件解析与口令提示的守卫（2026-10-26 审计 P1）：
//   - 交互式选文件的解析结果必须按 ID 升序（= 发送侧 manifest 序）——
//     降序输入（"2,1"）会让接收侧首个回执带上非首个文件的 ID ⇒ 发送侧判
//     「fileAck id 不符」⇒ 整场传输失败；
//   - printCode 的提示行不得把口令写进可复制的命令行（口令是唯一 bearer
//     凭据，命令行会留在 shell 历史与进程表里）。

import (
	"strings"
	"testing"

	"github.com/pigeonbox/p2p/internal/client"
)

func manifestFixture() []client.ManifestEntry {
	return []client.ManifestEntry{
		{ID: 0, Name: "a.bin", Size: 10},
		{ID: 1, Name: "b.bin", Size: 20},
		{ID: 2, Name: "c.bin", Size: 30},
	}
}

func idsOf(entries []client.ManifestEntry) []int {
	out := make([]int, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.ID)
	}
	return out
}

// TestParseSelectionSortedByID parseSelection 必须返回按 ID 升序的切片。
//
// 负对照：去掉排序 ⇒ 降序输入的用例红。
func TestParseSelectionSortedByID(t *testing.T) {
	files := manifestFixture()
	cases := []struct {
		name string
		line string
		want []int
	}{
		{"降序输入", "3,1", []int{0, 2}},
		{"乱序输入", "2,1,3", []int{0, 1, 2}},
		{"区间", "1-3", []int{0, 1, 2}},
		{"区间+单点(乱序)", "3,1-2", []int{0, 1, 2}},
		{"重复去重", "2,2,1", []int{0, 1}},
		{"越界忽略", "9", nil},
		{"非法忽略", "x,2", []int{1}},
		{"空", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSelection(tc.line, files)
			if len(got) != len(tc.want) {
				t.Fatalf("parseSelection(%q) 选中 %d 项,期望 %d 项(%v)", tc.line, len(got), len(tc.want), idsOf(got))
			}
			for i, id := range tc.want {
				if got[i].ID != id {
					t.Fatalf("parseSelection(%q) = %v,期望 %v", tc.line, idsOf(got), tc.want)
				}
			}
			// 升序不变量（表驱动之外的机械断言）
			for i := 1; i < len(got); i++ {
				if got[i-1].ID >= got[i].ID {
					t.Fatalf("parseSelection(%q) 未按 ID 升序: %v", tc.line, idsOf(got))
				}
			}
		})
	}
}

// TestPrintCodeHintHasNoSecretInCommand printCode 的「接收方执行」提示不得
// 含口令（口令只出现在「口令:」那一行——那是下游解析器的格式契约）。
//
// 负对照：把提示改回 `p2pc recv %s` ⇒ 红。
func TestPrintCodeHintHasNoSecretInCommand(t *testing.T) {
	const code = "ABCD-1234-WXYZ"
	got := captureStdout(t, func() { printCode(code) })
	if !strings.Contains(got, "口令: "+code+"\n") {
		t.Fatalf("口令行格式漂移: %q", got)
	}
	if !strings.Contains(got, "p2pc recv -") {
		t.Fatalf("提示行应引导 `p2pc recv -`（口令走 env）: %q", got)
	}
	if strings.Contains(got, "p2pc recv "+code) {
		t.Fatalf("提示行把口令写进了可复制命令行: %q", got)
	}
	// 口令只允许出现在「口令:」那一行
	if n := strings.Count(got, code); n != 1 {
		t.Fatalf("口令出现 %d 次（应仅 1 次）: %q", n, got)
	}
}
