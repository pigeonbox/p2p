package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// slowPanic panic 值:%v 格式化耗时 200ms——把「recover 向 errCh 投递」与
// 「wg.Done 唤醒主协程」之间的指令窗口从几条指令放大到秒级,使 F3 类 defer
// 顺序回归可被确定性观测:
//   - 旧顺序(recover 先注册):panic 展开先执行 wg.Done,主协程 wg.Wait 返回
//     后 select errCh 落 default=假成功,此刻 recover 还卡在格式化上——本测
//     试必红;
//   - 新顺序(wg.Done 先注册):投递先于 Done,经 WaitGroup happens-before,
//     Wait 返回时错误必已在 errCh——必绿。
type slowPanic struct{}

func (slowPanic) String() string {
	time.Sleep(200 * time.Millisecond)
	return "boom"
}

// TestSegWorkerPanicToErrChannel 表驱动 panic 注入:段处理 panic/错误必转投
// errCh 且不悬挂 wg.Wait;成功路径零投递、不触发 cancel。
func TestSegWorkerPanicToErrChannel(t *testing.T) {
	cases := []struct {
		name       string
		fn         func() error
		wantErr    string // "" = 零投递
		wantCancel bool
	}{
		{"panic 必转错误且不悬挂", func() error { panic(slowPanic{}) }, "seg2 panic: boom", true},
		{"段错误同待遇投递", func() error { return errors.New("boom-err") }, "seg2: boom-err", true},
		{"成功路径零投递", func() error { return nil }, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var wg sync.WaitGroup
			errCh := make(chan error, 1) // 与生产同形:缓冲 1
			cancelCalled := make(chan struct{})
			startSegWorker(&wg, errCh, func() { close(cancelCalled) }, 2, tc.fn)

			waited := make(chan struct{})
			go func() { wg.Wait(); close(waited) }()
			select {
			case <-waited:
			case <-time.After(5 * time.Second):
				t.Fatal("wg.Wait 悬挂 5s")
			}

			// F3 不变量:wg.Wait 返回时错误必已就位——非阻塞 select,禁止等待。
			select {
			case err := <-errCh:
				if tc.wantErr == "" {
					t.Fatalf("成功路径却向 errCh 投递: %v", err)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("错误文案不符: got %q want %q", err.Error(), tc.wantErr)
				}
			default:
				if tc.wantErr != "" {
					t.Fatal("假成功:wg.Wait 返回时 errCh 为空(段 panic/错误未投递)")
				}
			}
			// cancel 语义:错误路径必触发,成功路径必不触发。投递先于 cancel
			// 先于 wg.Done,Wait 返回后即已定局,非阻塞判定。
			select {
			case <-cancelCalled:
				if !tc.wantCancel {
					t.Fatal("成功路径不应触发 cancel")
				}
			default:
				if tc.wantCancel {
					t.Fatal("错误路径未触发 cancel")
				}
			}
		})
	}
}

// TestSegWorkerCancelUnblocksSibling panic 路径触发 cancel,唤醒同组阻塞段
// (生产编排:一处段 panic,其余段经 ctx 感知收摊,wg.Wait 不悬挂)。
func TestSegWorkerCancelUnblocksSibling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	startSegWorker(&wg, errCh, cancel, 0, func() error {
		<-ctx.Done()
		return ctx.Err()
	})
	startSegWorker(&wg, errCh, cancel, 1, func() error { panic("boom") })

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wg.Wait 悬挂:panic 未唤醒同组段")
	}
	// seg1 的 panic 投递先于 cancel(先于 seg0 解锁),必为 errCh 首值。
	select {
	case err := <-errCh:
		if got := err.Error(); got != "seg1 panic: boom" {
			t.Fatalf("首投递应为 panic 错误, got %q", got)
		}
	default:
		t.Fatal("panic 错误未投递")
	}
}
