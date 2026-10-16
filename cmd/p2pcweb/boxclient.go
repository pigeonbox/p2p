package main

// Box 客户端：投递到柜——PigeonBeam 与 PigeonBox 两应用之间唯一的桥
// （hub docs/specs/2026-10-16-two-app-split-design.md A1，桥方向翻转：
// Beam 作 Box 的 API 客户端，Box 不为本桥增加任何端点）。
// 仅调用公开契约 POST /share/file/（UserOrAPIKey 鉴权，X-API-Key 头）；
// 叶子仓零业务依赖守卫——不得 import 生态包，请求/响应字段以字面对齐
// contracts idl share.thrift。

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// 投递分享有效期 v1 固定 1 天（expire_style 枚举：minute/hour/day/week/month/year/forever）。
const (
	boxExpireValue = 1
	boxExpireStyle = "day"
	boxHTTPTimeout = 30 * time.Minute
)

// boxDeliverResult 建分享结果。PickupCode 为 6 位取件码（文本/文件分享同权铸造）。
type boxDeliverResult struct {
	ShareCode  string `json:"share_code"`
	PickupCode string `json:"pickup_code"`
	URL        string `json:"url"`
}

// deliverToBox 上传本地文件到 PigeonBox 建文件分享。multipart 头尾在内存拼装、
// 文件体直读原文件——请求定长（避开 chunked 编码，兼容严格解析
// Content-Length 的反代链路），大文件不落第二份盘。
func deliverToBox(baseURL, apiKey, path string) (*boxDeliverResult, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		return nil, errors.New("未配置文件柜地址（「文件柜」页）")
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("未配置文件柜 API Key（「文件柜」页；柜侧 个人设置 → API Token 生成）")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, errors.New("目录不支持投递，请逐文件")
	}

	var head bytes.Buffer
	mw := multipart.NewWriter(&head)
	_ = mw.WriteField("expire_value", strconv.Itoa(boxExpireValue))
	_ = mw.WriteField("expire_style", boxExpireStyle)
	_ = mw.WriteField("require_auth", "false")
	if _, err := mw.CreateFormFile("file", filepath.Base(path)); err != nil {
		return nil, err
	}
	boundary := strings.TrimPrefix(mw.FormDataContentType(), "multipart/form-data; boundary=")
	tail := "\r\n--" + boundary + "--\r\n"

	req, err := http.NewRequest(http.MethodPost, base+"/share/file/",
		io.MultiReader(&head, f, strings.NewReader(tail)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-API-Key", apiKey)
	req.ContentLength = int64(head.Len()) + st.Size() + int64(len(tail))

	client := &http.Client{Timeout: boxHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接文件柜: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var br struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Code       string `json:"code"`
			URL        string `json:"url"`
			PickupCode string `json:"pickup_code"`
		} `json:"data"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(body, &br); err != nil {
		return nil, fmt.Errorf("响应解析失败(HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || br.Code != 0 {
		msg := br.Message
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, errors.New(msg)
	}
	if br.Data.Code == "" {
		return nil, errors.New("响应缺分享码")
	}
	return &boxDeliverResult{ShareCode: br.Data.Code, PickupCode: br.Data.PickupCode, URL: br.Data.URL}, nil
}
