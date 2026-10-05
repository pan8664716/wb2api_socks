package upstream

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// TestChatStreamKeepsProxyBinding 回归：chat 主链路必须把代理标记带到传输层。
//
// 曾经的真实 bug：ChatStreamContext 先 ChatHeaders（内含 bindProxy，把代理写进
// req.Context()），随后又 `req.WithContext(context.WithCancel(调用方 ctx))` ——
// 这一步把代理标记整个覆盖掉，结果「指定了死代理的账号聊天照样成功直连」（实测
// 复现：指定 socks5://127.0.0.1:1 后 /v1/chat/completions 仍 200）。
func TestChatStreamKeepsProxyBinding(t *testing.T) {
	c := New()
	c.ProxyFor = func(uid string) string {
		if uid == "u1" {
			return "socks5://1.2.3.4:1080"
		}
		return ""
	}
	var seen atomic.Value // string（传输层看到的代理 URL）
	// chat 路径走 chatHTTP()：New() 已把 ChatHTTP 设成真实 client，必须覆盖它才拦得住。
	c.ChatHTTP = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		u, _ := c.proxyForRequest(r)
		if u != nil {
			seen.Store(u.String())
		}
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n")),
		}, nil
	})}

	rc, status, _, err := c.ChatStreamContext(context.Background(),
		&auth.Auth{UID: "u1", AccessToken: "t"},
		[]byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`), "", ChatMeta{})
	if err != nil || status != 200 {
		t.Fatalf("chat 请求失败: status=%d err=%v", status, err)
	}
	rc.Close()
	got, _ := seen.Load().(string)
	if got != "socks5://1.2.3.4:1080" {
		t.Fatalf("chat 请求的 context 丢了代理标记，传输层看到 %v", seen.Load())
	}
}

// TestProxyResultHook 出站结果回调（代理池「连续失败自动换代理」的归因入口）：
//   - 经代理的传输层失败 → OnProxyFailure(uid, addr, err)；
//   - 经代理的传输层成功（含 HTTP 5xx）→ OnProxySuccess(uid)；
//   - 直连请求（无代理）→ 两个回调都不触发。
func TestProxyResultHook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // 业务失败 ≠ 传输层失败
	}))
	defer srv.Close()
	proxy := startTestSocks5(t)

	c := New()
	c.ProxyFor = func(uid string) string {
		switch uid {
		case "uid-ok", "uid-5xx":
			return proxy.addr()
		case "uid-bad":
			return "socks5://127.0.0.1:1" // 必然连不上
		}
		return ""
	}

	var mu sync.Mutex
	type event struct {
		kind, uid, addr string
	}
	var events []event
	c.OnProxyFailure = func(uid, addr string, err error) {
		if err == nil {
			t.Error("OnProxyFailure 不应收到 nil 错误")
		}
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event{"fail", uid, addr})
	}
	c.OnProxySuccess = func(uid string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event{"ok", uid, ""})
	}

	get := func(uid string) error {
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		c.CommonHeaders(req, &auth.Auth{UID: uid})
		resp, err := c.HTTP.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}

	if err := get("uid-ok"); err != nil {
		t.Fatalf("经代理请求失败: %v", err)
	}
	if err := get("uid-5xx"); err != nil {
		t.Fatalf("HTTP 500 在传输层仍是成功: %v", err)
	}
	if err := get("uid-bad"); err == nil {
		t.Fatal("坏代理请求应失败")
	}
	if err := get("uid-direct"); err != nil {
		t.Fatalf("直连请求失败: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []event{
		{"ok", "uid-ok", ""},
		{"ok", "uid-5xx", ""},
		{"fail", "uid-bad", "socks5://127.0.0.1:1"},
	}
	if len(events) != len(want) {
		t.Fatalf("回调事件 = %+v，期望 %+v", events, want)
	}
	for i, w := range want {
		if events[i] != w {
			t.Fatalf("事件[%d] = %+v，期望 %+v", i, events[i], w)
		}
	}
}

// TestProxyResultHookNilSafe 未接线（OnProxyFailure/OnProxySuccess == nil）时行为不变。
func TestProxyResultHookNilSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := New()
	c.ProxyFor = func(string) string { return "socks5://127.0.0.1:1" }
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.CommonHeaders(req, &auth.Auth{UID: "u"})
	if resp, err := c.HTTP.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("坏代理应失败")
	}
}
