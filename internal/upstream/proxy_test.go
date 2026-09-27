package upstream

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// testSocks5 最小 SOCKS5 服务端（仅测试用）：记录收到的 CONNECT 目标，按需转发。
type testSocks5 struct {
	ln     net.Listener
	conns  atomic.Int64
	target atomic.Value // 最近一次 CONNECT 目标
}

func startTestSocks5(t *testing.T) *testSocks5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSocks5{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *testSocks5) addr() string { return "socks5://" + s.ln.Addr().String() }

func (s *testSocks5) handle(c net.Conn) {
	defer c.Close()
	s.conns.Add(1)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, head[1])); err != nil {
		return
	}
	c.Write([]byte{0x05, 0x00}) //nolint:errcheck // 无认证
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		io.ReadFull(c, b) //nolint:errcheck
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(c, l) //nolint:errcheck
		b := make([]byte, l[0])
		io.ReadFull(c, b) //nolint:errcheck
		host = string(b)
	default:
		return
	}
	pb := make([]byte, 2)
	io.ReadFull(c, pb) //nolint:errcheck
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))))
	s.target.Store(target)

	up, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }() //nolint:errcheck
	go func() { io.Copy(c, up); done <- struct{}{} }() //nolint:errcheck
	<-done
}

// TestClientRoutesThroughAssignedProxy 指定了代理的账号，其出站请求确实经该代理
// （而非直连）：这是「账号池里为每个账号单独指定代理」的端到端判据。
func TestClientRoutesThroughAssignedProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}))
	defer srv.Close()
	proxy := startTestSocks5(t)

	c := New()
	c.ProxyFor = func(uid string) string {
		if uid == "uid-proxied" {
			return proxy.addr()
		}
		return "" // 未指定 → 直连
	}

	// 1) 指定了代理的账号：请求必须经代理（代理侧能看到 CONNECT 目标）。
	a := &auth.Auth{UID: "uid-proxied"}
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.CommonHeaders(req, a)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatalf("经代理请求失败: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("状态码 = %d", resp.StatusCode)
	}
	got := proxy.target.Load()
	if got == nil {
		t.Fatal("代理未收到 CONNECT（请求没走代理）")
	}
	if got.(string) != srv.Listener.Addr().String() {
		t.Fatalf("CONNECT 目标 = %v，期望 %v", got, srv.Listener.Addr())
	}
	if n := proxy.conns.Load(); n != 1 {
		t.Fatalf("代理连接数 = %d，期望 1", n)
	}

	// 2) 未指定代理的账号：直连，代理连接数不变。
	b := &auth.Auth{UID: "uid-direct"}
	req2, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.CommonHeaders(req2, b)
	resp2, err := c.HTTP.Do(req2)
	if err != nil {
		t.Fatalf("直连请求失败: %v", err)
	}
	resp2.Body.Close()
	if n := proxy.conns.Load(); n != 1 {
		t.Fatalf("未指定代理的账号不应走代理，代理连接数 = %d", n)
	}
}

// TestClientProxyUnavailableFails 代理不可用时报错，**不静默回落直连**——
// 静默直连会掩盖配置错误（运维以为在走代理，实际暴露了本机 IP）。
func TestClientProxyUnavailableFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c := New()
	c.ProxyFor = func(string) string { return "socks5://127.0.0.1:1" } // 必然连不上

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.CommonHeaders(req, &auth.Auth{UID: "uid-x"})
	resp, err := c.HTTP.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("代理不可用时请求应失败")
	}
}

// TestProxyBindingCoversAllOutboundPaths 覆盖各出站路径的绑定点：CommonHeaders
// （chat / refresh / 模型探测）、BillingHeaders（余额 / 签到 / 上报）与自建头路径
// （desktop 事件上报 / 学校活动）。判据 = 请求 context 里带上代理地址。
func TestProxyBindingCoversAllOutboundPaths(t *testing.T) {
	c := New()
	c.ProxyFor = func(uid string) string {
		if uid == "uid-p" {
			return "socks5://1.2.3.4:1080"
		}
		return ""
	}
	a := &auth.Auth{UID: "uid-p", AccessToken: "t"}
	bound := func(req *http.Request) bool {
		u, err := c.proxyForRequest(req)
		return err == nil && u != nil && u.Host == "1.2.3.4:1080"
	}

	newReq := func() *http.Request {
		req, err := http.NewRequest(http.MethodPost, "https://copilot.tencent.com/v2/chat/completions", nil)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	r1 := newReq()
	c.CommonHeaders(r1, a)
	if !bound(r1) {
		t.Error("CommonHeaders 未绑定代理")
	}
	r2 := newReq()
	c.BillingHeaders(r2, a)
	if !bound(r2) {
		t.Error("BillingHeaders 未绑定代理")
	}
	r3 := newReq()
	c.RefreshHeaders(r3, a)
	if !bound(r3) {
		t.Error("RefreshHeaders 未绑定代理")
	}
	r4 := newReq()
	c.ChatHeaders(r4, a, "", ChatMeta{ConversationRequestID: "x"})
	if !bound(r4) {
		t.Error("ChatHeaders 未绑定代理")
	}

	// 未指定代理的账号：不绑定（直连）。
	r5 := newReq()
	c.CommonHeaders(r5, &auth.Auth{UID: "uid-other"})
	if u, _ := c.proxyForRequest(r5); u != nil {
		t.Errorf("未指定代理的账号不应绑定，实际 %v", u)
	}
}

// TestProxyForNil 未接线的 Client（ProxyFor == nil，测试/嵌入式装配）行为不变：
// 不绑定、直连，且不 panic。
func TestProxyForNil(t *testing.T) {
	c := New()
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.CommonHeaders(req, &auth.Auth{UID: "u"})
	if u, _ := c.proxyForRequest(req); u != nil {
		t.Fatalf("ProxyFor 未接线时不应有代理，实际 %v", u)
	}
}

// TestProxyBindingSelfBuiltHeaderPaths 自建请求头的出站路径同样绑定代理：
// v3/config 模型探测、Web 域领奖、global 注册链路、桌面端事件上报与主题设置。
// 判据 = 捕获到的每个请求 context 里都带上了该账号的代理地址。
func TestProxyBindingSelfBuiltHeaderPaths(t *testing.T) {
	var mu sync.Mutex
	var bound []string
	c := New()
	c.ProxyFor = func(string) string { return "socks5://1.2.3.4:1080" }
	c.HTTP = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		u, err := c.proxyForRequest(r)
		mu.Lock()
		defer mu.Unlock()
		if err != nil || u == nil {
			bound = append(bound, "none")
		} else {
			bound = append(bound, u.Host)
		}
		return jsonResp(200, `{"code":0,"data":{}}`), nil
	})}

	// global 域账号（domain 后缀 → Realm()=="global"），覆盖注册链路。
	a := &auth.Auth{UID: "uid-p", AccessToken: "tok", Domain: "www.workbuddy.ai"}

	// 各路径只关心「请求有没有绑定代理」，返回值与错误忽略。
	_, _ = c.fetchV3ConfigModelMap(a, "ua")
	_, _, _ = c.ClaimReward(a, "task_x")
	_, _, _, _ = c.GlobalRegisterStatus(a)
	_ = c.ReportDesktopEvent(a, DesktopEvent{"eventCode": "x"})
	_ = c.SetAppearanceTheme(a, "theme-tkmw7j")
	_, _ = c.MarketExpertList(a, "agent")

	mu.Lock()
	defer mu.Unlock()
	if len(bound) < 6 {
		t.Fatalf("捕获请求数 = %d（%v），期望 ≥6", len(bound), bound)
	}
	for i, h := range bound {
		if h != "1.2.3.4:1080" {
			t.Errorf("第 %d 个请求未绑定代理：%v（全部=%v）", i, h, bound)
		}
	}
}
