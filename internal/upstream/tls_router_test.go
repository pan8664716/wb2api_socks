package upstream

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// tlsGet 经 client 发一个 GET（带上账号头，走 CommonHeaders → bindProxy 的完整链路）。
// 返回错误文案与状态码。
func tlsGet(c *Client, uid, url string) (string, int) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err.Error(), 0
	}
	c.CommonHeaders(req, &auth.Auth{UID: uid})
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err.Error(), 0
	}
	defer resp.Body.Close()
	return "", resp.StatusCode
}

// TestTLSSkipVerifyGlobal 全局开关（config upstream.tls_skip_verify）：
// 默认严格校验 → 自签证书失败；打开 → 通过；关回去 → 再次失败（热生效可反复切）。
func TestTLSSkipVerifyGlobal(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c := New()
	if c.TLSSkipVerify() {
		t.Fatal("默认应为严格校验")
	}

	if msg, _ := tlsGet(c, "u1", srv.URL); !strings.Contains(msg, "certificate") {
		t.Fatalf("默认应因证书不可信失败，实际: %q", msg)
	}

	c.SetTLSSkipVerify(true)
	if !c.TLSSkipVerify() {
		t.Fatal("SetTLSSkipVerify(true) 未生效")
	}
	if msg, code := tlsGet(c, "u1", srv.URL); msg != "" || code != 200 {
		t.Fatalf("全局免校验后应成功，实际 msg=%q code=%d", msg, code)
	}

	c.SetTLSSkipVerify(false)
	if msg, _ := tlsGet(c, "u1", srv.URL); !strings.Contains(msg, "certificate") {
		t.Fatalf("关回严格校验后应再次失败，实际: %q", msg)
	}
}

// TestTLSSkipVerifyPerProxy 每代理标记（代理池 skip_verify）：只让经该代理的请求免校验，
// 同进程内其它账号（直连 / 其它代理）不受影响。
func TestTLSSkipVerifyPerProxy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	proxy := startTestSocks5(t)

	c := New()
	skip := false
	c.ProxyFor = func(uid string) string {
		if uid == "proxied" {
			return proxy.addr()
		}
		return "" // direct
	}
	c.ProxySkipVerifyFor = func(uid string) bool { return uid == "proxied" && skip }

	// 标记关：经代理 → 证书不可信（证明请求确实经代理且仍严格校验）
	if msg, _ := tlsGet(c, "proxied", srv.URL); !strings.Contains(msg, "certificate") {
		t.Fatalf("未标记时应因证书失败，实际: %q", msg)
	}
	if proxy.conns.Load() == 0 {
		t.Fatal("请求未经过代理")
	}

	// 直连账号：同样失败（不受影响）
	if msg, _ := tlsGet(c, "direct", srv.URL); !strings.Contains(msg, "certificate") {
		t.Fatalf("直连账号应因证书失败，实际: %q", msg)
	}

	// 打开该代理的免校验 → 经代理成功
	skip = true
	if msg, code := tlsGet(c, "proxied", srv.URL); msg != "" || code != 200 {
		t.Fatalf("标记后经代理应成功，实际 msg=%q code=%d", msg, code)
	}
	// 直连账号仍严格校验（粒度正确：没有全局放行）
	if msg, _ := tlsGet(c, "direct", srv.URL); !strings.Contains(msg, "certificate") {
		t.Fatalf("直连账号不应被放行，实际: %q", msg)
	}
}

// TestSetHeaderTimeoutCoversBothTransports 装配期设置响应头超时必须同时落到两条
// Transport（secure/insecure），否则免校验链路会丢掉首字节超时保护。
func TestSetHeaderTimeoutCoversBothTransports(t *testing.T) {
	c := New()
	if c.transport == nil {
		t.Fatal("New() 应注入 Transport 分发器")
	}
	d := 42 * time.Second
	c.SetHeaderTimeout(d)
	if c.transport.secure.ResponseHeaderTimeout != d || c.transport.insecure.ResponseHeaderTimeout != d {
		t.Fatalf("ResponseHeaderTimeout 未同步：secure=%v insecure=%v",
			c.transport.secure.ResponseHeaderTimeout, c.transport.insecure.ResponseHeaderTimeout)
	}
	// 两条 Transport 的其余参数必须一致（只有 TLS 校验不同）。
	s, i := c.transport.secure, c.transport.insecure
	if s.MaxIdleConns != i.MaxIdleConns || s.MaxIdleConnsPerHost != i.MaxIdleConnsPerHost ||
		s.IdleConnTimeout != i.IdleConnTimeout || s.TLSHandshakeTimeout != i.TLSHandshakeTimeout {
		t.Fatal("两条 Transport 的连接层参数应一致")
	}
	if s.TLSClientConfig != nil && s.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("secure Transport 不得关闭证书校验")
	}
	if i.TLSClientConfig == nil || !i.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("insecure Transport 应关闭证书校验")
	}
	// 分发器必须实现 closeIdler（失败清池路径依赖它）。
	var _ closeIdler = c.transport
}
