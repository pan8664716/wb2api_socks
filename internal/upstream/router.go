// router.go 出站 Transport 分发器：按请求决定「是否跳过 TLS 证书校验」。
//
// 背景：TLS 校验开关在 net/http 里是**Transport 级**的（TLSClientConfig），没有
// 每请求钩子；而「免校验」的需求往往是**局部**的——某个 socks5 代理会 MITM 掉 443，
// 只有经它的请求需要免校验，其它账号（直连或走正常代理）不应被降级。
//
// 做法：构造两条参数完全一致的 Transport（secure / insecure，仅 TLS 校验不同），
// 由本分发器按请求选择：
//   - 全局开关（config upstream.tls_skip_verify，热生效）→ 全部走 insecure；
//   - 否则看请求 context 是否被标记（账号的代理带 skip_verify 标记，见 bindProxy）
//     → 只有那些请求走 insecure。
//
// 连接池按 Transport 隔离（两条各自维护），并发安全：RoundTrip 只读 atomic + context。
package upstream

import (
	"net/http"
	"sync/atomic"
)

// tlsSkipCtxKey 请求 context 中承载「本次请求免 TLS 证书校验」的键。
type tlsSkipCtxKey struct{}

// proxyTLSRouter 双 Transport 分发器（实现 http.RoundTripper）。
type proxyTLSRouter struct {
	secure   *http.Transport
	insecure *http.Transport
	// skipAll 全局免校验开关（config upstream.tls_skip_verify，面板保存即热生效）。
	skipAll atomic.Bool
	// onResult 出站结果回调（可空）：只有「经代理的请求」才会被回调，用于代理池的
	// 「连续失败自动换代理」归因。err == nil 表示传输层成功（HTTP 状态码不算失败——
	// 4xx/5xx 是业务错误，不该记到代理头上）。
	onResult func(req *http.Request, err error)
}

func (r *proxyTLSRouter) RoundTrip(req *http.Request) (*http.Response, error) {
	var (
		resp *http.Response
		err  error
	)
	if r.skipAll.Load() || requestSkipsTLSVerify(req) {
		resp, err = r.insecure.RoundTrip(req)
	} else {
		resp, err = r.secure.RoundTrip(req)
	}
	if r.onResult != nil && proxyAddrOf(req) != "" {
		r.onResult(req, err)
	}
	return resp, err
}

// proxyAddrOf 取请求 context 里绑定的代理地址（未绑定 = 直连）。
func proxyAddrOf(req *http.Request) string {
	if req == nil {
		return ""
	}
	addr, _ := req.Context().Value(proxyCtxKey{}).(string)
	return addr
}

// CloseIdleConnections 清空两条 Transport 的空闲连接池（连接层加固的失败清池路径）。
func (r *proxyTLSRouter) CloseIdleConnections() {
	r.secure.CloseIdleConnections()
	r.insecure.CloseIdleConnections()
}

// requestSkipsTLSVerify 报告请求是否被标记为免校验。
func requestSkipsTLSVerify(req *http.Request) bool {
	if req == nil {
		return false
	}
	v, _ := req.Context().Value(tlsSkipCtxKey{}).(bool)
	return v
}
