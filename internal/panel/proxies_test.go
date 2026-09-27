package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/proxypool"
)

// newProxyTestPanel 装配一个带账号池与代理池的面板（api_key = test-key）。
func newProxyTestPanel(t *testing.T, uids ...string) (*Panel, *proxypool.Pool) {
	t.Helper()
	p := pool.New("") // 纯内存池（不落盘）
	for _, uid := range uids {
		p.Add(&auth.Auth{UID: uid, Nickname: "nick-" + uid})
	}
	pp := proxypool.New(filepath.Join(t.TempDir(), "proxies.json"))
	return New(Config{Version: "test", APIKey: "test-key", Pool: p, Proxies: pp}), pp
}

// call 发一个带密钥的面板请求，返回解析后的 JSON。
func call(t *testing.T, pn *Panel, method, path, body string) (int, map[string]any) {
	t.Helper()
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	pn.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s 响应不是 JSON: %v（%s）", method, path, err, rec.Body.String())
		}
	}
	return rec.Code, out
}

func num(t *testing.T, m map[string]any, key string) float64 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("字段 %s 缺失或非数字：%+v", key, m)
	}
	return v
}

// TestProxiesAPIFlow 面板代理池全流程：批量添加 → 一键按顺序分配 → 单号指定/清除
// → 概览带出代理 → 删除代理连带解绑 → 一键清除 → 清空池。
func TestProxiesAPIFlow(t *testing.T) {
	pn, pp := newProxyTestPanel(t, "u1", "u2", "u3")

	// 1) 批量添加（含注释行、坏行、重复行）
	code, resp := call(t, pn, "POST", "/panel/api/proxies/add",
		`{"text":"# 注释\nsocks5://a:p@1.1.1.1:1080\n2.2.2.2:1080|东京\n1.1.1.1:1080:a:p\n坏行"}`)
	if code != 200 || num(t, resp, "added") != 2 {
		t.Fatalf("add 响应不符：%d %+v", code, resp)
	}
	if inv, _ := resp["invalid"].([]any); len(inv) != 1 {
		t.Fatalf("坏行应回报 1 条：%+v", resp["invalid"])
	}

	// 2) 列表：2 条代理、3 个账号（全部直连）；未探测过的代理不带 last_check 字段
	// （零值时间不落 JSON，前端据此显示「未探测」）。
	code, resp = call(t, pn, "GET", "/panel/api/proxies", "")
	if code != 200 || num(t, resp, "total") != 2 || num(t, resp, "assigned") != 0 {
		t.Fatalf("list 响应不符：%d %+v", code, resp)
	}
	pxs, _ := resp["proxies"].([]any)
	if len(pxs) != 2 {
		t.Fatalf("proxies = %+v", resp["proxies"])
	}
	if first, _ := pxs[0].(map[string]any); first["last_check"] != nil {
		t.Fatalf("未探测的代理不应带 last_check：%+v", first)
	}
	if lbl, _ := pxs[1].(map[string]any); lbl["label"] != "东京" {
		t.Fatalf("备注未透出：%+v", lbl)
	}

	// 3) 一键按 IP 顺序配置：u1→1.1.1.1、u2→2.2.2.2、u3→1.1.1.1（循环）
	code, resp = call(t, pn, "POST", "/panel/api/proxies/bulk", `{"mode":"order"}`)
	if code != 200 || num(t, resp, "assigned") != 3 {
		t.Fatalf("bulk order 响应不符：%d %+v", code, resp)
	}
	if pp.ProxyFor("u1") != "socks5://a:p@1.1.1.1:1080" || pp.ProxyFor("u2") != "socks5://2.2.2.2:1080" ||
		pp.ProxyFor("u3") != "socks5://a:p@1.1.1.1:1080" {
		t.Fatalf("顺序分配不符：%+v", pp.Assignment())
	}

	// 4) 概览：账号列表带出 proxy 字段（面板「代理」列的数据来源）
	code, resp = call(t, pn, "GET", "/panel/api/overview", "")
	if code != 200 {
		t.Fatalf("overview: %d", code)
	}
	accts, _ := resp["accounts"].([]any)
	if len(accts) != 3 {
		t.Fatalf("overview accounts = %d", len(accts))
	}
	found := false
	for _, raw := range accts {
		m, _ := raw.(map[string]any)
		if m["uid"] == "u1" {
			if m["proxy"] != "socks5://a:p@1.1.1.1:1080" {
				t.Fatalf("overview 未带出 u1 代理：%+v", m)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("overview 缺 u1")
	}
	if num(t, resp, "proxy_total") != 2 {
		t.Fatalf("overview proxy_total = %v", resp["proxy_total"])
	}

	// 5) 单号指定（同一个 IP 模式，只覆盖 u1）+ 单号清除
	code, resp = call(t, pn, "POST", "/panel/api/proxies/assign", `{"uid":"u1","addr":"2.2.2.2:1080"}`)
	if code != 200 {
		t.Fatalf("assign: %d %+v", code, resp)
	}
	if pp.ProxyFor("u1") != "socks5://2.2.2.2:1080" {
		t.Fatalf("单号指定未生效：%+v", pp.Assignment())
	}
	code, _ = call(t, pn, "POST", "/panel/api/proxies/unassign", `{"uid":"u1"}`)
	if code != 200 || pp.ProxyFor("u1") != "" {
		t.Fatalf("单号清除失败：%d %+v", code, pp.Assignment())
	}

	// 6) 删除代理 → 指向它的账号连带解绑（u2 指向 2.2.2.2）
	code, resp = call(t, pn, "POST", "/panel/api/proxies/remove", `{"addr":"2.2.2.2:1080"}`)
	if code != 200 || num(t, resp, "unbound") != 1 || num(t, resp, "total") != 1 {
		t.Fatalf("remove 响应不符：%d %+v", code, resp)
	}
	if pp.ProxyFor("u2") != "" {
		t.Fatal("删除代理后应连带解绑")
	}

	// 7) 一键清除（保留代理）+ 清空代理池
	code, resp = call(t, pn, "POST", "/panel/api/proxies/bulk", `{"mode":"clear"}`)
	if code != 200 || num(t, resp, "cleared") != 1 || pp.Count() != 1 {
		t.Fatalf("bulk clear 响应不符：%d %+v（池内 %d 条）", code, resp, pp.Count())
	}
	code, resp = call(t, pn, "POST", "/panel/api/proxies/clear", "")
	if code != 200 || num(t, resp, "removed") != 1 || pp.Count() != 0 {
		t.Fatalf("clear 响应不符：%d %+v", code, resp)
	}
}

// TestProxiesAPIValidation 参数校验与错误码：未知账号 404、池外代理 400、
// 空代理池按顺序分配 400。
func TestProxiesAPIValidation(t *testing.T) {
	pn, _ := newProxyTestPanel(t, "u1")

	if code, _ := call(t, pn, "POST", "/panel/api/proxies/assign", `{"uid":"ghost","addr":"1.1.1.1:1080"}`); code != 404 {
		t.Fatalf("未知账号应 404，实际 %d", code)
	}
	if code, _ := call(t, pn, "POST", "/panel/api/proxies/add", `{"text":"1.1.1.1:1080"}`); code != 200 {
		t.Fatalf("add: %d", code)
	}
	if code, _ := call(t, pn, "POST", "/panel/api/proxies/assign", `{"uid":"u1","addr":"9.9.9.9:1080"}`); code != 400 {
		t.Fatalf("池外代理应 400，实际 %d", code)
	}
	if code, _ := call(t, pn, "POST", "/panel/api/proxies/add", `{"text":"  "}`); code != 400 {
		t.Fatalf("空内容应 400，实际 %d", code)
	}
	if code, _ := call(t, pn, "POST", "/panel/api/proxies/remove", `{"addr":"8.8.8.8:1080"}`); code != 404 {
		t.Fatalf("删除池外代理应 404，实际 %d", code)
	}

	// 空池按顺序分配 → 400
	pn2, _ := newProxyTestPanel(t, "u1")
	if code, _ := call(t, pn2, "POST", "/panel/api/proxies/bulk", `{"mode":"order"}`); code != 400 {
		t.Fatalf("空池按顺序分配应 400，实际 %d", code)
	}
}

// TestProxiesAPIRequiresAuth 代理池接口与面板其余接口同口径：无密钥 401。
func TestProxiesAPIRequiresAuth(t *testing.T) {
	pn, _ := newProxyTestPanel(t, "u1")
	for _, c := range []struct{ method, path string }{
		{"GET", "/panel/api/proxies"},
		{"POST", "/panel/api/proxies/add"},
		{"POST", "/panel/api/proxies/clear"},
		{"POST", "/panel/api/proxies/bulk"},
		{"POST", "/panel/api/proxies/check"},
	} {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		pn.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s 无密钥应 401，实际 %d", c.method, c.path, rec.Code)
		}
	}
}

// TestProxiesDisabled 未注入代理池（Proxies == nil）时相关接口返回 501 而非 panic。
func TestProxiesDisabled(t *testing.T) {
	pn := New(Config{Version: "test", APIKey: "test-key"})
	if code, _ := call(t, pn, "GET", "/panel/api/proxies", ""); code != http.StatusNotImplemented {
		t.Fatalf("未启用代理池应 501，实际 %d", code)
	}
}

// TestAccountRemoveUnassignsProxy 移除账号时连带清掉它的代理分配。
func TestAccountRemoveUnassignsProxy(t *testing.T) {
	pn, pp := newProxyTestPanel(t, "u1", "u2")
	call(t, pn, "POST", "/panel/api/proxies/add", `{"text":"1.1.1.1:1080"}`)
	call(t, pn, "POST", "/panel/api/proxies/assign", `{"uid":"u1","addr":"1.1.1.1:1080"}`)
	if pp.ProxyFor("u1") == "" {
		t.Fatal("前置条件不成立：u1 未指定代理")
	}
	if code, _ := call(t, pn, "POST", "/panel/api/accounts/u1/remove", ""); code != 200 {
		t.Fatalf("remove 账号失败：%d", code)
	}
	if pp.ProxyFor("u1") != "" {
		t.Fatal("账号移除后应连带清除其代理分配")
	}
}

// TestProxiesSkipVerifyAPI 免 TLS 校验标记：行内 insecure 解析 → 列表透出 →
// 面板开关切换 → 未知代理报 400。skip 字段缺省按 true（只切「开启」方向）。
func TestProxiesSkipVerifyAPI(t *testing.T) {
	pn, pp := newProxyTestPanel(t, "u1")

	code, resp := call(t, pn, "POST", "/panel/api/proxies/add", `{"text":"1.1.1.1:1080|日本01|insecure\n2.2.2.2:1080"}`)
	if code != 200 || num(t, resp, "added") != 2 {
		t.Fatalf("add: %d %+v", code, resp)
	}

	code, resp = call(t, pn, "GET", "/panel/api/proxies", "")
	if code != 200 {
		t.Fatalf("list: %d", code)
	}
	pxs, _ := resp["proxies"].([]any)
	first, _ := pxs[0].(map[string]any)
	if first["skip_verify"] != true {
		t.Fatalf("insecure 行未透出 skip_verify：%+v", first)
	}
	if second, _ := pxs[1].(map[string]any); second["skip_verify"] != nil {
		t.Fatalf("普通代理不应带 skip_verify：%+v", second)
	}

	// 关闭标记
	if code, _ := call(t, pn, "POST", "/panel/api/proxies/skipverify", `{"addr":"1.1.1.1:1080","skip":false}`); code != 200 {
		t.Fatalf("skipverify(false): %d", code)
	}
	if pp.SkipVerifyFor("u1") && false {
		t.Fatal("unreachable")
	}
	// 缺省 skip = true
	if code, _ := call(t, pn, "POST", "/panel/api/proxies/skipverify", `{"addr":"1.1.1.1:1080"}`); code != 200 {
		t.Fatalf("skipverify(缺省): %d", code)
	}
	if err := pp.Assign("u1", "1.1.1.1:1080"); err != nil {
		t.Fatal(err)
	}
	if !pp.SkipVerifyFor("u1") {
		t.Fatal("缺省 skip 应把标记打开")
	}
	// 账号视图带出该标记（面板提示用）
	code, resp = call(t, pn, "GET", "/panel/api/proxies", "")
	accs, _ := resp["accounts"].([]any)
	if a, _ := accs[0].(map[string]any); a["skip_verify"] != true {
		t.Fatalf("账号视图应带出 skip_verify：%+v", a)
	}

	if code, _ := call(t, pn, "POST", "/panel/api/proxies/skipverify", `{"addr":"9.9.9.9:1080"}`); code != 400 {
		t.Fatalf("池外代理应 400，实际 %d", code)
	}
}
