package proxypool

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestParseLine 覆盖面板文本框里可能出现的各种写法（含真实代理商常见格式）。
func TestParseLine(t *testing.T) {
	cases := []struct {
		in       string
		wantAddr string
		wantLbl  string
		wantSkip bool
		wantErr  bool
	}{
		{"socks5://user:pass@1.2.3.4:1080", "socks5://user:pass@1.2.3.4:1080", "", false, false},
		{"socks5h://1.2.3.4:1080", "socks5://1.2.3.4:1080", "", false, false},
		{"socks://user@1.2.3.4:1080", "socks5://user@1.2.3.4:1080", "", false, false},
		{"1.2.3.4:1080", "socks5://1.2.3.4:1080", "", false, false},
		{"user:pass@1.2.3.4:1080", "socks5://user:pass@1.2.3.4:1080", "", false, false},
		{"1.2.3.4:1080:user:pass", "socks5://user:pass@1.2.3.4:1080", "", false, false},
		{"  1.2.3.4:1080 | 香港01 ", "socks5://1.2.3.4:1080", "香港01", false, false},
		{"socks5://user:pass@proxy.example.com:1080|美国-2", "socks5://user:pass@proxy.example.com:1080", "美国-2", false, false},
		{"[2001:db8::1]:1080", "socks5://[2001:db8::1]:1080", "", false, false},
		// 免 TLS 校验标记（MITM 型代理）
		{"1.2.3.4:1080|insecure", "socks5://1.2.3.4:1080", "", true, false},
		{"1.2.3.4:1080|香港01|insecure", "socks5://1.2.3.4:1080", "香港01", true, false},
		{"socks5://user:pass@1.2.3.4:1080|INSECURE", "socks5://user:pass@1.2.3.4:1080", "", true, false},
		{"1.2.3.4:1080|skip-verify|备注与标记顺序无关", "socks5://1.2.3.4:1080", "备注与标记顺序无关", true, false},
		{"1.2.3.4:1080|日本02", "socks5://1.2.3.4:1080", "日本02", false, false},
		{"http://1.2.3.4:8080", "", "", false, true}, // 非 socks5
		{"1.2.3.4", "", "", false, true},             // 缺端口
		{"1.2.3.4:99999", "", "", false, true},       // 端口越界
		{"", "", "", false, true},                    // 空行
		{"socks5://", "", "", false, true},           // 只有 scheme
	}
	for _, c := range cases {
		addr, label, skip, err := ParseLine(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseLine(%q) 期望报错，实际 addr=%q", c.in, addr)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseLine(%q) 意外报错: %v", c.in, err)
			continue
		}
		if addr != c.wantAddr || label != c.wantLbl || skip != c.wantSkip {
			t.Errorf("ParseLine(%q) = (%q, %q, skip=%v)，期望 (%q, %q, skip=%v)",
				c.in, addr, label, skip, c.wantAddr, c.wantLbl, c.wantSkip)
		}
	}
}

// TestAddDedupeAndInvalid 批量添加：去重、坏行原样回报、注释行忽略。
func TestAddDedupeAndInvalid(t *testing.T) {
	p := New("")
	res, err := p.Add([]string{
		"# 注释行",
		"",
		"socks5://u:p@1.1.1.1:1080",
		"1.1.1.1:1080",     // 与上一行规范化后不同（一个有认证）→ 两条
		"1.1.1.1:1080",     // 重复
		"1.1.1.1:1080:u:p", // 规范化后 = socks5://u:p@1.1.1.1:1080 → 重复
		"2.2.2.2:1080|东京",
		"这不是代理",
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(res.Added) != 3 {
		t.Fatalf("新增 %d 条，期望 3：%+v", len(res.Added), res.Added)
	}
	if len(res.Dupe) != 2 {
		t.Fatalf("重复 %d 条，期望 2：%+v", len(res.Dupe), res.Dupe)
	}
	if len(res.Invalid) != 1 || res.Invalid[0] != "这不是代理" {
		t.Fatalf("坏行回报不符：%+v", res.Invalid)
	}
	if p.Count() != 3 {
		t.Fatalf("池内 %d 条，期望 3", p.Count())
	}
	if got := p.Addrs()[2]; got != "socks5://2.2.2.2:1080" {
		t.Fatalf("第 3 条 = %q（应保持添加顺序）", got)
	}
}

// TestAssignUnassignProxyFor 单账号指定 / 单独清除 / 删除代理连带解绑。
func TestAssignUnassignProxyFor(t *testing.T) {
	p := New("")
	if _, err := p.Add([]string{"1.1.1.1:1080", "2.2.2.2:1080"}); err != nil {
		t.Fatal(err)
	}
	addr := p.Addrs()[0]

	if err := p.Assign("uid-a", "1.1.1.1:1080"); err != nil { // 非规范化输入也应接受
		t.Fatalf("Assign: %v", err)
	}
	if got := p.ProxyFor("uid-a"); got != addr {
		t.Fatalf("ProxyFor(uid-a) = %q，期望 %q", got, addr)
	}
	if got := p.ProxyFor("uid-b"); got != "" {
		t.Fatalf("未分配账号应直连，实际 %q", got)
	}
	if err := p.Assign("uid-a", "3.3.3.3:1080"); err == nil {
		t.Fatal("指定池外代理应报错")
	}

	if had, err := p.Unassign("uid-a"); err != nil || !had {
		t.Fatalf("Unassign = (%v, %v)，期望 (true, nil)", had, err)
	}
	if got := p.ProxyFor("uid-a"); got != "" {
		t.Fatalf("清除后应直连，实际 %q", got)
	}

	// 删除代理 → 指向它的账号一并解绑。
	if err := p.Assign("uid-c", "2.2.2.2:1080"); err != nil {
		t.Fatal(err)
	}
	ok, unbound, err := p.Remove("2.2.2.2:1080")
	if err != nil || !ok {
		t.Fatalf("Remove = (%v, %v)", ok, err)
	}
	if len(unbound) != 1 || unbound[0] != "uid-c" {
		t.Fatalf("连带解绑 = %+v，期望 [uid-c]", unbound)
	}
	if p.ProxyFor("uid-c") != "" {
		t.Fatal("代理删除后账号应回到直连")
	}
}

// TestAssignBulkModes 一键配置三种模式：按顺序 / 同一个 / 一键清除。
func TestAssignBulkModes(t *testing.T) {
	p := New("")
	if _, err := p.Add([]string{"1.1.1.1:1080", "2.2.2.2:1080"}); err != nil {
		t.Fatal(err)
	}
	uids := []string{"u1", "u2", "u3", "u4"}

	res, err := p.AssignBulk(uids, BulkOrder, "", false)
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	if len(res.Assigned) != 4 {
		t.Fatalf("order 生效 %d 个，期望 4", len(res.Assigned))
	}
	// 顺序：u1→1.1.1.1、u2→2.2.2.2、u3→1.1.1.1（代理用尽从头循环）、u4→2.2.2.2
	if p.ProxyFor("u1") != "socks5://1.1.1.1:1080" || p.ProxyFor("u2") != "socks5://2.2.2.2:1080" ||
		p.ProxyFor("u3") != "socks5://1.1.1.1:1080" || p.ProxyFor("u4") != "socks5://2.2.2.2:1080" {
		t.Fatalf("order 分配顺序不符：%+v", p.Assignment())
	}

	// 同一个 IP：全部账号 → 2.2.2.2（含已分配的 u1，覆盖）。
	if _, err := p.AssignBulk([]string{"u1", "u2"}, BulkSame, "2.2.2.2:1080", false); err != nil {
		t.Fatalf("same: %v", err)
	}
	if p.ProxyFor("u1") != "socks5://2.2.2.2:1080" {
		t.Fatal("same 未覆盖已有分配")
	}

	// onlyUnassigned：只补未分配的账号（u3/u4 已有分配 → 跳过，u1/u2 也不动）。
	res, err = p.AssignBulk(uids, BulkSame, "1.1.1.1:1080", true)
	if err != nil {
		t.Fatalf("same+only: %v", err)
	}
	if len(res.Assigned) != 0 || len(res.Skipped) != 4 {
		t.Fatalf("only_unassigned 结果不符：assigned=%d skipped=%d", len(res.Assigned), len(res.Skipped))
	}
	// 先清 u3，再补：只有 u3 被分配。
	if _, err := p.Unassign("u3"); err != nil {
		t.Fatal(err)
	}
	res, err = p.AssignBulk(uids, BulkSame, "1.1.1.1:1080", true)
	if err != nil || len(res.Assigned) != 1 {
		t.Fatalf("only_unassigned 补分配 = %d 个（err=%v），期望 1", len(res.Assigned), err)
	}
	if p.ProxyFor("u3") != "socks5://1.1.1.1:1080" {
		t.Fatal("u3 应被补分配")
	}

	// 一键清除：全部分配清空，代理列表保留。
	res, err = p.AssignBulk(uids, BulkClear, "", false)
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if res.Cleared != 4 || len(p.Assignment()) != 0 {
		t.Fatalf("clear 清除 %d 个（剩余 %d），期望 4/0", res.Cleared, len(p.Assignment()))
	}
	if p.Count() != 2 {
		t.Fatal("一键清除不应删除代理本身")
	}

	// 空池按顺序分配 → 明确报错。
	if _, err := New("").AssignBulk(uids, BulkOrder, "", false); err == nil {
		t.Fatal("空池按顺序分配应报错")
	}
	if _, err := p.AssignBulk(uids, BulkMode("nope"), "", false); err == nil {
		t.Fatal("未知模式应报错")
	}
}

// TestPersistRoundTrip 落盘 → 重新载入：代理、备注、探测结论、分配全部还原；
// 文件权限必须是 0600（含代理口令）。
func TestPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data", "proxies.json")

	p := New(path)
	if _, err := p.Add([]string{"socks5://u:p@1.1.1.1:1080|香港", "2.2.2.2:1080"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Assign("uid-a", "socks5://u:p@1.1.1.1:1080"); err != nil {
		t.Fatal(err)
	}
	if err := p.MarkCheck("2.2.2.2:1080", false, 0, "连接被拒绝"); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("落盘权限 = %o，期望 600（文件含代理口令）", perm)
	}

	q := New(path)
	if err := q.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if q.Count() != 2 || q.List()[0].Label != "香港" {
		t.Fatalf("载入后代理不符：%+v", q.List())
	}
	if got := q.ProxyFor("uid-a"); got != "socks5://u:p@1.1.1.1:1080" {
		t.Fatalf("载入后分配 = %q", got)
	}
	bad := q.List()[1]
	if bad.OK || bad.LastErr != "连接被拒绝" || bad.LastCheck.IsZero() {
		t.Fatalf("载入后探测结论不符：%+v", bad)
	}
}

// TestLoadMissingFileAndDirtyData 文件不存在 = 空池；脏数据（坏地址 / 指向不存在代理的
// 分配）被丢弃而不是整池加载失败。
func TestLoadMissingFileAndDirtyData(t *testing.T) {
	dir := t.TempDir()
	empty := New(filepath.Join(dir, "nope.json"))
	if err := empty.Load(); err != nil {
		t.Fatalf("文件不存在应视为空池，实际: %v", err)
	}

	path := filepath.Join(dir, "dirty.json")
	raw := `{"proxies":[{"addr":"1.1.1.1:1080"},{"addr":"http://bad:1"},{"addr":"1.1.1.1:1080"}],
	         "assignments":{"ok":"1.1.1.1:1080","ghost":"3.3.3.3:1080"}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	p := New(path)
	if err := p.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Count() != 1 {
		t.Fatalf("脏数据应只剩 1 条有效代理，实际 %d", p.Count())
	}
	assign := p.Assignment()
	if len(assign) != 1 || assign["ok"] != "socks5://1.1.1.1:1080" {
		t.Fatalf("分配清洗不符：%+v", assign)
	}
}

// TestPruneAssignmentsAndClear 账号移除后的收尾清理 + 清空代理池。
func TestPruneAssignmentsAndClear(t *testing.T) {
	p := New("")
	if _, err := p.Add([]string{"1.1.1.1:1080"}); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{"a", "b", "c"} {
		if err := p.Assign(uid, "1.1.1.1:1080"); err != nil {
			t.Fatal(err)
		}
	}
	n, err := p.PruneAssignments(map[string]bool{"a": true})
	if err != nil || n != 2 {
		t.Fatalf("PruneAssignments = (%d, %v)，期望 (2, nil)", n, err)
	}
	if p.ProxyFor("b") != "" || p.ProxyFor("a") == "" {
		t.Fatal("清理结果不符")
	}

	removed, err := p.Clear()
	if err != nil || removed != 1 {
		t.Fatalf("Clear = (%d, %v)，期望 (1, nil)", removed, err)
	}
	if p.Count() != 0 || len(p.Assignment()) != 0 {
		t.Fatal("清空后应无代理、无分配")
	}
}

// TestProxyForConcurrent ProxyFor 是每请求热路径：并发读写不能出现数据竞争
// （CI 用 -race 跑）且结果一致。
func TestProxyForConcurrent(t *testing.T) {
	p := New("")
	if _, err := p.Add([]string{"1.1.1.1:1080", "2.2.2.2:1080"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Assign("hot", "1.1.1.1:1080"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if got := p.ProxyFor("hot"); got != "socks5://1.1.1.1:1080" {
					t.Errorf("ProxyFor = %q", got)
					return
				}
				if i%4 == 0 {
					_, _ = p.Unassign("tmp")
					_ = p.Assign("tmp", "2.2.2.2:1080")
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestMaskProxy 日志脱敏：口令不进日志。
func TestMaskProxy(t *testing.T) {
	if got := MaskProxy("socks5://user:secret@1.2.3.4:1080"); got != "socks5://user:***@1.2.3.4:1080" {
		t.Fatalf("MaskProxy = %q", got)
	}
	if got := MaskProxy("socks5://1.2.3.4:1080"); got != "socks5://1.2.3.4:1080" {
		t.Fatalf("MaskProxy（无口令）= %q", got)
	}
}

// TestSaveConcurrent 并发落盘回归（面板一次并发探测 N 条代理时每条都 MarkCheck →
// 每条都 Save）。历史 bug：并发 Save 共用同一个 `<file>.tmp`，先完成者 rename 走后
// 后者 ENOENT（"rename ... no such file or directory"）。本测试断言全部 Save 成功，
// 且最终文件是合法 JSON、内容与内存一致。
func TestSaveConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data", "proxies.json")
	p := New(path)
	var addrs []string
	for i := 0; i < 16; i++ {
		addrs = append(addrs, fmt.Sprintf("10.0.%d.1:1080", i))
	}
	if _, err := p.Add(addrs); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for _, addr := range addrs {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				if err := p.MarkCheck(addr, true, time.Duration(j)*time.Millisecond, ""); err != nil {
					errCh <- err
					return
				}
			}
		}(addr)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("并发落盘失败: %v", err)
	}

	// 文件必须可解析，且 16 条都在（没有因竞争丢数据/写坏文件）。
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ff fileFormat
	if err := json.Unmarshal(raw, &ff); err != nil {
		t.Fatalf("落盘文件不是合法 JSON: %v", err)
	}
	if len(ff.Proxies) != 16 {
		t.Fatalf("落盘代理数 = %d，期望 16", len(ff.Proxies))
	}
	// 目录里不应残留临时文件。
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "proxies.json" {
			t.Errorf("残留临时文件: %s", e.Name())
		}
	}
}

// TestSkipVerifyFlag 免 TLS 校验标记：随行内 insecure 解析、可面板切换、随分配生效、
// 重复行只做「叠加」（不会被重复行静默取消）。
func TestSkipVerifyFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxies.json")
	p := New(path)

	res, err := p.Add([]string{"1.1.1.1:1080|日本01|insecure", "2.2.2.2:1080|香港02"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Added[0].SkipVerify || res.Added[1].SkipVerify {
		t.Fatalf("行内标记解析不符：%+v", res.Added)
	}

	if err := p.Assign("u1", "1.1.1.1:1080"); err != nil {
		t.Fatal(err)
	}
	if err := p.Assign("u2", "2.2.2.2:1080"); err != nil {
		t.Fatal(err)
	}
	if !p.SkipVerifyFor("u1") || p.SkipVerifyFor("u2") {
		t.Fatalf("SkipVerifyFor 不符：u1=%v u2=%v", p.SkipVerifyFor("u1"), p.SkipVerifyFor("u2"))
	}
	if p.SkipVerifyFor("no-such-uid") {
		t.Fatal("未分配账号应为 false")
	}

	// 面板开关：开 → 关
	if err := p.SetSkipVerify("2.2.2.2:1080", true); err != nil {
		t.Fatal(err)
	}
	if !p.SkipVerifyFor("u2") {
		t.Fatal("SetSkipVerify(true) 未生效")
	}
	if err := p.SetSkipVerify("socks5://1.1.1.1:1080", false); err != nil {
		t.Fatal(err)
	}
	if p.SkipVerifyFor("u1") {
		t.Fatal("SetSkipVerify(false) 未生效")
	}
	if err := p.SetSkipVerify("9.9.9.9:1080", true); err == nil {
		t.Fatal("池外代理应报错")
	}

	// 重复行叠加：已存在（无标记）时补上 insecure，不会被静默取消
	if _, err := p.Add([]string{"2.2.2.2:1080|insecure"}); err != nil {
		t.Fatal(err)
	}
	if !p.SkipVerifyFor("u2") {
		t.Fatal("重复行应保持标记")
	}
	// 反向：已有标记时用无标记的重复行添加，不应把标记清掉
	if err := p.SetSkipVerify("2.2.2.2:1080", true); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Add([]string{"2.2.2.2:1080"}); err != nil {
		t.Fatal(err)
	}
	if !p.SkipVerifyFor("u2") {
		t.Fatal("重复行不应清除已有标记")
	}

	// 落盘 → 重载：标记必须持久化
	q := New(path)
	if err := q.Load(); err != nil {
		t.Fatal(err)
	}
	if !q.SkipVerifyFor("u2") || q.SkipVerifyFor("u1") {
		t.Fatalf("重载后标记不符：u1=%v u2=%v", q.SkipVerifyFor("u1"), q.SkipVerifyFor("u2"))
	}
}

// TestMaskProxyWithFlag 备注/标记不参与地址规范化（去重键仍只有地址）。
func TestMaskProxyWithFlag(t *testing.T) {
	addr, label, skip, err := ParseLine("socks5://u:p@1.2.3.4:1080|东京|insecure")
	if err != nil || label != "东京" || !skip {
		t.Fatalf("ParseLine = (%q, %q, %v, %v)", addr, label, skip, err)
	}
	if addr != "socks5://u:p@1.2.3.4:1080" {
		t.Fatalf("地址应不含备注/标记：%q", addr)
	}
}
