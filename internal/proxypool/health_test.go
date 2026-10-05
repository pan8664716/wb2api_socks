package proxypool

import (
	"path/filepath"
	"testing"
)

// TestRecordProxyFailureAutoSwitch 连续失败达阈值自动换代理：优先「没用过的」，
// 原代理记为失效；池里没有替代时解绑回直连。
func TestRecordProxyFailureAutoSwitch(t *testing.T) {
	p := New("")
	if _, err := p.Add([]string{"1.1.1.1:1080", "2.2.2.2:1080", "3.3.3.3:1080"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Assign("u1", "1.1.1.1:1080"); err != nil {
		t.Fatal(err)
	}

	// 阈值内（前两次）不切换。
	for i := 1; i <= DefaultFailThreshold-1; i++ {
		res, err := p.RecordProxyFailure("u1", "socks5://1.1.1.1:1080", "dial timeout")
		if err != nil {
			t.Fatal(err)
		}
		if res.Switched || res.Marked || res.Exhausted {
			t.Fatalf("第 %d 次失败不应触发切换：%+v", i, res)
		}
		if res.Count != i {
			t.Fatalf("第 %d 次失败后计数 = %d", i, res.Count)
		}
		if got := p.ProxyFor("u1"); got != "socks5://1.1.1.1:1080" {
			t.Fatalf("未达阈值不应换代理，实际 %q", got)
		}
	}

	// 第 3 次：切换到没用过的 2.2.2.2，原代理失效。
	res, err := p.RecordProxyFailure("u1", "1.1.1.1:1080", "dial timeout: connection refused")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Switched || !res.Marked {
		t.Fatalf("达阈值应切换并标记失效：%+v", res)
	}
	if res.To != "socks5://2.2.2.2:1080" {
		t.Fatalf("应换到没用过的 2.2.2.2，实际 %q", res.To)
	}
	if got := p.ProxyFor("u1"); got != "socks5://2.2.2.2:1080" {
		t.Fatalf("分配未更新：%q", got)
	}
	first := p.List()[0]
	if !first.Dead || first.DeadAt.IsZero() || first.DeadReason == "" {
		t.Fatalf("原代理应带失效记录：%+v", first)
	}
	if first.FailCount != DefaultFailThreshold {
		t.Fatalf("原代理累计失败 = %d", first.FailCount)
	}
	if fs := p.FailureStateOf("u1"); fs.Count != 0 || fs.Addr != "socks5://2.2.2.2:1080" || fs.Swaps != 1 {
		t.Fatalf("切换后状态应归零并指向新代理：%+v", fs)
	}

	// 第二条代理同样连续失败 → 换到第三条。
	for i := 0; i < DefaultFailThreshold; i++ {
		res, err = p.RecordProxyFailure("u1", "2.2.2.2:1080", "i/o timeout")
		if err != nil {
			t.Fatal(err)
		}
	}
	if !res.Switched || res.To != "socks5://3.3.3.3:1080" {
		t.Fatalf("应换到第三条：%+v", res)
	}

	// 第三条也连续失败 → 无可用替代 → 解绑回直连。
	for i := 0; i < DefaultFailThreshold; i++ {
		res, err = p.RecordProxyFailure("u1", "3.3.3.3:1080", "i/o timeout")
		if err != nil {
			t.Fatal(err)
		}
	}
	if !res.Exhausted || res.Switched {
		t.Fatalf("无可用替代应解绑：%+v", res)
	}
	if p.ProxyFor("u1") != "" {
		t.Fatal("解绑后应直连")
	}
	if dead := p.DeadCount(); dead != 3 {
		t.Fatalf("三条代理都应记为失效，实际 %d", dead)
	}
	if used := p.UsedAddrs("u1"); len(used) != 3 {
		t.Fatalf("用过清单应含三条：%v", used)
	}
}

// TestRecordProxySuccessResetsCounter 传输层成功清零连续失败计数；无变化时不落盘。
func TestRecordProxySuccessResetsCounter(t *testing.T) {
	p := New("")
	if _, err := p.Add([]string{"1.1.1.1:1080", "2.2.2.2:1080"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Assign("u1", "1.1.1.1:1080"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := p.RecordProxyFailure("u1", "1.1.1.1:1080", "timeout"); err != nil {
			t.Fatal(err)
		}
	}
	if fs := p.FailureStateOf("u1"); fs.Count != 2 {
		t.Fatalf("前置计数 = %d", fs.Count)
	}
	if err := p.RecordProxySuccess("u1"); err != nil {
		t.Fatal(err)
	}
	if fs := p.FailureStateOf("u1"); fs.Count != 0 || fs.LastErr != "" {
		t.Fatalf("成功应清零：%+v", fs)
	}
	// 再次失败从 1 重新计（不切换）。
	res, err := p.RecordProxyFailure("u1", "1.1.1.1:1080", "timeout")
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 1 || res.Switched {
		t.Fatalf("清零后应重新从 1 计数：%+v", res)
	}
}

// TestFailThresholdConfigurable 阈值可配置：设为 2 时第 2 次失败即切换。
func TestFailThresholdConfigurable(t *testing.T) {
	p := New("")
	if _, err := p.Add([]string{"1.1.1.1:1080", "2.2.2.2:1080"}); err != nil {
		t.Fatal(err)
	}
	if err := p.SetFailThreshold(2); err != nil {
		t.Fatal(err)
	}
	if err := p.Assign("u1", "1.1.1.1:1080"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RecordProxyFailure("u1", "1.1.1.1:1080", "x"); err != nil {
		t.Fatal(err)
	}
	res, err := p.RecordProxyFailure("u1", "1.1.1.1:1080", "x")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Switched || res.To != "socks5://2.2.2.2:1080" {
		t.Fatalf("阈值 2 时第 2 次失败应切换：%+v", res)
	}
	if err := p.SetFailThreshold(0); err == nil {
		t.Fatal("越界阈值应报错")
	}
	if p.FailThreshold() != 2 {
		t.Fatal("越界设置不应生效")
	}
}

// TestPurgeDead 一键清除过期代理：默认口径 = 失效 + 探测不通；只清失效时不误伤。
func TestPurgeDead(t *testing.T) {
	p := New("")
	if _, err := p.Add([]string{"1.1.1.1:1080", "2.2.2.2:1080", "3.3.3.3:1080"}); err != nil {
		t.Fatal(err)
	}
	if err := p.MarkDead("1.1.1.1:1080", true, "连续失败 3 次"); err != nil {
		t.Fatal(err)
	}
	if err := p.MarkCheck("2.2.2.2:1080", false, 0, "连接被拒绝"); err != nil {
		t.Fatal(err)
	}
	if err := p.Assign("u1", "1.1.1.1:1080"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RecordProxyFailure("u1", "1.1.1.1:1080", "x"); err != nil {
		t.Fatal(err)
	}

	// 只清失效：留下探测不通的那条。
	res, err := p.PurgeDead(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 1 || res.Removed[0] != "socks5://1.1.1.1:1080" {
		t.Fatalf("只清失效应移除 1 条：%+v", res)
	}
	if res.Unbound != 1 || p.ProxyFor("u1") != "" {
		t.Fatalf("被清代理的分配应解绑：%+v", res)
	}
	if len(p.UsedAddrs("u1")) != 0 {
		t.Fatal("被清代理应从用过清单移除")
	}

	// 含探测不通：2.2.2.2 也被清掉。
	res, err = p.PurgeDead(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 1 || res.Removed[0] != "socks5://2.2.2.2:1080" {
		t.Fatalf("含探测不通应移除 2.2.2.2：%+v", res)
	}
	if p.Count() != 1 || p.List()[0].Addr != "socks5://3.3.3.3:1080" {
		t.Fatalf("剩余应为 3.3.3.3：%+v", p.List())
	}

	// 无可清时是 no-op。
	res, err = p.PurgeDead(true)
	if err != nil || len(res.Removed) != 0 || res.Kept != 1 {
		t.Fatalf("无可清应为 no-op：%+v %v", res, err)
	}
}

// TestSetAllSkipVerify 一键免校验（全池 / 仅失效 / 指定地址）。
func TestSetAllSkipVerify(t *testing.T) {
	p := New("")
	if _, err := p.Add([]string{"1.1.1.1:1080", "2.2.2.2:1080", "3.3.3.3:1080"}); err != nil {
		t.Fatal(err)
	}
	if err := p.MarkDead("2.2.2.2:1080", true, "x"); err != nil {
		t.Fatal(err)
	}

	// 只给失效的 2.2.2.2 开。
	n, err := p.SetAllSkipVerify(true, true, nil)
	if err != nil || n != 1 {
		t.Fatalf("仅失效应变更 1 条：(%d, %v)", n, err)
	}
	if !p.List()[1].SkipVerify || p.List()[0].SkipVerify {
		t.Fatalf("标记位置不符：%+v", p.List())
	}

	// 全池开（已开的 2.2.2.2 不计入变更）。
	n, err = p.SetAllSkipVerify(true, false, nil)
	if err != nil || n != 2 {
		t.Fatalf("全池应变更 2 条：(%d, %v)", n, err)
	}
	for _, px := range p.List() {
		if !px.SkipVerify {
			t.Fatalf("全池应免校验：%+v", px)
		}
	}

	// 指定地址关闭。
	n, err = p.SetAllSkipVerify(false, false, []string{"1.1.1.1:1080"})
	if err != nil || n != 1 {
		t.Fatalf("指定关闭应变更 1 条：(%d, %v)", n, err)
	}
	if p.List()[0].SkipVerify {
		t.Fatal("指定地址应关闭免校验")
	}

	// 幂等：再开一次已开的 → 0 变更。
	if n, err = p.SetAllSkipVerify(false, false, []string{"1.1.1.1:1080"}); err != nil || n != 0 {
		t.Fatalf("重复设置应 0 变更：(%d, %v)", n, err)
	}
	if _, err = p.SetAllSkipVerify(true, false, []string{"http://bad:1"}); err == nil {
		t.Fatal("非法地址应报错")
	}
}

// TestHealthPersistRoundTrip 失败计数 / 用过清单 / 失效记录 / 阈值都随池落盘并可载入。
func TestHealthPersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.json")
	p := New(path)
	if _, err := p.Add([]string{"1.1.1.1:1080", "2.2.2.2:1080"}); err != nil {
		t.Fatal(err)
	}
	if err := p.SetFailThreshold(5); err != nil {
		t.Fatal(err)
	}
	if err := p.Assign("u1", "1.1.1.1:1080"); err != nil {
		t.Fatal(err)
	}
	if err := p.MarkDead("2.2.2.2:1080", true, "人工标记"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RecordProxyFailure("u1", "1.1.1.1:1080", "超时"); err != nil {
		t.Fatal(err)
	}

	q := New(path)
	if err := q.Load(); err != nil {
		t.Fatal(err)
	}
	if q.FailThreshold() != 5 {
		t.Fatalf("阈值未持久化：%d", q.FailThreshold())
	}
	fs := q.FailureStateOf("u1")
	if fs.Count != 1 || fs.Addr != "socks5://1.1.1.1:1080" || fs.LastErr != "超时" {
		t.Fatalf("失败状态未持久化：%+v", fs)
	}
	if used := q.UsedAddrs("u1"); len(used) != 1 || used[0] != "socks5://1.1.1.1:1080" {
		t.Fatalf("用过清单未持久化：%v", used)
	}
	dead := q.List()[1]
	if !dead.Dead || dead.DeadReason != "人工标记" || dead.DeadAt.IsZero() {
		t.Fatalf("失效记录未持久化：%+v", dead)
	}
	// 复活后失效字段清空。
	if err := q.MarkDead("2.2.2.2:1080", false, ""); err != nil {
		t.Fatal(err)
	}
	if q.List()[1].Dead || q.DeadCount() != 0 {
		t.Fatal("复活后不应再是失效")
	}
	// 清除失败记录。
	n, err := q.ResetFailures("")
	if err != nil || n != 1 {
		t.Fatalf("ResetFailures = (%d, %v)", n, err)
	}
	if fs := q.FailureStateOf("u1"); fs.Count != 0 {
		t.Fatalf("清除后应无计数：%+v", fs)
	}
}

// TestAutoSwitchSkipsDeadAndUnused 自动换代理优先「没用过且未失效」：已失效的不入选。
func TestAutoSwitchSkipsDeadAndUnused(t *testing.T) {
	p := New("")
	if _, err := p.Add([]string{"1.1.1.1:1080", "2.2.2.2:1080", "3.3.3.3:1080"}); err != nil {
		t.Fatal(err)
	}
	// 2.2.2.2 已失效（人工）→ 从 1.1.1.1 切换时应直接跳到 3.3.3.3。
	if err := p.MarkDead("2.2.2.2:1080", true, "人工"); err != nil {
		t.Fatal(err)
	}
	if err := p.Assign("u1", "1.1.1.1:1080"); err != nil {
		t.Fatal(err)
	}
	var res SwitchResult
	for i := 0; i < DefaultFailThreshold; i++ {
		var err error
		res, err = p.RecordProxyFailure("u1", "1.1.1.1:1080", "x")
		if err != nil {
			t.Fatal(err)
		}
	}
	if !res.Switched || res.To != "socks5://3.3.3.3:1080" {
		t.Fatalf("应跳过已失效的 2.2.2.2：%+v", res)
	}
}

// TestRecordProxyFailureIgnoresForeignAddr 失败地址不是该账号当前分配（人工已改）时，
// 只累计失效记录，不抢改人工分配。
func TestRecordProxyFailureIgnoresForeignAddr(t *testing.T) {
	p := New("")
	if _, err := p.Add([]string{"1.1.1.1:1080", "2.2.2.2:1080"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Assign("u1", "2.2.2.2:1080"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < DefaultFailThreshold; i++ {
		if _, err := p.RecordProxyFailure("u1", "1.1.1.1:1080", "x"); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.ProxyFor("u1"); got != "socks5://2.2.2.2:1080" {
		t.Fatalf("不应改动人工指定的分配，实际 %q", got)
	}
	if !p.List()[0].Dead {
		t.Fatal("失败的那条仍应记为失效")
	}
}

// TestRecordProxyFailureInvalidAddr 脏地址（无法规范化）不入账、不 panic。
func TestRecordProxyFailureInvalidAddr(t *testing.T) {
	p := New("")
	if _, err := p.Add([]string{"1.1.1.1:1080"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RecordProxyFailure("u1", "://bad", "x"); err != nil {
		t.Fatal(err)
	}
	if p.FailureStateOf("u1").Count != 0 {
		t.Fatal("脏地址不应产生失败计数")
	}
	// 空 uid/addr 是 no-op。
	if res, err := p.RecordProxyFailure("", "", "x"); err != nil || res.Switched {
		t.Fatalf("空入参应 no-op：%+v %v", res, err)
	}
	if err := p.RecordProxySuccess(""); err != nil {
		t.Fatal(err)
	}
}
