// health.go 代理池的「健康度」运维：连续失败自动换代理、失效代理记录与清理、
// 一键免校验、失败状态观测。
//
// 需求背景（运维视角）：
//   - 一条 socks5 代理随时可能挂掉（超时 / 拒绝连接 / 被墙 / MITM 证书错）；
//   - 账号绑死在一条死代理上会让该账号的所有出站（对话 / 余额 / 签到 / 上报）全灭；
//   - 所以：同一账号 + 同一代理**连续失败**达到阈值（缺省 3 次）→ 自动换到一条
//     「这个账号没用过的、且未标记失效的」代理；换不动（池里没有可用替代）时解绑
//     回直连，并把原代理记为失效。
//
// 计数语义：
//   - 连续 = 同一账号、同一代理地址；一旦换到别的代理，计数从 0 重新开始；
//   - 任何一次**传输层成功**（RoundTrip 无错）都会把该账号的连续失败计数清零；
//   - 失败计数按 uid 维护（不是按代理），因为「换代理」是账号级决策。
//
// 失效记录（Proxy.Dead）：自动换代理时把被换掉的代理标记为失效（含原因与时间），
// 也支持面板人工标记 / 复活。失效代理不会成为自动换代理的候选；面板可一键清除。
package proxypool

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// DefaultFailThreshold 连续失败阈值：同一账号经同一代理连续失败达到该次数即触发
// 自动换代理（需求原文：「连续失败超过 3 次」→ 第 3 次失败时切换）。
const DefaultFailThreshold = 3

// FailState 一个账号的连续失败状态（持久化到 proxies.json 的 failures 段）。
type FailState struct {
	Addr    string    `json:"addr,omitempty"` // 当前正在计数的那条代理
	Count   int       `json:"count"`          // 连续失败次数
	Last    time.Time `json:"last,omitempty"` // 最近一次失败时间
	LastErr string    `json:"last_err,omitempty"`
	Swaps   int       `json:"swaps,omitempty"` // 该账号累计自动切换次数（观测用）
}

// FailThreshold 当前连续失败阈值（>=1）。
func (p *Pool) FailThreshold() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.threshold < 1 {
		return DefaultFailThreshold
	}
	return p.threshold
}

// SetFailThreshold 设置连续失败阈值（1..1000），落盘。
func (p *Pool) SetFailThreshold(n int) error {
	if n < 1 || n > 1000 {
		return fmt.Errorf("阈值越界（应在 1..1000）：%d", n)
	}
	p.mu.Lock()
	if p.threshold == n {
		p.mu.Unlock()
		return nil
	}
	p.threshold = n
	p.mu.Unlock()
	return p.Save()
}

// FailureStateOf 返回某账号的连续失败状态快照（面板展示用；无记录 = 零值）。
func (p *Pool) FailureStateOf(uid string) FailState {
	if p == nil || uid == "" {
		return FailState{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if fs := p.fails[uid]; fs != nil {
		return *fs
	}
	return FailState{}
}

// UsedAddrs 返回某账号「已用过」的代理地址快照（自动换代理的候选排除清单）。
func (p *Pool) UsedAddrs(uid string) []string {
	if p == nil || uid == "" {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.used[uid]...)
}

// markUsedLocked 把 addr 记进 uid 的「用过清单」（有序去重）。调用方须持写锁。
func (p *Pool) markUsedLocked(uid, addr string) {
	if uid == "" || addr == "" {
		return
	}
	for _, a := range p.used[uid] {
		if a == addr {
			return
		}
	}
	if p.used == nil {
		p.used = map[string][]string{}
	}
	p.used[uid] = append(p.used[uid], addr)
}

// SwitchResult 「记录一次代理失败」的结论（面板 / 日志回报）。
type SwitchResult struct {
	UID       string `json:"uid"`
	From      string `json:"from,omitempty"`      // 失败的代理
	To        string `json:"to,omitempty"`        // 切换后的代理（空 = 未切换）
	Count     int    `json:"count"`               // 本次失败后的连续失败计数
	Switched  bool   `json:"switched"`            // 是否发生了自动换代理
	Marked    bool   `json:"marked_dead"`         // 是否把原代理记为失效
	Exhausted bool   `json:"exhausted,omitempty"` // 没有可用替代 → 已解绑回直连
	Reason    string `json:"reason,omitempty"`
}

// RecordProxyFailure 记录一次「账号 uid 经代理 addr 出站失败」（传输层错误）。
//
// 行为：
//  1. 累计该代理的 FailCount，并把 addr 记进 uid 的「用过清单」；
//  2. 同账号同代理连续失败计数 +1（换了代理则从 1 重新计）；
//  3. 计数达到阈值且该代理**仍是该账号当前分配**时：
//     - 把原代理标记为失效（Dead + 原因 + 时间）；
//     - 选一条「该账号没用过、未失效」的代理替换（池里没有则放宽到"用过但未失效"，
//     优先最近探测可用的）；一条都挑不出 → 解绑该账号（回直连）并置 Exhausted；
//     - 计数清零、Swaps+1。
//
// 落盘：仅在状态真的变化时写（成功路径由 RecordProxySuccess 负责清零，且无变化时不落盘）。
func (p *Pool) RecordProxyFailure(uid, addr, errMsg string) (SwitchResult, error) {
	res := SwitchResult{UID: uid, From: addr}
	if p == nil || uid == "" || addr == "" {
		return res, nil
	}
	norm, err := NormalizeAddr(addr)
	if err != nil {
		return res, nil // 非法地址不入账（调用方拿到的 addr 来自 context，正常不会是脏数据）
	}
	res.From = norm

	p.mu.Lock()
	th := p.threshold
	if th < 1 {
		th = DefaultFailThreshold
	}
	p.markUsedLocked(uid, norm)

	// 1) 代理侧累计失败。
	if idx, ok := p.index[norm]; ok {
		p.proxies[idx].FailCount++
	}

	// 2) 账号侧连续失败计数。
	fs := p.fails[uid]
	if fs == nil {
		fs = &FailState{}
		if p.fails == nil {
			p.fails = map[string]*FailState{}
		}
		p.fails[uid] = fs
	}
	if fs.Addr != norm {
		fs.Addr = norm
		fs.Count = 0
	}
	fs.Count++
	fs.Last = time.Now()
	fs.LastErr = truncate(errMsg, 200)
	res.Count = fs.Count

	// 3) 达阈值 → 记录失效；若该代理仍是该账号的当前分配，再自动换代理。
	if fs.Count >= th {
		res.Marked = true
		res.Reason = fmt.Sprintf("连续失败 %d 次：%s", fs.Count, truncate(errMsg, 120))
		p.markDeadLocked(norm, res.Reason)

		// 只在该代理仍是该账号当前分配时动分配：人工刚改过代理（context 里是旧地址）
		// 的失败只用于「记录失效」，不抢改人工决策。
		if p.assign[uid] == norm {
			if next, ok := p.pickReplacementLocked(uid, norm); ok {
				p.assign[uid] = next
				p.markUsedLocked(uid, next)
				res.To = next
				res.Switched = true
				fs.Addr = next
				fs.Count = 0
				fs.LastErr = ""
			} else {
				// 池里没有可换的代理：解绑回直连（直连是本功能上线前的默认行为，
				// 比继续挂在一条已判定失效的代理上更可能可用）。
				delete(p.assign, uid)
				res.Exhausted = true
				fs.Addr = ""
				fs.Count = 0
				fs.LastErr = ""
			}
			fs.Swaps++
		}
	}
	p.mu.Unlock()
	return res, p.Save()
}

// RecordProxySuccess 记录一次「账号 uid 经代理出站成功」：清零连续失败计数。
// 无变化（本来就没计数）时直接返回，不落盘——成功是热路径，不能每次都写盘。
func (p *Pool) RecordProxySuccess(uid string) error {
	if p == nil || uid == "" {
		return nil
	}
	p.mu.Lock()
	fs := p.fails[uid]
	if fs == nil || (fs.Count == 0 && fs.LastErr == "") {
		p.mu.Unlock()
		return nil
	}
	fs.Count = 0
	fs.LastErr = ""
	p.mu.Unlock()
	return p.Save()
}

// ResetFailures 清除失败记录：uid 为空 = 全部账号；否则只清该账号。
// 返回被清除的记录条数。代理自身的 Dead 标记不受影响（那是失效记录，另有复活接口）。
func (p *Pool) ResetFailures(uid string) (int, error) {
	p.mu.Lock()
	n := 0
	if uid == "" {
		n = len(p.fails)
		p.fails = map[string]*FailState{}
	} else if _, ok := p.fails[uid]; ok {
		delete(p.fails, uid)
		n = 1
	}
	p.mu.Unlock()
	if n == 0 {
		return 0, nil
	}
	return n, p.Save()
}

// pickReplacementLocked 挑一条替代代理。调用方须持写锁。
//
// 优先级：
//  1. 该账号没用过 + 未失效 + 非当前（需求原文：「自动更换一个没有用过的代理」）；
//  2. 用过但未失效（优先最近探测可用的）——池子小、代理都用过时的兜底；
//  3. 都没有 → false（调用方解绑回直连）。
func (p *Pool) pickReplacementLocked(uid, current string) (string, bool) {
	used := map[string]bool{}
	for _, a := range p.used[uid] {
		used[a] = true
	}
	for _, px := range p.proxies {
		if px.Dead || px.Addr == current || used[px.Addr] {
			continue
		}
		return px.Addr, true
	}
	fallback := ""
	for _, px := range p.proxies {
		if px.Dead || px.Addr == current {
			continue
		}
		if px.OK && !px.LastCheck.IsZero() {
			return px.Addr, true
		}
		if fallback == "" {
			fallback = px.Addr
		}
	}
	if fallback != "" {
		return fallback, true
	}
	return "", false
}

// markDeadLocked 把代理标记为失效（幂等：已失效则只更新原因）。调用方须持写锁。
func (p *Pool) markDeadLocked(addr, reason string) {
	idx, ok := p.index[addr]
	if !ok {
		return
	}
	px := &p.proxies[idx]
	px.Dead = true
	px.DeadAt = time.Now()
	if reason != "" {
		px.DeadReason = truncate(reason, 200)
	}
}

// MarkDead 人工标记 / 取消代理失效（面板「标记失效」「复活」按钮）。
// reason 仅在 dead=true 时使用。
func (p *Pool) MarkDead(addr string, dead bool, reason string) error {
	norm, err := NormalizeAddr(addr)
	if err != nil {
		return err
	}
	p.mu.Lock()
	idx, ok := p.index[norm]
	if !ok {
		p.mu.Unlock()
		return fmt.Errorf("代理不在池中：%s", norm)
	}
	if dead {
		p.markDeadLocked(norm, reason)
	} else {
		px := &p.proxies[idx]
		px.Dead = false
		px.DeadAt = time.Time{}
		px.DeadReason = ""
	}
	p.mu.Unlock()
	return p.Save()
}

// PurgeResult 清理失效代理的结论。
type PurgeResult struct {
	Removed []string `json:"removed"` // 被移除的代理地址
	Unbound int      `json:"unbound"` // 连带解绑的账号数
	Kept    int      `json:"kept"`    // 仍保留的代理条数
}

// PurgeDead 一键清除「过期/失效」代理。
//
//   - 失效代理（Dead=true，自动换代理标记或人工标记）一律清除；
//   - includeFailedCheck=true 时，额外清除「最近探测不通」的代理（LastCheck 非零且
//     OK=false）——即需求里的「过期代理」（探活已失败，但还没触发自动换代理的那些）；
//   - 被清除代理的分配一并解绑（账号回直连），并清理相关失败记录与"用过清单"。
//
// 返回被清除的地址列表与解绑账号数。
func (p *Pool) PurgeDead(includeFailedCheck bool) (PurgeResult, error) {
	var res PurgeResult
	p.mu.Lock()
	victim := map[string]bool{}
	for _, px := range p.proxies {
		if px.Dead || (includeFailedCheck && !px.LastCheck.IsZero() && !px.OK) {
			victim[px.Addr] = true
		}
	}
	if len(victim) == 0 {
		res.Kept = len(p.proxies)
		p.mu.Unlock()
		return res, nil
	}
	kept := p.proxies[:0]
	for _, px := range p.proxies {
		if victim[px.Addr] {
			res.Removed = append(res.Removed, px.Addr)
			continue
		}
		kept = append(kept, px)
	}
	p.proxies = kept
	p.reindexLocked()
	for uid, a := range p.assign {
		if victim[a] {
			delete(p.assign, uid)
			res.Unbound++
		}
	}
	for uid, fs := range p.fails {
		if fs != nil && victim[fs.Addr] {
			delete(p.fails, uid)
		}
	}
	for uid, addrs := range p.used {
		keep := addrs[:0]
		for _, a := range addrs {
			if !victim[a] {
				keep = append(keep, a)
			}
		}
		if len(keep) == 0 {
			delete(p.used, uid)
		} else {
			p.used[uid] = keep
		}
	}
	res.Kept = len(p.proxies)
	sort.Strings(res.Removed)
	p.mu.Unlock()
	return res, p.Save()
}

// SetAllSkipVerify 一键免校验：把池中代理的「免 TLS 证书校验」标记批量设置为 skip。
//
// onlyDead=true 时只处理失效代理（典型用法：先「一键清除过期代理」清掉死号，再对
// 剩下的、因 MITM 证书报错的代理批量开免校验）；addrs 非空时只处理这些地址。
// 返回实际发生变化的条数。
func (p *Pool) SetAllSkipVerify(skip bool, onlyDead bool, addrs []string) (int, error) {
	p.mu.Lock()
	want := map[string]bool{}
	for _, a := range addrs {
		norm, err := NormalizeAddr(a)
		if err != nil {
			p.mu.Unlock()
			return 0, err
		}
		want[norm] = true
	}
	n := 0
	for i := range p.proxies {
		px := &p.proxies[i]
		if len(want) > 0 && !want[px.Addr] {
			continue
		}
		if onlyDead && !px.Dead {
			continue
		}
		if px.SkipVerify == skip {
			continue
		}
		px.SkipVerify = skip
		n++
	}
	p.mu.Unlock()
	if n == 0 {
		return 0, nil
	}
	return n, p.Save()
}

// DeadCount 失效代理条数（面板统计）。
func (p *Pool) DeadCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, px := range p.proxies {
		if px.Dead {
			n++
		}
	}
	return n
}

// ErrNoProxy 池中无代理（供调用方判定）。
var ErrNoProxy = errors.New("代理池为空")
