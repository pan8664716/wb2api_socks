// Package proxypool 代理池：批量维护 socks5 代理列表 + 「账号 → 代理」分配关系，
// 持久化到独立 JSON 文件（与 state.json / usage.json 同目录同风格）。
//
// 设计约束：
//   - 零外部依赖：socks5 出站由 net/http 原生支持（http.Transport.Proxy 返回
//     socks5:// URL 即自动走 SOCKS5 握手 + 可选用户名/密码认证），健康检查用本包
//     内置的极简 SOCKS5 客户端（socks5.go），不引入 golang.org/x/net；
//   - 分配是稀疏映射 uid → 代理地址：未分配的账号**直连**（现状零回归）；
//   - 写操作原子落盘（临时文件 + rename，0600 —— 文件内含代理口令）；
//   - 读路径（ProxyFor）只做一次 RLock + map 查表，可挂到每请求的热路径上。
package proxypool

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Proxy 池中一条 socks5 代理记录。
//
// Addr 是规范化后的唯一键（socks5://[user:pass@]host:port），重复添加按它去重。
// LastCheck/OK/LastErr/LatencyMs 是最近一次连通性探测的运行态结论，一并持久化：
// 重启后面板仍能显示「上次测过、通/不通」，不必等下一次探测。
type Proxy struct {
	Addr    string    `json:"addr"`
	Label   string    `json:"label,omitempty"`
	AddedAt time.Time `json:"added_at,omitempty"`
	// SkipVerify 该代理是否免 TLS 证书校验（「去掉 tls 验证」）。
	//
	// 为什么需要：部分代理会 MITM 掉 443（自带一张过期/自签证书），经它的请求会
	// 直接死在 x509 校验上（实测文案："certificate has expired or is not yet valid"）。
	// 标记后，**只有经该代理的请求**关掉证书校验，其余账号（含直连与其它代理）不受影响
	// ——比全局关校验精确得多。写法见 ParseLine（竖线后缀加 insecure）。
	SkipVerify bool `json:"skip_verify,omitempty"`
	// LastCheck/OK/LastErr/LatencyMs 最近一次连通性探测结论（见 MarkCheck）。
	LastCheck time.Time `json:"last_check,omitempty"`
	OK        bool      `json:"ok"`
	LastErr   string    `json:"last_err,omitempty"`
	LatencyMs int64     `json:"latency_ms,omitempty"`
	// Dead/DeadAt/DeadReason 失效标记：连续失败达阈值（见 RecordProxyFailure）时自动
	// 打上，也可由面板人工标记。失效代理**保留在列表中**（可见、可一键清除、可复活），
	// 但自动换代理的选号会跳过它们。
	Dead       bool      `json:"dead,omitempty"`
	DeadAt     time.Time `json:"dead_at,omitempty"`
	DeadReason string    `json:"dead_reason,omitempty"`
	// FailCount 累计失败次数（只增不清，观测用；连续失败计数在 failures 里按账号维护）。
	FailCount int `json:"fail_count,omitempty"`
}

// Masked 返回脱敏地址（口令替换为 ***），用于日志展示。
func (p Proxy) Masked() string {
	u, err := url.Parse(p.Addr)
	if err != nil || u.User == nil {
		return p.Addr
	}
	if _, has := u.User.Password(); !has {
		return p.Addr
	}
	// 手工拼接口令段：url.UserPassword 会把 * 转义成 %2A（"user:%2A%2A%2A"），
	// 日志里看着像坏数据。用户名仍走 url 转义（可能含 @/: 等字符）。
	masked := strings.ReplaceAll(url.UserPassword(u.User.Username(), "***").String(), "%2A", "*")
	u.User = nil
	return u.Scheme + "://" + masked + "@" + u.Host
}

// fileFormat 落盘结构（proxies.json）。
type fileFormat struct {
	Proxies     []Proxy           `json:"proxies"`
	Assignments map[string]string `json:"assignments,omitempty"`
	// Failures 账号 uid → 连续失败状态（「连续失败 N 次自动换代理」的计数）。
	Failures map[string]FailState `json:"failures,omitempty"`
	// Used 账号 uid → 已经用过的代理地址（按时间顺序，去重）。自动换代理优先挑
	// 「这个账号没用过的」代理，这就是那份"用过"清单。
	Used map[string][]string `json:"used,omitempty"`
	// FailThreshold 连续失败阈值（0/缺省 = DefaultFailThreshold）。
	FailThreshold int       `json:"fail_threshold,omitempty"`
	SavedAt       time.Time `json:"saved_at,omitempty"`
}

// Pool 代理池。零值不可用，必须经 New 构造。
//
// 并发模型：所有读写都在 mu 内完成；落盘（Save）在写操作返回前同步完成——
// 代理池的写频率是人手操作级别（面板点击），不值得引入异步落盘的一致性问题。
type Pool struct {
	mu      sync.RWMutex
	path    string // 空 = 纯内存（不落盘，测试/嵌入式用）
	proxies []Proxy
	index   map[string]int    // Addr → proxies 下标
	assign  map[string]string // uid → Addr

	// fails/used/threshold 见文件头「连续失败自动换代理」一节；均由 mu 保护。
	fails     map[string]*FailState // uid → 连续失败状态
	used      map[string][]string   // uid → 已用过的代理（有序去重）
	threshold int                   // 连续失败阈值（>=1）

	// saveMu 串行化「写临时文件 + rename」这一对操作。
	//
	// 为什么必须独占：并发 Save 会各自写**同一个** .tmp 路径（面板一次并发探测 N 条
	// 代理，每条 MarkCheck 都落盘），先完成者把临时文件 rename 走，后者的 rename
	// 立刻 ENOENT（实测报 "rename data/proxies.json.tmp ...: no such file or
	// directory"）。串行化 + 每次用唯一临时名双保险。
	saveMu sync.Mutex
}

// New 构造代理池。path 为空 = 纯内存模式（不读写文件）。
func New(path string) *Pool {
	return &Pool{
		path:      path,
		index:     map[string]int{},
		assign:    map[string]string{},
		fails:     map[string]*FailState{},
		used:      map[string][]string{},
		threshold: DefaultFailThreshold,
	}
}

// Path 返回落盘路径（空 = 纯内存）。
func (p *Pool) Path() string { return p.path }

// Load 从磁盘载入。文件不存在视为空池（首次运行，不是错误）。
// 载入时重新做一次解析归一：历史文件里可能残留未规范化的地址/已失效的分配。
func (p *Pool) Load() error {
	if p.path == "" {
		return nil
	}
	raw, err := os.ReadFile(p.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var ff fileFormat
	if err := json.Unmarshal(raw, &ff); err != nil {
		return fmt.Errorf("parse %s: %w", p.path, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proxies = nil
	p.index = map[string]int{}
	for _, px := range ff.Proxies {
		addr, err := NormalizeAddr(px.Addr)
		if err != nil {
			continue // 脏行跳过（不因单条坏数据整池加载失败）
		}
		if _, dup := p.index[addr]; dup {
			continue
		}
		px.Addr = addr
		p.index[addr] = len(p.proxies)
		p.proxies = append(p.proxies, px)
	}
	p.assign = map[string]string{}
	for uid, addr := range ff.Assignments {
		if uid == "" || addr == "" {
			continue
		}
		norm, err := NormalizeAddr(addr)
		if err != nil {
			continue
		}
		if _, ok := p.index[norm]; !ok {
			continue // 分配指向的代理已不在池中 → 丢弃（防脏分配指向空地址）
		}
		p.assign[uid] = norm
	}
	p.threshold = ff.FailThreshold
	if p.threshold < 1 {
		p.threshold = DefaultFailThreshold
	}
	p.fails = map[string]*FailState{}
	for uid, fs := range ff.Failures {
		if uid == "" || fs.Count <= 0 {
			continue
		}
		if fs.Addr != "" {
			if norm, err := NormalizeAddr(fs.Addr); err == nil {
				fs.Addr = norm
			} else {
				fs.Addr = ""
			}
		}
		cp := fs
		p.fails[uid] = &cp
	}
	p.used = map[string][]string{}
	for uid, addrs := range ff.Used {
		if uid == "" {
			continue
		}
		seen := map[string]bool{}
		for _, a := range addrs {
			norm, err := NormalizeAddr(a)
			if err != nil || seen[norm] {
				continue
			}
			seen[norm] = true
			p.used[uid] = append(p.used[uid], norm)
		}
	}
	return nil
}

// Save 原子落盘（临时文件 + rename）。path 为空时 no-op。
//
// 并发安全：saveMu 串行化整个写盘过程（见字段注释）；每次用 os.CreateTemp 生成唯一
// 临时名（同目录，保证 rename 是同一文件系统内的原子操作），创建权限即 0600
// （文件内含代理口令，不对同机其他用户开放）。
func (p *Pool) Save() error {
	if p.path == "" {
		return nil
	}
	p.saveMu.Lock()
	defer p.saveMu.Unlock()
	p.mu.RLock()
	ff := fileFormat{
		Proxies:       append([]Proxy(nil), p.proxies...),
		Assignments:   make(map[string]string, len(p.assign)),
		Failures:      make(map[string]FailState, len(p.fails)),
		Used:          make(map[string][]string, len(p.used)),
		FailThreshold: p.threshold,
		SavedAt:       time.Now(),
	}
	for uid, addr := range p.assign {
		ff.Assignments[uid] = addr
	}
	for uid, fs := range p.fails {
		if fs == nil {
			continue
		}
		ff.Failures[uid] = *fs
	}
	for uid, addrs := range p.used {
		ff.Used[uid] = append([]string(nil), addrs...)
	}
	p.mu.RUnlock()

	raw, err := json.MarshalIndent(ff, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(p.path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(p.path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Count 池中代理条数。
func (p *Pool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.proxies)
}

// List 返回代理列表快照（按添加顺序，稳定输出）。
func (p *Pool) List() []Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]Proxy(nil), p.proxies...)
}

// Addrs 返回池中全部代理地址（按添加顺序）。
func (p *Pool) Addrs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.proxies))
	for _, px := range p.proxies {
		out = append(out, px.Addr)
	}
	return out
}

// AddResult 批量添加结果（供面板回报：新增 / 重复 / 失败明细）。
type AddResult struct {
	Added   []Proxy  `json:"added"`
	Dupe    []string `json:"dupe,omitempty"`    // 已在池中（按规范化地址去重）
	Invalid []string `json:"invalid,omitempty"` // 解析失败的原行（原样回显，便于运维定位）
}

// Add 批量添加：逐行解析（见 ParseLine），规范化去重后追加。落盘失败不回滚内存
// （内存态仍然生效，下次写操作会再尝试落盘），错误一并返回给调用方展示。
func (p *Pool) Add(lines []string) (AddResult, error) {
	var res AddResult
	now := time.Now()
	p.mu.Lock()
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		addr, label, skipVerify, err := ParseLine(trimmed)
		if err != nil {
			res.Invalid = append(res.Invalid, trimmed)
			continue
		}
		if idx, dup := p.index[addr]; dup {
			// 重复行只做「标记合并」：新行带 insecure 时给已有条目补上标记（免校验是
			// 叠加语义，不会被重复行静默取消），备注/探测结论保持原样。
			if skipVerify && !p.proxies[idx].SkipVerify {
				p.proxies[idx].SkipVerify = true
			}
			res.Dupe = append(res.Dupe, addr)
			continue
		}
		px := Proxy{Addr: addr, Label: label, AddedAt: now, SkipVerify: skipVerify}
		p.index[addr] = len(p.proxies)
		p.proxies = append(p.proxies, px)
		res.Added = append(res.Added, px)
	}
	p.mu.Unlock()
	if len(res.Added) == 0 {
		return res, nil
	}
	return res, p.Save()
}

// Remove 删除一个代理（按地址或原始输入匹配），并连带清除所有指向它的分配。
// 返回被清除的分配账号列表（供面板提示「已同时解绑 N 个账号」）。
func (p *Pool) Remove(addr string) (bool, []string, error) {
	norm, err := NormalizeAddr(addr)
	if err != nil {
		return false, nil, err
	}
	p.mu.Lock()
	idx, ok := p.index[norm]
	if !ok {
		p.mu.Unlock()
		return false, nil, nil
	}
	p.proxies = append(p.proxies[:idx], p.proxies[idx+1:]...)
	delete(p.index, norm)
	p.reindexLocked()
	var unbound []string
	for uid, a := range p.assign {
		if a == norm {
			delete(p.assign, uid)
			unbound = append(unbound, uid)
		}
	}
	// 失败状态与被删代理相关时一并收尾：连续失败计数指向它 → 清掉（换到别的代理后
	// 从零开始计数）；"用过清单"里去掉它（代理已不在池中，留着只会占位）。
	for uid, fs := range p.fails {
		if fs != nil && fs.Addr == norm {
			delete(p.fails, uid)
		}
	}
	for uid, addrs := range p.used {
		kept := addrs[:0]
		for _, a := range addrs {
			if a != norm {
				kept = append(kept, a)
			}
		}
		if len(kept) == 0 {
			delete(p.used, uid)
		} else {
			p.used[uid] = kept
		}
	}
	p.mu.Unlock()
	sort.Strings(unbound)
	return true, unbound, p.Save()
}

// Clear 清空代理列表与全部分配（返回被清掉的代理条数）。
func (p *Pool) Clear() (int, error) {
	p.mu.Lock()
	n := len(p.proxies)
	p.proxies = nil
	p.index = map[string]int{}
	p.assign = map[string]string{}
	p.fails = map[string]*FailState{}
	p.used = map[string][]string{}
	p.mu.Unlock()
	return n, p.Save()
}

// reindexLocked 重建 Addr → 下标索引。调用方必须已持写锁。
func (p *Pool) reindexLocked() {
	p.index = make(map[string]int, len(p.proxies))
	for i, px := range p.proxies {
		p.index[px.Addr] = i
	}
}

// Has 报告地址是否在池中。
func (p *Pool) Has(addr string) bool {
	norm, err := NormalizeAddr(addr)
	if err != nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.index[norm]
	return ok
}

// Assign 为单个账号指定代理（addr 会先规范化；必须已在池中）。
func (p *Pool) Assign(uid, addr string) error {
	if uid == "" {
		return errors.New("uid 为空")
	}
	norm, err := NormalizeAddr(addr)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if _, ok := p.index[norm]; !ok {
		p.mu.Unlock()
		return fmt.Errorf("代理不在池中：%s", norm)
	}
	p.assign[uid] = norm
	p.markUsedLocked(uid, norm)
	p.mu.Unlock()
	return p.Save()
}

// Unassign 清除单个账号的代理分配（返回是否原本有分配）。
func (p *Pool) Unassign(uid string) (bool, error) {
	p.mu.Lock()
	_, ok := p.assign[uid]
	if ok {
		delete(p.assign, uid)
	}
	p.mu.Unlock()
	if !ok {
		return false, nil
	}
	return true, p.Save()
}

// ClearAssignments 一键清除全部分配（不动代理列表），返回被清除的账号数。
func (p *Pool) ClearAssignments() (int, error) {
	p.mu.Lock()
	n := len(p.assign)
	p.assign = map[string]string{}
	p.mu.Unlock()
	return n, p.Save()
}

// Assignment 返回 uid → 代理地址 的分配快照（副本）。
func (p *Pool) Assignment() map[string]string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]string, len(p.assign))
	for uid, addr := range p.assign {
		out[uid] = addr
	}
	return out
}

// ProxyFor 返回账号当前生效的代理地址；空串 = 直连。
//
// 这是出站热路径唯一入口（upstream.Client.ProxyFor 直接接它）：只做一次 RLock +
// 两次 map 查表。分配指向的代理已被删除时返回空（视为直连），保证不会把请求打到
// 一个已不存在的地址上。
func (p *Pool) ProxyFor(uid string) string {
	if p == nil || uid == "" {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	addr := p.assign[uid]
	if addr == "" {
		return ""
	}
	if _, ok := p.index[addr]; !ok {
		return ""
	}
	return addr
}

// SkipVerifyFor 报告账号当前代理是否免 TLS 证书校验（无代理/未标记 → false）。
// 与 ProxyFor 同一把锁，出站热路径调用（每请求一次）。
func (p *Pool) SkipVerifyFor(uid string) bool {
	if p == nil || uid == "" {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	addr := p.assign[uid]
	if addr == "" {
		return false
	}
	idx, ok := p.index[addr]
	if !ok {
		return false
	}
	return p.proxies[idx].SkipVerify
}

// SetSkipVerify 设置/取消某个代理的「免 TLS 证书校验」标记（面板开关）。
func (p *Pool) SetSkipVerify(addr string, skip bool) error {
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
	if p.proxies[idx].SkipVerify == skip {
		p.mu.Unlock()
		return nil
	}
	p.proxies[idx].SkipVerify = skip
	p.mu.Unlock()
	return p.Save()
}

// BulkMode 一键配置模式。
type BulkMode string

const (
	// BulkOrder 按 IP 顺序配置：账号列表顺序 × 代理列表顺序，一对一，代理用尽则
	// 从头循环（账号多于代理时复用）。即「第 1 个账号用第 1 个 IP、第 2 个账号用第 2 个 IP…」
	BulkOrder BulkMode = "order"
	// BulkSame 同一个 IP：选定的一个代理分配给全部目标账号。
	BulkSame BulkMode = "same"
	// BulkClear 一键清除：清除目标账号的全部分配（addr 忽略）。
	BulkClear BulkMode = "clear"
)

// BulkResult 一键配置结果。
type BulkResult struct {
	Mode     string            `json:"mode"`
	Assigned map[string]string `json:"assigned,omitempty"` // uid → addr（本模式下的最终分配）
	Cleared  int               `json:"cleared,omitempty"`  // BulkClear 清除的账号数
	Skipped  []string          `json:"skipped,omitempty"`  // 已分配被跳过（onlyUnassigned=true）的账号
}

// AssignBulk 一键配置。
//
//   - uids：目标账号（调用方按「账号池顺序」传入，BulkOrder 的「顺序」即此序）；
//   - mode：order / same / clear；
//   - addr：BulkSame 必填，其余忽略；
//   - onlyUnassigned：仅对「当前没有分配」的账号生效（保留人工单独指定的结果）。
//
// 无代理时（order/same）返回错误，不做任何修改。
func (p *Pool) AssignBulk(uids []string, mode BulkMode, addr string, onlyUnassigned bool) (BulkResult, error) {
	res := BulkResult{Mode: string(mode)}
	p.mu.Lock()
	defer p.mu.Unlock()

	targets := make([]string, 0, len(uids))
	for _, uid := range uids {
		if uid == "" {
			continue
		}
		if onlyUnassigned {
			if _, ok := p.assign[uid]; ok {
				res.Skipped = append(res.Skipped, uid)
				continue
			}
		}
		targets = append(targets, uid)
	}

	switch mode {
	case BulkClear:
		for _, uid := range targets {
			if _, ok := p.assign[uid]; ok {
				delete(p.assign, uid)
				res.Cleared++
			}
		}
		if res.Cleared == 0 {
			return res, nil
		}
	case BulkOrder:
		if len(p.proxies) == 0 {
			return res, errors.New("代理池为空，无法按顺序分配")
		}
		res.Assigned = map[string]string{}
		for i, uid := range targets {
			px := p.proxies[i%len(p.proxies)].Addr
			p.assign[uid] = px
			p.markUsedLocked(uid, px)
			res.Assigned[uid] = px
		}
	case BulkSame:
		norm, err := NormalizeAddr(addr)
		if err != nil {
			return res, err
		}
		if _, ok := p.index[norm]; !ok {
			return res, fmt.Errorf("代理不在池中：%s", norm)
		}
		res.Assigned = map[string]string{}
		for _, uid := range targets {
			p.assign[uid] = norm
			p.markUsedLocked(uid, norm)
			res.Assigned[uid] = norm
		}
	default:
		return res, fmt.Errorf("未知配置模式：%s", mode)
	}
	if len(res.Assigned) == 0 && res.Cleared == 0 {
		return res, nil
	}
	// 落盘在锁外执行（Save 自己取 RLock）；先解锁再存，避免 Save 的 RLock 与
	// 本函数的写锁自锁（sync.RWMutex 不可重入）。
	p.mu.Unlock()
	err := p.Save()
	p.mu.Lock()
	return res, err
}

// PruneAssignments 清除指向「已不在账号池」的分配（账号被移除后的收尾）。
// valid 为当前账号池的 uid 集合；返回被清除的账号数。
func (p *Pool) PruneAssignments(valid map[string]bool) (int, error) {
	p.mu.Lock()
	n := 0
	for uid := range p.assign {
		if !valid[uid] {
			delete(p.assign, uid)
			n++
		}
	}
	p.mu.Unlock()
	if n == 0 {
		return 0, nil
	}
	return n, p.Save()
}

// MarkCheck 记录一次连通性探测结论（addr 须已在池中）。
func (p *Pool) MarkCheck(addr string, ok bool, latency time.Duration, errMsg string) error {
	norm, err := NormalizeAddr(addr)
	if err != nil {
		return err
	}
	p.mu.Lock()
	idx, found := p.index[norm]
	if !found {
		p.mu.Unlock()
		return fmt.Errorf("代理不在池中：%s", norm)
	}
	px := &p.proxies[idx]
	px.LastCheck = time.Now()
	px.OK = ok
	px.LatencyMs = latency.Milliseconds()
	if ok {
		px.LastErr = ""
	} else {
		px.LastErr = truncate(errMsg, 200)
	}
	p.mu.Unlock()
	return p.Save()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---------------------------------------------------------------------------
// 解析与规范化
// ---------------------------------------------------------------------------

// NormalizeAddr 把任意受支持写法归一为 socks5://[user:pass@]host:port。
func NormalizeAddr(raw string) (string, error) {
	addr, _, _, err := ParseLine(raw)
	return addr, err
}

// skipVerifyFlags 竖线后缀里被识别为「免 TLS 证书校验」标记的写法（大小写不敏感）。
var skipVerifyFlags = map[string]bool{
	"insecure": true, "insecure=1": true, "insecure=true": true,
	"skip-verify": true, "skipverify": true, "skip_verify": true, "no-verify": true,
}

// ParseLine 解析一行代理输入，返回规范化地址、备注与「免 TLS 校验」标记。
//
// 支持形态（每行一条，空行与 # / // 开头的行为注释）：
//
//	socks5://user:pass@host:port            标准 URL（socks5h:// / socks:// 等价接受）
//	host:port                               无认证
//	user:pass@host:port                     无 scheme
//	host:port:user:pass                     代理商常见的四段式
//	<以上任意>|<备注>                        竖线后缀为备注（口令含竖线请写成 %7C）
//	<以上任意>|insecure                     该代理免 TLS 证书校验（等价 skip-verify）
//	<以上任意>|香港01|insecure               备注与标记可同时给（顺序无关）
//
// 只接受 socks5 族（本项目按需求仅支持 socks5）；http/https/socks4 会返回明确错误。
func ParseLine(raw string) (addr, label string, skipVerify bool, err error) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return "", "", false, errors.New("空行")
	}
	// 竖线后缀（半角 | 与全角 ｜ 都认）：第 1 段是地址，其余段依次识别为标记或备注。
	// 口令里出现竖线时请写成 %7C（URL 转义），避免歧义。
	if i := strings.IndexAny(line, "|｜"); i >= 0 {
		parts := strings.FieldsFunc(line[i+1:], func(r rune) bool { return r == '|' || r == '｜' })
		line = strings.TrimSpace(line[:i])
		for _, part := range parts {
			tok := strings.TrimSpace(part)
			if tok == "" {
				continue
			}
			if skipVerifyFlags[strings.ToLower(tok)] {
				skipVerify = true
				continue
			}
			if label == "" {
				label = tok
			}
		}
	}
	if line == "" {
		return "", "", false, errors.New("缺少代理地址")
	}

	if i := strings.Index(line, "://"); i >= 0 {
		scheme := strings.ToLower(strings.TrimSpace(line[:i]))
		switch scheme {
		case "socks5", "socks5h", "socks":
			// 允许
		default:
			return "", "", false, fmt.Errorf("不支持的代理类型 %q（仅支持 socks5）", scheme)
		}
		line = line[i+3:]
	}
	// 去掉路径/查询串（形如 host:port/ 的尾巴）。
	if i := strings.IndexAny(line, "/?#"); i >= 0 {
		line = line[:i]
	}
	if line == "" {
		return "", "", false, errors.New("缺少主机:端口")
	}

	var user, pass, hostport string
	switch {
	case strings.Contains(line, "@"):
		cred, hp, _ := cutLast(line, "@")
		hostport = hp
		if cred != "" {
			if i := strings.Index(cred, ":"); i >= 0 {
				user, pass = cred[:i], cred[i+1:]
			} else {
				user = cred
			}
		}
	default:
		// 四段式 host:port:user:pass（含 IPv6 时不做该形态识别，需带 [] 或改用 @ 形态）。
		if parts := strings.Split(line, ":"); len(parts) == 4 && !strings.Contains(line, "[") {
			hostport = parts[0] + ":" + parts[1]
			user, pass = parts[2], parts[3]
		} else {
			hostport = line
		}
	}

	host, port, err := splitHostPort(hostport)
	if err != nil {
		return "", "", false, err
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return "", "", false, fmt.Errorf("端口非法：%q", port)
	}
	if n <= 0 || n > 65535 {
		return "", "", false, fmt.Errorf("端口越界：%q", port)
	}

	u := &url.URL{Scheme: "socks5", Host: net.JoinHostPort(host, port)}
	switch {
	case user != "" && pass != "":
		u.User = url.UserPassword(user, pass)
	case user != "":
		// 只有用户名（无口令）：url.User 生成 "user@host"，避免 UserPassword 的 "user:@host"。
		u.User = url.User(user)
	}
	return u.String(), label, skipVerify, nil
}

// splitHostPort 解析 host:port，容忍带方括号的 IPv6 与不带方括号的裸 IPv6。
func splitHostPort(s string) (host, port string, err error) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return strings.Trim(h, "[]"), p, nil
	}
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", fmt.Errorf("缺少端口：%q（应形如 host:port）", s)
	}
	return strings.Trim(s[:i], "[]"), s[i+1:], nil
}

// cutLast 在最后一个 sep 处切分。
func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}
