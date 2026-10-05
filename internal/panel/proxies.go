// proxies.go 面板「代理池」运维接口：批量增删 socks5 代理、账号 ↔ 代理分配、
// 一键配置（按 IP 顺序 / 同一个 IP / 一键清除）、连通性探测。
//
// 设计约束（与 panel.go 一致）：
//   - 全部操作落到 proxypool.Pool 的既有入口，面板不自己维护第二份状态；
//   - 分配是稀疏映射：没分配的账号直连，与本功能上线前行为完全一致；
//   - 探测（check）是唯一会出网的接口，走 proxypool.Check（内置 SOCKS5 客户端）。
package panel

import (
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/proxypool"
)

// proxies 代理池全量视图。
//
//	GET /panel/api/proxies
//
// 返回：
//
//	{
//	  "ok": true,
//	  "path": "data/proxies.json",
//	  "proxies": [{addr,label,added_at,last_check,ok,last_err,latency_ms,accounts:[uid...]}],
//	  "accounts": [{uid,nickname,realm,proxy,label}],   // 账号池顺序，proxy 空 = 直连
//	  "assigned": 2, "total": 5                          // 已分配账号数 / 代理条数
//	}
//
// 顺带做一次收尾：清除指向「已不在账号池」的分配（账号被移除后的残留）。
func (p *Panel) proxiesList(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	accounts := p.cfg.Pool.List()
	valid := make(map[string]bool, len(accounts))
	for _, st := range accounts {
		valid[st.UID] = true
	}
	if n, err := pp.PruneAssignments(valid); err != nil {
		log.Printf("panel: 代理池清理失效分配失败: %v", err)
	} else if n > 0 {
		log.Printf("panel: 代理池清理失效分配 %d 条（账号已移除）", n)
	}

	assign := pp.Assignment()
	byAddr := map[string][]string{}
	for uid, addr := range assign {
		byAddr[addr] = append(byAddr[addr], uid)
	}
	proxies := pp.List()
	// 视图用字符串时间：time.Time 的零值（从未探测）会被序列化成 "0001-01-01T00:00:00Z"，
	// 前端无法与"真的测过"区分——省略即为「未探测」。
	type proxyView struct {
		Addr      string `json:"addr"`
		Label     string `json:"label,omitempty"`
		AddedAt   string `json:"added_at,omitempty"`
		LastCheck string `json:"last_check,omitempty"`
		OK        bool   `json:"ok"`
		LastErr   string `json:"last_err,omitempty"`
		LatencyMs int64  `json:"latency_ms,omitempty"`
		// SkipVerify 该代理免 TLS 证书校验（MITM 型代理；见 proxypool.Proxy.SkipVerify）。
		SkipVerify bool     `json:"skip_verify,omitempty"`
		Accounts   []string `json:"accounts,omitempty"`
		// Dead/DeadAt/DeadReason 失效记录（连续失败自动标记或人工标记）。
		Dead       bool   `json:"dead,omitempty"`
		DeadAt     string `json:"dead_at,omitempty"`
		DeadReason string `json:"dead_reason,omitempty"`
		// FailCount 累计失败次数（观测用）。
		FailCount int `json:"fail_count,omitempty"`
	}
	out := make([]proxyView, 0, len(proxies))
	for _, px := range proxies {
		uids := byAddr[px.Addr]
		sort.Strings(uids)
		v := proxyView{
			Addr: px.Addr, Label: px.Label, OK: px.OK, SkipVerify: px.SkipVerify,
			LastErr: px.LastErr, LatencyMs: px.LatencyMs, Accounts: uids,
			Dead: px.Dead, DeadReason: px.DeadReason, FailCount: px.FailCount,
		}
		if !px.AddedAt.IsZero() {
			v.AddedAt = px.AddedAt.Format(time.RFC3339)
		}
		if !px.LastCheck.IsZero() {
			v.LastCheck = px.LastCheck.Format(time.RFC3339)
		}
		if !px.DeadAt.IsZero() {
			v.DeadAt = px.DeadAt.Format(time.RFC3339)
		}
		out = append(out, v)
	}

	type acctView struct {
		UID      string `json:"uid"`
		Nickname string `json:"nickname,omitempty"`
		Realm    string `json:"realm,omitempty"`
		Proxy    string `json:"proxy,omitempty"`
		Label    string `json:"label,omitempty"`
		// SkipVerify 该账号当前代理是否免 TLS 校验（面板提示用）。
		SkipVerify bool `json:"skip_verify,omitempty"`
		// FailCount 该账号经当前代理的连续失败次数（达阈值会自动换代理）。
		FailCount int `json:"fail_count,omitempty"`
		// FailAddr/FailErr 计数对应的代理与最近错误（面板提示用）。
		FailAddr string `json:"fail_addr,omitempty"`
		FailErr  string `json:"fail_err,omitempty"`
		// Used 该账号已用过的代理数（自动换代理的候选排除数）。
		Used int `json:"used,omitempty"`
	}
	labelOf := map[string]string{}
	skipOf := map[string]bool{}
	for _, px := range proxies {
		labelOf[px.Addr] = px.Label
		skipOf[px.Addr] = px.SkipVerify
	}
	accs := make([]acctView, 0, len(accounts))
	for _, st := range accounts {
		addr := assign[st.UID]
		fs := pp.FailureStateOf(st.UID)
		accs = append(accs, acctView{
			UID: st.UID, Nickname: st.Nickname, Realm: st.Realm,
			Proxy: addr, Label: labelOf[addr], SkipVerify: skipOf[addr],
			FailCount: fs.Count, FailAddr: fs.Addr, FailErr: fs.LastErr,
			Used: len(pp.UsedAddrs(st.UID)),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"path":      pp.Path(),
		"proxies":   out,
		"accounts":  accs,
		"total":     len(proxies),
		"assigned":  len(assign),
		"dead":      pp.DeadCount(),
		"threshold": pp.FailThreshold(),
	})
}

// proxiesAdd 批量添加代理。
//
//	POST /panel/api/proxies/add
//	{"text": "socks5://user:pass@1.2.3.4:1080\n5.6.7.8:1080\n..."}
//	或 {"lines": ["...", "..."]}
//
// 每行一条，支持 socks5:// / socks5h:// / host:port / user:pass@host:port /
// host:port:user:pass / 竖线备注；空行与 # 开头行忽略。重复地址自动去重。
func (p *Panel) proxiesAdd(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	var body struct {
		Text  string   `json:"text"`
		Lines []string `json:"lines"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "解析请求体失败: "+err.Error())
		return
	}
	lines := body.Lines
	if body.Text != "" {
		lines = append(lines, splitLines(body.Text)...)
	}
	if len(lines) == 0 {
		writeErr(w, http.StatusBadRequest, "没有可添加的内容")
		return
	}
	res, err := pp.Add(lines)
	if len(res.Added) == 0 && len(res.Dupe) == 0 && len(res.Invalid) == 0 {
		writeErr(w, http.StatusBadRequest, "没有可添加的内容（空行与 # 注释会被忽略）")
		return
	}
	resp := map[string]any{
		"ok":      true,
		"added":   len(res.Added),
		"dupe":    res.Dupe,
		"invalid": res.Invalid,
		"total":   pp.Count(),
	}
	if err != nil {
		resp["save_error"] = err.Error()
	}
	log.Printf("panel: 代理池添加 added=%d dupe=%d invalid=%d（池内共 %d 条）",
		len(res.Added), len(res.Dupe), len(res.Invalid), pp.Count())
	writeJSON(w, http.StatusOK, resp)
}

// proxiesRemove 删除单个代理（连带解绑所有指向它的账号）。
//
//	POST /panel/api/proxies/remove   {"addr": "socks5://..."}
func (p *Panel) proxiesRemove(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	var body struct {
		Addr string `json:"addr"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "解析请求体失败: "+err.Error())
		return
	}
	ok, unbound, err := pp.Remove(body.Addr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "代理不在池中")
		return
	}
	log.Printf("panel: 代理池删除 %s（同时解绑 %d 个账号）", proxypool.MaskProxy(body.Addr), len(unbound))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "unbound": len(unbound), "total": pp.Count()})
}

// proxiesClear 清空代理池（代理列表 + 全部分配）。
//
//	POST /panel/api/proxies/clear
func (p *Panel) proxiesClear(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	n, err := pp.Clear()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "落盘失败: "+err.Error())
		return
	}
	log.Printf("panel: 代理池清空（%d 条代理 + 全部账号分配）", n)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": n})
}

// proxiesAssign 单账号指定代理 / 单独清除。
//
//	POST /panel/api/proxies/assign   {"uid": "...", "addr": "socks5://..."}
//
// addr 为空 = 清除该账号的分配（单独清除，等价于 /unassign）。
func (p *Panel) proxiesAssign(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	var body struct {
		UID  string `json:"uid"`
		Addr string `json:"addr"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "解析请求体失败: "+err.Error())
		return
	}
	if _, ok := p.cfg.Pool.Status(body.UID); !ok {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}
	if body.Addr == "" {
		_, err := pp.Unassign(body.UID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "落盘失败: "+err.Error())
			return
		}
		log.Printf("panel: 代理池单独清除 uid=%s", body.UID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cleared": true})
		return
	}
	if err := pp.Assign(body.UID, body.Addr); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("panel: 代理池指定 uid=%s → %s", body.UID, proxypool.MaskProxy(body.Addr))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "uid": body.UID, "addr": body.Addr})
}

// proxiesSkipVerify 切换某个代理的「免 TLS 证书校验」标记。
//
//	POST /panel/api/proxies/skipverify   {"addr": "socks5://...", "skip": true}
//
// 语义：只影响**经该代理**的请求（MITM 型代理自带过期/自签证书时用）；直连与其它
// 代理仍走严格校验。与 config upstream.tls_skip_verify（全局关校验）互为粗细两档。
func (p *Panel) proxiesSkipVerify(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	var body struct {
		Addr string `json:"addr"`
		Skip *bool  `json:"skip"` // 缺省 = true（只切「开启」方向，避免误传空值把标记清掉）
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "解析请求体失败: "+err.Error())
		return
	}
	skip := true
	if body.Skip != nil {
		skip = *body.Skip
	}
	if err := pp.SetSkipVerify(body.Addr, skip); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("panel: 代理 %s 免 TLS 校验=%v", proxypool.MaskProxy(body.Addr), skip)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "addr": body.Addr, "skip_verify": skip})
}

// proxiesUnassign 单独清除某账号的代理分配。
//
//	POST /panel/api/proxies/unassign   {"uid": "..."}
func (p *Panel) proxiesUnassign(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	var body struct {
		UID string `json:"uid"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "解析请求体失败: "+err.Error())
		return
	}
	had, err := pp.Unassign(body.UID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "落盘失败: "+err.Error())
		return
	}
	log.Printf("panel: 代理池单独清除 uid=%s had=%v", body.UID, had)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cleared": had})
}

// proxiesBulk 一键配置。
//
//	POST /panel/api/proxies/bulk
//	{"mode": "order|same|clear", "addr": "socks5://...", "only_unassigned": false}
//
// mode=order  按 IP 顺序配置：账号池顺序 × 代理池顺序一对一（代理用尽从头循环）；
// mode=same   同一个 IP：addr 指定的代理分配给全部账号；
// mode=clear  一键清除：清除全部（或 only_unassigned 范围内的）账号分配。
//
// uids 可显式给出（面板勾选），缺省 = 账号池全部账号（pool.List() 已按 uid 排序，顺序稳定）。
func (p *Panel) proxiesBulk(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	var body struct {
		Mode           string   `json:"mode"`
		Addr           string   `json:"addr"`
		OnlyUnassigned bool     `json:"only_unassigned"`
		UIDs           []string `json:"uids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "解析请求体失败: "+err.Error())
		return
	}
	uids := body.UIDs
	if len(uids) == 0 {
		for _, st := range p.cfg.Pool.List() {
			uids = append(uids, st.UID)
		}
	}
	res, err := pp.AssignBulk(uids, proxypool.BulkMode(body.Mode), body.Addr, body.OnlyUnassigned)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("panel: 代理池一键配置 mode=%s 生效=%d 清除=%d 跳过=%d",
		body.Mode, len(res.Assigned), res.Cleared, len(res.Skipped))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"mode":     res.Mode,
		"assigned": len(res.Assigned),
		"cleared":  res.Cleared,
		"skipped":  len(res.Skipped),
		"map":      res.Assigned,
	})
}

// proxiesCheck 连通性探测（唯一出网接口）。
//
//	POST /panel/api/proxies/check   {"addrs": ["socks5://..."]}   缺省 = 全池
//
// 并发 8 路探测（SOCKS5 握手 + CONNECT + TLS 握手到上游 chat 域 443），结果写回
// 代理记录（ok / latency_ms / last_err）并持久化，面板表格直接展示。
func (p *Panel) proxiesCheck(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	var body struct {
		Addrs  []string `json:"addrs"`
		Target string   `json:"target"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)
	}
	addrs := body.Addrs
	if len(addrs) == 0 {
		addrs = pp.Addrs()
	}
	if len(addrs) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "results": []any{}})
		return
	}
	target := body.Target
	if target == "" {
		target = proxypool.DefaultCheckTarget
	}

	type result struct {
		Addr      string `json:"addr"`
		OK        bool   `json:"ok"`
		LatencyMs int64  `json:"latency_ms"`
		Error     string `json:"error,omitempty"`
	}
	results := make([]result, len(addrs))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, addr := range addrs {
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			lat, err := proxypool.Check(addr, target)
			res := result{Addr: addr, OK: err == nil, LatencyMs: lat.Milliseconds()}
			if err != nil {
				res.Error = err.Error()
			}
			if merr := pp.MarkCheck(addr, res.OK, lat, res.Error); merr != nil {
				log.Printf("panel: 代理探测结果写入失败 %s: %v", proxypool.MaskProxy(addr), merr)
			}
			results[i] = res
		}(i, addr)
	}
	wg.Wait()

	okCount := 0
	for _, res := range results {
		if res.OK {
			okCount++
		}
	}
	log.Printf("panel: 代理探测完成 target=%s 通=%d/%d", target, okCount, len(results))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "target": target, "healthy": okCount, "results": results,
	})
}

// proxiesPurge 一键清除「过期 / 失效」代理。
//
//	POST /panel/api/proxies/purge   {"include_failed_check": true}
//
// 清除对象 = 失效标记的代理（Dead，连续失败自动标记或人工标记）；include_failed_check
// 为 true 时**额外**清除「最近探测不通」的代理（探活已失败、但还没触发自动换代理的）。
// 被清代理的账号分配一并解绑（回直连），相关失败记录与"用过清单"同步清理。
func (p *Panel) proxiesPurge(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	var body struct {
		IncludeFailedCheck *bool `json:"include_failed_check"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
	}
	includeFailed := true // 缺省口径：失效 + 探测不通，都是运维眼里的「过期代理」
	if body.IncludeFailedCheck != nil {
		includeFailed = *body.IncludeFailedCheck
	}
	res, err := pp.PurgeDead(includeFailed)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "落盘失败: "+err.Error())
		return
	}
	log.Printf("panel: 代理池一键清除过期代理 移除=%d 解绑=%d 剩余=%d（含探测不通=%v）",
		len(res.Removed), res.Unbound, res.Kept, includeFailed)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"removed": len(res.Removed),
		"addrs":   res.Removed,
		"unbound": res.Unbound,
		"kept":    res.Kept,
	})
}

// proxiesSkipAll 一键免校验：批量打开（或关闭）代理的「免 TLS 证书校验」标记。
//
//	POST /panel/api/proxies/skipverify_all   {"skip": true, "only_dead": false, "addrs": []}
//
// 典型用法：整池代理都会 MITM 掉 443（证书报错）→ 一键全开；只想给探测不通的那几条
// 开 → only_dead=true。
func (p *Panel) proxiesSkipAll(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	var body struct {
		Skip     *bool    `json:"skip"`
		OnlyDead bool     `json:"only_dead"`
		Addrs    []string `json:"addrs"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)
	}
	skip := true
	if body.Skip != nil {
		skip = *body.Skip
	}
	n, err := pp.SetAllSkipVerify(skip, body.OnlyDead, body.Addrs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("panel: 代理池一键免校验 skip=%v only_dead=%v 变更=%d 条", skip, body.OnlyDead, n)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": n, "skip_verify": skip})
}

// proxiesDead 人工标记 / 取消单个代理的「失效」状态。
//
//	POST /panel/api/proxies/dead   {"addr": "socks5://...", "dead": true, "reason": "人工"}
func (p *Panel) proxiesDead(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	var body struct {
		Addr   string `json:"addr"`
		Dead   *bool  `json:"dead"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "解析请求体失败: "+err.Error())
		return
	}
	dead := true
	if body.Dead != nil {
		dead = *body.Dead
	}
	reason := body.Reason
	if reason == "" {
		reason = "人工标记"
	}
	if err := pp.MarkDead(body.Addr, dead, reason); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("panel: 代理 %s 失效标记=%v（%s）", proxypool.MaskProxy(body.Addr), dead, reason)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "addr": body.Addr, "dead": dead})
}

// proxiesResetFail 清除连续失败记录（uid 为空 = 全部账号）。
//
//	POST /panel/api/proxies/reset_fail   {"uid": "..."}
func (p *Panel) proxiesResetFail(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	var body struct {
		UID string `json:"uid"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
	}
	n, err := pp.ResetFailures(body.UID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "落盘失败: "+err.Error())
		return
	}
	log.Printf("panel: 代理池清除失败记录 uid=%q 条数=%d", body.UID, n)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cleared": n})
}

// proxiesThreshold 设置「连续失败 N 次自动换代理」的阈值。
//
//	POST /panel/api/proxies/threshold   {"n": 3}
func (p *Panel) proxiesThreshold(w http.ResponseWriter, r *http.Request) {
	pp := p.cfg.Proxies
	if pp == nil {
		writeErr(w, http.StatusNotImplemented, "代理池未启用")
		return
	}
	var body struct {
		N int `json:"n"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "解析请求体失败: "+err.Error())
		return
	}
	if err := pp.SetFailThreshold(body.N); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("panel: 代理池连续失败阈值设为 %d", pp.FailThreshold())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "threshold": pp.FailThreshold()})
}

// splitLines 按行切分（兼容 \r\n）。
func splitLines(s string) []string {
	out := make([]string, 0, 8)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start <= len(s)-1 {
		out = append(out, s[start:])
	}
	return out
}
