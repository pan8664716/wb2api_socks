// responses.go Responses API（POST /v1/responses）适配层。
//
// 为什么需要：Codex 0.155+ 的 `model_providers.<id>.wire_api` **只接受 "responses"**
// （官方配置参考原文："`responses` is the only supported value"，实测旧值 `chat` 会
// 直接报 "no longer supported" 拒绝加载配置），而本网关上游是 Chat Completions 口径
// （只实现 /v1/chat/completions）。于是这里做一层双向翻译：
//
//	Responses 请求 ──▶ Chat Completions 请求 ──▶ 复用既有 chatCompletions
//	                                              （选号 / 轮转 / 冷却 / 粘性 /
//	                                               SSE 重建 / 用量记录全不变）
//	Chat Completions 响应 ──▶ Responses 响应（含流式事件序列）
//
// 复用方式：内部把翻译后的请求交给 h.chatCompletions（同一 Handler），用 io.Pipe
// 捕获它的输出（SSE 帧或 JSON 体）再逐帧翻译。这样不改动那条已被真实流量打磨过的
// 轮转主链路——适配层只做「协议翻译」，不做调度。
package server

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 请求侧：Responses → Chat Completions
// ---------------------------------------------------------------------------

// respRequest Responses API 请求体中本适配层关心的字段（其余字段按需忽略：
// store/include/metadata/previous_response_id/truncation/service_tier/safety_identifier）。
type respRequest struct {
	Model             string          `json:"model"`
	Instructions      string          `json:"instructions"`
	Input             json.RawMessage `json:"input"`
	Tools             []respTool      `json:"tools"`
	ToolChoice        json.RawMessage `json:"tool_choice"`
	ParallelToolCalls *bool           `json:"parallel_tool_calls"`
	Reasoning         *respReasoning  `json:"reasoning"`
	MaxOutputTokens   int             `json:"max_output_tokens"`
	Temperature       *float64        `json:"temperature"`
	TopP              *float64        `json:"top_p"`
	Stream            bool            `json:"stream"`
	PromptCacheKey    string          `json:"prompt_cache_key"`
}

type respReasoning struct {
	Effort  string `json:"effort"`
	Summary string `json:"summary"`
}

// respTool Responses 的工具是**扁平**形态（{type:"function", name, description, parameters}），
// 与 Chat Completions 的嵌套形态（{type:"function", function:{...}}）不同，需转换。
type respTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
	Strict      *bool           `json:"strict"`
	// 命名空间工具（type="namespace"，Codex 多代理协作工具就长这样）：
	// 名字在 Name，内嵌工具在 Tools。chat 口径没有这个概念，需要拍平/还原。
	Namespace string     `json:"namespace,omitempty"`
	Tools     []respTool `json:"tools,omitempty"`
	// 自由格式工具（type="custom"，如 apply_patch）的语法描述，chat 口径无对应形态。
	Format json.RawMessage `json:"format,omitempty"`
}

// respInputItem Responses 的 input 数组元素（只列需要处理的类型）。
type respInputItem struct {
	Type      string          `json:"type"` // message / function_call / function_call_output / reasoning / item_reference
	Role      string          `json:"role"`
	Content   json.RawMessage `json:"content"`
	Name      string          `json:"name"`
	Namespace string          `json:"namespace"` // 命名空间工具的归属（如 collaboration）
	Arguments string          `json:"arguments"`
	CallID    string          `json:"call_id"`
	Output    json.RawMessage `json:"output"`
}

// toChatBody 把 Responses 请求翻译成 Chat Completions 请求体。
func (req respRequest) toChatBody() ([]byte, error) {
	msgs := make([]any, 0, 8)
	if s := strings.TrimSpace(req.Instructions); s != "" {
		msgs = append(msgs, map[string]any{"role": "system", "content": s})
	}
	inputMsgs, err := inputToMessages(req.Input)
	if err != nil {
		return nil, err
	}
	msgs = append(msgs, inputMsgs...)

	body := map[string]any{
		"model":    req.Model,
		"messages": msgs,
		"stream":   req.Stream,
	}
	if tools := respToolsToChat(req.Tools); len(tools) > 0 {
		body["tools"] = tools
		if tc := respToolChoiceToChat(req.ToolChoice); tc != nil {
			body["tool_choice"] = tc
		}
	}
	if req.ParallelToolCalls != nil {
		body["parallel_tool_calls"] = *req.ParallelToolCalls
	}
	if req.Reasoning != nil && req.Reasoning.Effort != "" {
		// 档位合法性/降级由网关既有 reasoning 归一化处理（不认识的值会被夹到合法档）。
		body["reasoning_effort"] = req.Reasoning.Effort
	}
	if req.MaxOutputTokens > 0 {
		body["max_tokens"] = req.MaxOutputTokens
	}
	if req.Temperature != nil {
		body["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		body["top_p"] = *req.TopP
	}
	if req.PromptCacheKey != "" {
		body["prompt_cache_key"] = req.PromptCacheKey
	}
	return json.Marshal(body)
}

// inputToMessages 把 input（字符串或 item 数组）翻译成 chat messages。
//
// 关键映射：
//   - message 项 → 同名 role 的 chat 消息（developer → system，网关侧也会再归一）；
//   - function_call 项 → assistant 消息的 tool_calls（**连续多条合并进同一条
//     assistant 消息**：并行工具调用在 chat 口径里就是一条消息带多个 tool_calls，
//     拆成多条会破坏配对）；
//   - function_call_output 项 → role=tool 消息；
//   - reasoning / item_reference → 跳过（加密推理内容对上游无意义，网关自带思维链注入）。
func inputToMessages(raw json.RawMessage) ([]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []any{map[string]any{"role": "user", "content": s}}, nil
	}
	var items []respInputItem
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("input 解析失败: %w", err)
	}
	msgs := make([]any, 0, len(items))
	var pending []any // 连续的 function_call 先攒着，遇到非 function_call 项再合并落地
	flush := func() {
		if len(pending) > 0 {
			msgs = append(msgs, map[string]any{"role": "assistant", "content": "", "tool_calls": pending})
			pending = nil
		}
	}
	for _, it := range items {
		switch it.Type {
		case "function_call":
			name := it.Name
			if it.Namespace != "" {
				// 历史里的命名空间调用要拍回 chat 的工具名，否则与 tools 列表对不上。
				name = flattenNSName(it.Namespace, it.Name)
			}
			pending = append(pending, map[string]any{
				"id": it.CallID, "type": "function",
				"function": map[string]any{"name": name, "arguments": it.Arguments},
			})
		case "function_call_output":
			flush()
			msgs = append(msgs, map[string]any{
				"role": "tool", "tool_call_id": it.CallID, "content": textOf(it.Output),
			})
		case "reasoning", "item_reference":
			// 跳过
		default: // "message" 或空 type
			flush()
			role := it.Role
			if role == "" {
				role = "user"
			}
			if role == "developer" {
				role = "system"
			}
			content, err := contentToChat(it.Content)
			if err != nil {
				return nil, err
			}
			msgs = append(msgs, map[string]any{"role": role, "content": content})
		}
	}
	flush()
	return msgs, nil
}

// contentToChat 把 Responses 的 content（字符串或 part 数组）翻译成 chat content。
// 全文本 → 直接拼成字符串（上游最省事）；含图片 → 输出 chat 的 parts 数组。
func contentToChat(raw json.RawMessage) (any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, nil
	}
	var parts []struct {
		Type     string `json:"type"`
		Text     string `json:"text"`
		ImageURL string `json:"image_url"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return "", fmt.Errorf("content 解析失败: %w", err)
	}
	hasImage := false
	var sb strings.Builder
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		switch p.Type {
		case "input_text", "output_text", "text", "":
			sb.WriteString(p.Text)
			out = append(out, map[string]any{"type": "text", "text": p.Text})
		case "input_image", "image_url":
			hasImage = true
			out = append(out, map[string]any{"type": "image_url", "image_url": map[string]any{"url": p.ImageURL}})
		}
	}
	if !hasImage {
		return sb.String(), nil
	}
	return out, nil
}

// textOf 取 Responses 里的文本载体（字符串，或 part 数组里的 text 拼接）。
func textOf(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		var sb strings.Builder
		for _, p := range parts {
			sb.WriteString(p.Text)
		}
		return sb.String()
	}
	return string(raw)
}

// ---------------------------------------------------------------------------
// 命名空间工具（namespace）拍平 / 还原
//
// Codex 的多代理协作工具（spawn_agent / send_message / followup_task /
// wait_agent / interrupt_agent / list_agents）在 Responses 口径里是**一个整体**：
//
//	{"type":"namespace","name":"collaboration","tools":[{...spawn_agent...}, ...]}
//
// 调用回来时 function_call 项带 `"namespace":"collaboration"`。Chat Completions 没有
// 命名空间概念，且 function.name 只允许 [a-zA-Z0-9_-]{1,64}（不能出现 '.'），所以：
//
//	上行：namespace 工具逐条拍平成 function，名字 <namespace>__<tool>
//	下行：按拍平名反查，还原出 name + namespace 两个字段
//
// 少了这一步：上行整包被丢弃（模型根本看不到 spawn_agent 等工具），下行丢 namespace
// 字段（Codex 按默认命名空间查表 → router 报 "unsupported call: spawn_agent"）。
// ---------------------------------------------------------------------------

const nsSep = "__"

type nsToolRef struct{ Namespace, Name string }

// nsToolIndex 拍平名 → 原名映射（只收 namespace 工具的内嵌条目）。
type nsToolIndex map[string]nsToolRef

func flattenNSName(namespace, name string) string { return namespace + nsSep + name }

func buildNSToolIndex(tools []respTool) nsToolIndex {
	idx := nsToolIndex{}
	for _, t := range tools {
		if t.Type != "namespace" {
			continue
		}
		for _, inner := range t.Tools {
			if inner.Name == "" {
				continue
			}
			idx[flattenNSName(t.Name, inner.Name)] = nsToolRef{Namespace: t.Name, Name: inner.Name}
		}
	}
	return idx
}

// resolveToolName 把上游回来的 function 名拆回 (namespace, name)；非命名空间工具返回 ("", 原名)。
func (idx nsToolIndex) resolveToolName(flat string) (string, string) {
	if ref, ok := idx[flat]; ok {
		return ref.Namespace, ref.Name
	}
	return "", flat
}

// respToolsToChat 扁平工具 → chat 嵌套工具。
//   - type="function"（或空）原样转换；
//   - type="namespace" 逐条拍平成 function（名字 <namespace>__<tool>），响应侧再还原；
//   - 其余类型（custom / web_search / mcp 等）chat 口径无对应形态，跳过。
func respToolsToChat(tools []respTool) []any {
	out := make([]any, 0, len(tools))
	for _, t := range tools {
		switch t.Type {
		case "namespace":
			for _, inner := range t.Tools {
				if fn := chatFunction(flattenNSName(t.Name, inner.Name), inner); fn != nil {
					out = append(out, fn)
				}
			}
		case "", "function":
			if fn := chatFunction(t.Name, t); fn != nil {
				out = append(out, fn)
			}
		}
	}
	return out
}

// chatFunction 单个 function 工具 → chat 嵌套形态；名字为空返回 nil。
func chatFunction(name string, t respTool) map[string]any {
	if name == "" {
		return nil
	}
	fn := map[string]any{"name": name}
	if t.Description != "" {
		fn["description"] = t.Description
	}
	if len(t.Parameters) > 0 {
		fn["parameters"] = json.RawMessage(t.Parameters)
	}
	if t.Strict != nil {
		fn["strict"] = *t.Strict
	}
	return map[string]any{"type": "function", "function": fn}
}

// respToolChoiceToChat "auto"/"none"/"required" 原样透传；{type:"function",name} → 嵌套形态。
func respToolChoiceToChat(raw json.RawMessage) any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.Type == "function" && obj.Name != "" {
		return map[string]any{"type": "function", "function": map[string]any{"name": obj.Name}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// 响应侧：Chat Completions → Responses
// ---------------------------------------------------------------------------

// newResponseID 生成 Responses 响应 id（resp_<24hex>）。
func newResponseID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("resp_%d", time.Now().UnixNano())
	}
	return "resp_" + hex.EncodeToString(b)
}

func newItemID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(b)
}

// usageToResponses chat usage → Responses usage 口径（含 details 子对象）。
func usageToResponses(u map[string]any) map[string]any {
	if u == nil {
		return nil
	}
	num := func(m map[string]any, k string) (float64, bool) {
		v, ok := m[k].(float64)
		return v, ok
	}
	out := map[string]any{}
	if v, ok := num(u, "prompt_tokens"); ok {
		out["input_tokens"] = v
	}
	if v, ok := num(u, "completion_tokens"); ok {
		out["output_tokens"] = v
	}
	if v, ok := num(u, "total_tokens"); ok {
		out["total_tokens"] = v
	}
	inDetails := map[string]any{}
	if d, ok := u["prompt_tokens_details"].(map[string]any); ok {
		if v, ok := num(d, "cached_tokens"); ok {
			inDetails["cached_tokens"] = v
		}
	}
	if v, ok := num(u, "prompt_cache_hit_tokens"); ok && inDetails["cached_tokens"] == nil {
		inDetails["cached_tokens"] = v
	}
	if len(inDetails) > 0 {
		out["input_tokens_details"] = inDetails
	}
	outDetails := map[string]any{}
	if d, ok := u["completion_tokens_details"].(map[string]any); ok {
		if v, ok := num(d, "reasoning_tokens"); ok {
			outDetails["reasoning_tokens"] = v
		}
	}
	if len(outDetails) > 0 {
		out["output_tokens_details"] = outDetails
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// messageToOutputItems 把一条 chat message 翻译成 Responses 的 output 项数组
// （文本消息一项 + 每个 tool_call 一项）。
// ns 用于把拍平的命名空间工具名还原成 name + namespace（Codex 多代理工具必需）。
func messageToOutputItems(msg map[string]any, ns nsToolIndex) []any {
	out := make([]any, 0, 2)
	if s, _ := msg["content"].(string); strings.TrimSpace(s) != "" {
		out = append(out, map[string]any{
			"type": "message", "id": newItemID("msg"), "status": "completed", "role": "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": s, "annotations": []any{}}},
		})
	}
	if tcs, ok := msg["tool_calls"].([]any); ok {
		for _, raw := range tcs {
			tc, _ := raw.(map[string]any)
			if tc == nil {
				continue
			}
			fn, _ := tc["function"].(map[string]any)
			name, args := "", ""
			if fn != nil {
				name, _ = fn["name"].(string)
				args, _ = fn["arguments"].(string)
			}
			callID, _ := tc["id"].(string)
			if callID == "" {
				callID = newItemID("call")
			}
			item := map[string]any{
				"type": "function_call", "id": newItemID("fc"), "call_id": callID,
				"name": name, "arguments": args, "status": "completed",
			}
			if namespace, plain := ns.resolveToolName(name); namespace != "" {
				item["name"] = plain
				item["namespace"] = namespace
				// 协作类工具的明文参数走这个标记（Codex 用它区分明文/加密参数）。
				item["encrypted_function_args"] = []any{}
			}
			out = append(out, item)
		}
	}
	return out
}

// chatToResponses 非流式：chat completion JSON → Responses 响应对象。
func chatToResponses(raw []byte, req respRequest, respID string) (map[string]any, error) {
	var chat map[string]any
	if err := json.Unmarshal(raw, &chat); err != nil {
		return nil, fmt.Errorf("上游响应解析失败: %w", err)
	}
	output := []any{}
	var usage map[string]any
	if choices, ok := chat["choices"].([]any); ok && len(choices) > 0 {
		if ch, ok := choices[0].(map[string]any); ok {
			if msg, ok := ch["message"].(map[string]any); ok {
				output = messageToOutputItems(msg, buildNSToolIndex(req.Tools))
			}
		}
	}
	if u, ok := chat["usage"].(map[string]any); ok {
		usage = usageToResponses(u)
	}
	model, _ := chat["model"].(string)
	if model == "" {
		model = req.Model
	}
	resp := map[string]any{
		"id":         respID,
		"object":     "response",
		"created_at": time.Now().Unix(),
		"status":     "completed",
		"model":      model,
		"output":     output,
		"output_text": func() string {
			var sb strings.Builder
			for _, item := range output {
				if m, ok := item.(map[string]any); ok && m["type"] == "message" {
					if parts, ok := m["content"].([]any); ok {
						for _, p := range parts {
							if pm, ok := p.(map[string]any); ok {
								if s, ok := pm["text"].(string); ok {
									sb.WriteString(s)
								}
							}
						}
					}
				}
			}
			return sb.String()
		}(),
		"parallel_tool_calls": true,
	}
	if req.Instructions != "" {
		resp["instructions"] = req.Instructions
	}
	if tools := respToolsToChat(req.Tools); len(tools) > 0 {
		resp["tools"] = tools
		if tc := respToolChoiceToChat(req.ToolChoice); tc != nil {
			resp["tool_choice"] = tc
		}
	}
	if req.ParallelToolCalls != nil {
		resp["parallel_tool_calls"] = *req.ParallelToolCalls
	}
	if usage != nil {
		resp["usage"] = usage
	}
	return resp, nil
}

// ---------------------------------------------------------------------------
// 流式翻译
// ---------------------------------------------------------------------------

// responsesStreamer 把 chat SSE 帧序列翻译成 Responses 事件序列。
//
// 事件序列（与 OpenAI Responses 流式协议对齐，Codex 按 JSON 里的 type 字段解析）：
//
//	response.created → (文本) response.output_item.added / content_part.added
//	                → response.output_text.delta* → output_text.done / content_part.done
//	                → response.output_item.done
//	                → (工具调用) output_item.added(function_call)
//	                → response.function_call_arguments.delta* → ...done → output_item.done
//	                → response.completed
//
// 文本项与工具项都按「首次出现顺序」分配 output_index（Responses 的 output 数组顺序）。
type responsesStreamer struct {
	w        http.ResponseWriter
	fl       http.Flusher
	req      respRequest
	respID   string
	created  int64
	seq      int
	started  bool
	failed   bool
	finish   string
	usage    map[string]any
	output   []any // 已完成的 output 项（按 output_index 顺序）
	nextIdx  int
	textIdx  int
	textID   string
	textOpen bool
	textBuf  strings.Builder
	toolIDs  map[int]string
	toolIdx  map[int]int
	toolName map[int]string
	toolNS   map[int]string // 每个工具项的命名空间（空串=普通 function）
	toolArgs map[int]*strings.Builder
	callIDs  map[int]string
	toolSeq  []int
	ns       nsToolIndex // 拍平名 → 原名（命名空间工具还原用）
}

func newResponsesStreamer(w http.ResponseWriter, fl http.Flusher, req respRequest, respID string) *responsesStreamer {
	return &responsesStreamer{
		w: w, fl: fl, req: req, respID: respID, created: time.Now().Unix(),
		toolIDs: map[int]string{}, toolIdx: map[int]int{}, toolName: map[int]string{},
		toolNS: map[int]string{}, toolArgs: map[int]*strings.Builder{}, callIDs: map[int]string{},
		textIdx: -1, ns: buildNSToolIndex(req.Tools),
	}
}

// emit 写一个 Responses 事件（event: <type> + data: <json>），带递增 sequence_number。
func (s *responsesStreamer) emit(event string, payload map[string]any) {
	payload["type"] = event
	payload["sequence_number"] = s.seq
	s.seq++
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = io.WriteString(s.w, "event: "+event+"\ndata: ")
	_, _ = s.w.Write(raw)
	_, _ = io.WriteString(s.w, "\n\n")
	if s.fl != nil {
		s.fl.Flush()
	}
}

// responseObject 构造 response 对象（created/completed 事件共用）。
func (s *responsesStreamer) responseObject(status string) map[string]any {
	model := s.req.Model
	obj := map[string]any{
		"id": s.respID, "object": "response", "created_at": s.created,
		"status": status, "model": model,
		"output":              append([]any(nil), s.output...),
		"parallel_tool_calls": true,
	}
	if s.req.Instructions != "" {
		obj["instructions"] = s.req.Instructions
	}
	if tools := respToolsToChat(s.req.Tools); len(tools) > 0 {
		obj["tools"] = tools
		if tc := respToolChoiceToChat(s.req.ToolChoice); tc != nil {
			obj["tool_choice"] = tc
		}
	}
	if s.req.ParallelToolCalls != nil {
		obj["parallel_tool_calls"] = *s.req.ParallelToolCalls
	}
	if s.usage != nil {
		obj["usage"] = s.usage
	}
	return obj
}

func (s *responsesStreamer) start() {
	if s.started {
		return
	}
	s.started = true
	s.emit("response.created", map[string]any{"response": s.responseObject("in_progress")})
	s.emit("response.in_progress", map[string]any{"response": s.responseObject("in_progress")})
}

// ensureTextItem 在首个文本增量到达时创建 message 项与 content part。
func (s *responsesStreamer) ensureTextItem() {
	if s.textOpen {
		return
	}
	s.textOpen = true
	s.textIdx = s.nextIdx
	s.nextIdx++
	s.textID = newItemID("msg")
	s.emit("response.output_item.added", map[string]any{
		"output_index": s.textIdx,
		"item": map[string]any{
			"type": "message", "id": s.textID, "status": "in_progress",
			"role": "assistant", "content": []any{},
		},
	})
	s.emit("response.content_part.added", map[string]any{
		"item_id": s.textID, "output_index": s.textIdx, "content_index": 0,
		"part": map[string]any{"type": "output_text", "text": "", "annotations": []any{}},
	})
}

// closeTextItem 收尾文本项（output_text.done → content_part.done → output_item.done）。
func (s *responsesStreamer) closeTextItem() {
	if !s.textOpen {
		return
	}
	s.textOpen = false
	text := s.textBuf.String()
	s.emit("response.output_text.done", map[string]any{
		"item_id": s.textID, "output_index": s.textIdx, "content_index": 0, "text": text,
	})
	s.emit("response.content_part.done", map[string]any{
		"item_id": s.textID, "output_index": s.textIdx, "content_index": 0,
		"part": map[string]any{"type": "output_text", "text": text, "annotations": []any{}},
	})
	item := map[string]any{
		"type": "message", "id": s.textID, "status": "completed", "role": "assistant",
		"content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}},
	}
	s.output = append(s.output, item)
	s.emit("response.output_item.done", map[string]any{"output_index": s.textIdx, "item": item})
}

// handleChunk 处理一帧 chat chunk。
func (s *responsesStreamer) handleChunk(chunk map[string]any) {
	if _, hasErr := chunk["error"]; hasErr {
		s.fail(chunk["error"])
		return
	}
	if u, ok := chunk["usage"].(map[string]any); ok {
		if mapped := usageToResponses(u); mapped != nil {
			s.usage = mapped
		}
	}
	choices, ok := chunk["choices"].([]any)
	if !ok || len(choices) == 0 {
		return
	}
	ch, _ := choices[0].(map[string]any)
	if ch == nil {
		return
	}
	if fr, ok := ch["finish_reason"].(string); ok && fr != "" {
		s.finish = fr
	}
	delta, _ := ch["delta"].(map[string]any)
	if delta == nil {
		return
	}
	if c, ok := delta["content"].(string); ok && c != "" {
		s.ensureTextItem()
		s.textBuf.WriteString(c)
		s.emit("response.output_text.delta", map[string]any{
			"item_id": s.textID, "output_index": s.textIdx, "content_index": 0, "delta": c,
		})
	}
	if tcs, ok := delta["tool_calls"].([]any); ok {
		for _, raw := range tcs {
			tc, _ := raw.(map[string]any)
			if tc == nil {
				continue
			}
			idx := 0
			if v, ok := tc["index"].(float64); ok {
				idx = int(v)
			}
			fn, _ := tc["function"].(map[string]any)
			if _, seen := s.toolIDs[idx]; !seen {
				// 首个工具调用片：文本项先收尾（顺序与模型输出一致）
				s.closeTextItem()
				id := newItemID("fc")
				s.toolIDs[idx] = id
				s.toolIdx[idx] = s.nextIdx
				s.nextIdx++
				s.toolSeq = append(s.toolSeq, idx)
				callID, _ := tc["id"].(string)
				if callID == "" {
					callID = newItemID("call")
				}
				name := ""
				if fn != nil {
					name, _ = fn["name"].(string)
				}
				namespace, plain := s.ns.resolveToolName(name)
				s.toolName[idx] = plain
				s.toolNS[idx] = namespace
				s.callIDs[idx] = callID
				s.toolArgs[idx] = &strings.Builder{}
				item := map[string]any{
					"type": "function_call", "id": id, "call_id": callID,
					"name": plain, "arguments": "", "status": "in_progress",
				}
				if namespace != "" {
					item["namespace"] = namespace
					item["encrypted_function_args"] = []any{}
				}
				s.emit("response.output_item.added", map[string]any{
					"output_index": s.toolIdx[idx],
					"item":         item,
				})
			}
			if fn != nil {
				if args, ok := fn["arguments"].(string); ok && args != "" {
					s.toolArgs[idx].WriteString(args)
					s.emit("response.function_call_arguments.delta", map[string]any{
						"item_id": s.toolIDs[idx], "output_index": s.toolIdx[idx], "delta": args,
					})
				}
			}
		}
	}
}

// closeToolItems 收尾全部工具项（arguments.done → output_item.done），按出现顺序。
func (s *responsesStreamer) closeToolItems() {
	for _, idx := range s.toolSeq {
		id := s.toolIDs[idx]
		args := ""
		if b := s.toolArgs[idx]; b != nil {
			args = b.String()
		}
		s.emit("response.function_call_arguments.done", map[string]any{
			"item_id": id, "output_index": s.toolIdx[idx], "arguments": args,
		})
		callID := s.callIDs[idx]
		if callID == "" {
			callID = id
		}
		item := map[string]any{
			"type": "function_call", "id": id, "call_id": callID, "name": s.toolName[idx],
			"arguments": args, "status": "completed",
		}
		if namespace := s.toolNS[idx]; namespace != "" {
			item["namespace"] = namespace
			item["encrypted_function_args"] = []any{}
		}
		s.output = append(s.output, item)
		s.emit("response.output_item.done", map[string]any{"output_index": s.toolIdx[idx], "item": item})
	}
	s.toolSeq = nil
}

// fail 上游在流中返回错误帧：发 response.failed 并标记（调用方随后收尾）。
func (s *responsesStreamer) fail(errVal any) {
	s.failed = true
	resp := s.responseObject("failed")
	msg := ""
	if m, ok := errVal.(map[string]any); ok {
		if v, ok := m["message"].(string); ok {
			msg = v
		}
	}
	if msg == "" {
		msg = "upstream error"
	}
	resp["error"] = map[string]any{"code": "upstream_error", "message": msg}
	s.emit("response.failed", map[string]any{"response": resp})
}

// run 读 chat SSE 帧并逐帧翻译；结束时收尾并写 response.completed。
func (s *responsesStreamer) run(br *bufio.Reader) {
	s.start()
	for {
		line, err := br.ReadString('\n')
		if trimmed := strings.TrimRight(line, "\r\n"); trimmed != "" {
			if payload, ok := strings.CutPrefix(trimmed, "data: "); ok {
				if payload == "[DONE]" {
					break
				}
				var chunk map[string]any
				if json.Unmarshal([]byte(payload), &chunk) == nil {
					s.handleChunk(chunk)
				}
			}
		}
		if err != nil {
			break
		}
	}
	if s.failed {
		return
	}
	s.closeTextItem()
	s.closeToolItems()
	s.emit("response.completed", map[string]any{"response": s.responseObject("completed")})
}

// ---------------------------------------------------------------------------
// HTTP 入口
// ---------------------------------------------------------------------------

// captureWriter 捕获内部 chatCompletions 的输出（写侧经 io.Pipe 交给翻译层）。
// io.Pipe 的写本身是同步投递（无缓冲），因此 Flush 为空实现即已满足逐帧实时性。
type captureWriter struct {
	mu     sync.Mutex
	hdr    http.Header
	status int
	pw     *io.PipeWriter
}

func (c *captureWriter) Header() http.Header { return c.hdr }

func (c *captureWriter) WriteHeader(code int) {
	c.mu.Lock()
	if c.status == 0 {
		c.status = code
	}
	c.mu.Unlock()
}

func (c *captureWriter) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.status == 0 {
		c.status = http.StatusOK
	}
	c.mu.Unlock()
	return c.pw.Write(b)
}

func (c *captureWriter) Flush() {}

func (c *captureWriter) Status() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// responses POST /v1/responses：Responses API 入口（Codex 等客户端）。
func (h *Handler) responses(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "read body: "+err.Error())
		return
	}
	var req respRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "请求体解析失败: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Model) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "缺少 model")
		return
	}
	chatBody, err := req.toChatBody()
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// 复用既有 chat 主链路：同一 Handler、同一鉴权上下文（withAuth 已在外层完成）、
	// 同一 clientIP 提取，选号/轮转/冷却/粘性/用量记录全部走原路径。
	r2 := r.Clone(r.Context())
	r2.Body = io.NopCloser(bytes.NewReader(chatBody))
	r2.ContentLength = int64(len(chatBody))
	r2.Header.Set("Content-Type", "application/json")

	pr, pw := io.Pipe()
	cw := &captureWriter{hdr: make(http.Header), pw: pw}
	go func() {
		defer pw.Close()
		h.chatCompletions(cw, r2)
	}()

	respID := newResponseID()
	if !req.Stream {
		raw, rerr := io.ReadAll(pr)
		if rerr != nil {
			writeOpenAIError(w, http.StatusBadGateway, "upstream_error", "内部响应读取失败: "+rerr.Error())
			return
		}
		if st := cw.Status(); st >= 400 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(st)
			_, _ = w.Write(raw)
			return
		}
		out, cerr := chatToResponses(raw, req, respID)
		if cerr != nil {
			writeOpenAIError(w, http.StatusBadGateway, "upstream_parse", cerr.Error())
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	br := bufio.NewReaderSize(pr, 1<<16)
	// 流 / 错误分流：以内部 handler 的 HTTP 状态为权威信号。
	//
	// 不能只看首字节判 SSE——网关的 SSE 流以 `: heartbeat` **注释行**开头（保活，
	// 见 upstream.StreamHint 前的保活帧），首字节是 ':' 而非 'd'；按首字节判定会把
	// 正常流误判成错误体（实测：Codex 收到 502 + 整段 SSE 原文）。
	// 状态 >=400 才是错误路径（内部 handler 以 JSON 错误信封 + 状态码返回）→ 原样透出，
	// 客户端（Codex）按 OpenAI 错误信封处理与重试。
	// Peek 在这里的作用是**同步**：它阻塞到内部 handler 写出首字节为止（WriteHeader 必
	// 先于 Write），此时 cw.Status() 才是最终值；否则会与写侧竞态读到 0 → 把错误体当流。
	head, perr := br.Peek(1)
	if len(head) == 0 && perr != nil {
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", "空响应")
		return
	}
	if st := cw.Status(); st >= 400 {
		raw, _ := io.ReadAll(br)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		_, _ = w.Write(raw)
		return
	}

	hdr := w.Header()
	hdr.Set("Content-Type", "text/event-stream")
	hdr.Set("Cache-Control", "no-cache")
	hdr.Set("Connection", "keep-alive")
	hdr.Set("X-Accel-Buffering", "no")
	fl, _ := w.(http.Flusher)
	w.WriteHeader(http.StatusOK)
	newResponsesStreamer(w, fl, req, respID).run(br)
}
