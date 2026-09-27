package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// sseToolCall 工具调用流的样本（chat 口径：首片带 id/name，后续片只带 arguments 增量）。
const sseToolCall = `data: {"id":"c1","object":"chat.completion.chunk","created":1753600000,"model":"glm-5.2","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"shell","arguments":""}}]}}]}` + "\n\n" +
	`data: {"id":"c1","object":"chat.completion.chunk","created":1753600000,"model":"glm-5.2","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"cmd\":"}}]}}]}` + "\n\n" +
	`data: {"id":"c1","object":"chat.completion.chunk","created":1753600000,"model":"glm-5.2","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"ls\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":7,"completion_tokens":5,"total_tokens":12,"completion_tokens_details":{"reasoning_tokens":3}}}` + "\n\n" +
	"data: [DONE]\n\n"

// respPost 发一个 /v1/responses 请求（可选带 stream），返回记录器。
func respPost(t *testing.T, h *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body)))
	return rec
}

// responsesEvents 把 SSE 输出解析成 (event, payload) 序列。
func responsesEvents(t *testing.T, raw string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, block := range strings.Split(raw, "\n\n") {
		for _, line := range strings.Split(block, "\n") {
			if payload, ok := strings.CutPrefix(line, "data: "); ok {
				var obj map[string]any
				if err := json.Unmarshal([]byte(payload), &obj); err != nil {
					t.Fatalf("事件不是 JSON: %v (%s)", err, payload)
				}
				out = append(out, obj)
			}
		}
	}
	return out
}

// TestResponsesToChatMapping 请求侧翻译：instructions / input items / tools / 档位 / 上限。
func TestResponsesToChatMapping(t *testing.T) {
	body := `{
	  "model": "global:glm-5.2",
	  "instructions": "You are Codex.",
	  "input": [
	    {"type":"message","role":"user","content":[{"type":"input_text","text":"跑一下"}]},
	    {"type":"function_call","name":"shell","arguments":"{\"cmd\":\"ls\"}","call_id":"call_1"},
	    {"type":"function_call","name":"shell","arguments":"{\"cmd\":\"pwd\"}","call_id":"call_2"},
	    {"type":"function_call_output","call_id":"call_1","output":"a.txt"},
	    {"type":"reasoning","summary":[]}
	  ],
	  "tools": [{"type":"function","name":"shell","description":"run","parameters":{"type":"object"}}],
	  "tool_choice": {"type":"function","name":"shell"},
	  "parallel_tool_calls": false,
	  "reasoning": {"effort":"high","summary":"concise"},
	  "max_output_tokens": 4096,
	  "stream": true
	}`
	var req respRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	raw, err := req.toChatBody()
	if err != nil {
		t.Fatal(err)
	}
	var chat map[string]any
	if err := json.Unmarshal(raw, &chat); err != nil {
		t.Fatal(err)
	}
	if chat["model"] != "global:glm-5.2" || chat["stream"] != true {
		t.Fatalf("model/stream 未透传：%+v", chat)
	}
	if chat["reasoning_effort"] != "high" || chat["max_tokens"] != float64(4096) {
		t.Fatalf("档位/上限未映射：%+v", chat)
	}
	msgs := chat["messages"].([]any)
	if len(msgs) != 4 {
		t.Fatalf("messages 数 = %d，期望 4（system + user + 合并后的 assistant + tool）：%+v", len(msgs), msgs)
	}
	if m := msgs[0].(map[string]any); m["role"] != "system" || m["content"] != "You are Codex." {
		t.Fatalf("instructions 未映射为 system：%+v", m)
	}
	if m := msgs[1].(map[string]any); m["role"] != "user" || m["content"] != "跑一下" {
		t.Fatalf("user 消息不符：%+v", m)
	}
	// 连续两条 function_call 必须合并进同一条 assistant 消息（并行工具调用配对）
	asst := msgs[2].(map[string]any)
	if asst["role"] != "assistant" {
		t.Fatalf("第 3 条应为 assistant：%+v", asst)
	}
	tcs := asst["tool_calls"].([]any)
	if len(tcs) != 2 {
		t.Fatalf("连续 function_call 应合并为 2 个 tool_calls：%+v", tcs)
	}
	if tc := tcs[0].(map[string]any); tc["id"] != "call_1" {
		t.Fatalf("tool_call id 未透传：%+v", tc)
	}
	toolMsg := msgs[3].(map[string]any)
	if toolMsg["role"] != "tool" || toolMsg["tool_call_id"] != "call_1" || toolMsg["content"] != "a.txt" {
		t.Fatalf("function_call_output 未映射为 tool 消息：%+v", toolMsg)
	}
	// 工具：扁平 → 嵌套
	tools := chat["tools"].([]any)
	fn := tools[0].(map[string]any)["function"].(map[string]any)
	if fn["name"] != "shell" || fn["description"] != "run" {
		t.Fatalf("工具未转成嵌套形态：%+v", tools[0])
	}
	if tc := chat["tool_choice"].(map[string]any); tc["type"] != "function" ||
		tc["function"].(map[string]any)["name"] != "shell" {
		t.Fatalf("tool_choice 未转成嵌套形态：%+v", tc)
	}
	if chat["parallel_tool_calls"] != false {
		t.Fatalf("parallel_tool_calls 未透传：%+v", chat["parallel_tool_calls"])
	}
}

// TestResponsesStringInputAndDeveloperRole input 为字符串、developer 角色归一。
func TestResponsesStringInputAndDeveloperRole(t *testing.T) {
	var req respRequest
	if err := json.Unmarshal([]byte(`{"model":"m","input":"直接一句话"}`), &req); err != nil {
		t.Fatal(err)
	}
	raw, _ := req.toChatBody()
	var chat map[string]any
	_ = json.Unmarshal(raw, &chat)
	msgs := chat["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["content"] != "直接一句话" {
		t.Fatalf("字符串 input 未映射为单条 user：%+v", msgs)
	}

	var req2 respRequest
	if err := json.Unmarshal([]byte(`{"model":"m","input":[{"type":"message","role":"developer","content":"规则"}]}`), &req2); err != nil {
		t.Fatal(err)
	}
	raw2, _ := req2.toChatBody()
	var chat2 map[string]any
	_ = json.Unmarshal(raw2, &chat2)
	if m := chat2["messages"].([]any)[0].(map[string]any); m["role"] != "system" {
		t.Fatalf("developer 应归一为 system：%+v", m)
	}
}

// TestResponsesStreamingText 流式文本：事件序列 + usage 口径映射。
func TestResponsesStreamingText(t *testing.T) {
	up := newFakeUpstream(t, func(string) (int, string, bool) { return 200, sseOK, true })
	h := NewHandler(Config{
		Pool:     testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}),
		Upstream: up,
	})
	rec := respPost(t, h, `{"model":"glm-5.2","input":[{"type":"message","role":"user","content":"hi"}],"stream":true}`)
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("Content-Type=%q", ct)
	}
	evs := responsesEvents(t, rec.Body.String())
	types := make([]string, 0, len(evs))
	for _, e := range evs {
		types = append(types, e["type"].(string))
	}
	want := []string{"response.created", "response.in_progress", "response.output_item.added",
		"response.content_part.added", "response.output_text.delta", "response.output_text.done",
		"response.content_part.done", "response.output_item.done", "response.completed"}
	if strings.Join(types, ",") != strings.Join(want, ",") {
		t.Fatalf("事件序列不符：\n got %v\nwant %v", types, want)
	}
	// 序号必须严格递增
	for i, e := range evs {
		if int(e["sequence_number"].(float64)) != i {
			t.Fatalf("第 %d 个事件 sequence_number=%v", i, e["sequence_number"])
		}
	}
	if d := evs[4]["delta"]; d != "你好" {
		t.Fatalf("文本增量=%v", d)
	}
	done := evs[8]["response"].(map[string]any)
	if done["status"] != "completed" {
		t.Fatalf("completed 状态=%v", done["status"])
	}
	u := done["usage"].(map[string]any)
	if u["input_tokens"] != float64(1) || u["output_tokens"] != float64(1) || u["total_tokens"] != float64(2) {
		t.Fatalf("usage 映射不符：%+v", u)
	}
	out := done["output"].([]any)
	if len(out) != 1 || out[0].(map[string]any)["type"] != "message" {
		t.Fatalf("output 不符：%+v", out)
	}
	if got := out[0].(map[string]any)["content"].([]any)[0].(map[string]any)["text"]; got != "你好" {
		t.Fatalf("output 文本=%v", got)
	}
}

// TestResponsesStreamingToolCall 流式工具调用：function_call 项 + 参数增量 + 完成后 output 项。
func TestResponsesStreamingToolCall(t *testing.T) {
	up := newFakeUpstream(t, func(string) (int, string, bool) { return 200, sseToolCall, true })
	h := NewHandler(Config{
		Pool:     testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}),
		Upstream: up,
	})
	rec := respPost(t, h, `{"model":"glm-5.2","input":"ls","stream":true,"tools":[{"type":"function","name":"shell","parameters":{}}]}`)
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	evs := responsesEvents(t, rec.Body.String())
	var added, argsDeltas, argsDone int
	var callID, name string
	for _, e := range evs {
		switch e["type"] {
		case "response.output_item.added":
			item := e["item"].(map[string]any)
			if item["type"] == "function_call" {
				added++
				callID, _ = item["call_id"].(string)
				name, _ = item["name"].(string)
			}
		case "response.function_call_arguments.delta":
			argsDeltas++
		case "response.function_call_arguments.done":
			argsDone++
			if e["arguments"] != `{"cmd":"ls"}` {
				t.Fatalf("参数拼接不符：%v", e["arguments"])
			}
		}
	}
	if added != 1 || argsDeltas != 2 || argsDone != 1 {
		t.Fatalf("工具事件计数：added=%d deltas=%d done=%d", added, argsDeltas, argsDone)
	}
	if callID != "call_abc" || name != "shell" {
		t.Fatalf("call_id/name 透传不符：%q %q", callID, name)
	}
	// completed 的 output 必须含 function_call（Codex 据此执行工具）
	last := evs[len(evs)-1]
	if last["type"] != "response.completed" {
		t.Fatalf("末事件=%v", last["type"])
	}
	resp := last["response"].(map[string]any)
	out := resp["output"].([]any)
	if len(out) != 1 {
		t.Fatalf("output=%+v", out)
	}
	item := out[0].(map[string]any)
	if item["type"] != "function_call" || item["name"] != "shell" || item["arguments"] != `{"cmd":"ls"}` ||
		item["call_id"] != "call_abc" || item["status"] != "completed" {
		t.Fatalf("output function_call 不符：%+v", item)
	}
	if u := resp["usage"].(map[string]any); u["total_tokens"] != float64(12) {
		t.Fatalf("usage=%+v", u)
	}
}

// TestResponsesNonStreaming 非流式：chat 聚合结果 → Responses 对象。
func TestResponsesNonStreaming(t *testing.T) {
	up := newFakeUpstream(t, func(string) (int, string, bool) { return 200, sseOK, true })
	h := NewHandler(Config{
		Pool:     testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}),
		Upstream: up,
	})
	rec := respPost(t, h, `{"model":"glm-5.2","input":"hi"}`)
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是 JSON：%v（%s）", err, rec.Body)
	}
	if resp["object"] != "response" || resp["status"] != "completed" {
		t.Fatalf("object/status=%v/%v", resp["object"], resp["status"])
	}
	if !strings.HasPrefix(resp["id"].(string), "resp_") {
		t.Fatalf("id=%v", resp["id"])
	}
	if resp["output_text"] != "你好" {
		t.Fatalf("output_text=%v", resp["output_text"])
	}
	item := resp["output"].([]any)[0].(map[string]any)
	if item["type"] != "message" || item["role"] != "assistant" {
		t.Fatalf("output 项=%+v", item)
	}
	if u := resp["usage"].(map[string]any); u["input_tokens"] != float64(1) || u["output_tokens"] != float64(1) {
		t.Fatalf("usage=%+v", u)
	}
}

// TestResponsesUpstreamErrorPassthrough 上游全失败（非 2xx）时：错误信封与状态码原样透出，
// 不是 SSE（Codex 按 HTTP 错误处理并重试）。
func TestResponsesUpstreamErrorPassthrough(t *testing.T) {
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		return 402, `{"code":1,"msg":"余额不足"}`, false
	})
	h := NewHandler(Config{
		Pool:     testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}),
		Upstream: up,
	})
	rec := respPost(t, h, `{"model":"glm-5.2","input":"hi","stream":true}`)
	if rec.Code == 200 {
		t.Fatalf("上游失败不应 200：%s", rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "event-stream") {
		t.Fatalf("错误路径不应是 SSE：%q", ct)
	}
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("错误体不是 JSON：%v（%s）", err, rec.Body)
	}
	if _, ok := env["error"]; !ok {
		t.Fatalf("错误信封缺 error：%+v", env)
	}
}

// TestResponsesRequiresModel 缺 model → 400（本地校验，不打上游）。
func TestResponsesRequiresModel(t *testing.T) {
	var calls int
	up := newFakeUpstream(t, func(string) (int, string, bool) { calls++; return 200, sseOK, true })
	h := NewHandler(Config{
		Pool:     testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}),
		Upstream: up,
	})
	rec := respPost(t, h, `{"input":"hi"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code=%d", rec.Code)
	}
	if calls != 0 {
		t.Fatalf("本地校验失败不应打上游，calls=%d", calls)
	}
}

// TestResponsesAuthRequired 与 /v1/chat/completions 同鉴权口径（api_key 非空时无密钥 401）。
func TestResponsesAuthRequired(t *testing.T) {
	up := newFakeUpstream(t, func(string) (int, string, bool) { return 200, sseOK, true })
	h := NewHandler(Config{
		Pool:     testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}),
		Upstream: up,
		APIKey:   "secret",
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/responses", bytes.NewReader([]byte(`{"model":"m","input":"hi"}`))))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无密钥应 401，实际 %d", rec.Code)
	}
}
