package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// nsToolRequest Codex 多代理场景的请求样本：一个 namespace 工具 + 一条带 namespace 的历史调用。
const nsToolRequest = `{
  "model": "deepseek-flash",
  "input": [
    {"type":"message","role":"user","content":"派个子代理"},
    {"type":"function_call","name":"spawn_agent","namespace":"collaboration","arguments":"{\"task_name\":\"w\"}","call_id":"call_1"},
    {"type":"function_call_output","call_id":"call_1","output":"done"}
  ],
  "tools": [
    {"type":"function","name":"exec_command","parameters":{"type":"object"}},
    {"type":"namespace","name":"collaboration","description":"Tools for spawning and managing sub-agents.",
     "tools":[
       {"type":"function","name":"spawn_agent","parameters":{"type":"object","properties":{"message":{"type":"string","encrypted":true}}}},
       {"type":"function","name":"list_agents","parameters":{"type":"object"}}
     ]}
  ],
  "stream": false
}`

// nsToolSSE 上游流式样本：模型调用了拍平后的 collaboration__spawn_agent。
const nsToolSSE = `data: {"id":"c1","object":"chat.completion.chunk","created":1753600000,"model":"deepseek-flash","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"collaboration__spawn_agent","arguments":""}}]}}]}` + "\n\n" +
	`data: {"id":"c1","object":"chat.completion.chunk","created":1753600000,"model":"deepseek-flash","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"task_name\":\"w\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}` + "\n\n" +
	"data: [DONE]\n\n"

// TestResponsesNamespaceToolsFlatten 上行：namespace 工具逐条拍平，历史里的命名空间调用拍回同一名字。
func TestResponsesNamespaceToolsFlatten(t *testing.T) {
	var req respRequest
	if err := json.Unmarshal([]byte(nsToolRequest), &req); err != nil {
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
	tools := chat["tools"].([]any)
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.(map[string]any)["function"].(map[string]any)["name"].(string))
	}
	want := "exec_command,collaboration__spawn_agent,collaboration__list_agents"
	if strings.Join(names, ",") != want {
		t.Fatalf("工具拍平结果不符：\n got %v\nwant %s", names, want)
	}
	// 内嵌 schema 原样保留（含 encrypted 标记）
	spawn := tools[1].(map[string]any)["function"].(map[string]any)["parameters"].(map[string]any)
	if _, ok := spawn["properties"].(map[string]any)["message"]; !ok {
		t.Fatalf("内嵌参数 schema 丢失：%+v", spawn)
	}
	// 历史 function_call 必须拍回 collaboration__spawn_agent，否则与 tools 列表对不上
	msgs := chat["messages"].([]any)
	asst := msgs[1].(map[string]any)
	if asst["role"] != "assistant" {
		t.Fatalf("第 2 条应为 assistant：%+v", asst)
	}
	tc := asst["tool_calls"].([]any)[0].(map[string]any)
	if got := tc["function"].(map[string]any)["name"]; got != "collaboration__spawn_agent" {
		t.Fatalf("历史命名空间调用未拍平：%v", got)
	}
}

// TestResponsesNamespaceToolCallNonStream 下行（非流式）：拍平名还原成 name + namespace。
func TestResponsesNamespaceToolCallNonStream(t *testing.T) {
	// 网关内部对上游恒用流式，客户端非流式时由适配层把 SSE 聚合成 JSON。
	up := newFakeUpstream(t, func(string) (int, string, bool) { return 200, nsToolSSE, true })
	h := NewHandler(Config{
		Pool:     testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}),
		Upstream: up,
	})
	rec := respPost(t, h, nsToolRequest)
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是 JSON：%v（%s）", err, rec.Body)
	}
	out := resp["output"].([]any)
	if len(out) != 1 {
		t.Fatalf("output 项数=%d：%+v", len(out), out)
	}
	item := out[0].(map[string]any)
	if item["type"] != "function_call" || item["name"] != "spawn_agent" ||
		item["namespace"] != "collaboration" || item["call_id"] != "call_abc" {
		t.Fatalf("命名空间未还原：%+v", item)
	}
	if args, ok := item["encrypted_function_args"].([]any); !ok || len(args) != 0 {
		t.Fatalf("明文参数标记缺失：%+v", item["encrypted_function_args"])
	}
}

// TestResponsesNamespaceToolCallStream 下行（流式）：output_item.added / done 都带 namespace。
func TestResponsesNamespaceToolCallStream(t *testing.T) {
	up := newFakeUpstream(t, func(string) (int, string, bool) { return 200, nsToolSSE, true })
	h := NewHandler(Config{
		Pool:     testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}),
		Upstream: up,
	})
	rec := respPost(t, h, strings.Replace(nsToolRequest, `"stream": false`, `"stream": true`, 1))
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	evs := responsesEvents(t, rec.Body.String())
	var added, done map[string]any
	for _, e := range evs {
		switch e["type"] {
		case "response.output_item.added":
			if item, ok := e["item"].(map[string]any); ok && item["type"] == "function_call" {
				added = item
			}
		case "response.output_item.done":
			if item, ok := e["item"].(map[string]any); ok && item["type"] == "function_call" {
				done = item
			}
		}
	}
	for label, item := range map[string]map[string]any{"added": added, "done": done} {
		if item == nil {
			t.Fatalf("%s 事件缺 function_call 项", label)
		}
		if item["name"] != "spawn_agent" || item["namespace"] != "collaboration" {
			t.Fatalf("%s 命名空间未还原：%+v", label, item)
		}
	}
	if done["arguments"] != `{"task_name":"w"}` {
		t.Fatalf("参数拼接不符：%v", done["arguments"])
	}
}
