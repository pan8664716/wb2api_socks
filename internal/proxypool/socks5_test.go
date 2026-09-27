package proxypool

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// socks5TestServer 最小 SOCKS5 服务端（仅用于测试）：握手 → 认证（可选）→ CONNECT
// → 双向转发。replyCode 非 0 时对 CONNECT 直接回该错误码（模拟"规则不允许/拒绝连接"）。
type socks5TestServer struct {
	ln        net.Listener
	user      string
	pass      string
	replyCode byte
	conns     atomic.Int64
	targets   sync.Map // 记录被 CONNECT 的目标 host:port（断言代理确实被用上）
}

func startSocks5TestServer(t *testing.T, user, pass string, replyCode byte) *socks5TestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &socks5TestServer{ln: ln, user: user, pass: pass, replyCode: replyCode}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *socks5TestServer) addr() string { return "socks5://" + s.ln.Addr().String() }

func (s *socks5TestServer) handle(c net.Conn) {
	defer c.Close()
	s.conns.Add(1)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	needAuth := s.user != ""
	if needAuth {
		c.Write([]byte{0x05, 0x02})
		ah := make([]byte, 2)
		if _, err := io.ReadFull(c, ah); err != nil {
			return
		}
		u := make([]byte, ah[1])
		io.ReadFull(c, u) //nolint:errcheck
		pl := make([]byte, 1)
		io.ReadFull(c, pl) //nolint:errcheck
		p := make([]byte, pl[0])
		io.ReadFull(c, p) //nolint:errcheck
		if string(u) != s.user || string(p) != s.pass {
			c.Write([]byte{0x01, 0x01})
			return
		}
		c.Write([]byte{0x01, 0x00})
	} else {
		c.Write([]byte{0x05, 0x00})
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		io.ReadFull(c, b) //nolint:errcheck
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(c, l) //nolint:errcheck
		b := make([]byte, l[0])
		io.ReadFull(c, b) //nolint:errcheck
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		io.ReadFull(c, b) //nolint:errcheck
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	io.ReadFull(c, pb) //nolint:errcheck
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))))
	s.targets.Store(target, true)

	if s.replyCode != 0 {
		c.Write([]byte{0x05, s.replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	up, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }() //nolint:errcheck
	go func() { io.Copy(c, up); done <- struct{}{} }() //nolint:errcheck
	<-done
}

// TestDialSocks5ThroughServer 端到端：经代理 CONNECT 到真实 TCP 服务并收发数据。
func TestDialSocks5ThroughServer(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c) //nolint:errcheck
		}
	}()

	proxy := startSocks5TestServer(t, "", "", 0)
	conn, err := DialSocks5(proxy.addr(), 5*time.Second, echo.Addr().String())
	if err != nil {
		t.Fatalf("DialSocks5: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("回显 = %q", buf)
	}
	if _, ok := proxy.targets.Load(echo.Addr().String()); !ok {
		t.Fatalf("代理未收到 CONNECT 目标 %s", echo.Addr())
	}
}

// TestDialSocks5UserPassAuth 用户名/口令认证：正确通过、错误报"认证失败"。
func TestDialSocks5UserPassAuth(t *testing.T) {
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()

	proxy := startSocks5TestServer(t, "alice", "s3cret", 0)
	good := fmt.Sprintf("socks5://alice:s3cret@%s", proxy.ln.Addr().String())
	conn, err := DialSocks5(good, 5*time.Second, echo.Addr().String())
	if err != nil {
		t.Fatalf("认证通过路径失败: %v", err)
	}
	conn.Close()

	bad := fmt.Sprintf("socks5://alice:wrong@%s", proxy.ln.Addr().String())
	if _, err := DialSocks5(bad, 5*time.Second, echo.Addr().String()); err == nil ||
		!strings.Contains(err.Error(), "认证失败") {
		t.Fatalf("错误口令应报认证失败，实际: %v", err)
	}
}

// TestCheckErrorPaths 探测失败路径的文案可读（面板直接展示这些字符串）。
func TestCheckErrorPaths(t *testing.T) {
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()

	refused := startSocks5TestServer(t, "", "", 0x05)
	if _, err := Check(refused.addr(), echo.Addr().String()); err == nil ||
		!strings.Contains(err.Error(), "连接被拒绝") {
		t.Fatalf("CONNECT 被拒应报「连接被拒绝」，实际: %v", err)
	}

	if _, err := Check("socks5://127.0.0.1:1", echo.Addr().String()); err == nil ||
		!strings.Contains(err.Error(), "连接代理失败") {
		t.Fatalf("代理不可达应报连接失败，实际: %v", err)
	}

	if _, err := Check("不是代理", echo.Addr().String()); err == nil {
		t.Fatal("非法地址应报错")
	}
}

// TestCheckSuccess 探测成功路径（目标端口非 443 → 只做 SOCKS5 握手 + CONNECT）。
func TestCheckSuccess(t *testing.T) {
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	proxy := startSocks5TestServer(t, "", "", 0)

	lat, err := Check(proxy.addr(), echo.Addr().String())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if lat <= 0 {
		t.Fatalf("耗时 = %v", lat)
	}
}

// TestTLSProbe 443 目标的 TLS 探活分支：能连上真 TLS 服务即通过，连不上要报 TLS 握手失败。
func TestTLSProbe(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	raw := strings.TrimPrefix(srv.URL, "https://")

	conn, err := net.DialTimeout("tcp", raw, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	host, _, _ := net.SplitHostPort(raw)
	if err := tlsProbe(conn, host); err != nil {
		t.Fatalf("tlsProbe: %v", err)
	}

	// 对普通 TCP 监听做 TLS 握手必然失败（报文不是 TLS）。
	plain, _ := net.Listen("tcp", "127.0.0.1:0")
	defer plain.Close()
	go func() {
		c, err := plain.Accept()
		if err == nil {
			c.Write([]byte("not tls")) //nolint:errcheck
			c.Close()
		}
	}()
	c2, err := net.DialTimeout("tcp", plain.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := tlsProbe(c2, "127.0.0.1"); err == nil {
		t.Fatal("非 TLS 目标应报 TLS 握手失败")
	}
}
