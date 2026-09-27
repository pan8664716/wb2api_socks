// socks5.go 极简 SOCKS5 客户端（RFC 1928 + 用户名/密码认证 RFC 1929）。
//
// 用途只有一个：**连通性探测**。真实出站不走这里——net/http 的
// http.Transport.Proxy 原生支持 socks5:// 代理 URL（Go 标准库内置 socks 实现，
// 含用户名/密码认证），生产请求由它接管。本文件只为面板的「测试」按钮提供一个
// 零依赖、可离线单测的探活实现。
package proxypool

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultCheckTarget 默认探测目标：上游 chat 域 443（真正要打通的地址）。
const DefaultCheckTarget = "copilot.tencent.com:443"

// CheckTimeout 单次探测的总超时上限。
const CheckTimeout = 12 * time.Second

// Check 对代理做一次端到端连通性探测：
//  1. TCP 连上代理；
//  2. SOCKS5 握手（按需用户名/密码认证）；
//  3. CONNECT 到 target；
//  4. target 端口为 443 时再做一次 TLS 握手（ServerName 取目标主机名，跳过证书校验——
//     只验证「代理能否把 TLS 流透到上游」，不对证书链做信任判断）。
//
// 返回总耗时与错误（错误文案已截断，可直接展示在面板上）。
func Check(proxyAddr string, target string) (time.Duration, error) {
	start := time.Now()
	conn, err := DialSocks5(proxyAddr, CheckTimeout, target)
	if err != nil {
		return time.Since(start), err
	}
	defer conn.Close()
	if host, port, err := splitHostPort(target); err == nil && port == "443" {
		if err := tlsProbe(conn, host); err != nil {
			return time.Since(start), err
		}
	}
	return time.Since(start), nil
}

// tlsProbe 在已建立的隧道上做一次 TLS 握手（跳过证书校验：只验证代理能否把 TLS 流
// 透到上游，不对证书链做信任判断——那是客户端的事，不是探活的判据）。
func tlsProbe(conn net.Conn, host string) error {
	_ = conn.SetDeadline(time.Now().Add(CheckTimeout))
	defer conn.SetDeadline(time.Time{})                                             //nolint:errcheck // 清 deadline 失败无副作用
	tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true}) //nolint:gosec // 见函数注释
	if err := tc.Handshake(); err != nil {
		return fmt.Errorf("TLS 握手失败：%w", err)
	}
	_ = tc.Close()
	return nil
}

// DialSocks5 经 socks5 代理（规范化地址 socks5://[user:pass@]host:port）建立到
// target（host:port）的 TCP 连接。
func DialSocks5(proxyAddr string, timeout time.Duration, target string) (net.Conn, error) {
	if timeout <= 0 {
		timeout = CheckTimeout
	}
	u, err := url.Parse(proxyAddr)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("代理地址非法：%q", proxyAddr)
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("代理地址非法：%q", proxyAddr)
	}
	var user, pass string
	needAuth := false
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
		needAuth = true
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return nil, fmt.Errorf("连接代理失败：%w", err)
	}
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)
	if err := socks5Handshake(conn, user, pass, needAuth, target); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{}) // 握手完成后清掉 deadline，交回调用方
	return conn, nil
}

// socks5Handshake 在已建立的连接上完成 SOCKS5 协商 + CONNECT。
func socks5Handshake(conn net.Conn, user, pass string, needAuth bool, target string) error {
	// 第 1 步：方法协商。0x00 = 无需认证，0x02 = 用户名/密码。
	methods := []byte{0x00}
	if needAuth {
		methods = []byte{0x02, 0x00}
	}
	req := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("SOCKS5 协商写入失败：%w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("SOCKS5 协商读取失败：%w", err)
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("SOCKS5 版本不符：0x%02x", reply[0])
	}
	switch reply[1] {
	case 0x00:
		// 无需认证，继续
	case 0x02:
		if err := socks5UserPassAuth(conn, user, pass); err != nil {
			return err
		}
	case 0xff:
		return fmt.Errorf("代理拒绝全部认证方式")
	default:
		return fmt.Errorf("代理要求不支持的认证方式：0x%02x", reply[1])
	}

	// 第 2 步：CONNECT 请求。
	host, port, err := splitHostPort(target)
	if err != nil {
		return fmt.Errorf("探测目标非法：%q", target)
	}
	pn, err := strconv.Atoi(port)
	if err != nil || pn <= 0 || pn > 65535 {
		return fmt.Errorf("探测目标端口非法：%q", target)
	}
	req = []byte{0x05, 0x01, 0x00} // VER, CMD=CONNECT, RSV
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("目标主机名过长")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(pn))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("SOCKS5 CONNECT 写入失败：%w", err)
	}

	// 第 3 步：读 CONNECT 回复（前 4 字节 + 变长地址 + 2 字节端口）。
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("SOCKS5 CONNECT 读取失败：%w", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("SOCKS5 CONNECT 版本不符：0x%02x", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT 被拒绝：%s", socks5ReplyText(head[1]))
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return fmt.Errorf("SOCKS5 回复地址读取失败：%w", err)
		}
		skip = int(l[0])
	default:
		return fmt.Errorf("SOCKS5 回复地址类型未知：0x%02x", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		return fmt.Errorf("SOCKS5 回复地址读取失败：%w", err)
	}
	return nil
}

// socks5UserPassAuth RFC 1929 用户名/密码子协商。
func socks5UserPassAuth(conn net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return fmt.Errorf("代理用户名/口令过长")
	}
	req := []byte{0x01, byte(len(user))}
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("SOCKS5 认证写入失败：%w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("SOCKS5 认证读取失败：%w", err)
	}
	if reply[0] != 0x01 {
		return fmt.Errorf("SOCKS5 认证版本不符：0x%02x", reply[0])
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("代理认证失败（用户名或口令错误）")
	}
	return nil
}

// socks5ReplyText 把 CONNECT 回复码翻译成可读文案（RFC 1928 §6）。
func socks5ReplyText(code byte) string {
	switch code {
	case 0x01:
		return "代理内部故障"
	case 0x02:
		return "规则不允许该连接"
	case 0x03:
		return "网络不可达"
	case 0x04:
		return "主机不可达"
	case 0x05:
		return "连接被拒绝"
	case 0x06:
		return "TTL 超时"
	case 0x07:
		return "不支持的命令"
	case 0x08:
		return "不支持的地址类型"
	default:
		return fmt.Sprintf("未知错误 0x%02x", code)
	}
}

// MaskProxy 供日志使用：把地址里的口令替换为 ***。
func MaskProxy(addr string) string {
	if !strings.Contains(addr, "@") {
		return addr
	}
	return Proxy{Addr: addr}.Masked()
}
