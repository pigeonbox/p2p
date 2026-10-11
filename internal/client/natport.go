// 端口映射(NAT-PMP RFC 6886 / PCP RFC 6887 / UPnP IGD)——Tailscale 口中的
// 「超充版 STUN」:路由器可控时(家庭/中小 NAS 场景的大头),直接在 NAT 上
// 开外部端口映射,对称 NAT 也变成可直连。纯客户端、失败无害(超时即弃)。
//
// 零第三方依赖手写:三协议都是极简报文/单次 SOAP,顺序 PCP → NAT-PMP →
// UPnP(前两者同端口 5351 一发一收,成本最低)。租约 5 分钟覆盖打洞窗口;
// establish 结束 best-effort 释放。
package client

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	pmpPort     = 5351 // NAT-PMP 与 PCP 同端口
	ssdpAddr    = "239.255.255.250:1900"
	mapLifetime = uint32(300) // 5 分钟租约:打洞窗口+一次中等传输
	mapTimeout  = 2 * time.Second
	soapTimeout = 3 * time.Second
)

// mapUDPPort 为 sock 的本地 UDP 端口申请外部映射,返回 外部地址+释放函数。
// 全部失败返回 ok=false(调用方照常走打洞/中继,无副作用)。
func mapUDPPort(sock *net.UDPConn) (ext *net.UDPAddr, release func(), ok bool) {
	release = func() {}
	localPort := sock.LocalAddr().(*net.UDPAddr).Port

	gw, localIP := gatewayAndLocalIP()
	if gw == nil || localIP == nil {
		return nil, release, false
	}

	if ext, ok = pcpMap(gw, localIP, localPort); ok {
		return ext, func() { _, _ = pcpMap(gw, localIP, localPort, 0) }, true
	}
	if ext, ok = pmpMap(gw, localPort); ok {
		return ext, func() { _, _ = pmpMap(gw, localPort, 0) }, true
	}
	if ctrlURL, svcType, ok := upnpDiscover(); ok {
		if upnpCtrl(ctrlURL, svcType, "AddPortMapping", localIP.String(), localPort, strconv.FormatUint(uint64(mapLifetime), 10)) {
			extIP := upnpExternalIP(ctrlURL, svcType, gw)
			return &net.UDPAddr{IP: extIP, Port: localPort},
				func() { upnpCtrl(ctrlURL, svcType, "DeletePortMapping", localIP.String(), localPort, "0") },
				true
		}
	}
	return nil, release, false
}

// usableExt 映射结果可用性:须为具体 IP 且端口非 0。
// 部分网关会 ACK 出 0.0.0.0:0 之类的空映射(真机实测),当成功会把垃圾候选喂给打洞。
func usableExt(ext *net.UDPAddr) bool {
	return ext != nil && ext.Port > 0 && ext.IP != nil && !ext.IP.IsUnspecified()
}

// ---- 网关发现 ----

// gatewayAndLocalIP 探测默认网关与本机内网 IPv4。Linux 解析 /proc/net/route;
// darwin/windows 借壳 route 命令;再兜底探同网段 .1/.254。
func gatewayAndLocalIP() (gw, local net.IP) {
	local = lanV4Local()
	if local == nil {
		return nil, nil
	}
	gwStr := procRouteGateway()
	if gwStr == "" {
		gwStr = routeCmdGateway()
	}
	if gwStr == "" {
		ip4 := local.To4()
		if ip4 == nil {
			return nil, local
		}
		for _, tail := range []byte{1, 254} {
			cand := net.IPv4(ip4[0], ip4[1], ip4[2], tail)
			c, err := net.DialTimeout("udp4", net.JoinHostPort(cand.String(), strconv.Itoa(pmpPort)), 500*time.Millisecond)
			if err == nil {
				_ = c.Close()
				gwStr = cand.String()
				break
			}
		}
	}
	if gwStr == "" {
		return nil, local
	}
	return net.ParseIP(gwStr), local
}

// lanV4Local 默认出向的本地 IPv4(UDP dial 技巧,不发包)。
func lanV4Local() net.IP {
	c, err := net.DialTimeout("udp4", "223.5.5.5:53", 500*time.Millisecond)
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }()
	addr := c.LocalAddr().(*net.UDPAddr)
	if addr.IP == nil || addr.IP.IsUnspecified() {
		return nil
	}
	return addr.IP
}

// procRouteGateway Linux:/proc/net/route 目的地 00000000 行的网关列(小端 hex)。
func procRouteGateway() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]).String()
	}
	return ""
}

// routeCmdGateway darwin/windows 借壳 route 命令解析默认网关。
func routeCmdGateway() string {
	var out string
	switch runtime.GOOS {
	case "darwin":
		raw, rerr := exec.Command("/sbin/route", "-n", "get", "default").Output()
		if rerr == nil {
			out = string(raw)
			for _, line := range strings.Split(out, "\n") {
				if s := strings.TrimSpace(line); strings.HasPrefix(s, "gateway:") {
					if cand := strings.TrimSpace(strings.TrimPrefix(s, "gateway:")); net.ParseIP(cand) != nil {
						return cand
					}
				}
			}
		}
	case "windows":
		raw, rerr := exec.Command("route", "print", "0.0.0.0").Output()
		if rerr == nil {
			out = string(raw)
			for _, line := range strings.Split(out, "\n") {
				f := strings.Fields(strings.TrimSpace(line))
				if len(f) >= 5 && f[0] == "0.0.0.0" {
					if cand := f[len(f)-1]; net.ParseIP(cand) != nil {
						return cand
					}
				}
			}
		}
	}
	return ""
}

// ---- NAT-PMP(RFC 6886)----

// pmpMap UDP MAP 请求;lifetime=0 即删除。成功返回外部地址。
func pmpMap(gw net.IP, internalPort int, lifetime ...uint32) (*net.UDPAddr, bool) {
	life := mapLifetime
	if len(lifetime) > 0 {
		life = lifetime[0]
	}
	req := make([]byte, 12)
	req[0] = 0 // version
	req[1] = 1 // opcode: UDP MAP
	binary.BigEndian.PutUint16(req[4:6], uint16(internalPort))
	binary.BigEndian.PutUint16(req[6:8], uint16(internalPort)) // 建议外部端口=内部
	binary.BigEndian.PutUint32(req[8:12], life)

	r, ok := udpRoundTrip(net.JoinHostPort(gw.String(), strconv.Itoa(pmpPort)), req, 16)
	// 响应: ver(1) op=129(1) result(2) epoch(4) internal(2) external(2) lifetime(4)
	if !ok || len(r) < 16 || r[1] != 129 || binary.BigEndian.Uint16(r[2:4]) != 0 {
		return nil, false
	}
	return &net.UDPAddr{IP: gw, Port: int(binary.BigEndian.Uint16(r[8:10]))}, true
}

// ---- PCP(RFC 6887)----

// pcpMap MAP 请求(UDP,protocol=17 UDP);lifetime=0 即删除。
// v4 客户端用 v4-mapped 客户端地址,外部地址字段 32 位(报文总长 60)。
func pcpMap(gw, local net.IP, internalPort int, lifetime ...uint32) (*net.UDPAddr, bool) {
	life := mapLifetime
	if len(lifetime) > 0 {
		life = lifetime[0]
	}
	req := make([]byte, 60) // header24 + MAP payload36(v4)
	req[0] = 2              // version
	req[1] = 1              // opcode: MAP
	binary.BigEndian.PutUint32(req[4:8], life)
	copy(req[8:24], local.To16()) // client IP(v4-mapped)
	// nonce [24:36] 全零即可(映射去重用,会话内不重复申请)
	req[36] = 17 // protocol UDP
	binary.BigEndian.PutUint16(req[40:42], uint16(internalPort))
	binary.BigEndian.PutUint16(req[42:44], uint16(internalPort))
	// requested external address [44:48] 全零=网关决定

	r, ok := udpRoundTrip(net.JoinHostPort(gw.String(), strconv.Itoa(pmpPort)), req, 60)
	// 响应: ver(1) op|0x80(1) rsv(2) result(2) epoch(4) clientIP(16) | nonce(12) proto(1) rsv(3) int(2) ext(2) extIP(4+12)
	if !ok || len(r) < 60 || r[1] != 0x81 || binary.BigEndian.Uint16(r[4:6]) != 0 {
		return nil, false
	}
	extPort := binary.BigEndian.Uint16(r[44:46])
	extIP := net.IP(r[46:50]).To4()
	if extIP == nil {
		return nil, false
	}
	return &net.UDPAddr{IP: extIP, Port: int(extPort)}, true
}

// ---- UPnP IGD ----

type upnpDevice struct {
	URLBase  string `xml:"URLBase"`
	Services []struct {
		ServiceType string `xml:"serviceType"`
		ControlURL  string `xml:"controlURL"`
	} `xml:"device>serviceList>service"`
}

// upnpDiscover SSDP 找网关的 WANIPConnection 控制 URL(含 v1/v2 两代服务类型)。
func upnpDiscover() (ctrlURL, svcType string, ok bool) {
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return "", "", false
	}
	defer func() { _ = pc.Close() }()
	msg := strings.Join([]string{
		"M-SEARCH * HTTP/1.1", "HOST: 239.255.255.250:1900",
		`MAN: "ssdp:discover"`, "MX: 2",
		"ST: urn:schemas-upnp-org:service:WANIPConnection:2", "", "",
	}, "\r\n")
	if _, err := pc.WriteTo([]byte(msg), mustUDP(ssdpAddr)); err != nil {
		return "", "", false
	}
	_ = pc.SetReadDeadline(time.Now().Add(mapTimeout))
	buf := make([]byte, 4096)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return "", "", false
		}
		loc := httpHeader(string(buf[:n]), "LOCATION")
		if loc == "" {
			continue
		}
		if url, st, found := upnpProbeControl(loc); found {
			return url, st, true
		}
	}
}

// upnpProbeControl 拉设备描述 XML,找 WANIPConnection 控制地址。
func upnpProbeControl(descURL string) (ctrlURL, svcType string, ok bool) {
	client := &http.Client{Timeout: soapTimeout}
	resp, err := client.Get(descURL)
	if err != nil {
		return "", "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	_ = resp.Body.Close()
	if err != nil {
		return "", "", false
	}
	var d upnpDevice
	if err := xml.Unmarshal(body, &d); err != nil {
		return "", "", false
	}
	base := d.URLBase
	if base == "" {
		if i := strings.LastIndex(descURL, "/"); i > 0 {
			base = descURL[:i+1]
		}
	}
	for _, svc := range d.Services {
		if strings.Contains(svc.ServiceType, "WANIPConnection") {
			return resolveURL(base, svc.ControlURL), svc.ServiceType, true
		}
	}
	return "", "", false
}

// upnpSOAP AddPortMapping/DeletePortMapping 的 SOAP 信封(UDP 固定)。
func upnpSOAP(action, svcType, localIP string, intPort int, lifetime string) string {
	return `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` + action + ` xmlns:u="` + svcType + `">` +
		`<NewRemoteHost></NewRemoteHost><NewExternalPort>` + strconv.Itoa(intPort) + `</NewExternalPort><NewProtocol>UDP</NewProtocol>` +
		`<NewInternalPort>` + strconv.Itoa(intPort) + `</NewInternalPort><NewInternalClient>` + localIP + `</NewInternalClient><NewEnabled>1</NewEnabled>` +
		`<NewPortMappingDescription>PigeonBox</NewPortMappingDescription><NewLeaseDuration>` + lifetime + `</NewLeaseDuration>` +
		`</u:` + action + `></s:Body></s:Envelope>`
}

// upnpCtrl 执行 SOAP 动作;2xx=成功。Delete 在老网关上可能报错,由调用方宽松处理。
func upnpCtrl(ctrlURL, svcType, action, localIP string, intPort int, lifetime string) bool {
	req, err := http.NewRequest(http.MethodPost, ctrlURL, strings.NewReader(upnpSOAP(action, svcType, localIP, intPort, lifetime)))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPACTION", `"`+svcType+`#`+action+`"`)
	client := &http.Client{Timeout: soapTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
	_ = resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// upnpExternalIP GetExternalIPAddress;失败回退网关地址(候选只用于探测,可验证)。
func upnpExternalIP(ctrlURL, svcType string, gw net.IP) net.IP {
	req, err := http.NewRequest(http.MethodPost, ctrlURL,
		strings.NewReader(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetExternalIPAddress xmlns:u="`+svcType+`"></u:GetExternalIPAddress></s:Body></s:Envelope>`))
	if err != nil {
		return gw
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPACTION", `"`+svcType+`#GetExternalIPAddress"`)
	client := &http.Client{Timeout: soapTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return gw
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	_ = resp.Body.Close()
	if i := strings.Index(string(body), "<NewExternalIPAddress>"); i >= 0 {
		rest := string(body)[i+len("<NewExternalIPAddress>"):]
		if j := strings.Index(rest, "</"); j > 0 {
			if ip := net.ParseIP(strings.TrimSpace(rest[:j])); ip != nil {
				return ip
			}
		}
	}
	return gw
}

// ---- 小件 ----

// udpRoundTrip 发一收一(单包协议通用)。
func udpRoundTrip(addr string, req []byte, respLen int) ([]byte, bool) {
	gw, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, false
	}
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, false
	}
	defer func() { _ = sock.Close() }()
	_ = sock.SetDeadline(time.Now().Add(mapTimeout))
	if _, err := sock.WriteToUDP(req, gw); err != nil {
		return nil, false
	}
	buf := make([]byte, respLen)
	n, _, err := sock.ReadFromUDP(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

func httpHeader(raw, name string) string {
	for _, line := range strings.Split(raw, "\r\n") {
		if i := strings.Index(line, ":"); i > 0 && strings.EqualFold(strings.TrimSpace(line[:i]), name) {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}

func resolveURL(base, ctrl string) string {
	if strings.HasPrefix(ctrl, "http://") || strings.HasPrefix(ctrl, "https://") {
		return ctrl
	}
	if !strings.HasPrefix(ctrl, "/") {
		ctrl = "/" + ctrl
	}
	if strings.HasSuffix(base, "/") && strings.HasPrefix(ctrl, "/") {
		return base[:len(base)-1] + ctrl
	}
	return base + ctrl
}

func mustUDP(addr string) *net.UDPAddr {
	a, _ := net.ResolveUDPAddr("udp4", addr)
	return a
}
