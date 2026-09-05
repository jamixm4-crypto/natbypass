package network

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/pion/stun/v2"
)


// NATType describes the type of NAT in front of the device.
type NATType int

const (
	NATTypeUnknown      NATType = iota
	NATTypeFullCone             // All packets from same internal addr always use same external port
	NATTypeRestricted           // Restricted Cone вЂ” port stable but restricted by remote IP
	NATTypePortRestricted       // Port Restricted Cone
	NATTypeSymmetric            // Each destination gets different external port вЂ” typical CGNAT on LTE
)

// String returns a short label for the NAT type.
func (n NATType) String() string {
	switch n {
	case NATTypeFullCone:
		return "full_cone"
	case NATTypeRestricted:
		return "restricted"
	case NATTypePortRestricted:
		return "port_restricted"
	case NATTypeSymmetric:
		return "symmetric"
	default:
		return "unknown"
	}
}

// IsSymmetric returns true when each outgoing connection gets a different external port.
// Classic UDP hole-punching is unreliable; use wide port-sweep or TCP/relay fallback.
func (n NATType) IsSymmetric() bool {
	return n == NATTypeSymmetric
}

// defaultSTUNServers вЂ” diverse list across vendors so at least one works on any operator.
var defaultSTUNServers = []string{
	"stun.cloudflare.com:3478",
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.nextcloud.com:443",
	"stun.twilio.com:3478",
	"relay.webwormhole.io:3478",
}

type STUNClient struct {
	servers []string
}

func NewSTUNClient(servers []string) *STUNClient {
	if len(servers) == 0 {
		servers = defaultSTUNServers
	}
	return &STUNClient{
		servers: servers,
	}
}

func (s *STUNClient) GetMappedAddress(ctx context.Context) (net.IP, int, error) {
	if len(s.servers) == 0 {
		return nil, 0, errors.New("no STUN servers configured")
	}

	type stunResult struct {
		ip   net.IP
		port int
		err  error
	}

	resCh := make(chan stunResult, len(s.servers))
	probeCtx, cancelProbes := context.WithTimeout(ctx, 3*time.Second)
	defer cancelProbes()

	for _, srv := range s.servers {
		go func(server string) {
			ip, port, err := s.getMappedAddressFromServer(probeCtx, server)
			resCh <- stunResult{ip: ip, port: port, err: err}
		}(srv)
	}

	var lastErr error
	for i := 0; i < len(s.servers); i++ {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case res := <-resCh:
			if res.err == nil && res.ip != nil {
				cancelProbes() // Cancel remaining probes immediately once first responds
				return res.ip, res.port, nil
			}
			lastErr = res.err
		}
	}

	if lastErr != nil {
		return nil, 0, lastErr
	}
	return nil, 0, errors.New("failed to get mapped address from all STUN servers")
}


func (s *STUNClient) getMappedAddressFromServer(ctx context.Context, server string) (net.IP, int, error) {
	addr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return nil, 0, err
	}

	// РџСЂРёРІСЏР·С‹РІР°РµРј Рє С„РёР·РёС‡РµСЃРєРѕРјСѓ LAN-IP С‡С‚РѕР±С‹ STUN-Р·Р°РїСЂРѕСЃС‹ РЅРµ СѓС…РѕРґРёР»Рё С‡РµСЂРµР· AWG/VPN-С‚РѕРЅРЅРµР»СЊ.
	// Р’С‹Р±РёСЂР°РµРј РїРµСЂРІС‹Р№ non-loopback, non-virtual IPv4-Р°РґСЂРµСЃ (РїСЂРѕРїСѓСЃРєР°РµРј 100.64.x.x вЂ” NatBypass VIP).
	var localAddr *net.UDPAddr
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				ipNet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip4 := ipNet.IP.To4()
				if ip4 == nil || ip4.IsLoopback() {
					continue
				}
				// РџСЂРѕРїСѓСЃРєР°РµРј РІРёСЂС‚СѓР°Р»СЊРЅС‹Р№ IP NatBypass (100.64.x.x)
				if ip4[0] == 10 && ip4[1] == 200 {
					continue
				}
				localAddr = &net.UDPAddr{IP: ip4, Port: 0}
				break
			}
			if localAddr != nil {
				break
			}
		}
	}

	conn, err := net.DialUDP("udp4", localAddr, addr)
	if err != nil {
		// Fallback: Р±РµР· РїСЂРёРІСЏР·РєРё Рє РёРЅС‚РµСЂС„РµР№СЃСѓ
		conn, err = net.DialUDP("udp4", nil, addr)
		if err != nil {
			return nil, 0, err
		}
	}
	defer conn.Close()

	c, err := stun.NewClient(conn)
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	var ip net.IP
	var port int
	var respErr error

	done := make(chan struct{})

	err = c.Do(message, func(res stun.Event) {
		defer close(done)
		if res.Error != nil {
			respErr = res.Error
			return
		}

		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(res.Message); err != nil {
			respErr = err
			return
		}
		ip = xorAddr.IP
		port = xorAddr.Port
	})

	if err != nil {
		return nil, 0, err
	}

	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	case <-done:
		if respErr != nil {
			return nil, 0, respErr
		}
		return ip, port, nil
	}
}

// DetectNATType classifies the NAT type by querying two different STUN servers
// from the EXACT SAME local socket.
//
//   - Same IP + Same Port  в†’ Full Cone / Restricted NAT (P2P hole punching works)
//   - Same IP + Diff Port  в†’ Symmetric NAT (CGNAT assigns a different port per destination)
//   - Diff IP              в†’ Symmetric NAT / Multi-WAN
func DetectNATType(ctx context.Context, _ *net.UDPConn, servers []string) (NATType, error) {
	if len(servers) == 0 {
		servers = defaultSTUNServers
	}

	srv1 := servers[0]
	srv2 := ""
	for _, s := range servers[1:] {
		if s != srv1 {
			srv2 = s
			break
		}
	}
	if srv2 == "" {
		return NATTypeUnknown, errors.New("need at least 2 STUN servers")
	}

	// Create ONE temporary UDP socket bound to an ephemeral port
	lAddr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
	if err != nil {
		return NATTypeUnknown, err
	}
	sock, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		return NATTypeUnknown, err
	}
	defer sock.Close()

	probeServer := func(server string) (net.IP, int, error) {
		srvAddr, err := net.ResolveUDPAddr("udp4", server)
		if err != nil {
			return nil, 0, err
		}

		msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		if _, err := sock.WriteToUDP(msg.Raw, srvAddr); err != nil {
			return nil, 0, err
		}

		buf := make([]byte, 1024)
		_ = sock.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := sock.ReadFromUDP(buf)
		if err != nil {
			return nil, 0, err
		}

		var stunMsg stun.Message
		stunMsg.Raw = make([]byte, n)
		copy(stunMsg.Raw, buf[:n])
		if err := stunMsg.Decode(); err != nil {
			return nil, 0, err
		}

		var xor stun.XORMappedAddress
		if err := xor.GetFrom(&stunMsg); err == nil {
			return xor.IP, xor.Port, nil
		}
		var plain stun.MappedAddress
		if err := plain.GetFrom(&stunMsg); err == nil {
			return plain.IP, plain.Port, nil
		}
		return nil, 0, errors.New("no mapped address attribute in STUN response")
	}

	ip1, port1, err1 := probeServer(srv1)
	if err1 != nil {
		return NATTypeUnknown, err1
	}

	// Small delay between probes from the same socket
	time.Sleep(50 * time.Millisecond)

	ip2, port2, err2 := probeServer(srv2)
	if err2 != nil {
		return NATTypeUnknown, err2
	}

	if ip1.Equal(ip2) && port1 == port2 {
		return NATTypeFullCone, nil
	}
	return NATTypeSymmetric, nil
}


