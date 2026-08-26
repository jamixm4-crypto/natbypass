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
	NATTypeRestricted           // Restricted Cone — port stable but restricted by remote IP
	NATTypePortRestricted       // Port Restricted Cone
	NATTypeSymmetric            // Each destination gets different external port — typical CGNAT on LTE
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

// defaultSTUNServers — diverse list across vendors so at least one works on any operator.
var defaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
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
	var lastErr error

	for _, server := range s.servers {
		ip, port, err := s.getMappedAddressFromServer(ctx, server)
		if err == nil {
			return ip, port, nil
		}
		lastErr = err
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

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return nil, 0, err
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
//   - Same IP + Same Port  → Full Cone / Restricted NAT (P2P hole punching works)
//   - Same IP + Diff Port  → Symmetric NAT (CGNAT assigns a different port per destination)
//   - Diff IP              → Symmetric NAT / Multi-WAN
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

