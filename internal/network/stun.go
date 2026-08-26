package network

import (
	"context"
	"errors"
	"net"
	"sync"
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

// DetectNATType classifies the NAT type by comparing the external (reflexive) addresses
// seen by two different STUN servers.
//
//   - Same IP + Same Port  → Full Cone / Restricted (UDP hole-punching works reliably)
//   - Same IP + Diff Port  → Symmetric NAT (CGNAT on LTE — each destination gets a new port)
//   - Diff IP              → Double NAT / Symmetric (treat as Symmetric)
//
// IMPORTANT: Each probe opens its own TEMPORARY UDP socket bound to the SAME local port
// (not the shared puncher socket).  This avoids races with the puncher's readLoop goroutine
// which also reads from the shared socket and would steal the STUN responses.
//
// localPort is the puncher's local port; pass 0 to let the OS choose a random port.
func DetectNATType(ctx context.Context, _ *net.UDPConn, servers []string) (NATType, error) {
	return DetectNATTypeFromPort(ctx, 0, servers)
}

// DetectNATTypeFromPort is the real implementation.  It creates two fresh UDP sockets,
// each bound to a random OS-assigned port, and queries a different STUN server.
func DetectNATTypeFromPort(ctx context.Context, _ int, servers []string) (NATType, error) {
	if len(servers) == 0 {
		servers = defaultSTUNServers
	}

	type mapped struct {
		ip   net.IP
		port int
		err  error
	}

	// Choose two distinct servers
	srv1 := servers[0]
	srv2 := ""
	for _, s := range servers[1:] {
		if s != srv1 {
			srv2 = s
			break
		}
	}
	if srv2 == "" {
		return NATTypeUnknown, errors.New("DetectNATType: need at least 2 distinct STUN servers")
	}

	// Each probe uses its own ephemeral socket — no contention with readLoop
	probeOne := func(server string) mapped {
		// Resolve STUN server
		srvAddr, err := net.ResolveUDPAddr("udp4", server)
		if err != nil {
			return mapped{err: err}
		}

		// Fresh temporary socket
		lAddr, _ := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
		sock, err := net.ListenUDP("udp4", lAddr)
		if err != nil {
			return mapped{err: err}
		}
		defer sock.Close()

		msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		if _, err := sock.WriteToUDP(msg.Raw, srvAddr); err != nil {
			return mapped{err: err}
		}

		buf := make([]byte, 1024)
		deadline, ok := ctx.Deadline()
		if !ok {
			deadline = time.Now().Add(2500 * time.Millisecond)
		}
		_ = sock.SetReadDeadline(deadline)
		n, _, err := sock.ReadFromUDP(buf)
		if err != nil {
			return mapped{err: err}
		}

		var stunMsg stun.Message
		stunMsg.Raw = make([]byte, n)
		copy(stunMsg.Raw, buf[:n])
		if err2 := stunMsg.Decode(); err2 != nil {
			return mapped{err: err2}
		}

		var xor stun.XORMappedAddress
		if err3 := xor.GetFrom(&stunMsg); err3 == nil {
			return mapped{ip: xor.IP, port: xor.Port}
		}
		var plain stun.MappedAddress
		if err4 := plain.GetFrom(&stunMsg); err4 == nil {
			return mapped{ip: plain.IP, port: plain.Port}
		}
		return mapped{err: errors.New("no mapped address in STUN response")}
	}

	var r1, r2 mapped
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r1 = probeOne(srv1) }()
	go func() { defer wg.Done(); r2 = probeOne(srv2) }()
	wg.Wait()

	if r1.err != nil || r2.err != nil {
		return NATTypeUnknown, errors.New("DetectNATType: STUN probe failed")
	}

	if r1.ip.Equal(r2.ip) && r1.port == r2.port {
		// Same external IP:Port seen by both servers → Full Cone / Restricted
		return NATTypeFullCone, nil
	}
	// Different external ports → Symmetric (port-remapping CGNAT)
	return NATTypeSymmetric, nil
}
