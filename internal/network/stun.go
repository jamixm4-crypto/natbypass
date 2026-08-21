package network

import (
	"context"
	"errors"
	"net"

	"github.com/pion/stun/v2"
)

var defaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
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
