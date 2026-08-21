package network

import (
	"context"
	"errors"
	"net"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
)

var (
	ErrNoUPnPDevice = errors.New("no UPnP device found")
)

type UPnPClient struct {
	router1 *internetgateway1.WANIPConnection1
	router2 *internetgateway2.WANIPConnection2
}

func NewUPnPClient() *UPnPClient {
	return &UPnPClient{}
}

func (u *UPnPClient) IsAvailable() bool {
	return u.router1 != nil || u.router2 != nil
}

func (u *UPnPClient) discover() error {
	if u.IsAvailable() {
		return nil
	}

	devices2, err := goupnp.DiscoverDevices(internetgateway2.URN_WANIPConnection_2)
	if err == nil {
		for _, d := range devices2 {
			if d.Err != nil || d.Root == nil {
				continue
			}
			clients, err := internetgateway2.NewWANIPConnection2ClientsFromRootDevice(d.Root, d.Location)
			if err == nil && len(clients) > 0 {
				u.router2 = clients[0]
				return nil
			}
		}
	}

	devices1, err := goupnp.DiscoverDevices(internetgateway1.URN_WANIPConnection_1)
	if err == nil {
		for _, d := range devices1 {
			if d.Err != nil || d.Root == nil {
				continue
			}
			clients, err := internetgateway1.NewWANIPConnection1ClientsFromRootDevice(d.Root, d.Location)
			if err == nil && len(clients) > 0 {
				u.router1 = clients[0]
				return nil
			}
		}
	}

	return ErrNoUPnPDevice
}

func (u *UPnPClient) AddPortMapping(ctx context.Context, internalPort, externalPort int, proto, description string, leaseDuration uint32) error {
	if err := u.discover(); err != nil {
		return err
	}

	localIP, err := getLocalIP()
	if err != nil {
		return err
	}

	if u.router2 != nil {
		return u.router2.AddPortMapping("", uint16(externalPort), proto, uint16(internalPort), localIP, true, description, leaseDuration)
	}

	if u.router1 != nil {
		return u.router1.AddPortMapping("", uint16(externalPort), proto, uint16(internalPort), localIP, true, description, leaseDuration)
	}

	return ErrNoUPnPDevice
}

func (u *UPnPClient) DeletePortMapping(ctx context.Context, externalPort int, proto string) error {
	if err := u.discover(); err != nil {
		return err
	}

	if u.router2 != nil {
		return u.router2.DeletePortMapping("", uint16(externalPort), proto)
	}

	if u.router1 != nil {
		return u.router1.DeletePortMapping("", uint16(externalPort), proto)
	}

	return ErrNoUPnPDevice
}

func (u *UPnPClient) GetExternalIPAddress(ctx context.Context) (net.IP, error) {
	if err := u.discover(); err != nil {
		return nil, err
	}

	var ipStr string
	var err error

	if u.router2 != nil {
		ipStr, err = u.router2.GetExternalIPAddress()
	} else if u.router1 != nil {
		ipStr, err = u.router1.GetExternalIPAddress()
	} else {
		return nil, ErrNoUPnPDevice
	}

	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, errors.New("invalid IP address returned by UPnP router")
	}

	return ip, nil
}

func getLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}
