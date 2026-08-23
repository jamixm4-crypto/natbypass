//go:build !windows && !linux

package tunnel

import (
	"errors"
)

var ErrTunnelNotSupported = errors.New("tun adapter is only supported on Windows and Linux")

type Device struct {
	AdapterName string
	VirtualIP   string
}

func CreateAdapter(adapterName, virtualIP string) (*Device, error) {
	return nil, ErrTunnelNotSupported
}

func (d *Device) ReadPacket() ([]byte, error) {
	return nil, ErrTunnelNotSupported
}

func (d *Device) WritePacket(packet []byte) error {
	return ErrTunnelNotSupported
}

func (d *Device) SetVirtualIP(virtualIP string) error {
	return ErrTunnelNotSupported
}

func (d *Device) Close() error {
	return nil
}