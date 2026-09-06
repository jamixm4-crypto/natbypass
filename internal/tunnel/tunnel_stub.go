//go:build !windows && !linux

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

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