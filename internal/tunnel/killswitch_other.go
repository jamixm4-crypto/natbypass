//go:build !linux

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package tunnel

import (
	"context"
	"sync"
)

// KillSwitch — кроссплатформенная заглушка для Windows / macOS
type KillSwitch struct {
	enabled      bool
	tunInterface string
	mu           sync.Mutex
}

func NewKillSwitch() *KillSwitch {
	return &KillSwitch{}
}

func (k *KillSwitch) Enable(tunInterface string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.tunInterface = tunInterface
	k.enabled = true
	return nil
}

func (k *KillSwitch) Disable() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.enabled = false
	return nil
}

func (k *KillSwitch) IsEnabled() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.enabled
}

func (k *KillSwitch) AutoEnableOnTunnelDown(ctx context.Context, tunInterface string) {}
