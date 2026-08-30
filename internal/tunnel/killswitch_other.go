//go:build !linux

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
