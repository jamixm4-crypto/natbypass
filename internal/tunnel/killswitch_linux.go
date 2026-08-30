//go:build linux

package tunnel

import (
	"context"
	"net"
	"os/exec"
	"sync"
	"time"
)

// KillSwitch блокирует весь трафик в обход TUN-интерфейса для предотвращения IP-утечек.
type KillSwitch struct {
	enabled      bool
	tunInterface string
	mu           sync.Mutex
}

// NewKillSwitch создаёт новый экземпляр KillSwitch.
func NewKillSwitch() *KillSwitch {
	return &KillSwitch{}
}

// Enable активирует блокировку утечек трафика через iptables.
func (k *KillSwitch) Enable(tunInterface string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if tunInterface == "" {
		tunInterface = "nb0"
	}
	k.tunInterface = tunInterface

	// 1. Удаляем предыдущие правила если были
	_ = k.disableInternal()

	// 2. Разрешаем локальный loopback
	_ = exec.Command("iptables", "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT").Run()

	// 3. Разрешаем трафик через TUN
	_ = exec.Command("iptables", "-I", "OUTPUT", "2", "-o", tunInterface, "-j", "ACCEPT").Run()

	// 4. Разрешаем локальную сеть mesh (100.64.200.0/24)
	_ = exec.Command("iptables", "-I", "OUTPUT", "3", "-d", "100.64.200.0/24", "-j", "ACCEPT").Run()

	// 5. Разрешаем локальные LAN-подсети
	_ = exec.Command("iptables", "-I", "OUTPUT", "4", "-d", "192.168.0.0/16", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-I", "OUTPUT", "5", "-d", "10.0.0.0/8", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-I", "OUTPUT", "6", "-d", "172.16.0.0/12", "-j", "ACCEPT").Run()

	// 6. Блокируем весь остальной незашифрованный исходящий трафик
	_ = exec.Command("iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT").Run()

	k.enabled = true
	return nil
}

// Disable деактивирует Kill Switch и восстанавливает правила iptables.
func (k *KillSwitch) Disable() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.disableInternal()
}

func (k *KillSwitch) disableInternal() error {
	if k.tunInterface == "" {
		k.tunInterface = "nb0"
	}
	_ = exec.Command("iptables", "-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-D", "OUTPUT", "-o", k.tunInterface, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-D", "OUTPUT", "-d", "100.64.200.0/24", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-D", "OUTPUT", "-d", "192.168.0.0/16", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-D", "OUTPUT", "-d", "10.0.0.0/8", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-D", "OUTPUT", "-d", "172.16.0.0/12", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-D", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT").Run()
	k.enabled = false
	return nil
}

// IsEnabled возвращает текущее состояние Kill Switch.
func (k *KillSwitch) IsEnabled() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.enabled
}

// AutoEnableOnTunnelDown запускает мониторинг TUN и управляет Kill Switch автоматически.
func (k *KillSwitch) AutoEnableOnTunnelDown(ctx context.Context, tunInterface string) {
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ifaces, err := net.Interfaces()
				if err != nil {
					continue
				}
				found := false
				for _, iface := range ifaces {
					if iface.Name == tunInterface && (iface.Flags&net.FlagUp) != 0 {
						found = true
						break
					}
				}

				k.mu.Lock()
				if !found && !k.enabled {
					k.mu.Unlock()
					_ = k.Enable(tunInterface)
				} else if found && k.enabled {
					k.mu.Unlock()
					_ = k.Disable()
				} else {
					k.mu.Unlock()
				}
			}
		}
	}()
}