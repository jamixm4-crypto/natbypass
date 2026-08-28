package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/natbypass/natbypass/internal/daemon"
	"github.com/spf13/cobra"
)

// newServiceCmd manages Windows service lifecycle.
func newServiceCmd() *cobra.Command {
	svcCmd := &cobra.Command{
		Use:   "service",
		Short: "Manage Windows background service (install, uninstall, start, stop, status)",
	}

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install NatBypass as a Windows background service",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := daemon.InstallService(configFile)
			if err != nil {
				return fmt.Errorf("failed to install service: %w", err)
			}
			fmt.Println("✓ Служба NatBypass успешно установлена в Windows!")
			fmt.Println("  Тип запуска: Автоматически")
			fmt.Println("  Для запуска выполните: natbypass service start")
			return nil
		},
	}

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall NatBypass service from Windows",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := daemon.UninstallService()
			if err != nil {
				return fmt.Errorf("failed to uninstall service: %w", err)
			}
			fmt.Println("✓ Служба NatBypass удалена из системы.")
			return nil
		},
	}

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the installed Windows service",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := daemon.StartWindowsService()
			if err != nil {
				return fmt.Errorf("failed to start service: %w", err)
			}
			fmt.Println("✓ Служба NatBypass запущена.")
			return nil
		},
	}

	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the running Windows service",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := daemon.StopWindowsService()
			if err != nil {
				return fmt.Errorf("failed to stop service: %w", err)
			}
			fmt.Println("✓ Служба NatBypass остановлена.")
			return nil
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Query status of Windows service",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := daemon.QueryServiceStatus()
			if err != nil {
				return fmt.Errorf("failed to query service status: %w", err)
			}
			fmt.Printf("Статус службы Windows: %s\n", st)
			return nil
		},
	}

	svcCmd.AddCommand(installCmd, uninstallCmd, startCmd, stopCmd, statusCmd)
	return svcCmd
}

// newInstallCmd creates system service installation command for Linux systemd, procd, and entware.
func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install as a system service (Linux: systemd, procd, entware)",
		RunE: func(cmd *cobra.Command, args []string) error {
			svcType, _ := cmd.Flags().GetString("service")
			return installLinuxService(svcType)
		},
	}
	cmd.Flags().String("service", "systemd", "Service type: systemd|procd|entware")
	return cmd
}

func installLinuxService(svcType string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, _ = filepath.Abs(exePath)

	switch svcType {
	case "systemd":
		unit := fmt.Sprintf(`[Unit]
Description=NatBypass — P2P Mesh VPN and NAT Traversal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s start --config /etc/natbypass/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`, exePath)
		if err := os.MkdirAll("/etc/natbypass", 0755); err != nil {
			return err
		}
		if err := os.WriteFile("/etc/systemd/system/natbypass.service", []byte(unit), 0644); err != nil {
			return err
		}
		fmt.Println("✓ systemd unit установлен: /etc/systemd/system/natbypass.service")
		fmt.Println("Выполните: systemctl daemon-reload && systemctl enable --now natbypass")

	case "procd":
		fmt.Println("Для OpenWrt: скопируйте scripts/init/natbypass.procd в /etc/init.d/natbypass")
		fmt.Println("Затем: chmod +x /etc/init.d/natbypass && /etc/init.d/natbypass enable && /etc/init.d/natbypass start")

	case "entware":
		fmt.Println("Для Keenetic/Entware: скопируйте scripts/init/S99natbypass в /opt/etc/init.d/S99natbypass")
		fmt.Println("Затем: chmod +x /opt/etc/init.d/S99natbypass && /opt/etc/init.d/S99natbypass start")

	default:
		return fmt.Errorf("unknown service type: %s", svcType)
	}
	return nil
}