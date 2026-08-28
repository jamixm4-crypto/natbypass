package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/natbypass/natbypass/internal/constants"
	"github.com/natbypass/natbypass/internal/daemon"
	"github.com/spf13/cobra"
)

var (
	Version   = "1.9.11"
	Commit    = "unknown"
	BuildDate = "unknown"
)

var (
	configFile string
	logLevel   string
	noWebUI    bool
	webUIPort  int
	useTray    bool
	uiMode     string
)


func main() {
	// If running as a Windows background service, dispatch directly to service handler
	if daemon.IsWindowsService() {
		err := daemon.RunService(func(ctx context.Context) error {
			cfg, err := loadConfigOrDefault(configFile, true)
			if err != nil {
				return err
			}
			return runEngine(ctx, cfg, false)
		})
		if err != nil {
			os.Exit(1)
		}
		return
	}

	rootCmd := &cobra.Command{
		Use:   "natbypass",
		Short: "NatBypass — P2P Mesh VPN & NAT Traversal",
		Long: fmt.Sprintf(`NatBypass v%s (%s) — High-performance P2P mesh network and NAT traversal tool
with multi-channel signaling (Telegram, MQTT, HTTP Webhook, DNS TXT) and DPI obfuscation.

Supported platforms: Windows, Linux (amd64/arm64/mips/mipsle), Android, iOS.`, Version, Commit),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfigOrDefault(configFile, true)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if runtime.GOOS == "windows" {
				p := cfg.WebUI.Port
				if webUIPort > 0 {
					p = webUIPort
				}
				if p <= 0 {
					p = constants.DefaultWebUIPort
				}
				if !acquireSingleInstanceMutex(p) {
					return nil
				}
			}
			return runEngine(ctx, cfg, runtime.GOOS == "windows")
		},
	}

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.yaml", "Path to configuration file")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level: debug/info/warn/error")
	rootCmd.PersistentFlags().BoolVar(&noWebUI, "no-webui", false, "Disable embedded Web UI")
	rootCmd.PersistentFlags().IntVar(&webUIPort, "port", 0, "Override Web UI HTTP port")
	rootCmd.PersistentFlags().StringVar(&uiMode, "ui", "auto", "UI launch mode: auto | native | browser")

	rootCmd.AddCommand(
		newStartCmd(),
		newGuiCmd(),
		newServiceCmd(),
		newStopCmd(),
		newStatusCmd(),
		newKeygenCmd(),
		newWGCmd(),
		newInstallCmd(),
		newAntigravityCmd(),
		newKonamiCmd(),
		newVersionCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}