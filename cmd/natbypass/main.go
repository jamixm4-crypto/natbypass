package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/natbypass/natbypass/internal/constants"
	"github.com/natbypass/natbypass/internal/daemon"
	"github.com/spf13/cobra"
)


var (
	Version   = "1.9.180"
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
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			timestamp := time.Now().Format("2006-01-02 15:04:05.000")
			crashMsg := fmt.Sprintf("[%s] FATAL PANIC: %v\nStack Trace:\n%s\n", timestamp, r, string(stack))
			fmt.Fprintln(os.Stderr, crashMsg)

			_ = os.MkdirAll("dist", 0755)
			if f, err := os.OpenFile("dist/crash.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				_, _ = f.WriteString(crashMsg)
				_ = f.Close()
			}
			if f2, err2 := os.OpenFile("crash.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err2 == nil {
				_, _ = f2.WriteString(crashMsg)
				_ = f2.Close()
			}

			cleanupTrayIcon()
			os.Exit(2)
		}
		cleanupTrayIcon()
	}()

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
				if !acquireSingleInstanceMutex(configFile, p) {
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
		newDiagCmd(),
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