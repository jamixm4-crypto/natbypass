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
	Version   = "1.9.221-beta.3"
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
	// Normalize common single-dash long flags for seamless CLI UX (-config -> --config)
	for i, arg := range os.Args {
		if arg == "-config" {
			os.Args[i] = "--config"
		} else if arg == "-port" {
			os.Args[i] = "--port"
		} else if arg == "-log-level" {
			os.Args[i] = "--log-level"
		}
	}

	// Resolve configFile from os.Args early (before cobra parsing and service dispatch).
	// This ensures Windows Service and shortcut launches always find config.yaml next to the exe.
	for i, arg := range os.Args {
		if (arg == "--config" || arg == "-c") && i+1 < len(os.Args) {
			configFile = resolveConfigPath(os.Args[i+1])
			break
		}
	}
	if configFile == "" {
		configFile = resolveConfigPath("config.yaml")
	}

	// Embedded router optimization: reduce GC and OS thread pressure on MIPS/ARM
	if runtime.GOARCH == "mips" || runtime.GOARCH == "mipsle" || runtime.GOARCH == "arm" {
		runtime.GOMAXPROCS(1)
		debug.SetGCPercent(10)
		debug.SetMemoryLimit(48 << 20) // soft 48 MB heap limit
	}

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
			defer releaseSingleInstanceMutex()

			return runEngine(ctx, cfg, runtime.GOOS == "windows")
		},
	}

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", configFile, "Path to configuration file")
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
