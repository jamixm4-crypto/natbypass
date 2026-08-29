package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"runtime"
	"strconv"
	"syscall"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/constants"
	"github.com/natbypass/natbypass/internal/crypto"
	"github.com/natbypass/natbypass/internal/signaling"
	"github.com/natbypass/natbypass/internal/wireguard"
	"github.com/spf13/cobra"
)

// newStartCmd creates the daemon start command.
func newStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start NatBypass daemon in foreground",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfigOrDefault(configFile, true)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			return runEngine(ctx, cfg, useTray)
		},
	}
	cmd.Flags().BoolVarP(&useTray, "tray", "t", runtime.GOOS == "windows", "Minimize to system tray (Windows)")
	return cmd
}

// newGuiCmd creates the GUI launcher command.
func newGuiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gui",
		Short: "Start NatBypass in GUI mode with system tray",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfigOrDefault(configFile, true)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			return runEngine(ctx, cfg, true)
		},
	}
}

// findRunningPID finds the active NatBypass process PID across candidate files.
func findRunningPID(pidFile string) int {
	pidCandidates := []string{
		pidFile,
		"/run/natbypass.pid",
		"/var/run/natbypass.pid",
		"/opt/var/run/natbypass.pid",
		"/tmp/natbypass.pid",
		"natbypass.pid",
	}

	for _, pPath := range pidCandidates {
		if pPath == "" {
			continue
		}
		if data, err := os.ReadFile(pPath); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
				if proc, err := os.FindProcess(pid); err == nil {
					if err := proc.Signal(syscall.Signal(0)); err == nil {
						return pid
					}
				}
			}
		}
	}
	return 0
}

// newStopCmd creates the daemon stop command.
func newStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the running daemon via PID file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := loadConfigOrDefault(configFile, false)
			pidFile := ""
			if cfg != nil {
				pidFile = cfg.Daemon.PidFile
			}

			pid := findRunningPID(pidFile)
			if pid <= 0 {
				return fmt.Errorf("daemon is not running (PID not found)")
			}

			proc, err := os.FindProcess(pid)
			if err != nil {
				return fmt.Errorf("process not found: %w", err)
			}
			if err := proc.Signal(syscall.SIGTERM); err != nil {
				return fmt.Errorf("failed to send SIGTERM: %w", err)
			}
			fmt.Printf("SIGTERM signal sent to process %d\n", pid)
			return nil
		},
	}
}

// newStatusCmd creates the status reporting command.
func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check running status of the daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := loadConfigOrDefault(configFile, false)
			if cfg == nil {
				cfg = buildDefaultConfig()
			}

			port := cfg.WebUI.Port
			if webUIPort > 0 {
				port = webUIPort
			}
			if port <= 0 {
				port = constants.DefaultWebUIPort
			}

			// 1. Check PID
			runningPID := findRunningPID(cfg.Daemon.PidFile)

			// 2. Probe HTTP API (127.0.0.1:port/healthz)
			client := http.Client{Timeout: 500 * time.Millisecond}
			resp, httpErr := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
			isHttpRunning := (httpErr == nil && resp != nil && resp.StatusCode == 200)
			if resp != nil {
				_ = resp.Body.Close()
			}

			if runningPID > 0 || isHttpRunning {
				if runningPID > 0 {
					fmt.Printf("Status: RUNNING (PID: %d)\n", runningPID)
				} else {
					fmt.Println("Status: RUNNING")
				}
				fmt.Printf("Web UI: http://localhost:%d\n", port)
				return nil
			}

			fmt.Println("Status: NOT RUNNING")
			return nil
		},
	}
}


// newKeygenCmd creates the key generation command for NaCl keys.
func newKeygenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new NaCl Curve25519 keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, priv, err := crypto.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("failed to generate keypair: %w", err)
			}
			fmt.Println("# NaCl/Box Keypair (X25519 + XSalsa20-Poly1305)")
			fmt.Printf("public_key:  %s\n", crypto.KeyToHex(pub))
			fmt.Printf("private_key: %s\n", crypto.KeyToHex(priv))
			fmt.Println("")
			fmt.Println("# Add this to config.yaml under crypto section:")
			fmt.Printf("# crypto:\n#   public_key: \"%s\"\n#   private_key: \"%s\"\n",
				crypto.KeyToHex(pub), crypto.KeyToHex(priv))
			return nil
		},
	}
}

// newWGCmd creates WireGuard configuration subcommands.
func newWGCmd() *cobra.Command {
	wgCmd := &cobra.Command{
		Use:   "wg",
		Short: "WireGuard key and mesh configuration commands",
	}

	wgKeygenCmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a WireGuard keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := wireguard.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("failed to generate WireGuard keys: %w", err)
			}
			fmt.Println("# WireGuard Keypair")
			fmt.Printf("PrivateKey = %s\n", kp.PrivateKey)
			fmt.Printf("PublicKey  = %s\n", kp.PublicKey)
			return nil
		},
	}

	wgConfigCmd := &cobra.Command{
		Use:   "config",
		Short: "Generate sample WireGuard mesh configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := wireguard.GenerateKeyPair()
			if err != nil {
				return err
			}
			wgCfg := &wireguard.WGConfig{
				InterfaceName: "wg0",
				PrivateKey:    kp.PrivateKey,
				Address:       "100.64.200.1/24",
				ListenPort:    51820,
				DNS:           "",
				MTU:           1420,
			}
			conf, err := wireguard.GenerateWGConfig(wgCfg)
			if err != nil {
				return err
			}
			fmt.Println(conf)
			return nil
		},
	}

	wgCmd.AddCommand(wgKeygenCmd, wgConfigCmd)
	return wgCmd
}

// newVersionCmd creates the version printing command.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("NatBypass %s (commit: %s, built: %s)\n", Version, Commit, BuildDate)
		},
	}
}

// buildSignalingChannels instantiates configured signaling channels from config.
func buildSignalingChannels(cfg *config.Config) ([]signaling.SignalingChannel, error) {
	var channels []signaling.SignalingChannel

	for _, chCfg := range cfg.Signaling.Channels {
		if !chCfg.Enabled {
			continue
		}
		var ch signaling.SignalingChannel
		switch chCfg.Type {
		case "telegram":
			token := chCfg.Params["token"]
			chatID := chCfg.Params["chat_id"]
			proxy := chCfg.Params["proxy"]
			if token == "" || chatID == "" {
				continue
			}
			ch = signaling.NewTelegramChannel(token, chatID, proxy)

		case "mqtt":
			brokerURL := chCfg.Params["broker_url"]
			if brokerURL == "" {
				brokerURL = chCfg.Params["broker"]
			}
			topic := chCfg.Params["topic"]
			clientID := chCfg.Params["client_id"]
			username := chCfg.Params["username"]
			if username == "" {
				username = chCfg.Params["user"]
			}
			password := chCfg.Params["password"]
			if password == "" {
				password = chCfg.Params["pass"]
			}
			if brokerURL == "" || topic == "" {
				continue
			}
			ch = signaling.NewMQTTChannel(brokerURL, topic, clientID, username, password)

		case "webhook":
			postURL := chCfg.Params["post_url"]
			pollURL := chCfg.Params["poll_url"]
			secret := chCfg.Params["secret"]
			if postURL == "" {
				continue
			}
			ch = signaling.NewWebhookChannel(postURL, pollURL, secret)

		case "dns":
			cfToken := chCfg.Params["cf_api_token"]
			zoneID := chCfg.Params["zone_id"]
			recordName := chCfg.Params["record_name"]
			if cfToken == "" || zoneID == "" || recordName == "" {
				continue
			}
			ch = signaling.NewDNSChannel(cfToken, zoneID, recordName)

		default:
			continue
		}
		channels = append(channels, ch)
	}

	return channels, nil
}