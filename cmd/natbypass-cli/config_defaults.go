package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/natbypass/natbypass/internal/config"
	"github.com/natbypass/natbypass/internal/constants"
)

// resolveConfigPath returns an absolute path for the config file.
func resolveConfigPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	exePath, err := os.Executable()
	if err != nil {
		return path
	}
	return filepath.Join(filepath.Dir(exePath), path)
}

// loadConfigOrDefault loads configuration from path or initializes defaults if missing.
func loadConfigOrDefault(path string, createIfMissing bool) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg = buildDefaultConfig()
			if createIfMissing {
				ensureConfigFileExists(path)
			}
		} else {
			return nil, fmt.Errorf("failed to load configuration: %w", err)
		}
	}
	applyBuiltinDefaults(cfg)
	return cfg, nil
}

// buildDefaultConfig constructs a clean default configuration with an isolated random mesh profile.
func buildDefaultConfig() *config.Config {
	cfg := &config.Config{}

	cfg.App.LogLevel = "info"
	cfg.App.PublishInterval = int(constants.DefaultPublishInterval.Seconds())
	cfg.WebUI.Enabled = true
	cfg.WebUI.Port = constants.DefaultWebUIPort
	cfg.Network.UpnpEnabled = true
	cfg.Network.IPTimeout = int(constants.DefaultIPTimeout.Seconds())
	cfg.Network.UDPPort = constants.DefaultUDPPort
	cfg.WireGuard.Enabled = true
	cfg.WireGuard.ListenPort = constants.DefaultWGListenPort
	cfg.WireGuard.MTU = constants.DefaultWGMTU

	// Generate default random isolated mesh profile
	defaultProf := config.GenerateDefaultProfile("Main Network")
	cfg.Profiles = []config.Profile{defaultProf}
	cfg.ActiveProfileID = defaultProf.ID

	return cfg
}

// applyBuiltinDefaults applies fallback values to missing or zero fields.
func applyBuiltinDefaults(cfg *config.Config) {
	if cfg.App.LogLevel == "" {
		cfg.App.LogLevel = "info"
	}
	if cfg.App.PublishInterval <= 0 {
		cfg.App.PublishInterval = int(constants.DefaultPublishInterval.Seconds())
	}
	if cfg.WebUI.Port <= 0 {
		cfg.WebUI.Port = constants.DefaultWebUIPort
	}
	if cfg.Network.IPTimeout <= 0 {
		cfg.Network.IPTimeout = int(constants.DefaultIPTimeout.Seconds())
	}
	if cfg.Network.UDPPort <= 0 {
		cfg.Network.UDPPort = constants.DefaultUDPPort
	}
	if cfg.WireGuard.ListenPort <= 0 {
		cfg.WireGuard.ListenPort = constants.DefaultWGListenPort
	}
	if cfg.WireGuard.MTU <= 0 {
		cfg.WireGuard.MTU = constants.DefaultWGMTU
	}
	if len(cfg.Network.StunServers) == 0 {
		cfg.Network.StunServers = []string{
			"stun.l.google.com:19302",
			"stun1.l.google.com:19302",
			"stun.cloudflare.com:3478",
		}
	}
	if len(cfg.Network.IPApis) == 0 {
		cfg.Network.IPApis = []string{
			"https://api.ipify.org",
			"https://ifconfig.me/ip",
			"https://icanhazip.com",
			"https://ident.me",
		}
	}
}

// ensureConfigFileExists writes a default config to path if it does not yet exist.
func ensureConfigFileExists(path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := buildDefaultConfig()
		_ = config.Save(cfg, path, false)
	}
}

// ifEmpty returns fallback if val is empty.
func ifEmpty(val, fallback string) string {
	if val == "" {
		return fallback
	}
	return val
}