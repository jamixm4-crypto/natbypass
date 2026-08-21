package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// AppConfig — базовые настройки приложения
type AppConfig struct {
	Name            string `mapstructure:"name"`
	Version         string `mapstructure:"version"`
	LogLevel        string `mapstructure:"log_level"`
	LogFile         string `mapstructure:"log_file"`
	DeviceID        string `mapstructure:"device_id"`
	PublishInterval int    `mapstructure:"publish_interval"`
}

// WebUIConfig — настройки встроенного Web UI
type WebUIConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// NetworkConfig — сетевые настройки
type NetworkConfig struct {
	StunServers []string `mapstructure:"stun_servers"`
	UpnpEnabled bool     `mapstructure:"upnp_enabled"`
	IPApis      []string `mapstructure:"ip_apis"`
	IPTimeout   int      `mapstructure:"ip_timeout"`
	DoHEnabled  bool     `mapstructure:"doh_enabled"`
	DoHProvider string   `mapstructure:"doh_provider"`
	Socks5Proxy string   `mapstructure:"socks5_proxy"`
}

// ChannelConfig — настройки одного сигнального канала
type ChannelConfig struct {
	Type     string            `mapstructure:"type"`
	Priority int               `mapstructure:"priority"`
	Enabled  bool              `mapstructure:"enabled"`
	Params   map[string]string `mapstructure:"params"`
}

// SignalingConfig — конфигурация всех сигнальных каналов
type SignalingConfig struct {
	Channels []ChannelConfig `mapstructure:"channels"`
}

// WGPeerConfig — настройки одного WG пира
type WGPeerConfig struct {
	PublicKey string   `mapstructure:"public_key"`
	Endpoint  string   `mapstructure:"endpoint"`
	AllowedIP []string `mapstructure:"allowed_ips"`
}

// WireGuardConfig — настройки WireGuard
type WireGuardConfig struct {
	Enabled        bool           `mapstructure:"enabled"`
	Interface      string         `mapstructure:"interface"`
	ListenPort     int            `mapstructure:"listen_port"`
	PrivateKeyFile string         `mapstructure:"private_key_file"`
	Address        string         `mapstructure:"address"`
	DNS            string         `mapstructure:"dns"`
	MTU            int            `mapstructure:"mtu"`
	Peers          []WGPeerConfig `mapstructure:"peers"`
}

// CryptoConfig — настройки шифрования NaCl
type CryptoConfig struct {
	PublicKey    string   `mapstructure:"public_key"`
	PrivateKey   string   `mapstructure:"private_key"`
	KeysFile     string   `mapstructure:"keys_file"`
	TrustedKeys  []string `mapstructure:"trusted_keys"`
}

// DaemonConfig — настройки демона
type DaemonConfig struct {
	PidFile       string `mapstructure:"pid_file"`
	SyslogEnabled bool   `mapstructure:"syslog_enabled"`
	RestartDelay  int    `mapstructure:"restart_delay"`
}

// Config — корневая структура конфигурации
type Config struct {
	App       AppConfig       `mapstructure:"app"`
	WebUI     WebUIConfig     `mapstructure:"web_ui"`
	Network   NetworkConfig   `mapstructure:"network"`
	Signaling SignalingConfig `mapstructure:"signaling"`
	WireGuard WireGuardConfig `mapstructure:"wireguard"`
	Crypto    CryptoConfig    `mapstructure:"crypto"`
	Daemon    DaemonConfig    `mapstructure:"daemon"`
}

// setDefaults устанавливает значения по умолчанию
func setDefaults(v *viper.Viper) {
	v.SetDefault("app.name", "NatBypass")
	v.SetDefault("app.log_level", "info")
	v.SetDefault("app.publish_interval", 60)

	v.SetDefault("web_ui.enabled", true)
	v.SetDefault("web_ui.port", 8080)

	v.SetDefault("network.upnp_enabled", true)
	v.SetDefault("network.ip_timeout", 10)
	v.SetDefault("network.stun_servers", []string{
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"stun.cloudflare.com:3478",
	})
	v.SetDefault("network.ip_apis", []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
	})

	v.SetDefault("wireguard.interface", "wg0")
	v.SetDefault("wireguard.listen_port", 51820)
	v.SetDefault("wireguard.mtu", 1420)

	v.SetDefault("daemon.pid_file", "/var/run/natbypass.pid")
	v.SetDefault("daemon.restart_delay", 5)
}

// Load загружает конфигурацию из файла с поддержкой переменных окружения
func Load(path string) (*Config, error) {
	v := viper.New()

	// Если передан относительный путь, проверяем как в cwd, так и рядом с .exe
	if !filepath.IsAbs(path) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if exePath, err := os.Executable(); err == nil {
				candidate := filepath.Join(filepath.Dir(exePath), path)
				if _, err := os.Stat(candidate); err == nil {
					path = candidate
				}
			}
		}
	}

	v.SetConfigFile(path)

	// Поддержка переменных окружения: NATBYPASS_APP_LOGLEVEL → app.log_level
	v.SetEnvPrefix("NATBYPASS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	setDefaults(v)

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Reload перезагружает конфиг (вызывается по SIGHUP)
func Reload(cfg *Config, path string) error {
	newCfg, err := Load(path)
	if err != nil {
		return err
	}
	*cfg = *newCfg
	return nil
}
