package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// HeaderEncryptedConfig — сигнатура заголовка зашифрованного файла конфигурации
const HeaderEncryptedConfig = "# NATBYPASS_ENCRYPTED_CONFIG:v1"

// AppConfig — базовые настройки приложения
type AppConfig struct {
	Name            string            `mapstructure:"name" yaml:"name"`
	Version         string            `mapstructure:"version" yaml:"version,omitempty"`
	LogLevel        string            `mapstructure:"log_level" yaml:"log_level"`
	LogFile         string            `mapstructure:"log_file" yaml:"log_file,omitempty"`
	DeviceID        string            `mapstructure:"device_id" yaml:"device_id,omitempty"`
	DeviceName      string            `mapstructure:"device_name" yaml:"device_name"`
	SaveLogsToDisk  bool              `mapstructure:"save_logs" yaml:"save_logs"`
	ShowDiagnostics bool              `mapstructure:"show_diagnostics" yaml:"show_diagnostics"`
	AddressBook     map[string]string `mapstructure:"address_book" yaml:"address_book,omitempty"`
	PublishInterval int               `mapstructure:"publish_interval" yaml:"publish_interval"`
}

// WebUIConfig — настройки встроенного Web UI
type WebUIConfig struct {
	Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
	Port     int    `mapstructure:"port" yaml:"port"`
	Username string `mapstructure:"username" yaml:"username,omitempty"`
	Password string `mapstructure:"password" yaml:"password,omitempty"`
}

// NetworkConfig — сетевые настройки
type NetworkConfig struct {
	Address            string   `mapstructure:"address" yaml:"address,omitempty"`
	StunServers        []string `mapstructure:"stun_servers" yaml:"stun_servers,omitempty"`

	UpnpEnabled        bool     `mapstructure:"upnp_enabled" yaml:"upnp_enabled"`
	IPApis             []string `mapstructure:"ip_apis" yaml:"ip_apis,omitempty"`
	IPTimeout          int      `mapstructure:"ip_timeout" yaml:"ip_timeout,omitempty"`
	DoHEnabled         bool     `mapstructure:"doh_enabled" yaml:"doh_enabled,omitempty"`
	DoHProvider        string   `mapstructure:"doh_provider" yaml:"doh_provider,omitempty"`
	Socks5Proxy        string   `mapstructure:"socks5_proxy" yaml:"socks5_proxy,omitempty"`
	AllowExitNode      bool     `mapstructure:"allow_exit_node" yaml:"allow_exit_node"`
	AdvertisedSubnets  []string `mapstructure:"advertised_subnets" yaml:"advertised_subnets,omitempty"`
	SelectedExitNode   string   `mapstructure:"selected_exit_node" yaml:"selected_exit_node,omitempty"`
	ActiveSubnetRoutes []string `mapstructure:"active_subnet_routes" yaml:"active_subnet_routes,omitempty"`
	// UDPPort — локальный порт UDP Hole Punch сокета.
	// 0 (по умолчанию) = OS назначает случайный порт.
	// Задайте явно (например, 47832) если нужен фиксированный порт для firewall-правил.
	// НЕ используйте 51820 если на этой машине работает локальный WireGuard/AmneziaWG!
	UDPPort int `mapstructure:"udp_port" yaml:"udp_port,omitempty"`
}

// ChannelConfig — настройки одного сигнального канала
type ChannelConfig struct {
	Type     string            `mapstructure:"type" yaml:"type"`
	Priority int               `mapstructure:"priority" yaml:"priority"`
	Enabled  bool              `mapstructure:"enabled" yaml:"enabled"`
	Params   map[string]string `mapstructure:"params" yaml:"params,omitempty"`
}

// SignalingConfig — конфигурация всех сигнальных каналов
type SignalingConfig struct {
	DefaultChannel string          `mapstructure:"default_channel" yaml:"default_channel,omitempty"`
	MQTTBroker     string          `mapstructure:"mqtt_broker" yaml:"mqtt_broker,omitempty"`
	MQTTTopic      string          `mapstructure:"mqtt_topic" yaml:"mqtt_topic,omitempty"`
	Channels       []ChannelConfig `mapstructure:"channels" yaml:"channels,omitempty"`
}


// WGPeerConfig — настройки одного WG пира
type WGPeerConfig struct {
	PublicKey string   `mapstructure:"public_key" yaml:"public_key"`
	Endpoint  string   `mapstructure:"endpoint" yaml:"endpoint,omitempty"`
	AllowedIP []string `mapstructure:"allowed_ips" yaml:"allowed_ips,omitempty"`
}

// AWGConfig — параметры обфускации AmneziaWG 2.0
type AWGConfig struct {
	Enabled bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Jc      int    `mapstructure:"jc" json:"jc" yaml:"jc,omitempty"`
	Jmin    int    `mapstructure:"jmin" json:"jmin" yaml:"jmin,omitempty"`
	Jmax    int    `mapstructure:"jmax" json:"jmax" yaml:"jmax,omitempty"`
	S1      int    `mapstructure:"s1" json:"s1" yaml:"s1,omitempty"`
	S2      int    `mapstructure:"s2" json:"s2" yaml:"s2,omitempty"`
	H1      uint32 `mapstructure:"h1" json:"h1" yaml:"h1,omitempty"`
	H2      uint32 `mapstructure:"h2" json:"h2" yaml:"h2,omitempty"`
	H3      uint32 `mapstructure:"h3" json:"h3" yaml:"h3,omitempty"`
	H4      uint32 `mapstructure:"h4" json:"h4" yaml:"h4,omitempty"`
}

// WireGuardConfig — настройки WireGuard и AmneziaWG 2.0
type WireGuardConfig struct {
	Enabled        bool           `mapstructure:"enabled" yaml:"enabled"`
	Interface      string         `mapstructure:"interface" yaml:"interface,omitempty"`
	ListenPort     int            `mapstructure:"listen_port" yaml:"listen_port,omitempty"`
	PrivateKeyFile string         `mapstructure:"private_key_file" yaml:"private_key_file,omitempty"`
	Address        string         `mapstructure:"address" yaml:"address,omitempty"`
	DNS            string         `mapstructure:"dns" yaml:"dns,omitempty"`
	MTU            int            `mapstructure:"mtu" yaml:"mtu,omitempty"`
	AWG            AWGConfig      `mapstructure:"awg" yaml:"awg,omitempty"`
	Peers          []WGPeerConfig `mapstructure:"peers" yaml:"peers,omitempty"`
}

// CryptoConfig — настройки шифрования NaCl
type CryptoConfig struct {
	PublicKey    string   `mapstructure:"public_key" yaml:"public_key,omitempty"`
	PrivateKey   string   `mapstructure:"private_key" yaml:"private_key,omitempty"`
	KeysFile     string   `mapstructure:"keys_file" yaml:"keys_file,omitempty"`
	TrustedKeys  []string `mapstructure:"trusted_keys" yaml:"trusted_keys,omitempty"`
}

// DaemonConfig — настройки демона
type DaemonConfig struct {
	PidFile       string `mapstructure:"pid_file" yaml:"pid_file,omitempty"`
	SyslogEnabled bool   `mapstructure:"syslog_enabled" yaml:"syslog_enabled,omitempty"`
	RestartDelay  int    `mapstructure:"restart_delay" yaml:"restart_delay,omitempty"`
}

// Config — корневая структура конфигурации
type Config struct {
	App             AppConfig       `mapstructure:"app" yaml:"app"`
	WebUI           WebUIConfig     `mapstructure:"web_ui" yaml:"web_ui"`
	Network         NetworkConfig   `mapstructure:"network" yaml:"network"`
	Signaling       SignalingConfig `mapstructure:"signaling" yaml:"signaling"`
	WireGuard       WireGuardConfig `mapstructure:"wireguard" yaml:"wireguard"`
	Crypto          CryptoConfig    `mapstructure:"crypto" yaml:"crypto"`
	Daemon          DaemonConfig    `mapstructure:"daemon" yaml:"daemon"`
	Profiles        []Profile       `mapstructure:"profiles" yaml:"profiles,omitempty"`
	ActiveProfileID string          `mapstructure:"active_profile_id" yaml:"active_profile_id,omitempty"`
}

// setDefaults устанавливает значения по умолчанию
func setDefaults(v *viper.Viper) {
	v.SetDefault("app.name", "NatBypass")
	v.SetDefault("app.log_level", "info")
	v.SetDefault("app.publish_interval", 10)
	v.SetDefault("app.save_logs", false)
	v.SetDefault("app.show_diagnostics", false)

	v.SetDefault("web_ui.enabled", true)
	v.SetDefault("web_ui.port", 8080)

	v.SetDefault("network.upnp_enabled", true)
	v.SetDefault("network.ip_timeout", 10)
	v.SetDefault("network.allow_exit_node", false)
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

// Load загружает конфигурацию из файла с поддержкой шифрования и переменных окружения
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

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	plain, err := DecryptConfigData(raw)
	if err != nil {
		return nil, fmt.Errorf("decrypt config: %w", err)
	}

	v.SetConfigType("yaml")

	// Поддержка переменных окружения: NATBYPASS_APP_LOGLEVEL → app.log_level
	v.SetEnvPrefix("NATBYPASS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	setDefaults(v)

	if err := v.ReadConfig(bytes.NewReader(plain)); err != nil {
		return nil, err
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	cfg.EnsureActiveProfile()

	return &cfg, nil
}

// Save сохраняет конфигурацию в YAML файл с опциональным шифрованием
func Save(cfg *Config, path string, encrypt bool) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}

	yamlData, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config to yaml: %w", err)
	}

	outData := yamlData
	if encrypt {
		encData, err := EncryptConfigData(yamlData)
		if err != nil {
			return fmt.Errorf("failed to encrypt config: %w", err)
		}
		outData = encData
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(path, outData, 0600); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}

	return nil
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
