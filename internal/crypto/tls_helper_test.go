package crypto

import (
	"crypto/tls"
	"os"
	"testing"
)

func TestBuildTLSConfig(t *testing.T) {
	// 1. Standard remote broker URL
	cfg := BuildTLSConfig("ssl://broker.emqx.io:8883")
	if cfg.InsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify to be false for public broker, got true")
	}
	if cfg.ServerName != "broker.emqx.io" {
		t.Errorf("expected ServerName broker.emqx.io, got %s", cfg.ServerName)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS 1.2, got %x", cfg.MinVersion)
	}
	if cfg.RootCAs == nil {
		t.Errorf("expected non-nil RootCAs")
	}

	// 2. Localhost dev/test URL
	cfgLocal := BuildTLSConfig("wss://localhost:8443")
	if !cfgLocal.InsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify to be true for localhost, got false")
	}

	// 3. Env override
	os.Setenv("NATBYPASS_TLS_INSECURE", "1")
	defer os.Unsetenv("NATBYPASS_TLS_INSECURE")

	cfgInsecure := BuildTLSConfig("ssl://broker.hivemq.com:8883")
	if !cfgInsecure.InsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify to be true when NATBYPASS_TLS_INSECURE=1, got false")
	}
}
