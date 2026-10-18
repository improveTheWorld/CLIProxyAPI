//go:build windows

package watcher

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestExtractEmailFromIDToken(t *testing.T) {
	claims, _ := json.Marshal(map[string]any{"email": "dev@example.com"})
	token := "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
	got := extractEmailFromIDToken(token)
	if got != "dev@example.com" {
		t.Fatalf("extractEmailFromIDToken() = %q, want %q", got, "dev@example.com")
	}
}

func TestSyncAntigravityVaultOnce_RunsCleanly(t *testing.T) {
	tmp := t.TempDir()
	_ = syncAntigravityVaultOnce(tmp)
	entries, err := filepath.Glob(filepath.Join(tmp, "antigravity*.json"))
	if err != nil {
		t.Fatalf("Glob error: %v", err)
	}
	t.Logf("vault sync entries in temp dir: %v", entries)
}

func TestEnforceLocalSecurityPolicy(t *testing.T) {
	cfg := &config.Config{
		Host: "0.0.0.0",
		RemoteManagement: config.RemoteManagement{
			DisableAutoUpdatePanel: false,
		},
	}
	enforceLocalSecurityPolicy(cfg)
	if cfg.Host != "127.0.0.1" {
		t.Fatalf("cfg.Host = %q, want 127.0.0.1", cfg.Host)
	}
	if !cfg.RemoteManagement.DisableAutoUpdatePanel {
		t.Fatal("cfg.RemoteManagement.DisableAutoUpdatePanel = false, want true")
	}
}
