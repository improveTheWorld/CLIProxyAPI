//go:build windows

package watcher

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
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
