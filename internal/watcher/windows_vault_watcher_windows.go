//go:build windows

package watcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

var (
	modAdvapi32  = syscall.NewLazyDLL("advapi32.dll")
	procCredRead = modAdvapi32.NewProc("CredReadW")
	procCredFree = modAdvapi32.NewProc("CredFree")
)

type winFiletime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type winCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        winFiletime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

func readWindowsVaultGeneric(target string) ([]byte, bool) {
	targetPtr, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return nil, false
	}
	var credPtr uintptr
	r1, _, _ := procCredRead.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		1, // CRED_TYPE_GENERIC
		0,
		uintptr(unsafe.Pointer(&credPtr)),
	)
	if r1 == 0 || credPtr == 0 {
		return nil, false
	}
	defer procCredFree.Call(credPtr)

	cred := (*winCredential)(unsafe.Pointer(credPtr))
	if cred.CredentialBlobSize == 0 || cred.CredentialBlob == nil {
		return nil, false
	}
	raw := unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize)
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, true
}

func extractEmailFromIDToken(idToken string) string {
	parts := strings.Split(strings.TrimSpace(idToken), ".")
	if len(parts) < 2 {
		return ""
	}
	payloadB64 := parts[1]
	if rem := len(payloadB64) % 4; rem != 0 {
		payloadB64 += strings.Repeat("=", 4-rem)
	}
	decoded, err := base64.URLEncoding.DecodeString(payloadB64)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(payloadB64)
		if err != nil {
			return ""
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return ""
	}
	email, _ := claims["email"].(string)
	return strings.TrimSpace(email)
}

func syncAntigravityVaultOnce(authDir string) bool {
	authDir = strings.TrimSpace(authDir)
	if authDir == "" {
		return false
	}
	if st, err := os.Stat(authDir); err != nil || !st.IsDir() {
		return false
	}
	blob, ok := readWindowsVaultGeneric("gemini:antigravity")
	if !ok || len(blob) == 0 {
		return false
	}
	var vaultData map[string]any
	if err := json.Unmarshal(blob, &vaultData); err != nil {
		return false
	}
	tokenObj, _ := vaultData["token"].(map[string]any)
	if tokenObj == nil {
		return false
	}
	refresh, _ := tokenObj["refresh_token"].(string)
	access, _ := tokenObj["access_token"].(string)
	expiry, _ := tokenObj["expiry"].(string)
	idToken, _ := vaultData["id_token"].(string)
	email := extractEmailFromIDToken(idToken)
	refresh = strings.TrimSpace(refresh)
	if refresh == "" {
		return false
	}

	fileName := "antigravity.json"
	if email != "" {
		fileName = "antigravity-" + email + ".json"
	}
	targetPath := filepath.Join(authDir, fileName)

	existingPayload := make(map[string]any)
	if rawExisting, errRead := os.ReadFile(targetPath); errRead == nil {
		_ = json.Unmarshal(rawExisting, &existingPayload)
		oldRefresh, _ := existingPayload["refresh_token"].(string)
		oldEmail, _ := existingPayload["email"].(string)
		if strings.TrimSpace(oldRefresh) == refresh && strings.TrimSpace(oldEmail) == email {
			return false
		}
	}

	existingPayload["type"] = "antigravity"
	existingPayload["refresh_token"] = refresh
	if strings.TrimSpace(access) != "" {
		existingPayload["access_token"] = strings.TrimSpace(access)
	}
	if strings.TrimSpace(expiry) != "" {
		existingPayload["expiry"] = strings.TrimSpace(expiry)
	}
	if email != "" {
		existingPayload["email"] = email
	}
	if _, hasProj := existingPayload["project_id"]; !hasProj {
		existingPayload["project_id"] = "aicode-consumers"
	}

	encoded, errMarshal := json.MarshalIndent(existingPayload, "", "  ")
	if errMarshal != nil {
		return false
	}
	if errMkdir := os.MkdirAll(authDir, 0o700); errMkdir != nil {
		return false
	}
	tmpPath := targetPath + ".tmp"
	if errWrite := os.WriteFile(tmpPath, encoded, 0o600); errWrite != nil {
		return false
	}
	if errRename := os.Rename(tmpPath, targetPath); errRename != nil {
		_ = os.Remove(tmpPath)
		return false
	}
	log.Infof("watcher: auto-synced Antigravity account from Windows Vault -> %s", fileName)
	return true
}

func isTCPPortListening(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func resolveACP2APIBinaryAndConfig() (string, string) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", ""
	}
	base := filepath.Join(home, ".cliproxyapi")
	cfgPath := filepath.Join(base, "acp2api.yaml")
	if st, err := os.Stat(cfgPath); err != nil || st.IsDir() {
		return "", ""
	}
	candidates := []string{
		filepath.Join(base, "acp2api", "node_modules", ".bin", "acp2api.cmd"),
		filepath.Join(base, "acp2api", "node_modules", ".bin", "acp2api"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, cfgPath
		}
	}
	return "", ""
}

func (w *Watcher) startSupervisedACPBridge(ctx context.Context) {
	binPath, cfgPath := resolveACP2APIBinaryAndConfig()
	if binPath == "" || cfgPath == "" {
		return
	}
	go func() {
		var currentCmd *exec.Cmd
		defer func() {
			if currentCmd != nil && currentCmd.Process != nil {
				_ = currentCmd.Process.Kill()
			}
		}()
		for {
			if ctx.Err() != nil || w.stopped.Load() {
				return
			}
			if !isTCPPortListening("127.0.0.1:10021") {
				cmd := exec.CommandContext(ctx, binPath, "--config", cfgPath)
				cmd.Dir = filepath.Dir(cfgPath)
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
				if errStart := cmd.Start(); errStart == nil {
					currentCmd = cmd
					log.Infof("watcher: started supervised Claude Code ACP bridge (%s)", filepath.Base(binPath))
					_ = cmd.Wait()
					currentCmd = nil
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
	}()
}

func (w *Watcher) startPlatformAccountWatcher(ctx context.Context) {
	if w == nil {
		return
	}
	syncAntigravityVaultOnce(w.authDir)
	w.startSupervisedACPBridge(ctx)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if w.stopped.Load() {
					return
				}
				syncAntigravityVaultOnce(w.authDir)
			}
		}
	}()
}
