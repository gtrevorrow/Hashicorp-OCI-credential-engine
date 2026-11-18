//go:build integration

package ocibackend

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Opt-in acceptance against an isolated child Vault and a local synthetic OCI
// endpoint. No existing Vault instance, ~/.vault-token, or OCI account is used.
func TestIntegrationVaultAuditProtectsCredentialMaterial(t *testing.T) {
	if os.Getenv("OCI_SECURITY_AUDIT_TEST") != "1" {
		t.Skip("set OCI_SECURITY_AUDIT_TEST=1 to exercise a disposable local Vault")
	}
	vaultPath, err := exec.LookPath("vault")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	directory := t.TempDir()
	plugins := filepath.Join(directory, "plugins")
	require.NoError(t, os.Mkdir(plugins, 0700))
	binary := filepath.Join(plugins, "vault-plugin-secrets-oci")
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", binary, ".")
	cwd, err := os.Getwd()
	require.NoError(t, err)
	build.Dir = filepath.Dir(cwd)
	output, err := build.CombinedOutput()
	require.NoError(t, err, "plugin build failed: %s", output)
	image, err := os.ReadFile(binary)
	require.NoError(t, err)
	checksum := sha256.Sum256(image)

	goodSubject := "SUBJECT_JWT_CANARY_6984a9"
	badSubject := "REJECTED_SUBJECT_CANARY_4901ab"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error("mock OCI could not parse form")
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("opc-request-id", loggingRequestID)
		if r.Form.Get("subject_token") == badSubject {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": loggingClientSecret, "error_description": loggingClaim + " " + badSubject + " " + loggingSession})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": loggingSession, "expires_in": 600})
	}))
	defer upstream.Close()
	certificate := filepath.Join(directory, "mock-oci-ca.pem")
	require.NoError(t, os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0600))
	rootBytes := make([]byte, 32)
	_, err = rand.Read(rootBytes)
	require.NoError(t, err)
	rootToken := hex.EncodeToString(rootBytes)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	serverLog := filepath.Join(directory, "vault.log")
	log, err := os.OpenFile(serverLog, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	defer log.Close()
	server := exec.CommandContext(ctx, vaultPath, "server", "-dev", "-dev-no-store-token", "-dev-listen-address="+address, "-dev-plugin-dir="+plugins, "-log-level=info")
	server.Stdout, server.Stderr = log, log
	for _, entry := range os.Environ() {
		name := strings.SplitN(entry, "=", 2)[0]
		if strings.HasPrefix(name, "VAULT_") || strings.HasPrefix(name, "OCI_") || strings.HasSuffix(strings.ToLower(name), "_proxy") || name == "SSL_CERT_FILE" || name == "SSL_CERT_DIR" {
			continue
		}
		server.Env = append(server.Env, entry)
	}
	server.Env = append(server.Env, "VAULT_DEV_ROOT_TOKEN_ID="+rootToken, "SSL_CERT_FILE="+certificate)
	require.NoError(t, server.Start())
	exited := make(chan struct{})
	go func() { _ = server.Wait(); close(exited) }()
	defer func() {
		_ = server.Process.Signal(os.Interrupt)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = server.Process.Kill()
			<-exited
		}
	}()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	call := func(method, path string, payload interface{}) (int, []byte, error) {
		var body bytes.Buffer
		if payload != nil {
			if err := json.NewEncoder(&body).Encode(payload); err != nil {
				return 0, nil, err
			}
		}
		request, err := http.NewRequestWithContext(ctx, method, "http://"+address+"/v1/"+path, &body)
		if err != nil {
			return 0, nil, err
		}
		request.Header.Set("X-Vault-Token", rootToken)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			return 0, nil, err
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		return response.StatusCode, data, err
	}
	ready := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		select {
		case <-exited:
			t.Fatal("disposable Vault exited before readiness; output remains private")
		default:
		}
		status, _, err := call(http.MethodGet, "auth/token/lookup-self", nil)
		if err == nil && status == http.StatusOK {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.True(t, ready, "disposable Vault did not authenticate its private root token")
	write := func(path string, payload interface{}) []byte {
		t.Helper()
		status, body, err := call(http.MethodPost, path, payload)
		require.NoError(t, err)
		require.True(t, status >= 200 && status < 300, "Vault operation %s failed with status %d; response suppressed", path, status)
		return body
	}
	auditPath := filepath.Join(directory, "audit.log")
	write("sys/audit/security-review", map[string]interface{}{"type": "file", "options": map[string]string{"file_path": auditPath, "mode": "0600"}})
	write("sys/plugins/catalog/secret/oci", map[string]string{"sha256": hex.EncodeToString(checksum[:]), "command": "vault-plugin-secrets-oci"})
	write("sys/mounts/oci", map[string]string{"type": "plugin", "plugin_name": "oci"})
	write("oci/config", map[string]interface{}{"domain_url": upstream.URL, "client_id": "synthetic-client", "client_secret": loggingClientSecret, "enable_plugin_issued_subject_token": false, "default_ttl": 60, "max_ttl": 600})
	success := write("oci/exchange", map[string]string{"subject_token": goodSubject})
	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(success, &response))
	data, ok := response["data"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, loggingSession, data["access_token"])
	private, ok := data["private_key"].(string)
	require.True(t, ok)
	require.Contains(t, private, "BEGIN PRIVATE KEY")
	status, rejected, err := call(http.MethodPost, "oci/exchange", map[string]string{"subject_token": badSubject})
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status)
	assertNoCredentialValues(t, string(rejected), goodSubject, badSubject, rootToken)
	require.Contains(t, string(rejected), "oci_rejected")
	audit, err := os.ReadFile(auditPath)
	require.NoError(t, err)
	assertNoCredentialValues(t, string(audit), goodSubject, badSubject, rootToken, strings.Split(private, "\n")[1])
	require.Contains(t, string(audit), "hmac-sha256:")
	require.Contains(t, string(audit), "oci/exchange")
	require.Contains(t, string(audit), "private_key")
	operations, err := os.ReadFile(serverLog)
	require.NoError(t, err)
	// Vault's dev startup deliberately prints its root token to the private server
	// log. Examine project-owned events separately from those dev startup lines.
	var events []string
	var infoConfiguration, warnRejection bool
	for _, line := range strings.Split(string(operations), "\n") {
		if strings.Contains(line, "OCI security event") {
			events = append(events, line)
			infoConfiguration = infoConfiguration || (strings.Contains(line, "[INFO]") && strings.Contains(line, "configuration_changed"))
			warnRejection = warnRejection || (strings.Contains(line, "[WARN]") && strings.Contains(line, "oci_rejected"))
		}
	}
	require.NotEmpty(t, events)
	require.True(t, infoConfiguration && warnRejection, "Vault must preserve INFO configuration and WARN rejection levels")
	eventText := strings.Join(events, "\n")
	require.Contains(t, eventText, "credential_exchange")
	require.Contains(t, eventText, "oci_rejected")
	assertNoCredentialValues(t, eventText, goodSubject, badSubject, rootToken, strings.Split(private, "\n")[1])
	info, err := os.Stat(auditPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	t.Log(fmt.Sprintf("Verified credential success/failure, redacted client errors, operational events, and default HMAC audit records with Vault %s", filepath.Base(vaultPath)))
}
