// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package remote_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"

	"github.com/stacklok/toolhive/pkg/auth/remote"
	"github.com/stacklok/toolhive/pkg/config"
	"github.com/stacklok/toolhive/pkg/secrets"
)

// TestHandler_EncryptedOAuthWorkflow uses separate processes so the OS credential
// backend can be replaced before any secret factory initializes. Only that
// boundary is mocked: HTTP, OAuth, PKCE, encryption, and disk persistence are real.
func TestHandler_EncryptedOAuthWorkflow(t *testing.T) {
	if stage := os.Getenv("TOOLHIVE_OAUTH_FIXTURE_STAGE"); stage != "" {
		runEncryptedOAuthChild(t, stage)
		return
	}
	t.Parallel()
	root := t.TempDir()
	fixture := &encryptedOAuthFixture{calls: make(map[string]int)}
	server := httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(server.Close)
	fixture.mu.Lock()
	fixture.endpoint = server.URL
	fixture.mu.Unlock()
	executable, err := os.Executable()
	require.NoError(t, err)
	for stage := range 3 {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		t.Cleanup(cancel)
		command := exec.CommandContext(ctx, executable, "-test.run=^TestHandler_EncryptedOAuthWorkflow$", "-test.v")
		command.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"TOOLHIVE_OAUTH_FIXTURE_STAGE=" + strconv.Itoa(stage),
			"TOOLHIVE_OAUTH_FIXTURE_ENDPOINT=" + server.URL,
			"TOOLHIVE_OAUTH_FIXTURE_ROOT=" + root,
			"XDG_DATA_HOME=" + filepath.Join(root, "data"),
			"XDG_CONFIG_HOME=" + filepath.Join(root, "config"),
			"XDG_CACHE_HOME=" + filepath.Join(root, "cache"),
			"XDG_STATE_HOME=" + filepath.Join(root, "state"),
			"XDG_RUNTIME_DIR=" + filepath.Join(root, "run"),
			"TOOLHIVE_SECRETS_PROVIDER=bitwarden",
			"TOOLHIVE_BWS_PATH=" + filepath.Join(root, "bws-must-not-be-used"),
		}
		var output, stderrOutput bytes.Buffer
		command.Stdout = &output
		stderr, err := command.StderrPipe()
		require.NoError(t, err)
		require.NoError(t, command.Start())
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			const prefix = "Please open this URL in your browser: "
			if strings.HasPrefix(line, prefix) {
				require.Zero(t, stage, "restart unexpectedly requested browser authorization")
				client := &http.Client{Timeout: 10 * time.Second}
				response, requestErr := client.Get(strings.TrimPrefix(line, prefix))
				require.NoError(t, requestErr)
				_, copyErr := io.Copy(io.Discard, response.Body)
				require.NoError(t, copyErr)
				require.NoError(t, response.Body.Close())
				require.Equal(t, http.StatusOK, response.StatusCode)
			} else {
				stderrOutput.WriteString(line + "\n")
			}
		}
		require.NoError(t, scanner.Err())
		err = command.Wait()
		cancel()
		require.NoError(t, err, "stage %d: %s\n%s", stage, output.String(), stderrOutput.String())
		encrypted, err := os.ReadFile(filepath.Join(root, "data", "toolhive", "secrets_encrypted"))
		require.NoError(t, err)
		require.True(t, bytes.HasPrefix(encrypted, []byte("THVSEC")))
		metadata, err := os.ReadFile(filepath.Join(root, "oauth-config.json"))
		require.NoError(t, err)
		for _, token := range []string{"fixture-refresh-0", "fixture-refresh-1", "fixture-refresh-2", "fixture-access-0", "fixture-access-1", "fixture-access-2"} {
			require.NotContains(t, string(encrypted), token)
			require.NotContains(t, string(metadata), token)
		}
		t.Logf("process %d: authenticated MCP initialize/list/call; encrypted refresh token persisted", stage)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	require.Equal(t, 1, fixture.authorizations)
	require.Equal(t, []string{"authorization_code", "refresh_token", "refresh_token"}, fixture.grants)
	require.Equal(t, map[string]int{"initialize": 3, "notifications/initialized": 3, "tools/list": 3, "tools/call": 3}, fixture.calls)
}

type encryptedOAuthFixture struct {
	mu             sync.Mutex
	endpoint       string
	challenge      string
	authorizations int
	grants         []string
	calls          map[string]int
}

func (f *encryptedOAuthFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.endpoint, "authorization_endpoint": f.endpoint + "/authorize", "token_endpoint": f.endpoint + "/token", "response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}})
	case "/authorize":
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("resource") != f.endpoint+"/mcp" {
			http.Error(w, "invalid PKCE authorization", 400)
			return
		}
		f.authorizations++
		f.challenge = q.Get("code_challenge")
		callback, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "invalid callback", 400)
			return
		}
		values := callback.Query()
		values.Set("code", "fixture-code")
		values.Set("state", q.Get("state"))
		callback.RawQuery = values.Encode()
		http.Redirect(w, r, callback.String(), http.StatusFound)
	case "/token":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", 400)
			return
		}
		grant := r.Form.Get("grant_type")
		number := len(f.grants)
		if grant == "authorization_code" {
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if number != 0 || r.Form.Get("code") != "fixture-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
				http.Error(w, "PKCE validation failed", 400)
				return
			}
		} else if grant != "refresh_token" || r.Form.Get("refresh_token") != fmt.Sprintf("fixture-refresh-%d", number-1) {
			http.Error(w, "invalid rotated refresh token", 400)
			return
		}
		if r.Form.Get("resource") != f.endpoint+"/mcp" {
			http.Error(w, "missing resource binding", 400)
			return
		}
		f.grants = append(f.grants, grant)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("fixture-access-%d", number), "refresh_token": fmt.Sprintf("fixture-refresh-%d", number), "token_type": "Bearer", "expires_in": 3600})
	case "/mcp":
		if r.Header.Get("Authorization") != fmt.Sprintf("Bearer fixture-access-%d", len(f.grants)-1) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+f.endpoint+`"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var request struct {
			ID     *int           `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid RPC", 400)
			return
		}
		f.calls[request.Method]++
		var result any
		switch request.Method {
		case "initialize":
			if request.Params["protocolVersion"] != "2025-11-25" || request.Params["capabilities"] == nil || request.Params["clientInfo"] == nil {
				http.Error(w, "invalid initialization parameters", http.StatusBadRequest)
				return
			}
			result = map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "oauth-fixture", "version": "1"}}
		case "notifications/initialized":
			if request.ID != nil || f.calls["initialize"] != f.calls["notifications/initialized"] {
				http.Error(w, "invalid initialized notification", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			return
		case "tools/list":
			if len(request.Params) != 0 || f.calls["notifications/initialized"] != f.calls["initialize"] {
				http.Error(w, "invalid tools list", http.StatusBadRequest)
				return
			}
			result = map[string]any{"tools": []any{map[string]any{"name": "ping", "inputSchema": map[string]any{"type": "object"}}}}
		case "tools/call":
			if request.Params["name"] != "ping" || request.Params["arguments"] == nil {
				http.Error(w, "invalid tools call", http.StatusBadRequest)
				return
			}
			result = map[string]any{"content": []any{map[string]string{"type": "text", "text": "oauth-workflow-ok"}}}
		default:
			http.Error(w, "unexpected RPC", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
	default:
		http.NotFound(w, r)
	}
}

func runEncryptedOAuthChild(t *testing.T, stage string) {
	t.Helper()
	// Install the in-memory keyring before constructing any provider: real OS
	// keyring reads/writes, including availability probes, must never happen here.
	keyring.MockInit()
	require.NoError(t, keyring.Set("toolhive", "toolhive", "fixture-only-local-encryption-password"))
	xdg.Reload()
	require.Empty(t, os.Getenv("BWS_ACCESS_TOKEN"))
	settings := config.Secrets{ProviderType: "bitwarden", SetupCompleted: true}
	systemType, err := settings.GetSystemProviderType()
	require.NoError(t, err)
	require.Equal(t, secrets.EncryptedType, systemType)
	local, err := secrets.CreateProvider(systemType, secrets.WithScope(secrets.ScopeWorkloads))
	require.NoError(t, err)
	endpoint := os.Getenv("TOOLHIVE_OAUTH_FIXTURE_ENDPOINT")
	configPath := filepath.Join(os.Getenv("TOOLHIVE_OAUTH_FIXTURE_ROOT"), "oauth-config.json")
	cfg := &remote.Config{ClientID: "fixture-public-client", Issuer: endpoint, AuthorizeURL: endpoint + "/authorize", TokenURL: endpoint + "/token", Resource: endpoint + "/mcp", SkipBrowser: true, UsePKCE: true, Timeout: 20 * time.Second}
	if stage != "0" {
		saved, readErr := os.ReadFile(configPath)
		require.NoError(t, readErr)
		require.NoError(t, json.Unmarshal(saved, cfg))
	}
	handler := remote.NewHandler(cfg)
	handler.SetSecretProvider(local)
	handler.SetTokenPersister(func(value string, expiry time.Time) error {
		const ref = "OAUTH_REFRESH_TOKEN_fixture"
		if writeErr := local.SetSecret(t.Context(), ref, value); writeErr != nil {
			return writeErr
		}
		cfg.CachedRefreshTokenRef = ref
		cfg.CachedTokenExpiry = expiry
		saved, marshalErr := json.Marshal(cfg)
		if marshalErr != nil {
			return marshalErr
		}
		return os.WriteFile(configPath, saved, 0600)
	})
	source, err := handler.Authenticate(t.Context(), endpoint+"/mcp")
	require.NoError(t, err)
	require.NotNil(t, source)
	client := oauth2.NewClient(t.Context(), source)
	client.Timeout = 5 * time.Second
	requests := []struct {
		body   string
		status int
		want   string
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"oauth-workflow-test","version":"1"}}}`, http.StatusOK, `"protocolVersion":"2025-11-25"`},
		{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, http.StatusAccepted, ""},
		{`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, http.StatusOK, `"name":"ping"`},
		{`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping","arguments":{}}}`, http.StatusOK, "oauth-workflow-ok"},
	}
	for _, step := range requests {
		request, requestErr := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint+"/mcp", strings.NewReader(step.body))
		require.NoError(t, requestErr)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("MCP-Protocol-Version", "2025-11-25")
		response, requestErr := client.Do(request)
		require.NoError(t, requestErr)
		payload, readErr := io.ReadAll(response.Body)
		require.NoError(t, readErr)
		require.NoError(t, response.Body.Close())
		require.Equal(t, step.status, response.StatusCode, "%s", payload)
		if step.want != "" {
			require.Contains(t, string(payload), `"result"`)
			require.Contains(t, string(payload), step.want)
		} else {
			require.Empty(t, payload)
		}
	}
	stored, err := local.GetSecret(t.Context(), cfg.CachedRefreshTokenRef)
	require.NoError(t, err)
	var envelope struct {
		Token    string `json:"token"`
		Issuer   string `json:"issuer"`
		TokenURL string `json:"token_url"`
	}
	require.NoError(t, json.Unmarshal([]byte(stored), &envelope))
	require.Equal(t, "fixture-refresh-"+stage, envelope.Token)
	require.Equal(t, endpoint, envelope.Issuer)
	require.Equal(t, endpoint+"/token", envelope.TokenURL)
}
