// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	secretmocks "github.com/stacklok/toolhive/pkg/secrets/mocks"
)

func TestAuthenticate_NonInteractiveEnvironment(t *testing.T) {
	for _, value := range []string{"", "false", "0", "true", "1", "invalid-secret-value"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(NonInteractiveEnvVarName, value)
			handler := NewHandler(&Config{BearerToken: "configured-token"})
			source, err := handler.Authenticate(t.Context(), "https://unused.example/mcp")
			if value == "invalid-secret-value" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), NonInteractiveEnvVarName)
				assert.NotContains(t, err.Error(), value)
				assert.Nil(t, source)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, source)
			token, err := source.Token()
			require.NoError(t, err)
			assert.Equal(t, "configured-token", token.AccessToken)
		})
	}
}

func TestAuthenticate_NonInteractiveOAuthRecovery(t *testing.T) {
	for _, tt := range []struct {
		name          string
		environment   string
		cached        bool
		rejectRefresh bool
	}{
		{name: "fresh authorization refused", environment: "true"},
		{name: "numeric true refuses fresh authorization", environment: "1"},
		{name: "rejected refresh preserves session", environment: "true", cached: true, rejectRefresh: true},
		{name: "cached refresh and token rotation succeed", environment: "true", cached: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(NonInteractiveEnvVarName, tt.environment)
			var refreshes, interactiveRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				baseURL := "http://" + r.Host
				switch r.URL.Path {
				case "/mcp":
					w.Header().Set("WWW-Authenticate", `Bearer realm="`+baseURL+`"`)
					w.WriteHeader(http.StatusUnauthorized)
				case "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server":
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"issuer": baseURL, "authorization_endpoint": baseURL + "/authorize",
						"token_endpoint": baseURL + "/token", "registration_endpoint": baseURL + "/register",
					})
				case "/token":
					refreshes.Add(1)
					if err := r.ParseForm(); err != nil {
						http.Error(w, "bad form", http.StatusBadRequest)
						return
					}
					assert.Equal(t, "refresh_token", r.Form.Get("grant_type"))
					assert.Equal(t, "cached-session-secret", r.Form.Get("refresh_token"))
					w.Header().Set("Content-Type", "application/json")
					if tt.rejectRefresh {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = fmt.Fprint(w, `{"error":"invalid_grant","error_description":"cached-session-secret"}`)
						return
					}
					_, _ = fmt.Fprint(w, `{"access_token":"access","refresh_token":"rotated-session","token_type":"Bearer","expires_in":3600}`)
				case "/authorize", "/register":
					interactiveRequests.Add(1)
					http.Error(w, "interactive authorization must not start", http.StatusBadRequest)
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)
			config := &Config{
				Issuer: server.URL, AuthorizeURL: server.URL + "/authorize", TokenURL: server.URL + "/token",
				// Regression protection: a missing noninteractive guard must never
				// open a real browser or wait indefinitely during this test.
				SkipBrowser: true, Timeout: 20 * time.Millisecond,
			}
			provider := secretmocks.NewMockProvider(gomock.NewController(t))
			if tt.cached {
				config.CachedRefreshTokenRef = "refresh-reference"
				config.CachedClientID = "existing-public-client"
				config.CachedRegTokenRef = "registration-reference"
				config.CachedRegClientURI = server.URL + "/register/client"
				config.CachedTokenEndpointAuthMethod = "none"
				envelope, err := encodeCachedRefreshToken("cached-session-secret", server.URL, config.TokenURL)
				require.NoError(t, err)
				provider.EXPECT().GetSecret(gomock.Any(), config.CachedRefreshTokenRef).Return(envelope, nil)
			}
			before := *config
			handler := NewHandler(config)
			handler.SetSecretProvider(provider)
			var persisted string
			handler.SetTokenPersister(func(value string, _ time.Time) error {
				persisted = value
				return nil
			})
			handler.SetClientCredentialsPersister(func(string, string, time.Time, string, string, string, int) error {
				t.Error("noninteractive recovery must not register a fresh client")
				return nil
			})
			source, err := handler.Authenticate(t.Context(), server.URL+"/mcp")
			if !tt.cached || tt.rejectRefresh {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "non-interactive")
				assert.NotContains(t, err.Error(), "cached-session-secret")
				assert.Nil(t, source)
				assert.Empty(t, persisted)
				assert.Equal(t, before, *config, "failed recovery must preserve cached session metadata")
			} else {
				require.NoError(t, err)
				require.NotNil(t, source)
				token, err := source.Token()
				require.NoError(t, err)
				assert.Equal(t, "access", token.AccessToken)
				envelope, err := decodeCachedRefreshToken(persisted)
				require.NoError(t, err)
				assert.Equal(t, "rotated-session", envelope.Token)
				assert.Equal(t, server.URL, envelope.Issuer)
			}
			assert.Zero(t, interactiveRequests.Load())
			if tt.cached {
				assert.EqualValues(t, 1, refreshes.Load())
			} else {
				assert.Zero(t, refreshes.Load())
			}
		})
	}
}
