// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.yaml.in/yaml/v3"

	"github.com/stacklok/toolhive/pkg/auth/remote"
	secretsmocks "github.com/stacklok/toolhive/pkg/secrets/mocks"
)

func TestRunConfig_WithSecretsSeparatesProviders(t *testing.T) {
	t.Parallel()

	const (
		externalClient = "bws://12345678-1234-4234-8234-123456789abc"
		externalBearer = "bws://87654321-4321-4321-8321-cba987654321"
		clientValue    = "sentinel-client-secret-value"
		bearerValue    = "sentinel-bearer-token-value"
		headerValue    = "sentinel-header-secret-value"
	)

	for _, tc := range []struct {
		name           string
		clientRef      string
		bearerRef      string
		externalClient bool
		externalBearer bool
	}{
		{"generated auth stays local", "OAUTH_CLIENT_SECRET_workload", "BEARER_TOKEN_workload", false, false},
		{"static auth comes from Bitwarden", externalClient, externalBearer, true, true},
		{"external client and local bearer", externalClient, "BEARER_TOKEN_workload", true, false},
		{"local client and external bearer", "OAUTH_CLIENT_SECRET_workload", externalBearer, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			systemProvider := secretsmocks.NewMockProvider(ctrl)
			userProvider := secretsmocks.NewMockProvider(ctrl)
			ctx := context.Background()
			userProvider.EXPECT().GetSecret(ctx, "bws://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").Return("env-secret", nil)
			userProvider.EXPECT().GetSecret(ctx, "bws://bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").Return(headerValue, nil)
			clientProvider := systemProvider
			if tc.externalClient {
				clientProvider = userProvider
			}
			clientProvider.EXPECT().GetSecret(ctx, tc.clientRef).Return(clientValue, nil)
			bearerProvider := systemProvider
			if tc.externalBearer {
				bearerProvider = userProvider
			}
			bearerProvider.EXPECT().GetSecret(ctx, tc.bearerRef).Return(bearerValue, nil)

			cfg := &RunConfig{
				Secrets: []string{"bws://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa,target=API_KEY"},
				HeaderForward: &HeaderForwardConfig{
					AddHeadersFromSecret: map[string]string{"X-API-Key": "bws://bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},
				},
				RemoteAuthConfig: &remote.Config{
					ClientSecret: tc.clientRef + ",target=client_secret",
					BearerToken:  tc.bearerRef + ",target=bearer_token",
				},
			}
			wantAuth := *cfg.RemoteAuthConfig
			wantAuth.SetResolvedClientSecret(clientValue)
			wantAuth.SetResolvedBearerToken(bearerValue)

			got, err := cfg.WithSecrets(ctx, systemProvider, userProvider)
			require.NoError(t, err)
			assert.Same(t, cfg, got)
			assert.Equal(t, "env-secret", cfg.EnvVars["API_KEY"])
			assert.Equal(t, headerValue, cfg.HeaderForward.ResolvedHeaders()["X-API-Key"])
			assert.Equal(t, wantAuth, *cfg.RemoteAuthConfig,
				"resolved credentials must be available at runtime without replacing persistable references")

			var encoded bytes.Buffer
			require.NoError(t, cfg.WriteJSON(&encoded))
			yamlBytes, err := yaml.Marshal(cfg)
			require.NoError(t, err)
			for _, serialized := range []string{encoded.String(), string(yamlBytes)} {
				assert.Contains(t, serialized, tc.clientRef)
				assert.Contains(t, serialized, tc.bearerRef)
				assert.NotContains(t, serialized, clientValue)
				assert.NotContains(t, serialized, bearerValue)
				assert.NotContains(t, serialized, headerValue)
			}
		})
	}
}

func TestRunConfig_WithSecretsDoesNotFallbackBetweenProviders(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		ref      string
		client   bool
		external bool
	}{
		{"external client failure", "bws://12345678-1234-4234-8234-123456789abc", true, true},
		{"external bearer failure", "bws://12345678-1234-4234-8234-123456789abc", false, true},
		{"local client failure", "OAUTH_CLIENT_SECRET_workload", true, false},
		{"local bearer failure", "BEARER_TOKEN_workload", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			systemProvider := secretsmocks.NewMockProvider(ctrl)
			userProvider := secretsmocks.NewMockProvider(ctrl)
			provider := systemProvider
			if tc.external {
				provider = userProvider
			}
			failure := errors.New("secret unavailable")
			provider.EXPECT().GetSecret(gomock.Any(), tc.ref).Return("", failure)
			cfg := &RunConfig{RemoteAuthConfig: &remote.Config{}}
			if tc.client {
				cfg.RemoteAuthConfig.ClientSecret = tc.ref + ",target=client_secret"
			} else {
				cfg.RemoteAuthConfig.BearerToken = tc.ref + ",target=bearer_token"
			}
			_, err := cfg.WithSecrets(context.Background(), systemProvider, userProvider)
			require.ErrorIs(t, err, failure)
		})
	}
}
