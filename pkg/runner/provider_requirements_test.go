// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stacklok/toolhive/pkg/auth/remote"
)

func TestSecretProviderRequirements(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		config RunConfig
		system bool
		user   bool
	}{
		{name: "no secrets"},
		{name: "cached refresh only remains local", config: RunConfig{RemoteAuthConfig: &remote.Config{CachedRefreshTokenRef: "OAUTH_REFRESH_TOKEN_demo"}}},
		{name: "local OAuth needs no external provider", config: RunConfig{RemoteAuthConfig: &remote.Config{ClientSecret: "OAUTH_CLIENT_SECRET_demo,target=oauth_secret"}}, system: true},
		{name: "plaintext auth requires no storage", config: RunConfig{RemoteAuthConfig: &remote.Config{ClientSecret: "plain-client", BearerToken: "plain-bearer"}}},
		{name: "external client secret", config: RunConfig{RemoteAuthConfig: &remote.Config{ClientSecret: "bws://12345678-1234-4234-8234-123456789abc,target=oauth_secret"}}, user: true},
		{name: "mixed auth", config: RunConfig{RemoteAuthConfig: &remote.Config{ClientSecret: "OAUTH_CLIENT_SECRET_demo,target=oauth_secret", BearerToken: "bws://12345678-1234-4234-8234-123456789abc,target=bearer_token"}}, system: true, user: true},
		{name: "environment secrets only", config: RunConfig{Secrets: []string{"api-key,target=API_KEY"}}, user: true},
		{name: "header secrets only", config: RunConfig{HeaderForward: &HeaderForwardConfig{AddHeadersFromSecret: map[string]string{"X-Key": "api-key"}}}, user: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			system, user := tc.config.SecretProviderRequirements()
			assert.Equal(t, tc.system, system, "system provider requirement")
			assert.Equal(t, tc.user, user, "user provider requirement")
		})
	}
}
