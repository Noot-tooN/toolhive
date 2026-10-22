// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	registry "github.com/stacklok/toolhive-core/registry/types"
	"github.com/stacklok/toolhive/pkg/config"
	configmocks "github.com/stacklok/toolhive/pkg/config/mocks"
	"github.com/stacklok/toolhive/pkg/secrets"
)

func TestCLIEnvVarValidator_BitwardenReferences(t *testing.T) {
	const reference = "bws://12345678-1234-4234-8234-123456789abc,target=API_KEY"

	for _, tc := range []struct {
		name         string
		envOverride  string
		required     bool
		defaultValue string
		refs         []string
		supplied     map[string]string
		wantError    bool
		incomplete   bool
	}{
		{name: "required missing secret fails closed", required: true, wantError: true},
		{name: "incomplete setup cannot prompt for plaintext", required: true, incomplete: true, wantError: true},
		{name: "optional default secret cannot fall back to plaintext", defaultValue: "sensitive-default", wantError: true},
		{name: "required default secret cannot fall back to plaintext", required: true, defaultValue: "sensitive-default", wantError: true},
		{name: "optional secret with no default is skipped"},
		{name: "explicit reference skips local provider initialization", required: true, refs: []string{reference}},
		{name: "explicit reference overrides secret default", defaultValue: "sensitive-default", refs: []string{reference}},
		{name: "deliberately supplied env value is preserved", required: true, supplied: map[string]string{"API_KEY": "explicit-value"}},
		{name: "effective provider override also fails closed", envOverride: "bitwarden", required: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(secrets.ProviderEnvVar, tc.envOverride)
			ctrl := gomock.NewController(t)
			provider := configmocks.NewMockProvider(ctrl)
			providerType := "bitwarden"
			if tc.envOverride != "" {
				providerType = "encrypted"
			}
			// No second config lookup for constructing a local secrets manager is allowed.
			// The invalid internal provider also ensures no usable local storage exists.
			provider.EXPECT().GetConfig().Return(&config.Config{Secrets: config.Secrets{
				ProviderType:       providerType,
				SystemProviderType: "invalid-test-provider",
				SetupCompleted:     !tc.incomplete,
			}}).Times(1)
			metadata := &registry.ImageMetadata{EnvVars: []*registry.EnvVar{
				{Name: "API_KEY", Secret: true, Required: tc.required, Default: tc.defaultValue},
				{Name: "MODE", Default: "production"},
			}}
			originalMetadata := *metadata.EnvVars[0]
			originalRefs := slices.Clone(tc.refs)
			originalSupplied := maps.Clone(tc.supplied)
			runConfig := &RunConfig{Secrets: slices.Clone(tc.refs)}
			got, err := NewCLIEnvVarValidator(provider).Validate(context.Background(), metadata, runConfig, tc.supplied)
			assert.Equal(t, originalMetadata, *metadata.EnvVars[0], "validation must not rewrite registry metadata")
			assert.Len(t, metadata.EnvVars, 2)
			assert.Equal(t, originalSupplied, tc.supplied, "validation must not modify supplied variables")
			assert.Equal(t, len(originalRefs), len(runConfig.Secrets), "validation must not manufacture local secret references")
			for i, ref := range originalRefs {
				assert.Equal(t, ref, runConfig.Secrets[i])
			}
			if tc.wantError {
				require.Error(t, err)
				if !tc.incomplete {
					require.ErrorContains(t, err, "API_KEY")
				}
				if !tc.incomplete {
					assert.Contains(t, err.Error(), "bws://")
				}
				assert.NotContains(t, err.Error(), "sensitive-default")
				assert.Nil(t, got, "no plaintext environment should be returned on failure")
				return
			}
			require.NoError(t, err)
			want := map[string]string{"MODE": "production"}
			maps.Copy(want, tc.supplied)
			assert.Equal(t, want, got)
		})
	}
}

func TestCLIEnvVarValidator_LegacyProviderDefaults(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider string
		setup    bool
	}{
		{name: "environment provider", provider: "environment", setup: true},
		{name: "encrypted before setup", provider: "encrypted"},
		{name: "onepassword before setup", provider: "1password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(secrets.ProviderEnvVar, "")
			provider := configmocks.NewMockProvider(gomock.NewController(t))
			provider.EXPECT().GetConfig().Return(&config.Config{Secrets: config.Secrets{
				ProviderType: tc.provider, SetupCompleted: tc.setup,
			}}).Times(2)
			metadata := &registry.ImageMetadata{EnvVars: []*registry.EnvVar{
				{Name: "OPTIONAL_SECRET", Secret: true, Default: "legacy-default"},
				{Name: "MODE", Default: "default-mode"},
			}}
			runConfig := &RunConfig{}
			got, err := NewCLIEnvVarValidator(provider).Validate(t.Context(), metadata, runConfig,
				map[string]string{"MODE": "supplied-mode"})
			require.NoError(t, err)
			assert.Equal(t, map[string]string{"OPTIONAL_SECRET": "legacy-default", "MODE": "supplied-mode"}, got)
			assert.Empty(t, runConfig.Secrets)
		})
	}
}
