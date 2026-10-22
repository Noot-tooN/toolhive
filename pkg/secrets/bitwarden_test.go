// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBitwardenReadOnly(t *testing.T) {
	t.Parallel()
	provider := &BitwardenManager{}
	ctx := context.Background()
	require.ErrorIs(t, provider.SetSecret(ctx, "key", "value"), ErrBitwardenReadOnly)
	require.ErrorIs(t, provider.DeleteSecret(ctx, "key"), ErrBitwardenReadOnly)
	require.NoError(t, provider.DeleteSecrets(ctx, []string{"key"}))
	require.NoError(t, provider.Cleanup())
	require.Equal(t, ProviderCapabilities{CanRead: true, CanList: true}, provider.Capabilities())
}

func TestBitwardenReference(t *testing.T) {
	t.Parallel()
	provider := &BitwardenManager{}
	for _, tc := range []struct {
		reference string
		explicit  bool
	}{
		{"bws://87d93628-d8d7-40db-82ef-fdc5ff9ce70a", true},
		{"bws://invalid", true},
		{"bws://", true},
		{"87d93628-d8d7-40db-82ef-fdc5ff9ce70a", false},
		{"__thv_oauth_refresh_token", false},
		{"op://vault/item/field", false},
		{"prefix-bws://invalid", false},
	} {
		require.Equal(t, tc.explicit, IsBitwardenReference(tc.reference))
		if !tc.explicit {
			_, err := provider.GetSecret(context.Background(), tc.reference)
			require.ErrorContains(t, err, "bws://UUID")
			require.False(t, IsNotFoundError(err))
		}
	}
}

func TestNewBitwardenManager(t *testing.T) {
	t.Setenv("BWS_ACCESS_TOKEN", "")
	_, err := NewBitwardenManager()
	require.ErrorContains(t, err, "BWS_ACCESS_TOKEN")

	t.Setenv("BWS_ACCESS_TOKEN", "test-token")
	t.Setenv("TOOLHIVE_BWS_PATH", filepath.Join(t.TempDir(), "unavailable-bws"))
	_, err = NewBitwardenManager()
	require.ErrorContains(t, err, "executable unavailable")
	require.False(t, IsNotFoundError(err))

	binary, err := os.Executable()
	require.NoError(t, err)
	t.Setenv("TOOLHIVE_BWS_PATH", binary)
	provider, err := NewBitwardenManager()
	require.NoError(t, err)
	require.True(t, provider.Capabilities().IsReadOnly())
	_, err = provider.GetSecret(context.Background(), "bws://not-a-uuid")
	require.ErrorContains(t, err, "canonical UUID")
	require.False(t, IsNotFoundError(err))
}
