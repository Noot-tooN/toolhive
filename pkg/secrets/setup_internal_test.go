// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	zalandokeyring "github.com/zalando/go-keyring"

	"github.com/stacklok/toolhive/pkg/secrets/keyring"
)

// ValidateEncryptedProviderForTest exposes the private probe to external tests,
// whose generated provider mocks import this package.
var ValidateEncryptedProviderForTest = validateEncryptedProvider

func TestMain(m *testing.M) {
	if mode := os.Getenv("TOOLHIVE_TEST_BWS_CREDENTIALS"); mode != "" && len(os.Args) > 1 && os.Args[1] == "--output" {
		os.Exit(runBitwardenCredentialHelper(mode))
	}
	if os.Getenv("TOOLHIVE_TEST_BWS_SETUP") == "1" && len(os.Args) > 1 && os.Args[1] == "--output" {
		fmt.Fprint(os.Stdout, "[]")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

//nolint:tparallel // Parent calls Parallel after the isolated child branch, which uses Setenv and returns early.
func TestValidateProviderSetup_LocalStorage(t *testing.T) {
	if mode := os.Getenv("TOOLHIVE_TEST_LOCAL_SETUP"); mode != "" {
		// Each case runs in its own test process. MockInit cannot restore the
		// platform backend, so never install it in the parent test process.
		if mode == "unavailable" {
			zalandokeyring.MockInitWithError(errors.New("synthetic keyring unavailable"))
		} else {
			zalandokeyring.MockInit()
		}
		keyringOnce.Do(func() { keyringProvider = keyring.NewZalandoKeyringProvider() })
		t.Setenv("XDG_DATA_HOME", t.TempDir())
		xdg.Reload()
		binary, err := os.Executable()
		require.NoError(t, err)
		t.Setenv("TOOLHIVE_BWS_PATH", binary)
		t.Setenv("BWS_ACCESS_TOKEN", "synthetic-access-token")
		t.Setenv("TOOLHIVE_TEST_BWS_SETUP", "1")
		result := ValidateProviderSetup(t.Context(), BitwardenType, "synthetic-local-password")
		if mode == "unavailable" {
			assert.False(t, result.Success)
			require.ErrorIs(t, result.Error, ErrKeyringNotAvailable)
			return
		}
		require.NoError(t, result.Error)
		require.True(t, result.Success)
		assert.Equal(t, BitwardenType, result.ProviderType)
		// A second open without a password proves detached processes can use
		// the keyring credential and that validation removed its temporary key.
		local, err := CreateSecretProvider(EncryptedType)
		require.NoError(t, err)
		entries, err := local.ListSecrets(t.Context())
		require.NoError(t, err)
		assert.Empty(t, entries)
		require.NoError(t, local.SetSecret(t.Context(), "oauth-test", "synthetic-refresh-token"))
		reopened, err := CreateSecretProvider(EncryptedType)
		require.NoError(t, err)
		value, err := reopened.GetSecret(t.Context(), "oauth-test")
		require.NoError(t, err)
		assert.Equal(t, "synthetic-refresh-token", value)
		stored, err := os.ReadFile(filepath.Join(xdg.DataHome, "toolhive", "secrets_encrypted"))
		require.NoError(t, err)
		assert.NotContains(t, string(stored), "synthetic-refresh-token")
		assert.NotContains(t, string(stored), "synthetic-access-token")
		return
	}
	t.Parallel()
	for _, mode := range []string{"ready", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			binary, err := os.Executable()
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, "-test.run=^TestValidateProviderSetup_LocalStorage$")
			command.Env = append(os.Environ(), "TOOLHIVE_TEST_LOCAL_SETUP="+mode)
			output, err := command.CombinedOutput()
			require.NoError(t, err, "%s", output)
		})
	}
}
