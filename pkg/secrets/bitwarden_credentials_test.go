// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive/pkg/secrets"
	"github.com/stacklok/toolhive/pkg/secrets/clients"
	"github.com/stacklok/toolhive/pkg/secrets/keyring"
	secretmocks "github.com/stacklok/toolhive/pkg/secrets/mocks"
)

const credentialTestToken = "synthetic-credential-token"

func TestBitwardenCredentialsClient(t *testing.T) {
	for _, tc := range []struct {
		name     string
		override *string
		stored   string
		storeErr error
		err      string
		notFound bool
	}{
		{name: "explicit override skips credential store", override: credentialTokenPointer(credentialTestToken)},
		{name: "explicit empty override prevents fallback", override: credentialTokenPointer(""), err: "valid access token"},
		{name: "invalid override prevents fallback", override: credentialTokenPointer("invalid token"), err: "valid access token"},
		{name: "saved token", stored: credentialTestToken},
		{name: "missing token", storeErr: fmt.Errorf("wrapped: %w", keyring.ErrNotFound), err: "thv secret bitwarden login", notFound: true},
		{name: "locked credential store", storeErr: errors.New(credentialTestToken), err: "unlock"},
		{name: "invalid saved token", stored: "invalid token", err: "valid access token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binary := credentialTestBinary(t, "success")
			store := secretmocks.NewMockbitwardenCredentialStore(gomock.NewController(t))
			if tc.override != nil {
				t.Setenv("BWS_ACCESS_TOKEN", *tc.override)
			} else {
				unsetCredentialEnvironment(t)
				store.EXPECT().Get("toolhive-bitwarden", "access-token").Return(tc.stored, tc.storeErr)
			}
			credentials := secrets.NewBitwardenCredentialsForTest(store)
			client, err := credentials.Client(binary)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				require.Nil(t, client)
				require.Equal(t, tc.notFound, errors.Is(err, secrets.ErrBitwardenTokenNotFound))
				require.NotContains(t, err.Error(), credentialTestToken)
				return
			}
			require.NoError(t, err)
			// The helper rejects a wrong token and tokens passed as arguments.
			_, err = client.ListSecrets(t.Context())
			require.NoError(t, err)
		})
	}
}

func TestBitwardenCredentialsSave(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     string
		token    string
		storeErr error
		store    bool
		cancel   bool
		err      string
	}{
		{name: "validated explicit token overrides inherited environment", mode: "success", token: credentialTestToken, store: true},
		{name: "validation failure does not overwrite saved token", mode: "failure", token: credentialTestToken, err: "validate Bitwarden access token"},
		{name: "empty input does not touch store", token: "", err: "valid access token"},
		{name: "multiline input does not touch store", token: "token\nsecond", err: "valid access token"},
		{name: "oversized input does not touch store", token: strings.Repeat("t", clients.BitwardenAccessTokenLimit+1), err: "valid access token"},
		{name: "storage failure is sanitized", mode: "success", token: credentialTestToken, store: true, storeErr: errors.New(credentialTestToken), err: "cannot save"},
		{name: "cancellation does not overwrite saved token", mode: "success", token: credentialTestToken, cancel: true, err: "interrupted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binary := credentialTestBinary(t, tc.mode)
			t.Setenv("BWS_ACCESS_TOKEN", "inherited-token-must-not-be-saved")
			store := secretmocks.NewMockbitwardenCredentialStore(gomock.NewController(t))
			if tc.store {
				store.EXPECT().Set("toolhive-bitwarden", "access-token", credentialTestToken).Return(tc.storeErr)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			err := secrets.NewBitwardenCredentialsForTest(store).Save(ctx, binary, tc.token)
			if tc.err == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.err)
			require.NotContains(t, err.Error(), credentialTestToken)
			require.NotContains(t, err.Error(), "synthetic-secret-value")
			if tc.cancel {
				require.ErrorIs(t, err, context.Canceled)
			}
		})
	}
}

func TestBitwardenCredentialsDelete(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "deletes only dedicated credential"},
		{name: "native failure is sanitized", err: errors.New(credentialTestToken)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := secretmocks.NewMockbitwardenCredentialStore(gomock.NewController(t))
			store.EXPECT().Delete("toolhive-bitwarden", "access-token").Return(tc.err)
			err := secrets.NewBitwardenCredentialsForTest(store).Delete()
			if tc.err == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, "unlock")
			require.NotContains(t, err.Error(), credentialTestToken)
		})
	}
}

func credentialTestBinary(t *testing.T, mode string) string {
	t.Helper()
	t.Setenv("TOOLHIVE_TEST_BWS_CREDENTIALS", mode)
	binary, err := os.Executable()
	require.NoError(t, err)
	return binary
}

func unsetCredentialEnvironment(t *testing.T) {
	t.Helper()
	// Register restoration with Setenv before removing the variable; an empty
	// value is an explicit override and must not simulate an absent variable.
	t.Setenv("BWS_ACCESS_TOKEN", "")
	require.NoError(t, os.Unsetenv("BWS_ACCESS_TOKEN"))
}

func credentialTokenPointer(token string) *string { return &token }
