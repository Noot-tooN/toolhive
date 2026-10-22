// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive/pkg/secrets"
	secretmocks "github.com/stacklok/toolhive/pkg/secrets/mocks"
)

func TestValidateEncryptedProviderCleansUpProbe(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		value     string
		readErr   error
		deleteErr error
		success   bool
	}{
		{name: "successful read and write", value: "test-value", success: true},
		{name: "failed read still removes probe", readErr: errors.New("read unavailable")},
		{name: "mismatch does not disclose value", value: "sentinel-unexpected-secret"},
		{name: "failed cleanup rejects setup", value: "test-value", deleteErr: errors.New("delete unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			provider := secretmocks.NewMockProvider(gomock.NewController(t))
			var probe string
			gomock.InOrder(
				provider.EXPECT().SetSecret(gomock.Any(), gomock.Any(), "test-value").DoAndReturn(
					func(_ context.Context, key, _ string) error {
						probe = key
						return nil
					}),
				provider.EXPECT().GetSecret(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, key string) (string, error) {
						assert.Equal(t, probe, key)
						return tc.value, tc.readErr
					}),
				provider.EXPECT().DeleteSecret(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, key string) error {
						assert.Equal(t, probe, key)
						return tc.deleteErr
					}),
			)
			result := secrets.ValidateEncryptedProviderForTest(t.Context(), provider, &secrets.SetupResult{ProviderType: secrets.EncryptedType})
			assert.Equal(t, tc.success, result.Success)
			if !tc.success {
				require.Error(t, result.Error)
				assert.NotContains(t, result.Error.Error(), "sentinel-unexpected-secret")
			}
		})
	}
}
