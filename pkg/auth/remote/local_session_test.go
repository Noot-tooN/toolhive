// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive/pkg/secrets"
	secretmocks "github.com/stacklok/toolhive/pkg/secrets/mocks"
)

func TestHandler_LocalSessionSurvivesRestartAndTokenRotation(t *testing.T) {
	t.Parallel()

	const (
		issuer    = "https://issuer.example"
		ref       = "OAUTH_REFRESH_TOKEN_local"
		scopedRef = "__thv_workloads_" + ref
	)
	requests := make(chan string, 2)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		token := r.Form.Get("refresh_token")
		select {
		case requests <- token:
		default:
			http.Error(w, "unexpected extra refresh", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"access","refresh_token":%q,"token_type":"Bearer","expires_in":3600}`, token+"-rotated")
	}))
	t.Cleanup(endpoint.Close)

	cached, err := encodeCachedRefreshToken("initial", issuer, endpoint.URL)
	require.NoError(t, err)
	provider := secretmocks.NewMockProvider(gomock.NewController(t))
	local := secrets.NewScopedProvider(provider, secrets.ScopeWorkloads)
	for _, expected := range []string{"initial", "initial-rotated"} {
		provider.EXPECT().GetSecret(gomock.Any(), scopedRef).Return(cached, nil)
		provider.EXPECT().SetSecret(gomock.Any(), scopedRef, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ string, value string) error {
				cached = value
				return nil
			})

		// Recreate the handler and config for each start. The only session state
		// available is the reference and the value in the local scoped provider.
		handler := NewHandler(&Config{
			ClientID:              "public-client",
			TokenURL:              endpoint.URL,
			CachedRefreshTokenRef: ref,
		})
		handler.SetSecretProvider(local)
		handler.SetTokenPersister(func(value string, _ time.Time) error {
			return local.SetSecret(t.Context(), ref, value)
		})
		source, err := handler.tryRestoreFromCachedTokens(t.Context(), issuer, nil, nil)
		require.NoError(t, err)
		token, err := source.Token()
		require.NoError(t, err)
		assert.Equal(t, "access", token.AccessToken)
		select {
		case received := <-requests:
			assert.Equal(t, expected, received)
		case <-time.After(5 * time.Second):
			t.Fatal("refresh request was not received")
		}
		envelope, err := decodeCachedRefreshToken(cached)
		require.NoError(t, err)
		assert.Equal(t, expected+"-rotated", envelope.Token)
	}
}
