// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/stacklok/toolhive/pkg/secrets/clients"
	"github.com/stacklok/toolhive/pkg/secrets/keyring"
)

const (
	bitwardenCredentialService = "toolhive-bitwarden"
	bitwardenCredentialAccount = "access-token"
)

// ErrBitwardenTokenNotFound indicates that neither an environment override nor
// a saved native credential exists. Only interactive setup should prompt.
var ErrBitwardenTokenNotFound = errors.New(
	"no Bitwarden access token found; run 'thv secret bitwarden login' or set BWS_ACCESS_TOKEN")

//go:generate mockgen -destination=mocks/mock_bitwarden_credential_store.go -package=mocks -source=bitwarden_credentials.go

type bitwardenCredentialStore interface {
	Get(service, key string) (string, error)
	Set(service, key, value string) error
	Delete(service, key string) error
}

// BitwardenCredentials manages the single bootstrap credential for Bitwarden.
// It is separate from ToolHive's local OAuth encryption key and remote secrets.
type BitwardenCredentials struct {
	store bitwardenCredentialStore
}

// NewBitwardenCredentials uses the native persistent credential store: macOS
// Keychain, Windows Credential Manager, or Linux Secret Service. It never falls
// back to a file or the Linux kernel keyring, and does not probe or modify the
// store during construction. Headless callers can supply BWS_ACCESS_TOKEN.
func NewBitwardenCredentials() *BitwardenCredentials {
	return &BitwardenCredentials{store: keyring.NewZalandoKeyringProvider()}
}

// Client resolves an explicit BWS_ACCESS_TOKEN override before reading the
// dedicated native credential. An invalid override never falls back. The token
// stays in memory and is passed only through the bws child's environment.
func (b *BitwardenCredentials) Client(binaryPath string) (*clients.BitwardenClient, error) {
	if token, present := os.LookupEnv("BWS_ACCESS_TOKEN"); present {
		return clients.NewBitwardenClient(binaryPath, token)
	}
	token, err := b.store.Get(bitwardenCredentialService, bitwardenCredentialAccount)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrBitwardenTokenNotFound
	}
	if err != nil {
		// Native command errors can contain credentials; do not wrap them.
		return nil, errors.New("cannot read Bitwarden access token from the OS credential store; unlock it or set BWS_ACCESS_TOKEN")
	}
	client, err := clients.NewBitwardenClient(binaryPath, token)
	if err != nil {
		return nil, fmt.Errorf("initialize Bitwarden with saved credential (run 'thv secret bitwarden login' to replace it): %w", err)
	}
	return client, nil
}

// Save validates the supplied token with bws before replacing the native
// credential. It deliberately ignores BWS_ACCESS_TOKEN for this validation;
// an existing environment override continues to take precedence at runtime.
func (b *BitwardenCredentials) Save(ctx context.Context, binaryPath, token string) error {
	client, err := clients.NewBitwardenClient(binaryPath, token)
	if err != nil {
		return err
	}
	if _, err := client.ListSecrets(ctx); err != nil {
		return fmt.Errorf("validate Bitwarden access token: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.store.Set(bitwardenCredentialService, bitwardenCredentialAccount, token); err != nil {
		return errors.New("cannot save Bitwarden access token in the OS credential store; " +
			"unlock it or use BWS_ACCESS_TOKEN for automation")
	}
	return nil
}

// Delete removes only the saved local bootstrap token. It does not revoke the
// remote token, clear environment overrides, or alter OAuth or remote secrets.
func (b *BitwardenCredentials) Delete() error {
	if err := b.store.Delete(bitwardenCredentialService, bitwardenCredentialAccount); err != nil {
		return errors.New("cannot remove Bitwarden access token from the OS credential store; " +
			"verify it is unlocked and a saved token exists")
	}
	return nil
}
