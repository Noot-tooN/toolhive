// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/stacklok/toolhive/pkg/secrets/clients"
)

const bitwardenReferencePrefix = "bws://"

// ErrBitwardenReadOnly is returned for attempts to change Bitwarden secrets.
var ErrBitwardenReadOnly = errors.New("bitwarden secrets manager is read-only; manage secrets in Bitwarden")

// BitwardenManager reads static secrets through bws. OAuth and other generated
// credentials must use a separate writable local provider.
type BitwardenManager struct {
	client *clients.BitwardenClient
}

var _ Provider = (*BitwardenManager)(nil)

// NewBitwardenManager resolves BWS_ACCESS_TOKEN or the dedicated OS credential
// and validates the local bws executable. TOOLHIVE_BWS_PATH optionally selects
// the executable. No network request occurs until GetSecret or ListSecrets;
// configure a read-only machine account in BWS.
func NewBitwardenManager() (Provider, error) {
	client, err := NewBitwardenCredentials().Client(os.Getenv("TOOLHIVE_BWS_PATH"))
	if err != nil {
		return nil, err
	}
	return &BitwardenManager{client: client}, nil
}

// IsBitwardenReference reports an explicit Bitwarden reference prefix. The UUID
// is validated on retrieval, so invalid explicit references cannot fall back to
// a different backend.
func IsBitwardenReference(reference string) bool {
	return strings.HasPrefix(reference, bitwardenReferencePrefix)
}

// GetSecret resolves a bws://UUID reference without caching its value.
func (b *BitwardenManager) GetSecret(ctx context.Context, reference string) (string, error) {
	if !IsBitwardenReference(reference) {
		return "", errors.New("bitwarden secrets require a bws://UUID reference")
	}
	return b.client.GetSecret(ctx, strings.TrimPrefix(reference, bitwardenReferencePrefix))
}

// ListSecrets returns references and display names, never secret values.
func (b *BitwardenManager) ListSecrets(ctx context.Context) ([]SecretDescription, error) {
	entries, err := b.client.ListSecrets(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]SecretDescription, 0, len(entries))
	for _, entry := range entries {
		result = append(result, SecretDescription{Key: bitwardenReferencePrefix + entry.ID, Description: entry.Key})
	}
	return result, nil
}

// SetSecret is unsupported: callers must create secrets in Bitwarden directly.
func (*BitwardenManager) SetSecret(context.Context, string, string) error {
	return ErrBitwardenReadOnly
}

// DeleteSecret is unsupported for this read-only provider.
func (*BitwardenManager) DeleteSecret(context.Context, string) error {
	return ErrBitwardenReadOnly
}

// DeleteSecrets is a no-op, as required by the read-only Provider contract.
func (*BitwardenManager) DeleteSecrets(context.Context, []string) error { return nil }

// Cleanup is a no-op: this provider owns no remote data or local cache.
func (*BitwardenManager) Cleanup() error { return nil }

// Capabilities advertises only read and list operations.
func (*BitwardenManager) Capabilities() ProviderCapabilities {
	return ProviderCapabilities{CanRead: true, CanList: true}
}
