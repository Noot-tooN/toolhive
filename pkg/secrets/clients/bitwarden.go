// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

const (
	bitwardenTimeout     = 30 * time.Second
	bitwardenOutputLimit = 8 << 20
	bitwardenErrorLimit  = 64 << 10
	// BitwardenAccessTokenLimit bounds token input before native keyring storage.
	// In particular it stays below the macOS backend's interactive command limit.
	BitwardenAccessTokenLimit = 2048
)

// BitwardenClient invokes a separately installed bws executable. It only exposes
// read operations; the caller must also provision a read-only machine account.
// Tokens are passed through the child environment, never command arguments.
type BitwardenClient struct {
	binary string
	token  string
}

// BitwardenSecretDescription contains metadata only. bws list returns values as
// well; they are deliberately discarded rather than exposed to list callers.
type BitwardenSecretDescription struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// NewBitwardenClient validates local prerequisites without running bws or making
// network requests. binaryPath may be empty to resolve bws from PATH.
func NewBitwardenClient(binaryPath, accessToken string) (*BitwardenClient, error) {
	if accessToken == "" || len(accessToken) > BitwardenAccessTokenLimit ||
		strings.IndexFunc(accessToken, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return nil, errors.New("BWS_ACCESS_TOKEN must contain a valid access token")
	}
	if binaryPath == "" {
		binaryPath = "bws"
	}
	binary, err := exec.LookPath(binaryPath)
	if err != nil {
		return nil, errors.New("bws executable unavailable; install it or set TOOLHIVE_BWS_PATH")
	}
	return &BitwardenClient{binary: binary, token: accessToken}, nil
}

// GetSecret retrieves a secret by canonical UUID and verifies the response ID.
func (b *BitwardenClient) GetSecret(ctx context.Context, id string) (string, error) {
	if !validBitwardenID(id) {
		return "", errors.New("bitwarden reference must contain a canonical UUID")
	}
	output, err := b.run(ctx, "secret", "get", id)
	if err != nil {
		return "", err
	}
	defer clear(output)
	var secret struct {
		ID    string  `json:"id"`
		Value *string `json:"value"`
	}
	if err := json.Unmarshal(output, &secret); err != nil {
		return "", errors.New("bws returned invalid secret JSON")
	}
	if !strings.EqualFold(secret.ID, id) || secret.Value == nil {
		return "", errors.New("bws returned an incomplete or mismatched secret")
	}
	return *secret.Value, nil
}

// ListSecrets returns stable IDs and names; duplicate names remain distinct.
func (b *BitwardenClient) ListSecrets(ctx context.Context) ([]BitwardenSecretDescription, error) {
	output, err := b.run(ctx, "secret", "list")
	if err != nil {
		return nil, err
	}
	defer clear(output)
	var descriptions []BitwardenSecretDescription
	if err := json.Unmarshal(output, &descriptions); err != nil || descriptions == nil {
		return nil, errors.New("bws returned invalid secret list JSON")
	}
	for _, description := range descriptions {
		if !validBitwardenID(description.ID) {
			return nil, errors.New("bws returned a secret with an invalid UUID")
		}
	}
	return descriptions, nil
}

func (b *BitwardenClient) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, bitwardenTimeout)
	defer cancel()
	// #nosec G204 -- trusted configured executable resolved by LookPath; fixed read operations and validated UUID, no shell.
	cmd := exec.CommandContext(ctx, b.binary, append([]string{"--output", "json", "--color", "no"}, args...)...)
	cmd.Env = bitwardenEnvironment(b.token)
	// Bound pipe draining even if a descendant inherits an output descriptor.
	cmd.WaitDelay = time.Second
	stdout := &bitwardenOutput{limit: bitwardenOutputLimit, cancel: cancel}
	stderr := &bitwardenOutput{limit: bitwardenErrorLimit, cancel: cancel, discard: true}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		clear(stdout.buffer.Bytes())
		return nil, errors.New("bws exceeded the command output limit")
	}
	if err != nil {
		clear(stdout.buffer.Bytes())
		if ctx.Err() != nil {
			return nil, fmt.Errorf("bws command interrupted: %w", ctx.Err())
		}
		// bws has no stable structured error contract. Never propagate its raw
		// output, or mistake an auth/network/CLI failure for a missing secret.
		return nil, errors.New("bws command failed; verify access token, permissions, server configuration and connectivity")
	}
	return stdout.buffer.Bytes(), nil
}

func validBitwardenID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && strings.EqualFold(parsed.String(), id)
}

func bitwardenEnvironment(token string) []string {
	env := make([]string, 0, len(os.Environ())+4)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "BWS_ACCESS_TOKEN", "RUST_LOG", "RUST_BACKTRACE", "RUST_LIB_BACKTRACE":
			continue
		}
		env = append(env, entry)
	}
	return append(env, "BWS_ACCESS_TOKEN="+token, "RUST_LOG=off", "RUST_BACKTRACE=0", "RUST_LIB_BACKTRACE=0")
}

// bitwardenOutput caps memory and terminates a process that floods either pipe.
// stderr is counted but never retained, since it may contain credentials.
type bitwardenOutput struct {
	// Keep the buffer named: embedding would expose ReaderFrom and let io.Copy
	// bypass Write, including the size limit and stderr discard behavior.
	buffer   bytes.Buffer
	limit    int
	count    int
	cancel   context.CancelFunc
	discard  bool
	exceeded bool
}

func (b *bitwardenOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.count {
		b.exceeded = true
		b.cancel()
		return 0, errors.New("bws output limit exceeded")
	}
	b.count += len(p)
	if b.discard {
		return len(p), nil
	}
	return b.buffer.Write(p)
}
