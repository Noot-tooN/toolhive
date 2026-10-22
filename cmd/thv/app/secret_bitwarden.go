// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/stacklok/toolhive/pkg/secrets"
	"github.com/stacklok/toolhive/pkg/secrets/clients"
)

func newSecretBitwardenCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bitwarden",
		Short: "Manage the local Bitwarden access token",
		Long: `Store or remove the Bitwarden Secrets Manager bootstrap token in the native OS credential store.

This credential is separate from remote Bitwarden secrets and local OAuth storage.
BWS_ACCESS_TOKEN, when set, overrides the saved credential.`,
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newSecretBitwardenLoginCommand(), &cobra.Command{
		Use:   "logout",
		Short: "Remove the saved Bitwarden access token",
		Long: `Remove only the saved local Bitwarden access token.

This does not revoke the token in Bitwarden, remove BWS_ACCESS_TOKEN from the
environment, or change remote secrets or local OAuth credentials.`,
		Args:              cobra.NoArgs,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(_ *cobra.Command, _ []string) error {
			return secrets.NewBitwardenCredentials().Delete()
		},
	})
	return cmd
}

func newSecretBitwardenLoginCommand() *cobra.Command {
	var tokenStdin bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Save a Bitwarden access token in the OS credential store",
		Long: `Read a Bitwarden machine-account access token from a hidden terminal prompt,
validate it with bws, and save or replace it in the native OS credential store.

Use --token-stdin to read from a pipe explicitly. Tokens are never accepted as
command arguments. The native store must be available and unlocked; there is no
file or temporary keyring fallback. This does not change the selected provider.

If BWS_ACCESS_TOKEN is set, it still takes precedence over this saved token.
Unset it to use the saved credential.`,
		Args:              cobra.NoArgs,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return loginBitwarden(cmd, tokenStdin)
		},
	}
	cmd.Flags().BoolVar(&tokenStdin, "token-stdin", false, "Read the access token from stdin instead of a hidden terminal prompt")
	return cmd
}

func loginBitwarden(cmd *cobra.Command, tokenStdin bool) error {
	token, err := readBitwardenToken(cmd, tokenStdin)
	if err != nil {
		return err
	}
	defer clear(token)
	return secrets.NewBitwardenCredentials().Save(cmd.Context(), os.Getenv("TOOLHIVE_BWS_PATH"), string(token))
}

func readBitwardenToken(cmd *cobra.Command, tokenStdin bool) ([]byte, error) {
	if tokenStdin {
		// Allow one CRLF terminator in addition to the bounded token itself.
		value, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), clients.BitwardenAccessTokenLimit+3))
		if err != nil {
			clear(value)
			return nil, errors.New("cannot read Bitwarden access token from stdin")
		}
		token := strings.TrimSuffix(strings.TrimSuffix(string(value), "\n"), "\r")
		clear(value)
		if len(token) > clients.BitwardenAccessTokenLimit {
			return nil, errors.New("the Bitwarden access token exceeds the size limit")
		}
		return []byte(token), nil
	}
	if !term.IsTerminal(int(syscall.Stdin)) {
		return nil, errors.New("a terminal is required for Bitwarden login; use --token-stdin to explicitly read a piped token")
	}
	if _, err := fmt.Fprint(cmd.ErrOrStderr(), "Bitwarden access token (input hidden): "); err != nil {
		return nil, errors.New("cannot display Bitwarden access token prompt")
	}
	token, err := term.ReadPassword(int(syscall.Stdin))
	if _, writeErr := fmt.Fprintln(cmd.ErrOrStderr()); writeErr != nil {
		clear(token)
		return nil, errors.New("cannot complete Bitwarden access token prompt")
	}
	if err != nil {
		clear(token)
		return nil, errors.New("cannot read Bitwarden access token from terminal")
	}
	return token, nil
}
