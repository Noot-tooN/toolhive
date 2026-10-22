// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/secrets/clients"
)

func TestReadBitwardenTokenStdin(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		input io.Reader
		want  string
		err   string
	}{
		{name: "token without terminator", input: strings.NewReader("synthetic-token"), want: "synthetic-token"},
		{name: "LF terminator", input: strings.NewReader("synthetic-token\n"), want: "synthetic-token"},
		{name: "CRLF terminator", input: strings.NewReader("synthetic-token\r\n"), want: "synthetic-token"},
		{name: "does not conceal multiple lines", input: strings.NewReader("first\nsecond\n"), want: "first\nsecond"},
		{name: "maximum size with CRLF", input: strings.NewReader(strings.Repeat("t", clients.BitwardenAccessTokenLimit) + "\r\n"),
			want: strings.Repeat("t", clients.BitwardenAccessTokenLimit)},
		{name: "oversized input", input: strings.NewReader(strings.Repeat("t", clients.BitwardenAccessTokenLimit+1)), err: "size limit"},
		{name: "input error is sanitized", input: iotest.ErrReader(errors.New("synthetic-token")), err: "cannot read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd := &cobra.Command{}
			cmd.SetIn(tc.input)
			token, err := readBitwardenToken(cmd, true)
			if tc.err == "" {
				require.NoError(t, err)
				require.Equal(t, tc.want, string(token))
				return
			}
			require.ErrorContains(t, err, tc.err)
			require.NotContains(t, err.Error(), "synthetic-token")
			require.Nil(t, token)
		})
	}
}
