// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	bwsTestID      = "87d93628-d8d7-40db-82ef-fdc5ff9ce70a"
	bwsTestOtherID = "1263d2bf-5608-4f62-86aa-5828e3c6d1fe"
	bwsTestToken   = "test-access-token-do-not-leak"
	bwsTestValue   = "secret-value-do-not-leak"
)

// TestMain lets the test binary act as bws, exercising real subprocess argument,
// environment, cancellation and pipe handling without installing or contacting BWS.
func TestMain(m *testing.M) {
	if mode := os.Getenv("TOOLHIVE_BWS_TEST_MODE"); mode != "" {
		os.Exit(runBWSHelper(mode))
	}
	os.Exit(m.Run())
}

func runBWSHelper(mode string) int {
	if !reflect.DeepEqual(os.Args[1:5], []string{"--output", "json", "--color", "no"}) ||
		os.Getenv("BWS_ACCESS_TOKEN") != bwsTestToken ||
		os.Getenv("RUST_LOG") != "off" || os.Getenv("RUST_BACKTRACE") != "0" ||
		os.Getenv("RUST_LIB_BACKTRACE") != "0" || strings.Contains(strings.Join(os.Args, " "), bwsTestToken) {
		return 2
	}
	switch mode {
	case "failure":
		fmt.Fprint(os.Stderr, "not found: "+bwsTestToken+" "+bwsTestValue)
		fmt.Fprint(os.Stdout, bwsTestValue)
		return 1
	case "oversized stdout":
		fmt.Fprint(os.Stdout, strings.Repeat("x", bitwardenOutputLimit+1))
	case "oversized stderr":
		fmt.Fprint(os.Stderr, strings.Repeat("x", bitwardenErrorLimit+1))
	case "malformed":
		fmt.Fprint(os.Stdout, "invalid JSON "+bwsTestValue)
	case "missing value":
		fmt.Fprintf(os.Stdout, `{"id":%q}`, bwsTestID)
	case "wrong id":
		fmt.Fprintf(os.Stdout, `{"id":%q,"value":%q}`, bwsTestOtherID, bwsTestValue)
	case "empty list":
		fmt.Fprint(os.Stdout, "[]")
	case "null list":
		fmt.Fprint(os.Stdout, "null")
	case "invalid list id":
		fmt.Fprint(os.Stdout, `[{"id":"not-a-uuid","key":"name"}]`)
	case "wait":
		time.Sleep(10 * time.Second)
	case "success":
		switch {
		case reflect.DeepEqual(os.Args[5:], []string{"secret", "get", bwsTestID}):
			fmt.Fprintf(os.Stdout, `{"id":%q,"value":%q}`, bwsTestID, bwsTestValue)
		case reflect.DeepEqual(os.Args[5:], []string{"secret", "list"}):
			fmt.Fprintf(os.Stdout, `[{"id":%q,"key":"duplicate","value":%q},{"id":%q,"key":"duplicate","value":%q}]`,
				bwsTestID, bwsTestValue, bwsTestOtherID, bwsTestValue)
		default:
			return 2
		}
	}
	return 0
}

func newBWSProcessClient(t *testing.T, mode string) *BitwardenClient {
	t.Helper()
	t.Setenv("TOOLHIVE_BWS_TEST_MODE", mode)
	t.Setenv("BWS_ACCESS_TOKEN", "inherited-token-must-be-replaced")
	t.Setenv("RUST_LOG", "debug")
	t.Setenv("RUST_BACKTRACE", "full")
	t.Setenv("RUST_LIB_BACKTRACE", "full")
	binary, err := os.Executable()
	require.NoError(t, err)
	client, err := NewBitwardenClient(binary, bwsTestToken)
	require.NoError(t, err)
	return client
}

//nolint:paralleltest // newBWSProcessClient uses t.Setenv for subprocess isolation.
func TestBitwardenClientGetSecret(t *testing.T) {
	for _, tc := range []struct {
		mode string
		err  string
	}{
		{"success", ""},
		{"failure", "command failed"},
		{"oversized stdout", "output limit"},
		{"oversized stderr", "output limit"},
		{"malformed", "invalid secret JSON"},
		{"missing value", "incomplete or mismatched"},
		{"wrong id", "incomplete or mismatched"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			client := newBWSProcessClient(t, tc.mode)
			value, err := client.GetSecret(context.Background(), bwsTestID)
			if tc.err == "" {
				require.NoError(t, err)
				require.Equal(t, bwsTestValue, value)
				return
			}
			require.ErrorContains(t, err, tc.err)
			require.Empty(t, value)
			require.NotContains(t, err.Error(), bwsTestValue)
			require.NotContains(t, err.Error(), bwsTestToken)
			require.NotContains(t, err.Error(), "not found")
		})
	}
}

//nolint:paralleltest // newBWSProcessClient uses t.Setenv for subprocess isolation.
func TestBitwardenClientListSecrets(t *testing.T) {
	for _, tc := range []struct {
		mode  string
		count int
		err   string
	}{
		{"success", 2, ""},
		{"empty list", 0, ""},
		{"null list", 0, "invalid secret list JSON"},
		{"malformed", 0, "invalid secret list JSON"},
		{"invalid list id", 0, "invalid UUID"},
		{"failure", 0, "command failed"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			client := newBWSProcessClient(t, tc.mode)
			entries, err := client.ListSecrets(context.Background())
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				require.Nil(t, entries)
				return
			}
			require.NoError(t, err)
			require.Len(t, entries, tc.count)
			if tc.count > 0 {
				require.Equal(t, entries[0].Key, entries[1].Key)
				require.NotEqual(t, entries[0].ID, entries[1].ID)
			}
			serialized, err := json.Marshal(entries)
			require.NoError(t, err)
			require.NotContains(t, string(serialized), bwsTestValue)
		})
	}
}

//nolint:paralleltest // newBWSProcessClient uses t.Setenv for subprocess isolation.
func TestBitwardenClientCancellation(t *testing.T) {
	client := newBWSProcessClient(t, "wait")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := client.GetSecret(ctx, bwsTestID)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	_, err = client.GetSecret(ctx, bwsTestID)
	require.ErrorIs(t, err, context.Canceled)
}

func TestBitwardenClientInvalidIDs(t *testing.T) {
	t.Parallel()
	client := &BitwardenClient{}
	for _, id := range []string{"", "--help", "name", "00000000-0000-0000-0000-000000000000",
		"87d93628d8d740db82effdc5ff9ce70a", "{" + bwsTestID + "}", "bws://" + bwsTestID} {
		_, err := client.GetSecret(context.Background(), id)
		require.ErrorContains(t, err, "canonical UUID")
	}
}

func TestNewBitwardenClient(t *testing.T) {
	t.Parallel()
	binary, err := os.Executable()
	require.NoError(t, err)
	for _, token := range []string{"", "  ", "token\x00invalid", "token\ninvalid", "token\tinvalid", "token\u00a0invalid",
		strings.Repeat("t", BitwardenAccessTokenLimit+1)} {
		_, err := NewBitwardenClient(binary, token)
		require.ErrorContains(t, err, "BWS_ACCESS_TOKEN")
	}
	_, err = NewBitwardenClient(binary, strings.Repeat("t", BitwardenAccessTokenLimit))
	require.NoError(t, err)
	_, err = NewBitwardenClient(filepath.Join(t.TempDir(), "unavailable-bws"), bwsTestToken)
	require.ErrorContains(t, err, "executable unavailable")
}
