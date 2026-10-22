// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"fmt"
	"os"
	"reflect"
	"strings"
)

// NewBitwardenCredentialsForTest permits external tests to inject generated
// mocks without replacing the process-wide native credential backend.
func NewBitwardenCredentialsForTest(store bitwardenCredentialStore) *BitwardenCredentials {
	return &BitwardenCredentials{store: store}
}

func runBitwardenCredentialHelper(mode string) int {
	if !reflect.DeepEqual(os.Args[1:], []string{"--output", "json", "--color", "no", "secret", "list"}) ||
		os.Getenv("BWS_ACCESS_TOKEN") != "synthetic-credential-token" ||
		strings.Contains(strings.Join(os.Args, " "), "synthetic-credential-token") {
		return 2
	}
	if mode == "failure" {
		fmt.Fprint(os.Stderr, "synthetic-credential-token synthetic-secret-value")
		return 1
	}
	fmt.Fprint(os.Stdout, "[]")
	return 0
}
