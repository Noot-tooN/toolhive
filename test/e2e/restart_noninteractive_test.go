// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package e2e_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/stacklok/toolhive/pkg/auth/remote"
	rt "github.com/stacklok/toolhive/pkg/container/runtime"
	"github.com/stacklok/toolhive/pkg/core"
	"github.com/stacklok/toolhive/pkg/networking"
	"github.com/stacklok/toolhive/pkg/runner"
	"github.com/stacklok/toolhive/test/e2e"
)

var _ = Describe("Noninteractive restart", Label("cli", "noninteractive-auth", "e2e"), func() {
	It("propagates the policy to the detached child without starting authorization", func() {
		root, err := filepath.EvalSymlinks(GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred())
		config := e2e.NewTestConfig()
		config.TestTimeout = 30 * time.Second
		name := e2e.GenerateUniqueServerName("noninteractive-auth")
		env := []string{
			"TOOLHIVE_DEV=true", "TOOLHIVE_SKIP_DESKTOP_CHECK=true",
			remote.NonInteractiveEnvVarName + "=false", // The CLI flag must override the inherited value.
		}
		for key, directory := range map[string]string{
			"XDG_CONFIG_HOME": "config", "XDG_DATA_HOME": "data", "XDG_STATE_HOME": "state",
			"XDG_CACHE_HOME": "cache", "XDG_RUNTIME_DIR": "runtime",
		} {
			path := filepath.Join(root, directory)
			Expect(os.MkdirAll(path, 0700)).To(Succeed())
			env = append(env, key+"="+path)
		}
		thv := func(args ...string) *e2e.THVCommand {
			return e2e.NewTHVCommand(config, args...).WithEnv(env...)
		}
		DeferCleanup(func() {
			// Surgical cleanup also handles a regression that leaves the detached worker alive.
			_, stderr, stopErr := thv("stop", name, "--timeout", "3").RunWithTimeout(10 * time.Second)
			if stopErr != nil {
				GinkgoWriter.Printf("Isolated workload cleanup: %v (%s)\n", stopErr, stderr)
			}
		})

		var discoveries, interactiveRequests atomic.Int32
		provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			base := "http://" + r.Host
			switch r.URL.Path {
			case "/mcp":
				discoveries.Add(1)
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s"`, base))
				w.WriteHeader(http.StatusUnauthorized)
			case "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server":
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer": base, "authorization_endpoint": base + "/authorize",
					"token_endpoint": base + "/token", "registration_endpoint": base + "/register",
				})
			default:
				interactiveRequests.Add(1)
				http.Error(w, "unexpected authorization request", http.StatusBadRequest)
			}
		}))
		DeferCleanup(provider.Close)
		callbackPort, err := networking.FindOrUsePort(0)
		Expect(err).NotTo(HaveOccurred())
		port, err := networking.FindOrUsePort(0)
		Expect(err).NotTo(HaveOccurred())
		runConfig := runner.RunConfig{
			SchemaVersion: runner.CurrentSchemaVersion, Name: name, BaseName: name, ContainerName: name,
			RemoteURL: provider.URL + "/mcp", Transport: "streamable-http", ProxyMode: "streamable-http",
			Host: "127.0.0.1", Port: port, Group: "default",
			RemoteAuthConfig: &remote.Config{
				ClientID: "synthetic-public-client", Issuer: provider.URL, UsePKCE: true,
				AuthorizeURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token",
				CallbackPort: callbackPort,
				// Keep the fixture harmless if the noninteractive guard regresses:
				// skip browser launch and bound any accidental consent wait.
				SkipBrowser: true, Timeout: 500 * time.Millisecond,
			},
		}
		data, err := json.Marshal(runConfig)
		Expect(err).NotTo(HaveOccurred())
		runConfigDir := filepath.Join(root, "state", "toolhive", "runconfigs")
		Expect(os.MkdirAll(runConfigDir, 0700)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(runConfigDir, name+".json"), data, 0600)).To(Succeed())

		By("launching the real detached CLI with no saved OAuth session")
		thv("start", name, "--non-interactive").ExpectSuccess()
		By("checking the child outcome instead of accepting the parent's successful launch")
		statusPath := filepath.Join(root, "data", "toolhive", "statuses", name+".json")
		Eventually(func(g Gomega) {
			statusData, readErr := os.ReadFile(statusPath)
			g.Expect(readErr).NotTo(HaveOccurred())
			var workload core.Workload
			g.Expect(json.Unmarshal(statusData, &workload)).To(Succeed())
			g.Expect(workload.Status).To(Equal(rt.WorkloadStatusError))
			g.Expect(workload.StatusContext).To(ContainSubstring("non-interactive authentication requires a saved session"))
		}, 30*time.Second, 100*time.Millisecond).Should(Succeed())
		Expect(discoveries.Load()).To(BeNumerically(">", 0))
		Expect(interactiveRequests.Load()).To(BeZero())
	})
})
