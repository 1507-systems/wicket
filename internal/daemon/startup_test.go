package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1507-systems/wicket/internal/protocol"
)

// --- Early socket / startup readiness ---
//
// These cover the 2026-10-17 boot race: the socket used to appear only after
// every provider had loaded (54-93s on a cold boot), so a client asking in
// that window saw no socket and gave up. RunWithStartupLoad listens first and
// holds early requests until the load finishes.

// installGatedFakeCoffer installs a fake `coffer` whose `get` blocks while
// the returned gate file exists, so a test controls exactly when the startup
// provider load can finish. Values live as flat files in the vault dir, as
// with installFakeCoffer.
func installGatedFakeCoffer(t *testing.T) (gate string) {
	t.Helper()
	binDir := t.TempDir()
	gate = filepath.Join(t.TempDir(), "gate")
	if err := os.WriteFile(gate, nil, 0600); err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}
	script := "#!/bin/sh\n" +
		"set -e\n" +
		"while [ -f \"" + gate + "\" ]; do sleep 0.02; done\n" +
		"key=$(printf '%s' \"$2\" | tr '/' '_')\n" +
		"if [ ! -f \"$key\" ]; then echo \"fake coffer: no such key $2\" >&2; exit 1; fi\n" +
		"cat \"$key\"\n"
	if err := os.WriteFile(filepath.Join(binDir, "coffer"), []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake coffer script: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return gate
}

// startLoadingDaemon builds a coffer-backed daemon on a short socket path and
// starts RunWithStartupLoad in the background. The returned channel yields
// Run's result once the daemon stops.
func startLoadingDaemon(t *testing.T, vaultDir string, providers map[string]string) (*Daemon, <-chan error) {
	t.Helper()
	d := newCofferBackedDaemon(t, vaultDir, providers)
	d.cfg.SocketPath = filepath.Join(shortSocketDir(t), "w.sock")

	done := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		done <- d.RunWithStartupLoad()
		close(stopped)
	}()
	t.Cleanup(func() {
		d.cancel()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
		}
	})
	return d, done
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %s did not appear", path)
}

func removeGate(t *testing.T, gate string) {
	t.Helper()
	if err := os.Remove(gate); err != nil {
		t.Fatalf("failed to remove gate: %v", err)
	}
}

func TestSocketListensBeforeProvidersLoadAndEarlyGetWaits(t *testing.T) {
	gate := installGatedFakeCoffer(t)
	vaultDir := t.TempDir()
	setFakeCofferValue(t, vaultDir, "a/secret", "value-a")

	d, _ := startLoadingDaemon(t, vaultDir, map[string]string{"prov-a": "a/secret"})

	// The socket must exist while the load is still blocked on the gate.
	waitForSocket(t, d.cfg.SocketPath)

	// A client with a timeout far shorter than the load still gets its
	// token: the daemon's loading marker stretches the client's deadline.
	type result struct {
		token string
		err   error
	}
	got := make(chan result, 1)
	go func() {
		c := &protocol.Client{SocketPath: d.cfg.SocketPath, Timeout: 300 * time.Millisecond}
		raw, err := c.SendAndCheck(&protocol.Request{Action: "get", Provider: "prov-a", Scope: "token"})
		if err != nil {
			got <- result{err: err}
			return
		}
		got <- result{token: string(raw)}
	}()

	select {
	case r := <-got:
		t.Fatalf("get answered before providers loaded: %+v", r)
	case <-time.After(800 * time.Millisecond):
	}

	removeGate(t, gate)

	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("early get failed: %v", r.err)
		}
		if !strings.Contains(r.token, `"value-a"`) {
			t.Errorf("early get response = %s, want token value-a", r.token)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("early get never answered after providers loaded")
	}
}

func TestGetAfterStartupIsServedWithoutLoadingMarker(t *testing.T) {
	vaultDir := t.TempDir()
	installFakeCoffer(t, t.TempDir())
	setFakeCofferValue(t, vaultDir, "a/secret", "value-a")

	d, _ := startLoadingDaemon(t, vaultDir, map[string]string{"prov-a": "a/secret"})
	select {
	case <-d.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("daemon never became ready")
	}

	c := protocol.NewClient(d.cfg.SocketPath)
	raw, err := c.Send(&protocol.Request{Action: "get", Provider: "prov-a", Scope: "token"})
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if !strings.Contains(string(raw), `"value-a"`) {
		t.Errorf("response = %s, want token value-a", raw)
	}
}

func TestStartupLoadFailureAnswersWaitersAndStopsDaemon(t *testing.T) {
	gate := installGatedFakeCoffer(t)
	vaultDir := t.TempDir() // "a/secret" deliberately absent: a hard coffer error

	d, done := startLoadingDaemon(t, vaultDir, map[string]string{"prov-a": "a/secret"})
	waitForSocket(t, d.cfg.SocketPath)

	errCh := make(chan error, 1)
	go func() {
		c := &protocol.Client{SocketPath: d.cfg.SocketPath, Timeout: 300 * time.Millisecond}
		_, err := c.SendAndCheck(&protocol.Request{Action: "status"})
		errCh <- err
	}()
	time.Sleep(200 * time.Millisecond)
	removeGate(t, gate)

	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), protocol.ErrInternalError) {
			t.Errorf("waiting client error = %v, want %s", err, protocol.ErrInternalError)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("waiting client never answered")
	}

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "failed to load providers") {
			t.Errorf("Run() error = %v, want a provider load failure", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon kept running after a failed startup load")
	}
}

func TestLoadProvidersWithWorkerPoolLoadsEveryProvider(t *testing.T) {
	vaultDir := t.TempDir()
	installFakeCoffer(t, t.TempDir())
	providers := make(map[string]string)
	for i := 0; i < 3*providerLoadWorkers+1; i++ {
		path := fmt.Sprintf("p%d/secret", i)
		providers[fmt.Sprintf("prov-%d", i)] = path
		setFakeCofferValue(t, vaultDir, path, fmt.Sprintf("value-%d", i))
	}

	d := newCofferBackedDaemon(t, vaultDir, providers)
	if err := d.LoadProviders(); err != nil {
		t.Fatalf("LoadProviders() error: %v", err)
	}
	for i := range len(providers) {
		resp := callHandleGet(t, d, fmt.Sprintf("prov-%d", i), "token")
		if want := fmt.Sprintf("value-%d", i); resp["token"] != want {
			t.Errorf("prov-%d token = %v, want %s", i, resp["token"], want)
		}
	}
}
