package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/1507-systems/wicket/internal/config"
	"github.com/1507-systems/wicket/internal/protocol"
	"github.com/1507-systems/wicket/internal/provider"
)

// fakeProvider is a TokenProvider that mints deterministic tokens and counts
// how many times GetToken was called, so tests can observe cache hits.
type fakeProvider struct {
	mu    sync.Mutex
	calls int
	ttl   time.Duration
}

func (f *fakeProvider) Name() string     { return "fake" }
func (f *fakeProvider) Type() string     { return "fake" }
func (f *fakeProvider) Scopes() []string { return []string{"s"} }
func (f *fakeProvider) Healthy() bool    { return true }
func (f *fakeProvider) Close() error     { return nil }

func (f *fakeProvider) GetToken(ctx context.Context, scope string, opts map[string]any) (*provider.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	exp := time.Now().Add(f.ttl)
	return &provider.Token{
		Value:     fmt.Sprintf("tok-%d", f.calls),
		ExpiresAt: &exp,
		Provider:  "fake",
		Scope:     scope,
		Type:      "short-lived",
	}, nil
}

func (f *fakeProvider) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// newTestDaemon builds a daemon with no configured providers (so unlock's
// LoadProviders never shells out to coffer) and throwaway state paths.
func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		SocketPath: filepath.Join(dir, "wicket.sock"),
		CofferPath: dir,
		AuditLog:   filepath.Join(dir, "audit.log"),
		PIDFile:    filepath.Join(dir, "wicket.pid"),
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	t.Cleanup(func() { d.auditor.Close() })
	return d
}

func testPeer() *PeerInfo {
	return &PeerInfo{UID: uint32(os.Getuid()), PID: int32(os.Getpid())}
}

// callHandleGet invokes handleGet over an in-memory pipe and decodes the
// single JSON response the daemon writes.
func callHandleGet(t *testing.T, d *Daemon, providerName, scope string) map[string]any {
	t.Helper()
	return callHandleGetOpts(t, d, providerName, scope, nil)
}

// callHandleGetOpts is callHandleGet with provider-specific request options.
func callHandleGetOpts(t *testing.T, d *Daemon, providerName, scope string, opts map[string]any) map[string]any {
	t.Helper()
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		d.handleGet(server, &protocol.Request{Action: "get", Provider: providerName, Scope: scope, Options: opts}, testPeer())
	}()

	var raw map[string]any
	if err := json.NewDecoder(client).Decode(&raw); err != nil {
		t.Fatalf("failed to decode handleGet response: %v", err)
	}
	return raw
}

// callHandleUnlock invokes handleUnlock over an in-memory pipe.
func callHandleUnlock(t *testing.T, d *Daemon) map[string]any {
	t.Helper()
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		d.handleUnlock(server)
	}()

	var raw map[string]any
	if err := json.NewDecoder(client).Decode(&raw); err != nil {
		t.Fatalf("failed to decode handleUnlock response: %v", err)
	}
	return raw
}

func TestLockUnlockStateMachine(t *testing.T) {
	d := newTestDaemon(t)

	if d.locked.Load() {
		t.Fatal("daemon should start unlocked")
	}

	d.Lock()
	if !d.locked.Load() {
		t.Fatal("daemon should be locked after Lock()")
	}
	d.Lock() // idempotent

	if err := d.Unlock(); err != nil {
		t.Fatalf("Unlock() error: %v", err)
	}
	if d.locked.Load() {
		t.Fatal("daemon should be unlocked after Unlock()")
	}
	if err := d.Unlock(); err != nil { // idempotent
		t.Fatalf("Unlock() on unlocked daemon error: %v", err)
	}
}

func TestHandleUnlockResponse(t *testing.T) {
	d := newTestDaemon(t)
	d.Lock()

	resp := callHandleUnlock(t, d)
	if resp["status"] != "unlocked" {
		t.Errorf("status = %v, want unlocked", resp["status"])
	}
	if d.locked.Load() {
		t.Error("daemon should be unlocked after handleUnlock")
	}
}

func TestHandleGetLockedReturnsLockedCode(t *testing.T) {
	d := newTestDaemon(t)
	d.providers["fake"] = &fakeProvider{ttl: time.Hour}
	d.Lock()

	resp := callHandleGet(t, d, "fake", "s")
	if resp["code"] != protocol.ErrLocked {
		t.Errorf("code = %v, want %s", resp["code"], protocol.ErrLocked)
	}
}

func TestHandleGetServesCachedToken(t *testing.T) {
	d := newTestDaemon(t)
	fp := &fakeProvider{ttl: time.Hour}
	d.providers["fake"] = fp

	first := callHandleGet(t, d, "fake", "s")
	second := callHandleGet(t, d, "fake", "s")

	if first["token"] != "tok-1" || second["token"] != "tok-1" {
		t.Errorf("tokens = %v, %v; want tok-1 twice (cache hit)", first["token"], second["token"])
	}
	if got := fp.callCount(); got != 1 {
		t.Errorf("provider called %d times, want 1", got)
	}
	if got := d.tokensIssued.Load(); got != 2 {
		t.Errorf("tokensIssued = %d, want 2 (cache hits still count)", got)
	}
}

func TestHandleGetRefreshesNearlyExpiredToken(t *testing.T) {
	d := newTestDaemon(t)
	// 1ns TTL: by the time the second request arrives the cached token has
	// (far) less than 30% of its TTL remaining, forcing a fresh mint.
	fp := &fakeProvider{ttl: time.Nanosecond}
	d.providers["fake"] = fp

	callHandleGet(t, d, "fake", "s")
	second := callHandleGet(t, d, "fake", "s")

	if second["token"] != "tok-2" {
		t.Errorf("second token = %v, want tok-2 (fresh mint)", second["token"])
	}
	if got := fp.callCount(); got != 2 {
		t.Errorf("provider called %d times, want 2", got)
	}
}

func TestHandleGetOptionsBypassCache(t *testing.T) {
	d := newTestDaemon(t)
	fp := &fakeProvider{ttl: time.Hour}
	d.providers["fake"] = fp

	// Prime the cache with a default-shaped token.
	callHandleGet(t, d, "fake", "s")

	// A request carrying provider-specific overrides must not be served the
	// cached default token...
	withOpts := callHandleGetOpts(t, d, "fake", "s", map[string]any{"ttl": "5m"})
	if withOpts["token"] != "tok-2" {
		t.Errorf("options request token = %v, want tok-2 (fresh mint)", withOpts["token"])
	}

	// ...and its options-shaped token must not overwrite the cached one.
	third := callHandleGet(t, d, "fake", "s")
	if third["token"] != "tok-1" {
		t.Errorf("default request token = %v, want tok-1 (cache intact)", third["token"])
	}
	if got := fp.callCount(); got != 2 {
		t.Errorf("provider called %d times, want 2", got)
	}
}

func TestLockClearsTokenCache(t *testing.T) {
	d := newTestDaemon(t)
	fp := &fakeProvider{ttl: time.Hour}
	d.providers["fake"] = fp

	callHandleGet(t, d, "fake", "s")
	d.Lock()
	if err := d.Unlock(); err != nil {
		t.Fatalf("Unlock() error: %v", err)
	}
	// Unlock rebuilt the (empty) provider registry; re-inject the fake the
	// way LoadProviders would for a configured provider.
	d.pmu.Lock()
	d.providers["fake"] = fp
	d.pmu.Unlock()

	resp := callHandleGet(t, d, "fake", "s")
	if resp["token"] != "tok-2" {
		t.Errorf("post-lock token = %v, want tok-2 (cache was cleared)", resp["token"])
	}
	if got := fp.callCount(); got != 2 {
		t.Errorf("provider called %d times, want 2", got)
	}
}
