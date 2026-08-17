package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// callHandleReload invokes handleReload over an in-memory pipe.
func callHandleReload(t *testing.T, d *Daemon) map[string]any {
	t.Helper()
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		d.handleReload(server)
	}()

	var raw map[string]any
	if err := json.NewDecoder(client).Decode(&raw); err != nil {
		t.Fatalf("failed to decode handleReload response: %v", err)
	}
	return raw
}

// installFakeCoffer puts a fake `coffer` executable on PATH for the
// remainder of the test (t.Setenv auto-restores it). The fake stores each
// vault value as a flat file, named by replacing "/" with "_", inside
// whatever directory the caller (coffer.Reader) sets as the command's
// working directory -- i.e. the real CofferPath. This lets tests drive the
// actual production code path (coffer.Reader shelling out to a binary named
// "coffer") without a real SOPS+age vault, so Reload's coffer round-trip is
// exercised for real rather than mocked at the Go level.
func installFakeCoffer(t *testing.T, binDir string) {
	t.Helper()
	script := "#!/bin/sh\n" +
		"set -e\n" +
		"case \"$1\" in\n" +
		"  get)\n" +
		"    key=$(printf '%s' \"$2\" | tr '/' '_')\n" +
		"    if [ ! -f \"$key\" ]; then\n" +
		"      echo \"fake coffer: no such key $2\" >&2\n" +
		"      exit 1\n" +
		"    fi\n" +
		"    cat \"$key\"\n" +
		"    ;;\n" +
		"  set)\n" +
		"    key=$(printf '%s' \"$2\" | tr '/' '_')\n" +
		"    cat > \"$key\"\n" +
		"    ;;\n" +
		"  *)\n" +
		"    echo \"fake coffer: unsupported args: $*\" >&2\n" +
		"    exit 1\n" +
		"    ;;\n" +
		"esac\n"

	path := filepath.Join(binDir, "coffer")
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake coffer script: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// setFakeCofferValue seeds/rotates a value in the fake vault at vaultDir,
// simulating `coffer set <path> --stdin`.
func setFakeCofferValue(t *testing.T, vaultDir, path, value string) {
	t.Helper()
	key := strings.ReplaceAll(path, "/", "_")
	if err := os.WriteFile(filepath.Join(vaultDir, key), []byte(value), 0600); err != nil {
		t.Fatalf("failed to seed fake coffer value: %v", err)
	}
}

// newCofferBackedDaemon builds a daemon wired to a fake coffer vault at
// vaultDir with the given passthrough providers (name -> coffer path),
// suitable for tests that need a real (faked) coffer round-trip rather than
// the empty-provider-set shortcut newTestDaemon uses.
func newCofferBackedDaemon(t *testing.T, vaultDir string, passthroughProviders map[string]string) *Daemon {
	t.Helper()
	stateDir := t.TempDir()

	providers := make(map[string]config.ProviderConfig, len(passthroughProviders))
	for name, cofferPath := range passthroughProviders {
		providers[name] = config.ProviderConfig{Type: "passthrough", Credential: cofferPath}
	}

	cfg := &config.Config{
		SocketPath: filepath.Join(stateDir, "wicket.sock"),
		CofferPath: vaultDir,
		AuditLog:   filepath.Join(stateDir, "audit.log"),
		PIDFile:    filepath.Join(stateDir, "wicket.pid"),
		Providers:  providers,
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	t.Cleanup(func() { d.auditor.Close() })
	return d
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

// --- Reload ---
//
// These cover the actual bug fixed tonight: `wicket unlock` on an
// already-unlocked daemon is a documented no-op (see
// TestLockUnlockStateMachine) and never re-reads coffer, so a `coffer set`
// rotating a credential wicket already has a provider for was never picked
// up without a full daemon restart. Reload is the dedicated fix: an
// operation that always re-reads coffer regardless of lock state (except
// while actually locked, see below), with no restart and no dropped socket.

func TestReloadPicksUpChangedVaultValue(t *testing.T) {
	binDir := t.TempDir()
	vaultDir := t.TempDir()
	installFakeCoffer(t, binDir)
	setFakeCofferValue(t, vaultDir, "tailscale/oauth-client-secret", "old-secret")

	d := newCofferBackedDaemon(t, vaultDir, map[string]string{
		"tailscale-oauth-client-secret": "tailscale/oauth-client-secret",
	})
	if err := d.LoadProviders(); err != nil {
		t.Fatalf("initial LoadProviders() error: %v", err)
	}

	before := callHandleGet(t, d, "tailscale-oauth-client-secret", "token")
	if before["token"] != "old-secret" {
		t.Fatalf("token before rotation = %v, want old-secret", before["token"])
	}

	// Simulate `coffer set tailscale/oauth-client-secret --stdin` rotating
	// the value on disk, exactly as happened tonight.
	setFakeCofferValue(t, vaultDir, "tailscale/oauth-client-secret", "new-secret")

	if err := d.Reload(); err != nil {
		t.Fatalf("Reload() error: %v", err)
	}

	after := callHandleGet(t, d, "tailscale-oauth-client-secret", "token")
	if after["token"] != "new-secret" {
		t.Errorf("token after Reload() = %v, want new-secret (stale value still served)", after["token"])
	}
}

func TestReloadLeavesUnrotatedProviderValueIntact(t *testing.T) {
	binDir := t.TempDir()
	vaultDir := t.TempDir()
	installFakeCoffer(t, binDir)
	setFakeCofferValue(t, vaultDir, "a/secret", "value-a")
	setFakeCofferValue(t, vaultDir, "b/secret", "value-b")

	d := newCofferBackedDaemon(t, vaultDir, map[string]string{
		"prov-a": "a/secret",
		"prov-b": "b/secret",
	})
	if err := d.LoadProviders(); err != nil {
		t.Fatalf("initial LoadProviders() error: %v", err)
	}

	// Rotate only prov-a's backing value.
	setFakeCofferValue(t, vaultDir, "a/secret", "value-a-rotated")

	if err := d.Reload(); err != nil {
		t.Fatalf("Reload() error: %v", err)
	}

	if got := callHandleGet(t, d, "prov-a", "token"); got["token"] != "value-a-rotated" {
		t.Errorf("prov-a token = %v, want value-a-rotated", got["token"])
	}
	if got := callHandleGet(t, d, "prov-b", "token"); got["token"] != "value-b" {
		t.Errorf("prov-b token = %v, want value-b (unrotated provider must survive reload unchanged)", got["token"])
	}
}

func TestReloadClosesSupersededProviderInstances(t *testing.T) {
	binDir := t.TempDir()
	vaultDir := t.TempDir()
	installFakeCoffer(t, binDir)
	setFakeCofferValue(t, vaultDir, "a/secret", "value-a")

	d := newCofferBackedDaemon(t, vaultDir, map[string]string{"prov-a": "a/secret"})
	if err := d.LoadProviders(); err != nil {
		t.Fatalf("initial LoadProviders() error: %v", err)
	}

	d.pmu.RLock()
	oldInstance := d.providers["prov-a"]
	d.pmu.RUnlock()

	setFakeCofferValue(t, vaultDir, "a/secret", "value-a-rotated")
	if err := d.Reload(); err != nil {
		t.Fatalf("Reload() error: %v", err)
	}

	// The superseded instance must be Close()'d (credential zeroed, marked
	// unhealthy) so the old, now-invalid-for-rotation-purposes value doesn't
	// sit around reachable in memory via a stale reference.
	if _, err := oldInstance.GetToken(context.Background(), "token", nil); err == nil {
		t.Error("superseded provider instance should be closed by Reload and refuse to serve, want error")
	}
}

func TestReloadWhileLockedReturnsErrorWithoutUnlocking(t *testing.T) {
	d := newTestDaemon(t)
	d.providers["fake"] = &fakeProvider{ttl: time.Hour}
	d.Lock()

	err := d.Reload()
	if !errors.Is(err, ErrReloadRequiresUnlock) {
		t.Fatalf("Reload() while locked error = %v, want ErrReloadRequiresUnlock", err)
	}
	if !d.locked.Load() {
		t.Error("daemon should still be locked after a failed Reload() -- reload must not implicitly unlock")
	}
}

func TestHandleReloadWhileLockedReturnsLockedCode(t *testing.T) {
	d := newTestDaemon(t)
	d.Lock()

	resp := callHandleReload(t, d)
	if resp["code"] != protocol.ErrLocked {
		t.Errorf("code = %v, want %s", resp["code"], protocol.ErrLocked)
	}
	if !d.locked.Load() {
		t.Error("daemon should still be locked after a reload attempt while locked")
	}
}

func TestHandleReloadResponse(t *testing.T) {
	d := newTestDaemon(t)

	resp := callHandleReload(t, d)
	if resp["status"] != "reloaded" {
		t.Errorf("status = %v, want reloaded", resp["status"])
	}
	if d.locked.Load() {
		t.Error("reload must not lock the daemon")
	}
}

func TestReloadDoesNotClearTokenCache(t *testing.T) {
	d := newTestDaemon(t)
	fp := &fakeProvider{ttl: time.Hour}
	d.providers["fake"] = fp

	first := callHandleGet(t, d, "fake", "s")

	if err := d.Reload(); err != nil {
		t.Fatalf("Reload() error: %v", err)
	}
	// newTestDaemon has no providers in its config, so Reload's
	// LoadProviders rebuilds an empty registry -- re-inject "fake" the way a
	// real coffer-backed reload would leave an unrotated provider in place,
	// then confirm the cached token for it survived the reload untouched
	// (rotating a root credential doesn't revoke already-issued derived
	// tokens, so reload -- unlike Lock -- must not force-evict the cache).
	d.pmu.Lock()
	d.providers["fake"] = fp
	d.pmu.Unlock()

	second := callHandleGet(t, d, "fake", "s")
	if second["token"] != first["token"] {
		t.Errorf("token after Reload() = %v, want unchanged %v (cache should survive reload)", second["token"], first["token"])
	}
	if got := fp.callCount(); got != 1 {
		t.Errorf("provider called %d times, want 1 (cached token must not be re-minted by reload)", got)
	}
}
