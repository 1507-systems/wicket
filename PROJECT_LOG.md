<!-- summary: Local credential broker daemon — exchanges root secrets from Coffer for short-lived scoped tokens via Unix socket. -->
# Wicket -- Project Log

## 2026-04-07

### Project Created

- Wrote initial SPEC.md with full architecture, provider definitions, protocol spec, security model, CLI interface, config format, and project structure
- Providers specified: Cloudflare (short-lived), GitHub App (installation tokens), Tailscale OAuth, Zoho OAuth, passthrough (HA, SwitchBot, etc.)
- Language: Go (static binary, Unix socket support, cross-compile friendly)
- Depends on coffer (SOPS+age vault) for root credential storage
- Integration options: shell `$()` capture, MCP server, or custom Claude Code command

### Initial Implementation (feat/initial-implementation branch)

- Scaffolded full Go project with `go mod init github.com/1507-systems/wicket`
- Built all core packages:
  - `cmd/wicket/main.go`: CLI entry point with subcommands (start, stop, status, get, lock, unlock, audit, providers, version)
  - `internal/daemon/daemon.go`: Unix socket server with connection handling, signal-based shutdown, idle timeout, PID file management
  - `internal/daemon/auth.go` + platform-specific `auth_darwin.go` / `auth_linux.go`: getpeereid peer authentication using `golang.org/x/sys/unix`
  - `internal/config/config.go`: YAML config parsing with validation for all provider types
  - `internal/coffer/reader.go`: Shells out to `coffer get/set` CLI
  - `internal/provider/provider.go`: TokenProvider interface definition
  - `internal/provider/cloudflare.go`: CF meta-token to short-lived scoped token exchange
  - `internal/provider/github.go`: GitHub App JWT -> installation access token (RS256 signing)
  - `internal/provider/tailscale.go`: OAuth client_credentials flow
  - `internal/provider/zoho.go`: OAuth refresh_token flow with refresh token writeback to coffer
  - `internal/provider/passthrough.go`: Static credential passthrough
  - `internal/protocol/types.go`: JSON request/response types for socket protocol
  - `internal/protocol/client.go`: Unix socket client for CLI commands
  - `internal/audit/audit.go`: Append-only JSON audit log
  - `internal/notify/ntfy.go`: Rate-limited ntfy push notifications for critical failures
- CI: `.github/workflows/ci.yml` with build + vet + test jobs
- Tests: 21 tests passing across config, audit, passthrough, daemon auth, and CLI parsing
- Binary builds to ~10MB static binary
- Fixed: YAML `permissions` key collision between Cloudflare ([]string) and GitHub (map[string]string) by using `gh_permissions` YAML tag for GitHub scopes

### Current State

- Initial implementation complete on `feat/initial-implementation` branch
- All tests pass, `go vet` clean
- GitHub repo created: `1507-systems/wicket` (public)
- Coffer vault exists at `~/dev/coffer/` — prerequisite satisfied

### Next Steps

- Build coffer (SOPS+age vault) so wicket can read credentials
- Integration test with real Cloudflare API
- Implement `unlock` subcommand (re-read coffer after idle-lock)
- Add token caching (return same token if >30% TTL remaining)
- LaunchAgent setup for Wiles and Verve
- MCP server mode (`wicket mcp-server`)
- Optional binary path verification via LOCAL_PEERPID on macOS

## 2026-07-02

### Catch-up (log had gone stale since April)

- Merged to `main` since the last entry: the initial implementation branch, the stdin-secrets/audit-EOF fix (tagged **`v0.1.0-audit-clean`**, 2026-04-13), and the keycard → wicket rename.
- **PR #1** merged 2026-06-04: `fix(security): medium/low hardening (corpus audit)` — added the `allowed_binaries` executable allowlist (`AuthenticatePeerWithBinaries` + per-platform exepath resolution) and provider hardening.
- **PR #2** merged 2026-06-22: `ci: bump actions/checkout v4 -> v5` (Node 24 migration).
- 2026-06-27: CI gained an at-merge Cortex issue closer, iterated to a SHA-pinned call of the shared public `cortex-close` workflow (org policy blocked private `workflow_call`).

### `unlock` subcommand + token caching

- **`wicket unlock`** is now implemented end-to-end: new `unlock` protocol action; the daemon re-reads coffer via `LoadProviders()` (which now builds a fresh registry and swaps it atomically — a partial failure zeros the abandoned providers and leaves the daemon locked), clears the locked flag, and returns `{"status":"unlocked","providers_loaded":N}`. Coffer decryption is delegated to the coffer CLI; if the vault needs an interactive passphrase, unlock fails, the daemon stays locked, and an ntfy alert fires (per SPEC "Coffer locked/unreadable"). Provider registry access is now guarded by an RWMutex since unlock swaps it at runtime.
- **Token caching** (SPEC "Token Caching"): issued tokens are cached in memory keyed by provider/scope and reused while **>30% of their original TTL** remains; stale entries are evicted and re-minted. Passthrough tokens (no expiry) are never cached, and requests carrying provider-specific `options` bypass the cache in both directions (a token minted under overrides is never reused for a default request, and vice versa). Cache hits are audited like fresh issuances (now including `caller_binary`, which the success path previously omitted). `lock` and shutdown clear the cache so cached token values don't outlive the credentials that minted them.
- Tests: 31 → 43 (`tokenCache` threshold/eviction/keying/clear, lock/unlock state machine, cache wiring through `handleGet` via `net.Pipe`, options-bypass, locked-daemon `LOCKED` code). Also fixed a macOS-only pre-existing failure: long `t.TempDir()` paths overflow the 104-byte `sun_path` limit in the daemon socket tests (`bind: invalid argument`); socket tests now use a short `os.MkdirTemp` dir.
- `go build`, `go vet`, `go test -race ./...` all clean.

### Next Steps

- Integration test with real Cloudflare API
- LaunchAgent setup for Wiles and Verve (daemon starts locked under launchd; `wicket unlock` now exists for that flow)
- MCP server mode (`wicket mcp-server`) — deliberately deferred, bigger design surface
- Optional binary path verification via LOCAL_PEERPID on macOS — deliberately deferred
- `wicket unlock --auto` (keychain-stored coffer passphrase) once coffer exposes it
