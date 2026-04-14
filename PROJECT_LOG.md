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

- Scaffolded full Go project with `go mod init github.com/shasb/wicket`
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
- GitHub repo created: `bryce-shashinka/wicket` (private)
- Coffer project does not exist yet (prerequisite for actually running the daemon)

### Next Steps

- Build coffer (SOPS+age vault) so wicket can read credentials
- Integration test with real Cloudflare API
- Implement `unlock` subcommand (re-read coffer after idle-lock)
- Add token caching (return same token if >30% TTL remaining)
- LaunchAgent setup for Wiles and Verve
- MCP server mode (`wicket mcp-server`)
- Optional binary path verification via LOCAL_PEERPID on macOS
