# Wicket -- Local Credential Broker Daemon

## Project Overview

Wicket is a per-machine daemon that brokers API credentials for AI coding assistants (primarily Claude Code) and automation scripts. Instead of giving Claude Code direct access to root API tokens or the macOS Keychain, Wicket sits between the caller and a SOPS+age vault ("coffer"), issuing short-lived, narrowly scoped tokens on demand.

The core value proposition: **Claude Code never sees root credentials.** It asks for what it needs, gets a token that expires in minutes, and Wicket logs every issuance for audit.

For services that don't support short-lived token generation (e.g., Home Assistant long-lived tokens), Wicket acts as a passthrough broker -- the credential still flows through wicket's Unix socket rather than being read directly from the vault, maintaining the single-point-of-audit guarantee.

### Goals

1. **Eliminate root credential exposure** -- Claude Code and scripts never read the vault directly
2. **Enforce least-privilege** -- tokens are scoped to the specific operation requested
3. **Time-bound access** -- short-lived tokens limit blast radius of any leak
4. **Full audit trail** -- every token issuance is logged with caller identity, scope, and timestamp
5. **Zero-config for callers** -- a single CLI command or MCP tool call returns a usable token
6. **Portable** -- runs on macOS (Verve, Wiles) and Linux; single static binary

### Non-Goals

- Wicket is NOT a secrets manager (coffer handles that)
- Wicket does NOT manage credential rotation for root secrets
- Wicket does NOT handle authentication for end users (it authenticates local processes via kernel mechanisms)
- Wicket does NOT replace provider-specific CLIs (e.g., `wrangler`, `gh`) -- it complements them

---

## Architecture

```
coffer (SOPS+age vault on disk)
       |
       | reads root credentials at startup
       v
wicket daemon (credentials held in memory only)
       |
       | Unix socket: /tmp/wicket-$(id -u).sock
       | (0700 permissions, getpeereid() on every connection)
       v
wicket CLI client  /  MCP server  /  shell scripts
       |
       | receives short-lived scoped token (or passthrough credential)
       v
Claude Code  /  automation scripts  /  CI tasks
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Go** | Small static binary, excellent Unix socket support, cross-compiles trivially for darwin/arm64 and linux/amd64, same language as Tailscale and the Setec ecosystem |
| **Unix socket (not TCP)** | Kernel-enforced peer authentication via getpeereid(); no network exposure; no TLS complexity |
| **SOPS+age vault (coffer)** | Already planned/in-use for secret storage; age is simpler than GPG; SOPS handles structured files |
| **In-memory credential hold** | Root secrets are read from coffer on startup and held in memory only; never written to disk by wicket |
| **JSON-over-socket protocol** | Simple, debuggable, no dependency on gRPC/protobuf; adequate for local IPC at this scale |
| **Provider plugin model** | Each provider is a Go interface implementation; adding new providers is a single file |

---

## Technical Requirements

### Runtime

- **Go 1.22+** (for improved crypto, structured logging via `log/slog`)
- **macOS 13+** (Ventura) and Linux (kernel 3.10+)
- **No CGo** -- pure Go for easy cross-compilation (use `golang.org/x/sys/unix` for getpeereid)

### Dependencies (minimal)

| Dependency | Purpose |
|------------|---------|
| `golang.org/x/sys/unix` | getpeereid(), LOCAL_PEERPID |
| `gopkg.in/yaml.v3` | Config file parsing |
| `filippo.io/age` | Decrypt age-encrypted coffer files (if reading vault directly) |
| `log/slog` (stdlib) | Structured logging |
| `github.com/awnumar/memguard` | Secure memory enclave for credential storage; explicit zeroing on lock/shutdown (optional -- can use manual zeroing instead, but memguard provides mlock + guard pages) |

If coffer provides its own CLI for decryption, wicket can shell out to `sops` instead of embedding age decryption. Prefer the library approach to avoid a runtime dependency on sops being installed.

### Build Output

```
wicket          # single static binary (~8-12MB)
```

Installed to `~/.local/bin/wicket` or `/usr/local/bin/wicket`.

---

## Daemon Lifecycle

### Startup

1. Parse config from `~/.config/wicket/config.yaml`
2. Read coffer vault at configured path
3. Decrypt root credentials into memory (requires age identity / passphrase)
4. Initialize provider instances with their root credentials
5. Create Unix socket at configured path with 0700 permissions
6. Begin accepting connections
7. Write PID file to `~/.config/wicket/wicket.pid`

### Idle Lock

After a configurable idle timeout, the daemon clears credentials from memory:

1. Zero all credential memory (explicit `memset`-equivalent, not just GC)
2. Close provider connections
3. Socket remains open but returns `{"error": "daemon locked", "code": "LOCKED"}`
4. Unlock requires re-reading coffer (user provides passphrase interactively or via agent)

**Headless machines (Wiles):** Set `idle_timeout: 0` to disable auto-lock entirely.
Headless dev machines run autonomous operations (marathon mode, cron jobs, LaunchAgents)
and are checked on from mobile devices where re-prompting is impractical. The security
tradeoff is accepted: credentials stay in memory until daemon restart or explicit `wicket lock`.
On laptops (Verve), a timeout (default: 4h) is appropriate since the machine sleeps/travels.

### Shutdown

1. Zero all credential memory
2. Remove Unix socket
3. Remove PID file
4. Flush and close audit log
5. Exit 0

---

## Unix Socket Protocol

All communication is newline-delimited JSON over the Unix socket. Each connection handles exactly one request-response pair, then closes (no persistent connections, no multiplexing).

### Request Format

```json
{
  "action": "get",
  "provider": "cloudflare",
  "scope": "dns",
  "options": {}
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | yes | One of: `get`, `status`, `providers`, `audit`, `lock` |
| `provider` | string | for `get` | Provider name from config |
| `scope` | string | for `get` | Scope name within the provider |
| `options` | object | no | Provider-specific overrides (e.g., custom TTL, zone filter) |

### Response Format (success)

```json
{
  "token": "cf-v4-xxx...",
  "expires_at": "2026-04-07T12:15:00Z",
  "provider": "cloudflare",
  "scope": "dns",
  "type": "short-lived"
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `token` | string | The credential to use |
| `expires_at` | string (RFC 3339) | Expiration time; `null` for passthrough tokens |
| `provider` | string | Echo of requested provider |
| `scope` | string | Echo of requested scope |
| `type` | string | `"short-lived"` or `"passthrough"` |

### Response Format (error)

```json
{
  "error": "provider not configured",
  "code": "PROVIDER_NOT_FOUND"
}
```

**Error codes:**

| Code | Meaning |
|------|---------|
| `PROVIDER_NOT_FOUND` | No provider with that name in config |
| `SCOPE_NOT_FOUND` | Provider exists but scope not configured |
| `TOKEN_EXCHANGE_FAILED` | Provider API returned an error during token creation |
| `LOCKED` | Daemon is idle-locked; needs unlock |
| `UNAUTHORIZED` | getpeereid() check failed |
| `INTERNAL_ERROR` | Unexpected daemon error |

### Failure Notifications (ntfy)

Critical failures MUST send urgent push notifications via ntfy so the operator is alerted even when not watching logs. The daemon sends these automatically -- no external watcher required.

**Endpoint:**

```bash
curl -s -H "Priority: urgent" -H "Title: Wicket Error" -H "Tags: key,warning" \
  -d "Error description" "https://ntfy.sh/roguenode-watchdog-6ffbaa666ec3"
```

**Events that trigger notifications:**

| Event | Condition |
|-------|-----------|
| Daemon crash/restart | Sent on startup if a stale PID file or socket is detected (implies previous unclean exit) |
| Repeated TOKEN_EXCHANGE_FAILED | 3+ consecutive failures for the same provider within 5 minutes (provider API likely down) |
| Unauthorized connection attempt | Any getpeereid() UID mismatch (potential rogue process probing the socket) |
| Coffer locked / unreadable | Daemon cannot decrypt vault on startup or after unlock attempt |

Notifications are best-effort (fire-and-forget HTTP POST). A notification failure MUST NOT block daemon operation. Rate-limit to at most 1 notification per event type per 5 minutes to avoid spam during sustained outages.

### Action: `status`

```json
{"action": "status"}
```

Response:

```json
{
  "status": "running",
  "locked": false,
  "uptime_seconds": 3600,
  "providers_loaded": 5,
  "tokens_issued": 42,
  "last_request": "2026-04-07T11:58:00Z"
}
```

### Action: `providers`

```json
{"action": "providers"}
```

Response:

```json
{
  "providers": [
    {
      "name": "cloudflare",
      "type": "cloudflare",
      "scopes": ["dns", "pages"],
      "healthy": true
    },
    {
      "name": "homeassistant",
      "type": "passthrough",
      "scopes": ["token"],
      "healthy": true
    }
  ]
}
```

### Action: `audit`

```json
{"action": "audit", "options": {"limit": 20}}
```

Response: last N entries from the audit log.

### Action: `lock`

```json
{"action": "lock"}
```

Immediately triggers idle-lock behavior. Responds with `{"status": "locked"}`.

---

## CLI Interface

The `wicket` binary is both the daemon and the client. Subcommand determines behavior.

```
wicket start                          # Start daemon in foreground
wicket start -d                       # Start daemon, daemonize
wicket stop                           # Send shutdown signal to running daemon
wicket status                         # Show daemon status, loaded providers
wicket lock                           # Immediately lock the daemon
wicket unlock                         # Unlock daemon (reads coffer passphrase)
wicket unlock --auto                  # Unlock using keychain-stored coffer password

wicket get <provider>/<scope>         # Request a token (prints to stdout)
wicket get cloudflare/dns             # Short-lived Cloudflare DNS token
wicket get github/repos               # GitHub App installation token
wicket get tailscale/api              # Tailscale OAuth access token
wicket get zoho/crm                   # Zoho OAuth access token
wicket get homeassistant/token        # Passthrough HA long-lived token
wicket get switchbot/api              # Passthrough SwitchBot API key

wicket audit                          # Show recent token issuance log
wicket audit --limit 50               # Show last 50 entries
wicket providers                      # List configured providers and health

wicket version                        # Print version and build info
```

**Output behavior:**

- `wicket get` prints ONLY the token to stdout (for `$()` capture)
- All status/error messages go to stderr
- Exit code 0 on success, 1 on error, 2 on daemon-locked

**Example usage in scripts:**

```bash
# Direct capture
export CF_API_TOKEN=$(wicket get cloudflare/dns)
wrangler deploy

# With error handling
if token=$(wicket get cloudflare/dns 2>/dev/null); then
  export CF_API_TOKEN="$token"
else
  echo "Failed to get Cloudflare token" >&2
  exit 1
fi
```

---

## Providers

Each provider implements the `TokenProvider` interface:

```go
type TokenProvider interface {
    // Name returns the provider's configured name
    Name() string

    // Type returns the provider type (e.g., "cloudflare", "passthrough")
    Type() string

    // Scopes returns available scope names
    Scopes() []string

    // GetToken exchanges root credentials for a scoped, short-lived token
    GetToken(ctx context.Context, scope string, opts map[string]any) (*Token, error)

    // Healthy returns whether the provider can currently issue tokens
    Healthy() bool

    // Close cleans up resources and zeros credential memory
    Close() error
}

type Token struct {
    Value     string     `json:"token"`
    ExpiresAt *time.Time `json:"expires_at"`  // nil for passthrough
    Provider  string     `json:"provider"`
    Scope     string     `json:"scope"`
    Type      string     `json:"type"`  // "short-lived" or "passthrough"
}
```

### Provider: Cloudflare

| Detail | Value |
|--------|-------|
| Root credential | API token with "Create Additional Tokens" permission |
| Token exchange | `POST https://api.cloudflare.com/client/v4/user/tokens` |
| Token body | Policies array with permission groups + resource scoping, `expires_on` field |
| Default TTL | 15 minutes |
| Cleanup | Created tokens auto-expire; optionally DELETE on daemon shutdown |

**Scope configuration maps to Cloudflare permission groups:**

```yaml
scopes:
  dns:
    permissions:
      - zone:dns_records:edit
    zone_ids: ["*"]            # or specific zone IDs
  pages:
    permissions:
      - account:pages:edit
    account_ids: ["abc123"]
  workers:
    permissions:
      - account:workers_scripts:edit
      - account:workers_routes:edit
    account_ids: ["abc123"]
```

### Provider: GitHub

| Detail | Value |
|--------|-------|
| Root credential | GitHub App private key (PEM) |
| Token exchange | 1. Sign JWT with app_id + private key; 2. `POST /app/installations/{id}/access_tokens` |
| Token body | `permissions` object + optional `repositories` filter |
| Default TTL | 1 hour (GitHub maximum) |
| Note | GitHub controls the exact expiration; cannot request shorter |

**Scope configuration:**

```yaml
scopes:
  repos:
    permissions:
      contents: write
      pull_requests: write
    repositories: ["*"]         # or specific repo names
  issues:
    permissions:
      issues: write
    repositories: ["*"]
```

### Provider: Tailscale OAuth

| Detail | Value |
|--------|-------|
| Root credential | OAuth client_id + client_secret |
| Token exchange | `POST https://api.tailscale.com/api/v2/oauth/token` (client_credentials grant) |
| Token body | `grant_type=client_credentials` |
| Default TTL | 1 hour (Tailscale default) |
| Scoping | Scopes are set on the OAuth client in Tailscale admin; wicket requests the intersection |

### Provider: Zoho OAuth

| Detail | Value |
|--------|-------|
| Root credential | OAuth refresh_token + client_id + client_secret |
| Token exchange | `POST https://accounts.zoho.com/oauth/v2/token` (refresh_token grant) |
| Default TTL | 1 hour (Zoho default) |
| Note | Refresh token may rotate; wicket must persist the new refresh token back to coffer if Zoho issues one |

**Refresh token writeback:** When Zoho issues a new refresh token during a token exchange, wicket MUST write it back to coffer immediately by shelling out to `coffer set zoho/refresh-token <new_value>`. This requires coffer to support a `set` subcommand for in-place updates to SOPS-encrypted vault files. See the coffer SPEC.md for the `coffer set` capability. If the writeback fails, wicket logs an error and sends an ntfy notification (this is a critical failure -- the old refresh token may now be invalidated).

**Scope configuration:**

```yaml
scopes:
  crm:
    zoho_scopes:
      - ZohoCRM.modules.ALL
      - ZohoCRM.settings.ALL
```

### Provider: Passthrough

| Detail | Value |
|--------|-------|
| Root credential | Any static credential from coffer |
| Token exchange | None (returns the credential directly) |
| TTL | N/A (no expiration control) |
| Use case | Services without short-lived token support (Home Assistant, SwitchBot, VoIP.ms, etc.) |

The passthrough provider still provides value:
- Credentials flow through wicket's audit log
- Claude Code never reads the vault
- Callers use the same interface regardless of provider type
- If/when a service adds short-lived token support, swap the provider type without changing callers

---

## Security Model

### Process Authentication

Every connection to the Unix socket is authenticated:

1. **Socket permissions (0700)** -- only the owning user can connect
2. **getpeereid()** -- kernel returns the UID/GID of the connecting process; daemon verifies it matches the daemon's own UID
3. **Optional PID verification (macOS)** -- using `LOCAL_PEERPID` socket option + `proc_pidpath()` to verify the connecting binary path (e.g., only allow connections from known binaries like `wicket`, `claude`, `node`)

### Credential Memory Safety

- Root credentials are read from coffer into Go byte slices
- On idle-lock or shutdown, slices are explicitly zeroed (not just dereferenced)
- Use `memguard` or manual `for i := range b { b[i] = 0 }` patterns
- Go's GC may copy memory, so true memory-safe zeroing has limits in Go (documented trade-off; acceptable for this threat model where the attacker is "leaked token" not "memory forensics")

### Audit Log

Append-only JSON file at `~/.config/wicket/audit.log`:

```json
{
  "timestamp": "2026-04-07T12:00:00Z",
  "action": "get",
  "provider": "cloudflare",
  "scope": "dns",
  "caller_pid": 12345,
  "caller_uid": 501,
  "caller_binary": "/usr/local/bin/claude",
  "token_type": "short-lived",
  "expires_at": "2026-04-07T12:15:00Z",
  "success": true
}
```

Failed requests are also logged (with `"success": false` and an `"error"` field).

The audit log is NOT rotated by wicket itself. Use `newsyslog` or `logrotate` externally.

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Claude Code reads root secrets from vault | Wicket is the only process that reads the vault; Claude uses `wicket get` |
| Leaked short-lived token | 15-minute TTL limits blast radius; audit log shows what was issued |
| Rogue local process requests token | getpeereid() restricts to same UID; optional binary path verification |
| Daemon memory dump | Idle-lock zeros credentials; Go GC limitation is accepted (see above) |
| Audit log tampering | Append-only mode (O_APPEND); could add log signing in the future |
| Socket hijacking | 0700 permissions; socket removed on shutdown; stale socket detection on startup |

---

## Configuration

**Location:** `~/.config/wicket/config.yaml`

```yaml
# Socket path -- defaults to /tmp/wicket-$(id -u).sock (UID-suffixed)
# Supports multi-user machines and avoids socket conflicts
socket_path: /tmp/wicket-$(id -u).sock

# Path to the coffer vault directory
coffer_path: ~/dev/coffer

# How long before the daemon auto-locks and clears credentials from memory
# Set to 0 on headless machines (Wiles) to disable auto-lock
# Set to 4h on laptops (Verve) where sleep/travel is common
idle_timeout: 0  # headless: never auto-lock

# Audit log location
audit_log: ~/.config/wicket/audit.log

# Optional: restrict connecting binaries (macOS only, requires LOCAL_PEERPID)
# This is what enables PID verification. If the list is empty or omitted,
# only the UID check (getpeereid) is performed -- any process running as
# the same UID can connect. If populated, BOTH UID and binary path are
# verified: the connecting process must match the daemon's UID AND its
# binary path must appear in this list.
allowed_binaries: []
  # - /usr/local/bin/claude
  # - /opt/homebrew/bin/node

# Provider definitions
providers:
  cloudflare:
    type: cloudflare
    root_credential: cloudflare/meta-token  # coffer path
    default_ttl: 15m
    scopes:
      dns:
        permissions:
          - zone:dns_records:edit
        zone_ids: ["*"]
      pages:
        permissions:
          - account:pages:edit
        account_ids: []
      workers:
        permissions:
          - account:workers_scripts:edit
          - account:workers_routes:edit
        account_ids: []

  github:
    type: github
    app_id: 12345
    installation_id: 67890
    private_key: github/app-private-key  # coffer path
    scopes:
      repos:
        permissions:
          contents: write
          pull_requests: write
        repositories: ["*"]
      issues:
        permissions:
          issues: write
        repositories: ["*"]

  tailscale:
    type: tailscale_oauth
    client_id: tailscale/oauth-client-id      # coffer path
    client_secret: tailscale/oauth-client-secret  # coffer path
    scopes:
      api:
        tailscale_scopes:
          - devices:read
          - dns:read

  zoho:
    type: zoho_oauth
    client_id: zoho/oauth-client-id         # coffer path
    client_secret: zoho/oauth-client-secret  # coffer path
    refresh_token: zoho/oauth-refresh-token  # coffer path
    domain: zoho.com                          # or zoho.eu, zoho.in, etc.
    scopes:
      crm:
        zoho_scopes:
          - ZohoCRM.modules.ALL
          - ZohoCRM.settings.ALL

  homeassistant:
    type: passthrough
    credential: home-automation/ha-token  # coffer path

  switchbot:
    type: passthrough
    credential: home-automation/switchbot-api  # coffer path
```

### Coffer Vault Path Mapping

Coffer paths referenced in `root_credential` and other config fields (e.g., `cloudflare/meta-token`) map to keys within SOPS-encrypted YAML category files in the coffer vault directory. The path format is `<category>/<key>`:

- `cloudflare/meta-token` -- key `meta-token` in `~/dev/coffer/vault/cloudflare.yaml`
- `github/app-private-key` -- key `app-private-key` in `~/dev/coffer/vault/github.yaml`
- `home-automation/ha-token` -- key `ha-token` in `~/dev/coffer/vault/home-automation.yaml`

Wicket reads these via coffer's decryption layer (either the `coffer` CLI or by embedding age decryption directly). See the coffer SPEC.md for the full vault format specification.

---

## Integration with Claude Code

### Option A: Shell Function (simple)

Add to Claude Code's environment (via `.bashrc`, `.zshrc`, or Claude Code's shell init):

```bash
# Convenience wrapper
kc() { wicket get "$1" 2>/dev/null; }

# Usage in Claude Code
export CF_API_TOKEN=$(kc cloudflare/dns)
```

### Option B: MCP Server (preferred)

An MCP server that wraps wicket, exposing credential retrieval as MCP tools:

```
Tool: get_credential
  Arguments:
    provider: string (required)
    scope: string (required)
  Returns: { token: string, expires_at: string, type: string }
```

This is cleaner because:
- Claude Code requests credentials through the structured MCP protocol
- The MCP server connects to wicket's Unix socket (same-machine)
- No shell escaping or environment variable juggling
- MCP tool descriptions can document available providers/scopes

The MCP server would be a separate small binary (or a mode of the wicket binary itself: `wicket mcp-server`).

### Option C: Claude Code Custom Command

A custom slash command (`/get-token cloudflare/dns`) that wraps the CLI call.

---

## LaunchAgent (macOS Auto-Start)

**Location:** `~/Library/LaunchAgents/com.1507.wicket.plist`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.1507.wicket</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/wicket</string>
        <string>start</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>StandardOutPath</key>
    <string>/tmp/wicket.stdout.log</string>

    <key>StandardErrorPath</key>
    <string>/tmp/wicket.stderr.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>/Users/bryce</string>
    </dict>
</dict>
</plist>
```

**Note:** The daemon starts in locked state when launched by launchd (since there's no interactive passphrase prompt). An `unlock` command or keychain-stored age identity would be needed for non-interactive startup.

---

## Project Structure

```
wicket/
  cmd/
    wicket/
      main.go              # CLI entrypoint, subcommand routing
  internal/
    daemon/
      server.go            # Unix socket server, connection handling
      auth.go              # getpeereid(), PID verification
      state.go             # Daemon state machine (running, locked, stopping)
    provider/
      provider.go          # TokenProvider interface
      cloudflare.go        # Cloudflare token exchange
      github.go            # GitHub App installation tokens
      tailscale.go         # Tailscale OAuth client_credentials
      zoho.go              # Zoho OAuth refresh_token
      passthrough.go       # Static credential passthrough
    config/
      config.go            # YAML config parsing and validation
    audit/
      logger.go            # Append-only JSON audit log
    coffer/
      reader.go            # Interface to coffer vault (sops/age)
    protocol/
      types.go             # Request/Response JSON types
      client.go            # Unix socket client (used by CLI)
  mcp/
    server.go              # Optional MCP server mode
  SPEC.md
  PROJECT_LOG.md
  go.mod
  go.sum
```

---

## Future Enhancements

### Bitwarden Backend

When Bitwarden's AI credential retrieval spec ships, add a `bitwarden` coffer backend. The broker pattern remains identical (wicket still issues short-lived tokens), only the source of root credentials changes.

### Token Caching

Cache issued tokens in memory and return the same token for repeat requests if it has >30% of its TTL remaining. Reduces API calls to providers and improves latency.

### Multi-User Support

If deployed on a shared machine, wicket could run as a system service with per-user credential stores. Not needed for the initial single-user use case.

### Log Signing

Sign audit log entries with an ed25519 key to detect tampering. Each entry includes a hash chain of previous entries.

### Prometheus Metrics

Expose `/metrics` on an optional localhost HTTP port for monitoring token issuance rates, provider health, and error counts.

### Systemd Socket Activation (Linux)

Use systemd socket activation so wicket starts on first connection rather than at boot.

---

## Relationship to Other Projects

| Project | Relationship |
|---------|-------------|
| **coffer** | Upstream dependency. Wicket reads root credentials from coffer's SOPS+age vault |
| **Claude Code** | Primary consumer. Requests scoped tokens via CLI or MCP |
| **Reconvoy** | Could use wicket for Cloudflare API tokens during deploys |
| **Hellga's Kitchen** | Could use wicket for CF Pages tokens and Resend API keys |
| **icloud-mcp** | No direct relationship (icloud-mcp doesn't need API tokens) |
| **HostHum** | Could use wicket for Home Assistant tokens |

---

## Success Criteria

1. `wicket get cloudflare/dns` returns a working short-lived token in <500ms
2. Token expires within configured TTL (verified by attempting use after expiry)
3. Audit log captures every token request with caller identity
4. Idle-lock engages after configured timeout and blocks further requests
5. `wicket get` works seamlessly as `$(wicket get ...)` in shell scripts
6. Single binary, no runtime dependencies beyond coffer vault files
7. All providers pass integration tests against real APIs
