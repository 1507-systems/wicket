# Wicket

Local credential broker daemon: exchanges root secrets from Coffer for short-lived,
scoped tokens over a Unix socket. The full design, protocol and configuration are in
[SPEC.md](SPEC.md); the change history is in [PROJECT_LOG.md](PROJECT_LOG.md).

## Pausing alerts (no deploy)

Wicket's urgent ntfy alerts can be muted without a rebuild, reinstall or restart. The
daemon reads a pause file on every send, so creating or removing it takes effect on the
next alert.

Pause file: `~/.local/state/wicket/notify-paused`, resolved from the daemon's `HOME`
(on Verve the LaunchAgent sets `HOME=/Users/bryce`). Set `WICKET_PAUSE_FILE` in the
daemon's environment to use a different path.

What the file may contain:

| Contents | Effect |
|----------|--------|
| empty, or `indefinite` | paused until the file is removed |
| a future ISO-8601 time, e.g. `2026-11-08T09:00:00-07:00` or `2026-11-08T16:00Z` | paused until then; a time with no zone is UTC; a bare date means midnight UTC |
| a past time, anything unparseable, a bare number such as `12345` | NOT paused |
| no file, or the file cannot be read | NOT paused |

A value must start with a full `YYYY-MM-DD` date to count as a time. Anything that does
not clearly mean "paused" fails open, so a typo can never silence alerts.

To pause indefinitely:

```bash
mkdir -p ~/.local/state/wicket && echo indefinite > ~/.local/state/wicket/notify-paused
```

To pause until a set time, write the time instead of `indefinite`:

```bash
mkdir -p ~/.local/state/wicket && echo 2026-11-08T09:00:00-07:00 > ~/.local/state/wicket/notify-paused
```

To resume:

```bash
rm ~/.local/state/wicket/notify-paused
```

What is muted: only the outbound ntfy POST. What is not: every check, token exchange,
state change and log line carries on as normal. Each suppressed alert logs one line,
`ntfy notification suppressed: alerts paused`, with the event type and the pause file
path. A suppressed alert does not use up its 5-minute rate-limit slot, so the first
matching event after the pause ends alerts immediately.
