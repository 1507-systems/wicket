# wicket build + deploy
#
# WHY THIS EXISTS
# ---------------
# There was no deploy step at all: the daemon ran a hand-copied binary from
# ~/.local/bin/wicket, so merged fixes never reached production. On 2026-07-25
# the deployed binary turned out to be from 2026-04-09 — old enough that PR #3's
# token caching had never shipped (which is why token minting was hammering the
# Cloudflare token cap) and PR #1's allowed_binaries enforcement was being
# silently ignored. Nobody noticed for four months because nothing compared the
# running binary to the repo.
#
# So `make install` is deliberately verify-or-fail: it refuses to leave the
# daemon down, and it proves the credential path works before declaring success.
# `make check-deployed` answers "is what's running actually current?" — run it
# whenever wicket behaves in a way the source says it shouldn't.

BINARY      := wicket
INSTALL_DIR := $(HOME)/.local/bin
INSTALLED   := $(INSTALL_DIR)/$(BINARY)
BUILD_OUT   := ./$(BINARY)
# Any scope is fine here; this only has to prove the daemon answers and can mint.
VERIFY_SCOPE := cloudflare/d1-read

.PHONY: build test vet fmt install check-deployed restart uninstall-check

build:
	go build -o $(BUILD_OUT) ./cmd/wicket

test:
	go test ./...

vet:
	go vet ./...

fmt:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi; \
	echo "gofmt clean"

# Full gate. Never install something that does not build, test, vet and format.
install: fmt vet test build
	@set -e; \
	echo "==> backing up the current binary (rollback path)"; \
	if [ -f "$(INSTALLED)" ]; then \
		cp "$(INSTALLED)" "/tmp/wicket-rollback-$$(date +%s)"; \
		echo "    saved /tmp/wicket-rollback-*"; \
	else \
		echo "    none installed yet"; \
	fi; \
	echo "==> stopping daemon"; \
	$(BINARY) stop 2>/dev/null || echo "    (not running)"; \
	echo "==> installing $(BUILD_OUT) -> $(INSTALLED)"; \
	mkdir -p "$(INSTALL_DIR)"; \
	cp "$(BUILD_OUT)" "$(INSTALLED)"; \
	chmod +x "$(INSTALLED)"; \
	echo "==> starting daemon"; \
	"$(INSTALLED)" start -d; \
	sleep 3; \
	echo "==> verifying"; \
	if ! "$(INSTALLED)" status >/dev/null 2>&1; then \
		echo "FAILED: daemon does not answer status. Rolling back."; \
		latest=$$(ls -t /tmp/wicket-rollback-* 2>/dev/null | head -1); \
		if [ -n "$$latest" ]; then \
			"$(INSTALLED)" stop 2>/dev/null || true; \
			cp "$$latest" "$(INSTALLED)"; "$(INSTALLED)" start -d; \
			echo "rolled back to $$latest"; \
		fi; \
		exit 1; \
	fi; \
	if ! "$(INSTALLED)" get $(VERIFY_SCOPE) >/dev/null 2>&1; then \
		echo "FAILED: daemon answers but cannot mint ($(VERIFY_SCOPE)). Rolling back."; \
		latest=$$(ls -t /tmp/wicket-rollback-* 2>/dev/null | head -1); \
		if [ -n "$$latest" ]; then \
			"$(INSTALLED)" stop 2>/dev/null || true; \
			cp "$$latest" "$(INSTALLED)"; "$(INSTALLED)" start -d; \
			echo "rolled back to $$latest"; \
		fi; \
		exit 1; \
	fi; \
	echo "OK: installed, daemon healthy, credential path verified"

# Is the running binary built from current HEAD? Compares the installed binary
# against a fresh build of the working tree.
check-deployed: build
	@installed_hash=$$(shasum -a 256 "$(INSTALLED)" 2>/dev/null | cut -d' ' -f1); \
	fresh_hash=$$(shasum -a 256 "$(BUILD_OUT)" | cut -d' ' -f1); \
	echo "installed: $${installed_hash:-<none>}"; \
	echo "fresh    : $$fresh_hash"; \
	if [ "$$installed_hash" = "$$fresh_hash" ]; then \
		echo "MATCH — the running binary is current"; \
	else \
		echo "DRIFT — the installed binary differs from a build of this tree."; \
		echo "        Run 'make install'. (A four-month drift went unnoticed once.)"; \
		exit 1; \
	fi

restart:
	@$(BINARY) stop 2>/dev/null || true; $(BINARY) start -d; sleep 2; $(BINARY) status
