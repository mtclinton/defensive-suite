# defensive-suite — top-level Makefile.
#
# `build` / `release-local` compile all 8 Go modules as static, version-injected
# binaries. `install` runs the shipped ./install.sh. Per-module Makefiles still
# work (cd <module> && make ...). Everything is stdlib-only.

# Version injected into every binary (main.version). A tag → that tag; otherwise
# a describe string; otherwise "dev". Override with `make VERSION=v1.2.3 build`.
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# The six detector tools (kept for parity with the original target list).
TOOLS := authwatch instguard credsentinel egresswatch posturescan bpfsentry

# All 8 Go modules, as "module:binary:build_pkg". bpfsentry builds from
# ./cmd/bpfsentry; agent's binary is agentd; the rest build their root package.
MODULES := \
	authwatch:authwatch:. \
	credsentinel:credsentinel:. \
	instguard:instguard:. \
	posturescan:posturescan:. \
	egresswatch:egresswatch:. \
	bpfsentry:bpfsentry:./cmd/bpfsentry \
	collector:collector:. \
	agent:agentd:.

# Static-binary build flags shared with install.sh and the release workflow.
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath
export CGO_ENABLED := 0

BINDIR  := bin
DISTDIR := dist
RELEASE_ARCHES := amd64 arm64

.PHONY: all build install release-local clean test lint tidy version

all: build

## build — compile all 8 modules (static, version-injected) into ./bin
build:
	@mkdir -p $(BINDIR)
	@echo ">> building all modules @ version $(VERSION)"
	@for spec in $(MODULES); do \
		mod=$${spec%%:*}; rest=$${spec#*:}; bin=$${rest%%:*}; pkg=$${rest#*:}; \
		echo ">> $$mod -> $$bin"; \
		( cd $$mod && go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ../$(BINDIR)/$$bin $$pkg ) || exit 1; \
	done
	@ls -l $(BINDIR)

## install — run the shipped installer (detection/observe tier). Pass FLAGS=...
## e.g.  make install FLAGS="--destdir /tmp/x"   or   sudo make install
install:
	@./install.sh --version $(VERSION) $(FLAGS)

## release-local — build the per-arch tarballs (amd64 + arm64) locally with
## SHA256SUMS, mirroring the CI release (no AppImage — that needs the Tauri
## toolchain; CI builds it). Output in ./dist.
release-local:
	@rm -rf $(DISTDIR); mkdir -p $(DISTDIR)
	@for arch in $(RELEASE_ARCHES); do \
		stage="defensive-suite-$(VERSION)-linux-$$arch"; \
		echo ">> assembling $$stage"; \
		rm -rf "$(DISTDIR)/$$stage"; mkdir -p "$(DISTDIR)/$$stage/bin"; \
		for spec in $(MODULES); do \
			mod=$${spec%%:*}; rest=$${spec#*:}; bin=$${rest%%:*}; pkg=$${rest#*:}; \
			( cd $$mod && GOOS=linux GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
				-o "../$(DISTDIR)/$$stage/bin/$$bin" $$pkg ) || exit 1; \
		done; \
		for spec in $(MODULES); do mod=$${spec%%:*}; \
			if [ -d "$$mod/deploy" ]; then mkdir -p "$(DISTDIR)/$$stage/$$mod"; cp -R "$$mod/deploy" "$(DISTDIR)/$$stage/$$mod/"; fi; \
		done; \
		cp install.sh "$(DISTDIR)/$$stage/"; chmod +x "$(DISTDIR)/$$stage/install.sh"; \
		cp -R dashboard "$(DISTDIR)/$$stage/"; \
		[ -f README.md ] && cp README.md "$(DISTDIR)/$$stage/" || true; \
		[ -d docs ] && cp -R docs "$(DISTDIR)/$$stage/" || true; \
		tar -czf "$(DISTDIR)/$$stage.tar.gz" -C "$(DISTDIR)" "$$stage"; \
		rm -rf "$(DISTDIR)/$$stage"; \
	done
	@( cd $(DISTDIR) && sha256sum *.tar.gz > SHA256SUMS )
	@echo ">> release tarballs:"; ls -l $(DISTDIR)

## version — print the version that would be injected
version:
	@echo $(VERSION)

## test — go test every module
test:
	@for spec in $(MODULES); do mod=$${spec%%:*}; \
		echo ">> testing $$mod"; ( cd $$mod && go test ./... ) || exit 1; \
	done

## lint — go vet every module
lint:
	@for spec in $(MODULES); do mod=$${spec%%:*}; \
		echo ">> vetting $$mod"; ( cd $$mod && go vet ./... ) || exit 1; \
	done

## tidy — go mod tidy every module
tidy:
	@for spec in $(MODULES); do mod=$${spec%%:*}; \
		( cd $$mod && go mod tidy ); \
	done

## clean — remove build + dist output (top-level and per-module)
clean:
	@rm -rf $(BINDIR) $(DISTDIR) */bin */dist
