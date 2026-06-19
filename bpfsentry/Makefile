BINARY  := bpfsentry
PKG     := ./cmd/bpfsentry
LDFLAGS := -s -w

.PHONY: all build static release test vet tidy clean install ebpf-build py-check

all: build

build:
	go build -o bin/$(BINARY) $(PKG)

# Single static binary (no cgo) — the deployable artifact. Default build is
# stdlib-only, so this is fully static and builds offline.
static:
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY) $(PKG)

# Cross-compiled release binaries for Linux targets.
release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-linux-arm64 $(PKG)

test:
	go test ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf bin

install: static
	install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)

# Build the cilium/ebpf direct-enumeration path. This is a Linux-only ARTIFACT
# behind `//go:build linux && ebpf`, excluded from the default build. It pulls in
# the only external dependency, which you add explicitly:
#   go get github.com/cilium/ebpf@latest
ebpf-build:
	CGO_ENABLED=0 GOOS=linux go build -tags ebpf $(PKG)

# Validate the out-of-band forensics Python (syntax only; runs nothing privileged).
py-check:
	python3 -m py_compile forensics/*.py
