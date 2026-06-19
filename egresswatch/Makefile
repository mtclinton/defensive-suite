BINARY  := egresswatch
PKG     := .
LDFLAGS := -s -w

.PHONY: all build static release test vet fmt tidy clean install generate-ebpf build-ebpf

all: build

build:
	go build -o bin/$(BINARY) $(PKG)

# Single static binary (no cgo) — the deployable artifact. Default build is
# stdlib-only: no external requires, no clang, builds and passes offline.
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

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

clean:
	rm -rf bin

install: static
	install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)

# --- eBPF sensor (opt-in; NOT part of the default build) ---
# These targets need clang, libbpf headers, a BTF kernel, and pull in
# github.com/cilium/ebpf. They are shown for operators building the sensor; the
# default `make`/`make static`/`make test` never invoke them. See deploy/README.md.

# Generate the bpf2go bindings from bpf/magicpacket.bpf.c (requires bpf/vmlinux.h).
generate-ebpf:
	go generate ./bpf/...

# Build the eBPF-enabled binary (after generate-ebpf).
build-ebpf:
	CGO_ENABLED=0 go build -tags ebpf -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-ebpf $(PKG)
