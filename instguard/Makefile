BINARY  := instguard
PKG     := .
LDFLAGS := -s -w

.PHONY: all build static release test vet tidy fmt clean install

all: build

build:
	go build -o bin/$(BINARY) $(PKG)

# Single static binary (no cgo) — the deployable artifact.
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
	gofmt -w .

tidy:
	go mod tidy

clean:
	rm -rf bin

install: static
	install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)
