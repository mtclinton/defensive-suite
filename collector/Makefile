BINARY  := collector
LDFLAGS := -s -w

.PHONY: all build static release test vet tidy clean run install

all: build

build:
	go build -o bin/$(BINARY) .

# Single static binary (no cgo) — the deployable artifact. Embeds the dashboard.
static:
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY) .

release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-linux-arm64 .

test:
	go test ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf bin

# Run locally with a throwaway token + data dir.
run: build
	COLLECTOR_TOKEN=$${COLLECTOR_TOKEN:-dev-token} ./bin/$(BINARY) --addr 127.0.0.1:8787 --data ./data

install: static
	install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)
