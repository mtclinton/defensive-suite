BINARY  := agentd
LDFLAGS := -s -w

.PHONY: all build static release test vet tidy clean run install

all: build

build:
	go build -o bin/$(BINARY) .

# Single static binary (no cgo).
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

# Evaluate a recorded Tetragon event file (no Tetragon needed) — handy for dev.
run: build
	./bin/$(BINARY) scan -file events.jsonl -no-post

install: static
	install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)
