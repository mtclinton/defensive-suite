TOOLS := authwatch instguard credsentinel egresswatch posturescan bpfsentry

.PHONY: all build test lint tidy clean

all: build

build:
	@for t in $(TOOLS); do \
		if [ -f $$t/go.mod ]; then echo ">> building $$t"; (cd $$t && go build ./...); fi; \
	done

test:
	@for t in $(TOOLS); do \
		if [ -f $$t/go.mod ]; then echo ">> testing $$t"; (cd $$t && go test ./...); fi; \
	done

lint:
	@for t in $(TOOLS); do \
		if [ -f $$t/go.mod ]; then echo ">> vetting $$t"; (cd $$t && go vet ./...); fi; \
	done

tidy:
	@for t in $(TOOLS); do \
		if [ -f $$t/go.mod ]; then (cd $$t && go mod tidy); fi; \
	done

clean:
	@rm -rf */bin */dist