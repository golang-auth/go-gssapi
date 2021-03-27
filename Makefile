current_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

GOPATH          ?= $(shell go env GOPATH)

GOBIN ?= $(shell go env GOBIN)

ifeq (${GOBIN},)
	GOBIN = $(shell go env GOPATH)/bin
endif


.DEFAULT: build

.PHONY: build
build: fmtcheck
	go install

.PHONY: fmtcheck
fmtcheck:
	@"$(CURDIR)/scripts/gofmtcheck.sh"

.PHONY: lint
lint:
	$(GOBIN)/golangci-lint run ./...

.PHONY: tools
tools:
	@echo "==> installing required tooling..."
	GO111MODULE=off go get -u github.com/client9/misspell/cmd/misspell
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin v1.31.0


