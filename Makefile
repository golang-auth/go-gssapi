current_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
src_dir = v3
GO          ?= go
GOBIN ?= $(shell go env GOBIN)
TOOLBIN := $(current_dir)/toolbin


ifeq (${GOBIN},)
	GOBIN = $(shell go env GOPATH)/bin
endif


.DEFAULT: build

.PHONY: build
build: generate
	./scripts/gofmt

.PHONY: generate
generate: $(src_dir)/names_gen.go $(src_dir)/mechs_gen.go

$(src_dir)/names_gen.go: build-tools/gen-gss-name-oids.go $(src_dir)/names.go
	$(GO) generate $(src_dir)/names.go

$(src_dir)/mechs_gen.go: build-tools/gen-gss-mech-oids.go $(src_dir)/mechs.go
	$(GO) generate $(src_dir)/mechs.go


.PHONY: test
test:
	cd $(src_dir) && ../scripts/gofmt
	cd $(src_dir) && ${GO} test ./... -coverprofile=./cover.out -covermode=atomic


.PHONY: lint
lint: | $(TOOLBIN)/golangci-lint
	cd $(src_dir) && $(TOOLBIN)/golangci-lint run 

.PHONY: tools
tools: $(TOOLBIN)/golangci-lint
	@echo "==> installing required tooling..."

$(TOOLBIN)/golangci-lint: | $(GOENV)
	GOBIN=$(TOOLBIN) GO111MODULE=on $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@v1
