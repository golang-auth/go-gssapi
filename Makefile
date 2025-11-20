current_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
GO          ?= go
GOBIN       ?= $(shell go env GOBIN)
TOOLBIN     := $(current_dir)/toolbin


ifeq (${GOBIN},)
	GOBIN = $(shell go env GOPATH)/bin
endif


.DEFAULT: build

.PHONY: build
build: generate
	./scripts/gofmt

.PHONY: generate
generate: names_gen.go mechs_gen.go mech_attrs_gen.go http/test/testvecs_gen_test.go

names_gen.go: build-tools/gen-gss-name-oids/gen-gss-name-oids.go names.go
	$(GO) generate names.go

mechs_gen.go: build-tools/gen-gss-mech-oids/gen-gss-mech-oids.go mechs.go
	$(GO) generate mechs.go

mech_attrs_gen.go: build-tools/gen-gss-mech-attrs/gen-gss-mech-attrs.go mech_attrs.go
	$(GO) generate mech_attrs.go

http/test/testvecs_gen_test.go: build-tools/mk-test-vectors http/test/common_test.go
	$(GO) generate http/test/common_test.go


.PHONY: test
test:
	./scripts/gofmt
	${GO} test -coverprofile=./cover.out -covermode=atomic
	cd http/test && ../../scripts/gofmt
	cd http/test && ${GO} test

.PHONY: lint
lint: | $(TOOLBIN)/golangci-lint
	$(TOOLBIN)/golangci-lint run 

.PHONY: tools
tools: $(TOOLBIN)/golangci-lint
	@echo "==> installing required tooling..."

$(TOOLBIN)/golangci-lint: | $(GOENV)
	GOBIN=$(TOOLBIN) GO111MODULE=on $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@v1
