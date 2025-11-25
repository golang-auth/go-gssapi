ifeq ($(.CURDIR),)
	current_dir  = $(shell /bin/pwd)
else
	current_dir  = $(.CURDIR)
endif

GO          ?= go
GOOS 		?= $(shell $(GO) env GOOS)
GOARCH 		?= $(shell $(GO) env GOARCH)
TOOLBIN 	 = $(current_dir)/toolbin/$(GOOS)_$(GOARCH)

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

PKGS = $(shell $(GO) list ./... | egrep -v '/examples/|/build-tools/')

.PHONY: test
test: $(TOOLBIN)/gocovmerge $(TOOLBIN)/go-test-coverage
	@echo "==> check code formatting"
	@./scripts/gofmt
	@echo "==> run tests for " $(PKGS)
	@${GO} test $(PKGS) -coverprofile=cover.out -covermode=atomic
	@echo "==> run tests for http/test"
	@cd http/test && ${GO} test -coverpkg ../ -coverprofile=cover.out -covermode=atomic
	@echo "==> procesisng coverage data"
	@$(TOOLBIN)/gocovmerge ./cover.out ./http/test/cover.out > cover-all.out
	@go tool cover -html=cover-all.out -o coverage.html
	@$(TOOLBIN)/go-test-coverage --config .testcoverage.yml

.PHONY: lint
lint: | $(TOOLBIN)/golangci-lint
	$(TOOLBIN)/golangci-lint run 

.PHONY: tools
tools: $(TOOLBIN)/golangci-lint $(TOOLBIN)/gocovmerge $(TOOLBIN)/go-test-coverage
	@echo "==> installing required tooling..."

$(TOOLBIN)/golangci-lint:
	GOBIN=$(TOOLBIN) GO111MODULE=on $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2

$(TOOLBIN)/gocovmerge:
	GOBIN=$(TOOLBIN) GO111MODULE=on $(GO) install github.com/wadey/gocovmerge@latest

$(TOOLBIN)/go-test-coverage:
	GOBIN=$(TOOLBIN) GO111MODULE=on $(GO) install github.com/vladopajic/go-test-coverage/v2@latest

