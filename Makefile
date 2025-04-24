# Makefile for ipdex
APP_NAME             := ipdex
CMD_DIR              := ./cmd/$(APP_NAME)
DIST_DIR             := ./dist

GORELEASER_VERBOSE       ?= false
GORELEASER_IMAGE         := ghcr.io/goreleaser/goreleaser-cross:v1.21.5
GORELEASER_CONFIG     ?= .goreleaser.yaml

GOOS_LIST            := linux darwin windows
GOARCH_LIST          := amd64 arm64
CGO_ENABLED          := 1

GIT_COMMIT           := $(shell git rev-parse --short HEAD)
GIT_COMMIT_LONG      := $(shell git rev-parse HEAD)
GIT_TAG              := $(shell git describe --tags --always)

GO_LINKMODE          ?= external
GO_MOD               ?= readonly
BUILD_TAGS           ?= osusergo,netgo
GO_LDFLAGS           := -linkmode=$(GO_LINKMODE) \
                       -X crowdsecurity/ipdex/pkg/version.Version=$(GIT_TAG) \
                       -X crowdsecurity/ipdex/pkg/version.Version.Commit=$(GIT_COMMIT_LONG) \
                       -X crowdsecurity/ipdex/pkg/version.Version.BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

GO_BUILD_FLAGS       := -mod=$(GO_MOD) -tags='$(BUILD_TAGS)' -ldflags '$(GO_LDFLAGS)'

.DEFAULT_GOAL := build

.PHONY: all build test clean release

all: clean build

build:
	go build $(GO_BUILD_FLAGS) -o ipdex ./cmd/ipdex

test:
	go test -v ./...

clean:
	rm -rf $(DIST_DIR)

release:
	@echo "Releasing with GoReleaser..."
	docker run \
		--rm \
		-e MOD="$(GO_MOD)" \
		-e BUILD_TAGS="$(BUILD_TAGS)" \
		-e LINKMODE="$(GO_LINKMODE)" \
		-e GITHUB_TOKEN="$(GITHUB_TOKEN)" \
		-e GORELEASER_CURRENT_TAG="$(RELEASE_TAG)" \
		-e GOPATH=/go \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(GOPATH):/go \
		-v $(PWD):/go/src/$(GO_MOD_NAME) \
		-w /go/src/$(GO_MOD_NAME) \
		$(GORELEASER_IMAGE) \
		-f "$(GORELEASER_CONFIG)" \
		release \
		--verbose=$(GORELEASER_VERBOSE) \
		--clean \
