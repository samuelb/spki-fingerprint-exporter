# Plain version without the tag's v prefix, matching the image and chart
# versions (v0.7.2 -> 0.7.2).
VERSION     ?= $(patsubst v%,%,$(shell git describe --tags --always --dirty))
BINARY_DIR  ?= dist
BINARY_NAME ?= spki-fingerprint-exporter
PLATFORMS   ?= linux/386 linux/amd64 linux/arm64 linux/mips linux/mipsle linux/mips64 linux/mips64le linux/ppc64 linux/ppc64le linux/riscv64 linux/s390x netbsd/386 netbsd/amd64 openbsd/amd64 windows/amd64 darwin/amd64 darwin/arm64

GO         ?= go
GOOPTS     ?=
GOHOSTOS   ?= $(shell $(GO) env GOHOSTOS)
GOHOSTARCH ?= $(shell $(GO) env GOHOSTARCH)
# Go release line for the build image, taken from go.mod (1.26.0 -> 1.26).
GO_VERSION ?= $(shell sed -n 's/^go \([0-9]*\.[0-9]*\).*/\1/p' go.mod)

DOCKER            ?= docker
DOCKER_REPO       ?= basa
DOCKER_IMAGE_NAME ?= spki-fingerprint-exporter
SHA256SUM         ?= $(if $(shell command -v sha256sum 2>/dev/null),sha256sum,shasum -a 256)

# The host platform is always buildable, even when it is not a release
# platform.
HOST_PLATFORM := $(GOHOSTOS)/$(GOHOSTARCH)
ALL_PLATFORMS := $(sort $(PLATFORMS) $(HOST_PLATFORM))

# Windows binaries carry an .exe suffix.
artifact   = $(BINARY_DIR)/$(BINARY_NAME)-$(subst /,-,$(1))$(if $(filter windows/%,$(1)),.exe)
ARTIFACTS := $(foreach platform,$(PLATFORMS),$(call artifact,$(platform)))

# Same flags as the Dockerfile: reproducible paths, no debug symbols.
BUILDFLAGS := -trimpath -ldflags "-s -w -X main.Version=$(VERSION)"

_OS   = $(word 1, $(subst /, ,$@))
_ARCH = $(word 2, $(subst /, ,$@))

.PHONY: all build test clean build-all checksums docker release version $(ALL_PLATFORMS)

all: build

build: $(HOST_PLATFORM)

build-all: $(PLATFORMS)

test:
	$(GO) vet $(GOOPTS) ./...
	$(GO) test $(GOOPTS) -race ./...

$(ALL_PLATFORMS):
	CGO_ENABLED=0 GOOS=$(_OS) GOARCH=$(_ARCH) $(GO) build $(GOOPTS) $(BUILDFLAGS) \
		 -o $(call artifact,$@)

docker:
	$(DOCKER) build \
		--build-arg VERSION=$(VERSION) \
		--build-arg GO_VERSION=$(GO_VERSION) \
		-t $(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(VERSION) .

checksums: build-all
	$(SHA256SUM) $(ARTIFACTS) | sed "s|$(BINARY_DIR)/||" > $(BINARY_DIR)/sha256sums.txt

release: test checksums

clean:
	$(GO) clean
	rm -rf $(BINARY_DIR)

version:
	@echo $(VERSION)
