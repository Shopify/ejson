NAME=ejson
RUBY_MODULE=EJSON
PACKAGE=github.com/Shopify/ejson
VERSION=$(shell cat VERSION)
GEM=pkg/$(NAME)-$(VERSION).gem
AMD64_DEB=dist/ejson_$(VERSION)_linux_amd64.deb
AMD64_DEB=dist/ejson_$(VERSION)_linux_arm64.deb

GOFILES=$(shell find . -type f -name '*.go')

BUNDLE_EXEC=bundle exec
SHELL=/usr/bin/env bash

.PHONY: default all binaries gem clean dev_bootstrap

default: all
all: gem deb
binaries: \
	dist/ejson_linux_amd64_v1/ejson \
	dist/ejson_linux_arm64_v8.0/ejson \
	dist/ejson_darwin_amd64_v1/ejson \
	dist/ejson_darwin_arm64_v8.0/ejson \
	dist/ejson_freebsd_amd64_v1/ejson \
	dist/ejson_windows_arm64_v8.0/ejson.exe
gem: $(GEM)
deb: $(AMD64_DEB) $(ARM64_DEB)

dist/ejson_linux_amd64_v1/ejson: $(GOFILES)
	goreleaser build --clean
dist/ejson_linux_arm64_v8.0/ejson: $(GOFILES)
	goreleaser build --clean
dist/ejson_darwin_amd64_v1/ejson: $(GOFILES)
	goreleaser build --clean
dist/ejson_darwin_arm64_v8.0/ejson: $(GOFILES)
	goreleaser build --clean
dist/ejson_freebsd_amd64_v1/ejson: $(GOFILES)
	goreleaser build --clean
dist/ejson_windows_arm64_v8.0/ejson.exe: $(GOFILES)
	goreleaser build --clean

$(GEM): rubygem/$(NAME)-$(VERSION).gem
	mkdir -p $(@D)
	mv "$<" "$@"

rubygem/$(NAME)-$(VERSION).gem: \
	rubygem/lib/$(NAME)/version.rb \
	rubygem/build/linux-amd64/ejson \
	rubygem/build/linux-arm64/ejson \
	rubygem/LICENSE.txt \
	rubygem/build/darwin-amd64/ejson \
	rubygem/build/darwin-arm64/ejson \
	rubygem/build/freebsd-amd64/ejson \
	rubygem/build/windows-amd64/ejson.exe
	cd rubygem && gem build ejson.gemspec

rubygem/LICENSE.txt: LICENSE.txt
	cp "$<" "$@"

rubygem/build/darwin-amd64/ejson: dist/ejson_darwin_amd64_v1/ejson
	mkdir -p $(@D)
	cp -a "$<" "$@"

rubygem/build/darwin-arm64/ejson: dist/ejson_darwin_arm64_v8.0/ejson
	mkdir -p $(@D)
	cp -a "$<" "$@"

rubygem/build/freebsd-amd64/ejson: dist/ejson_freebsd_amd64_v1/ejson
	mkdir -p $(@D)
	cp -a "$<" "$@"

rubygem/build/linux-amd64/ejson: dist/ejson_linux_amd64_v1/ejson
	mkdir -p $(@D)
	cp -a "$<" "$@"

rubygem/build/linux-arm64/ejson: dist/ejson_linux_arm64_v8.0/ejson
	mkdir -p $(@D)
	cp -a "$<" "$@"

rubygem/build/windows-amd64/ejson.exe: dist/ejson_windows_amd64_v1/ejson.exe
	mkdir -p $(@D)
	cp -a "$<" "$@"

rubygem/lib/$(NAME)/version.rb: VERSION
	mkdir -p $(@D)
	printf '%b' 'module $(RUBY_MODULE)\n  VERSION = "$(VERSION)"\nend\n' > $@

$(AMD64_DEB): dist/ejson_linux_amd64_v1/ejson
	goreleaser release --clean --skip publish

$(ARM64_DEB): dist/ejson_linux_arm64_v8.0/ejson
	goreleaser release --clean --skip publish

clean:
	rm -rf build dist pkg rubygem/{LICENSE.txt,lib/ejson/version.rb,build,*.gem}
