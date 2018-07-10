NAME=ejson
RUBY_MODULE=EJSON
PACKAGE=github.com/Shopify/ejson
VERSION=$(shell cat VERSION)
GEM=pkg/$(NAME)-$(VERSION).gem
DEB=pkg/$(NAME)_$(VERSION)_amd64.deb

GOFILES=$(shell find . -type f -name '*.go')
MANFILES=$(shell find man -name '*.ronn' -exec echo build/{} \; | sed 's/\.ronn/\.gz/')

GODEP_PATH=$(shell pwd)/Godeps/_workspace

BUNDLE_EXEC=bundle exec

.PHONY: default all binaries gem man clean dev_bootstrap

default: all
all: gem deb
binaries: build/bin/linux-amd64 build/bin/darwin-amd64
gem: $(GEM)
deb: $(DEB)
man: $(MANFILES)

build/man/%.gz: man/%.ronn
	mkdir -p "$(@D)"
	set -euo pipefail ; $(BUNDLE_EXEC) ronn -r --pipe "$<" | gzip > "$@"

build/bin/linux-amd64/%: $(GOFILES) cmd/%/version.go
	mkdir -p $(@D)
	GOPATH=$(GODEP_PATH):$$GOPATH GOOS=linux GOARCH=amd64 go build -o "$@" "$(PACKAGE)/cmd/$(@F)"

build/bin/darwin-amd64/%: $(GOFILES) cmd/%/version.go
	GOPATH=$(GODEP_PATH):$$GOPATH GOOS=darwin GOARCH=amd64 go build -o "$@" "$(PACKAGE)/cmd/$(@F)"

$(GEM): rubygem/$(NAME)-$(VERSION).gem
	mkdir -p $(@D)
	mv "$<" "$@"
	
rubygem/$(NAME)-$(VERSION).gem: \
	rubygem/lib/$(NAME)/version.rb \
	rubygem/build/linux-amd64/ejson \
	rubygem/build/linux-amd64/ejson2env \
	rubygem/LICENSE.txt \
	rubygem/build/darwin-amd64/ejson \
	rubygem/build/darwin-amd64/ejson2env \
	rubygem/man
	cd rubygem && gem build ejson.gemspec

rubygem/LICENSE.txt: LICENSE.txt
	cp "$<" "$@"

rubygem/man: man
	cp -a build/man $@

rubygem/build/darwin-amd64/%: build/bin/darwin-amd64/%
	mkdir -p $(@D)
	cp -a "$<" "$@"

rubygem/build/linux-amd64/%: build/bin/linux-amd64/%
	mkdir -p $(@D)
	cp -a "$<" "$@"

cmd/$(NAME)/version.go: VERSION
	echo 'package main\n\nconst VERSION string = "$(VERSION)"' > $@

rubygem/lib/$(NAME)/version.rb: VERSION
	mkdir -p $(@D)
	echo 'module $(RUBY_MODULE)\n  VERSION = "$(VERSION)"\nend' > $@

$(DEB): build/bin/linux-amd64/ejson build/bin/linux-amd64/ejson2env man
	mkdir -p $(@D)
	rm -f "$@"
	$(BUNDLE_EXEC) fpm \
		-t deb \
		-s dir \
		--name="$(NAME)" \
		--version="$(VERSION)" \
		--package="$@" \
		--license=MIT \
		--category=admin \
		--no-depends \
		--no-auto-depends \
		--architecture=amd64 \
		--maintainer="Burke Libbey <burke.libbey@shopify.com>" \
		--description="utility for managing a collection of secrets in source control. Secrets are encrypted using public key, elliptic curve cryptography." \
		--url="https://github.com/Shopify/ejson" \
		./build/man/=/usr/share/man/ \
		./build/bin/linux-amd64/ejson=/usr/bin/ejson \
		./build/bin/linux-amd64/ejson2env=/usr/bin/ejson2env

clean:
	rm -rf build pkg rubygem/{LICENSE.txt,lib/ejson/version.rb,build,*.gem}
