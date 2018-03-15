# MAKEFILE
#
# @author      Nicola Asuni <nicola.asuni@miracl.com>
# @link        https://github.com/miracl/go-xmlsec
# ------------------------------------------------------------------------------

# List special make targets that are not associated with files
.PHONY: help all test format fmtcheck vet lint coverage cyclo ineffassign misspell astscan qa deps clean nuke buildall dbuild

# Use bash as shell (Note: Ubuntu now uses dash which doesn't support PIPESTATUS).
SHELL=/bin/bash

# CVS path (path to the parent dir containing the project)
CVSPATH=github.com/miracl/go-xmlsec

# Project vendor
VENDOR=miracl

# Project name
PROJECT=go-xmlsec

# Project version
VERSION=$(shell cat VERSION)

# Project release number (packaging build number)
RELEASE=$(shell cat RELEASE)

# Current directory
CURRENTDIR=$(shell pwd)

# GO lang path
ifneq ($(GOPATH),)
	ifeq ($(findstring $(GOPATH),$(CURRENTDIR)),)
		# the defined GOPATH is not valid
		GOPATH=
	endif
endif
ifeq ($(GOPATH),)
	# extract the GOPATH
	GOPATH=$(firstword $(subst /src/, ,$(CURRENTDIR)))
endif

# Add the GO binary dir in the PATH
export PATH := $(GOPATH)/bin:$(PATH)

GOENV=GOPATH=$(GOPATH) CGO_CFLAGS_ALLOW='-w'

# --- MAKE TARGETS ---

# Display general help about this command
help:
	@echo ""
	@echo "$(PROJECT) Makefile."
	@echo "GOPATH=$(GOPATH)"
	@echo "The following commands are available:"
	@echo ""
	@echo "    make qa          : Run all the tests and static analysis reports"
	@echo "    make test        : Run the unit tests"
	@echo ""
	@echo "    make format      : Format the source code"
	@echo "    make fmtcheck    : Check if the source code has been formatted"
	@echo "    make vet         : Check for suspicious constructs"
	@echo "    make lint        : Check for style errors"
	@echo "    make coverage    : Generate the coverage report"
	@echo "    make cyclo       : Generate the cyclomatic complexity report"
	@echo "    make ineffassign : Detect ineffectual assignments"
	@echo "    make misspell    : Detect commonly misspelled words in source files"
	@echo "    make astscan     : GO AST scanner"
	@echo ""
	@echo "    make docs        : Generate source code documentation"
	@echo ""
	@echo "    make deps        : Get the dependencies"
	@echo "    make clean       : Remove any build artifact"
	@echo "    make nuke        : Deletes any intermediate file"
	@echo ""
	@echo "    make buildall    : Full build and test sequence"
	@echo "    make dbuild      : Build everything inside a Docker container"
	@echo ""

# Alias for help target
all: help

# Run the unit tests
test:
	@mkdir -p target/test
	$(GOENV) go test -covermode=atomic -bench=. -race -v . | \
	tee >($(GOENV) go-junit-report > target/test/report.xml); \
	test $${PIPESTATUS[0]} -eq 0

# Format the source code
format:
	@find . -type f -name "*.go" -exec gofmt -s -w {} \;

# Check if the source code has been formatted
fmtcheck:
	@mkdir -p target
	@find . -type f -name "*.go" -exec gofmt -s -d {} \; | tee target/format.diff
	@test ! -s target/format.diff || { echo "ERROR: the source code has not been formatted - please use 'make format' or 'gofmt'"; exit 1; }

# Check for syntax errors
vet:
	$(GOENV) go vet .

# Check for style errors
lint:
	$(GOENV) golint .

# Generate the coverage report
coverage:
	@mkdir -p target/report
	$(GOENV) go test -covermode=count -coverprofile=target/report/coverage.out -v . && \
	$(GOENV) go tool cover -html=target/report/coverage.out -o target/report/coverage.html

# Report cyclomatic complexity
cyclo:
	@mkdir -p target/report
	$(GOENV) gocyclo -avg . | tee target/report/cyclo.txt ; test $${PIPESTATUS[0]} -eq 0

# Detect ineffectual assignments
ineffassign:
	@mkdir -p target/report
	$(GOENV) ineffassign . | tee target/report/ineffassign.txt ; test $${PIPESTATUS[0]} -eq 0

# Detect commonly misspelled words in source files
misspell:
	@mkdir -p target/report
	$(GOENV) misspell -error .  | tee target/report/misspell.txt ; test $${PIPESTATUS[0]} -eq 0

# AST scanner
astscan:
	@mkdir -p target/report
	$(GOENV) gas ./... | tee target/report/astscan.txt ; test $${PIPESTATUS[0]} -eq 0

# Generate source docs
docs:
	@mkdir -p target/docs
	nohup sh -c '$(GOENV) godoc -http=127.0.0.1:6060' > target/godoc_server.log 2>&1 &
	wget --directory-prefix=target/docs/ --execute robots=off --retry-connrefused --recursive --no-parent --adjust-extension --page-requisites --convert-links http://127.0.0.1:6060/pkg/github.com/${VENDOR}/${PROJECT}/ ; kill -9 `lsof -ti :6060`
	@echo '<html><head><meta http-equiv="refresh" content="0;./127.0.0.1:6060/pkg/'${CVSPATH}'/'${PROJECT}'/index.html"/></head><a href="./127.0.0.1:6060/pkg/'${CVSPATH}'/'${PROJECT}'/index.html">'${PKGNAME}' Documentation ...</a></html>' > target/docs/index.html

# Alias to run targets: fmtcheck test vet lint coverage
qa: fmtcheck test vet lint coverage cyclo ineffassign misspell astscan

# --- INSTALL ---

# Get the dependencies
deps:
	$(GOENV) go get $(go list ./... | grep -v /vendor/)
	$(GOENV) go get github.com/inconshreveable/mousetrap
	$(GOENV) go get github.com/golang/lint/golint
	$(GOENV) go get github.com/jstemmer/go-junit-report
	$(GOENV) go get github.com/axw/gocov/gocov
	$(GOENV) go get github.com/fzipp/gocyclo
	$(GOENV) go get github.com/gordonklaus/ineffassign
	$(GOENV) go get github.com/client9/misspell/cmd/misspell
	$(GOENV) go get github.com/HewlettPackard/gas/cmd/gas
	$(GOENV) go get gopkg.in/check.v1

# Remove any build artifact
clean:
	$(GOENV) go clean ./...

# Deletes any intermediate file
nuke:
	rm -rf ./target
	$(GOENV) go clean -i ./...

# Full build and test sequence
buildall: deps qa

# Build everything inside a Docker container
dbuild:
	@mkdir -p target
	@rm -rf target/*
	@echo 0 > target/make.exit
	CVSPATH=$(CVSPATH) VENDOR=$(VENDOR) PROJECT=$(PROJECT) MAKETARGET='$(MAKETARGET)' ./dockerbuild.sh
	@exit `cat target/make.exit`
