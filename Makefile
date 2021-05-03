# Global makefile variables
BINARY=e3db
# For backwards compatibility / lack of surprise for using this library in >= go 1.11 but before 1.14
export GO111MODULE=on
# Import environment file
include .env
# Source all variables in environment file
# This only runs in the make command shell
# so won't muddy up, e.g. your login shell
export $(shell sed 's/=.*//' .env)

# Default target executed when user runs `make`
default:
	lint build

all: lint build

# lint target that lints ,compile checks, lints the source code and dependency list
lint:
	go vet ./...
	go mod tidy

# Target for building a cli binary complied for the current platform
build:
	go build -o ${BINARY} ./cmd/${BINARY}

# Target for building and moving the binary to the local system execution path
install:
	go install ./cmd/${BINARY}

test : lint
	go test -count=1 -v -cover --race ./...

testone: lint
	TEST_SERVICE_API=$(serviceApi) TEST_LOGFILE=$(log) LOG_QUERIES=$(qlog) PARATEST=$(paratest) go test -v -race -count=1 ./... -run "^($(method))$$"

# target for tagging and publishing a new version of the SDK
# run like make version=X.Y.Z
version:
	git tag v${version}
	git push origin v${version}
