# Global makefile variables
BINARY=e3db
# For backwards compatibility / lack of surprise for using this library in >= go 1.11 but before 1.14
export GO111MODULE=on

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

# target for tagging and publishing a new version of the SDK
# run like make version=X.Y.Z
version:
	git tag v${version}
	git push origin v${version}
