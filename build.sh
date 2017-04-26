#! /bin/sh

set -e
set -x

mkdir -p build

glide install
for os in darwin linux windows; do
  for arch in 386 amd64; do
    GOOS=$os GOARCH=$arch go build -v -o build/e3db-$os-$arch ./cmd/e3db
  done
done
