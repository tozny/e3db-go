#! /bin/sh

set -e
set -x

suffix=""
if [[ -n "$VER" ]]; then
    suffix="-$VER"
fi

rm -rf build
mkdir -p build

export XDG_CACHE_HOME="/tmp/.cache"
CGO_ENABLED=0 go build

for os in darwin linux windows; do
  for arch in 386 amd64; do
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build ./cmd/e3db
    case $os in
        windows)
            mv e3db.exe build/e3db-$os-$arch$suffix.exe
            ;;
        *)
            mv e3db build/e3db-$os-$arch$suffix
            ;;
    esac
  done
done
