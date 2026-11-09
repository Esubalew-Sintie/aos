#!/usr/bin/env bash
# Builds the engine for every supported platform into dist/:
#   aos_<version>_<os>_<arch>.tar.gz (zip on Windows), each holding the
#   aos program, LICENSE and README.md, and checksums.txt (SHA-256).
# Usage: scripts/release.sh v0.3.0
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:?usage: scripts/release.sh <version, such as v0.3.0>}"
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

rm -rf dist && mkdir -p dist
for t in $targets; do
  os="${t%/*}"; arch="${t#*/}"
  name="aos_${version}_${os}_${arch}"
  dir="dist/$name"; mkdir -p "$dir"
  exe="aos"; [[ $os == windows ]] && exe="aos.exe"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
    -ldflags="-s -w -X github.com/flash-softeware/aos/initiator.BuildVersion=$version" \
    -o "$dir/$exe" ./cmd
  cp LICENSE README.md "$dir/"
  if [[ $os == windows ]]; then
    (cd "$dir" && zip -q -r "../$name.zip" .)
  else
    tar -C "$dir" -czf "dist/$name.tar.gz" .
  fi
  rm -rf "$dir"
done
(cd dist && sha256sum aos_* > checksums.txt)
ls -1 dist
