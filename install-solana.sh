#!/bin/sh

DIR="solana"
mkdir -p "$DIR"

if [ -z $1 ]
then
    echo "Usage: bash script.sh <version> <libsolana_program.rlib only>"
    exit 1
fi

version=$1

_ostype="$(uname -s)"
_cputype="$(uname -m)"

case "$_ostype" in
Linux)
    _ostype=unknown-linux-gnu
    ;;
Darwin)
    if [[ $_cputype = arm64 ]]; then
    _cputype=aarch64
    fi
    _ostype=apple-darwin
    ;;
*)
    err "machine architecture is currently unsupported"
    ;;
esac
TARGET="${_cputype}-${_ostype}"

download_url="https://github.com/solana-labs/solana/releases/download/v$version/solana-release-$TARGET.tar.bz2"

echo "Downloading solana-release-$TARGET from $download_url"

wget $download_url -O solana-release-$TARGET.tar.bz2

tar -xvf solana-release-$TARGET.tar.bz2

rm solana-release-$TARGET.tar.bz2

mv solana-release "$DIR/solana-release-$version"