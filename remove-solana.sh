#!/bin/sh

DIR="solana"

if [ -z $1 ]
then
    echo "Usage: bash remove-solana.sh <version>"
    exit 1
fi

version=$1

#rm -rf "$DIR/solana-release-$version"
