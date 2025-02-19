#!/bin/sh

DIR="crates"
mkdir -p "$DIR"

if [ -z $1 ] || [ -z $2 ]
then
    echo "Usage: bash script.sh <package> <version>"
    exit 1
fi

`curl -L https://crates.io/api/v1/crates/"$1"/"$2"/download | tar -zxf -` || echo "Cannot download the package!"
mv "$1-$2" "$DIR/$1-$2"