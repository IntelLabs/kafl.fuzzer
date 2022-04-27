#!/bin/bash

set -e

URL='https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.3_build/ghidra_10.1.3_PUBLIC_20220421.zip'

ZIPFILE="$(basename "$URL")"

pushd $HOME

wget -O "$ZIPFILE" "$URL"
unzip "$ZIPFILE"

sudo apt-get install openjdk-11-jdk openjdk-11-jre
