#!/bin/bash
#
# Helper script to launch Ghidra coverage analysis with given kAFL traces and target ELF.
#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: MIT

set -e

function fail {
	echo
	echo -e "Error: $1"
	echo
	echo -e "Usage:\n\t$0 <kafl_workdir> <target_binary> <script>"
	echo
	exit 1
}

# check for kAFL workspace env vars
if [ -z ${KAFL_ROOT+x} ]; then
	fail "kAFL workspace env vars not found. Use make env first"
	exit 1
fi

set -u

BIN=$GHIDRA_ROOT/support/analyzeHeadless

# check ghidra bin
test -f "$BIN"     || fail "Missing ghidra executable $BIN. Check kAFL deployment."

test $# -eq 3 || fail "Missing arguments."

WORKDIR="$(realpath $1)" # kAFL work dir with traces/ folder
TARGET="$(realpath $2)"  # original target input (tested with basic ELF file loaded as -kernel)
SCRIPT="$(realpath $3)"  # script to run

PROJDIR=$WORKDIR/traces/ghidra
PROJ=cov_analysis

test -d $PROJDIR || mkdir $PROJDIR
test -f "$TARGET"  || fail "Could not find target binary at $TARGET"
test -f "$SCRIPT"  || fail "Could not find coverage analysis script at $SCRIPT"

# Check if traces have been generated and optionally create unique edges file
test -d "$WORKDIR/traces/" || fail "Could not find traces/ folder in workdir."
test -f "$WORKDIR/traces/edges_uniq.lst" || $KAFL_ROOT/tools/unique_edges.sh $WORKDIR

# TODO: how can we hand the file argument directly to ghidra script?
ln -sf "$WORKDIR/traces/edges_uniq.lst" /tmp/edges_uniq.lst

# create project and import binary - slow but only required once per binary
test -f $PROJDIR/$PROJ.gpr || $BIN $PROJDIR $PROJ -import $TARGET -overwrite
# analyse coverage
$BIN $PROJDIR $PROJ -noanalysis -process $(basename $TARGET) -prescript GetAndSetAnalysisOptionsScript.java -scriptPath "$(dirname $SCRIPT)" -postscript "$(basename $SCRIPT)"
