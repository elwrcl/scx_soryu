#!/usr/bin/env bash
#
# Does cpu.weight reach the scheduler?
#
# Not an A/B on latency -- cgroup weight changes fairness between groups, so
# what is measured is CPU time each group actually got. Two cgroups, each with
# nproc spinners so the CPUs are genuinely oversubscribed: with one spinner per
# group on a 4-thread box both simply get a core and the weight never comes
# into play.
#
# Run the scheduler in another terminal, once with --cgrp-weight-levels 0 and
# once with 6, and compare the ratio.
#
#   sudo ./tools/cgroup-share.sh [seconds] [spinners-per-group]
#
# Cgroups are created directly rather than through systemd-run. That started as
# a workaround -- transient units were not surviving reliably here -- but it is
# the better test anyway: making a fresh cgroup while the scheduler is attached
# exercises ops.cgroup_init, which is the path being checked.

set -euo pipefail

DUR=${1:-30}
# Spinners per group. The default matters more than it looks: with exactly
# nproc per group, a hi task whose slice expires is not yet back in its DSQ
# when that CPU calls ops.dispatch, and the other three are on CPUs, so level
# 19 is momentarily empty and dispatch legitimately falls through to lo. The
# ratio then measures the test's shape as much as the weight. Oversubscribe a
# group and its queue stops emptying.
N=${2:-$(nproc)}
HI=1000
LO=10
ROOT=/sys/fs/cgroup/soryu-test

if [ "$(id -u)" -ne 0 ]; then
	echo "needs root: sudo $0 $*" >&2
	exit 1
fi

PIDS=()

cleanup() {
	for p in ${PIDS+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
	sleep 0.3
	rmdir "$ROOT/hi" "$ROOT/lo" "$ROOT" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

mkdir -p "$ROOT"
# The parent must delegate cpu before its children can have cpu.weight. The
# root already delegates it, or nothing on this system would have a weight.
grep -qw cpu "$ROOT/cgroup.subtree_control" || echo "+cpu" > "$ROOT/cgroup.subtree_control"

mkdir -p "$ROOT/hi" "$ROOT/lo"
echo "$HI" > "$ROOT/hi/cpu.weight"
echo "$LO" > "$ROOT/lo/cpu.weight"

echo "hi cpu.weight = $(cat "$ROOT/hi/cpu.weight")   lo cpu.weight = $(cat "$ROOT/lo/cpu.weight")"

spawn() {
	local dir=$1 i
	for i in $(seq "$N"); do
		( while :; do :; done ) &
		PIDS+=("$!")
		# One pid per write; cgroup.procs takes a single value.
		echo "$!" > "$dir/cgroup.procs"
	done
}

spawn "$ROOT/hi"
spawn "$ROOT/lo"

usage() { awk '/^usage_usec/{print $2}' "$1/cpu.stat"; }

# Let both groups reach steady state before the first sample.
sleep 3

h0=$(usage "$ROOT/hi"); l0=$(usage "$ROOT/lo")
echo "running $((N * 2)) spinners ($N per group) on $(nproc) CPUs for ${DUR}s..."
sleep "$DUR"
h1=$(usage "$ROOT/hi"); l1=$(usage "$ROOT/lo")

dh=$((h1 - h0)); dl=$((l1 - l0))

printf '\n  hi  cpu.weight=%-5s  %8s ms\n' "$HI" "$((dh / 1000))"
printf '  lo  cpu.weight=%-5s  %8s ms\n' "$LO" "$((dl / 1000))"
awk -v a="$dh" -v b="$dl" 'BEGIN {
	if (b > 0) printf "\n  ratio hi:lo = %.2f : 1\n", a / b
	else       printf "\n  ratio hi:lo = inf (lo got nothing)\n"
}'
