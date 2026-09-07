#!/usr/bin/env bash
# Regenerate compile_commands.json for src/bpf/main.bpf.c so clangd sees the
# same flags the real BPF build uses.
#
# scx_cargo prints its computed cflags to the build-script output as a line
# starting with `scx_utils:clang=`. The include paths in it point into
# target/<profile>/build/scx_soryu-<hash>/out, and that hash changes whenever
# the build-script inputs change, so this is generated rather than committed.
#
# Run inside the devShell after a build:
#   cargo build --release && ./tools/gen-compile-commands.sh

set -euo pipefail

cd "$(dirname "$0")/.."
root="$PWD"

profile="${1:-release}"
out=$(ls -td "target/$profile"/build/scx_soryu-*/output 2>/dev/null | head -1 || true)

if [ -z "$out" ]; then
  echo "error: no build-script output under target/$profile/build/." >&2
  echo "       run 'cargo build --${profile/dev/}' first (inside the devShell)." >&2
  exit 1
fi

line=$(grep -h '^scx_utils:clang=' "$out" | tail -1 || true)
if [ -z "$line" ]; then
  echo "error: no 'scx_utils:clang=' line in $out" >&2
  echo "       the build script was cached; touch src/bpf/main.bpf.c and rebuild." >&2
  exit 1
fi

# The cflags are the bracketed Rust Vec<String> debug print at the end of the
# line: ["-g", "-O2", ...]. Pull the quoted strings out of that part only.
flags=$(printf '%s' "$line" \
  | sed 's/.*\(\[[^][]*\]\)$/\1/' \
  | grep -o '"[^"]*"' \
  | sed 's/^"//; s/"$//')

if [ -z "$flags" ]; then
  echo "error: could not parse cflags out of: $line" >&2
  exit 1
fi

{
  printf '[\n  {\n'
  printf '    "directory": "%s",\n' "$root"
  printf '    "file": "%s/src/bpf/main.bpf.c",\n' "$root"
  printf '    "arguments": [\n'
  printf '      "clang",\n'
  printf '      "-xc",\n'
  printf '      "-target", "bpf",\n'
  while IFS= read -r f; do
    printf '      %s,\n' "$(printf '%s' "$f" | sed 's/\\/\\\\/g; s/"/\\"/g; s/^/"/; s/$/"/')"
  done <<<"$flags"
  printf '      "-c",\n'
  printf '      "%s/src/bpf/main.bpf.c"\n' "$root"
  printf '    ]\n  }\n]\n'
} >compile_commands.json

echo "wrote compile_commands.json ($(wc -l <<<"$flags") flags, profile=$profile)"
