#!/usr/bin/env bash
set -euo pipefail

bundle_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ownership_tool="$bundle_root/ownership.py"
install_prefix="${XDG_DATA_HOME:-${HOME}/.local/share}/nukotech-hive-local"
if [[ "${1:-}" == "--prefix" && $# -ge 2 ]]; then
    install_prefix="$2"
elif (($#)); then
    echo "usage: ./uninstall.sh [--prefix ABSOLUTE_PATH]" >&2
    exit 2
fi

command -v python3 >/dev/null || { echo "ERROR: Python 3 is required" >&2; exit 2; }
[[ -f "$ownership_tool" && ! -L "$ownership_tool" ]] || {
    echo "ERROR: ownership helper is absent or unsafe" >&2
    exit 2
}
install_prefix="$(python3 "$ownership_tool" canonicalize "$install_prefix")"
result="$(python3 "$ownership_tool" uninstall "$install_prefix")"
echo "PASS: removed only manifest-owned files from $install_prefix"
echo "$result"
