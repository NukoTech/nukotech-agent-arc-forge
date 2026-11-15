#!/usr/bin/env bash
set -euo pipefail

bundle_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ownership_tool="$bundle_root/ownership.py"
install_prefix="${XDG_DATA_HOME:-${HOME}/.local/share}/nukotech-hive-local"

while (($#)); do
    case "$1" in
        --prefix)
            [[ $# -ge 2 ]] || { echo "ERROR: --prefix requires a path" >&2; exit 2; }
            install_prefix="$2"
            shift 2
            ;;
        --help|-h)
            echo "usage: ./install.sh [--prefix ABSOLUTE_PATH]"
            exit 0
            ;;
        *)
            echo "ERROR: unsupported argument: $1" >&2
            exit 2
            ;;
    esac
done

command -v python3 >/dev/null || { echo "ERROR: Python 3 is required" >&2; exit 2; }
command -v git >/dev/null || { echo "ERROR: Git is required" >&2; exit 2; }
[[ -f "$ownership_tool" && ! -L "$ownership_tool" ]] || {
    echo "ERROR: ownership helper is absent or unsafe" >&2
    exit 2
}

install_prefix="$(python3 "$ownership_tool" canonicalize "$install_prefix")"
mkdir -p -- "$install_prefix"
install_prefix="$(python3 "$ownership_tool" canonicalize "$install_prefix")"

set +e
existing="$(python3 "$ownership_tool" check "$install_prefix" 2>&1)"
existing_status=$?
set -e
case "$existing_status" in
    0)
        python3 "$ownership_tool" uninstall "$install_prefix" >/dev/null
        ;;
    3)
        ;;
    *)
        echo "$existing" >&2
        echo "ERROR: refusing install over invalid ownership controls" >&2
        exit 2
        ;;
esac

installation_id="$(python3 "$ownership_tool" new-id "$install_prefix")"
owned_root="$install_prefix/.nukotech-hive-local-owned-$installation_id"
bin_created=0
cleanup_required=1
cleanup_partial() {
    status=$?
    trap - EXIT
    if [[ "$cleanup_required" == 1 ]]; then
        arguments=(cleanup-partial "$install_prefix" "$installation_id")
        [[ "$bin_created" == 1 ]] && arguments+=(--bin-created)
        python3 "$ownership_tool" "${arguments[@]}" >/dev/null 2>&1 || true
    fi
    exit "$status"
}
trap cleanup_partial EXIT

mkdir -- "$owned_root"
python3 -m venv "$owned_root/venv"
"$owned_root/venv/bin/python" -m pip install \
    --disable-pip-version-check \
    --no-index \
    --find-links "$bundle_root/wheelhouse" \
    "nukotech-hive-local==0.1.0"
if [[ -e "$install_prefix/bin" || -L "$install_prefix/bin" ]]; then
    [[ -d "$install_prefix/bin" && ! -L "$install_prefix/bin" ]] || {
        echo "ERROR: install prefix bin path is unsafe" >&2
        exit 2
    }
else
    mkdir -- "$install_prefix/bin"
    bin_created=1
fi
[[ ! -e "$install_prefix/bin/hive-local" && ! -L "$install_prefix/bin/hive-local" ]] || {
    echo "ERROR: refusing to replace pre-existing bin/hive-local" >&2
    exit 2
}
ln -s -- "$owned_root/venv/bin/hive-local" "$install_prefix/bin/hive-local"
finalize_arguments=(finalize "$install_prefix" "$installation_id")
[[ "$bin_created" == 1 ]] && finalize_arguments+=(--bin-created)
python3 "$ownership_tool" "${finalize_arguments[@]}" >/dev/null
cleanup_required=0

echo "PASS: NukoTech Hive Local Alpha installed at $install_prefix"
echo "Run: $install_prefix/bin/hive-local --help"
