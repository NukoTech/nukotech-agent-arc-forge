#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
lock_file="$repo_root/packaging/locks/linux-x86_64-py312.lock"
build_lock_file="$repo_root/packaging/locks/build-py312.lock"
bundle_name="nukotech-hive-local-alpha-v0.1.0-linux-x86_64"
build_root="$(mktemp -d -t nukotech-hive-x86_64-build.XXXXXX)"
trap 'rm -rf -- "$build_root"' EXIT
# Alpha.1 was built with a collaborative (group-writable) umask; retaining it keeps
# the sanitized, architecture-neutral product wheel byte-reproducible.
umask 002
export PYTHONHASHSEED=0
export SOURCE_DATE_EPOCH=0

python_version="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
[[ "$python_version" == "3.12" ]] || {
    echo "ERROR: reproducible x86_64 build requires CPython 3.12, found $python_version" >&2
    exit 2
}
[[ -f "$lock_file" ]] || { echo "ERROR: dependency lock missing: $lock_file" >&2; exit 2; }
[[ -f "$build_lock_file" ]] || { echo "ERROR: build lock missing: $build_lock_file" >&2; exit 2; }

bundle_root="$build_root/$bundle_name"
mkdir -p "$bundle_root/wheelhouse" "$bundle_root/verify" "$repo_root/dist"
python3 -m pip download \
    --disable-pip-version-check \
    --require-hashes \
    --no-deps \
    --only-binary=:all: \
    --python-version 312 \
    --implementation cp \
    --abi cp312 \
    --platform manylinux_2_34_x86_64 \
    --platform manylinux_2_28_x86_64 \
    --platform manylinux2014_x86_64 \
    --platform manylinux_2_17_x86_64 \
    --dest "$bundle_root/wheelhouse" \
    --requirement "$lock_file" >&2

python3 -m venv "$build_root/build-venv"
build_python="$build_root/build-venv/bin/python"
"$build_python" -m pip install \
    --disable-pip-version-check \
    --require-hashes \
    --requirement "$build_lock_file" >&2
"$build_python" -m pip wheel \
    --disable-pip-version-check \
    --no-build-isolation \
    --no-deps \
    --wheel-dir "$bundle_root/wheelhouse" \
    "$repo_root" >&2
product_wheel="$(find "$bundle_root/wheelhouse" -maxdepth 1 -type f -name 'nukotech_hive_local-0.1.0-*.whl' -print -quit)"
[[ -n "$product_wheel" ]] || { echo "ERROR: product wheel missing" >&2; exit 2; }
python3 "$repo_root/scripts/sanitize_product_wheel.py" "$product_wheel"
if [[ "${HIVE_CYCLE2_DEVELOPMENT:-0}" != "1" ]]; then
    python3 "$repo_root/scripts/verify_alpha1_wheel_parity.py" "$product_wheel" >&2
fi

cp "$repo_root/installer/install.sh" "$bundle_root/install.sh"
cp "$repo_root/installer/uninstall.sh" "$bundle_root/uninstall.sh"
cp "$repo_root/installer/ownership.py" "$bundle_root/ownership.py"
cp "$repo_root/LICENSE" "$bundle_root/LICENSE"
cp "$repo_root/THIRD_PARTY_NOTICES.md" "$bundle_root/THIRD_PARTY_NOTICES.md"
cp "$repo_root/packaging/product-readme.md" "$bundle_root/README.md"
cp "$repo_root/docs/install/alpha-install.md" "$bundle_root/INSTALL.md"
cp "$repo_root/scripts/m4-installed-shell-e2e.py" "$bundle_root/verify/m4-installed-shell-e2e.py"
chmod 0755 "$bundle_root/install.sh" "$bundle_root/uninstall.sh" "$bundle_root/ownership.py" "$bundle_root/verify/m4-installed-shell-e2e.py"
python3 "$repo_root/scripts/generate_artifact_metadata.py" "$bundle_root"

artifact="$repo_root/dist/$bundle_name.tar.gz"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    --mode='u+rwX,go+rX,go-w' \
    -I 'gzip -n -9' -C "$build_root" -cf "$artifact" "$bundle_name"
(cd "$repo_root/dist" && sha256sum "$bundle_name.tar.gz") >"$repo_root/dist/SHA256SUMS-linux-x86_64"
echo "$artifact"
