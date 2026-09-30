#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
export PYTHONDONTWRITEBYTECODE=1
python3 "$ROOT/tests/secure_extract_zip.test.py"
python3 "$ROOT/tests/release_runtime_test.py"
