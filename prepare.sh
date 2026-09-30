#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
TOOLING="${W_TOOLING_ROOT:-${ROOT}/../w-tooling}"
[[ -f "$TOOLING/prepare.sh" ]] || { printf 'Задай W_TOOLING_ROOT: путь к w-tooling.\n' >&2; exit 1; }
exec bash "$TOOLING/prepare.sh" --releases-root "$ROOT" "$@"
