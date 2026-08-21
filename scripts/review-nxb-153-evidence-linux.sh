#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
evidence_directory="${2:-$repo_root/target/nxb-validation}"

command -v python3 >/dev/null 2>&1 || {
    printf 'NXB-153 evidence closure failed: python3 is unavailable\n' >&2
    exit 1
}

exec python3 \
    "$repo_root/scripts/review-nxb-153-evidence-linux.py" \
    "$repo_root" \
    "$evidence_directory"
