#!/bin/sh
# Regenerates internal/popularity/top-packagist.txt: Packagist (Composer) packages ranked by last
# month's downloads, from the ecosyste.ms packages API (data: CC BY-SA 4.0,
# https://ecosyste.ms). Needs curl and python3.
set -eu
out="$(cd "$(dirname "$0")/.." && pwd)/internal/popularity/top-packagist.txt"
pages=5 # 1000 names per page
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
page=1
while [ "$page" -le "$pages" ]; do
  curl -fsS --max-time 60 --retry 3 --retry-all-errors "https://packages.ecosyste.ms/api/v1/registries/packagist.org/package_names?sort=downloads&order=desc&per_page=1000&page=$page" |
    python3 -c 'import json, sys; print("\n".join(json.load(sys.stdin)))' >>"$tmp"
  page=$((page + 1))
done
{
  echo "# Packagist (Composer) packages ranked by last month's downloads, most popular first."
  echo "# Source: ecosyste.ms packages API, $(date -u +%Y-%m-%d). Data licensed CC BY-SA 4.0"
  echo "# (https://creativecommons.org/licenses/by-sa/4.0/), (c) ecosyste.ms; this list is an"
  echo "# adaptation under the same license. Regenerate with scripts/update-popular-packagist.sh"
  cat "$tmp"
} >"$out"
echo "wrote $(grep -vc '^#' "$out") names to $out"
