#!/bin/sh
# Regenerates internal/popularity/top.txt from npm-high-impact (MIT, Titus Wormer):
# npm packages ranked by downloads. Needs npm and node.
set -eu
out="$(cd "$(dirname "$0")/.." && pwd)/internal/popularity/top.txt"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
npm pack npm-high-impact --silent >/dev/null
tar xzf npm-high-impact-*.tgz
version="$(node -p "require('./package/package.json').version")"
{
  echo "# npm packages ranked by downloads, most popular first."
  echo "# Source: npm-high-impact@$version (MIT, Copyright (c) Titus Wormer)"
  echo "# Regenerate with scripts/update-popular.sh"
  node --input-type=module -e "import { topDownload } from './package/lib/top-download.js'; console.log(topDownload.join('\n'))"
} > "$out"
echo "wrote $(grep -vc '^#' "$out") names to $out"
