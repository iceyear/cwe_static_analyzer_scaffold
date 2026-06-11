#!/usr/bin/env bash
# Install Souffle on GitHub hosted runners without relying on the legacy PPA.
# The old PPA package can depend on libffi7, which is not available on Ubuntu 24.04.
# This script queries the official GitHub Release assets and prefers an Ubuntu 24 amd64 .deb.
set -euo pipefail

if command -v souffle >/dev/null 2>&1; then
  echo "Souffle is already installed: $(souffle --version)"
  exit 0
fi

release_api="${SOUFFLE_RELEASE_API:-https://api.github.com/repos/souffle-lang/souffle/releases/latest}"
release_json="${RUNNER_TEMP:-/tmp}/souffle-release.json"
deb_path="${RUNNER_TEMP:-/tmp}/souffle.deb"

curl_headers=(
  -H "Accept: application/vnd.github+json"
  -H "X-GitHub-Api-Version: 2022-11-28"
)
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  curl_headers+=( -H "Authorization: Bearer ${GITHUB_TOKEN}" )
fi

echo "Querying Souffle release assets: ${release_api}"
if ! curl -fsSL "${curl_headers[@]}" "${release_api}" -o "${release_json}"; then
  echo "Could not query Souffle release assets; analyzer will use the Python fallback."
  exit 0
fi

asset_url="$({
python - "${release_json}" <<'PYSELECT'
import json
import re
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    release = json.load(fh)
assets = release.get("assets", [])

# Prefer Ubuntu 24 / Noble amd64 packages. Fall back to any Ubuntu amd64 .deb.
patterns = [
    re.compile(r"(?i)(ubuntu|noble).*?(24|noble).*?(amd64|x86_64).*?\.deb$"),
    re.compile(r"(?i)(amd64|x86_64).*?(ubuntu|noble).*?(24|noble).*?\.deb$"),
    re.compile(r"(?i)(ubuntu|noble).*?(amd64|x86_64).*?\.deb$"),
    re.compile(r"(?i)(amd64|x86_64).*?(ubuntu|noble).*?\.deb$"),
]

for pattern in patterns:
    for asset in assets:
        name = asset.get("name", "")
        if pattern.search(name):
            print(asset.get("browser_download_url", ""))
            sys.exit(0)

print("")
PYSELECT
} )"

if [[ -z "${asset_url}" ]]; then
  echo "No compatible Ubuntu amd64 .deb was found in the Souffle release assets."
  echo "Available assets were:"
  python - "${release_json}" <<'PYASSETS'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as fh:
    release = json.load(fh)
for asset in release.get("assets", []):
    print("-", asset.get("name", "<unnamed>"))
PYASSETS
  echo "Analyzer will use the Python fallback mirror of rules/cwe_rules.dl."
  exit 0
fi

echo "Downloading Souffle package: ${asset_url}"
if ! curl -fL "${asset_url}" -o "${deb_path}"; then
  echo "Could not download Souffle package; analyzer will use the Python fallback."
  exit 0
fi

sudo apt-get update
if sudo apt-get install -y "${deb_path}"; then
  echo "Souffle installed successfully."
  souffle --version
else
  echo "Souffle package install failed; analyzer will use the Python fallback mirror of rules/cwe_rules.dl."
  exit 0
fi
