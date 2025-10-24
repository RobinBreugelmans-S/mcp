# agents.md

Purpose
- Use cve-checker-mcp to validate a package (and a candidate version) before installing.
- If a version has too many vulnerabilities, try other versions until an acceptable one is found.

Quick notes
- Requires: cve-checker-mcp, jq, and your package manager (example: npm or pip).
- Configure thresholds via environment variables:
    - MAX_CRITICAL (default 0)
    - MAX_HIGH (default 1)
    - MAX_TOTAL (default 5)

Example agent script (bash)
- Save as mcp-install.sh and make executable. Call with the package name.

```bash
#!/usr/bin/env bash
set -euo pipefail

PKG="$1"
MAX_CRITICAL="${MAX_CRITICAL:-0}"
MAX_HIGH="${MAX_HIGH:-1}"
MAX_TOTAL="${MAX_TOTAL:-5}"

# Run cve-checker-mcp for a specific package@version and return 0 if acceptable.
check_version() {
    local target="$1"   # e.g. pkg@1.2.3 or pkg==1.2.3 for pip
    local out
    out=$(cve-checker-mcp "$target" --format json 2>/dev/null) || return 1

    local critical high total
    critical=$(echo "$out" | jq '[.vulnerabilities[]? | select(.severity == "CRITICAL")] | length')
    high=$(echo "$out" | jq '[.vulnerabilities[]? | select(.severity == "HIGH")] | length')
    total=$(echo "$out" | jq '.vulnerabilities | length')

    if (( critical <= MAX_CRITICAL && high <= MAX_HIGH && total <= MAX_TOTAL )); then
        return 0
    else
        return 2
    fi
}

# Example: npm flow
try_npm() {
    echo "Checking npm versions for $PKG..."
    mapfile -t versions < <(npm view "$PKG" versions --json 2>/dev/null | jq -r '.[]' | tac)
    for v in "${versions[@]}"; do
        echo "Checking $PKG@$v ..."
        if check_version "${PKG}@${v}"; then
            echo "Acceptable: $PKG@$v — installing..."
            npm install "${PKG}@${v}"
            exit 0
        fi
    done
    echo "No acceptable npm version found."
    return 1
}

# Example: pip flow
try_pip() {
    echo "Checking pip versions for $PKG..."
    mapfile -t versions < <(pip index versions "$PKG" 2>/dev/null | sed -n 's/^[[:space:]]*-\s*//p')
    for v in "${versions[@]}"; do
        echo "Checking $PKG==$v ..."
        if check_version "${PKG}==${v}"; then
            echo "Acceptable: $PKG==$v — installing..."
            pip install "${PKG}==${v}"
            exit 0
        fi
    done
    echo "No acceptable pip version found."
    return 1
}

# Choose manager by environment or fallback
MANAGER="${MANAGER:-auto}"
if [[ "$MANAGER" == "auto" ]]; then
    if command -v npm >/dev/null; then MANAGER="npm"; elif command -v pip >/dev/null; then MANAGER="pip"; fi
fi

if [[ "$MANAGER" == "npm" ]]; then
    try_npm
elif [[ "$MANAGER" == "pip" ]]; then
    try_pip
else
    echo "Unknown manager. Set MANAGER=npm or MANAGER=pip"
    exit 2
fi
```

Usage examples
- npm (default thresholds):
    - ./mcp-install.sh lodash
- pip with stricter rules:
    - MAX_HIGH=0 MAX_TOTAL=2 MANAGER=pip ./mcp-install.sh requests

Integration tips
- Replace direct install steps in CI or local agents with this script.
- Tune thresholds per-project or per-environment.
- Add caching of cve-checker-mcp reports to avoid repeated scans for the same version.

That's it — run this agent instead of installing a package directly so the cve-checker-mcp is always consulted first.