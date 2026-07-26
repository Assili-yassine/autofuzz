#!/usr/bin/env bash
# Installs AutoFuzz as a global `autofuzz` command.
#
# Usage:
#   ./install.sh          # installs for the current user (~/.local/bin)
#   sudo ./install.sh     # installs system-wide (/usr/local/bin or similar)
#
# This just wraps `pip install .`, which is what actually creates the
# `autofuzz` executable — see pyproject.toml's [project.scripts] entry.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

PIP_ARGS=(install --break-system-packages .)
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    PIP_ARGS=(install --break-system-packages --user .)
fi

echo "Installing AutoFuzz..."
python3 -m pip "${PIP_ARGS[@]}"

if command -v autofuzz >/dev/null 2>&1; then
    echo
    echo "Done. 'autofuzz' is on PATH:"
    command -v autofuzz
    echo
    echo "Try:  autofuzz --help"
else
    echo
    echo "Installed, but 'autofuzz' isn't on PATH yet."
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
        echo '  export PATH="$HOME/.local/bin:$PATH"'
    else
        echo "Check where pip installed the script (usually /usr/local/bin) and confirm it's on PATH."
    fi
fi

echo
echo "Reminder: AutoFuzz orchestrates external tools (httpx, katana, gau,"
echo "wayback, ffuf, linkfinder) that are NOT installed by this script."
echo "See the README's 'Prerequisites' section, or use the Docker image"
echo "instead, which bundles everything."
