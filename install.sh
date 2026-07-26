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

# Clean any stale build artifacts from a previous failed attempt (e.g. a
# broken toolchain that built a package literally named "UNKNOWN") so they
# can't poison this build.
rm -rf build dist ./*.egg-info UNKNOWN.egg-info

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
        echo "Run this now, then add it permanently to ~/.bashrc / ~/.zshrc:"
        echo
        echo '  export PATH="$HOME/.local/bin:$PATH"'
        echo
        echo "Or make it permanent in one step:"
        echo '  echo '"'"'export PATH="$HOME/.local/bin:$PATH"'"'"' >> ~/.bashrc && source ~/.bashrc'
    else
        echo "You're root but something put it in \$HOME/.local/bin instead of a"
        echo "system-wide location (e.g. you ran 'pip install --user .' directly"
        echo "instead of this script). Either:"
        echo
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\"     # quick fix, this shell only"
        echo
        echo "  — or reinstall system-wide instead —"
        echo "  pip uninstall -y autofuzz && pip install --break-system-packages ."
    fi
fi

echo
echo "Reminder: AutoFuzz orchestrates external tools (httpx, katana, gau,"
echo "wayback, ffuf, linkfinder) that are NOT installed by this script."
echo "See the README's 'Prerequisites' section, or use the Docker image"
echo "instead, which bundles everything."
