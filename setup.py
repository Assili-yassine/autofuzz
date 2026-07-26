"""Classic setuptools entrypoint, kept alongside pyproject.toml on purpose.

Some pip/setuptools combinations (notably older ones shipped by Debian/
Ubuntu/Kali) don't read the PEP 621 [project] table in pyproject.toml
correctly even when [build-system].requires asks for a newer setuptools —
the symptom is a wheel built as "UNKNOWN-0.0.0" with no entry points, which
means the `autofuzz` console script never gets created.

setup.py is understood by effectively every version of pip/setuptools ever
shipped, so it's the reliable fallback: setuptools.build_meta will run this
file directly if it's present, which guarantees the real package name,
version, and entry_points (the actual thing that creates the `autofuzz`
command) regardless of how old the toolchain is.
"""
from setuptools import setup

setup(
    name="autofuzz",
    version="1.0.0",
    description="Recon + ffuf orchestration for authorized bug bounty testing",
    packages=["autofuzz", "autofuzz.recon", "autofuzz.fuzz", "autofuzz.report"],
    python_requires=">=3.10",
    install_requires=[
        "rich>=13.7",
        "PyYAML>=6.0",
        "Jinja2>=3.1",
    ],
    entry_points={
        "console_scripts": [
            "autofuzz=autofuzz.cli:main",
        ],
    },
)
