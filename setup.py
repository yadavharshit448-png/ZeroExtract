#!/usr/bin/env python3
"""Setup configuration for ZeroExtract."""

from setuptools import find_packages, setup

setup(
    name="zeroextract",
    version="0.1.0",
    description="Extract massive archives without requiring 2x extra disk space via in-place progressive disk space recycling.",
    author="ZeroExtract Team",
    packages=find_packages(include=["zeroextract", "zeroextract.*"]),
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "zeroextract=zeroextract.cli.main:main",
        ],
    },
)
