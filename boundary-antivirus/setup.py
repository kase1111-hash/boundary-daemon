#!/usr/bin/env python3
"""Setup script for Boundary Antivirus"""

from setuptools import setup, find_packages

setup(
    name="boundary-antivirus",
    version="0.1.0",
    author="Agent OS Team",
    description="Standalone malware detection engine - extracted from Boundary Daemon",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    install_requires=[
        "psutil>=5.9.0",
    ],
    entry_points={
        'console_scripts': [
            'boundary-antivirus=boundary_antivirus.scanner:main',
        ],
    },
)
