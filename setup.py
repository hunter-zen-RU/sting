"""Setup script for STING - WiFi Security Testing & Investigation Tool."""

from pathlib import Path

from setuptools import find_packages, setup

import sting

README = Path(__file__).with_name("README.md").read_text(encoding="utf-8")

setup(
    name="sting-wifi",
    version=sting.__version__,
    author=sting.__author__,
    license=sting.__license__,
    description=sting.__description__,
    long_description=README,
    long_description_content_type="text/markdown",
    url=sting.__github_url__,
    project_urls={
        "Source": sting.__github_url__,
        "Issues": f"{sting.__github_url__}/issues",
    },
    packages=find_packages(exclude=("tests", "tests.*")),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "scapy>=2.5.0",
        "requests>=2.25.0",
    ],
    extras_require={
        "test": ["pytest>=7"],
    },
    entry_points={
        "console_scripts": [
            "sting=sting.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    keywords="wifi deauth security penetration-testing educational 802.11 pmf wpa3",
)
