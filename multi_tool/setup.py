#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="multi-tool",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A multi-functional CLI-based tool for network reconnaissance and website analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/multi-tool",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "multi-tool=multi_tool.main:main",
        ],
    },
    install_requires=[
        "requests>=2.25.0",
        "beautifulsoup4>=4.9.3",
        "dnspython>=2.1.0",
        "python-whois>=0.7.3",
        "tabulate>=0.8.9",
        "cryptography>=3.4.7",
        "pyOpenSSL>=20.0.1",
    ],
    keywords="network, security, reconnaissance, website analysis, CLI",
)
