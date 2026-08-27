from setuptools import setup, find_packages

# Read version from scanner package
import re
import ast

with open("scanner/__init__.py") as f:
    for line in f:
        if line.startswith("__version__"):
            version = ast.literal_eval(line.split("=")[1].strip())
            break
    else:
        version = "0.0.0"

setup(
    name="reconstrike",
    version=version,
    description="Advanced Web & Network Vulnerability Assessment Framework",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="CypherSec",
    author_email="cyphersec.404@gmail.com",
    url="https://github.com/Un-9oon/ReconStrike-ng",
    packages=find_packages(),
    py_modules=["reconstrike"],
    python_requires=">=3.10",
    install_requires=[
        "requests[socks]>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "urllib3>=2.0.0",
        "colorama>=0.4.6",
        "dnspython>=2.4.0",
        "fpdf2>=2.8.0",
    ],
    entry_points={
        "console_scripts": [
            "reconstrike=reconstrike:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
    ],
)
