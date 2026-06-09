from setuptools import setup, find_packages

setup(
    name="forma-sdk",
    version="1.0.0",
    description="FORMA — AI agent compliance SDK. Zero-config tracking, EU AI Act/DPDP/RBI compliance, cryptographic audit trails.",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="FORMA",
    author_email="sdk@forma.ai",
    url="https://github.com/amit5115/forma-sdk",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "httpx>=0.24.0",
        "pydantic>=2.0",
    ],
    extras_require={
        "cli": ["click>=8.0"],
        "openai": ["openai>=1.0"],
        "anthropic": ["anthropic>=0.20"],
        "litellm": ["litellm>=1.0"],
        "langchain": ["langchain-core>=0.1"],
        "all": ["click>=8.0", "openai>=1.0", "anthropic>=0.20", "litellm>=1.0", "langchain-core>=0.1"],
    },
    entry_points={
        "console_scripts": [
            "provn=provn.cli:main",
            "trustlayer=trustlayer.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    keywords="ai agents compliance eu-ai-act rbi dpdp audit cryptography llm openai",
)
