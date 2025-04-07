from setuptools import setup
from setuptools_rust import RustExtension

setup(
    name="autonomi-client",
    version="0.3.0",
    description="Autonomi client API",
    long_description=open("README_PYTHON.md").read(),
    long_description_content_type="text/markdown",
    author="MaidSafe Developers",
    author_email="dev@maidsafe.net",
    url="https://github.com/maidsafe/autonomi",
    rust_extensions=[
        RustExtension(
            "autonomi_client.autonomi_client",
            "Cargo.toml",
            features=["extension-module"],
            py_limited_api=True,
            debug=False,
        )
    ],
    packages=["autonomi_client"],
    package_dir={"": "python"},
    zip_safe=False,
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Rust",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
) 