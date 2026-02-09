python_requirements(
    name="pyproject",
    source="pyproject.toml",
)

files(
    name="build_files",
    sources=["pyproject.toml", "README.md", "LICENSE"],
)

python_distribution(
    name="dss-sdk",
    dependencies=["src/dss_sdk", ":build_files"],
    provides=python_artifact(),
    generate_setup = False,
    repositories=[
        "https://upload.pypi.org/legacy/",
    ],
)

pex_binary(
    name="dss",
    entry_point="dss_sdk.cli:main",
    dependencies=["src/dss_sdk", ":pyproject"],
)
