python_requirements(
    name="pyproject",
    source="pyproject.toml",
)

files(
    name="build_files",
    sources=["pyproject.toml", "README.md", "LICENSE"],
)

python_sources(
    name="src",
    sources=["src/dss/**/*.py"]
)

python_distribution(
    name="dss-sdk",
    dependencies=[":src", ":build_files"],
    provides=python_artifact(),
    generate_setup = False,
    repositories=[
        "https://upload.pypi.org/legacy/",
    ],
)
