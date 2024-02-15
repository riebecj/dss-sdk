"""DSS-SDK Version."""
import importlib.metadata
import pathlib
import tomllib

try:
    with pathlib.Path("pyproject.toml").open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)
    version = pyproject["project"]["version"]
except FileNotFoundError:
    version = importlib.metadata.version("dss-sdk")
