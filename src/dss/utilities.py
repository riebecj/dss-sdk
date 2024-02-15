"""Utilities for DSS SDK."""
import datetime
import platform
from enum import Enum, StrEnum
from typing import TypeVar

from click.exceptions import Exit

from dss import __version__

_T = TypeVar("_T")


class OutputTypes(Enum):
    """Console output types."""
    TABLE = "table"
    JSON = "json"
    CLIPBOARD = "clipboard"


class HelpText(StrEnum):
    """Help Text for CLI."""
    client_id = "The client ID registered with your Delinea server."
    client_secret = "The client secret for the specified client ID registered with your Delinea server."  # noqa: S105
    include_username = "Include the username in the output (Does not copy username to clipboard)."
    output_format = "Output as a table, JSON, or copy to clipboard."
    server = "The FQDN of your Delinea Secret Server."
    windows = "The name of a Windows Credential containing the Client ID and Client Secret"


def assert_windows(value: _T) -> _T:
    """Used as a Typer callback to check if a platform is Windows.

    Args:
        value: The value of the option/argument from Typer.

    Returns:
        The value
    """
    if value and not platform.platform().startswith("Windows"):
        msg = "Not a Windows machine."
        raise RuntimeError(msg)
    return value


def version_callback(value: bool) -> None:  # noqa: FBT001
    """Prints the version when the version flag is set.

    Args:
        value: `True`, if the `--version` flag is set.
    """
    if value:
        print(f"DSS CLI v{__version__.version}")  # noqa: T201
        raise Exit


def format_dtg(date_string: datetime.datetime | _T) -> str | _T:
    """Formats datetime date in `isoformat()`.

    Args:
        date_string: The optional datetime string.

    Returns:
        The formatted string if the `date_string` is a datetime object, otherwise it just returns the value.
    """
    if not date_string:
        return date_string
    return date_string.isoformat()
