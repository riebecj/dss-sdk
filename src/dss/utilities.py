"""Utilities for DSS SDK."""
import datetime
import platform
from enum import Enum, StrEnum, auto
from typing import TypeVar

from click.exceptions import Exit

from dss import __version__
from dss.models import SecretInfo

_T = TypeVar("_T")


class OutputTypes(Enum):
    """Console output types."""
    TABLE = "table"
    JSON = "json"
    CLIPBOARD = "clipboard"


class SearchSecretsExtraFields(StrEnum):
    """Extra fields to print for secret info."""
    site_id = auto()
    checked_out = auto()
    is_restricted = auto()
    create_date = auto()
    days_until_expiration = auto()
    auto_change_enabled = auto()

    @classmethod
    def add_extra_headers(cls, headers: list[str], extra_fields: list[str]) -> list[str]:
        """Adds additional headers if the extra field is applied."""
        for field in extra_fields:
            match field:
                case cls.site_id:
                    headers.append("Site ID")
                case cls.checked_out:
                    headers.append("Checked Out")
                case cls.is_restricted:
                    headers.append("Is Restricted")
                case cls.create_date:
                    headers.append("Create Date")
                case cls.days_until_expiration:
                    headers.append("Days Until Expiration")
                case cls.auto_change_enabled:
                    headers.append("Auto Change Enabled")
        return headers

    @classmethod
    def append_extra_data(cls, secret_info: SecretInfo, row: list[_T], extra_fields: list[str]) -> list[_T]:
        """Adds requisite data if the extra field is applied."""
        for field in extra_fields:
            match field:
                case cls.site_id:
                    row.append(str(secret_info.site_id))
                case cls.checked_out:
                    row.append(str(secret_info.checked_out))
                case cls.is_restricted:
                    row.append(str(secret_info.is_restricted))
                case cls.create_date:
                    row.append(format_dtg(secret_info.create_date))
                case cls.days_until_expiration:
                    row.append(str(secret_info.days_until_expiration))
                case cls.auto_change_enabled:
                    row.append(str(secret_info.auto_change_enabled))
        return row


class HelpText(StrEnum):
    """Help Text for CLI."""
    client_id = "The client ID registered with your Delinea server."
    client_secret = "The client secret for the specified client ID registered with your Delinea server."  # noqa: S105
    include_username = "Include the username in the output (Does not copy username to clipboard)."
    output_format = "Output as a table, JSON, or copy to clipboard."
    server = "The FQDN of your Delinea Secret Server."
    windows = "The name of a Windows Credential containing the Client ID and Client Secret"
    parent_folder_id = "The parent folder ID to search for child folders."
    search_text = "Text to search for."
    store_in_windows = "Store the registered client ID and secret as Windows credentials."


def hide_non_windows() -> bool:
    """Used as a Typer callback to check if a platform is Windows.

    Args:
        value: The value of the option/argument from Typer.

    Returns:
        The value
    """
    return not platform.platform().startswith("Windows")


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
