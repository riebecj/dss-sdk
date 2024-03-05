"""The DSS CLI."""
import platform
from typing import Annotated

import pyperclip
from click import Abort, ClickException, Context, confirm, prompt
from rich.console import Console
from rich.table import Table
from rich.text import Text
from typer import Option, Typer

from dss.credentials import CredFileProvider
from dss.models import SearchFoldersParams, SearchSecretsParams
from dss.server import RegisterClient, SecretServerClient
from dss.utilities import (
    HelpText,
    OutputTypes,
    SearchSecretsExtraFields,
    format_dtg,
    hide_non_windows,
    version_callback,
)
from dss.windows_credentials import Windows

cli = Typer()


def config_prompt(
        profile_config: dict,
        key: str,
        message: str,
        *,
        required: bool = False,
        prompt_kwargs: dict = None,
) -> str | None:
    """Method used when configuring a profile in the credentials file.

    Args:
        profile_config: The credentials file profile config.
        key: The key for the item in the profile config.
        message: The message used in the prompt.
        required: If the key in the profile is required.
        prompt_kwargs: Extra kwargs to pass to click's `prompt()`.
    """
    if not prompt_kwargs:
        prompt_kwargs = {}

    current_value = profile_config.get(key)

    while True:
        new_value = prompt(message, default=current_value if current_value else "", **prompt_kwargs)

        if new_value:
            return new_value
        if not new_value and not current_value and required:
            Console().print(f"A {key} is required.")
        else:
            return current_value


@cli.command()
def register_client(
        service_account: str,
        onboarding_key: Annotated[str, Option(prompt=True, hide_input=True)],
        description: Annotated[str, Option(show_default=False)] = None,
        server: Annotated[str, Option()] = None,
        store_in_windows: Annotated[bool, Option(
            "--store-in-windows", help=HelpText.store_in_windows, hidden=hide_non_windows(),
        )] = False,  # noqa: FBT002
        output_format: Annotated[OutputTypes, Option()] = OutputTypes.CLIPBOARD.value,
) -> None:
    """Registers a new client with your server."""
    if not server:
        CredFileProvider.ensure_file()
        creds = CredFileProvider.read_file()
        server = creds.get("default", {}).get("server")
        if not server:
            msg = "No default server found and --server not provided."
            raise ClickException(msg)

    client_id, client_secret = RegisterClient(
        server=server, service_account=service_account, onboarding_key=onboarding_key, description=description,
    )

    if store_in_windows:
        store_windows_credential(client_id=client_id, client_secret=client_secret)
        return

    if output_format == OutputTypes.JSON:
        Console().print({"client_id": client_id, "client_secret": client_secret})
    elif output_format == OutputTypes.TABLE:
        table = Table("Name", "Value")
        table.add_row("Client ID", client_id)
        table.add_row("Client Secret", client_secret)
        Console().print(table)
    else:
        Console().print(f"Client ID: {client_id}")
        pyperclip.copy(client_secret)
        Console().print("Client Secret copied to clipboard.")


@cli.command()
def get_secret(
        context: Context,
        secret_id: int,
        include_username: Annotated[bool, Option(
            "--include-username", help=HelpText.include_username,
        )] = False,  # noqa: FBT002
        output_format: Annotated[OutputTypes, Option(help=HelpText.output_format)] = OutputTypes.CLIPBOARD.value,
) -> None:
    """Gets a secret."""
    secret = context.obj.get_secret(secret_id=secret_id)

    username = secret.get_username()
    password = secret.get_password()

    if output_format == OutputTypes.JSON:
        output = {"password": password}
        if include_username:
            output["username"] = username
    elif output_format == OutputTypes.TABLE:
        output = Table("Type", "Value")
        output.add_row("Password", password)
        if include_username:
            output.add_row("Username", username)
    else:
        pyperclip.copy(password)
        output = f"Secret for {username} copied to clipboard."

    Console().print(output)


@cli.command()
def search_folders(
    context: Context,
    parent_folder_id: Annotated[int, Option(show_default=False, help=HelpText.parent_folder_id)] = None,
    search_text: Annotated[str, Option(show_default=False, help=HelpText.search_text)] = None,
) -> None:
    """Search for accessible folders."""
    params = SearchFoldersParams(
        parent_folder_id=parent_folder_id,
        search_text=search_text,
    )

    folders = context.obj.get_folders(params=params)
    table = Table("Name", "ID", "Path", "Parent Folder ID", "Folder Type ID", "Inherit Permissions")

    for folder in folders.folders:
        table.add_row(
            folder.name, str(folder.folder_id), folder.path, str(folder.parent_folder_id),
            str(folder.folder_type_id), str(folder.inherit_permissions),
        )

    Console().print(table)


@cli.command()
def get_folder(context: Context, folder_id: int) -> None:
    """Get details about a Folder ID."""
    folder_details = context.obj.get_folder_details(folder_id=folder_id)

    table = Table("Folder", f"{folder_details.name} ({folder_details.folder_id})")
    table.add_row("Actions", ", ".join(folder_details.actions), end_section=True)
    table.add_row("Allowed Templates", "\n".join(
        [f"{template.name} (ID: {template.template_id})" for template in folder_details.allowed_templates],
    ))
    Console().print(table)


@cli.command()
def get_template(context: Context, template_id: int) -> None:
    """Get details about a given Template ID."""
    template = context.obj.get_template(template_id=template_id)

    table = Table("Template", f"{template.name} ({template.template_id})")
    for field in template.fields:
        table.add_row("Field Name", field.name)
        table.add_row("Field ID", str(field.secret_template_field_id))
        table.add_row("Display Name", field.display_name)
        table.add_row("Description", field.description)
        table.add_row("Slug", field.field_slug_name)
        table.add_row(
            "Required",
            Text(str(field.is_required), style="bold red" if field.is_required else None),
            end_section=True,
        )
    Console().print(table)


@cli.command(hidden=hide_non_windows())
def store_windows_credential(
        client_id: Annotated[str, Option(help=HelpText.client_id)],
        client_secret: Annotated[str, Option(help=HelpText.client_secret)],
        name: Annotated[str, Option(help=HelpText.windows)] = "dss-cli-client",
) -> None:
    """Stores Client ID and Client Secret in Windows Credential Manager."""
    if Windows.windows_credential_exists(name=name):
        if not confirm(f"Credential '{name}' exists. Are you sure you want to delete it?"):
            raise Abort
        Windows.delete_credential(name=name)

    Windows.set_windows_credential(name=name, client_id=client_id, client_secret=client_secret)
    Console().print(f"Credentials stored under: {name}")


@cli.command()
def search_secrets(
        context: Context,
        recent: Annotated[bool, Option("--recent")] = False,  # noqa: FBT002
        search_text: Annotated[str, Option(show_default=False)] = None,
        folder_id: Annotated[int, Option(show_default=False)] = None,
        secret_template_ids: Annotated[list[int], Option(show_default=False)] = None,
        extra_fields: Annotated[list[SearchSecretsExtraFields], Option(
            "--extra-fields", "-f", show_default=False,
        )] = None,
) -> None:
    """Search available secrets using various parameters."""
    headers = ["Name", "ID", "Template ID", "Template Name", "Folder ID", "Folder Name", "Last Accessed"]
    if extra_fields:
        headers = SearchSecretsExtraFields.add_extra_headers(headers=headers, extra_fields=extra_fields)
    table = Table(*headers)

    params = SearchSecretsParams(
        search_text=search_text,
        folder_id=folder_id,
        secret_template_ids=secret_template_ids,
        scope="Recent" if recent else None,
    )

    secrets = context.obj.search_secrets(params=params)

    for secret_info in secrets.records:
        row = [
            secret_info.name,
            str(secret_info.secret_id),
            str(secret_info.secret_template_id),
            secret_info.secret_template_name,
            str(secret_info.folder_id),
            secret_info.folder_path,
            format_dtg(secret_info.last_accessed),
        ]
        if extra_fields:
            row = SearchSecretsExtraFields.append_extra_data(
                secret_info=secret_info, row=row, extra_fields=extra_fields,
            )
        table.add_row(*row)
    Console().print(table)


@cli.command()
def config(
        profile: Annotated[str, Option(help="The Delinea credentials profile.")] = "default",
        server: Annotated[str, Option(help="Delinea Server", show_default=False)] = None,
        client_id: Annotated[str, Option(help="Delinea Service Client ID", show_default=False)] = None,
        client_secret: Annotated[str, Option(help="Delinea Service Client Secret", show_default=False)] = None,
        windows_credential_name: Annotated[str, Option(
            help="Delinea Service Client Windows Credential",
            show_default=False,
            hidden=hide_non_windows(),
        )] = None,
) -> None:
    """Configure a DSS CLI profile."""
    CredFileProvider.ensure_file()
    creds = CredFileProvider.read_file()
    profile_config = creds.get(profile, {})

    if any([server, client_id, client_secret, windows_credential_name]):
        options = {
            "server": server,
            "client_id": client_id,
            "client_secret": client_secret,
            "windows_credential_name": windows_credential_name,
        }

        for key, val in options.items():
            match val:
                case None:
                    pass
                case _:
                    profile_config[key] = val

    else:
        profile_config["server"] = config_prompt(
            profile_config=profile_config, key="server", message="Delinea Server Name/URL", required=True,
        )

        client_id = config_prompt(profile_config=profile_config, key="client_id", message="Delinea Client ID")
        if client_id:
            profile_config["client_id"] = client_id

            client_secret = config_prompt(
                profile_config=profile_config,
                key="client_secret",
                message="Delinea Client Secret",
                required=bool(client_id),
                prompt_kwargs={"show_default": False, "hide_input": True},
            )
            if client_secret:
                profile_config["client_secret"] = client_secret

        if platform.platform().startswith("Windows"):
            windows_credential_name = config_prompt(
                profile_config=profile_config,
                key="windows_credential_name",
                message="Delinea Windows Credential Name",
            )
            if windows_credential_name:
                profile_config["windows_credential_name"] = windows_credential_name

    creds[profile] = profile_config
    CredFileProvider.write_file(config=creds)


@cli.command()
def login(api_key: Annotated[str, Option(prompt=True, hide_input=True)]) -> None:
    """Log in to DSS using API Key."""
    CredFileProvider.ensure_file()
    creds = CredFileProvider.read_file()
    profile_config = creds.get("default", {})
    if "server" not in profile_config:
        msg = "Server not configured for default profile. Run `dss config` to configure server."
        raise ClickException(msg)
    profile_config["api_key"] = api_key
    creds["default"] = profile_config
    CredFileProvider.write_file(config=creds)


@cli.callback()
def dss(
        context: Context,
        profile: Annotated[str, Option(help="The Delinea credentials profile.")] = "default",
        _: Annotated[bool, Option("--version", callback=version_callback)] = None,
) -> None:
    """Delinea Secret Server CLI."""
    context.obj = SecretServerClient(profile=profile, mode="cli")


def main() -> None:
    """The CLI main entrypoint."""
    cli()


if __name__ == "__main__":
    main()
