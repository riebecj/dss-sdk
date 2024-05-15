"""The DSS CLI."""
import platform
import time
import typing

import click
import pyperclip
import rich
import rich.table
import rich.text
import typer

from . import credentials, models, utilities
from . import server as ss

cli = typer.Typer()


def config_prompt(
        profile_config: dict,
        key: str,
        message: str,
        *,
        required: bool = False,
        prompt_kwargs: dict | None = None,
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
        new_value = click.prompt(message, default=current_value if current_value else "", **prompt_kwargs)

        if new_value:
            return new_value
        if not new_value and not current_value and required:
            rich.console.Console().print(f"A {key} is required.")
        else:
            return current_value


@cli.command()
def register_client(
        service_account: str,
        onboarding_key: typing.Annotated[str, typer.Option(prompt=True, hide_input=True)],
        description: typing.Annotated[str | None, typer.Option(show_default=False)] = None,
        server: typing.Annotated[str | None, typer.Option()] = None,
        store_in_windows: typing.Annotated[bool | None, typer.Option(
            "--store-in-windows", help=utilities.HelpText.store_in_windows,
            hidden=utilities.hide_non_windows())] = None,
        output_format: typing.Annotated[utilities.OutputTypes, typer.Option()] = utilities.OutputTypes.CLIPBOARD.value,
) -> None:
    """Registers a new client with your server."""
    if not server:
        credentials.CredFileProvider.ensure_file()
        creds = credentials.CredFileProvider.read_file()
        server = creds.get("default", {}).get("server")
        if not server:
            msg = "No default server found and --server not provided."
            raise click.ClickException(msg)

    client_id, client_secret = ss.RegisterClient(
        server=server, service_account=service_account, onboarding_key=onboarding_key, description=description,
    )

    if store_in_windows:
        store_windows_credential(client_id=client_id, client_secret=client_secret)
        return

    if output_format == utilities.OutputTypes.JSON:
        rich.console.Console().print({"client_id": client_id, "client_secret": client_secret})
    elif output_format == utilities.OutputTypes.TABLE:
        table = rich.table.Table("Name", "Value")
        table.add_row("Client ID", client_id)
        table.add_row("Client Secret", client_secret)
        rich.console.Console().print(table)
    else:
        rich.console.Console().print(f"Client ID: {client_id}")
        pyperclip.copy(client_secret)
        rich.console.Console().print("Client Secret copied to clipboard.")


@cli.command()
def get_secret(
        context: click.Context,
        secret_id: int,
        include_username: typing.Annotated[bool | None, typer.Option(
            "--include-username", help=utilities.HelpText.include_username)] = None,
        output_format: typing.Annotated[utilities.OutputTypes, typer.Option(
            help=utilities.HelpText.output_format)] = utilities.OutputTypes.CLIPBOARD.value,
) -> None:
    """Gets a secret."""
    server: ss.SecretServerClient = context.obj
    secret = server.get_secret(secret_id=secret_id)

    username = secret.get_username()
    password = secret.get_password()

    if output_format == utilities.OutputTypes.JSON:
        output = {"password": password}
        if include_username:
            output["username"] = username
    elif output_format == utilities.OutputTypes.TABLE:
        output = rich.table.Table("Type", "Value")
        output.add_row("Password", password)
        if include_username:
            output.add_row("Username", username)
    else:
        pyperclip.copy(password)
        output = f"Secret for {username} copied to clipboard."

    rich.console.Console().print(output)


@cli.command()
def search_folders(
    context: click.Context,
    parent_folder_id: typing.Annotated[int | None, typer.Option(
        show_default=False, help=utilities.HelpText.parent_folder_id)] = None,
    search_text: typing.Annotated[str | None, typer.Option(
        show_default=False, help=utilities.HelpText.search_text)] = None,
) -> None:
    """Search for accessible folders."""
    params = models.SearchFoldersParams(
        parent_folder_id=parent_folder_id,
        search_text=search_text,
    )

    server: ss.SecretServerClient = context.obj
    folders = server.get_folders(params=params)
    table = rich.table.Table("Name", "ID", "Path", "Parent Folder ID", "Folder Type ID", "Inherit Permissions")

    for folder in folders.folders:
        table.add_row(
            folder.name, str(folder.folder_id), folder.path, str(folder.parent_folder_id),
            str(folder.folder_type_id), str(folder.inherit_permissions),
        )

    rich.console.Console().print(table)


@cli.command()
def get_folder(context: click.Context, folder_id: int) -> None:
    """Get details about a Folder ID."""
    server: ss.SecretServerClient = context.obj
    folder_details = server.get_folder_details(folder_id=folder_id)

    table = rich.table.Table("Folder", f"{folder_details.name} ({folder_details.folder_id})")
    table.add_row("Actions", ", ".join(folder_details.actions), end_section=True)
    table.add_row("Allowed Templates", "\n".join(
        [f"{template.name} (ID: {template.template_id})" for template in folder_details.allowed_templates],
    ))
    rich.console.Console().print(table)


@cli.command()
def get_template(context: click.Context, template_id: int) -> None:
    """Get details about a given Template ID."""
    server: ss.SecretServerClient = context.obj
    template = server.get_template(template_id=template_id)

    table = rich.table.Table("Template", f"{template.name} ({template.template_id})")
    for field in template.fields:
        table.add_row("Field Name", field.name)
        table.add_row("Field ID", str(field.secret_template_field_id))
        table.add_row("Display Name", field.display_name)
        table.add_row("Description", field.description)
        table.add_row("Slug", field.field_slug_name)
        table.add_row(
            "Required",
            rich.text.Text(str(field.is_required), style="bold red" if field.is_required else None),
            end_section=True,
        )
    rich.console.Console().print(table)


@cli.command(hidden=utilities.hide_non_windows())
def store_windows_credential(
        client_id: typing.Annotated[str, typer.Option(help=utilities.HelpText.client_id)],
        client_secret: typing.Annotated[str, typer.Option(help=utilities.HelpText.client_secret)],
        name: typing.Annotated[str, typer.Option(help=utilities.HelpText.windows)] = "dss-cli-client",
) -> None:
    """Stores Client ID and Client Secret in credentials.Windows Credential Manager."""
    if credentials.Windows.windows_credential_exists(name=name):
        if not click.confirm(f"Credential '{name}' exists. Are you sure you want to delete it?"):
            raise click.Abort
        credentials.Windows.delete_credential(name=name)

    credentials.Windows.set_windows_credential(name=name, client_id=client_id, client_secret=client_secret)
    rich.console.Console().print(f"Credentials stored under: {name}")


@cli.command()
def search_secrets(
        context: click.Context,
        recent: typing.Annotated[bool, typer.Option("--recent")] = False,  # noqa: FBT002
        search_text: typing.Annotated[str | None, typer.Option(show_default=False)] = None,
        folder_id: typing.Annotated[int | None, typer.Option(show_default=False)] = None,
        secret_template_ids: typing.Annotated[list[int] | None, typer.Option(show_default=False)] = None,
        extra_fields: typing.Annotated[list[utilities.SearchSecretsExtraFields] | None, typer.Option(
            "--extra-fields", "-f", show_default=False)] = None,
) -> None:
    """Search available secrets using various parameters."""
    headers = ["Name", "ID", "Template ID", "Template Name", "Folder ID", "Folder Name", "Last Accessed"]
    if extra_fields:
        headers = utilities.SearchSecretsExtraFields.add_extra_headers(headers=headers, extra_fields=extra_fields)
    table = rich.table.Table(*headers)

    params = models.SearchSecretsParams(
        search_text=search_text,
        folder_id=folder_id,
        secret_template_ids=secret_template_ids,
        scope="Recent" if recent else None,
    )

    server: ss.SecretServerClient = context.obj
    secrets = server.search_secrets(params=params)

    for secret_info in secrets.records:
        row = [
            secret_info.name,
            str(secret_info.secret_id),
            str(secret_info.secret_template_id),
            secret_info.secret_template_name,
            str(secret_info.folder_id),
            secret_info.folder_path,
            utilities.format_dtg(secret_info.last_accessed),
        ]
        if extra_fields:
            row = utilities.SearchSecretsExtraFields.append_extra_data(
                secret_info=secret_info, row=row, extra_fields=extra_fields,
            )
        table.add_row(*row)
    rich.console.Console().print(table)


@cli.command()
def generate_otp(
    context: click.Context,
    secret_id: int,
    min_remaining: typing.Annotated[int, typer.Option(
        help=utilities.HelpText.min_remaining_seconds, callback=utilities.constrained_integer(min=1, max=29))] = 3,
    output_format: typing.Annotated[utilities.OutputTypes, typer.Option(
        help=utilities.HelpText.output_format)] = utilities.OutputTypes.CLIPBOARD.value,
) -> None:
    """Generate an OTP if the secret supports it."""
    server: ss.SecretServerClient = context.obj
    otp = server.generate_otp(secret_id=secret_id)
    if otp.remaining_seconds < min_remaining:
        rich.console.Console().print(f"Waiting {otp.remaining_seconds} to regenerate OTP...")
        time.sleep(otp.remaining_seconds)
    otp = server.generate_otp(secret_id=secret_id)

    if output_format == utilities.OutputTypes.JSON:
        output = otp.model_dump_json(by_alias=True)
    elif output_format == utilities.OutputTypes.TABLE:
        output = rich.table.Table("Name", "Value")
        for key, value in otp.model_dump(by_alias=True).items():
            output.add_row(key.capitalize(), str(value))
    else:
        pyperclip.copy(otp.code)
        output = f"OTP with {otp.remaining_seconds} remaining seconds copied to clipboard."

    rich.console.Console().print(output)


@cli.command()
def config(
        profile: typing.Annotated[str, typer.Option(help="The Delinea credentials profile.")] = "default",
        server: typing.Annotated[str | None, typer.Option(help="Delinea Server", show_default=False)] = None,
        client_id: typing.Annotated[str | None, typer.Option(
            help="Delinea Service Client ID", show_default=False)] = None,
        client_secret: typing.Annotated[str | None, typer.Option(
            help="Delinea Service Client Secret", show_default=False)] = None,
        windows_credential_name: typing.Annotated[str | None, typer.Option(
            help="Delinea Service Client credentials.Windows Credential",
            show_default=False,
            hidden=utilities.hide_non_windows())] = None,
) -> None:
    """Configure a DSS CLI profile."""
    credentials.CredFileProvider.ensure_file()
    creds = credentials.CredFileProvider.read_file()
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

        if platform.platform().startswith("credentials.Windows"):
            windows_credential_name = config_prompt(
                profile_config=profile_config,
                key="windows_credential_name",
                message="Delinea credentials.Windows Credential Name",
            )
            if windows_credential_name:
                profile_config["windows_credential_name"] = windows_credential_name

    creds[profile] = profile_config
    credentials.CredFileProvider.write_file(config=creds)


@cli.command()
def login(api_key: typing.Annotated[str, typer.Option(prompt=True, hide_input=True)]) -> None:
    """Log in to DSS using API Key."""
    credentials.CredFileProvider.ensure_file()
    creds = credentials.CredFileProvider.read_file()
    profile_config = creds.get("default", {})
    if "server" not in profile_config:
        msg = "Server not configured for default profile. Run `dss config` to configure server."
        raise click.ClickException(msg)
    profile_config["api_key"] = api_key
    creds["default"] = profile_config
    credentials.CredFileProvider.write_file(config=creds)


@cli.callback()
def dss(
        context: click.Context,
        profile: typing.Annotated[str, typer.Option(help="The Delinea credentials profile.")] = "default",
        _: typing.Annotated[bool | None, typer.Option("--version", callback=utilities.version_callback)] = None,
) -> None:
    """Delinea Secret Server CLI."""
    context.obj = ss.SecretServerClient(profile=profile, mode="cli")


def main() -> None:
    """The CLI main entrypoint."""
    cli()


if __name__ == "__main__":
    main()
