"""The DSS CLI."""
from dataclasses import asdict
from typing import Annotated

import pyperclip
from click import Abort, Context, MissingParameter, confirm
from rich import print
from rich.console import Console
from rich.table import Table
from typer import BadParameter, Option, Typer

from dss.server import RegisterClient, SecretServerClient
from dss.utilities import HelpText, OutputTypes, assert_windows, format_dtg, version_callback
from dss.windows_credentials import Windows

cli = Typer()
state = {}


@cli.command()
def register_client(
        service_account: Annotated[str, Option()],
        onboarding_key: Annotated[str, Option()],
        description: Annotated[str, Option()] = "Delinea Python SDK",
        store_in_windows: Annotated[bool, Option(
            "--store-in-windows",
            help="Store the registered client ID and secret as Windows credentials.",
            callback=assert_windows,
        )] = False,  # noqa: FBT002
        output_format: Annotated[OutputTypes, Option()] = OutputTypes.CLIPBOARD.value,
) -> None:
    """Registers a new client with your server."""
    credentials = RegisterClient(
        server=state["server"], service_account=service_account, onboarding_key=onboarding_key, description=description,
    )

    if store_in_windows:
        store_windows_credential(client_id=credentials.client_id, client_secret=credentials.client_secret)
        return

    if output_format == OutputTypes.JSON:
        print(asdict(credentials))
    elif output_format == OutputTypes.TABLE:
        table = Table("Name", "Value")
        table.add_row("Client ID", credentials.client_id)
        table.add_row("Client Secret", credentials.client_secret)
        Console().print(table)
    else:
        print(f"Client ID: {credentials.client_id}")
        pyperclip.copy(credentials.client_secret)
        print("Client Secret copied to clipboard.")


@cli.command()
def get_secret(
        secret_id: int,
        include_username: Annotated[bool, Option(
            "--include-username", help=HelpText.include_username,
        )] = False,  # noqa: FBT002
        output_format: Annotated[OutputTypes, Option(help=HelpText.output_format)] = OutputTypes.CLIPBOARD.value,
) -> None:
    """Gets a secret."""
    secret = SecretServerClient(
        server=state["server"], client_id=state["client_id"], client_secret=state["client_secret"], mode="cli",
    ).get_secret(secret_id=secret_id)

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
def store_windows_credential(
        client_id: Annotated[str, Option(
            help="The client ID registered with your Delinea server.",
            callback=assert_windows,
        )],
        client_secret: Annotated[str, Option(
            help="The client secret for the specified client ID registered with your Delinea server.",
        )],
        name: Annotated[str, Option(help="The name to use in Windows credentials.")] = "dss-cli-client",
) -> None:
    """Stores Client ID and Client Secret in Windows Credential Manager."""
    if Windows.windows_credential_exists(name=name):
        if not confirm(f"Credential '{name}' exists. Are you sure you want to delete it?"):
            raise Abort
        Windows.delete_credential(name=name)

    Windows.set_windows_credential(name=name, client_id=client_id, client_secret=client_secret)
    print(f"Credentials stored under: {name}")


@cli.command()
def search_secrets(
        recent: Annotated[bool, Option("--recent")] = False,  # noqa: FBT002
        search_text: Annotated[str, Option()] = None,
        folder_id: Annotated[int, Option()] = None,
        secret_template_ids: Annotated[list[int], Option()] = None,
) -> None:
    """Search available secrets using various parameters."""
    params = {}

    if search_text:
        params["filter.searchText"] = search_text
    if folder_id:
        params["filter.folderId"] = folder_id
    if secret_template_ids:
        params["filter.secretTemplateIdsCombined"] = ",".join([str(template_id) for template_id in secret_template_ids])
    if recent:
        params["filter.scope"] = "Recent"

    secrets = SecretServerClient(
        server=state["server"], client_id=state["client_id"], client_secret=state["client_secret"], mode="cli",
    ).search_secrets(params=params)
    table = Table("Name", "ID", "Template ID", "Template Name", "Folder ID", "Folder Name", "Last Accessed")
    for secret in secrets:
        table.add_row(
            secret.name, str(secret.id), str(secret.secretTemplateId), secret.secretTemplateName,
            str(secret.folderId), secret.folderPath, format_dtg(secret.lastAccessed),
        )
    Console().print(table)


# noinspection PyUnusedLocal
@cli.callback()
def dss(
        context: Context,
        server: Annotated[str, Option(envvar="DELINEA_SERVER", help=HelpText.server)],
        client_id: Annotated[str, Option(envvar="DELINEA_CLIENT_ID", help=HelpText.client_id)] = None,
        client_secret: Annotated[str, Option(envvar="DELINEA_CLIENT_SECRET", help=HelpText.client_secret)] = None,
        windows_credential: Annotated[str, Option(
            envvar="DELINEA_WINDOWS_CREDENTIAL", help=HelpText.windows, callback=assert_windows,
        )] = None,
        _: Annotated[bool | None, Option("--version", callback=version_callback)] = None,
) -> None:
    """Delinea Secret Server CLI."""
    if context.invoked_subcommand in ["register-client", "store-windows-credential"]:
        return

    state["server"] = server
    if windows_credential:
        if any([client_id, client_secret]):
            msg = "Cannot use `--windows-credential` with `--client-id` and `--client-secret`."
            raise BadParameter(msg)
        windows_client_id, windows_client_secret = Windows.get_from_windows_credential(name=windows_credential)
        if not all([windows_client_id, windows_client_secret]):
            msg = f"Unable to find Windows credentials for: {windows_credential}"
            raise BadParameter(msg)
        state["client_id"] = windows_client_id
        state["client_secret"] = windows_client_secret
    elif not all([client_id, client_secret]):
        msg = "Missing option `--client-id` and/or `--client-secret`."
        raise MissingParameter(msg)
    else:
        state["client_id"] = client_id
        state["client_secret"] = client_secret


def main() -> None:
    """The CLI main entrypoint."""
    cli()


if __name__ == "__main__":
    main()
