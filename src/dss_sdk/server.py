"""The Delinea Secret Server SDK."""
import abc
import functools
import getpass
import os
import typing
import uuid

import click
import httpx

from . import credentials, models

_T = typing.TypeVar("_T")
ClientId = typing.TypeVar("ClientId", bound=str)
ClientSecret = typing.TypeVar("ClientSecret", bound=str)


class SecretServer(abc.ABC):
    """The Secret Server Abstract Class."""

    def __init__(self, provider_chain: credentials.ProviderChain) -> None:
        """Initialize the class.

        The bellow dunder properties will be overwritten by the client implementation.
        """
        self.__provider_chain__ = provider_chain
        self.__token__ = None
        self.__endpoint__ = None

    @property
    @abc.abstractmethod
    def client(self) -> httpx.Client | httpx.AsyncClient:
        """Client abstract property."""
        ...

    @property
    def headers(self) -> dict[str, str]:
        """The headers used by the Delinea API."""
        return {
            "Accept": "application/json",
            "Accept-Language": "en-US",
            "Accept-Charset": "ISO-8859-l,utf-8",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
        }

    @property
    def token(self) -> str:
        """The HTTP Bearer Token."""
        if not self.__token__:
            self.__token__, self.__endpoint__ = self.__provider_chain__.get_endpoint_and_token()
        return self.__token__

    @property
    def endpoint(self) -> str:
        """The Secret Server Endpoint."""
        if not self.__endpoint__:
            self.__token__, self.__endpoint__ = self.__provider_chain__.get_endpoint_and_token()
        return self.__endpoint__


class RegisterClient:
    """Registers a new client with Delinea."""

    def __new__(
            cls,
            server: str,
            service_account: str,
            onboarding_key: str,
            description: str = "",
            *,
            export: bool = False,
    ) -> tuple[ClientId, ClientSecret] | None:
        """Registers the new client and returns the credentials.

        Args:
            server: The Delinea server FQDN/URL.
            service_account: The Delinea Service Account.
            onboarding_key: The onboarding key for the service account.
            description: The description of the client.
            export: If the environment variables should be exported after registration.
        """
        server = cls.__format_server_name__(server=server)
        if not description:
            description = f"dss-sdk-{getpass.getuser()}"

        data = {
            "onboardingKey": onboarding_key,
            "ruleName": service_account,
            "clientId": str(uuid.uuid4()),
            "description": description,
            "name": service_account,
        }
        data = cls.__register__(server=server, data=data)

        if export:
            os.environ["DELINEA_SERVER"] = server
            os.environ["DELINEA_CLIENT_ID"] = data["clientId"]
            os.environ["DELINEA_CLIENT_SECRET"] = data["clientSecret"]
            return None
        client_secret = data["clientSecret"]
        client_id = data["clientId"]
        return client_id, client_secret

    @classmethod
    def __format_server_name__(cls, server: str) -> str:
        """Formats the Delinea server name.

        Args:
            server: The server name/url

        Returns:
            A properly formatted server API url.
        """
        # noinspection HttpUrlsUsage
        if not server.startswith("http://") or server.startswith("https://"):
            server = f"https://{server}"

        if server.endswith("/"):
            # Remove the trailing slash
            server = server[:-1]

        return server

    @classmethod
    def __register__(cls, server: str, data: dict[str, str]) -> dict:
        """Registers the new client.

        Args:
            server: The server name/url
            data: The JSON data request body.

        Returns:
            The JSON response.
        """
        with httpx.Client() as client:
            response = client.post(
                f"{server}/api/v1/sdk-client-accounts",
                headers={
                    "Accept": "application/json",
                    "Accept-Language": "en-US",
                    "Accept-Charset": "ISO-8859-l,utf-8",
                    "Content-Type": "application/json",
                },
                json=data,
            )
            response.raise_for_status()
            return response.json()


class SecretServerClient(SecretServer):
    """The Synchronous Delinea Secret Server Client."""

    def __init__(self, *, profile: str = "", mode: str = "sdk") -> None:
        """Initialize the class.

        Args:
            profile: The credential profile to use.
            mode: The access mode (sdk or cli).
        """
        super().__init__(provider_chain=credentials.ProviderChain(profile=profile))
        if profile:
            self.profile = profile
        self.mode = mode

    @functools.cached_property
    def client(self) -> httpx.Client:
        """Creates and caches the httpx Client."""
        return httpx.Client()

    def __get__(self, url: str, *, params: dict[str, str] | None = None) -> _T:
        """Performs an HTTPX GET.

        Args:
            url: The URL to GET.
            params: The optional query parameters.

        Returns:
            The JSON response. Could be a list or dict, depending on request.
        """
        response = self.client.get(url=url, headers=self.headers, params=params)
        self.__handle_exception__(response=response)
        return response.json()

    def __post__(self, url: str, *, body: dict | None = None) -> dict:
        """Performs an HTTPX POST.

        Args:
            url: The URL to POST.
            body: The optional POST body.

        Returns:
            The JSON response.
        """
        response = self.client.post(url=url, headers=self.headers, json=body)
        self.__handle_exception__(response=response)
        return response.json()

    def __put__(self, url: str, *, body: dict | None = None) -> dict:
        """Performs an HTTPX PUT.

        Args:
            url: The URL to PUT.
            body: The optional PUT body.

        Returns:
            The JSON response.
        """
        response = self.client.put(url=url, headers=self.headers, json=body)
        self.__handle_exception__(response=response)
        return response.json()

    def __handle_exception__(self, response: httpx.Response) -> None:
        """Handle any possible HTTP Exception and print a more helpful message.

        Args:
            response: The HTTPX response.
        """
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            err = response.json()
            err_msg = err.get("message", "No error message found in HTTP exception.")
            if "modelState" in err:
                details = "; ".join(*err["modelState"].values())
                err_msg = f"{err_msg} {details}"

            msg = f"HTTP {e.response.status_code}: {err_msg}"
            if self.mode == "cli":
                raise click.ClickException(msg) from e
            raise ConnectionError(msg) from e

    def search_secrets(self, *, params: models.SearchSecretsParams | None = None) -> models.SecretsInfo:
        """Search Delinea Secrets.

        Args:
            params: The query parameters model.

        Returns:
            The information on available Secrets.
        """
        if not params:
            params = models.SearchSecretsParams()

        response = self.__get__(
            url=f"{self.endpoint}/api/v2/secrets", params=params.model_dump(by_alias=True, exclude_none=True),
        )
        return models.SecretsInfo(**response)

    def get_secret(self, secret_id: int) -> models.Secret:
        """Gets a secret.

        Args:
            secret_id: The ID of the Secret.

        Returns:
            The secret.
        """
        response = self.__get__(url=f"{self.endpoint}/api/v2/secrets/{secret_id}")
        return models.Secret(**response)

    def get_template(self, template_id: int) -> models.SecretTemplate:
        """Get a Secret Template.

        Args:
            template_id: The template ID.

        Returns:
            The SecretTemplate model.
        """
        response = self.__get__(url=f"{self.endpoint}/api/v1/secret-templates/{template_id}")
        return models.SecretTemplate(**response)

    def create_secret(self, secret: models.CreateSecret) -> models.Secret:
        """Create a new secret.

        Args:
            secret: The CreateSecret model.

        Returns:
            The created Secret model.
        """
        response = self.__post__(url=f"{self.endpoint}/api/v1/secrets", body=secret.model_dump(by_alias=True))
        return models.Secret(**response)

    def get_folders(self, params: models.SearchFoldersParams = None) -> models.Folders:
        """Get all accessible and/or filtered folders.

        Args:
            params: The params to filter the response by.

        Returns:
            The Folders model.
        """
        if not params:
            params = models.SearchFoldersParams()
        response = self.__get__(
            url=f"{self.endpoint}/api/v1/folders", params=params.model_dump(by_alias=True, exclude_none=True),
        )
        return models.Folders(folders=response.get("records", []))

    def get_folder_details(self, folder_id: int) -> models.FolderDetails:
        """Get details of a particular folder.

        Args:
            folder_id: The ID of the folder.

        Returns:
            The FolderDetails model.
        """
        response = self.__get__(url=f"{self.endpoint}/api/v1/folder-details/{folder_id}")
        return models.FolderDetails(**response)

    def get_sites(self) -> models.Sites:
        """Get the available sites.

        Returns:
            The Sites model.
        """
        response = self.__get__(url=f"{self.endpoint}/api/v1/sites")
        return models.Sites(sites=response)

    def update_secret(self, secret: models.UpdateSecret) -> models.Secret:
        """Updates various fields of a secret.

        Args:
            secret: The UpdateSecret model containing the fields to update.

        Returns:
            The updated Secret model.
        """
        response = self.__put__(
            url=f"{self.endpoint}/api/v1/secrets/{secret.secret_id}",
            body=secret.model_dump(by_alias=True, exclude_none=True),
        )
        return models.Secret(**response)

    def generate_otp(self, secret_id: int) -> models.OneTimePasscode:
        """Generates an One Time Passcode if the secret supports it.

        Args:
            secret_id (int): The secret ID.

        Returns:
            The One Time Passcode model.
        """
        response = self.__get__(url=f"{self.endpoint}/api/v1/one-time-password-code/{secret_id}")
        return models.OneTimePasscode(**response[0])
