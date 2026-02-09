"""The Delinea Secret Server SDK."""

import os
import ssl
from json import JSONDecodeError

import click
import httpx

from dss_sdk import credentials, models


class SecretServer:
    """The Secret Server Abstract Class."""

    def __init__(self, provider_chain: credentials.ProviderChain) -> None:
        """Initialize the class."""
        ctx = ssl.create_default_context(cafile=os.environ.get("DSS_CA_CERTS"))
        self.client = httpx.Client(verify=ctx)
        self._token, self._endpoint = provider_chain.resolve()

    @property
    def headers(self) -> dict[str, str]:
        """The headers used by the Delinea API."""
        return {
            "Accept": "application/json",
            "Accept-Language": "en-US",
            "Accept-Charset": "ISO-8859-l,utf-8",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._token}",
        }


class SecretServerClient(SecretServer):
    """The Synchronous Delinea Secret Server Client."""

    def __init__(self, *, profile: str = "", mode: str = "sdk") -> None:
        """Initialize the class."""
        super().__init__(provider_chain=credentials.ProviderChain(profile=profile))
        if profile:
            self.profile = profile
        self.mode = mode

    def __get__(self, uri: str, *, params: dict[str, str] | None = None) -> dict:
        """Performs an HTTPX GET."""
        response = self.client.get(url=f"{self._endpoint}/api/{uri}", headers=self.headers, params=params)
        self.__handle_exception__(response=response)
        return response.json()

    def __post__(self, uri: str, *, body: dict | None = None) -> dict:
        """Performs an HTTPX POST."""
        response = self.client.post(url=f"{self._endpoint}/api/{uri}", headers=self.headers, json=body)
        self.__handle_exception__(response=response)
        return response.json()

    def __put__(self, uri: str, *, body: dict | None = None) -> dict:
        """Performs an HTTPX PUT."""
        response = self.client.put(url=f"{self._endpoint}/api/{uri}", headers=self.headers, json=body)
        self.__handle_exception__(response=response)
        return response.json()

    def __handle_exception__(self, response: httpx.Response) -> None:
        """Handle any possible HTTP Exception and print a more helpful message."""
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            try:
                err = response.json()
            except JSONDecodeError:
                err = {}
            err_msg = err.get("message", "No error message found in HTTP exception.")
            if "modelState" in err:
                details = "; ".join(*err["modelState"].values())
                err_msg = f"{err_msg} {details}"

            msg = f"HTTP {e.response.status_code}: {err_msg}"
            if self.mode == "cli":
                raise click.ClickException(msg) from e
            raise ConnectionError(msg) from e

    def search_secrets(self, *, params: models.SearchSecretsParams | None = None) -> models.SecretsInfo:
        """Search Delinea Secrets."""
        if not params:
            params = models.SearchSecretsParams()
        response = self.__get__(uri="v2/secrets", params=params.model_dump(by_alias=True, exclude_none=True))
        return models.SecretsInfo(**response)

    def get_secret(self, secret_id: int) -> models.Secret:
        """Gets a secret."""
        response = self.__get__(uri=f"v2/secrets/{secret_id}")
        return models.Secret(**response)

    def get_template(self, template_id: int) -> models.SecretTemplate:
        """Get a Secret Template."""
        response = self.__get__(uri=f"v1/secret-templates/{template_id}")
        return models.SecretTemplate(**response)

    def create_secret(self, secret: models.CreateSecret) -> models.Secret:
        """Create a new secret."""
        response = self.__post__(uri="v1/secrets", body=secret.model_dump(by_alias=True))
        return models.Secret(**response)

    def get_folders(self, params: models.SearchFoldersParams = None) -> models.Folders:
        """Get all accessible and/or filtered folders."""
        if not params:
            params = models.SearchFoldersParams()
        response = self.__get__(uri="v1/folders", params=params.model_dump(by_alias=True, exclude_none=True))
        return models.Folders(folders=response.get("records", []))

    def get_folder_details(self, folder_id: int) -> models.FolderDetails:
        """Get details of a particular folder."""
        response = self.__get__(uri=f"v1/folder-details/{folder_id}")
        return models.FolderDetails(**response)

    def get_sites(self) -> models.Sites:
        """Get the available sites."""
        response = self.__get__(uri="v1/sites")
        return models.Sites(sites=response)

    def update_secret(self, secret: models.UpdateSecret) -> models.Secret:
        """Updates various fields of a secret."""
        body = secret.model_dump(by_alias=True, exclude_none=True)
        response = self.__put__(url=f"v1/secrets/{secret.secret_id}", body=body)
        return models.Secret(**response)

    def generate_otp(self, secret_id: int) -> models.OneTimePasscode:
        """Generates an One Time Passcode if the secret supports it."""
        response = self.__get__(uri=f"v1/one-time-password-code/{secret_id}")
        return models.OneTimePasscode(**response[0])
