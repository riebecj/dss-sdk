"""DSS SDK Credential Providers and Chain."""
import os
import platform
from abc import ABC, abstractmethod
from functools import cached_property
from pathlib import Path
from typing import TypeVar

import httpx
import toml
from httpx import HTTPStatusError, Response

from dss.windows_credentials import Windows

Token = TypeVar("Token", bound=str)
Endpoint = TypeVar("Endpoint", bound=str)


class ClientTokenGrantError(Exception):
    """Exception raised when a Client ID/Secret fails to generate an OAuth2 token."""
    def __init__(self, client_id: str, reason: str = None) -> None:
        """Initialize the exception."""
        msg = f"Unable to acquire a token using client credential grant for {client_id}"
        if reason:
            msg = f"{msg}: {reason}"
        super().__init__(msg)


class NoCredentialsFoundError(Exception):
    """Exception raised when the ProviderChain finds no available and configured credentials."""
    def __init__(self) -> None:
        """Initialize the exception."""
        super().__init__("Unable to locate credentials.")


class ServerConfigurationError(Exception):
    """Exception raised when the server isn't configured in a credentials file profile."""
    def __init__(self, path: str) -> None:
        """Initialize the exception."""
        super().__init__(f"Server not configured in {path}")


class InvalidClientError(Exception):
    """Exception raised when Delinea return `invalid_client` error."""
    def __init__(self, client_id: str) -> None:
        """Initialize the exception."""
        super().__init__(f"Client ID '{client_id}' is not valid.")


class Provider(ABC):
    """The base Provider class all providers in the ProviderChain must derive from."""

    @property
    @abstractmethod
    def api_token(self) -> str:
        """Should return an API token (usually gotten from inside Delinea via `User Preferences`)."""
        ...

    @property
    @abstractmethod
    def server(self) -> str:
        """Should return the DSS server name or URL."""
        ...

    @property
    @abstractmethod
    def client_id(self) -> str:
        """Should return a Client ID."""
        ...

    @property
    @abstractmethod
    def client_secret(self) -> str:
        """Should return a Client Secret associated with the Client ID."""
        ...

    @property
    @abstractmethod
    def win_cred(self) -> str:
        """Should return a Windows Credential name."""
        ...

    def client_grant(self) -> dict[str, str]:
        """Formats and returns a `client_credentials` grant."""
        if all([self.client_id, self.client_secret]):
            return {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
        return {}

    @classmethod
    def __format_client_id__(cls, client_id: str) -> str:
        """Formats the Client ID for use in `client_credentials` grant.

        While registering a client returns a UUID, when used in the `client_credentials` grant for obtaining an
        OAuth2 token, it requires the Client ID start with `sdk-client-` followed by the UUID.

        Args:
            client_id: The DSS Client ID.

        Returns:
            The formatted Client ID.
        """
        if client_id and not client_id.startswith("sdk-client-"):
            return f"sdk-client-{client_id}"
        return client_id


class EnvironmentProvider(Provider):
    """Environment Variable Provider."""

    @property
    def server(self) -> str:
        """Returns a configured DSS Server, if any."""
        return os.environ.get("DELINEA_SERVER", "")

    @property
    def client_id(self) -> str:
        """Returns a configured Client ID, if any."""
        return self.__format_client_id__(client_id=os.environ.get("DELINEA_CLIENT_ID", ""))

    @property
    def client_secret(self) -> str:
        """Returns a configured Client Secret, if any."""
        return os.environ.get("DELINEA_CLIENT_SECRET", "")

    @property
    def api_token(self) -> str:
        """Returns a configured API Key, if any."""
        return os.environ.get("DELINEA_API_TOKEN", "")

    @property
    def win_cred(self) -> str:
        """Returns a configured Windows Credential, if any."""
        win_cred_name = os.environ.get("DELINEA_WINDOWS_CREDENTIAL", "")
        if platform.platform().startswith("Windows") and win_cred_name:
            return win_cred_name
        return ""


class CredFileProvider(Provider):
    """Credentials File Provider."""
    cred_file = Path().home() / ".dss" / ".credentials"

    def __init__(self, profile: str = "default") -> None:
        """Initialize the provider.

        Args:
            profile: The profile to use when reading the credentials file.
        """
        self.profile = profile

    @classmethod
    def ensure_file(cls) -> None:
        """Ensures that the credentials file exists, creating an empty one if it doesn't."""
        if not cls.cred_file.exists():
            cls.cred_file.parent.mkdir(exist_ok=True)

            with cls.cred_file.open("wt+") as cred_file:
                cred_file.write(toml.dumps({}))

    @classmethod
    def read_file(cls) -> dict:
        """Public classmethod used by the CLI to read the credentials file.

        Returns:
            The loaded TOML credentials file as a dict.
        """
        with cls.cred_file.open("rt") as cred_file:
            return toml.loads(cred_file.read())

    @classmethod
    def write_file(cls, config: dict) -> None:
        """Public classmethod used by CLI to write changes to the credentials file.

        Args:
            config: The updated config to write.
        """
        with cls.cred_file.open("wt") as cred_file:
            cred_file.write(toml.dumps(config))

    @property
    def server(self) -> str:
        """Returns the DSS server name."""
        server = self.__config__.get(self.profile, {}).get("server", "")
        if not server:
            raise ServerConfigurationError(path=str(self.cred_file))
        return server

    @property
    def win_cred(self) -> str:
        """Returns a configured Windows Credential, if any."""
        win_cred_name = self.__config__.get(self.profile, {}).get("win_cred", "")
        if platform.platform().startswith("Windows") and win_cred_name:
            return win_cred_name
        return ""

    @property
    def client_id(self) -> str:
        """Returns a configured Client ID, if any."""
        return self.__format_client_id__(client_id=self.__config__.get(self.profile, {}).get("client_id", ""))

    @property
    def client_secret(self) -> str:
        """Returns a configured Client Secret, if any."""
        return self.__config__.get(self.profile, {}).get("client_secret", "")

    @property
    def api_token(self) -> str:
        """Returns a configured API key, if any."""
        return self.__config__.get(self.profile, {}).get("api_key", "")

    @cached_property
    def __config__(self) -> dict[str, str | dict]:
        """Private method used to read the credentials file."""
        try:
            with self.cred_file.open("rt") as credential_file:
                _data = credential_file.read()
        except FileNotFoundError:
            return {}
        else:
            return toml.loads(_data)


class ProviderChain:
    """The ProviderChain class is the single entrypoint into finding available credentials.

    In some instances, like in automation, it is easier and more secure to read them from
    environment variables. In local usage by a user, it is easier to get the API Key from User Preferences inside
    Delinea and use the `dss login` command. This attempts to read from multiple places until it finds properly
    configured credentials.

    For those wishing to provide their own Provider, just create a subclassed instance of `Provider` and `insert` it
    into the `providers` property after initializing the class.

    Example:
        ```python3
        from dss.credentials import Provider, ProviderChain
        from dss.server import SecretServerClient

        class MyProvider(Provider):
            ...
            # Be sure to implement all required abstract methods.

        def main():
            provider_chain = ProviderChain()
            provider_chain.providers.insert(0, MyProvider())
            client = SecretServerClient(provider_chain=provider_chain)
            ...
            # Do something with the client that can acquire credentials from `MyProvider`

        ```
        In the above example, we can see that we need to implement all abstract methods from `Provider` (not done here),
        and an instance of `MyProvider` was inserted at the `0` index. This means that `MyProvider` will be the first
        provider used to attempt to acquire credentials.

        We then pass it into the `SecretServerClient` and then make some API calls. When the call attempts to get the
        OAuth2 token, it will use call the `ProviderChain`'s `get_endpoint_and_token()` method.
    """
    def __init__(self, profile: str) -> None:
        """Initialize the provider chain.

        Args:
            profile: The profile to use for the file provider.
        """
        self.providers = [
            EnvironmentProvider(),
            CredFileProvider(profile=profile),
        ]

    def get_endpoint_and_token(self) -> tuple[Token, Endpoint]:
        """Public method that gets the OAuth2 token and configured endpoint.

        Returns:
            The OAuth2 Token and configured Endpoint.
        """
        for provider in self.providers:
            if provider.api_token:
                return provider.api_token, self.__get_endpoint__(provider=provider)

            if all([provider.client_id, provider.client_secret]):
                endpoint = self.__get_endpoint__(provider=provider)
                return self.__get_access_token__(provider=provider, endpoint=endpoint), endpoint

            if provider.win_cred and Windows.windows_credential_exists(name=provider.win_cred):
                endpoint = self.__get_endpoint__(provider=provider)
                return self.__get_access_token_from_windows__(provider=provider, endpoint=endpoint), endpoint

        raise NoCredentialsFoundError

    @classmethod
    def __get_endpoint__(cls, provider: Provider) -> str:
        """Gets the configured DSS endpoint.

        Args:
            provider: The Provider whose server config to use.

        Returns:
            The configured DSS endpoint.
        """
        server = provider.server
        # noinspection HttpUrlsUsage
        if not server.startswith("http://") or server.startswith("https://"):
            server = f"https://{provider.server}"

        if server.endswith("/"):
            # Remove the trailing slash
            server = provider.server[:-1]

        return server

    @cached_property
    def __client__(self) -> httpx.Client:
        """The cached HTTPX Client used for getting the token."""
        return httpx.Client()

    def __get_access_token_from_windows__(self, endpoint: str, provider: Provider) -> str:
        """Get an access token using a Windows Credential.

        Args:
            endpoint: The configured DSS endpoint.
            provider: The Provider whose Windows Credential to use.

        Returns:
            The OAuth2 Token.
        """
        client_id, client_secret = Windows.get_from_windows_credential(name=provider.win_cred)
        grant = provider.client_grant()
        grant["client_id"] = client_id
        grant["client_secret"] = client_secret
        response = self.__auth_token_call__(endpoint=endpoint, grant=grant)
        try:
            response.raise_for_status()
        except HTTPStatusError as err:
            reason = err.response.json().get("error", "No error message received")
            raise ClientTokenGrantError(client_id=client_id, reason=reason) from err
        else:
            return response.json()["access_token"]

    def __get_access_token__(self, endpoint: str, provider: Provider) -> str:
        """Get an access token.

        Args:
            endpoint: The configured DSS endpoint.
            provider: The provider whose credentials to use.

        Returns:
            The OAuth2 Token.
        """
        response = self.__auth_token_call__(endpoint=endpoint, grant=provider.client_grant())

        try:
            response.raise_for_status()
        except HTTPStatusError as err:
            reason = err.response.json().get("error", "No error message received")
            raise ClientTokenGrantError(client_id=provider.client_id, reason=reason) from err
        else:
            return response.json()["access_token"]

    def __auth_token_call__(self, endpoint: str, grant: dict[str, str]) -> Response:
        """HTTP Post call to get an OAuth2 token.

        Args:
            endpoint: The configured DSS endpoint.
            grant: The formatted grant body.

        Returns:
            The HTTPX Response.
        """
        return self.__client__.post(
            f"{endpoint}/oauth2/token",
            headers={
                "Accept": "application/json",
                "Accept-Language": "en-US",
                "Accept-Charset": "ISO-8859-l,utf-8",
            },
            data=grant,
        )
