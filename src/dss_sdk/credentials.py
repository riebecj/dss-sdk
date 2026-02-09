"""DSS SDK Credential Providers and Chain."""

import abc
import functools
import os
import pathlib
import platform
import shelve
import ssl
import subprocess
import time
import tomllib
import typing
from json import JSONDecodeError

import httpx

from dss_sdk import exceptions, utilities

Token = typing.TypeVar("Token", bound=str)
Endpoint = typing.TypeVar("Endpoint", bound=str)


class Provider(abc.ABC):
    """The base Provider class all providers in the ProviderChain must derive from."""

    @property
    @abc.abstractmethod
    def api_token(self) -> str:
        """Should return an API token (usually gotten from inside Delinea via `User Preferences`)."""

    @property
    @abc.abstractmethod
    def tenant_id(self) -> str:
        """Should return the Delinea tenant ID."""

    @property
    @abc.abstractmethod
    def client_id(self) -> str:
        """Should return a Client ID."""

    @property
    @abc.abstractmethod
    def client_secret(self) -> str:
        """Should return a Client Secret associated with the Client ID."""

    @property
    @abc.abstractmethod
    def win_cred(self) -> str:
        """Should return a Windows Credential name."""

    @property
    def resolveable(self) -> bool:
        """Returns True if tenant_id, client_id, and client_secret are all set."""
        return all([self.tenant_id, self.client_id, self.client_secret]) or all([self.tenant_id, self.win_cred])

    def client_grant(self) -> dict[str, str]:
        """Formats and returns a `client_credentials` grant."""
        if self.resolveable:
            if self.win_cred:
                client_id, client_secret = Windows.get_from_windows_credential(name=self.win_cred)
                return {
                    "grant_type": "client_credentials",
                    "scope": "xpmheadless",
                    "client_id": client_id,
                    "client_secret": client_secret,
                }
            return {
                "grant_type": "client_credentials",
                "scope": "xpmheadless",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
        return {}


class EnvironmentProvider(Provider):
    """Environment Variable Provider."""

    @property
    def tenant_id(self) -> str:
        """Returns a configured DSS Server, if any."""
        return os.environ.get(utilities.EnvironmentVariables.TENANT_ID.value, "")

    @property
    def client_id(self) -> str:
        """Returns a configured Client ID, if any."""
        return os.environ.get(utilities.EnvironmentVariables.CLIENT_ID.value, "")

    @property
    def client_secret(self) -> str:
        """Returns a configured Client Secret, if any."""
        return os.environ.get(utilities.EnvironmentVariables.CLIENT_SECRET.value, "")

    @property
    def api_token(self) -> str:
        """Returns a configured API Key, if any."""
        return os.environ.get(utilities.EnvironmentVariables.API_TOKEN.value, "")

    @property
    def win_cred(self) -> str:
        """Returns a configured Windows Credential, if any."""
        win_cred_name = os.environ.get(utilities.EnvironmentVariables.WINDOWS_CREDENTIAL.value, "")
        if platform.platform().startswith("Windows") and win_cred_name:
            return win_cred_name
        return ""


class CredFileProvider(Provider):
    """Credentials File Provider."""

    cred_file = pathlib.Path().home() / ".dss" / ".credentials"

    def __init__(self, profile: str = "default") -> None:
        """Initialize the provider."""
        self.profile = profile
        self.cred_file.parent.mkdir(exist_ok=True)

    @classmethod
    def read_file(cls) -> dict:
        """Public classmethod used by the CLI to read the credentials file."""
        cls.cred_file.parent.mkdir(exist_ok=True)
        with cls.cred_file.open("rt") as cred_file:
            return tomllib.loads(cred_file.read())

    @classmethod
    def _dump_toml(cls, data: dict, table: str = "") -> str:
        """Dump TOML credential data to file."""
        toml = []
        for key, value in data.items():
            if isinstance(value, dict):
                table_key = f"{table}.{key}" if table else key
                toml.append(f"\n[{table_key}]\n{cls._dump_toml(value, table_key)}")
            else:
                toml.append(f"{key} = '{value}'")
        return "\n".join(toml)

    @classmethod
    def write_file(cls, config: dict) -> None:
        """Public classmethod used by CLI to write changes to the credentials file."""
        with cls.cred_file.open("wt+") as cred_file:
            cred_file.write(cls._dump_toml(config))

    @property
    def tenant_id(self) -> str:
        """Returns the DSS Tenant ID."""
        return self.__config__.get(self.profile, {}).get("tenant_id", "")

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
        return self.__config__.get(self.profile, {}).get("client_id", "")

    @property
    def client_secret(self) -> str:
        """Returns a configured Client Secret, if any."""
        return self.__config__.get(self.profile, {}).get("client_secret", "")

    @property
    def api_token(self) -> str:
        """Returns a configured API key, if any."""
        return self.__config__.get(self.profile, {}).get("api_key", "")

    @functools.cached_property
    def __config__(self) -> dict[str, str | dict]:
        """Private method used to read the credentials file."""
        return self.read_file()


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

    _cache_ = pathlib.Path.home() / ".dss" / ".cache"

    def __init__(self, profile: str) -> None:
        """Initialize the provider chain."""
        self._cache_.parent.mkdir(exist_ok=True)
        self.providers: list[Provider] = [
            EnvironmentProvider(),
            CredFileProvider(profile=profile),
        ]

    @functools.cached_property
    def __client__(self) -> httpx.Client:
        """The cached HTTPX Client used for getting the token."""
        ctx = ssl.create_default_context(cafile=os.environ.get("DSS_CA_CERTS"))
        return httpx.Client(verify=ctx)

    def resolve(self) -> tuple[Token, Endpoint]:
        """Attempts to resolve and return a valid token and endpoint from the available credential providers."""
        for provider in self.providers:
            if provider.api_token:
                return provider.api_token, self.__get_endpoint__(provider=provider, access_token=provider.api_token)

            if provider.resolveable:
                return self.__resolve_provider__(provider=provider)

        raise exceptions.NoCredentialsFoundError

    def __resolve_provider__(self, provider: Provider) -> tuple[Token, Endpoint]:
        """Resolve and return a valid token and endpoint for the given provider."""
        real_cache = self._cache_.parent / f"{self._cache_}.db"
        if real_cache.exists():
            try:
                return self.__get_from_cache__(provider=provider)
            except exceptions.CredentialsExpiredError:
                real_cache.unlink(missing_ok=True)
        access_token = self.__get_access_token__(provider=provider)
        return access_token, self.__get_endpoint__(provider=provider, access_token=access_token)

    def __get_from_cache__(self, provider: Provider) -> tuple[Token, Endpoint]:
        """Retrieve token and endpoint from cache if valid, otherwise refresh or raise expiration error."""
        with shelve.open(str(self._cache_)) as _cache:  # noqa: S301
            token_expired = float(_cache["expires_in"]) < time.time()
            session_expired = float(_cache["session_expires_in"]) < time.time()
            if not token_expired:
                return _cache["access_token"], _cache["server_url"]
            if token_expired and not session_expired:
                return self.__get_access_token__(
                    provider=provider,
                    access_token=_cache["access_token"],
                    refresh_token=_cache["refresh_token"],
                ), _cache["server_url"]
        raise exceptions.CredentialsExpiredError

    def __save_to_cache__(self, data: dict[str, str | int]) -> None:
        """Save credential data to the cache file."""
        with shelve.open(str(self._cache_), writeback=True) as _cache:  # noqa: S301
            now_unix = time.time()
            for key, value in data.items():
                _cache[key] = value
                if key in ("expires_in", "session_expires_in"):
                    _cache[key] = value - 5 + now_unix

    def __get_endpoint__(self, provider: Provider, access_token: str) -> str:
        """Gets the global DSS endpoint."""
        response = self.__client__.get(
            f"https://{provider.tenant_id}.delinea.app/vaultbroker/api/vaults/global-default-cloud-url",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
        server_url = response.content.decode().replace('"', "")

        if server_url.endswith("/"):
            # Remove the trailing slash
            server_url = server_url[:-1]

        self.__save_to_cache__(data={"server_url": server_url})
        return server_url

    def __get_access_token__(self, provider: Provider, access_token: str = "", refresh_token: str = "") -> str:
        """Gets or refreshes an access token."""
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Accept-Language": "en-US",
            "Accept-Charset": "ISO-8859-l,utf-8",
        }
        data = provider.client_grant()
        if access_token and refresh_token:
            headers["Authorization"] = f"Bearer {access_token}"
            data = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }

        try:
            response = self.__client__.post(
                url=f"https://{provider.tenant_id}.delinea.app/identity/api/oauth2/token/xpmplatform",
                headers=headers,
                data=data,
                follow_redirects=True,
                timeout=10,
            )
            response.raise_for_status()
            data: dict = response.json()
        except httpx.HTTPStatusError as err:
            try:
                error: dict = err.response.json()
            except JSONDecodeError:
                error = {}
            reason = error.get("error", "No error message received")
            raise exceptions.ClientTokenGrantError(client_id=provider.client_id, reason=reason) from err
        else:
            self.__save_to_cache__(data=data)
            return data["access_token"]


class Powershell:
    """Abstraction around generating Powershell commands.

    All functions except for the `command` property return the object itself to allow for command chaining like:

    ```python3
    ps = Powershell().find_all_by_resource(
        name="name", save_as="myVar"
    ).retrieve_password(
        from_var="myVar"
    ).access_property(
        var="myVar", prop="password"
    )
    print(ps.command)
    ```
    """

    import_and_create_password_vault: typing.Final = (
        "[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];"  # noqa: S105
        "$vault = New-Object Windows.Security.Credentials.PasswordVault;"
    )

    def __init__(self) -> None:
        """Initialize the class."""
        self.__commands__ = [self.import_and_create_password_vault]

    def find_all_by_resource(self, name: str, save_as: str, *, select_first: bool = True) -> "Powershell":
        """Finds all credentials with the given name."""
        _pipe = ""
        if select_first:
            _pipe = " | select -First 1"

        self.__commands__.append(f"${save_as} = $vault.FindAllByResource('{name}'){_pipe}")
        return self

    def retrieve_password(self, from_var: str) -> "Powershell":
        """Retrieve the password for a powershell variable."""
        self.__commands__.append(f"${from_var}.retrievePassword()")
        return self

    def retrieve_cred(self, from_var: str, save_as: str) -> "Powershell":
        """Retrieve the credential object from a variable containing the resource and username of the cred."""
        self.__commands__.append(f"${save_as} = $vault.Retrieve(${from_var}.resource, ${from_var}.username)")
        return self

    def remove_cred(self, var: str) -> "Powershell":
        """Remove a credential from Windows Credential Manager."""
        self.__commands__.append(f"$vault.Remove(${var})")
        return self

    def access_property(self, var: str, prop: str) -> "Powershell":
        """Attempt to access a property of a variable."""
        self.__commands__.append(f"${var}.{prop}")
        return self

    def create_credential(self, name: str, username: str, password: str, save_as: str) -> "Powershell":
        """Create a new PasswordCredential object for storing in Windows Credential Manager."""
        new_cred_object = "New-Object Windows.Security.Credentials.PasswordCredential"
        self.__commands__.append(f"${save_as} = {new_cred_object}('{name}', '{username}', '{password}')")
        return self

    def add_cred(self, var: str) -> "Powershell":
        """Add a new credential."""
        self.__commands__.append(f"$vault.Add(${var})")
        return self

    @property
    def command(self) -> str:
        """Formats and returns the Powershell commands as a single script/string."""
        return ";".join(self.__commands__)


class Windows:
    """Abstraction around interacting with Windows Credential Manager / Password Vault."""

    @classmethod
    def get_from_windows_credential(cls, name: str) -> tuple[str, str]:
        """Get the windows credential."""
        powershell = (
            Powershell()
            .find_all_by_resource(
                name=name,
                save_as="cred",
            )
            .retrieve_password(
                from_var="cred",
            )
            .access_property(
                var="cred",
                prop="userName",
            )
            .access_property(
                var="cred",
                prop="password",
            )
        )

        output = subprocess.check_output(["powershell.exe", powershell.command]).decode()  # noqa: S603, S607

        if "Exception" in output:
            return "", ""

        client_id, client_secret, *_ = output.split("\n")
        return client_id, client_secret

    @classmethod
    def delete_credential(cls, name: str) -> None:
        """Deletes a windows credential."""
        powershell = (
            Powershell()
            .find_all_by_resource(
                name=name,
                save_as="c",
            )
            .retrieve_cred(
                from_var="c",
                save_as="cred",
            )
            .remove_cred(
                var="cred",
            )
        )

        output = subprocess.check_output(["powershell.exe", powershell.command]).decode()  # noqa: S603, S607
        if "Exception" in output:
            raise exceptions.DeleteCredentialError(output=output)

        print(f"Old credential '{name}' deleted.")  # noqa: T201

    @classmethod
    def windows_credential_exists(cls, name: str) -> bool:
        """Check if a credential exists."""
        powershell = (
            Powershell()
            .find_all_by_resource(
                name=name,
                save_as="cred",
            )
            .access_property(
                var="cred",
                prop="resource",
            )
        )
        try:
            subprocess.check_output(["powershell.exe", powershell.command]).decode()  # noqa: S603, S607
        except subprocess.CalledProcessError:
            return False
        else:
            return True

    @classmethod
    def set_windows_credential(cls, name: str, client_id: str, client_secret: str) -> None:
        """Sets a new windows credential."""
        powershell = (
            Powershell()
            .create_credential(
                name=name,
                username=client_id,
                password=client_secret,
                save_as="cred",
            )
            .add_cred(
                var="cred",
            )
        )

        output = subprocess.check_output(["powershell.exe", powershell.command]).decode()  # noqa: S603, S607
        if "Exception" in output:
            raise exceptions.SetCredentialError(output=output)
