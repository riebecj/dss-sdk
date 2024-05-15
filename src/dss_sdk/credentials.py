"""DSS SDK Credential Providers and Chain."""
import abc
import functools
import os
import pathlib
import platform
import subprocess
import typing

import httpx
import toml

Token = typing.TypeVar("Token", bound=str)
Endpoint = typing.TypeVar("Endpoint", bound=str)


class ClientTokenGrantError(Exception):
    """Exception raised when a Client ID/Secret fails to generate an OAuth2 token."""
    def __init__(self, client_id: str, reason: str = "") -> None:
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


class Provider(abc.ABC):
    """The base Provider class all providers in the ProviderChain must derive from."""

    @property
    @abc.abstractmethod
    def api_token(self) -> str:
        """Should return an API token (usually gotten from inside Delinea via `User Preferences`)."""
        ...

    @property
    @abc.abstractmethod
    def server(self) -> str:
        """Should return the DSS server name or URL."""
        ...

    @property
    @abc.abstractmethod
    def client_id(self) -> str:
        """Should return a Client ID."""
        ...

    @property
    @abc.abstractmethod
    def client_secret(self) -> str:
        """Should return a Client Secret associated with the Client ID."""
        ...

    @property
    @abc.abstractmethod
    def win_cred(self) -> str:
        """Should return a Windows Credential name."""
        ...

    def client_grant(self) -> dict[str, str]:
        """Formats and returns a `client_credentials` grant."""
        if all([self.client_id, self.client_secret]):
            return {
                "grant_type": "client_credentials",
                "client_id": self.__format_client_id__(client_id=self.client_id),
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
        return os.environ.get("DELINEA_CLIENT_ID", "")

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
    cred_file = pathlib.Path().home() / ".dss" / ".credentials"

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

    __provider_in_use__: Provider


    def __init__(self, profile: str) -> None:
        """Initialize the provider chain.

        Args:
            profile: The profile to use for the file provider.
        """
        self.providers = [
            EnvironmentProvider(),
            CredFileProvider(profile=profile),
        ]

    @property
    def current_provider(self) -> Provider:
        """Returns the current provider being used."""
        return self.__provider_in_use__

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

    def __get_endpoint__(self, provider: Provider) -> str:
        """Gets the configured DSS endpoint.

        Args:
            provider: The Provider whose server config to use.

        Returns:
            The configured DSS endpoint.
        """
        server = provider.server
        # noinspection HttpUrlsUsage
        if not any([server.startswith("http://"), server.startswith("https://")]):
            server = f"https://{provider.server}"

        if server.endswith("/"):
            # Remove the trailing slash
            server = provider.server[:-1]

        self.__provider_in_use__ = provider
        return server

    @functools.cached_property
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
        except httpx.HTTPStatusError as err:
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
        except httpx.HTTPStatusError as err:
            reason = err.response.json().get("error", "No error message received")
            raise ClientTokenGrantError(client_id=provider.client_id, reason=reason) from err
        else:
            return response.json()["access_token"]

    def __auth_token_call__(self, endpoint: str, grant: dict[str, str]) -> httpx.Response:
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


class DeleteCredentialError(Exception):
    """Delete Credential Exception."""
    def __init__(self, output: str) -> None:
        """Initialize exception."""
        super().__init__(f"Exception caught when attempting to delete credential: \n{output}")


class SetCredentialError(Exception):
    """Set Credential Exception."""
    def __init__(self, output: str) -> None:
        """Initialize exception."""
        super().__init__(f"Exception caught when attempting to create credential: \n{output}")


class Powershell:
    """Abstraction around generating Powershell commands.

    All functions except for the `command` property return the object itself to allow for command chaining like:

    ```python3
    ps = Powershell().find_all_by_resource(
        name="name", save_as="myVar"
    ).retrieve_password(
        from_var="myVar"
    ).write_host(
        var="myVar", prop="password"
    )
    print(ps.command)
    ```
    """
    import_and_create_password_vault: typing.Final = \
        ("[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];"
         "$vault = New-Object Windows.Security.Credentials.PasswordVault;")

    def __init__(self) -> None:
        """Initialize the class."""
        self.__commands__ = [self.import_and_create_password_vault]

    def find_all_by_resource(self, name: str, save_as: str, *, select_first: bool = True) -> "Powershell":
        """Finds all credentials with the given name.

        Args:
            name: The name of the Windows Credential to find.
            save_as: The PowerShell variable to save the credential as.
            select_first: Select the first one, if multiple.

        Returns:
            `self`
        """
        _pipe = ""
        if select_first:
            _pipe = " | select -First 1"

        self.__commands__.append(f"${save_as} = $vault.FindAllByResource('{name}'){_pipe}")
        return self

    def retrieve_password(self, from_var: str) -> "Powershell":
        """Retrieve the password for a powershell variable.

        Args:
            from_var: The variable that contains a Windows Credential.

        Returns:
            `self`
        """
        self.__commands__.append(f"${from_var}.retrievePassword()")
        return self

    def write_host(self, var: str, prop: str) -> "Powershell":
        """Write the output of a prop from a variable.

        Args:
            var: The variable to get the value of.
            prop: The property of the variable to print.

        Returns:
            `self`
        """
        self.__commands__.append(f"${var}.{prop}")
        return self

    def retrieve_cred(self, from_var: str, save_as: str) -> "Powershell":
        """Retrieve the credential object from a variable containing the resource and username of the cred.

        Args:
            from_var: The variable containing credential information.
            save_as: The variable to save the credential object as.

        Returns:
            `self`
        """
        self.__commands__.append(f"${save_as} = $vault.Retrieve(${from_var}.resource, ${from_var}.username)")
        return self

    def remove_cred(self, var: str) -> "Powershell":
        """Remove a credential from Windows Credential Manager.

        Args:
            var: The variable containing the credential to remove.

        Returns:
            `self`
        """
        self.__commands__.append(f"$vault.Remove(${var})")
        return self

    def access_property(self, var: str, prop: str) -> "Powershell":
        """Attempt to access a property of a variable.

        Useful for checking if the variable and it's data exist or not. Will raise an `Exception` in
        Powershell if it doesn't exist.

        Args:
            var: The variable to access the property from.
            prop: The property to access.

        Returns:
            `self`
        """
        self.__commands__.append(f"${var}.{prop}")
        return self

    def create_credential(self, name: str, username: str, password: str, save_as: str) -> "Powershell":
        """Create a new PasswordCredential object for storing in Windows Credential Manager.

        Args:
            name: THe name of the new credential.
            username: The username
            password: The password
            save_as: The variable to save the credential as.

        Returns:
            `self`
        """
        new_cred_object = "New-Object Windows.Security.Credentials.PasswordCredential"
        self.__commands__.append(f"${save_as} = {new_cred_object}('{name}', '{username}', '{password}')")
        return self

    def add_cred(self, var: str) -> "Powershell":
        """Add a new credential.

        Args:
            var: The variable containing the PasswordCredential to store in Windows Credential Manager.

        Returns:
            `self`
        """
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
        """Get the windows credential.

        Args:
            name: The name of the credential to get.

        Returns:
            The client ID and secret, respectively.
        """
        powershell = Powershell().find_all_by_resource(
            name=name, save_as="cred",
        ).retrieve_password(
            from_var="cred",
        ).write_host(
            var="cred", prop="userName",
        ).write_host(
            var="cred", prop="password",
        )

        output = subprocess.check_output(["powershell.exe", powershell.command]).decode()  # noqa: S603, S607

        if "Exception" in output:
            return "", ""

        client_id, client_secret, *_ = output.split("\n")
        return client_id, client_secret

    @classmethod
    def delete_credential(cls, name: str) -> None:
        """Deletes a windows credential.

        Args:
            name: The name of the credential to delete.
        """
        powershell = Powershell().find_all_by_resource(
            name=name, save_as="c",
        ).retrieve_cred(
            from_var="c", save_as="cred",
        ).remove_cred(
            var="cred",
        )

        output = subprocess.check_output(["powershell.exe", powershell.command]).decode()  # noqa: S603, S607
        if "Exception" in output:
            raise DeleteCredentialError(output=output)

        print(f"Old credential '{name}' deleted.")  # noqa: T201

    @classmethod
    def windows_credential_exists(cls, name: str) -> bool:
        """Check if a credential exists.

        Args:
            name: The name of the credential to check.

        Returns:
            `True` if it exists, else `False`.
        """
        powershell = Powershell().find_all_by_resource(
            name=name, save_as="cred",
        ).access_property(
            var="cred", prop="resource",
        )
        try:
            subprocess.check_output(["powershell.exe", powershell.command]).decode()  # noqa: S603, S607
        except subprocess.CalledProcessError:
            return False
        else:
            return True

    @classmethod
    def set_windows_credential(cls, name: str, client_id: str, client_secret: str) -> None:
        """Sets a new windows credential.

        Args:
            name: The name of the credential to create.
            client_id: The Delinea Client ID or username.
            client_secret: The Delinea Client Secret or password.
        """
        powershell = Powershell().create_credential(
            name=name, username=client_id, password=client_secret, save_as="cred",
        ).add_cred(
            var="cred",
        )

        output = subprocess.check_output(["powershell.exe", powershell.command]).decode()  # noqa: S603, S607
        if "Exception" in output:
            raise SetCredentialError(output=output)
