"""DSS SDK Exceptions."""


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


class CredentialsExpiredError(Exception):
    """Exception raised when the cached credentials have expired and can no longer be refreshed."""

    def __init__(self) -> None:
        """Initialize the exception."""
        super().__init__("The cached credentials have expired")


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
