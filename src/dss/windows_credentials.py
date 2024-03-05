"""Windows Credential Integration."""  # noqa: INP001
import subprocess
from typing import Final


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
    import_and_create_password_vault: Final = \
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
    def get_from_windows_credential(cls, name: str) -> (str, str):
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

        output = subprocess.check_output(["powershell.exe", powershell.command]).decode()

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

        output = subprocess.check_output(["powershell.exe", powershell.command]).decode()
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
            subprocess.check_output(["powershell.exe", powershell.command]).decode()
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

        output = subprocess.check_output(["powershell.exe", powershell.command]).decode()
        if "Exception" in output:
            raise SetCredentialError(output=output)
