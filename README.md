# dss-sdk
A better SDK for Delinea Secret Server.

This is an SDK and CLI for interacting with Delinea Secret Server. The CLI uses [Typer](https://typer.tiangolo.com/), 
and the SDK uses [httpx](https://www.python-httpx.org/). Both use [Pydantic](https://docs.pydantic.dev/latest/) for 
data serialization from the Delinea APIs.

# Table of Contents
- [Installation](#installation)
- [Usage](#usage)
  - [CLI](#the-dss-command-line-tool)
  - [SDK](#the-dss-software-development-kit)
- [Roadmap](#roadmap)
- [Contributing](#contributing)

# Installation
To install, ensure Python 3.8+ is installed and run:

```bash
pip install dss-sdk
```

or

```powershell
pip install --user dss-sdk
```

depending on available permissions.

# Usage
This small package contains two-fold purpose. The first is a command line tool you can use to interact with your Delinea
Secret Server. This is done via the `dss` tool in your terminal. The second purpose is for those wanting to perform a 
bit more automation or complicated tasks with Delinea SS. This is done via `import dss` in your Python code.

## The `dss` Command Line Tool
After installation, the tool should immediately be available in your terminal. If not, you either need to close your
terminal and re-open, or ensure your python `Scripts` path is in your `PATH`. 

Running `dss --help` gives you the following:

```bash
 Usage: dss [OPTIONS] COMMAND [ARGS]...

 Delinea Secret Server CLI.

╭─ Options──────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --profile                   TEXT  The Delinea credentials profile. [default: default]                                 │
│ --version                         Prints the current version and exits.                                               │
│ --install-completion              Install completion for the current shell.                                           │
│ --show-completion                 Show completion for the current shell, to copy it or customize the installation.    │
│ --help                            Show this message and exit.                                                         │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ get-secret       Gets a secret.                                                                                       │
│ search-folders   Search for accessible folders.                                                                       │
│ get-folder       Get details about a Folder ID.                                                                       │
│ get-template     Get details about a given Template ID.                                                               │
│ search-secrets   Search available secrets using various parameters.                                                   │
│ generate-otp     Generate an OTP if the secret supports it.                                                           │
│ config           Configure a DSS CLI profile.                                                                         │
│ login            Log in to DSS using API Key.                                                                         │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### Main Options

#### Option: `--tenant-id`
The `--tenant-id` option is required, or you can specify an environment variable called `DELINEA_TENANT_ID` that is the name
of your Delinea App Instance Tenant. Let's assume it's `myorg`. You can either use it like:

```bash
dss --tenant-id myorg
```

or you can export the environment variable:
```bash
# Mac / Linux
export DELINEA_TENANT_ID='myorg'
```
```powershell
# Windows
$env:DELINEA_TENANT_ID='myorg'
```

If you export the environment variable, you do not need to provide the `--tenant-id` option in the command line. 

#### Option: `--client-id` and `--client-secret`

When using these options, they're both required to be set. Just like with `--server`, you can specify the options before 
the command, or export the environment variables:

```bash
dss --client-id test-id --client-secret some-test-super-secret
```

or you can export the environment variable:
```bash
# Mac / Linux
export DELINEA_CLIENT_ID='test-id'
export DELINEA_CLIENT_SECRET='some-test-super-secret'
```
```powershell
# Windows
$env:DELINEA_CLIENT_ID='test-id'
$env:DELINEA_CLIENT_SECRET='some-test-super-secret'
```

This is what the CLI will use to acquire an OAuth2 token from your Delinea instance and subsequently use the token to
auth the API calls.

#### Option: `--windows-credential`

> NOTE: This will ONLY work on a Windows machine.

When providing this option, you don't need to provide the Client ID or Client Secret via the command line or environment
variables, as it will access them via a Windows Credential. You can store your credentials in Windows Credential Manager
using the [`store-windows-credential`](#command-store-windows-credential) command.

### Commands
The commands are how you interact with the Delinea Secret Server from the CLI.

#### Command: `store-windows-credential`
```bash
Usage: dss store-windows-credential [OPTIONS]

 Stores Client ID and Client Secret in Windows Credential Manager.

╭─ Options ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --client-id            TEXT  The client ID registered with your Delinea server. [default: None] [required]                                  │
│ *  --client-secret        TEXT  The client secret for the specified client ID registered with your Delinea server. [default: None] [required]  │
│    --name                 TEXT  The name to use in Windows credentials. [default: dss-cli-client]                                              │
│    --help                       Show this message and exit.                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

This command can be used to store your Client ID and Client Secret in Windows Credential Manager via:
```bash
dss store-windows-credential --client-id test-id --client-secret some-test-super-secret
```
You can also change the name by using the `--name` option, like: `--name MyDelineaCreds`. Just be sure to provide that
name when specifying `--windows-credential` or `DELINEA_WINDOWS_CREDENTIAL`.

You could also use it to store any credential in the Windows Credential Manager, just remember that the `--client-id` is
the username and `--client-secret` is the password.

#### Command: `search-secrets`
```bash
Usage: dss search-secrets [OPTIONS]

 Search available secrets using various parameters.

╭─ Options ──────────────────────────────────────────────────────────╮
│ --recent                                                           │
│ --search-text                TEXT     [default: None]              │
│ --folder-id                  INTEGER  [default: None]              │
│ --secret-template-ids        INTEGER  [default: None]              │
│ --help                                Show this message and exit.  │
╰────────────────────────────────────────────────────────────────────╯
```

You can specify no other options, and it will output a table of all the secrets to which the service account has access.
However, you can provide the `--recent` boolean flag to search only through the recently used secrets, the `--folder-id`
to search for secrets only in that folder, `--secret-template-ids` to search only for secrets that use a specific
template (you can specify it multiple times for multiple template IDs), or `--search-text` to look for secrets that 
contain text in various places (name, attribute, slug, etc.).

### Command `get-secret`
```bash
Usage: dss get-secret [OPTIONS] SECRET_ID

 Gets a secret.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    secret_id      INTEGER  [default: None] [required]                                                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --include-username                                Include the username in the output (Does not copy username to clipboard).  │
│ --output-format           [table|json|clipboard]  Output as a table, JSON, or copy to clipboard. [default: clipboard]        │
│ --help                                            Show this message and exit.                                                │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

This is self-explanatory. Provide the `SECRET_ID` to get that secret. You can add the `--include-username` boolean flag
to have it print out the username tied to the secret, otherwise it just gets the "password" value. You can specify the
output here, as well, just like in the [`register-client`](#command-register-client) command. 


## The `dss` Software Development Kit
For those that need to do complex logic, or automation, the SDK can provide the same means as the CLI, but in Python
classes.

### Search Secrets Example
```python3
from dss_sdk.server import SecretServerClient
from dss_sdk.models import SearchSecretsParams

search_text = "Some Text"
username = "my-user"

ss = SecretServerClient()
params = SearchSecretsParams(search_text=search_text)
secrets = ss.search_secrets(params=params)
for secret in secrets.records:
    print(secret.name, secret.secret_id)
```

### Get Secret Example
```python3
from dss_sdk.server import SecretServerClient

secret_id = 12345

ss = SecretServerClient()
secret = ss.get_secret(secret_id=secret_id)

# Do something with the secret
...
```

# Roadmap
- Create tests
  - For SDK
  - And CLI
- Build `Async` client
- Implement `set_secret()`
  - For SDK
  - And CLI
- Support `password` grant type
- ? 

# Contributing
If you'd like to contribute, please for the repo and create a pull request!

[`Back to Top`](#table-of-contents)
