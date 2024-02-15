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

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --server                    TEXT  The FQDN of your Delinea Secret Server. [env var: DELINEA_SERVER] [default: None] [required]                                            │
│    --client-id                 TEXT  The client ID registered with your Delinea server. [env var: DELINEA_CLIENT_ID] [default: None]                                         │
│    --client-secret             TEXT  The client secret for the specified client ID registered with your Delinea server. [env var: DELINEA_CLIENT_SECRET] [default: None]     │
│    --windows-credential        TEXT  The name of a Windows Credential containing the Client ID and Client Secret [env var: DELINEA_WINDOWS_CREDENTIAL] [default: None]       │
│    --version                                                                                                                                                                 │
│    --install-completion              Install completion for the current shell.                                                                                               │
│    --show-completion                 Show completion for the current shell, to copy it or customize the installation.                                                        │
│    --help                            Show this message and exit.                                                                                                             │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ get-secret                                                        Gets a secret.                                                                                             │
│ register-client                                                   Registers a new client with your server.                                                                   │
│ search-secrets                                                    Search available secrets using various parameters.                                                         │
│ store-windows-credential                                          Stores Client ID and Client Secret in Windows Credential Manager.                                          │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### Main Options

#### Option: `--server`
The `--server` option is required, or you can specify an environment variable called `DELINEA_SERVER` that is the name
of your Delinea instance. Let's assume it's `test.secretservercloud.com`. You can either use it like:

```bash
dss --server test.secretservercloud.com
```

or you can export the environment variable:
```bash
# Mac / Linux
export DELINEA_SERVER='test.secretservercloud.com'
```
```powershell
# Windows
$env:DELINEA_SERVER='test.secretservercloud.com'
```

If you export the environment variable, you do not need to provide the `--server` option in the command line. 

#### Option: `--client-id` and `--client-secret`

When using these options, they're both required to be set. You can acquire a Client ID and Secret using the 
[`register-client`](#command-register-client) command. Just like with `--server`, you can specify the options before 
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

#### Command: `register-client`

```bash
 Usage: dss register-client [OPTIONS]

 Registers a new client with your server.

╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --service-account         TEXT                    [default: None] [required]                                         │
│ *  --onboarding-key          TEXT                    [default: None] [required]                                         │
│    --description             TEXT                    [default: Delinea Python SDK]                                      │
│    --store-in-windows                                Store the registered client ID and secret as Windows credentials.  │
│    --output-format           [table|json|clipboard]  [default: clipboard]                                               │
│    --help                                            Show this message and exit.                                        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

You need to get your service account and onboarding key from your security team or create them in Delinea, if you have 
access. Then you can use them to create a Client ID and Client Secret via:
```bash
dss register-client --service-account myServiceAccount --onboarding-key 1234567890abcdefg
```

You can specify a `--description` which will show up in Delinea as a registered client. It's `Delinea Python SDK` by 
default. If you specify the `--store-in-windows` boolean flag, it will store it as a Windows Credential under the name
`dss-cli-client`.

By default, all secrets are exported to your clipboard and are not printed in the console. You can change this behavior
by specifying and `--output-format` of **json** for a JSON output or **table** to print them in a pretty table.

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
from dss.server import SecretServerClient

search_text = "Some Text"
username = "my-user"

ss = SecretServerClient(
    server="test.secretservercloud.com",
    client_id="test-id",
    client_secret="some-test-super-secret"
)
secrets = ss.search_secrets(params={
    "filter.searchText": search_text,
})
for secret in secrets:
    print(secret.name, secret.id)
```

### Get Secret Example
```python3
from dss.server import SecretServerClient

secret_name = "my-secret"

ss = SecretServerClient(
    server="test.secretservercloud.com",
    client_id="test-id",
    client_secret="some-test-super-secret"
)
secret_id = ss.get_secret_id(secret_name=secret_name)
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
