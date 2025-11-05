# IS_FINALE

A small encrypted/local messaging project with simple cryptography utilities, a messaging module, and scripts to encode/decode chat logs. Intended as a compact demonstration of message encryption, authentication and local chat history storage.

## Overview

This repository contains a lightweight messaging application and supporting utilities. The code demonstrates:
- basic message handling and a small protocol layer (`messaging/`)
- local encrypted chat logs (`chat_logs/`)
- simple cryptographic helpers (`infoSec/simpleCrypto.py`)
- scripts that interact with chat logs (`decoder.py`, `app.py`)

The project appears to be a learning/assignment project for secure messaging. Treat this README as a reference for running and exploring the code locally.

## Quick start (Windows PowerShell)

1. Create a virtual environment and activate it:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Run the main application (if `app.py` is the entrypoint):

```powershell
python .\app.py
```

4. Use `decoder.py` to inspect/decode chat logs (the script usage may accept a filename):

```powershell
python .\decoder.py
# Example (if decoder expects a file):
# python .\decoder.py chat_logs\Server_history.enc
```

Note: Exact CLI arguments for `decoder.py` or `app.py` are not documented here — inspect the top of those files for usage and required parameters.

## Project structure

- `app.py` — top-level application script (entrypoint). Review its contents to see how the app is launched.
- `decoder.py` — script to decode or view encrypted chat logs in `chat_logs/`.
- `requirements.txt` — Python dependencies used by the project.
- `users.json` — local user data used by the app.
- `chat_logs/` — directory containing encrypted chat history files (example: `Server_history.enc`, `parth-2005_history.enc`).
- `infoSec/` — simple cryptography utilities
  - `simpleCrypto.py` — helper functions for encryption / decryption used by the project.
- `messaging/` — messaging-related package
  - `auth.py` — authentication helpers
  - `chat_history.py` — chat history utilities (reading/writing logs)
  - `protocol.py` — message protocol definitions and helpers
  - `__init__.py`

## How the pieces fit

- The `messaging` package implements the messaging protocol and handles chat history storage.
- `infoSec/simpleCrypto.py` provides the cryptographic primitives for encrypting/decrypting chat logs and messages. Review this file to understand the algorithms and key handling.
- `decoder.py` is a convenience script to decode chat history files in `chat_logs/` for local inspection.

## Assumptions and notes

- Assumption: The repository is a local/demo project. There's no deployed server included here.
- Assumption: `app.py` and `decoder.py` are executable scripts for running the app and decoding logs — check their docstrings/top-of-file comments for exact CLI usage.
- Do not store real secrets or real user passwords in `users.json` or in the repository. If keys exist in the repo, rotate them.

## Security considerations

- The project uses a local, possibly educational cryptographic helper. For production use, use well-vetted libraries and follow best practices.
- Never commit real private keys, secrets, or production credentials.
- If you plan to store chat logs, consider stronger key management and access controls.

## Development & testing

- There are no automated tests included by default. Recommended next steps:
  - Add unit tests for `infoSec/simpleCrypto.py` (encryption/decryption roundtrips).
  - Add tests for `messaging/chat_history.py` read/write behavior.

## Suggested next steps

- Add documentation for CLI usage of `decoder.py` and `app.py` (help flags, examples).
- Add a small test suite (pytest recommended) and a `Makefile` or `tasks.json` for convenience.

## Contributing

If you plan to contribute:
- Open an issue first describing the change.
- Add tests for new functionality.

## License

No license file found in the repository. Add `LICENSE` if you want to specify reuse terms.

## Contact

For questions about this repository, inspect `users.json`, the top-level scripts, or reach out to the original author in the repository metadata.
