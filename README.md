# SSH Tunnel Helper

A simple Windows/Linux desktop GUI for creating SSH tunnels with Python and `sshtunnel`.

## AI Disclaimer

This project was created with assistance from OpenAI Codex. Review and test the code before using it in production or security-sensitive environments.

## What it does

The app opens a local port on your computer and forwards it through an SSH server to a remote service.

Typical use cases:

- Connect to a private database through a bastion host.
- Reach an internal web service without exposing it publicly.
- Test a remote API through an encrypted SSH connection.

## Requirements

- Python 3.9 or newer
- Windows or Linux
- `sshtunnel`

Install the Python dependency:

```bash
python -m pip install -r requirements.txt
```

If dependencies are missing or outdated, refresh them with:

```bash
python -m pip install -U -r requirements.txt
```

The app includes a compatibility guard for Paramiko 4.x, where the old `DSSKey` attribute was removed. DSA/DSS private keys are not supported on Paramiko 4.x; use RSA, ECDSA, or Ed25519 keys instead.

Linux systems may also need Tkinter installed through the OS package manager, for example:

```bash
sudo apt install python3-tk
```

## Run

```bash
python sshtunnel_gui.py
```

## How to fill in the fields

- **SSH server**: the machine you can log into with SSH, for example `bastion.example.com`.
- **SSH username**: your SSH login name.
- **Authentication**: choose password or private key.
- **Remote host**: the destination as seen from the SSH server. `127.0.0.1` means the service runs on the SSH server itself.
- **Remote port**: the port of the destination service, for example `5432` for PostgreSQL.
- **Local bind host**: use `127.0.0.1` unless you intentionally want other machines to connect to this tunnel.
- **Local port**: the port your local application connects to.

Example: to forward local `127.0.0.1:15432` to PostgreSQL on the remote side at `127.0.0.1:5432`, set:

- Remote host: `127.0.0.1`
- Remote port: `5432`
- Local bind host: `127.0.0.1`
- Local port: `15432`

Then configure your database client to connect to `127.0.0.1:15432`.

## Testing a tunnel

The app checks two things when you start a tunnel:

1. SSH login works.
2. The SSH server can open a connection to the remote host and port.

Testing the local port with a command such as `Test-NetConnection 127.0.0.1 -Port 3398` only proves that the local listener is open. It does not prove that the SSH server can reach the remote service. If the GUI reports a remote-side timeout, check firewall rules, routing, service status, and whether the remote host/port are correct from the SSH server's network.

## Profiles

Profiles save connection fields except passwords. Passwords are intentionally not saved.

Saved profiles are stored in:

- Windows: `C:\Users\<you>\.ssh_tunnel_helper_profiles.json`
- Linux: `/home/<you>/.ssh_tunnel_helper_profiles.json`

## Security notes

- Keep **Local bind host** as `127.0.0.1` unless you understand the exposure risk.
- Prefer SSH keys over passwords for regular use.
- Do not share profile files if they contain hostnames or usernames you consider sensitive.
