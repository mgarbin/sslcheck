# sslcheck

Local re-implementation of the checks an SSL Labs server test performs. No SSL Labs API or other
third-party scanner is used: protocol, cipher and key-exchange probing is done with hand-built TLS
ClientHello messages over raw sockets, so results do not depend on what your local OpenSSL still
supports (SSLv2, SSLv3, export suites, RC4 ... are all probed).

## What it checks

- **Protocols and ciphers**: SSL 2.0 - TLS 1.3, full cipher-suite enumeration per protocol, server
  cipher-order preference, DH parameter size, supported EC groups
- **Certificates**: validity, key, signature, SAN/hostname, trust (system store), chain order,
  must-staple, SCT, OCSP revocation, CRL/AIA, SPKI pin; RSA + ECDSA dual certificates
- **Handshake features**: secure renegotiation, OCSP stapling, session tickets/resumption,
  extended master secret, ALPN (h2 / http/1.1), TLS_FALLBACK_SCSV
- **Vulnerabilities**: Heartbleed, OpenSSL CCS injection, ROBOT, POODLE, BEAST, CRIME, FREAK,
  Logjam, DROWN, Sweet32, RC4
- **HTTP**: status, HSTS, Alt-Svc, Server header (HTTPS targets)
- **SMTP**: STARTTLS negotiation on ports 25/587, banner and EHLO extensions; every TLS check above
  runs on the upgraded connection
- **Client handshake simulation**: 47 real-world clients (Android, Chrome, Firefox, IE/Edge,
  Java 6/7/8/11/21, OpenSSL, Safari, Googlebot, Apple ATS) and whether each can still connect
- **Grade**: SSL Labs-style score and letter grade (an approximation of the public rating guide)

## Requirements

- Python 3.9 or newer
- the `cryptography` package (>= 42.0, see `requirements.txt`)

Nothing else is needed; everything else is the Python standard library. The `openssl` binary is
not used.

## Installation

Use a virtual environment so the dependency stays out of your system Python.

### Installing Python 3.9+ with pyenv (optional)

Skip this if `python3 --version` already shows 3.9 or newer. Otherwise [pyenv](https://github.com/pyenv/pyenv)
installs and switches Python versions without touching the system Python.

**1. Install pyenv**

```sh
# Linux (installer script from the pyenv project)
curl https://pyenv.run | bash

# macOS
brew install pyenv
```

Add pyenv to your shell (bash/zsh: put these lines in `~/.bashrc` or `~/.zshrc`, then open a new shell):

```sh
export PYENV_ROOT="$HOME/.pyenv"
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
```

**2. Install the build dependencies** (pyenv compiles Python; without the OpenSSL headers the
resulting Python has no `ssl` module and `sslcheck.py` cannot run)

```sh
# Debian / Ubuntu
sudo apt install -y build-essential curl libssl-dev zlib1g-dev libbz2-dev libreadline-dev \
  libsqlite3-dev libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev

# Fedora
sudo dnf install -y make gcc patch zlib-devel bzip2 bzip2-devel readline-devel sqlite sqlite-devel \
  openssl-devel tk-devel libffi-devel xz-devel

# Arch / Manjaro
sudo pacman -S --needed base-devel openssl zlib xz tk

# macOS
xcode-select --install
brew install openssl readline sqlite3 xz zlib tcl-tk
```

**3. Install Python and select it for this project**

```sh
pyenv install 3.9          # latest 3.9.x known to your pyenv; list versions: pyenv install --list
cd sslscan
pyenv local 3.9            # writes .python-version, so this directory uses 3.9
python --version           # Python 3.9.x
```

Any newer version works as well (for example `pyenv install 3.12`); 3.9 is only the minimum the
script supports. After `pyenv local`, the `python3 -m venv .venv` command below creates the
virtual environment with that interpreter.

**Windows:** use [pyenv-win](https://github.com/pyenv-win/pyenv-win) (it provides the same
`pyenv install` / `pyenv local` commands and needs no build dependencies), or install Python from
python.org.

If `pyenv install` fails while building, read the error: it almost always names a missing
`-dev`/`-devel` package from step 2. To check the result, `python -c "import ssl"` must print nothing.

### Linux / macOS

```sh
cd sslscan
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
cd sslscan
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell refuses to run the activation script, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use `cmd.exe` and
`.venv\Scripts\activate.bat`.

### Notes

- On Debian/Ubuntu, `python3 -m venv` may fail until you install `python3-venv`
  (`sudo apt install python3-venv`).
- On Arch/Manjaro and Fedora the venv module ships with Python.
- Activate the environment (`source .venv/bin/activate`) in every new shell before running the
  script. Leave it with `deactivate`.
- You can also run it without activating: `.venv/bin/python sslcheck.py example.com`.

## Usage

```sh
./sslcheck.py example.com                 # port 443
./sslcheck.py example.com:8443
./sslcheck.py https://example.com:8443
./sslcheck.py host1.example host2.example # several targets, scanned one after another

# SMTP: ports 25 and 587 are upgraded with STARTTLS automatically
./sslcheck.py mail.example.com:25
./sslcheck.py mail.example.com:587

# SMTP on a non-standard port, or implicit TLS on 465 (no option needed for 465)
./sslcheck.py --starttls smtp mail.example.com:2525
./sslcheck.py mail.example.com:465
```

If the script is not executable, run it with `python sslcheck.py ...` instead.

### Options

| Option | Meaning |
|---|---|
| `--ip IP` | Connect to this IP instead of resolving the hostname. The hostname is still used for SNI and certificate matching. |
| `--timeout SECONDS` | Per-handshake timeout (default 5). |
| `--workers N` | Parallel connections (default 8). Use `1` for fragile or single-threaded servers. |
| `--no-ocsp` | Do not contact OCSP responders or AIA URLs (no outbound requests besides the target). |
| `--no-sim` | Skip the client handshake simulation (about 47 extra connections). |
| `--json` | Machine-readable output instead of the report. |
| `--no-color` | Plain text; colour is also disabled automatically when output is not a terminal. |
| `--starttls {auto,smtp,none}` | Upgrade the plaintext connection with STARTTLS before testing. `auto` (default) uses SMTP on ports 25 and 587; port 465 is implicit TLS and needs nothing. `none` forces a direct TLS handshake. |
| `--ehlo NAME` | Host name sent in the SMTP `EHLO` (default `sslcheck.invalid`). Use a resolvable name if the server rejects the default. |

Examples:

```sh
# test one backend behind a load balancer, keeping the real hostname for SNI
./sslcheck.py --ip 203.0.113.10 www.example.com

# gentle scan of a slow server
./sslcheck.py --workers 1 --timeout 10 intranet.example

# fast scan, offline apart from the target
./sslcheck.py --no-ocsp --no-sim example.com

# JSON: list which simulated clients fail and why
./sslcheck.py --json example.com | jq '.handshake_simulation[] | select(.ok|not) | {client, reason}'

# SMTP with a longer timeout (greylisting / postscreen delay the banner)
./sslcheck.py --timeout 15 --workers 2 mail.example.com:25
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan finished and the grade is not `F`, `T` or `M` |
| `1` | Connection failed, no TLS service found, or grade is `F` / `T` / `M` |
| `2` | Target could not be parsed or resolved |

### Reading the report

Sections, in order: Summary (grade and score), Certificate chain(s), Protocols, Cipher suites,
Handshake simulation (HTTPS targets), Protocol features, Vulnerabilities, then HTTP (HTTPS targets)
or SMTP (STARTTLS targets).

In the handshake simulation each client is shown as:

```
Android 9.0 (native)    OK   TLS 1.3  TLS_AES_128_GCM_SHA256  x25519  FS
Java 7u25               FAIL DH parameters (2048 bits) above the client maximum (1024)
```

`OK` lines give the negotiated protocol, cipher suite, key exchange and whether it has forward
secrecy (`FS`). `FAIL` lines give the reason the client would abort.

## Limitations

- The simulation does not evaluate whether each client trusts the certificate chain (root stores
  differ per client); the report says so.
- For TLS 1.3 the certificate is encrypted, so simulation checks use the primary certificate chain
  found by the scan.
- Client profiles are approximations based on published ClientHello captures; treat results for
  very old clients as indicative.
- Scanning a bare IP address as the target (`./sslcheck.py 203.0.113.10`) currently crashes in the
  trust check. Use a hostname, or pass `--ip` together with the hostname.
- SMTP targets: every probe opens its own SMTP session (banner, EHLO, STARTTLS), so a scan makes
  many short connections. Mail servers may rate-limit or log them; lower `--workers`
  and keep to servers you operate. The client handshake simulation, ALPN and the HTTP checks are
  skipped for STARTTLS targets (browser/OS profiles do not apply to mail traffic), and the grade
  cannot reach A+ because that needs an HSTS header.
- Only STARTTLS for SMTP is implemented; IMAP, POP3 and others are not.
- Only scan servers you are allowed to test.

## Troubleshooting

- `sslcheck needs the 'cryptography' package`: the virtual environment is not active, or
  `pip install -r requirements.txt` was not run in it.
- Many `FAIL` or `timeout` results: the server may rate-limit or drop parallel connections; retry
  with `--workers 1` and a larger `--timeout`.
- Trust shows "unknown": the system CA bundle was not found; the script looks in the Python/OpenSSL
  default paths, `/etc/ssl/certs/ca-certificates.crt` and `/etc/pki/tls/certs/ca-bundle.crt`.
- `server does not advertise STARTTLS` / `not an SMTP reply`: the port is not an SMTP service that
  offers STARTTLS. Check the port, or use `--starttls none` for implicit TLS.

## License

Licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE). Source files carry the
`SPDX-License-Identifier: Apache-2.0` tag.

Third-party data: the client profiles used by the handshake simulation (`_CLIENT_DATA` in
`sslcheck.py`) are derived from published ClientHello captures (the Qualys SSL Labs client list, as
redistributed in the GPL-licensed testssl.sh project, `etc/client-simulation.txt`). Check that this
is acceptable for your distribution before publishing the project.
