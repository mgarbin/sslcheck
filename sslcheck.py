#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""sslcheck - local re-implementation of the checks an SSL Labs server test performs.

No SSL Labs API (or any third-party scanner) is used. Protocol / cipher / key-exchange
probing is done with hand-built TLS ClientHello messages over raw sockets, so results do not
depend on what the local OpenSSL build still supports (SSLv2/SSLv3/export/RC4 ... are all probed).

Checks
  * protocol support SSL 2.0 - TLS 1.3, full cipher-suite enumeration per protocol,
    server cipher-order preference, DH parameter size, supported EC groups
  * certificate chain: validity, key, signature, SAN/hostname, trust (system store), chain order,
    must-staple, SCT, OCSP revocation, CRL/AIA, SPKI pin; RSA + ECDSA dual certificates
  * handshake features: secure renegotiation, OCSP stapling, session tickets/resumption,
    extended master secret, ALPN (h2 / http/1.1), TLS_FALLBACK_SCSV
  * vulnerabilities: Heartbleed, OpenSSL CCS injection, ROBOT, POODLE (SSLv3), BEAST,
    CRIME (TLS compression), FREAK, Logjam, DROWN, Sweet32, RC4, weak DH
  * HTTP: status, HSTS, Alt-Svc, Server header
  * client handshake simulation: ~45 real-world clients (Android, Chrome, Firefox, IE/Edge, Java 6-21,
    OpenSSL, Safari, Googlebot ...) -- which of them can still connect, and with what protocol/cipher
  * SMTP: STARTTLS negotiation (ports 25 / 587 automatically, or --starttls smtp), banner and
    EHLO extensions; all TLS checks run on the upgraded connection
  * SSL Labs-style numeric score and letter grade (approximation of the public rating guide)

Requires: Python >= 3.9, `cryptography`.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import warnings
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import (
        dsa, ec, ed448, ed25519, rsa, x448, x25519,
    )
    from cryptography.x509 import ocsp
    from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
except ImportError:  # pragma: no cover
    sys.exit("sslcheck needs the 'cryptography' package:  pip install cryptography")

# --------------------------------------------------------------------------------------
# constants / tables
# --------------------------------------------------------------------------------------
SSL2, SSL3, TLS10, TLS11, TLS12, TLS13 = 0x0200, 0x0300, 0x0301, 0x0302, 0x0303, 0x0304
VERSION_NAMES = {SSL2: "SSL 2.0", SSL3: "SSL 3.0", TLS10: "TLS 1.0", TLS11: "TLS 1.1",
                 TLS12: "TLS 1.2", TLS13: "TLS 1.3"}
PROBE_VERSIONS = (SSL3, TLS10, TLS11, TLS12, TLS13)

GROUP_NAMES = {23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448",
               256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144",
               260: "ffdhe8192", 21: "secp224r1", 19: "secp192r1", 22: "secp256k1",
               0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x6399: "X25519Kyber768Draft00"}
PROBE_GROUPS = (29, 23, 24, 25, 30)

ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
          21: "decryption_failed", 22: "record_overflow", 40: "handshake_failure",
          42: "bad_certificate", 47: "illegal_parameter", 50: "decode_error",
          51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
          80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled",
          109: "missing_extension", 112: "unrecognized_name", 120: "no_application_protocol"}

HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

SIGALGS = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807,
           0x0203, 0x0201, 0x0603, 0x0202)

_CIPHER_TABLE = """
0001 TLS_RSA_WITH_NULL_MD5
0002 TLS_RSA_WITH_NULL_SHA
0003 TLS_RSA_EXPORT_WITH_RC4_40_MD5
0004 TLS_RSA_WITH_RC4_128_MD5
0005 TLS_RSA_WITH_RC4_128_SHA
0006 TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
0007 TLS_RSA_WITH_IDEA_CBC_SHA
0008 TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
0009 TLS_RSA_WITH_DES_CBC_SHA
000A TLS_RSA_WITH_3DES_EDE_CBC_SHA
0011 TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
0012 TLS_DHE_DSS_WITH_DES_CBC_SHA
0013 TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
0014 TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
0015 TLS_DHE_RSA_WITH_DES_CBC_SHA
0016 TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
0017 TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
0018 TLS_DH_anon_WITH_RC4_128_MD5
0019 TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
001A TLS_DH_anon_WITH_DES_CBC_SHA
001B TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
002F TLS_RSA_WITH_AES_128_CBC_SHA
0032 TLS_DHE_DSS_WITH_AES_128_CBC_SHA
0033 TLS_DHE_RSA_WITH_AES_128_CBC_SHA
0034 TLS_DH_anon_WITH_AES_128_CBC_SHA
0035 TLS_RSA_WITH_AES_256_CBC_SHA
0038 TLS_DHE_DSS_WITH_AES_256_CBC_SHA
0039 TLS_DHE_RSA_WITH_AES_256_CBC_SHA
003A TLS_DH_anon_WITH_AES_256_CBC_SHA
003B TLS_RSA_WITH_NULL_SHA256
003C TLS_RSA_WITH_AES_128_CBC_SHA256
003D TLS_RSA_WITH_AES_256_CBC_SHA256
0040 TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
0041 TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
0044 TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
0045 TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
0067 TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
006A TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
006B TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
006C TLS_DH_anon_WITH_AES_128_CBC_SHA256
006D TLS_DH_anon_WITH_AES_256_CBC_SHA256
0084 TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
0087 TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
0088 TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
0096 TLS_RSA_WITH_SEED_CBC_SHA
009A TLS_DHE_RSA_WITH_SEED_CBC_SHA
009C TLS_RSA_WITH_AES_128_GCM_SHA256
009D TLS_RSA_WITH_AES_256_GCM_SHA384
009E TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
009F TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
00A2 TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
00A3 TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
00A6 TLS_DH_anon_WITH_AES_128_GCM_SHA256
00A7 TLS_DH_anon_WITH_AES_256_GCM_SHA384
00BA TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
00BE TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
00C0 TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
00C4 TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
1301 TLS_AES_128_GCM_SHA256
1302 TLS_AES_256_GCM_SHA384
1303 TLS_CHACHA20_POLY1305_SHA256
1304 TLS_AES_128_CCM_SHA256
1305 TLS_AES_128_CCM_8_SHA256
C001 TLS_ECDH_ECDSA_WITH_NULL_SHA
C002 TLS_ECDH_ECDSA_WITH_RC4_128_SHA
C003 TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
C004 TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
C005 TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
C006 TLS_ECDHE_ECDSA_WITH_NULL_SHA
C007 TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
C008 TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
C009 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
C00A TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
C00B TLS_ECDH_RSA_WITH_NULL_SHA
C00C TLS_ECDH_RSA_WITH_RC4_128_SHA
C00D TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
C00E TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
C00F TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
C010 TLS_ECDHE_RSA_WITH_NULL_SHA
C011 TLS_ECDHE_RSA_WITH_RC4_128_SHA
C012 TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
C013 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
C014 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
C015 TLS_ECDH_anon_WITH_NULL_SHA
C016 TLS_ECDH_anon_WITH_RC4_128_SHA
C017 TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
C018 TLS_ECDH_anon_WITH_AES_128_CBC_SHA
C019 TLS_ECDH_anon_WITH_AES_256_CBC_SHA
C023 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
C024 TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
C025 TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
C026 TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
C027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
C028 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
C029 TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
C02A TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
C02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
C02C TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
C02D TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
C02E TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
C02F TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
C030 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
C031 TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
C032 TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
C072 TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
C073 TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
C076 TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
C077 TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
C09C TLS_RSA_WITH_AES_128_CCM
C09D TLS_RSA_WITH_AES_256_CCM
C09E TLS_DHE_RSA_WITH_AES_128_CCM
C09F TLS_DHE_RSA_WITH_AES_256_CCM
C0A0 TLS_RSA_WITH_AES_128_CCM_8
C0A1 TLS_RSA_WITH_AES_256_CCM_8
C0A2 TLS_DHE_RSA_WITH_AES_128_CCM_8
C0A3 TLS_DHE_RSA_WITH_AES_256_CCM_8
C0AC TLS_ECDHE_ECDSA_WITH_AES_128_CCM
C0AD TLS_ECDHE_ECDSA_WITH_AES_256_CCM
C0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
C0AF TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
CCA8 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
CCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
CCAA TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
"""

# SSLv2 cipher specs (3 bytes): code, name, bits
SSL2_CIPHERS = {
    0x010080: ("SSL2_RC4_128_WITH_MD5", 128),
    0x020080: ("SSL2_RC4_128_EXPORT40_WITH_MD5", 40),
    0x030080: ("SSL2_RC2_128_CBC_WITH_MD5", 128),
    0x040080: ("SSL2_RC2_128_CBC_EXPORT40_WITH_MD5", 40),
    0x050080: ("SSL2_IDEA_128_CBC_WITH_MD5", 128),
    0x060040: ("SSL2_DES_64_CBC_WITH_MD5", 56),
    0x0700C0: ("SSL2_DES_192_EDE3_CBC_WITH_MD5", 112),
}


@dataclass(frozen=True)
class Suite:
    id: int
    name: str
    kx: str          # RSA, DHE_RSA, ECDHE_ECDSA, DH_anon, ... ("" for TLS 1.3)
    enc: str
    bits: int
    mode: str        # AEAD / CBC / STREAM / NONE
    mac: str
    tls13: bool

    @property
    def fs(self) -> bool:
        return self.tls13 or self.kx.startswith(("DHE", "ECDHE"))

    @property
    def anon(self) -> bool:
        return "anon" in self.kx

    @property
    def export(self) -> bool:
        return "EXPORT" in self.kx

    @property
    def auth(self) -> str:
        if "ECDSA" in self.kx:
            return "ECDSA"
        if "DSS" in self.kx:
            return "DSS"
        if self.anon:
            return "anon"
        return "RSA"

    @property
    def block64(self) -> bool:
        return any(x in self.enc for x in ("3DES", "DES_CBC", "DES40", "IDEA", "RC2"))

    @property
    def tls12_only(self) -> bool:
        return self.mode == "AEAD" or self.mac in ("SHA256", "SHA384")

    @property
    def level(self) -> str:
        if (self.anon or self.export or self.mode == "NONE" or "RC4" in self.enc
                or self.bits <= 56 or self.mac == "MD5"):
            return "INSECURE"
        if self.block64 or "SEED" in self.enc or self.bits < 112:
            return "WEAK"
        if self.tls13 or (self.mode == "AEAD" and self.fs):
            return "STRONG"
        return "OK"


def _bits(enc: str) -> int:
    tok = enc.split("_")
    if enc.startswith("NULL"):
        return 0
    if "40" in tok or "DES40" in tok:
        return 40
    if "3DES" in tok:
        return 112
    if enc.startswith("DES_"):
        return 56
    if "CHACHA20" in tok or "256" in tok:
        return 256
    return 128  # AES_128, RC4_128, CAMELLIA_128, IDEA, SEED


def _make_suite(code: int, name: str) -> Suite:
    tls13 = "_WITH_" not in name
    if tls13:
        kx, enc = "", name[4:]
    else:
        kx, enc = name[4:].split("_WITH_")
    if "GCM" in enc or "CCM" in enc or "POLY1305" in enc:
        mode = "AEAD"
    elif "CBC" in enc:
        mode = "CBC"
    elif "RC4" in enc:
        mode = "STREAM"
    else:
        mode = "NONE"
    mac = enc.rsplit("_", 1)[-1]
    return Suite(code, name, kx, enc, _bits(enc), mode, mac, tls13)


SUITES: list[Suite] = []
for _line in _CIPHER_TABLE.strip().splitlines():
    _code, _name = _line.split()
    SUITES.append(_make_suite(int(_code, 16), _name))
SUITE_BY_ID = {s.id: s for s in SUITES}


def suite_label(s: Suite) -> str:
    return s.name


# --------------------------------------------------------------------------------------
# wire helpers
# --------------------------------------------------------------------------------------
def u16(n: int) -> bytes:
    return struct.pack(">H", n)


def u24(n: int) -> bytes:
    return n.to_bytes(3, "big")


def ext(t: int, data: bytes = b"") -> bytes:
    return u16(t) + u16(len(data)) + data


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def keygen(group: int) -> bytes:
    if group == 29:
        return x25519.X25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if group == 30:
        return x448.X448PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    curve = {23: ec.SECP256R1(), 24: ec.SECP384R1(), 25: ec.SECP521R1()}[group]
    return ec.generate_private_key(curve).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def client_hello(version: int, suites: list[int], host: str, *, groups=PROBE_GROUPS,
                 key_share: int | None = None, compress: bool = False,
                 fallback_scsv: bool = False) -> bytes:
    """Build a complete ClientHello record."""
    tls13 = version == TLS13
    legacy = TLS12 if tls13 else version
    ciphers = list(suites)
    if version == SSL3:
        ciphers.append(0x00FF)          # TLS_EMPTY_RENEGOTIATION_INFO_SCSV (no extensions in SSLv3)
    if fallback_scsv:
        ciphers.append(0x5600)
    cs = b"".join(u16(c) for c in ciphers)
    sid = os.urandom(32) if tls13 else b""
    body = (u16(legacy) + os.urandom(32) + bytes([len(sid)]) + sid + u16(len(cs)) + cs
            + (b"\x02\x01\x00" if compress else b"\x01\x00"))
    exts = b""
    if version != SSL3:
        if host and not is_ip(host):
            h = host.encode("idna")
            entry = b"\x00" + u16(len(h)) + h
            exts += ext(0, u16(len(entry)) + entry)
        exts += ext(10, u16(2 * len(groups)) + b"".join(u16(g) for g in groups))
        exts += ext(11, b"\x01\x00")
        if version >= TLS12:
            exts += ext(13, u16(2 * len(SIGALGS)) + b"".join(u16(a) for a in SIGALGS))
        if tls13:
            exts += ext(43, b"\x02\x03\x04") + ext(45, b"\x01\x01")
            g = key_share if key_share is not None else groups[0]
            ks = u16(g) + u16(len(keygen(g))) + keygen(g)
            exts += ext(51, u16(len(ks)) + ks)
        else:
            exts += ext(0xFF01, b"\x00") + ext(23) + ext(35) + ext(15, b"\x01")
            exts += ext(5, b"\x01\x00\x00\x00\x00")
        # pad to dodge F5-style 256..511 byte ClientHello bugs
        total = 4 + len(body) + 2 + len(exts)
        if 0x100 <= total < 0x200 + 4:
            pad = 0x200 + 4 - total - 4
            exts += ext(21, b"\x00" * max(pad, 1))
        body += u16(len(exts)) + exts
    hs = b"\x01" + u24(len(body)) + body
    rec_ver = SSL3 if version == SSL3 else TLS10
    return b"\x16" + u16(rec_ver) + u16(len(hs)) + hs


def ssl2_client_hello() -> bytes:
    specs = b"".join(c.to_bytes(3, "big") for c in SSL2_CIPHERS)
    challenge = os.urandom(16)
    body = b"\x01" + u16(2) + u16(len(specs)) + u16(0) + u16(len(challenge)) + specs + challenge
    return u16(0x8000 | len(body)) + body


# --------------------------------------------------------------------------------------
# probing engine
# --------------------------------------------------------------------------------------
@dataclass
class Target:
    host: str
    port: int
    ip: str
    timeout: float = 5.0
    workers: int = 8
    starttls: str | None = None   # "smtp": negotiate STARTTLS on the plaintext connection first
    ehlo: str = "sslcheck.invalid"

    @property
    def sni(self) -> str | None:
        return None if is_ip(self.host) else self.host


class StartTlsError(OSError):
    """The plaintext STARTTLS negotiation failed (not an SMTP server, STARTTLS missing or refused ...)."""


def _smtp_reply(sock: socket.socket, deadline: float) -> tuple[int, list[str]]:
    """Read one (possibly multi-line) SMTP reply; returns (code, line texts without the code)."""
    buf, lines = b"", []
    while True:
        while b"\n" not in buf:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            chunk = sock.recv(4096)
            if not chunk:
                raise StartTlsError("connection closed during SMTP negotiation")
            buf += chunk
            if len(buf) > 65536:
                raise StartTlsError("oversized SMTP reply")
        raw, _, buf = buf.partition(b"\n")
        line = raw.rstrip(b"\r").decode("latin-1")
        if len(line) < 3 or not line[:3].isdigit() or line[3:4] not in ("", " ", "-"):
            raise StartTlsError(f"not an SMTP reply: {line[:40]!r}")
        lines.append(line[4:])
        if line[3:4] != "-":
            return int(line[:3]), lines
        if len(lines) > 200:
            raise StartTlsError("oversized SMTP reply")


def smtp_starttls(sock: socket.socket, ehlo: str, timeout: float, info: dict) -> None:
    """Banner, EHLO, STARTTLS; afterwards the socket speaks TLS. Server details are stored in `info`."""
    def reply():
        return _smtp_reply(sock, time.monotonic() + timeout)

    code, lines = reply()
    info["banner"] = " ".join(lines)
    if code != 220:
        raise StartTlsError(f"SMTP server greeted with {code} {info['banner']}")
    sock.sendall(f"EHLO {ehlo}\r\n".encode("ascii"))
    code, lines = reply()
    info["greeting"], info["extensions"] = lines[0], [e for e in lines[1:] if e.strip()]
    if code != 250:
        raise StartTlsError(f"EHLO rejected: {code} {lines[0]}")
    if not any(e.split()[0].upper() == "STARTTLS" for e in info["extensions"]):
        raise StartTlsError("server does not advertise STARTTLS")
    sock.sendall(b"STARTTLS\r\n")
    code, lines = reply()
    if code != 220:
        raise StartTlsError(f"STARTTLS refused: {code} {lines[0]}")


def open_conn(t: Target, timeout: float | None = None, info: dict | None = None) -> socket.socket:
    """TCP connection to the target. With t.starttls the plaintext negotiation is done first, so
    the returned socket is ready for a TLS ClientHello in every case."""
    timeout = timeout or t.timeout
    sock = socket.create_connection((t.ip, t.port), timeout=timeout)
    if t.starttls == "smtp":
        try:
            smtp_starttls(sock, t.ehlo, timeout, info if info is not None else {})
            sock.settimeout(timeout)
        except Exception:
            sock.close()
            raise
    return sock


@dataclass
class Hello:
    ok: bool = False
    alert: tuple[int, int] | None = None
    version: int = 0
    cipher: int = 0
    compression: int = 0
    exts: dict = field(default_factory=dict)
    hrr: bool = False
    certs: list = field(default_factory=list)
    ske: bytes | None = None
    done: bool = False
    error: str | None = None
    sock: socket.socket | None = None

    @property
    def alert_name(self) -> str:
        return ALERTS.get(self.alert[1], str(self.alert[1])) if self.alert else ""


def _recv_exact(sock: socket.socket, n: int, deadline: float) -> bytes:
    buf = b""
    while len(buf) < n:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def read_record(sock: socket.socket, deadline: float):
    h = _recv_exact(sock, 5, deadline)
    t, v, n = h[0], struct.unpack(">H", h[1:3])[0], struct.unpack(">H", h[3:5])[0]
    if t not in (20, 21, 22, 23, 24) or (v >> 8) != 3 or n > 18432 + 2048:
        raise ValueError("not TLS")
    return t, v, _recv_exact(sock, n, deadline)


def _parse_server_hello(body: bytes, r: Hello) -> None:
    ver = struct.unpack_from(">H", body, 0)[0]
    random = body[2:34]
    sid_len = body[34]
    p = 35 + sid_len
    r.cipher = struct.unpack_from(">H", body, p)[0]
    r.compression = body[p + 2]
    p += 3
    if len(body) >= p + 2:
        end = p + 2 + struct.unpack_from(">H", body, p)[0]
        p += 2
        while p + 4 <= end:
            t, ln = struct.unpack_from(">HH", body, p)
            r.exts[t] = body[p + 4:p + 4 + ln]
            p += 4 + ln
    r.version = ver
    if 43 in r.exts and len(r.exts[43]) == 2:
        r.version = struct.unpack(">H", r.exts[43])[0]
    r.hrr = random == HRR_RANDOM
    r.ok = True


def _parse_certs(body: bytes) -> list[bytes]:
    out, p = [], 3
    end = 3 + int.from_bytes(body[0:3], "big")
    while p + 3 <= min(end, len(body)):
        ln = int.from_bytes(body[p:p + 3], "big")
        out.append(body[p + 3:p + 3 + ln])
        p += 3 + ln
    return out


def tls_probe(t: Target, data: bytes, keep: bool = False, timeout: float | None = None) -> Hello:
    """Send a ClientHello, read the server's first flight (until ServerHelloDone)."""
    r = Hello()
    timeout = timeout or t.timeout
    sock = None
    try:
        sock = open_conn(t, timeout)
        sock.sendall(data)
        deadline = time.monotonic() + timeout
        hs = b""
        stop = False
        while not stop:
            rtype, _, payload = read_record(sock, deadline)
            if rtype == 21:
                if len(payload) >= 2:
                    r.alert = (payload[0], payload[1])
                break
            if rtype != 22:
                if rtype == 20 and r.ok:
                    continue
                break
            hs += payload
            while len(hs) >= 4:
                mlen = int.from_bytes(hs[1:4], "big")
                if len(hs) < 4 + mlen:
                    break
                mtype, mbody, hs = hs[0], hs[4:4 + mlen], hs[4 + mlen:]
                if mtype == 2:
                    _parse_server_hello(mbody, r)
                    if r.version >= TLS13 or r.hrr:
                        stop = True
                        break
                elif mtype == 11:
                    r.certs = _parse_certs(mbody)
                elif mtype == 12:
                    r.ske = mbody
                elif mtype == 14:
                    r.done = True
                    stop = True
                    break
    except TimeoutError:
        r.error = "timeout"
    except EOFError:
        r.error = "eof"
    except ValueError:
        r.error = "not-tls"
    except OSError as e:
        r.error = type(e).__name__
    except Exception as e:  # malformed server hello etc.
        r.error = f"parse: {e}"
    if keep and r.ok and sock:
        r.sock = sock
    elif sock:
        sock.close()
    return r


def classify_reply(sock: socket.socket, timeout: float = 4.0) -> str:
    """Summarise what the server sends back (used for CCS/ROBOT oracles)."""
    deadline = time.monotonic() + timeout
    out: list[str] = []
    try:
        while len(out) < 3:
            t, _, p = read_record(sock, deadline)
            if t == 21 and len(p) == 2:
                out.append(f"alert:{ALERTS.get(p[1], p[1])}")
            else:
                out.append(f"rec{t}")
    except TimeoutError:
        out.append("timeout")
    except EOFError:
        out.append("eof")
    except ValueError:
        out.append("garbage")
    except OSError:
        out.append("reset")
    return "|".join(out)


def probe_sslv2(t: Target) -> list[str] | None:
    """Return the list of SSLv2 cipher names if the server speaks SSLv2, else None."""
    try:
        with open_conn(t) as s:
            s.sendall(ssl2_client_hello())
            deadline = time.monotonic() + t.timeout
            h = _recv_exact(s, 2, deadline)
            if not h[0] & 0x80:
                return None
            ln = ((h[0] & 0x7F) << 8) | h[1]
            body = _recv_exact(s, min(ln, 8192), deadline)
            if not body or body[0] != 4:
                return None
            cert_len, spec_len = struct.unpack_from(">HH", body, 5)
            specs = body[11 + cert_len:11 + cert_len + spec_len]
            names = []
            for i in range(0, len(specs) - 2, 3):
                code = int.from_bytes(specs[i:i + 3], "big")
                names.append(SSL2_CIPHERS.get(code, (f"0x{code:06X}", 0))[0])
            return names or ["(unknown)"]
    except (OSError, EOFError, ValueError):
        return None


# --------------------------------------------------------------------------------------
# protocol / cipher enumeration
# --------------------------------------------------------------------------------------
@dataclass
class Accepted:
    suite: Suite
    kx: dict | None = None


@dataclass
class Proto:
    version: int
    supported: bool = False
    accepted: list[Accepted] = field(default_factory=list)
    server_order: bool | None = None
    exts: set = field(default_factory=set)       # ServerHello extension ids at first accept
    certs: list = field(default_factory=list)    # (auth, [der, ...])


def kx_detail(s: Suite, ske: bytes | None) -> dict | None:
    if not ske:
        return None
    try:
        if s.kx.startswith("DHE") or s.kx == "DH_anon":
            plen = struct.unpack_from(">H", ske, 0)[0]
            p = int.from_bytes(ske[2:2 + plen], "big")
            return {"type": "DH", "bits": p.bit_length()}
        if s.kx.startswith("ECDHE") or s.kx == "ECDH_anon":
            if ske[0] == 3:
                cid = struct.unpack_from(">H", ske, 1)[0]
                return {"type": "ECDH", "curve": GROUP_NAMES.get(cid, f"0x{cid:04x}")}
    except (struct.error, IndexError):
        pass
    return None


def enumerate_version(t: Target, version: int) -> Proto:
    res = Proto(version)
    if version == TLS13:
        pool = [s for s in SUITES if s.tls13]
    else:
        pool = [s for s in SUITES if not s.tls13 and (version >= TLS12 or not s.tls12_only)]
    remaining = list(pool)
    while remaining:
        r = tls_probe(t, client_hello(version, [s.id for s in remaining], t.sni or t.host))
        if not r.ok or r.version != version or r.cipher not in {s.id for s in remaining}:
            break
        s = SUITE_BY_ID[r.cipher]
        res.accepted.append(Accepted(s, kx_detail(s, r.ske)))
        if not res.supported:
            res.supported = True
            res.exts = set(r.exts)
        if r.certs:
            res.certs.append((s.auth, r.certs))
        remaining = [x for x in remaining if x.id != s.id]
    if len(res.accepted) >= 2:
        ids = [a.suite.id for a in sorted(res.accepted, key=lambda a: [x.id for x in pool].index(a.suite.id))]
        host = t.sni or t.host
        a = tls_probe(t, client_hello(version, ids, host))
        b = tls_probe(t, client_hello(version, ids[::-1], host))
        if a.ok and b.ok:
            res.server_order = a.cipher == b.cipher
    return res


def best12(protos: dict[int, Proto]) -> Proto | None:
    for v in (TLS12, TLS11, TLS10, SSL3):
        if protos[v].supported:
            return protos[v]
    return None


# --------------------------------------------------------------------------------------
# certificate analysis
# --------------------------------------------------------------------------------------
def key_info(pub) -> tuple[str, int]:
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC ({pub.curve.name})", pub.key_size
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(pub).__name__, 0


def effective_bits(kind: str, bits: int) -> int:
    """Map EC / EdDSA key sizes to RSA-equivalent strength (as SSL Labs does)."""
    if kind.startswith(("EC", "Ed")):
        return 7680 if bits >= 384 else 3072 if bits >= 256 else 2048 if bits >= 224 else 1024 if bits >= 160 else 512
    return bits


def host_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.split(".", 1)[1] == n[2:]:
            return True
    return False


def _ext(cert, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def is_issued_by(cert, issuer) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
        return False


def analyze_cert(cert: x509.Certificate, host: str) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    kind, bits = key_info(cert.public_key())
    try:
        hash_name = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except UnsupportedAlgorithm:
        hash_name = None
    san = _ext(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    names = []
    if san:
        names += san.get_values_for_type(x509.DNSName)
        names += [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    aia = _ext(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    ocsp_urls, ca_issuers = [], []
    for d in aia or []:
        if d.access_method == AuthorityInformationAccessOID.OCSP:
            ocsp_urls.append(d.access_location.value)
        elif d.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            ca_issuers.append(d.access_location.value)
    crl = _ext(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS)
    crl_urls = [n.value for dp in (crl or []) for n in (dp.full_name or [])
                if isinstance(n, x509.UniformResourceIdentifier)]
    tlsf = _ext(cert, ExtensionOID.TLS_FEATURE)
    bc = _ext(cert, ExtensionOID.BASIC_CONSTRAINTS)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": nb.isoformat(), "not_after": na.isoformat(),
        "days_left": (na - now).days, "lifetime_days": (na - nb).days,
        "expired": na < now, "not_yet_valid": nb > now,
        "key_type": kind, "key_bits": bits,
        "sig_alg": getattr(cert.signature_algorithm_oid, "_name", cert.signature_algorithm_oid.dotted_string),
        "sig_hash": hash_name,
        "weak_sig": hash_name in ("md5", "sha1", "md2"),
        "san": names, "hostname_match": host_matches(host, names),
        "ocsp_urls": ocsp_urls, "ca_issuers": ca_issuers, "crl_urls": crl_urls,
        "must_staple": bool(tlsf and x509.TLSFeatureType.status_request in tlsf),
        "sct": _ext(cert, ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS) is not None,
        "is_ca": bool(bc and bc.ca),
        "self_signed": cert.subject == cert.issuer and is_issued_by(cert, cert),
        "sha256": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        "pin_sha256": base64.b64encode(hashlib.sha256(spki).digest()).decode(),
    }


def analyze_chain(chain_der: list[bytes], host: str) -> dict:
    certs = [x509.load_der_x509_certificate(d) for d in chain_der]
    items = [analyze_cert(c, host) for c in certs]
    issues = []
    linked = True
    seen = set()
    for i, it in enumerate(items):
        if it["sha256"] in seen:
            issues.append(f"certificate #{i + 1} is a duplicate of an earlier certificate in the chain")
        seen.add(it["sha256"])
    for i in range(len(certs) - 1):
        if not is_issued_by(certs[i], certs[i + 1]):
            linked = False
    if not linked:
        # distinguish "wrong order / extras" from "leaf issuer missing"
        if not any(is_issued_by(certs[0], c) for c in certs[1:]) and not items[0]["self_signed"]:
            issues.append("chain incomplete: issuing intermediate of the leaf is not in the chain sent")
        else:
            issues.append("chain not in order (each certificate should be followed by its issuer)")
    if len(certs) == 1 and not items[0]["self_signed"]:
        issues.append("chain incomplete: server did not send the issuing intermediate certificate")
    for i, it in enumerate(items):
        if i > 0 and it["weak_sig"] and not it["self_signed"]:
            issues.append(f"intermediate #{i + 1} signed with {it['sig_hash']}")
        if i > 0 and it["expired"]:
            issues.append(f"intermediate #{i + 1} expired")
    for i, it in enumerate(items):
        if i > 0 and it["self_signed"]:
            issues.append(f"chain contains trust anchor #{i + 1} ({it['subject']}); it should be omitted")
    return {"certs": items, "linked": linked, "issues": issues, "_objs": certs}


def fetch_issuer(cert_info: dict) -> x509.Certificate | None:
    for url in cert_info["ca_issuers"]:
        if not url.startswith("http"):
            continue
        try:
            data = urllib.request.urlopen(url, timeout=8).read()
            try:
                return x509.load_der_x509_certificate(data)
            except ValueError:
                return x509.load_pem_x509_certificate(data)
        except Exception:
            continue
    return None


def ocsp_check(chain: dict) -> dict:
    leaf_o, info = chain["_objs"][0], chain["certs"][0]
    if not info["ocsp_urls"]:
        return {"status": "n/a", "detail": "no OCSP responder in certificate"
                + (" (CRL only)" if info["crl_urls"] else "")}
    issuer = next((c for c in chain["_objs"][1:] if is_issued_by(chain["_objs"][0], c)), None) or fetch_issuer(info)
    if issuer is None:
        return {"status": "unknown", "detail": "issuer certificate unavailable"}
    try:
        req = ocsp.OCSPRequestBuilder().add_certificate(leaf_o, issuer, hashes.SHA1()).build()
        rq = urllib.request.Request(info["ocsp_urls"][0], req.public_bytes(serialization.Encoding.DER),
                                    {"Content-Type": "application/ocsp-request"})
        resp = ocsp.load_der_ocsp_response(urllib.request.urlopen(rq, timeout=8).read())
        if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return {"status": "unknown", "detail": resp.response_status.name}
        out = {"status": resp.certificate_status.name.lower(), "detail": info["ocsp_urls"][0]}
        if resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            out["revoked_at"] = str(resp.revocation_time_utc)
        return out
    except Exception as e:
        return {"status": "unknown", "detail": f"{type(e).__name__}: {e}"}


# --------------------------------------------------------------------------------------
# checks that use Python's ssl module (trust, ALPN, resumption, HTTP)
# --------------------------------------------------------------------------------------
def _liberal_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        pass
    return ctx


def _connect(t: Target, ctx: ssl.SSLContext, **kw) -> ssl.SSLSocket:
    s = open_conn(t)
    try:
        return ctx.wrap_socket(s, server_hostname=t.sni, **kw)
    except Exception:
        s.close()
        raise


def check_trust(t: Target) -> dict:
    ctx = ssl.create_default_context()
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    try:
        with _connect(t, ctx) as s:
            return {"trusted": True, "error": None, "protocol": s.version(), "cipher": s.cipher()[0]}
    except ssl.SSLCertVerificationError as e:
        return {"trusted": False, "error": e.verify_message, "code": e.verify_code,
                "hostname_error": "hostname" in e.verify_message.lower() or e.verify_code == 62}
    except (ssl.SSLError, OSError) as e:
        return {"trusted": None, "error": f"{type(e).__name__}: {e}"}


def verify_with_store(chain: dict, host: str) -> dict:
    """Offline path validation against the system CA bundle (used when Python's own TLS stack
    cannot negotiate with the server, e.g. RC4-only / SSLv3-only servers)."""
    from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
    paths = ssl.get_default_verify_paths()
    bundle = next((p for p in (paths.cafile, paths.openssl_cafile, "/etc/ssl/certs/ca-certificates.crt",
                               "/etc/pki/tls/certs/ca-bundle.crt") if p and os.path.isfile(p)), None)
    if not bundle:
        return {"trusted": None, "error": "system CA bundle not found"}
    with open(bundle, "rb") as fh:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # some system roots have non-RFC-5280 serials
            roots = x509.load_pem_x509_certificates(fh.read())
    objs = chain["_objs"]
    name = x509.IPAddress(ipaddress.ip_address(host)) if is_ip(host) else x509.DNSName(host)
    try:
        PolicyBuilder().store(Store(roots)).build_server_verifier(name).verify(objs[0], objs[1:])
        return {"trusted": True, "error": None, "method": "offline"}
    except VerificationError as e:
        msg = str(e).split(" (encountered")[0]
        return {"trusted": False, "error": msg, "method": "offline",
                "hostname_error": "subject" in msg.lower() and "match" in msg.lower()}


def fallback_chain(t: Target) -> list[bytes]:
    ctx = _liberal_ctx()
    with _connect(t, ctx) as s:
        if hasattr(s, "get_unverified_chain"):
            return [c if isinstance(c, bytes) else c.public_bytes(ssl.ENCODING_DER)
                    for c in s.get_unverified_chain()]
        return [s.getpeercert(binary_form=True)]


def check_alpn(t: Target) -> dict:
    out = {}
    for proto in ("h2", "http/1.1"):
        ctx = _liberal_ctx()
        ctx.set_alpn_protocols([proto])
        try:
            with _connect(t, ctx) as s:
                out[proto] = s.selected_alpn_protocol() == proto
        except (ssl.SSLError, OSError):
            out[proto] = False
    return out


def check_resumption(t: Target) -> dict:
    ctx = _liberal_ctx()
    try:
        with _connect(t, ctx) as s:
            s.sendall(f"HEAD / HTTP/1.1\r\nHost: {t.host}\r\nConnection: close\r\n\r\n".encode())
            try:
                s.recv(4096)
            except (OSError, ssl.SSLError):
                pass
            sess, version = s.session, s.version()
        if sess is None:
            return {"resumption": False, "protocol": version}
        for _ in range(2):  # multi-node frontends may miss the ticket on the first try
            with _connect(t, ctx, session=sess) as s2:
                if s2.session_reused:
                    return {"resumption": True, "protocol": version}
        return {"resumption": False, "protocol": version}
    except (ssl.SSLError, OSError) as e:
        return {"resumption": None, "error": str(e)}


def check_http(t: Target) -> dict:
    try:
        ctx = _liberal_ctx()
        tls = _connect(t, ctx)
        conn = http.client.HTTPSConnection(t.host, t.port, timeout=t.timeout)
        conn.sock = tls
        conn.request("GET", "/", headers={"User-Agent": "sslcheck/1.0", "Connection": "close",
                                          "Accept": "*/*"})
        resp = conn.getresponse()
        h = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    out = {"status": resp.status, "server": h.get("server"), "alt_svc": h.get("alt-svc"),
           "location": h.get("location"), "hsts": None}
    sts = h.get("strict-transport-security")
    if sts:
        m = re.search(r"max-age\s*=\s*\"?(\d+)", sts, re.I)
        out["hsts"] = {"raw": sts, "max_age": int(m.group(1)) if m else 0,
                       "include_subdomains": "includesubdomains" in sts.lower(),
                       "preload": "preload" in sts.lower()}
    return out


# --------------------------------------------------------------------------------------
# protocol-level probes (feature / vulnerability checks)
# --------------------------------------------------------------------------------------
def check_compression(t: Target, p12: Proto | None) -> dict:
    if not p12:
        return {"status": "n/a"}
    ids = [a.suite.id for a in p12.accepted]
    r = tls_probe(t, client_hello(p12.version, ids, t.sni or t.host, compress=True))
    if not r.ok:
        return {"status": "unknown"}
    return {"status": "vulnerable" if r.compression != 0 else "ok"}


def check_fallback_scsv(t: Target, protos: dict[int, Proto]) -> dict:
    sup = [v for v in PROBE_VERSIONS if protos[v].supported]
    low = [v for v in sup if v <= TLS12 and v < max(sup, default=0)]
    if not low:
        return {"status": "n/a", "detail": "server supports a single protocol version"}
    v = max(low)
    ids = [a.suite.id for a in protos[v].accepted]
    r = tls_probe(t, client_hello(v, ids, t.sni or t.host, fallback_scsv=True))
    if r.alert and r.alert[1] == 86:
        return {"status": "ok", "detail": "inappropriate_fallback alert received"}
    if r.ok:
        return {"status": "missing", "detail": f"downgrade to {VERSION_NAMES[v]} accepted"}
    return {"status": "unknown", "detail": r.alert_name or r.error}


def check_groups(t: Target, protos: dict[int, Proto]) -> dict:
    out: dict[str, list[str]] = {}
    host = t.sni or t.host
    p12 = best12(protos)
    if p12:
        ec_ids = [a.suite.id for a in p12.accepted if a.suite.kx.startswith("ECDHE")]
        if ec_ids:
            found = []
            for g in PROBE_GROUPS:
                r = tls_probe(t, client_hello(p12.version, ec_ids, host, groups=(g,)))
                d = kx_detail(SUITE_BY_ID[r.cipher], r.ske) if r.ok and r.cipher in SUITE_BY_ID else None
                if r.ok and d and d.get("curve") == GROUP_NAMES[g]:
                    found.append(GROUP_NAMES[g])
            out["TLS 1.2"] = found
    if protos[TLS13].supported:
        ids = [a.suite.id for a in protos[TLS13].accepted]
        found = []
        for g in PROBE_GROUPS:
            r = tls_probe(t, client_hello(TLS13, ids, host, groups=(g,), key_share=g))
            if r.ok and r.version == TLS13:
                found.append(GROUP_NAMES[g])
        out["TLS 1.3"] = found
    return out


def check_heartbleed(t: Target, p12: Proto | None) -> dict:
    if not p12:
        return {"status": "n/a"}
    ids = [a.suite.id for a in p12.accepted]
    r = tls_probe(t, client_hello(p12.version, ids, t.sni or t.host), keep=True)
    if not (r.ok and r.done and r.sock):
        return {"status": "unknown"}
    try:
        if 15 not in r.exts:
            return {"status": "ok", "detail": "heartbeat extension not offered by server"}
        r.sock.sendall(b"\x18" + u16(p12.version) + u16(3) + b"\x01\x40\x00")
        try:
            t_, _, payload = read_record(r.sock, time.monotonic() + 4)
            if t_ == 24:
                return {"status": "vulnerable", "detail": f"server returned {len(payload)} bytes of heartbeat data"}
        except (TimeoutError, EOFError, ValueError, OSError):
            pass
        return {"status": "ok"}
    finally:
        r.sock.close()


def check_ccs(t: Target, p12: Proto | None) -> dict:
    if not p12:
        return {"status": "n/a"}
    ids = [a.suite.id for a in p12.accepted]
    r = tls_probe(t, client_hello(p12.version, ids, t.sni or t.host), keep=True)
    if not (r.ok and r.done and r.sock):
        return {"status": "unknown"}
    ccs = b"\x14" + u16(p12.version) + u16(1) + b"\x01"
    try:
        r.sock.sendall(ccs)
        first = classify_reply(r.sock, 3.0)
        if first.startswith(("alert", "eof", "reset")):
            return {"status": "ok", "detail": first.split("|")[0]}
        r.sock.sendall(ccs)
        second = classify_reply(r.sock, 3.0)
        if any(a in second for a in ("bad_record_mac", "decryption_failed", "decrypt_error")):
            return {"status": "vulnerable", "detail": "premature CCS accepted (CVE-2014-0224)"}
        return {"status": "unknown", "detail": f"no alert for stray CCS ({first} / {second})"}
    finally:
        r.sock.close()


def _pkcs1_block(k: int, variant: int) -> bytes:
    rnd = lambda n: bytes((b % 255) + 1 for b in os.urandom(n))  # non-zero bytes
    pms_len = 48
    if variant == 0:     # valid padding, right version
        return b"\x00\x02" + rnd(k - 3 - pms_len) + b"\x00" + b"\x03\x03" + os.urandom(pms_len - 2)
    if variant == 1:     # invalid first bytes
        return b"\x41\x17" + rnd(k - 3 - pms_len) + b"\x00" + b"\x03\x03" + os.urandom(pms_len - 2)
    if variant == 2:     # 0x00 separator in wrong position
        return b"\x00\x02" + rnd(k - 3 - pms_len - 10) + b"\x00" + rnd(10) + b"\x03\x03" + os.urandom(pms_len - 2)
    if variant == 3:     # no 0x00 separator
        return b"\x00\x02" + rnd(k - 2)
    # variant 4: valid padding, wrong version in premaster
    return b"\x00\x02" + rnd(k - 3 - pms_len) + b"\x00" + b"\x02\x02" + os.urandom(pms_len - 2)


def check_robot(t: Target, protos: dict[int, Proto]) -> dict:
    cands = [(p, a.suite) for p in (protos[v] for v in (TLS12, TLS11, TLS10)) if p.supported
             for a in p.accepted if a.suite.kx == "RSA"]
    if not cands:
        return {"status": "ok", "detail": "no RSA key-exchange cipher suites offered"}
    proto, suite = cands[0]
    host = t.sni or t.host
    results: list[list[str]] = []
    for _ in range(2):
        row = []
        for variant in range(5):
            r = tls_probe(t, client_hello(proto.version, [suite.id], host), keep=True)
            if not (r.ok and r.done and r.sock and r.certs):
                if r.sock:
                    r.sock.close()
                return {"status": "unknown", "detail": "could not complete handshake flight"}
            try:
                pub = x509.load_der_x509_certificate(r.certs[0]).public_key()
                if not isinstance(pub, rsa.RSAPublicKey):
                    return {"status": "unknown", "detail": "non-RSA certificate"}
                nums = pub.public_numbers()
                k = (nums.n.bit_length() + 7) // 8
                enc = pow(int.from_bytes(_pkcs1_block(k, variant), "big"), nums.e, nums.n).to_bytes(k, "big")
                cke = b"\x10" + u24(len(enc) + 2) + u16(len(enc)) + enc
                v = u16(proto.version)
                r.sock.sendall(b"\x16" + v + u16(len(cke)) + cke
                               + b"\x14" + v + u16(1) + b"\x01"
                               + b"\x16" + v + u16(40) + os.urandom(40))
                row.append(classify_reply(r.sock, 3.0))
            except OSError:
                row.append("reset")
            finally:
                r.sock.close()
        results.append(row)
    a, b = results
    stable = [x == y for x, y in zip(a, b)]
    distinct = set(a)
    if len(distinct) == 1:
        return {"status": "ok", "detail": f"identical response to all padding variants ({a[0]})"}
    if all(stable):
        return {"status": "vulnerable", "detail": "distinguishable responses: " + ", ".join(
            f"v{i}={x}" for i, x in enumerate(a))}
    return {"status": "unknown", "detail": "responses differ but are unstable (timing noise)"}


# --------------------------------------------------------------------------------------
# scoring (SSL Labs rating guide, approximated)
# --------------------------------------------------------------------------------------
GRADE_ORDER = ["A+", "A", "A-", "B", "C", "D", "E", "F"]
PROTO_SCORE = {SSL2: 0, SSL3: 80, TLS10: 90, TLS11: 95, TLS12: 100, TLS13: 100}


def _kx_score(bits: int) -> int:
    return 20 if bits < 512 else 40 if bits < 1024 else 80 if bits < 2048 else 90 if bits < 4096 else 100


def _cipher_score(bits: int) -> int:
    return 0 if bits == 0 else 20 if bits < 128 else 80 if bits < 256 else 100


def letter(score: float) -> str:
    return "A" if score >= 80 else "B" if score >= 65 else "C" if score >= 50 else "D" if score >= 35 \
        else "E" if score >= 20 else "F"


def compute_grade(rep: dict) -> dict:
    protos: dict[int, Proto] = rep["_protos"]
    sup = [v for v in PROBE_VERSIONS if protos[v].supported]
    if rep["sslv2"]:
        sup.append(SSL2)
    notes: list[str] = []
    caps: list[tuple[str, str]] = []          # (max grade, reason)
    if not sup:
        return {"grade": "-", "score": None, "notes": ["no TLS service detected"]}

    proto_score = (PROTO_SCORE[max(sup)] + PROTO_SCORE[min(sup)]) / 2

    accepted = [a for v in PROBE_VERSIONS for a in protos[v].accepted]
    bits = [a.suite.bits for a in accepted]
    if rep["sslv2"]:
        bits += [b for _, b in SSL2_CIPHERS.values()]
    cipher_score = (_cipher_score(max(bits)) + _cipher_score(min(bits))) / 2 if bits else 0

    key_bits = []
    for c in rep.get("chains", []):
        leaf = c["certs"][0]
        key_bits.append(effective_bits(leaf["key_type"], leaf["key_bits"]))
    dh_bits = [a.kx["bits"] for a in accepted if a.kx and a.kx["type"] == "DH"]
    kx_bits = min(key_bits + dh_bits) if (key_bits or dh_bits) else 0
    kx_score = 0 if any(a.suite.anon for a in accepted) else _kx_score(kx_bits) if kx_bits else 0
    total = round(0.3 * proto_score + 0.3 * kx_score + 0.4 * cipher_score, 1)
    base = letter(total)

    # --- hard failures -----------------------------------------------------------
    trust = rep["trust"]
    overall: str | None = None
    if trust.get("trusted") is False:
        overall = "M" if trust.get("hostname_error") else "T"
        notes.append(f"certificate not trusted: {trust.get('error')}")
    for ch in rep.get("chains", []):
        leaf = ch["certs"][0]
        if leaf["expired"] or leaf["not_yet_valid"]:
            overall = overall or "T"
            notes.append("certificate expired / not yet valid")
        if not leaf["hostname_match"] and overall is None:
            overall = "M"
            notes.append("certificate does not match hostname")
        if leaf["weak_sig"]:
            overall = overall or "T"
            notes.append(f"leaf certificate signed with {leaf['sig_hash']}")
    if rep["sslv2"]:
        caps.append(("F", "SSL 2.0 supported (DROWN)"))
    if any(a.suite.anon or a.suite.export or a.suite.mode == "NONE" for a in accepted):
        caps.append(("F", "anonymous / export / NULL cipher suites accepted"))
    for name in ("heartbleed", "ccs", "robot"):
        if rep["vulns"].get(name, {}).get("status") == "vulnerable":
            caps.append(("F", f"vulnerable to {name}"))
    if any(c["certs"][0]["key_type"] in ("RSA", "DSA") and c["certs"][0]["key_bits"] < 1024
           for c in rep.get("chains", [])):
        caps.append(("F", "certificate key < 1024 bits"))
    # --- caps --------------------------------------------------------------------
    if rep["features"].get("secure_renegotiation") is False:
        caps.append(("C", "secure renegotiation not supported"))
    if protos[SSL3].supported:
        caps.append(("C", "SSL 3.0 supported (POODLE)"))
    if not protos[TLS12].supported and not protos[TLS13].supported:
        caps.append(("C", "TLS 1.2 not supported"))
    if any(a.suite.block64 for a in accepted):
        caps.append(("C", "64-bit block cipher accepted (Sweet32)"))
    if any("RC4" in a.suite.enc for a in accepted):
        caps.append(("C", "RC4 accepted"))
    if rep["vulns"].get("crime", {}).get("status") == "vulnerable":
        caps.append(("C", "TLS compression enabled (CRIME)"))
    if any(c["certs"][0]["key_type"] == "RSA" and c["certs"][0]["key_bits"] < 2048 for c in rep.get("chains", [])):
        caps.append(("C", "RSA key < 2048 bits"))
    if protos[TLS10].supported or protos[TLS11].supported:
        caps.append(("B", "TLS 1.0 / 1.1 supported"))
    if accepted and not any(a.suite.fs for a in accepted):
        caps.append(("B", "no forward secrecy"))
    if dh_bits and min(dh_bits) < 1024:
        caps.append(("F", f"DH parameters {min(dh_bits)} bits (Logjam)"))
    elif dh_bits and min(dh_bits) < 2048:
        caps.append(("B", f"weak DH parameters ({min(dh_bits)} bits)"))
    for ch in rep.get("chains", []):
        if any("incomplete" in i for i in ch["issues"]):
            caps.append(("B", "certificate chain incomplete"))
            break

    grade = base
    for g, reason in caps:
        if GRADE_ORDER.index(g) > GRADE_ORDER.index(grade):
            notes.append(f"capped at {g}: {reason}")
            grade = g
    if overall:
        grade = overall
    elif grade == "A":
        hsts = rep.get("http", {}).get("hsts")
        if hsts and hsts["max_age"] >= 15768000:
            grade = "A+"
    return {"grade": grade, "score": total, "protocol_score": proto_score, "key_exchange_score": kx_score,
            "cipher_score": cipher_score, "notes": notes}


# --------------------------------------------------------------------------------------
# client handshake simulation
# --------------------------------------------------------------------------------------
# Each profile replays the ClientHello of a real client (protocol range, cipher suites and their
# order, extensions and their order, groups, signature algorithms). The server's answer is then
# judged with the limits that client's TLS library enforces after the ServerHello (DH size, RSA /
# ECDSA key size, SHA-1 certificates, ...). Data derived from published ClientHello captures
# (Qualys SSL Labs client list, as redistributed in testssl.sh's etc/client-simulation.txt); SNI and
# key_share payloads are regenerated. Trust-store differences between clients are NOT modelled.
#
# row: (name, client_version, record_version, max_version, min_version, cipher suites,
#       extensions "type[:hex]" ("0000" = SNI, "0033:@" = fresh key_share, "0015" = padding), options)
_CLIENT_DATA = [
    ('Android 2.3.7', 0x0301, 0x0301, 0x0301, 0x0300,
     '0004 0005 002f 0033 0032 000a 0016 0013 0009 0015 0012 0003 0008 0014 0011 00ff ',
     ' ',
     {}),
    ('Android 4.0.4', 0x0301, 0x0301, 0x0301, 0x0300,
     'c014 c00a 0039 0038 c00f c005 0035 c012 c008 0016 0013 c00d c003 000a c013 c009 0033 '
     '0032 c00e c004 002f c011 c007 c00c c002 0005 0004 00ff ',
     '0000 000b:03000102 '
     '000a:0032000100020003000400050006000700080009000a000b000c000d000e000f0010001100120013001400150016001700180019 '
     '0023 3374 ',
     {'deflate': True}),
    ('Android 4.3', 0x0301, 0x0301, 0x0301, 0x0300,
     'c014 c00a c022 c021 0039 0038 c00f c005 0035 c012 c008 c01c c01b 0016 0013 c00d c003 '
     '000a c013 c009 c01f c01e 0033 0032 c00e c004 002f c011 c007 c00c c002 0005 0004 00ff ',
     '0000 000b:03000102 '
     '000a:0032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f00100011 '
     '0023 3374 ',
     {}),
    ('Android 4.4.2', 0x0303, 0x0301, 0x0303, 0x0300,
     'c030 c02c c014 c00a 00a3 009f 006b 006a 0039 0038 009d 003d 0035 c012 c008 0016 0013 '
     '000a c02f c02b c027 c023 c013 c009 00a2 009e 0067 0040 0033 0032 009c 003c 002f c011 '
     'c007 0005 0004 00ff ',
     '0000 000b:0100 000a:0006001900180017 0023 '
     '000d:00200601060206030501050205030401040204030301030203030201020202030101 3374 ',
     {}),
    ('Android 5.0.0', 0x0303, 0x0301, 0x0303, 0x0300,
     'cc14 cc13 cc15 c014 c00a 0039 0038 0035 c012 c008 0016 0013 000a c02f c02b c013 c009 '
     '00a2 009e 0033 0032 009c 002f c011 c007 0005 0004 00ff ',
     '0000 0023 000d:00200601060206030501050205030401040204030301030203030201020202030101 '
     '3374 000b:0100 000a:0006001900180017 ',
     {}),
    ('Android 6.0', 0x0303, 0x0301, 0x0303, 0x0301,
     'cc14 cc13 cc15 c02b c02f 009e c00a c014 0039 c009 c013 0033 009c 0035 002f 000a 00ff ',
     '0000 0017 0023 000d:00140601060305010503040104030301030302010203 0005:0100000000 '
     '3374 0012 0010:001208687474702f312e3108737064792f332e31 000b:0100 000a:000400170018 ',
     {}),
    ('Android 7.0 (native)', 0x0303, 0x0301, 0x0303, 0x0301,
     'c02b c02c cca9 c02f c030 cca8 c013 c014 009c 009d 002f 0035 ',
     'ff01:00 0000 0017 0023 000d:00140601060305010503040104030301030302010203 '
     '0010:000c02683208687474702f312e31 000b:0100 000a:00020017 ',
     {}),
    ('Android 8.1 (native)', 0x0303, 0x0301, 0x0303, 0x0301,
     'c02b c02c cca9 c02f c030 cca8 c009 c00a c013 c014 009c 009d 002f 0035 ',
     '0000 0017 ff01:00 000a:0006001d00170018 000b:0100 0005:0100000000 '
     '000d:0012040308040401050308050501080606010201 ',
     {}),
    ('Android 9.0 (native)', 0x0303, 0x0301, 0x0304, 0x0301,
     '0a0a 1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035 000a ',
     '7a7a 0000 0017 ff01:00 000a:0008aaaa001d00170018 000b:0100 0023 '
     '0010:000c02683208687474702f312e31 0005:0100000000 '
     '000d:0012040308040401050308050501080606010201 0012 0033:@ 002d:0101 '
     '002b:0aeaea0304030303020301 001b:020002 6a6a:00 ',
     {}),
    ('Android 13/14 (native)', 0x0303, 0x0301, 0x0304, 0x0303,
     '1301 1302 1303 c02b c02c cca9 c02f c030 cca8 c009 c00a c013 c014 009c 009d 002f 0035 ',
     '0000 0017 ff01:00 000a:0006001d00170018 000b:0100 0023 0010:000908687474702f312e31 '
     '0005:0100000000 000d:0012040308040401050308050501080606010201 0033:@ 002d:0101 '
     '002b:0403040303 ',
     {}),
    ('Chrome 49 XP SP3', 0x0303, 0x0301, 0x0303, 0x0301,
     'c02f cca8 cc13 c014 c013 009c 0035 002f 000a ',
     'ff01:00 0000 0017 0023 000d:00140601060305010503040104030301030302010203 '
     '0005:0100000000 3374 0012 0010:001502683208737064792f332e3108687474702f312e31 7550 '
     '000b:0100 000a:000400170018 ',
     {'dh_min': 1024}),
    ('Chrome 57 Win 7', 0x0303, 0x0301, 0x0304, 0x0301,
     '3a3a 1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035 000a ',
     '3a3a ff01:00 0000 0017 0023 000d:0012040308040401050308050501080606010201 '
     '0005:0100000000 0012 0010:000c02683208687474702f312e31 7550 000b:0100 '
     '0028:00290a0a000100001d0020beb55ec17fee5371560958f78db49d4dc33723e42a200b24646b6d77a7a94867 '
     '002d:0101 002b:0aaaaa7f12030303020301 000a:00080a0a001d00170018 dada:00 0015 ',
     {'dh_min': 1024}),
    ('Chrome 70 Win 10', 0x0303, 0x0301, 0x0304, 0x0301,
     '9a9a 1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035 000a ',
     '3a3a ff01:00 0000 0017 0023 000d:0012040308040401050308050501080606010201 '
     '0005:0100000000 0012 0010:000c02683208687474702f312e31 7550 000b:0100 0033:@ '
     '002d:0101 002b:0a0a0a0304030303020301 000a:00081a1a001d00170018 001b:020002 2a2a:00 '
     '0015 ',
     {'dh_min': 1024}),
    ('Chrome 101 (Win 10)', 0x0303, 0x0301, 0x0304, 0x0303,
     '1a1a 1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035 ',
     '2a2a 0000 0017 ff01:00 000a:00083a3a001d00170018 000b:0100 0023 '
     '0010:000c02683208687474702f312e31 0005:0100000000 '
     '000d:001004030804040105030805050108060601 0012 0033:@ 002d:0101 002b:06aaaa03040303 '
     '001b:020002 4469:0003026832 4a4a:00 0015 ',
     {'dh_min': 1024, 'sha2_only': True}),
    ('Chromium 137 (Win 11)', 0x0303, 0x0301, 0x0304, 0x0303,
     'eaea 1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035 ',
     '4a4a 0023 0033:@ 002d:0101 0005:0100000000 000d:001004030804040105030805050108060601 '
     '0000 0010:000c02683208687474702f312e31 002b:06dada03040303 0017 0012 44cd:0003026832 '
     '000b:0100 001b:020002 000a:000a9a9a11ec001d00170018 ff01:00 8a8a:00 ',
     {'dh_min': 1024, 'sha2_only': True}),
    ('Firefox 31.3.0 ESR Win 7', 0x0303, 0x0301, 0x0303, 0x0301,
     'c02b c02f c00a c009 c013 c014 c012 c007 c011 0033 0032 0045 0039 0038 0088 0016 002f '
     '0041 0035 0084 000a 0005 0004 ',
     '0000 ff01:00 000a:0006001700180019 000b:0100 0023 3374 0005:0100000000 '
     '000d:001004010501020104030503020304020202 ',
     {}),
    ('Firefox 47 Win 7', 0x0303, 0x0301, 0x0303, 0x0301,
     'c02b c02f cca9 cca8 c00a c009 c013 c014 0033 0039 002f 0035 000a ',
     '0000 0017 ff01:00 000a:0006001700180019 000b:0100 0023 3374 '
     '0010:001502683208737064792f332e3108687474702f312e31 0005:0100000000 '
     '000d:00140401050106010201040305030603020304020202 ',
     {'dh_min': 1023}),
    ('Firefox 62 Win 7', 0x0303, 0x0301, 0x0304, 0x0301,
     '1301 1303 1302 c02b c02f cca9 cca8 c02c c030 c013 c014 002f 0035 000a ',
     '0000 0017 ff01:00 000a:000c001d00170018001901000101 000b:0100 0023 '
     '0010:000c02683208687474702f312e31 0005:0100000000 0033:@ 002b:087f1c030303020301 '
     '000d:001604030503060308040805080604010501060102030201 002d:0101 0015 ',
     {'dh_min': 1023}),
    ('Firefox 100 (Win 10)', 0x0303, 0x0301, 0x0304, 0x0303,
     '1301 1303 1302 c02b c02f cca9 cca8 c02c c030 c00a c009 c013 c014 009c 009d 002f 0035 ',
     '0000 0017 ff01:00 000a:000c001d00170018001901000101 000b:0100 0023 '
     '0010:000c02683208687474702f312e31 0005:0100000000 0022:00080403050306030203 0033:@ '
     '002b:0403040303 000d:001604030503060308040805080604010501060102030201 002d:0101 '
     '001c:4001 0015 ',
     {'dh_min': 1023}),
    ('Firefox 137 (Win 11)', 0x0303, 0x0301, 0x0304, 0x0303,
     '1301 1303 1302 c02b c02f cca9 cca8 c02c c030 c00a c009 c013 c014 009c 009d 002f 0035 ',
     '0000 0017 ff01:00 000a:000e11ec001d00170018001901000101 000b:0100 0023 '
     '0010:000c02683208687474702f312e31 0005:0100000000 0022:00080403050306030203 0012 '
     '0033:@ 002b:0403040303 000d:001604030503060308040805080604010501060102030201 '
     '002d:0101 001c:4001 001b:06000100020003 ',
     {'dh_min': 1023}),
    ('Googlebot Feb 2018', 0x0303, 0x0301, 0x0303, 0x0300,
     'c02b c02f cca9 cca8 c02c c030 c009 c013 c00a c014 009c 009d 002f 0035 000a ',
     'ff01:00 0000 0017 0023 000d:0012040308040401050308050501080606010201 0005:0100000000 '
     '3374 0012 000b:0100 000a:0006001d00170018 ',
     {}),
    ('IE 7 Vista', 0x0301, 0x0301, 0x0301, 0x0300,
     '002f 0035 0005 000a c009 c00a c013 c014 0032 0038 0013 0004 ',
     '0000 0005:0100000000 000a:0006001700180019 000b:0100 ff01:00 ',
     {}),
    ('IE 8 XP', 0x0301, 0x0301, 0x0301, 0x0300,
     '0004 0005 000a 0009 0064 0062 0003 0006 0013 0012 0063 ',
     'ff01:00 ',
     {}),
    ('IE 8-10 Win 7', 0x0301, 0x0301, 0x0301, 0x0300,
     'c014 c013 0035 002f c00a c009 0038 0032 000a 0013 0005 0004 ',
     '0000 0005:0100000000 000a:0006001700180019 000b:0100 ff01:00 ',
     {'dh_min': 1024, 'dh_max': 4096, 'rsa_max': 16384}),
    ('IE 11 Win 7', 0x0303, 0x0303, 0x0303, 0x0301,
     'c028 c027 c014 c013 009f 009e 009d 009c 003d 003c 0035 002f c02c c02b c024 c023 c00a '
     'c009 006a 0040 0038 0032 000a 0013 ',
     '0000 0005:0100000000 000a:000400170018 000b:0100 '
     '000d:0012060106030401050102010403050302030202 0017 ff01:00 ',
     {'dh_min': 1024, 'dh_max': 4096, 'rsa_max': 16384}),
    ('IE 11 Win 10', 0x0303, 0x0303, 0x0303, 0x0301,
     'c02c c02b c030 c02f 009f 009e c024 c023 c028 c027 c00a c009 c014 c013 0039 0033 009d '
     '009c 003d 003c 0035 002f 000a 006a 0040 0038 0032 0013 ',
     '0000 0005:0100000000 000a:000400170018 000b:0100 '
     '000d:0012040105010201040305030203020206010603 0023 0010:000c02683208687474702f312e31 '
     '0017 5500:000100020002 ff01:00 ',
     {'dh_min': 1024, 'dh_max': 4096, 'rsa_max': 16384}),
    ('Edge 15 Win 10', 0x0303, 0x0303, 0x0303, 0x0301,
     'c02c c02b c030 c02f c024 c023 c028 c027 c00a c009 c014 c013 009d 009c 003d 003c 0035 '
     '002f 000a ',
     '0000 0005:0100000000 000a:0006001d00170018 000b:0100 '
     '000d:0012040105010201040305030203020206010603 0023 0010:000c02683208687474702f312e31 '
     '0017 0018:000a03020100 ff01:00 ',
     {'dh_min': 1024, 'dh_max': 4096, 'rsa_max': 16384}),
    ('Edge 133 Win 11 23H2', 0x0303, 0x0301, 0x0304, 0x0303,
     '1a1a 1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035 ',
     '3a3a 0012 0017 0005:0100000000 000a:000a1a1a11ec001d00170018 ff01:00 '
     '002b:067a7a03040303 001b:020002 000b:0100 4469:0003026832 0033:@ 002d:0101 '
     '0010:000c02683208687474702f312e31 0023 000d:001004030804040105030805050108060601 '
     '0000 aaaa:00 ',
     {'rsa_max': 16384, 'sha2_only': True}),
    ('Java 6u45', 0x0301, 0x0000, 0x0301, 0x0200,
     '000004 010080 000005 00002f 000033 000032 00000a 0700c0 000016 000013 000009 060040 '
     '000015 000012 000003 020080 000008 000014 000011 0000ff ',
     ' ',
     {'dh_max': 1024, 'v2': True}),
    ('Java 7u25', 0x0301, 0x0301, 0x0301, 0x0300,
     'c009 c013 002f c004 c00e 0033 0032 c007 c011 0005 c002 c00c c008 c012 000a c003 c00d '
     '0016 0013 0004 00ff ',
     '000a:003200170001000300130015000600070009000a0018000b000c0019000d000e000f001000110002001200040005001400080016 '
     '000b:0100 0000 ',
     {'dh_max': 1024}),
    ('Java 8u161', 0x0303, 0x0303, 0x0303, 0x0301,
     'c024 c028 003d c026 c02a 006b 006a c00a c014 0035 c005 c00f 0039 0038 c023 c027 003c '
     'c025 c029 0067 0040 c009 c013 002f c004 c00e 0033 0032 c02c c02b c030 009d c02e c032 '
     '009f 00a3 c02f 009c c02d c031 009e 00a2 c008 c012 000a c003 c00d 0016 0013 00ff ',
     '000a:00140017001800190009000a000b000c000d000e0016 000b:0100 '
     '000d:00140603060105030501040304010402020302010202 0017 0000 ',
     {'dh_max': 2048}),
    ('Java 8u442 (OpenJDK)', 0x0303, 0x0303, 0x0304, 0x0303,
     '1302 1301 1303 c02c c02b cca9 c030 cca8 c02f 009f ccaa 009e c024 c028 c023 c027 006b '
     '0067 c00a c014 c009 c013 0039 0033 009d 009c 003d 003c 0035 002f 00ff ',
     '0000 0005:0100000000 000a:0014001d001700180019001e01000101010201030104 000b:0100 '
     '0011:000702000400000000 0017 0023 '
     '000d:0020040305030603080708080804080508060809080a080b04010501060103030301 '
     '002b:0403040303 002d:0101 '
     '0032:0020040305030603080708080804080508060809080a080b04010501060103030301 0033:@ ',
     {'dh_min': 1024, 'ec_min': 224, 'sha2_only': True}),
    ('Java 11.0.2 (OpenJDK)', 0x0303, 0x0303, 0x0304, 0x0301,
     '1301 1302 c02c c02b c030 009d c02e c032 009f 00a3 c02f 009c c02d c031 009e 00a2 c024 '
     'c028 003d c026 c02a 006b 006a c00a c014 0035 c005 c00f 0039 0038 c023 c027 003c c025 '
     'c029 0067 0040 c009 c013 002f c004 c00e 0033 0032 ',
     '0000 0005:0100000000 '
     '000a:001e0017001800190009000a000b000c000d000e001601000101010201030104 000b:0100 '
     '000d:00260403050306030804080508060809080a080b0401050106010402030303010302020302010202 '
     '0032:00260403050306030804080508060809080a080b0401050106010402030303010302020302010202 '
     '0011:000702000400000000 0017 002b:080304030303020301 002d:0101 0033:@ ff01:00 ',
     {'dh_min': 1024, 'ec_min': 224}),
    ('Java 21.0.6 (OpenJDK)', 0x0303, 0x0303, 0x0304, 0x0301,
     '1302 1301 1303 c02c c02b cca9 c030 cca8 c02f 009f ccaa 009e c024 c028 c023 c027 006b '
     '0067 c00a c014 c009 c013 0039 0033 009d 009c 003d 003c 0035 002f 00ff ',
     '0000 0005:0100000000 000a:0014001d001700180019001e01000101010201030104 000b:0100 '
     '0011:000702000400000000 0017 0023 '
     '000d:0020040305030603080708080804080508060809080a080b04010501060103030301 '
     '002b:0403040303 002d:0101 '
     '0032:0020040305030603080708080804080508060809080a080b04010501060103030301 0033:@ ',
     {'dh_min': 1024, 'ec_min': 224, 'sha2_only': True}),
    ('OpenSSL 0.9.8y', 0x0301, 0x0301, 0x0301, 0x0300,
     '0039 0038 0035 0016 0013 000a 0033 0032 002f 0007 0005 0004 0015 0012 0009 0014 0011 '
     '0008 0006 0003 00ff ',
     '0000 0023 ',
     {}),
    ('OpenSSL 1.0.1l', 0x0303, 0x0301, 0x0303, 0x0300,
     'c030 c02c c028 c024 c014 c00a 00a3 009f 006b 006a 0039 0038 0088 0087 c032 c02e c02a '
     'c026 c00f c005 009d 003d 0035 0084 c02f c02b c027 c023 c013 c009 00a2 009e 0067 0040 '
     '0033 0032 009a 0099 0045 0044 c031 c02d c029 c025 c00e c004 009c 003c 002f 0096 0041 '
     '0007 c011 c007 c00c c002 0005 0004 c012 c008 0016 0013 c00d c003 000a 0015 0012 0009 '
     '0014 0011 0008 0006 0003 00ff ',
     '0000 000b:03000102 '
     '000a:0032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f00100011 '
     '0023 000d:001e060106020603050105020503040104020403030103020303020102020203 '
     '0005:0100000000 000f:01 ',
     {}),
    ('OpenSSL 1.0.2e', 0x0303, 0x0301, 0x0303, 0x0300,
     'c030 c02c c028 c024 c014 c00a 00a5 00a3 00a1 009f 006b 006a 0069 0068 0039 0038 0037 '
     '0036 0088 0087 0086 0085 c032 c02e c02a c026 c00f c005 009d 003d 0035 0084 c02f c02b '
     'c027 c023 c013 c009 00a4 00a2 00a0 009e 0067 0040 003f 003e 0033 0032 0031 0030 009a '
     '0099 0098 0097 0045 0044 0043 0042 c031 c02d c029 c025 c00e c004 009c 003c 002f 0096 '
     '0041 0007 c011 c007 c00c c002 0005 0004 c012 c008 0016 0013 0010 000d c00d c003 000a '
     '0015 0012 000f 000c 0009 00ff ',
     '0000 000b:03000102 000a:001a00170019001c001b0018001a0016000e000d000b000c0009000a '
     '0023 000d:001e060106020603050105020503040104020403030103020303020102020203 '
     '0005:0100000000 000f:01 ',
     {}),
    ('OpenSSL 1.1.0l (Debian)', 0x0303, 0x0301, 0x0303, 0x0301,
     'c02c c030 009f cca9 cca8 ccaa c02b c02f 009e c024 c028 006b c023 c027 0067 c00a c014 '
     '0039 c009 c013 0033 009d 009c 003d 003c 0035 002f 00ff ',
     '0000 000b:03000102 000a:0008001d001700190018 0023 0016 0017 '
     '000d:001e060106020603050105020503040104020403030103020303020102020203 ',
     {}),
    ('OpenSSL 1.1.1d (Debian)', 0x0303, 0x0301, 0x0304, 0x0301,
     '1302 1303 1301 c02c c030 009f cca9 cca8 ccaa c02b c02f 009e c024 c028 006b c023 c027 '
     '0067 c00a c014 0039 c009 c013 0033 009d 009c 003d 003c 0035 002f 00ff ',
     '0000 000b:03000102 000a:000a001d0017001e00190018 0023 0016 0017 '
     '000d:0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602 '
     '002b:0403040303 002d:0101 0033:@ ',
     {'sha2_only': True}),
    ('OpenSSL 3.0.15 (Debian)', 0x0303, 0x0301, 0x0304, 0x0301,
     '1302 1303 1301 c02c c030 009f cca9 cca8 ccaa c02b c02f 009e c024 c028 006b c023 c027 '
     '0067 c00a c014 0039 c009 c013 0033 009d 009c 003d 003c 0035 002f 00ff ',
     '0000 000b:03000102 000a:0014001d0017001e0019001801000101010201030104 0023 0016 0017 '
     '000d:0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602 '
     '002b:080304030303020301 002d:0101 0033:@ ',
     {'sha2_only': True}),
    ('Safari 5.1.9 OS X 10.6.8', 0x0301, 0x0301, 0x0301, 0x0300,
     'c00a c009 c007 c008 c013 c014 c011 c012 c004 c005 c002 c003 c00e c00f c00c c00d 002f '
     '0005 0004 0035 000a 0009 0003 0008 0006 0032 0033 0038 0039 0016 0015 0014 0013 0012 '
     '0011 ',
     '0000 000a:0006001700180019 000b:0100 ',
     {'rsa_max': 4096}),
    ('Safari 7 iOS 7.1', 0x0303, 0x0301, 0x0303, 0x0300,
     '00ff c024 c023 c00a c009 c007 c008 c028 c027 c014 c013 c011 c012 c026 c025 c02a c029 '
     'c005 c004 c002 c003 c00f c00e c00c c00d 003d 003c 002f 0005 0004 0035 000a 0067 006b '
     '0033 0039 0016 ',
     '0000 000a:0006001700180019 000b:0100 000d:000a05010401020104030203 ',
     {'rsa_max': 4096}),
    ('Safari 9 iOS 9', 0x0303, 0x0301, 0x0303, 0x0301,
     '00ff c02c c02b c024 c023 c00a c009 c008 c030 c02f c028 c027 c014 c013 c012 009d 009c '
     '003d 003c 0035 002f 000a c007 c011 0005 0004 ',
     '0000 000a:0006001700180019 000b:0100 000d:000c050104010201050304030203 3374 '
     '0010:002e0268320568322d31360568322d31350568322d313408737064792f332e3106737064792f3308687474702f312e31 '
     '0005:0100000000 0012 ',
     {'dh_min': 768, 'rsa_max': 8192}),
    ('Safari 10 iOS 10', 0x0303, 0x0301, 0x0303, 0x0301,
     '00ff c02c c02b c024 c023 c00a c009 c008 c030 c02f c028 c027 c014 c013 c012 009d 009c '
     '003d 003c 0035 002f 000a ',
     '0000 000a:0006001700180019 000b:0100 000d:001004010201050106010403020305030603 3374 '
     '0010:002e0268320568322d31360568322d31350568322d313408737064792f332e3106737064792f3308687474702f312e31 '
     '0005:0100000000 0012 0017 ',
     {'dh_min': 768, 'rsa_max': 8192}),
    ('Safari 12.1 (iOS 12.2)', 0x0303, 0x0301, 0x0304, 0x0301,
     '1303 1301 1302 c02c c02b c024 c023 c00a c009 cca9 c030 c02f c028 c027 c014 c013 cca8 '
     '009d 009c 003d 003c 0035 002f c008 c012 000a ',
     'ff01:00 0000 0017 000d:001604030804040105030203080508050501080606010201 '
     '0005:0100000000 3374 0012 '
     '0010:002e0268320568322d31360568322d31350568322d313408737064792f332e3106737064792f3308687474702f312e31 '
     '000b:0100 0033:@ 002d:0101 002b:080304030303020301 000a:0008001d001700180019 0015 ',
     {}),
    ('Safari 18.4 (macOS 15.4)', 0x0303, 0x0301, 0x0304, 0x0301,
     'eaea 1301 1302 1303 c02c c02b cca9 c030 c02f cca8 c00a c009 c014 c013 009d 009c 0035 '
     '002f c008 c012 000a ',
     'caca 0000 0017 ff01:00 000a:000a6a6a001d001700180019 000b:0100 '
     '0010:000c02683208687474702f312e31 0005:0100000000 '
     '000d:00140403080404010503080508050501080606010201 0012 0033:@ 002d:0101 '
     '002b:0afafa0304030303020301 001b:020001 7a7a:00 0015 ',
     {'dh_min': 1024}),
    ('Apple ATS 9 iOS 9', 0x0303, 0x0303, 0x0303, 0x0303,
     '00ff c02c c02b c024 c00a c023 c009 c030 c02f c028 c027 c013 ',
     '0000 000a:0006001700180019 000b:0100 000d:000c050104010201050304030203 3374 '
     '0010:002e0268320568322d31360568322d31350568322d313408737064792f332e3106737064792f3308687474702f312e31 '
     '0005:0100000000 0012 ',
     {'dh_min': 768, 'rsa_min': 2048, 'rsa_max': 8192, 'ec_min': 256, 'sha2_only': True}),
]

SIGALG_NAMES = {
    0x0201: "rsa_pkcs1_sha1", 0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384", 0x0601: "rsa_pkcs1_sha512",
    0x0203: "ecdsa_sha1", 0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512", 0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512", 0x0807: "ed25519", 0x0808: "ed448",
}
CURVE_GROUPS = {"secp256r1": 23, "secp384r1": 24, "secp521r1": 25}


def _u16_list(d: bytes | None) -> list[int]:
    """Decode a length-prefixed list of 16-bit values (supported_groups, signature_algorithms)."""
    if not d or len(d) < 2:
        return []
    body = d[2:2 + struct.unpack_from(">H", d, 0)[0]]
    return [struct.unpack_from(">H", body, i)[0] for i in range(0, len(body) - 1, 2)]


@dataclass
class Client:
    name: str
    version: int                 # client_version of the hello
    record_version: int
    max_version: int
    min_version: int
    ciphers: tuple[int, ...]     # preference order; 24-bit SSLv2-style specs when v2
    exts: tuple[tuple[int, bytes | None], ...]   # None = generated (key_share)
    v2: bool = False             # SSLv2-format ClientHello (Java 6)
    deflate: bool = False        # offers TLS compression
    dh_min: int = 0              # client limits; 0 = none
    dh_max: int = 0
    rsa_min: int = 0
    rsa_max: int = 0
    ec_min: int = 0
    sha2_only: bool = False      # rejects MD5/SHA-1 signed certificates
    offered: frozenset = field(init=False, repr=False)
    groups: frozenset = field(init=False, repr=False)
    sigalgs: frozenset = field(init=False, repr=False)
    sni: bool = field(init=False)

    def __post_init__(self):
        self.offered = frozenset(c for c in self.ciphers if c <= 0xFFFF)
        data = dict(self.exts)
        self.groups = frozenset(_u16_list(data.get(10)))
        self.sigalgs = frozenset(_u16_list(data.get(13)))
        self.sni = 0 in data


def _make_client(name, version, record_version, max_version, min_version, ciphers, exts, opts) -> Client:
    es = []
    for tok in exts.split():
        t, _, d = tok.partition(":")
        es.append((int(t, 16), None if d == "@" else bytes.fromhex(d)))
    return Client(name, version, record_version, max_version, min_version,
                  tuple(int(x, 16) for x in ciphers.split()), tuple(es), **opts)


CLIENTS = tuple(_make_client(*row) for row in _CLIENT_DATA)


def profile_hello(c: Client, host: str | None) -> bytes:
    """Build the ClientHello `c` would send to `host` (None / IP address: no SNI)."""
    if c.v2:
        specs = b"".join(x.to_bytes(3, "big") for x in c.ciphers)
        challenge = os.urandom(32)
        body = b"\x01" + u16(c.version) + u16(len(specs)) + u16(0) + u16(len(challenge)) + specs + challenge
        return u16(0x8000 | len(body)) + body
    sid = os.urandom(32) if c.max_version >= TLS13 else b""
    cs = b"".join(u16(x) for x in c.ciphers)
    body = (u16(c.version) + os.urandom(32) + bytes([len(sid)]) + sid + u16(len(cs)) + cs
            + (b"\x02\x01\x00" if c.deflate else b"\x01\x00"))
    exts, pad = b"", False
    for t, d in c.exts:
        if t == 0:
            if not host:
                continue
            h = host.encode("idna")
            entry = b"\x00" + u16(len(h)) + h
            d = u16(len(entry)) + entry
        elif t == 21:
            pad = True
            continue
        elif d is None:
            g = next((g for g in (29, 23, 24, 25) if g in c.groups), 23)
            pub = keygen(g)
            share = u16(g) + u16(len(pub)) + pub
            d = u16(len(share)) + share
        exts += ext(t, d)
    if pad:  # same F5-style 256..511 byte workaround the real clients apply
        total = 4 + len(body) + 2 + len(exts)
        if 0x100 <= total < 0x200 + 4:
            exts += ext(21, b"\x00" * max(0x200 + 4 - total - 4, 1))
    if exts:
        body += u16(len(exts)) + exts
    hs = b"\x01" + u24(len(body)) + body
    return b"\x16" + u16(c.record_version) + u16(len(hs)) + hs


def _ske_params(s: Suite, ske: bytes) -> tuple[int | None, int | None]:
    """(named group, signature algorithm) of a ServerKeyExchange; the algorithm field exists in TLS 1.2 only."""
    try:
        if s.kx.startswith("ECDHE") and ske[0] == 3:
            return struct.unpack_from(">H", ske, 1)[0], struct.unpack_from(">H", ske, 4 + ske[3])[0]
        if s.kx.startswith("DHE"):
            p = 0
            for _ in range(3):  # p, g, Ys
                p += 2 + struct.unpack_from(">H", ske, p)[0]
            return None, struct.unpack_from(">H", ske, p)[0]
    except (struct.error, IndexError):
        pass
    return None, None


def _cert_facts(der: bytes, host: str, cache: dict) -> dict | None:
    if der not in cache:
        try:
            cache[der] = analyze_cert(x509.load_der_x509_certificate(der), host)
        except Exception:
            cache[der] = None
    return cache[der]


def _fail_reason(r: Hello) -> str:
    if r.alert:
        why = {40: "no cipher suite in common", 70: "no protocol version in common",
               71: "insufficient security", 112: "unrecognized name"}.get(r.alert[1])
        return f"server sent alert {r.alert_name}" + (f" ({why})" if why else "")
    return {"timeout": "no response (timeout)", "eof": "connection closed by server",
            "not-tls": "reply is not TLS"}.get(r.error, r.error or "no ServerHello")


def _client_problem(c: Client, r: Hello, s: Suite | None, kxd: dict | None, chains: list[dict],
                    cache: dict, host: str) -> str | None:
    """First reason why client `c` would abort after the ServerHello, or None."""
    if not c.min_version <= r.version <= c.max_version:
        return f"server chose {VERSION_NAMES.get(r.version, hex(r.version))}, outside the client's range"
    if r.cipher not in c.offered:
        return "server chose a cipher suite the client did not offer"
    if s is None:
        return None
    if kxd and kxd["type"] == "DH":
        bits = kxd["bits"]
        if c.dh_min and bits < c.dh_min:
            return f"DH parameters ({bits} bits) below the client minimum ({c.dh_min})"
        if c.dh_max and bits > c.dh_max:
            return f"DH parameters ({bits} bits) above the client maximum ({c.dh_max})"
    if r.version <= TLS12 and r.ske and s.kx.startswith(("ECDHE", "DHE")):
        group, alg = _ske_params(s, r.ske)
        if group is not None and c.groups and group not in c.groups:
            return f"server curve {GROUP_NAMES.get(group, hex(group))} not offered by the client"
        if r.version == TLS12 and alg is not None and c.sigalgs and alg not in c.sigalgs:
            return f"key exchange signed with {SIGALG_NAMES.get(alg, hex(alg))}, unsupported by the client"
    if r.version >= TLS13:  # certificates are encrypted: assume the primary chain
        items = chains[0]["certs"] if chains else []
    else:
        items = [f for f in (_cert_facts(d, host, cache) for d in r.certs) if f]
    if not items:
        return None
    leaf = items[0]
    kind, bits = leaf["key_type"], leaf["key_bits"]
    if kind == "RSA":
        if c.rsa_max and bits > c.rsa_max:
            return f"RSA key ({bits} bits) larger than the client supports ({c.rsa_max})"
        if c.rsa_min and bits < c.rsa_min:
            return f"RSA key ({bits} bits) below the client minimum ({c.rsa_min})"
    elif kind.startswith("EC"):
        if c.ec_min and bits < c.ec_min:
            return f"ECDSA key ({bits} bits) below the client minimum ({c.ec_min})"
        gid = CURVE_GROUPS.get(kind[4:-1])
        if gid and c.groups and gid not in c.groups:
            return f"ECDSA certificate curve {kind[4:-1]} not supported by the client"
    if c.sha2_only:
        for i, it in enumerate(items):
            if it["weak_sig"] and not it["self_signed"]:
                return f"{'leaf' if i == 0 else f'intermediate #{i + 1}'} certificate signed with {it['sig_hash']}"
    if not c.sni and chains and chains[0]["certs"][0]["hostname_match"] and not leaf["hostname_match"]:
        return "client sends no SNI: server returns a default certificate that does not match the host"
    return None


def simulate_client(t: Target, c: Client, chains: list[dict], cache: dict) -> dict:
    """Probe the server with one client profile and judge the answer the way that client would."""
    res = {"client": c.name, "ok": False, "protocol": None, "cipher": None, "kx": None,
           "forward_secrecy": None, "level": None, "reason": None}
    r = tls_probe(t, profile_hello(c, t.sni))
    if not r.ok:
        res["reason"] = _fail_reason(r)
        return res
    res["protocol"] = VERSION_NAMES.get(r.version, f"0x{r.version:04x}")
    s = SUITE_BY_ID.get(r.cipher)
    res["cipher"] = s.name if s else f"0x{r.cipher:04X}"
    kxd = None
    if s:
        res["forward_secrecy"], res["level"] = s.fs, s.level
        if r.version >= TLS13:
            if len(r.exts.get(51, b"")) >= 2:
                g = struct.unpack_from(">H", r.exts[51], 0)[0]
                res["kx"] = GROUP_NAMES.get(g, f"0x{g:04x}")
        elif s.kx == "RSA":
            res["kx"] = "RSA"
        elif (kxd := kx_detail(s, r.ske)):
            res["kx"] = f"DH {kxd['bits']} bits" if kxd["type"] == "DH" else f"ECDH {kxd['curve']}"
    res["reason"] = _client_problem(c, r, s, kxd, chains, cache, t.host)
    res["ok"] = res["reason"] is None
    return res


# --------------------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------------------
def scan(t: Target, all_ips: list[str], do_ocsp: bool, do_sim: bool = True, log=lambda m: None) -> dict:
    rep: dict = {"target": {"host": t.host, "port": t.port, "ip": t.ip, "ips": all_ips, "starttls": t.starttls}}
    smtp: dict = {}
    try:
        open_conn(t, info=smtp).close()
    except OSError as e:  # StartTlsError is an OSError
        rep["error"] = (f"{t.ip}:{t.port}: {e}" if isinstance(e, StartTlsError)
                        else f"cannot connect to {t.ip}:{t.port}: {e}")
        if smtp:
            rep["smtp"] = smtp
        return rep
    if t.starttls:
        rep["smtp"] = smtp
        if do_sim:
            log("client simulation skipped: browser/OS client profiles do not apply to STARTTLS services")
            do_sim = False
    log("probing protocols and cipher suites ...")
    with cf.ThreadPoolExecutor(max_workers=t.workers) as ex:
        f_protos = {v: ex.submit(enumerate_version, t, v) for v in PROBE_VERSIONS}
        f_ssl2 = ex.submit(probe_sslv2, t)
        f_trust = ex.submit(check_trust, t)
        f_res = ex.submit(check_resumption, t)
        f_alpn = f_http = None
        if not t.starttls:  # ALPN and the HTTP request make no sense on an SMTP connection
            f_alpn, f_http = ex.submit(check_alpn, t), ex.submit(check_http, t)
        protos = {v: f.result() for v, f in f_protos.items()}
        ssl2 = f_ssl2.result()
        rep["trust"], rep["resumption"] = f_trust.result(), f_res.result()
        if f_alpn:
            rep["alpn"], rep["http"] = f_alpn.result(), f_http.result()
    rep["_protos"] = protos
    rep["sslv2"] = ssl2
    if not ssl2 and not any(p.supported for p in protos.values()):
        rep["error"] = "no TLS/SSL service detected on this port"
        rep["grade"] = compute_grade({**rep, "chains": [], "vulns": {}, "features": {}})
        return rep

    # certificates ------------------------------------------------------------------
    chains_der: dict[str, tuple[str, list[bytes]]] = {}
    for p in protos.values():
        for auth, certs in p.certs:
            if certs:
                chains_der.setdefault(hashlib.sha256(certs[0]).hexdigest(), (auth, certs))
    if not chains_der and protos[TLS13].supported or not chains_der:
        try:
            ch = fallback_chain(t)
            chains_der[hashlib.sha256(ch[0]).hexdigest()] = ("RSA", ch)
        except Exception as e:
            rep["cert_error"] = str(e)
    chains = []
    for _, (auth, der) in chains_der.items():
        try:
            c = analyze_chain(der, t.host)
            c["auth"] = auth
            chains.append(c)
        except Exception as e:
            rep["cert_error"] = f"{type(e).__name__}: {e}"
    rep["chains"] = chains
    if rep["trust"].get("trusted") is None and chains:
        try:
            rep["trust"] = {**verify_with_store(chains[0], t.host), "python_tls_error": rep["trust"].get("error")}
        except Exception as e:
            rep["trust"]["error"] += f" (offline verification failed: {e})"

    p12 = best12(protos)
    log("probing features, groups, vulnerabilities" + (" and client compatibility" if do_sim else "") + " ...")
    with cf.ThreadPoolExecutor(max_workers=t.workers) as ex:
        f = {
            "crime": ex.submit(check_compression, t, p12),
            "fallback": ex.submit(check_fallback_scsv, t, protos),
            "groups": ex.submit(check_groups, t, protos),
            "heartbleed": ex.submit(check_heartbleed, t, p12),
            "ccs": ex.submit(check_ccs, t, p12),
            "robot": ex.submit(check_robot, t, protos),
            "ocsp": [ex.submit(ocsp_check, c) for c in chains] if do_ocsp else [],
        }
        sim_cache: dict = {}
        sim = [ex.submit(simulate_client, t, c, chains, sim_cache) for c in CLIENTS] if do_sim else []
        rep["groups"] = f["groups"].result()
        rep["fallback_scsv"] = f["fallback"].result()
        vulns = {k: f[k].result() for k in ("crime", "heartbleed", "ccs", "robot")}
        for c, fut in zip(chains, f["ocsp"]):
            c["ocsp"] = fut.result()
        if do_sim:
            rep["handshake_simulation"] = [fut.result() for fut in sim]

    # derived vulnerability checks -----------------------------------------------------
    accepted = [(v, a) for v in PROBE_VERSIONS for a in protos[v].accepted]
    vulns["poodle_ssl3"] = {"status": "vulnerable" if any(v == SSL3 and a.suite.mode in ("CBC", "STREAM")
                                                           for v, a in accepted) else "ok"}
    vulns["beast"] = {"status": "vulnerable" if any(v in (SSL3, TLS10) and a.suite.mode == "CBC"
                                                    for v, a in accepted) else "ok",
                      "detail": "CBC suites on SSL3/TLS1.0 (mitigated client-side by modern browsers)"}
    vulns["freak"] = {"status": "vulnerable" if any(a.suite.export and a.suite.kx.startswith("RSA")
                                                    for _, a in accepted) else "ok"}
    weak_dh = [a.kx["bits"] for _, a in accepted if a.kx and a.kx["type"] == "DH" and a.kx["bits"] < 2048]
    vulns["logjam"] = {"status": "vulnerable" if any(a.suite.export and "DH" in a.suite.kx for _, a in accepted)
                       or any(b <= 1024 for b in weak_dh) else "ok",
                       "detail": (f"DH parameters {min(weak_dh)} bits" if weak_dh else None)}
    vulns["drown"] = {"status": "vulnerable" if ssl2 else "ok"}
    vulns["sweet32"] = {"status": "vulnerable" if any(a.suite.block64 for _, a in accepted) else "ok"}
    vulns["rc4"] = {"status": "vulnerable" if any("RC4" in a.suite.enc for _, a in accepted) else "ok"}
    rep["vulns"] = vulns

    # handshake features -----------------------------------------------------------------
    ext12 = p12.exts if p12 else set()
    tls12_scsv = bool(p12 and (0xFF01 in ext12))
    rep["features"] = {
        "secure_renegotiation": (tls12_scsv if p12 and p12.version != SSL3 else None),
        "ocsp_stapling": (5 in ext12) if p12 else None,
        "session_tickets": (35 in ext12) if p12 else None,
        "extended_master_secret": (23 in ext12) if p12 else None,
        "heartbeat_ext": (15 in ext12) if p12 else None,
        "forward_secrecy_all": all(a.suite.fs for _, a in accepted) if accepted else None,
        "forward_secrecy_any": any(a.suite.fs for _, a in accepted) if accepted else None,
    }
    rep["grade"] = compute_grade(rep)
    return rep


# --------------------------------------------------------------------------------------
# presentation
# --------------------------------------------------------------------------------------
class Style:
    on = True

    @classmethod
    def c(cls, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.on else text


def green(s): return Style.c(s, "32")
def red(s): return Style.c(s, "31")
def yellow(s): return Style.c(s, "33")
def bold(s): return Style.c(s, "1")
def dim(s): return Style.c(s, "2")


def status(ok: bool | None, good="OK", bad="BAD", unknown="?") -> str:
    return green(good) if ok is True else red(bad) if ok is False else yellow(unknown)


def level_color(level: str) -> str:
    return {"STRONG": green, "OK": green, "WEAK": yellow, "INSECURE": red}[level](f"{level:<9}")


def grade_color(g: str) -> str:
    return (green if g.startswith("A") else yellow if g in ("B", "C") else red)(bold(g))


def render(rep: dict) -> str:
    L: list[str] = []
    add = L.append
    tg = rep["target"]

    def head(title: str):
        add("")
        add(bold(f"== {title} " + "=" * max(0, 70 - len(title))))

    add(bold(f"SSL check: {tg['host']}:{tg['port']}") + dim(f"  ({tg['ip']}; resolved: {', '.join(tg['ips'])})")
        + (dim(f"  [{tg['starttls'].upper()} STARTTLS]") if tg.get("starttls") else ""))
    if rep.get("error"):
        add(red(rep["error"]))
        return "\n".join(L)
    g = rep["grade"]
    head("Summary")
    add(f"Overall rating : {grade_color(g['grade'])}   (score {g['score']}; protocol {g['protocol_score']:.0f}, "
        f"key exchange {g['key_exchange_score']:.0f}, cipher strength {g['cipher_score']:.0f})")
    for n in g["notes"]:
        add("  - " + yellow(n))

    # certificates
    head("Certificate chain(s)")
    tr = rep["trust"]
    add("Trusted (system store): " + (green("yes") if tr.get("trusted") else red(f"NO  ({tr.get('error')})")
        if tr.get("trusted") is False else yellow(f"unknown ({tr.get('error')})")))
    for n, ch in enumerate(rep.get("chains", []), 1):
        leaf = ch["certs"][0]
        add(bold(f"\nCertificate #{n} ({ch.get('auth', '')} server certificate)"))
        add(f"  Subject      : {leaf['subject']}")
        add(f"  Alt names    : {', '.join(leaf['san']) or '-'}")
        add(f"  Hostname     : " + status(leaf["hostname_match"], "match", "MISMATCH"))
        add(f"  Issuer       : {leaf['issuer']}")
        days = leaf["days_left"]
        v = f"{leaf['not_before'][:10]} .. {leaf['not_after'][:10]}  ({days} days left)"
        add("  Valid        : " + (red(v + " EXPIRED") if leaf["expired"] or leaf["not_yet_valid"]
                                  else yellow(v) if days < 14 else green(v)))
        kb = leaf["key_bits"]
        weak_key = effective_bits(leaf["key_type"], kb) < 2048
        add("  Key          : " + (red if weak_key else green)(f"{leaf['key_type']} {kb} bits"))
        add("  Signature    : " + (red if leaf["weak_sig"] else green)(leaf["sig_alg"]))
        add(f"  Serial       : {leaf['serial']}")
        add(f"  SHA-256      : {leaf['sha256']}")
        add(f"  Pin (SPKI)   : sha256//{leaf['pin_sha256']}")
        add(f"  SCT (CT)     : " + status(leaf["sct"], "embedded", "none embedded"))
        add(f"  Must-Staple  : {'yes' if leaf['must_staple'] else 'no'}")
        add(f"  OCSP / CRL   : {', '.join(leaf['ocsp_urls']) or '-'} / {', '.join(leaf['crl_urls']) or '-'}")
        if "ocsp" in ch:
            o = ch["ocsp"]
            col = green if o["status"] == "good" else red if o["status"] == "revoked" else yellow
            add("  Revocation   : " + col(f"OCSP {o['status']}") + dim(f"  {o.get('detail', '')}"))
        add("  Chain sent   :")
        for i, c in enumerate(ch["certs"]):
            add(f"    {i + 1}. {c['subject']}  " + dim(f"[{c['key_type']} {c['key_bits']}, {c['sig_alg']}, "
                                                    f"exp {c['not_after'][:10]}]"))
        for i in ch["issues"]:
            add("  " + yellow("! " + i))
    if rep.get("cert_error"):
        add(red("certificate retrieval problem: " + rep["cert_error"]))

    # protocols
    head("Protocols")
    protos: dict[int, Proto] = rep["_protos"]
    s2 = rep["sslv2"]
    rows = [(SSL2, bool(s2))] + [(v, protos[v].supported) for v in PROBE_VERSIONS]
    for v, sup in reversed(rows):
        bad = v <= SSL3 or v in (TLS10, TLS11)
        txt = (red("Yes") if bad else green("Yes")) if sup else (green("No") if bad else yellow("No"))
        if v == TLS13 and not sup:
            txt = yellow("No")
        add(f"  {VERSION_NAMES[v]:<8} {txt}")

    head("Cipher suites (server preference order where enforced)")
    if s2:
        add(bold("SSL 2.0"))
        for n in s2:
            add(f"  {n:<42} {red('INSECURE')}")
    for v in reversed(PROBE_VERSIONS):
        p = protos[v]
        if not p.supported:
            continue
        order = {True: "server enforces its own order", False: "client order is honoured",
                 None: "order undetermined"}[p.server_order]
        add(bold(f"\n{VERSION_NAMES[v]}") + dim(f"  ({order})"))
        for a in p.accepted:
            s = a.suite
            kx = ""
            if a.kx:
                kx = f"DH {a.kx['bits']} bits" if a.kx["type"] == "DH" else a.kx["curve"]
            add(f"  0x{s.id:04X} {s.name:<46} {s.bits:>3} bit  {'FS ' if s.fs else '   '} "
                f"{level_color(s.level)} {dim(kx)}")
    add("")
    add(f"Forward secrecy: " + ("all suites" if rep["features"]["forward_secrecy_all"] else
        "some suites" if rep["features"]["forward_secrecy_any"] else "none"))
    for ver, groups in rep.get("groups", {}).items():
        add(f"Named groups ({ver}): {', '.join(groups) or '-'}")

    if rep.get("handshake_simulation"):
        head("Handshake simulation (client compatibility)")
        sim = rep["handshake_simulation"]
        for s in sim:
            if s["ok"]:
                col = {"STRONG": green, "OK": green, "WEAK": yellow}.get(s["level"], red)
                add(f"  {s['client']:<26} {green('OK  ')} {s['protocol']:<8} {col(s['cipher'])}"
                    + (dim(f"  {s['kx']}") if s["kx"] else "") + ("  FS" if s["forward_secrecy"] else ""))
            else:
                add(f"  {s['client']:<26} {red('FAIL')} {red(s['reason'])}"
                    + (dim(f"  [{s['protocol']} {s['cipher']}]") if s["cipher"] else ""))
        n_ok = sum(1 for s in sim if s["ok"])
        add(dim(f"  {n_ok}/{len(sim)} simulated clients can connect (certificate trust per client is not evaluated)"))

    # features
    head("Protocol features")
    f = rep["features"]

    def yn(x, good_if=True):
        if x is None:
            return yellow("n/a")
        return green("Yes") if x == good_if else red("No") if good_if else yellow("No")
    add(f"  Secure renegotiation  : {yn(f['secure_renegotiation'])}")
    add(f"  OCSP stapling         : {yn(f['ocsp_stapling'])}")
    add(f"  Session tickets       : {yn(f['session_tickets'])}")
    add(f"  Session resumption    : {yn(rep['resumption'].get('resumption'))}")
    add(f"  Extended master secret: {yn(f['extended_master_secret'])}")
    if "alpn" in rep:
        add(f"  ALPN h2 / http/1.1    : {yn(rep['alpn'].get('h2'))} / {yn(rep['alpn'].get('http/1.1'))}")
    fb = rep["fallback_scsv"]
    add(f"  TLS_FALLBACK_SCSV     : " + (green("Yes") if fb["status"] == "ok" else red("No") if fb["status"] == "missing"
                                         else yellow(fb["status"])) + dim(f"  {fb.get('detail', '')}"))

    # vulns
    head("Vulnerabilities")
    labels = {"heartbleed": "Heartbleed (CVE-2014-0160)", "ccs": "OpenSSL CCS injection (CVE-2014-0224)",
              "robot": "ROBOT", "poodle_ssl3": "POODLE (SSL 3.0)", "beast": "BEAST (TLS 1.0 CBC)",
              "crime": "CRIME (TLS compression)", "freak": "FREAK (export RSA)", "logjam": "Logjam (weak/export DH)",
              "drown": "DROWN (SSL 2.0)", "sweet32": "Sweet32 (64-bit block ciphers)", "rc4": "RC4 suites"}
    for k, label in labels.items():
        v = rep["vulns"][k]
        st = v["status"]
        mark = red("VULNERABLE") if st == "vulnerable" and k != "beast" else yellow("affected") \
            if st == "vulnerable" else green("not vulnerable") if st == "ok" else yellow(st)
        add(f"  {label:<40} {mark}" + (dim(f"  {v['detail']}") if v.get("detail") else ""))

    if rep.get("smtp"):
        sm = rep["smtp"]
        head("SMTP")
        add(f"  Banner       : {sm['banner']}")
        add(f"  EHLO reply   : {sm['greeting']}")
        add(f"  Extensions   : {', '.join(sm['extensions']) or '-'}")
        auth = next((e for e in sm["extensions"] if e.split()[0].upper() == "AUTH"), None)
        if auth:
            add(yellow(f"  ! '{auth}' is offered before STARTTLS: make sure clients cannot send credentials in clear text"))

    if "http" in rep:
        head("HTTP")
        h = rep["http"]
        if "error" in h:
            add(yellow(f"  request failed: {h['error']}"))
        else:
            add(f"  Status : {h['status']}  Server: {h.get('server') or '-'}")
            if h.get("location"):
                add(f"  Location: {h['location']}")
            hs = h.get("hsts")
            if hs:
                ok = hs["max_age"] >= 15768000
                add("  HSTS   : " + (green if ok else yellow)(hs["raw"]))
            else:
                add("  HSTS   : " + yellow("not set"))
            if h.get("alt_svc"):
                add(f"  Alt-Svc: {h['alt_svc']}  {dim('(HTTP/3 advertised)' if 'h3' in h['alt_svc'] else '')}")
    return "\n".join(L)


def to_json(rep: dict) -> dict:
    if "_protos" not in rep:
        return {k: v for k, v in rep.items() if not k.startswith("_")}
    out = {k: v for k, v in rep.items() if not k.startswith("_")}
    out["chains"] = [{k: v for k, v in c.items() if not k.startswith("_")} for c in rep.get("chains", [])]
    out["sslv2"] = rep["sslv2"]
    out["protocols"] = {
        VERSION_NAMES[v]: {
            "supported": p.supported, "server_order": p.server_order,
            "ciphers": [{"id": f"0x{a.suite.id:04X}", "name": a.suite.name, "bits": a.suite.bits,
                         "forward_secrecy": a.suite.fs, "level": a.suite.level, "kx": a.kx}
                        for a in p.accepted]}
        for v, p in rep["_protos"].items()}
    return out


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------
def parse_target(arg: str) -> tuple[str, int]:
    u = urllib.parse.urlsplit(arg if "//" in arg else "//" + arg)
    if not u.hostname:
        raise ValueError(f"cannot parse target {arg!r}")
    return u.hostname, u.port or 443


STARTTLS_PORTS = {25: "smtp", 587: "smtp"}


def starttls_mode(choice: str, port: int) -> str | None:
    """Resolve --starttls: 'auto' picks the protocol from well-known plaintext ports."""
    return STARTTLS_PORTS.get(port) if choice == "auto" else None if choice == "none" else choice


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SSL Labs-style TLS server assessment (no external API).")
    ap.add_argument("targets", nargs="+", help="host, host:port or https://host[:port]")
    ap.add_argument("--ip", help="connect to this IP instead of resolving the hostname")
    ap.add_argument("--timeout", type=float, default=5.0, help="per-handshake timeout in seconds (default 5)")
    ap.add_argument("--json", action="store_true", help="machine readable output")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--no-ocsp", action="store_true", help="do not contact OCSP responders / AIA URLs")
    ap.add_argument("--workers", type=int, default=8,
                    help="parallel connections (default 8; use 1 for single-threaded servers)")
    ap.add_argument("--no-sim", action="store_true", help="skip the client handshake simulation")
    ap.add_argument("--starttls", choices=("auto", "smtp", "none"), default="auto",
                    help="upgrade the plaintext connection with STARTTLS before testing "
                         "(auto: smtp on ports 25 and 587; port 465 is implicit TLS and needs no option)")
    ap.add_argument("--ehlo", default="sslcheck.invalid", help="host name sent in EHLO for SMTP (default sslcheck.invalid)")
    args = ap.parse_args(argv)
    Style.on = sys.stdout.isatty() and not args.no_color and not args.json
    code = 0
    results = []
    for target in args.targets:
        try:
            host, port = parse_target(target)
            infos = socket.getaddrinfo(args.ip or host, port, type=socket.SOCK_STREAM)
        except (ValueError, socket.gaierror) as e:
            print(f"{target}: {e}", file=sys.stderr)
            code = 2
            continue
        ips = list(dict.fromkeys(i[4][0] for i in infos))
        ip = next((i for i in ips if ":" not in i), ips[0])
        t = Target(host, port, ip, args.timeout, max(1, args.workers), starttls_mode(args.starttls, port), args.ehlo)
        log = (lambda m: None) if args.json else (lambda m: print(dim(f"[{host}] {m}"), file=sys.stderr))
        rep = scan(t, ips, not args.no_ocsp, not args.no_sim, log)
        if args.json:
            results.append(to_json(rep))
        else:
            print(render(rep))
        if rep.get("error") or rep["grade"]["grade"] in ("F", "T", "M"):
            code = max(code, 1)
    if args.json:
        print(json.dumps(results if len(results) != 1 else results[0], indent=2, default=str))
    return code


if __name__ == "__main__":
    sys.exit(main())
