"""Export certificate and negotiation evidence, retaining original line numbers."""
import re

_FIELDS = re.compile(
    rb"(?:Connecting to [0-9a-fA-F:.%]+|"
    rb"(?:New|Reused), [A-Za-z0-9.]+, Cipher is [A-Za-z0-9_()-]+|"
    rb"(?:Protocol(?: version)?|Cipher(?:suite)?)\s*:\s*[A-Za-z0-9_.()-]+|"
    rb"(?:Peer|Server) Temp Key: [A-Za-z0-9_,. +()-]+|"
    rb"Negotiated TLS1\.3 group: [A-Za-z0-9_.-]+|"
    rb"Peer (?:signing digest|signature type): [A-Za-z0-9_.-]+|"
    rb"Verification: OK|Verify return code: [0-9]+ \([A-Za-z0-9 _.-]+\)|"
    rb"CONNECTION ESTABLISHED)"
)

def shareable_tls(raw):
    """Keep an allowlist of public fields and PEM certificates only."""
    inside_certificate = False
    public_lines = []
    for line in raw.splitlines():
        value = line.strip()
        if value == b"-----BEGIN CERTIFICATE-----":
            inside_certificate = True
            public_lines.append(value)
        elif inside_certificate and value == b"-----END CERTIFICATE-----":
            inside_certificate = False
            public_lines.append(value)
        elif inside_certificate and re.fullmatch(rb"[A-Za-z0-9+/=]+",value):
            public_lines.append(value)
        else:
            public_lines.append(line if _FIELDS.fullmatch(value) else b"")
    return b"\n".join(public_lines) + (b"\n" if public_lines else b"")
