#!/usr/bin/env python3
"""ssh-keyaudit-lite: audit one SSH authorized_keys file (read-only).

Reads a single authorized_keys file (default ~/.ssh/authorized_keys) and prints,
for every key, the SHA256 fingerprint in the same format as `ssh-keygen -lf`,
the key type, the key size in bits and the comment. It flags DSA keys, RSA
keys below a minimum size (default 3072 bits), keys without a comment, and
lines that are not valid keys. It never edits the file.

Python 3.9+ standard library only. MIT license.

Exit codes: 0 = no findings, 1 = at least one key or line was flagged,
2 = error (file not readable, bad arguments).

Full version (fleet scan over your own ssh, keys reused across hosts, owner
mapping, offboarded/unknown owners, removal plan script, JSON report):
https://py-forge.com/products/ssh-keyaudit-fleet-key-inventory?utm_source=github&utm_medium=readme&utm_campaign=ssh-keyaudit-lite
"""

import argparse
import base64
import binascii
import hashlib
import os
import sys
from typing import Dict, List, Optional, Tuple

__version__ = "0.1.1"

DEFAULT_FILE = os.path.join("~", ".ssh", "authorized_keys")
DEFAULT_MIN_RSA_BITS = 3072
PRO_URL = (
    "https://py-forge.com/products/ssh-keyaudit-fleet-key-inventory"
    "?utm_source=github&utm_medium=readme&utm_campaign=ssh-keyaudit-lite"
)

CERT_SUFFIX = "-cert-v01@openssh.com"
BASE_KEY_TYPES = (
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)
KNOWN_KEY_TYPES = set(BASE_KEY_TYPES)
for _t in BASE_KEY_TYPES:
    KNOWN_KEY_TYPES.add(_t.replace("@openssh.com", "") + CERT_SUFFIX)

# Short type names as printed by `ssh-keygen -l`
TYPE_LABELS = {
    "ssh-rsa": "RSA",
    "ssh-dss": "DSA",
    "ssh-ed25519": "ED25519",
    "ecdsa-sha2-nistp256": "ECDSA",
    "ecdsa-sha2-nistp384": "ECDSA",
    "ecdsa-sha2-nistp521": "ECDSA",
    "sk-ssh-ed25519@openssh.com": "ED25519-SK",
    "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-SK",
}
ECDSA_BITS = {"nistp256": 256, "nistp384": 384, "nistp521": 521}
# number of public-key fields that follow the nonce in a certificate blob
CERT_KEY_FIELDS = {"ssh-rsa": 2, "ssh-dss": 4, "ssh-ed25519": 1,
                   "sk-ssh-ed25519": 2, "sk-ecdsa-sha2-nistp256": 3}


# ---------------------------------------------------------------------------
# SSH wire format and fingerprints
# ---------------------------------------------------------------------------

def read_wire_bytes(buf: bytes, offset: int) -> Tuple[bytes, int]:
    """Read one length-prefixed string / mpint from an SSH wire-format buffer."""
    if offset + 4 > len(buf):
        raise ValueError("key data truncated (field length)")
    length = int.from_bytes(buf[offset:offset + 4], "big")
    offset += 4
    if offset + length > len(buf):
        raise ValueError("key data truncated (field data)")
    return buf[offset:offset + length], offset + length


def _plain_key_blob(key_type: str, raw: bytes, offset: int) -> Tuple[str, bytes]:
    """For an OpenSSH certificate, rebuild the plain public key blob that
    `ssh-keygen -l` fingerprints. Plain keys are returned unchanged."""
    if not key_type.endswith(CERT_SUFFIX):
        return key_type, raw
    base = key_type[:-len(CERT_SUFFIX)]
    plain_type = base + "@openssh.com" if base.startswith("sk-") else base
    count = CERT_KEY_FIELDS.get(base, 2 if base.startswith("ecdsa-sha2-") else 0)
    if not count:
        raise ValueError("unsupported certificate type")
    _nonce, offset = read_wire_bytes(raw, offset)
    fields = [plain_type.encode("ascii")]
    for _ in range(count):
        field, offset = read_wire_bytes(raw, offset)
        fields.append(field)
    return plain_type, b"".join(len(f).to_bytes(4, "big") + f for f in fields)


def _key_bits(key_type: str, blob: bytes, offset: int) -> int:
    """Key size in bits as `ssh-keygen -l` reports it (plain key types only)."""
    if key_type == "ssh-rsa":
        _e, offset = read_wire_bytes(blob, offset)
        n, _ = read_wire_bytes(blob, offset)
        if not n:
            raise ValueError("empty RSA modulus")
        return int.from_bytes(n, "big").bit_length()
    if key_type == "ssh-dss":
        p, _ = read_wire_bytes(blob, offset)
        return int.from_bytes(p, "big").bit_length()
    if key_type in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
        pub, _ = read_wire_bytes(blob, offset)
        if len(pub) != 32:
            raise ValueError("ed25519 public key must be 32 bytes")
        return 256
    if key_type.startswith(("ecdsa-sha2-", "sk-ecdsa-sha2-")):
        curve, offset = read_wire_bytes(blob, offset)
        point, _ = read_wire_bytes(blob, offset)
        if not point:
            raise ValueError("empty ECDSA public point")
        return ECDSA_BITS.get(curve.decode("ascii", "replace"), 0)
    return 0


def sha256_fingerprint(blob: bytes) -> str:
    """OpenSSH SHA256 fingerprint: base64 of the SHA-256 digest, no padding."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def type_label(key_type: str) -> str:
    """`ssh-keygen -l` style label: RSA, ED25519, ECDSA-SK, RSA-CERT, ..."""
    if key_type.endswith(CERT_SUFFIX):
        base = key_type[:-len(CERT_SUFFIX)]
        base = base + "@openssh.com" if base.startswith("sk-") else base
        return TYPE_LABELS.get(base, "UNKNOWN") + "-CERT"
    return TYPE_LABELS.get(key_type, "UNKNOWN")


def parse_key_blob(b64_key: str, declared_type: Optional[str] = None) -> Dict[str, object]:
    """Decode a base64 OpenSSH public key and return type, bits and fingerprint.
    On a problem the result carries an "error" entry."""
    try:
        raw = base64.b64decode(b64_key.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        return {"error": "invalid base64 key data (%s)" % exc}
    try:
        type_bytes, offset = read_wire_bytes(raw, 0)
        key_type = type_bytes.decode("ascii")
    except (ValueError, UnicodeDecodeError) as exc:
        return {"error": "corrupt key data (%s)" % exc}
    if declared_type and declared_type != key_type:
        return {"error": "key type in line (%s) does not match the key data (%s)"
                         % (declared_type, key_type)}
    try:
        plain_type, plain_blob = _plain_key_blob(key_type, raw, offset)
        _t, plain_offset = read_wire_bytes(plain_blob, 0)
        bits = _key_bits(plain_type, plain_blob, plain_offset)
    except ValueError as exc:
        return {"error": "corrupt %s key data (%s)" % (key_type, exc)}
    return {
        "type": key_type,
        "plain_type": plain_type,
        "label": type_label(key_type),
        "bits": bits,
        "fingerprint": sha256_fingerprint(plain_blob),
    }


# ---------------------------------------------------------------------------
# authorized_keys parsing
# ---------------------------------------------------------------------------

def split_fields(line: str) -> List[str]:
    """Split on whitespace, keeping quoted option values (command="a b") together."""
    fields: List[str] = []
    cur: List[str] = []
    in_quotes = escaped = False
    for ch in line:
        if escaped:
            cur.append(ch)
            escaped = False
        elif ch == "\\" and in_quotes:
            cur.append(ch)
            escaped = True
        elif ch == '"':
            in_quotes = not in_quotes
            cur.append(ch)
        elif ch.isspace() and not in_quotes:
            if cur:
                fields.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        fields.append("".join(cur))
    return fields


def parse_line(line: str) -> Optional[Dict[str, object]]:
    """Parse one authorized_keys line: [options] keytype base64 [comment].
    Returns None for blank lines and # comments."""
    line = line.strip().lstrip("\ufeff").strip()
    if not line or line.startswith("#"):
        return None
    fields = split_fields(line)
    options = ""
    idx = 0
    if fields and fields[0] not in KNOWN_KEY_TYPES:
        options = fields[0]
        idx = 1
    if idx + 1 >= len(fields) or fields[idx] not in KNOWN_KEY_TYPES:
        return {"error": "not a recognised key line (no supported key type + key data)"}
    info = parse_key_blob(fields[idx + 1], declared_type=fields[idx])
    info["options"] = options
    info["comment"] = " ".join(fields[idx + 2:])
    return info


def check_key(info: Dict[str, object], min_rsa_bits: int = DEFAULT_MIN_RSA_BITS) -> List[str]:
    """Return the findings for one parsed line (empty list = OK)."""
    if info.get("error"):
        return ["INVALID_LINE: %s" % info["error"]]
    findings: List[str] = []
    plain_type = info.get("plain_type")
    bits = int(info.get("bits") or 0)
    if plain_type == "ssh-dss":
        findings.append("DSA_KEY: DSA keys are deprecated (disabled by default since OpenSSH 7.0, removed in OpenSSH 10.0)")
    elif plain_type == "ssh-rsa" and 0 < bits < min_rsa_bits:
        findings.append("WEAK_RSA: RSA key is %d bits, below %d" % (bits, min_rsa_bits))
    if not info.get("comment"):
        findings.append("NO_COMMENT: no comment, so the key owner cannot be told from the file")
    return findings


def audit_text(text: str, min_rsa_bits: int = DEFAULT_MIN_RSA_BITS) -> List[Dict[str, object]]:
    """Audit the content of one authorized_keys file. Returns one entry per
    non-blank, non-comment line, with "line" (1-based) and "findings"."""
    results: List[Dict[str, object]] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        info = parse_line(raw)
        if info is None:
            continue
        info["line"] = lineno
        info["findings"] = check_key(info, min_rsa_bits)
        results.append(info)
    return results


def keygen_style(info: Dict[str, object]) -> str:
    """'<bits> SHA256:<fp> <comment> (<TYPE>)', the `ssh-keygen -lf` line format."""
    return "%s %s %s (%s)" % (info["bits"], info["fingerprint"],
                              info.get("comment") or "no comment", info["label"])


# ---------------------------------------------------------------------------
# report and CLI
# ---------------------------------------------------------------------------

def render_report(source: str, results: List[Dict[str, object]], min_rsa_bits: int) -> str:
    out = ["ssh-keyaudit-lite %s: %s" % (__version__, source), ""]
    if not results:
        out.append("  No keys found.")
    for r in results:
        if r.get("error"):
            out.append("  FLAG  line %d: invalid line" % r["line"])
        else:
            status = "FLAG" if r["findings"] else "OK  "
            out.append("  %s  line %d: %s" % (status, r["line"], keygen_style(r)))
        for f in r["findings"]:
            out.append("          - %s" % f)
    keys = [r for r in results if not r.get("error")]
    invalid = len(results) - len(keys)
    flagged = sum(1 for r in keys if r["findings"])
    counts = []
    for code, label in (("DSA_KEY", "DSA"), ("WEAK_RSA", "RSA < %d bits" % min_rsa_bits),
                        ("NO_COMMENT", "no comment")):
        n = sum(1 for r in keys if any(f.startswith(code) for f in r["findings"]))
        if n:
            counts.append("%d %s" % (n, label))
    out.append("")
    out.append("%d key(s): %d OK, %d flagged%s; %d invalid line(s)."
               % (len(keys), len(keys) - flagged, flagged,
                  " (" + ", ".join(counts) + ")" if counts else "", invalid))
    out.append("Read-only: the file was not changed.")
    return "\n".join(out)


DEMO_AUTHORIZED_KEYS = "\n".join([
    "# demo authorized_keys (public test keys, private halves discarded)",
    "ssh-ed25519 " + (
        "AAAAC3NzaC1lZDI1NTE5AAAAIF2qygAXG2+jbV8W50Nq9rY7zGDvoLFg2K2z/DAY"
        "ZMh3"
    ) + " alice@laptop",
    'from="10.0.0.0/8",no-pty ssh-rsa ' + (
        "AAAAB3NzaC1yc2EAAAADAQABAAAAgQCjbTjcefm9hye2rZNztr7v23FSCwNngeMq"
        "ImppI8cEyH5xHVF7GLGca1lZDFbOJU3ZkfLLknR1TPG8W3vi3xtEvLlw3Vwkb9b4"
        "9N81hHTFH5D6bQ8pb7rF4l4p1Br2X5Z6fgiJS7aqM9FTonTGVXaMnMWOfYCnPVx1"
        "/w37tUbv/Q=="
    ) + " bob@old-laptop",
    "ssh-ed25519 " + (
        "AAAAC3NzaC1lZDI1NTE5AAAAIA6yhSu/pEz3TK/5/D3Sxc78vKyb+m4DuFhEdDau"
        "x0cL"
    ),
    "ssh-dss " + (
        "AAAAB3NzaC1kc3MAAACBAKyASLUAE09CXhic4BA00UHmyZOueeR1BsYo9gzzONyb"
        "0JVyVWHON2/rjg7RkX0p6/jTYGyuBbAoaIvqEkFn5Dw7mABOJ/at/N+X4asbBkyn"
        "7cPX/NcPxFDKKIrvtBp3Rf5Rpt/Y4Xc84xo7wWnwdauBQzaNEjWxA4uMmsg7h3Oj"
        "AAAAFQDXfMZ7YOGMSLPO4hhtsBQFVjpMcwAAAIEAo9VT55CfHG4jZLS8d8B+Fnm1"
        "H7I/kp6vZuzw5JosgXC/n91+Fxvo1l2447cAZZKv4a0BGE6XLb1maBPdpPH1l9IV"
        "v5sx8wE51xGLQYUgcxL28i1ct44faN9CKMSmpbkUlmByMJsxBGya0ZgIaybrcFh5"
        "Ptcrpuhhnp6b5jnsMGwAAACBAIIiFRI0Qjazx0I2siq1y0r7beU9hZxxCEqb0F8f"
        "cAElcG6P1vFZ8VNQX8l+RVnrbTAjqtqYomgXXBW8zyst89ytbkG3Y1EDz3fQrnnc"
        "f5JHlY0WdXwfyyYxk67piAL5ZL3XUBK9e8IiARIMfj3+ds1H4tvXeKZkNj10rdQ9"
        "kSTl"
    ) + " legacy-ci",
    "ssh-rsa not-a-real-key broken-paste",
])


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ssh-keyaudit-lite",
        description="Audit one SSH authorized_keys file: SHA256 fingerprints (ssh-keygen -lf format), "
                    "key type, bits and comment; flags DSA keys, weak RSA keys and keys without a comment. "
                    "Read-only.",
        epilog="Fleet scan, owner mapping, removal plan and JSON report: " + PRO_URL,
    )
    parser.add_argument("file", nargs="?", default=None,
                        help="authorized_keys file to audit (default: ~/.ssh/authorized_keys; '-' reads stdin)")
    parser.add_argument("--min-rsa-bits", type=int, default=DEFAULT_MIN_RSA_BITS, metavar="N",
                        help="flag RSA keys smaller than N bits (default: %d)" % DEFAULT_MIN_RSA_BITS)
    parser.add_argument("--demo", action="store_true", help="audit a built-in sample file (offline)")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = parser.parse_args(argv)

    if args.min_rsa_bits < 0:
        parser.error("--min-rsa-bits must be 0 or more")

    if args.demo:
        source, text = "demo (built-in sample authorized_keys)", DEMO_AUTHORIZED_KEYS
    elif args.file == "-":
        source, text = "<stdin>", sys.stdin.read()
    else:
        path = os.path.expanduser(args.file or DEFAULT_FILE)
        source = path
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            sys.stderr.write("ssh-keyaudit-lite: cannot read %s: %s\n" % (path, exc.strerror or exc))
            return 2

    results = audit_text(text, args.min_rsa_bits)
    print(render_report(source, results, args.min_rsa_bits))
    return 1 if any(r["findings"] for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
