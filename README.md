# ssh-keyaudit-lite: audit an SSH authorized_keys file, read-only

ssh-keyaudit-lite helps with a quick look at who can log in to one machine: it reads one `authorized_keys` file and prints, for every key, the SHA256 fingerprint (same format as `ssh-keygen -lf`), the key type, the key size in bits and the comment. It flags DSA keys, RSA keys below 3072 bits, keys with no comment, and lines that are not valid keys. It exits `1` when something is flagged, so it fits a cron job or a pre-check script. It never edits the file. One file, Python 3.9+ standard library only, MIT.

Need to audit a whole fleet, find keys reused across hosts, map keys to owners, or get a removal plan? That is the full [SSH KeyAudit](https://py-forge.com/products/ssh-keyaudit-fleet-key-inventory?utm_source=github&utm_medium=readme&utm_campaign=ssh-keyaudit-lite) (one-time payment, yours to keep, no subscription). A table later in this README lists what lite does and what the paid tool adds. Or get every PyForge tool, current and future, with the [All-Access Pass](https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=ssh-keyaudit-lite) ($99, one payment).

- Optional `pip install`, or just download the one file. No config, no state, no network access.
- Reads one file (default `~/.ssh/authorized_keys`, or a path you pass, or `-` for stdin). Nothing is written.
- Understands `authorized_keys` options (`from="..."`, `command="..."`, `no-pty`, ...), comments, blank lines and OpenSSH certificates.
- Fingerprints are computed in Python from the key data; no `ssh-keygen` needed.
- Flags: `--min-rsa-bits`, `--demo`, `--version`. After `pip install`, use `ssh-keyaudit-lite` in place of `python3 ssh_keyaudit_lite.py`.

<!-- TODO: terminal GIF of `--demo` is still missing. Place it under the intro, before Install. Do not invent a GIF. -->

## Install

```bash
pip install ssh-keyaudit-lite
ssh-keyaudit-lite --help
```

Or download the single file (Python 3.9+, stdlib only, no extra packages):

```bash
curl -fsSLO https://raw.githubusercontent.com/alessio1999xx-debug/ssh-keyaudit-lite/main/ssh_keyaudit_lite.py
python3 ssh_keyaudit_lite.py --help
```

## See the output first (offline demo)

```bash
python3 ssh_keyaudit_lite.py --demo
# ssh-keyaudit-lite 0.1.0: demo (built-in sample authorized_keys)
#
#   OK    line 2: 256 SHA256:ehngEyw0ibJhOPXM8qj4kHqp7PMOVB8whu2zTPeF2Dc alice@laptop (ED25519)
#   FLAG  line 3: 1024 SHA256:8r4r4yg1OcSAK7Bz9sMFslRJNPLryUYiOko0gbhQGOw bob@old-laptop (RSA)
#           - WEAK_RSA: RSA key is 1024 bits, below 3072
#   FLAG  line 4: 256 SHA256:qoGqsyZZLKieeTNmmTa5cxqEaRS0oE9CI9MpxJV+VpE no comment (ED25519)
#           - NO_COMMENT: no comment, so the key owner cannot be told from the file
#   FLAG  line 5: 1024 SHA256:1+DAnFbM29PkFgyIxsfhJPVm0c/YXZ4Zr1hP+xtf7qI legacy-ci (DSA)
#           - DSA_KEY: DSA keys are deprecated (disabled by default since OpenSSH 7.0, removed in OpenSSH 10.0)
#   FLAG  line 6: invalid line
#           - INVALID_LINE: invalid base64 key data (Only base64 data is allowed)
#
# 4 key(s): 1 OK, 3 flagged (1 DSA, 1 RSA < 3072 bits, 1 no comment); 1 invalid line(s).
# Read-only: the file was not changed.
```

The demo uses a built-in sample file with public test keys.

## Audit your authorized_keys file

```bash
python3 ssh_keyaudit_lite.py                               # ~/.ssh/authorized_keys
python3 ssh_keyaudit_lite.py /home/deploy/.ssh/authorized_keys
sudo python3 ssh_keyaudit_lite.py /root/.ssh/authorized_keys
cat authorized_keys | python3 ssh_keyaudit_lite.py -       # stdin
python3 ssh_keyaudit_lite.py --min-rsa-bits 2048           # your own RSA threshold
```

The part after `line N:` is the same text `ssh-keygen -lf` prints for that key (`<bits> SHA256:<fingerprint> <comment> (<TYPE>)`), so you can match it against `ssh-keygen -lf ~/.ssh/id_ed25519.pub` on the client side.

## What gets flagged

| Finding | Meaning |
| --- | --- |
| `DSA_KEY` | `ssh-dss` key. DSA has been disabled by default since OpenSSH 7.0 and is removed in OpenSSH 10.0 |
| `WEAK_RSA` | RSA key smaller than `--min-rsa-bits` (default 3072, the same default as the full SSH KeyAudit) |
| `NO_COMMENT` | Key without a comment, so you cannot tell from the file whose key it is |
| `INVALID_LINE` | Line that is not a valid key: unknown type, bad base64, truncated key data, or a type that does not match the key data |

Key types read: RSA, DSA, ECDSA (P-256/384/521), Ed25519, the FIDO `sk-` variants, and their OpenSSH certificates (the fingerprint shown for a certificate is the certified key's, as `ssh-keygen -l` does).

## Exit codes for cron

| Exit code | Meaning |
| --- | --- |
| `0` | No findings (or no keys in the file) |
| `1` | At least one key or line was flagged |
| `2` | File not readable, or bad arguments |

```bash
# crontab: check every Monday at 07:00, keep the last report
0 7 * * 1 python3 /opt/ssh_keyaudit_lite.py /home/deploy/.ssh/authorized_keys > /var/log/ssh-keyaudit-lite.txt 2>&1
```

## ssh-keyaudit-lite vs SSH KeyAudit

ssh-keyaudit-lite reads one local `authorized_keys` file and prints a plain-text list. That's it.

The full [SSH KeyAudit](https://py-forge.com/products/ssh-keyaudit-fleet-key-inventory?utm_source=github&utm_medium=readme&utm_campaign=ssh-keyaudit-lite) scans a list of hosts through your own `ssh` client (it reads every readable `authorized_keys` on each host), finds the same key on several hosts, maps keys to owners from a simple owners file, flags offboarded and unknown owners and keys without restricting options, compares against the previous run, and writes a removal script that you review and run yourself. One-time payment, yours to keep. No subscription.

Lite is not a strict subset: the `NO_COMMENT` flag and the `0` / `1` exit code on findings are not in the paid tool.

| Capability | Lite (free) | Paid SSH KeyAudit |
| --- | --- | --- |
| One local `authorized_keys` file (or stdin) | Yes | Yes |
| SHA256 fingerprint, type, bits, comment | Yes | Yes |
| DSA keys, RSA below a threshold (default 3072) | Yes | Yes |
| Invalid lines reported | Yes | Yes |
| Keys without a comment | Yes | No |
| Fleet scan of many hosts through your own `ssh` (`--hosts`) | No | Yes |
| Same key reused across hosts | No | Yes |
| Owner mapping, offboarded / unknown owners (`--owners`) | No | Yes |
| Keys without restricting options (`from=`, `command=`, ...) | No | Yes |
| Diff against the previous run (`--out-state`, `--diff`) | No | Yes |
| Removal plan script you review and run (`--out-plan`, never run by the tool) | No | Yes |
| Output | Plain text | Text or JSON (`--json`) |
| Exit code `1` when something is flagged | Yes | No (exits `0` with findings) |

Neither version edits `authorized_keys` files by itself.

> Need the full version? **SSH KeyAudit** on PyForge:
> [py-forge.com/products/ssh-keyaudit-fleet-key-inventory](https://py-forge.com/products/ssh-keyaudit-fleet-key-inventory?utm_source=github&utm_medium=readme&utm_campaign=ssh-keyaudit-lite)
>
> Or get every PyForge tool, current and future, with the All-Access Pass ($99, one payment):
> [py-forge.com/pass](https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=ssh-keyaudit-lite)

## Tests

```bash
python3 test_ssh_keyaudit_lite.py
```

The tests are offline. The fixture keys in `fixtures/` are public keys generated with `ssh-keygen` (private halves discarded), with the recorded `ssh-keygen -lf` output. When `ssh-keygen` is installed the tests also compare against a live `ssh-keygen -lf` run.

## License

MIT (this lite version). The full SSH KeyAudit is sold separately under its own license.
