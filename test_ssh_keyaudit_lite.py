"""Offline tests for ssh-keyaudit-lite.

Fixture keys in fixtures/ are public keys generated with ssh-keygen (private
halves discarded). fixtures/expected_fingerprints.txt holds the matching
`ssh-keygen -lf` output. When ssh-keygen is installed, the tests also compare
against a live `ssh-keygen -lf` run.
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import ssh_keyaudit_lite as ska

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
SAMPLE = os.path.join(FIX, "authorized_keys_sample")


def read(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


def expected():
    out = {}
    for line in read("expected_fingerprints.txt").splitlines():
        name, rest = line.split(" ", 1)
        out[name] = rest
    return out


def run(*argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    old_stdin = sys.stdin
    if stdin is not None:
        sys.stdin = io.StringIO(stdin)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = ska.main(list(argv))
    finally:
        sys.stdin = old_stdin
    return code, out.getvalue(), err.getvalue()


def ssh_keygen_lf(path):
    """Live `ssh-keygen -lf` output, or None when ssh-keygen is missing or rejects the key."""
    exe = shutil.which("ssh-keygen")
    if not exe:
        return None
    proc = subprocess.run([exe, "-lf", path], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, universal_newlines=True)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


class FingerprintTests(unittest.TestCase):
    def test_each_fixture_matches_recorded_ssh_keygen_output(self):
        exp = expected()
        self.assertGreaterEqual(len(exp), 10)
        for name, want in exp.items():
            with self.subTest(key=name):
                results = ska.audit_text(read(name))
                self.assertEqual(len(results), 1)
                self.assertEqual(ska.keygen_style(results[0]), want)

    def test_each_fixture_matches_live_ssh_keygen(self):
        if not shutil.which("ssh-keygen"):
            self.skipTest("ssh-keygen not installed")
        checked = 0
        for name in expected():
            live = ssh_keygen_lf(os.path.join(FIX, name))
            if live is None:  # e.g. DSA on OpenSSH 10+, which dropped DSA support
                continue
            with self.subTest(key=name):
                self.assertEqual(ska.keygen_style(ska.audit_text(read(name))[0]), live)
                checked += 1
        self.assertGreaterEqual(checked, 8)

    def test_sample_file_matches_live_ssh_keygen_line_by_line(self):
        live = ssh_keygen_lf(SAMPLE)
        if live is None:
            self.skipTest("ssh-keygen not installed")
        ours = [ska.keygen_style(r) for r in ska.audit_text(read("authorized_keys_sample"))]
        live_lines = live.splitlines()
        # older ssh-keygen versions also print the DSA key; newer ones skip it
        if len(live_lines) == len(ours) - 1:
            ours = [o for o in ours if not o.endswith("(DSA)")]
        self.assertEqual(ours, live_lines)

    def test_types_and_bits(self):
        cases = {
            "ed25519.pub": ("ED25519", 256), "rsa4096.pub": ("RSA", 4096),
            "rsa1024.pub": ("RSA", 1024), "rsa2048.pub": ("RSA", 2048),
            "ecdsa256.pub": ("ECDSA", 256), "ecdsa384.pub": ("ECDSA", 384),
            "ecdsa521.pub": ("ECDSA", 521), "dsa1024.pub": ("DSA", 1024),
            "ed25519-cert.pub": ("ED25519-CERT", 256),
        }
        for name, (label, bits) in cases.items():
            with self.subTest(key=name):
                r = ska.audit_text(read(name))[0]
                self.assertEqual((r["label"], r["bits"]), (label, bits))

    def test_certificate_fingerprint_is_the_certified_key(self):
        plain = ska.audit_text(read("ed25519.pub"))[0]["fingerprint"]
        cert = ska.audit_text(read("ed25519-cert.pub"))[0]["fingerprint"]
        self.assertEqual(plain, cert)


class ParsingTests(unittest.TestCase):
    def setUp(self):
        self.results = ska.audit_text(read("authorized_keys_sample"))

    def test_blank_and_comment_lines_are_skipped_and_line_numbers_kept(self):
        self.assertEqual([r["line"] for r in self.results], [3, 4, 5, 7, 8, 9, 10])

    def test_options_prefixed_lines(self):
        by_line = {r["line"]: r for r in self.results}
        self.assertEqual(by_line[4]["options"], 'from="10.0.0.0/8",no-agent-forwarding')
        self.assertEqual(by_line[4]["comment"], "backup-operator")
        self.assertTrue(by_line[5]["options"].startswith('command="/usr/local/bin/backup --mode \\"full run\\""'))
        self.assertEqual(by_line[5]["comment"], "ci-deploy key")
        self.assertEqual(by_line[5]["bits"], 2048)

    def test_comment_less_key(self):
        r = ska.audit_text(read("nocomment.pub"))[0]
        self.assertEqual(r["comment"], "")
        self.assertIn("no comment (ED25519)", ska.keygen_style(r))

    def test_bom_crlf_and_tabs(self):
        key = read("ed25519.pub").split()
        text = "\ufeff" + key[0] + "\t" + key[1] + "\t alice@laptop\r\n\r\n"
        r = ska.audit_text(text)
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["comment"], "alice@laptop")
        self.assertEqual(r[0]["findings"], [])

    def test_invalid_lines(self):
        key = read("ed25519.pub").split()[1]
        rsa = read("rsa2048.pub").split()[1]
        text = "\n".join([
            "ssh-ed25519 !!!notbase64!!! bad",
            "garbage line here",
            "ssh-rsa " + key + " type-mismatch",
            "ssh-ed25519 " + key[:20] + " truncated",
            "ssh-rsa " + rsa[:60] + " truncated-rsa",
            "ssh-ed25519",
        ])
        results = ska.audit_text(text)
        self.assertEqual(len(results), 6)
        for r in results:
            self.assertIn("error", r)
            self.assertTrue(r["findings"][0].startswith("INVALID_LINE"))
        self.assertIn("does not match", results[2]["error"])

    def test_split_fields_keeps_quoted_spaces(self):
        self.assertEqual(ska.split_fields('command="a b",no-pty ssh-ed25519 AAAA c d'),
                         ['command="a b",no-pty', "ssh-ed25519", "AAAA", "c", "d"])


class FindingTests(unittest.TestCase):
    def findings(self, name, **kw):
        return ska.audit_text(read(name), **kw)[0]["findings"]

    def test_dsa_flagged(self):
        self.assertTrue(self.findings("dsa1024.pub")[0].startswith("DSA_KEY"))

    def test_rsa_threshold_default_3072(self):
        self.assertTrue(self.findings("rsa1024.pub")[0].startswith("WEAK_RSA"))
        self.assertTrue(self.findings("rsa2048.pub")[0].startswith("WEAK_RSA"))
        self.assertEqual(self.findings("rsa4096.pub"), [])

    def test_rsa_threshold_configurable(self):
        self.assertEqual(self.findings("rsa2048.pub", min_rsa_bits=2048), [])
        self.assertTrue(self.findings("rsa1024.pub", min_rsa_bits=2048)[0].startswith("WEAK_RSA"))

    def test_no_comment_flagged(self):
        self.assertEqual([f.split(":")[0] for f in self.findings("nocomment.pub")], ["NO_COMMENT"])

    def test_modern_keys_ok(self):
        for name in ("ed25519.pub", "ecdsa256.pub", "ecdsa384.pub", "ecdsa521.pub", "ed25519-cert.pub"):
            with self.subTest(key=name):
                self.assertEqual(self.findings(name), [])


class CliTests(unittest.TestCase):
    def test_sample_file_exit_1_and_summary(self):
        code, out, _ = run(SAMPLE)
        self.assertEqual(code, 1)
        self.assertIn("7 key(s): 3 OK, 4 flagged (1 DSA, 2 RSA < 3072 bits, 1 no comment); 0 invalid line(s).", out)
        self.assertIn("OK    line 3: 256 SHA256:ehngEyw0ibJhOPXM8qj4kHqp7PMOVB8whu2zTPeF2Dc alice@laptop (ED25519)", out)

    def test_clean_file_exit_0(self):
        code, out, _ = run(os.path.join(FIX, "ed25519.pub"))
        self.assertEqual(code, 0)
        self.assertIn("1 key(s): 1 OK, 0 flagged; 0 invalid line(s).", out)

    def test_min_rsa_bits_option(self):
        code, out, _ = run("--min-rsa-bits", "1024", os.path.join(FIX, "rsa1024.pub"))
        self.assertEqual(code, 0)

    def test_missing_file_exit_2(self):
        code, _, err = run(os.path.join(FIX, "does-not-exist"))
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    def test_empty_file_exit_0(self):
        with tempfile.NamedTemporaryFile("w", suffix="_ak", delete=False) as fh:
            fh.write("# only a comment\n\n")
        try:
            code, out, _ = run(fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual(code, 0)
        self.assertIn("No keys found.", out)

    def test_default_path_is_home_authorized_keys(self):
        tmp = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(tmp, ".ssh"))
            shutil.copy(os.path.join(FIX, "ecdsa256.pub"), os.path.join(tmp, ".ssh", "authorized_keys"))
            old = os.environ.get("HOME")
            os.environ["HOME"] = tmp
            try:
                code, out, _ = run()
            finally:
                if old is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = old
        finally:
            shutil.rmtree(tmp)
        self.assertEqual(code, 0)
        self.assertIn(os.path.join(tmp, ".ssh", "authorized_keys"), out)
        self.assertIn("carol@desk (ECDSA)", out)

    def test_stdin(self):
        code, out, _ = run("-", stdin=read("rsa1024.pub"))
        self.assertEqual(code, 1)
        self.assertIn("<stdin>", out)
        self.assertIn("WEAK_RSA", out)

    def test_demo(self):
        code, out, _ = run("--demo")
        self.assertEqual(code, 1)
        self.assertIn("4 key(s): 1 OK, 3 flagged (1 DSA, 1 RSA < 3072 bits, 1 no comment); 1 invalid line(s).", out)

    def test_file_is_not_modified(self):
        before = os.stat(SAMPLE).st_mtime_ns, read("authorized_keys_sample")
        run(SAMPLE)
        self.assertEqual(before, (os.stat(SAMPLE).st_mtime_ns, read("authorized_keys_sample")))

    def test_version(self):
        with self.assertRaises(SystemExit) as cm:
            run("--version")
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
