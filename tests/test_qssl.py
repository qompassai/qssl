"""Qssl gate (Tiger Style wave 2, 2026-10-17).

Runs the shipped pqctest harness against the system OpenSSL and asserts
the post-quantum signature algorithms actually complete
key-gen/sign/verify. Adversarial: a missing openssl must fail loudly, and a tampered signature must not verify.
"""
import os
import subprocess

import pytest

ROOT = __file__.rsplit("/tests/", 1)[0]
SCRIPT = ROOT + "/scripts/tests/pqctest.sh"
BT = chr(96)


def run_pqctest(env_extra=None):
    env = dict(os.environ)
    env.pop("OPENSSL_CONF", None)
    env.pop("OPENSSL_MODULES", None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(["/usr/bin/bash", SCRIPT], capture_output=True, text=True,
                          timeout=900, env=env)


@pytest.fixture(scope="module")
def report():
    r = run_pqctest()
    assert r.returncode == 0, r.stderr[-2000:]
    return r.stdout


def row_for(report, alg):
    rows = [ln for ln in report.splitlines() if (BT + alg + BT) in ln]
    assert rows, alg + " missing from report"
    return rows[0]


@pytest.mark.parametrize("alg", ["MLDSA44", "MLDSA65", "MLDSA87",
                                 "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f"])
def test_pq_signature_algorithms_roundtrip(report, alg):
    cells = [c.strip() for c in row_for(report, alg).split("|")]
    assert cells[2:5] == ["OK", "OK", "OK"], row_for(report, alg)


@pytest.mark.parametrize("alg", ["ED25519", "rsaEncryption"])
def test_classical_roundtrips(report, alg):
    assert "| OK | OK | OK |" in row_for(report, alg)


def test_missing_openssl_fails_loudly(tmp_path):
    # Adversarial: with openssl absent from PATH the harness must fail
    # loudly, never print an empty report with exit 0 (the old
    # process-substitution form did exactly that).
    shim = tmp_path / "bin"
    shim.mkdir()
    import shutil as _sh
    for tool in ("mktemp", "awk", "sed", "grep", "sort", "cat", "rm"):
        src = _sh.which(tool)
        assert src, tool
        (shim / tool).symlink_to(src)
    r = run_pqctest({"PATH": str(shim)})
    assert r.returncode != 0


def test_tampered_signature_rejected(tmp_path):
    key = tmp_path / "k.pem"
    pub = tmp_path / "p.pem"
    msg = tmp_path / "m.txt"
    sig = tmp_path / "s.bin"
    msg.write_text("Quantum-test")
    subprocess.run(["openssl", "genpkey", "-algorithm", "MLDSA44", "-out", str(key)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-in", str(msg),
                    "-out", str(sig)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)],
                   check=True, capture_output=True)
    msg.write_text("tampered")
    r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub),
                        "-in", str(msg), "-sigfile", str(sig)],
                       capture_output=True)
    assert r.returncode != 0
