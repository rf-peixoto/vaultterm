#!/usr/bin/env python3
"""
pqsign.py -- post-quantum release signatures for VaultTerm (ML-DSA-87, FIPS 204).

Standalone on purpose: needs only Python 3.10+ and `cryptography` >= 50, so a
user can check a release without running VaultTerm itself.

  pqsign.py keygen --out NAME            NAME.key (passphrase-encrypted) + NAME.pub
  pqsign.py fingerprint NAME.pub         print the key fingerprint to publish
  pqsign.py sign --key NAME.key FILE...  writes FILE.mldsa next to each file
  pqsign.py verify --pub NAME.pub [--fingerprint FP] FILE...
                                         checks FILE.mldsa; exit 0 only if all valid

The private key file holds the 32-byte ML-DSA seed encrypted with
Argon2id (256 MiB) -> HKDF-BLAKE2b -> ChaCha20-Poly1305 + BLAKE2b key commitment.
Publish the fingerprint through a channel separate from the download.
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import sys

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CONTEXT = b"vaultterm-release-v1"
KEY_FORMAT = "vaultterm-mldsa87-key-v1"
SIG_HEADER = "vaultterm-mldsa87-signature-v1"
PUB_HEADER = "VaultTerm ML-DSA-87 public key"
KDF = {"time_cost": 3, "memory_cost": 262144, "parallelism": 4}


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def fingerprint(pub: bytes) -> str:
    h = hashlib.blake2b(pub, digest_size=20, person=b"vt-mldsa-fpr").hexdigest().upper()
    return " ".join(h[i:i + 4] for i in range(0, len(h), 4))


def _kek(passphrase: str, salt: bytes, kdf: dict) -> bytes:
    raw = Argon2id(salt=salt, length=64, iterations=kdf["time_cost"], lanes=kdf["parallelism"],
                   memory_cost=kdf["memory_cost"]).derive(passphrase.encode("utf-8"))
    return HKDF(algorithm=hashes.BLAKE2b(64), length=32, salt=None, info=b"vaultterm/pqsign/kek").derive(raw)


def _commit(key: bytes, nonce: bytes) -> bytes:
    return hashlib.blake2b(nonce, key=key, digest_size=32, person=b"vt-pqsign-cmt").digest()


def _write_new(path: str, data: bytes, mode: int):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def load_pub(path: str) -> bytes:
    lines = [ln.strip() for ln in open(path, encoding="ascii").read().splitlines() if ln.strip()]
    if not lines or lines[0] != PUB_HEADER:
        raise SystemExit(f"[ERR] {path}: not a VaultTerm ML-DSA-87 public key")
    pub = b64d(lines[1])
    mldsa.MLDSA87PublicKey.from_public_bytes(pub)
    return pub


def cmd_keygen(a):
    pw = getpass.getpass("passphrase for the new signing key: ")
    if len(pw) < 12 or pw != getpass.getpass("confirm passphrase: "):
        raise SystemExit("[ERR] passphrase mismatch or shorter than 12 characters")
    key = mldsa.MLDSA87PrivateKey.generate()
    seed, pub = key.private_bytes_raw(), key.public_key().public_bytes_raw()
    salt, nonce = os.urandom(32), os.urandom(12)
    kek = _kek(pw, salt, KDF)
    aad = KEY_FORMAT.encode() + pub
    blob = nonce + _commit(kek, nonce) + ChaCha20Poly1305(kek).encrypt(nonce, seed, aad)
    doc = {"format": KEY_FORMAT, "kdf": KDF, "salt": b64e(salt), "pub": b64e(pub), "blob": b64e(blob)}
    _write_new(a.out + ".key", json.dumps(doc, indent=1).encode() + b"\n", 0o600)
    _write_new(a.out + ".pub", f"{PUB_HEADER}\n{b64e(pub)}\n".encode("ascii"), 0o644)
    os.chmod(a.out + ".pub", 0o644)  # public: readable regardless of the private umask
    print(f"[OK] wrote {a.out}.key (keep it offline and private) and {a.out}.pub")
    print(f"     fingerprint: {fingerprint(pub)}")


def load_private(path: str) -> mldsa.MLDSA87PrivateKey:
    doc = json.load(open(path))
    if doc.get("format") != KEY_FORMAT:
        raise SystemExit(f"[ERR] {path}: unknown key format")
    pub, blob = b64d(doc["pub"]), b64d(doc["blob"])
    kek = _kek(getpass.getpass(f"passphrase for {path}: "), b64d(doc["salt"]), doc["kdf"])
    nonce, cm, ct = blob[:12], blob[12:44], blob[44:]
    try:
        if not hmac.compare_digest(cm, _commit(kek, nonce)):
            raise InvalidTag()
        seed = ChaCha20Poly1305(kek).decrypt(nonce, ct, KEY_FORMAT.encode() + pub)
    except InvalidTag:
        raise SystemExit("[ERR] wrong passphrase or damaged key file")
    key = mldsa.MLDSA87PrivateKey.from_seed_bytes(seed)
    if key.public_key().public_bytes_raw() != pub:
        raise SystemExit("[ERR] key file is inconsistent")
    return key


def cmd_sign(a):
    key = load_private(a.key)
    pub = key.public_key().public_bytes_raw()
    for f in a.files:
        data = open(f, "rb").read()
        sig = key.sign(data, CONTEXT)
        out = (f"{SIG_HEADER}\nkey: {fingerprint(pub)}\nfile: {os.path.basename(f)}\n"
               f"blake2b: {hashlib.blake2b(data).hexdigest()}\nsig: {b64e(sig)}\n")
        with open(f + ".mldsa", "w", encoding="ascii") as fh:
            fh.write(out)
        os.chmod(f + ".mldsa", 0o644)    # signatures are public
        print(f"[OK] signed {f} -> {f}.mldsa")


def cmd_verify(a):
    pub = load_pub(a.pub)
    fpr = fingerprint(pub)
    if a.fingerprint and a.fingerprint.replace(" ", "").upper() != fpr.replace(" ", ""):
        print(f"[FAIL] public key fingerprint {fpr} does not match the expected one", file=sys.stderr)
        return 1
    pk = mldsa.MLDSA87PublicKey.from_public_bytes(pub)
    bad = 0
    for f in a.files:
        try:
            fields = dict(ln.split(": ", 1) for ln in open(f + ".mldsa", encoding="ascii").read().splitlines()[1:] if ": " in ln)
            data = open(f, "rb").read()
            if fields.get("key") != fpr:
                raise ValueError("signed by a different key")
            pk.verify(b64d(fields["sig"]), data, CONTEXT)
            print(f"[PASS] {f}: valid ML-DSA-87 signature (key {fpr})")
        except (OSError, KeyError, ValueError, InvalidSignature) as e:
            print(f"[FAIL] {f}: {type(e).__name__}: {str(e) or 'invalid signature'}", file=sys.stderr)
            bad += 1
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out", required=True)
    f = sub.add_parser("fingerprint")
    f.add_argument("pub")
    s = sub.add_parser("sign")
    s.add_argument("--key", required=True)
    s.add_argument("files", nargs="+")
    v = sub.add_parser("verify")
    v.add_argument("--pub", required=True)
    v.add_argument("--fingerprint")
    v.add_argument("files", nargs="+")
    a = ap.parse_args()
    os.umask(0o077)
    if a.cmd == "keygen":
        cmd_keygen(a)
    elif a.cmd == "fingerprint":
        print(fingerprint(load_pub(a.pub)))
    elif a.cmd == "sign":
        cmd_sign(a)
    else:
        return cmd_verify(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
