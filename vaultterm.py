#!/usr/bin/env python3
"""
VAULTTERM v4 -- offline terminal password vault for Linux.

Storage model (see README.md for the full design):
  * one vault file: MAGIC | header (JSON, authenticated) | payload (ChaCha20-Poly1305)
  * the payload is the whole vault (entries, settings, audit log, keys), padded
    to 32 KiB buckets, encrypted with a random 256-bit data key (DEK)
  * the DEK is wrapped by a key derived from the master password with Argon2id
  * optional paper recovery kit: a second wrap of the DEK under a random
    recovery key that is split with Shamir's secret sharing and printed
  * attachments ("secret keys") are separate encrypted, padded blob files whose
    SHA-256 is recorded inside the authenticated payload
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import gc
import hashlib
import hmac
import io
import json
import math
import os
import re
import resource
import secrets
import select
import shutil
import signal
import stat
import string
import struct
import subprocess
import sys
import tarfile
import tempfile
import termios
import threading
import time
import traceback
import unicodedata
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

if not getattr(sys, "frozen", False):  # `python -I` drops the script dir from sys.path
    _here = os.path.dirname(os.path.abspath(__file__))
    if _here not in sys.path:
        sys.path.insert(0, _here)
from vaultterm_wordlist import WORDS as EFF_WORDS  # noqa: E402

try:  # optional: QR codes on the paper recovery kit
    import qrcode
    import qrcode.constants
except Exception:  # pragma: no cover - optional dependency
    qrcode = None

# ── constants ────────────────────────────────────────────────────────────────

VERSION = "4.0.0"
FORMAT_VERSION = 4
MAGIC = b"VTVAULT\x04"

ARGON2_RECOMMENDED = {"time_cost": 3, "memory_cost": 262144, "parallelism": 4}   # 256 MiB
ARGON2_MIN = {"time_cost": 2, "memory_cost": 65536, "parallelism": 1}            # 64 MiB
ARGON2_MAX = {"time_cost": 64, "memory_cost": 4194304, "parallelism": 16}        # 4 GiB
SALT_LEN = 32
KEY_LEN = 32
WRAP_LEN = 12 + KEY_LEN + 16

PAYLOAD_BUCKET = 32 * 1024
MAX_HEADER = 64 * 1024
MAX_VAULT_FILE = 256 * 1024 * 1024
MAX_ATTACHMENT = 64 * 1024 * 1024
MAX_SHOW_TEXT = 64 * 1024
LOG_MAX_ITEMS = 2000
HISTORY_MAX = 24
EVENTS_MAX_BYTES = 256 * 1024

MASTER_MIN_LEN = 12
MASTER_TARGET_BITS = 60
ENTRY_WARN_LEN = 12

KINDS = ("password", "pin", "passphrase", "secret_key")
KIND_LABEL = {"password": "password", "pin": "PIN", "passphrase": "passphrase", "secret_key": "secret key"}
KIND_SHORT = {"password": "pw", "pin": "pin", "passphrase": "phrase", "secret_key": "key"}

DEFAULT_SETTINGS = {
    "expiry_days": 30,
    "auto_lock_minutes": 10,
    "clipboard_enabled": False,
    "clipboard_clear_seconds": 30,
}

DEADMAN_SENTINEL = b"VAULTTERM::DEADMAN::v4"
RECOVERY_INFO = b"vaultterm/v4/recovery-kek"
EVENT_INFO = b"vaultterm/v4/sealed-event"

ERROR_TEXT = {
    "AUTH_FAILED": "authentication failed.",
    "VAULT_FORMAT": "vault file is unreadable.",
    "VAULT_INTEGRITY": "vault database corrupted. unable to recover vault state. "
                       "reinstall VaultTerm and initialise a new vault.",
    "VAULT_MISSING": "vault file not found, but other vault data exists.",
    "KDF_PARAMS": "key-derivation parameters are outside safe limits.",
    "BLOB_INTEGRITY": "an encrypted attachment failed its integrity check.",
    "IO_ERROR": "a file operation failed.",
    "BACKUP_INVALID": "the backup could not be verified.",
    "RECOVERY_INVALID": "recovery shares are invalid.",
    "CLIPBOARD": "clipboard unavailable.",
    "INPUT": "invalid input.",
    "INTERNAL": "unexpected internal error.",
}

# ── palette / console ────────────────────────────────────────────────────────

C_HEAD = "bright_cyan"
C_KEY = "bright_cyan"
C_OK = "green"
C_WARN = "yellow"
C_ERR = "bright_red"
C_DIM = "grey50"
C_DATA = "white"
C_PW = "bright_yellow"
C_LABEL = "cyan"

console = Console(highlight=False)


class Paths:
    def __init__(self, base: Path):
        self.base = base
        self.vault = base / "vault.vt"
        self.blobs = base / "blobs"
        self.backups = base / "backups"
        self.events = base / "events.sealed"


def _default_base() -> Path:
    env = os.environ.get("VAULTTERM_DIR")
    return Path(env).expanduser().absolute() if env else Path.home() / ".vaultterm"


P = Paths(_default_base())

# ── errors ───────────────────────────────────────────────────────────────────


class VaultError(Exception):
    """Every user-visible failure. `kind` is shown, `detail` goes to the LOG."""

    def __init__(self, kind: str, detail: str = "", ref: Optional[str] = None):
        super().__init__(f"{kind}: {detail}")
        self.kind = kind if kind in ERROR_TEXT else "INTERNAL"
        self.detail = detail
        self.ref = ref or secrets.token_hex(3)


class DeadmanTriggered(Exception):
    pass


class LockTimeout(BaseException):
    """Raised from any prompt when the auto-lock deadline passes."""

# ── small helpers ────────────────────────────────────────────────────────────


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_ts(ts: str) -> datetime:
    try:
        d = datetime.fromisoformat(ts)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)  # unreadable == maximally old


def local_date(ts: str) -> str:
    d = parse_ts(ts)
    if d.year == 1:
        return "?"
    return d.astimezone().strftime("%Y-%m-%d %H:%M")


def age_days(ts: str) -> int:
    return max(0, (datetime.now(timezone.utc) - parse_ts(ts)).days)


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(raw)).decode("ascii")


def b64d(txt: str) -> bytes:
    if not isinstance(txt, str):
        raise ValueError("expected base64 text")
    return base64.b64decode(txt.encode("ascii"), altchars=b"-_", validate=True)


def canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def clean(s: str) -> str:
    """Single-line user text: drop control/format characters, trim."""
    s = unicodedata.normalize("NFC", s)
    return "".join(ch for ch in s if unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co")).strip()


def printable(s: str, keep_newlines: bool = False) -> str:
    """Make arbitrary text safe to print (no terminal escape sequences)."""
    out = []
    for ch in s:
        if keep_newlines and ch in "\n\t":
            out.append(ch)
        elif unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co"):
            out.append(f"\\x{ord(ch):02x}" if ord(ch) < 256 else f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


def human_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def clr():
    """Clear screen AND scrollback (ESC[3J) so revealed secrets don't linger."""
    sys.stdout.write("\033[H\033[2J\033[3J")
    sys.stdout.flush()


def ok(msg: str):
    console.print(f"\n  [{C_OK}][OK][/{C_OK}]  {msg}\n")


def err(msg: str):
    console.print(f"\n  [{C_ERR}][ERR][/{C_ERR}] {msg}\n")


def warn(msg: str):
    console.print(f"\n  [{C_WARN}][WARN][/{C_WARN}] {msg}\n")


def inf(msg: str):
    console.print(f"\n  [{C_HEAD}][SYS][/{C_HEAD}] {msg}\n")


def header(title: str):
    console.print()
    console.print(f"  [{C_HEAD}]>> {escape(title)}[/{C_HEAD}]")
    console.print(f"  [{C_DIM}]{'─' * (len(title) + 4)}[/{C_DIM}]")
    console.print()


def banner():
    console.print()
    w = min(console.width or 72, 100)
    tag = f"  VAULTTERM v{VERSION}  //  ChaCha20-Poly1305  //  Argon2id  //  OFFLINE"
    console.print(f"[{C_HEAD}]{'=' * w}[/{C_HEAD}]")
    console.print(f"[{C_HEAD}]{tag}[/{C_HEAD}]")
    console.print(f"[{C_HEAD}]{'=' * w}[/{C_HEAD}]")
    console.print()

# ── process hardening ────────────────────────────────────────────────────────

_HARDENING = {"core_dumps_disabled": False, "non_dumpable": False}


def harden_process():
    """No core dumps, not ptrace-attachable by same-user processes, private umask."""
    os.umask(0o077)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        _HARDENING["core_dumps_disabled"] = resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
    except Exception:
        pass
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        PR_SET_DUMPABLE, PR_GET_DUMPABLE = 4, 3
        libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        _HARDENING["non_dumpable"] = libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
    except Exception:
        pass


def swap_status() -> Tuple[str, bool]:
    """Returns (description, looks_safe)."""
    try:
        lines = Path("/proc/swaps").read_text().splitlines()[1:]
    except Exception:
        return "unknown", False
    devs = [ln.split()[0] for ln in lines if ln.strip()]
    if not devs:
        return "no swap", True
    risky = [d for d in devs if not (d.startswith("/dev/zram") or d.startswith("/dev/dm-") or d.startswith("/dev/mapper/"))]
    if risky:
        return f"swap may be unencrypted: {', '.join(risky)}", False
    return f"zram / device-mapper swap: {', '.join(devs)}", True


@contextmanager
def signals_blocked():
    """Defer Ctrl+C / SIGTERM / SIGHUP until a commit step has fully finished."""
    sigs = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT}
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    old = signal.pthread_sigmask(signal.SIG_BLOCK, sigs)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)

# ── filesystem ───────────────────────────────────────────────────────────────


def ensure_dir(path: Path):
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = os.lstat(path)
    except OSError as e:
        raise VaultError("IO_ERROR", f"cannot create {path}: {e.strerror}")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise VaultError("IO_ERROR", f"{path} is not a real directory (symlink?)")
    if st.st_uid != os.getuid():
        raise VaultError("IO_ERROR", f"{path} is owned by uid {st.st_uid}, not you")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(path, 0o700)


def fsync_dir(path: Path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _write_all(fd: int, data: bytes):
    mv = memoryview(data)
    while mv:
        n = os.write(fd, mv)
        mv = mv[n:]


def atomic_write(path: Path, data: bytes):
    """Write to a private temp file, fsync, then rename over the target.
    Callers that must not be interrupted wrap this in signals_blocked()."""
    ensure_dir(path.parent)
    tmp = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if isinstance(e, OSError):
            raise VaultError("IO_ERROR", f"writing {path.name}: {e.strerror}")
        raise
    fsync_dir(path.parent)


def read_file_nofollow(path: Path, max_size: Optional[int] = None) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise VaultError("IO_ERROR", f"{path.name}: file not found")
    except OSError as e:
        raise VaultError("IO_ERROR", f"{path.name}: {e.strerror}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise VaultError("IO_ERROR", f"{path.name}: not a regular file")
        if st.st_uid != os.getuid():
            raise VaultError("IO_ERROR", f"{path.name}: owned by another user")
        if max_size is not None and st.st_size > max_size:
            raise VaultError("IO_ERROR", f"{path.name}: file too large ({st.st_size} bytes)")
        chunks = []
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks)
    finally:
        os.close(fd)


def shred_file(path: Path):
    """Best-effort overwrite + unlink. Never follows symlinks.
    NOT reliable on SSDs / journaling / copy-on-write filesystems: use full-disk
    encryption for real protection of data at rest."""
    try:
        st = os.lstat(path)
    except OSError:
        return
    if stat.S_ISREG(st.st_mode):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                remaining = st.st_size
                while remaining > 0:
                    n = min(remaining, 1 << 20)
                    _write_all(fd, os.urandom(n))
                    remaining -= n
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(path)
    except OSError:
        pass


def shred_tree(root: Path):
    if not os.path.lexists(root):
        return
    if os.path.islink(root):
        os.unlink(root)
        return
    for dirpath, dirnames, filenames in os.walk(root, topdown=False, followlinks=False):
        for f in filenames:
            shred_file(Path(dirpath) / f)
        for d in dirnames:
            p = Path(dirpath) / d
            try:
                if p.is_symlink():
                    p.unlink()
                else:
                    p.rmdir()
            except OSError:
                pass
    try:
        root.rmdir()
    except OSError:
        pass

# ── crypto primitives ────────────────────────────────────────────────────────


def wipe(buf: Optional[bytearray]):
    if isinstance(buf, bytearray) and buf:
        ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


def aead_seal(key, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(bytes(key)).encrypt(nonce, plaintext, aad)


def aead_open(key, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < 28:
        raise InvalidTag()
    return ChaCha20Poly1305(bytes(key)).decrypt(blob[:12], blob[12:], aad)


def hkdf(ikm, info: bytes, length: int = KEY_LEN) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(bytes(ikm))


def check_kdf_params(p: Any) -> Dict[str, int]:
    if not isinstance(p, dict) or set(p) != set(ARGON2_RECOMMENDED):
        raise VaultError("KDF_PARAMS", f"unexpected kdf parameter set: {sorted(p) if isinstance(p, dict) else type(p).__name__}")
    for k in ARGON2_RECOMMENDED:
        v = p[k]
        if type(v) is not int or not (ARGON2_MIN[k] <= v <= ARGON2_MAX[k]):
            raise VaultError("KDF_PARAMS", f"{k}={v!r} outside [{ARGON2_MIN[k]}, {ARGON2_MAX[k]}]")
    if p["memory_cost"] < 8 * p["parallelism"]:
        raise VaultError("KDF_PARAMS", "memory_cost < 8 * parallelism")
    return p


def kdf_weaker(p: Dict[str, int], ref: Dict[str, int] = ARGON2_RECOMMENDED) -> bool:
    return p["memory_cost"] < ref["memory_cost"] or p["time_cost"] < ref["time_cost"]


def derive_kek(password: str, salt: bytes, params: Dict[str, int]) -> bytearray:
    check_kdf_params(params)
    pw = unicodedata.normalize("NFC", password).encode("utf-8")
    try:
        out = Argon2id(salt=salt, length=KEY_LEN, iterations=params["time_cost"],
                       lanes=params["parallelism"], memory_cost=params["memory_cost"]).derive(pw)
    except MemoryError:
        raise VaultError("KDF_PARAMS", "not enough memory for the configured Argon2id parameters")
    return bytearray(out)


class DataKeys:
    """Subkeys of one data-encryption key (DEK)."""

    def __init__(self, dek: bytes):
        self.dek = bytearray(dek)
        self.payload = bytearray(hkdf(dek, b"vaultterm/v4/payload"))
        self.blob = bytearray(hkdf(dek, b"vaultterm/v4/blob"))

    def wipe(self):
        for b in (self.dek, self.payload, self.blob):
            wipe(b)


def aad_wrap(kind: str, core: Dict) -> bytes:
    return b"vaultterm|v4|wrap|" + kind.encode() + b"|" + canon(core)


def aad_payload(header_bytes: bytes) -> bytes:
    return MAGIC + b"|payload|" + header_bytes


def aad_blob(bid: str) -> bytes:
    return b"vaultterm|v4|blob|" + bid.encode("ascii")


def aad_deadman(salt: bytes) -> bytes:
    return b"vaultterm|v4|deadman|" + salt


def pad_bucket(pt: bytes, bucket: int) -> bytes:
    body = struct.pack(">Q", len(pt)) + pt
    total = -(-len(body) // bucket) * bucket
    return body + bytes(total - len(body))


def blob_pad(pt: bytes) -> bytes:
    """Power-of-two buckets up to 1 MiB, then whole MiB: hides exact file sizes."""
    body = struct.pack(">Q", len(pt)) + pt
    n = len(body)
    if n <= 1 << 20:
        size = max(4096, 1 << (n - 1).bit_length())
    else:
        size = -(-n // (1 << 20)) * (1 << 20)
    return body + bytes(size - n)


def unpad(buf: bytes) -> bytes:
    if len(buf) < 8:
        raise ValueError("padded block too short")
    n = struct.unpack(">Q", buf[:8])[0]
    if n > len(buf) - 8 or any(buf[8 + n:]):
        raise ValueError("bad padding")
    return buf[8:8 + n]

# ── deadman ──────────────────────────────────────────────────────────────────


def make_deadman(password: str, params: Dict[str, int]) -> Dict:
    salt = os.urandom(SALT_LEN)
    k = derive_kek(password, salt, params)
    try:
        verify = aead_seal(k, DEADMAN_SENTINEL, aad_deadman(salt))
    finally:
        wipe(k)
    return {"kdf": dict(params), "salt": b64e(salt), "verify": b64e(verify)}


def deadman_matches(password: str, dm: Dict) -> bool:
    salt = b64d(dm["salt"])
    k = derive_kek(password, salt, dm["kdf"])
    try:
        return hmac.compare_digest(aead_open(k, b64d(dm["verify"]), aad_deadman(salt)), DEADMAN_SENTINEL)
    except InvalidTag:
        return False
    finally:
        wipe(k)

# ── vault file format ────────────────────────────────────────────────────────


def validate_header(h: Any):
    def need(cond: bool, msg: str):
        if not cond:
            raise VaultError("VAULT_FORMAT", f"header: {msg}")

    try:
        need(isinstance(h, dict) and set(h) == {"core", "wraps"}, "top-level keys")
        core, wraps = h["core"], h["wraps"]
        need(isinstance(core, dict) and set(core) == {"format", "kdf", "salt", "deadman", "event_pubkey", "recovery_kit"}, "core keys")
        need(core["format"] == FORMAT_VERSION, f"format {core['format']!r}")
        need(len(b64d(core["salt"])) == SALT_LEN, "salt length")
        dm = core["deadman"]
        need(isinstance(dm, dict) and set(dm) == {"kdf", "salt", "verify"}, "deadman keys")
        need(len(b64d(dm["salt"])) == SALT_LEN, "deadman salt length")
        need(len(b64d(dm["verify"])) == 12 + len(DEADMAN_SENTINEL) + 16, "deadman token length")
        need(len(b64d(core["event_pubkey"])) == 32, "event key length")
        rk = core["recovery_kit"]
        need(rk is None or (isinstance(rk, str) and re.fullmatch(r"[0-9a-f]{8}", rk) is not None), "recovery kit id")
        need(isinstance(wraps, dict) and set(wraps) == {"master", "recovery"}, "wrap keys")
        need(len(b64d(wraps["master"])) == WRAP_LEN, "master wrap length")
        if rk is None:
            need(wraps["recovery"] is None, "dangling recovery wrap")
        else:
            need(isinstance(wraps["recovery"], str) and len(b64d(wraps["recovery"])) == WRAP_LEN, "recovery wrap length")
    except VaultError:
        raise
    except (ValueError, TypeError, KeyError) as e:
        raise VaultError("VAULT_FORMAT", f"header: {type(e).__name__}: {e}")
    check_kdf_params(core["kdf"])
    check_kdf_params(dm["kdf"])


def split_vault(raw: bytes) -> Tuple[Dict, bytes, bytes]:
    if len(raw) < 12 or raw[:8] != MAGIC:
        raise VaultError("VAULT_FORMAT", "bad magic (not a VaultTerm v4 vault)")
    hl = struct.unpack(">I", raw[8:12])[0]
    if hl == 0 or hl > MAX_HEADER or 12 + hl + 28 > len(raw):
        raise VaultError("VAULT_FORMAT", f"bad header length {hl}")
    hb = raw[12:12 + hl]
    try:
        hdr = json.loads(hb.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise VaultError("VAULT_FORMAT", f"header JSON: {e}")
    validate_header(hdr)
    if canon(hdr) != hb:
        raise VaultError("VAULT_FORMAT", "header is not canonical")
    return hdr, hb, raw[12 + hl:]


def pack_vault(hdr: Dict, keys: DataKeys, data: Dict) -> bytes:
    hb = canon(hdr)
    ct = aead_seal(keys.payload, pad_bucket(canon(data), PAYLOAD_BUCKET), aad_payload(hb))
    return MAGIC + struct.pack(">I", len(hb)) + hb + ct


def validate_payload(d: Any):
    def need(cond: bool, msg: str):
        if not cond:
            raise VaultError("VAULT_INTEGRITY", f"payload: {msg}")

    try:
        need(isinstance(d, dict) and d.get("format") == FORMAT_VERSION, "format")
        for k in ("generation", "next_id"):
            need(type(d[k]) is int and d[k] >= 0, k)
        need(isinstance(d["settings"], dict), "settings")
        for k, v in DEFAULT_SETTINGS.items():
            d["settings"].setdefault(k, v)
            need(type(d["settings"][k]) is type(v), f"setting {k}")
        need(isinstance(d["entries"], list), "entries")
        ids = set()
        for e in d["entries"]:
            need(isinstance(e, dict), "entry type")
            need(type(e["id"]) is int and e["id"] not in ids, "entry id")
            ids.add(e["id"])
            need(e["kind"] in KINDS, "entry kind")
            for k in ("uuid", "name", "url", "login", "password", "notes", "totp", "created_at", "rotated_at", "modified_at"):
                need(isinstance(e[k], str), f"entry field {k}")
            need(isinstance(e["history"], list), "history")
            att = e["attachment"]
            need(att is None or (isinstance(att, dict) and att.get("blob") in d["blobs"]), "attachment reference")
        need(isinstance(d["blobs"], dict), "blobs")
        for bid, meta in d["blobs"].items():
            need(re.fullmatch(r"[0-9a-f]{32}", bid) is not None, "blob id")
            need(isinstance(meta, dict) and isinstance(meta.get("sha256"), str), "blob meta")
        lg = d["log"]
        need(isinstance(lg, dict) and isinstance(lg["items"], list) and type(lg["next_seq"]) is int, "log")
        need(len(b64d(d["keys"]["history"])) == KEY_LEN and len(b64d(d["keys"]["log"])) == KEY_LEN, "inner keys")
        need(len(b64d(d["event_privkey"])) == 32, "event key")
        rec = d["recovery"]
        need(rec is None or (isinstance(rec, dict) and len(b64d(rec["rk"])) == KEY_LEN), "recovery")
    except VaultError:
        raise
    except (ValueError, TypeError, KeyError) as e:
        raise VaultError("VAULT_INTEGRITY", f"payload: {type(e).__name__}: {e}")


def open_payload(hdr: Dict, hb: bytes, ct: bytes, dek: bytes) -> Tuple[DataKeys, Dict]:
    keys = DataKeys(dek)
    try:
        data = json.loads(unpad(aead_open(keys.payload, ct, aad_payload(hb))))
    except (InvalidTag, ValueError, struct.error) as e:
        keys.wipe()
        raise VaultError("VAULT_INTEGRITY", f"payload authentication failed ({type(e).__name__})")
    try:
        validate_payload(data)
    except VaultError:
        keys.wipe()
        raise
    return keys, data


def build_header(core: Dict, kek, dek, data: Dict) -> Dict:
    wraps = {"master": b64e(aead_seal(kek, bytes(dek), aad_wrap("master", core))), "recovery": None}
    if core["recovery_kit"]:
        rk = b64d(data["recovery"]["rk"])
        wraps["recovery"] = b64e(aead_seal(hkdf(rk, RECOVERY_INFO), bytes(dek), aad_wrap("recovery", core)))
    return {"core": core, "wraps": wraps}


def read_vault_file(path: Optional[Path] = None) -> bytes:
    path = path or P.vault
    if not os.path.lexists(path):
        raise VaultError("VAULT_MISSING", f"{path} does not exist")
    try:
        return read_file_nofollow(path, MAX_VAULT_FILE)
    except VaultError as e:
        raise VaultError("VAULT_FORMAT", e.detail)


def peek_event_pubkey() -> Optional[str]:
    try:
        hdr, _, _ = split_vault(read_vault_file())
        return hdr["core"]["event_pubkey"]
    except Exception:
        return None

# ── sealed pre-unlock events (readable only after unlock) ────────────────────


def seal_event(pub_b64: Optional[str], event: Dict):
    if not pub_b64:
        return
    try:
        if os.path.lexists(P.events) and os.lstat(P.events).st_size > EVENTS_MAX_BYTES:
            return
        pub = b64d(pub_b64)
        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes_raw()
        key = hkdf(eph.exchange(X25519PublicKey.from_public_bytes(pub)) + eph_pub + pub, EVENT_INFO)
        line = (b64e(eph_pub + aead_seal(key, canon(event), b"vaultterm|v4|event")) + "\n").encode("ascii")
        ensure_dir(P.base)
        fd = os.open(P.events, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            _write_all(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        pass


def unseal_events(priv_b64: str) -> Tuple[List[Dict], int]:
    if not os.path.lexists(P.events):
        return [], 0
    try:
        raw = read_file_nofollow(P.events, EVENTS_MAX_BYTES * 2)
    except VaultError:
        return [], 1
    priv = X25519PrivateKey.from_private_bytes(b64d(priv_b64))
    pub = priv.public_key().public_bytes_raw()
    events, bad = [], 0
    for line in raw.splitlines():
        try:
            blob = b64d(line.decode("ascii").strip())
            eph_pub = blob[:32]
            key = hkdf(priv.exchange(X25519PublicKey.from_public_bytes(eph_pub)) + eph_pub + pub, EVENT_INFO)
            ev = json.loads(aead_open(key, blob[32:], b"vaultterm|v4|event"))
            if isinstance(ev, dict):
                events.append(ev)
            else:
                bad += 1
        except Exception:
            bad += 1
    return events, bad

# ── attachments ("secret key" files) ─────────────────────────────────────────


def blob_file(bid: str) -> Path:
    return P.blobs / f"{bid}.blob"


def write_blob(keys: DataKeys, plain: bytes) -> Tuple[str, Dict]:
    ensure_dir(P.blobs)
    bid = secrets.token_hex(16)
    ct = aead_seal(keys.blob, blob_pad(plain), aad_blob(bid))
    atomic_write(blob_file(bid), ct)
    return bid, {"sha256": hashlib.sha256(ct).hexdigest(), "size": len(plain)}


def read_blob(keys: DataKeys, bid: str, meta: Dict, raw: Optional[bytes] = None) -> bytes:
    if raw is None:
        try:
            raw = read_file_nofollow(blob_file(bid), MAX_ATTACHMENT * 2 + (1 << 20))
        except VaultError as e:
            raise VaultError("BLOB_INTEGRITY", f"blob {bid}: {e.detail}")
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), meta["sha256"]):
        raise VaultError("BLOB_INTEGRITY", f"blob {bid}: SHA-256 mismatch")
    try:
        return unpad(aead_open(keys.blob, raw, aad_blob(bid)))
    except (InvalidTag, ValueError, struct.error):
        raise VaultError("BLOB_INTEGRITY", f"blob {bid}: authentication failed")

# ── the vault ────────────────────────────────────────────────────────────────


class Vault:
    def __init__(self, hdr: Dict, keys: DataKeys, kek: Optional[bytearray], data: Dict):
        self.header = hdr
        self.keys = keys
        self.kek = kek          # None when opened through the paper recovery kit
        self.data = data

    # ---- lifecycle -----------------------------------------------------------

    @classmethod
    def create(cls, master: str, deadman: str, params: Optional[Dict] = None) -> "Vault":
        params = dict(params or ARGON2_RECOMMENDED)
        salt = os.urandom(SALT_LEN)
        kek = derive_kek(master, salt, params)
        keys = DataKeys(os.urandom(KEY_LEN))
        evk = X25519PrivateKey.generate()
        core = {
            "format": FORMAT_VERSION, "kdf": params, "salt": b64e(salt),
            "deadman": make_deadman(deadman, params),
            "event_pubkey": b64e(evk.public_key().public_bytes_raw()),
            "recovery_kit": None,
        }
        now = utc_now()
        data = {
            "format": FORMAT_VERSION, "generation": 0, "created_at": now, "saved_at": now,
            "settings": dict(DEFAULT_SETTINGS), "next_id": 1, "entries": [], "blobs": {},
            "log": {"anchor": "0" * 64, "next_seq": 1, "items": []},
            "keys": {"history": b64e(os.urandom(KEY_LEN)), "log": b64e(os.urandom(KEY_LEN))},
            "event_privkey": b64e(evk.private_bytes_raw()),
            "recovery": None,
        }
        v = cls(build_header(core, kek, keys.dek, data), keys, kek, data)
        ensure_dir(P.base)
        with v.transaction():
            v.log("INIT", detail=f"argon2id t={params['time_cost']} m={params['memory_cost']}KiB p={params['parallelism']}")
        return v

    @classmethod
    def unlock(cls, password: str) -> "Vault":
        hdr, hb, ct = split_vault(read_vault_file())
        core = hdr["core"]
        kek = derive_kek(password, b64d(core["salt"]), core["kdf"])
        try:
            dek = aead_open(kek, b64d(hdr["wraps"]["master"]), aad_wrap("master", core))
        except InvalidTag:
            wipe(kek)
            if deadman_matches(password, core["deadman"]):
                raise DeadmanTriggered()
            raise VaultError("AUTH_FAILED", "master key unwrap failed (wrong password or modified header)")
        try:
            keys, data = open_payload(hdr, hb, ct, dek)
        except VaultError:
            wipe(kek)
            raise
        return cls(hdr, keys, kek, data)

    @classmethod
    def unlock_with_recovery(cls, rk: bytes) -> "Vault":
        hdr, hb, ct = split_vault(read_vault_file())
        if not hdr["core"]["recovery_kit"]:
            raise VaultError("RECOVERY_INVALID", "this vault has no active recovery kit")
        try:
            dek = aead_open(hkdf(rk, RECOVERY_INFO), b64d(hdr["wraps"]["recovery"]), aad_wrap("recovery", hdr["core"]))
        except InvalidTag:
            raise VaultError("RECOVERY_INVALID", "the combined shares do not unwrap the data key")
        keys, data = open_payload(hdr, hb, ct, dek)
        return cls(hdr, keys, None, data)

    def close(self):
        if self.keys:
            self.keys.wipe()
        wipe(self.kek)
        self.kek = None
        self.data = {}

    def verify_master(self, password: str) -> bool:
        core = self.header["core"]
        k = derive_kek(password, b64d(core["salt"]), core["kdf"])
        try:
            dek = aead_open(k, b64d(self.header["wraps"]["master"]), aad_wrap("master", core))
            return hmac.compare_digest(dek, bytes(self.keys.dek))
        except InvalidTag:
            return False
        finally:
            wipe(k)

    # ---- persistence -----------------------------------------------------------

    def _commit(self):
        """Encrypt and atomically replace the vault file. Caller blocks signals."""
        data = dict(self.data)
        data["generation"] = self.data["generation"] + 1
        data["saved_at"] = utc_now()
        atomic_write(P.vault, pack_vault(self.header, self.keys, data))
        self.data["generation"] = data["generation"]
        self.data["saved_at"] = data["saved_at"]

    @contextmanager
    def transaction(self):
        """Mutate self.data inside the block; it is saved atomically on exit or
        rolled back in memory if anything (including Ctrl+C) interrupts it."""
        snap = canon(self.data)
        try:
            yield
        except BaseException:
            self.data = json.loads(snap)
            raise
        with signals_blocked():
            try:
                self._commit()
            except BaseException:
                self.data = json.loads(snap)
                raise

    # ---- tamper-evident audit log ---------------------------------------------

    def log(self, action: str, entry_id: Optional[int] = None, detail: str = "",
            ref: Optional[str] = None, ts: Optional[str] = None):
        """Append to the hash-chained log. Call inside a transaction()."""
        lg = self.data["log"]
        items = lg["items"]
        item = {
            "seq": lg["next_seq"], "ts": ts or utc_now(), "action": action, "entry_id": entry_id,
            "detail": str(detail)[:2000], "ref": ref,
            "prev": items[-1]["mac"] if items else lg["anchor"],
        }
        item["mac"] = hmac.new(b64d(self.data["keys"]["log"]), canon(item), hashlib.sha256).hexdigest()
        items.append(item)
        lg["next_seq"] += 1
        if len(items) > LOG_MAX_ITEMS:
            drop = len(items) - LOG_MAX_ITEMS
            lg["anchor"] = items[drop]["prev"]
            del items[:drop]

    def log_and_save(self, action: str, entry_id: Optional[int] = None, detail: str = "", ref: Optional[str] = None):
        with self.transaction():
            self.log(action, entry_id, detail, ref)

    def verify_log(self) -> Tuple[bool, int, Optional[int]]:
        lg = self.data["log"]
        key = b64d(self.data["keys"]["log"])
        prev = lg["anchor"]
        items = lg["items"]
        for i, it in enumerate(items):
            body = {k: v for k, v in it.items() if k != "mac"}
            good = (
                it.get("prev") == prev
                and isinstance(it.get("mac"), str)
                and hmac.compare_digest(hmac.new(key, canon(body), hashlib.sha256).hexdigest(), it["mac"])
                and (i == 0 or it["seq"] == items[i - 1]["seq"] + 1)
            )
            if not good:
                return False, len(items), it.get("seq")
            prev = it["mac"]
        if items and lg["next_seq"] != items[-1]["seq"] + 1:
            return False, len(items), lg["next_seq"]
        return True, len(items), None

    # ---- settings / entries ------------------------------------------------------

    @property
    def settings(self) -> Dict:
        return self.data["settings"]

    def entries(self) -> List[Dict]:
        return sorted(self.data["entries"], key=lambda e: (e["name"].lower(), e["id"]))

    def get(self, eid: int) -> Optional[Dict]:
        return next((e for e in self.data["entries"] if e["id"] == eid), None)

    def is_expired(self, e: Dict) -> bool:
        return age_days(e["rotated_at"]) >= self.settings["expiry_days"]

    def fingerprint(self, entry_uuid: str, password: str) -> str:
        """Per-entry keyed hash of a retired password (history only)."""
        msg = entry_uuid.encode() + b"\x00" + unicodedata.normalize("NFC", password).encode("utf-8")
        return hmac.new(b64d(self.data["keys"]["history"]), msg, hashlib.sha256).hexdigest()

    def used_before(self, e: Dict, password: str) -> bool:
        if e["password"] and hmac.compare_digest(e["password"].encode(), password.encode()):
            return True
        fp = self.fingerprint(e["uuid"], password)
        return any(hmac.compare_digest(fp, h) for h in e["history"])

    def sharing_password(self, password: str, exclude: Optional[int] = None) -> List[Dict]:
        return [e for e in self.data["entries"]
                if e["id"] != exclude and e["password"] and hmac.compare_digest(e["password"].encode(), password.encode())]

    def search(self, q: str) -> List[Dict]:
        q = q.lower().strip()
        if not q:
            return []
        out = []
        for e in self.entries():
            hay = [e["name"], e["url"], e["login"], e["notes"]]
            if e["attachment"]:
                hay.append(e["attachment"]["filename"])
            if any(q in h.lower() for h in hay):
                out.append(e)
        return out

    def duplicate_hits(self, name: str, url: str, login: str) -> List[Dict]:
        hits = []
        for e in self.entries():
            same_name = e["name"].lower() == name.lower() and e["login"].lower() == login.lower()
            same_url = bool(url) and e["url"].lower() == url.lower() and e["login"].lower() == login.lower()
            if same_name or same_url:
                hits.append(e)
        return hits

    def add_entry(self, kind: str, name: str, url: str, login: str, password: str, notes: str,
                  totp: str, file: Optional[Tuple[str, bytes]] = None) -> int:
        bid = None
        if file:
            bid, bmeta = write_blob(self.keys, file[1])
        try:
            with self.transaction():
                eid = self.data["next_id"]
                self.data["next_id"] += 1
                now = utc_now()
                att = None
                if bid:
                    self.data["blobs"][bid] = bmeta
                    att = {"blob": bid, "filename": file[0], "size": len(file[1]),
                           "sha256": hashlib.sha256(file[1]).hexdigest()}
                self.data["entries"].append({
                    "id": eid, "uuid": str(uuid.uuid4()), "kind": kind, "name": name, "url": url,
                    "login": login, "password": password, "notes": notes, "totp": totp, "history": [],
                    "created_at": now, "rotated_at": now, "modified_at": now, "attachment": att,
                })
                self.log("ADD", eid, KIND_LABEL[kind])
        except BaseException:
            if bid and bid not in self.data["blobs"]:
                shred_file(blob_file(bid))
            raise
        return eid

    def update_entry(self, eid: int, changes: Dict[str, str], file: Optional[Tuple[str, bytes]] = None) -> bool:
        e = self.get(eid)
        if not e:
            raise VaultError("INPUT", f"entry {eid} does not exist")
        fields = [k for k in ("name", "url", "login", "notes", "totp", "password") if k in changes and changes[k] != e[k]]
        if not fields and not file:
            return False
        bid = old_bid = None
        if file:
            bid, bmeta = write_blob(self.keys, file[1])
        try:
            with self.transaction():
                e = self.get(eid)
                now = utc_now()
                if "password" in fields:
                    if e["password"]:
                        e["history"].insert(0, self.fingerprint(e["uuid"], e["password"]))
                        del e["history"][HISTORY_MAX:]
                    e["rotated_at"] = now
                for k in fields:
                    e[k] = changes[k]
                if bid:
                    if e["attachment"]:
                        old_bid = e["attachment"]["blob"]
                        self.data["blobs"].pop(old_bid, None)
                    self.data["blobs"][bid] = bmeta
                    e["attachment"] = {"blob": bid, "filename": file[0], "size": len(file[1]),
                                       "sha256": hashlib.sha256(file[1]).hexdigest()}
                    e["rotated_at"] = now
                    fields.append("file")
                e["modified_at"] = now
                self.log("EDIT", eid, ",".join(fields))
        except BaseException:
            if bid and bid not in self.data["blobs"]:
                shred_file(blob_file(bid))
            raise
        if old_bid and old_bid not in self.data["blobs"]:
            shred_file(blob_file(old_bid))
        return True

    def delete_entry(self, eid: int):
        old_bid = None
        with self.transaction():
            e = self.get(eid)
            if not e:
                raise VaultError("INPUT", f"entry {eid} does not exist")
            self.data["entries"].remove(e)
            if e["attachment"]:
                old_bid = e["attachment"]["blob"]
                self.data["blobs"].pop(old_bid, None)
            self.log("PURGE", eid, KIND_LABEL[e["kind"]])
        if old_bid:
            shred_file(blob_file(old_bid))

    def attachment_bytes(self, e: Dict) -> bytes:
        att = e["attachment"]
        plain = read_blob(self.keys, att["blob"], self.data["blobs"][att["blob"]])
        if not hmac.compare_digest(hashlib.sha256(plain).hexdigest(), att["sha256"]):
            raise VaultError("BLOB_INTEGRITY", f"entry {e['id']}: plaintext hash mismatch")
        return plain

    # ---- key management ------------------------------------------------------------

    def rekey(self, new_password: str, params: Optional[Dict] = None) -> DataKeys:
        """Rotate the data key AND the master password/KDF parameters.

        Every attachment is re-encrypted to a new blob file first; the single
        atomic rename of the vault file is the commit point. Interrupting at
        any moment leaves either the old vault (plus orphan blobs that are
        cleaned at the next unlock) or the new one. Returns the OLD data keys
        so the caller can re-encrypt backups, then must wipe them.
        """
        params = check_kdf_params(dict(params or ARGON2_RECOMMENDED))
        new_keys = DataKeys(os.urandom(KEY_LEN))
        created: List[str] = []
        new_kek: Optional[bytearray] = None
        try:
            mapping: Dict[str, Tuple[str, Dict]] = {}
            for bid, meta in list(self.data["blobs"].items()):
                plain = read_blob(self.keys, bid, meta)
                nbid, nmeta = write_blob(new_keys, plain)
                created.append(nbid)
                mapping[bid] = (nbid, nmeta)
            data = json.loads(canon(self.data))
            data["blobs"] = {nb: nm for nb, nm in mapping.values()}
            for e in data["entries"]:
                if e["attachment"]:
                    e["attachment"]["blob"] = mapping[e["attachment"]["blob"]][0]
            new_salt = os.urandom(SALT_LEN)
            new_kek = derive_kek(new_password, new_salt, params)
            core = dict(self.header["core"], kdf=params, salt=b64e(new_salt))
            nv = Vault(build_header(core, new_kek, new_keys.dek, data), new_keys, new_kek, data)
            nv.log("REKEY", detail=f"data key rotated; argon2id t={params['time_cost']} "
                                   f"m={params['memory_cost']}KiB p={params['parallelism']}; "
                                   f"{len(mapping)} attachment(s) re-encrypted")
            old_keys, old_kek, old_blobs = self.keys, self.kek, list(self.data["blobs"])
            with signals_blocked():
                nv._commit()
                self.header, self.keys, self.kek, self.data = nv.header, nv.keys, nv.kek, nv.data
        except BaseException:
            if self.keys is not new_keys:
                for nb in created:
                    shred_file(blob_file(nb))
                new_keys.wipe()
                wipe(new_kek)
            raise
        wipe(old_kek)
        for b in old_blobs:
            shred_file(blob_file(b))
        return old_keys

    def change_deadman(self, new_deadman: str):
        if self.kek is None:
            raise VaultError("INPUT", "set a new master password first")
        core = dict(self.header["core"], deadman=make_deadman(new_deadman, ARGON2_RECOMMENDED))
        old = self.header
        self.header = build_header(core, self.kek, self.keys.dek, self.data)
        try:
            with self.transaction():
                self.log("DEADMAN_CHANGED")
        except BaseException:
            self.header = old
            raise

    def create_recovery(self, threshold: int, shares: int) -> Tuple[str, List[Tuple[int, bytes]]]:
        if self.kek is None:
            raise VaultError("INPUT", "set a new master password first")
        rk = os.urandom(KEY_LEN)
        kit_id = secrets.token_hex(4)
        old = self.header
        try:
            with self.transaction():
                self.data["recovery"] = {"kit_id": kit_id, "rk": b64e(rk), "threshold": threshold,
                                         "shares": shares, "created_at": utc_now()}
                core = dict(self.header["core"], recovery_kit=kit_id)
                self.header = build_header(core, self.kek, self.keys.dek, self.data)
                self.log("RECOVERY_KIT", detail=f"new kit {kit_id}: any {threshold} of {shares} shares")
        except BaseException:
            self.header = old
            raise
        return kit_id, shamir_split(rk, threshold, shares)

    def revoke_recovery(self):
        if self.kek is None:
            raise VaultError("INPUT", "set a new master password first")
        old = self.header
        try:
            with self.transaction():
                kit = (self.data["recovery"] or {}).get("kit_id")
                self.data["recovery"] = None
                core = dict(self.header["core"], recovery_kit=None)
                self.header = build_header(core, self.kek, self.keys.dek, self.data)
                self.log("RECOVERY_REVOKED", detail=f"kit {kit}")
        except BaseException:
            self.header = old
            raise

# ── backups ──────────────────────────────────────────────────────────────────

BACKUP_SUFFIX = ".vtbak"
_BLOB_MEMBER = re.compile(r"^blobs/([0-9a-f]{32})\.blob$")


class BackupInfo:
    def __init__(self, path, raw, blobs, hdr, keys, data, kek):
        self.path, self.raw, self.blobs, self.header, self.keys, self.data, self.kek = path, raw, blobs, hdr, keys, data, kek

    def wipe(self):
        self.keys.wipe()
        wipe(self.kek)


def list_backups() -> List[Path]:
    if not P.backups.is_dir():
        return []
    out = [p for p in P.backups.iterdir() if p.name.endswith(BACKUP_SUFFIX) and p.is_file() and not p.is_symlink()]
    return sorted(out, key=lambda p: p.stat().st_mtime, reverse=True)


def _tar_add_bytes(tar: tarfile.TarFile, name: str, data: bytes):
    ti = tarfile.TarInfo(name)
    ti.size, ti.mode, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = len(data), 0o600, 0, 0, 0, "", ""
    tar.addfile(ti, io.BytesIO(data))


def _write_backup_file(final: Path, vault_raw: bytes, blob_ids: List[str], blob_source: Dict[str, bytes]):
    """Write tar to <final>.partial, fsync, rename. blob_source overrides disk."""
    ensure_dir(P.backups)
    tmp = final.with_name(final.name + ".partial")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            with tarfile.open(fileobj=fh, mode="w", format=tarfile.PAX_FORMAT) as tar:
                _tar_add_bytes(tar, "vault.vt", vault_raw)
                for bid in blob_ids:
                    data = blob_source.get(bid)
                    if data is None:
                        data = read_file_nofollow(blob_file(bid))
                    _tar_add_bytes(tar, f"blobs/{bid}.blob", data)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        shred_file(tmp)
        raise
    return tmp


def read_backup(path: Path) -> Tuple[bytes, Dict[str, bytes]]:
    """Strict reader: only regular members named vault.vt / blobs/<hex>.blob.
    Nothing is ever extracted to disk by name."""
    try:
        st = os.lstat(path)
    except OSError as e:
        raise VaultError("BACKUP_INVALID", f"{path}: {e.strerror}")
    if not stat.S_ISREG(st.st_mode):
        raise VaultError("BACKUP_INVALID", f"{path}: not a regular file")
    vault_raw, blobs = None, {}
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as fh, tarfile.open(fileobj=fh, mode="r:") as tar:
            for m in tar:
                if not m.isreg():
                    raise VaultError("BACKUP_INVALID", f"member {m.name!r} is not a regular file")
                if m.name == "vault.vt":
                    if vault_raw is not None or m.size > MAX_VAULT_FILE:
                        raise VaultError("BACKUP_INVALID", "duplicate or oversized vault.vt")
                    vault_raw = tar.extractfile(m).read()
                    continue
                mm = _BLOB_MEMBER.match(m.name)
                if not mm or mm.group(1) in blobs or m.size > MAX_ATTACHMENT * 2 + (1 << 20):
                    raise VaultError("BACKUP_INVALID", f"unexpected member {m.name!r}")
                blobs[mm.group(1)] = tar.extractfile(m).read()
    except VaultError:
        raise
    except (OSError, tarfile.TarError) as e:
        raise VaultError("BACKUP_INVALID", f"{path.name}: {type(e).__name__}: {e}")
    if vault_raw is None:
        raise VaultError("BACKUP_INVALID", "archive has no vault.vt")
    return vault_raw, blobs


def verify_backup(path: Path, dek=None, kek=None, password: Optional[str] = None) -> BackupInfo:
    """Fully verify: header, master-key unwrap, payload authentication, and
    every referenced attachment (hash + decryption)."""
    raw, blobs = read_backup(path)
    try:
        hdr, hb, ct = split_vault(raw)
    except VaultError as e:
        raise VaultError("BACKUP_INVALID", f"{path.name}: {e.detail}")
    core = hdr["core"]
    use_kek = None
    if password is not None:
        use_kek = derive_kek(password, b64d(core["salt"]), core["kdf"])
    elif kek is not None:
        use_kek = bytearray(kek)
    unwrapped = None
    if use_kek is not None:
        try:
            unwrapped = aead_open(use_kek, b64d(hdr["wraps"]["master"]), aad_wrap("master", core))
        except InvalidTag:
            if password is not None:
                wipe(use_kek)
                raise VaultError("AUTH_FAILED", f"{path.name}: wrong password for this backup")
            wipe(use_kek)
            use_kek = None
    candidate = unwrapped if unwrapped is not None else (bytes(dek) if dek is not None else None)
    if candidate is None:
        raise VaultError("BACKUP_INVALID", f"{path.name}: no key available (older password?)")
    try:
        keys, data = open_payload(hdr, hb, ct, candidate)
    except VaultError as e:
        wipe(use_kek)
        raise VaultError("BACKUP_INVALID", f"{path.name}: {e.detail}")
    try:
        for bid, meta in data["blobs"].items():
            if bid not in blobs:
                raise VaultError("BACKUP_INVALID", f"{path.name}: attachment {bid} missing")
            read_blob(keys, bid, meta, raw=blobs[bid])
    except VaultError as e:
        keys.wipe()
        wipe(use_kek)
        raise VaultError("BACKUP_INVALID", f"{path.name}: {e.detail}")
    return BackupInfo(path, raw, blobs, hdr, keys, data, use_kek)


def backup_uses_current_password(path: Path, vault: Vault) -> Optional[bool]:
    try:
        with open(path, "rb") as fh, tarfile.open(fileobj=fh, mode="r:") as tar:
            m = tar.getmember("vault.vt")
            head = tar.extractfile(m).read(12 + MAX_HEADER)
        hl = struct.unpack(">I", head[8:12])[0]
        hdr = json.loads(head[12:12 + hl].decode("ascii"))
        core = vault.header["core"]
        return hdr["core"]["salt"] == core["salt"] and hdr["core"]["kdf"] == core["kdf"]
    except Exception:
        return None


def create_backup(vault: Vault, label: str = "manual") -> Tuple[Path, BackupInfo]:
    ensure_dir(P.backups)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    final = P.backups / f"vaultterm_{ts}_{label}{BACKUP_SUFFIX}"
    while os.path.lexists(final):
        final = P.backups / f"vaultterm_{ts}_{label}_{secrets.token_hex(2)}{BACKUP_SUFFIX}"
    raw = read_vault_file()
    tmp = _write_backup_file(final, raw, list(vault.data["blobs"]), {})
    with signals_blocked():
        os.replace(tmp, final)
    fsync_dir(P.backups)
    try:
        info = verify_backup(final, dek=vault.keys.dek, kek=vault.kek)
    except VaultError as e:
        shred_file(final)
        raise VaultError("BACKUP_INVALID", f"fresh backup failed verification: {e.detail}")
    return final, info


def preserve_unverified_state(label: str) -> Optional[Path]:
    """Archive whatever vault files exist (when they cannot be unlocked)."""
    if not os.path.lexists(P.vault):
        return None
    raw = read_file_nofollow(P.vault, MAX_VAULT_FILE)
    ids = []
    if P.blobs.is_dir():
        ids = [m.group(1) for m in (_BLOB_MEMBER.match("blobs/" + p.name) for p in P.blobs.iterdir()) if m]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    final = P.backups / f"vaultterm_{ts}_{label}{BACKUP_SUFFIX}"
    tmp = _write_backup_file(final, raw, ids, {})
    os.replace(tmp, final)
    fsync_dir(P.backups)
    return final


def convert_backups(old_keys: DataKeys, vault: Vault) -> Tuple[List[Path], List[Path]]:
    """After a rekey: re-wrap every backup that was made under the previous
    data key so it opens with the NEW master password. Returns (converted, stale)."""
    converted, stale = [], []
    for path in list_backups():
        try:
            raw, blobs = read_backup(path)
            hdr, hb, ct = split_vault(raw)
            keys, data = open_payload(hdr, hb, ct, old_keys.dek)
        except VaultError:
            stale.append(path)
            continue
        try:
            core = dict(hdr["core"], kdf=vault.header["core"]["kdf"], salt=vault.header["core"]["salt"])
            if core["recovery_kit"] and not data.get("recovery"):
                core["recovery_kit"] = None
            new_hdr = build_header(core, vault.kek, keys.dek, data)
            new_raw = pack_vault(new_hdr, keys, data)
            tmp = _write_backup_file(path.with_name(path.name + ".converting-dst"), new_raw, list(blobs), blobs)
            conv = path.with_name(path.name + ".converting")
            os.replace(tmp, conv)
            with signals_blocked():
                shred_file(path)          # best-effort overwrite of the old-password copy
                os.replace(conv, path)
            fsync_dir(P.backups)
            converted.append(path)
        except VaultError:
            stale.append(path)
        finally:
            keys.wipe()
    return converted, stale


def install_backup(info: BackupInfo) -> Vault:
    """Write a verified backup's blobs and vault file into place."""
    ensure_dir(P.blobs)
    for bid, meta in info.data["blobs"].items():
        target = blob_file(bid)
        if os.path.lexists(target):
            try:
                same = hashlib.sha256(read_file_nofollow(target)).hexdigest() == meta["sha256"]
            except VaultError:
                same = False
            if same:
                continue
            shred_file(target)
        atomic_write(target, info.blobs[bid])
    with signals_blocked():
        atomic_write(P.vault, info.raw)
    kek = info.kek
    info.kek = None
    v = Vault(info.header, info.keys, kek, info.data)
    with v.transaction():
        v.log("RESTORED", detail=f"from {info.path.name}")
    return v

# ── housekeeping ─────────────────────────────────────────────────────────────


def housekeeping(vault: Vault) -> List[Tuple[str, str]]:
    """Remove leftovers of interrupted operations; returns log lines."""
    notes: List[Tuple[str, str]] = []
    referenced = set(vault.data["blobs"])
    for d in (P.base, P.blobs, P.backups):
        if d.is_dir() and not d.is_symlink():
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass
    if P.blobs.is_dir():
        for f in P.blobs.iterdir():
            m = re.fullmatch(r"([0-9a-f]{32})\.blob", f.name)
            if f.is_symlink():
                f.unlink()
                notes.append(("CLEANUP", f"removed symlink blobs/{f.name}"))
            elif m and m.group(1) in referenced:
                os.chmod(f, 0o600)
            else:
                shred_file(f)
                notes.append(("CLEANUP", f"shredded orphan blobs/{f.name}"))
    for f in P.base.glob(".vault.vt.*.tmp"):
        shred_file(f)
        notes.append(("CLEANUP", f"shredded interrupted write {f.name}"))
    if P.backups.is_dir():
        for f in P.backups.iterdir():
            if f.name.endswith(".partial") or f.name.endswith(".converting-dst") or f.name.endswith(".tmp"):
                shred_file(f)
                notes.append(("CLEANUP", f"shredded incomplete backup {f.name}"))
            elif f.name.endswith(".converting"):
                final = f.with_name(f.name[: -len(".converting")])
                if os.path.lexists(final):
                    shred_file(f)
                else:
                    os.replace(f, final)
                notes.append(("CLEANUP", f"finished interrupted backup conversion {final.name}"))
            elif f.is_file() and not f.is_symlink():
                os.chmod(f, 0o600)
    if P.vault.exists():
        os.chmod(P.vault, 0o600)
    for bid in referenced:
        if not blob_file(bid).exists():
            notes.append(("ERROR", f"BLOB_INTEGRITY: attachment blob {bid} is missing"))
    return notes

# ── Shamir secret sharing over GF(256) + share encoding ──────────────────────

_GF_EXP = [0] * 512
_GF_LOG = [0] * 256


def _gf_init():
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        # multiply by generator 3 in GF(2^8) with the AES polynomial 0x11b
        y = x << 1
        if y & 0x100:
            y ^= 0x11B
        x = y ^ x
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


_gf_init()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError
    if a == 0:
        return 0
    return _GF_EXP[(_GF_LOG[a] - _GF_LOG[b]) % 255]


def shamir_split(secret: bytes, k: int, n: int) -> List[Tuple[int, bytes]]:
    if not (1 <= k <= n <= 16):
        raise VaultError("INPUT", "need 1 <= threshold <= shares <= 16")
    out = {x: bytearray() for x in range(1, n + 1)}
    for byte in secret:
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(k - 1)]
        for x in out:
            y = 0
            for c in reversed(coeffs):
                y = _gf_mul(y, x) ^ c
            out[x].append(y)
    return [(x, bytes(v)) for x, v in out.items()]


def shamir_combine(shares: Dict[int, bytes]) -> bytes:
    xs = list(shares)
    length = len(next(iter(shares.values())))
    res = bytearray(length)
    for i in range(length):
        acc = 0
        for xj in xs:
            num = den = 1
            for xm in xs:
                if xm != xj:
                    num = _gf_mul(num, xm)
                    den = _gf_mul(den, xj ^ xm)
            acc ^= _gf_mul(shares[xj][i], _gf_div(num, den))
        res[i] = acc
    return bytes(res)


def encode_share(kit_id: str, k: int, x: int, y: bytes) -> str:
    body = bytes.fromhex(kit_id) + bytes([k, x]) + y
    chk = hashlib.sha256(b"vaultterm-share-v4" + body).digest()[:4]
    s = base64.b32encode(body + chk).decode("ascii").rstrip("=")
    return "VT4-" + "-".join(s[i:i + 4] for i in range(0, len(s), 4))


def decode_share(text: str) -> Tuple[str, int, int, bytes]:
    s = re.sub(r"[\s\-]", "", text.upper())
    if s.startswith("VT4"):
        s = s[3:]
    try:
        raw = base64.b32decode(s + "=" * (-len(s) % 8))
    except Exception:
        raise VaultError("RECOVERY_INVALID", "share is not valid base32 (letters A-Z and digits 2-7 only)")
    if len(raw) != 4 + 2 + KEY_LEN + 4:
        raise VaultError("RECOVERY_INVALID", f"share has wrong length ({len(raw)} bytes)")
    body, chk = raw[:-4], raw[-4:]
    if not hmac.compare_digest(hashlib.sha256(b"vaultterm-share-v4" + body).digest()[:4], chk):
        raise VaultError("RECOVERY_INVALID", "share checksum mismatch (typo?)")
    k, x = body[4], body[5]
    if not (1 <= k <= 16 and 1 <= x <= 16):
        raise VaultError("RECOVERY_INVALID", "share parameters out of range")
    return body[:4].hex(), k, x, body[6:]

# ── recovery kit PDF (no external PDF library) ───────────────────────────────


def _pdf_str(s: str) -> str:
    s = s.encode("ascii", "replace").decode("ascii")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _qr_matrix(text: str) -> Optional[List[List[bool]]]:
    if qrcode is None:
        return None
    try:
        q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=4)
        q.add_data(text)
        q.make(fit=True)
        return q.get_matrix()
    except Exception:
        return None


def build_recovery_pdf(kit_id: str, k: int, n: int, shares: List[Tuple[int, str]], created: str) -> bytes:
    pages = []
    for x, text in shares:
        ops: List[str] = []

        def t(xp: float, yp: float, size: int, s: str, font: str = "F1"):
            ops.append(f"BT /{font} {size} Tf {xp:.1f} {yp:.1f} Td ({_pdf_str(s)}) Tj ET")

        t(50, 790, 18, "VAULTTERM PAPER RECOVERY KIT", "F2")
        t(50, 766, 12, f"Share {x} of {n}   --   any {k} share(s) open the vault", "F2")
        t(50, 748, 10, f"Kit ID: {kit_id}      Created: {created}")
        ops.append("0.6 w 50 735 m 545 735 l S")
        groups = text.split("-")
        lines = ["-".join(groups[i:i + 4]) for i in range(0, len(groups), 4)]
        y = 700
        for ln in lines:
            t(50, y, 14, ln, "F3")
            y -= 24
        matrix = _qr_matrix(text)
        if matrix:
            mod = min(4.6, 190 / len(matrix))
            size = mod * len(matrix)
            x0, y0 = 545 - size, 715 - size
            rects = []
            for r, row in enumerate(matrix):
                for c, dark in enumerate(row):
                    if dark:
                        rects.append(f"{x0 + c * mod:.2f} {y0 + (len(matrix) - 1 - r) * mod:.2f} {mod:.2f} {mod:.2f} re")
            ops.append("0 g " + " ".join(rects) + " f")
        info = [
            "HOW TO USE",
            f"Run   vaultterm --recover   (or ./start.sh --recover) and type at least {k} different",
            "shares from this kit. Dashes and spaces are optional; letters are A-Z and digits 2-7.",
            "You will then be asked to set a new master password.",
            "",
            "KEEP SAFE",
            f"Fewer than {k} share(s) reveal nothing. {k} share(s) open the whole vault WITHOUT the",
            "master password - store each sheet in a different secure place.",
            "Never photograph them or type them anywhere except VaultTerm. The QR code holds the",
            "same text, for a keyboard-style barcode scanner during --recover.",
            "",
            "VALIDITY",
            "Shares stay valid when you change the master password. Generating a new kit or",
            "revoking it in the RECOVERY menu invalidates every sheet of this kit.",
            "The kit cannot bring back a vault destroyed by the deadman password.",
        ]
        y = 470
        for ln in info:
            t(50, y, 11 if ln.isupper() and ln else 10, ln, "F2" if ln.isupper() and ln else "F1")
            y -= 16
        t(50, 60, 8, f"VaultTerm {VERSION} - kit {kit_id} - share {x}/{n}")
        pages.append("\n".join(ops).encode("ascii"))

    objs: Dict[int, bytes] = {
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold >>",
    }
    kids, num = [], 6
    for stream in pages:
        objs[num] = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
        objs[num + 1] = (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                         b"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R >>" % num)
        kids.append(num + 1)
        num += 2
    objs[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objs[2] = b"<< /Type /Pages /Kids [" + b" ".join(b"%d 0 R" % k_ for k_ in kids) + b"] /Count %d >>" % len(kids)
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for i in range(1, num):
        offsets[i] = len(out)
        out += b"%d 0 obj\n" % i + objs[i] + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % num
    out += b"".join(b"%010d 00000 n \n" % offsets[i] for i in range(1, num))
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (num, xref)
    return bytes(out)

# ── password generation and strength estimation ─────────────────────────────

SYMBOLS = "!@#$%^&*-_=+[]{}|;:,.<>?"
SAFE_SYMBOLS = "!@#$%*-_=+?"
GEN_PROFILES = {
    "high": (string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS),
    "compat": (string.ascii_lowercase, string.ascii_uppercase, string.digits, SAFE_SYMBOLS),
    "no_symbols": (string.ascii_lowercase, string.ascii_uppercase, string.digits),
}
PW_LEN = (16, 128)
PIN_LEN = (4, 12)
PHRASE_WORDS = (5, 12)


def gen_password(length: int, profile: str = "high") -> Tuple[str, float]:
    length = max(PW_LEN[0], min(PW_LEN[1], length))
    classes = GEN_PROFILES[profile]
    pool = "".join(classes)
    while True:  # rejection sampling keeps the output uniform over valid passwords
        pw = "".join(secrets.choice(pool) for _ in range(length))
        if all(any(c in cls for c in pw) for cls in classes):
            return pw, length * math.log2(len(pool)) - 0.1


def gen_pin(length: int) -> Tuple[str, float]:
    length = max(PIN_LEN[0], min(PIN_LEN[1], length))
    return "".join(secrets.choice(string.digits) for _ in range(length)), length * math.log2(10)


def gen_passphrase(words: int, sep: str = "-") -> Tuple[str, float]:
    words = max(PHRASE_WORDS[0], min(PHRASE_WORDS[1], words))
    return sep.join(secrets.choice(EFF_WORDS) for _ in range(words)), words * math.log2(len(EFF_WORDS))


_EFF_SET = frozenset(EFF_WORDS)
_COMMON = frozenset("""
password passw0rd pass admin administrator root user login welcome letmein qwerty qwertz azerty iloveyou
monkey dragon football baseball soccer master shadow sunshine princess trustno1 summer winter spring autumn
hello secret love god jesus ninja superman batman michael jordan charlie freedom whatever starwars pokemon
computer internet samsung google facebook apple microsoft linux ubuntu changeme default guest test temp
abc123 111111 123123 666666 696969 654321 7777777 football1 hunter killer mustang access flower lovely
cookie chocolate banana orange purple yellow silver golden diamond tigger matrix hockey ranger buster
thomas robert daniel andrew joshua jessica ashley amanda maria brasil brazil senha amor
""".split())
_ROWS = ("qwertyuiop", "asdfghjklç", "zxcvbnm", "1234567890", "qwertzuiop", "azertyuiop", "!@#$%^&*()")
_LEET = str.maketrans({"4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "|": "i", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t"})


def _is_sequence(s: str) -> bool:
    if len(s) < 3:
        return False
    d = [ord(b) - ord(a) for a, b in zip(s, s[1:])]
    return all(x == d[0] for x in d) and d[0] in (-1, 1)


def estimate_bits(pw: str) -> float:
    """Conservative entropy estimate: cheapest decomposition of the password
    into guessable pieces (dictionary words, common passwords, years,
    sequences, keyboard runs, repeats, digit runs, random characters)."""
    n = len(pw)
    if n == 0:
        return 0.0
    pool = 0
    if any(c.islower() for c in pw):
        pool += 26
    if any(c.isupper() for c in pw):
        pool += 26
    if any(c.isdigit() for c in pw):
        pool += 10
    if any((not c.isalnum()) and c.isascii() for c in pw):
        pool += 33
    if any(not c.isascii() for c in pw):
        pool += 100
    char_bits = math.log2(max(pool, 2))
    norm = pw.lower().translate(_LEET)
    low = pw.lower()
    best = [0.0] + [math.inf] * n
    for i in range(1, n + 1):
        best[i] = best[i - 1] + char_bits
        j = i - 1
        while j >= 0 and pw[j].isdigit():
            best[i] = min(best[i], best[j] + (i - j) * math.log2(10))
            j -= 1
        for j in range(max(0, i - 24), i - 2):
            raw, sub, L = pw[j:i], norm[j:i], i - j
            cost = None
            if sub in _COMMON or low[j:i] in _COMMON:
                cost = 6.0
            elif sub in _EFF_SET or low[j:i] in _EFF_SET:
                cost = math.log2(len(_EFF_SET))
            elif L == 4 and raw.isdigit() and 1900 <= int(raw) <= 2099:
                cost = 7.0
            elif _is_sequence(low[j:i]):
                cost = 5 + math.log2(L)
            elif L >= 4 and any(low[j:i] in r or low[j:i] in r[::-1] for r in _ROWS):
                cost = 6 + math.log2(L)
            elif raw in pw[:j]:
                cost = 2 + math.log2(j + 1)
            elif len(set(raw)) == 1:
                cost = char_bits + math.log2(L)
            if cost is not None:
                ups = sum(c.isupper() for c in raw)
                cost += 1.0 if (ups and ups == 1 and raw[0].isupper()) else min(ups, L)
                if sub != low[j:i]:
                    cost += 1.0
                best[i] = min(best[i], best[j] + cost)
    return best[n]


def strength_label(bits: float) -> Tuple[str, str]:
    if bits < 40:
        return "CRITICAL", C_ERR
    if bits < 60:
        return "WEAK", C_WARN
    if bits < 80:
        return "MODERATE", "yellow"
    if bits < 100:
        return "STRONG", C_OK
    return "MAXSEC", "bright_green"


def strength_line(bits: float) -> Text:
    label, color = strength_label(bits)
    width = 24
    filled = int(min(bits, 128) / 128 * width)
    t = Text("  strength   ", style=C_DIM)
    t.append("[" + "#" * filled + "." * (width - filled) + "]", style=color)
    t.append(f"  {label}  ~{bits:.0f} bits", style=color)
    return t

# ── TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ───────────────────────────────────


def totp_key(secret: str) -> bytes:
    s = re.sub(r"[\s\-]", "", secret.upper())
    try:
        key = base64.b32decode(s + "=" * (-len(s) % 8))
    except Exception:
        raise VaultError("INPUT", "TOTP secret is not valid base32")
    if len(key) < 10:
        raise VaultError("INPUT", "TOTP secret is too short (< 80 bits)")
    return key


def totp_code(secret: str, at: Optional[float] = None, step: int = 30, digits: int = 6) -> str:
    key = totp_key(secret)
    counter = int((time.time() if at is None else at) // step)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)

# ── terminal input with auto-lock deadline ───────────────────────────────────


class Term:
    def __init__(self):
        self.fd = sys.stdin.fileno()
        self.tty = os.isatty(self.fd)
        self._buf = b""

    def readline(self, prompt_cb, deadline: Optional[float] = None, secret: bool = False) -> str:
        old = None
        if secret and self.tty:
            old = termios.tcgetattr(self.fd)
            new = termios.tcgetattr(self.fd)
            new[3] &= ~termios.ECHO
            termios.tcsetattr(self.fd, termios.TCSADRAIN, new)
        try:
            prompt_cb()
            sys.stdout.flush()
            while b"\n" not in self._buf:
                timeout = None
                if deadline is not None:
                    timeout = deadline - time.monotonic()
                    if timeout <= 0:
                        raise LockTimeout()
                r, _, _ = select.select([self.fd], [], [], timeout)
                if not r:
                    continue
                chunk = os.read(self.fd, 4096)
                if not chunk:
                    if self._buf:
                        self._buf += b"\n"
                        break
                    raise EOFError
                self._buf += chunk
            line, _, self._buf = self._buf.partition(b"\n")
            return line.decode("utf-8", "replace").rstrip("\r")
        finally:
            if old is not None:
                termios.tcsetattr(self.fd, termios.TCSADRAIN, old)
                sys.stdout.write("\n")
                sys.stdout.flush()

    def poll_enter(self) -> bool:
        try:
            r, _, _ = select.select([self.fd], [], [], 0)
        except (OSError, ValueError):
            return False
        if r:
            chunk = os.read(self.fd, 4096)
            if not chunk:
                return True
            self._buf += chunk
        if b"\n" in self._buf:
            _, _, self._buf = self._buf.partition(b"\n")
            return True
        return False

    def discard_input(self):
        self._buf = b""
        if self.tty:
            try:
                termios.tcflush(self.fd, termios.TCIFLUSH)
            except termios.error:
                pass

# ── clipboard (Wayland: wl-clipboard, X11: xclip or xsel) ────────────────────


class Clipboard:
    def __init__(self):
        self.used = False

    @staticmethod
    def backend() -> Optional[Tuple[str, str]]:
        if os.environ.get("WAYLAND_DISPLAY"):
            c, p = shutil.which("wl-copy"), shutil.which("wl-paste")
            if c and p:
                return "wayland", c
        if os.environ.get("DISPLAY"):
            for tool in ("xclip", "xsel"):
                path = shutil.which(tool)
                if path:
                    return tool, path
        return None

    @staticmethod
    def _run(args: List[str], data: Optional[bytes] = None, capture: bool = False):
        return subprocess.run(args, input=data, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=5, check=False)

    def copy(self, text: str, clear_after: int):
        b = self.backend()
        if not b:
            raise VaultError("CLIPBOARD", "no clipboard tool found (install wl-clipboard, xclip or xsel)")
        kind, exe = b
        data = text.encode("utf-8")
        try:
            if kind == "wayland":
                self._run([exe, "--type", "text/plain;charset=utf-8"], data)
            elif kind == "xclip":
                self._run([exe, "-selection", "clipboard", "-in"], data)
            else:
                self._run([exe, "--clipboard", "--input"], data)
        except (OSError, subprocess.SubprocessError) as e:
            raise VaultError("CLIPBOARD", f"{kind}: {e}")
        self.used = True
        digest = hashlib.sha256(data).digest()
        t = threading.Timer(clear_after, self._clear_if_ours, args=(digest,))
        t.daemon = True  # the exit paths clear the clipboard unconditionally
        t.start()

    def _paste(self) -> Optional[bytes]:
        b = self.backend()
        if not b:
            return None
        kind, exe = b
        try:
            if kind == "wayland":
                r = self._run([shutil.which("wl-paste") or "wl-paste", "--no-newline"], capture=True)
            elif kind == "xclip":
                r = self._run([exe, "-selection", "clipboard", "-out"], capture=True)
            else:
                r = self._run([exe, "--clipboard", "--output"], capture=True)
            return r.stdout
        except (OSError, subprocess.SubprocessError):
            return None

    def _clear_if_ours(self, digest: bytes):
        cur = self._paste()
        if cur is not None and hmac.compare_digest(hashlib.sha256(cur).digest(), digest):
            self.clear_all()

    def clear_all(self):
        """Empty both CLIPBOARD and PRIMARY selections."""
        b = self.backend()
        if not b:
            return
        kind, exe = b
        try:
            if kind == "wayland":
                self._run([exe, "--clear"])
                self._run([exe, "--primary", "--clear"])
            elif kind == "xclip":
                self._run([exe, "-selection", "clipboard", "-in"], b"")
                self._run([exe, "-selection", "primary", "-in"], b"")
            else:
                self._run([exe, "--clipboard", "--clear"])
                self._run([exe, "--primary", "--clear"])
        except (OSError, subprocess.SubprocessError):
            pass

# ── application ──────────────────────────────────────────────────────────────


class App:
    def __init__(self):
        self.term = Term()
        self.clip = Clipboard()
        self.vault: Optional[Vault] = None
        self.last_input = time.monotonic()

    # ---- input helpers --------------------------------------------------------

    def deadline(self) -> Optional[float]:
        if not self.vault:
            return None
        minutes = self.vault.settings.get("auto_lock_minutes", 10)
        return None if minutes <= 0 else self.last_input + minutes * 60

    def touch(self):
        self.last_input = time.monotonic()

    def check_lock(self):
        d = self.deadline()
        if d is not None and time.monotonic() >= d:
            raise LockTimeout()

    def ask(self, prompt: str, default: Optional[str] = None, choices: Optional[List[str]] = None,
            secret: bool = False, timed: bool = True, show_default: bool = True) -> str:
        while True:
            label = f"  [{C_HEAD}]{prompt}[/{C_HEAD}]"
            if default not in (None, "") and show_default and not secret:
                label += f" [{C_DIM}]({escape(default)})[/{C_DIM}]"
            if choices and len(choices) <= 8:
                label += f" [{C_DIM}]{escape('[' + '/'.join(choices) + ']')}[/{C_DIM}]"
            line = self.term.readline(lambda: console.print(label + " >> ", end=""),
                                      deadline=self.deadline() if timed else None, secret=secret)
            self.touch()
            if not secret:
                line = line.strip()
            if line == "" and default is not None:
                line = default
            if choices:
                if line.lower() in choices:
                    return line.lower()
                err(f"choose one of: {escape(', '.join(choices))}")
                continue
            return line

    def confirm(self, prompt: str, default: bool = False) -> bool:
        a = self.ask(prompt, default="y" if default else "n", choices=["y", "n"], show_default=False)
        return a == "y"

    def ask_int(self, prompt: str, default: int, lo: int, hi: int) -> int:
        while True:
            raw = self.ask(f"{prompt} ({lo}-{hi})", default=str(default))
            try:
                v = int(raw)
            except ValueError:
                err("expected a whole number.")
                continue
            if lo <= v <= hi:
                return v
            err(f"must be between {lo} and {hi}.")

    def pause(self):
        self.ask(f"[{C_DIM}]press ENTER to continue[/{C_DIM}]", default="", show_default=False)

    def report(self, e: VaultError, persist: bool = True):
        hint = "  [dim]-- details in LOG [7][/dim]" if (self.vault and persist) else ""
        err(f"{e.kind}  {escape(ERROR_TEXT.get(e.kind, 'error'))}  [dim](ref {e.ref})[/dim]{hint}")
        if not persist:
            return
        if self.vault:
            try:
                self.vault.log_and_save("ERROR", detail=f"{e.kind}: {e.detail}", ref=e.ref)
            except Exception:
                pass
        else:
            seal_event(peek_event_pubkey(), {"type": "ERROR", "ts": utc_now(), "kind": e.kind, "detail": e.detail, "ref": e.ref})

    # ---- entry point ------------------------------------------------------------

    def run(self, args):
        if args.restore:
            self.cli_restore(Path(args.restore).expanduser())
        elif args.recover:
            self.cli_recover()
        else:
            self.start()
        self.main_loop()

    def start(self):
        clr()
        banner()
        ensure_dir(P.base)
        if not os.path.lexists(P.vault):
            leftovers = [p for p in (P.blobs, P.backups, P.events) if os.path.lexists(p) and (not p.is_dir() or any(p.iterdir()))]
            if leftovers:
                self.report(VaultError("VAULT_MISSING", f"found {', '.join(p.name for p in leftovers)} without vault.vt"), persist=False)
                console.print(f"  [{C_DIM}]restore a backup with:  ./start.sh --restore <file.vtbak>\n"
                              f"  or move {escape(str(P.base))} away to start a brand-new vault.[/{C_DIM}]\n")
                sys.exit(4)
            self.init_vault()
        else:
            self.unlock_interactive()

    def main_loop(self):
        while True:
            try:
                self.menu()
            except LockTimeout:
                self.lock()
                banner()
                warn("session locked due to inactivity.")
                self.unlock_interactive()

    # ---- unlock / lock / init ----------------------------------------------------

    def _ask_new_password(self, what: str, min_len: int, check_other) -> str:
        while True:
            pw = self.ask(f"new {what}", secret=True)
            if len(pw) < min_len:
                err(f"too short. minimum {min_len} characters.")
                continue
            if self.ask(f"confirm {what}", secret=True) != pw:
                err("mismatch. try again.")
                continue
            if check_other and check_other(pw):
                err("master and deadman passwords must be different.")
                continue
            bits = estimate_bits(pw)
            console.print(strength_line(bits))
            if bits < MASTER_TARGET_BITS:
                warn(f"estimated strength is below {MASTER_TARGET_BITS} bits. a 6-word passphrase from GENERATE [6] is a good choice.")
                if not self.confirm("use it anyway?", default=False):
                    continue
            return pw

    def init_vault(self):
        console.print(f"  [{C_WARN}]NO VAULT DETECTED.[/{C_WARN}]")
        console.print(f"  [{C_DIM}]initialising a new encrypted vault at {escape(str(P.base))}[/{C_DIM}]\n")
        master = self._ask_new_password("master password", MASTER_MIN_LEN, None)
        console.print(f"\n  [{C_DIM}]the DEADMAN password, typed at the unlock prompt, silently destroys the vault.[/{C_DIM}]")
        deadman = self._ask_new_password("deadman password", MASTER_MIN_LEN, lambda p: p == master)
        console.print(f"\n  [{C_DIM}]deriving keys (Argon2id, 256 MiB)...[/{C_DIM}]")
        self.vault = Vault.create(master, deadman)
        self.touch()
        ok("vault initialised.")
        if self.confirm("create a printable paper recovery kit now? (also available later in RECOVERY [13])", default=False):
            self._generate_kit()

    def unlock_interactive(self):
        pub = peek_event_pubkey()
        console.print(f"  [{C_DIM}]vault: {escape(str(P.vault))}[/{C_DIM}]\n")
        while True:
            pw = self.ask("master password", secret=True, timed=False)
            if not pw:
                continue
            try:
                vault = Vault.unlock(pw)
            except DeadmanTriggered:
                self.deadman()
            except VaultError as e:
                if e.kind == "AUTH_FAILED":
                    err("AUTH_FAILED  authentication failed.")
                    seal_event(pub, {"type": "UNLOCK_FAIL", "ts": utc_now()})
                    continue
                self.report(e, persist=True)
                if e.kind == "VAULT_INTEGRITY":
                    console.print(f"  [{C_DIM}]if you have a backup:  ./start.sh --restore <file.vtbak>[/{C_DIM}]\n")
                sys.exit(3)
            self.vault = vault
            self.touch()
            self.after_unlock(pw)
            return

    def after_unlock(self, password: Optional[str]):
        v = self.vault
        events, bad = unseal_events(v.data["event_privkey"])
        notes = housekeeping(v)
        fails = sum(1 for ev in events if ev.get("type") == "UNLOCK_FAIL")
        with v.transaction():
            for ev in events:
                if ev.get("type") == "UNLOCK_FAIL":
                    v.log("UNLOCK_FAIL", ts=str(ev.get("ts", "")))
                else:
                    v.log("ERROR", detail=f"(before unlock) {ev.get('kind')}: {ev.get('detail')}",
                          ref=ev.get("ref"), ts=str(ev.get("ts", "")))
            if bad:
                v.log("ERROR", detail=f"{bad} sealed pre-unlock event(s) could not be decrypted")
            for action, detail in notes:
                v.log(action, detail=detail)
            v.log("UNLOCK")
        shred_file(P.events)
        ok("access granted.")
        console.print(f"  [{C_DIM}]last saved {local_date(v.data['saved_at'])}  ·  generation {v.data['generation']}"
                      f"  (a lower generation than you remember means an older copy was restored)[/{C_DIM}]")
        if fails:
            warn(f"{fails} failed unlock attempt(s) since your last session -- see LOG [7].")
        if any(a == "ERROR" for a, _ in notes):
            warn("some attachments are missing -- run HEALTH [11].")
        if password and kdf_weaker(v.header["core"]["kdf"]):
            warn("this vault uses weaker key-derivation parameters than recommended.")
            if self.confirm("upgrade now? (an automatic verified backup is made first)", default=True):
                self.do_rekey(password)
        expired = [e for e in v.entries() if v.is_expired(e)]
        if expired:
            console.print(f"\n  [{C_WARN}]!! EXPIRY ALERT !! {len(expired)} secret(s) not rotated in {v.settings['expiry_days']}+ days.[/{C_WARN}]\n")
            console.print(self._entry_table(expired))
        self.pause()

    def lock(self):
        self.clip.clear_all()
        if self.vault:
            self.vault.close()
        self.vault = None
        gc.collect()
        self.term.discard_input()
        clr()

    def deadman(self):
        self.clip.clear_all()
        shred_tree(P.base)
        clr()
        ref = secrets.token_hex(3)
        err(f"VAULT_INTEGRITY  {escape(ERROR_TEXT['VAULT_INTEGRITY'])}  [dim](ref {ref})[/dim]")
        console.print(f"  [{C_DIM}]if you have a backup:  ./start.sh --restore <file.vtbak>[/{C_DIM}]\n")
        sys.exit(3)

    def shutdown(self):
        if self.clip.used:
            self.clip.clear_all()
        if self.vault:
            self.vault.close()
            self.vault = None

    # ---- menu ---------------------------------------------------------------------

    MENU = [
        ("1", "LIST", "display vault entries"),
        ("2", "SEARCH", "query by name/url/login/notes/file"),
        ("3", "INJECT", "add a password, PIN, passphrase or secret key"),
        ("4", "MODIFY", "edit an entry"),
        ("5", "PURGE", "delete an entry"),
        ("6", "GENERATE", "password / PIN / passphrase generator"),
        ("7", "LOG", "tamper-evident audit trail and error details"),
        ("8", "REKEY", "master/deadman password, KDF upgrade"),
        ("9", "CLONE", "backups: create, verify, restore"),
        ("10", "TOTP", "live TOTP code display"),
        ("11", "HEALTH", "vault health check"),
        ("12", "SETTINGS", "expiry, auto-lock, clipboard"),
        ("13", "RECOVERY", "printable paper recovery kit"),
        ("0", "EJECT", "clear clipboard, lock and exit"),
    ]

    def menu(self):
        clr()
        banner()
        v = self.vault
        expired = sum(1 for e in v.data["entries"] if v.is_expired(e))
        ec = C_ERR if expired else C_OK
        console.print(f"  [{C_DIM}]entries[/{C_DIM}] [{C_HEAD}]{len(v.data['entries']):<4}[/{C_HEAD}]  "
                      f"[{C_DIM}]expired[/{C_DIM}] [{ec}]{expired:<4}[/{ec}]  "
                      f"[{C_DIM}]vault[/{C_DIM}] [{C_OK}]UNLOCKED[/{C_OK}]  "
                      f"[{C_DIM}]auto-lock[/{C_DIM}] {v.settings['auto_lock_minutes'] or 'off'}{'m' if v.settings['auto_lock_minutes'] else ''}\n")
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column("K", width=4)
        t.add_column("CMD", width=10)
        t.add_column("DESC")
        for key, cmd, desc in self.MENU:
            t.add_row(f"[{C_KEY}][{key}][/{C_KEY}]", f"[{C_HEAD}]{cmd}[/{C_HEAD}]", f"[{C_DIM}]{desc}[/{C_DIM}]")
        console.print(t)
        choice = self.ask("cmd", choices=[k for k, _, _ in self.MENU])
        clr()
        fn = {
            "1": self.cmd_list, "2": self.cmd_search, "3": self.cmd_inject, "4": self.cmd_modify,
            "5": self.cmd_purge, "6": self.cmd_generate, "7": self.cmd_log, "8": self.cmd_rekey,
            "9": self.cmd_clone, "10": self.cmd_totp, "11": self.cmd_health, "12": self.cmd_settings,
            "13": self.cmd_recovery, "0": self.cmd_eject,
        }[choice]
        try:
            fn()
        except KeyboardInterrupt:
            console.print(f"\n  [{C_DIM}]cancelled.[/{C_DIM}]\n")
            time.sleep(0.4)
        except VaultError as e:
            self.report(e)
            self.pause()
        except Exception as e:  # never show a raw traceback; keep it in the encrypted LOG
            self.report(VaultError("INTERNAL", f"{type(e).__name__}: {e}\n{traceback.format_exc(limit=8)}"))
            self.pause()

    # ---- tables / picking -----------------------------------------------------------

    def _entry_table(self, entries: List[Dict]) -> Table:
        t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {C_HEAD}", border_style=C_DIM, padding=(0, 1))
        for col, kw in (("ID", {"justify": "right"}), ("TYPE", {}), ("NAME", {"min_width": 14}), ("URL", {"min_width": 14}),
                        ("LOGIN", {"min_width": 12}), ("AGE", {"justify": "right"}), ("2FA", {"justify": "center"}),
                        ("STATUS", {"justify": "center"})):
            t.add_column(col, **kw)
        for e in entries:
            exp = self.vault.is_expired(e)
            t.add_row(
                Text(str(e["id"]), style=C_DIM), Text(KIND_SHORT[e["kind"]], style=C_DIM),
                Text(printable(e["name"]), style=C_DATA), Text(printable(e["url"]) or "—", style=C_DIM),
                Text(printable(e["login"]) or "—", style=C_LABEL),
                Text(f"{age_days(e['rotated_at'])}d", style=C_ERR if exp else C_DIM),
                Text("yes" if e["totp"] else "no", style=C_OK if e["totp"] else C_DIM),
                Text("[EXPIRED]", style=f"bold {C_ERR}") if exp else Text("[ACTIVE]", style=C_OK),
            )
        return t

    def _pick(self, entries: List[Dict], prompt: str = "entry id") -> Optional[Dict]:
        raw = self.ask(prompt)
        try:
            eid = int(raw)
        except ValueError:
            err("expected a numeric id.")
            return None
        hit = next((e for e in entries if e["id"] == eid), None)
        if not hit:
            err(f"no entry with id {eid}.")
        return hit

    # ---- LIST / SEARCH / VIEW --------------------------------------------------------

    def cmd_list(self, entries: Optional[List[Dict]] = None, title: str = "VAULT LISTING"):
        entries = self.vault.entries() if entries is None else entries
        banner()
        header(title)
        if not entries:
            inf("vault is empty. use INJECT [3] to add entries.")
            self.pause()
            return
        console.print(self._entry_table(entries))
        console.print(f"  [{C_KEY}][C][/{C_KEY}] copy password   [{C_KEY}][V][/{C_KEY}] view   "
                      f"[{C_KEY}][U][/{C_KEY}] update password   [{C_KEY}][T][/{C_KEY}] TOTP   "
                      f"[{C_KEY}][X][/{C_KEY}] export key file   [{C_KEY}][B][/{C_KEY}] back\n")
        act = self.ask("action", default="b", choices=["c", "v", "u", "t", "x", "b"], show_default=False)
        if act == "c":
            self._copy(entries)
        elif act == "v":
            self._view(entries)
        elif act == "u":
            self._quick_update(entries)
        elif act == "t":
            self._totp_for(entries)
        elif act == "x":
            self._export_file(entries)

    def cmd_search(self):
        banner()
        header("SEARCH")
        q = clean(self.ask("query"))
        if not q:
            warn("empty query.")
            self.pause()
            return
        res = self.vault.search(q)
        if not res:
            warn(f"no results for: {escape(q)}")
            self.pause()
            return
        self.cmd_list(res, title=f"SEARCH >> {q} ({len(res)} match(es))")

    def _copy(self, entries: List[Dict]):
        s = self.vault.settings
        if not s["clipboard_enabled"]:
            err("clipboard use is disabled. enable it in SETTINGS [12] only if your threat model allows it.")
            self.pause()
            return
        e = self._pick(entries, "entry id to copy")
        if not e:
            self.pause()
            return
        if not e["password"]:
            err("this entry has no password.")
            self.pause()
            return
        self.clip.copy(e["password"], s["clipboard_clear_seconds"])
        ok(f"password for '{escape(printable(e['name']))}' copied. clipboard clears in {s['clipboard_clear_seconds']} s and on EJECT/lock.")
        self.pause()

    def _view(self, entries: List[Dict]):
        e = self._pick(entries, "entry id to view")
        if not e:
            self.pause()
            return
        sep = f"  [{C_DIM}]{'─' * 58}[/{C_DIM}]"

        def row(k: str, v: str, vc: str = C_DATA):
            t = Text(f"  {k:<11}", style=C_DIM)
            t.append(v, style=vc)
            console.print(t)

        console.print("\n" + sep)
        row("ID", str(e["id"]), C_DIM)
        row("TYPE", KIND_LABEL[e["kind"]], C_DIM)
        row("NAME", printable(e["name"]))
        row("URL", printable(e["url"]) or "—", C_DIM)
        row("LOGIN", printable(e["login"]) or "—", C_LABEL)
        if e["password"]:
            row("PASSWORD", f"[hidden, {len(e['password'])} chars]", C_DIM)
            if self.confirm("  reveal password once on screen?", default=False):
                row("PASSWORD", printable(e["password"]), C_PW)
        if e["notes"]:
            row("NOTES", f"[hidden, {len(e['notes'])} chars]", C_DIM)
            if self.confirm("  reveal notes?", default=False):
                row("NOTES", printable(e["notes"]), C_DIM)
        row("CREATED", local_date(e["created_at"]), C_DIM)
        row("ROTATED", local_date(e["rotated_at"]), C_DIM)
        row("AGE", f"{age_days(e['rotated_at'])} day(s)", C_ERR if self.vault.is_expired(e) else C_DIM)
        if e["totp"]:
            try:
                rem = 30 - int(time.time()) % 30
                row("TOTP", f"{totp_code(e['totp'])}  ({rem}s left -- use [10] for live display)", C_PW)
            except VaultError:
                row("TOTP", "[invalid secret]", C_ERR)
        att = e["attachment"]
        if att:
            row("FILE", f"{printable(att['filename'])}  ({human_size(att['size'])})", C_DATA)
            row("SHA-256", att["sha256"], C_DIM)
        if e["password"] and e["kind"] != "pin":
            console.print(strength_line(estimate_bits(e["password"])))
        console.print(sep + "\n")
        if att and att["size"] <= MAX_SHOW_TEXT and self.confirm("  show the key file content on screen?", default=False):
            data = self.vault.attachment_bytes(e)
            try:
                txt = data.decode("utf-8")
                console.print(Text(printable(txt, keep_newlines=True), style=C_PW))
            except UnicodeDecodeError:
                warn("binary file -- use [X] export instead.")
        self.pause()

    def _export_file(self, entries: List[Dict]):
        e = self._pick([x for x in entries if x["attachment"]], "secret key entry id to export")
        if not e:
            self.pause()
            return
        data = self.vault.attachment_bytes(e)
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", e["attachment"]["filename"]).lstrip(".") or "secret.key"
        target = Path(self.ask("export to path", default=str(Path.cwd() / safe_name))).expanduser()
        if os.path.lexists(target):
            if os.path.islink(target) or not target.is_file():
                err("target exists and is not a regular file.")
                self.pause()
                return
            if not self.confirm(f"  {escape(str(target))} exists. overwrite?", default=False):
                self.pause()
                return
        atomic_write(target.absolute(), data)
        self.vault.log_and_save("EXPORT", e["id"], "secret key file exported")
        ok(f"exported to {escape(str(target))} (mode 0600, sha-256 verified).")
        warn("this copy is NOT encrypted. shred it when you no longer need it.")
        self.pause()

    # ---- INJECT / MODIFY / PURGE ---------------------------------------------------

    def _ask_kind(self) -> str:
        console.print(f"  [{C_KEY}][1][/{C_KEY}] password   [{C_KEY}][2][/{C_KEY}] PIN   "
                      f"[{C_KEY}][3][/{C_KEY}] passphrase   [{C_KEY}][4][/{C_KEY}] secret key (encrypted file)\n")
        return {"1": "password", "2": "pin", "3": "passphrase", "4": "secret_key"}[
            self.ask("type", default="1", choices=["1", "2", "3", "4"], show_default=False)]

    def _ask_totp(self, prompt: str = "TOTP secret (hidden, base32, ENTER to skip)") -> Optional[str]:
        while True:
            raw = self.ask(prompt, secret=True)
            if not raw.strip():
                return None
            s = re.sub(r"[\s\-]", "", raw.upper())
            try:
                code = totp_code(s)
            except VaultError as e:
                err(escape(e.detail))
                if not self.confirm("try again?", default=True):
                    return None
                continue
            ok(f"TOTP validated. current code: [{C_PW}]{code}[/{C_PW}] -- compare with your authenticator.")
            return s

    def _ask_secret_file(self) -> Optional[Tuple[str, bytes, str]]:
        while True:
            raw = self.ask("path of the key file to encrypt (ENTER to cancel)")
            if not raw:
                return None
            path = os.path.realpath(os.path.expanduser(raw))
            try:
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            except OSError as e:
                err(f"cannot open file: {escape(e.strerror or str(e))}")
                continue
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    err("not a regular file.")
                    continue
                if st.st_size > MAX_ATTACHMENT:
                    err(f"file too large (max {human_size(MAX_ATTACHMENT)}).")
                    continue
                with os.fdopen(os.dup(fd), "rb") as fh:
                    data = fh.read(MAX_ATTACHMENT + 1)
            finally:
                os.close(fd)
            if len(data) > MAX_ATTACHMENT:
                err("file too large.")
                continue
            name = clean(os.path.basename(path))[:200] or "secret.key"
            ok(f"read {escape(name)} ({human_size(len(data))}, sha-256 {hashlib.sha256(data).hexdigest()[:16]}...)")
            return name, data, path

    def _manual_secret(self, kind: str) -> str:
        what = KIND_LABEL[kind] if kind != "secret_key" else "password"
        while True:
            p1 = self.ask(f"new {what}", secret=True)
            if not p1:
                err("empty value.")
                continue
            if self.ask(f"confirm {what}", secret=True) != p1:
                err("mismatch.")
                continue
            if kind == "pin":
                if not p1.isdigit():
                    warn("this PIN contains non-digit characters.")
            else:
                if len(p1) < ENTRY_WARN_LEN:
                    warn(f"shorter than {ENTRY_WARN_LEN} characters. keep it only if the site forces this length.")
                console.print(strength_line(estimate_bits(p1)))
            return p1

    def _generator(self, kind: str) -> Optional[str]:
        while True:
            if kind == "pin":
                pw, bits = gen_pin(self.ask_int("PIN length", 6, *PIN_LEN))
            elif kind == "passphrase":
                pw, bits = gen_passphrase(self.ask_int("words", 6, *PHRASE_WORDS))
            else:
                console.print(f"  [{C_KEY}][1][/{C_KEY}] high entropy   [{C_KEY}][2][/{C_KEY}] max compatibility (safe symbols)   "
                              f"[{C_KEY}][3][/{C_KEY}] no symbols\n")
                profile = {"1": "high", "2": "compat", "3": "no_symbols"}[
                    self.ask("profile", default="1", choices=["1", "2", "3"], show_default=False)]
                pw, bits = gen_password(self.ask_int("length", 24, *PW_LEN), profile)
            label, color = strength_label(bits)
            console.print(f"\n  [{C_DIM}]generated  {escape(f'[hidden: {len(pw)} chars]')}  exact entropy[/{C_DIM}] [{color}]{bits:.0f} bits ({label})[/{color}]")
            if self.confirm("  reveal generated value once?", default=False):
                console.print(Text(f"  value      {pw}", style=C_PW))
            if self.confirm("  use this value?", default=True):
                return pw
            if not self.confirm("  generate another?", default=True):
                return None

    def _password_flow(self, kind: str, entry: Optional[Dict] = None) -> Optional[str]:
        console.print(f"  [{C_KEY}][G][/{C_KEY}] generate   [{C_KEY}][M][/{C_KEY}] manual\n")
        mode = self.ask(f"{KIND_LABEL[kind]} mode", default="g", choices=["g", "m"], show_default=False)
        pw = self._generator(kind) if mode == "g" else self._manual_secret(kind)
        if pw is None:
            return None
        return pw if self._reuse_ok(pw, entry) else None

    def _reuse_ok(self, pw: str, entry: Optional[Dict]) -> bool:
        if entry is not None and self.vault.used_before(entry, pw):
            warn("this value appears in this entry's history.")
            if not self.confirm("use it anyway?", default=False):
                return False
        others = self.vault.sharing_password(pw, exclude=entry["id"] if entry else None)
        if others:
            names = ", ".join(f"#{o['id']} {printable(o['name'])}" for o in others[:5])
            warn(f"the same value is already used by: {escape(names)}")
            if not self.confirm("reuse it anyway?", default=False):
                return False
        return True

    def cmd_inject(self):
        banner()
        header("INJECT -- NEW ENTRY")
        kind = self._ask_kind()
        name = ""
        while not name:
            name = clean(self.ask("name"))
        url = clean(self.ask("url (optional)", default=""))
        login = clean(self.ask("login/email (optional)", default=""))
        notes = clean(self.ask("notes (optional)", default=""))
        totp = self._ask_totp() or ""
        dupes = self.vault.duplicate_hits(name, url, login)
        if dupes:
            warn("possible duplicate entry detected.")
            console.print(self._entry_table(dupes))
            if not self.confirm("continue anyway?", default=False):
                inf("aborted.")
                self.pause()
                return
        file = None
        password = ""
        if kind == "secret_key":
            file = self._ask_secret_file()
            if not file:
                inf("aborted.")
                self.pause()
                return
            if self.confirm("store a password/passphrase with this key (e.g. the key's own passphrase)?", default=False):
                password = self._manual_secret("secret_key")
                if not self._reuse_ok(password, None):
                    self.pause()
                    return
        else:
            password = self._password_flow(kind)
            if password is None:
                inf("aborted.")
                self.pause()
                return
        console.print()
        console.print(Text(f"  TYPE  {KIND_LABEL[kind]}", style=C_DIM))
        console.print(Text(f"  NAME  {printable(name)}", style=C_DATA))
        console.print(Text(f"  LOGIN {printable(login) or '—'}", style=C_DATA))
        if password:
            console.print(Text(f"  VALUE {'*' * min(len(password), 32)} ({len(password)} chars)", style=C_DIM))
        if file:
            console.print(Text(f"  FILE  {printable(file[0])} ({human_size(len(file[1]))})", style=C_DATA))
        if not self.confirm("commit to vault?", default=True):
            inf("aborted.")
            self.pause()
            return
        eid = self.vault.add_entry(kind, name, url, login, password, notes, totp, (file[0], file[1]) if file else None)
        ok(f"entry injected. id={eid}")
        if file:
            self._offer_delete_original(file[2])
        self.pause()

    def _offer_delete_original(self, path: str):
        warn("the original file is still on disk, unencrypted.")
        console.print(f"  [{C_DIM}]deletion overwrites then unlinks it. on SSDs, journaling or copy-on-write filesystems the\n"
                      f"  old blocks may survive -- full-disk encryption is the real protection.[/{C_DIM}]")
        if self.confirm(f"  delete the original {escape(path)}?", default=False):
            shred_file(Path(path))
            if os.path.lexists(path):
                err("could not delete the original file.")
            else:
                ok("original file overwritten and deleted.")

    def _keep_edit_clear(self, label: str, current: str, secret: bool) -> Optional[str]:
        """Returns None to keep, otherwise the new value ('' clears)."""
        if current:
            console.print(f"  [{C_DIM}]{label}: {escape(f'[hidden, {len(current)} chars]')}[/{C_DIM}]")
            a = self.ask(f"{label}: [K]eep / [E]dit / [C]lear", default="k", choices=["k", "e", "c"], show_default=False)
            if a == "k":
                return None
            if a == "c":
                return ""
        elif not self.confirm(f"add {label}?", default=False):
            return None
        if label == "TOTP secret":
            return self._ask_totp("new TOTP secret (hidden, base32)")
        val = self.ask(f"new {label}", secret=secret)
        return clean(val)

    def cmd_modify(self):
        banner()
        header("MODIFY -- EDIT ENTRY")
        entries = self.vault.entries()
        if not entries:
            inf("vault is empty.")
            self.pause()
            return
        console.print(self._entry_table(entries))
        e = self._pick(entries, "entry id to modify")
        if not e:
            self.pause()
            return
        console.print(f"\n  modifying [{C_HEAD}]{escape(printable(e['name']))}[/{C_HEAD}] ({KIND_LABEL[e['kind']]})")
        console.print(f"  [{C_DIM}]ENTER keeps the current value. type '-' to clear url or login.[/{C_DIM}]\n")
        ch: Dict[str, str] = {}
        name = clean(self.ask("name", default=e["name"]))
        if name:
            ch["name"] = name
        for fld in ("url", "login"):
            val = clean(self.ask(fld, default=e[fld]))
            ch[fld] = "" if val == "-" else val
        notes = self._keep_edit_clear("notes", e["notes"], secret=False)
        if notes is not None:
            ch["notes"] = notes
        totp = self._keep_edit_clear("TOTP secret", e["totp"], secret=True)
        if totp is not None:
            ch["totp"] = totp
        file = None
        if e["kind"] == "secret_key":
            if self.confirm("replace the stored key file?", default=False):
                file = self._ask_secret_file()
            if e["password"]:
                console.print(f"  [{C_DIM}]password: {escape('[hidden, %d chars]' % len(e['password']))}[/{C_DIM}]")
            a = self.ask("password: [K]eep / [S]et / [C]lear", default="k", choices=["k", "s", "c"], show_default=False)
            if a == "c":
                ch["password"] = ""
            elif a == "s":
                pw = self._manual_secret("secret_key")
                if self._reuse_ok(pw, e):
                    ch["password"] = pw
        else:
            console.print(f"\n  [{C_KEY}][K][/{C_KEY}] keep {KIND_LABEL[e['kind']]}   [{C_KEY}][G][/{C_KEY}] generate   [{C_KEY}][M][/{C_KEY}] manual\n")
            mode = self.ask(KIND_LABEL[e["kind"]], default="k", choices=["k", "g", "m"], show_default=False)
            if mode != "k":
                pw = self._generator(e["kind"]) if mode == "g" else self._manual_secret(e["kind"])
                if pw and self._reuse_ok(pw, e):
                    ch["password"] = pw
        if self.vault.update_entry(e["id"], ch, (file[0], file[1]) if file else None):
            ok(f"entry {e['id']} modified.")
            if file:
                self._offer_delete_original(file[2])
        else:
            inf("no changes.")
        self.pause()

    def _quick_update(self, entries: List[Dict]):
        e = self._pick(entries, "entry id to update")
        if not e:
            self.pause()
            return
        if e["kind"] == "secret_key":
            inf("use MODIFY [4] to change a secret key entry.")
            self.pause()
            return
        pw = self._password_flow(e["kind"], e)
        if pw is None:
            self.pause()
            return
        self.vault.update_entry(e["id"], {"password": pw})
        ok(f"{KIND_LABEL[e['kind']]} updated for '{escape(printable(e['name']))}'.")
        self.pause()

    def cmd_purge(self):
        banner()
        header("PURGE -- DELETE ENTRY")
        entries = self.vault.entries()
        if not entries:
            inf("vault is empty.")
            self.pause()
            return
        console.print(self._entry_table(entries))
        e = self._pick(entries, "entry id to purge")
        if not e:
            self.pause()
            return
        console.print(Text(f"\n  target: {printable(e['name'])} ({printable(e['login']) or '—'})", style=C_ERR))
        if self.confirm("confirm purge?", default=False):
            self.vault.delete_entry(e["id"])
            ok(f"entry {e['id']} purged.")
        else:
            inf("aborted.")
        self.pause()

    # ---- GENERATE / TOTP --------------------------------------------------------------

    def cmd_generate(self):
        banner()
        header("GENERATE -- STANDALONE")
        while True:
            console.print(f"  [{C_KEY}][1][/{C_KEY}] password   [{C_KEY}][2][/{C_KEY}] PIN   [{C_KEY}][3][/{C_KEY}] passphrase (EFF wordlist)\n")
            kind = {"1": "password", "2": "pin", "3": "passphrase"}[self.ask("type", default="1", choices=["1", "2", "3"], show_default=False)]
            pw = self._generator(kind)
            s = self.vault.settings
            if pw and s["clipboard_enabled"] and self.clip.backend() and self.confirm("copy to clipboard?", default=False):
                self.clip.copy(pw, s["clipboard_clear_seconds"])
                ok(f"copied. clears in {s['clipboard_clear_seconds']} s and on EJECT/lock.")
            if not self.confirm("generate another?", default=False):
                break

    def cmd_totp(self):
        banner()
        header("TOTP -- LIVE CODE")
        entries = [e for e in self.vault.entries() if e["totp"]]
        if not entries:
            inf("no entries with TOTP configured.")
            self.pause()
            return
        console.print(self._entry_table(entries))
        self._totp_for(entries)

    def _totp_for(self, entries: List[Dict]):
        e = self._pick([x for x in entries if x["totp"]], "entry id for TOTP")
        if not e:
            self.pause()
            return
        try:
            totp_code(e["totp"])
        except VaultError:
            err("invalid TOTP secret stored for this entry.")
            self.pause()
            return
        self._totp_live(e)

    def _totp_live(self, e: Dict):
        console.print(f"\n  [{C_DIM}]live TOTP for[/{C_DIM}] [{C_HEAD}]{escape(printable(e['name']))}[/{C_HEAD}]  [{C_DIM}]-- press ENTER to exit[/{C_DIM}]\n")
        G, Y, R, CY, B, D, X, EL = "\033[92m", "\033[93m", "\033[91m", "\033[96m", "\033[1m", "\033[2m", "\033[0m", "\033[K"
        width = max(10, min(30, (console.width or 80) - 36))
        last = None
        try:
            while True:
                self.check_lock()
                now = time.time()
                rem = 30 - int(now) % 30
                code = totp_code(e["totp"], now)
                filled = int(rem / 30 * width)
                bar = "[" + "#" * filled + "." * (width - filled) + "]"
                col = R if rem <= 5 else (Y if rem <= 10 else G)
                nxt = f"  {Y}next: {B}{totp_code(e['totp'], now + rem + 1)}{X}" if rem <= 5 else ""
                sys.stdout.write(f"\r  {B}{R if rem <= 5 else CY}{code}{X}  {col}{bar}{X}  {D}{rem:2d}s{X}{nxt}{EL}")
                sys.stdout.flush()
                last = code
                time.sleep(0.5)
                if self.term.poll_enter():
                    break
        except KeyboardInterrupt:
            pass
        sys.stdout.write("\n")
        self.touch()
        s = self.vault.settings
        if last and s["clipboard_enabled"] and self.clip.backend() and self.confirm(f"copy {last} to clipboard?", default=False):
            self.clip.copy(last, s["clipboard_clear_seconds"])
            ok("code copied.")

    # ---- LOG ---------------------------------------------------------------------------

    def cmd_log(self):
        banner()
        header("AUDIT LOG")
        v = self.vault
        good, count, bad_seq = v.verify_log()
        if good:
            console.print(f"  [{C_OK}]hash chain verified[/{C_OK}] [{C_DIM}]({count} events kept, HMAC-SHA256 chained, stored inside the encrypted vault)[/{C_DIM}]\n")
        else:
            console.print(f"  [{C_ERR}]HASH CHAIN BROKEN at seq {bad_seq}[/{C_ERR}] -- the log was modified.\n")
        items = v.data["log"]["items"][-60:][::-1]
        t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {C_HEAD}", border_style=C_DIM, padding=(0, 1))
        for c in ("SEQ", "TIME", "ACTION", "ID", "REF", "DETAIL"):
            t.add_column(c)
        colors = {"ADD": C_OK, "EDIT": C_WARN, "PURGE": C_ERR, "REKEY": "magenta", "ERROR": C_ERR,
                  "UNLOCK_FAIL": C_ERR, "RESTORED": "magenta", "RECOVERY_USED": "magenta"}
        for it in items:
            det = printable(it.get("detail") or "")
            t.add_row(Text(str(it["seq"]), style=C_DIM), Text(local_date(it["ts"]), style=C_DIM),
                      Text(it["action"], style=colors.get(it["action"], C_DIM)),
                      Text(str(it["entry_id"] or "—"), style=C_DIM), Text(it.get("ref") or "", style=C_DIM),
                      Text(det[:60] + ("…" if len(det) > 60 else ""), style=C_DIM))
        console.print(t)
        while True:
            q = self.ask("ref or seq for full details (ENTER to go back)", default="")
            if not q:
                return
            hit = [it for it in v.data["log"]["items"] if it.get("ref") == q.lower() or str(it["seq"]) == q]
            if not hit:
                err("not found.")
                continue
            for it in hit:
                console.print(Text(f"  #{it['seq']}  {local_date(it['ts'])}  {it['action']}  entry={it['entry_id']}  ref={it.get('ref')}", style=C_HEAD))
                console.print(Text("  " + printable(it.get("detail") or "(no detail)"), style=C_DATA))

    # ---- REKEY -------------------------------------------------------------------------

    def cmd_rekey(self):
        banner()
        header("REKEY -- KEYS AND PASSWORDS")
        p = self.vault.header["core"]["kdf"]
        r = ARGON2_RECOMMENDED
        console.print(f"  [{C_DIM}]current KDF: argon2id t={p['time_cost']} m={p['memory_cost']}KiB p={p['parallelism']}"
                      f"   recommended: t={r['time_cost']} m={r['memory_cost']}KiB p={r['parallelism']}[/{C_DIM}]\n")
        console.print(f"  [{C_KEY}][1][/{C_KEY}] change master password (rotates the data key, re-encrypts everything)\n"
                      f"  [{C_KEY}][2][/{C_KEY}] change deadman password\n"
                      f"  [{C_KEY}][3][/{C_KEY}] upgrade KDF parameters / rotate data key (same password)\n"
                      f"  [{C_KEY}][B][/{C_KEY}] back\n")
        c = self.ask("option", default="b", choices=["1", "2", "3", "b"], show_default=False)
        if c == "b":
            return
        cur = self.ask("current master password", secret=True)
        if not self.vault.verify_master(cur):
            raise VaultError("AUTH_FAILED", "REKEY: current master password rejected")
        if c == "1":
            dm = self.vault.header["core"]["deadman"]
            new = self._ask_new_password("master password", MASTER_MIN_LEN, lambda pw: deadman_matches(pw, dm))
            if self.confirm("make a verified backup, then re-encrypt the vault with the new password?", default=True):
                self.do_rekey(new)
        elif c == "2":
            new = self._ask_new_password("deadman password", MASTER_MIN_LEN, lambda pw: self.vault.verify_master(pw))
            self.vault.change_deadman(new)
            ok("deadman password changed.")
        else:
            self.do_rekey(cur)
        self.pause()

    def do_rekey(self, new_password: str):
        v = self.vault
        console.print(f"\n  [{C_DIM}]1/3 creating verified safety backup...[/{C_DIM}]")
        try:
            path, info = create_backup(v, "pre-rekey")
            info.wipe()
        except VaultError as e:
            self.report(e)
            err("rekey aborted before any change: the safety backup could not be created. the vault is unchanged.")
            return
        console.print(f"  [{C_DIM}]2/3 rotating data key, re-encrypting vault and attachments...[/{C_DIM}]")
        old_salt = v.header["core"]["salt"]
        try:
            old_keys = v.rekey(new_password, ARGON2_RECOMMENDED)
        except VaultError as e:
            self.report(e)
            err(f"rekey failed. the vault is unchanged and still opens with the OLD password. safety backup: {escape(path.name)}")
            return
        except KeyboardInterrupt:
            if v.header["core"]["salt"] == old_salt:
                err("rekey interrupted. the vault is unchanged and still opens with the OLD password.")
            else:
                warn("interrupted right after the commit: the vault now opens with the NEW password; "
                     "backups were not converted (the pre-rekey backup opens with the old one).")
            return
        console.print(f"  [{C_DIM}]3/3 re-encrypting backups to the new password...[/{C_DIM}]")
        try:
            converted, stale = convert_backups(old_keys, v)
        except VaultError as e:
            self.report(e)
            converted, stale = [], []
            warn("the vault was re-keyed, but converting backups failed. old backups may still use the OLD password.")
        finally:
            old_keys.wipe()
        with v.transaction():
            v.log("BACKUPS_CONVERTED", detail=f"{len(converted)} converted, {len(stale)} still on older passwords")
        ok(f"vault re-keyed. {len(converted)} backup(s) now open with the new password.")
        if stale:
            warn(f"{len(stale)} backup(s) use an older password and were not converted:")
            for s in stale:
                console.print(Text(f"    {s.name}", style=C_DIM))
            if self.confirm("shred them now?", default=False):
                for s in stale:
                    shred_file(s)
                with v.transaction():
                    v.log("BACKUP_SHRED", detail=f"{len(stale)} older-password backup(s) shredded")
                ok("older backups shredded.")
        warn("copies you placed OUTSIDE the vault folder still open with the old password.")

    # ---- CLONE (backups) -------------------------------------------------------------------

    def cmd_clone(self):
        while True:
            clr()
            banner()
            header("CLONE -- BACKUPS")
            backups = list_backups()
            t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {C_HEAD}", border_style=C_DIM, padding=(0, 1))
            for c in ("#", "FILE", "DATE", "SIZE", "PASSWORD"):
                t.add_column(c)
            for i, b in enumerate(backups, 1):
                cur = backup_uses_current_password(b, self.vault)
                st = b.stat()
                t.add_row(str(i), b.name, datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"), human_size(st.st_size),
                          Text("current" if cur else ("older" if cur is False else "unreadable"),
                               style=C_OK if cur else C_WARN))
            if backups:
                console.print(t)
            else:
                inf("no backups yet.")
            console.print(f"  [{C_DIM}]location: {escape(str(P.backups))} -- copy backups to another disk yourself.[/{C_DIM}]\n")
            console.print(f"  [{C_KEY}][N][/{C_KEY}] new backup   [{C_KEY}][V][/{C_KEY}] verify   [{C_KEY}][R][/{C_KEY}] restore   "
                          f"[{C_KEY}][D][/{C_KEY}] shred   [{C_KEY}][B][/{C_KEY}] back\n")
            a = self.ask("action", default="b", choices=["n", "v", "r", "d", "b"], show_default=False)
            if a == "b":
                return
            if a == "n":
                path, info = create_backup(self.vault)
                n_ent = len(info.data["entries"])
                info.wipe()
                self.vault.log_and_save("BACKUP", detail=path.name)
                ok(f"backup written and fully verified: {escape(path.name)} ({n_ent} entries, all attachments checked)")
                self.pause()
                continue
            if not backups:
                continue
            idx = self.ask_int("backup #", 1, 1, len(backups))
            b = backups[idx - 1]
            if a == "d":
                if self.confirm(f"shred {escape(b.name)}?", default=False):
                    shred_file(b)
                    self.vault.log_and_save("BACKUP_SHRED", detail=b.name)
                    ok("backup shredded.")
                    self.pause()
                continue
            opened = self._open_backup(b)
            if not opened:
                self.pause()
                continue
            info, other_password = opened
            console.print(f"  [{C_OK}]verified[/{C_OK}] [{C_DIM}]generation {info.data['generation']} · saved {local_date(info.data['saved_at'])} · "
                          f"{len(info.data['entries'])} entries · {len(info.data['blobs'])} attachment(s)[/{C_DIM}]\n")
            if a == "v":
                info.wipe()
                self.vault.log_and_save("BACKUP_VERIFY", detail=f"{b.name}: OK")
                self.pause()
                continue
            if not self.confirm("replace the CURRENT vault with this backup? (the current vault is backed up first)", default=False):
                info.wipe()
                continue
            try:
                pre, pinfo = create_backup(self.vault, "pre-restore")
                pinfo.wipe()
            except VaultError as e:
                info.wipe()
                self.report(e)
                err("restore aborted: could not back up the current vault first.")
                self.pause()
                continue
            old = self.vault
            self.vault = install_backup(info)
            old.close()
            self.touch()
            for action, detail in housekeeping(self.vault):
                self.vault.log_and_save(action, detail=detail)
            ok(f"restored {escape(b.name)}. the previous vault was saved as {escape(pre.name)}.")
            if other_password:
                warn("you are now using the backup's master password (the one you just typed).")
            self.pause()
            return

    def _open_backup(self, path: Path) -> Optional[Tuple[BackupInfo, bool]]:
        v = self.vault
        try:
            if backup_uses_current_password(path, v) and v.kek is not None:
                return verify_backup(path, kek=v.kek, dek=v.keys.dek), False
            pw = self.ask("this backup uses an older password -- enter it", secret=True)
            return verify_backup(path, password=pw), True
        except VaultError as e:
            self.report(e)
            return None

    # ---- HEALTH --------------------------------------------------------------------------------

    def _perm_ok(self, p: Path, mode: int) -> bool:
        try:
            st = os.lstat(p)
            return stat.S_IMODE(st.st_mode) == mode and st.st_uid == os.getuid() and not stat.S_ISLNK(st.st_mode)
        except OSError:
            return False

    def cmd_health(self):
        banner()
        header("HEALTH CHECK")
        v = self.vault
        checks: List[Tuple[str, bool, str]] = []
        checks.append(("vault file authenticated", True, "whole-vault AEAD verified at unlock"))
        good, count, bad = v.verify_log()
        checks.append(("audit log hash chain", good, f"{count} events" if good else f"broken at seq {bad}"))
        att_ok, att_bad = 0, []
        for e in v.data["entries"]:
            if e["attachment"]:
                try:
                    v.attachment_bytes(e)
                    att_ok += 1
                except VaultError as ex:
                    att_bad.append(f"#{e['id']}")
                    v.log_and_save("ERROR", e["id"], f"{ex.kind}: {ex.detail}", ex.ref)
        checks.append(("attachments decrypt + hash", not att_bad, f"{att_ok} ok" + (f", FAILED: {', '.join(att_bad)}" if att_bad else "")))
        perm = [self._perm_ok(P.base, 0o700), self._perm_ok(P.vault, 0o600)]
        if P.blobs.exists():
            perm.append(self._perm_ok(P.blobs, 0o700))
            perm += [self._perm_ok(f, 0o600) for f in P.blobs.iterdir()]
        if P.backups.exists():
            perm.append(self._perm_ok(P.backups, 0o700))
            perm += [self._perm_ok(f, 0o600) for f in P.backups.iterdir()]
        checks.append(("permissions 0700/0600, owned by you", all(perm), f"{sum(perm)}/{len(perm)} paths"))
        checks.append(("core dumps disabled", _HARDENING["core_dumps_disabled"], "RLIMIT_CORE=0"))
        checks.append(("process non-dumpable", _HARDENING["non_dumpable"], "prctl(PR_SET_DUMPABLE, 0)"))
        sw, sw_ok = swap_status()
        checks.append(("swap", sw_ok, sw))
        kdf = v.header["core"]["kdf"]
        checks.append(("KDF parameters", not kdf_weaker(kdf), f"t={kdf['time_cost']} m={kdf['memory_cost']}KiB p={kdf['parallelism']}"))
        dmk = v.header["core"]["deadman"]["kdf"]
        checks.append(("deadman KDF parameters", not kdf_weaker(dmk), "change the deadman password to upgrade" if kdf_weaker(dmk) else "ok"))
        rec = v.data["recovery"]
        checks.append(("paper recovery kit", True, f"active: any {rec['threshold']} of {rec['shares']} (kit {rec['kit_id']})" if rec else "none (optional)"))
        t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {C_HEAD}", border_style=C_DIM, padding=(0, 1))
        t.add_column("CHECK")
        t.add_column("STATUS", justify="center")
        t.add_column("DETAIL")
        for name, passed, det in checks:
            t.add_row(name, Text("OK" if passed else "WARN", style=C_OK if passed else C_WARN), Text(det, style=C_DIM))
        console.print(t)
        ents = v.data["entries"]
        weak = [e for e in ents if e["password"] and e["kind"] in ("password", "passphrase", "secret_key") and estimate_bits(e["password"]) < MASTER_TARGET_BITS]
        expired = [e for e in ents if v.is_expired(e)]
        seen: Dict[str, int] = {}
        for e in ents:
            if e["password"]:
                seen[e["password"]] = seen.get(e["password"], 0) + 1
        reused = sum(1 for e in ents if e["password"] and seen[e["password"]] > 1)
        backups = list_backups()
        older = sum(1 for b in backups if backup_uses_current_password(b, v) is False)
        newest = int((time.time() - backups[0].stat().st_mtime) // 86400) if backups else None
        console.print(f"\n  [{C_DIM}]entries[/{C_DIM}]                {len(ents)}")
        console.print(f"  [{C_DIM}]weak (< {MASTER_TARGET_BITS} bits)[/{C_DIM}]         {len(weak)}" + (f"  [{C_DIM}]ids: {', '.join(str(e['id']) for e in weak[:12])}[/{C_DIM}]" if weak else ""))
        console.print(f"  [{C_DIM}]expired[/{C_DIM}]                {len(expired)}")
        console.print(f"  [{C_DIM}]sharing a password[/{C_DIM}]     {reused}")
        console.print(f"  [{C_DIM}]backups[/{C_DIM}]                {len(backups)}" + (f", newest {newest} day(s) old" if newest is not None else "")
                      + (f", [{C_WARN}]{older} on an older password[/{C_WARN}]" if older else ""))
        console.print(f"  [{C_DIM}]vault generation[/{C_DIM}]       {v.data['generation']}\n")
        v.log_and_save("HEALTH", detail=f"{sum(1 for c in checks if not c[1])} warning(s)")
        self.pause()

    # ---- SETTINGS ---------------------------------------------------------------------------------

    def cmd_settings(self):
        banner()
        header("SETTINGS")
        s = self.vault.settings
        console.print(f"  [{C_DIM}]all settings are stored inside the encrypted vault.[/{C_DIM}]\n")
        expiry = self.ask_int("expiry_days (flag secrets not rotated for this long)", s["expiry_days"], 1, 3650)
        lock = self.ask_int("auto_lock_minutes (0 = disabled)", s["auto_lock_minutes"], 0, 1440)
        if lock == 0:
            warn("auto-lock disabled: an unattended terminal stays unlocked.")
        clip = self.confirm(f"enable clipboard? (currently {'on' if s['clipboard_enabled'] else 'off'})", default=s["clipboard_enabled"])
        secs = s["clipboard_clear_seconds"]
        if clip:
            if not self.clip.backend():
                warn("no clipboard tool found (wl-clipboard, xclip or xsel).")
            warn("clipboard managers / history tools may keep copies regardless of auto-clear.")
            secs = self.ask_int("clipboard_clear_seconds", secs, 5, 300)
        with self.vault.transaction():
            s.update({"expiry_days": expiry, "auto_lock_minutes": lock, "clipboard_enabled": clip, "clipboard_clear_seconds": secs})
            self.vault.log("SETTINGS", detail=f"expiry={expiry} lock={lock} clipboard={clip} clear={secs}")
        if not clip and self.clip.used:
            self.clip.clear_all()
        ok("settings saved.")
        self.pause()

    # ---- RECOVERY ---------------------------------------------------------------------------------

    def cmd_recovery(self):
        banner()
        header("RECOVERY -- PAPER KIT")
        rec = self.vault.data["recovery"]
        if rec:
            console.print(f"  [{C_OK}]active kit {rec['kit_id']}[/{C_OK}]: any {rec['threshold']} of {rec['shares']} share(s), created {local_date(rec['created_at'])}\n")
        else:
            console.print(f"  [{C_DIM}]no recovery kit. a kit lets you open the vault with printed shares if you forget the master password.[/{C_DIM}]\n")
        console.print(f"  [{C_KEY}][G][/{C_KEY}] generate {'a NEW kit (old sheets stop working)' if rec else 'a kit'}   "
                      + (f"[{C_KEY}][R][/{C_KEY}] revoke kit   " if rec else "") + f"[{C_KEY}][B][/{C_KEY}] back\n")
        a = self.ask("action", default="b", choices=["g", "r", "b"] if rec else ["g", "b"], show_default=False)
        if a == "g":
            cur = self.ask("master password", secret=True)
            if not self.vault.verify_master(cur):
                raise VaultError("AUTH_FAILED", "RECOVERY: master password rejected")
            self._generate_kit()
        elif a == "r":
            if self.confirm("revoke the kit? every printed sheet becomes useless.", default=False):
                self.vault.revoke_recovery()
                ok("recovery kit revoked.")
        self.pause()

    def _generate_kit(self):
        n = self.ask_int("number of shares to print", 3, 1, 10)
        k = self.ask_int("shares needed to recover", min(2, n), 1, n)
        if k == 1:
            warn("with a threshold of 1, ANY single sheet opens your vault without the master password.")
            if not self.confirm("continue?", default=False):
                return
        kit_id, shares = self.vault.create_recovery(k, n)
        texts = [(x, encode_share(kit_id, k, x, y)) for x, y in shares]
        pdf = build_recovery_pdf(kit_id, k, n, texts, datetime.now().strftime("%Y-%m-%d"))
        shm = Path("/dev/shm")
        default_dir = shm if shm.is_dir() and os.access(shm, os.W_OK) else Path.home()
        target = Path(self.ask("write PDF to", default=str(default_dir / f"vaultterm-recovery-{kit_id}.pdf"))).expanduser().absolute()
        if not str(target).startswith("/dev/shm/"):
            warn("this path is on disk. /dev/shm (RAM) is safer for a file this sensitive.")
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(pdf)
        except OSError as e:
            raise VaultError("IO_ERROR", f"recovery PDF: {e.strerror}")
        ok(f"recovery kit {kit_id} written: {escape(str(target))}")
        if qrcode is None:
            warn("python 'qrcode' not installed: sheets contain text shares only.")
        console.print(f"  [{C_DIM}]this PDF contains ALL shares, so it alone can open your vault. print it now,\n"
                      f"  then let VaultTerm shred it. test a recovery with --recover on a copy if you like.[/{C_DIM}]\n")
        self.ask("press ENTER after printing to shred the PDF", default="", show_default=False)
        if self.confirm("shred the PDF now?", default=True):
            shred_file(target)
            ok("PDF shredded.")
        else:
            warn(f"PDF kept at {escape(str(target))} -- delete it yourself.")

    # ---- EJECT -------------------------------------------------------------------------------------

    def cmd_eject(self):
        self.clip.clear_all()          # always, even if nothing was copied this session
        self.clip.used = False
        if self.vault:
            try:
                self.vault.log_and_save("LOCK")
            except VaultError:
                pass
            self.vault.close()
            self.vault = None
        clr()
        w = min(console.width or 72, 100)
        console.print(f"\n[{C_HEAD}]{'=' * w}[/{C_HEAD}]\n[{C_HEAD}]  VAULT LOCKED  //  CLIPBOARD CLEARED  //  SESSION TERMINATED[/{C_HEAD}]\n[{C_HEAD}]{'=' * w}[/{C_HEAD}]\n")
        sys.exit(0)

    # ---- CLI flows ---------------------------------------------------------------------------------

    def cli_restore(self, path: Path):
        clr()
        banner()
        header("RESTORE FROM BACKUP")
        ensure_dir(P.base)
        console.print(f"  [{C_DIM}]backup: {escape(str(path))}[/{C_DIM}]\n")
        pw = self.ask("master password of this backup", secret=True, timed=False)
        try:
            info = verify_backup(path, password=pw)
        except VaultError as e:
            self.report(e, persist=False)
            sys.exit(3)
        console.print(f"  [{C_OK}]verified[/{C_OK}] [{C_DIM}]generation {info.data['generation']} · saved {local_date(info.data['saved_at'])} · "
                      f"{len(info.data['entries'])} entries · {len(info.data['blobs'])} attachment(s)[/{C_DIM}]\n")
        if not self.confirm("install this backup as the active vault?", default=False):
            sys.exit(0)
        if os.path.lexists(P.vault):
            saved = preserve_unverified_state("pre-restore-unverified")
            if saved:
                inf(f"the existing vault files were archived as {escape(saved.name)}")
        self.vault = install_backup(info)
        self.touch()
        ok("backup restored.")
        self.after_unlock(pw)

    def cli_recover(self):
        clr()
        banner()
        header("PAPER RECOVERY")
        try:
            hdr, _, _ = split_vault(read_vault_file())
        except VaultError as e:
            self.report(e, persist=False)
            sys.exit(3)
        kit = hdr["core"]["recovery_kit"]
        if not kit:
            self.report(VaultError("RECOVERY_INVALID", "vault has no active recovery kit"), persist=False)
            sys.exit(3)
        shares: Dict[int, bytes] = {}
        need: Optional[int] = None
        while need is None or len(shares) < need:
            s = self.ask(f"share {len(shares) + 1}" + (f" of {need}" if need else ""), timed=False)
            clr()
            banner()
            header("PAPER RECOVERY")
            try:
                kid, k, x, y = decode_share(s)
            except VaultError as e:
                err(escape(e.detail))
                continue
            if kid != kit:
                err("this share belongs to a different (old or revoked) kit.")
                continue
            if x in shares:
                err(f"share #{x} was already entered.")
                continue
            need = k
            shares[x] = y
            ok(f"share #{x} accepted ({len(shares)}/{k}).")
        rk = shamir_combine(shares)
        try:
            self.vault = Vault.unlock_with_recovery(rk)
        except VaultError as e:
            self.report(e, persist=False)
            sys.exit(3)
        self.touch()
        self.vault.log_and_save("RECOVERY_USED", detail=f"kit {kit}")
        ok("vault opened with the recovery kit. set a new master password now.")
        dm = self.vault.header["core"]["deadman"]
        new = self._ask_new_password("master password", MASTER_MIN_LEN, lambda pw: deadman_matches(pw, dm))
        self.do_rekey(new)
        warn("the shares you just typed were exposed. consider generating a NEW kit in RECOVERY [13].")
        self.after_unlock(None)

# ── self-test (used by compile.sh; never touches the real vault) ─────────────


def selftest() -> int:
    global P
    old_p = P
    tmp = tempfile.mkdtemp(prefix="vaultterm-selftest-")
    P = Paths(Path(tmp) / "vault")
    fast = dict(ARGON2_MIN)
    try:
        assert totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", at=59, digits=8) == "94287082"
        assert totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", at=1111111109, digits=8) == "07081804"
        secret = os.urandom(32)
        sh = shamir_split(secret, 3, 5)
        assert shamir_combine({x: y for x, y in sh[1:4]}) == secret
        assert shamir_combine({x: y for x, y in sh[:2]}) != secret
        kid, k, x, y = decode_share(encode_share("0a1b2c3d", 3, 2, sh[1][1]))
        assert (kid, k, x, y) == ("0a1b2c3d", 3, 2, sh[1][1])
        assert estimate_bits("Password123!Password") < 40
        assert estimate_bits(gen_passphrase(6)[0]) > 70
        v = Vault.create("correct horse battery", "deadman deadman 1", fast)
        eid = v.add_entry("secret_key", "ssh", "", "me", "", "", "", ("id_ed25519", b"KEYDATA" * 100))
        v.add_entry("password", "mail", "", "me", "pw-one-xxxxxxxxx", "", "")
        v.close()
        v = Vault.unlock("correct horse battery")
        assert v.attachment_bytes(v.get(eid)) == b"KEYDATA" * 100
        try:
            Vault.unlock("deadman deadman 1")
            raise AssertionError("deadman not detected")
        except DeadmanTriggered:
            pass
        try:
            Vault.unlock("wrong password here")
            raise AssertionError("wrong password accepted")
        except VaultError as e:
            assert e.kind == "AUTH_FAILED"
        bpath, info = create_backup(v)
        info.wipe()
        old = v.rekey("new master password", fast)
        conv, stale = convert_backups(old, v)
        old.wipe()
        assert conv == [bpath] and not stale
        assert verify_backup(bpath, password="new master password").data["entries"]
        assert v.verify_log()[0]
        assert build_recovery_pdf("0a1b2c3d", 2, 3, [(1, "VT4-AAAA")], "2026-01-01").startswith(b"%PDF-1.4")
        v.close()
        print("selftest OK")
        return 0
    except Exception as e:  # pragma: no cover
        print(f"selftest FAILED: {type(e).__name__}: {e}")
        return 1
    finally:
        P = old_p
        shutil.rmtree(tmp, ignore_errors=True)

# ── main ─────────────────────────────────────────────────────────────────────


def _raise_exit(signum, _frame):
    raise SystemExit(128 + signum)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="vaultterm", description="Offline terminal password vault (Linux).")
    ap.add_argument("--restore", metavar="BACKUP", help="install a .vtbak backup as the active vault")
    ap.add_argument("--recover", action="store_true", help="open the vault with paper recovery shares")
    ap.add_argument("--selftest", action="store_true", help="run built-in crypto/format tests in a temp dir and exit")
    ap.add_argument("--version", action="version", version=f"VaultTerm {VERSION}")
    args = ap.parse_args(argv)
    harden_process()
    if args.selftest:
        return selftest()
    if not sys.platform.startswith("linux"):
        print("VaultTerm v4 supports Linux only.", file=sys.stderr)
        return 1
    if not sys.stdin.isatty():
        print("VaultTerm needs an interactive terminal.", file=sys.stderr)
        return 1
    signal.signal(signal.SIGTERM, _raise_exit)
    signal.signal(signal.SIGHUP, _raise_exit)
    app = App()
    try:
        app.run(args)
    except (KeyboardInterrupt, EOFError):
        console.print(f"\n\n  [{C_DIM}]interrupted -- vault locked.[/{C_DIM}]\n")
        return 0
    except VaultError as e:
        app.report(e, persist=True)
        return 3
    except Exception as e:
        app.report(VaultError("INTERNAL", f"{type(e).__name__}: {e}\n{traceback.format_exc(limit=8)}"), persist=True)
        return 3
    finally:
        app.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
