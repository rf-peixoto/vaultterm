#!/usr/bin/env python3
"""
VAULTTERM v3.0 -- LOCAL TERMINAL PASSWORD VAULT
ChaCha20-Poly1305 // Argon2id // encrypted metadata // local-only
"""

import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import string
import sys
import tarfile
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from rich import box
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

try:
    import pyotp
except Exception:
    pyotp = None

try:
    import pyperclip
    _CLIP = True
except Exception:
    pyperclip = None
    _CLIP = False

# ── user-tunable settings ─────────────────────────────────────────────────────

VERSION = "3.0"
SCHEMA_VERSION = 4
VAULT_DIR = Path.home() / ".vaultterm"
DB_PATH = VAULT_DIR / "vault.db"
META_PATH = VAULT_DIR / "meta.json"
BACKUP_DIR = VAULT_DIR / "backups"

EXPIRY_DAYS = 30
PW_MIN_LEN = 16
PW_MAX_LEN = 96
MAX_ATTEMPTS = 5
CLIPBOARD_CLEAR_SECONDS = 30
AUTO_LOCK_SECONDS = 10 * 60

ARGON2_PARAMS = {
    "type": "argon2id",
    "time_cost": 3,
    "memory_cost": 262144,  # KiB = 256 MiB
    "parallelism": 2,
    "hash_len": 64,
    "salt_len": 32,
}

SENTINEL = "VAULTTERM::ONLINE::v3"
DEADMAN_SENTINEL = "VAULTTERM::DEADMAN::v3"
AAD_LEGACY = b"vaultterm-v3"
AAD_PREFIX = f"vaultterm|schema={SCHEMA_VERSION}".encode("utf-8")
ENTRY_ENCRYPTED_FIELDS = ("name", "url", "login", "password", "notes", "totp_secret")

def aad_for_entry(entry_uuid: str, field: str) -> bytes:
    if field not in ENTRY_ENCRYPTED_FIELDS:
        raise ValueError(f"invalid encrypted field for AAD: {field}")
    return AAD_PREFIX + b"|entry|" + entry_uuid.encode("utf-8") + b"|field|" + field.encode("utf-8")

def aad_for_meta(label: str) -> bytes:
    return AAD_PREFIX + b"|meta|" + label.encode("utf-8")

# ── palette ───────────────────────────────────────────────────────────────────

C_HEAD = "bright_cyan"
C_KEY = "bright_cyan"
C_OK = "green"
C_WARN = "yellow"
C_ERR = "bright_red"
C_DIM = "grey50"
C_DATA = "white"
C_PW = "bright_yellow"
C_LABEL = "cyan"

console = Console()

# ── small helpers ─────────────────────────────────────────────────────────────


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_ts(ts: str) -> datetime:
    try:
        d = datetime.fromisoformat(ts)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d
    except Exception:
        return datetime.now(timezone.utc)


def local_date(ts: str) -> str:
    return parse_ts(ts).astimezone().strftime("%Y-%m-%d %H:%M")


def age_days(ts: str) -> int:
    return max(0, (datetime.now(timezone.utc) - parse_ts(ts)).days)


def clr():
    os.system("cls" if os.name == "nt" else "clear")


def ln(style: str = C_DIM):
    console.print(Rule(style=style))


def ok(msg: str):
    console.print(f"\n  [{C_OK}][OK][/{C_OK}]  {msg}\n")


def err(msg: str):
    console.print(f"\n  [{C_ERR}][ERR][/{C_ERR}] {msg}\n")


def warn(msg: str):
    console.print(f"\n  [{C_WARN}][WARN][/{C_WARN}] {msg}\n")


def inf(msg: str):
    console.print(f"\n  [{C_HEAD}][SYS][/{C_HEAD}] {msg}\n")


def pause():
    try:
        console.print(f"  [{C_DIM}]press ENTER to continue...[/{C_DIM}]", end="")
        input()
    except (KeyboardInterrupt, EOFError):
        console.print()  # newline after the ^C echo


def ask_pw(prompt: str = "password") -> str:
    return getpass.getpass(f"  {prompt} >> ")


def header(title: str):
    console.print()
    console.print(f"  [{C_HEAD}]>> {title}[/{C_HEAD}]")
    console.print(f"  [{C_DIM}]{'─' * (len(title) + 4)}[/{C_DIM}]")
    console.print()


def banner():
    console.print()
    w = console.width or 72
    line = "=" * w
    tag = f"  VAULTTERM v{VERSION}  //  ChaCha20-Poly1305  //  Argon2id  //  LOCAL"
    console.print(f"[{C_HEAD}]{line}[/{C_HEAD}]")
    console.print(f"[{C_HEAD}]{tag}[/{C_HEAD}]")
    console.print(f"[{C_HEAD}]{line}[/{C_HEAD}]")
    console.print()


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def b64d(txt: str) -> bytes:
    return base64.urlsafe_b64decode(txt.encode("ascii"))


def secure_mkdir(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path, 0o700)


def secure_file(path: Path):
    if not path.exists():
        return
    if os.name != "nt":
        os.chmod(path, 0o600)
    else:
        # Best-effort local-user-only ACL hardening on Windows. This is not a
        # substitute for a properly hardened host, but it avoids the previous
        # behavior where Windows was effectively treated as permissionless.
        try:
            import subprocess
            subprocess.run(["icacls", str(path), "/inheritance:r"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            user = os.environ.get("USERNAME")
            if user:
                subprocess.run(["icacls", str(path), "/grant:r", f"{user}:F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except Exception:
            pass


def set_permissions():
    secure_mkdir(VAULT_DIR)
    secure_mkdir(BACKUP_DIR)
    for p in (DB_PATH, META_PATH, Path(str(DB_PATH) + "-wal"), Path(str(DB_PATH) + "-shm"), Path(str(DB_PATH) + "-journal")):
        secure_file(p)
    for p in BACKUP_DIR.glob("*"):
        if p.is_file():
            secure_file(p)


def secure_delete_file(path: Path, passes: int = 3):
    try:
        if not path.exists() or not path.is_file():
            return
        size = path.stat().st_size
        with path.open("r+b", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        path.unlink(missing_ok=True)
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass


def shred_vault():
    targets = []
    if VAULT_DIR.exists():
        for p in sorted(VAULT_DIR.rglob("*"), key=lambda x: len(str(x)), reverse=True):
            targets.append(p)
    for p in targets:
        if p.is_file():
            secure_delete_file(p)
    for p in targets:
        if p.is_dir():
            try:
                p.rmdir()
            except Exception:
                pass
    try:
        VAULT_DIR.rmdir()
    except Exception:
        pass


def _clip_clear(value: str, delay: int = CLIPBOARD_CLEAR_SECONDS):
    def _run():
        time.sleep(delay)
        try:
            if pyperclip and pyperclip.paste() == value:
                pyperclip.copy("")
        except Exception:
            pass
    threading.Thread(target=_run, daemon=True).start()

# ── crypto ───────────────────────────────────────────────────────────────────


class Crypto:
    def __init__(self):
        self.enc_key: Optional[bytes] = None
        self.hash_key: Optional[bytes] = None

    @staticmethod
    def derive(password: str, salt: bytes, params: Dict) -> bytes:
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=int(params["time_cost"]),
            memory_cost=int(params["memory_cost"]),
            parallelism=int(params["parallelism"]),
            hash_len=int(params.get("hash_len", 64)),
            type=Type.ID,
        )

    def init_from_raw(self, raw: bytes):
        if len(raw) < 64:
            raise ValueError("derived key too short")
        self.enc_key = raw[:32]
        self.hash_key = raw[32:64]

    def init(self, password: str, salt: bytes, params: Dict):
        self.init_from_raw(self.derive(password, salt, params))

    def enc(self, text: str, aad: bytes) -> str:
        if self.enc_key is None:
            raise RuntimeError("crypto not ready")
        nonce = os.urandom(12)
        ct = ChaCha20Poly1305(self.enc_key).encrypt(nonce, text.encode("utf-8"), aad)
        return b64e(nonce + ct)

    def dec(self, token: str, aad: bytes) -> str:
        if self.enc_key is None:
            raise RuntimeError("crypto not ready")
        raw = b64d(token)
        nonce, ct = raw[:12], raw[12:]
        return ChaCha20Poly1305(self.enc_key).decrypt(nonce, ct, aad).decode("utf-8")

    def legacy_dec(self, token: str) -> str:
        if self.enc_key is None:
            raise RuntimeError("crypto not ready")
        raw = b64d(token)
        return ChaCha20Poly1305(self.enc_key).decrypt(raw[:12], raw[12:], AAD_LEGACY).decode("utf-8")

    def enc_field(self, entry_uuid: str, field: str, text: str) -> str:
        return self.enc(text, aad_for_entry(entry_uuid, field))

    def dec_field(self, entry_uuid: str, field: str, token: str) -> str:
        return self.dec(token, aad_for_entry(entry_uuid, field))

    def pw_hash(self, password: str) -> str:
        if self.hash_key is None:
            raise RuntimeError("hash key not ready")
        return b64e(hmac.new(self.hash_key, password.encode("utf-8"), hashlib.sha256).digest())

    @staticmethod
    def verify_with_raw(raw: bytes, token: str, expected: str, aad: bytes) -> bool:
        try:
            enc_key = raw[:32]
            blob = b64d(token)
            pt = ChaCha20Poly1305(enc_key).decrypt(blob[:12], blob[12:], aad).decode("utf-8")
            return hmac.compare_digest(pt, expected)
        except Exception:
            return False

    @staticmethod
    def legacy_verify_with_raw(raw: bytes, token: str, expected: str) -> bool:
        try:
            enc_key = raw[:32]
            blob = b64d(token)
            pt = ChaCha20Poly1305(enc_key).decrypt(blob[:12], blob[12:], AAD_LEGACY).decode("utf-8")
            return hmac.compare_digest(pt, expected)
        except Exception:
            return False

# ── meta file ────────────────────────────────────────────────────────────────


class Meta:
    def __init__(self, path: Path):
        self.path = path

    def _atomic_write(self, data: Dict):
        secure_mkdir(self.path.parent)
        prev_umask = os.umask(0o077)
        tmp_name = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(self.path.parent), delete=False) as fh:
                tmp_name = fh.name
                json.dump(data, fh, indent=2)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self.path)
            secure_file(self.path)
        finally:
            os.umask(prev_umask)
            if tmp_name:
                try:
                    Path(tmp_name).unlink(missing_ok=True)
                except Exception:
                    pass

    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> Dict:
        return json.loads(self.path.read_text())

    def params(self) -> Dict:
        return self.load()["kdf"]

    def salt(self) -> bytes:
        return b64d(self.load()["salt"])

    def deadman_salt(self) -> bytes:
        return b64d(self.load()["deadman_salt"])

    def token(self) -> str:
        return self.load()["verify"]

    def deadman_token(self) -> str:
        return self.load()["deadman_verify"]

    def create(self, master_pw: str, deadman_pw: str, crypto: Crypto):
        secure_mkdir(self.path.parent)
        salt = os.urandom(ARGON2_PARAMS["salt_len"])
        dead_salt = os.urandom(ARGON2_PARAMS["salt_len"])
        crypto.init(master_pw, salt, ARGON2_PARAMS)
        dead_raw = Crypto.derive(deadman_pw, dead_salt, ARGON2_PARAMS)
        dead_crypto = Crypto()
        dead_crypto.init_from_raw(dead_raw)
        data = {
            "version": VERSION,
            "schema_version": SCHEMA_VERSION,
            "cipher": "ChaCha20Poly1305",
            "kdf": ARGON2_PARAMS,
            "salt": b64e(salt),
            "deadman_salt": b64e(dead_salt),
            "verify": crypto.enc(SENTINEL, aad_for_meta("verify")),
            "deadman_verify": dead_crypto.enc(DEADMAN_SENTINEL, aad_for_meta("deadman_verify")),
            "created_at": utc_now(),
            "updated_at": utc_now(),
        }
        self._atomic_write(data)

    def update_master(self, salt: bytes, verify_token: str):
        d = self.load()
        d["salt"] = b64e(salt)
        d["verify"] = verify_token
        d["updated_at"] = utc_now()
        self._atomic_write(d)

# ── database ─────────────────────────────────────────────────────────────────


class DB:
    def __init__(self, path: Path, crypto: Crypto):
        self.path = path
        self.crypto = crypto
        self._db: Optional[sqlite3.Connection] = None

    def open(self):
        secure_mkdir(self.path.parent)
        prev_umask = os.umask(0o077)
        try:
            self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        finally:
            os.umask(prev_umask)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=DELETE")
        self._db.execute("PRAGMA secure_delete=ON")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA temp_store=MEMORY")
        self._schema()
        self._migrate_context_bound_encryption()
        set_permissions()

    def close(self):
        if self._db:
            self._db.close()
            self._db = None

    def _schema(self):
        self._db.executescript(f"""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT OR REPLACE INTO settings (key,value) VALUES ('schema_version','{SCHEMA_VERSION}');
            INSERT OR IGNORE  INTO settings (key,value) VALUES ('expiry_days',   '{EXPIRY_DAYS}');
            INSERT OR IGNORE  INTO settings (key,value) VALUES ('auto_lock_minutes', '10');
            INSERT OR IGNORE  INTO settings (key,value) VALUES ('clipboard_enabled', '0');
            INSERT OR IGNORE  INTO settings (key,value) VALUES ('aad_migrated_v4', '0');

            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_uuid TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL,
                url TEXT NOT NULL DEFAULT '',
                login TEXT NOT NULL,
                password TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                totp_secret TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id INTEGER NOT NULL,
                password_hash TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                FOREIGN KEY(entry_id) REFERENCES entries(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                action TEXT NOT NULL,
                entry_id INTEGER
            );
        """)
        self._db.commit()
        cols = [r[1] for r in self._db.execute("PRAGMA table_info(entries)").fetchall()]
        if "entry_uuid" not in cols:
            self._db.execute("ALTER TABLE entries ADD COLUMN entry_uuid TEXT NOT NULL DEFAULT ''")
            self._db.commit()

    def _migrate_context_bound_encryption(self):
        if self.setting("aad_migrated_v4", "0") == "1":
            return
        rows = self._db.execute("SELECT * FROM entries ORDER BY id").fetchall()
        self._db.execute("BEGIN IMMEDIATE")
        try:
            for r in rows:
                raw = dict(r)
                entry_uuid = raw.get("entry_uuid") or str(uuid.uuid4())
                values = {"entry_uuid": entry_uuid}
                for field in ENTRY_ENCRYPTED_FIELDS:
                    token = raw.get(field) or ""
                    if not token:
                        values[field] = ""
                        continue
                    try:
                        # Already context-bound; normalize by decrypting/re-encrypting.
                        plain = self.crypto.dec_field(entry_uuid, field, token)
                    except Exception:
                        # Legacy vaults used one global AAD for every field.
                        plain = self.crypto.legacy_dec(token)
                    values[field] = self.crypto.enc_field(entry_uuid, field, plain)
                clause = ", ".join(f"{k}=?" for k in values)
                self._db.execute(f"UPDATE entries SET {clause} WHERE id=?", [*values.values(), raw["id"]])
            self._db.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('aad_migrated_v4','1')")
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

    def _log(self, action: str, entry_id: Optional[int] = None):
        self._db.execute("INSERT INTO log (ts,action,entry_id) VALUES (?,?,?)", (utc_now(), action, entry_id))

    def _row_summary(self, row: sqlite3.Row) -> Dict:
        d = dict(row)
        out = {
            "id": d["id"],
            "entry_uuid": d.get("entry_uuid") or "",
            "name": self._safe_dec(d.get("entry_uuid") or "", "name", d["name"], "[ERR:DECRYPT]"),
            "url": self._safe_dec(d.get("entry_uuid") or "", "url", d["url"], "") if d.get("url") else "",
            "login": self._safe_dec(d.get("entry_uuid") or "", "login", d["login"], "[ERR:DECRYPT]"),
            "has_notes": bool(d.get("notes")),
            "has_totp": bool(d.get("totp_secret")),
            "created_at": d["created_at"],
            "updated_at": d["updated_at"],
            "age": age_days(d["updated_at"]),
        }
        out["expired"] = out["age"] >= self.expiry_days
        return out

    def _row_full(self, row: sqlite3.Row) -> Dict:
        d = self._row_summary(row)
        raw = dict(row)
        entry_uuid = raw.get("entry_uuid") or d.get("entry_uuid") or ""
        d["password"] = self.crypto.dec_field(entry_uuid, "password", raw["password"])
        d["notes"] = self.crypto.dec_field(entry_uuid, "notes", raw["notes"]) if raw.get("notes") else ""
        d["totp_secret"] = self.crypto.dec_field(entry_uuid, "totp_secret", raw["totp_secret"]) if raw.get("totp_secret") else ""
        d["password_hash"] = raw["password_hash"]
        return d

    def _safe_dec(self, entry_uuid: str, field: str, token: str, fallback: str) -> str:
        try:
            return self.crypto.dec_field(entry_uuid, field, token)
        except Exception:
            return fallback

    def get_all_summaries(self) -> List[Dict]:
        rows = self._db.execute("SELECT * FROM entries ORDER BY id").fetchall()
        items = [self._row_summary(r) for r in rows]
        return sorted(items, key=lambda x: x["name"].lower())

    def get_full(self, eid: int) -> Optional[Dict]:
        r = self._db.execute("SELECT * FROM entries WHERE id=?", (eid,)).fetchone()
        return self._row_full(r) if r else None

    def search_summaries(self, query: str) -> List[Dict]:
        q = query.lower().strip()
        matches = []
        rows = self._db.execute("SELECT * FROM entries ORDER BY id").fetchall()
        for row in rows:
            s = self._row_summary(row)
            if q in s["name"].lower() or q in s["url"].lower() or q in s["login"].lower():
                matches.append(s)
            elif dict(row).get("notes"):
                # Only decrypt notes when the entry didn't already match on cheaper fields
                notes = self._safe_dec(dict(row).get("entry_uuid") or "", "notes", dict(row)["notes"], "")
                if q in notes.lower():
                    matches.append(s)
        return sorted(matches, key=lambda x: x["name"].lower())

    def duplicate_hits(self, name: str, url: str, login: str) -> List[Dict]:
        hits = []
        for e in self.get_all_summaries():
            same_name_login = e["name"].lower() == name.lower() and e["login"].lower() == login.lower()
            same_url_login = bool(url and e["url"] and e["url"].lower() == url.lower() and e["login"].lower() == login.lower())
            if same_name_login or same_url_login:
                hits.append(e)
        return hits

    def password_was_used(self, eid: int, password: str) -> bool:
        ph = self.crypto.pw_hash(password)
        cur = self._db.execute("SELECT password_hash FROM entries WHERE id=?", (eid,)).fetchone()
        if cur and hmac.compare_digest(cur["password_hash"], ph):
            return True
        rows = self._db.execute("SELECT password_hash FROM password_history WHERE entry_id=?", (eid,)).fetchall()
        return any(hmac.compare_digest(r["password_hash"], ph) for r in rows)

    def add(self, name: str, url: str, login: str, password: str, notes: str = "", totp_secret: str = "") -> int:
        now = utc_now()
        ph = self.crypto.pw_hash(password)
        entry_uuid = str(uuid.uuid4())
        cur = self._db.execute(
            "INSERT INTO entries (entry_uuid,name,url,login,password,notes,totp_secret,password_hash,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (entry_uuid, self.crypto.enc_field(entry_uuid, "name", name), self.crypto.enc_field(entry_uuid, "url", url) if url else "", self.crypto.enc_field(entry_uuid, "login", login), self.crypto.enc_field(entry_uuid, "password", password),
             self.crypto.enc_field(entry_uuid, "notes", notes) if notes else "", self.crypto.enc_field(entry_uuid, "totp_secret", totp_secret) if totp_secret else "", ph, now, now),
        )
        eid = int(cur.lastrowid)
        self._db.execute("INSERT INTO password_history (entry_id,password_hash,changed_at) VALUES (?,?,?)", (eid, ph, now))
        self._log("ADD", eid)
        self._db.commit()
        return eid

    def update(self, eid: int, **kw):
        current = self.get_full(eid)
        if not current:
            return
        entry_uuid = current.get("entry_uuid") or str(uuid.uuid4())
        fields = {"entry_uuid": entry_uuid, "updated_at": utc_now()}
        if "name" in kw:
            fields["name"] = self.crypto.enc_field(entry_uuid, "name", kw["name"])
        if "url" in kw:
            fields["url"] = self.crypto.enc_field(entry_uuid, "url", kw["url"]) if kw["url"] else ""
        if "login" in kw:
            fields["login"] = self.crypto.enc_field(entry_uuid, "login", kw["login"])
        if "notes" in kw:
            fields["notes"] = self.crypto.enc_field(entry_uuid, "notes", kw["notes"]) if kw["notes"] else ""
        if "totp_secret" in kw:
            fields["totp_secret"] = self.crypto.enc_field(entry_uuid, "totp_secret", kw["totp_secret"]) if kw["totp_secret"] else ""
        if "password" in kw:
            old_hash = current["password_hash"]
            fields["password"] = self.crypto.enc_field(entry_uuid, "password", kw["password"])
            fields["password_hash"] = self.crypto.pw_hash(kw["password"])
            self._db.execute("INSERT INTO password_history (entry_id,password_hash,changed_at) VALUES (?,?,?)", (eid, old_hash, utc_now()))
            self._db.execute("INSERT INTO password_history (entry_id,password_hash,changed_at) VALUES (?,?,?)", (eid, fields["password_hash"], utc_now()))
        clause = ", ".join(f"{k}=?" for k in fields)
        self._db.execute(f"UPDATE entries SET {clause} WHERE id=?", [*fields.values(), eid])
        self._log("EDIT", eid)
        self._db.commit()

    def delete(self, eid: int):
        self._db.execute("DELETE FROM entries WHERE id=?", (eid,))
        self._log("PURGE", eid)
        self._db.commit()

    def setting(self, key: str, default: str = "") -> str:
        r = self._db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r[0] if r else default

    def set_setting(self, key: str, value: str):
        self._db.execute(
            "INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (key, value)
        )
        self._db.commit()

    @property
    def expiry_days(self) -> int:
        try:
            return max(1, int(self.setting("expiry_days", str(EXPIRY_DAYS))))
        except Exception:
            return EXPIRY_DAYS

    @property
    def auto_lock_seconds(self) -> int:
        try:
            minutes = int(self.setting("auto_lock_minutes", "10"))
            return minutes * 60
        except Exception:
            return AUTO_LOCK_SECONDS

    def get_log(self, n: int = 80) -> List[Dict]:
        rows = self._db.execute("SELECT * FROM log ORDER BY ts DESC LIMIT ?", (n,)).fetchall()
        return [dict(r) for r in rows]

    def reencrypt_atomic(self, new_crypto: Crypto, new_salt: bytes, meta: Meta):
        rows = self._db.execute("SELECT * FROM entries").fetchall()
        self._db.execute("BEGIN IMMEDIATE")
        try:
            for r in rows:
                full = self._row_full(r)
                new_ph = new_crypto.pw_hash(full["password"])
                self._db.execute(
                    "UPDATE entries SET name=?,url=?,login=?,password=?,notes=?,totp_secret=?,password_hash=? WHERE id=?",
                    (new_crypto.enc_field(full["entry_uuid"], "name", full["name"]), new_crypto.enc_field(full["entry_uuid"], "url", full["url"]) if full["url"] else "",
                     new_crypto.enc_field(full["entry_uuid"], "login", full["login"]), new_crypto.enc_field(full["entry_uuid"], "password", full["password"]),
                     new_crypto.enc_field(full["entry_uuid"], "notes", full["notes"]) if full["notes"] else "",
                     new_crypto.enc_field(full["entry_uuid"], "totp_secret", full["totp_secret"]) if full["totp_secret"] else "", new_ph, full["id"]),
                )
                self._db.execute("DELETE FROM password_history WHERE entry_id=?", (full["id"],))
                self._db.execute("INSERT INTO password_history (entry_id,password_hash,changed_at) VALUES (?,?,?)", (full["id"], new_ph, utc_now()))
            self._log("REKEY", None)
            verify = new_crypto.enc(SENTINEL, aad_for_meta("verify"))
            meta.update_master(new_salt, verify)
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

    def health(self) -> Dict:
        result = {"db_readable": False, "decryptable": True, "entries": 0, "weak": 0, "expired": 0, "reused_hashes": 0}
        rows = self._db.execute("SELECT * FROM entries").fetchall()
        result["db_readable"] = True
        result["entries"] = len(rows)
        seen_hashes = set()
        for r in rows:
            try:
                full = self._row_full(r)
                sc, _, _ = strength(full["password"])
                if sc < 50:
                    result["weak"] += 1
                if age_days(full["updated_at"]) >= self.expiry_days:
                    result["expired"] += 1
                if full["password_hash"] in seen_hashes:
                    result["reused_hashes"] += 1
                seen_hashes.add(full["password_hash"])
            except Exception:
                result["decryptable"] = False
        return result

# ── password helpers ─────────────────────────────────────────────────────────


def gen_pw(length: int = 24, profile: str = "high") -> str:
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*-_=+[]{}|;:,.<>?"
    safe_symbols = "!@#$%*-_=+?"
    # PIN must be clamped independently — PW_MIN_LEN does not apply to numeric PINs
    if profile == "pin":
        return "".join(secrets.choice(digits) for _ in range(max(4, min(length, 8))))
    length = max(PW_MIN_LEN, min(PW_MAX_LEN, length))
    if profile == "no_symbols":
        pool = lower + upper + digits
        seed = [secrets.choice(lower), secrets.choice(upper), secrets.choice(digits)]
    elif profile == "compat":
        pool = lower + upper + digits + safe_symbols
        seed = [secrets.choice(lower), secrets.choice(upper), secrets.choice(digits), secrets.choice(safe_symbols)]
    else:
        pool = lower + upper + digits + symbols
        seed = [secrets.choice(lower), secrets.choice(upper), secrets.choice(digits), secrets.choice(symbols)]
    rest = [secrets.choice(pool) for _ in range(max(0, length - len(seed)))]
    chars = seed + rest
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def gen_passphrase(words_count: int = 5) -> str:
    words = [
        "amber", "anchor", "atlas", "binary", "black", "cinder", "cipher", "cobalt", "comet", "crimson",
        "delta", "ember", "falcon", "forest", "ghost", "granite", "harbor", "helium", "iron", "ivory",
        "jaguar", "kernel", "lunar", "matrix", "nebula", "onyx", "orbit", "phoenix", "quantum", "raven",
        "signal", "silver", "storm", "temple", "umbra", "vector", "velvet", "vortex", "winter", "zenith",
    ]
    return "-".join(secrets.choice(words) for _ in range(max(4, words_count))) + "-" + str(secrets.randbelow(9000) + 1000)


def strength(pw: str) -> Tuple[int, str, str]:
    s = 0
    if len(pw) >= 8: s += 10
    if len(pw) >= 12: s += 10
    if len(pw) >= 16: s += 10
    if len(pw) >= 20: s += 10
    if len(pw) >= 32: s += 10
    if len(pw) >= 64: s += 10
    if any(c.islower() for c in pw): s += 8
    if any(c.isupper() for c in pw): s += 10
    if any(c.isdigit() for c in pw): s += 12
    if any(c in "!@#$%^&*-_=+[]{}|;:,.<>?" for c in pw): s += 20
    s = min(s, 100)
    if s < 30: return s, "CRITICAL", C_ERR
    if s < 50: return s, "WEAK", C_WARN
    if s < 70: return s, "MODERATE", "yellow"
    if s < 85: return s, "STRONG", C_OK
    return s, "MAXSEC", "bright_green"


def strength_bar(score: int, width: int = 24) -> Text:
    filled = int(score / 100 * width)
    if score < 30: color = C_ERR
    elif score < 50: color = C_WARN
    elif score < 70: color = "yellow"
    elif score < 85: color = C_OK
    else: color = "bright_green"
    t = Text()
    t.append("[" + "#" * filled + "." * (width - filled) + "]", style=color)
    return t

# ── application ──────────────────────────────────────────────────────────────


class VaultTerm:
    def __init__(self):
        self.crypto = Crypto()
        self.meta = Meta(META_PATH)
        self.db: Optional[DB] = None
        self.last_activity = time.monotonic()

    def touch(self):
        self.last_activity = time.monotonic()

    def check_timeout(self):
        if self.db and time.monotonic() - self.last_activity > self.db.auto_lock_seconds:
            if self.db:
                self.db.close()
            clr()
            warn("session locked due to inactivity.")
            sys.exit(0)

    def start(self):
        set_permissions()
        clr(); banner()
        if not self.meta.exists():
            self._init_vault()
        else:
            self._unlock()
        self._expiry_check()

    def _init_vault(self):
        console.print(f"  [{C_WARN}]NO VAULT DETECTED.[/{C_WARN}]")
        console.print(f"  [{C_DIM}]Initialising new encrypted vault at {VAULT_DIR}[/{C_DIM}]\n")
        while True:
            pw = ask_pw("master password")
            if len(pw) < 12:
                err("too short. minimum 12 characters."); continue
            pw2 = ask_pw("confirm master password")
            if pw != pw2:
                err("mismatch. try again."); continue
            dead = ask_pw("deadman password")
            if len(dead) < 12:
                err("deadman password too short. minimum 12 characters."); continue
            dead2 = ask_pw("confirm deadman password")
            if dead != dead2:
                err("deadman mismatch. try again."); continue
            if hmac.compare_digest(pw, dead):
                err("master and deadman passwords must be different."); continue
            sc, label, color = strength(pw)
            console.print("\n  master strength  ", end=""); console.print(strength_bar(sc), end="")
            console.print(f"  [{color}]{label}[/{color}] ({sc}/100)\n")
            if sc < 50 and not Confirm.ask("  weak master password -- continue?", default=False):
                continue
            break
        self.meta.create(pw, dead, self.crypto)
        self.db = DB(DB_PATH, self.crypto)
        self.db.open()
        set_permissions()
        ok("vault initialised.")
        time.sleep(0.5)

    def _unlock(self):
        console.print(f"  [{C_DIM}]vault found at {DB_PATH}[/{C_DIM}]\n")
        md = self.meta.load()
        params = md["kdf"]
        for attempt in range(MAX_ATTEMPTS):
            pw = ask_pw("master password")
            try:
                raw = Crypto.derive(pw, b64d(md["salt"]), params)
                if Crypto.verify_with_raw(raw, md["verify"], SENTINEL, aad_for_meta("verify")) or Crypto.legacy_verify_with_raw(raw, md["verify"], SENTINEL):
                    self.crypto.init_from_raw(raw)
                    try:
                        if Crypto.legacy_verify_with_raw(raw, md["verify"], SENTINEL):
                            self.meta.update_master(b64d(md["salt"]), self.crypto.enc(SENTINEL, aad_for_meta("verify")))
                    except Exception:
                        pass
                    self.db = DB(DB_PATH, self.crypto)
                    self.db.open()
                    ok("access granted.")
                    time.sleep(0.25)
                    self.touch()
                    return
                dead_raw = Crypto.derive(pw, b64d(md["deadman_salt"]), params)
                if Crypto.verify_with_raw(dead_raw, md["deadman_verify"], DEADMAN_SENTINEL, aad_for_meta("deadman_verify")) or Crypto.legacy_verify_with_raw(dead_raw, md["deadman_verify"], DEADMAN_SENTINEL):
                    shred_vault()
                    console.print(f"\n  [{C_ERR}][ERR][/{C_ERR}] database corrupted. unable to recover vault state.\n")
                    sys.exit(2)
            except Exception:
                pass
            left = MAX_ATTEMPTS - attempt - 1
            if left:
                console.print(f"  [{C_ERR}]wrong password. {left} attempt(s) remaining.[/{C_ERR}]")
        err("too many failed attempts. terminating.")
        sys.exit(1)

    def _expiry_check(self):
        expired = [e for e in self.db.get_all_summaries() if e["expired"]]
        if not expired:
            return
        clr(); banner()
        console.print(f"  [{C_WARN}]!! EXPIRY ALERT !! {len(expired)} password(s) not rotated in {self.db.expiry_days}+ days.[/{C_WARN}]\n")
        console.print(self._entry_table(expired))
        pause()

    def run(self):
        self.start()
        while True:
            self.check_timeout()
            clr(); banner(); self._stats(); self._menu(); self.touch()

    def _stats(self):
        entries = self.db.get_all_summaries()
        total = len(entries)
        expired = sum(1 for e in entries if e["expired"])
        ec = C_ERR if expired else C_OK
        console.print(
            f"  [{C_DIM}]entries[/{C_DIM}] [{C_HEAD}]{total:<4}[/{C_HEAD}]  "
            f"[{C_DIM}]expired[/{C_DIM}] [{ec}]{expired:<4}[/{ec}]  "
            f"[{C_DIM}]vault[/{C_DIM}] [{C_OK}]UNLOCKED[/{C_OK}]"
        )
        console.print()

    def _menu(self):
        items = [
            ("1", "LIST",     "display vault entries"),
            ("2", "SEARCH",   "query by name/url/login/notes"),
            ("3", "INJECT",   "add a new entry"),
            ("4", "MODIFY",   "edit an entry"),
            ("5", "PURGE",    "delete an entry"),
            ("6", "GENERATE", "password generator"),
            ("7", "LOG",      "view audit trail"),
            ("8", "REKEY",    "change master password"),
            ("9", "CLONE",    "encrypted vault backup"),
            ("10", "TOTP",    "live TOTP code display"),
            ("11", "HEALTH",  "vault health check"),
            ("12", "SETTINGS","expiry days, auto-lock timeout"),
            ("0",  "EJECT",   "lock and exit"),
        ]
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column("K", width=4); t.add_column("CMD", width=10); t.add_column("DESC")
        for key, cmd, desc in items:
            t.add_row(f"[{C_KEY}][{key}][/{C_KEY}]", f"[{C_HEAD}]{cmd}[/{C_HEAD}]", f"[{C_DIM}]{desc}[/{C_DIM}]")
        console.print(t); console.print()
        choices = ["0","1","2","3","4","5","6","7","8","9","10","11","12"]
        choice = Prompt.ask(f"  [{C_HEAD}]cmd[/{C_HEAD}]", choices=choices, show_choices=False)
        clr()
        dispatch = {
            "1": self.cmd_list,     "2": self.cmd_search,   "3": self.cmd_inject,
            "4": self.cmd_modify,   "5": self.cmd_purge,    "6": self.cmd_generate,
            "7": self.cmd_log,      "8": self.cmd_rekey,    "9": self.cmd_clone,
            "10": self.cmd_totp,    "11": self.cmd_health,  "12": self.cmd_settings,
            "0": self.cmd_eject,
        }
        try:
            dispatch[choice]()
        except KeyboardInterrupt:
            console.print(f"\n  [{C_DIM}]cancelled.[/{C_DIM}]\n")

    def _entry_table(self, entries: List[Dict]) -> Table:
        t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {C_HEAD}", border_style=C_DIM, padding=(0, 2))
        t.add_column("ID", width=5, justify="right"); t.add_column("NAME", min_width=18)
        t.add_column("URL", min_width=22); t.add_column("LOGIN", min_width=18)
        t.add_column("AGE", width=8, justify="right"); t.add_column("2FA", width=5, justify="center"); t.add_column("STATUS", width=14, justify="center")
        for e in entries:
            status = Text("[EXPIRED]", style=f"bold {C_ERR}") if e["expired"] else Text("[ACTIVE]", style=C_OK)
            age_s = Text(f"{e['age']}d", style=C_ERR if e["expired"] else C_DIM)
            t.add_row(Text(str(e["id"]), style=C_DIM), Text(e["name"], style=C_DATA), Text(e.get("url") or "—", style=C_DIM), Text(e["login"], style=C_LABEL), age_s, Text("yes" if e.get("has_totp") else "no", style=C_OK if e.get("has_totp") else C_DIM), status)
        return t

    def cmd_list(self, entries: Optional[List[Dict]] = None, title: str = "VAULT LISTING"):
        if entries is None:
            entries = self.db.get_all_summaries()
        banner(); header(title)
        if not entries:
            inf("vault is empty. use INJECT [3] to add entries."); pause(); return
        console.print(self._entry_table(entries)); console.print(); self._entry_actions(entries)

    def _entry_actions(self, entries: List[Dict]):
        t = Table.grid(padding=(0, 4)); t.add_column(); t.add_column(); t.add_column(); t.add_column(); t.add_column()
        t.add_row(f"[{C_KEY}][C][/{C_KEY}] copy password", f"[{C_KEY}][V][/{C_KEY}] view", f"[{C_KEY}][U][/{C_KEY}] update password", f"[{C_KEY}][T][/{C_KEY}] TOTP", f"[{C_KEY}][B][/{C_KEY}] back")
        console.print(t); console.print()
        act = Prompt.ask(f"  [{C_HEAD}]action[/{C_HEAD}]", choices=["c","C","v","V","u","U","t","T","b","B"], show_choices=False, default="B").upper()
        if act == "C": self._copy(entries)
        elif act == "V": self._view(entries)
        elif act == "U": self._quick_update(entries)
        elif act == "T": self._totp_for(entries)

    def _pick(self, entries: List[Dict], prompt: str = "id") -> Optional[Dict]:
        raw = Prompt.ask(f"  [{C_HEAD}]{prompt}[/{C_HEAD}]")
        try:
            eid = int(raw)
            hit = next((e for e in entries if e["id"] == eid), None)
            if not hit: err(f"no entry with id {eid}.")
            return hit
        except ValueError:
            err("expected a numeric id."); return None

    def _clipboard_allowed(self) -> bool:
        return self.db.setting("clipboard_enabled", "0") == "1"

    def _copy(self, entries: List[Dict]):
        if not self._clipboard_allowed():
            err("clipboard use is disabled. Enable it in SETTINGS only if your local threat model allows it."); pause(); return
        if not _CLIP:
            err("clipboard unavailable. install xclip/xsel/wl-clipboard on Linux."); pause(); return
        e = self._pick(entries, "entry id to copy")
        if not e: pause(); return
        full = self.db.get_full(e["id"])
        pyperclip.copy(full["password"])
        ok(f"password for '{full['name']}' copied to clipboard.")
        console.print(f"  [{C_DIM}]clipboard will be cleared in {CLIPBOARD_CLEAR_SECONDS} seconds.[/{C_DIM}]\n")
        _clip_clear(full["password"]); pause()

    def _view(self, entries: List[Dict]):
        e = self._pick(entries, "entry id to view")
        if not e: pause(); return
        full = self.db.get_full(e["id"])
        sc, label, color = strength(full["password"])
        sep = f"  [{C_DIM}]{'─' * 58}[/{C_DIM}]"
        def row(k, v, vc=C_DATA): console.print(f"  [{C_DIM}]{k:<10}[/{C_DIM}]  [{vc}]{v}[/{vc}]")
        console.print(); console.print(sep)
        row("ID", str(full["id"]), C_DIM); row("NAME", full["name"]); row("URL", full.get("url") or "—", C_DIM)
        row("LOGIN", full["login"], C_LABEL); row("PASSWORD", "[hidden]", C_DIM)
        if Confirm.ask("  reveal password once on screen?", default=False): row("PASSWORD", full["password"], C_PW)
        row("CREATED", local_date(full["created_at"]), C_DIM); row("UPDATED", local_date(full["updated_at"]), C_DIM)
        row("AGE", f"{full['age']} day(s)", C_ERR if full["expired"] else C_DIM)
        if full.get("notes"): row("NOTES", full["notes"], C_DIM)
        if full.get("totp_secret") and pyotp is not None:
            try:
                totp_obj  = pyotp.TOTP(full["totp_secret"])
                remaining = totp_obj.interval - (int(time.time()) % totp_obj.interval)
                code      = totp_obj.now()
                code_color = C_ERR if remaining <= 5 else (C_WARN if remaining <= 10 else C_PW)
                row("TOTP", f"{code}  [{C_DIM}]({remaining}s remaining — use [10] for live display)[/{C_DIM}]", code_color)
                if remaining <= 5:
                    next_code = totp_obj.at(time.time() + remaining + 1)
                    row("TOTP NEXT", next_code, C_WARN)
            except Exception:
                row("TOTP", "[invalid secret]", C_ERR)
        elif full.get("totp_secret"):
            row("TOTP", "configured", C_OK)
        else:
            row("TOTP", "not configured", C_DIM)
        console.print(f"  [{C_DIM}]STRENGTH  [/{C_DIM}]", end=""); console.print(strength_bar(sc), end="")
        console.print(f"  [{color}]{label}[/{color}] ({sc}/100)"); console.print(sep); console.print(); pause()

    def cmd_search(self):
        banner(); header("SEARCH")
        q = Prompt.ask(f"  [{C_HEAD}]query[/{C_HEAD}]")
        results = self.db.search_summaries(q)
        if not results:
            warn(f"no results for: {q}"); pause(); return
        self.cmd_list(results, title=f"SEARCH >> {q} ({len(results)} match(es))")

    def _password_input_flow(self, eid: Optional[int] = None) -> Optional[str]:
        console.print(f"  [{C_KEY}][G][/{C_KEY}] generate   [{C_KEY}][M][/{C_KEY}] manual\n")
        choice = Prompt.ask(f"  [{C_HEAD}]password mode[/{C_HEAD}]", choices=["g","G","m","M"], show_choices=False).upper()
        pw = self._gen_pw() if choice == "G" else self._manual_pw()
        if eid is not None and pw and self.db.password_was_used(eid, pw):
            warn("this password appears in this entry's password history.")
            if not Confirm.ask("  use it anyway?", default=False):
                return None
        return pw

    def cmd_inject(self):
        banner(); header("INJECT -- NEW ENTRY")
        name = Prompt.ask(f"  [{C_HEAD}]name[/{C_HEAD}]")
        url = Prompt.ask(f"  [{C_HEAD}]url[/{C_HEAD}]    [{C_DIM}](optional)[/{C_DIM}]", default="")
        login = Prompt.ask(f"  [{C_HEAD}]login/email[/{C_HEAD}]")
        notes = Prompt.ask(f"  [{C_HEAD}]notes[/{C_HEAD}]  [{C_DIM}](optional)[/{C_DIM}]", default="")
        totp_secret = self._totp_input()
        dupes = self.db.duplicate_hits(name, url, login)
        if dupes:
            warn("possible duplicate entry detected.")
            console.print(self._entry_table(dupes))
            if not Confirm.ask("  continue anyway?", default=False):
                inf("aborted."); pause(); return
        pw = self._password_input_flow()
        if pw is None: pause(); return
        console.print(); console.print(f"  [{C_DIM}]NAME[/{C_DIM}]  {name}")
        console.print(f"  [{C_DIM}]LOGIN[/{C_DIM}] {login}")
        console.print(f"  [{C_DIM}]PASS[/{C_DIM}]  {'*' * len(pw)} ({len(pw)} chars)")
        if Confirm.ask("  commit to vault?", default=True):
            eid = self.db.add(name, url, login, pw, notes, totp_secret.strip().replace(" ", ""))
            ok(f"entry injected. id={eid}")
        else: inf("aborted.")
        pause()

    def cmd_modify(self):
        banner(); header("MODIFY -- EDIT ENTRY")
        entries = self.db.get_all_summaries()
        if not entries: inf("vault is empty."); pause(); return
        console.print(self._entry_table(entries)); console.print()
        e = self._pick(entries, "entry id to modify")
        if not e: pause(); return
        full = self.db.get_full(e["id"])
        console.print(f"\n  modifying [{C_HEAD}]{full['name']}[/{C_HEAD}]")
        console.print(f"  [{C_DIM}](press ENTER to keep current value)[/{C_DIM}]\n")
        updates = {
            "name": Prompt.ask(f"  [{C_HEAD}]name[/{C_HEAD}]", default=full["name"]),
            "url": Prompt.ask(f"  [{C_HEAD}]url[/{C_HEAD}]", default=full.get("url", "")),
            "login": Prompt.ask(f"  [{C_HEAD}]login/email[/{C_HEAD}]", default=full["login"]),
            "notes": Prompt.ask(f"  [{C_HEAD}]notes[/{C_HEAD}]", default=full.get("notes", "")),
        }
        if Confirm.ask("  edit TOTP secret?", default=False):
            updates["totp_secret"] = self._totp_input(current=full.get("totp_secret", ""))
        console.print(f"\n  [{C_KEY}][K][/{C_KEY}] keep password   [{C_KEY}][G][/{C_KEY}] generate   [{C_KEY}][M][/{C_KEY}] manual\n")
        mode = Prompt.ask(f"  [{C_HEAD}]password[/{C_HEAD}]", choices=["k","K","g","G","m","M"], show_choices=False).upper()
        if mode == "G": updates["password"] = self._gen_pw(e["id"])
        elif mode == "M":
            pw = self._manual_pw()
            if pw and self.db.password_was_used(e["id"], pw):
                warn("this password appears in this entry's password history.")
                if Confirm.ask("  use it anyway?", default=False): updates["password"] = pw
            elif pw: updates["password"] = pw
        self.db.update(e["id"], **updates)
        ok(f"entry {e['id']} modified."); pause()

    def _quick_update(self, entries: List[Dict]):
        e = self._pick(entries, "entry id to update password")
        if not e: pause(); return
        pw = self._password_input_flow(e["id"])
        if pw is None: pause(); return
        self.db.update(e["id"], password=pw)
        ok(f"password updated for '{e['name']}'."); pause()

    def cmd_purge(self):
        banner(); header("PURGE -- DELETE ENTRY")
        entries = self.db.get_all_summaries()
        if not entries: inf("vault is empty."); pause(); return
        console.print(self._entry_table(entries)); console.print()
        e = self._pick(entries, "entry id to purge")
        if not e: pause(); return
        console.print(f"\n  [{C_ERR}]target: {e['name']} ({e['login']})[/{C_ERR}]")
        if Confirm.ask("  confirm purge?", default=False):
            self.db.delete(e["id"]); ok(f"entry {e['id']} purged.")
        else: inf("aborted.")
        pause()

    def _profile_prompt(self) -> str:
        console.print(f"  [{C_KEY}][1][/{C_KEY}] maximum compatibility")
        console.print(f"  [{C_KEY}][2][/{C_KEY}] no symbols")
        console.print(f"  [{C_KEY}][3][/{C_KEY}] PIN")
        console.print(f"  [{C_KEY}][4][/{C_KEY}] passphrase")
        console.print(f"  [{C_KEY}][5][/{C_KEY}] high entropy\n")
        choice = Prompt.ask(f"  [{C_HEAD}]profile[/{C_HEAD}]", choices=["1","2","3","4","5"], default="5", show_choices=False)
        return {"1":"compat", "2":"no_symbols", "3":"pin", "4":"passphrase", "5":"high"}[choice]

    def _gen_pw(self, eid: Optional[int] = None) -> str:
        while True:
            profile = self._profile_prompt()
            if profile == "passphrase":
                raw = Prompt.ask(f"  [{C_HEAD}]words[/{C_HEAD}]", default="5")
                try: words = int(raw)
                except ValueError: words = 5
                pw = gen_passphrase(words)
            else:
                raw = Prompt.ask(f"  [{C_HEAD}]length[/{C_HEAD}] [{C_DIM}]({PW_MIN_LEN}-{PW_MAX_LEN})[/{C_DIM}]", default="24")
                try: length = int(raw)
                except ValueError: length = 24
                pw = gen_pw(length, profile)
            sc, label, color = strength(pw)
            console.print(f"\n  [{C_DIM}]generated  [/{C_DIM}][{C_DIM}][hidden: {len(pw)} chars][/{C_DIM}]")
            if Confirm.ask("  reveal generated password once?", default=False):
                console.print(f"  [{C_DIM}]value      [/{C_DIM}][{C_PW}]{pw}[/{C_PW}]")
            console.print(f"  [{C_DIM}]strength   [/{C_DIM}]", end=""); console.print(strength_bar(sc), end="")
            console.print(f"  [{color}]{label}[/{color}] ({sc}/100)\n")
            if eid is not None and self.db.password_was_used(eid, pw):
                warn("generated password appears in this entry's history; regenerating is recommended.")
            if Confirm.ask("  use this password?", default=True):
                return pw

    def _manual_pw(self) -> Optional[str]:
        while True:
            p1 = ask_pw("new password")
            p2 = ask_pw("confirm password")
            if p1 != p2:
                err("mismatch."); continue
            sc, label, color = strength(p1)
            console.print(f"\n  [{C_DIM}]strength   [/{C_DIM}]", end=""); console.print(strength_bar(sc), end="")
            console.print(f"  [{color}]{label}[/{color}] ({sc}/100)\n")
            if sc < 30 and not Confirm.ask("  very weak -- continue?", default=False):
                continue
            return p1

    def cmd_generate(self):
        banner(); header("GENERATE -- STANDALONE")
        while True:
            pw = self._gen_pw()
            if self._clipboard_allowed() and _CLIP and Confirm.ask("  copy to clipboard?", default=False):
                pyperclip.copy(pw); ok(f"copied. clears in {CLIPBOARD_CLEAR_SECONDS} seconds."); _clip_clear(pw)
            if not Confirm.ask("  generate another?", default=False): break
        pause()

    def _totp_input(self, current: str = "") -> str:
        """Prompt for a TOTP base32 secret, validate it, and return the cleaned value.
        Returns empty string if the user skips or enters an invalid secret."""
        while True:
            prompt_default = current if current else ""
            raw = Prompt.ask(
                f"  [{C_HEAD}]totp secret[/{C_HEAD}] [{C_DIM}](base32 from QR code, ENTER to skip)[/{C_DIM}]",
                default=prompt_default,
            ).strip().replace(" ", "").upper()

            if not raw:
                return ""   # user skipped

            if pyotp is None:
                warn("pyotp not installed — secret stored without validation.")
                return raw

            try:
                totp_obj = pyotp.TOTP(raw)
                code     = totp_obj.now()
                ok(f"TOTP validated.  current code: [{C_PW}]{code}[/{C_PW}]")
                return raw
            except Exception:
                err("invalid TOTP secret. must be a valid base32 string.")
                if not Confirm.ask("  try again?", default=True):
                    return current   # keep old value unchanged

    def cmd_totp(self):
        banner(); header("TOTP -- LIVE CODE")
        entries = [e for e in self.db.get_all_summaries() if e.get("has_totp")]
        if not entries:
            inf("no entries with TOTP configured."); pause(); return
        console.print(self._entry_table(entries)); console.print()
        self._totp_for(entries)

    def _totp_for(self, entries: List[Dict]):
        if pyotp is None:
            err("pyotp unavailable. run install.sh again."); pause(); return
        e = self._pick(entries, "entry id for TOTP")
        if not e: pause(); return
        full = self.db.get_full(e["id"])
        if not full.get("totp_secret"):
            warn("entry has no TOTP secret."); pause(); return
        try:
            totp_obj = pyotp.TOTP(full["totp_secret"])
            totp_obj.now()   # validate secret is usable
        except Exception:
            err("invalid TOTP secret stored for this entry."); pause(); return

        self._totp_live(totp_obj, full["name"])

    def _totp_live(self, totp_obj, name: str):
        """
        Cross-platform live TOTP display.
        A background thread watches stdin for Enter; the main thread renders
        the code + countdown bar every 0.5 s using raw ANSI escapes so that
        Rich's buffering never gets in the way of the \\r overwrite.
        """
        interval = totp_obj.interval   # 30 s for standard TOTP

        # ── background stdin watcher (cross-platform: no select.select) ──────
        _stop = threading.Event()
        def _stdin_watcher():
            try:
                sys.stdin.readline()
            except Exception:
                pass
            _stop.set()
        threading.Thread(target=_stdin_watcher, daemon=True).start()

        # ── ANSI codes (work on Linux, macOS, and modern Windows terminals) ──
        _CYAN  = "\033[96m";  _BOLD  = "\033[1m"
        _GREEN = "\033[92m";  _YELLOW= "\033[93m"
        _RED   = "\033[91m";  _DIM   = "\033[2m"
        _RESET = "\033[0m"

        console.print(
            f"\n  [{C_DIM}]live TOTP for[/{C_DIM}] [{C_HEAD}]{name}[/{C_HEAD}]"
            f"  [{C_DIM}]-- press ENTER to exit[/{C_DIM}]\n"
        )

        BAR_WIDTH = 30
        last_code = None
        try:
            while not _stop.is_set():
                ts        = int(time.time())
                remaining = interval - (ts % interval)
                code      = totp_obj.now()

                # Bar depletes left→right as the window runs out
                filled = int((remaining / interval) * BAR_WIDTH)
                bar    = "[" + "#" * filled + "." * (BAR_WIDTH - filled) + "]"

                if remaining <= 5:
                    bar_col = _RED
                    try:
                        next_code  = totp_obj.at(time.time() + remaining + 1)
                        next_label = f"  {_YELLOW}next: {_BOLD}{next_code}{_RESET}"
                    except Exception:
                        next_label = ""
                elif remaining <= 10:
                    bar_col    = _YELLOW
                    next_label = ""
                else:
                    bar_col    = _GREEN
                    next_label = ""

                # Flash the code text whenever it changes
                code_style = _BOLD + (_RED if remaining <= 5 else _CYAN)

                line = (
                    f"\r  {code_style}{code}{_RESET}"
                    f"  {bar_col}{bar}{_RESET}"
                    f"  {_DIM}{remaining:2d}s{_RESET}"
                    f"{next_label}   "
                )
                sys.stdout.write(line)
                sys.stdout.flush()

                last_code = code
                _stop.wait(timeout=0.5)

        except KeyboardInterrupt:
            _stop.set()

        sys.stdout.write("\n")
        sys.stdout.flush()
        console.print()

        # Offer clipboard copy of the last displayed code
        if last_code and self._clipboard_allowed() and _CLIP:
            if Confirm.ask(f"  copy [{last_code}] to clipboard?", default=False):
                pyperclip.copy(last_code)
                _clip_clear(last_code)
                ok("code copied.")
        pause()

    def cmd_log(self):
        banner(); header("AUDIT LOG")
        logs = self.db.get_log(80)
        if not logs: inf("no log entries."); pause(); return
        t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {C_HEAD}", border_style=C_DIM, padding=(0, 2))
        t.add_column("TIMESTAMP", width=22); t.add_column("ACTION", width=8); t.add_column("ID", width=5, justify="right")
        colors = {"ADD": C_OK, "EDIT": C_WARN, "PURGE": C_ERR, "REKEY": "magenta"}
        for lg in logs:
            c = colors.get(lg["action"], C_DIM)
            t.add_row(Text(local_date(lg["ts"]), style=C_DIM), Text(lg["action"], style=c), Text(str(lg["entry_id"] or "—"), style=C_DIM))
        console.print(t); pause()

    def cmd_rekey(self):
        banner(); header("REKEY -- CHANGE MASTER PASSWORD")
        cur = ask_pw("current master password")
        md = self.meta.load()
        try:
            raw = Crypto.derive(cur, b64d(md["salt"]), md["kdf"])
            if not (Crypto.verify_with_raw(raw, md["verify"], SENTINEL, aad_for_meta("verify")) or Crypto.legacy_verify_with_raw(raw, md["verify"], SENTINEL)):
                err("authentication failed."); pause(); return
        except Exception:
            err("authentication failed."); pause(); return
        while True:
            new = ask_pw("new master password")
            if len(new) < 12: err("too short."); continue
            new2 = ask_pw("confirm new master password")
            if new != new2: err("mismatch."); continue
            sc, label, color = strength(new)
            console.print(f"\n  strength  ", end=""); console.print(strength_bar(sc), end=""); console.print(f"  [{color}]{label}[/{color}] ({sc}/100)\n")
            if sc < 50 and not Confirm.ask("  weak password -- continue?", default=False): continue
            break
        if not Confirm.ask("  atomically re-encrypt vault with new key?", default=True):
            inf("aborted."); pause(); return
        new_salt = os.urandom(ARGON2_PARAMS["salt_len"])
        new_crypto = Crypto(); new_crypto.init(new, new_salt, md["kdf"])
        try:
            self.db.reencrypt_atomic(new_crypto, new_salt, self.meta)
            self.crypto = new_crypto; self.db.crypto = self.crypto
            ok("vault re-keyed atomically.")
        except Exception as ex:
            err(f"rekey failed and was rolled back: {ex}")
        pause()

    def cmd_clone(self):
        banner(); header("CLONE -- BACKUP")
        secure_mkdir(BACKUP_DIR)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = BACKUP_DIR / f"vaultterm_{ts}.tar.gz"
        with tarfile.open(out, "w:gz") as tar:
            if DB_PATH.exists(): tar.add(DB_PATH, arcname="vault.db")
            if META_PATH.exists(): tar.add(META_PATH, arcname="meta.json")
        secure_file(out)
        ok(f"backup written:\n  {out}")
        warn("keep this archive safe. it contains encrypted vault material and metadata.")
        pause()

    def cmd_health(self):
        banner(); header("HEALTH CHECK")
        h = self.db.health()
        backup_files = sorted(BACKUP_DIR.glob("*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True) if BACKUP_DIR.exists() else []
        newest_backup_age = None
        if backup_files:
            newest_backup_age = int((time.time() - backup_files[0].stat().st_mtime) // 86400)
        checks = [
            ("DB readable", h["db_readable"]), ("Entries decryptable", h["decryptable"]),
            ("Vault dir permission 0700", self._perm_ok(VAULT_DIR, 0o700)),
            ("DB permission 0600", self._perm_ok(DB_PATH, 0o600)), ("Meta permission 0600", self._perm_ok(META_PATH, 0o600)),
        ]
        t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {C_HEAD}", border_style=C_DIM, padding=(0, 2))
        t.add_column("CHECK"); t.add_column("STATUS", justify="center")
        for name, passed in checks:
            t.add_row(name, Text("OK" if passed else "FAIL", style=C_OK if passed else C_ERR))
        console.print(t); console.print()
        console.print(f"  [{C_DIM}]entries[/{C_DIM}]          {h['entries']}")
        console.print(f"  [{C_DIM}]weak passwords[/{C_DIM}]   {h['weak']}")
        console.print(f"  [{C_DIM}]expired[/{C_DIM}]          {h['expired']}")
        console.print(f"  [{C_DIM}]reused hashes[/{C_DIM}]    {h['reused_hashes']}")
        console.print(f"  [{C_DIM}]latest backup[/{C_DIM}]    {str(newest_backup_age) + ' day(s) old' if newest_backup_age is not None else 'none'}")
        pause()

    def _perm_ok(self, path: Path, expected: int) -> bool:
        if os.name == "nt": return True
        try: return (path.stat().st_mode & 0o777) == expected
        except Exception: return False

    def cmd_settings(self):
        banner(); header("SETTINGS")

        cur_expiry = self.db.setting("expiry_days",       str(EXPIRY_DAYS))
        cur_lock   = self.db.setting("auto_lock_minutes", "10")
        cur_clip   = self.db.setting("clipboard_enabled", "0")

        console.print(f"  [{C_DIM}]expiry_days       [/{C_DIM}]  [{C_DATA}]{cur_expiry}[/{C_DATA}]"
                      f"  [{C_DIM}]days before a password is flagged [EXPIRED][/{C_DIM}]")
        console.print(f"  [{C_DIM}]auto_lock_minutes [/{C_DIM}]  [{C_DATA}]{cur_lock}[/{C_DATA}]"
                      f"  [{C_DIM}]minutes of inactivity before lock (0 = disabled)[/{C_DIM}]")
        console.print(f"  [{C_DIM}]clipboard_enabled [/{C_DIM}]  [{C_DATA}]{cur_clip}[/{C_DATA}]"
                      f"  [{C_DIM}]0 = disabled, 1 = enabled[/{C_DIM}]\n")

        new_expiry = Prompt.ask(f"  [{C_HEAD}]expiry_days[/{C_HEAD}]",       default=cur_expiry)
        new_lock   = Prompt.ask(f"  [{C_HEAD}]auto_lock_minutes[/{C_HEAD}]", default=cur_lock)
        new_clip   = Prompt.ask(f"  [{C_HEAD}]clipboard_enabled[/{C_HEAD}]", default=cur_clip, choices=["0", "1"], show_choices=False)

        errors = []
        try:
            ed = int(new_expiry)
            if ed < 1: raise ValueError
        except ValueError:
            errors.append("expiry_days must be a positive integer.")
            ed = int(cur_expiry)

        try:
            lm = int(new_lock)
            if lm < 0: raise ValueError
        except ValueError:
            errors.append("auto_lock_minutes must be 0 or a positive integer.")
            lm = int(cur_lock)

        for e in errors:
            err(e)

        if not errors or Confirm.ask("  save valid values anyway?", default=False):
            self.db.set_setting("expiry_days",       str(ed))
            self.db.set_setting("auto_lock_minutes", str(lm))
            self.db.set_setting("clipboard_enabled", new_clip)
            ok("settings saved.")

        pause()

    def cmd_eject(self):
        if self.db: self.db.close()
        clr(); console.print(); console.print(f"[{C_HEAD}]{'=' * (console.width or 72)}[/{C_HEAD}]")
        console.print(f"[{C_HEAD}]  VAULT LOCKED  //  SESSION TERMINATED[/{C_HEAD}]")
        console.print(f"[{C_HEAD}]{'=' * (console.width or 72)}[/{C_HEAD}]"); console.print(); sys.exit(0)


def main():
    try:
        VaultTerm().run()
    except KeyboardInterrupt:
        console.print(f"\n\n  [{C_DIM}]interrupted -- vault locked.[/{C_DIM}]\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
    
