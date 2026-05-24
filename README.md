# VaultTerm

```
=========================================================================
  VAULTTERM v3.0  //  ChaCha20-Poly1305  //  Argon2id  //  LOCAL
=========================================================================
```

A terminal password manager that keeps everything local and encrypted.
No cloud, no accounts, no telemetry. One Python file, one SQLite database.

---

## Security model

| Layer | Choice | Why |
|---|---|---|
| Cipher | ChaCha20-Poly1305 | Authenticated encryption. Every field gets a fresh 12-byte random nonce on each write. |
| KDF | Argon2id (256 MB, t=3, p=2) | Memory-hard. Raises the cost of GPU/ASIC brute-force against the master password. |
| Key split | 64-byte Argon2id output → `enc_key[:32]` + `hash_key[32:]` | Encryption and HMAC operations never share a key. |
| Scope | Field-level | `name`, `url`, `login`, `password`, `notes`, `totp_secret` each carry their own nonce. |
| AAD | `vaultterm\|schema=4\|entry\|{uuid}\|field\|{field}` | Every ciphertext is domain-bound to the schema version, the specific entry UUID, and the field name. A token from one entry or field cannot be replayed to another. |
| Password history | HMAC-SHA256 keyed with `hash_key` | Prior passwords are stored as keyed hashes — reuse detection without exposing plaintext. |
| File permissions | `0700` (vault dir) · `0600` (db, meta, backups) | Enforced on Linux and macOS. Best-effort `icacls` ACL hardening on Windows (not a substitute for a hardened host). |
| Deadman | Independent Argon2id derivation + independent sentinel | Triggers silently at login. Shreds the vault and exits with a fake corruption message. |

Nothing leaves the machine.

---

## What is stored in plaintext

- Audit log: action codes (`ADD`, `EDIT`, `PURGE`, `REKEY`) and entry IDs only
- The `has_totp` flag (0 or 1) per entry — the list view needs it to show the 2FA column without decrypting
- Timestamps (`created_at`, `updated_at`) in UTC ISO 8601

Everything else — name, URL, login, password, notes, TOTP secret — is an encrypted blob.

---

## Requirements

- Python 3.10+
- Linux, macOS, or Windows
- Clipboard support on Linux requires `xclip`, `xsel`, or `wl-clipboard`

---

## Installation

```bash
git clone https://github.com/you/vaultterm
cd vaultterm
chmod +x install.sh start.sh
./install.sh
```

`install.sh` creates a `.venv` virtual environment and installs all five dependencies from `requirements.txt`. Nothing touches your system Python.

---

## Running

```bash
./start.sh
```

### First run

You will be asked to set two passwords before the vault is created.

**Master password** — unlocks the vault normally. Minimum 12 characters.

**Deadman password** — if entered at the login prompt, silently destroys the entire vault and exits with a fake error. Must differ from the master password. Also minimum 12 characters. There is no skip option — both passwords are required.

---

## Menu

```
[1]  LIST      display vault entries (passwords never shown in list)
[2]  SEARCH    query by name, url, login, or notes
[3]  INJECT    add a new entry
[4]  MODIFY    edit an entry
[5]  PURGE     permanently delete an entry
[6]  GENERATE  password generator
[7]  LOG       view audit trail
[8]  REKEY     change master password and re-encrypt vault
[9]  CLONE     create encrypted backup archive
[10] TOTP      live TOTP code display with countdown
[11] HEALTH    vault health and security report
[12] SETTINGS  configure expiry threshold, auto-lock timeout, and clipboard
[0]  EJECT     lock vault and exit
```

Pressing `Ctrl+C` inside any command cancels it and returns to this menu. It does not exit the application.

---

## Entry fields

| Field | Required | Encrypted |
|---|---|---|
| name | yes | yes |
| url | no | yes |
| login | yes | yes |
| password | yes | yes |
| notes | no | yes |
| totp_secret | no | yes |

---

## Password list — lazy decryption

`LIST` and `SEARCH` decrypt `name`, `url`, and `login` for display. The `password` and `notes` fields are **never decrypted** during list or search operations — the password column is not present in the table at all. A full decrypt of a single entry only happens when you explicitly choose `[V] view` or `[C] copy password`.

---

## Copying a password

Clipboard access is **disabled by default** and must be explicitly enabled in `[12] SETTINGS` (`clipboard_enabled = 1`). This is a deliberate security default — only enable it if your local threat model permits clipboard use.

Once enabled, press `[C]` from the list view and enter the entry ID. The password is decrypted, sent to the clipboard, and **never printed to the terminal**. The clipboard is automatically cleared after 30 seconds.

---

## TOTP

### How it works

TOTP (RFC 6238) uses a shared secret and the current time — no server contact required. Both VaultTerm and the remote service independently compute `HMAC-SHA1(secret, floor(unix_time / 30))`, truncate it to six digits, and compare. The code changes every 30 seconds because the time counter increments.

### Adding a TOTP secret

During `INJECT` or `MODIFY`, paste the base32 string from your authenticator app's QR code (most apps let you reveal it as plain text). VaultTerm validates the secret immediately by generating the current code and displaying it so you can cross-check against your phone before the entry is saved.

### Live display — `[10] TOTP`

```
  681289  [##########################....]  4s
```

The display updates every 0.5 seconds. The progress bar shows remaining time as a filled segment that shrinks from right to left as the 30-second window drains:

- Bar **green**, code **cyan** when time is comfortable
- Bar **yellow** when ≤ 10 seconds remain
- Bar **red**, code **red** when ≤ 5 seconds remain — the **next** code appears in yellow so you have it ready before the current one expires

Press `Enter` to exit the live display. If clipboard is enabled, the last visible code can be optionally copied to clipboard before returning to the menu.

`[T]` in the list action bar triggers the same live display for any entry with a TOTP secret.

### TOTP in the entry view

`[V] view` shows the current code and seconds remaining as a snapshot. For the live ticker, use `[10] TOTP` or `[T]` from the list.

---

## Password generator — `[6] GENERATE`

Five profiles:

| Profile | Charset | Length |
|---|---|---|
| `high` | `a-z A-Z 0-9` + full symbol set | 16–96 |
| `compat` | `a-z A-Z 0-9` + reduced symbols (`!@#$%*-_=+?`) | 16–96 |
| `no_symbols` | `a-z A-Z 0-9` | 16–96 |
| `pin` | digits only | 4–8 |
| `passphrase` | random words joined by hyphens + 4-digit suffix | 4–8 words |

All profiles except PIN guarantee at least one character from each applicable character class before filling the rest randomly. The generator loops until you accept — no recursion depth risk.

The same generator is available inside `INJECT` and `MODIFY`.

---

## Password expiry

Passwords not changed within the configured threshold are flagged `[EXPIRED]` in the list and trigger an alert on every login. The default is 30 days. You are never forced to rotate — expiry is advisory only.

The threshold is configurable per vault via `[12] SETTINGS`.

---

## Password history

Every password change pushes the previous password's HMAC-SHA256 hash to a history table. When you set a new password, VaultTerm checks whether that exact value has been used before for the same entry. The check uses constant-time HMAC comparison — no plaintext is ever stored in history or compared directly.

**History is cleared on master password change (rekey)** because the HMAC hashes are bound to the `hash_key` derived from the old master password. They cannot be compared against new passwords without storing the original plaintexts, which VaultTerm does not do.

---

## Search

`[2] SEARCH` queries name, URL, login, and notes. Notes are only decrypted for entries that did not already match on the cheaper fields, so the common case pays no extra cost.

---

## Changing the master password — `[8] REKEY`

Re-encryption is atomic. All row updates run inside a single `BEGIN IMMEDIATE` transaction. The meta file is only written after the database commits successfully. During the meta file update, a `.json.bak` copy of the previous meta is kept as a recovery fallback — if the meta write fails, the backup is restored automatically so the vault is never left in a split-key state. If anything fails mid-operation, the database rolls back and the meta file is untouched — the vault is either fully re-encrypted under the new key or entirely unchanged under the old one.

---

## Deadman password

If the deadman password is entered at the login prompt:

1. The vault directory (`~/.vaultterm/`) is shredded: each file is overwritten with random bytes three times before deletion.
2. All backup archives in `~/.vaultterm/backups/` are also shredded.
3. The application exits with the message: `database corrupted. unable to recover vault state.`

No output distinguishes a deadman trigger from a genuine corruption error. The master password is always checked first; the deadman is only checked if the master fails. The resulting timing difference (one vs. two Argon2id derivations, roughly 0.5–2 seconds) is not meaningful in the coercion scenario this feature is designed for.

> **SSD caveat.** Overwrite-based shredding is unreliable on journaling filesystems (ext4, NTFS), copy-on-write filesystems (APFS, Btrfs, ZFS), and any SSD or NVMe drive with wear-levelling or over-provisioning. The OS or hardware may redirect overwrite writes to new physical blocks, leaving the original data recoverable elsewhere on the medium. For reliable physical deniability, full-disk encryption (LUKS, FileVault, BitLocker) is the appropriate layer.

---

## Backups — `[9] CLONE`

Creates a `.tar.gz` archive of `vault.db` and `meta.json` inside `~/.vaultterm/backups/`, timestamped and set to `0600`. After writing, the archive is immediately re-opened and verified — if the file is unreadable or empty, an error is reported before claiming success. Both files are required to restore — the database without the meta file cannot be decrypted.

To restore: extract both files into `~/.vaultterm/` and launch normally.

---

## Auto-lock

The session locks after a configurable period of inactivity (default 10 minutes). The check fires at the start of each menu loop — it does not interrupt you mid-input. When triggered, the database connection is closed and re-authentication is required without restarting the application. Set to `0` to disable.

---

## Health check — `[11] HEALTH`

| Check | What it verifies |
|---|---|
| DB readable | SQLite file opens without error |
| Entries decryptable | Every entry decrypts successfully |
| Vault dir permission | `~/.vaultterm` is `0700` |
| DB permission | `vault.db` is `0600` |
| Meta permission | `meta.json` is `0600` |
| Weak passwords | Entries with a strength score below 50 |
| Expired passwords | Entries past the configured expiry threshold |
| Reused password hashes | Entries sharing an identical password |
| Latest backup age | Days since the most recent backup archive |

---

## Settings — `[12] SETTINGS`

Stored in the `settings` table inside `vault.db`. Persist across sessions. Applied immediately without restart.

| Key | Default | Description |
|---|---|---|
| `expiry_days` | `30` | Days before a password is flagged `[EXPIRED]`. Minimum 1. |
| `auto_lock_minutes` | `10` | Minutes of inactivity before the session locks. Set to `0` to disable. |
| `clipboard_enabled` | `0` | Enables clipboard operations (`[C] copy`, TOTP copy). `0` = disabled, `1` = enabled. Disabled by default — only enable if your threat model permits it. |

---

## Vault structure

```
~/.vaultterm/
├── meta.json          (0600)  KDF parameters, salts, verify tokens
├── vault.db           (0600)  Encrypted SQLite database
└── backups/
    └── vaultterm_YYYYMMDD_HHMMSS.tar.gz   (0600)
```

### `meta.json`

```json
{
  "version": "3.0",
  "schema_version": 4,
  "cipher": "ChaCha20Poly1305",
  "kdf": {
    "type": "argon2id",
    "time_cost": 3,
    "memory_cost": 262144,
    "parallelism": 2,
    "hash_len": 64,
    "salt_len": 32
  },
  "salt": "<base64url>",
  "deadman_salt": "<base64url>",
  "verify": "<base64url(nonce[12] | ciphertext_with_tag)>",
  "deadman_verify": "<base64url(nonce[12] | ciphertext_with_tag)>",
  "created_at": "2025-01-01T00:00:00+00:00",
  "updated_at": "2025-01-01T00:00:00+00:00"
}
```

`verify` holds the string `VAULTTERM::ONLINE::v3` encrypted with the master key. `deadman_verify` holds `VAULTTERM::DEADMAN::v3` encrypted with the deadman key. They use different salts, different derived keys, and different sentinel strings — a master key cannot decrypt a deadman token and vice versa.

### SQLite tables

```
entries          one row per credential; all sensitive columns are encrypted blobs
password_history HMAC-SHA256 hashes of previous passwords per entry (no plaintext)
log              action code + entry ID only; no sensitive content; last 80 entries shown
settings         per-vault key/value configuration
```

---

## Dependencies

```
rich>=13.7.0         terminal UI
cryptography>=42.0.0 ChaCha20-Poly1305
argon2-cffi>=23.1.0  Argon2id key derivation
pyotp>=2.9.0         TOTP generation and validation
pyperclip>=1.8.2     clipboard integration
```

All installed into `.venv` by `install.sh`. No system-wide installation.

---

## Known limitations

- **SSD shredding is not guaranteed.** Overwrite-based deletion is unreliable on journaling and copy-on-write filesystems and any SSD with wear-levelling. Full-disk encryption is the only reliable mitigation.
- **Clipboard is disabled by default.** It must be explicitly enabled in `[12] SETTINGS`. Once enabled, passwords are cleared from the clipboard automatically after 30 seconds, but this relies on `pyperclip` being able to read the current clipboard contents — it may not work in all environments.
- **Password history is cleared on rekey.** HMAC hashes are key-bound and cannot survive a master password change without storing plaintext.
- **Windows clipboard auto-clear** may not work without a compatible clipboard utility installed.
- **Auto-lock fires at menu boundaries**, not mid-input. It does not interrupt active typing.

---

## License

The Unlicense
