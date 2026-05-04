# VaultTerm

```
=========================================================================
  VAULTTERM v3.0  //  ChaCha20-Poly1305  //  Argon2id  //  LOCAL
=========================================================================
```

A terminal password manager built for people who don't trust clouds. All data lives in an encrypted SQLite database on your machine. No sync, no accounts, no telemetry.

---

## Security model

| Layer | Choice | Why |
|---|---|---|
| Cipher | ChaCha20-Poly1305 | Authenticated encryption. Each field gets a fresh random 12-byte nonce. |
| KDF | Argon2id (256 MB, t=3, p=2) | Memory-hard. Resists GPU and ASIC brute-force against the master password. |
| Key split | 64-byte KDF output → `enc_key[:32]` + `hash_key[32:]` | Encryption and HMAC operations never share the same key. |
| Scope | Field-level encryption | `name`, `url`, `login`, `password`, `notes`, `totp_secret` are each encrypted independently with their own nonce. |
| AAD | `b"vaultterm-v3"` | Domain-binds every ciphertext. A token from one version can't be replayed into another context. |
| Password history | HMAC-SHA256 (hash_key) | Old passwords are stored as keyed hashes, not plaintext. Reuse detection without exposing prior passwords. |
| File permissions | `0700` (vault dir) · `0600` (db, meta, backups) | On Linux and macOS only. Windows is not enforced. |
| Deadman | Separate Argon2id derivation, separate sentinel | Triggered at login. Shreds vault silently and exits with a fake corruption error. |

Nothing leaves the machine. No network calls are made.

---

## What is stored in plaintext

- Audit log action codes (`ADD`, `EDIT`, `PURGE`, `REKEY`) and entry IDs
- The `has_totp` flag (0 or 1) per entry, so the list view can show the OTP column without decrypting
- Timestamps (`created_at`, `updated_at`) in UTC ISO format

Everything else is an encrypted blob.

---

## Requirements

- Python 3.10 or newer
- Linux, macOS, or Windows (clipboard auto-clear requires `xclip`, `xsel`, or `wl-clipboard` on Linux)

---

## Installation

```bash
git clone https://github.com/you/vaultterm
cd vaultterm
chmod +x install.sh start.sh
./install.sh
```

`install.sh` creates a `.venv` virtual environment and installs all dependencies from `requirements.txt`. It does not touch your system Python.

---

## Usage

```bash
./start.sh
```

On first run you will be asked to set two passwords.

**Master password** unlocks the vault normally. Minimum 12 characters.

**Deadman password** triggers silent vault destruction if entered at the login prompt. It must differ from the master password. Also minimum 12 characters. There is no skip — both are required.

After setup, the main menu:

```
[1] LIST      display vault entries
[2] SEARCH    query by name/url/login
[3] INJECT    add a new entry
[4] MODIFY    edit an entry
[5] PURGE     delete an entry
[6] GENERATE  password generator
[7] LOG       view audit trail
[8] REKEY     change master password
[9] CLONE     encrypted vault backup
[10] TOTP     generate TOTP code
[11] HEALTH   vault health check
[0] EJECT     lock and exit
```

---

## Password generator profiles

| Profile | Description |
|---|---|
| `high` | Full charset (`a-z A-Z 0-9` + symbols), 16–96 chars. Default. |
| `compat` | Letters, digits, and a reduced symbol set (`!@#$%*-_=+?`). For sites with strict rules. |
| `no_symbols` | Letters and digits only. |
| `pin` | Numeric only, 4–8 digits. |
| `passphrase` | Random words joined by hyphens with a 4-digit suffix. Human-readable, still strong. |

The generator loops until you accept — no recursion, no stack depth issues.

---

## Expiry

Passwords not changed in 30 days are flagged `[EXPIRED]` in the list view. On every login, an expiry alert is shown listing all affected entries. You are never forced to update them.

---

## TOTP

Store a TOTP secret (base32, the string behind a QR code) per entry. VaultTerm validates it on entry and can display the live 6-digit code with a countdown. The secret is encrypted like every other sensitive field.

---

## Password history

Every password change pushes the old password's HMAC hash to a history table. When setting a new password, VaultTerm checks whether it has been used before for that entry. The check uses keyed HMAC comparison — no plaintext is stored or compared.

History is cleared on master password change (rekey), because the HMAC hashes are bound to the old `hash_key` and cannot be re-derived.

---

## Changing the master password

```
[8] REKEY → [M] change master password
```

Re-encryption is atomic. The operation wraps every row update in a single `BEGIN IMMEDIATE` transaction. If anything fails, the database is rolled back to the previous state and the meta file is not touched. Either the entire vault is re-encrypted or nothing changes.

---

## Deadman password

If you enter the deadman password at the login prompt instead of the master password:

1. The vault directory (`~/.vaultterm/`) is shredded: each file is overwritten with random bytes three times, then deleted.
2. Any backup archives found in `~/.vaultterm/backups/` are also shredded.
3. The application exits with a fake error message: `database corrupted. unable to recover vault state.`

No output distinguishes a deadman trigger from a database error. The attacker sees the same thing either way.

> Note: Overwrite-based shredding is best-effort on SSDs due to wear leveling and flash translation layers. For full deniability on SSDs, full-disk encryption (LUKS, FileVault, BitLocker) is the correct layer.

---

## Backups

```
[9] CLONE
```

Creates a `.tar.gz` archive containing `vault.db` and `meta.json` inside `~/.vaultterm/backups/`. Both files are required to restore. The archive is set to `0600`.

To restore, place both files back in `~/.vaultterm/` and launch normally.

---

## Health check

```
[11] HEALTH
```

Checks and reports on:

- Database readability
- Full decryptability of all entries
- File permissions (`0700` / `0600`)
- Weak passwords (strength score < 50)
- Reused passwords (same hash across entries)
- Expired passwords
- Backup age

---

## Vault structure

```
~/.vaultterm/
├── meta.json       # KDF parameters, salts, verify tokens (0600)
├── vault.db        # Encrypted SQLite database (0600)
└── backups/
    └── vaultterm_YYYYMMDD_HHMMSS.tar.gz   (0600)
```

### `meta.json` fields

```json
{
  "version": "3.0",
  "schema_version": 3,
  "cipher": "ChaCha20Poly1305",
  "kdf": { "type": "argon2id", "time_cost": 3, "memory_cost": 262144, "parallelism": 2, "hash_len": 64, "salt_len": 32 },
  "salt": "<base64>",
  "deadman_salt": "<base64>",
  "verify": "<base64(nonce + ciphertext)>",
  "deadman_verify": "<base64(nonce + ciphertext)>",
  "created_at": "2025-01-01T00:00:00+00:00",
  "updated_at": "2025-01-01T00:00:00+00:00"
}
```

The `verify` token is the string `VAULTTERM::ONLINE::v3` encrypted with the master key. The `deadman_verify` token is `VAULTTERM::DEADMAN::v3` encrypted with the deadman key. They use different salts, different derived keys, and different sentinel values — a master key cannot verify a deadman token and vice versa.

---

## Dependencies

```
rich>=13.7.0         # terminal UI
cryptography>=42.0.0 # ChaCha20-Poly1305
argon2-cffi>=23.1.0  # Argon2id KDF
pyotp>=2.9.0         # TOTP
pyperclip>=1.8.2     # clipboard
```

All installed into `.venv` by `install.sh`. Nothing is installed system-wide.

---

## Auto-lock

The session locks after 10 minutes of inactivity by default. The timeout is configurable per vault. When triggered, the derived key is wiped from memory, the database connection is closed, and re-authentication is required.

---

## Known limitations

- **SSD shredding is not guaranteed.** See deadman note above.
- **Windows clipboard auto-clear** may not work without additional dependencies.
- **History is cleared on rekey.** HMAC hashes are key-bound and cannot survive a key change.

---

## License

The Unlicense
