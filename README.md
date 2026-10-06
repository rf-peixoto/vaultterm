# VaultTerm

```
=========================================================================
  VAULTTERM v4.0.0  //  ChaCha20-Poly1305  //  Argon2id  //  OFFLINE
=========================================================================
```

An offline password vault for the Linux terminal. No cloud, no accounts, no
network code, no telemetry. One encrypted vault file.

> **v4 is a fresh start.** It cannot read v3 vaults or v3 backups. Export what
> you need from v3 by hand, then initialise a new v4 vault.

---

## Contents

1. [What changed in v4](#what-changed-in-v4)
2. [Security design](#security-design)
3. [What an attacker with your files can and cannot learn](#what-an-attacker-with-your-files-can-and-cannot-learn)
4. [Known limits](#known-limits)
5. [Install, run, build, verify](#install-run-build-verify)
6. [Using VaultTerm](#using-vaultterm)
7. [Files on disk](#files-on-disk)
8. [Tests](#tests)
9. [Dependencies and licences](#dependencies-and-licences)

---

## What changed in v4

| v3 problem | v4 |
|---|---|
| Auto-lock never fired: idle time at a prompt was never counted | Every prompt has a deadline. Idle for N minutes anywhere, whether at the menu, a "press ENTER" or the live TOTP view, and the vault locks: keys are wiped, the clipboard is cleared, the screen and scrollback are erased, and typed-ahead input is discarded. |
| Nothing checked the vault as a whole (rows could be rolled back or deleted, settings changed) | The whole vault, including entries, settings, log and inner keys, is **one authenticated ciphertext**. Changing any byte makes it fail to open. |
| Ctrl+C or a crash during REKEY could leave entries unreadable | **Random data key** wrapped by the master key. A rekey re-encrypts everything under a *new* data key, and a single atomic file rename is the commit point. Signals are deferred during the commit. |
| 40-word passphrase list (~40 bits), naive strength meter | **EFF large wordlist** (7,776 words, 12.9 bits/word; default 6 words ≈ 78 bits). Pattern-based strength estimator (dictionary words, common passwords, years, sequences, keyboard runs, repeats). Generators show their exact entropy. |
| Identical passwords had identical hashes in the DB | The history hashes are keyed per entry (`HMAC(key, uuid ‖ password)`) **and** stored inside the encrypted vault. Reuse is detected by comparing decrypted values in memory. |
| Ciphertext length showed password/notes length and empty fields | The vault is padded to 32 KiB buckets and attachments to size buckets. There are no per-field ciphertexts on disk any more. |
| MODIFY printed the TOTP secret and notes | Shown as `[hidden, N chars]` with Keep / Edit / Clear. TOTP input is not echoed. URL/notes/TOTP can now be cleared. |
| Missing or mismatched files handled silently | Generic error with a type and reference on screen (`[ERR] VAULT_MISSING ... (ref 3fa9c1)`), with full details in the encrypted LOG. The app refuses to create a new vault over leftover data. |
| REKEY never upgraded KDF parameters | REKEY always uses the current recommended parameters, after an **automatic verified backup**. Weaker vaults are offered an upgrade at unlock. Out-of-range parameters are rejected before any derivation. |
| Old backups opened with the old password after rekey; "verify" only listed file names | After a rekey, backups in `backups/` are **re-encrypted to the new password**. Backups on older passwords are listed and can be shredded. Verify now authenticates the vault and decrypts every attachment. A restore always backs up the current vault first. |
| Clipboard not cleared if you exited quickly | Clipboard and primary selection are cleared on EJECT (always), on auto-lock, and on any exit after a copy. The 30 s timer still clears it only if the clipboard still holds the value VaultTerm put there. |
| Manual entry passwords had to be ≥ 12 chars | Any length is accepted, with a warning under 12. |
| Revealed passwords stayed in scrollback; core dumps possible | `ESC[3J` scrollback wipe on every screen change. `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0`. |
| Deadman message didn't hold up | Identical to a genuine corruption error: *"vault database corrupted ... reinstall VaultTerm and initialise a new vault."* |
| 5-attempt limit (cosmetic) | Removed. Failed attempts are recorded (sealed, see below) and reported after the next successful unlock. |
| Corrupt meta.json crashed with a traceback | Strict header/payload validation returns typed errors. Unexpected exceptions are reported as `INTERNAL` with the traceback stored only in the encrypted LOG. |
| Unpinned dependencies, smoke test that could never fail | `requirements*.txt` pinned with SHA-256 hashes, wheels only. `compile.sh` runs the full test suite and a real binary self-test in a throw-away `HOME`. |
| Plaintext audit log | Encrypted with the vault and **HMAC hash-chained**. LOG shows whether the chain verifies. |
| *(new)* | Reproducible single-file ELF build with `SHA256SUMS`, `SOURCE-SHA256SUMS`, optional GPG signatures, and `verify.sh`. |
| *(new)* | Optional **paper recovery kit**: Shamir k-of-n shares, auto-generated printable PDF with QR codes. |
| *(new)* | **Secret keys**: encrypt any file (SSH/GPG keys, recovery codes, ...) as a new entry type. |

---

## Security design

### Keys

```
master password ──Argon2id(salt, t=3, m=256 MiB, p=4)──► KEK ─┐
                                                              ├─ wraps ─► DEK (random 256-bit data key)
recovery key (optional, 256-bit random, Shamir-split) ─HKDF─► ─┘                │
                                                                                ├─HKDF─► payload key
                                                                                └─HKDF─► attachment key
inside the encrypted payload:  history-HMAC key · log-HMAC key · event private key (X25519)
```

* **Cipher**: ChaCha20-Poly1305 with random 96-bit nonces (the payload is re-encrypted on every save).
* **Argon2id**, from `cryptography`'s OpenSSL backend. Parameters live in the header and are bound into the key wrap. Values outside `t ∈ [2,64]`, `m ∈ [64 MiB, 4 GiB]`, `p ∈ [1,16]` are rejected before deriving, which blocks downgrade and memory-exhaustion tampering.
* **Rekey** rotates the DEK as well as the password: an old backup plus the old password does **not** decrypt anything written after the rekey.
* Passwords are Unicode-NFC-normalised before derivation, so the same password typed on different keyboards/locales gives the same key.

### Vault file (`vault.vt`)

```
"VTVAULT\x04" | u32 header length | header (canonical JSON) | nonce | ChaCha20-Poly1305(payload)
```

* **Header** (plaintext, authenticated): format, KDF parameters, salt, the wrapped DEK(s), deadman verifier, the public key for sealed events, recovery-kit id. The whole header is the payload's AAD, and its `core` is the AAD of every key wrap, so editing any header field makes unlocking fail.
* **Payload** (encrypted): every entry, settings, password history, the hash-chained log, inner keys, and the SHA-256 of every attachment blob. It is padded to a multiple of 32 KiB.
* **Saves are atomic**: write a private temp file, `fsync`, `rename`, `fsync` the directory. Ctrl+C/SIGTERM/SIGHUP are deferred during the rename so memory and disk can never disagree.

### Attachments (`blobs/<random-id>.blob`)

Encrypted with the attachment key, AAD-bound to their random id, and padded
(powers of two up to 1 MiB, then whole MiB). Their ciphertext hash lives in
the authenticated payload, so a swapped, rolled-back or corrupted blob is
detected.

### Sealed pre-unlock events (`events.sealed`)

Failed unlock attempts and errors that happen *before* unlock can't go into
the encrypted log (no key yet). They are sealed to the vault's X25519 public
key, so they can be written but not read without unlocking. After the next
unlock they are imported into the LOG and the file is shredded.

### Deadman password

Has its own salt and Argon2id parameters. It is only checked when the master
password fails, so a wrong password always costs two derivations and a correct
master costs one. When it matches, the whole vault folder, backups included,
is shredded and the generic `VAULT_INTEGRITY` corruption message is printed.
Symlinks are never followed while shredding.

### Process hardening

`umask 077`, no core dumps (`RLIMIT_CORE=0`), non-dumpable process
(`PR_SET_DUMPABLE=0`: no `ptrace`, no `/proc/<pid>/mem` for other processes of
your user), no terminal escape sequences from stored data (all control
characters are neutralised before printing), and the scrollback is wiped on
every screen change.

---

## What an attacker with your files can and cannot learn

| Visible without the master password | Hidden |
|---|---|
| That this is a VaultTerm v4 vault, its KDF parameters | Number of entries (to within the 32 KiB bucket) |
| Whether a paper recovery kit exists | Names, URLs, logins, passwords, notes, TOTP secrets, entry types |
| Number of attachments and their *padded* sizes | Settings, history, audit log, timestamps |
| File modification times (filesystem metadata) | Which entries share a password |
| Size of `events.sealed` (≈ number of failed unlocks since the last session) | Contents of those events |

---

## Known limits

Be clear about these:

* **Whole-file rollback.** Replacing `vault.vt` with an *older complete copy* (for example an old backup) produces a vault that opens normally; that's how restore works. VaultTerm shows the **generation number** and last-saved time at every unlock. If the generation is lower than you remember, an older copy was put back.
* **Memory.** Python cannot reliably erase strings. Key buffers are zeroed on lock, but decrypted values may stay in process memory until reused. Disabling core dumps and ptrace removes the easy ways to read them. Use **encrypted swap** (or zram/no swap); HEALTH reports what it finds.
* **Shredding** (deadman, deleted originals, old backups) overwrites then unlinks. On SSDs, journaling and copy-on-write filesystems the old blocks may survive. **Full-disk encryption (LUKS) is the real protection for data at rest.**
* **Deadman vs a disk image.** Someone who copied your files *before* you typed the deadman password still has them, and offline brute force against the copy is limited only by your master password's strength.
* **Clipboard managers** (Klipper, GPaste, CopyQ, ...) may keep their own history regardless of auto-clear. Clipboard use is off by default.
* **Copies outside `~/.vaultterm/backups`** are not re-encrypted on rekey. They keep opening with the password they were made under.
* **Verifying the program.** A modified binary can lie about its own hash, so self-checks prove nothing. Trust comes from checking `SHA256SUMS` (and its GPG signature) **with tools you already trust, before running anything**. See below.

---

## Install, run, build, verify

### Requirements

Linux, Python 3.10+. For the clipboard: `wl-clipboard` (Wayland) or `xclip` /
`xsel` (X11).

### Run from source

```bash
./verify.sh --source        # if the release ships SOURCE-SHA256SUMS(.asc)
./install.sh                # .venv + hash-pinned wheels only + selftest
./start.sh
```

`start.sh` refuses to run if `SOURCE-SHA256SUMS` is present and the files don't
match. That only catches accidental or naive changes: anyone able to edit
`vaultterm.py` can edit `start.sh` too.

### Build the ELF binary

```bash
./compile.sh                       # dist/vaultterm + SHA256SUMS + SOURCE-SHA256SUMS + BUILDINFO
./compile.sh --sign                # + GPG-signed SHA256SUMS.asc / SOURCE-SHA256SUMS.asc
./compile.sh --sign-key 0xABCD1234
./compile.sh --onedir              # directory bundle instead of one file
```

What it does:

1. Creates a separate build venv and installs **only** the hash-pinned wheels in `requirements.txt` + `requirements-build.txt`.
2. Runs the unit tests and the source self-test. The build stops on failure.
3. Builds with PyInstaller using `SOURCE_DATE_EPOCH` (last git commit, else the source mtime) and `PYTHONHASHSEED=0`.
4. Runs `dist/vaultterm --version` and `--selftest` with an empty environment and a throw-away `HOME`, so your real vault is never touched. Any failure stops the build.
5. Writes `SHA256SUMS` (binary), `SOURCE-SHA256SUMS` (the exact sources), `BUILDINFO` (Python, distro, glibc, every package version), and signatures if requested.

Two builds of the same source with the same Python and distro produce the
**same hash**, so anyone can rebuild and compare against what you published.
Publish `SHA256SUMS(.asc)` and your GPG key fingerprint somewhere other than the
download itself.

### Verify a release before running it

```bash
./verify.sh dist/vaultterm                    # checks SHA256SUMS (+ .asc signature) next to the binary
./verify.sh --hash <sha256-you-got-elsewhere> dist/vaultterm
./verify.sh --source                          # the source tree vs SOURCE-SHA256SUMS(.asc)
```

Or by hand with nothing but coreutils and gpg:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS && sha256sum -c SHA256SUMS
```

### Command line

```
vaultterm                      normal start (initialise or unlock)
vaultterm --restore FILE       install a .vtbak backup as the active vault
vaultterm --recover            open the vault with paper recovery shares
vaultterm --selftest           built-in crypto/format tests in a temp dir
vaultterm --version
```

`VAULTTERM_DIR=/path` uses another vault folder (default `~/.vaultterm`).

---

## Using VaultTerm

### First run

You set a **master password** (≥ 12 chars; the estimator asks for confirmation
below ~60 bits) and a **deadman password**, which must be different. You can
create a paper recovery kit right away or later.

### Menu

```
[1]  LIST      entries (passwords never shown in lists)
[2]  SEARCH    name / url / login / notes / attached file name
[3]  INJECT    add a password, PIN, passphrase or secret key
[4]  MODIFY    edit an entry
[5]  PURGE     delete an entry (its attachment is shredded)
[6]  GENERATE  password / PIN / passphrase generator
[7]  LOG       tamper-evident audit trail and error details
[8]  REKEY     master/deadman password, KDF upgrade
[9]  CLONE     backups: create, verify, restore, shred
[10] TOTP      live TOTP code display
[11] HEALTH    vault health check
[12] SETTINGS  expiry, auto-lock, clipboard
[13] RECOVERY  printable paper recovery kit
[0]  EJECT     clear clipboard, lock and exit
```

From LIST/SEARCH: `[C]` copy password, `[V]` view, `[U]` update password,
`[T]` live TOTP, `[X]` export a secret-key file. Ctrl+C cancels the current
command. At the main menu, Ctrl+C locks and exits.

### Entry types

| Type | Value | Generator |
|---|---|---|
| password | any text (warning under 12 chars) | 16–128 chars, profiles: high entropy / max compatibility / no symbols |
| PIN | digits | 4–12 digits |
| passphrase | words | 5–12 EFF words (default 6 ≈ 78 bits) |
| secret key | an **encrypted copy of a file** + optional password (e.g. the key's own passphrase) | — |

**Secret keys**: give the file path (up to 64 MiB). VaultTerm encrypts a copy,
shows its SHA-256, and asks whether to delete the original (overwrite + unlink,
with the SSD caveat). `[V]` can print small text files on screen; `[X]` exports
the file back (mode 0600, hash-checked). The exported copy is *not* encrypted,
so shred it when you're done.

Each entry also has an optional URL, login, notes and TOTP secret. When you set
a value, VaultTerm warns if the entry used it before (per-entry keyed history,
last 24) or if another entry uses the same value.

### TOTP

Paste the base32 secret (input hidden). VaultTerm shows the current code so you
can compare it with your phone before saving. Standard TOTP only (SHA-1, 6
digits, 30 s), RFC 6238 test vectors pass. `[10]` shows a live countdown; in the
last 5 seconds it also shows the next code.

### Expiry

Advisory: an entry is flagged `[EXPIRED]` when its secret (password or file)
hasn't changed for `expiry_days`. Editing other fields doesn't reset the clock.

### Backups — `[9] CLONE`

* **New** writes `backups/vaultterm_<date>_<label>.vtbak` (tar of `vault.vt` + attachments, mode 0600, metadata zeroed) and then **fully verifies** it: header, key unwrap, payload authentication, every attachment's hash and decryption.
* **Verify** repeats that check on any backup. Backups on an older password ask for that password.
* **Restore** verifies, backs up the current vault, installs the backup, and continues unlocked with the backup's password.
* **Shred** deletes a backup.
* After every **rekey**, backups made since the previous rekey are re-encrypted to the new password. Older ones are listed and you can shred them.

Copy `.vtbak` files to another disk yourself: the backup folder lives next to
the vault and the deadman password destroys it too.

From the command line (for example when the vault file is gone):
`./start.sh --restore backup.vtbak`. Any existing vault files are archived
first as `..._pre-restore-unverified.vtbak`.

### REKEY — `[8]`

1. **Change master password**: creates a verified safety backup, rotates the data key, re-encrypts the vault and every attachment under the recommended KDF parameters, commits with one atomic rename, then converts backups. If anything fails before the commit, the vault is unchanged and the message says so. If something fails after it, the message says exactly that.
2. **Change deadman password**, which also upgrades its KDF parameters.
3. **Upgrade KDF / rotate data key** keeping the same password.

### Paper recovery kit — `[13] RECOVERY` (optional)

Pick *n* shares and a threshold *k* (default 2 of 3). VaultTerm creates a random
256-bit recovery key, wraps the data key with it, splits it with Shamir's
secret sharing over GF(256), and writes a printable PDF with one page per share.
Each page has the share as text (base32 groups with a checksum that catches
typos) plus a QR code of the same text, for a keyboard-style barcode scanner.

* The PDF goes to `/dev/shm` (RAM) by default. Print it, then let VaultTerm shred it.
* Fewer than *k* shares reveal nothing. *k* shares open the vault **without** the master password, so keep each sheet in a different place.
* Shares stay valid across master-password changes. Generating a new kit or revoking it invalidates every old sheet.
* To use it: `./start.sh --recover`, type *k* shares, set a new master password (this rekeys). Consider generating a new kit afterwards.

### LOG — `[7]`

Every action (unlock, add, edit, purge, rekey, backup, restore, settings,
failed unlocks, errors, cleanups) is appended to an HMAC-chained log inside the
encrypted vault (last 2,000 events). The screen shows whether the chain
verifies. Errors appear on screen as `[ERR] <TYPE> <generic text> (ref abc123)`;
type the ref (or the sequence number) in LOG to see the full detail.

| Error type | Meaning |
|---|---|
| `AUTH_FAILED` | wrong password (or a modified header) |
| `VAULT_FORMAT` | the vault file isn't a readable v4 vault |
| `VAULT_INTEGRITY` | authentication of the vault contents failed (corruption or tampering) |
| `VAULT_MISSING` | vault data exists but `vault.vt` doesn't |
| `KDF_PARAMS` | KDF parameters outside safe limits, or not enough memory |
| `BLOB_INTEGRITY` | an attachment is missing, corrupt or swapped |
| `BACKUP_INVALID` | a backup failed verification |
| `RECOVERY_INVALID` | recovery shares invalid or for another kit |
| `IO_ERROR`, `CLIPBOARD`, `INPUT`, `INTERNAL` | as named |

### HEALTH — `[11]`

Vault authentication, log chain, every attachment decrypted and hash-checked,
permissions (0700/0600, owned by you), core dumps and dumpable flag, swap,
KDF parameters (vault and deadman), recovery kit, weak (< 60 bits) / expired /
shared passwords, backup count and age, backups on older passwords, vault
generation.

### SETTINGS — `[12]`

Stored inside the encrypted vault.

| Setting | Default | Range |
|---|---|---|
| `expiry_days` | 30 | 1–3650 |
| `auto_lock_minutes` | 10 | 0 (off) – 1440 |
| clipboard | off | on/off |
| `clipboard_clear_seconds` | 30 | 5–300 |

---

## Files on disk

```
~/.vaultterm/                 0700
├── vault.vt                  0600   header + encrypted, padded payload
├── blobs/<id>.blob           0600   encrypted, padded attachments
├── backups/*.vtbak           0600   verified backups (tar)
└── events.sealed             0600   sealed pre-unlock events (temporary)
```

Leftovers of interrupted operations (temp files, orphan blobs, half-converted
backups) are cleaned at the next unlock and recorded in the LOG.

---

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v       # 36 unit tests
.venv/bin/python vaultterm.py --selftest
pip install pexpect && python tests/e2e_pty.py vaultterm.py       # end-to-end in a pty
python tests/e2e_pty.py dist/vaultterm                            # same, against the binary
```

The unit tests cover tamper detection (payload bit flips, header edits, KDF
downgrade, truncated files), padding, Ctrl+C and I/O failure in the middle of a
rekey, attachment tampering, backup convert/restore, malicious tar members
(path traversal, symlinks), Shamir subsets, share typos, log-chain forgery,
sealed events, TOTP vectors, generators and the estimator.

The end-to-end test drives the real UI. It checks that auto-lock fires while
idle at the menu, that EJECT empties the clipboard, that MODIFY never prints
secrets, and that secret-key, rekey + backup conversion, CLI restore, paper
recovery from the generated PDF, and deadman all work.

---

## Dependencies and licences

Runtime (pinned with hashes in `requirements.txt`, wheels only):

| Package | Why |
|---|---|
| `cryptography` | ChaCha20-Poly1305, Argon2id, HKDF, X25519 |
| `rich` (+ `markdown-it-py`, `mdurl`, `pygments`) | terminal UI |
| `qrcode` | QR codes in the recovery PDF (optional; text-only sheets without it) |
| `cffi`, `pycparser` | required by `cryptography` |

TOTP, Shamir sharing, the PDF writer and the strength estimator are implemented
in `vaultterm.py` itself, so there are fewer third-party packages to trust.
Build only: `pyinstaller` and its helpers (`requirements-build.txt`).

VaultTerm is released under The Unlicense. The EFF large wordlist
(`vaultterm_wordlist.py`) is © Electronic Frontier Foundation, CC BY 3.0 US,
<https://www.eff.org/dice>.
