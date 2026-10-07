# VaultTerm

```
=====================================================================================
  VAULTTERM v5.0.0  //  ChaCha20-Poly1305 + BLAKE2b  //  Argon2id  //  ML-KEM  //  OFFLINE
=====================================================================================
```

An offline password vault for the Linux terminal. No cloud, no accounts, no
network code, no telemetry. One encrypted vault file.

> **v5 is a fresh start.** It cannot read v4 (or older) vaults or backups.
> Copy what you need out of the old version by hand, then initialise a new vault.

---

## Contents

1. [What changed in v5](#what-changed-in-v5)
2. [Security design](#security-design)
3. [Post-quantum position](#post-quantum-position)
4. [What an attacker with your files can and cannot learn](#what-an-attacker-with-your-files-can-and-cannot-learn)
5. [Known limits](#known-limits)
6. [Install, run, build, verify](#install-run-build-verify)
7. [Using VaultTerm](#using-vaultterm)
8. [Files on disk](#files-on-disk)
9. [Tests](#tests)
10. [Dependencies and licences](#dependencies-and-licences)

---

## What changed in v5

| Area | v5 |
|---|---|
| **Hashes** | Every hash, MAC and KDF is BLAKE2b-based: HKDF-BLAKE2b-512 for all sub-keys, keyed BLAKE2b-512 for the log chain, password history and rollback record, BLAKE2b-512 for attachment and release checksums (`B2SUMS`, compatible with `b2sum`). Argon2id is itself built on BLAKE2b. The only SHA-2/SHA-1 left are where a standard dictates it (see below). |
| **Key commitment** | Every ciphertext carries a 32-byte keyed-BLAKE2b commitment to its key, nonce and associated data. ChaCha20-Poly1305 on its own lets a specially crafted ciphertext decrypt under two different keys; v5 rejects that. |
| **Post-quantum sealing** | Pre-unlock events (failed unlocks, early errors) are sealed with a **hybrid X25519 + ML-KEM-1024** KEM. They stay confidential as long as either algorithm holds. |
| **Post-quantum release signatures** | `compile.sh --pq-sign` adds **ML-DSA-87** (FIPS 204) signatures next to the GPG ones. `verify.sh --pq-pub` checks them. |
| **Password strength target** | Master and deadman passwords are now held to **80 bits** (estimated), up from 60. The default generated passphrase is 7 EFF words (≈ 90 bits). |
| **Optional keyfile** | A second factor: any file (for example 64 random bytes on a USB stick) whose BLAKE2b digest is mixed into the key derivation. It can be added, replaced or removed in REKEY. The deadman password works without it. |
| **Rollback detection** | A keyed record outside the vault folder remembers the BLAKE2b of the last vault file this machine wrote and the highest generation seen. An older copy put back in place triggers **ROLLBACK DETECTED** at every unlock until you explicitly accept it. |
| **TOTP** | The algorithm is now chosen per entry: SHA-1 (default, what most sites use), SHA-256 or SHA-512. A wrong guess is caught because VaultTerm shows the code and asks whether it matches before saving. |

v4's fixes all carry over: the auto-lock deadline on every prompt, the whole
vault as one authenticated ciphertext, the random data key with atomic rekey,
the EFF wordlist, padding, typed errors with details in the LOG, verified
backups, clipboard clearing, core-dump protection, and the reproducible build.

---

## Security design

### Keys

```
master password ─Argon2id(salt, t=3, m=256 MiB, p=4)─► 64 B ─┐
optional keyfile ─BLAKE2b-512─────────────────────────────────┴─HKDF-BLAKE2b─► KEK ─┐
                                                                                    ├ wraps ► DEK (random 256-bit)
recovery key (optional, random 256-bit, Shamir-split) ─HKDF-BLAKE2b───────────────► ┘          │
                                                                                               ├─HKDF-BLAKE2b─► payload key
                                                                                               └─HKDF-BLAKE2b─► attachment key
inside the encrypted payload: history-MAC key · log-MAC key · rollback-record key ·
                              event private keys (X25519 + ML-KEM-1024 seed)
```

* **AEAD** = ChaCha20-Poly1305 (random 96-bit nonce) + keyed-BLAKE2b key commitment: `nonce ‖ commit ‖ ciphertext ‖ tag`.
* **Argon2id** parameters live in the header and are bound into the key wrap. Values outside `t ∈ [2,64]`, `m ∈ [64 MiB, 4 GiB]`, `p ∈ [1,16]` are rejected before any derivation, which blocks downgrade and memory-exhaustion tampering.
* **Rekey** rotates the data key as well as the password, keyfile or KDF parameters. An old backup plus an old password decrypts nothing written afterwards.
* Passwords are Unicode-NFC-normalised before derivation.

### Vault file (`vault.vt`)

```
"VTVAULT\x05" | u32 header length | header (canonical JSON) | AEAD(payload)
```

* **Header** (plaintext, authenticated): format, vault id, KDF parameters, salt, whether a keyfile is required, wrapped DEK(s), the deadman verifier, the public keys for sealed events, and the recovery-kit id. The whole header is the payload's associated data, and its `core` is bound into every key wrap.
* **Payload** (encrypted, padded to 32 KiB buckets): entries, settings, history, the hash-chained log, inner keys, and the BLAKE2b-512 of every attachment.
* **Saves are atomic**: private temp file, `fsync`, `rename`, `fsync` of the directory. Signals are deferred during the commit.

### Rollback record (`~/.config/vaultterm/<vault-id>.state`)

Keyed-BLAKE2b-authenticated `{generation (highest seen), BLAKE2b of the last vault file written, pending}`.

* At unlock, the vault you opened must be that exact file. Otherwise:
  * if its generation is not newer than the record, it is **rollback**;
  * if it is newer, it is **ahead**, meaning an interrupted save or an edit made on another machine. That is noted in the LOG.
* While a rollback is unaccepted, the record keeps the evidence (`pending`). Working on the old copy, even past the recorded generation, cannot erase the warning.
* Restoring a backup on purpose continues the generation counter, so it never looks like a rollback.

### Deadman password

It has its own salt and KDF parameters and never needs the keyfile, so it works under coercion. It is checked only when the master password fails. When it matches:

1. The vault folder, backups and the rollback record are shredded, without following symlinks.
2. The generic `VAULT_INTEGRITY` corruption message is printed.

### Process hardening

`umask 077`, `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, control characters in stored
data neutralised before printing, and the scrollback wiped on every screen change.

---

## Post-quantum position

| Mechanism | Primitive | After a large quantum computer |
|---|---|---|
| Vault and attachment encryption | ChaCha20-Poly1305, 256-bit keys | ≈ 128-bit security (Grover); safe |
| All hashing, MACs, KDFs | BLAKE2b-512 (keyed / HKDF) | safe |
| Password stretching | Argon2id, 256 MiB | Grover can at most halve the password's bits, and running 256 MiB Argon2 on a quantum computer is wildly impractical. The 80-bit target keeps a margin anyway. |
| Pre-unlock event sealing | X25519 **+ ML-KEM-1024** hybrid | safe while ML-KEM holds |
| Paper recovery | Shamir over GF(256) | information-theoretic; unaffected |
| Release signatures | GPG (Ed25519/RSA) **+ ML-DSA-87** | the ML-DSA signature stays valid |
| TOTP | HMAC-SHA-1/256/512, as the site dictates | the 6-digit code is the limit, not the hash; unaffected |

**Where SHA-2/SHA-1 remain, and why:**

* **TOTP** must use exactly the algorithm the website uses (RFC 6238 defines SHA-1, SHA-256 and SHA-512). No authenticator or website supports BLAKE2.
* **`requirements*.txt`**: pip's `--require-hashes` only accepts SHA-2, and PyPI publishes SHA-256.
* **GPG** signatures use SHA-512 (`--digest-algo SHA512`), because GnuPG has no BLAKE2.

---

## What an attacker with your files can and cannot learn

| Visible without the master password | Hidden |
|---|---|
| That this is a VaultTerm v5 vault; its KDF parameters; whether a keyfile is required; whether a recovery kit exists | Number of entries (to within 32 KiB) |
| Number of attachments and their *padded* sizes | Names, URLs, logins, passwords, notes, TOTP secrets and algorithms, entry types |
| File times; size of `events.sealed` (≈ failed unlocks since the last session) | Settings, history, audit log, timestamps, event contents |
| The rollback record's generation number | Which entries share a password |

---

## Known limits

* **Rollback across machines.** The rollback record is per machine. A copy moved to a machine that has never opened this vault has nothing to compare against. The generation number shown at every unlock is the manual check.
* **Memory.** Python cannot reliably erase strings. Key buffers are zeroed on lock, but decrypted values may linger in process memory. Core dumps and ptrace are disabled. Use **encrypted swap** (or zram/none); HEALTH reports what it finds.
* **Shredding** is overwrite + unlink. On SSDs, journaling and copy-on-write filesystems old blocks may survive. **Full-disk encryption (LUKS) is the real protection at rest.**
* **Deadman vs a disk image.** Anything copied before the deadman password was typed survives.
* **Keyfile.** If you lose it, only the paper recovery kit opens the vault. The file must never change (a single byte locks you out), so keep a copy somewhere safe.
* **Clipboard managers** may keep their own history. Clipboard use is off by default.
* **Copies outside `~/.vaultterm/backups`** are not re-encrypted on rekey.
* **Verifying the program.** A modified binary can lie about itself. Trust comes from checking `B2SUMS` and its signatures with tools you already trust, before running anything.

---

## Install, run, build, verify

### Requirements

Linux, Python 3.10+, GNU coreutils (`b2sum`). For the clipboard: `wl-clipboard`
(Wayland) or `xclip` / `xsel` (X11).

### Run from source

```bash
./verify.sh --source [--pq-pub vaultterm-release.pub]   # if the release ships SOURCE-B2SUMS
./install.sh                                            # .venv + hash-pinned wheels only + selftest
./start.sh                                              # or: ./start.sh --keyfile /media/usb/vault.key
```

`start.sh` refuses to run if `SOURCE-B2SUMS` is present and the files don't
match. That only catches accidental changes; real assurance comes from the
signatures.

### Build the ELF binary

```bash
./compile.sh                                    # dist/vaultterm + B2SUMS + SOURCE-B2SUMS + BUILDINFO
./compile.sh --sign                             # + GPG signatures (*.asc)
./compile.sh --sign --pq-sign vaultterm-release.key   # + ML-DSA-87 signatures (*.mldsa) + the .pub
./compile.sh --onedir                           # directory bundle instead of one file
```

The build:

1. Installs **only** hash-pinned wheels into a separate build venv.
2. Runs the unit tests and the source self-test.
3. Builds with PyInstaller using `SOURCE_DATE_EPOCH` + `PYTHONHASHSEED=0`.
4. Runs the binary's `--selftest` with an empty environment in a throw-away `HOME`.
5. Writes the checksums and signatures.

Two builds of the same source with the same Python and distro produce the
**same binary**, so anyone can rebuild and compare.

### Post-quantum signing key (once)

```bash
.venv/bin/python pqsign.py keygen --out vaultterm-release   # .key (Argon2id-encrypted, keep offline) + .pub
.venv/bin/python pqsign.py fingerprint vaultterm-release.pub
```

Publish the `.pub` and its fingerprint (and your GPG fingerprint) somewhere
other than the download itself.

### Verify a release before running it

```bash
./verify.sh dist/vaultterm                                             # B2SUMS (+ GPG .asc if present)
./verify.sh dist/vaultterm --pq-pub vaultterm-release.pub \
            --pq-fingerprint "XXXX XXXX …"                             # also REQUIRE the ML-DSA-87 signature
./verify.sh --b2 <blake2b-512-you-got-elsewhere> dist/vaultterm
./verify.sh --source --pq-pub vaultterm-release.pub
```

By hand: `b2sum -c B2SUMS`, `gpg --verify B2SUMS.asc B2SUMS`, and
`python3 pqsign.py verify --pub vaultterm-release.pub B2SUMS`.

### Command line

```
vaultterm                      initialise or unlock
vaultterm --keyfile PATH       default keyfile path to offer (also $VAULTTERM_KEYFILE)
vaultterm --restore FILE       install a .vtbak backup as the active vault
vaultterm --recover            open the vault with paper recovery shares
vaultterm --selftest           built-in crypto/format tests in a temp dir
vaultterm --version
```

`VAULTTERM_DIR` changes the vault folder (default `~/.vaultterm`);
`VAULTTERM_STATE_DIR` changes where rollback records live (default
`$XDG_CONFIG_HOME/vaultterm`).

---

## Using VaultTerm

### First run

1. Set a **master password**: at least 12 characters, with a confirmation prompt if it estimates below 80 bits.
2. Set a **deadman password**, which must be different.
3. Optionally add a **keyfile**: VaultTerm can generate one (64 random bytes, mode 0400) or use an existing file.
4. Optionally print a **paper recovery kit**. This is recommended when you use a keyfile.

### Menu

```
[1]  LIST      entries (passwords never shown in lists)
[2]  SEARCH    name / url / login / notes / attached file name
[3]  INJECT    add a password, PIN, passphrase or secret key
[4]  MODIFY    edit an entry
[5]  PURGE     delete an entry (its attachment is shredded)
[6]  GENERATE  password / PIN / passphrase generator
[7]  LOG       tamper-evident audit trail and error details
[8]  REKEY     master/deadman password, keyfile, KDF upgrade
[9]  CLONE     backups: create, verify, restore, shred
[10] TOTP      live TOTP code display
[11] HEALTH    vault health check
[12] SETTINGS  expiry, auto-lock, clipboard
[13] RECOVERY  printable paper recovery kit
[0]  EJECT     clear clipboard, lock and exit
```

From LIST/SEARCH: `[C]` copy password, `[V]` view, `[U]` update password,
`[T]` live TOTP, `[X]` export a secret-key file.

### Entry types

| Type | Value | Generator |
|---|---|---|
| password | any text (warning under 12 chars) | 16–128 chars: high entropy / max compatibility / no symbols |
| PIN | digits | 4–12 digits |
| passphrase | words | 5–12 EFF words (default 7 ≈ 90 bits) |
| secret key | an **encrypted copy of a file** (≤ 64 MiB) + optional password | — |

**Secret keys:**

* VaultTerm encrypts a copy of the file and shows its BLAKE2b-512, so you can compare it with `b2sum`.
* It then offers to delete the original.
* `[V]` can show small text files on screen, and `[X]` exports the file back (mode 0600, hash-checked).

### TOTP

1. Paste the base32 secret (input hidden).
2. Pick the algorithm: **SHA-1** (most sites; the default), SHA-256 or SHA-512. The site decides which; its setup page or the `otpauth://` link says `algorithm=` when it isn't SHA-1.
3. VaultTerm shows the current code and asks whether it matches the site or your phone. If not, pick another algorithm.

MODIFY can change the secret, change only the algorithm, or clear TOTP.

### REKEY — `[8]`

Every option asks for the current master password, and every key change makes
a verified backup first.

1. **Change master password**: rotates the data key, re-encrypts everything, commits atomically, then re-encrypts backups.
2. **Change deadman password** (also upgrades its KDF parameters).
3. **Upgrade KDF / rotate data key**, keeping the same password.
4. **Add / replace keyfile.**
5. **Remove the keyfile requirement.**

### Backups — `[9] CLONE`

* **New** creates a backup and fully verifies it: header, key unwrap, payload authentication, and every attachment.
* **Verify** repeats that check on any backup.
* **Restore** backs up the current vault, installs the chosen backup and keeps the generation counter monotonic.
* **Shred** deletes a backup.
* After a rekey, backups made since the previous rekey are re-encrypted to the new credentials. Older ones are listed and you can shred them.
* From the command line: `./start.sh --restore backup.vtbak`.

Copy backups to another disk yourself.

### Paper recovery kit — `[13] RECOVERY` (optional)

* A random 256-bit recovery key is split *k*-of-*n* with Shamir's secret sharing.
* VaultTerm writes a PDF with one page per share: base32 text with a BLAKE2b checksum, plus a QR code. The PDF goes to `/dev/shm` by default; print it, then let VaultTerm shred it.
* *k* shares open the vault **without** the master password or keyfile. Fewer reveal nothing.
* Shares stay valid across password and keyfile changes. Generating a new kit or revoking it invalidates every old sheet.
* To use it: `./start.sh --recover`, type *k* shares, then set a new master password (and optionally a keyfile).

### LOG — `[7]`

The log holds the last 2,000 events in a keyed-BLAKE2b hash chain inside the
encrypted vault, and the LOG screen shows whether the chain verifies. Errors
appear on screen as `[ERR] <TYPE> <generic text> (ref abc123)`; type the ref in
LOG to see the details.

| Error type | Meaning |
|---|---|
| `AUTH_FAILED` | wrong password / keyfile (or a modified header) |
| `KEYFILE` | keyfile missing, unreadable, or too small |
| `VAULT_FORMAT` | not a readable v5 vault |
| `VAULT_INTEGRITY` | authentication of the vault contents failed |
| `VAULT_MISSING` | vault data exists but `vault.vt` doesn't |
| `KDF_PARAMS` | KDF parameters outside safe limits, or not enough memory |
| `BLOB_INTEGRITY` | an attachment is missing, corrupt or swapped |
| `BACKUP_INVALID` | a backup failed verification |
| `RECOVERY_INVALID` | recovery shares invalid or for another kit |
| `IO_ERROR`, `CLIPBOARD`, `INPUT`, `INTERNAL` | as named |

Log events you'll see besides normal actions: `UNLOCK_FAIL`, `ROLLBACK_WARNING`,
`ROLLBACK_ACCEPTED`, `STATE_AHEAD`, `STATE_WARNING`, `CLEANUP`.

### HEALTH — `[11]`

HEALTH checks:

* vault authentication, the log chain, and the rollback record;
* every attachment (decrypted and BLAKE2b-checked);
* permissions;
* core-dump and dumpable flags, and swap;
* vault and deadman KDF parameters, the keyfile, PQ event sealing, and the recovery kit;
* weak, expired and shared passwords;
* backups (age, older credentials) and the generation number.

### SETTINGS — `[12]`

| Setting | Default | Range |
|---|---|---|
| `expiry_days` | 30 | 1–3650 |
| `auto_lock_minutes` | 10 | 0 (off) – 1440 |
| clipboard | off | on/off |
| `clipboard_clear_seconds` | 30 | 5–300 |

---

## Files on disk

```
~/.vaultterm/                       0700
├── vault.vt                        0600   header + encrypted, padded payload
├── blobs/<id>.blob                 0600   encrypted, padded attachments
├── backups/*.vtbak                 0600   verified backups (tar)
└── events.sealed                   0600   hybrid-PQ-sealed pre-unlock events (temporary)
~/.config/vaultterm/<id>.state      0600   rollback record (keyed BLAKE2b)
```

---

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v                   # 48 unit tests
.venv/bin/python vaultterm.py --selftest
pip install pexpect && python tests/e2e_pty.py vaultterm.py         # end-to-end in a pty (all scenarios)
python tests/e2e_pty.py dist/vaultterm                              # same, against the binary
```

The unit tests cover:

* key commitment, BLAKE2b domain separation, hybrid KEM sealing;
* tamper detection (bit flips, header edits, KDF downgrade, truncation, wrong format version);
* rollback detection (older copy, same generation with different content, an interrupted state write, accepting, restore staying monotonic, record tampering);
* keyfile (required, wrong file, deadman without it, add/remove, backup conversion);
* Ctrl+C and I/O failure mid-rekey, attachment tampering, malicious tar members;
* Shamir subsets and share typos, log-chain forgery;
* RFC 6238 vectors for SHA-1/256/512, generators and the estimator.

The end-to-end scenarios are basic, autolock, secretkey, recovery, deadman, keyfile and rollback.

---

## Dependencies and licences

Runtime (pinned with hashes in `requirements.txt`, wheels only):

| Package | Why |
|---|---|
| `cryptography` ≥ 50 | ChaCha20-Poly1305, Argon2id, HKDF-BLAKE2b, X25519, ML-KEM-1024, ML-DSA-87 |
| `rich` (+ `markdown-it-py`, `mdurl`, `pygments`) | terminal UI |
| `qrcode` | QR codes on the recovery PDF (optional) |
| `cffi`, `pycparser` | required by `cryptography` |

BLAKE2b, TOTP, Shamir sharing, the PDF writer and the strength estimator use
the Python standard library or are implemented in `vaultterm.py`. Build only:
`pyinstaller` and helpers (`requirements-build.txt`).

VaultTerm is released under The Unlicense. The EFF large wordlist
(`vaultterm_wordlist.py`) is © Electronic Frontier Foundation, CC BY 3.0 US,
<https://www.eff.org/dice>.
