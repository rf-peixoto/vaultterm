"""Optional end-to-end test: drives VaultTerm in a pseudo-terminal (needs `pip install pexpect`).

Usage:  python tests/e2e_pty.py vaultterm.py [basic autolock secretkey recovery deadman]
        python tests/e2e_pty.py dist/vaultterm        (test the compiled binary)
Uses a throw-away VAULTTERM_DIR and a fake wl-copy/wl-paste; never touches your vault.
"""
import os, re, sys, time, shutil, tempfile
from pathlib import Path
import pexpect

SCRIPT = sys.argv[1]
PY = sys.executable
WANT = set(sys.argv[2:])
MASTER, DEAD = "Kq8!vZ2#rT6@wL9-master", "Gx7#mQ2!pL9$wR4@dead"

work = Path(tempfile.mkdtemp(prefix="vt-e2e-"))
fakebin = work / "bin"; fakebin.mkdir()
clipfile = work / "clip.txt"
(fakebin / "wl-copy").write_text(f"""#!/bin/sh
case "$*" in *--clear*) : > "{clipfile}"; exit 0;; esac
cat > "{clipfile}"
""")
(fakebin / "wl-paste").write_text(f"#!/bin/sh\ncat '{clipfile}'\n")
for f in fakebin.iterdir(): f.chmod(0o755)

def env(base):
    e = dict(os.environ, VAULTTERM_DIR=str(base), NO_COLOR="1", WAYLAND_DISPLAY="fake",
             PATH=f"{fakebin}:{os.environ['PATH']}", TERM="xterm")
    e.pop("DISPLAY", None)
    return e

def spawn(base, *args):
    c = pexpect.spawn(*((PY, [SCRIPT, *args]) if SCRIPT.endswith(".py") else (SCRIPT, list(args))), env=env(base), encoding="utf-8", timeout=30, dimensions=(60, 160))
    c.logfile_read = open(work / "transcript.log", "a")
    return c

def prompt(c, text):
    c.expect(re.escape(text) + r".*?>> ")

def menu(c, choice):
    prompt(c, "cmd"); c.sendline(choice)

def init(base):
    c = spawn(base)
    prompt(c, "new master password"); c.sendline(MASTER)
    prompt(c, "confirm master password"); c.sendline(MASTER)
    prompt(c, "new deadman password"); c.sendline(DEAD)
    prompt(c, "confirm deadman password"); c.sendline(DEAD)
    c.expect("vault initialised", timeout=60)
    prompt(c, "paper recovery kit"); c.sendline("n")
    return c

def unlock(c, pw=MASTER):
    prompt(c, "master password"); c.sendline(pw)
    c.expect("access granted", timeout=60)
    prompt(c, "press ENTER"); c.sendline("")

results = []
def check(name, cond):
    results.append((name, bool(cond))); print(("PASS " if cond else "FAIL ") + name, flush=True)

def run(name):
    return not WANT or name in WANT

# ── scenario 1: basic flow + clipboard + eject ──────────────────────────────
if run("basic"):
    base = work / "v1"
    c = init(base)
    menu(c, "12")  # settings: enable clipboard
    prompt(c, "expiry_days"); c.sendline("")
    prompt(c, "auto_lock_minutes"); c.sendline("")
    prompt(c, "enable clipboard"); c.sendline("y")
    prompt(c, "clipboard_clear_seconds"); c.sendline("")
    c.expect("settings saved"); prompt(c, "press ENTER"); c.sendline("")
    menu(c, "3")
    prompt(c, "type"); c.sendline("1")
    prompt(c, "name"); c.sendline("bank")
    prompt(c, "url (optional)"); c.sendline("https://bank.example")
    prompt(c, "login/email"); c.sendline("alice")
    prompt(c, "notes (optional)"); c.sendline("security answer: blue")
    prompt(c, "TOTP secret"); c.sendline("JBSWY3DPEHPK3PXP")
    c.expect("TOTP validated")
    prompt(c, "password mode"); c.sendline("m")
    prompt(c, "new password"); c.sendline("short1")
    prompt(c, "confirm password"); c.sendline("short1")
    c.expect("shorter than 12 characters")
    check("short manual password only warns", True)
    prompt(c, "commit to vault"); c.sendline("y")
    c.expect("entry injected"); prompt(c, "press ENTER"); c.sendline("")
    # modify: TOTP and notes must not be displayed
    menu(c, "4"); prompt(c, "entry id to modify"); c.sendline("1")
    prompt(c, "name"); c.sendline(""); prompt(c, "url"); c.sendline("-"); prompt(c, "login"); c.sendline("")
    c.expect(r"notes: \[hidden, 21 chars\]"); prompt(c, "notes: [K]eep"); c.sendline("k")
    c.expect(r"TOTP secret: \[hidden, 16 chars\]"); prompt(c, "TOTP secret: [K]eep"); c.sendline("c")
    prompt(c, "password"); c.sendline("k")
    c.expect("entry 1 modified"); seen = c.before
    prompt(c, "press ENTER"); c.sendline("")
    tr = (work / "transcript.log").read_text()
    check("MODIFY never prints TOTP secret or notes", "JBSWY3DPEHPK3PXP" not in tr.split("TOTP validated")[1] and "blue" not in tr.split("entry injected")[1])
    # copy to clipboard
    menu(c, "1"); prompt(c, "action"); c.sendline("c"); prompt(c, "entry id to copy"); c.sendline("1")
    c.expect("copied"); prompt(c, "press ENTER")
    check("password reached clipboard", clipfile.read_text() == "short1")
    c.sendline("")
    menu(c, "0"); c.expect("CLIPBOARD CLEARED"); c.expect(pexpect.EOF)
    check("EJECT empties the clipboard", clipfile.read_text() == "")
    clipfile.write_text("unrelated text the user copied")
    c = spawn(base); unlock(c); menu(c, "0"); c.expect(pexpect.EOF)
    check("EJECT clears clipboard even if nothing was copied this session", clipfile.read_text() == "")
    raw = (base / "vault.vt").read_bytes()
    check("no plaintext in vault file", b"bank" not in raw and b"alice" not in raw)
    # wrong password then good one -> failed attempt reported after unlock
    c = spawn(base)
    prompt(c, "master password"); c.sendline("wrong wrong wrong")
    c.expect("AUTH_FAILED", timeout=60)
    prompt(c, "master password")
    sealed = (base / "events.sealed").read_bytes()
    check("failed unlock sealed (not readable before unlock)", b"UNLOCK_FAIL" not in sealed and len(sealed) > 50)
    c.sendline(MASTER)
    c.expect("1 failed unlock attempt", timeout=60)
    check("failed attempt reported after unlock", True)
    prompt(c, "press ENTER"); c.sendline("")
    menu(c, "7"); c.expect("hash chain verified"); c.expect("UNLOCK_FAIL")
    check("LOG shows verified chain and UNLOCK_FAIL", True)
    prompt(c, "ref or seq"); c.sendline("")
    menu(c, "0"); c.expect(pexpect.EOF)

# ── scenario 2: auto-lock while idle at the menu prompt ─────────────────────
if run("autolock"):
    base = work / "v2"
    c = init(base)
    menu(c, "12")
    prompt(c, "expiry_days"); c.sendline("")
    prompt(c, "auto_lock_minutes"); c.sendline("1")
    prompt(c, "enable clipboard"); c.sendline("n")
    c.expect("settings saved"); prompt(c, "press ENTER"); c.sendline("")
    prompt(c, "cmd")
    t0 = time.time()
    c.expect("session locked due to inactivity", timeout=90)
    check(f"auto-lock fired while idle at the menu ({time.time()-t0:.0f}s)", 55 < time.time() - t0 < 75)
    c.sendline("1")   # someone walks up and types a command -> must be treated as a password attempt
    c.expect("AUTH_FAILED", timeout=60)
    check("input after lock goes to the password prompt, not the menu", True)
    unlock(c)
    menu(c, "0"); c.expect(pexpect.EOF)

# ── scenario 3: secret key attachment ───────────────────────────────────────
if run("secretkey"):
    base = work / "v3"
    keyfile = work / "id_test"; keyfile.write_text("-----BEGIN KEY-----\nabc\n-----END KEY-----\n")
    c = init(base)
    menu(c, "3"); prompt(c, "type"); c.sendline("4")
    prompt(c, "name"); c.sendline("server key"); prompt(c, "url"); c.sendline(""); prompt(c, "login"); c.sendline("root")
    prompt(c, "notes"); c.sendline(""); prompt(c, "TOTP secret"); c.sendline("")
    prompt(c, "path of the key file"); c.sendline(str(keyfile))
    c.expect("read id_test"); prompt(c, "store a password"); c.sendline("n")
    prompt(c, "commit to vault"); c.sendline("y"); c.expect("entry injected")
    prompt(c, "delete the original"); c.sendline("y"); c.expect("original file overwritten and deleted")
    check("original key file deleted", not keyfile.exists())
    prompt(c, "press ENTER"); c.sendline("")
    blobs = list((base / "blobs").iterdir())
    check("one padded encrypted blob", len(blobs) == 1 and blobs[0].stat().st_size == 4096 + 28 and b"BEGIN" not in blobs[0].read_bytes())
    out = work / "exported.key"
    menu(c, "1"); prompt(c, "action"); c.sendline("x"); prompt(c, "secret key entry id"); c.sendline("1")
    prompt(c, "export to path"); c.sendline(str(out)); c.expect("exported to")
    check("export restores identical file with 0600", out.read_text().startswith("-----BEGIN KEY") and (out.stat().st_mode & 0o777) == 0o600)
    prompt(c, "press ENTER"); c.sendline("")
    # backup, then rekey -> backups converted
    menu(c, "9"); prompt(c, "action"); c.sendline("n"); c.expect("fully verified"); prompt(c, "press ENTER"); c.sendline("")
    prompt(c, "action"); c.sendline("b")
    menu(c, "8"); prompt(c, "option"); c.sendline("1")
    prompt(c, "current master password"); c.sendline(MASTER)
    prompt(c, "new master password"); c.sendline("Np4!xR8#kW2@zT6-second")
    prompt(c, "confirm master password"); c.sendline("Np4!xR8#kW2@zT6-second")
    prompt(c, "make a verified backup"); c.sendline("y")
    c.expect(r"vault re-keyed\. 2 backup\(s\) now open with the new password", timeout=120)
    check("rekey converted manual + safety backups", True)
    prompt(c, "press ENTER"); c.sendline("")
    menu(c, "11"); c.expect("attachments decrypt"); c.expect("1 ok"); prompt(c, "press ENTER"); c.sendline("")
    check("HEALTH: attachment ok after rekey", True)
    menu(c, "0"); c.expect(pexpect.EOF)
    # restore from CLI into a fresh dir
    bk = sorted((base / "backups").glob("*.vtbak"))[0]
    base4 = work / "v4"
    c = spawn(base4, "--restore", str(bk))
    prompt(c, "master password of this backup"); c.sendline("Np4!xR8#kW2@zT6-second")
    c.expect("verified", timeout=60); prompt(c, "install this backup"); c.sendline("y")
    c.expect("backup restored"); c.expect("access granted"); prompt(c, "press ENTER"); c.sendline("")
    menu(c, "1"); c.expect("server key"); prompt(c, "action"); c.sendline("b")
    check("CLI restore into empty dir works", True)
    menu(c, "0"); c.expect(pexpect.EOF)

# ── scenario 4: paper recovery kit ──────────────────────────────────────────
if run("recovery"):
    base = work / "v5"
    c = init(base)
    menu(c, "13"); prompt(c, "action"); c.sendline("g")
    prompt(c, "master password"); c.sendline(MASTER)
    prompt(c, "number of shares"); c.sendline("3"); prompt(c, "shares needed"); c.sendline("2")
    pdfpath = work / "kit.pdf"
    prompt(c, "write PDF to"); c.sendline(str(pdfpath)); c.expect("recovery kit .* written")
    pdf = pdfpath.read_bytes()
    shutil.copy(pdfpath, work / "kit-copy.pdf")
    prompt(c, "press ENTER after printing"); c.sendline("")
    prompt(c, "shred the PDF now"); c.sendline("y"); c.expect("PDF shredded")
    check("kit PDF shredded after printing", not pdfpath.exists())
    prompt(c, "press ENTER"); c.sendline("")
    menu(c, "0"); c.expect(pexpect.EOF)
    lines = re.findall(rb"\((VT4-[A-Z2-7-]+|[A-Z2-7]{4}(?:-[A-Z2-7]{4}){0,3})\) Tj", pdf)
    shares, cur = [], None
    for l in lines:
        l = l.decode()
        if l.startswith("VT4-"):
            cur = [l]; shares.append(cur)
        else:
            cur.append(l)
    shares = ["-".join(s) for s in shares]
    check("3 shares extracted from PDF", len(shares) == 3)
    c = spawn(base, "--recover")
    prompt(c, "share 1"); c.sendline(shares[2].lower())
    c.expect(r"share #3 accepted \(1/2\)")
    prompt(c, "share 2 of 2"); c.sendline(shares[0])
    c.expect("vault opened with the recovery kit", timeout=60)
    prompt(c, "new master password"); c.sendline("Hb3!yQ7#fM5@jK1-third")
    prompt(c, "confirm master password"); c.sendline("Hb3!yQ7#fM5@jK1-third")
    c.expect("vault re-keyed", timeout=120)
    check("paper recovery + forced new master password", True)
    prompt(c, "press ENTER"); c.sendline("")
    menu(c, "0"); c.expect(pexpect.EOF)
    c = spawn(base); unlock(c, "Hb3!yQ7#fM5@jK1-third"); menu(c, "0"); c.expect(pexpect.EOF)
    check("new master password works after recovery", True)

# ── scenario 5: deadman ──────────────────────────────────────────────────────
if run("deadman"):
    base = work / "v6"
    c = init(base)
    menu(c, "9"); prompt(c, "action"); c.sendline("n"); c.expect("fully verified"); prompt(c, "press ENTER"); c.sendline("")
    prompt(c, "action"); c.sendline("b")
    menu(c, "0"); c.expect(pexpect.EOF)
    c = spawn(base)
    prompt(c, "master password"); c.sendline(DEAD)
    c.expect("VAULT_INTEGRITY", timeout=60); c.expect("reinstall VaultTerm"); c.expect(pexpect.EOF)
    check("deadman: generic corruption message", True)
    check("deadman: vault dir and backups gone", not base.exists())

print(f"\n{sum(ok for _, ok in results)}/{len(results)} checks passed")
shutil.rmtree(work, ignore_errors=True)
sys.exit(0 if all(ok for _, ok in results) else 1)
