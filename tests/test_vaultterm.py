"""VaultTerm v4 test suite (stdlib unittest; never touches ~/.vaultterm).

Run:  .venv/bin/python -m unittest discover -s tests -v
"""
import json
import os
import shutil
import struct
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import vaultterm as vt  # noqa: E402

FAST = dict(vt.ARGON2_MIN)
MASTER = "correct horse battery staple"
DEADMAN = "deadman deadman deadman"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vt-test-")
        self._oldP = vt.P
        vt.P = vt.Paths(Path(self.tmp) / "vault")
        self.v = vt.Vault.create(MASTER, DEADMAN, FAST)

    def tearDown(self):
        try:
            self.v.close()
        except Exception:
            pass
        vt.P = self._oldP
        shutil.rmtree(self.tmp, ignore_errors=True)

    def reopen(self, pw=MASTER):
        self.v.close()
        self.v = vt.Vault.unlock(pw)
        return self.v

    def raw(self):
        return vt.P.vault.read_bytes()

    def write_raw(self, data):
        vt.P.vault.write_bytes(data)


class FormatAndIntegrity(Base):
    def test_roundtrip_and_no_plaintext_on_disk(self):
        self.v.add_entry("password", "bank-name", "https://bank.example", "alice", "S3cret-Value-XYZ", "note-text", "")
        self.reopen()
        e = self.v.entries()[0]
        self.assertEqual(e["password"], "S3cret-Value-XYZ")
        blob = self.raw()
        for needle in (b"bank-name", b"alice", b"S3cret", b"note-text", b"bank.example", b"expiry", b"history"):
            self.assertNotIn(needle, blob)

    def test_padding_hides_entry_count_and_lengths(self):
        size0 = len(self.raw())
        self.v.add_entry("password", "a", "", "", "x" * 12, "", "")
        size1 = len(self.raw())
        for i in range(20):
            self.v.add_entry("password", f"name{i}", "https://example.com/" + "p" * i, "user", "y" * (12 + i), "n" * i, "")
        self.assertEqual(size0, size1)
        self.assertEqual(size0, len(self.raw()))

    def test_payload_bitflip_is_integrity_error(self):
        raw = bytearray(self.raw())
        raw[-40] ^= 1
        self.write_raw(bytes(raw))
        with self.assertRaises(vt.VaultError) as cm:
            self.reopen()
        self.assertEqual(cm.exception.kind, "VAULT_INTEGRITY")

    def test_header_tamper_is_detected(self):
        hdr, hb, ct = vt.split_vault(self.raw())
        hdr["core"]["kdf"]["time_cost"] += 1          # still within limits
        hb2 = vt.canon(hdr)
        self.write_raw(vt.MAGIC + struct.pack(">I", len(hb2)) + hb2 + ct)
        with self.assertRaises(vt.VaultError) as cm:
            self.reopen()
        self.assertEqual(cm.exception.kind, "AUTH_FAILED")   # wrap AAD covers the core

    def test_kdf_downgrade_rejected_before_derivation(self):
        hdr, hb, ct = vt.split_vault(self.raw())
        hdr["core"]["kdf"]["memory_cost"] = 8
        hb2 = vt.canon(hdr)
        self.write_raw(vt.MAGIC + struct.pack(">I", len(hb2)) + hb2 + ct)
        with self.assertRaises(vt.VaultError) as cm:
            self.reopen()
        self.assertEqual(cm.exception.kind, "KDF_PARAMS")

    def test_garbage_and_truncation_are_format_errors(self):
        for bad in (b"", b"hello world", self.raw()[:20], b"VTVAULT\x04" + b"\xff" * 40):
            self.write_raw(bad)
            with self.assertRaises(vt.VaultError) as cm:
                vt.Vault.unlock(MASTER)
            self.assertEqual(cm.exception.kind, "VAULT_FORMAT")

    def test_wrong_password_and_deadman(self):
        with self.assertRaises(vt.VaultError) as cm:
            vt.Vault.unlock("not the password")
        self.assertEqual(cm.exception.kind, "AUTH_FAILED")
        with self.assertRaises(vt.DeadmanTriggered):
            vt.Vault.unlock(DEADMAN)

    def test_settings_live_inside_encryption(self):
        with self.v.transaction():
            self.v.settings["clipboard_enabled"] = True
        self.assertNotIn(b"clipboard", self.raw())
        self.assertTrue(self.reopen().settings["clipboard_enabled"])

    def test_rollback_of_single_entry_impossible(self):
        # the old per-row attack: there are no rows any more. replacing the
        # whole file with an older copy is visible through the generation.
        self.v.add_entry("password", "bank", "", "", "OLD-compromised-1", "", "")
        old = self.raw()
        e = self.v.entries()[0]
        self.v.update_entry(e["id"], {"password": "NEW-rotated-pw-2"})
        new_gen = self.v.data["generation"]
        self.write_raw(old)
        self.assertLess(self.reopen().data["generation"], new_gen)


class EntriesAndHistory(Base):
    def test_identical_passwords_give_different_history_fingerprints(self):
        a = self.v.add_entry("password", "a", "", "", "Same-Password-123", "", "")
        b = self.v.add_entry("password", "b", "", "", "Same-Password-123", "", "")
        self.v.update_entry(a, {"password": "other-1-xxxxxxxx"})
        self.v.update_entry(b, {"password": "other-2-xxxxxxxx"})
        ha, hb = self.v.get(a)["history"][0], self.v.get(b)["history"][0]
        self.assertNotEqual(ha, hb)
        self.assertTrue(self.v.used_before(self.v.get(a), "Same-Password-123"))
        self.assertFalse(self.v.used_before(self.v.get(a), "never-used-value"))

    def test_history_survives_rekey(self):
        a = self.v.add_entry("password", "a", "", "", "first-password-1", "", "")
        self.v.update_entry(a, {"password": "second-password-2"})
        self.v.rekey("brand new master 1", FAST).wipe()
        self.assertTrue(self.v.used_before(self.v.get(a), "first-password-1"))

    def test_metadata_edit_does_not_reset_expiry(self):
        a = self.v.add_entry("password", "a", "", "", "first-password-1", "", "")
        with self.v.transaction():
            self.v.get(a)["rotated_at"] = "2000-01-01T00:00:00+00:00"
        self.v.update_entry(a, {"notes": "edited"})
        self.assertTrue(self.v.is_expired(self.v.get(a)))
        self.v.update_entry(a, {"password": "rotated-password-9"})
        self.assertFalse(self.v.is_expired(self.v.get(a)))

    def test_clear_optional_fields(self):
        a = self.v.add_entry("password", "a", "u", "l", "first-password-1", "notes", "JBSWY3DPEHPK3PXP")
        self.v.update_entry(a, {"url": "", "notes": "", "totp": ""})
        e = self.v.get(a)
        self.assertEqual((e["url"], e["notes"], e["totp"]), ("", "", ""))

    def test_failed_save_rolls_back_memory(self):
        before = json.dumps(self.v.data, sort_keys=True)
        with mock.patch.object(vt, "atomic_write", side_effect=vt.VaultError("IO_ERROR", "disk full")):
            with self.assertRaises(vt.VaultError):
                self.v.add_entry("password", "x", "", "", "some-password-1", "", "")
        self.assertEqual(before, json.dumps(self.v.data, sort_keys=True))


class Attachments(Base):
    def test_store_read_tamper(self):
        data = os.urandom(5000)
        eid = self.v.add_entry("secret_key", "ssh", "", "", "", "", "", ("id_ed25519", data))
        self.assertEqual(self.reopen().attachment_bytes(self.v.get(eid)), data)
        bid = self.v.get(eid)["attachment"]["blob"]
        f = vt.blob_file(bid)
        self.assertEqual(f.stat().st_size, 8192 + 28)     # padded bucket
        raw = bytearray(f.read_bytes())
        raw[100] ^= 1
        f.write_bytes(bytes(raw))
        with self.assertRaises(vt.VaultError) as cm:
            self.v.attachment_bytes(self.v.get(eid))
        self.assertEqual(cm.exception.kind, "BLOB_INTEGRITY")

    def test_delete_entry_shreds_blob_and_housekeeping_removes_orphans(self):
        eid = self.v.add_entry("secret_key", "k", "", "", "", "", "", ("k", b"abc"))
        bid = self.v.get(eid)["attachment"]["blob"]
        self.v.delete_entry(eid)
        self.assertFalse(vt.blob_file(bid).exists())
        orphan = vt.P.blobs / ("ab" * 16 + ".blob")
        orphan.write_bytes(b"junk")
        notes = vt.housekeeping(self.v)
        self.assertFalse(orphan.exists())
        self.assertTrue(any("orphan" in d for _, d in notes))


class Rekey(Base):
    def test_rekey_rotates_dek_and_blobs(self):
        eid = self.v.add_entry("secret_key", "k", "", "", "", "", "", ("k", b"payload"))
        old_bid = self.v.get(eid)["attachment"]["blob"]
        old_dek = bytes(self.v.keys.dek)
        self.v.rekey("brand new master 1", FAST).wipe()
        self.assertNotEqual(old_dek, bytes(self.v.keys.dek))
        self.assertFalse(vt.blob_file(old_bid).exists())
        self.reopen("brand new master 1")
        self.assertEqual(self.v.attachment_bytes(self.v.get(eid)), b"payload")
        with self.assertRaises(vt.VaultError):
            vt.Vault.unlock(MASTER)

    def test_ctrl_c_during_blob_reencryption_leaves_old_vault_intact(self):
        for i in range(3):
            self.v.add_entry("secret_key", f"k{i}", "", "", "", "", "", (f"k{i}", os.urandom(100)))
        before = self.raw()
        real = vt.write_blob
        calls = {"n": 0}

        def boom(keys, plain):
            calls["n"] += 1
            if calls["n"] == 2:
                raise KeyboardInterrupt
            return real(keys, plain)

        with mock.patch.object(vt, "write_blob", boom):
            with self.assertRaises(KeyboardInterrupt):
                self.v.rekey("brand new master 1", FAST)
        self.assertEqual(before, self.raw())
        self.assertEqual(len(list(vt.P.blobs.iterdir())), 3)     # new blobs cleaned up
        v = self.reopen(MASTER)
        for e in v.entries():
            v.attachment_bytes(e)

    def test_crash_during_commit_leaves_old_vault_intact(self):
        self.v.add_entry("password", "a", "", "", "first-password-1", "", "")
        before = self.raw()
        with mock.patch.object(vt.os, "replace", side_effect=OSError(5, "I/O error")):
            with self.assertRaises(vt.VaultError):
                self.v.rekey("brand new master 1", FAST)
        self.assertEqual(before, self.raw())
        self.assertEqual(self.reopen(MASTER).entries()[0]["password"], "first-password-1")
        self.assertEqual(list(vt.P.base.glob(".vault.vt.*.tmp")), [])

    def test_rekey_upgrades_kdf_params(self):
        params = dict(FAST, time_cost=3)
        self.v.rekey(MASTER, params).wipe()
        self.assertEqual(self.v.header["core"]["kdf"], params)


class Backups(Base):
    def test_backup_verify_convert_restore(self):
        eid = self.v.add_entry("secret_key", "k", "", "", "pw-inside-xxxxx", "", "", ("k", b"blobdata"))
        path, info = vt.create_backup(self.v)
        info.wipe()
        old = self.v.rekey("brand new master 1", FAST)
        conv, stale = vt.convert_backups(old, self.v)
        old.wipe()
        self.assertEqual((conv, stale), ([path], []))
        with self.assertRaises(vt.VaultError):
            vt.verify_backup(path, password=MASTER)          # old password no longer opens it
        info = vt.verify_backup(path, password="brand new master 1")
        self.v.delete_entry(eid)
        self.v.close()
        self.v = vt.install_backup(info)
        self.assertEqual(self.v.attachment_bytes(self.v.get(eid)), b"blobdata")

    def test_stale_backup_is_reported(self):
        path, info = vt.create_backup(self.v)
        info.wipe()
        self.v.rekey("brand new master 1", FAST).wipe()
        old = self.v.rekey("third master pass 3", FAST)
        conv, stale = vt.convert_backups(old, self.v)
        old.wipe()
        self.assertEqual(stale, [path])

    def test_corrupt_backup_fails_verification(self):
        self.v.add_entry("secret_key", "k", "", "", "", "", "", ("k", b"blobdata"))
        path, info = vt.create_backup(self.v)
        info.wipe()
        raw, blobs = vt.read_backup(path)
        bid = next(iter(blobs))
        evil = Path(self.tmp) / "evil.vtbak"
        with tarfile.open(evil, "w") as tar:
            vt._tar_add_bytes(tar, "vault.vt", raw)
            vt._tar_add_bytes(tar, f"blobs/{bid}.blob", b"x" * len(blobs[bid]))
        with self.assertRaises(vt.VaultError) as cm:
            vt.verify_backup(evil, kek=self.v.kek, dek=self.v.keys.dek)
        self.assertEqual(cm.exception.kind, "BACKUP_INVALID")

    def test_path_traversal_members_rejected(self):
        evil = Path(self.tmp) / "evil.vtbak"
        with tarfile.open(evil, "w") as tar:
            vt._tar_add_bytes(tar, "vault.vt", self.raw())
            vt._tar_add_bytes(tar, "../../outside", b"x")
        with self.assertRaises(vt.VaultError):
            vt.read_backup(evil)
        evil2 = Path(self.tmp) / "evil2.vtbak"
        with tarfile.open(evil2, "w") as tar:
            ti = tarfile.TarInfo("vault.vt")
            ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
            tar.addfile(ti)
        with self.assertRaises(vt.VaultError):
            vt.read_backup(evil2)


class Recovery(Base):
    def test_kit_opens_vault_and_survives_rekey(self):
        self.v.add_entry("password", "a", "", "", "first-password-1", "", "")
        kit, shares = self.v.create_recovery(2, 3)
        texts = [vt.encode_share(kit, 2, x, y) for x, y in shares]
        self.v.rekey("brand new master 1", FAST).wipe()
        picked = {}
        for t in (texts[0], texts[2]):
            kid, k, x, y = vt.decode_share(t.lower().replace("-", " "))
            picked[x] = y
        rv = vt.Vault.unlock_with_recovery(vt.shamir_combine(picked))
        self.assertEqual(rv.entries()[0]["password"], "first-password-1")
        rv.close()

    def test_one_share_is_not_enough_and_revoke_works(self):
        kit, shares = self.v.create_recovery(2, 3)
        with self.assertRaises(vt.VaultError):
            vt.Vault.unlock_with_recovery(vt.shamir_combine({shares[0][0]: shares[0][1]}))
        self.v.revoke_recovery()
        with self.assertRaises(vt.VaultError):
            vt.Vault.unlock_with_recovery(vt.shamir_combine(dict(shares[:2])))

    def test_typo_detected(self):
        kit, shares = self.v.create_recovery(1, 1)
        t = vt.encode_share(kit, 1, 1, shares[0][1])
        bad = t[:-3] + ("A" if t[-3] != "A" else "B") + t[-2:]
        with self.assertRaises(vt.VaultError):
            vt.decode_share(bad)

    def test_pdf(self):
        pdf = vt.build_recovery_pdf("0a1b2c3d", 2, 3, [(1, "VT4-ABCD-EFGH"), (2, "VT4-IJKL")], "2026-01-01")
        self.assertTrue(pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF"))
        self.assertIn(b"/Count 2", pdf)


class LogAndEvents(Base):
    def test_chain_detects_edits_and_deletions(self):
        for i in range(5):
            self.v.log_and_save("TEST", detail=str(i))
        self.assertTrue(self.v.verify_log()[0])
        self.v.data["log"]["items"][2]["detail"] = "forged"
        self.assertFalse(self.v.verify_log()[0])
        self.reopen()
        del self.v.data["log"]["items"][3]
        self.assertFalse(self.v.verify_log()[0])

    def test_chain_survives_rekey_and_truncation(self):
        with mock.patch.object(vt, "LOG_MAX_ITEMS", 10):
            for i in range(25):
                self.v.log_and_save("TEST", detail=str(i))
        self.v.rekey("brand new master 1", FAST).wipe()
        self.assertTrue(self.v.verify_log()[0])

    def test_sealed_events_only_readable_after_unlock(self):
        pub = vt.peek_event_pubkey()
        vt.seal_event(pub, {"type": "UNLOCK_FAIL", "ts": "2026-01-01T00:00:00+00:00"})
        self.assertNotIn(b"UNLOCK_FAIL", vt.P.events.read_bytes())
        events, bad = vt.unseal_events(self.v.data["event_privkey"])
        self.assertEqual((events[0]["type"], bad), ("UNLOCK_FAIL", 0))


class PasswordsAndTotp(unittest.TestCase):
    def test_estimator(self):
        for weak in ("Password123!Password", "Summer2024!Summer2024!", "qwertyuiop123", "aaaaaaaaaaaaaaaa1A!"):
            self.assertLess(vt.estimate_bits(weak), 40, weak)
        self.assertGreater(vt.estimate_bits(vt.gen_password(24)[0]), 120)
        self.assertGreater(vt.estimate_bits(vt.gen_passphrase(6)[0]), 70)

    def test_generators(self):
        pw, bits = vt.gen_passphrase(6)
        self.assertEqual(len(pw.split("-")), 6)
        self.assertAlmostEqual(bits, 6 * 12.925, places=2)
        pin, _ = vt.gen_pin(6)
        self.assertTrue(pin.isdigit() and len(pin) == 6)
        for prof in vt.GEN_PROFILES:
            p, _ = vt.gen_password(16, prof)
            self.assertEqual(len(p), 16)
            for cls in vt.GEN_PROFILES[prof]:
                self.assertTrue(any(c in cls for c in p))

    def test_totp_rfc6238(self):
        s = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        for t, code in ((59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (2000000000, "69279037")):
            self.assertEqual(vt.totp_code(s, at=t, digits=8), code)
        with self.assertRaises(vt.VaultError):
            vt.totp_code("not base32 !!")

    def test_shamir_all_subsets(self):
        import itertools
        secret = os.urandom(32)
        shares = vt.shamir_split(secret, 3, 5)
        for combo in itertools.combinations(shares, 3):
            self.assertEqual(vt.shamir_combine(dict(combo)), secret)


class Filesystem(unittest.TestCase):
    def test_shred_does_not_follow_symlinks(self):
        d = Path(tempfile.mkdtemp())
        try:
            target = d / "precious"
            target.write_bytes(b"keep me")
            (d / "tree").mkdir()
            (d / "tree" / "link").symlink_to(target)
            (d / "tree" / "file").write_bytes(b"x")
            vt.shred_tree(d / "tree")
            self.assertFalse((d / "tree").exists())
            self.assertEqual(target.read_bytes(), b"keep me")
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
