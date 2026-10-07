"""VaultTerm v5 test suite (stdlib unittest; never touches ~/.vaultterm).

Run:  .venv/bin/python -m unittest discover -s tests -v
"""
import base64
import itertools
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
        vt.P = vt.Paths(Path(self.tmp) / "vault", Path(self.tmp) / "state")
        self.v = vt.Vault.create(MASTER, DEADMAN, FAST)

    def tearDown(self):
        try:
            self.v.close()
        except Exception:
            pass
        vt.P = self._oldP
        shutil.rmtree(self.tmp, ignore_errors=True)

    def reopen(self, pw=MASTER, kf=None):
        self.v.close()
        self.v = vt.Vault.unlock(pw, kf)
        return self.v

    def raw(self):
        return vt.P.vault.read_bytes()

    def write_raw(self, data):
        vt.P.vault.write_bytes(data)


class Primitives(unittest.TestCase):
    def test_key_commitment(self):
        k1, k2 = os.urandom(32), os.urandom(32)
        blob = vt.aead_seal(k1, b"secret", b"aad")
        self.assertEqual(vt.aead_open(k1, blob, b"aad"), b"secret")
        for key, aad in ((k2, b"aad"), (k1, b"other")):
            with self.assertRaises(vt.InvalidTag):
                vt.aead_open(key, blob, aad)
        forged = bytearray(blob)
        forged[20] ^= 1          # inside the commitment tag
        with self.assertRaises(vt.InvalidTag):
            vt.aead_open(k1, bytes(forged), b"aad")

    def test_blake2b_everywhere(self):
        self.assertEqual(vt.b2file_hex(b"abc"), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                                                "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
        self.assertNotEqual(vt.b2(b"x", b"a"), vt.b2(b"x", b"b"))      # personalisation separates domains
        self.assertNotEqual(vt.b2(b"x", key=b"k1"), vt.b2(b"x", key=b"k2"))

    def test_hybrid_kem_events(self):
        tmp = tempfile.mkdtemp()
        old = vt.P
        vt.P = vt.Paths(Path(tmp) / "v", Path(tmp) / "s")
        try:
            priv, pub = vt.new_event_keys()
            vt.seal_event(pub, {"type": "UNLOCK_FAIL", "ts": "t1"})
            vt.seal_event(pub, {"type": "ERROR", "detail": "secret detail"})
            raw = vt.P.events.read_bytes()
            self.assertNotIn(b"secret detail", raw)
            self.assertGreater(len(raw.splitlines()[0]), (32 + vt.MLKEM_CT_LEN) * 4 // 3)   # ML-KEM ciphertext present
            events, bad = vt.unseal_events(priv)
            self.assertEqual(([e["type"] for e in events], bad), (["UNLOCK_FAIL", "ERROR"], 0))
            other, _ = vt.new_event_keys()
            self.assertEqual(vt.unseal_events(other), ([], 2))
        finally:
            vt.P = old
            shutil.rmtree(tmp, ignore_errors=True)


class FormatAndIntegrity(Base):
    def test_roundtrip_and_no_plaintext_on_disk(self):
        self.v.add_entry("password", "bank-name", "https://bank.example", "alice", "S3cret-Value-XYZ", "note-text", "")
        self.reopen()
        self.assertEqual(self.v.entries()[0]["password"], "S3cret-Value-XYZ")
        blob = self.raw()
        for needle in (b"bank-name", b"alice", b"S3cret", b"note-text", b"bank.example", b"expiry", b"history"):
            self.assertNotIn(needle, blob)

    def test_padding_hides_entry_count_and_lengths(self):
        size0 = len(self.raw())
        self.v.add_entry("password", "a", "", "", "x" * 12, "", "")
        for i in range(20):
            self.v.add_entry("password", f"name{i}", "https://example.com/" + "p" * i, "user", "y" * (12 + i), "n" * i, "")
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
        hdr["core"]["kdf"]["time_cost"] += 1
        hb2 = vt.canon(hdr)
        self.write_raw(vt.MAGIC + struct.pack(">I", len(hb2)) + hb2 + ct)
        with self.assertRaises(vt.VaultError) as cm:
            self.reopen()
        self.assertEqual(cm.exception.kind, "AUTH_FAILED")

    def test_kdf_downgrade_rejected_before_derivation(self):
        hdr, hb, ct = vt.split_vault(self.raw())
        hdr["core"]["kdf"]["memory_cost"] = 8
        hb2 = vt.canon(hdr)
        self.write_raw(vt.MAGIC + struct.pack(">I", len(hb2)) + hb2 + ct)
        with self.assertRaises(vt.VaultError) as cm:
            self.reopen()
        self.assertEqual(cm.exception.kind, "KDF_PARAMS")

    def test_garbage_and_truncation_are_format_errors(self):
        for bad in (b"", b"hello world", self.raw()[:20], vt.MAGIC + b"\xff" * 80, b"VTVAULT\x04" + self.raw()[8:]):
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


class Rollback(Base):
    def test_older_copy_is_detected(self):
        self.v.add_entry("password", "bank", "", "", "OLD-compromised-1", "", "")
        old = self.raw()
        self.v.update_entry(self.v.entries()[0]["id"], {"password": "NEW-rotated-pw-2"})
        self.assertEqual(self.v.rollback_status()[0], "ok")
        self.write_raw(old)
        status, body = self.reopen().evaluate_rollback()
        self.assertEqual(status, "rollback")
        self.assertGreater(body["generation"], self.v.data["generation"])
        # working on the old copy (even past the recorded generation) must keep the evidence
        for _ in range(6):
            self.v.log_and_save("TEST")
        self.assertEqual(self.v.rollback_status()[0], "rollback")
        self.assertEqual(self.reopen().evaluate_rollback()[0], "rollback")      # survives a restart
        self.v.accept_older_copy()
        self.assertEqual(self.v.rollback_status()[0], "ok")
        self.assertEqual(self.reopen().evaluate_rollback()[0], "ok")

    def test_same_generation_different_content_is_rollback(self):
        old = self.raw()
        self.v.log_and_save("A")
        self.write_raw(old)
        v = self.reopen()
        self.assertEqual(v.evaluate_rollback()[0], "rollback")

    def test_interrupted_state_write_is_only_ahead(self):
        with mock.patch.object(vt, "write_state"):
            self.v.log_and_save("A")          # vault written, state not updated (simulated crash)
        self.assertEqual(self.reopen().evaluate_rollback()[0], "ahead")
        self.v.log_and_save("B")
        self.assertEqual(self.v.rollback_status()[0], "ok")

    def test_accepting_continues_the_counter(self):
        old = self.raw()
        self.v.log_and_save("A")
        self.v.log_and_save("B")
        newest = self.v.data["generation"]
        self.write_raw(old)
        v = self.reopen()
        self.assertEqual(v.evaluate_rollback()[0], "rollback")
        v.accept_older_copy()
        self.assertEqual(v.rollback_status()[0], "ok")
        self.assertGreater(v.data["generation"], newest)

    def test_state_file_tamper_detected(self):
        f = vt.P.state_file(self.v.vault_id)
        doc = json.loads(f.read_text())
        doc["generation"] = 999999
        f.write_text(json.dumps(doc))
        self.assertEqual(self.v.rollback_status()[0], "tampered")

    def test_restore_keeps_generation_monotonic(self):
        path, info = vt.create_backup(self.v)
        info.wipe()
        for i in range(5):
            self.v.log_and_save("X")
        newest = self.v.data["generation"]
        info = vt.verify_backup(path, password=MASTER)
        self.v.close()
        self.v = vt.install_backup(info)
        self.assertGreater(self.v.data["generation"], newest)
        self.assertEqual(self.v.rollback_status()[0], "ok")


class Keyfile(Base):
    def setUp(self):
        super().setUp()
        self.kf_path = str(Path(self.tmp) / "usb.key")
        self.kf = vt.create_keyfile(self.kf_path)

    def test_keyfile_required_and_checked(self):
        self.v.add_entry("password", "a", "", "", "first-password-1", "", "")
        self.v.rekey(MASTER, FAST, self.kf).wipe()
        self.v.close()
        with self.assertRaises(vt.VaultError) as cm:
            vt.Vault.unlock(MASTER)
        self.assertEqual(cm.exception.kind, "KEYFILE")
        other = Path(self.tmp) / "other.key"
        other.write_bytes(os.urandom(64))
        with self.assertRaises(vt.VaultError) as cm:
            vt.Vault.unlock(MASTER, vt.read_keyfile(str(other)))
        self.assertEqual(cm.exception.kind, "AUTH_FAILED")
        self.v = vt.Vault.unlock(MASTER, vt.read_keyfile(self.kf_path))
        self.assertEqual(self.v.entries()[0]["password"], "first-password-1")
        self.assertTrue(self.v.verify_master(MASTER))

    def test_deadman_works_without_keyfile(self):
        self.v.rekey(MASTER, FAST, self.kf).wipe()
        self.v.close()
        with self.assertRaises(vt.DeadmanTriggered):
            vt.Vault.unlock(DEADMAN)
        with self.assertRaises(vt.DeadmanTriggered):
            vt.Vault.unlock(DEADMAN, self.kf)

    def test_remove_keyfile_and_convert_backups(self):
        path, info = vt.create_backup(self.v)
        info.wipe()
        old = self.v.rekey(MASTER, FAST, self.kf)
        self.assertEqual(vt.convert_backups(old, self.v)[0], [path])
        old.wipe()
        with self.assertRaises(vt.VaultError):
            vt.verify_backup(path, password=MASTER)                    # now needs the keyfile
        vt.verify_backup(path, password=MASTER, keyfile=self.kf).wipe()
        self.v.rekey(MASTER, FAST, None).wipe()
        self.reopen(MASTER)

    def test_tiny_or_missing_keyfile_rejected(self):
        small = Path(self.tmp) / "small"
        small.write_bytes(b"x" * 10)
        for p in (str(small), str(Path(self.tmp) / "nope")):
            with self.assertRaises(vt.VaultError) as cm:
                vt.read_keyfile(p)
            self.assertEqual(cm.exception.kind, "KEYFILE")


class EntriesAndHistory(Base):
    def test_identical_passwords_give_different_history_fingerprints(self):
        a = self.v.add_entry("password", "a", "", "", "Same-Password-123", "", "")
        b = self.v.add_entry("password", "b", "", "", "Same-Password-123", "", "")
        self.v.update_entry(a, {"password": "other-1-xxxxxxxx"})
        self.v.update_entry(b, {"password": "other-2-xxxxxxxx"})
        self.assertNotEqual(self.v.get(a)["history"][0], self.v.get(b)["history"][0])
        self.assertEqual(len(self.v.get(a)["history"][0]), 128)               # BLAKE2b-512 hex
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

    def test_totp_algorithm_per_entry(self):
        a = self.v.add_entry("password", "a", "u", "l", "first-password-1", "notes", "JBSWY3DPEHPK3PXP", None, "SHA512")
        self.assertEqual(self.reopen().get(a)["totp_algo"], "SHA512")
        self.v.update_entry(a, {"totp_algo": "SHA1"})
        self.assertEqual(self.v.get(a)["totp_algo"], "SHA1")
        with self.assertRaises(vt.VaultError):
            self.v.update_entry(a, {"totp_algo": "BLAKE2B"})
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
        att = self.v.get(eid)["attachment"]
        self.assertEqual(att["b2"], vt.hashlib.blake2b(data).hexdigest())     # same as `b2sum`
        f = vt.blob_file(att["blob"])
        self.assertEqual(f.stat().st_size, 8192 + vt.AEAD_OVERHEAD)
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
        self.assertEqual(len(list(vt.P.blobs.iterdir())), 3)
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
            vt.verify_backup(path, password=MASTER)
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
    def test_kit_opens_vault_and_survives_rekey_and_keyfile(self):
        self.v.add_entry("password", "a", "", "", "first-password-1", "", "")
        kit, shares = self.v.create_recovery(2, 3)
        texts = [vt.encode_share(kit, 2, x, y) for x, y in shares]
        self.assertTrue(texts[0].startswith("VT5-"))
        kf = vt.create_keyfile(str(Path(self.tmp) / "k"))
        self.v.rekey("brand new master 1", FAST, kf).wipe()
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
        pdf = vt.build_recovery_pdf("0a1b2c3d", 2, 3, [(1, "VT5-ABCD-EFGH"), (2, "VT5-IJKL")], "2026-01-01")
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
        vt.seal_event(vt.peek_core()["event_pub"], {"type": "UNLOCK_FAIL", "ts": "2026-01-01T00:00:00+00:00"})
        self.assertNotIn(b"UNLOCK_FAIL", vt.P.events.read_bytes())
        events, bad = vt.unseal_events(self.v.data["event_keys"])
        self.assertEqual((events[0]["type"], bad), ("UNLOCK_FAIL", 0))


class PasswordsAndTotp(unittest.TestCase):
    def test_estimator(self):
        for weak in ("Password123!Password", "Summer2024!Summer2024!", "qwertyuiop123", "aaaaaaaaaaaaaaaa1A!"):
            self.assertLess(vt.estimate_bits(weak), 40, weak)
        self.assertGreater(vt.estimate_bits(vt.gen_password(24)[0]), 120)
        self.assertGreater(vt.estimate_bits(vt.gen_passphrase(vt.PHRASE_DEFAULT)[0]), vt.MASTER_TARGET_BITS)

    def test_generators(self):
        pw, bits = vt.gen_passphrase(7)
        self.assertEqual(len(pw.split("-")), 7)
        self.assertAlmostEqual(bits, 7 * 12.925, places=2)
        pin, _ = vt.gen_pin(6)
        self.assertTrue(pin.isdigit() and len(pin) == 6)
        for prof in vt.GEN_PROFILES:
            p, _ = vt.gen_password(16, prof)
            self.assertEqual(len(p), 16)
            for cls in vt.GEN_PROFILES[prof]:
                self.assertTrue(any(c in cls for c in p))

    def test_totp_rfc6238_all_algorithms(self):
        keys = {"SHA1": b"12345678901234567890", "SHA256": b"12345678901234567890123456789012",
                "SHA512": b"1234567890" * 6 + b"1234"}
        vectors = {  # RFC 6238 appendix B
            59: ("94287082", "46119246", "90693936"),
            1111111109: ("07081804", "68084774", "25091201"),
            1111111111: ("14050471", "67062674", "99943326"),
            1234567890: ("89005924", "91819424", "93441116"),
            2000000000: ("69279037", "90698825", "38618901"),
            20000000000: ("65353130", "77737706", "47863826"),
        }
        for t, codes in vectors.items():
            for algo, code in zip(("SHA1", "SHA256", "SHA512"), codes):
                secret = base64.b32encode(keys[algo]).decode()
                self.assertEqual(vt.totp_code(secret, at=t, algo=algo, digits=8), code, (t, algo))
        with self.assertRaises(vt.VaultError):
            vt.totp_code("not base32 !!")

    def test_shamir_all_subsets(self):
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
