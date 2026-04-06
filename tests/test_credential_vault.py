"""Tests for credential vault."""

from utils.credential_vault import CredentialVault, CredType


class TestCredentialVault:
    def test_add_password(self, tmp_session):
        vault = CredentialVault(tmp_session)
        is_new = vault.add_password(username="admin", password="pass123",
                                    host="192.168.1.1", service="ssh")
        assert is_new is True
        assert vault.stats()["total"] == 1
        assert vault.stats()["passwords"] == 1

    def test_deduplication(self, tmp_session):
        vault = CredentialVault(tmp_session)
        vault.add_password(username="admin", password="pass123", host="1.1.1.1")
        vault.add_password(username="admin", password="pass123", host="1.1.1.1")
        assert vault.stats()["total"] == 1  # Duplicate not added

    def test_different_types_not_deduped(self, tmp_session):
        vault = CredentialVault(tmp_session)
        vault.add_password(username="admin", password="pass123")
        vault.add_hash(username="admin", hash_value="aad3b:31d6c",
                       hash_type=CredType.NTLM_HASH)
        assert vault.stats()["total"] == 2

    def test_add_hash(self, tmp_session):
        vault = CredentialVault(tmp_session)
        vault.add_hash(username="admin", hash_value="aad3b435:31d6cfe0",
                       hash_type=CredType.NTLM_HASH, host="1.1.1.1")
        assert vault.stats()["hashes"] == 1

    def test_get_for_host(self, tmp_session):
        vault = CredentialVault(tmp_session)
        vault.add_password(username="admin", password="pass", host="1.1.1.1", service="ssh")
        vault.add_password(username="root", password="toor", host="2.2.2.2", service="ssh")
        creds = vault.get_for_host("1.1.1.1", service="ssh")
        assert len(creds) >= 1
        assert any(c.username == "admin" for c in creds)

    def test_domain_creds_apply_everywhere(self, tmp_session):
        vault = CredentialVault(tmp_session)
        vault.add_password(username="admin", password="pass", domain="LAB",
                           host="1.1.1.1", service="smb")
        creds = vault.get_for_host("2.2.2.2")  # Different host
        assert len(creds) >= 1  # Domain creds are reusable

    def test_mark_verified(self, tmp_session):
        vault = CredentialVault(tmp_session)
        vault.add_password(username="admin", password="pass")
        vault.mark_verified("admin", "pass", "1.1.1.1", admin=True)
        admin_creds = vault.get_admin_creds()
        assert len(admin_creds) == 1

    def test_persistence(self, tmp_session):
        vault1 = CredentialVault(tmp_session)
        vault1.add_password(username="user1", password="pass1", host="1.1.1.1")
        # Create new vault instance — should load from file
        vault2 = CredentialVault(tmp_session)
        assert vault2.stats()["total"] == 1
        assert any(c.username == "user1" for c in vault2.get_all())

    def test_stats(self, tmp_session):
        vault = CredentialVault(tmp_session)
        vault.add_password(username="a", password="1", host="1.1.1.1")
        vault.add_password(username="b", password="2", host="2.2.2.2")
        vault.add_hash(username="c", hash_value="hash", hash_type=CredType.NTLM_HASH)
        vault.add_hash(username="d", hash_value="krb", hash_type=CredType.ASREP_HASH)
        stats = vault.stats()
        assert stats["total"] == 4
        assert stats["passwords"] == 2
        assert stats["hashes"] == 1
        assert stats["kerberos"] == 1
        assert stats["unique_users"] == 4

    def test_report_data_masks_secrets(self, tmp_session):
        vault = CredentialVault(tmp_session)
        vault.add_password(username="admin", password="SuperSecretPassword123")
        report = vault.to_report_data()
        assert len(report) == 1
        # Secret should be partially masked
        assert report[0]["secret"] != "SuperSecretPassword123"
        assert "*" in report[0]["secret"]

    def test_get_unique_usernames(self, tmp_session):
        vault = CredentialVault(tmp_session)
        vault.add_password(username="admin", password="pass1")
        vault.add_password(username="admin", password="pass2")
        vault.add_password(username="root", password="toor")
        assert vault.get_unique_usernames() == {"admin", "root"}
