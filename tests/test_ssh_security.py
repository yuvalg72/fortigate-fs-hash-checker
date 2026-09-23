import base64
import hashlib

import pytest

paramiko = pytest.importorskip("paramiko")

import fs_hash_checker as fhc


class FakeKey:
    def __init__(self, material=b"key-material"):
        self.material = material

    def asbytes(self):
        return self.material

    def get_name(self):
        return "ssh-ed25519"

    def get_base64(self):
        return base64.b64encode(self.material).decode()


class CompletedChannel:
    closed = False

    def __init__(self):
        self.sent = []
        self.chunks = []

    def send(self, value):
        self.sent.append(value)
        if value == "diagnose sys filesystem hash\n":
            self.chunks.append(b"Filesystem hash complete. Hashed 0 files.\n")

    def recv_ready(self):
        return bool(self.chunks)

    def recv(self, _size):
        return self.chunks.pop(0)


class FakeSSHClient:
    instance = None

    def __init__(self):
        FakeSSHClient.instance = self
        self.policy = None
        self.width = None
        self.height = None
        self.channel = CompletedChannel()

    def load_system_host_keys(self):
        pass

    def load_host_keys(self, _path):
        pass

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, *args, **kwargs):
        self.connect_kwargs = kwargs

    def invoke_shell(self, term, width, height):
        self.width = width
        self.height = height
        return self.channel

    def close(self):
        pass


def test_default_unknown_host_policy_is_reject(monkeypatch):
    monkeypatch.setattr(paramiko, "SSHClient", FakeSSHClient)
    output = fhc.collect_raw_hashes("192.0.2.1", "admin", collection_timeout=1, idle_timeout=1)
    client = FakeSSHClient.instance
    assert isinstance(client.policy, paramiko.RejectPolicy)
    assert "Filesystem hash complete" in output


def test_collector_requests_wide_pty(monkeypatch):
    monkeypatch.setattr(paramiko, "SSHClient", FakeSSHClient)
    fhc.collect_raw_hashes("192.0.2.1", "admin", collection_timeout=1, idle_timeout=1)
    client = FakeSSHClient.instance
    assert client.width == fhc.PTY_WIDTH
    assert client.width > 240
    assert client.height == fhc.PTY_HEIGHT
    assert client.channel.sent == ["diagnose sys filesystem hash\n"]


def test_pinned_policy_accepts_exact_unknown_key():
    key = FakeKey(b"expected-key")
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    policy = fhc.make_pinned_policy(paramiko, expected)
    policy.missing_host_key(None, "fortigate.example", key)


def test_pinned_policy_rejects_wrong_unknown_key():
    expected_key = FakeKey(b"expected-key")
    actual_key = FakeKey(b"different-key")
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(expected_key.asbytes()).digest()).decode().rstrip("=")
    policy = fhc.make_pinned_policy(paramiko, expected)
    with pytest.raises(paramiko.SSHException, match="fingerprint mismatch"):
        policy.missing_host_key(None, "fortigate.example", actual_key)


def test_changed_known_host_key_is_translated_to_collection_failure(monkeypatch):
    class ChangedKeyClient(FakeSSHClient):
        def connect(self, *args, **kwargs):
            raise paramiko.BadHostKeyException("fortigate.example", FakeKey(b"new"), FakeKey(b"old"))

    monkeypatch.setattr(paramiko, "SSHClient", ChangedKeyClient)
    with pytest.raises(fhc.CollectionError, match="host-key mismatch"):
        fhc.collect_raw_hashes("fortigate.example", "admin")
