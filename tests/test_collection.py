import hashlib
import base64
import time

import pytest

import fs_hash_checker as fhc


class FakeChannel:
    def __init__(self, chunks, close_after=False):
        self.chunks = list(chunks)
        self.closed = False
        self.close_after = close_after

    def recv_ready(self):
        if self.chunks:
            return True
        if self.close_after:
            self.closed = True
        return False

    def recv(self, _size):
        if not self.chunks:
            return b""
        return self.chunks.pop(0)


def test_chunked_output_waits_for_completion_marker():
    channel = FakeChannel([
        b"FGT # diagnose sys filesystem hash\nHash contents: /bin\n",
        ("a" * 64 + " /bin/a\nFilesystem hash complete. ").encode(),
        b"Hashed 1 files.\n",
    ])
    output = fhc.read_until_completion(channel, collection_timeout=2, idle_timeout=1)
    assert "Filesystem hash complete. Hashed 1 files." in output


def test_disconnect_before_completion_fails_closed():
    channel = FakeChannel([b"partial output\n"], close_after=True)
    with pytest.raises(fhc.CollectionError, match="closed before") as exc:
        fhc.read_until_completion(channel, collection_timeout=1, idle_timeout=0.2)
    assert "partial output" in exc.value.partial_output


def test_idle_timeout_fails_closed():
    channel = FakeChannel([])
    start = time.monotonic()
    with pytest.raises(fhc.CollectionError, match="idle timeout"):
        fhc.read_until_completion(channel, collection_timeout=1, idle_timeout=0.1)
    assert time.monotonic() - start < 1


def test_sha256_host_key_fingerprint_format():
    key = b"fake-public-key-material"
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")
    assert fhc.host_key_sha256(key) == expected
    assert fhc.normalize_pin(expected + "==") == expected


def test_invalid_fingerprint_pin_is_rejected():
    with pytest.raises(fhc.InputValidationError, match="SHA256"):
        fhc.normalize_pin("MD5:aa:bb")


def test_overall_timeout_fails_closed():
    channel = FakeChannel([])
    with pytest.raises(fhc.CollectionError, match="overall timeout"):
        fhc.read_until_completion(channel, collection_timeout=0.1, idle_timeout=1)
