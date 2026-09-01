"""Unit tests for client.acme_client pure logic (no network access).

Per CONTRIBUTING.md: unit test pure logic (base64url helpers, JWK thumbprint,
JWS signing) without hitting the network; mock httpx.Client for endpoint tests.
"""

from __future__ import annotations

import json
import os
import stat
from unittest import mock

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from client.acme_client import AcmeClient, _b64url, _b64url_decode


class TestBase64URLHelpers:
    def test_roundtrip(self):
        data = b"\x00\x01\xff\xfe\x10hello world"
        assert _b64url_decode(_b64url(data)) == data

    def test_no_padding_or_unsafe_characters(self):
        encoded = _b64url(b"\xfb\xff\xbf")

        assert "=" not in encoded
        assert "+" not in encoded
        assert "/" not in encoded

    def test_decode_adds_missing_padding(self):
        # 5 raw bytes -> base64 needs 2 '=' of padding, stripped by encoder.
        data = b"abcde"
        encoded = _b64url(data)
        assert _b64url_decode(encoded) == data

    def test_decode_handles_dash_and_underscore(self):
        # base64 alphabet chars '+' and '/' map to '-' and '_' in base64url.
        raw = bytes.fromhex("fbff")  # encodes to "+/8=" in standard base64
        encoded = _b64url(raw)
        assert "-" in encoded or "_" in encoded
        assert _b64url_decode(encoded) == raw


@pytest.fixture()
def acme_client(tmp_path) -> AcmeClient:
    return AcmeClient(ra_url="https://ra.example.com", data_dir=str(tmp_path))


class TestAccountKeyPersistence:
    def test_generates_ec_p256_key_on_first_use(self, acme_client):
        key = acme_client._load_or_create_key()

        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp256r1"

    def test_key_file_created_with_owner_only_permissions(self, acme_client):
        acme_client._load_or_create_key()

        mode = stat.S_IMODE(os.stat(acme_client._key_path).st_mode)
        assert mode == 0o600

    def test_reuses_persisted_key_across_instances(self, tmp_path):
        first = AcmeClient(ra_url="https://ra.example.com", data_dir=str(tmp_path))
        key1 = first._load_or_create_key()

        second = AcmeClient(ra_url="https://ra.example.com", data_dir=str(tmp_path))
        key2 = second._load_or_create_key()

        assert key1.public_key().public_numbers() == key2.public_key().public_numbers()

    def test_rejects_non_ec_key_on_disk(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        client = AcmeClient(ra_url="https://ra.example.com", data_dir=str(tmp_path))
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with open(client._key_path, "wb") as fh:
            fh.write(pem)

        with pytest.raises(TypeError, match="Expected EC private key"):
            client._load_or_create_key()


class TestJWK:
    def test_get_jwk_has_expected_shape(self, acme_client):
        jwk = acme_client._get_jwk()

        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert isinstance(jwk["x"], str)
        assert isinstance(jwk["y"], str)

    def test_thumbprint_is_stable_for_same_key(self, acme_client):
        assert acme_client._thumbprint() == acme_client._thumbprint()

    def test_thumbprint_differs_across_distinct_keys(self, tmp_path):
        client_a = AcmeClient(ra_url="https://ra.example.com", data_dir=str(tmp_path / "a"))
        client_b = AcmeClient(ra_url="https://ra.example.com", data_dir=str(tmp_path / "b"))

        assert client_a._thumbprint() != client_b._thumbprint()

    def test_thumbprint_matches_rfc7638_canonical_json(self, acme_client):
        jwk = acme_client._get_jwk()
        members = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
        canonical = json.dumps(members, sort_keys=True, separators=(",", ":"))

        import hashlib

        expected = _b64url(hashlib.sha256(canonical.encode()).digest())
        assert acme_client._thumbprint() == expected


class TestSignJWS:
    def test_produces_flattened_json_with_expected_keys(self, acme_client):
        body_bytes = acme_client._sign_jws(
            "https://ra.example.com/acme/new-account",
            {"termsOfServiceAgreed": True},
            use_jwk=True,
            nonce="test-nonce",
        )
        body = json.loads(body_bytes)

        assert set(body.keys()) == {"protected", "payload", "signature"}

    def test_signature_verifies_against_public_key(self, acme_client):
        url = "https://ra.example.com/acme/new-order"
        payload = {"identifiers": [{"type": "dns", "value": "example.com"}]}
        body_bytes = acme_client._sign_jws(url, payload, use_jwk=True, nonce="abc123")
        body = json.loads(body_bytes)

        sign_input = f"{body['protected']}.{body['payload']}".encode()
        sig_p1363 = _b64url_decode(body["signature"])
        r = int.from_bytes(sig_p1363[:32], "big")
        s = int.from_bytes(sig_p1363[32:], "big")
        sig_der = encode_dss_signature(r, s)

        public_key = acme_client._load_or_create_key().public_key()
        from cryptography.hazmat.primitives import hashes

        # Raises InvalidSignature if verification fails.
        public_key.verify(sig_der, sign_input, ec.ECDSA(hashes.SHA256()))

    def test_use_jwk_embeds_public_key_in_protected_header(self, acme_client):
        body_bytes = acme_client._sign_jws(
            "https://ra.example.com/acme/new-account",
            {},
            use_jwk=True,
            nonce="n1",
        )
        body = json.loads(body_bytes)
        protected = json.loads(_b64url_decode(body["protected"]))

        assert "jwk" in protected
        assert "kid" not in protected

    def test_without_jwk_uses_kid_from_account_id(self, acme_client):
        acme_client._account_id = "12345"
        body_bytes = acme_client._sign_jws(
            "https://ra.example.com/acme/new-order",
            {},
            use_jwk=False,
            nonce="n2",
        )
        body = json.loads(body_bytes)
        protected = json.loads(_b64url_decode(body["protected"]))

        assert protected["kid"] == "https://ra.example.com/acme/account/12345"
        assert "jwk" not in protected

    def test_none_payload_produces_empty_payload_for_post_as_get(self, acme_client):
        body_bytes = acme_client._sign_jws(
            "https://ra.example.com/acme/order/1", None, use_jwk=True, nonce="n3"
        )
        body = json.loads(body_bytes)

        assert body["payload"] == ""


class TestHttpClientTLSVerification:
    def test_disables_verification_when_no_ca_cert_configured(self, tmp_path):
        client = AcmeClient(ra_url="https://ra.example.com", data_dir=str(tmp_path))

        with mock.patch("client.acme_client.httpx.Client") as spy:
            client._http_client()

        assert spy.call_args.kwargs["verify"] is False

    def test_uses_ca_cert_path_when_provided(self, tmp_path):
        ca_cert = tmp_path / "ca.crt"
        ca_cert.write_text("dummy")
        client = AcmeClient(
            ra_url="https://ra.example.com",
            data_dir=str(tmp_path),
            ca_cert_path=str(ca_cert),
        )

        with mock.patch("client.acme_client.httpx.Client") as spy:
            client._http_client()

        assert spy.call_args.kwargs["verify"] == str(ca_cert)
