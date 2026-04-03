"""
uPKI CLI - ACME v2 Client (RFC 8555).

Pure-Python ACME client using:
- cryptography  — key generation, CSR, P12, JWS signing
- httpx         — HTTP/HTTPS requests

No josepy, no subprocess openssl.

JWS details:
- Account key: EC P-256
- Serialization: flattened JSON  {"protected","payload","signature"}
- EC signature format: IEEE P1363 (r || s), NOT DER — per RFC 8555 / JWS
- RFC 7638 key thumbprint: SHA-256 over {"crv","kty","x","y"} in lex order
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from base64 import b64decode, b64encode
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import pkcs12 as _pkcs12
from cryptography.x509 import (
    CertificateSigningRequestBuilder,
    DNSName,
    Name,
    NameAttribute,
    NameOID,
    SubjectAlternativeName,
    load_pem_x509_certificate,
)


# ============================================================================
# Base64URL helpers (RFC 4648 §5)
# ============================================================================


def _b64url(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return b64encode(data).decode().rstrip("=").replace("+", "-").replace("/", "_")


def _b64url_decode(data: str) -> bytes:
    """Decode base64url string (adds missing padding)."""
    pad = 4 - (len(data) % 4)
    if pad != 4:
        data += "=" * pad
    return b64decode(data.replace("-", "+").replace("_", "/"))


# ============================================================================
# AcmeClient
# ============================================================================


class AcmeClient:
    """ACME v2 client for uPKI CLI.

    Manages an account key per data directory. On first run the key and
    account are created automatically via the RA's ACME endpoints.

    Args:
        ra_url: Base URL of the RA (e.g. "https://ra.example.com").
        data_dir: Local directory where keys and certificates are stored.
        ca_cert_path: Path to the CA certificate used to verify the RA TLS
            connection. None disables server-certificate verification (only
            acceptable on private networks where the CA is self-signed and
            the cert hasn't been fetched yet).
    """

    def __init__(
        self,
        ra_url: str,
        data_dir: str,
        ca_cert_path: str | None = None,
    ) -> None:
        self._ra_url = ra_url.rstrip("/")
        self._data_dir = data_dir
        self._ca_cert_path = ca_cert_path

        self._key_path = os.path.join(data_dir, "acme_account.key")
        self._account_path = os.path.join(data_dir, "acme_account.json")

        self._private_key: ec.EllipticCurvePrivateKey | None = None
        self._account_id: str | None = None
        self._directory: dict[str, Any] | None = None

        os.makedirs(data_dir, exist_ok=True)

    # -------------------------------------------------------------------------
    # Account key helpers
    # -------------------------------------------------------------------------

    def _load_or_create_key(self) -> ec.EllipticCurvePrivateKey:
        """Load the account key from disk, generating a new one if absent.

        Returns:
            EC P-256 private key.
        """
        if self._private_key is not None:
            return self._private_key

        if os.path.isfile(self._key_path):
            with open(self._key_path, "rb") as fh:
                self._private_key = serialization.load_pem_private_key(
                    fh.read(), password=None
                )
        else:
            self._private_key = ec.generate_private_key(ec.SECP256R1())
            pem = self._private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            with open(self._key_path, "wb") as fh:
                fh.write(pem)
            os.chmod(self._key_path, 0o600)

        return self._private_key

    def _get_jwk(self) -> dict[str, Any]:
        """Return the public key as a JWK dict (EC P-256).

        Returns:
            JWK dictionary with kty, crv, x, y.
        """
        key = self._load_or_create_key()
        pub = key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(pub.x.to_bytes(32, "big")),
            "y": _b64url(pub.y.to_bytes(32, "big")),
        }

    def _thumbprint(self) -> str:
        """Compute RFC 7638 JWK Thumbprint for the account key.

        Only required members in lexicographic order, compact JSON encoding.

        Returns:
            Base64url-encoded SHA-256 of the canonical JWK.
        """
        jwk = self._get_jwk()
        members = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
        digest = hashlib.sha256(
            json.dumps(members, sort_keys=True, separators=(",", ":")).encode()
        ).digest()
        return _b64url(digest)

    # -------------------------------------------------------------------------
    # JWS signing
    # -------------------------------------------------------------------------

    def _sign_jws(
        self,
        url: str,
        payload: dict[str, Any] | None,
        *,
        use_jwk: bool = False,
        nonce: str | None = None,
    ) -> bytes:
        """Build and sign a flattened-JSON JWS body.

        Args:
            url: The target URL (goes into the "url" protected header field).
            payload: The payload dict. None produces an empty-string payload
                (used for POST-as-GET requests per RFC 8555 §6.3).
            use_jwk: If True, embed the public key in the protected header
                instead of a kid. Required for new-account.
            nonce: Nonce to embed. If None, a fresh one is fetched from the RA.

        Returns:
            UTF-8 encoded JSON body ready to POST.
        """
        if nonce is None:
            nonce = self._get_nonce()

        protected: dict[str, Any] = {
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
        }
        if use_jwk:
            protected["jwk"] = self._get_jwk()
        else:
            protected["kid"] = f"{self._ra_url}/acme/account/{self._account_id}"

        protected_b64 = _b64url(json.dumps(protected, separators=(",", ":")).encode())

        if payload is None:
            payload_b64 = ""
        else:
            payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())

        sign_input = f"{protected_b64}.{payload_b64}".encode()

        key = self._load_or_create_key()
        sig_der = key.sign(sign_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(sig_der)
        sig_p1363 = r.to_bytes(32, "big") + s.to_bytes(32, "big")

        body = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _b64url(sig_p1363),
        }
        return json.dumps(body, separators=(",", ":")).encode()

    # -------------------------------------------------------------------------
    # HTTP helpers
    # -------------------------------------------------------------------------

    def _http_client(self) -> httpx.Client:
        """Return an httpx.Client with appropriate TLS settings.

        Returns:
            Configured httpx.Client.
        """
        verify: bool | str = self._ca_cert_path if self._ca_cert_path else False
        return httpx.Client(verify=verify, timeout=30.0)

    def _get_directory(self) -> dict[str, Any]:
        """Fetch and cache the ACME directory.

        Returns:
            Directory dict with endpoint URLs.
        """
        if self._directory:
            return self._directory
        with self._http_client() as client:
            resp = client.get(f"{self._ra_url}/acme/directory")
            resp.raise_for_status()
            self._directory = resp.json()
        return self._directory

    def _get_nonce(self) -> str:
        """Fetch a fresh anti-replay nonce from the RA.

        Returns:
            Nonce string.

        Raises:
            RuntimeError: If the RA does not return a Replay-Nonce header.
        """
        directory = self._get_directory()
        url = directory.get("newNonce", f"{self._ra_url}/acme/new-nonce")
        with self._http_client() as client:
            resp = client.get(url)
        nonce = resp.headers.get("Replay-Nonce") or resp.headers.get("replay-nonce")
        if not nonce:
            raise RuntimeError("RA returned no Replay-Nonce header")
        return nonce

    def _post(self, url: str, body: bytes) -> httpx.Response:
        """POST a JWS body to the RA.

        Args:
            url: Target URL.
            body: JSON-encoded JWS body.

        Returns:
            httpx.Response.
        """
        with self._http_client() as client:
            resp = client.post(
                url,
                content=body,
                headers={"Content-Type": "application/jose+json"},
            )
        return resp

    # -------------------------------------------------------------------------
    # Account lifecycle
    # -------------------------------------------------------------------------

    def bootstrap_account(self) -> str:
        """Ensure an ACME account exists; create one if not.

        Stores the account ID in ``acme_account.json`` for reuse.

        Returns:
            Account ID string (RFC 7638 key thumbprint).
        """
        if os.path.isfile(self._account_path):
            with open(self._account_path) as fh:
                state = json.load(fh)
            self._account_id = state.get("id")
            self._load_or_create_key()
            if self._account_id:
                return self._account_id

        # Create account
        directory = self._get_directory()
        url = directory.get("newAccount", f"{self._ra_url}/acme/new-account")
        payload = {"termsOfServiceAgreed": True}
        body = self._sign_jws(url, payload, use_jwk=True)
        resp = self._post(url, body)
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Account creation failed: {resp.status_code} {resp.text}"
            )

        self._account_id = self._thumbprint()
        with open(self._account_path, "w") as fh:
            json.dump({"id": self._account_id}, fh)
        os.chmod(self._account_path, 0o600)
        return self._account_id

    # -------------------------------------------------------------------------
    # Certificate enrollment / renewal
    # -------------------------------------------------------------------------

    def enroll(
        self,
        cn: str,
        profile: str = "server",
        sans: list[str] | None = None,
        p12: bool = False,
        passwd: str | None = None,
    ) -> dict[str, str]:
        """Enroll a new certificate via ACME.

        Steps: new-order → (skip challenges if pre-auth) → finalize → download.

        Args:
            cn: Common Name for the certificate.
            profile: Certificate profile (passed to the RA CA).
            sans: Subject Alternative Names (DNS). cn is always included.
            p12: If True, also write a PKCS#12 bundle.
            passwd: Password for the P12 file (None = no password).

        Returns:
            Dict with keys ``key``, ``cert``, ``pem`` (and ``p12`` if requested).
        """
        self.bootstrap_account()
        all_sans = list({cn} | set(sans or []))
        identifiers = [{"type": "dns", "value": s} for s in all_sans]

        # Generate node key + CSR
        node_key = ec.generate_private_key(ec.SECP256R1())
        key_file = self._node_path(cn, profile, "key")
        key_pem = node_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with open(key_file, "wb") as fh:
            fh.write(key_pem)
        os.chmod(key_file, 0o400)

        csr = (
            CertificateSigningRequestBuilder()
            .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, cn)]))
            .add_extension(
                SubjectAlternativeName([DNSName(s) for s in all_sans]),
                critical=False,
            )
            .sign(node_key, hashes.SHA256())
        )
        # RFC 8555 §7.4: the csr field MUST be DER-encoded, base64url.
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        csr_b64 = _b64url(csr_der)
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        # New-order
        directory = self._get_directory()
        order_url = directory.get("newOrder", f"{self._ra_url}/acme/new-order")
        body = self._sign_jws(
            order_url, {"identifiers": identifiers, "profile": profile}
        )
        resp = self._post(order_url, body)
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"new-order failed: {resp.status_code} {resp.text}")
        order = resp.json()

        # Poll until ready (pre-authorized clients skip challenges)
        finalize_url = order.get("finalize")
        if not finalize_url:
            raise RuntimeError("RA returned no finalize URL")

        if order.get("status") not in ("ready", "valid"):
            order = self._wait_for_order_ready(order, directory)

        # Finalize
        body = self._sign_jws(finalize_url, {"csr": csr_b64})
        resp = self._post(finalize_url, body)
        if resp.status_code not in (200, 201):
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            raise RuntimeError(f"finalize failed ({resp.status_code}): {detail}")
        result = resp.json()

        cert_url = result.get("certificate")
        if not cert_url:
            # Poll order until valid
            order_id = finalize_url.rstrip("/finalize").split("/")[-1]
            full_url = f"{self._ra_url}/acme/order/{order_id}"
            cert_url = self._wait_for_cert_url(full_url)

        # Download certificate
        with self._http_client() as client:
            cert_resp = client.get(cert_url)
            cert_resp.raise_for_status()
        cert_pem: str = cert_resp.json().get("certificate", "")
        if not cert_pem:
            raise RuntimeError("RA returned empty certificate")

        # Write files
        crt_file = self._node_path(cn, profile, "crt")
        pem_file = self._node_path(cn, profile, "pem")

        with open(crt_file, "w") as fh:
            fh.write(cert_pem)
        os.chmod(crt_file, 0o444)

        with open(pem_file, "w") as fh:
            fh.write(cert_pem)
            fh.write(key_pem.decode())
        os.chmod(pem_file, 0o400)

        paths = {"key": key_file, "cert": crt_file, "pem": pem_file}

        if p12:
            p12_file = self._write_p12(cn, profile, node_key, cert_pem, passwd)
            paths["p12"] = p12_file

        return paths

    def renew(
        self,
        cn: str,
        profile: str = "server",
        sans: list[str] | None = None,
        p12: bool = False,
        passwd: str | None = None,
    ) -> dict[str, str]:
        """Renew an existing certificate (identical to enroll; overwrites files).

        Args:
            cn: Common Name.
            profile: Certificate profile.
            sans: Subject Alternative Names.
            p12: Regenerate P12 bundle.
            passwd: P12 password.

        Returns:
            Dict with file paths.
        """
        # Unlock existing files first
        for ext in ("key", "crt", "pem", "p12"):
            path = self._node_path(cn, profile, ext)
            if os.path.isfile(path):
                os.chmod(path, 0o600)

        return self.enroll(cn, profile=profile, sans=sans, p12=p12, passwd=passwd)

    def revoke(self, cert_pem: str, reason: int = 0) -> None:
        """Revoke a certificate.

        Args:
            cert_pem: PEM-encoded certificate to revoke.
            reason: RFC 5280 revocation reason code (0 = unspecified).
        """
        self.bootstrap_account()
        directory = self._get_directory()
        revoke_url = directory.get("revokeCert", f"{self._ra_url}/acme/revoke-cert")
        cert_b64 = _b64url(cert_pem.encode())
        body = self._sign_jws(revoke_url, {"certificate": cert_b64, "reason": reason})
        resp = self._post(revoke_url, body)
        if resp.status_code not in (200, 204):
            raise RuntimeError(f"Revocation failed: {resp.status_code} {resp.text}")

    # -------------------------------------------------------------------------
    # CA cert and CRL
    # -------------------------------------------------------------------------

    def get_ca_certificate(self) -> str:
        """Fetch the CA certificate from the RA.

        Returns:
            PEM-encoded CA certificate string.
        """
        with self._http_client() as client:
            resp = client.get(f"{self._ra_url}/api/v1/ca")
            resp.raise_for_status()
        return resp.json().get("data", {}).get("certificate", "")

    def get_crl(self) -> str:
        """Fetch the current CRL from the RA.

        Returns:
            PEM-encoded CRL string.
        """
        with self._http_client() as client:
            resp = client.get(f"{self._ra_url}/api/v1/crl")
            resp.raise_for_status()
        return resp.json().get("data", {}).get("crl", "")

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _node_path(self, cn: str, profile: str, ext: str) -> str:
        """Return the canonical path for a node file.

        Args:
            cn: Common Name.
            profile: Certificate profile.
            ext: File extension (key / crt / pem / p12).

        Returns:
            Absolute file path.
        """
        return os.path.join(self._data_dir, f"{profile}.{cn}.{ext}")

    def _write_p12(
        self,
        cn: str,
        profile: str,
        private_key: ec.EllipticCurvePrivateKey,
        cert_pem: str,
        passwd: str | None,
    ) -> str:
        """Write a PKCS#12 bundle to disk.

        Args:
            cn: Common Name.
            profile: Certificate profile.
            private_key: Node private key.
            cert_pem: PEM-encoded certificate.
            passwd: Optional P12 password.

        Returns:
            Path to the written .p12 file.
        """
        p12_file = self._node_path(cn, profile, "p12")
        cert_obj = load_pem_x509_certificate(cert_pem.encode())
        password = passwd.encode() if passwd else None
        p12_bytes = _pkcs12.serialize_key_and_certificates(
            name=cn.encode(),
            key=private_key,
            cert=cert_obj,
            cas=None,
            encryption_algorithm=(
                serialization.BestAvailableEncryption(password)
                if password
                else serialization.NoEncryption()
            ),
        )
        with open(p12_file, "wb") as fh:
            fh.write(p12_bytes)
        os.chmod(p12_file, 0o444)
        return p12_file

    def _wait_for_order_ready(
        self,
        initial_order: dict[str, Any],
        directory: dict[str, Any],
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Poll order until status is 'ready' or raise on failure.

        For orders without pre-authorization the client must trigger challenges
        and wait. This implementation supports mTLS pre-authorized flows only —
        for non-pre-auth flows the caller must handle challenges first.

        Args:
            initial_order: Order dict returned by new-order.
            directory: ACME directory.
            timeout: Maximum seconds to wait.

        Returns:
            Updated order dict with status 'ready'.

        Raises:
            RuntimeError: If the order times out or becomes 'invalid'.
        """
        # Try to find the order poll URL
        finalize_url: str = initial_order.get("finalize", "")
        if not finalize_url:
            raise RuntimeError("No finalize URL in order")
        # Derive order poll URL: .../order/{id}/finalize → .../order/{id}
        order_poll_url = finalize_url.rstrip("/").removesuffix("/finalize")

        deadline = time.monotonic() + timeout
        order = initial_order
        while time.monotonic() < deadline:
            status = order.get("status")
            if status == "ready":
                return order
            if status in ("valid", "processing"):
                return order
            if status == "invalid":
                raise RuntimeError(f"Order became invalid: {order.get('error')}")
            time.sleep(2)
            with self._http_client() as client:
                resp = client.get(order_poll_url)
            if resp.status_code == 200:
                order = resp.json()

        raise RuntimeError(
            f"Order not ready after {timeout}s (status={order.get('status')})"
        )

    def _wait_for_cert_url(self, order_url: str, timeout: int = 60) -> str:
        """Poll order until a certificate URL is available.

        Args:
            order_url: URL to poll for order status.
            timeout: Maximum seconds to wait.

        Returns:
            Certificate download URL.

        Raises:
            RuntimeError: On timeout or invalid order.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._http_client() as client:
                resp = client.get(order_url)
            if resp.status_code == 200:
                order = resp.json()
                if order.get("certificate"):
                    return order["certificate"]
                if order.get("status") == "invalid":
                    raise RuntimeError(f"Order invalid: {order.get('error')}")
            time.sleep(2)

        raise RuntimeError(f"Certificate not available after {timeout}s")
