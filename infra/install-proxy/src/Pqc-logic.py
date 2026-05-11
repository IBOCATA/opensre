import oqs
from typing import Tuple, Optional, Final

class PQCSecretKey:
    """Opaque wrapper for PQC secret material to prevent log leakage."""
    def __init__(self, key_bytes: bytes, algorithm: str):
        self.__key: Final[bytes] = key_bytes
        self.algorithm: Final[str] = algorithm

    def expose(self) -> bytes:
        return self.__key

class PQCCore:
    """NIST Category 3/5 Lattice-based Cryptography Core with Domain Auth."""
    
    def __init__(self, security_level: int = 3, auth_domain: Optional[str] = None) -> None:
        self.auth_domain: Final[Optional[str]] = auth_domain
        
        # Mapping security levels to NIST-standard algorithms
        if security_level == 5:
            self.kem_alg, self.sig_alg = "Kyber1024", "Dilithium5"
        else:
            self.kem_alg, self.sig_alg = "Kyber768", "Dilithium3"

    def _is_domain_authorized(self, email: str) -> bool:
        """Validates if the provided email matches the required auth domain."""
        if not self.auth_domain:
            return True  # Default to open if no domain restriction is set
        return email.lower().endswith(f"@{self.auth_domain.lower()}")

    # --- KEM Handshake Operations ---

    def generate_kem_keypair(self) -> Tuple[bytes, PQCSecretKey]:
        """Generates a Public Key and an opaque Secret Key wrapper."""
        with oqs.KeyEncapsulation(self.kem_alg) as client:
            public_key = client.generate_keypair()
            secret_key = PQCSecretKey(client.export_secret_key(), self.kem_alg)
            return public_key, secret_key

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Creates a shared secret and an encrypted ciphertext for a public key.
        This completes the 'missing' half of the KEM workflow.
        """
        with oqs.KeyEncapsulation(self.kem_alg) as server:
            ciphertext, shared_secret = server.encapsulate(public_key)
            return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes, secret_key: PQCSecretKey) -> bytes:
        """Recovers the shared secret using the private key material."""
        with oqs.KeyEncapsulation(self.kem_alg) as client:
            client.import_secret_key(secret_key.expose())
            return client.decapsulate(ciphertext)

    # --- Telemetry & Verification Operations ---

    def sign_telemetry(self, data: bytes, secret_key: PQCSecretKey, auth_email: str) -> bytes:
        """
        Signs telemetry data using Dilithium. 
        Enforces double authentication via mail domain check.
        """
        if not self._is_domain_authorized(auth_email):
            raise PermissionError(
                f"Authentication failed: {auth_email} is not from authorized domain {self.auth_domain}"
            )
            
        with oqs.Signature(self.sig_alg) as signer:
            signer.import_secret_key(secret_key.expose())
            return signer.sign(data)

    def verify_signature(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verifies the authenticity of signed telemetry."""
        with oqs.Signature(self.sig_alg) as verifier:
            return verifier.verify(data, signature, public_key)
