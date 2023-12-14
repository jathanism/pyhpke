from cryptography.hazmat.primitives.ciphers import aead

from ..aead_key_interface import AEADKeyInterface


class AESSIVKey(AEADKeyInterface):
    """
    The AES-SIV key.
    """

    def __init__(self, key: bytes, size: int):
        if size not in (32, 64):
            raise ValueError(f"Invalid key size: {len(key)}.")
        if len(key) != size:
            raise ValueError("Key size mismatch.")
        self._ctx = aead.AESSIV(key)

    def seal(self, pt: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        """Note that `nonce` is ignored here."""
        if not aad:
            aad = None
        return self._ctx.encrypt(pt, aad)

    def open(self, ct: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        """Note that `nonce` is ignored here."""
        if not aad:
            aad = None
        return self._ctx.decrypt(ct, aad)
