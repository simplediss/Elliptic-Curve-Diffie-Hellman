from secrets import randbelow
from typing import Callable, Optional

from curve import Curve, Point


class Keypair:
    """
    Represents a key pair for Elliptic Curve Cryptography (ECC).
    
    Args:
        curve (Curve): The elliptic curve domain parameters.
        kdf_hashfunc (Optional[Callable]): The hash function to use for the Key Derivation Function (KDF).
    """
    def __init__(self, curve: Curve, kdf_hashfunc: Optional[Callable] = None) -> None:
        self.private_key = randbelow(curve.field.n)
        self.public_key = self.private_key * curve.g
        self.kdf_hashfunc = kdf_hashfunc

    def __eq__(self, other: 'Keypair') -> bool:
        if not isinstance(other, Keypair):
            return False
        return self.private_key == other.private_key and self.public_key == other.public_key

    def __str__(self) -> str:
        return f"Private key: {self.private_key}\nPublic key: {self.public_key}"
    
    def get_shared_secret(self, public_key: Point) -> Point:
        """
        Computes the shared secret point between two parties.
        
        Args:
            public_key (Point): The other party's public key.
        
        Returns:
            Point: The shared secret point.
        """
        shared_secret = self.private_key * public_key
        if self.kdf_hashfunc:
            return kdf(shared_secret, self.kdf_hashfunc)
        return shared_secret
    

def kdf(shared_secret: Point, hashfunc: Callable, length=32) -> bytes:
    """
    Key Derivation Function (KDF) to derive a symmetric key from the shared secret.

    Args:
        shared_secret (Point): The shared secret point.
        length (int): The desired length of the derived key.
        hashfunc (Callable): The hash function to use.

    Returns:
        bytes: The derived key.
    """
    num_bytes = (shared_secret.x.bit_length() + 7) // 8  # pad with 7 bits to ensure adding full byte size
    shared_secret_bytes = shared_secret.x.to_bytes(num_bytes, byteorder='big')
    return hashfunc(shared_secret_bytes).digest()[:length]
