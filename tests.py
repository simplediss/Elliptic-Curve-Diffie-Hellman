import hashlib
import rich
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from time import perf_counter

from curve import get_curve
from ec_utils import Keypair

TAB = "    "


def test_ecdh():
    """Test Elliptic Curve Diffie-Hellman (ECDH) key exchange."""
    rich.print("\n[bold][blue]Elliptic Curve Diffie-Hellman (ECDH) Key Exchange")
    curve = get_curve('secp256k1')
    rich.print(TAB + '[purple][*] Curve:')
    print(TAB*2 + f'{curve}')

    # Generate key pairs for party A and B
    before = perf_counter()
    keypair_a = Keypair(curve, hashlib.sha256)
    keypair_b = Keypair(curve, hashlib.sha256)
    duration = 1000 * (perf_counter() - before)
    rich.print(TAB + f'[green][+] Keys generated successfully ({duration:.01f}ms):')
    rich.print(TAB*2 + '[purple][*] Key Pair A:')
    print(TAB*3 + f'private: {keypair_a.private_key}')
    print(TAB*3 + f'public:  {keypair_a.public_key.x}')
    rich.print(TAB*2 + '[purple][*] Key Pair B:')
    print(TAB*3 + f'private: {keypair_b.private_key}')
    print(TAB*3 + f'public:  {keypair_b.public_key.x}')

    # Compute the shared secret
    before = perf_counter()
    shared_secret_a = keypair_a.get_shared_secret(keypair_b.public_key)
    shared_secret_b = keypair_b.get_shared_secret(keypair_a.public_key)
    duration = 1000 * (perf_counter() - before)
    if shared_secret_a == shared_secret_b:
        rich.print(TAB + f"[green][+] Shared secret computed successfully ({duration:.01f}ms):")
        print(TAB*2 + "shared_secret_a = shared_secret_b")
        print(TAB*3 + f"= {shared_secret_a}\n")
        return shared_secret_a
    else:
        rich.print(TAB*2 + "[red][-] Shared secret mismatch.")


def test_encryption(shared_secret: bytes, message: bytes):
    """Test encryption and decryption using AES with key from ECDH."""
    rich.print("[bold][blue]AES Encryption and Decryption")
    rich.print(TAB + "[purple][*] Encrypting message:")
    print(TAB*2 + f"{message}")

    # Encrypt the message using AES
    before = perf_counter()
    cipher = AES.new(shared_secret, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    duration = 1000 * (perf_counter() - before)
    rich.print(TAB + f"[green][+] Message encrypted successfully ({duration:.01f}ms):")
    print(TAB*2 + f"{ciphertext}")

    # Decrypt the message to verify
    before = perf_counter()
    cipher = AES.new(shared_secret, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    duration = 1000 * (perf_counter() - before)

    if decrypted_message == message:
        rich.print(TAB + f"[green][+] Decrypted message matches the original message ({duration:.01f}ms):")
        print(TAB*2 + f"{decrypted_message}\n")
    else:
        rich.print(TAB + "[red][-] Decrypted message does not match the original message:")
        print(TAB*2 + f"{decrypted_message}\n")


if __name__ == '__main__':
    shared_secret = test_ecdh()
    test_encryption(shared_secret, b"This is a secret message.")
