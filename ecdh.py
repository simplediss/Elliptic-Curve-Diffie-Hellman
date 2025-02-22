import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from curve import get_curve
from ec_utils import Keypair


# Create a curve instance
curve = get_curve('secp256k1')
print(curve)

# Generate key pairs for party A and B
keypair_a = Keypair(curve, hashlib.sha256)
keypair_b = Keypair(curve, hashlib.sha256)

# Compute the shared secret
shared_secret_a = keypair_a.get_shared_secret(keypair_b.public_key)
shared_secret_b = keypair_b.get_shared_secret(keypair_a.public_key)
assert shared_secret_a == shared_secret_b
shared_secret = shared_secret_a

# Generate an arbitrary message
message = b"This is a secret message."

# Encrypt the message using AES
cipher = AES.new(shared_secret, AES.MODE_CBC)
iv = cipher.iv
ciphertext = cipher.encrypt(pad(message, AES.block_size))

print("Ciphertext:", ciphertext)
print("IV:", iv)

# Decrypt the message to verify
cipher = AES.new(shared_secret, AES.MODE_CBC, iv)
decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)

print("Decrypted message:", decrypted_message)
