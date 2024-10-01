from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os

# Generating a random AES256 key
def generate_aes_key():
    return os.urandom(32) # 32 bytes for AES-256

# Encrypt data using AES-256
def aes_encrypt(data, key):
    iv = os.urandom(16) # AES block size is 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend()) 
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv, ciphertext

# Decrypt AES-256 encrypted data
def aes_decrypt(iv, ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data

# Generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend = default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt AES key using RSA public key
def rsa_encrypt_key(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# Decrypt AES key using RSA private key
def rsa_decrypt_key(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )
    return decrypted_key

# Example usage
if __name__ == "__main__":
    token = b"my_secret_token"
    
    # AES Encryption
    aes_key = generate_aes_key()
    iv, encrypted_token = aes_encrypt(token, aes_key)

    print(f"AES Encrypted Token: {encrypted_token}")

    # RSA Key Generation
    private_key, public_key = generate_rsa_key_pair()

    # RSA encryption of AES key
    encrypted_aes_key = rsa_encrypt_key(aes_key, public_key)
    print(f"RSA Encrypted AES Key: {encrypted_aes_key}")

    # RSA decryption AES key
    decrypted_aes_key = rsa_decrypt_key(encrypted_aes_key, private_key)

    # AES decryption of token
    decrypted_token = aes_decrypt(iv, encrypted_token, decrypted_aes_key)
    print(f"Decrypted Token: {decrypted_token.decode()}")