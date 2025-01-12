from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# AES Encryption
def aes_encrypt_decrypt(text):
    print("\nAES Encryption/Decryption")
    key = get_random_bytes(16)  # 16 bytes key for AES
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    print("Ciphertext:", ciphertext)

    # Decryption
    cipher = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')
    print("Decrypted Text:", plaintext)

# DES Encryption
def des_encrypt_decrypt(text):
    print("\nDES Encryption/Decryption")
    key = get_random_bytes(8)  # 8 bytes key for DES
    cipher = DES.new(key, DES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    print("Ciphertext:", ciphertext)

    # Decryption
    cipher = DES.new(key, DES.MODE_EAX, nonce=cipher.nonce)
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')
    print("Decrypted Text:", plaintext)

# RSA Encryption
def rsa_encrypt_decrypt(text):
    print("\nRSA Encryption/Decryption")

    # Generate RSA keys
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Encrypt with public key
    ciphertext = public_key.encrypt(
        text.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Ciphertext:", ciphertext)

    # Decrypt with private key
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')
    print("Decrypted Text:", plaintext)

if __name__ == "__main__":
    text = input("Enter text to encrypt and decrypt: ")
    aes_encrypt_decrypt(text)
    des_encrypt_decrypt(text)
    rsa_encrypt_decrypt(text)
