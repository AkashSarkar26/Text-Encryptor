from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import rsa  
# AES Encryption
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# DES Encryption
def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), DES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

def des_decrypt(ciphertext, key):
    iv = ciphertext[:8]
    ct = ciphertext[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), DES.block_size)
    return pt.decode()

# RSA Encryption
def rsa_encrypt(plaintext, public_key):
    return rsa.encrypt(plaintext.encode(), public_key)

def rsa_decrypt(ciphertext, private_key):
    return rsa.decrypt(ciphertext, private_key).decode()

def generate_rsa_keys():
    (public_key, private_key) = rsa.newkeys(2048)
    return public_key, private_key
