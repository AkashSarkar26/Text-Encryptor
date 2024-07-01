from encryption import aes_encrypt, aes_decrypt, des_encrypt, des_decrypt, rsa_encrypt, rsa_decrypt, generate_rsa_keys
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def main():
    # AES Example
    aes_key = get_random_bytes(16)
    plaintext = "This is a secret message"
    aes_ciphertext = aes_encrypt(plaintext, aes_key)
    print(f"AES Encrypted: {aes_ciphertext}")
    print(f"AES Decrypted: {aes_decrypt(aes_ciphertext, aes_key)}")

    # DES Example
    des_key = get_random_bytes(8)
    des_ciphertext = des_encrypt(plaintext, des_key)
    print(f"DES Encrypted: {des_ciphertext}")
    print(f"DES Decrypted: {des_decrypt(des_ciphertext, des_key)}")

    # RSA Example
    public_key, private_key = generate_rsa_keys()
    rsa_ciphertext = rsa_encrypt(plaintext, public_key)
    print(f"RSA Encrypted: {rsa_ciphertext}")
    print(f"RSA Decrypted: {rsa_decrypt(rsa_ciphertext, private_key)}")

if __name__ == "__main__":
    main()
