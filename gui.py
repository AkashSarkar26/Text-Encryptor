import tkinter as tk
from tkinter import messagebox
from encryption import aes_encrypt, aes_decrypt, des_encrypt, des_decrypt, rsa_encrypt, rsa_decrypt, generate_rsa_keys
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Text Encryption")
        
        self.label = tk.Label(root, text="Enter Text:")
        self.label.pack()
        
        self.text_entry = tk.Entry(root, width=50)
        self.text_entry.pack()
        
        self.aes_button = tk.Button(root, text="AES Encrypt", command=self.aes_encrypt)
        self.aes_button.pack()
        
        self.des_button = tk.Button(root, text="DES Encrypt", command=self.des_encrypt)
        self.des_button.pack()
        
        self.rsa_button = tk.Button(root, text="RSA Encrypt", command=self.rsa_encrypt)
        self.rsa_button.pack()

        self.result_label = tk.Label(root, text="")
        self.result_label.pack()

    def aes_encrypt(self):
        plaintext = self.text_entry.get()
        key = get_random_bytes(16)
        ciphertext = aes_encrypt(plaintext,key)
        self.result_label.config(text=f"AES Encrypted: {ciphertext}")

    def des_encrypt(self):
        plaintext = self.text_entry.get()
        key = get_random_bytes(8)
        ciphertext = des_encrypt(plaintext, key)
        self.result_label.config(text=f"DES Encrypted: {ciphertext}")

    def rsa_encrypt(self):
        plaintext = self.text_entry.get()
        public_key, private_key = generate_rsa_keys()
        ciphertext = rsa_encrypt(plaintext, public_key)
        self.result_label.config(text=f"RSA Encrypted: {ciphertext}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
