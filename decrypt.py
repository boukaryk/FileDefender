import os
from Crypto.Cipher import AES
import tkinter as tk

# Define function to remove padding from data
def unpad_data(data):
    padding = data[-1]
    return data[:-padding]

# Define function to decrypt a file
def decrypt_file(input_file_path, key_path):
    # Open the input file
    with open(input_file_path, 'rb') as input_file:
        # Read the IV from the input file
        iv = input_file.read(16)
        
        # Read the encryption key from the key file
        with open(key_path, 'rb') as key_file:
            key = key_file.read()
            
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Read data from the input file, decrypt it, and remove padding
        data = input_file.read()
        decrypted_data = cipher.decrypt(data)
        unpadded_data = unpad_data(decrypted_data)

        # Write the decrypted data back to the input file
        with open(input_file_path, 'wb') as output_file:
            output_file.write(unpadded_data)

# Define function to decrypt a directory recursively
def decrypt_directory(input_dir_path, key_path, output_text):
    # Traverse the input directory and decrypt each file
    for root, dirs, files in os.walk(input_dir_path):
        for file_name in files:
            input_file_path = os.path.join(root, file_name)
            if not file_name.endswith(".key"):
                #print(f"Decrypting {input_file_path}...")
                output_text.insert(tk.END, f"Decrypted {input_file_path}...\n")
                decrypt_file(input_file_path, key_path)
                

# Define main function to run the decryption module
def main():
    # Get input directory path and key file path from user
    input_dir_path = input("Enter the path to the input directory: ")
    key_path = input("Enter the path to the encryption key file: ")
    
    # Decrypt the directory recursively using AES decryption in place
    output_text = tk.Text()
    decrypt_directory(input_dir_path, key_path, output_text)

 

# Call the main function
if __name__ == "__main__":
    main()
