import tkinter as tk
import tkinter.filedialog as filedialog
import encrypt, decrypt, os, malware
from tkinter import messagebox
from termcolor import colored
from datetime import datetime
from tkinter import filedialog
from PIL import Image, ImageTk


class FileDefenderGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Defender")
        self.geometry("800x600")
        self.iconbitmap("icon.ico")

        # create label widget
        self.label = tk.Label(text="File Defender Program", font=("Colonna MT", 14,"bold"))
        self.img = tk.PhotoImage(file="file_defender.png").subsample(2, 2)  # Use subsample method to reduce image size
        label = tk.Label(self, image=self.img)
        self.label.pack()
        label.pack()



        # Create menu
        menu = tk.Menu(self)
        self.config(menu=menu)

        # Create Cryptography menu and submenu
        crypto_submenu = tk.Menu(menu,font=("Times new Roman", 14))
        menu.add_cascade(label="Cryptography",menu=crypto_submenu)
        crypto_submenu.add_command(label="Browse Directory to Encrypt", command=self.browse_encrypt)
        crypto_submenu.add_separator()
        crypto_submenu.add_command(label="Browse Directory to Decrypt", command=self.browse_decrypt)

        # Create Malware Scanner menu item
        scan_submenu = tk.Menu(menu,font=("Times new Roman", 14))
        menu.add_cascade(label="Malware Scanner", menu=scan_submenu, font=("Times new Roman", 20, "bold"))
        scan_submenu.add_command(label="Browse to scan a Directory", command=self.Directory_scan)
        scan_submenu.add_separator()
        scan_submenu.add_command(label="Browse to scan a File", command=self.File_scan)
        
        
        # Scroll button, list box
        self.output_text = tk.Listbox(self, font=("Times new Roman", 12), height=15, selectbackground="grey")
        scrollbar = tk.Scrollbar(self, orient="vertical", command=self.output_text.yview)
        self.output_text.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.output_text.pack(pady=10, padx=10, fill="both", expand=True)

        self.output_text.delete(0, tk.END)

            # insert the welcome message into the Listbox
        wl = '''
                                          Welcome to BK & HNA File Defender Software version 0.1 2023 
                The File Defender program is provided "as is" and without warranty of any kind. 
                The developers Boukary KABORE & Henry Ndolleh Alpha are not responsible for any 
                loss, damage, or inconvenience caused by the use of this program.

                The File Defender program is intended for educational and demonstration purposes only. 
                The user assumes full responsibility and risk for the use of this program. The developers
                Boukary KABORE & Henry Ndolleh Alpha   will not be liable for any damages, including but
                not limited to direct, indirect, special, incidental, or consequential damages or losses 
                arising from the use of this program.

                The user is solely responsible for ensuring the legality of using this program. The developers
                Boukary KABORE and Henry Ndolleh Alpha do not endorse or condone any illegal activity related
                to the use of this program.

                By using this program, the user agrees to indemnify and hold harmless the developers 
                Boukary KABORE & Henry Ndolleh Alpha, from and against any claims, damages, liabilities,
                costs, and expenses arising from the use of this program.
            '''
        
        for line in wl.split('\n'):
                self.output_text.insert(tk.END,line)
                self.output_text.itemconfigure(tk.END, fg="#964B00")
                self.output_text.configure(font=("Times new Roman", 13))


        # Create clear screen button to clear all text in the window
        clear_screen_button = tk.Button(self, text="Clear Screen", font=("Helvetica", 12, "bold"), command=self.clear_screen, bg="#ADD8E6", padx=10, pady=10)

        clear_screen_button.pack(pady=20)

    def clear_screen(self):
        self.output_text.delete('0', tk.END)


    def browse_encrypt(self):
        directory = filedialog.askdirectory()
        if directory:
            #Delete existing message on the Listbox
            self.output_text.delete(0, tk.END)
            #Scanning defauld message
            self.output_text.insert(tk.END, "\n\n" + "="*5 + "Encrypting directory: {}\n\n".format(directory) + "="*5 + "\n\n")
            self.output_text.itemconfigure(tk.END, fg="green")
            self.output_text.insert(tk.END, "\n\n")
            self.output_text.update_idletasks()

            # Generate a new encryption key
            key = os.urandom(32)
            # Save the key to a file
    
            with open("key.txt", "wb") as key_file:
                key_file.write(key)
            # Encrypt the directory using the new key
            encrypt.encrypt_directory(directory, key, self.output_text)
            self.output_text.insert(tk.END, "File on Directory : " + directory + "Encrypted")
            self.output_text.itemconfigure(tk.END, fg="green")
            self.output_text.insert(tk.END, "\n\n" + "="*5 + " Encryption completed " + "="*5 + "\n\n")
            self.output_text.itemconfigure(tk.END, fg="green")
            messagebox.showinfo("Encryption notification","The Encryption report is ready to view")
            
        else:
                # #Default message
            self.output_text.delete(0, tk.END)
            self.output_text.insert(tk.END, "\n No Encrypt directory browse...")
            self.output_text.itemconfigure(tk.END, fg="red")
            


    #Clear button function
    def clear_output(self):
        self.output_text.delete('1.0', tk.END)
      
       
    def browse_decrypt(self):
        directory = filedialog.askdirectory()
        if directory:
            #Delete existing message on the Listbox
            self.output_text.delete(0, tk.END)
            #Scanning defauld message
            self.output_text.insert(tk.END, "\n\n" + "="*5 + "Decrypting directory: {}\n\n".format(directory) + "="*5 + "\n\n")
            self.output_text.itemconfigure(tk.END, fg="green")
            self.output_text.insert(tk.END, "\n\n")
            self.output_text.update_idletasks()
            
            # Get the path to the encryption key file
            key_path = filedialog.askopenfilename(initialdir="/", title="Select key file", filetypes=(("Key files", "*.txt"), ("All files", "*.*")))
            if key_path:
                # Call the decrypt_directory function with the directory path and key file path
                decrypt.decrypt_directory(directory, key_path, self.output_text)
                self.output_text.insert(tk.END, "File on directory Decrypting: " + directory + "Decrypted")
                self.output_text.itemconfigure(tk.END, fg="green")
                self.output_text.insert(tk.END, "\n\n" + "="*5 + " Decryption completed " + "="*5 + "\n\n") 
                self.output_text.itemconfigure(tk.END, fg="green")
                messagebox.showinfo("Decryption notification","The decryption report is ready to view")
                
            else:
                self.output_text.delete(0, tk.END)
                self.output_text.insert(tk.END, "\n No Key browse...")
                self.output_text.itemconfigure(tk.END, fg="red")
                
        else:
            # #Default message
            self.output_text.delete(0, tk.END)
            self.output_text.insert(tk.END, "\n No Decrypt directory browse...")
            self.output_text.itemconfigure(tk.END, fg="red")

    def Directory_scan(self):
        directory_path = filedialog.askdirectory()
        signatures_folder ="signatures"
        if directory_path:
            #Delete existing message on the Listbox
            self.output_text.delete(0, tk.END)
            #Scanning defauld message
            self.output_text.insert(tk.END, "\n\n" + "="*5 + "Scanning Directory: {}\n\n".format(directory_path) + "="*5 + "\n\n")
            self.output_text.itemconfigure(tk.END, fg="green")
            self.output_text.update_idletasks() 
            self.output_text.insert(tk.END, "\n\n")

            
            malicious_files = malware.scan_files(directory_path, signatures_folder, self.output_text)
            if malicious_files:            
                self.output_text.insert(tk.END, "\n\n" + "="*5 + " Scan complete " + "="*5 + "\n\n")
                self.output_text.itemconfigure(tk.END, fg="green")
        
                # Finished report
                messagebox.showinfo("Scan notification","Malware scan report is ready to view")
                self.output_text.insert(tk.END, "\n\n")
                self.output_text.insert(tk.END, "\n Malicious files found: {}\n\n".format(len(malicious_files)))
                self.output_text.itemconfigure(tk.END, fg="green")
                self.output_text.insert(tk.END, "\n\n")
                self.output_text.insert(tk.END, "\n===== Malicious files details =====\n\n")
                self.output_text.itemconfigure(tk.END, fg="green")
                self.output_text.insert(tk.END, "\n\n")

                for file_path, file_size, last_modified_time, file_hash in malicious_files:
                    self.output_text.see(tk.END)
                    #self.update()
                    is_malicious = malware.scan_file(file_path, signatures_folder, self.output_text)
                    if is_malicious:
                        self.output_text.insert(tk.END, "\n\n")
                        self.output_text.insert(tk.END, "\nMalicious file Scanned: " + file_path)
                        self.output_text.itemconfigure(tk.END, fg="red")
                        self.output_text.insert(tk.END, "\n\n")
                        self.output_text.insert(tk.END, "File size: {}\n".format(file_size))
                        self.output_text.insert(tk.END, "Last modified time: {}\n".format(last_modified_time))
                        self.output_text.insert(tk.END, "File hash: {}\n\n".format(file_hash))
                        #self.output_text.insert(tk.END, "Matched rules: {}\n\n".format(matched_rules))
                        self.output_text.insert(tk.END, "\n\n")
            else:
                    self.output_text.insert(tk.END, "\n\n" + "="*5 + " Scan complete " + "="*5 + "\n\n")
                    messagebox.showinfo("Scan notification","Malware scan report is ready to view")
                    self.output_text.insert(tk.END, "\n")
                    self.output_text.insert(tk.END, "\n\n No Malicious string or signature found in Files on directory:")
                    self.output_text.itemconfigure(tk.END, fg="green")
                    self.output_text.insert(tk.END, "{}".format(directory_path))
                    self.output_text.itemconfigure(tk.END, fg="blue")
        else:    
                self.output_text.delete(0, tk.END)
                self.output_text.insert(tk.END, "\n No Directory browser.")
                self.output_text.itemconfigure(tk.END, fg="red")
                



    def File_scan(self):
            file_path = filedialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("Executable files", "*.exe"), ("All files", "*.*")))
            signatures_folder ="signatures"

            
            if file_path:
                #Delete existing message on the Listbox
                self.output_text.delete(0, tk.END)
                #Scanning defauld message
                self.output_text.insert(tk.END, "\n\n" + "="*5 + "Scanning File: {}\n\n".format(file_path) + "="*5 + "\n\n")
                self.output_text.itemconfigure(tk.END, fg="green")
                self.output_text.insert(tk.END, "\n\n")
                self.output_text.update_idletasks()

                malicious_files = malware.scan_file(file_path, signatures_folder, self.output_text)

                # Add thick straight lines
                self.output_text.insert(tk.END, "\n\n" + "="*5 + " Scan complete " + "="*5 + "\n\n")

                # Fineshed report
                messagebox.showinfo("Scan notification","Malware scan report is ready to view")
                if malicious_files:
                    self.output_text.insert(tk.END, "\n Malicious files found: {}\n\n".format(len(malicious_files)))
                    self.output_text.insert(tk.END, "\n\n")
                    self.output_text.insert(tk.END, "\n===== Malicious files details =====\n\n")

                    for file_path, file_size, last_modified_time, file_hash in malicious_files:
                        
                        self.output_text.insert(tk.END, "Malicious file Sanned: " + file_path)
                        self.output_text.itemconfigure(tk.END, fg="red")
                        self.output_text.insert(tk.END, "\n\nFile size: {}\n\n".format(file_size))
                        self.output_text.insert(tk.END, "Last modified time: {}\n\n".format(last_modified_time))
                        self.output_text.insert(tk.END, "File type: {}\n\n".format(os.path.splitext(file_path)[1]))
                        self.output_text.insert(tk.END, "Hash of the malicious file: {}\n\n".format(file_hash))
                        #self.output_text.insert(tk.END, "Matched rules: {}\n\n".format(matched_rules))
                        self.output_text.insert(tk.END, "\n\n")
                else:
                    self.output_text.insert(tk.END, "\n")
                    self.output_text.insert(tk.END, "\n\n No Malicious string or signature found in File:")
                    self.output_text.itemconfigure(tk.END, fg="green")
                    self.output_text.itemconfigure(tk.END, fg="green")
                    self.output_text.insert(tk.END, "{}\n\n".format(file_path))
                    self.output_text.itemconfigure(tk.END, fg="blue")
            else:
                self.output_text.delete(0, tk.END)
                self.output_text.insert(tk.END, "\n No path browser.")
                self.output_text.itemconfigure(tk.END, fg="red")
                

            

if __name__ == "__main__":
    app = FileDefenderGUI()
    app.mainloop()
