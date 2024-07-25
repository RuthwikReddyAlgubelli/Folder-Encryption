import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import webbrowser
class InputDialog(tk.Toplevel):
    def __init__(self, title, fields):
        super().__init__()
        self.title(title)
        self.entries = {}
        for field in fields:
            label = tk.Label(self, text=field)
            label.grid(row=len(self.entries), column=0, padx=5, pady=5)

            entry = tk.Entry(self)
            entry.grid(row=len(self.entries), column=1, padx=5, pady=5)

            self.entries[field] = entry

        ok_button = tk.Button(self, text="OK", command=self.ok)
        ok_button.grid(row=len(self.entries), column=0, columnspan=2, pady=10)

    def ok(self):
        self.result = [entry.get() for entry in self.entries.values()]
        self.destroy()

def encrypt_file(filepath, key, receiver_email, sender_email, smtp_password):
    try:
        fernet = Fernet(key)

        if os.path.isfile(filepath):
            with open(filepath, 'rb') as file:
                data = file.read()

            encrypted_data = fernet.encrypt(data)

            with open(filepath, 'wb') as file:
                file.write(encrypted_data)

            send_key_email(sender_email, smtp_password, receiver_email, key, filepath)

            messagebox.showinfo("Info", "Folder encrypted successfully.")

        else:
            messagebox.showerror("Error", "Invalid file path.")

    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")

def send_key_email(sender_email, smtp_password, receiver_email, key, filepath):
    subject = "The Key for Encrypted file"
    message = f"The Key for Encrypted file is:\n{key}\nFilepath is:\n{filepath}"

    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'plain'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, smtp_password)

        server.send_message(msg)

        server.quit()

    except Exception as e:
        messagebox.showerror("Error", f"Failed to send key: {str(e)}")

def decrypt_file(filepath, password):
    try:
        key_file_path = "key.txt"
        key_encrypted = open(key_file_path, "rb").readlines()[0].strip()
        key = Fernet(password.encode()).decrypt(key_encrypted)
        fernet = Fernet(key)
        if os.path.isfile(filepath):
            with open(filepath, 'rb') as file:
                encrypted_data = file.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            with open(filepath, 'wb') as file:
                file.write(decrypted_data)
            messagebox.showinfo("Info", "Folder decrypted successfully.")
        else:
            messagebox.showerror("Error", "Invalid file path.")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
def encrypt_folder(folder_path, key, receiver_email, sender_email, smtp_password):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, key, receiver_email, sender_email, smtp_password)

def decrypt_folder(folder_path, password):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt_file(file_path, password)

def encrypt_process():
    folder_path = filedialog.askdirectory(title="Select a folder for encryption")

    if folder_path:
        dialog = InputDialog("Enter Details", ["Sender Email", "SMTP Password", "Receiver Email"])
        dialog.wait_window()

        inputs = dialog.result

        if not all(inputs):
            messagebox.showerror("Error", "Sender email, SMTP password, and receiver email are required.")
            return

        sender_email, smtp_password, receiver_email = inputs

        key = Fernet.generate_key()
        encrypted_password = Fernet(key).encrypt(key)

        with open("key.txt", "wb") as key_file:
            key_file.write(encrypted_password)

        encrypt_folder(folder_path, key, receiver_email, sender_email, smtp_password)

def decrypt_process():
    folder_path = filedialog.askdirectory(title="Select a folder for decryption")

    if folder_path:
        password = simpledialog.askstring("Password", "Enter the password for decryption:")
        if password:
            decrypt_folder(folder_path, password)
def open_details_page():
    html_page_path = "details.html"
    webbrowser.open(html_page_path)
root = tk.Tk()
root.title("Folder Encrypter")
root.configure(bg="black")
logo_path = "logo.png"
if os.path.isfile(logo_path):
    logo_image = tk.PhotoImage(file=logo_path)
    new_width=350
    new_height=300
    logo_image = logo_image.subsample(int(logo_image.width() / new_width), int(logo_image.height() / new_height))
    logo_label = tk.Label(root, image=logo_image)
    logo_label.pack(pady=20)
title_label = tk.Label(root, text="Folder Encrypter", font="algerian")
title_label.pack(pady=10)
encrypt_button = tk.Button(root, text="Encrypt Folder", command=encrypt_process, font=("Helvetica", 10, "bold"))
encrypt_button.pack(pady=10)
decrypt_button = tk.Button(root, text="Decrypt Folder", command=decrypt_process, font=("Helvetica", 10, "bold"))
decrypt_button.pack(pady=10)
details_button = tk.Button(root, text="Details", command=open_details_page, font=("Helvetica", 10, "bold"))
details_button.pack(pady=10)
root.mainloop()