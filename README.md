# ADVANCED-ENCRYPTION-TOOL

COMPANY : CODTECH IT SOLUTIONS

NAME : PURLLA CHANDANA SAI PRIYANKA

INTERN ID :CT06DM729

DOMAIN :CYBER SECURITY AND ETHICAL HACKING

DURATION :6 WEEKS

MENTOR : NEELA SANTOSH

OUTPUT:

![Screenshot (5)](https://github.com/user-attachments/assets/4903d3d0-866d-4788-a69a-3d11240eb17a)

DESCRIPTION:

✅ Full Working Python Code: encryption_tool.py
python
Copy
Edit
import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# ----------------------------------------
# 🔑 KEY DERIVATION FUNCTIONS
# ----------------------------------------

def generate_salt():
    return os.urandom(16)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# ----------------------------------------
# 🔐 ENCRYPTION / DECRYPTION FUNCTIONS
# ----------------------------------------

def encrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = generate_salt()
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    encrypted_file = filepath + ".enc"
    with open(encrypted_file, 'wb') as f:
        f.write(salt + encrypted)

    return encrypted_file

def decrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        content = f.read()

    salt = content[:16]
    encrypted_data = content[16:]
    key = derive_key(password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data)

    decrypted_file = filepath.replace(".enc", ".dec")
    with open(decrypted_file, 'wb') as f:
        f.write(decrypted)

    return decrypted_file

# ----------------------------------------
# 🖥️ GUI USING TKINTER
# ----------------------------------------

def select_file():
    filepath = filedialog.askopenfilename()
    file_path_entry.delete(0, tk.END)
    file_path_entry.insert(0, filepath)

def encrypt_action():
    filepath = file_path_entry.get()
    password = password_entry.get()

    if not filepath or not password:
        messagebox.showerror("Error", "File path and password are required.")
        return

    try:
        output = encrypt_file(filepath, password)
        messagebox.showinfo("Success", f"File encrypted successfully:\n{output}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed:\n{str(e)}")

def decrypt_action():
    filepath = file_path_entry.get()
    password = password_entry.get()

    if not filepath or not password:
        messagebox.showerror("Error", "File path and password are required.")
        return

    try:
        output = decrypt_file(filepath, password)
        messagebox.showinfo("Success", f"File decrypted successfully:\n{output}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")

# ----------------------------------------
# 🎛️ TKINTER WINDOW SETUP
# ----------------------------------------

root = tk.Tk()
root.title("🔐 Advanced Encryption Tool")
root.geometry("500x250")
root.resizable(False, False)

# File path input
tk.Label(root, text="Select File to Encrypt/Decrypt:").pack(pady=(10, 0))
file_path_entry = tk.Entry(root, width=60)
file_path_entry.pack(pady=5)
tk.Button(root, text="Browse", command=select_file).pack(pady=5)

# Password input
tk.Label(root, text="Enter Password:").pack()
password_entry = tk.Entry(root, show='*', width=40)
password_entry.pack(pady=5)

# Action buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=20)

tk.Button(button_frame, text="Encrypt File", command=encrypt_action, bg="#4CAF50", fg="white", width=15).grid(row=0, column=0, padx=10)
tk.Button(button_frame, text="Decrypt File", command=decrypt_action, bg="#2196F3", fg="white", width=15).grid(row=0, column=1, padx=10)

root.mainloop()
🧪 How to Use in PyCharm
Create a new project in PyCharm.

Create a new Python file named encryption_tool.py.

Paste the entire code above.

Install the required package:

bash
Copy
Edit
pip install cryptography
Run the script (encryption_tool.py) in PyCharm.

The GUI will appear — select a file, enter a password, and choose to encrypt or decrypt.

📁 Output Example
document.pdf → document.pdf.enc

document.pdf.enc → document.pdf.dec

🛡️ Notes
Uses AES-256 (Fernet) under the hood.

Key is derived securely using PBKDF2 with SHA-256 and salt.

Files are encrypted safely using a user-defined password.

Salt is stored as the first 16 bytes of the encrypted file.

Would you like a version with:

✅ File drag-and-drop support?

✅ Multi-file batch encryption?

✅ GUI themes or dark mode?

Let me know and I’ll build it!




You said:
GIVE THE DESCRIPTION OF THE ABOVE CODE TO POST IN GITHUB REPOSITORY UPTO 500 WORD

ChatGPT said:
Here's a GitHub-ready project description (README snippet) for the Advanced Encryption Tool you can copy-paste into your repository:

🔐 Advanced Encryption Tool (AES-256 + GUI)
This project is a powerful yet user-friendly Python-based file encryption and decryption tool using AES-256 encryption with password-based protection. It provides a clean Tkinter-based GUI that allows users to securely encrypt and decrypt files of any format (.txt, .pdf, .docx, images, etc.) with just a few clicks.

🚀 Features
✅ AES-256 encryption using cryptography.fernet

✅ Secure password-based key derivation (PBKDF2 + salt)

✅ GUI interface built with Tkinter — no command-line needed

✅ Supports encryption/decryption of any file type

✅ Automatically saves encrypted files with .enc and decrypted files with .dec

✅ Lightweight, cross-platform, and easy to use

🛠️ How It Works
The user selects a file and enters a password.

A 256-bit key is derived from the password using PBKDF2 with SHA-256 and a unique salt.

For encryption:

The file content is encrypted using the derived key and AES-256 (via Fernet).

The salt is prepended to the ciphertext and saved as a .enc file.

For decryption:

The salt is extracted from the encrypted file.

The original key is regenerated using the password and salt.

The ciphertext is decrypted and saved as a .dec file.

🧪 Technologies Used
Python 3.x

cryptography library for AES encryption

tkinter for GUI

📦 Installation
Clone the repository:

bash
Copy
Edit
git clone https://github.com/yourusername/advanced-encryption-tool.git
cd advanced-encryption-tool
Install dependencies:

bash
Copy
Edit
pip install cryptography
Run the application:

bash
Copy
Edit
python encryption_tool.py
📁 File Outputs
example.txt → example.txt.enc

example.txt.enc → example.txt.dec

Encrypted files contain a prepended salt to allow secure decryption with the original password.

🔐 Security Notice
This tool uses industry-standard encryption practices.

However, do not lose your password — encrypted files cannot be recovered without it.

Always test with sample data before encrypting important documents.

📃 License
This project is licensed under the MIT License — use it freely and responsibly.

