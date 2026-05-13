import base64
import os
import tkinter as tk
from tkinter import messagebox, ttk

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    raise SystemExit("Установите библиотеку: pip install cryptography")


SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 200_000


def get_crypto_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())

def encrypt_data(plaintext: str, password: str) -> str:
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = get_crypto_key(password, salt)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(salt + iv + ciphertext).decode()

def decrypt_data(token: str, password: str) -> str:
    raw = base64.b64decode(token.encode())
    salt = raw[:SALT_SIZE]
    iv = raw[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = raw[SALT_SIZE + IV_SIZE:]

    key = get_crypto_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded_plaintext) + unpadder.finalize()).decode()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES Cryptographer")
        self.geometry("800x600")
        self.configure(bg="#f0f0f0")
        self._setup_ui()

    def _setup_ui(self):
        main_container = ttk.Frame(self, padding="20")
        main_container.pack(fill="both", expand=True)


        pwd_frame = ttk.Frame(main_container)
        pwd_frame.pack(fill="x", pady=(0, 15))
        ttk.Label(pwd_frame, text="Мастер-пароль:").pack(side="left")
        self.pwd_entry = ttk.Entry(pwd_frame, show="•", width=30)
        self.pwd_entry.pack(side="left", padx=10, fill="x", expand=True)
        
        self.show_pwd = tk.BooleanVar()
        ttk.Checkbutton(pwd_frame, text="Показать", variable=self.show_pwd, command=self._toggle_pwd).pack(side="left")

        # Поля ввода/вывода
        self.input_area = self._create_text_section(main_container, "Входные данные")
        
        btn_frame = ttk.Frame(main_container)
        btn_frame.pack(pady=15)
        
        ttk.Button(btn_frame, text="Зашифровать", command=lambda: self._run(encrypt_data)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Расшифровать", command=lambda: self._run(decrypt_data)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Очистить", command=self._clear).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Копировать результат", command=self._copy).pack(side="left", padx=5)

        self.output_area = self._create_text_section(main_container, "Результат")

    def _create_text_section(self, parent, title):
        frame = ttk.LabelFrame(parent, text=title, padding="10")
        frame.pack(fill="both", expand=True)
        txt = tk.Text(frame, wrap="word", font=("Consolas", 10))
        txt.pack(fill="both", expand=True)
        return txt

    def _toggle_pwd(self):
        self.pwd_entry.config(show="" if self.show_pwd.get() else "•")

    def _run(self, crypto_func):
        pwd = self.pwd_entry.get()
        data = self.input_area.get("1.0", "end-1c").strip()
        
        if not pwd or not data:
            messagebox.showwarning("Внимание", "Введите пароль и данные")
            return
        
        try:
            result = crypto_func(data, pwd)
            self.output_area.delete("1.0", "end")
            self.output_area.insert("1.0", result)
        except Exception as e:
            messagebox.showerror("Ошибка", "Неверный пароль или поврежденные данные")

    def _clear(self):
        self.input_area.delete("1.0", "end")
        self.output_area.delete("1.0", "end")
        self.pwd_entry.delete(0, "end")

    def _copy(self):
        res = self.output_area.get("1.0", "end-1c")
        if res:
            self.clipboard_clear()
            self.clipboard_append(res)

if __name__ == "__main__":
    App().mainloop()
