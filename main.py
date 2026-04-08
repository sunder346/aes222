import base64
import tkinter as tk
from tkinter import messagebox, ttk
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    raise SystemExit(
        "Не найден пакет 'cryptography'. Установите его командой:\n"
        "pip install cryptography"
    )
import os

SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITERATIONS = 200_000

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_text(plaintext: str, password: str) -> str:
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    payload = salt + iv + ciphertext
    return base64.b64encode(payload).decode("utf-8")

def decrypt_text(encoded_payload: str, password: str) -> str:
    raw = base64.b64decode(encoded_payload.encode("utf-8"))
    if len(raw) < SALT_SIZE + IV_SIZE + 16:
        raise ValueError("Слишком короткие данные для дешифрования.")
    salt = raw[:SALT_SIZE]
    iv = raw[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = raw[SALT_SIZE + IV_SIZE:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext_bytes.decode("utf-8")

class AESApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("AES Шифратор / Дешифратор (Tkinter)")
        self.geometry("760x540")
        self.minsize(680, 500)
        self._build_ui()

    def _build_ui(self) -> None:
        top_frame = ttk.Frame(self, padding=10)
        top_frame.pack(fill="x")

        ttk.Label(top_frame, text="Пароль: ").pack(side="left", padx=(0, 8))

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(top_frame, textvariable=self.password_var, show="*", width=40)
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.show_password_var = tk.BooleanVar(value=False)
        show_check = ttk.Checkbutton(
            top_frame,
            text="Показать пароль",
            variable=self.show_password_var,
            command=self._toggle_password_visibility,
        )
        show_check.pack(side="left")

        input_frame = ttk.LabelFrame(self, text="Входные данные", padding=10)
        input_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.input_text = tk.Text(input_frame, wrap="word", height=10)
        self.input_text.pack(fill="both", expand=True)

        actions_frame = ttk.Frame(self, padding=(10, 0, 10, 10))
        actions_frame.pack(fill="x")

        encrypt_btn = ttk.Button(actions_frame, text="Зашифровать →", command=self._on_encrypt)
        encrypt_btn.pack(side="left", padx=(0, 8))

        decrypt_btn = ttk.Button(actions_frame, text="Дешифровать →", command=self._on_decrypt)
        decrypt_btn.pack(side="left", padx=(0, 8))

        clear_btn = ttk.Button(actions_frame, text="Очистить", command=self._on_clear)
        clear_btn.pack(side="left", padx=(0, 8))

        swap_btn = ttk.Button(actions_frame, text="Результат → Вход", command=self._on_swap)
        swap_btn.pack(side="left")

        output_frame = ttk.LabelFrame(self, text="Результат", padding=10)
        output_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.output_text = tk.Text(output_frame, wrap="word", height=10)
        self.output_text.pack(fill="both", expand=True)

        self.status_var = tk.StringVar(value="Готово.")
        status_label = ttk.Label(self, textvariable=self.status_var, anchor="w", padding=(10, 0, 10, 10))
        status_label.pack(fill="x")

    def _toggle_password_visibility(self) -> None:
        self.password_entry.configure(show="" if self.show_password_var.get() else "*")

    def _read_password(self) -> str:
        password = self.password_var.get().strip()
        if not password:
            raise ValueError("Введите пароль.")
        if len(password) < 4:
            raise ValueError("Пароль должен быть не короче 4 символов.")
        return password

    def _read_input_text(self) -> str:
        text = self.input_text.get("1.0", "end").strip()
        if not text:
            raise ValueError("Введите данные в поле 'Входные данные'.")
        return text

    def _set_output(self, text: str) -> None:
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", text)

    def _set_status(self, text: str) -> None:
        self.status_var.set(text)

    def _on_encrypt(self) -> None:
        try:
            password = self._read_password()
            plaintext = self._read_input_text()
            encrypted = encrypt_text(plaintext, password)
            self._set_output(encrypted)
            self._set_status("Текст успешно зашифрован.")
        except Exception as exc:
            messagebox.showerror("Ошибка шифрования", str(exc))
            self._set_status("Ошибка шифрования.")

    def _on_decrypt(self) -> None:
        try:
            password = self._read_password()
            encrypted_text = self._read_input_text()
            decrypted = decrypt_text(encrypted_text, password)
            self._set_output(decrypted)
            self._set_status("Текст успешно дешифрован.")
        except Exception as exc:
            messagebox.showerror("Ошибка дешифрования", str(exc))
            self._set_status("Ошибка дешифрования.")

    def _on_clear(self) -> None:
        self.input_text.delete("1.0", "end")
        self.output_text.delete("1.0", "end")
        self._set_status("Поля очищены.")

    def _on_swap(self) -> None:
        result = self.output_text.get("1.0", "end").strip()
        if not result:
            messagebox.showinfo("Информация", "Поле результата пустое.")
            return
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", result)
        self._set_status("Результат перенесён во входные данные.")

def main() -> None:
    app = AESApp()
    app.mainloop()

if __name__ == "__main__":
    main()