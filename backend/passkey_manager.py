import base64
import os
import sqlite3
from datetime import datetime
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from backend.config import DATABASE_DIR
from session_manager import SessionManager

DATABASE_NAME = "DefaultFortalice"
DATABASE_PATH = os.path.join(DATABASE_DIR, f"{DATABASE_NAME}.db")

# Ensure the directory for the database exists
if not os.path.exists(DATABASE_DIR):
    os.makedirs(DATABASE_DIR)


def create_passkey_table():
    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS passkeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                salt TEXT NOT NULL,
                nonce TEXT NOT NULL,
                tag TEXT NOT NULL,
                passkey TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL
            )
            """)
            conn.commit()
    except sqlite3.Error as e:
        raise Exception(f"Database error during table creation: {e}")


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(master_password.encode())


def encrypt_passkey(passkey: str, key: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_passkey = encryptor.update(passkey.encode()) + encryptor.finalize()
    return encrypted_passkey, encryptor.tag


def decrypt_passkey(
    encrypted_passkey: bytes, key: bytes, nonce: bytes, tag: bytes
) -> str:
    cipher = Cipher(
        algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decrypted_passkey = decryptor.update(encrypted_passkey) + decryptor.finalize()
    return decrypted_passkey.decode()


def add_passkey(passkey: str, description: str):
    session = SessionManager.get_instance()
    master_password = session.get_master_password()
    if not master_password:
        raise ValueError("Master password not set.")

    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    nonce = os.urandom(12)
    encrypted_passkey, tag = encrypt_passkey(passkey, key, nonce)

    # Encode binary data to base64 strings for storage
    b64_salt = base64.b64encode(salt).decode("utf-8")
    b64_nonce = base64.b64encode(nonce).decode("utf-8")
    b64_tag = base64.b64encode(tag).decode("utf-8")
    b64_encrypted_passkey = base64.b64encode(encrypted_passkey).decode("utf-8")

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO passkeys (salt, nonce, tag, passkey, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    b64_salt,
                    b64_nonce,
                    b64_tag,
                    b64_encrypted_passkey,
                    description,
                    created_at,
                ),
            )
            conn.commit()
    except sqlite3.Error as e:
        raise Exception(f"Failed to add passkey: {e}")


def get_all_passkeys():
    session = SessionManager.get_instance()
    master_password = session.get_master_password()
    if not master_password:
        raise ValueError("Master password not set.")

    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM passkeys")
            passkeys = cursor.fetchall()
            decrypted_passkeys = []

            for (
                id,
                b64_salt,
                b64_nonce,
                b64_tag,
                b64_encrypted_passkey,
                description,
                created_at,
            ) in passkeys:
                # Decode base64 encoded values
                salt = base64.b64decode(b64_salt)
                nonce = base64.b64decode(b64_nonce)
                tag = base64.b64decode(b64_tag)
                encrypted_passkey = base64.b64decode(b64_encrypted_passkey)

                key = derive_key(master_password, salt)
                decrypted_passkey = decrypt_passkey(encrypted_passkey, key, nonce, tag)
                decrypted_passkeys.append(
                    (id, decrypted_passkey, description, created_at)
                )

            return decrypted_passkeys
    except sqlite3.Error as e:
        raise Exception(f"Database error: {e}")
    except Exception as e:
        raise Exception(f"Failed to retrieve passkeys: {e}")


# Ensure the passkey table is created
create_passkey_table()
