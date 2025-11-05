# messaging/chat_history.py
import os
from datetime import datetime

# MODIFIED: Import from the IS1 crypto file
from infoSec.simpleCrypto import aes_encrypt, aes_decrypt, generate_aes_key

LOG_DIR = "chat_logs"
KEY_FILE = os.path.join(LOG_DIR, "history_key.bin")
os.makedirs(LOG_DIR, exist_ok=True)

# ===== Persistent Key Handling =====
def _get_log_key():
    """Ensure the same AES key is used for encrypting/decrypting history."""
    if not os.path.exists(KEY_FILE):
        # Use 16-byte key for AES-128, matching simpleCrypto
        key = generate_aes_key(16) 
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

def _log_path(username):
    """Return path for user28s encrypted chat log."""
    return os.path.join(LOG_DIR, f"{username}_history.enc")

def append_encrypted_log(username, message):
    """Append one encrypted line to user28s chat log."""
    path = _log_path(username)
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
    log_key = _get_log_key()
    
    # Use aes_encrypt directly (it handles string-to-bytes)
    enc = aes_encrypt(timestamp + message + "\n", log_key)
    
    with open(path, "ab") as f:
        f.write(enc + b"<END>") # Use a delimiter

def load_chat_history(username):
    """Load and decrypt all previous chat lines."""
    path = _log_path(username)
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        data = f.read()

    log_key = _get_log_key()
    lines = []
    for block in data.split(b"<END>"): # Split by delimiter
        if not block.strip():
            continue
        try:
            # Use aes_decrypt directly (it handles bytes-to-string)
            lines.append(aes_decrypt(block, log_key))
        except Exception:
            continue # Skip blocks that fail decryption (e.g., partial)
    return lines
