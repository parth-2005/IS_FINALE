from Crypto.Cipher import AES
import sys

def simple_unpad(data: bytes) -> bytes:
    """
    Remove the custom padding by reading the last byte
    which indicates padding length.
    (From infoSec/simpleCrypto.py)
    """
    try:
        padding_length = data[-1]
        if padding_length > len(data) or padding_length == 0:
            raise ValueError("Invalid padding length.")
        
        # Check if all padding bytes are correct
        for i in range(1, padding_length + 1):
            if data[-i] != padding_length:
                raise ValueError("Invalid padding bytes.")
                
        return data[:-padding_length]
    except (IndexError, ValueError) as e:
        raise ValueError(f"Decryption failed: Invalid padding. {e}")

def aes_decrypt(ciphertext: bytes, key: bytes) -> str:
    """
    Decrypts the AES payload.
    (From infoSec/simpleCrypto.py)
    """
    try:
        if len(ciphertext) < AES.block_size:
            raise ValueError("Invalid ciphertext length (too short).")
        
        # Extract IV and ciphertext
        iv = ciphertext[:AES.block_size]
        ct = ciphertext[AES.block_size:]
        
        if len(ct) % AES.block_size != 0:
             raise ValueError("Ciphertext length is not a multiple of block size.")

        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ct)
        
        # Remove padding and convert to string
        plaintext = simple_unpad(padded_plaintext)
        return plaintext.decode('utf-8')
    except Exception as e:
        # Re-raise as a ValueError for clarity
        raise ValueError(f"Decryption failed: {str(e)}")

def decode_message(data_hex: str, key_hex: str):
    """
    Decodes a full data frame from your protocol.
    """
    try:
        # 1. Convert hex strings to bytes
        key_bytes = bytes.fromhex(key_hex)
        data_bytes = bytes.fromhex(data_hex)
        
        # 2. Parse the data frame based on your protocol
        # (4-byte header + payload)
        header_len = 4
        payload = data_bytes[header_len:]
        
        # 3. Decrypt the payload
        message = aes_decrypt(payload, key_bytes)
        return message
        
    except ValueError as e:
        return f"Error: {e}"

# --- MAIN ---

# Paste your data and key here
data_hex = input("Data: ")
key_hex = input("Key: ")

decoded_message = decode_message(data_hex, key_hex)

print(f"Message: {decoded_message}")