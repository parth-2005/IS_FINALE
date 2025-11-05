# messaging/protocol.py
import socket
import threading
from typing import Optional
import os
import json
import base64

# Use the simplified crypto implementation
from infoSec.simpleCrypto import generate_keypair, generate_aes_key, aes_encrypt, aes_decrypt

# Import auth and history functions
from .auth import authenticate, register_user
from .chat_history import load_chat_history, append_encrypted_log

# --- IS1 Networking Functions ---
def send_bytes(sock: socket.socket, data: bytes) -> None:
    """Send a 4-byte length prefix followed by data."""
    length = len(data)
    sock.sendall(length.to_bytes(4, "big") + data)

def recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    """Receive exactly n bytes."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def recv_frame(sock: socket.socket) -> Optional[bytes]:
    """Receive a complete frame (header + payload)."""
    header = recv_exact(sock, 4)
    if not header:
        return None
    length = int.from_bytes(header, "big")
    return recv_exact(sock, length)

def recv_line(sock: socket.socket) -> Optional[bytes]:
    """Receive a newline-terminated string (for RSA handshake)."""
    data = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            return None
        data += ch
        if ch == b"\n":
            break
    return data.rstrip(b"\n")


class MessagingService:
    def __init__(self, host: str = "127.0.0.1", port: int = 5555):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # --- File Transfer Methods ---
    def send_file(self, sock: socket.socket, filepath: str, aes_key: bytes, log_user: str):
        """Encrypts and sends a file using the framing protocol."""
        if not os.path.exists(filepath):
            print(f"File not found: {filepath}")
            return
        
        try:
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            
            # 1. Send file metadata (as a JSON string)
            meta = {"type": "file_meta", "filename": filename, "size": filesize}
            meta_json = json.dumps(meta)
            print(f"Sending file: {filename} ({filesize} bytes)")
            send_bytes(sock, aes_encrypt(meta_json, aes_key))
            
            # 2. Send file chunks (as Base64 strings)
            with open(filepath, "rb") as f:
                while chunk := f.read(4096 * 3): # Read raw bytes
                    # Encode bytes as Base64 string to safely pass through text encryption
                    chunk_b64 = base64.b64encode(chunk).decode('utf-8')
                    
                    # Create a JSON wrapper
                    chunk_msg = {"type": "file_chunk", "data": chunk_b64}
                    chunk_json = json.dumps(chunk_msg)
                    
                    send_bytes(sock, aes_encrypt(chunk_json, aes_key))
            
            # 3. Send file end marker
            end_meta = {"type": "file_end"}
            end_json = json.dumps(end_meta)
            send_bytes(sock, aes_encrypt(end_json, aes_key))
            
            print(f"[+] File '{filename}' sent successfully.")
            append_encrypted_log(log_user, f"[Sent File: {filename}]")
            
        except Exception as e:
            print(f"Error sending file: {e}")

    def receive_file(self, first_frame_payload: str, sock: socket.socket, aes_key: bytes, log_user: str):
        """Receives a file using the framing protocol."""
        try:
            # 1. Process the metadata (which we already decrypted)
            metadata = json.loads(first_frame_payload)
            filename = metadata["filename"]
            filesize = metadata["size"]
            
            print(f"Receiving file: {filename} ({filesize} bytes)...")
            file_path = f"received_{filename}"
            received_bytes = 0
            
            # 2. Receive file chunks
            with open(file_path, "wb") as f:
                while True:
                    frame = recv_frame(sock)
                    if not frame:
                        print("Connection lost during file transfer.")
                        return
                    
                    decrypted_json = aes_decrypt(frame, aes_key)
                    msg = json.loads(decrypted_json)
                    
                    if msg.get("type") == "file_chunk":
                        # Decode Base64 string to raw bytes
                        chunk = base64.b64decode(msg.get("data", ""))
                        f.write(chunk)
                        received_bytes += len(chunk)
                    elif msg.get("type") == "file_end":
                        break # File transfer complete
                    else:
                        print("Unexpected message type during file transfer.")
            
            print(f"[+] File saved as '{file_path}' ({received_bytes} bytes).")
            append_encrypted_log(log_user, f"[Received File: {filename}]")
            
        except Exception as e:
            print(f"Error receiving file: {e}")

    # --- Server Logic ---
    def start_server(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(5) # Listen for more than 1
        print(f"Server listening on {self.host}:{self.port}")

        while True:
            try:
                client, address = self.socket.accept()
                print(f"Connected with {address}")
                t = threading.Thread(target=self.handle_client, args=(client,))
                t.start()
            except KeyboardInterrupt:
                print("\nShutting down server.")
                break
            except Exception as e:
                print(f"Server error: {e}")
        self.socket.close()

    def handle_client(self, client: socket.socket):
        client_address = client.getpeername()
        username = "unknown" # For logging
        try:
            # --- Handshake Logic ---
            public_key, private_key = generate_keypair(256)
            e, n = public_key
            d, _ = private_key
            handshake = f"{e},{n}\n".encode()
            client.sendall(handshake)

            line = recv_line(client)
            if not line:
                print(f"Client {client_address} closed during handshake")
                return
            
            parts = line.decode().split(":", 1)
            key_len = int(parts[0])
            c_hex = parts[1]
            c_bytes = bytes.fromhex(c_hex)
            c_int = int.from_bytes(c_bytes, "big")
            m_int = pow(c_int, d, n)
            aes_key = m_int.to_bytes(key_len, "big")
            print(f"Derived AES key ({len(aes_key)} bytes) for client {client_address}")

            # --- SECURE AUTHENTICATION ---
            while True:
                auth_frame = recv_frame(client)
                if not auth_frame:
                    print(f"Client {client_address} closed during auth.")
                    return
                
                try:
                    auth_msg = aes_decrypt(auth_frame, aes_key)
                    # Use split with maxsplit=2
                    parts = auth_msg.split(":", 2)
                    if len(parts) != 3:
                        raise ValueError("Invalid auth format")
                    
                    command = parts[0]
                    username_attempt = parts[1]
                    password_attempt = parts[2]
                    
                    if command == "LOGIN":
                        if authenticate(username_attempt, password_attempt):
                            username = username_attempt
                            send_bytes(client, aes_encrypt("Authenticated", aes_key))
                            print(f"Auth OK: {username} from {client_address}")
                            break
                        else:
                            send_bytes(client, aes_encrypt("Auth Failed", aes_key))
                    elif command == "REGISTER":
                        if register_user(username_attempt, password_attempt):
                            send_bytes(client, aes_encrypt("Registered successfully. Please log in.", aes_key))
                        else:
                            send_bytes(client, aes_encrypt("Username already exists.", aes_key))
                except Exception as e:
                    print(f"Auth error: {e}")
                    send_bytes(client, aes_encrypt("Auth Error", aes_key))

            # --- SEND CHAT HISTORY ---
            print(f"--- Sending chat history to {username} ---")
            history = load_chat_history(username)
            history_json = json.dumps(history if history else [])
            send_bytes(client, aes_encrypt(history_json, aes_key))

            # --- Symmetrical Send/Receive Logic ---
            def server_recv_thread():
                try:
                    while True:
                        frame = recv_frame(client)
                        if frame is None:
                            print(f"\nClient {username} closed connection.")
                            break
                        
                        try:
                            decrypted_data = aes_decrypt(frame, aes_key)
                            msg = json.loads(decrypted_data)
                            msg_type = msg.get("type")
                            
                            if msg_type == "chat":
                                plaintext = msg.get("content", "")
                                if plaintext.lower() == 'quit':
                                    print(f"\nClient {username} sent quit.")
                                    break
                                print(f"\nClient {username}: {plaintext}\n> ", end="", flush=True)
                                append_encrypted_log(username, plaintext)
                            elif msg_type == "file_meta":
                                print("\n", end="") # Newline for file prompt
                                self.receive_file(decrypted_data, client, aes_key, username)
                                print("> ", end="", flush=True)
                            
                        except json.JSONDecodeError:
                            print(f"\nClient {username} sent invalid JSON: {decrypted_data}\n> ", end="", flush=True)
                        except Exception as e:
                            print(f"Decryption/Processing error: {e}")
                except ConnectionError:
                    print(f"\nConnection lost with client {username}.")
                finally:
                    print(f"\nReceive thread for {username} stopping.")
                    client.close()

            rt = threading.Thread(target=server_recv_thread, daemon=True)
            rt.start()

            print(f"--- Enter messages for {username} (or 'quit' / 'file <path>') ---")
            while rt.is_alive():
                try:
                    message = input("> ")
                    if not rt.is_alive():
                        break
                    if message.lower() == 'quit':
                        break
                    
                    if message.startswith("file "):
                        filepath = message.split(" ", 1)[1].strip()
                        self.send_file(client, filepath, aes_key, "Server")
                    else:
                        chat_msg = {"type": "chat", "content": message}
                        chat_json = json.dumps(chat_msg)
                        ct = aes_encrypt(chat_json, aes_key)
                        send_bytes(client, ct)
                        append_encrypted_log("Server", message)

                except ConnectionError:
                    break
                except Exception as e:
                    print(f"\nError sending message: {e}")
                    break

        except ConnectionError:
            pass # Handled by recv_thread
        except Exception as e:
            print(f"Error handling client {username}@{client_address}: {e}")
        finally:
            print(f"Closing connection for {username}@{client_address}.")
            client.close()

    # --- Client Logic ---
    def connect_to_server(self) -> bool:
        try:
            self.socket.connect((self.host, self.port))
            print(f"Connected to server at {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def start_client_loop(self):
        try:
            # --- Handshake ---
            line = recv_line(self.socket)
            if not line:
                print("Server closed during handshake")
                return
            e_str, n_str = line.decode().split(",")
            e = int(e_str)
            n = int(n_str)
            n_bytes = (n.bit_length() + 7) // 8
            key_len = 16  # AES-128
            aes_key = generate_aes_key(key_len)
            m_int = int.from_bytes(aes_key, "big")
            c_int = pow(m_int, e, n)
            c_bytes = c_int.to_bytes(n_bytes, "big")
            msg = f"{key_len}:{c_bytes.hex()}\n".encode()
            self.socket.sendall(msg)
            print(f"Sent wrapped AES key ({key_len} bytes)")

            # --- SECURE AUTHENTICATION ---
            username = ""
            while True:
                choice = input("Do you have an account? (y/n): ").strip().lower()
                if choice == 'n':
                    print("--- Register New User ---")
                    username_attempt = input("Choose username: ")
                    password = input("Choose password: ")
                    auth_msg = f"REGISTER:{username_attempt}:{password}"
                    send_bytes(self.socket, aes_encrypt(auth_msg, aes_key))
                else:
                    print("--- Login ---")
                    username_attempt = input("Username: ")
                    password = input("Password: ")
                    auth_msg = f"LOGIN:{username_attempt}:{password}"
                    send_bytes(self.socket, aes_encrypt(auth_msg, aes_key))
                
                auth_response_frame = recv_frame(self.socket)
                if not auth_response_frame:
                    print("Server closed connection during auth.")
                    return
                
                auth_status = aes_decrypt(auth_response_frame, aes_key)
                print(f"Server: {auth_status}")
                
                if auth_status == "Authenticated":
                    username = username_attempt
                    break
                if "Registered successfully" in auth_status:
                    print("Please log in now.")
            
            print(f"--- Logged in as {username} ---")

            # --- RECEIVE CHAT HISTORY ---
            print("--- Loading previous chat history ---")
            history_frame = recv_frame(self.socket)
            if history_frame:
                try:
                    history_payload = aes_decrypt(history_frame, aes_key)
                    if history_payload == "[]":
                        print("No previous chat history.")
                    else:
                        history_lines = json.loads(history_payload)
                        for line in history_lines:
                            print(line.strip())
                except Exception as e:
                    print(f"Could not parse chat history: {e}")
            print("-------------------------------------")

            # --- Receive Thread ---
            def recv_thread():
                try:
                    while True:
                        try:
                            frame = recv_frame(self.socket)
                            if frame is None:
                                print("\nServer closed connection")
                                break
                            
                            decrypted_data = aes_decrypt(frame, aes_key)
                            msg = json.loads(decrypted_data)
                            msg_type = msg.get("type")
                            
                            if msg_type == "chat":
                                txt = msg.get("content", "")
                                print(f"\nServer: {txt}\n> ", end="", flush=True)
                                append_encrypted_log("Server", txt)
                            elif msg_type == "file_meta":
                                print("\n", end="") # Newline for file prompt
                                self.receive_file(decrypted_data, self.socket, aes_key, "Server")
                                print("> ", end="", flush=True)
                            
                        except json.JSONDecodeError:
                            print(f"\nServer sent invalid JSON: {decrypted_data}\n> ", end="", flush=True)
                        except ConnectionError as e:
                            print(f"\nConnection error: {e}")
                            break
                        except Exception as exc:
                            print(f"\nFailed to process server message: {exc}")
                            break
                finally:
                    print("\nConnection lost. Press Enter to exit.")
                    self.socket.close()

            rt = threading.Thread(target=recv_thread, daemon=True)
            rt.start()

            # --- Send Loop ---
            while rt.is_alive():
                try:
                    message = input("> ")
                    if not rt.is_alive():
                        break
                    if message.lower() == 'quit':
                        ct = aes_encrypt(json.dumps({"type": "chat", "content": "quit"}), aes_key)
                        send_bytes(self.socket, ct)
                        break
                    
                    if message.startswith("file "):
                        filepath = message.split(" ", 1)[1].strip()
                        self.send_file(self.socket, filepath, aes_key, username)
                    else:
                        chat_msg = {"type": "chat", "content": message}
                        chat_json = json.dumps(chat_msg)
                        ct = aes_encrypt(chat_json, aes_key)
                        send_bytes(self.socket, ct)
                        append_encrypted_log(username, message)

                except ConnectionError:
                    break
                except Exception as e:
                    print(f"\nError sending message: {e}")
                    break
        except KeyboardInterrupt:
            print("\nDisconnecting...")
        finally:
            self.socket.close()

    # --- Entry Point ---
    def start(self, mode: str = "server"):
        if mode == "server":
            # Run server in main thread to allow keyboard interrupt
            self.start_server()
        else:
            if self.connect_to_server():
                self.start_client_loop()
