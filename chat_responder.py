import socket
import json
from datetime import datetime
import threading
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

TCP_PORT = 6001

class ChatResponder:
    def __init__(self, peer_discovery):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(('', TCP_PORT))
        self.sock.listen(5)
        self.peers = {}
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        self.peer_discovery = peer_discovery

    def listen(self):
        while True:
            conn, addr = self.sock.accept()
            threading.Thread(target=self.handle_connection, args=(conn, addr)).start()

    def handle_connection(self, conn, addr):
        data = conn.recv(1024)
        message = json.loads(data.decode())
        if "key" in message:
            self.exchange_keys(conn, addr, message["key"])
        elif "encrypted message" in message:
            self.decrypt_message(addr, bytes.fromhex(message["encrypted message"]))
        elif "unencrypted message" in message:
            self.display_message(addr, message["unencrypted message"])
        conn.close()

    def exchange_keys(self, conn, addr, peer_public_key_hex):
        private_key = self.dh_parameters.generate_private_key()
        peer_public_key = load_pem_public_key(bytes.fromhex(peer_public_key_hex), backend=default_backend())
        shared_key = private_key.exchange(peer_public_key)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)
        public_key = private_key.public_key()
        conn.send(json.dumps({"key": public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex()}).encode())
        self.peers[addr[0]] = key

    def decrypt_message(self, addr, encrypted_message):
        key = self.peers.get(addr[0])
        if not key:
            print("Key not found for this peer.")
            return
        cipher = Cipher(algorithms.AES(key), modes.CFB8(key[:16]), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
        self.display_message(addr, decrypted_message.decode())

    def display_message(self, addr, message):
        print(f"Message from {addr[0]}: {message}")
        self.log_message(addr[0], "RECEIVED", message)

    def log_message(self, ip, direction, message):
        with open("chat_history.log", "a") as log_file:
            peer = self.peer_discovery.peers.get(ip)
            username = peer.username if peer else "Unknown"
            log_file.write(f"{datetime.now()}, {username}, {ip}, {direction}, {message}\n")
