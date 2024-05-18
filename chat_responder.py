import base64
import socket
import json
from datetime import datetime
import threading
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes

TCP_PORT = 6001

class ChatResponder:
    def __init__(self, peer_discovery):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(('', TCP_PORT))
        self.sock.listen(5)
        self.peers = {}
        self.peer_discovery = peer_discovery
        self.shared_secret = None

        self.parameters = (17087896287367280659160173621749326217267278844161313900219344892915400724841504636696352281067519, 11111111111111111111111111111111111111111111111111111111111111111111111111111111111011111111111111)
 

    def listen(self):
        while True:
            conn, addr = self.sock.accept()
            threading.Thread(target=self.handle_connection, args=(conn, addr)).start()

    def handle_connection(self, conn, addr):
        data = conn.recv(1024)
        message = json.loads(data.decode())

        if "key" in message:
            self.exchange_keys(conn, message["key"])

            # Then receive the encrypted message
            d = conn.recv(1024)
            m = json.loads(d.decode())
            self.decrypt_message(addr, m["encrypted_message"])
        elif "unencrypted_message" in message:
            self.display_message(addr, message["unencrypted_message"])

        conn.close()


    def exchange_keys(self, conn, key):
        private_key = random.randrange(1, 100)
        message = json.dumps({"key": self.parameters[1] ** private_key % self.parameters[0]})
        conn.send(message.encode())

        self.shared_secret = key ** private_key % self.parameters[0]
        print(f"Shared secret key is: {self.shared_secret}")
        
    def decrypt_message(self, addr, encoded_message):
        encrypted_message = base64.b64decode(encoded_message)
        iv = encrypted_message[:16]
        ct = encrypted_message[16:]
        cipher = Cipher(algorithms.AES(self.generate_key_from_number(self.shared_secret)), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        self.display_message(addr, data)
    
    def generate_key_from_number(self, number):
        # Convert the number to a string and encode it to bytes
        number_str = str(number).encode()
        # Hash the number to get a 256-bit key
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(number_str)   
        key = digest.finalize()
        return key

    def display_message(self, addr, message):
        print(f"Message from {addr[0]}: {message}")
        self.log_message(addr[0], "RECEIVED", message)

    def log_message(self, ip, direction, message):
        with open("chat_history.log", "a") as log_file:
            peer = self.peer_discovery.peers.get(ip)
            username = peer.username if peer else "Unknown"
            log_file.write(f"{datetime.now()}, {username}, {ip}, {direction}, {message}\n")
