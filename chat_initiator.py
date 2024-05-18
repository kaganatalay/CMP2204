import socket
import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from peer_discovery import PeerDiscovery

TCP_PORT = 6001

class ChatInitiator:
    def __init__(self, peer_discovery):
        self.peer_discovery = peer_discovery

        self.parameters = (17087896287367280659160173621749326217267278844161313900219344892915400724841504636696352281067519, 11111111111111111111111111111111111111111111111111111111111111111111111111111111111011111111111111)

    def start_chat(self, secure):
        peers = self.peer_discovery.get_active_peers()
        if not peers:
            print("No users available.")
            return
        print("Available users:")
        for ip, (username, status) in peers.items():
            print(f"{username} ({status}) - {ip}")
        target_username = input("Enter the username to chat with: ")
        target_ip = next((ip for ip, (username, _) in peers.items() if username == target_username), None)
        if not target_ip:
            print("User not found.")
            return
        message = input("Enter your message: ")
        if secure:
            self.secure_chat(target_ip, message)
        else:
            self.unsecure_chat(target_ip, message)

    def secure_chat(self, target_ip, message):
        number = int(input("Enter a number to initiate the key exchange: ").strip())
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.connect((target_ip, TCP_PORT))
            
            # Send the initial number
            message = json.dumps({"key": self.parameters[1] ** number % self.parameters[0]})

            print(f"message is {message}")
            conn.send(message.encode())
            
            # Wait for peer's number and generate the shared key
            peer_message = json.loads(conn.recv(1024).decode())
            print(f"peer message is {peer_message}")

            if "key" in peer_message:
                peer_number = int(peer_message["key"])
                shared_secret = peer_number ** number % self.parameters[0]
            else:
                print("Key exchange failed.")
                return
            
            print(f"Shared secret key is: {shared_secret}")
            
            # encrypted_message = self.encrypt_message(shared_secret, message)
            # message = json.dumps({"encrypted_message": encrypted_message.hex()})
            # conn.send(message.encode())
            # self.log_message(target_ip, "SENT", message)

    def unsecure_chat(self, target_ip, message):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((target_ip, TCP_PORT))
            s.send(json.dumps({"unencrypted_message": message}).encode())
            self.log_message(target_ip, "SENT", message)

    def exchange_keys(self, s, private_key):
        public_key = private_key.public_key()
        s.send(json.dumps({"key": public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex()}).encode())
        data = s.recv(1024)
        message = json.loads(data.decode())
        peer_public_key_bytes = bytes.fromhex(message["key"])
        peer_public_key = load_pem_public_key(peer_public_key_bytes, backend=default_backend())
        return peer_public_key

    def log_message(self, target_ip, direction, message):
        with open("chat_history.log", "a") as log_file:
            log_file.write(f"{datetime.now()}, {self.peer_discovery.peers[target_ip].username}, {target_ip}, {direction}, {message}\n")

    def view_chat_history(self):
        try:
            with open("chat_history.log", "r") as log_file:
                for line in log_file:
                    print(line.strip())
        except FileNotFoundError:
            print("No chat history found.")
