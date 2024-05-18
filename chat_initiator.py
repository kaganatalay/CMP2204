import base64
import os
import socket
import json
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend

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

            conn.send(message.encode())
            
            # Wait for peer's number and generate the shared key
            peer_message = json.loads(conn.recv(1024).decode())

            if "key" in peer_message:
                peer_number = int(peer_message["key"])
                shared_secret = peer_number ** number % self.parameters[0]
            else:
                print("Key exchange failed.")
                return
            
            print(f"Shared secret key is: {shared_secret}")

            
            iv = b'\x00' * 16  # Use a fixed IV for simplicity (not recommended for production)
            cipher = Cipher(algorithms.AES(self.generate_key_from_number(shared_secret)), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(message.encode()) + padder.finalize()
            
            ct = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_message = iv + ct

            # Base64 encode the encrypted message
            encoded_message = base64.b64encode(encrypted_message).decode('utf-8')

            payload = json.dumps({"encrypted_message": encoded_message})

            print(f"payload is {payload}")

            conn.send(payload.encode())

            self.log_message(target_ip, "SENT", message)  

    def generate_key_from_number(self, number):
        # Convert the number to a string and encode it to bytes
        number_str = str(number).encode()
        # Hash the number to get a 256-bit key
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(number_str)   
        key = digest.finalize()
        return key

    def unsecure_chat(self, target_ip, message):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((target_ip, TCP_PORT))
            s.send(json.dumps({"unencrypted_message": message}).encode())
            self.log_message(target_ip, "SENT", message)

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
