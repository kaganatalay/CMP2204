import socket
import json
import threading
import time
import datetime
import os
import sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode

# Constants
BROADCAST_IP = '255.255.255.255'
ANNOUNCE_PORT = 6000
CHAT_PORT = 6001
ANNOUNCE_INTERVAL = 8
USER_TIMEOUT = 15 * 60  # 15 minutes
RECENT_TIMEOUT = 10  # 10 seconds

# Utility functions
def current_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Generate a Diffie-Hellman key pair
def generate_dh_key_pair():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Derive a shared key from a private key and a peer's public key
def derive_shared_key(private_key, peer_public_key_bytes):
    peer_public_key = dh.DHPublicKey.from_encoded_point(private_key.public_key().public_numbers().parameter_numbers().p, peer_public_key_bytes)
    shared_key = private_key.exchange(peer_public_key)
    return shared_key

# Derive a symmetric key from the shared key
def derive_symmetric_key(shared_key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(shared_key)

# Encrypt a message using AES
def encrypt_message(message, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return urlsafe_b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')

# Decrypt a message using AES
def decrypt_message(encrypted_message, key):
    encrypted_message = urlsafe_b64decode(encrypted_message)
    iv, tag, ciphertext = encrypted_message[:12], encrypted_message[12:28], encrypted_message[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')

# Service Announcer
class ServiceAnnouncer(threading.Thread):
    def __init__(self, username):
        threading.Thread.__init__(self)
        self.username = username

    def run(self):
        while True:
            self.announce_service()
            time.sleep(ANNOUNCE_INTERVAL)

    def announce_service(self):
        message = json.dumps({"username": self.username})
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(message.encode('utf-8'), (BROADCAST_IP, ANNOUNCE_PORT))
        print(f"Announced presence: {self.username}")

# Peer Discovery
class PeerDiscovery(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.peers = {}
        self.lock = threading.Lock()

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('', ANNOUNCE_PORT))
            while True:
                data, addr = s.recvfrom(1024)
                self.process_announcement(data, addr)

    def process_announcement(self, data, addr):
        try:
            message = json.loads(data.decode('utf-8'))
            username = message.get("username")
            if username:
                with self.lock:
                    self.peers[addr[0]] = {'username': username, 'last_seen': time.time()}
                print(f"{username} is online")
        except json.JSONDecodeError:
            print("Failed to decode JSON message")

    def get_online_users(self):
        current_time = time.time()
        online_users = []
        with self.lock:
            for ip, info in self.peers.items():
                if current_time - info['last_seen'] <= USER_TIMEOUT:
                    status = "Online" if current_time - info['last_seen'] <= RECENT_TIMEOUT else "Away"
                    online_users.append(f"{info['username']} ({status})")
        return online_users

# Chat Initiator
class ChatInitiator:
    def __init__(self, peer_discovery):
        self.peer_discovery = peer_discovery

    def start(self):
        while True:
            choice = input("Enter 'Users' to view online users, 'Chat' to initiate chat, or 'History' to view chat history: ")
            if choice.lower() == 'users':
                self.show_online_users()
            elif choice.lower() == 'chat':
                self.initiate_chat()
            elif choice.lower() == 'history':
                self.show_chat_history()

    def show_online_users(self):
        users = self.peer_discovery.get_online_users()
        print("Online users:")
        for user in users:
            print(user)

    def initiate_chat(self):
        username = input("Enter the username to chat with: ")
        secure = input("Do you want to chat securely? (yes/no): ").lower() == 'yes'
        peer_ip = self.get_ip_by_username(username)
        if not peer_ip:
            print(f"No online user found with username: {username}")
            return
        if secure:
            self.secure_chat(peer_ip, username)
        else:
            self.unsecure_chat(peer_ip, username)

    def secure_chat(self, peer_ip, username):
        private_key, public_key = generate_dh_key_pair()
        public_key_bytes = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((peer_ip, CHAT_PORT))
                s.sendall(json.dumps({"key": public_key_bytes.hex()}).encode('utf-8'))
                data = s.recv(1024)
                response = json.loads(data.decode('utf-8'))
                peer_public_key_bytes = bytes.fromhex(response.get("key"))
                shared_key = derive_shared_key(private_key, peer_public_key_bytes)
                symmetric_key = derive_symmetric_key(shared_key)
                print("Secure key exchange successful")
                self.chat(peer_ip, username, secure=True, symmetric_key=symmetric_key)
        except Exception as e:
            print(f"Error during key exchange: {e}")

    def unsecure_chat(self, peer_ip, username):
        self.chat(peer_ip, username, secure=False)

    def chat(self, peer_ip, username, secure, symmetric_key=None):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((peer_ip, CHAT_PORT))
                while True:
                    message = input("Enter your message: ")
                    if secure:
                        encrypted_message = encrypt_message(message, symmetric_key)
                        s.sendall(json.dumps({"encrypted message": encrypted_message}).encode('utf-8'))
                    else:
                        s.sendall(json.dumps({"unencrypted message": message}).encode('utf-8'))
                    self.log_message(username, message, sent=True)
        except Exception as e:
            print(f"Error during chat: {e}")

    def get_ip_by_username(self, username):
        with self.peer_discovery.lock:
            for ip, info in self.peer_discovery.peers.items():
                if info['username'] == username:
                    return ip
        return None

    def log_message(self, username, message, sent):
        log_entry = {
            "timestamp": current_time(),
            "username": username,
            "message": message,
            "direction": "SENT" if sent else "RECEIVED"
        }
        with open("chat_log.txt", "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")

    def show_chat_history(self):
        if os.path.exists("chat_log.txt"):
            with open("chat_log.txt", "r") as log_file:
                logs = log_file.readlines()
                for log in logs:
                    entry = json.loads(log)
                    print(f"{entry['timestamp']} - {entry['username']} ({entry['direction']}): {entry['message']}")
        else:
            print("No chat history found")

# Chat Responder
class ChatResponder(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', CHAT_PORT))
            s.listen()
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_connection, args=(conn, addr)).start()

    def handle_connection(self, conn, addr):
        private_key, public_key = generate_dh_key_pair()
        public_key_bytes = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        with conn:
            data = conn.recv(1024)
            message = json.loads(data.decode('utf-8'))
            if "key" in message:
                peer_public_key_bytes = bytes.fromhex(message["key"])
                shared_key = derive_shared_key(private_key, peer_public_key_bytes)
                symmetric_key = derive_symmetric_key(shared_key)
                conn.sendall(json.dumps({"key": public_key_bytes.hex()}).encode('utf-8'))
                print(f"Secure chat key exchange with {addr[0]}")
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                message = json.loads(data.decode('utf-8'))
                if "encrypted message" in message:
                    decrypted_message = decrypt_message(message["encrypted message"], symmetric_key)
                    print(f"Received encrypted message from {addr[0]}: {decrypted_message}")
                    self.log_message(addr[0], decrypted_message, sent=False)
                elif "unencrypted message" in message:
                    print(f"Received message from {addr[0]}: {message['unencrypted message']}")
                    self.log_message(addr[0], message["unencrypted message"], sent=False)

    def log_message(self, ip, message, sent):
        log_entry = {
            "timestamp": current_time(),
            "username": ip,
            "message": message,
            "direction": "SENT" if sent else "RECEIVED"
        }
        with open("chat_log.txt", "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")

# Main script
if __name__ == "__main__":
    username = input("Enter your username: ")
    
    service_announcer = ServiceAnnouncer(username)
    service_announcer.start()
    
    peer_discovery = PeerDiscovery()
    peer_discovery.start()
    
    chat_responder = ChatResponder()
    chat_responder.start()
    
    chat_initiator = ChatInitiator(peer_discovery)
    chat_initiator.start()
