import socket
import threading
import json
import time
from datetime import datetime, timedelta
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


BROADCAST_IP = '192.168.1.255'
BROADCAST_PORT = 6000
TCP_PORT = 6001
USERNAME = None
PEER_DICT = {}
PEER_TIMEOUT = 900
AWAY_TIMEOUT = 10
LOCK = threading.Lock()

# Service Announcer
def service_announcer():
    global USERNAME
    USERNAME = input("Enter your username: ")
    msg = json.dumps({"username": USERNAME}).encode('utf-8')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            s.sendto(msg, (BROADCAST_IP, BROADCAST_PORT))
            time.sleep(8)

# Peer Discovery
def peer_discovery():
    global PEER_DICT
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', BROADCAST_PORT))
        while True:
            data, addr = s.recvfrom(1024)
            msg = json.loads(data.decode('utf-8'))
            with LOCK:
                if addr[0] in PEER_DICT:
                    PEER_DICT[addr[0]]['last_seen'] = datetime.now()
                else:
                    PEER_DICT[addr[0]] = {'username': msg['username'], 'last_seen': datetime.now()}
                    print(f"{msg['username']} is online")

# Chat Initiator
def chat_initiator():
    global PEER_DICT
    while True:
        action = input("Enter action (Users/Chat/History): ").strip().lower()
        if action == 'users':
            with LOCK:
                now = datetime.now()
                for ip, info in PEER_DICT.items():
                    status = "Online" if (now - info['last_seen']).seconds <= AWAY_TIMEOUT else "Away"
                    print(f"{info['username']} ({status})")
        elif action == 'chat':
            peer_username = input("Enter username to chat with: ").strip()
            secure_chat = input("Secure chat? (yes/no): ").strip().lower() == 'yes'
            with LOCK:
                peer_ip = None
                for ip, info in PEER_DICT.items():
                    if info['username'] == peer_username:
                        peer_ip = ip
                        break
                if peer_ip:
                    initiate_chat(peer_ip, secure_chat)
                else:
                    print("User not found")
        elif action == 'history':
            view_chat_history()


def initiate_chat(peer_ip, secure_chat):
    global USERNAME
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((peer_ip, TCP_PORT))
            if secure_chat:
                key = dh_key_exchange(s)
            else:
                key = None
            while True:
                message = input("Enter message: ")
                if key:
                    encrypted_message = encrypt_message(key, message)
                    s.sendall(json.dumps({"encrypted message": encrypted_message}).encode('utf-8'))
                else:
                    s.sendall(json.dumps({"unencrypted message": message}).encode('utf-8'))
                log_message(peer_ip, "SENT", message)
        except Exception as e:
            print(f"Error: {e}")

def dh_key_exchange(s):
    parameters = dh.generate_parameters(generator=2, key_size=512)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    s.sendall(json.dumps({"key": public_key.decode('utf-8')}).encode('utf-8'))
    response = json.loads(s.recv(1024).decode('utf-8'))
    peer_public_key = response['key'].encode('utf-8')
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def encrypt_message(key, message):
    # Implement encryption using the derived key
    pass

def log_message(peer_ip, direction, message):
    global USERNAME
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "username": USERNAME,
        "peer_ip": peer_ip,
        "direction": direction,
        "message": message
    }
    with open("chat_log.txt", "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

def view_chat_history():
    if os.path.exists("chat_log.txt"):
        with open("chat_log.txt", "r") as log_file:
            for line in log_file:
                entry = json.loads(line)
                print(f"{entry['timestamp']} - {entry['username']} ({entry['direction']}): {entry['message']}")
    else:
        print("No chat history found")

# Chat Responder
def chat_responder():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', TCP_PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_chat, args=(conn, addr)).start()

def handle_chat(conn, addr):
    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            msg = json.loads(data.decode('utf-8'))
            if "key" in msg:
                key_exchange_response(conn, msg["key"])
            elif "encrypted message" in msg:
                message = decrypt_message(msg["encrypted message"])
                print(f"Encrypted message from {addr[0]}: {message}")
                log_message(addr[0], "RECEIVED", message)
            elif "unencrypted message" in msg:
                message = msg["unencrypted message"]
                print(f"Message from {addr[0]}: {message}")
                log_message(addr[0], "RECEIVED", message)

def key_exchange_response(conn, peer_public_key):
    parameters = dh.generate_parameters(generator=2, key_size=512)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    conn.sendall(json.dumps({"key": public_key.decode('utf-8')}).encode('utf-8'))
    shared_key = private_key.exchange(peer_public_key.encode('utf-8'))
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def decrypt_message(encrypted_message):
    # Implement decryption using the derived key
    pass

if __name__ == "__main__":
    threading.Thread(target=service_announcer).start()
    threading.Thread(target=peer_discovery).start()
    threading.Thread(target=chat_initiator).start()
    threading.Thread(target=chat_responder).start()
