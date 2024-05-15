import socket
import json
import time
import threading
import os
from datetime import datetime, timedelta

# Constants
BROADCAST_IP = '192.168.169.255'  # Replace with your broadcast IP
BROADCAST_PORT = 6000
CHAT_PORT = 6001
DISCOVERY_TIMEOUT = 900  # 15 minutes in seconds
ACTIVE_THRESHOLD = 10  # 10 seconds to be considered online

def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def save_log(entry):
    with open('chat_history.log', 'a') as file:
        file.write(f"{entry}\n")

class ServiceAnnouncer:
    def __init__(self, username):
        self.username = username
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def announce_presence(self):
        message = json.dumps({"username": self.username})
        while True:
            self.socket.sendto(message.encode(), (BROADCAST_IP, BROADCAST_PORT))
            time.sleep(8)


class PeerDiscovery(threading.Thread):
    def __init__(self):
        super().__init__()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("", BROADCAST_PORT))
        self.peers = {}

    def run(self):
        while True:
            message, addr = self.socket.recvfrom(1024)
            data = json.loads(message.decode())
            self.peers[addr[0]] = {'username': data['username'], 'last_seen': get_timestamp()}
            print(f"{data['username']} is online")



class ChatInitiator:
    def __init__(self, peer_discovery):
        self.peer_discovery = peer_discovery

    def view_users(self):
        current_time = datetime.now()
        for ip, info in self.peer_discovery.peers.items():
            last_seen = datetime.strptime(info['last_seen'], '%Y-%m-%d %H:%M:%S')
            if (current_time - last_seen) <= timedelta(seconds=DISCOVERY_TIMEOUT):
                status = "(Online)" if (current_time - last_seen).seconds <= ACTIVE_THRESHOLD else "(Away)"
                print(f"{info['username']} {status}")

    def initiate_chat(self, username, message, secure=False):
        for ip, info in self.peer_discovery.peers.items():
            if info['username'] == username:
                self.send_message(ip, message, secure)
                break

    def send_message(self, ip, message, secure):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, CHAT_PORT))
            if secure:
                # Secure chat implementation (simplified)
                message = json.dumps({"encrypted message": message})  # Encrypt here
            else:
                message = json.dumps({"unencrypted message": message})
            s.sendall(message.encode())
            log_entry = f"{get_timestamp()} SENT to {ip}: {message}"
            save_log(log_entry)


class ChatResponder(threading.Thread):
    def __init__(self):
        super().__init__()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("", CHAT_PORT))
        self.socket.listen(1)

    def run(self):
        while True:
            conn, addr = self.socket.accept()
            with conn:
                message = json.loads(conn.recv(1024).decode())
                if 'key' in message:
                    # Handle key exchange here
                    pass
                elif 'encrypted message' in message:
                    # Decrypt message here
                    content = message['encrypted message']
                else:
                    content = message['unencrypted message']
                print(f"Message from {addr}: {content}")
                log_entry = f"{get_timestamp()} RECEIVED from {addr}: {content}"
                save_log(log_entry)

def main():
    username = input("Enter your username: ")
    announcer = ServiceAnnouncer(username)
    discovery = PeerDiscovery()
    responder = ChatResponder()
    initiator = ChatInitiator(discovery)

    # Start background processes
    threading.Thread(target=announcer.announce_presence).start()
    discovery.run()
    responder.run()

    # User interaction loop
    while True:
        print("\nMenu:")
        print("1 - View Online Users")
        print("2 - Start a Chat")
        print("3 - View Chat History")
        print("4 - Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            initiator.view_users()
        elif choice == '2':
            username = input("Enter the username to chat with: ")
            message = input("Enter your message: ")
            secure = input("Secure chat? (yes/no): ").lower() == 'yes'
            initiator.initiate_chat(username, message, secure)
        elif choice == '3':
            with open('chat_history.log', 'r') as file:
                print(file.read())
        elif choice == '4':
            print("Exiting chat application.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()


