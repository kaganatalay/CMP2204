import socket
import json
import time
import threading
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

class ChatInitiator:
    def __init__(self, peer_discovery):
        self.peer_discovery = peer_discovery
        self.running = True

    def view_users(self):
        current_time = datetime.now()
        for ip, info in self.peer_discovery.peers.items():
            last_seen = datetime.strptime(info['last_seen'], '%Y-%m-%d %H:%M:%S')
            if (current_time - last_seen) <= timedelta(seconds=DISCOVERY_TIMEOUT):
                status = "(Online)" if (current_time - last_seen).seconds <= ACTIVE_THRESHOLD else "(Away)"
                print(f"{info['username']} {status}")

    def initiate_chat(self, username):
        for ip, info in self.peer_discovery.peers.items():
            if info['username'] == username:
                threading.Thread(target=self.handle_chat, args=(ip,)).start()
                break
        else:
            print("User not found or not available.")

    def handle_chat(self, ip):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((ip, CHAT_PORT))
                while self.running:
                    message = input("You: ")
                    if message.lower() == "exit":
                        self.running = False
                        break
                    message = json.dumps({"encrypted message": message})  # Encrypt here
                    s.sendall(message.encode())
                    log_entry = f"{get_timestamp()} SENT to {ip}: {message}"
                    save_log(log_entry)
            except ConnectionRefusedError:
                print("Failed to connect to the user.")

class ChatResponder(threading.Thread):
    def __init__(self):
        super().__init__()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("", CHAT_PORT))
        self.socket.listen(1)

    def run(self):
        print("Chat responder started and listening for incoming connections...")
        while True:
            conn, addr = self.socket.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr)).start()

    def handle_client(self, conn, addr):
        with conn:
            try:
                while True:
                    message = json.loads(conn.recv(1024).decode())
                    if 'encrypted message' in message:
                        content = message['encrypted message']  # Decrypt here
                    else:
                        content = message['unencrypted message']
                    print(f"\nMessage from {addr}: {content}")
                    log_entry = f"{get_timestamp()} RECEIVED from {addr}: {content}"
                    save_log(log_entry)
            except json.JSONDecodeError:
                print("Connection closed by client.")

def main():
    username = input("Enter your username: ")
    announcer = ServiceAnnouncer(username)
    discovery = PeerDiscovery()
    responder = ChatResponder()
    initiator = ChatInitiator(discovery)

    announcer_thread = threading.Thread(target=announcer.announce_presence)
    announcer_thread.daemon = True
    announcer_thread.start()

    discovery.daemon = True
    discovery.start()

    responder.daemon = True
    responder.start()

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
            initiator.initiate_chat(username)
        elif choice == '3':
            try:
                with open('chat_history.log', 'r') as file:
                    print(file.read())
            except FileNotFoundError:
                print("Chat history is currently empty.")
        elif choice == '4':
            print("Exiting chat application.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
