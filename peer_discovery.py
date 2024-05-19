import socket
import json
from datetime import datetime, timedelta

BROADCAST_PORT = 6000

class Peer:
    def __init__(self, username, ip, last_seen):
        self.username = username
        self.ip = ip
        self.last_seen = last_seen
        self.status = "Online"

class PeerDiscovery:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', BROADCAST_PORT))
        self.peers = {}

    def listen(self):
        while True:
            data, addr = self.sock.recvfrom(1024)
            try:
                message = json.loads(data.decode())
                username = message.get("username")
                if username:
                    ip = addr[0]
                    current_time = datetime.now()
                    new_status = "Online"
                    
                    if ip in self.peers:
                        peer = self.peers[ip]
                        peer.last_seen = current_time

                        # Update user if needed
                        if peer.username != username:
                            peer.username = username

                        if peer.status != new_status:
                            peer.status = new_status
                            print(f"{peer.username} is online")
                    else:
                        self.peers[ip] = Peer(username, ip, current_time)
                        print(f"{username} is online")
            except json.JSONDecodeError:
                continue

    def get_username_from_ip(self, ip):
        peer = self.peers.get(ip)
        if peer:
            return peer.username
        return None

    def get_active_peers(self):
        active_peers = {}
        current_time = datetime.now()
        for ip, peer in self.peers.items():
            last_seen_delta = current_time - peer.last_seen
            if last_seen_delta < timedelta(minutes=15):
                new_status = "Online" if last_seen_delta < timedelta(seconds=10) else "Away"
                if peer.status != new_status:
                    peer.status = new_status
                    status_message = "online" if new_status == "Online" else "away"
                    print(f"{peer.username} is {status_message}")
                active_peers[ip] = (peer.username, new_status)
        return active_peers
