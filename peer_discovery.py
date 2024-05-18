import socket
import json
from datetime import datetime, timedelta

BROADCAST_PORT = 6000

class Peer:
    def __init__(self, username, ip, last_seen):
        self.username = username
        self.ip = ip
        self.last_seen = last_seen

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
                    self.peers[addr[0]] = Peer(username, addr[0], datetime.now())
                    print(f"{username} is online")
            except json.JSONDecodeError:
                continue

    def get_active_peers(self):
        active_peers = {}
        for ip, peer in self.peers.items():
            if datetime.now() - peer.last_seen < timedelta(minutes=15):
                status = "Online" if datetime.now() - peer.last_seen < timedelta(seconds=10) else "Away"
                active_peers[ip] = (peer.username, status)
        return active_peers
