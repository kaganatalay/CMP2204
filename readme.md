# Peer-to-Peer Chat Application

This program is a peer-to-peer chat application that supports both secure and unsecure messaging. The application consists of several components: `ServiceAnnouncer`, `PeerDiscovery`, `ChatInitiator`, and `ChatResponder`. The `ServiceAnnouncer` broadcasts the user's presence to the network, while the `PeerDiscovery` component listens for these broadcasts to maintain a list of active peers. Users can start chats using the `ChatInitiator`, which allows them to choose a peer to communicate with and select whether to use secure messaging. For secure messaging, a Diffie-Hellman key exchange is implemented to generate a shared secret key, which is then used to encrypt messages with AES. The `ChatResponder` handles incoming chat requests, performing key exchange if necessary and decrypting messages for secure communication. The application logs all messages to a chat history file for later review.

## How to Run the Application

**Running the Application:**

- Update the `BROADCAST_IP` in the `ServiceAnnouncer` to the correct broadcast address for your network.
- Entry point is the `main.py` file.
- Run `python main.py` on a terminal window to start the application.

## Known Limitations

1. **Non-Unicode Characters:**

   - The application crashes when it encounters non-Unicode characters such as ü, ç, ş, etc. Ensure that all messages contain only Unicode characters to avoid crashes.

2. **Non-random public parameters**
   - The application's public parameters are pre-defined prime integers, making it less secure.
