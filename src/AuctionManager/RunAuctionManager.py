import socket
import base64
from AuctionManager.AuctionManagerActions import *
from App.App import *
import json

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Create Auction Actions
actions = AuctionManagerActions(sock)


# Bind the socket to the port
print('starting up on {} port {}'.format(*AM_ADDRESS))
sock.bind(AM_ADDRESS)

while True:
    print('\nwaiting to receive message')
    data, address = sock.recvfrom(16384)

    # Data from session comes as base64 and as json
    decoded_data = base64.b64decode(data)
    message_json = json.loads(decoded_data, strict=False)

    print('received {} bytes from {}'.format(
        len(data), address))

    if message_json["type"] == "create_auction":
        actions.create_auction(address, message_json)
    elif message_json["type"] == "session":
        actions.create_session_key(message_json, address)
    elif message_json["type"] == "login":
        actions.login_actions(address, message_json)

    if data:
        sent = sock.sendto(data, address)
        print('sent {} bytes back to {}'.format(
            sent, address))