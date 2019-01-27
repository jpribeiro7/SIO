import socket
import base64
from AuctionManager.AuctionManagerActions import *
import App.app as utils_app
import json

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Create Auction Actions
actions = AuctionManagerAuctions(sock)

# Bind the socket to the port
print('starting up on {} port {}'.format(*utils_app.AM_ADDRESS))
sock.bind(utils_app.AM_ADDRESS)

while True:

    print('\nwaiting to receive message')
    data, address = sock.recvfrom(utils_app.SOCKET_BYTES)

    # Data from session comes as base64 and as json
    decoded_data = base64.b64decode(data)
    print(decoded_data)
    message_json = json.loads(decoded_data, strict=False)

    print('received {} bytes from {}'.format(
        len(data), address))

    if message_json["type"] == "create_auction":
        data = actions.create_auction(message_json, address)
    elif message_json["type"] == "session_key":
        data = actions.create_session_key_user_server(message_json)
    elif message_json["type"] == "build_trust":
        data = actions.build_trust(message_json)


    if data:
        sent = sock.sendto(data, address)
        print('sent {} bytes back to {}'.format(
            sent, address))
