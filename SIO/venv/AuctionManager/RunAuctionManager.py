import socket
import base64
from venv.AuctionManager import AuctionManagerActions
from venv.APP.App import *
import json



# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Create Auction Actions
actions = AuctionManagerActions.AuctionManagerActions(sock)


# Bind the socket to the port
print('starting up on {} port {}'.format(*AM_ADDRESS))
sock.bind(AM_ADDRESS)

while True:
    print('\nwaiting to receive message')
    data, address = sock.recvfrom(4096)

    # This try and expect is to make sure that the data is decoded, in both cases
    # Data from session comes as base64
    # Data from the rest can't be base64 decoded
    decoded_data = base64.b64decode(data)
    message_json = json.loads(decoded_data, strict=False)

    print('received {} bytes from {}'.format(
        len(data), address))

    if message_json["type"] == "createAuction":
        actions.createAuction()
    elif message_json["type"] == "session":
        actions.createSessionKey(message_json,address)
    elif message_json["type"] == "login":
        actions.login_actions(message_json)

    if data:
        sent = sock.sendto(data, address)
        print('sent {} bytes back to {}'.format(
            sent, address))