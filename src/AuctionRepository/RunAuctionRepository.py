import socket
import base64
from App.App import *
import json
from AssymetricKeys.RSAKeyGen import RSAKeyGen
from AuctionRepository.AuctionRepositoryActions import AuctionRepositoryActions
# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the port
print('starting up on {} port {}'.format(*AR_ADDRESS))
sock.bind(AR_ADDRESS)
actions = AuctionRepositoryActions(sock)
while True:
    print('\nwaiting to receive message')
    data, address = sock.recvfrom(16384)

    # Data from session comes as base64 and as json
    decoded_data = base64.b64decode(data)
    message_json = json.loads(decoded_data, strict=False)

    if message_json["type"] == "create_auction":
        actions.create_auction(message_json, address)
    elif message_json["type"] == "session":
        actions.create_session_key(message_json, address)
    elif message_json["type"] == "session_server":
        actions.create_session_key_server(message_json, address)
