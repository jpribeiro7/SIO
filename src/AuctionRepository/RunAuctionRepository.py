import socket
import base64
from App.app import *
import json
from AuctionRepository.AuctionRepositoryActions import AuctionRepositoryActions
import App.app as utils_app


# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the port
print('starting up on {} port {}'.format(*AR_ADDRESS))
sock.bind(AR_ADDRESS)
actions = AuctionRepositoryActions(sock)

while True:
    print('\nwaiting to receive message')
    data, address = sock.recvfrom(utils_app.SOCKET_BYTES)

    decoded_data = base64.b64decode(data)
    message_json = json.loads(decoded_data, strict=False)
    print(message_json)

    if message_json["type"] == "create_auction":
        data = actions.create_auction(message_json, address)
    elif message_json["type"] == "session_key":
        data = actions.create_session_key(message_json, address)
    elif message_json["type"] == "session_server":
        data = actions.create_session_key_server(message_json, address)
    elif message_json["type"] == "list_auctions":
        data = actions.list_auctions(message_json)
    elif message_json["type"] == "build_trust":
        data = actions.build_trust(message_json)

    if data != b"":
        sent = sock.sendto(data, address)
        print('sent {} bytes back to {}'.format(
                sent, address))
