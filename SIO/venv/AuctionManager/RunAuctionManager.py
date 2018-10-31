import socket
import sys
import base64
from venv.APP.App import *

def createAuction():
    message = "Create Auction"
    message = base64.b64encode(message.encode("utf-8"))
    server_address = AR_ADDRESS

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Send data
        print('sending {!r}'.format(message))
        sent = sock.sendto(message, server_address)

        # Receive response
        print('waiting to receive')
        data, server = sock.recvfrom(4096)
        print('received {!r}'.format(data))

    finally:
        print('closing socket')
        sock.close()








# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the port
print('starting up on {} port {}'.format(*AM_ADDRESS))
sock.bind(AM_ADDRESS)

while True:
    print('\nwaiting to receive message')
    data, address = sock.recvfrom(4096)
    print(base64.b64decode(data))
    print('received {} bytes from {}'.format(
        len(data), address))
    print(data)
    if(base64.b64decode(data).decode('utf-8') == "createAuction"):
        createAuction();
    if data:
        sent = sock.sendto(data, address)
        print('sent {} bytes back to {}'.format(
            sent, address))



