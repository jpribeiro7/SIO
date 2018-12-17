import socket
import base64
from App.App import *

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the port
print('starting up on {} port {}'.format(*AR_ADDRESS))
sock.bind(AR_ADDRESS)

while True:
    print('\nwaiting to receive message')
    data, address = sock.recvfrom(4096)
    print(base64.b64decode(data))
    print('received {} bytes from {}'.format(
        len(data), address))
    print(data)

    if data:
        sent = sock.sendto(data, address)
        print('sent {} bytes back to {}'.format(
            sent, address))

