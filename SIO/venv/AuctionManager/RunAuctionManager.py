import socket
import sys
import base64

from venv.APP.App import *
import json
import codecs
import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

#Function to create a auction
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

#Function to create a session key
def createSessionKey(message_json, address):

    #decode the data
    parameters = pickle.loads(codecs.decode(message_json["data"].encode(), "base64"))
    par = load_pem_parameters(parameters, backend=default_backend())

    #Generate our public/private key
    private_key = par.generate_private_key()
    public_key = private_key.public_key()

    #Get the public key from the user
    peer_public_key_bytes = message_json["pk"].encode()
    peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes,default_backend())
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',
                       backend=default_backend()).derive(shared_key)

    #Now send our public key to the client
    message = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

    sent = sock.sendto(base64.b64encode(message.encode('utf-8')), address)




# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the port
print('starting up on {} port {}'.format(*AM_ADDRESS))
sock.bind(AM_ADDRESS)

while True:
    print('\nwaiting to receive message')
    data, address = sock.recvfrom(4096)
    print(base64.b64decode(data))

    decoded_data = base64.b64decode(data)

    print('received {} bytes from {}'.format(
        len(data), address))

    message_json = json.loads(decoded_data,strict=False)


    if message_json["type"] == "createAuction":
        createAuction()
    elif message_json["type"] == "session":
        createSessionKey(message_json,address)



    if data:
        sent = sock.sendto(data, address)
        print('sent {} bytes back to {}'.format(
            sent, address))



