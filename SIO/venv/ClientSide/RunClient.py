from locale import format

from venv.ClientSide.ClientActions import *
from venv.ClientSide.Client import *
from venv.APP.App import *
import socket
import base64
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import codecs
import pickle

#This class is responsible for the comunication between the system and the client

def switch(op):
    c = Client("username")
    actions = ClientActions()
    address=()
    msg = ""
    if op == 1:
        msg = actions.Login(c)
    elif op == 2:
        msg = actions.createAuction(c)
        address = AM_ADDRESS
    elif op == 3:
        msg = actions.terminateAuction(c,"auction")
        address = AM_ADDRESS
    elif op == 4:
        val = input("introduce val: ")
        msg = actions.setBidValidation()
        address = AM_ADDRESS
    elif op == 5:
        val = input("introduce val: ")
        msg = actions.bid(c,"auction",val)
        address = AR_ADDRESS

    return (msg, address)


#initializes the session key
#Crying in python
def sessionKeyInit():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #Our parameters
    parameters = dh.generate_parameters(generator=5, key_size=512,backend = default_backend())

    #Our private key and public key
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    #needs the server parameters, send our parameters, for now our parameters are the ones to be done
    message = codecs.encode(pickle.dumps(parameters.parameter_bytes(encoding=Encoding.PEM,format=ParameterFormat.PKCS3)),"base64" ).decode()

    #message construction
    json_message = "{ " + "\n"
    json_message += "\"type\" : \"session\","+ "\n"
    json_message += "\"data\" : \"" + message + "\", \n"
    json_message += "\"pk\" : \"" + public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8') + "\""
    json_message += "}"

    print(json_message)
    try:
        #send response
        sent = sock.sendto(base64.b64encode(json_message.encode('utf-8')), AM_ADDRESS)

        # Receive response
        data, server = sock.recvfrom(4096)
        #derivate the key
        peer_public_key_bytes = base64.b64decode(data)
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, default_backend())
        shared_key = private_key.exchange(peer_public_key)

        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data',
                           backend=default_backend()).derive(shared_key)

    finally:
        sock.close()



def menu():
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    op = -1
    sessionKeyInit()
    while(op != 6):
        print("1 - Login")
        print("2 - Create an auction")
        print("3 - Terminate an auction")
        print("4 - Create bid validation")
        print("5 - Bid")
        print("6 - Leave")
        op = input("Choose and option: ")
        if int(op) == 6:
            break

        message, server_address = switch(int(op))

        message = base64.b64encode(message.encode("utf-8"))

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

menu()