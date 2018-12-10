from venv.ClientSide.ClientActions import *
from venv.ClientSide.Client import *
from venv.APP.App import *
import socket
import base64


# This class is responsible for the communication between the system and the client

def switch(op):
    c = Client("username")
    c.initialize_session_key()
    c.set_keys()
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

    return msg, address

def menu():
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    op = -1

    while op != 6:
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