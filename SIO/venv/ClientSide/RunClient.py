from venv.ClientSide.ClientActions import *
from venv.ClientSide.Client import *
from venv.APP.App import *
import socket
import base64


# This class is responsible for the communication between the system and the client
class RunClient:

    def __init__(self):
        self.client = None
        self.actions = ClientActions()

    def switch(self, op):

        address=()
        msg = ""

        if op == 1:
            # In the login, The client sends the public key to the server
            # ( the server may be changed to AR_ADDRESS?!) TODO
            msg, self.client = self.actions.Login()
            address = AM_ADDRESS

        elif op == 2:
            msg = self.actions.createAuction(self.client)
            address = AM_ADDRESS

        elif op == 3:
            msg = self.actions.terminateAuction(self.client,"auction")
            address = AM_ADDRESS

        elif op == 4:
            val = input("introduce val: ")
            msg = self.actions.setBidValidation()
            address = AM_ADDRESS

        elif op == 5:
            val = input("introduce val: ")
            msg = self.actions.bid(self.client,"auction",val)
            address = AR_ADDRESS

        return msg, address

    def menu(self):
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        op = -1

        while op != 6:
            # Since the socket is always closed create a new one
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            print("1 - Login")
            print("2 - Create an auction")
            print("3 - Terminate an auction")
            print("4 - Create bid validation")
            print("5 - Bid")
            print("6 - Leave")
            op = input("Choose and option: ")
            if int(op) == 6:
                break

            message, server_address = self.switch(int(op))

            # verify if its a byte like message
            # A message like this comes from Login, Auction etc (Requires padding and encryption)
            # The only one, at the moment, that needs b64 is the Session key implement.
            if not isinstance(message, (bytes, bytearray)):
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


#Running Client
c = RunClient()
c.menu()