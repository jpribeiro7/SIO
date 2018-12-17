from ClientSide.ClientActions import *
from App import App
import socket
import base64
import json


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
            address = App.AM_ADDRESS

        elif op == 2:
            msg = self.actions.create_auction(self.client)
            address = App.AM_ADDRESS

        elif op == 3:
            msg = self.actions.terminateAuction(self.client,"auction")
            address = App.AM_ADDRESS

        elif op == 4:
            val = input("introduce val: ")
            msg = self.actions.setBidValidation()
            address = App.AM_ADDRESS

        elif op == 5:
            val = input("introduce val: ")
            msg = self.actions.bid(self.client,"auction",val)
            address = App.AR_ADDRESS

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
                data, server = sock.recvfrom(16384)
                print('received {!r}'.format(data))

                #try:
                # Verify if it recieved the server public key and saves it
                message_decoded = json.loads(base64.b64decode(data), strict=False)
                public_key_server_pem = self.actions.decrypt_function_complete(self.client.session_key, message_decoded["server"], self.client)
                public_file = open(os.getcwd()+"/" + self.client.username + "/server_key.pem", "wb+")
                public_file.write(public_key_server_pem)
                self.client.server_public_key = RSAKeyGen().load_server_key(os.getcwd()+"/" + self.client.username)
                #except:
                    #print(b"")

            finally:
                print('closing socket')
                sock.close()


#Running Client
c = RunClient()
c.menu()