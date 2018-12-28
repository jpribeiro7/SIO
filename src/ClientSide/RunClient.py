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

    def switch(self, op, sock):

        address=()
        msg = ""

        if op == 1:
            # In the login, The client sends the public key to the server
            msg, self.client = self.actions.login()
            address = App.AM_ADDRESS

        elif op == 2:
            if self.client is None:
                print("Not logged in \n")
                self.menu()
            else:
                # Creates an Auction
                # TODO: Put the CC and PublicKey in the Auction
                msg, self.client = self.actions.create_auction(self.client)
                address = App.AM_ADDRESS

        elif op == 3:
            if self.client is None:
                print("Not logged in \n")
                self.menu()
            else:
                msg = self.actions.terminateAuction(self.client, "auction")
                address = App.AM_ADDRESS

        elif op == 4:
            if self.client is None:
                print("Not logged in \n")
                self.menu()
            else:
                val = input("introduce val: ")
                msg = self.actions.setBidValidation()
                address = App.AM_ADDRESS

        elif op == 5:
            if self.client is None:
                print("Not logged in \n")
                self.menu()
            else:
                val = input("introduce val: ")
                msg = self.actions.bid(self.client,"auction",val)
                address = App.AR_ADDRESS
        elif op == 6:
            if self.client is None:
                print("Not logged in \n")
                self.menu()
            else:
                msg = self.actions.list_auction(self.client, sock)
                address = App.AR_ADDRESS

        return msg, address

    def menu(self):
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        op = -1

        while op != 7:
            # Since the socket is always closed create a new one
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if self.client is None:
                print("1 - Login")
            else:
                print("2 - Create an auction")
                if self.client.num_auctions != 0:
                    print("3 - Terminate an auction")
                print("4 - Create bid validation")
                print("5 - Bid")
                print("6 - List Auctions")
                print("7 - Leave")
            op = input("Choose and option: ")
            if int(op) == 7:
                break

            message, server_address = self.switch(int(op), sock)

            # verify if its a byte like message
            # A message like this comes from Login, Auction etc (Requires padding and encryption)
            # The only one, at the moment, that needs b64 is the Session key implement.
            if not isinstance(message, (bytes, bytearray)):
                message = base64.b64encode(message.encode("utf-8"))

            try:
                if message != b"":
                    # Send data
                    print('sending {!r}'.format(message))
                    sent = sock.sendto(message, server_address)
                    # Receive response
                    print('waiting to receive')
                    data, server = sock.recvfrom(16384)
                    print('received {!r}'.format(base64.b64decode(data)))

                    # This will verify if it is a success or not message
                    success_message = json.loads(base64.b64decode(data), strict=False)
                    if "success" in success_message:
                        # This means that the message that we recieved is a success or error one
                        if success_message["success"] == "error":
                            # There was an error
                            print("There was an error")
                        else:
                            print("Success")


                    try:
                        # Verify if it received the server public key and saves it
                        message_decoded = json.loads(base64.b64decode(data), strict=False)

                        print(message_decoded)
                        public_key_server_pem = self.actions.decrypt_function_complete(self.client.session_key,
                                                                                       message_decoded,
                                                                                       self.client, "server")

                        # Save to file
                        public_file = open(os.getcwd()+"/" + self.client.username + "/server_key.pem", "wb+")
                        public_file.write(public_key_server_pem)
                        public_file.close()
                        # Load it from the file
                        self.client.server_public_key = RSAKeyGen().load_server_key(os.getcwd()+"/" + self.client.username)
                    except:
                       pass
            finally:
                print('closing socket')
                sock.close()


# Running Client
c = RunClient()
c.menu()
