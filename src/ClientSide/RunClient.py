from ClientSide.ClientActions import *
from App.app import *
import socket
import base64
import json


class RunClient():

    def __init__(self):
        self.current_client = None
        self.client_actions = ClientActions()

    # Switch method
    def switch(self, option, array_options = None):
        msg = ""
        address = ""

        if option == "1":
            # Creates a auction
            msg, address = self.client_actions.create_auction(self.current_client)
        else:
            pass

        message_encoded = base64.b64encode(msg.encode("utf-8"))
        return message_encoded, address

    # Initial menu
    def login_menu(self):
        print("1- Login")
        print("2- Exit")

        option = input("> ")

        if option == "1":
            self.current_client = self.client_actions.login()
            self.build_trust()
        else:
            sys.exit(0)

    # Builds the trust with the servers
    # This means that the server recieves our signatures and verifies them
    # If we are invalid then the program does not continue and the server does not accept our connection
    def build_trust(self):
        # build trust for manager
        msg = self.client_actions.trust_server(self.current_client,address=AM_ADDRESS)
        msg_encoded = base64.b64encode(msg.encode('utf-8'))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg_encoded, AM_ADDRESS)
        data,server = sock.recvfrom(SOCKET_BYTES)

        decoded_message = base64.b64decode(data)
        message = json.loads(decoded_message, strict = False)

        if message['response'] != 'success':
            print('No connection established')
            sys.exit(0)


        # build trust for repos
        msg = self.client_actions.trust_server(self.current_client,address=AR_ADDRESS)
        msg_encoded = base64.b64encode(msg.encode('utf-8'))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg_encoded, AR_ADDRESS)
        # print("SENT")
        data,server = sock.recvfrom(SOCKET_BYTES)

        decoded_message = base64.b64decode(data)
        message = json.loads(decoded_message, strict = False)

        if message['response'] != 'success':
            print('No connection established')
            sys.exit(0)

        self.menu()

    # Menu to be shown after the login
    def menu(self):

        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        option = "-1"

        while option != "3":
            print('\n')
            print("1- Create a Auction")
            print("2- List all auctions")
            print("3- Leave")
            option = input("> ")
            message, address = self.switch(option)

            try:
                # Doesn't send any empty message
                if message != b"":
                    sock.sendto(message, address)
                    print("Waiting for a response")
                    data, server = sock.recvfrom(SOCKET_BYTES)
                    # The client should always recieve a confirmation from the server
                    decoded_message = base64.b64decode(data)
                    message = json.loads(decoded_message, strict = False)

                    # Verifies the response
                    if message['response'] != 'success':
                        if option == "1":
                            print('No Auction created')

            finally:
                sock.close()




r = RunClient()
r.login_menu()