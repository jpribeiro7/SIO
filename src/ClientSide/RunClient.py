from ClientSide.ClientActions import *
from App.app import *
import socket
import base64
import json
import pickle

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
        elif option == "2":
            msg, address = self.client_actions.list_auctions(self.current_client)
        elif option == "3":
            msg, address = self.client_actions.make_bid(self.current_client)




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
        data, server = sock.recvfrom(SOCKET_BYTES)

        decoded_message = base64.b64decode(data)
        message = json.loads(decoded_message, strict = False)

        if message['type'] != 'success':
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

        if message['type'] != 'success':
            print('No connection established')
            sys.exit(0)



    # Menu to be shown after the login
    def menu(self):

        option = "-1"

        while option != "4":
            # Create a UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            print('\n')
            print("1- Create a Auction")
            print("2- List all auctions")
            print("3- Bid")
            print("4- Leave")
            option = input("> ")
            message, address = self.switch(option)
            print(message)
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
                    if message['type'] != 'success':
                        if option == "1":
                            print('No Auction created')
                        if option == "3":
                            print("Couldn't make bid")
                    if message['type'] == 'list_auctions':
                        message_list = unpadd_data(message['list'], self.current_client.session_key_repository)
                        print("message_list, ",message_list)
                        auction_list = pickle.loads(message_list)
                        print("auction_list, ",auction_list)
                        for auction in auction_list:
                            print(auction)




            finally:
                sock.close()




r = RunClient()
r.login_menu()
r.menu()