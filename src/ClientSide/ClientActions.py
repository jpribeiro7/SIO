from ClientSide.Client import Client
from App.utilities import *
from App.app import *
from RSAKeyGenerator.RSAKGen import RSAKGen
import sys
from CitizenCard.CitizenCard import CitizenCard


class ClientActions:
    _client_path = ""

    # Logs in with the servers
    def login(self):
        rsa_gen = RSAKGen()
        print("\n")
        username = input("Username: ")
        password = input("password: ")

        current_client = Client(username)
        current_client.password = password
        self._client_path = os.getcwd() + "/" + username

        # Check existence
        if check_directory(self._client_path):
            try:
                keys = rsa_gen.load_key_clients(self._client_path, password)
            except ValueError:
                print("\nPassword Entered was incorrect!")
                sys.exit(0)

            # Private key
            current_client.private_key = keys[0]
            current_client.public_key = keys[1]
            current_client.auction_private_key = keys[2]
            current_client.auction_public_key = keys[3]

            current_client.server_public_key_manager = rsa_gen.\
                load_public_key(self._client_path,"server_manager.pem")

            current_client.server_public_key_repository = rsa_gen.\
                load_public_key(self._client_path,"server_repository.pem")

        else:
            os.mkdir(self._client_path)
            keys = rsa_gen.generate_key_pair_client()
            # Private key
            current_client.private_key = keys[0]
            current_client.public_key = keys[1]
            current_client.auction_private_key = keys[2]
            current_client.auction_public_key = keys[3]
            rsa_gen.save_keys_client(self._client_path, password)

        # builds DH
        current_client.initialize_session_key(AM_ADDRESS)
        current_client.initialize_session_key(AR_ADDRESS)

        current_client.citizenCard = CitizenCard()

        return current_client

    # Sends the message to the server to begin the trust
    def trust_server(self,client, address=None):

        # loads citizen card
        rsa = RSAKGen()
        certificate = client.citizenCard.load_authentication_certificate()
        # print(client.username)
        digital_signature = client.citizenCard.digital_signature(client.username.encode('utf-8'))
        rsa_sign = rsa.sign_message(client.username.encode('utf-8'), client.private_key)
        # print(rsa.sign_message(client.username.encode('utf-8'), client.private_key) )
        # builds trust message
        json_message = "{ " + "\n"
        json_message += "\"type\" : \"build_trust\"," + "\n"
        json_message += "\"public\" : \"" + encrypt_message_sk(get_public_key_bytes(client.public_key),
                                                               client, address=address) + "\", \n"
        json_message += "\"rsa_signature\" : \"" + encrypt_message_sk(rsa_sign,client,address=address) + "\", \n"
        json_message += "\"username\" : \"" + client.username + "\", \n"
        json_message += "\"certificate\" : \"" + encrypt_message_sk(certificate, client,address=address) + "\", \n"
        json_message += "\"digital_signature\" : \"" + encrypt_message_sk(digital_signature, client,address=address) + "\""
        json_message += "\n" + "}"
        # print(digital_signature)

        return json_message

    # This will create the auction with the server
    # The message is organized in this way
    # type : STRING, username: STRING, message= json with the attributes
    def create_auction(self, client):
        message = "{ \"type\" : \"create_auction\" ,\n"
        message += "\"username\" : \"" + client.username + "\",\n"

        # Now ask for all the details
        print("\n")
        # Verify the fields

        # Auction needs a name
        auction_name = input("Auction name: ")
        while auction_name == "":
            auction_name = input("Auction name: ")

        # If there is no description then put it as None
        auction_description = input("Auction description: ")
        if auction_description == "":
            auction_description = "None"

        # If no given minimum the put it at zero $
        auction_min_number_bids = input("Minimum price bid: ")
        if auction_min_number_bids == "":
            auction_min_number_bids = "0"

        # There needs to be a limit
        auction_time = input("Auction time limit (Hrs): ")
        while int(auction_time) < 0:
            auction_time = input("Auction time limit (Hrs): ")

        # If there is no max bids then 0
        auction_max_number_bids = input("Auction maximum number of bids: ")
        if auction_max_number_bids == "":
            auction_max_number_bids = "0"

        # If there is no given names then put it as None
        auction_allowed_bidders = input("Auction allowed bidders (separate with [,]): ")
        if auction_allowed_bidders == "":
            auction_allowed_bidders = "None"

        # If there is no threshold then 0
        auction_threshold = input("Auction threshold (min,max): ")
        if auction_threshold == "":
            auction_threshold = "0"

        # There must have a type
        auction_type = input("Auction type ((B)lind or (N)ormal): ")
        if auction_type.lower() in ["b", "blind"]:
            auction_type = "blind"
            print("Blind auction is being created...")
        else:
            auction_type = "Normal"
            print("Normal auction is being created...")

        # sign the session key
        rsa = RSAKGen()
        signature = rsa.sign_message(client.session_key_manager,client.auction_private_key)

        message += "\"auction_name\" : \""+ auction_name + "\" ,\n"
        message += "\"auction_description\" : \""+ auction_description + "\" ,\n"
        message += "\"auction_min_number_bids\" : \""+ auction_min_number_bids + "\" ,\n"
        message += "\"auction_time\" : \""+ auction_time + "\" ,\n"
        message += "\"auction_max_number_bids\" : \""+ auction_max_number_bids + "\" ,\n"
        message += "\"auction_allowed_bidders\" : \""+ auction_allowed_bidders + "\" ,\n"
        message += "\"auction_type\" : \""+ auction_type + "\" ,\n"
        message += "\"auction_threshold\" : \""+ auction_threshold + "\"\n,"

        # now put our public auction key and a signature to prove that he has the private key
        message += "\"auction_user_key\" : \"" + get_public_key_bytes(client.auction_public_key) + "\", \n"
        message += "\"auction_signature\" : \"" + str(base64.b64encode(signature), 'utf-8') + "\" \n"

        # auction_json_message += "}"
        # message += "\"message\" : \"" + auction_json_message + "\""

        message += "}"
        return message, AM_ADDRESS
