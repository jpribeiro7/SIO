from App.utilities import *
from App.app import *
import base64
import os
import sys
from CitizenCard.CitizenCard import *
from AuctionRepository.AuctionRepositoryEntity import AuctionRepositoryEntity
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
import codecs
import json
import pickle
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from AuctionRepository.Auction import Auction
from RSAKeyGenerator.RSAKGen import RSAKGen
import datetime

class AuctionRepositoryActions:

    # Server path and server hex password
    _server_path = os.getcwd() + "/server"
    _server_password = "t0zj7bIPnzZQk3"

    def __init__(self, sock):
        # Create the Entity and socket
        self.auction_repository = AuctionRepositoryEntity()
        self.sock = sock

        # Create the Public key and Private key
        rsa_kg = RSAKGen()

        # Check for the existence of the directory
        if check_directory(self._server_path):

            try:
                # Get the keys from the folders
                self.auction_repository.private_key, self.auction_repository.public_key = rsa_kg.load_key_servers(
                    self._server_path, self._server_password)

                # Get the server public key
                self.auction_repository.manager_public = rsa_kg.load_public_key(self._server_path, "manager_server.pem")
            except ValueError:
                # Exits
                sys.exit("The password is incorrect! All information has been deleted and the server will"
                         "now become unstable")

        else:
            # Since it doesn't exist, we create the folders
            os.mkdir(self._server_path)
            os.mkdir(os.getcwd() + "/Clients")
            self.auction_repository.private_key, self.auction_repository.public_key = rsa_kg.generate_key_pair_server()
            rsa_kg.save_keys_server(self._server_path, self._server_password)

    # Function to create a session key between server and server
    def create_session_key_server(self, message_json, address):

        # decode the params
        parameters = pickle.loads(codecs.decode(message_json["params"].encode(), "base64"))
        par = load_pem_parameters(parameters, backend=default_backend())

        # Get the server public key
        manager_pub = message_json["public"].encode()
        save_server_key_client(self._server_path, manager_pub, "/manager_server.pem")

        # Load the key
        r = RSAKGen()
        self.auction_repository.manager_public = r.load_public_key(self._server_path, "manager_server.pem")

        # Generate our public/private key
        private_key = par.generate_private_key()
        public_key = private_key.public_key()

        # Get the public key from the user
        peer_public_key_bytes = message_json["pk"].encode()
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, default_backend())
        shared_key = private_key.exchange(peer_public_key)

        calendar_date = str(datetime.datetime.now())

        derived_key = HKDF(algorithm=hashes.SHA256(), length= DH_HKDF_KEY, salt=None, info=calendar_date.encode(),
                           backend=default_backend()).derive(shared_key)

        # Construct the message with the keys
        message = "{ \"type\" : \"session_server\" ,\n"

        # Now send our DH public key to the client
        pk_dh = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

        message += "\"pk\" : \"" + pk_dh + "\" ,\n"
        message += "\"info\" : \"" + calendar_date + "\",\n"
        message += "\"server_key\" : \"" + self.auction_repository.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')+"\""

        message += "}"

        # Set the sessionKey as the bytes of the derived_key
        self.auction_repository.session_key_server = derived_key
        return base64.b64encode(message.encode('utf-8'))

    # Creates the session key with the client
    def create_session_key(self, message_json, address):

        # Get the parameters
        parameters = pickle.loads(codecs.decode(message_json["params"].encode(), "base64"))
        par = load_pem_parameters(parameters, backend=default_backend())

        # Generate our DH public/private key
        private_key = par.generate_private_key()
        public_key = private_key.public_key()

        # Get the public key bytes from the user
        peer_public_key_bytes = message_json["pk"].encode()
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, default_backend())

        calendar_date = str(datetime.datetime.now())

        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=DH_HKDF_KEY, salt=None, info=calendar_date.encode("utf-8"),
                           backend=default_backend()).derive(shared_key)

        # Construct the message with the keys
        message = "{ \"type\" : \"session\" ,\n"

        # Now send our DH public key to the client
        pk_dh = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

        message += "\"pk\" : \"" + pk_dh + "\" ,\n"
        message += "\"info\" : \"" + calendar_date + "\",\n"
        message += "\"server_key\" : \"" + self.auction_repository.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')+"\""

        message += "}"
        # Get the username and set the session key
        self.auction_repository.session_key_clients[message_json["username"]] = derived_key

        return base64.b64encode(message.encode('utf-8'))

    # Builds the trust with the client
    # Must be done alongside the login
    def build_trust(self, message_json):

        # decipher with the session key
        cert = unpadd_data(message_json["certificate"], self.auction_repository.session_key_clients[message_json["username"]])
        signature = unpadd_data(message_json["digital_signature"],
                                self.auction_repository.session_key_clients[message_json["username"]])

        certificate = x509.load_pem_x509_certificate(cert,default_backend())
        citizen = CitizenCard()
        print(signature)
        if not citizen.check_signature(certificate, signature, message_json["username"].encode('utf-8')):
            return base64.b64encode("{ \"type\" : \"No valid signature\"}".encode('utf-8'))

        if not citizen.validate_certificate(certificate):
            return base64.b64encode("{ \"type\" : \"No valid certificate\"}".encode('utf-8'))

        user_pub_key = unpadd_data(message_json["public"], self.auction_repository.session_key_clients[message_json["username"]])

        # Get the user key from the dir
        user_key = serialization.load_pem_public_key(
            user_pub_key,
            backend=default_backend())

        rsa = RSAKGen()
        # Verify the user signature of the session key
        if rsa.verify_sign(message_json["rsa_signature"].encode('utf-8'),
                           self.auction_repository.session_key_clients[message_json["username"]], user_key):
            # It is invalid
            return base64.b64encode("{\"type\" : \"No valid rsa signature\"}".encode("utf-8"))

        _dir = os.getcwd() + "/Clients/" + message_json["username"]
        if not check_directory(_dir):
            if not check_directory(os.getcwd() + "/Clients"):
                os.mkdir(os.getcwd() + "/Clients")
            os.mkdir(_dir)
            with open(_dir+"/" + PK_NAME, "wb") as file:
                file.write(user_pub_key)

        return base64.b64encode("{\"type\" : \"success\"}".encode("utf-8"))

    # Should store all the auctions some sort of memory
    # TODO: save the auctions
    # All methods should have address to then send to where it should go
    def create_auction(self, message_json, address):

        # Decrypts the message
        data = decrypt_data(self.auction_repository.session_key_server,
                            message_json["message"], base64.b64decode(message_json["iv"]),
                            base64.b64decode(message_json["Key"]),
                            self.auction_repository.private_key)

        # Loads the messsage to json
        message_json = json.loads(data,strict="False")

        # get all the values
        auction_name = unpadd_data(message_json["auction_name"],
                                   self.auction_repository.session_key_server)
        auction_description = unpadd_data(message_json["auction_description"],
                                          self.auction_repository.session_key_server)
        auction_min_number_bids = unpadd_data(message_json["auction_min_number_bids"],
                                              self.auction_repository.session_key_server)
        auction_time = unpadd_data(message_json["auction_time"],
                                   self.auction_repository.session_key_server)
        auction_max_number_bids = unpadd_data(message_json["auction_max_number_bids"],
                                              self.auction_repository.session_key_server)
        auction_allowed_bidders = unpadd_data(message_json["auction_allowed_bidders"],
                                              self.auction_repository.session_key_server)
        auction_type = unpadd_data(message_json["auction_type"],
                                   self.auction_repository.session_key_server)
        # Unpad the data
        auct_padd = unpadd_data(
            message_json["auction_user_key"].encode('utf-8'),self.auction_repository.session_key_server)

        auction_user_key = serialization.load_pem_public_key(auct_padd,
                                                             default_backend())

        print(auction_description)
        auction = Auction(auction_name=str(auction_name,"utf8"),
                          description = str(auction_description,"utf8"),
                          auction_min_number_bids = str(auction_min_number_bids,"utf8"),
                          auction_time = str(auction_time,"utf8"),
                          auction_max_number_bids = str(auction_max_number_bids,"utf8"),
                          auction_allowed_bidders = str(auction_allowed_bidders,"utf8"),
                          auction_threshold = None,
                          auction_type=str(auction_type,"utf8"),
                          auction_user_key=auction_user_key
                         )
        self.auction_repository.addAuction(auction)
        # All values are here
        print("NAME ", auction_name)
        return b""

    # Lists all the auctions in the repository
    # TODO maybe present the current max bid (if not Blind)
    def list_auctions(self,message_json):
        # gets the list of auctions and serializes it
        auction_list = self.auction_repository.listAuctions()
        serialized = pickle.dumps(auction_list)

        # loads the shared secret between the server and the user
        username = message_json["username"]
        session_key = self.auction_repository.session_key_clients[username]

        message = "{ \"type\" : \"list_auctions\" ,\n"
        message += "\"list\" : \"" + encrypt_message_sk(serialized, session_key) + "\" \n"
        message += "}"

        print("auction_repos", message)
        return base64.b64encode(message.encode("utf-8"))

    # User made a bid
    # and then put it in and send RECEIPT TODO
    def make_bid(self,message_json):
        # Decrypts the message
        username = message_json["username"]
        data = decrypt_data(self.auction_repository.session_key_clients[username],
                            message_json["message"], base64.b64decode(message_json["iv"]),
                            base64.b64decode(message_json["Key"]),
                            self.auction_repository.private_key)
        # Loads the messsage to json
        message_json = json.loads(data,strict="False")

        auction_id = unpadd_data(
            message_json["auction_id"],
            self.auction_repository.session_key_clients[username])
        amount = unpadd_data(
            message_json["amount"],
            self.auction_repository.session_key_clients[username])
        signature = unpadd_data(
            message_json["signature"],
            self.auction_repository.session_key_clients[username])

        certificate = unpadd_data(
            message_json["certificate"],
            self.auction_repository.session_key_clients[username])

        # validate certificate and signature
        cert = x509.load_pem_x509_certificate(certificate, default_backend())
        citizen = CitizenCard()
        if not citizen.check_signature(cert, signature, amount):
            return base64.b64encode("{ \"type\" : \"No valid signature\"}".encode('utf-8'))

        if not citizen.validate_certificate(cert):
            return base64.b64encode("{ \"type\" : \"No valid certificate\"}".encode('utf-8'))

        auction = self.auction_repository.auctions[str(auction_id, "utf-8")]
        response = auction.makeBid(username, amount, signature, certificate)

        success = "success" if response else "nope"
        print("result: ", success)

        #TODO future should print a receipt
        return base64.b64encode(("{ \"type\" : \""+success+"\"}").encode("utf-8"))
