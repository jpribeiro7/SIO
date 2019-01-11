#from AuctionRepository.Auction import Auction
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
import codecs
import json
import pickle
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from RSAKeyGenerator.RSAKGen import RSAKGen
#from Blockchain.blockchain import BlockChain
import datetime

class AuctionRepositoryActions:

    _server_path = os.getcwd() + "/server"
    _server_password = "t0zj7bIPnzZQk3"

    def __init__(self, sock):

        self.auction_repository = AuctionRepositoryEntity()
        self.sock = sock

        # Create the Public key and Private key
        rsa_kg = RSAKGen()

        # Check for the existence of the directory
        if check_directory(self._server_path):
            try:
                self.auction_repository.private_key, self.auction_repository.public_key = rsa_kg.load_key_servers(
                    self._server_path, self._server_password)
            except ValueError:
                print("The password is incorrect!"
                      "All information has been deleted and the server will now become instable")
                sys.exit(0)

        else:
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
        # server_pub = serialization.load_pem_public_key(message_json["public"].encode(),default_backend())

        manager_pub = message_json["public"].encode()
        save_server_key_client(self._server_path, manager_pub,"/manager_server.pem")

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
        # print(derived_key)

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
            return base64.b64encode("{ \"response\" : \"No valid signature\"}".encode('utf-8'))

        if not citizen.validate_certificate(certificate):
            return base64.b64encode("{ \"response\" : \"No valid certificate\"}".encode('utf-8'))

        user_pub_key = unpadd_data(message_json["public"], self.auction_repository.session_key_clients[message_json["username"]])

        # Get the user key from the dir
        user_key = serialization.load_pem_public_key(
            user_pub_key,
            backend=default_backend())

        rsa = RSAKGen()
        # Verify the uses signature of the session key
        if rsa.verify_sign(message_json["rsa_signature"].encode('utf-8'),
                           self.auction_repository.session_key_clients[message_json["username"]], user_key):
            # It is invalid
            return base64.b64encode("{\"response\" : \"No valid rsa signature\"}".encode("utf-8"))

        _dir = os.getcwd() + "/Clients/" + message_json["username"]
        if not check_directory(_dir):
            if not check_directory(os.getcwd() + "/Clients"):
                os.mkdir(os.getcwd() + "/Clients")
            os.mkdir(_dir)
            with open(_dir+"/" + PK_NAME, "wb") as file:
                file.write(user_pub_key)

        return base64.b64encode("{\"response\" : \"success\"}".encode("utf-8"))

    # Should store all the auctions some sort of memory
    # TODO: save the auctions
    # All methods should have address to then send to where it should go
    def create_auction(self, message_json, address):
        # get all the values
        auction_name = message_json["auction_name"]
        auction_description = message_json["auction_description"]
        auction_min_number_bids = message_json["auction_min_number_bids"]
        auction_time = message_json["auction_time"]
        auction_max_number_bids = message_json["auction_max_number_bids"]
        auction_allowed_bidders = message_json["auction_allowed_bidders"]
        auction_threshold = message_json["auction_threshold"]
        auction_type = message_json["auction_type"]
        auction_user_key = serialization.load_pem_public_key(message_json["auction_user_key"].encode('utf-8'),
                                                             default_backend())

        # All values are here
        print(auction_name)
        print(auction_allowed_bidders)
        return b""

    # Save this atm
    def qualquermerda(self):
        # Get the public key from the user key from the user
        _dir = os.getcwd() + "/Clients/" + message_json["username"]
        if not check_directory(_dir):
            if not check_directory(os.getcwd() + "/Clients"):
                os.mkdir(os.getcwd() + "/Clients")
            os.mkdir(_dir)
            with open(_dir+"/" + PK_NAME, "wb") as file:
                file.write(message_json["public"].encode())
