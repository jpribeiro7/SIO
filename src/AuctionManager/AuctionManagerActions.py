import socket
import App.app as utils_app
from App.utilities import *
import base64
import os
from CitizenCard.CitizenCard import *
from AuctionManager.AuctionManagerEntity import AuctionManagerEntity
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as async_padd
from RSAKeyGenerator.RSAKGen import RSAKGen
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import ParameterFormat
import cryptography.hazmat.primitives.kdf.hkdf
from cryptography.hazmat.primitives import hashes
from cryptography import x509
#from CitizenCard.CitizenCard import *
import codecs
import pickle
import datetime
from RSAKeyGenerator.RSAKGen import RSAKGen
import sys
from App.HMAC_Conf import HMAC_Conf


class AuctionManagerAuctions:
    _server_path = os.getcwd() + "/server"
    _server_password = "tozj8bINQSQk3"

    def __init__(self, sock):
        self.sock = sock
        self.auction_manager = AuctionManagerEntity()

        # Create the Public key and Private key
        rsa_kg = RSAKGen()

        # Check for the existence of the directory
        if check_directory(self._server_path):
            try:
                self.auction_manager.private_key, self.auction_manager.public_key = rsa_kg.load_key_servers(
                    self._server_path,self._server_password)
                self.auction_manager.public_repository_key = rsa_kg.load_public_key(os.getcwd()+"/server",
                                                                                    "repository_server.pem")
            except ValueError:
                print("The password is incorrect!"
                      "All information has been deleted and the server will now become instable")
                sys.exit(0)

        else:
            os.mkdir(self._server_path)
            self.auction_manager.private_key, self.auction_manager.public_key = rsa_kg.generate_key_pair_server()
            rsa_kg.save_keys_server(self._server_path, self._server_password)

        # Create the sessionKey with the other Repository
        self.create_session_key_server()

    # Function to create a session key between user and server
    def create_session_key_user_server(self, message_json):

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
        derived_key = HKDF(algorithm=hashes.SHA256(), length=utils_app.DH_HKDF_KEY, salt=None, info=calendar_date.encode("utf-8"),
                           backend=default_backend()).derive(shared_key)

        # Construct the message with the keys
        message = "{ \"type\" : \"session\" ,\n"

        # Now send our DH public key to the client
        pk_dh = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

        message += "\"pk\" : \"" + pk_dh + "\" ,\n"
        message += "\"info\" : \"" + calendar_date + "\",\n"
        message += "\"server_key\" : \"" + self.auction_manager.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')+"\""

        message += "}"
        # Get the username and set the session key
        self.auction_manager.session_clients[message_json["username"]] = derived_key
        # print(derived_key)

        return base64.b64encode(message.encode('utf-8'))

    # Initializes the session key with the server
    def create_session_key_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Our parameters
        parameters = dh.generate_parameters(generator=5, key_size=utils_app.DH_KEY_SIZE, backend=default_backend())

        # Our private key and public key
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        message = codecs.encode(
            pickle.dumps(parameters.parameter_bytes(encoding=Encoding.PEM, format=ParameterFormat.PKCS3)),
            "base64").decode()

        # message construction
        json_message = "{ " + "\n"
        json_message += "\"type\" : \"session_server\"," + "\n"
        json_message += "\"params\" : \"" + message + "\", \n"
        json_message += "\"pk\" : \"" + public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo)\
            .decode('utf-8') + "\","
        json_message += "\"public\" : \"" + self.auction_manager.public_key.\
            public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)\
            .decode('utf-8') + "\""
        json_message += "}"

        try:
            # send type
            sock.sendto(base64.b64encode(json_message.encode('utf-8')), utils_app.AR_ADDRESS)

            # Receive type
            data, server = sock.recvfrom(utils_app.SOCKET_BYTES)
            json_message = json.loads(base64.b64decode(data), strict=False)

            # derivate the key
            peer_public_key_bytes = json_message["pk"].encode()
            peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, default_backend())
            shared_key = private_key.exchange(peer_public_key)

            derived_key = cryptography.hazmat.primitives.kdf.hkdf.HKDF(algorithm=hashes.SHA256(),
                                                                       length=utils_app.DH_HKDF_KEY,
                                                                       salt=None, info=json_message["info"].encode(),
                                                                       backend=default_backend()).derive(shared_key)
            self.auction_manager.session_key_repository = derived_key

            save_server_key_client(self._server_path, json_message["server_key"].encode(), "/repository_server.pem")

            #Load the key
            r = RSAKGen()
            self.auction_manager.public_repository_key = r.load_public_key(os.getcwd()+"/server",
                                                                           "repository_server.pem")
            print("Session Set with repository")
        finally:
            sock.close()

    # Builds the trust with the client
    # Must be done alongside the login
    def build_trust(self, message_json):

        hm = base64.b64decode(message_json["hmac"])
        cr = message_json["certificate"].encode("utf-8")
        sk = self.auction_manager.session_clients[message_json["username"]]
        if not HMAC_Conf.verify_integrity(hm,cr,sk):
            return base64.b64encode("{ \"type\" : \"Tempered data\"}".encode('utf-8'))


        # decipher with the session key
        cert = unpadd_data(message_json["certificate"], self.auction_manager.session_clients[message_json["username"]])
        signature = unpadd_data(message_json["digital_signature"],
                                self.auction_manager.session_clients[message_json["username"]])

        certificate = x509.load_pem_x509_certificate(cert,default_backend())
        citizen = CitizenCard()

        print(signature)
        if not citizen.check_signature(certificate, signature, message_json["username"].encode('utf-8')):
            return base64.b64encode("{ \"type\" : \"No valid signature\"}".encode('utf-8'))

        if not citizen.validate_certificate(certificate):
            return base64.b64encode("{ \"type\" : \"No valid certificate\"}".encode('utf-8'))

        user_pub_key = unpadd_data(message_json["public"], self.auction_manager.session_clients[message_json["username"]])

        # Get the user key from the dir
        user_key = serialization.load_pem_public_key(
            user_pub_key,
            backend=default_backend())

        rsa = RSAKGen()
        # Verify the uses signature of the session key
        if rsa.verify_sign(message_json["rsa_signature"].encode('utf-8'),
                           self.auction_manager.session_clients[message_json["username"]], user_key):
            # It is invalid
            return base64.b64encode("{\"type\" : \"No valid rsa signature\"}".encode("utf-8"))

        # Get the public key from the user key from the user
        _dir = os.getcwd() + "/Clients/" + message_json["username"]
        if not check_directory(_dir):
            if not check_directory(os.getcwd() + "/Clients"):
                os.mkdir(os.getcwd() + "/Clients")
            os.mkdir(_dir)
            with open(_dir+"/" + utils_app.PK_NAME, "wb") as file:
                file.write(user_pub_key)

        return base64.b64encode("{\"type\" : \"success\"}".encode("utf-8"))

    # Checks everything from the auction and then sends to the other server
    def create_auction(self, message_json, address):
        hm = base64.b64decode(message_json["hmac"])
        cr = message_json["message"].encode()
        sk = self.auction_repository.session_key_clients[message_json["username"]]
        if not HMAC_Conf.verify_integrity(hm,cr,sk):
            return base64.b64encode("{ \"type\" : \"Tempered data\"}".encode('utf-8'))

        username = message_json["username"]
        session_key_client = self.auction_manager.session_clients[message_json["username"]]

        # Decrypts the message
        data = decrypt_data(session_key_client,
                            message_json["message"], base64.b64decode(message_json["iv"]),
                            base64.b64decode(message_json["Key"]),
                            self.auction_manager.private_key)

        # Loads the messsage to json
        message_json = json.loads(data,strict="False")

        # Decrypt the rest of the data with the SessionKey
        auction_name = unpadd_data(message_json["auction_name"],session_key_client)
        auction_description = unpadd_data(message_json["auction_description"], session_key_client)
        auction_min_number_bids = unpadd_data(message_json["auction_min_number_bids"],session_key_client)
        auction_time = unpadd_data(message_json["auction_time"],session_key_client)
        auction_max_number_bids = unpadd_data(message_json["auction_max_number_bids"], session_key_client)
        auction_allowed_bidders = unpadd_data(message_json["auction_allowed_bidders"], session_key_client)
        auction_type = unpadd_data(message_json["auction_type"], session_key_client)

        auct_padd = unpadd_data(
            message_json["auction_user_key"].encode('utf-8'),session_key_client)

        auction_user_key = serialization.load_pem_public_key(auct_padd, default_backend())

        auction_signature = unpadd_data(message_json["auction_signature"], session_key_client)

        rsa = RSAKGen()
        verification = rsa.verify_sign(base64.b64decode(auction_signature),
                                       session_key_client, auction_user_key)

        # if its not valid then the address is the client's and the message is an error
        if not verification:
            return base64.b64encode("{\"type\" : \"Not a valid auction signature\"}".encode("utf-8")), address

        # Construct the message to send to the AR
        message_final_json = "{"
        message_final_json += "\"type\" : \"create_auction\", \n"
        # create the encrypted message

        message_interm = "{"
        message_interm += "\"username\" : \"" + encrypt_message_sk(username,
                                                                       self.auction_manager.session_key_repository) + "\", \n"
        message_interm += "\"auction_name\" : \"" + encrypt_message_sk(auction_name,
                                                                       self.auction_manager.session_key_repository) + "\", \n"
        message_interm += "\"auction_description\" : \"" + encrypt_message_sk(auction_description,
                                                                              self.auction_manager.session_key_repository) + "\", \n"
        message_interm += "\"auction_min_number_bids\" : \"" + encrypt_message_sk(auction_min_number_bids,
                                                                                  self.auction_manager.session_key_repository) + "\", \n"
        message_interm += "\"auction_time\" : \"" + encrypt_message_sk(auction_time,
                                                                       self.auction_manager.session_key_repository) + "\", \n"
        message_interm += "\"auction_max_number_bids\" : \"" + encrypt_message_sk(auction_max_number_bids,
                                                                                  self.auction_manager.session_key_repository) + "\", \n"
        message_interm += "\"auction_allowed_bidders\" : \"" + encrypt_message_sk(auction_allowed_bidders,
                                                                                  self.auction_manager.session_key_repository) + "\", \n"
        message_interm += "\"auction_type\" : \"" + encrypt_message_sk(auction_type,
                                                                       self.auction_manager.session_key_repository) + "\", \n"
        message_interm += "\"auction_user_key\" : \"" + encrypt_message_sk(auct_padd,
                                                                           self.auction_manager.session_key_repository) + "\" \n"
        message_interm += "}"

        # Encrypt Complete
        enc_json_message = encrypt_message_complete(base64.b64encode(message_interm.encode("utf-8")),
                                                    self.auction_manager.session_key_repository,
                                                    self.auction_manager.public_repository_key)

        key = enc_json_message[0]
        iv = enc_json_message[2]
        data = enc_json_message[1]

        message_final_json += "\"message\" : \"" + data + "\",\n"
        message_final_json += "\"Key\" : \"" + str(base64.b64encode(key), 'utf-8') + "\",\n"
        message_final_json += "\"iv\" : \"" + str(base64.b64encode(iv), 'utf-8') + "\"\n"
        message_final_json += "\n}"

        print(message_final_json)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(base64.b64encode(message_final_json.encode("utf-8")), AR_ADDRESS)

        return base64.b64encode("{\"type\" : \"success\"}".encode("utf-8"))
