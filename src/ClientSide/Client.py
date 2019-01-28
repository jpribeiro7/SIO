import os
import socket
import base64
from App.HMAC_Conf import HMAC_Conf
from RSAKeyGenerator.RSAKGen import RSAKGen
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.kdf import hkdf
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding, utils, rsa
import codecs
import pickle
import App.app as utils_app
import App.utilities as utilities
import json
import sys

class Client:
    def __init__(self, username):
        # Generic information
        self.id = os.urandom(12)
        self.username = username
        self.password = None
        self.credentials = ()
        # RSA key pair
        self.private_key = None
        self.public_key = None
        # Session keys
        self.session_key_manager = None
        self.session_key_repository = None
        # Server public key
        self.server_public_key_manager = None
        self.server_public_key_repository = None
        # Citizen card
        self.citizen = None
        # Auction keys
        self.auction_public_key = None
        self.auction_private_key = None
        # Other vars
        self.logged = False
        self.num_auctions = 0
        self.citizenCard = None

    def set_username(self, username):
        self.username = username

    def set_credentials(self, username, password):
        self.credentials = (username, password)

    # Initializes the session key with both servers
    # address is the wanted server
    def initialize_session_key(self, address, actions):
        # asks for a challenge
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        message = "{\"type\" : \"ask_challenge\"," + "\n"
        message += "\"username\" : \"" + self.username + "\"" + "\n"
        message += "}"
        sock.sendto(base64.b64encode(message.encode("utf-8")), address)

        # receives the challenge
        data, server = sock.recvfrom(utils_app.SOCKET_BYTES)
        decoded_message = base64.b64decode(data)
        sock.close()
        message = json.loads(decoded_message, strict = False)
        challenge = message["challenge"]

        # Our parameters
        parameters = dh.generate_parameters(generator=5, key_size=utils_app.DH_KEY_SIZE, backend=default_backend())
        # Our private key and public key from DH
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        pickled_params = codecs.encode(
            pickle.dumps(parameters.parameter_bytes(encoding=Encoding.PEM, format=ParameterFormat.PKCS3)),
            "base64").decode()

        message = "{\"type\" : \"session_key\"," + "\n"
        message += "\"params\" : \"" + pickled_params + "\"," + "\n"
        message += "\"username\" : \"" + self.username + "\"," + "\n"
        message += "\"pk\" : \"" + public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(
                                                                                                        'utf-8') + "\",\n"

        message += "\"public\" : \"" + self.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                         format=serialization.PublicFormat.
                                                                         SubjectPublicKeyInfo).decode('utf-8') + "\","

        inner_message = actions.trust_server(self, challenge=challenge)
        enc_json_message = None
        server_pub = None
        if address == utils_app.AM_ADDRESS:
            server_pub = self.server_public_key_manager
        else:
            server_pub = self.server_public_key_repository

        enc_json_message = utilities.encrypt_message_complete(base64.b64encode(inner_message.encode("utf-8")),
                                                      "",
                                                      server_pub)
        key = enc_json_message[0]
        iv = enc_json_message[2]
        data = enc_json_message[1]
        rsa_kg = RSAKGen()
        random_key = Fernet.generate_key()
        hmac = HMAC_Conf.integrity_control(data.encode(), random_key)
        random_key = rsa_kg.cipher_public_key(server_pub, random_key)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        message += "\"message\" : \"" + data + "\",\n"
        message += "\"Key\" : \"" + str(base64.b64encode(key), 'utf-8') + "\",\n"
        message += "\"hmac\" : \"" + str(base64.b64encode(hmac), 'utf-8')+ "\", \n"
        message += "\"random_key\" : \"" + str(base64.b64encode(random_key), 'utf-8') + "\", \n"
        message += "\"iv\" : \"" + str(base64.b64encode(iv), 'utf-8') + "\"\n"
        message += "}"
        sock.sendto(base64.b64encode(message.encode("utf-8")), address)
        #print(message)

        ##### Sent the parameters with all the information #####
        ###########################################################################################################

        # Receive response
        data, server = sock.recvfrom(utils_app.SOCKET_BYTES)
        decoded_data = base64.b64decode(data).decode()
        json_message = json.loads(decoded_data, strict=False)
        if json_message["type"] == "No valid signature":
            print("No valid signature")
            sys.exit(0)
        elif json_message["type"] == "No valid certificate":
            print("No valid signature")
            sys.exit(0)

        # 'type', 'pk' -> public dh_key , 'info' -> handshake data, 'server_key'

        peer_pk = serialization.load_pem_public_key(json_message["pk"].encode('utf-8'), default_backend())
        shared_secret = private_key.exchange(peer_pk)

        derived_key = hkdf.HKDF(algorithm=hashes.SHA256(), length=utils_app.DH_HKDF_KEY, salt=None,
                                info=json_message["info"].encode('utf-8'), backend=default_backend())\
            .derive(shared_secret)

        if address == utils_app.AM_ADDRESS:
            self.session_key_manager = derived_key
        else:
            self.session_key_repository = derived_key

        ### Recieved the key from the server and created the public key ####
        ############################################################################################################
        sock.close()








