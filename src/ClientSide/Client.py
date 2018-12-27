import os
import socket
import base64
from AssymetricKeys.RSAKeyGen import RSAKeyGen
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import ParameterFormat
import cryptography.hazmat.primitives.kdf.hkdf
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
import codecs
import pickle
from CitizenCard import CitizenCard
from App.App import *


# This class has all the information of a client
class Client:

    def __init__(self, username):
        self.id = os.urandom(12)
        self.username = username
        self.credentials = ()
        self.private_key = None
        self.public_key = None
        self.session_key = None
        self.session_key_repository = None
        self.server_public_key = None
        self.server_public_key_repository = None
        self.citizen = None
        self.logged = False
        self.num_auctions = 0

    def set_username(self, username):
        self.username = username

    def set_credentials(self, username, password):
        self.credentials = (username, password)

    # Initializes the session key
    def initialize_session_key(self, address):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Our parameters
        parameters = dh.generate_parameters(generator=5, key_size=512, backend=default_backend())

        # Our private key and public key
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        # needs the server parameters, send our parameters, for now our parameters are the ones to be accepted
        message = codecs.encode(
            pickle.dumps(parameters.parameter_bytes(encoding=Encoding.PEM, format=ParameterFormat.PKCS3)),
            "base64").decode()

        # message construction
        json_message = "{ " + "\n"
        json_message += "\"type\" : \"session\"," + "\n"
        json_message += "\"username\" : \"" + self.username + "\"," + "\n"
        json_message += "\"data\" : \"" + message + "\", \n"
        json_message += "\"pk\" : \"" + public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(
            'utf-8') + "\""
        json_message += "}"

        try:
            # send response
            sent = sock.sendto(base64.b64encode(json_message.encode('utf-8')), address)

            # Receive response
            data, server = sock.recvfrom(16384)
            # derivate the key
            peer_public_key_bytes = base64.b64decode(data)
            peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, default_backend())
            shared_key = private_key.exchange(peer_public_key)

            derived_key = cryptography.hazmat.primitives.kdf.hkdf.HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data',
                                                                       backend=default_backend()).derive(shared_key)

            #For now we use it as a SEED
            if address == AM_ADDRESS:
                self.session_key = derived_key
            else:
                self.session_key_repository = derived_key

        finally:
            sock.close()

    #   Used to set the keys in case of not having already a given key pair
    #   Creates the keys and creates a directory and saves them
    def set_keys(self, password=None):
        rsa = RSAKeyGen()
        self.private_key, self.public_key = rsa.generate_key_pair()
        # directory creation and saving
        os.mkdir(os.getcwd()+"/" + self.username)
        rsa.save_keys(os.getcwd()+"/" + self.username,password)

    #   Used to load the keys if they already exist
    def load_keys(self, password=None):
        rsa_kg = RSAKeyGen()
        self.private_key, self.public_key = rsa_kg.load_key(os.getcwd()+"/" + self.username, password)

    #   Signs a message with the KeyPair
    #   After a signature, the public key must be passed to check that it is the real person who sent
    #   If a message is 300 chars or longer it will use digest! (This changes the verify_signature ->
    #   Not yet implemented with digest)
    def sign_message(self, message):

        # if Messages are to large use Pre-hashing
        if len(message) > 300:
            used_hash = hashes.SHA256()
            hasher = hashes.Hash(used_hash,default_backend())

            message_init, message_end = message[:len(message) / 2], message[len(message) / 2:]
            hasher.update(message_init.encode())
            hasher.update(message_end.encode())

            digest = hasher.finalize()

            signature = self.private_key.sign(digest,
                                              padding.PSS(
                                                  mgf=padding.MGF1(hashes.SHA256()),
                                                  salt_length=padding.PSS.MAX_LENGTH
                                              ),
                                              utils.Prehashed(used_hash))

        else:
            signature = self.private_key.sign(message.encode(),
                                              padding.PSS(
                                                  mgf=padding.MGF1(hashes.SHA256()),
                                                  salt_length=padding.PSS.MAX_LENGTH
                                              ),
                                              hashes.SHA256())
        return str(base64.b64encode(signature), 'utf-8')

    # Verifies the signature given a message
    # If invalid signature it raises:
    # raise InvalidSignature cryptography.exceptions.InvalidSignature
    # If it is VALID returns NONE
    # The type argument is either BYTES or STRING because of the message.encode
    def verify_sign(self, signature, message, peer_public_key, type="BYTES"):
        try:
            if type=="BYTES":
                return peer_public_key.verify(signature, message,
                                              padding.PSS(
                                                  mgf=padding.MGF1(hashes.SHA256()),
                                                  salt_length=padding.PSS.MAX_LENGTH
                                              ), hashes.SHA256())
            else:
                return peer_public_key.verify(signature,message.encode(),
                                              padding.PSS(
                                                  mgf=padding.MGF1(hashes.SHA256()),
                                                  salt_length=padding.PSS.MAX_LENGTH
                                              ),hashes.SHA256())
        except:
            return "INVALID"

    # Should verify if user already exists
    # if so, load keys, else create keys
    # Returns: True if Exists
    def verify_existence(self,username):

        if os.path.isdir(os.getcwd() + "/" + username):
            return True
        else:
            return False

    def load_citizen_card(self):
        self.citizen = CitizenCard()

    def get_citizen_card(self):
        return self.citizen
