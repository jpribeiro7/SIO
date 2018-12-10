import os
import socket
import base64
from venv.AssymetricKeys.RSAKeyGen import *
from venv.APP.App import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
import codecs
import pickle


# This class has all the information of a client
class Client:

    def __init__(self, username):
        self.id = os.urandom(12)
        self.username = username
        self.credentials = ()

        self.private_key = None
        self.public_key  = None

    def set_username(self, username):
        self.username = username

    def set_credentials(self,username, password):
        self.credentials = (username, password)

    # Initializes the session key
    # Crying in python
    def initialize_session_key(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Our parameters
        parameters = dh.generate_parameters(generator=5, key_size=512, backend=default_backend())

        # Our private key and public key
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        # needs the server parameters, send our parameters, for now our parameters are the ones to be done
        message = codecs.encode(
            pickle.dumps(parameters.parameter_bytes(encoding=Encoding.PEM, format=ParameterFormat.PKCS3)),
            "base64").decode()

        # message construction
        json_message = "{ " + "\n"
        json_message += "\"type\" : \"session\"," + "\n"
        json_message += "\"data\" : \"" + message + "\", \n"
        json_message += "\"pk\" : \"" + public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(
            'utf-8') + "\""
        json_message += "}"

        print(json_message)
        try:
            # send response
            sent = sock.sendto(base64.b64encode(json_message.encode('utf-8')), AM_ADDRESS)

            # Receive response
            data, server = sock.recvfrom(4096)
            # derivate the key
            peer_public_key_bytes = base64.b64decode(data)
            peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, default_backend())
            shared_key = private_key.exchange(peer_public_key)

            derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data',
                               backend=default_backend()).derive(shared_key)

        finally:
            sock.close()

    #   Used to set the keys in case of not haveing already a given key pair
    def set_keys(self):
        rsa = RSAKeyGen()
        self.private_key, self.public_key = rsa.generate_key_pair()
        #TODO
        #TODO
        #TODO   Aqui criar um diretorio com o nome do cliente e passa-lo como path (eg. /Desktop/Client1)
        #TODO
        #TODO

    #   Used to load the keys if they already exist
    def load_keys(self):
        #TODO Load
        rsa = RSAKeyGen()
        rsa.load_key("ENTER PATH")

    #   Signs a message
    #   After a signature, the public key must be passed to check that it is the real person who sent
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
        return signature