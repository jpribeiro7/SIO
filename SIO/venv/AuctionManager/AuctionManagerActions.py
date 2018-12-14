import socket
import sys
from venv.APP.App import *
import base64
import codecs
import pickle
import os
from venv.AuctionManager.AuctionManager import AuctionManager
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from venv.AssymetricKeys.RSAKeyGen import RSAKeyGen
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AuctionManagerActions:

    # Create the necessary stuff for the server
    # Create the directory with the keys and loads them if they exist
    # No password yet
    def __init__(self, sock):
        self.sock = sock
        self.auction_manager = AuctionManager()

        # Keys creation/ Reload
        self.rsa_keygen = RSAKeyGen()
        if os.path.isdir(os.getcwd() + "/server"):
            self.auction_manager.private_key,self.auction_manager.public_key = self.rsa_keygen.load_key(os.getcwd() + "/server")
        else:
            os.mkdir(os.getcwd() + "/server")
            self.auction_manager.private_key, self.auction_manager.public_key = self.rsa_keygen.generate_key_pair()
            self.rsa_keygen.save_keys(path=os.getcwd() + "/server")



    # Function to create a session key between user and server
    def createSessionKey(self, message_json, address):
        # decode the data
        parameters = pickle.loads(codecs.decode(message_json["data"].encode(), "base64"))
        par = load_pem_parameters(parameters, backend=default_backend())

        # Generate our public/private key
        private_key = par.generate_private_key()
        public_key = private_key.public_key()

        # Get the public key from the user
        peer_public_key_bytes = message_json["pk"].encode()
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, default_backend())
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data',
                           backend=default_backend()).derive(shared_key)

        # Now send our public key to the client
        message = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                          format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

        # Set the sessionKey as the bytes of the derived_key
        self.auction_manager.session_key = derived_key

        sent = self.sock.sendto(base64.b64encode(message.encode('utf-8')), address)


    # Function to create a auction
    def create_auction(self,address, message_json):

        server_address = AR_ADDRESS

        ### TESTING SIGNATURE
        ### TODO : Create in rsa a function to load the pubkey from a path (server path)
        cipher = Cipher(algorithms.AES(self.auction_manager.session_key), modes.CBC(
            self.auction_manager.session_key[:16]), backend=default_backend())

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_message = unpadder.update(
            cipher.decryptor().update(
                base64.b64decode(message_json["message"])) + cipher.decryptor().finalize()) + unpadder.finalize()

        t = self.rsa_keygen.verify_sign(codecs.decode(message_json["sign"].encode(), "base64"), decrypted_message, )
        print("HHHH")
        print(t)

        sent = self.sock.sendto("",address)

    # Verifies the login
    # Create the user folder
    def login_actions(self, data):

        # if it exists then do nothing because the key wont change
        if os.path.isdir(os.getcwd() + "/clients/" + data["username"]):
            return

        cipher = Cipher(algorithms.AES(self.auction_manager.session_key), modes.CBC(
            self.auction_manager.session_key[:16]), backend=default_backend())

        unpadder = padding.PKCS7(128).unpadder()

        decoded_public_key = unpadder.update(
            cipher.decryptor().update(base64.b64decode(data["pk"])) + cipher.decryptor().finalize()) + unpadder.finalize()

        self.create_dir_client(data["username"],decoded_public_key)

    # Creates the directory for all clients to be stored
    # Can also create a directory for a user
    # And saves the contents of public key to the file
    # Returns True if directory was created
    def create_dir_client(self, username, public_key):
        # Create the parent folder if it doens't exists
        if not os.path.isdir(os.getcwd() + "/clients"):
            os.mkdir(os.getcwd() + "/clients")

        # Create the folder with the client and save its public_key encrypted
        path = os.getcwd() + "/clients"

        # if client doesnt exist create it
        if not os.path.isdir(path +"/" + username):
            os.mkdir(path + "/" + username)
        else:
            return False

        file = open(path + "/" + username + "/public_key.pem", "wb+")
        #content = self.auction_manager.public_key.encrypt(public_key, padding=padding.OAEP(
        #    mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #    algorithm=hashes.SHA256(),
        #    label=None
        #))
        content = public_key
        file.write(content)
        return  True