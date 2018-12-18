import socket
from App.App import *
import base64
import codecs
import pickle
import os
from AuctionManager.AuctionManagerEntity import AuctionManagerEntity
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as async_padd
from AssymetricKeys.RSAKeyGen import RSAKeyGen
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
from cryptography.fernet import Fernet


class AuctionManagerActions:

    # Create the necessary stuff for the server
    # Create the directory with the keys and loads them if they exist
    # No password yet
    def __init__(self, sock):
        self.sock = sock
        self.auction_manager = AuctionManagerEntity()

        # Keys creation/ Reload
        self.rsa_keygen = RSAKeyGen()
        if os.path.isdir(os.getcwd() + "/server"):
            self.auction_manager.private_key, self.auction_manager.public_key = self.rsa_keygen.load_key(os.getcwd()
                                                                                                         + "/server")
        else:
            os.mkdir(os.getcwd() + "/server")
            self.auction_manager.private_key, self.auction_manager.public_key = self.rsa_keygen.generate_key_pair()
            self.rsa_keygen.save_keys(path=os.getcwd() + "/server")

    # Function to create a session key between user and server
    def create_session_key(self, message_json, address):
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
    def create_auction(self, address, message_json):
        server_address = AR_ADDRESS

        cipher = Cipher(algorithms.AES(self.auction_manager.session_key), modes.CBC(
            self.auction_manager.session_key[:16]), backend=default_backend())

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_message = unpadder.update(
            cipher.decryptor().update(
                base64.b64decode(message_json["message"])) + cipher.decryptor().finalize()) + unpadder.finalize()

        # Signing with the user key, not with DF key
        peer_pk = self.rsa_keygen.load_public_key(os.getcwd() + "/clients/"+message_json["username"])

        sign_val = self.rsa_keygen.verify_sign(codecs.decode(message_json["sign"].encode(), "base64"), decrypted_message
                                               , peer_pk)

        # This verifies if it is valid or not!
        if sign_val in [None]:

            auction_information = json.loads(decrypted_message, strict=False)
            print(auction_information)
            print("Valid")
            # Do the creation
            # -> Get all the params from the auction
            # -> Send to Auction Repository the new auction
        else:
            print("Invalid")
            sent = self.sock.sendto(b"",address)
            return

        sent = self.sock.sendto(b"",address)

    # Verifies the login
    # Create the user folder
    def login_actions(self, address, data):

        # if it exists then do nothing because the key wont change
        if os.path.isdir(os.getcwd() + "/clients/" + data["username"]):
            return
        # decode with the session key
        cipher = Cipher(algorithms.AES(self.auction_manager.session_key), modes.CBC(
            self.auction_manager.session_key[:16]), backend=default_backend())

        unpadder = padding.PKCS7(128).unpadder()
        decoded_public_key = unpadder.update(
            cipher.decryptor().update(base64.b64decode(data["pk"])) + cipher.decryptor().finalize()) + unpadder.finalize()

        # Create the user directory
        self.create_dir_client(data["username"], decoded_public_key)

        # send our public key to the user
        pk = self.auction_manager.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                       format=serialization.PublicFormat.SubjectPublicKeyInfo)\
            .decode('utf-8')
        # Get the user key from the dir
        user_key = serialization.load_pem_public_key(
            decoded_public_key,
            backend= default_backend())

        # This will encrypt with the session and then with the user public key
        # TODO: This only works for one client, guardar as session keys?! where
        # Key, message, iv
        encrypted_pk = self.encrypt_function(pk, self.auction_manager.session_key, user_key)

        message = "{\"server\" : \"" + str((encrypted_pk[1]), 'utf-8') + "\","
        message += "\"key\" : \"" + str(base64.b64encode(encrypted_pk[0]), 'utf-8') + "\","
        message += "\"iv\" : \"" + str(base64.b64encode(encrypted_pk[2]), 'utf-8') + "\"}"

        print(message)
        self.sock.sendto(base64.b64encode(message.encode('utf-8')), address)

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
        if not os.path.isdir(path + "/" + username):
            os.mkdir(path + "/" + username)
        else:
            return False

        file = open(path + "/" + username + "/public_key.pem", "wb+")

        content = public_key
        file.write(content)
        file.close()
        return True

    # Function that encrypts the message
    # Encrypts with 2 symmetric keys
    # Returns the  [Key, message, iv]
    def encrypt_function(self, message, session_key, pub_key):
        # Create a symmetric key to be sent to the user
        # The iv has to be sent but doesn't need to be encrypted
        key = Fernet.generate_key()
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv), backend=default_backend())
        encd = message.encode()
        enc = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        message_enc = b''
        while True:
            if len(encd) < 128:
                message_enc += enc.update(padder.update(encd) + padder.finalize()) + enc.finalize()
                break
            message_enc += enc.update(padder.update(encd[:128]))
            encd = encd[128:]

        message_enc_aes = base64.b64encode(message_enc)
        # the message was successfully encrypted with the AES algorithm
        # now encrypt with the session key

        cipher2 = Cipher(algorithms.AES(session_key), modes.CBC(session_key[:16]), backend=default_backend())
        enc2 = cipher2.encryptor()
        padder2 = padding.PKCS7(128).padder()
        message_enc = b''
        while True:
            if len(message_enc_aes) < 128:
                message_enc += enc2.update(padder2.update(message_enc_aes) + padder2.finalize()) + enc2.finalize()
                break
            message_enc += enc2.update(padder2.update(message_enc_aes[:128]))
            message_enc_aes = message_enc_aes[128:]

        message_enc_full = base64.b64encode(message_enc)

        enc_key = pub_key.encrypt(key, padding=async_padd.OAEP(
                mgf=async_padd.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                ))

        array = [enc_key, message_enc_full, iv]
        return array

