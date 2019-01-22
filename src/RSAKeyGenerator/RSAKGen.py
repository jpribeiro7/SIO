from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import App.app as utils_app
import os
from cryptography.exceptions import InvalidSignature


class RSAKGen:

    def __init__(self):
        self.private_key_auction = None
        self.private_key = None
        self.public_key_auction = None
        self.public_key = None
        self.password = None

    #   Generates the Key pair for the client
    #   Returns all keys (Auction and Client)
    #   Returns ARRAY [private_k, pub_k, private_auc_k, pub_auc_k]
    def generate_key_pair_client(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=utils_app.KEY_SIZE_RSA,
                                                    backend=default_backend())
        self.public_key = self.private_key.public_key()

        self.private_key_auction = rsa.generate_private_key(public_exponent=65537, key_size=utils_app.KEY_SIZE_RSA,
                                                            backend=default_backend())

        self.public_key_auction = self.private_key_auction.public_key()

        return [self.private_key, self.public_key, self.private_key_auction, self.public_key_auction]

    #   Generates the Key pair for the server
    #   Returns private and public keys
    #   Returns tuple (private_k, public_k)
    def generate_key_pair_server(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=utils_app.KEY_SIZE_RSA,
                                                    backend=default_backend())
        self.public_key = self.private_key.public_key()

        return self.private_key, self.public_key

    #   Saves the keys in .pem files from the client
    #   path must be the folder  /etc/testing
    def save_keys_client(self, path, password):
        # Private keys
        private_auction_pem = self.private_key_auction.private_bytes(encoding=serialization.Encoding.PEM,
                                                                     format=serialization.PrivateFormat.PKCS8,
                                                                     encryption_algorithm=serialization.
                                                                     BestAvailableEncryption(password.encode()))
        private_pem = self.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                                     format=serialization.PrivateFormat.PKCS8,
                                                                     encryption_algorithm=serialization.
                                                                     BestAvailableEncryption(password.encode()))
        # Public keys
        public_auction_pem = self.public_key_auction.public_bytes(
            encoding= serialization.Encoding.PEM,
            format= serialization.PublicFormat.SubjectPublicKeyInfo)
        public_pem = self.public_key.public_bytes(
            encoding= serialization.Encoding.PEM,
            format= serialization.PublicFormat.SubjectPublicKeyInfo)

        files = ["/private_key.pem","/auction_private_key.pem", "/public_key.pem", "/auction_public_key.pem"]
        pem_files = [private_pem, private_auction_pem, public_pem, public_auction_pem]
        count = 0
        for name in files:
            with open(path + name, "wb+") as file:
                file.write(pem_files[count])
                file.close()
            count += 1

    #   Saves the keys in .pem files from the client
    #   path must be the folder  /etc/testing
    def save_keys_server(self, path, password, private_key="/private_key.pem",public_key="/public_key.pem"):
        # Private key
        private_pem = self.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PrivateFormat.PKCS8,
                                                     encryption_algorithm=serialization.
                                                     BestAvailableEncryption(password.encode()))
        # Public keys
        public_pem = self.public_key.public_bytes(
            encoding= serialization.Encoding.PEM,
            format= serialization.PublicFormat.SubjectPublicKeyInfo)

        files=[private_key, public_key]
        pem_files = [private_pem, public_pem]
        count = 0
        for name in files:
            with open(path + name, "wb+") as file:
                file.write(pem_files[count])
                file.close()
            count += 1

    #   Given a path "/etc"
    #   Loads the keys for the client
    #   Returns ARRAY [private_k, pub_k, private_auc_k, pub_auc_k]
    def load_key_clients(self, path, password):
        # Private key
        with open(path + "/private_key.pem", "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode(),
                backend=default_backend())

        # Public key
        with open(path + "/public_key.pem", "rb") as key_file:
            self.public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend())
        # Auction private key
        with open(path + "/auction_private_key.pem", "rb") as key_file:
            self.private_key_auction = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode(),
                backend=default_backend())

        # Auction public key
        with open(path + "/auction_public_key.pem", "rb") as key_file:
            self.public_key_auction = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend())

        return [self.private_key, self.public_key, self.private_key_auction, self.public_key_auction]

    #   Given a path "/etc"
    #   Loads the keys for the server
    #   Returns (private_k, pub_k)
    def load_key_servers(self, path, password, private_key="/private_key.pem", public_key="/public_key.pem"):
        # Private key
        with open(path + private_key, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode(),
                backend=default_backend())

        # Public key
        with open(path + public_key, "rb") as key_file:
            self.public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend())

        return self.private_key, self.public_key

    #   Given a complete path
    #   Loads the public key there
    #   Name if is not given then it will assume its public_key.pem
    #   This is done to speed process of remembering the names
    def load_public_key(self, path, name=utils_app.PK_NAME):
        p_k = b""
        # Public key
        with open(path + "/" + name, "rb") as key_file:
            p_k = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend())
        return p_k





    #   Signs a message with the RSA KeyPair
    #   Returns the encoded signature of the message
    def sign_message(self, message, private_key):

        signature = private_key.sign(message,
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                 salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

        return bytes(signature)

    # Verifies the signature given a message (message as bytes)
    # If invalid signature it raises:
    # raise InvalidSignature cryptography.exceptions.InvalidSignature
    def verify_sign(self, signature, message, peer_public_key):
        try:

            peer_public_key.verify(signature, message,
                                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                   hashes.SHA256())

            return True
        except InvalidSignature:
            return False

    def cipher_public_key(self,public_key,message):
        return public_key.encrypt(message, padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))

    def decipher_with_private_key(self,private_key, message):
        return private_key.decrypt(message, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
