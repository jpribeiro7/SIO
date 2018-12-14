from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
import base64

class RSAKeyGen:

    def __init__(self):
        self.private_key = None
        self.public_key = None
        # Password is to be used when encrypting/decrypting the private key?
        self.password = None

    #   Generates the Key pair
    #   Returns the Private_key, Public_key tuple
    def generate_key_pair(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537,
                                    key_size=2048,
                                    backend=default_backend())

        self.public_key = self.private_key.public_key()

        return self.private_key, self.public_key

    #   Saves the keys in .pem files
    #   If there is no password there wont be any encryption
    #   path must be the folder  /etc/testing
    def save_keys(self,path,password=None):

        # Verifies the case where it has or has not the password
        if password is not None:
            private_pem = self.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PrivateFormat.PKCS8,
                                                         encryption_algorithm=serialization.BestAvailableEncryption(
                                                             password.encode()))
        else:
            private_pem = self.private_key.private_bytes(encoding=serialization.Encoding.PEM ,
                                                         format=serialization.PrivateFormat.PKCS8,
                                                         encryption_algorithm=serialization.NoEncryption())

        # Public key doesn't need to be encrypted
        public_pem = self.public_key.public_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PublicFormat.SubjectPublicKeyInfo)

        # Save the files ( if in WINDOWS USE \\ )
        private_file = open(path+"/private_key.pem", "wb+")
        private_file.write(private_pem)
        public_file = open(path+"/public_key.pem", "wb+")
        public_file.write(public_pem)

    #   Given a path "/etc"
    #   Password is if there is any encryption in the private key
    #   Returns the Private_key, Public_key tuple
    def load_key(self,path, password=None):

        # Verifies both cases for the private key
        if password is not None:
            with open(path + "/private_key.pem", "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password = password.encode(),
                backend = default_backend())
        else:
            with open(path + "/private_key.pem", "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password = None,
                backend = default_backend())

        # Public key load
        with open(path + "/public_key.pem", "rb") as key_file:
            self.public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend = default_backend())

        return self.private_key, self.public_key

    #   Signs a message with the KeyPair
    #   After a signature, the public key must be passed to check that it is the real person who sent
    #   If a message is 300 chars or longer it will use digest! (This changes the verify_signature ->
    #   Not yet implemented with digest)
    def sign_message(self, message):

        # if Messages are to large use Pre-hashing
        if len(message) > 300:
            used_hash = hashes.SHA256()
            hasher = hashes.Hash(used_hash, default_backend())

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

        if type == "BYTES":
            return peer_public_key.verify(signature, message,
                                            padding.PSS(
                                                mgf=padding.MGF1(hashes.SHA256()),
                                                salt_length=padding.PSS.MAX_LENGTH
                                            ), hashes.SHA256())
        else:
            return peer_public_key.verify(signature, message.encode(),
                                            padding.PSS(
                                                mgf=padding.MGF1(hashes.SHA256()),
                                                salt_length=padding.PSS.MAX_LENGTH
                                            ), hashes.SHA256())