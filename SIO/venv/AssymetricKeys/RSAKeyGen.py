from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


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
        private_file = open(path+"\\private_key.pem", "wb+")
        private_file.write(private_pem)
        public_file = open(path+"\\public_key.pem", "wb+")
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