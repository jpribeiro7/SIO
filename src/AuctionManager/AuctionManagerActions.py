import socket
from App.App import *
import base64
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
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import ParameterFormat
import cryptography.hazmat.primitives.kdf.hkdf
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from CitizenCard.CitizenCard import *
import codecs
import pickle


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
                                                                                                         + "/server", "pass")
        else:
            os.mkdir(os.getcwd() + "/server")
            self.auction_manager.private_key, self.auction_manager.public_key = self.rsa_keygen.generate_key_pair()
            self.rsa_keygen.save_keys(path=os.getcwd() + "/server",password="pass")

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

        # Get the username
        self.auction_manager.session_clients.append((message_json["username"], self.auction_manager.session_key))
        return base64.b64encode(message.encode('utf-8'))

    # Function to create a auction
    def create_auction(self, address, message_json):
        server_address = AR_ADDRESS
        print(message_json)
        cipher = Cipher(algorithms.AES(self.auction_manager.session_key), modes.CBC(
            self.auction_manager.session_key[:16]), backend=default_backend())

        unpadder = cryptography.hazmat.primitives.padding.PKCS7(128).unpadder()
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
            auction_information["username"] = message_json["username"]
            unpadder = cryptography.hazmat.primitives.padding.PKCS7(128).unpadder()
            decrypted_message = unpadder.update(
                cipher.decryptor().update(
                    base64.b64decode(auction_information["pk"])) + cipher.decryptor().finalize()) + unpadder.finalize()

            auction_information["pk"] = codecs.encode(decrypted_message,"base64").decode()


            print(str(auction_information))
            encrypted_message_sk = self.encrypt_function_sk(str(auction_information))
            # Send the enc message to the server
            message = "{"
            message += "\"type\" : \"create_auction\" ,"
            message += "\"message\" : \"" + encrypted_message_sk + "\""
            message += "}"

            self.sock.sendto(base64.b64encode(message.encode()), AR_ADDRESS)

            data, add = self.sock.recvfrom(16384)
            decoded_data = base64.b64decode(data)
            json_message = json.loads(decoded_data)
            if json_message["success"] == "success":
                return base64.b64encode("{\"success\" : \"success\"}".encode('utf-8'))

        else:
            # Returns error
            return base64.b64encode("{\"success\" : \"error\"}".encode('utf-8'))

        # returns empty string
        return base64.b64encode("".encode())

    # Verifies the login
    # Create the user folder
    def login_actions(self, address, data):
        # decode with the session key
        cipher = Cipher(algorithms.AES(self.auction_manager.session_key), modes.CBC(
            self.auction_manager.session_key[:16]), backend=default_backend())

        unpadder = cryptography.hazmat.primitives.padding.PKCS7(128).unpadder()
        decoded_auth_cert = unpadder.update(
            cipher.decryptor().update(base64.b64decode(data["cert"])) + cipher.decryptor().finalize()) + unpadder.finalize()

        unpadder = cryptography.hazmat.primitives.padding.PKCS7(128).unpadder()
        decoded_digital_sign = unpadder.update(
            cipher.decryptor().update(base64.b64decode(data["sign"])) + cipher.decryptor().finalize()) + unpadder.finalize()
        print(decoded_auth_cert)
        print(decoded_digital_sign)
        certificate = x509.load_pem_x509_certificate(decoded_auth_cert ,default_backend())
        citizen  = CitizenCard()
        if not citizen.validate_certificate(certificate):
            return base64.b64encode("{ \"error\" : \"No valid certificate\"}".encode('utf-8'))

        # if it exists then return success because the key wont change
        if os.path.isdir(os.getcwd() + "/clients/" + data["username"]):
            return base64.b64encode("{ \"success\" : \"success\"}".encode('utf-8'))
        unpadder = cryptography.hazmat.primitives.padding.PKCS7(128).unpadder()
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

        # Verify the uses signature of the session key
        if self.rsa_keygen.verify_sign(base64.b64decode(data["signature"]), self.auction_manager.session_key, user_key) is not None:
            # It is invalid
            return base64.b64encode("{\"success\" : \"error\"}".encode("utf-8"))

        # This will encrypt with the session and then with the user public key
        # Key, message, iv
        # Get the key from the user
        session_key_user = b""
        for key, value in self.auction_manager.session_clients:
            if key == data["username"]:
                session_key_user = value
                break

        encrypted_pk = self.encrypt_function(pk, session_key_user, user_key)

        message = "{\"server\" : \"" + str((encrypted_pk[1]), 'utf-8') + "\","
        message += "\"key\" : \"" + str(base64.b64encode(encrypted_pk[0]), 'utf-8') + "\","
        message += "\"iv\" : \"" + str(base64.b64encode(encrypted_pk[2]), 'utf-8') + "\"}"

        return base64.b64encode(message.encode('utf-8'))

    # Initializes the session key with the server
    def initialize_session_key_server(self):
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
        json_message += "\"type\" : \"session_server\"," + "\n"
        json_message += "\"data\" : \"" + message + "\", \n"
        json_message += "\"pk\" : \"" + public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(
            'utf-8') + "\""
        json_message += "}"

        try:
            # send response
            sent = sock.sendto(base64.b64encode(json_message.encode('utf-8')), AR_ADDRESS)

            # Receive response
            data, server = sock.recvfrom(16384)
            # derivate the key
            peer_public_key_bytes = base64.b64decode(data)
            peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, default_backend())
            shared_key = private_key.exchange(peer_public_key)

            derived_key = cryptography.hazmat.primitives.kdf.hkdf.HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data',
                                                                       backend=default_backend()).derive(shared_key)

            #For now we use it as a SEED
            self.auction_manager.session_key_server = derived_key

        finally:
            sock.close()

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
        padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
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
        padder2 = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
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

    # Function that encrypts the message with the session key only
    def encrypt_function_sk(self, message):
        cipher = Cipher(algorithms.AES(self.auction_manager.session_key_server), modes.CBC(self.auction_manager.
                                                                                           session_key_server[:16]),
                        backend=default_backend())
        temp = message.encode()
        enc = cipher.encryptor()
        padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
        message_enc = b''
        while True:
            if len(temp) < 128:
                message_enc += enc.update(padder.update(temp) + padder.finalize()) + enc.finalize()
                break
            message_enc += enc.update(padder.update(temp[:128]))
            temp = temp[128:]

        return str(base64.b64encode(message_enc), 'utf-8')