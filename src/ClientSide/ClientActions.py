import os
from ClientSide import Client
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as async_padd
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.hazmat.backends import default_backend
from AssymetricKeys.RSAKeyGen import RSAKeyGen
import sys
from cryptography.fernet import Fernet
from App.App import *


# This class has all the possible messages to communicate with the server
class ClientActions:

    # Logs in
    # Enter the username and password
    # if it is not the correct password closes the program
    def login(self):
        message = "{ \"type\" : \"login\","
        print("\n")
        username = input("Insert Username: ")
        password = input("Insert password: ")

        c = Client.Client(username)
        c.set_credentials(username, password)
        # Now establish the session key for secure communication with both servers
        c.initialize_session_key(AM_ADDRESS)

        # if it exists it wont send its keys
        if c.verify_existence(username):
            try:
                # Loads the keys and the server key
                c.load_keys(password)
                r = RSAKeyGen()
                c.server_public_key = r.load_server_key(os.getcwd()+"/" + c.username)

                # Loads the citizen card
                c.load_citizen_card()
                # Loads the authentication certificate
                cert = c.get_citizen_card().load_authentication_certificate()



            except:
                print("Wrong username/password")
                sys.exit(0)

            message += "\"username\" : \"" + c.username + "\""

        else:
            # Encrypt only the public key, since its the only "sensitive" information atm
            c.set_keys(password)
            pk = c.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(
                'utf-8')
            message += "\"username\" : \"" + c.username + "\","
            message += "\"pk\" : \"" + self.encrypt_function_sk(pk, c) + "\""

        message += " }"
        c.logged = True
        return message, c

    # When we create an auction
    # send a initial json with the Username, type, message encrypted and a signature of the message in clear text.
    # the message field contains all the information of the auction
    # json example clear text: { type : ___ , username : ___ , message :
    #                                                                   { auc_type : ___ , min : ___ },
    #                          signature : ___ }
    def create_auction(self, client):
        message = "{ \"type\" : \"create_auction\",\n"
        message += "\"username\" : \""+client.username + "\",\n"

        # break line
        print("\n")
        # Ask for Auction_type : Either Blind or Normal
        # If user is a smarty ask again.
        auc_type = input("Auction type (B)lind or (N)ormal: ")
        if auc_type.lower() in ["blind", "b"]:
            auc_type = "blind"
        elif auc_type.lower() in ["normal", "n"]:
            auc_type = "normal"
        else:
            self.create_auction(client)

        # Ask for Minimum Bid : [0,1999999]
        auc_min_bid = input("Minimum bid: ")

        # Ask for max bids
        auc_max_number_bids = input("Maximum number of bids \n(Enter 0 for no maximum):  ")

        # Update the auc values to a json
        auc = "{\"auction_type\" : \"" + auc_type + "\",\n"
        auc += "\"min_bid\" : \"" + auc_min_bid + "\" ,\n"
        auc += "\"max_num_bids\" : \"" + auc_max_number_bids + "\" ,\n"

        # Ask for threshold
        op = input("Do you want to customize the threshold? ")
        if op.lower() in ["yes", "y"]:
            th_min = input("Min: ")
            th_max = input("Max: ")
            auc += "\"th\" : \"" + th_min + "," + th_max + "\""
        else:
            auc += "\"th\" : \"" + "0" + "\""

        auc += "}"

        message += "\"message\" : \"" + self.encrypt_function_sk(auc, client) + "\", \n"
        message += "\"sign\" : \"" + client.sign_message(auc) + "\"}"

        client.num_auctions+=1
        return message, client

    #TODO
    def setBidValidation(self):
        message = "{ \"type\" : \"create_auction\",\n"
        message += "\"???\" : \"" + 777 + "\" }"
        return message

    #TODO
    def terminateAuction(self, client, auction):
        message = "{ \"type\" : \"terminate_auction\",\n"
        message += "\"client\" : \"" + client.id + "\", \n "
        message += "\"auction\" : \"" + auction + "\"}"
        return message

    #TODO
    def bid(self, client, auction, value):
        message = "{ \"type\" : \"bid\",\n"
        message += "\"client\" : \"" + client.id + "\", \n "
        message += "\"auction\" : \"" + auction + "\", \n"
        message += "\"value\" : \"" + value + "\"}"
        return message

    # List the auctions from the repository
    def list_auction(self, client, sock):
        if client.session_key_repository is None:
            # Set the session key
            client.initialize_session_key(AR_ADDRESS)

        # Now ask for the auctions
        message = "{ \"type\" : \"auction_list\" }"
        sock.sendto(base64.b64encode(message.encode()), AR_ADDRESS)

        data,address = sock.recvfrom(16384)
        message = base64.b64decode(data)
        print(message.decode())
        print("\n")

        return b""

    # Function that encrypts the message with the session key only
    # Client is necessary
    def encrypt_function_sk(self, message, client, address=None):
        if address == AM_ADDRESS or address is None:
            cipher = Cipher(algorithms.AES(client.session_key), modes.CBC(client.session_key[:16]), backend=default_backend())
        else:
            cipher = Cipher(algorithms.AES(client.session_key_repository),
                            modes.CBC(client.session_key_repository[:16]), backend=default_backend())

        temp = message.encode()
        enc = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        message_enc = b''
        while True:
            if len(temp) < 128:
                message_enc += enc.update(padder.update(temp) + padder.finalize()) + enc.finalize()
                break
            message_enc += enc.update(padder.update(temp[:128]))
            temp = temp[128:]

        return str(base64.b64encode(message_enc), 'utf-8')

    # Function that encrypts the message with the session key and AES key
    # Returns the  [Key, message, iv]
    def encrypt_function_complete(self, message, client, server_public_key):
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

        cipher2 = Cipher(algorithms.AES(client.session_key), modes.CBC(client.session_key[:16]), backend=default_backend())
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

        enc_key = server_public_key.encrypt(key, padding=async_padd.OAEP(
            mgf=async_padd.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))

        array = [enc_key, message_enc_full, iv]
        return array

    # Decrypt with the session key only!
    def decrypt_function_sk(self, session_key, data):

        cipher = Cipher(algorithms.AES(session_key), modes.CBC(
            session_key[:16]), backend=default_backend())

        unpadder = padding.PKCS7(128).unpadder()

        decoded_public_key = unpadder.update(
            cipher.decryptor().update(data) + cipher.decryptor().finalize()) + unpadder.finalize()

        return decoded_public_key

    # Decrypt with the sent key and then session key
    # Sent-key -> decrypt with private key
    # Use the sent-key + iv to get session encrypted message
    # Use session key to get the data
    # session_key: session key;
    # data: complete message
    # client: the current client
    # target_data : the data that we want returned from json; e.g server or username or type or key...
    def decrypt_function_complete(self, session_key, data, client, target_data):

        decoded_data_key = base64.b64decode(data["key"])

        plain_key = client.private_key.decrypt(decoded_data_key, async_padd.OAEP(
                                                     mgf=async_padd.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(),
                                                     label=None
                                                 ))
        decoded_data_iv = base64.b64decode(data["iv"])

        # Decrypt with the session key
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(
            session_key[:16]), backend=default_backend())

        unpadder = padding.PKCS7(128).unpadder()
        dec = unpadder.update(cipher.decryptor().update(
            base64.b64decode(data[target_data])) + cipher.decryptor().finalize()) + unpadder.finalize()

        # Decrypt with AES key
        cipher2 = Cipher(algorithms.AES(plain_key[:32]), modes.CBC(
            decoded_data_iv), backend=default_backend())

        unpadder2 = padding.PKCS7(128).unpadder()
        plain_text = unpadder2.update(cipher2.decryptor().update(
            base64.b64decode(dec)) + cipher2.decryptor().finalize()) + unpadder2.finalize()

        return plain_text
