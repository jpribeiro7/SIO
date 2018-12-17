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

# This class has all the possible messages to comunicate with the server
class ClientActions:

    # Logs in
    # Enter the username and password
    # if it is not the correct password it shall give an error
    # POR ENQUANTO O PROGRAMA CONTINUA NORMALMENTE MESMO ESTANDO ERRADA
    def Login(self):
        message = "{ \"type\" : \"login\","

        print("\n")

        username = input("Insert Username: ")
        password = input("Insert password: ")

        # Username is some information from the cc
        c = Client.Client(username)
        c.set_credentials(username,password)
        # Now establish the session key for secure communication
        c.initialize_session_key()

        # if it exists it wont send its keys
        if c.verify_existence(username):

            try:
                c.load_keys(password)
                r = RSAKeyGen()
                c.server_public_key = r.load_server_key(os.getcwd()+"/" + c.username)
            except:
                print("Wrong username/password")

            message += "\"username\" : \"" + c.username + "\""

        else:
            # Encrypt only the public key, since its the only sensitive information atm
            c.set_keys(password)
            pk = c.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(
                'utf-8')
            message += "\"username\" : \"" + c.username + "\","
            message += "\"pk\" : \"" + self.encrypt_function(pk, c)+ "\""

        message += " }"

        return message,c

    # When we create an auction
    # send a initial json with the Username, type, message encrypted and a signature of the message in clear text.
    # the message field contains all the information of the auction
    # json example clear text: { type : ___ , username : ___ , message :
    #                                                                   { auc_type : ___ , min : ___ },
    #                          signature : ___ }
    def create_auction(self,client):
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

        message += "\"message\" : \"" + self.encrypt_function(auc, client) + "\", \n"
        message += "\"sign\" : \"" + client.sign_message(auc) + "\"}"

        return message

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

    # Function that encrypts the message with the session key only
    # Client is necessary
    def encrypt_function(self, message, client):
        cipher = Cipher(algorithms.AES(client.session_key), modes.CBC(client.session_key[:16]), backend=default_backend())
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

    # Function that encrypts the message with the session key and public key
    # Client is necessary
    # TODO
    def encrypt_function_complete(self, message, client, server_public_key):
        cipher = Cipher(algorithms.AES(client.session_key), modes.CBC(client.session_key[:16]), backend=default_backend())
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

    # Decrypt with the session key only!
    def decrypt_function(self, session_key, data):

        cipher = Cipher(algorithms.AES(session_key), modes.CBC(
            session_key[:16]), backend=default_backend())

        unpadder = padding.PKCS7(128).unpadder()

        decoded_public_key = unpadder.update(
            cipher.decryptor().update(data) + cipher.decryptor().finalize()) + unpadder.finalize()

        return decoded_public_key

    # Decrypt with the private key and then session key
    def decrypt_function_complete(self, session_key, data, client):


        decoded_data = base64.b64decode(data)

        plain_text = client.private_key.decrypt(decoded_data,
                                                 async_padd.OAEP(
                                                     mgf=async_padd.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(),
                                                     label=None
                                                 ))
        plain_text = b""
        while True:
            if len(decoded_data) < 4096:
                plain_text += client.private_key.decrypt(decoded_data,
                                                         async_padd.OAEP(
                                                            mgf=async_padd.MGF1(algorithm=hashes.SHA256()),
                                                             algorithm=hashes.SHA256(),
                                                            label=None
                                                         ))
                break
            plain_text += client.private_key.decrypt(decoded_data[:4096],
                                                     async_padd.OAEP(
                                                         mgf=async_padd.MGF1(algorithm=hashes.SHA256()),
                                                         algorithm=hashes.SHA256(),
                                                         label=None
                                                     ))
            decoded_data = decoded_data[4096:]

        cipher = Cipher(algorithms.AES(session_key), modes.CBC(
            session_key[:16]), backend=default_backend())

        unpadder = padding.PKCS7(128).unpadder()

        dec = unpadder.update(
            cipher.decryptor().update(base64.b64decode(plain_text)) + cipher.decryptor().finalize()) + unpadder.finalize()

        print(dec)
        return dec
