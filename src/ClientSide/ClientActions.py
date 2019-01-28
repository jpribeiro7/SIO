from ClientSide.Client import Client
from App.utilities import *
from App.app import *
from RSAKeyGenerator.RSAKGen import RSAKGen
import sys
from CitizenCard.CitizenCard import CitizenCard
from App.HMAC_Conf import HMAC_Conf
import pickle
from AuctionRepository.Block import Block
import socket
import json
from AuctionRepository.Auction import Auction


class ClientActions:
    _client_path = ""
    digital_signature = None
    last = None

    # Logs in with the servers
    def login(self):
        rsa_gen = RSAKGen()
        print("\n")
        username = input("Username: ")
        password = input("password: ")

        current_client = Client(username)
        current_client.password = password
        self._client_path = os.getcwd() + "/" + username

        # Check existence
        if check_directory(self._client_path):
            try:
                keys = rsa_gen.load_key_clients(self._client_path, password)
            except ValueError:
                print("\nPassword Entered was incorrect!")
                sys.exit(0)

            # Private key
            current_client.private_key = keys[0]
            current_client.public_key = keys[1]
            current_client.auction_private_key = keys[2]
            current_client.auction_public_key = keys[3]

            current_client.server_public_key_manager = rsa_gen.\
                load_public_key(self._client_path,"server_manager.pem")

            current_client.server_public_key_repository = rsa_gen.\
                load_public_key(self._client_path,"server_repository.pem")

        else:
            os.mkdir(self._client_path)
            os.mkdir(self._client_path+"/receipts")
            keys = rsa_gen.generate_key_pair_client()
            # Private key
            current_client.private_key = keys[0]
            current_client.public_key = keys[1]
            current_client.auction_private_key = keys[2]
            current_client.auction_public_key = keys[3]
            rsa_gen.save_keys_client(self._client_path, password)

        # builds DH
        current_client.initialize_session_key(AM_ADDRESS)
        current_client.initialize_session_key(AR_ADDRESS)

        current_client.citizenCard = CitizenCard()

        return current_client

    # Sends the message to the server to begin the trust
    def trust_server(self,client, address=None):

        # loads citizen card
        rsa = RSAKGen()
        certificate = client.citizenCard.load_authentication_certificate()
        # print(client.username)
        if client.username != self.last and self.digital_signature is None:
            self.digital_signature = client.citizenCard.digital_signature(client.username.encode('utf-8'))
            self.last = client.username

        session_key = None
        if AM_ADDRESS == address:
            session_key = client.session_key_manager
        else:
            session_key = client.session_key_repository

        digital_signature = self.digital_signature
        rsa_sign = rsa.sign_message(client.username.encode('utf-8'), client.private_key)

        # We mac the CERTIFICATE
        hmac = HMAC_Conf.integrity_control(encrypt_message_sk(certificate, session_key).encode("utf-8"),
                                    session_key)

        # print(rsa.sign_message(client.username.encode('utf-8'), client.private_key) )
        # builds trust message
        json_message = "{ " + "\n"
        json_message += "\"type\" : \"build_trust\"," + "\n"
        json_message += "\"public\" : \"" + encrypt_message_sk(get_public_key_bytes(client.public_key),
                                                               session_key) + "\", \n"
        json_message += "\"rsa_signature\" : \"" + encrypt_message_sk(rsa_sign, session_key) + "\", \n"
        json_message += "\"username\" : \"" + client.username + "\", \n"
        json_message += "\"certificate\" : \"" + encrypt_message_sk(certificate, session_key) + "\", \n"
        json_message += "\"hmac\" : \"" + str(base64.b64encode(hmac), 'utf-8') + "\", \n"
        json_message += "\"digital_signature\" : \"" + encrypt_message_sk(digital_signature, session_key) + "\""
        json_message += "\n" + "}"
        return json_message

    # This will create the auction with the server
    # The message is organized in this way
    # type : STRING, username: STRING, message= json with the attributes
    def create_auction(self, client):
        message = "{ \"type\" : \"create_auction\" ,\n"
        message += "\"username\" : \"" + client.username + "\",\n"

        # Now ask for all the details
        print("\n")
        # Verify the fields

        # Auction needs a name
        auction_name = input("Auction name: ")
        while auction_name == "":
            auction_name = input("Auction name: ")

        # If there is no description then put it as None
        auction_description = input("Auction description: ")
        if auction_description == "":
            auction_description = "None"

        # If no given minimum the put it at zero $
        auction_min_number_bids = input("Minimum price bid: ")
        if auction_min_number_bids == "":
            auction_min_number_bids = "0"

        # There needs to be a limit
        auction_time = input("Auction time limit (Hrs): ")
        while int(auction_time) < 0:
            auction_time = input("Auction time limit (Hrs): ")

        # If there is no max bids then 0
        auction_max_number_bids = input("Auction maximum number of bids: ")
        if auction_max_number_bids == "":
            auction_max_number_bids = "0"

        # If there is no given names then put it as None
        auction_allowed_bidders = input("Auction allowed bidders (separate with [,]): ")
        if auction_allowed_bidders == "":
            auction_allowed_bidders = "None"

        # There must have a type
        auction_type = input("Auction type ((B)lind or (N)ormal): ")
        if auction_type.lower() in ["b", "blind"]:
            auction_type = BLIND_AUCTION
            print("Blind auction is being created...")
        else:
            auction_type = ENGLISH_AUCTION
            print("Normal auction is being created...")

        # sign the session key
        rsa = RSAKGen()
        signature = rsa.sign_message(client.session_key_manager,client.auction_private_key)

        auction_json_message = "{\"auction_name\" : \"" + encrypt_message_sk(auction_name, client.session_key_manager)+ "\" ,\n"

        auction_json_message += "\"auction_description\" : \"" + encrypt_message_sk(auction_description,
                                                                      client.session_key_manager) + "\" ,\n"

        auction_json_message += "\"auction_min_number_bids\" : \"" + encrypt_message_sk(auction_min_number_bids,
                                                                           client.session_key_manager) + "\",\n"

        auction_json_message += "\"auction_time\" : \"" + encrypt_message_sk(auction_time, client.session_key_manager) + "\" ,\n"

        auction_json_message += "\"auction_max_number_bids\" : \"" + encrypt_message_sk(auction_max_number_bids,
                                                                          client.session_key_manager) + "\" ,\n"

        auction_json_message += "\"auction_allowed_bidders\" : \"" + encrypt_message_sk(auction_allowed_bidders,
                                                                          client.session_key_manager) + "\" ,\n"

        auction_json_message += "\"auction_type\" : \""+ encrypt_message_sk(auction_type, client.session_key_manager) + "\" ,\n"

        # now put our public auction key and a signature to prove that he has the private key
        auction_json_message += "\"auction_user_key\" : \"" + encrypt_message_sk(get_public_key_bytes(client.auction_public_key),
                                                                    client.session_key_manager) + "\", \n"

        auction_json_message += "\"auction_signature\" : \"" + encrypt_message_sk(str(base64.b64encode(signature), 'utf-8'),
                                                                     client.session_key_manager)+ "\" \n"
        auction_json_message += "}"

        enc_json_message = encrypt_message_complete(base64.b64encode(auction_json_message.encode("utf-8")),
                                                    client.session_key_manager,
                                                    client.server_public_key_manager)

        key = enc_json_message[0]
        iv = enc_json_message[2]
        data = enc_json_message[1]

        hmac = HMAC_Conf.integrity_control(data.encode(), client.session_key_manager)

        message += "\"message\" : \"" + data + "\",\n"
        message += "\"Key\" : \"" + str(base64.b64encode(key), 'utf-8') + "\",\n"
        message += "\"hmac\" : \"" + str(base64.b64encode(hmac), 'utf-8')+ "\", \n"
        message += "\"iv\" : \"" + str(base64.b64encode(iv), 'utf-8') + "\"\n"

        message += "}"
        return message, AM_ADDRESS

    # List the auctions pressent in the server
    def list_auctions(self, client):
        hmac = HMAC_Conf.integrity_control(client.username.encode(), client.session_key_repository)

        message = "{ \"type\" : \"list_auctions\" ,\n"
        message += "\"username\" : \"" + client.username + "\",\n"
        message += "\"hmac\" : \"" + str(base64.b64encode(hmac), 'utf-8')+ "\"\n"
        message += "}"

        return message, AR_ADDRESS

    # Makes a bid to the repository
    # TODO: Get a cryptopuzzle and solve it
    def make_bid(self, client):

        amount = ""
        auction_id = ""
        while auction_id == "":
            auction_id = input("Auction ID: ")

        while amount == "":
            amount = input("Bid Amount: ")
        if not self.pre_bid(client,auction_id):
            return
        citizen = CitizenCard()
        certificate = citizen.load_authentication_certificate()
        signature = citizen.digital_signature(amount)
        message = "{ \"type\" : \"bid\" ,\n"
        message += "\"username\" : \"" + client.username + "\",\n"
        interm_message = "{ \"auction_id\" : \"" + encrypt_message_sk(auction_id,client.session_key_repository) + "\",\n"
        interm_message += "\"amount\" : \"" + encrypt_message_sk(amount,client.session_key_repository) + "\",\n"
        interm_message += "\"bidder\" : \"" + encrypt_message_sk(citizen.load_name(),client.session_key_repository) + "\",\n"
        interm_message += "\"certificate\" : \"" + encrypt_message_sk(certificate, client.session_key_repository) + "\",\n"
        interm_message += "\"signature\" : \"" + encrypt_message_sk(signature,client.session_key_repository) + "\"\n"
        interm_message += "}"

        enc_json_message = encrypt_message_complete(base64.b64encode(interm_message.encode("utf-8")),
                                                    client.session_key_repository,
                                                    client.server_public_key_repository)

        key = enc_json_message[0]
        iv = enc_json_message[2]
        data = enc_json_message[1]
        hmac = HMAC_Conf.integrity_control(data.encode(),client.session_key_repository)

        message += "\"message\" : \"" + data + "\",\n"
        message += "\"Key\" : \"" + str(base64.b64encode(key), 'utf-8') + "\",\n"
        message += "\"hmac\" : \"" + str(base64.b64encode(hmac), 'utf-8') + "\", \n"
        message += "\"iv\" : \"" + str(base64.b64encode(iv), 'utf-8') + "\"\n"
        message += "}"

        #print(message)
        return message, AR_ADDRESS


    def pre_bid_get_auction(self, client, auction_id):
        enc_auct_id = encrypt_message_sk(auction_id, client.session_key_repository)
        #print(enc_auct_id.encode())
        # Cipher the auction ID complete
        enc_json_message = encrypt_message_complete(base64.b64encode(enc_auct_id.encode("utf-8")),client.session_key_repository, client.server_public_key_repository)
        key = enc_json_message[0]
        iv = enc_json_message[2]
        data = enc_json_message[1]
        hmac = HMAC_Conf.integrity_control(data.encode(),client.session_key_repository)

        message = "{ \"type\" : \"pre_bid_auction\" ,\n"
        message += "\"username\" : \"" + client.username + "\" ,\n"
        message += "\"auction_id\" : \"" + data + "\",\n"
        message += "\"Key\" : \"" + str(base64.b64encode(key), 'utf-8') + "\",\n"
        message += "\"iv\" : \"" + str(base64.b64encode(iv), 'utf-8') + "\",\n"
        message += "\"hmac\" : \"" + str(base64.b64encode(hmac), 'utf-8') + "\"\n"
        message += "}"

        return message, AR_ADDRESS



    def get_auction(self, client):
        auction_id = ""
        while auction_id == "":
            auction_id = input("Auction ID: ")

        enc_auct_id = encrypt_message_sk(auction_id, client.session_key_repository)
        #print(enc_auct_id.encode())
        # Cipher the auction ID complete
        enc_json_message = encrypt_message_complete(base64.b64encode(enc_auct_id.encode("utf-8")),client.session_key_repository, client.server_public_key_repository)
        key = enc_json_message[0]
        iv = enc_json_message[2]
        data = enc_json_message[1]
        hmac = HMAC_Conf.integrity_control(data.encode(),client.session_key_repository)

        message = "{ \"type\" : \"get_auction_to_close\" ,\n"
        message += "\"username\" : \"" + client.username + "\" ,\n"
        message += "\"auction_id\" : \"" + data + "\",\n"
        message += "\"Key\" : \"" + str(base64.b64encode(key), 'utf-8') + "\",\n"
        message += "\"iv\" : \"" + str(base64.b64encode(iv), 'utf-8') + "\",\n"
        message += "\"hmac\" : \"" + str(base64.b64encode(hmac), 'utf-8') + "\"\n"
        message += "}"

        return message, AR_ADDRESS

    def close_auction(self, client, message_json):

        # VERIFYES THE message integrity
        if not HMAC_Conf.verify_function("message", message_json, client.session_key_repository):
            return base64.b64encode("{ \"type\" : \"Tempered data\"}".encode('utf-8'))

        # Decrypts the message
        data = decrypt_data(client.session_key_repository,
                            message_json["message"], base64.b64decode(message_json["iv"]),
                            base64.b64decode(message_json["Key"]),
                            client.private_key)

        data_json = json.loads(data, strict="false")
        something = unpadd_data(data_json["blockchain"], client.session_key_repository)
        blockchain = pickle.loads(something)
        rsa_kg = RSAKGen()
        for bid in blockchain:
            bid.second_symmetric_key = rsa_kg.decipher_with_private_key(client.auction_private_key, bid.second_symmetric_key)

        bloc_chain_enc = encrypt_message_sk(pickle.dumps(blockchain), client.session_key_repository)

        message = "{ \"type\" : \"close_auction\" ,\n"
        message += "\"username\" : \"" + client.username + "\" ,\n"

        message_interm = "{"
        message_interm += "\"auction_id\" : \"" + data_json["auction_id"]+ "\",\n"
        message_interm += "\"blockchain\" : \"" + bloc_chain_enc + "\"\n"
        message_interm += "}"

        enc_json_message = encrypt_message_complete(base64.b64encode(message_interm.encode("utf-8")), client.session_key_repository, client.server_public_key_repository)
        key = enc_json_message[0]
        iv = enc_json_message[2]
        data = enc_json_message[1]

        hmac = HMAC_Conf.integrity_control(data.encode(),client.session_key_repository)

        message += "\"message\" : \"" + data + "\" ,\n"
        message += "\"Key\" : \"" + str(base64.b64encode(key), 'utf-8') + "\",\n"
        message += "\"iv\" : \"" + str(base64.b64encode(iv), 'utf-8') + "\",\n"
        message += "\"hmac\" : \"" + str(base64.b64encode(hmac), 'utf-8') + "\"\n"
        message += "}"

        return message, AR_ADDRESS

    ## ADDED
    def auction_to_view(self, client, id_auc):
        message = "{\"type\" : \"auction_to_view\",\n"
        message += "\"username\" :\"" + client.username +"\", \n"

        idd = encrypt_message_sk(id_auc, client.session_key_repository)
        inter = encrypt_message_complete(base64.b64encode(idd.encode("utf-8")), client.session_key_repository, client.server_public_key_repository)

        key = inter[0]
        iv = inter[2]
        data = inter[1]
        hmac = HMAC_Conf.integrity_control(data.encode(),client.session_key_repository)

        message += "\"message\" : \"" + data + "\",\n"
        message += "\"Key\" : \"" + str(base64.b64encode(key), 'utf-8') + "\",\n"
        message += "\"hmac\" : \"" + str(base64.b64encode(hmac), 'utf-8') + "\", \n"
        message += "\"iv\" : \"" + str(base64.b64encode(iv), 'utf-8') + "\"\n"
        message += "}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(base64.b64encode(message.encode()), AR_ADDRESS)

            data, server = sock.recvfrom(SOCKET_BYTES)

            # The client should always receive a confirmation from the server
            decoded_message = base64.b64decode(data)
            message = json.loads(decoded_message, strict = False)

            if not HMAC_Conf.verify_function("message", message, client.session_key_repository):
                return base64.b64encode("{ \"type\" : \"Tempered data\"}".encode('utf-8'))

            # Decrypts the message
            data = decrypt_data(client.session_key_repository,
                                message["message"], base64.b64decode(message["iv"]),
                                base64.b64decode(message["Key"]),
                                client.private_key)

            data_json = json.loads(data, strict="false")

            # Now decript the blockchain
            auc_type = unpadd_data(data_json["auct_type"], client.session_key_repository)
            dec_bloc = unpadd_data(data_json["blockchain"], client.session_key_repository)
            block_chain = pickle.loads(dec_bloc)
            availability = unpadd_data(data_json["avail"],client.session_key_repository)

            #
            # Auction is still ongoing
            #
            if str(availability, "utf-8") == "True":
                # validate blockchain
                if not Auction.validate_blockchain(block_chain, auc_type):
                    print("The auction is not valid! ")
                    return base64.b64encode("{ \"type\" : \"Tempered data\"}".encode('utf-8'))

                for bid in block_chain:
                    print("------------------------")
                    print("User: " + str(bid.username, "utf-8"))
                    print("Ammount: " + str(bid.amount, "utf-8"))
                    if bid.previous_hash == None:
                        print("Previous_hash: " + str(bid.previous_hash))
                    else:
                        print("Previous_hash: " + str(bid.previous_hash, "utf-8"))
                    print("Bid Hash: " + str(bid.hash, "utf-8"))

                print("\nAuction is valid")

                return base64.b64encode("{ \"type\" : \"Valid\"}".encode('utf-8'))


            #
            # Always validate blockchain
            #
            if not Auction.validate_blockchain(block_chain, auc_type):
                print("The auction is not valid! ")
                return base64.b64encode("{ \"type\" : \"Tempered data\"}".encode('utf-8'))

            #
            #Auction is closed now we check
            #
            if str(auc_type, "utf-8") == ENGLISH_AUCTION:
                validity = True
                for bid in block_chain:
                    sec_dec = Fernet(bid.first_symmetric_key)

                    print("---------------------------------")
                    print("Bidder: " + str(sec_dec.decrypt(bid.username), "utf-8"))
                    print("Amount: " + str(bid.amount, "utf-8"))

                    cert_bytes = sec_dec.decrypt(bid.certificate)
                    cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
                    a = CitizenCard()
                    if not a.validate_certificate(cert):
                        validity = False

                    sign = sec_dec.decrypt(bid.signature)

                    if not a.check_signature(cert, sign, bid.amount ):
                        validity = False
                        print("Signature: Not valid")
                    else:
                        print("Signature: Valid")

                    if bid.previous_hash == None:
                        print("Previous_hash: " + str(bid.previous_hash))
                    else:
                        print("Previous_hash: " + str(bid.previous_hash, "utf-8"))

                    print("Bid Hash: " + str(bid.hash, "utf-8"))

                if validity == False:
                    print("The auction is not valid")

            else:
                validity = True
                prev_bid = None #amount
                bd = None #Winner bid
                for bid in block_chain:
                    sec_dec = Fernet(bid.first_symmetric_key)
                    dec_amount = sec_dec.decrypt(bid.amount)
                    ammount = int((str(dec_amount,"utf-8")))

                    if prev_bid == None:
                        prev_bid = ammount
                        bd = bid
                    else:
                        if prev_bid < ammount:
                            prev_bid = ammount
                            bd = bid

                print("---------------Winner--------------------")
                sec_dec = Fernet(bd.first_symmetric_key)
                dec_amount = sec_dec.decrypt(bd.amount)
                print("Amount: " + str(dec_amount,"utf-8"))
                dec_user = sec_dec.decrypt(bd.username)
                print("User: " + str(dec_user,"utf-8"))
                cert_bytes = sec_dec.decrypt(bd.certificate)
                cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
                a = CitizenCard()
                if not a.validate_certificate(cert):
                    validity = False
                    print("The auction is not valid")
            print("----------------")

        finally:
            sock.close()


    def save_receipt(self, client, message_json):
        # VERIFYES THE message integrity
        if not HMAC_Conf.verify_function("message", message_json, client.session_key_repository):
            return base64.b64encode("{ \"type\" : \"Tempered data\"}".encode('utf-8'))

        # Decrypts the message
        data = decrypt_data(client.session_key_repository,
                            message_json["message"], base64.b64decode(message_json["iv"]),
                            base64.b64decode(message_json["Key"]),
                            client.private_key)

        message_json = json.loads(data, strict="false")
        timestamp = unpadd_data(message_json["timestamp"], client.session_key_repository)
        server_signature = unpadd_data(message_json["server_signature"], client.session_key_repository)
        auction_id = unpadd_data(message_json["auction_id"], client.session_key_repository)
        bid_amount = unpadd_data(message_json["bid_amount"], client.session_key_repository)
        bid_signature = unpadd_data(message_json["bid_signature"], client.session_key_repository)
        bloc_hash = unpadd_data(message_json["bloc_hash"], client.session_key_repository)
        receipt_unique_hash = unpadd_data(message_json["receipt_unique_hash"], client.session_key_repository)
        bidder = unpadd_data(message_json["bidder"], client.session_key_repository)

        rsa_kg = RSAKGen()
        citizen = CitizenCard()
        result = rsa_kg.verify_sign(server_signature, bloc_hash, client.server_public_key_repository)
        if not result:
            print("The receipt signature is not valid")
            return
        cert = citizen.load_authentication_certificate()
        result = citizen.check_signature(cert, bid_signature, bid_amount)
        if not result:
            print("The client signature is not valid")
            return

        if citizen.load_name() != bidder:
            print("The bidder name is not the same as the citizen card")
            return

        receipt = create_receipt(timestamp,auction_id,server_signature,bid_amount,bid_signature,receipt_unique_hash,bloc_hash, bidder)

        file = open(os.getcwd() + "/" + client.username + "/receipts/"+str(auction_id)+"_"+str(timestamp)+".json","w")
        json.dump(receipt, file)


    def pre_bid(self,client,auction_id):

        msg, address = self.pre_bid_get_auction(client,auction_id)

        msg_encoded = base64.b64encode(msg.encode('utf-8'))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg_encoded, address)
        oo = True
        dee = b""
        while oo:
            data, server = sock.recvfrom(SOCKET_BYTES)
            dee += data
            try:
                decoded_message = base64.b64decode(dee)
                message_json = json.loads(decoded_message, strict = False)
                oo = False
            except:
                oo = True
                print("One")

        decoded_message = base64.b64decode(dee)
        message_json = json.loads(decoded_message, strict = False)
        print("I decoded")
        # VERIFYES THE message integrity
        if not HMAC_Conf.verify_function("message", message_json, client.session_key_repository):
            return base64.b64encode("{ \"type\" : \"Tempered data\"}".encode('utf-8'))

        # Decrypts the message
        data = decrypt_data(client.session_key_repository,
                            message_json["message"], base64.b64decode(message_json["iv"]),
                            base64.b64decode(message_json["Key"]),
                            client.private_key)

        data_json = json.loads(data, strict="false")
        something = unpadd_data(data_json["blockchain"], client.session_key_repository)
        chain_type = unpadd_data(data_json["auct_type"], client.session_key_repository)
        blockchain = pickle.loads(something)
        result = Auction.validate_blockchain(blockchain, chain_type)
        if not result:
            print("Chain is not legit")
            return False

        i = 0
        for bid in blockchain:
            i += 1
        Auction.cryptopuzzle(100+i,100-i)
        return True
    
    def show_receipts(self, client):
        dictt = {}
        for dirname, dirnames, filenames in os.walk(self._client_path + "/receipts/"):
            # print path to all filenames.
            i = 1
            for filename in filenames:
                dictt[i] = filename
                print(filename)
                i += 1
        print("IM HERE")

